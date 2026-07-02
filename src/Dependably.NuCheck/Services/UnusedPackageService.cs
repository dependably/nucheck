using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Heuristically detects NuGet packages that are declared as direct
/// <c>&lt;PackageReference&gt;</c> dependencies but whose namespace does not appear in
/// any <c>.cs</c> source file under the scan root. Findings are advisory only and never
/// cause the process to exit non-zero — build-tool, analyzer, and MSBuild-task packages
/// frequently trigger false positives.
/// </summary>
/// <remarks>
/// To keep the heuristic trustworthy, references that are <em>expected</em> to have no
/// runtime namespace are excluded up-front and never reported:
/// <list type="bullet">
///   <item>references marked as not flowing to consumers via MSBuild asset metadata —
///     <c>PrivateAssets="all"</c> (attribute or child element), or
///     <c>IncludeAssets</c>/<c>ExcludeAssets</c> indicating analyzers/build-only assets
///     with the compile assets excluded; and</item>
///   <item>a small built-in allowlist of common build/analyzer/source-generator package
///     ids (see <see cref="IsKnownBuildOrAnalyzerId"/>).</item>
/// </list>
/// Both are in addition to — not a replacement for — the user-supplied
/// <c>ignoreUnusedPackages</c> suppression list.
/// </remarks>
public static partial class UnusedPackageService
{
    /// <summary>
    /// Caps regex matching time so a pathological input file can never hang the scan
    /// (defends against ReDoS — the unused-package check must never disrupt the audit).
    /// </summary>
    private const int RegexTimeoutMs = 1000;

    /// <summary>
    /// Matches <c>using</c> (and <c>global using</c> / <c>using static</c>) directives.
    /// Capture group 1 is the namespace identifier.
    /// </summary>
    [GeneratedRegex(
        @"^\s*(?:global\s+)?using\s+(?:static\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;",
        RegexOptions.Multiline,
        RegexTimeoutMs)]
    private static partial Regex UsingDirectivePattern();

    /// <summary>
    /// Matches multi-segment qualified identifiers (e.g. <c>Foo.Bar.Thing</c>) that may
    /// appear as qualified type references in code that does not use a <c>using</c> directive.
    /// Applied only after comments and string/char literals have been stripped so that a
    /// package id appearing only in a comment or string does not count as usage.
    /// </summary>
    [GeneratedRegex(
        @"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\b",
        RegexOptions.None,
        RegexTimeoutMs)]
    private static partial Regex QualifiedNamePattern();

    /// <summary>
    /// Matches a <c>namespace</c> declaration (file-scoped or block-scoped) so the file's
    /// own namespace identifier is not counted as package usage by <see cref="QualifiedNamePattern"/>.
    /// </summary>
    [GeneratedRegex(
        @"\bnamespace\s+[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*",
        RegexOptions.None,
        RegexTimeoutMs)]
    private static partial Regex NamespaceDeclarationPattern();

    /// <summary>
    /// Disk-based entry point. Reads <c>*.csproj</c> and <c>Directory.Packages.props</c>
    /// files under <paramref name="scanDirectory"/> to obtain direct package ids, then
    /// checks each against namespace usages found in <c>.cs</c> files (excluding
    /// <c>bin/</c> and <c>obj/</c>). Packages in <paramref name="ignoredPackages"/> are
    /// never reported. Returns an empty list when no <c>.csproj</c> is found or when any
    /// internal error occurs — this check must never disrupt the vulnerability audit.
    /// </summary>
    public static IReadOnlyList<UnusedPackageFinding> Check(
        string scanDirectory,
        IReadOnlyList<string> ignoredPackages)
    {
        try
        {
            var directPackageIds = ReadDirectPackageIds(scanDirectory);
            if (directPackageIds.Count == 0)
            {
                return [];
            }

            var namespaceUsages = CollectNamespaceUsages(scanDirectory);
            return Check(directPackageIds, namespaceUsages, ignoredPackages);
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Pure, testable core — operates on already-extracted data, no disk access.
    /// </summary>
    /// <param name="directPackageIds">
    /// Direct (non-transitive) package ids from project files in the scan root.
    /// </param>
    /// <param name="namespaceUsages">
    /// Namespace strings found in .cs source files (from <c>using</c> directives and
    /// qualified type references).
    /// </param>
    /// <param name="ignoredPackages">
    /// Package ids that should never be reported, from <c>ignoreUnusedPackages</c> in
    /// <c>.dependably-check</c>.
    /// </param>
    public static IReadOnlyList<UnusedPackageFinding> Check(
        IReadOnlyList<string> directPackageIds,
        IReadOnlySet<string> namespaceUsages,
        IReadOnlyList<string> ignoredPackages)
    {
        var ignored = new HashSet<string>(ignoredPackages, StringComparer.OrdinalIgnoreCase);
        var findings = new List<UnusedPackageFinding>();

        foreach (var id in directPackageIds)
        {
            if (ignored.Contains(id))
            {
                continue;
            }

            if (!IsUsed(id, namespaceUsages))
            {
                findings.Add(new UnusedPackageFinding(
                    id,
                    $"Package '{id}' does not appear to be referenced in any .cs source file (heuristic). "
                    + "Build-tool, analyzer, and MSBuild-task packages are common false positives; "
                    + "suppress via ignoreUnusedPackages in .dependably-check."));
            }
        }

        return findings;
    }

    /// <summary>
    /// Returns true when any namespace usage string matches <paramref name="packageId"/>
    /// exactly or starts with <c>packageId.</c> (i.e. a sub-namespace), case-insensitive.
    /// </summary>
    private static bool IsUsed(string packageId, IReadOnlySet<string> namespaceUsages)
    {
        var prefix = packageId + ".";
        foreach (var ns in namespaceUsages)
        {
            if (ns.Equals(packageId, StringComparison.OrdinalIgnoreCase)
                || ns.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<string> ReadDirectPackageIds(string scanDirectory)
    {
        var files = Directory
            .EnumerateFiles(scanDirectory, "*.csproj", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(
                scanDirectory, "Directory.Packages.props", SearchOption.AllDirectories))
            .ToList();

        // Pre-collect IDs that carry dev-only markers on any <PackageReference> so that
        // a central <PackageVersion> entry for the same id can be suppressed (#24).
        var devOnlyIds = CollectDevOnlyPackageReferenceIds(files);

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            try
            {
                foreach (var id in ParsePackageReferences(file, devOnlyIds))
                {
                    ids.Add(id);
                }
            }
            catch
            {
                // A malformed project file skips silently.
            }
        }

        return [.. ids];
    }

    /// <summary>
    /// Returns the set of package ids for which at least one <c>&lt;PackageReference&gt;</c>
    /// element anywhere in <paramref name="files"/> carries dev-only asset metadata
    /// (see <see cref="IsDevBuildOnlyReference"/>). Used to propagate suppression from a
    /// <c>&lt;PackageReference&gt;</c> in a <c>.csproj</c> to the matching
    /// <c>&lt;PackageVersion&gt;</c> entry in <c>Directory.Packages.props</c>.
    /// </summary>
    private static HashSet<string> CollectDevOnlyPackageReferenceIds(IReadOnlyList<string> files)
    {
        var devOnly = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            try
            {
                AddDevOnlyIdsFromDoc(XDocument.Load(file), devOnly);
            }
            catch
            {
                // Malformed file — skip silently.
            }
        }

        return devOnly;
    }

    private static void AddDevOnlyIdsFromDoc(XDocument doc, HashSet<string> devOnly)
    {
        foreach (var element in doc.Descendants())
        {
            if (!element.Name.LocalName.Equals("PackageReference", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!IsDevBuildOnlyReference(element))
            {
                continue;
            }

            var include = element.Attribute("Include")?.Value
                ?? element.Attribute("Update")?.Value;
            if (!string.IsNullOrWhiteSpace(include))
            {
                devOnly.Add(include);
            }
        }
    }

    private static IEnumerable<string> ParsePackageReferences(
        string filePath, HashSet<string>? devOnlyIds = null)
    {
        XDocument doc;
        try
        {
            doc = XDocument.Load(filePath);
        }
        catch
        {
            yield break;
        }

        // Central Package Management uses <PackageVersion> in Directory.Packages.props
        // instead of <PackageReference>. Recognise both so that orphaned central-version
        // declarations are visible to the unused-package scan.
        var isCpmProps = Path.GetFileName(filePath)
            .Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase);

        foreach (var element in doc.Descendants().Where(e => IsPackageElement(e, isCpmProps)))
        {
            // <PackageReference Include="Foo.Bar" Version="..." /> or
            // <PackageVersion Include="Foo.Bar" Version="..." /> (CPM)
            var include = element.Attribute("Include")?.Value
                ?? element.Attribute("Update")?.Value;
            if (string.IsNullOrWhiteSpace(include))
            {
                continue;
            }

            // Skip dev/build/analyzer-only references — these are EXPECTED to have no
            // runtime namespace, so flagging them as "unused" is a false positive.
            if (IsDevBuildOnlyReference(element) || IsKnownBuildOrAnalyzerId(include))
            {
                continue;
            }

            // CPM: if any <PackageReference> in the project tree carries dev-only metadata
            // for this id, the central <PackageVersion> entry must also be suppressed (#24).
            if (isCpmProps
                && element.Name.LocalName.Equals("PackageVersion", StringComparison.OrdinalIgnoreCase)
                && devOnlyIds?.Contains(include) == true)
            {
                continue;
            }

            yield return include;
        }
    }

    /// <summary>
    /// Returns true for elements that represent a direct package reference: always
    /// <c>PackageReference</c>, and additionally <c>PackageVersion</c> when parsing
    /// a <c>Directory.Packages.props</c> file (Central Package Management).
    /// </summary>
    private static bool IsPackageElement(XElement element, bool includeCpmPackageVersion)
    {
        var name = element.Name.LocalName;
        if (name.Equals("PackageReference", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return includeCpmPackageVersion
            && name.Equals("PackageVersion", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns true when a <c>&lt;PackageReference&gt;</c> declares — via MSBuild asset
    /// metadata — that it does not contribute runtime/compile assets, i.e. it is a
    /// dev/build/analyzer-only dependency that does not flow to consumers. Such packages
    /// legitimately surface no <c>using</c> namespace and must not be flagged as unused.
    /// Recognised markers (attribute or child element form):
    /// <list type="bullet">
    ///   <item><c>PrivateAssets="all"</c> — the explicit "does not flow to consumers" flag;</item>
    ///   <item><c>ExcludeAssets</c> excluding <c>compile</c> (or <c>all</c>); and</item>
    ///   <item><c>IncludeAssets</c> limited to build/analyzer assets (<c>analyzers</c>/<c>build</c>/…)
    ///     with neither <c>runtime</c> nor <c>compile</c> (the namespace-bearing assets) included.</item>
    /// </list>
    /// </summary>
    private static bool IsDevBuildOnlyReference(XElement element)
    {
        var privateAssets = ReadAssetMetadata(element, "PrivateAssets");
        if (privateAssets.Contains("all"))
        {
            return true;
        }

        // ExcludeAssets="compile" (or "all") removes the compile-time reference assembly,
        // which is the only thing that makes a package's namespaces available to source.
        // Excluding only "runtime" still leaves compile-time types fully accessible —
        // the package can still be referenced with `using` directives and must remain in
        // scope for the unused-package scan.
        var excludeAssets = ReadAssetMetadata(element, "ExcludeAssets");
        if (excludeAssets.Contains("all")
            || excludeAssets.Contains("compile"))
        {
            return true;
        }

        // IncludeAssets restricted to build/analyzer assets, with the namespace-bearing
        // runtime/compile assets NOT included (e.g. "analyzers; build; buildtransitive").
        var includeAssets = ReadAssetMetadata(element, "IncludeAssets");
        if (includeAssets.Count > 0
            && !includeAssets.Contains("all")
            && !includeAssets.Contains("runtime")
            && !includeAssets.Contains("compile")
            && (includeAssets.Contains("analyzers")
                || includeAssets.Contains("build")
                || includeAssets.Contains("buildtransitive")
                || includeAssets.Contains("buildmultitargeting")))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Reads an MSBuild asset list (<c>PrivateAssets</c>/<c>IncludeAssets</c>/<c>ExcludeAssets</c>)
    /// from either an attribute or a child element, returning the semicolon-separated tokens
    /// lower-cased for case-insensitive comparison.
    /// </summary>
    private static HashSet<string> ReadAssetMetadata(XElement element, string name)
    {
        var raw = element.Attribute(name)?.Value
            ?? element.Elements()
                .FirstOrDefault(e => e.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))
                ?.Value;

        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return tokens;
        }

        foreach (var token in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            tokens.Add(token);
        }

        return tokens;
    }

    /// <summary>
    /// Suffixes and exact ids of common build/analyzer/source-generator packages that have
    /// no runtime namespace and are therefore expected to produce no <c>using</c> usage,
    /// even when authors add them WITHOUT <c>PrivateAssets</c> metadata. Matched
    /// case-insensitively by id or suffix. Kept deliberately small; further packages remain
    /// suppressible via <c>ignoreUnusedPackages</c> in <c>.dependably-check</c>.
    /// </summary>
    private static readonly string[] KnownBuildOrAnalyzerSuffixes =
    [
        ".Analyzers",
        ".SourceGenerators",
    ];

    private static readonly HashSet<string> KnownBuildOrAnalyzerIds =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "StyleCop.Analyzers",
            "Microsoft.CodeAnalysis.Analyzers",
            "Microsoft.CodeAnalysis.NetAnalyzers",
            "Microsoft.NET.Test.Sdk",
            "coverlet.collector",
            "coverlet.msbuild",
            "Nullable",
            "PolySharp",
            "GitVersion.MsBuild",
        };

    /// <summary>
    /// Returns true for ids in the built-in build/analyzer allowlist (see
    /// <see cref="KnownBuildOrAnalyzerIds"/> / <see cref="KnownBuildOrAnalyzerSuffixes"/>),
    /// e.g. <c>StyleCop.Analyzers</c>, ids ending in <c>.Analyzers</c>/<c>.SourceGenerators</c>,
    /// or any <c>Microsoft.SourceLink.*</c> provider.
    /// </summary>
    private static bool IsKnownBuildOrAnalyzerId(string id)
    {
        if (KnownBuildOrAnalyzerIds.Contains(id))
        {
            return true;
        }

        // Microsoft.SourceLink.* (GitHub, GitLab, Bitbucket, AzureRepos, …) — build-only.
        if (id.StartsWith("Microsoft.SourceLink.", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return KnownBuildOrAnalyzerSuffixes.Any(suffix => id.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
    }

    private static HashSet<string> CollectNamespaceUsages(string scanDirectory)
    {
        var usages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var csFiles = Directory
            .EnumerateFiles(scanDirectory, "*.cs", SearchOption.AllDirectories)
            .Where(f => !IsExcludedPath(f));

        foreach (var file in csFiles)
        {
            try
            {
                AddUsagesFromContent(File.ReadAllText(file), usages);
            }
            catch
            {
                // A file that cannot be read is skipped silently.
            }
        }

        return usages;
    }

    /// <summary>
    /// Extracts namespace usages from one file's text into <paramref name="usages"/>:
    /// explicit <c>using</c> directives (primary) plus qualified type references (secondary).
    /// The secondary scan runs on a comment- and literal-stripped copy of the content so that
    /// package ids mentioned only in comments, string values, or the file's own
    /// <c>namespace</c> declaration are not counted as usage.
    /// </summary>
    private static void AddUsagesFromContent(string content, HashSet<string> usages)
    {
        // Primary: explicit `using` directives on raw content — most reliable indicator.
        foreach (Match m in UsingDirectivePattern().Matches(content))
        {
            var ns = m.Groups[1].Value;
            if (!string.IsNullOrWhiteSpace(ns))
            {
                usages.Add(ns);
            }
        }

        // Secondary: qualified type references — strip comments, string/char literals, and
        // namespace declarations first so non-code mentions do not count as usage.
        var codeOnly = NamespaceDeclarationPattern().Replace(
            StripCommentsAndLiterals(content), " ");
        foreach (Match m in QualifiedNamePattern().Matches(codeOnly))
        {
            usages.Add(m.Groups[1].Value);
        }
    }

    /// <summary>
    /// Returns a copy of <paramref name="content"/> with <c>//</c> line comments,
    /// <c>/* */</c> block comments, double-quoted string literals, verbatim (<c>@"</c>)
    /// string literals, raw string literals (<c>"""..."""</c>), and single-quoted character
    /// literals replaced by empty space, so that dotted identifiers that appear only in those
    /// contexts are invisible to <see cref="QualifiedNamePattern"/>.
    /// Interpolated strings (<c>$"..."</c>, <c>$@"..."</c>, <c>@$"..."</c>) are handled
    /// specially: the literal text portions are stripped but code inside interpolation holes
    /// <c>{...}</c> is preserved so that qualified type references there count as usage.
    /// </summary>
    private static string StripCommentsAndLiterals(string content)
    {
        var sb = new System.Text.StringBuilder(content.Length);
        var i = 0;
        while (i < content.Length)
        {
            var next = i + 1 < content.Length ? content[i + 1] : '\0';
            if (content[i] == '/' && next == '/')
            {
                i = SkipLineComment(content, i);
            }
            else if (content[i] == '/' && next == '*')
            {
                i = SkipBlockComment(content, i);
            }
            else if (content[i] == '$' && next == '$')
            {
                // $$"...", $$"""...""", $$$"""...""", etc. — multi-dollar interpolated string.
                // Full n-dollar/n-brace hole parsing is complex; fail-safe by emitting the
                // entire literal content as code so any qualified name in a hole counts as used.
                i = EmitMultiDollarInterpolatedLiteral(content, i, sb);
            }
            else if (content[i] == '$' && next == '"' && i + 2 < content.Length && content[i + 2] == '"' && i + 3 < content.Length && content[i + 3] == '"')
            {
                // $"""...""" — interpolated raw string (≥ 3 quotes required); preserve hole code.
                i = SkipInterpolatedRawString(content, i + 1, sb);
            }
            else if (content[i] == '$' && next == '@' && i + 2 < content.Length && content[i + 2] == '"')
            {
                // $@"..." — verbatim interpolated string; preserve code in {holes}.
                i = SkipInterpolatedString(content, i + 3, sb, verbatim: true);
            }
            else if (content[i] == '$' && next == '"')
            {
                // $"..." — regular interpolated string; preserve code in {holes}.
                i = SkipInterpolatedString(content, i + 2, sb, verbatim: false);
            }
            else if (content[i] == '@' && next == '$' && i + 2 < content.Length && content[i + 2] == '"')
            {
                // @$"..." — verbatim interpolated string (@ first); preserve code in {holes}.
                i = SkipInterpolatedString(content, i + 3, sb, verbatim: true);
            }
            else if (content[i] == '@' && next == '"')
            {
                i = SkipVerbatimString(content, i);
            }
            else if (content[i] == '"' && next == '"' && i + 2 < content.Length && content[i + 2] == '"')
            {
                // """...""" — raw string literal (C# 11).
                i = SkipRawStringLiteral(content, i);
            }
            else if (content[i] == '"')
            {
                i = SkipRegularString(content, i);
            }
            else if (content[i] == '\'')
            {
                i = SkipCharLiteral(content, i);
            }
            else
            {
                sb.Append(content[i]);
                i++;
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Skips an interpolated string literal, emitting the content of each interpolation
    /// hole <c>{...}</c> into <paramref name="sb"/> so that qualified type references
    /// inside holes remain visible to <see cref="QualifiedNamePattern"/>.
    /// The literal (non-hole) text portions are not emitted.
    /// </summary>
    /// <param name="content">Full file content.</param>
    /// <param name="afterOpenQuote">Position immediately after the opening <c>"</c>.</param>
    /// <param name="sb">Builder receiving processed output.</param>
    /// <param name="verbatim">
    /// <see langword="true"/> for <c>$@"..."</c>/<c>@$"..."</c> (no backslash escapes;
    /// <c>""</c> is the quote escape); <see langword="false"/> for <c>$"..."</c>.
    /// </param>
    private static int SkipInterpolatedString(
        string content, int afterOpenQuote, System.Text.StringBuilder sb, bool verbatim)
    {
        var i = afterOpenQuote;
        var holeDepth = 0;
        while (i < content.Length)
        {
            var c = content[i];
            if (c == '"' && holeDepth == 0)
            {
                if (verbatim && i + 1 < content.Length && content[i + 1] == '"')
                {
                    i += 2; // "" is an escaped quote in verbatim — skip, keep scanning
                    continue;
                }

                return i + 1; // closing quote
            }

            i = AdvanceInterpolated(content, i, c, sb, verbatim, ref holeDepth);
        }

        return i;
    }

    /// <summary>
    /// Advances one character inside an interpolated string, handling brace-depth tracking
    /// and emitting hole content. Extracted from <see cref="SkipInterpolatedString"/> to
    /// keep the containing method's cognitive complexity below the gate threshold.
    /// </summary>
    private static int AdvanceInterpolated(
        string content, int i, char c,
        System.Text.StringBuilder sb, bool verbatim, ref int holeDepth)
    {
        if (c == '{')
        {
            return AdvanceInterpolatedOpenBrace(content, i, ref holeDepth);
        }

        if (c == '}')
        {
            return AdvanceInterpolatedCloseBrace(content, i, ref holeDepth);
        }

        if (holeDepth > 0)
        {
            return EmitInterpolatedHoleChar(content, i, c, sb);
        }

        // Literal text portion — skip. For non-verbatim strings handle backslash escapes.
        if (!verbatim && c == '\\' && i + 1 < content.Length)
        {
            return i + 2;
        }

        return i + 1;
    }

    private static int AdvanceInterpolatedOpenBrace(string content, int i, ref int holeDepth)
    {
        // {{ is a literal-brace escape only in the string's literal-text portion
        // (holeDepth == 0); inside a hole (holeDepth > 0) consecutive braces are
        // real code (e.g. a 2D array initialiser) and must each adjust depth.
        if (holeDepth == 0 && i + 1 < content.Length && content[i + 1] == '{')
        {
            return i + 2; // {{ literal-brace escape in string portion — skip
        }

        holeDepth++;
        return i + 1;
    }

    private static int AdvanceInterpolatedCloseBrace(string content, int i, ref int holeDepth)
    {
        if (holeDepth > 0)
        {
            holeDepth--;
            return i + 1;
        }

        // }} is a literal brace in the string literal portion — skip.
        return i + (i + 1 < content.Length && content[i + 1] == '}' ? 2 : 1);
    }

    /// <summary>
    /// Emits a character while inside an interpolation hole, or skips/recurses into a
    /// nested string literal or comment to maintain correct brace-depth accounting and
    /// preserve code inside nested interpolated-string holes.
    /// </summary>
    private static int EmitInterpolatedHoleChar(string content, int i, char c, System.Text.StringBuilder sb)
    {
        // Comments must be skipped so that a brace or quote inside a comment does not
        // desync hole depth or trigger string-boundary detection.
        if (c == '/' && i + 1 < content.Length && content[i + 1] == '/')
        {
            return SkipLineComment(content, i);
        }

        if (c == '/' && i + 1 < content.Length && content[i + 1] == '*')
        {
            return SkipBlockComment(content, i);
        }

        if (c == '$')
        {
            // $"...", $@"...", $"""...""", $$"""...""" — recurse so nested hole code is preserved.
            return EmitNestedInterpolatedString(content, i, sb);
        }

        if (c == '@' && i + 1 < content.Length && content[i + 1] == '$' && i + 2 < content.Length && content[i + 2] == '"')
        {
            // @$"..." — verbatim interpolated string; preserve nested hole code.
            return SkipInterpolatedString(content, i + 3, sb, verbatim: true);
        }

        if (c == '"' && i + 1 < content.Length && content[i + 1] == '"' && i + 2 < content.Length && content[i + 2] == '"')
        {
            // """...""" — raw string literal inside hole; skip so its content does not
            // affect brace accounting. (Interpolated raw strings are dispatched via $/$$ above.)
            return SkipRawStringLiteral(content, i);
        }

        if (c == '"')
        {
            // Nested regular string — skip so its content does not affect brace accounting.
            return SkipRegularString(content, i);
        }

        if (c == '@' && i + 1 < content.Length && content[i + 1] == '"')
        {
            // Nested verbatim string — skip.
            return SkipVerbatimString(content, i);
        }

        if (c == '\'')
        {
            // Char literal — skip it so its content (e.g. '}' or '"') does not affect
            // brace depth or string-boundary detection inside the hole.
            return SkipCharLiteral(content, i);
        }

        sb.Append(c);
        return i + 1;
    }

    /// <summary>
    /// Handles a <c>$</c> encountered inside an interpolation hole, dispatching to the
    /// appropriate nested interpolated-string handler so the nested hole's code is preserved.
    /// If <c>$</c> does not introduce a nested interpolated string it is emitted as plain code.
    /// </summary>
    private static int EmitNestedInterpolatedString(string content, int i, System.Text.StringBuilder sb)
    {
        var next = i + 1 < content.Length ? content[i + 1] : '\0';

        if (next == '$')
        {
            // $$"...", $$"""...""", etc. — multi-dollar interpolated string; emit entire
            // literal content as code (fail-safe) so any qualified name in a hole is visible.
            return EmitMultiDollarInterpolatedLiteral(content, i, sb);
        }

        if (next == '@' && i + 2 < content.Length && content[i + 2] == '"')
        {
            // $@"..." — verbatim interpolated; preserve nested hole code.
            return SkipInterpolatedString(content, i + 3, sb, verbatim: true);
        }

        if (next == '"' && i + 2 < content.Length && content[i + 2] == '"' && i + 3 < content.Length && content[i + 3] == '"')
        {
            // $"""...""" — interpolated raw string; preserve nested hole code.
            return SkipInterpolatedRawString(content, i + 1, sb);
        }

        if (next == '"')
        {
            // $"..." — regular interpolated; preserve nested hole code.
            return SkipInterpolatedString(content, i + 2, sb, verbatim: false);
        }

        // Bare $, not introducing a nested interpolated string.
        sb.Append('$');
        return i + 1;
    }

    /// <summary>
    /// Skips an interpolated raw string literal (<c>$"""..."""</c> etc.), emitting the
    /// content of each interpolation hole <c>{...}</c> into <paramref name="sb"/> so
    /// qualified type references in holes remain visible to <see cref="QualifiedNamePattern"/>.
    /// Called with <paramref name="start"/> pointing to the first <c>"</c> of the delimiter.
    /// </summary>
    private static int SkipInterpolatedRawString(
        string content, int start, System.Text.StringBuilder sb)
    {
        var quoteCount = CountQuoteRun(content, start);
        var i = start + quoteCount;
        var holeDepth = 0;

        while (i < content.Length)
        {
            var c = content[i];
            if (c == '{')
            {
                i = AdvanceInterpolatedOpenBrace(content, i, ref holeDepth);
            }
            else if (c == '}')
            {
                i = AdvanceInterpolatedCloseBrace(content, i, ref holeDepth);
            }
            else if (holeDepth > 0)
            {
                i = EmitInterpolatedHoleChar(content, i, c, sb);
            }
            else if (c == '"')
            {
                // In literal portion — advance past the quote run; return if it closes the string.
                var runLen = CountQuoteRun(content, i);
                i += runLen;
                if (runLen >= quoteCount)
                {
                    return i;
                }
            }
            else
            {
                i++;
            }
        }

        return i;
    }

    /// <summary>
    /// Returns the number of consecutive <c>"</c> characters starting at <paramref name="start"/>.
    /// </summary>
    private static int CountQuoteRun(string content, int start)
    {
        var count = 0;
        while (start + count < content.Length && content[start + count] == '"')
        {
            count++;
        }

        return count;
    }

    /// <summary>
    /// Returns the number of consecutive <paramref name="ch"/> characters starting at
    /// <paramref name="start"/>.
    /// </summary>
    private static int CountCharRun(string content, int start, char ch)
    {
        var count = 0;
        while (start + count < content.Length && content[start + count] == ch)
        {
            count++;
        }

        return count;
    }

    /// <summary>
    /// Skips a raw string literal (<c>"""..."""</c>, <c>""""...""""</c>, etc.) introduced
    /// in C# 11. The opening delimiter is 3 or more consecutive <c>"</c> characters; the
    /// closing delimiter must have at least as many. Returns the position immediately after
    /// the closing delimiter so that code on the same line is not consumed.
    /// </summary>
    private static int SkipRawStringLiteral(string content, int start)
    {
        // Count the opening delimiter length (≥ 3 quotes).
        var i = start;
        var quoteCount = 0;
        while (i < content.Length && content[i] == '"')
        {
            quoteCount++;
            i++;
        }

        // Scan for a run of closing quotes that is at least as long as the opening run.
        while (i < content.Length)
        {
            if (content[i] != '"')
            {
                i++;
                continue;
            }

            var closing = 0;
            while (i < content.Length && content[i] == '"')
            {
                closing++;
                i++;
            }

            if (closing >= quoteCount)
            {
                return i;
            }
        }

        return i;
    }

    private static int SkipLineComment(string content, int i)
    {
        while (i < content.Length && content[i] != '\n')
        {
            i++;
        }

        return i;
    }

    private static int SkipBlockComment(string content, int i)
    {
        i += 2; // skip /*
        while (i + 1 < content.Length && !(content[i] == '*' && content[i + 1] == '/'))
        {
            i++;
        }

        return Math.Min(i + 2, content.Length); // skip */
    }

    private static int SkipVerbatimString(string content, int i)
    {
        i += 2; // skip @"
        while (i < content.Length)
        {
            if (content[i] == '"')
            {
                i++;
                // "" inside a verbatim string is an escaped quote — keep scanning.
                if (i < content.Length && content[i] == '"')
                {
                    i++;
                }
                else
                {
                    break; // closing "
                }
            }
            else
            {
                i++;
            }
        }

        return i;
    }

    private static int SkipRegularString(string content, int i)
    {
        i++; // skip opening "
        while (i < content.Length && content[i] != '"' && content[i] != '\n')
        {
            if (content[i] == '\\')
            {
                i++; // skip escaped character
            }

            i++;
        }

        if (i < content.Length && content[i] == '"')
        {
            i++;
        }

        return i;
    }

    private static int SkipCharLiteral(string content, int i)
    {
        i++; // skip opening '
        while (i < content.Length && content[i] != '\'' && content[i] != '\n')
        {
            if (content[i] == '\\')
            {
                i++; // skip escaped character
            }

            i++;
        }

        if (i < content.Length && content[i] == '\'')
        {
            i++;
        }

        return i;
    }

    /// <summary>
    /// Handles a multi-dollar interpolated string (<c>$$"..."</c>, <c>$$"""..."""</c>,
    /// <c>$$$"""..."""</c>, etc.) starting at <paramref name="start"/> (the first <c>$</c>).
    /// For raw (triple-quoted) forms, hole tracking is delegated to
    /// <see cref="EmitRawMultiDollarContent"/> which is hole-aware and only closes the literal
    /// at brace depth 0. For single-quoted forms the entire content is emitted as code
    /// (fail-safe: over-preserving is harmless, over-stripping is the bug).
    /// </summary>
    private static int EmitMultiDollarInterpolatedLiteral(
        string content, int start, System.Text.StringBuilder sb)
    {
        var i = start;
        while (i < content.Length && content[i] == '$')
        {
            i++;
        }

        var dollarCount = i - start;
        var verbatim = i < content.Length && content[i] == '@';
        if (verbatim)
        {
            i++;
        }

        if (i >= content.Length || content[i] != '"')
        {
            // Not followed by a string opener — emit the consumed chars as code and return.
            for (var j = start; j < i; j++)
            {
                sb.Append(content[j]);
            }

            return i;
        }

        var quoteCount = CountQuoteRun(content, i);
        i += quoteCount;

        if (quoteCount >= 3)
        {
            return EmitRawMultiDollarContent(content, i, quoteCount, dollarCount, sb);
        }

        if (quoteCount == 1)
        {
            return EmitSingleQuoteMultiDollarContent(content, i, verbatim, sb);
        }

        // quoteCount == 2: not a valid C# string — advance past the quotes and return.
        return i;
    }

    /// <summary>
    /// Emits the body of a multi-dollar raw string literal (<c>$$"""..."""</c> etc.)
    /// into <paramref name="sb"/>, tracking interpolation hole depth so that a quote run
    /// inside a hole does not prematurely close the literal. Only a quote run of length
    /// &gt;= <paramref name="quoteCount"/> at hole depth 0 closes the literal.
    /// Called with <paramref name="i"/> pointing past the opening delimiter.
    /// When inside a hole (<c>holeDepth &gt; 0</c>) all content is dispatched through
    /// <see cref="EmitRawMultiDollarHoleChar"/> so that nested strings, comments, and
    /// char literals cannot desync the hole-depth counter or trigger a false close.
    /// Inside a hole, plain-code braces are tracked via a separate <c>codeDepth</c> counter
    /// (per Roslyn token balancing) so that initialiser brace-runs do not desync the hole.
    /// </summary>
    private static int EmitRawMultiDollarContent(
        string content, int i, int quoteCount, int dollarCount, System.Text.StringBuilder sb)
    {
        var holeDepth = 0;
        var codeDepth = 0; // tracks plain-code braces inside the current hole
        while (i < content.Length)
        {
            var c = content[i];
            if (holeDepth > 0)
            {
                // Inside a hole — dispatch through the nested-token-aware handler so that
                // braces/quotes inside nested strings or comments do not affect hole depth
                // or the closing-delimiter search.
                i = EmitRawMultiDollarHoleChar(content, i, c, sb, dollarCount, ref holeDepth, ref codeDepth);
            }
            else if (c == '"')
            {
                // Outside a hole — a long-enough quote run closes the literal.
                i = EmitRawMultiDollarQuoteRun(content, i, quoteCount, holeDepth, sb, out var closed);
                if (closed) return i;
            }
            else if (c == '{')
            {
                // A dollarCount-wide { run opens a hole; shorter runs are literal text.
                i = AdvanceRawMultiDollarBraceRun(content, i, '{', dollarCount, sb, ref holeDepth, +1);
                if (holeDepth > 0)
                {
                    codeDepth = 0; // reset code-brace depth on every hole entry
                }
            }
            else
            {
                // Literal text (including } at depth 0) — emit and advance.
                sb.Append(c);
                i++;
            }
        }

        return i;
    }

    /// <summary>
    /// Emits a character while inside a hole of a multi-dollar raw interpolated string,
    /// skipping or recursing into nested string literals, comments, and char literals so
    /// that their braces and quotes do not affect <paramref name="holeDepth"/> or trigger
    /// a false closing-delimiter match.
    /// Mirrors <see cref="EmitInterpolatedHoleChar"/> but uses per-token code-brace depth
    /// (<paramref name="codeDepth"/>) to separate plain-code braces from hole-close sequences,
    /// and only closes the hole when N consecutive <c>}</c> appear at code-brace depth 0.
    /// </summary>
    private static int EmitRawMultiDollarHoleChar(
        string content, int i, char c, System.Text.StringBuilder sb,
        int dollarCount, ref int holeDepth, ref int codeDepth)
    {
        // Skip comments so a brace or quote inside them does not desync hole depth.
        if (c == '/' && i + 1 < content.Length && content[i + 1] == '/')
        {
            return SkipLineComment(content, i);
        }

        if (c == '/' && i + 1 < content.Length && content[i + 1] == '*')
        {
            return SkipBlockComment(content, i);
        }

        // Nested interpolated strings — dispatch so nested hole code is preserved.
        if (c == '$')
        {
            return EmitNestedInterpolatedString(content, i, sb);
        }

        if (c == '@' && i + 1 < content.Length && content[i + 1] == '$'
            && i + 2 < content.Length && content[i + 2] == '"')
        {
            // @$"..." — verbatim interpolated string; preserve nested hole code.
            return SkipInterpolatedString(content, i + 3, sb, verbatim: true);
        }

        // Skip nested raw string literals so their quotes/braces don't affect depth.
        if (c == '"' && i + 1 < content.Length && content[i + 1] == '"'
            && i + 2 < content.Length && content[i + 2] == '"')
        {
            return SkipRawStringLiteral(content, i);
        }

        // Skip nested verbatim string.
        if (c == '@' && i + 1 < content.Length && content[i + 1] == '"')
        {
            return SkipVerbatimString(content, i);
        }

        // Skip nested regular string so its braces don't affect depth.
        if (c == '"')
        {
            return SkipRegularString(content, i);
        }

        // Skip char literal so a '}' or '"' inside it does not affect depth.
        if (c == '\'')
        {
            return SkipCharLiteral(content, i);
        }

        // Plain code braces — per Roslyn token balancing, each { increments codeDepth
        // and each } either decrements codeDepth (code block) or, when codeDepth is
        // already 0, counts toward the N-consecutive-} hole-close sequence.
        if (c == '{')
        {
            codeDepth++;
            sb.Append(c);
            return i + 1;
        }

        if (c == '}')
        {
            return AdvanceRawMultiDollarHoleCloseBrace(content, i, dollarCount, sb, ref holeDepth, ref codeDepth);
        }

        sb.Append(c);
        return i + 1;
    }

    /// <summary>
    /// Processes a run of <c>"</c> characters inside a multi-dollar raw string body.
    /// At hole depth 0, a run of length &gt;= <paramref name="quoteCount"/> closes the
    /// literal (<paramref name="closed"/> is set to <see langword="true"/>).
    /// At hole depth &gt; 0 the run is emitted as code — never terminates the outer literal.
    /// </summary>
    private static int EmitRawMultiDollarQuoteRun(
        string content, int i, int quoteCount, int holeDepth,
        System.Text.StringBuilder sb, out bool closed)
    {
        var runLen = CountQuoteRun(content, i);
        i += runLen;
        if (holeDepth == 0 && runLen >= quoteCount)
        {
            closed = true;
            return i;
        }

        // Inside a hole or short run — emit the quotes as code.
        closed = false;
        for (var j = 0; j < runLen; j++)
        {
            sb.Append('"');
        }

        return i;
    }

    /// <summary>
    /// Advances past a run of <paramref name="brace"/> characters in the <em>literal body</em>
    /// of a multi-dollar raw string (i.e. while <c>holeDepth == 0</c>), emitting all of them
    /// as code and setting <paramref name="holeDepth"/> to 1 when the run meets or exceeds
    /// <paramref name="dollarCount"/> (hole-open). Only called for <c>'{'</c> from the literal
    /// context in <see cref="EmitRawMultiDollarContent"/>; inside a hole, brace handling is
    /// performed by <see cref="EmitRawMultiDollarHoleChar"/> and
    /// <see cref="AdvanceRawMultiDollarHoleCloseBrace"/>.
    /// </summary>
    private static int AdvanceRawMultiDollarBraceRun(
        string content, int i, char brace, int dollarCount,
        System.Text.StringBuilder sb, ref int holeDepth, int depthDelta)
    {
        var runLen = CountCharRun(content, i, brace);
        for (var j = 0; j < runLen; j++)
        {
            sb.Append(brace);
        }

        i += runLen;
        if (runLen >= dollarCount)
        {
            holeDepth += depthDelta;
        }

        return i;
    }

    /// <summary>
    /// Processes a <c>}</c> encountered at plain-code level inside a multi-dollar raw
    /// interpolated string hole (called from <see cref="EmitRawMultiDollarHoleChar"/>).
    /// Uses per-token Roslyn-style code-brace balancing: when <paramref name="codeDepth"/>
    /// is positive the <c>}</c> closes a code block (decrement, emit, continue); when it is
    /// zero the <c>}</c> may be part of the N-consecutive-<c>}</c> hole-close sequence.
    /// Exactly <paramref name="dollarCount"/> consecutive <c>}</c> at code depth 0 closes the
    /// hole (<paramref name="holeDepth"/> is set to 0). A shorter run at code depth 0 is not a
    /// hole-close — the braces are emitted as code (fail-safe: preserve rather than strip).
    /// </summary>
    private static int AdvanceRawMultiDollarHoleCloseBrace(
        string content, int i, int dollarCount,
        System.Text.StringBuilder sb, ref int holeDepth, ref int codeDepth)
    {
        if (codeDepth > 0)
        {
            // This } closes a code block or initialiser — balance codeDepth, emit, continue.
            codeDepth--;
            sb.Append('}');
            return i + 1;
        }

        // codeDepth == 0: check for the N-consecutive-} hole-close sequence.
        var runLen = CountCharRun(content, i, '}');
        if (runLen >= dollarCount)
        {
            // Consume exactly dollarCount } to close the hole; leave any surplus for the
            // outer loop (they may be literal-body } after the hole closes).
            for (var j = 0; j < dollarCount; j++)
            {
                sb.Append('}');
            }

            holeDepth = 0;
            return i + dollarCount;
        }

        // Short run at code depth 0 — not a hole-close.
        // Fail-safe: emit all of them as code and keep scanning the hole.
        for (var j = 0; j < runLen; j++)
        {
            sb.Append('}');
        }

        return i + runLen;
    }

    /// <summary>
    /// Emits the body of a single-quoted multi-dollar string (<c>$$"..."</c>, <c>$$@"..."</c>)
    /// into <paramref name="sb"/> until the closing <c>"</c> is reached. Called with
    /// <paramref name="i"/> pointing past the opening <c>"</c>.
    /// </summary>
    private static int EmitSingleQuoteMultiDollarContent(
        string content, int i, bool verbatim, System.Text.StringBuilder sb)
    {
        while (i < content.Length)
        {
            var c = content[i];
            if (c == '"')
            {
                i++;
                if (verbatim && i < content.Length && content[i] == '"')
                {
                    sb.Append('"'); // "" is an escaped quote in verbatim
                    i++;
                    continue;
                }

                break; // closing "
            }

            if (!verbatim && c == '\\' && i + 1 < content.Length)
            {
                sb.Append(content[i + 1]); // emit the char after backslash
                i += 2;
                continue;
            }

            sb.Append(c);
            i++;
        }

        return i;
    }

    private static bool IsExcludedPath(string path)
    {
        return path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
            || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}");
    }
}
