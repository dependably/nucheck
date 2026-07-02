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
///     with the runtime/compile assets excluded; and</item>
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
    /// </summary>
    [GeneratedRegex(
        @"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\b",
        RegexOptions.None,
        RegexTimeoutMs)]
    private static partial Regex QualifiedNamePattern();

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
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var files = Directory
            .EnumerateFiles(scanDirectory, "*.csproj", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(
                scanDirectory, "Directory.Packages.props", SearchOption.AllDirectories));

        foreach (var file in files)
        {
            try
            {
                foreach (var id in ParsePackageReferences(file))
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

    private static IEnumerable<string> ParsePackageReferences(string filePath)
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

        foreach (var element in doc.Descendants()
            .Where(e => e.Name.LocalName.Equals("PackageReference", StringComparison.OrdinalIgnoreCase)))
        {
            // <PackageReference Include="Foo.Bar" Version="..." />
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

            yield return include;
        }
    }

    /// <summary>
    /// Returns true when a <c>&lt;PackageReference&gt;</c> declares — via MSBuild asset
    /// metadata — that it does not contribute runtime/compile assets, i.e. it is a
    /// dev/build/analyzer-only dependency that does not flow to consumers. Such packages
    /// legitimately surface no <c>using</c> namespace and must not be flagged as unused.
    /// Recognised markers (attribute or child element form):
    /// <list type="bullet">
    ///   <item><c>PrivateAssets="all"</c> — the explicit "does not flow to consumers" flag;</item>
    ///   <item><c>ExcludeAssets</c> excluding <c>runtime</c> (and/or <c>compile</c>); and</item>
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
    /// </summary>
    private static void AddUsagesFromContent(string content, HashSet<string> usages)
    {
        // Primary: explicit `using` directives are the most reliable indicator.
        foreach (Match m in UsingDirectivePattern().Matches(content))
        {
            var ns = m.Groups[1].Value;
            if (!string.IsNullOrWhiteSpace(ns))
            {
                usages.Add(ns);
            }
        }

        // Secondary: qualified type references for packages used without a `using`.
        foreach (Match m in QualifiedNamePattern().Matches(content))
        {
            usages.Add(m.Groups[1].Value);
        }
    }

    private static bool IsExcludedPath(string path)
    {
        return path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
            || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}");
    }
}
