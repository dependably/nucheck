using System.Text.RegularExpressions;
using System.Xml.Linq;
using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>
/// Heuristically detects NuGet packages that are declared as direct
/// <c>&lt;PackageReference&gt;</c> dependencies but whose namespace does not appear in
/// any <c>.cs</c> source file under the scan root. Findings are advisory only and never
/// cause the process to exit non-zero — build-tool, analyzer, and MSBuild-task packages
/// frequently trigger false positives.
/// </summary>
public static class UnusedPackageService
{
    /// <summary>
    /// Matches <c>using</c> (and <c>global using</c> / <c>using static</c>) directives.
    /// Capture group 1 is the namespace identifier.
    /// </summary>
    private static readonly Regex UsingDirectivePattern = new(
        @"^\s*(?:global\s+)?using\s+(?:static\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;",
        RegexOptions.Multiline | RegexOptions.Compiled);

    /// <summary>
    /// Matches multi-segment qualified identifiers (e.g. <c>Foo.Bar.Thing</c>) that may
    /// appear as qualified type references in code that does not use a <c>using</c> directive.
    /// </summary>
    private static readonly Regex QualifiedNamePattern = new(
        @"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\b",
        RegexOptions.Compiled);

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
            var include = element.Attribute("Include")?.Value;
            if (!string.IsNullOrWhiteSpace(include))
            {
                yield return include;
            }
        }
    }

    private static IReadOnlySet<string> CollectNamespaceUsages(string scanDirectory)
    {
        var usages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var csFiles = Directory
            .EnumerateFiles(scanDirectory, "*.cs", SearchOption.AllDirectories)
            .Where(f => !IsExcludedPath(f));

        foreach (var file in csFiles)
        {
            try
            {
                var content = File.ReadAllText(file);

                // Primary: explicit `using` directives are the most reliable indicator.
                foreach (Match m in UsingDirectivePattern.Matches(content))
                {
                    var ns = m.Groups[1].Value;
                    if (!string.IsNullOrWhiteSpace(ns))
                    {
                        usages.Add(ns);
                    }
                }

                // Secondary: qualified type references for packages used without a `using`.
                foreach (Match m in QualifiedNamePattern.Matches(content))
                {
                    usages.Add(m.Groups[1].Value);
                }
            }
            catch
            {
                // A file that cannot be read is skipped silently.
            }
        }

        return usages;
    }

    private static bool IsExcludedPath(string path)
    {
        return path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
            || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}");
    }
}
