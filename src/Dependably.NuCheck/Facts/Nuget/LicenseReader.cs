using System.Xml.Linq;

namespace Dependably.NuCheck.Facts.Nuget;

/// <summary>
/// Reads a package's SPDX license expression straight from its own .nuspec —
/// present in the global-packages cache next to the DLLs <see cref="NamespaceMap"/>
/// already reads from the same <c>packageFolders</c> (same
/// <c>folder/id-lowercase/version</c> layout convention).
/// </summary>
public static class LicenseReader
{
    /// <summary>
    /// Only the modern `&lt;license type="expression"&gt;` form is read — an
    /// SPDX expression string ("MIT", "(MIT OR Apache-2.0)"), usable as-is.
    /// An older nuspec with only `&lt;licenseUrl&gt;` (no expression) or
    /// `&lt;license type="file"&gt;` (a path into the package, not a string)
    /// is left absent rather than guessed at — a URL or file reference isn't
    /// itself the license identifier.
    /// </summary>
    /// <param name="unanalyzable">
    /// A nuspec that exists but cannot be parsed is reported here (kind
    /// <c>file</c>) as well as yielding null — "absent" then means "unreadable",
    /// not "the package states no expression".
    /// </param>
    public static string? Read(List<string> packageFolders, string id, string version, List<UnanalyzableEntry>? unanalyzable = null)
    {
        var idLower = id.ToLowerInvariant();
        foreach (var folder in packageFolders)
        {
            var nuspecPath = Path.Combine(folder, idLower, version, $"{idLower}.nuspec");
            if (!File.Exists(nuspecPath)) continue;

            try
            {
                var doc = XDocument.Load(nuspecPath);
                // Nuspec XML is namespaced (schema version varies by nuget.org
                // era), so match on LocalName only — same posture as
                // ProjectDiscovery's csproj element matching.
                var license = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "license"
                        && e.Attribute("type")?.Value == "expression");
                var expression = license?.Value.Trim();
                return string.IsNullOrEmpty(expression) ? null : expression;
            }
            catch (Exception ex)
            {
                // Malformed/unreadable nuspec: absent, not guessed — and reported.
                unanalyzable?.Add(new UnanalyzableEntry(
                    nuspecPath.Replace('\\', '/'), UnanalyzableEntry.KindFile, $"unparseable nuspec: {ex.Message}"));
                return null;
            }
        }
        return null;
    }
}
