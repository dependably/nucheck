using System.Xml.Linq;

namespace Dependably.NuCheck.Facts.Nuget;

/// <summary>
/// What a package's own .nuspec states about itself — present in the
/// global-packages cache next to the DLLs <see cref="NamespaceMap"/> already reads
/// from the same <c>packageFolders</c> (same <c>folder/id-lowercase/version</c>
/// layout convention). One load answers every question asked of the file; a
/// second reader would be a second parse of the same XML.
/// </summary>
/// <param name="License">
/// The SPDX expression, or null when the file states none in a usable form (see
/// <see cref="NuspecReader.Read"/>).
/// </param>
/// <param name="Producer">
/// <c>&lt;authors&gt;</c> / <c>&lt;owners&gt;</c> verbatim, each null when the
/// file states that element nowhere or states it empty. The object itself exists
/// only because a file was read — "the nuspec says no authors" and "there was no
/// nuspec" are different facts, and the document keeps them apart by omitting
/// this whole object in the second case.
/// </param>
public sealed record NuspecFacts(string? License, PackageProducerFacts Producer);

public static class NuspecReader
{
    /// <summary>
    /// Loads the package's .nuspec and reports what it states. Returns null when
    /// there is no readable file at all — an unrestored tree, a package folder
    /// that does not exist, or XML that would not parse — so a caller can tell
    /// "could not look" from "looked and the file says nothing".
    ///
    /// <para>Only the modern `&lt;license type="expression"&gt;` form is read for
    /// <see cref="NuspecFacts.License"/> — an SPDX expression string ("MIT",
    /// "(MIT OR Apache-2.0)"), usable as-is. An older nuspec with only
    /// `&lt;licenseUrl&gt;` (no expression) or `&lt;license type="file"&gt;` (a
    /// path into the package, not a string) leaves it null rather than guessed
    /// at — a URL or file reference isn't itself the license identifier.</para>
    ///
    /// <para><c>&lt;authors&gt;</c> and <c>&lt;owners&gt;</c> are comma-separated
    /// FREE TEXT, not identities: NuGet neither validates nor resolves them, so
    /// they are published exactly as written, never split on the comma, never
    /// deduped against each other, never attributed to a person or an
    /// organization. Surrounding whitespace is trimmed because it is XML
    /// pretty-printing rather than content, and an element that is empty after
    /// that is reported as absent — the file states no producer either way.</para>
    /// </summary>
    /// <param name="srcDir">The scanned tree, so a nuspec under it is reported relative to it.</param>
    /// <param name="unanalyzable">
    /// A nuspec that exists but cannot be parsed is reported here (kind
    /// <c>file</c>) as well as yielding null — "absent" then means "unreadable",
    /// not "the package states nothing".
    /// </param>
    public static NuspecFacts? Read(
        IReadOnlyList<string> packageFolders,
        string id,
        string version,
        string? srcDir = null,
        List<UnanalyzableEntry>? unanalyzable = null)
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
                return new NuspecFacts(
                    Text(license),
                    new PackageProducerFacts(Element(doc, "authors"), Element(doc, "owners")));
            }
            catch (Exception ex)
            {
                // Malformed/unreadable nuspec: absent, not guessed — and reported.
                var display = srcDir is null
                    ? Path.GetFullPath(nuspecPath).Replace('\\', '/')
                    : ProjectDiscovery.DisplayPath(srcDir, nuspecPath);
                unanalyzable?.Add(new UnanalyzableEntry(
                    display, UnanalyzableEntry.KindFile, $"unparseable nuspec: {UnanalyzableEntry.Describe(ex)}"));
                return null;
            }
        }
        return null;
    }

    /// The FIRST element with this local name. A nuspec states each metadata
    /// element once; taking the first rather than concatenating keeps the value
    /// something the file actually contains.
    private static string? Element(XDocument doc, string localName) =>
        Text(doc.Descendants().FirstOrDefault(e => e.Name.LocalName == localName));

    private static string? Text(XElement? element)
    {
        var text = element?.Value.Trim();
        return string.IsNullOrEmpty(text) ? null : text;
    }
}
