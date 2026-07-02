using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using NuGet.Packaging;
using NuGet.ProjectModel;
using NuGet.Versioning;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Reads installed packages from a NuGet manifest. Supports packages.config (XML),
/// packages.lock.json (the NuGet lock file format), and <c>&lt;Project&gt;</c>-rooted
/// MSBuild files — a <c>.csproj</c> or <c>.props</c> carrying
/// <c>&lt;PackageReference&gt;</c> / <c>&lt;PackageVersion&gt;</c> entries, including
/// Central Package Management (<c>Directory.Packages.props</c>). The exact NuGet
/// readers are used for packages.config / lock files so versions parse identically.
/// </summary>
/// <remarks>
/// This reader still fails CLOSED: it only routes to a parser when it can positively
/// recognise the format (a <c>&lt;packages&gt;</c> or <c>&lt;Project&gt;</c> XML root,
/// or a JSON document that actually looks like a lock file). Genuinely unrecognised
/// input — junk, or an XML root that is neither <c>packages</c> nor <c>Project</c> —
/// raises an error rather than silently reporting "0 packages / all secure", which
/// would make the vulnerability scanner fail open.
/// </remarks>
public static class PackageFileReader
{
    private const string UnsupportedSuffix =
        "Supported: packages.config, packages.lock.json, " +
        ".csproj / .props (PackageReference / PackageVersion).";

    public static IReadOnlyList<PackageRef> Read(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}", filePath);
        }

        // A .json input is only ever a lock file. If it does not parse as one, that
        // is an error — never a silent "0 packages".
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        if (extension == ".json")
        {
            return ReadLockFile(filePath);
        }

        // Everything else is recognised by content, not extension. packages.config is
        // identified by its <packages> XML root regardless of the file name.
        var root = TryGetXmlRootLocalName(filePath);
        if (string.Equals(root, "packages", StringComparison.OrdinalIgnoreCase))
        {
            return ReadPackagesConfig(filePath);
        }

        // A <Project> root is an MSBuild .csproj / .props: bare <PackageReference> or
        // Central Package Management (<PackageVersion> in a Directory.Packages.props).
        if (string.Equals(root, "Project", StringComparison.OrdinalIgnoreCase))
        {
            return ReadProjectFile(filePath);
        }

        throw new InvalidDataException(
            $"Unsupported manifest '{filePath}'. {UnsupportedSuffix}");
    }

    /// <summary>
    /// Returns the local name of the first XML element in the file, or <c>null</c>
    /// when the file is not XML (or cannot be read). Reads only as far as the root
    /// start tag, so a well-formed root with a malformed body still resolves.
    /// </summary>
    private static string? TryGetXmlRootLocalName(string path)
    {
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
            };
            using var stream = File.OpenRead(path);
            using var reader = XmlReader.Create(stream, settings);
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element)
                {
                    return reader.LocalName;
                }
            }
        }
        catch
        {
            // Not XML, or unreadable — treated as unrecognised by the caller.
        }

        return null;
    }

    private static List<PackageRef> ReadPackagesConfig(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            var reader = new PackagesConfigReader(stream);
            return reader.GetPackages()
                .Select(p => new PackageRef(p.PackageIdentity.Id, p.PackageIdentity.Version))
                .ToList();
        }
        catch (Exception ex)
        {
            throw new InvalidDataException($"Failed to parse packages.config: {ex.Message}", ex);
        }
    }

    private static List<PackageRef> ReadLockFile(string path)
    {
        // Guard against arbitrary JSON that parses but is not a lock file. A real
        // packages.lock.json always declares a numeric "version" and a "dependencies"
        // object; without them the NuGet reader would happily return zero packages
        // (a fail-open). Validate the shape ourselves before trusting it.
        if (!LooksLikeLockFile(path, out var reason))
        {
            throw new InvalidDataException(
                $"'{path}' is not a valid packages.lock.json ({reason}). {UnsupportedSuffix}");
        }

        PackagesLockFile lockFile;
        try
        {
            lockFile = PackagesLockFileFormat.Read(path);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException($"Failed to parse packages.lock.json: {ex.Message}", ex);
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var packages = new List<PackageRef>();

        foreach (var target in lockFile.Targets)
        {
            foreach (var dependency in target.Dependencies)
            {
                if (dependency.ResolvedVersion is null)
                {
                    continue;
                }

                if (seen.Add($"{dependency.Id}@{dependency.ResolvedVersion}"))
                {
                    packages.Add(new PackageRef(dependency.Id, dependency.ResolvedVersion));
                }
            }
        }

        return packages;
    }

    /// <summary>
    /// True when the JSON at <paramref name="path"/> has the defining top-level
    /// shape of a packages.lock.json: a numeric <c>version</c> and a
    /// <c>dependencies</c> object. Malformed JSON, arrays, and arbitrary objects
    /// fail this check so they surface as errors instead of an empty (secure) audit.
    /// </summary>
    private static bool LooksLikeLockFile(string path, out string reason)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var document = JsonDocument.Parse(stream);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                reason = "root is not a JSON object";
                return false;
            }

            if (!root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number)
            {
                reason = "missing numeric \"version\"";
                return false;
            }

            if (!root.TryGetProperty("dependencies", out var dependencies) || dependencies.ValueKind != JsonValueKind.Object)
            {
                reason = "missing \"dependencies\" object";
                return false;
            }
        }
        catch (JsonException ex)
        {
            reason = $"malformed JSON: {ex.Message}";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Reads packages from a <c>&lt;Project&gt;</c>-rooted MSBuild file — a
    /// <c>.csproj</c> or a <c>.props</c> (including a Central Package Management
    /// <c>Directory.Packages.props</c>) — via a lightweight <see cref="XDocument"/>
    /// parse with NO MSBuild evaluation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two shapes are handled. A <c>Directory.Packages.props</c> (a file whose
    /// <c>&lt;PackageVersion&gt;</c> set is non-empty and which carries no
    /// <c>&lt;PackageReference&gt;</c>) is audited directly as its set of
    /// centrally-managed versions. Any other project file is audited via its
    /// <c>&lt;PackageReference&gt;</c> entries, resolving each version from (in order)
    /// an explicit <c>Version</c> attribute / <c>&lt;Version&gt;</c> child /
    /// <c>VersionOverride</c> on the reference, then a <c>&lt;PackageVersion&gt;</c>
    /// declared in the same file, then a <c>Directory.Packages.props</c> found by
    /// walking UP the directory tree (Central Package Management).
    /// </para>
    /// <para>
    /// LIMITATIONS — this is a static parse, not a restore:
    /// <list type="bullet">
    /// <item>No MSBuild evaluation: MSBuild properties (<c>$(...)</c>),
    /// <c>Condition</c>s, <c>&lt;Import&gt;</c>s, and SDK-implicit packages are NOT
    /// expanded or resolved.</item>
    /// <item>Version ranges and floating versions (e.g. <c>[1.0,2.0)</c>, <c>6.*</c>)
    /// are audited at their declared LOWER BOUND — a conservative choice — NOT the
    /// version a <c>dotnet restore</c> would actually resolve. For exact resolved
    /// versions, point the tool at a <c>packages.lock.json</c>.</item>
    /// </list>
    /// </para>
    /// </remarks>
    private static List<PackageRef> ReadProjectFile(string path)
    {
        XDocument doc;
        try
        {
            doc = XDocument.Load(path);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException($"Failed to parse project file: {ex.Message}", ex);
        }

        // CPM version definitions declared in THIS file: id -> version string.
        var localVersions = GatherPackageVersions(doc);

        var packageReferences = doc.Descendants()
            .Where(e => e.Name.LocalName.Equals("PackageReference", StringComparison.OrdinalIgnoreCase))
            .Where(e => !string.IsNullOrWhiteSpace(GetIncludeId(e)))
            .ToList();

        // A Directory.Packages.props' whole purpose is to declare PackageVersions; with
        // no PackageReferences, audit those centrally-managed entries directly. Every
        // DISTINCT declared version is audited — duplicate (e.g. per-TFM) ids are not
        // collapsed to one version.
        if (localVersions.Count > 0 && packageReferences.Count == 0)
        {
            return BuildPackageRefs(localVersions);
        }

        // Otherwise resolve each PackageReference. Under Central Package Management the
        // version(s) live in a Directory.Packages.props up the tree, plus any file-local
        // <PackageVersion>. MSBuild Conditions are NOT evaluated here, so an id may carry
        // several DISTINCT central versions (e.g. one per TargetFramework); a version-less
        // reference must resolve to ALL of them so a vulnerable conditional pin is never
        // masked by a clean sibling.
        var centralVersions = ToVersionLookup(FindCentralPackageVersions(path).Concat(localVersions));

        var resolved = new List<(string Id, string Version)>();
        foreach (var element in packageReferences)
        {
            var id = GetIncludeId(element)!;
            var version = GetReferenceVersion(element);
            if (!string.IsNullOrWhiteSpace(version))
            {
                resolved.Add((id, version)); // Reference carries its own version.
            }
            else if (centralVersions.TryGetValue(id, out var centrals))
            {
                // Central Package Management: audit every distinct declared central version.
                resolved.AddRange(centrals.Select(central => (id, central)));
            }
        }

        return BuildPackageRefs(resolved);
    }

    /// <summary>The <c>Include</c> attribute (the package id), or null for a Remove/Update-only entry.</summary>
    private static string? GetIncludeId(XElement element) => element.Attribute("Include")?.Value;

    /// <summary>
    /// The declared version on a <c>&lt;PackageReference&gt;</c>: <c>Version</c>
    /// attribute, else a <c>&lt;Version&gt;</c> child element, else the
    /// <c>VersionOverride</c> attribute. Null when none is present (Central Package
    /// Management supplies the version elsewhere).
    /// </summary>
    private static string? GetReferenceVersion(XElement element)
    {
        var version = element.Attribute("Version")?.Value;
        if (string.IsNullOrWhiteSpace(version))
        {
            version = element.Elements()
                .FirstOrDefault(e => e.Name.LocalName.Equals("Version", StringComparison.OrdinalIgnoreCase))
                ?.Value;
        }

        if (string.IsNullOrWhiteSpace(version))
        {
            version = element.Attribute("VersionOverride")?.Value;
        }

        return version;
    }

    /// <summary>
    /// Collects every <c>&lt;PackageVersion Include="X" Version="Y" /&gt;</c> (the
    /// Central Package Management definitions) as (id, version) pairs. Duplicate ids —
    /// e.g. a version declared per <c>TargetFramework</c> via <c>Condition</c>s — are
    /// each preserved so no conditionally-declared version is silently dropped.
    /// </summary>
    private static List<(string Id, string Version)> GatherPackageVersions(XDocument doc)
    {
        var versions = new List<(string Id, string Version)>();
        foreach (var element in doc.Descendants()
            .Where(e => e.Name.LocalName.Equals("PackageVersion", StringComparison.OrdinalIgnoreCase)))
        {
            var id = element.Attribute("Include")?.Value;
            var version = element.Attribute("Version")?.Value
                ?? element.Elements()
                    .FirstOrDefault(e => e.Name.LocalName.Equals("Version", StringComparison.OrdinalIgnoreCase))
                    ?.Value;
            if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(version))
            {
                versions.Add((id, version));
            }
        }

        return versions;
    }

    /// <summary>
    /// Groups (id, version) pairs into an id -> DISTINCT versions lookup for resolving a
    /// <c>&lt;PackageReference&gt;</c> that omits its own version (Central Package
    /// Management). Because MSBuild <c>Condition</c>s are not evaluated, one id may be
    /// declared at several central versions (e.g. per <c>TargetFramework</c>); every
    /// distinct version is kept — matching <see cref="GatherPackageVersions"/> — so a
    /// version-less reference is audited against all of them and no conditional pin is
    /// dropped last-wins.
    /// </summary>
    private static Dictionary<string, List<string>> ToVersionLookup(IEnumerable<(string Id, string Version)> versions)
    {
        var lookup = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, version) in versions)
        {
            if (!lookup.TryGetValue(id, out var declared))
            {
                declared = [];
                lookup[id] = declared;
            }

            if (!declared.Contains(version, StringComparer.OrdinalIgnoreCase))
            {
                declared.Add(version);
            }
        }

        return lookup;
    }

    /// <summary>
    /// Walks UP the directory tree from <paramref name="projectFilePath"/> for the
    /// nearest <c>Directory.Packages.props</c>, returning ALL of its
    /// <c>&lt;PackageVersion&gt;</c> (id, version) pairs (empty when none is found).
    /// Duplicate ids are preserved — see <see cref="GatherPackageVersions"/> — so a
    /// version-less reference can be audited against every declared central version.
    /// MSBuild imports only the nearest by default, so the search stops at the first match.
    /// </summary>
    private static List<(string Id, string Version)> FindCentralPackageVersions(string projectFilePath)
    {
        var fullProjectPath = Path.GetFullPath(projectFilePath);
        var dir = Path.GetDirectoryName(fullProjectPath);
        while (!string.IsNullOrEmpty(dir))
        {
            var candidate = Path.Combine(dir, "Directory.Packages.props");
            if (File.Exists(candidate)
                && !string.Equals(Path.GetFullPath(candidate), fullProjectPath, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    return GatherPackageVersions(XDocument.Load(candidate));
                }
                catch (Exception ex)
                {
                    // MSBuild stops at the first Directory.Packages.props it finds; if that
                    // file is malformed, the build fails. Match that fail-closed behaviour:
                    // surface the error rather than silently falling back to a higher-level
                    // file whose versions would be wrong.
                    throw new InvalidDataException(
                        $"Failed to parse '{candidate}': {ex.Message}", ex);
                }
            }

            var parent = Path.GetDirectoryName(dir);
            if (string.Equals(parent, dir, StringComparison.Ordinal))
            {
                break;
            }

            dir = parent;
        }

        return [];
    }

    /// <summary>
    /// Converts resolved (id, version-string) pairs to <see cref="PackageRef"/>,
    /// skipping any whose version cannot be determined. De-duplication is keyed on
    /// (id, resolved version) — like the lock-file path — so every DISTINCT declared
    /// version of a package is audited (e.g. conditionally-declared per-TargetFramework
    /// versions of the same id). Entries that resolve to the SAME version are collapsed,
    /// preferring an exact version over a range whose lower bound matches it.
    /// </summary>
    private static List<PackageRef> BuildPackageRefs(IEnumerable<(string Id, string Version)> entries)
    {
        var byIdVersion = new Dictionary<string, (PackageRef Ref, bool Exact)>(StringComparer.OrdinalIgnoreCase);

        foreach (var (id, versionString) in entries)
        {
            if (!TryResolveVersion(versionString, out var version, out var exact))
            {
                continue; // No usable version — cannot audit, skip.
            }

            var key = $"{id}@{version.ToNormalizedString()}";
            if (!byIdVersion.TryGetValue(key, out var existing) || (exact && !existing.Exact))
            {
                byIdVersion[key] = (new PackageRef(id, version), exact);
            }
        }

        return byIdVersion.Values.Select(v => v.Ref).ToList();
    }

    /// <summary>
    /// Resolves a declared MSBuild version string to a concrete <see cref="NuGetVersion"/>.
    /// An exact version parses directly (<paramref name="exact"/> = true); a range or
    /// floating version (e.g. <c>[1.0,2.0)</c>, <c>6.*</c>) is audited at its declared
    /// lower bound (<see cref="VersionRange.MinVersion"/>). Returns false when neither
    /// yields a version.
    /// </summary>
    private static bool TryResolveVersion(string? versionString, out NuGetVersion version, out bool exact)
    {
        version = null!;
        exact = false;
        if (string.IsNullOrWhiteSpace(versionString))
        {
            return false;
        }

        if (NuGetVersion.TryParse(versionString, out var parsed))
        {
            version = parsed;
            exact = true;
            return true;
        }

        if (VersionRange.TryParse(versionString, out var range) && range.MinVersion is not null)
        {
            version = range.MinVersion;
            exact = false;
            return true;
        }

        return false;
    }
}
