using System.Text.Json;
using System.Xml;
using NuGet.Packaging;
using NuGet.ProjectModel;
using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>
/// Reads installed packages from a NuGet manifest. Supports packages.config (XML)
/// and packages.lock.json (the NuGet lock file format), using the native NuGet
/// readers so versions parse exactly as NuGet itself parses them.
/// </summary>
/// <remarks>
/// This reader deliberately fails CLOSED: it only routes to a parser when it can
/// positively recognise the format (a <c>&lt;packages&gt;</c> XML root, or a JSON
/// document that actually looks like a lock file). Any other input — a
/// <c>.csproj</c>, a Central Package Management <c>Directory.Packages.props</c>, a
/// bare <c>&lt;PackageReference&gt;</c> project, or junk — raises an error rather
/// than silently reporting "0 packages / all secure", which would make the
/// vulnerability scanner fail open.
/// </remarks>
public static class PackageFileReader
{
    private const string UnsupportedSuffix =
        "Supported: packages.config, packages.lock.json. " +
        "(Central Package Management and bare <PackageReference> are not yet supported.)";

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
}
