using NuGet.Packaging;
using NuGet.ProjectModel;
using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>
/// Reads installed packages from a NuGet manifest. Supports packages.config (XML)
/// and packages.lock.json (the NuGet lock file format), using the native NuGet
/// readers so versions parse exactly as NuGet itself parses them.
/// </summary>
public static class PackageFileReader
{
    public static IReadOnlyList<PackageRef> Read(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}", filePath);
        }

        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        return extension == ".json" ? ReadLockFile(filePath) : ReadPackagesConfig(filePath);
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
}
