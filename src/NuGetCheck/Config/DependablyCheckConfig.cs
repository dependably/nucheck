using System.Text.Json;

namespace NuGetCheck.Config;

/// <summary>
/// The shared repo-root <c>.dependably-check</c> config, consumed across the
/// Dependably checker tools. Only the data relevant to the NuGet checker is
/// surfaced: the union of <c>common.allowedRegistryHosts</c> and
/// <c>nuget.allowedRegistryHosts</c>. Other sections and unknown keys are ignored.
/// </summary>
public sealed class DependablyCheckConfig
{
    /// <summary>The config file name discovered by walking up the directory tree.</summary>
    public const string FileName = ".dependably-check";

    private DependablyCheckConfig(IReadOnlyList<string> allowedRegistryHosts)
    {
        AllowedRegistryHosts = allowedRegistryHosts;
    }

    /// <summary>
    /// Bare hostnames that are trusted as NuGet package sources, in addition to the
    /// built-in public hosts. The union of the config's <c>common</c> and <c>nuget</c>
    /// <c>allowedRegistryHosts</c>, de-duplicated case-insensitively.
    /// </summary>
    public IReadOnlyList<string> AllowedRegistryHosts { get; }

    /// <summary>An empty config (no allowlisted hosts), used when no file is found.</summary>
    public static DependablyCheckConfig Empty { get; } = new([]);

    /// <summary>
    /// Loads the config. When <paramref name="explicitPath"/> is given it is read
    /// directly; otherwise <c>.dependably-check</c> is discovered by walking up from
    /// <paramref name="startDirectory"/>. Returns <see cref="Empty"/> when no file is found.
    /// Throws when an existing file cannot be parsed (the path is included in the message).
    /// </summary>
    public static DependablyCheckConfig Load(string? explicitPath, string startDirectory)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            if (!File.Exists(explicitPath))
            {
                throw new FileNotFoundException($"Config file not found: {explicitPath}", explicitPath);
            }

            return Parse(explicitPath);
        }

        var discovered = Discover(startDirectory);
        return discovered is null ? Empty : Parse(discovered);
    }

    /// <summary>
    /// Walks up from <paramref name="startDirectory"/> looking for a <c>.dependably-check</c>
    /// file. The walk stops at the filesystem root, or at a directory containing a
    /// <c>.git</c> entry (the repo boundary) after checking that directory. Returns the
    /// file path, or null when none is found.
    /// </summary>
    public static string? Discover(string startDirectory)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(startDirectory));

        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, FileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            // Stop at the repository boundary once this directory has been checked.
            var gitPath = Path.Combine(directory.FullName, ".git");
            if (Directory.Exists(gitPath) || File.Exists(gitPath))
            {
                return null;
            }

            directory = directory.Parent;
        }

        return null;
    }

    private static DependablyCheckConfig Parse(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var document = JsonDocument.Parse(stream);
            var root = document.RootElement;

            var hosts = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            AppendHosts(root, "common", hosts, seen);
            AppendHosts(root, "nuget", hosts, seen);

            return new DependablyCheckConfig(hosts);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Failed to parse {path}: {ex.Message}", ex);
        }
    }

    private static void AppendHosts(JsonElement root, string section, List<string> hosts, HashSet<string> seen)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty(section, out var sectionElement)
            || sectionElement.ValueKind != JsonValueKind.Object
            || !sectionElement.TryGetProperty("allowedRegistryHosts", out var hostsElement)
            || hostsElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var element in hostsElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var host = element.GetString();
            if (!string.IsNullOrWhiteSpace(host) && seen.Add(host))
            {
                hosts.Add(host);
            }
        }
    }
}
