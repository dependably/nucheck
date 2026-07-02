using System.Text.Json;

namespace Dependably.NuCheck.Config;

/// <summary>
/// The shared repo-root <c>.dependably-check</c> config, consumed across the
/// Dependably checker tools. Only the data relevant to the NuGet checker is
/// surfaced: the union of the <c>common.*</c> and <c>nuget.*</c>
/// <c>allowedRegistryHosts</c>, <c>ignoreUnusedPackages</c>, and
/// <c>allowedLocalFeeds</c> arrays. Other sections and unknown keys are ignored.
/// </summary>
public sealed class DependablyCheckConfig
{
    /// <summary>The config file name discovered by walking up the directory tree.</summary>
    public const string FileName = ".dependably-check";

    private DependablyCheckConfig(
        IReadOnlyList<string> allowedRegistryHosts,
        IReadOnlyList<string> ignoreUnusedPackages,
        IReadOnlyList<string> allowedLocalFeeds)
    {
        AllowedRegistryHosts = allowedRegistryHosts;
        IgnoreUnusedPackages = ignoreUnusedPackages;
        AllowedLocalFeeds = allowedLocalFeeds;
    }

    /// <summary>
    /// Bare hostnames that are trusted as NuGet package sources, in addition to the
    /// built-in public hosts. The union of the config's <c>common</c> and <c>nuget</c>
    /// <c>allowedRegistryHosts</c>, de-duplicated case-insensitively.
    /// </summary>
    public IReadOnlyList<string> AllowedRegistryHosts { get; }

    /// <summary>
    /// Package ids that should never be reported as unused, regardless of whether they
    /// appear in source. The union of the config's <c>common</c> and <c>nuget</c>
    /// <c>ignoreUnusedPackages</c>, de-duplicated case-insensitively. Useful for
    /// build-tool, analyzer, MSBuild-task, and <c>PrivateAssets</c> packages that
    /// have no runtime namespace.
    /// </summary>
    public IReadOnlyList<string> IgnoreUnusedPackages { get; }

    /// <summary>
    /// Local folder feeds (relative paths or <c>file://</c> URIs) that are explicitly
    /// trusted even though they are declared inside the repository tree. The union of the
    /// config's <c>common</c> and <c>nuget</c> <c>allowedLocalFeeds</c>, de-duplicated
    /// case-insensitively. An entry matches a source when it equals the source's path, or
    /// when it is a trailing path-segment suffix of it (e.g. <c>feeds</c> or <c>./feeds</c>
    /// matches a resolved <c>/repo/feeds</c>). Any enabled local feed NOT listed here is
    /// reported as a policy error, because a repo-committed local feed can smuggle tampered
    /// packages past a restore.
    /// </summary>
    public IReadOnlyList<string> AllowedLocalFeeds { get; }

    /// <summary>An empty config (no allowlisted hosts, no ignored packages, no local feeds), used when no file is found.</summary>
    public static DependablyCheckConfig Empty { get; } = new([], [], []);

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
            var seenHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            AppendStringArray(root, "common", "allowedRegistryHosts", hosts, seenHosts);
            AppendStringArray(root, "nuget", "allowedRegistryHosts", hosts, seenHosts);

            var ignored = new List<string>();
            var seenIgnored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            AppendStringArray(root, "common", "ignoreUnusedPackages", ignored, seenIgnored);
            AppendStringArray(root, "nuget", "ignoreUnusedPackages", ignored, seenIgnored);

            var localFeeds = new List<string>();
            var seenLocalFeeds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            AppendStringArray(root, "common", "allowedLocalFeeds", localFeeds, seenLocalFeeds);
            AppendStringArray(root, "nuget", "allowedLocalFeeds", localFeeds, seenLocalFeeds);

            return new DependablyCheckConfig(hosts, ignored, localFeeds);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Failed to parse {path}: {ex.Message}", ex);
        }
    }

    private static void AppendStringArray(
        JsonElement root,
        string section,
        string arrayKey,
        List<string> values,
        HashSet<string> seen)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty(section, out var sectionElement)
            || sectionElement.ValueKind != JsonValueKind.Object
            || !sectionElement.TryGetProperty(arrayKey, out var arrayElement)
            || arrayElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var element in arrayElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var value = element.GetString();
            if (!string.IsNullOrWhiteSpace(value) && seen.Add(value))
            {
                values.Add(value);
            }
        }
    }
}
