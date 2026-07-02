using NuGet.Configuration;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Audits the NuGet package sources <b>declared within the repository</b> (the
/// <c>nuget.config</c> files from the audited path up to and including the repo root)
/// and flags any enabled source that a restore would honour but the policy does not trust:
/// an http(s) source whose host is neither a built-in public host nor explicitly
/// allowlisted, and any local folder feed (relative path or <c>file://</c> URI) that is
/// not listed in <c>allowedLocalFeeds</c>. Local feeds are fail-closed on purpose: a
/// repo-committed folder feed can smuggle tampered <c>.nupkg</c> files past a restore.
/// Disabled sources are ignored.
/// <para>
/// The host machine's user/global NuGet configuration is intentionally OUT OF SCOPE:
/// the verdict must depend only on what the repo declares, so it is reproducible and
/// machine-independent (the same repo passes or fails identically on any machine and in
/// CI, and auditing a stranger's repo never flags the auditor's personal feeds).
/// </para>
/// </summary>
public static class SourceTrustService
{
    /// <summary>Hosts always trusted as public NuGet sources, regardless of config.</summary>
    public static readonly IReadOnlyList<string> PublicHosts = ["api.nuget.org", "nuget.org"];

    /// <summary>
    /// Returns one <see cref="SourceFinding"/> per enabled package source <b>declared inside
    /// the repository tree</b> (config from <paramref name="directory"/> up to and including
    /// the repo root) that the policy does not trust: an http(s) source whose host is not in
    /// the trusted set (public hosts ∪ <paramref name="allowedHosts"/>), or a local folder
    /// feed whose path is not in <paramref name="allowedLocalFeeds"/>. Sources contributed
    /// solely by the host machine's user/global NuGet config are not audited, so a repo that
    /// declares no <c>nuget.config</c> produces no findings (its implicit default is nuget.org).
    /// <para>
    /// When no repository boundary (<c>.git</c>) can be located, the manifest directory is
    /// treated as the boundary and configs in parent directories are excluded; an <c>info</c>
    /// finding is emitted in that case if any such parent config exists, because a restore
    /// from a non-git checkout would still honour those unaudited sources.
    /// </para>
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(
        string directory,
        IReadOnlyList<string> allowedHosts,
        IReadOnlyList<string>? allowedLocalFeeds = null)
    {
        var settings = Settings.LoadDefaultSettings(directory);
        var boundaryFound = TryFindRepoRoot(directory, out var repoRoot);

        // Origin config paths of the package sources actually declared inside the repo
        // tree. LoadDefaultSettings honours NuGet's <clear/> / enabled / disabled merge
        // semantics; we then keep only the items whose declaring file lives under the
        // repo root, discarding anything inherited from the user/global machine config.
        var packageSources = settings.GetSection("packageSources");
        var repoSourceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (packageSources is not null)
        {
            repoSourceNames.UnionWith(packageSources.Items.OfType<SourceItem>()
                .Where(item => IsUnderRoot(item.ConfigPath, repoRoot))
                .Select(item => item.Key));
        }

        var sources = new PackageSourceProvider(settings)
            .LoadPackageSources()
            .Where(source => repoSourceNames.Contains(source.Name));

        var findings = new List<SourceFinding>(Check(sources, allowedHosts, allowedLocalFeeds ?? []));

        if (!boundaryFound && packageSources is not null)
        {
            var notice = ParentConfigNotice(directory, packageSources);
            if (notice is not null)
            {
                findings.Add(notice);
            }
        }

        return findings;
    }

    /// <summary>
    /// Core logic over an already-loaded source list, testable without touching disk.
    /// Every source given here is assumed to be repo-declared (the disk overload filters
    /// user/global sources out first).
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(
        IEnumerable<PackageSource> sources,
        IReadOnlyList<string> allowedHosts) => Check(sources, allowedHosts, []);

    /// <summary>
    /// Core logic over an already-loaded source list, with an explicit allowlist of trusted
    /// local folder feeds. Testable without touching disk.
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(
        IEnumerable<PackageSource> sources,
        IReadOnlyList<string> allowedHosts,
        IReadOnlyList<string> allowedLocalFeeds)
    {
        var trustedHosts = BuildTrustedSet(PublicHosts, allowedHosts);
        var findings = new List<SourceFinding>();

        foreach (var source in sources)
        {
            if (!source.IsEnabled)
            {
                continue;
            }

            var finding = Evaluate(source, trustedHosts, allowedLocalFeeds);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }

    /// <summary>
    /// Evaluate a single enabled source: http(s) sources are checked against the trusted
    /// host set; everything else is a local folder feed checked against the allowlist.
    /// Returns null when the source is trusted.
    /// </summary>
    private static SourceFinding? Evaluate(
        PackageSource source,
        HashSet<string> trustedHosts,
        IReadOnlyList<string> allowedLocalFeeds)
    {
        if (IsRemoteHttpSource(source.Source, out var host))
        {
            return trustedHosts.Contains(host) ? null : UntrustedHostFinding(source, host);
        }

        return IsAllowedLocalFeed(source.Source, allowedLocalFeeds) ? null : LocalFeedFinding(source);
    }

    private static SourceFinding UntrustedHostFinding(PackageSource source, string host) =>
        new(host,
            source.Name,
            $"NuGet source '{source.Name}' ({source.Source}) uses untrusted host '{host}'. "
                + "Add it to allowedRegistryHosts in .dependably-check to permit it.");

    private static SourceFinding LocalFeedFinding(PackageSource source) =>
        new(source.Source,
            source.Name,
            $"NuGet source '{source.Name}' ({source.Source}) is a repo-declared local folder feed. "
                + "A committed local feed can smuggle tampered packages past a restore; add its path "
                + "to allowedLocalFeeds in .dependably-check to permit it.");

    private static bool IsRemoteHttpSource(string value, out string host)
    {
        host = string.Empty;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        host = uri.Host;
        return true;
    }

    private static HashSet<string> BuildTrustedSet(IEnumerable<string> baseline, IEnumerable<string> extra)
    {
        var trusted = new HashSet<string>(baseline, StringComparer.OrdinalIgnoreCase);
        foreach (var value in extra)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                trusted.Add(value);
            }
        }

        return trusted;
    }

    private static bool IsAllowedLocalFeed(string sourcePath, IReadOnlyList<string> allowedFeeds)
    {
        foreach (var entry in allowedFeeds)
        {
            if (!string.IsNullOrWhiteSpace(entry) && LocalFeedPathMatches(sourcePath, entry))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when <paramref name="entry"/> is a trailing path-segment suffix of (or equal to)
    /// <paramref name="sourcePath"/>, comparing segments case-insensitively and ignoring
    /// separator style and <c>.</c> segments. So <c>feeds</c> or <c>./feeds</c> matches a
    /// resolved <c>/repo/feeds</c>, while <c>feeds</c> does NOT match <c>/repo/myfeeds</c>.
    /// </summary>
    private static bool LocalFeedPathMatches(string sourcePath, string entry)
    {
        var sourceSegments = SplitPathSegments(sourcePath);
        var entrySegments = SplitPathSegments(entry);
        if (entrySegments.Length == 0 || entrySegments.Length > sourceSegments.Length)
        {
            return false;
        }

        var offset = sourceSegments.Length - entrySegments.Length;
        for (var i = 0; i < entrySegments.Length; i++)
        {
            if (!string.Equals(sourceSegments[offset + i], entrySegments[i], StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static string[] SplitPathSegments(string path) =>
        path.Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(segment => segment != ".")
            .ToArray();

    /// <summary>
    /// Resolves the repository boundary for <paramref name="startDirectory"/>: the nearest
    /// ancestor (inclusive) containing a <c>.git</c> file or directory. Returns true when
    /// such a boundary was found; <paramref name="root"/> is that directory, or the start
    /// directory itself when no boundary exists (so a non-repo path audits only its own
    /// declared config).
    /// </summary>
    private static bool TryFindRepoRoot(string startDirectory, out string root)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(startDirectory));

        while (directory is not null)
        {
            var gitPath = Path.Combine(directory.FullName, ".git");
            if (Directory.Exists(gitPath) || File.Exists(gitPath))
            {
                root = directory.FullName;
                return true;
            }

            directory = directory.Parent;
        }

        root = Path.GetFullPath(startDirectory);
        return false;
    }

    /// <summary>
    /// When no repository boundary was found, package sources declared in directories ABOVE
    /// the manifest directory were excluded from the audit even though a restore from a
    /// non-git checkout would still honour them. Returns a visible <c>info</c> finding naming
    /// those excluded config files, or null when there are none.
    /// </summary>
    private static SourceFinding? ParentConfigNotice(string startDirectory, SettingSection packageSources)
    {
        var manifestDir = Path.GetFullPath(startDirectory);

        var excluded = packageSources.Items.OfType<SourceItem>()
            .Where(item => IsStrictAncestorConfig(item.ConfigPath, manifestDir))
            .Select(item => Path.GetFullPath(item.ConfigPath!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        if (excluded.Count == 0)
        {
            return null;
        }

        return new SourceFinding(
            "(unaudited)",
            "parent-config",
            $"No repository boundary (.git) was found above '{manifestDir}', so NuGet config "
                + $"declared in parent directories was NOT audited even though a restore would honour it: "
                + $"{string.Join(", ", excluded)}. Verify these feeds, or run the audit from the repository root.",
            Severity.Info);
    }

    /// <summary>
    /// True when <paramref name="configPath"/> is a config file located in a STRICT ancestor
    /// directory of <paramref name="manifestDir"/> (i.e. above the manifest, not in it).
    /// </summary>
    private static bool IsStrictAncestorConfig(string? configPath, string manifestDir)
    {
        if (string.IsNullOrEmpty(configPath))
        {
            return false;
        }

        var configDir = Path.GetDirectoryName(Path.GetFullPath(configPath));
        if (string.IsNullOrEmpty(configDir))
        {
            return false;
        }

        var relative = Path.GetRelativePath(configDir, manifestDir);
        return relative != "."
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && relative != ".."
            && !Path.IsPathRooted(relative);
    }

    /// <summary>
    /// True when <paramref name="configPath"/> (a source's origin config file) is located
    /// at or under <paramref name="root"/>. Null/empty origins (sources with no on-disk
    /// declaration) are treated as outside the repo.
    /// </summary>
    private static bool IsUnderRoot(string? configPath, string root)
    {
        if (string.IsNullOrEmpty(configPath))
        {
            return false;
        }

        var relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(configPath));
        return relative != ".."
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !Path.IsPathRooted(relative);
    }
}
