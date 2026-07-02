using NuGet.Configuration;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Audits the NuGet package sources <b>declared within the repository</b> (the
/// <c>nuget.config</c> files from the audited path up to and including the repo root)
/// and flags any enabled http(s) source whose host is neither a built-in public host
/// nor explicitly allowlisted in the shared <c>.dependably-check</c> config. Local
/// folder feeds and disabled sources are ignored.
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
    /// Returns one <see cref="SourceFinding"/> (error) per enabled http(s) package source
    /// <b>declared inside the repository tree</b> (config from <paramref name="directory"/>
    /// up to and including the repo root) whose host is not in the trusted set (public
    /// hosts ∪ <paramref name="allowedHosts"/>). Sources contributed solely by the host
    /// machine's user/global NuGet config are not audited, so a repo that declares no
    /// <c>nuget.config</c> produces no findings (its implicit default is nuget.org).
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(string directory, IReadOnlyList<string> allowedHosts)
    {
        var settings = Settings.LoadDefaultSettings(directory);
        var repoRoot = FindRepoRoot(directory);

        // Names of the package sources actually declared inside the repo tree, discarding
        // anything inherited from the user/global machine config.
        var repoSourceNames = UnderRootKeys(settings, "packageSources", repoRoot);

        // Enabled/disabled is resolved solely from repo-declared <disabledPackageSources>:
        // the merged PackageSource.IsEnabled flag also reflects the auditor's machine-local
        // disabledPackageSources, which would let a local disable suppress a repo-declared
        // untrusted source on one machine yet flag it in CI (non-reproducible verdict).
        var repoDisabledNames = UnderRootKeys(settings, "disabledPackageSources", repoRoot);

        var sources = new PackageSourceProvider(settings)
            .LoadPackageSources()
            .Where(source => repoSourceNames.Contains(source.Name))
            .Select(source =>
            {
                source.IsEnabled = !repoDisabledNames.Contains(source.Name);
                return source;
            });

        return Check(sources, allowedHosts);
    }

    /// <summary>
    /// Keys of the items in section <paramref name="sectionName"/> whose declaring config
    /// file lives at or under <paramref name="repoRoot"/>, discarding anything inherited from
    /// the user/global machine config. <see cref="SourceItem"/> (packageSources) and plain
    /// <see cref="AddItem"/> (disabledPackageSources) entries are both matched.
    /// </summary>
    private static HashSet<string> UnderRootKeys(ISettings settings, string sectionName, string repoRoot)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var section = settings.GetSection(sectionName);
        if (section is not null)
        {
            keys.UnionWith(section.Items.OfType<AddItem>()
                .Where(item => IsUnderRoot(item.ConfigPath, repoRoot))
                .Select(item => item.Key));
        }

        return keys;
    }

    /// <summary>
    /// Core logic over an already-loaded source list, testable without touching disk.
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(
        IEnumerable<PackageSource> sources,
        IReadOnlyList<string> allowedHosts)
    {
        var trusted = new HashSet<string>(PublicHosts, StringComparer.OrdinalIgnoreCase);
        foreach (var host in allowedHosts)
        {
            if (!string.IsNullOrWhiteSpace(host))
            {
                trusted.Add(host);
            }
        }

        var findings = new List<SourceFinding>();

        foreach (var source in sources)
        {
            if (!source.IsEnabled)
            {
                continue;
            }

            if (!Uri.TryCreate(source.Source, UriKind.Absolute, out var uri))
            {
                continue;
            }

            // Only network feeds carry a host worth trusting. http(s) always qualify; a
            // file:// / UNC source with a non-empty host is a remote SMB share on an
            // arbitrary server (e.g. \\evil-server\feed) and must be trust-checked too.
            // Truly local folder feeds (empty host) remain out of scope.
            if (!IsNetworkSource(uri))
            {
                continue;
            }

            var host = uri.Host;
            if (trusted.Contains(host))
            {
                continue;
            }

            findings.Add(new SourceFinding(
                host,
                source.Name,
                $"NuGet source '{source.Name}' ({source.Source}) uses untrusted host '{host}'. "
                    + "Add it to allowedRegistryHosts in .dependably-check to permit it."));
        }

        return findings;
    }

    /// <summary>
    /// True when <paramref name="uri"/> reaches a network host worth trust-checking: any
    /// http(s) feed, or a <c>file://</c> / UNC feed with a non-empty host (a remote share on
    /// an arbitrary server). Truly local folder feeds (empty host) are not network sources.
    /// </summary>
    private static bool IsNetworkSource(Uri uri)
    {
        if (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
        {
            return true;
        }

        if (uri.IsUnc || uri.Scheme == Uri.UriSchemeFile)
        {
            return !string.IsNullOrEmpty(uri.Host);
        }

        return false;
    }

    /// <summary>
    /// Resolves the repository boundary for <paramref name="startDirectory"/>: the nearest
    /// ancestor (inclusive) containing a <c>.git</c> file or directory. When none is found,
    /// the start directory itself is the boundary, so a non-repo path audits only its own
    /// declared config.
    /// </summary>
    private static string FindRepoRoot(string startDirectory)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(startDirectory));

        while (directory is not null)
        {
            var gitPath = Path.Combine(directory.FullName, ".git");
            if (Directory.Exists(gitPath) || File.Exists(gitPath))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return Path.GetFullPath(startDirectory);
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
