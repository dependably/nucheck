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

        // Origin config paths of the package sources actually declared inside the repo
        // tree. LoadDefaultSettings honours NuGet's <clear/> / enabled / disabled merge
        // semantics; we then keep only the items whose declaring file lives under the
        // repo root, discarding anything inherited from the user/global machine config.
        var repoSourceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var packageSources = settings.GetSection("packageSources");
        if (packageSources is not null)
        {
            foreach (var item in packageSources.Items.OfType<SourceItem>())
            {
                if (IsUnderRoot(item.ConfigPath, repoRoot))
                {
                    repoSourceNames.Add(item.Key);
                }
            }
        }

        var sources = new PackageSourceProvider(settings)
            .LoadPackageSources()
            .Where(source => repoSourceNames.Contains(source.Name));

        return Check(sources, allowedHosts);
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

            // Only network feeds carry a host worth trusting; local folder feeds are file:// paths.
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
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
}
