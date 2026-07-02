using NuGet.Configuration;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Audits the NuGet package sources <b>declared within the repository</b> — the
/// <c>nuget.config</c> files walked up from the audited path to the repo root <b>and</b> any
/// config declared in a subdirectory of the scan root — and flags any enabled source that a
/// restore would honour but the policy does not trust:
/// <list type="bullet">
///   <item>an http(s) source whose host is neither a built-in public host nor explicitly
///   allowlisted (a plain-http source on an otherwise trusted host is downgraded to a
///   <c>warning</c> rather than passing silently, because http is still MITM-able);</item>
///   <item>a local folder feed (relative path or <c>file://</c> URI) not listed in
///   <c>allowedLocalFeeds</c> — fail-closed, because a repo-committed folder feed can smuggle
///   tampered <c>.nupkg</c> files past a restore;</item>
///   <item>a remote-host <c>file://</c>/UNC network share, which is trusted only by an
///   allowlisted host or an EXACT <c>allowedLocalFeeds</c> entry — never by a bare local-path
///   entry.</item>
/// </list>
/// Disabled sources are ignored (only a repo-declared disable counts, so an auditor's
/// machine-local <c>disabledPackageSources</c> cannot suppress a finding).
/// <para>
/// The host machine's user/global NuGet configuration is intentionally OUT OF SCOPE:
/// the verdict must depend only on what the repo declares, so it is reproducible and
/// machine-independent (the same repo passes or fails identically on any machine and in
/// CI, and auditing a stranger's repo never flags the auditor's personal feeds).
/// </para>
/// <para>
/// When no repository boundary (<c>.git</c>) can be located, the manifest directory is
/// treated as the boundary and configs in parent directories are excluded; an <c>info</c>
/// finding is emitted in that case if any such parent config exists, because a restore
/// from a non-git checkout would still honour those unaudited sources.
/// </para>
/// </summary>
public static class SourceTrustService
{
    /// <summary>Hosts always trusted as public NuGet sources, regardless of config.</summary>
    public static readonly IReadOnlyList<string> PublicHosts = ["api.nuget.org", "nuget.org"];

    /// <summary>
    /// Returns one <see cref="SourceFinding"/> per enabled package source <b>declared inside
    /// the repository tree</b> (config from <paramref name="directory"/> up to the repo root,
    /// plus any subdirectory config) that the policy does not trust: an http(s) source whose
    /// host is not in the trusted set (public hosts ∪ <paramref name="allowedHosts"/>), a
    /// plain-http source on a trusted host (as a warning), or a local/remote folder feed not
    /// permitted by <paramref name="allowedLocalFeeds"/>. Sources contributed solely by the
    /// host machine's user/global NuGet config are not audited, so a repo that declares no
    /// <c>nuget.config</c> produces no findings (its implicit default is nuget.org).
    /// <para>
    /// When no repository boundary (<c>.git</c>) can be located, an <c>info</c> finding is
    /// emitted naming any parent-directory config a restore would honour but the audit excluded.
    /// </para>
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(
        string directory,
        IReadOnlyList<string> allowedHosts,
        IReadOnlyList<string>? allowedLocalFeeds = null)
    {
        var boundaryFound = TryFindRepoRoot(directory, out var repoRoot);

        var sources = CollectRepoDeclaredSources(directory, repoRoot);

        var findings = new List<SourceFinding>(
            CheckCore(sources, allowedHosts, allowedLocalFeeds ?? [], repoRoot));

        if (!boundaryFound)
        {
            var packageSources = Settings.LoadDefaultSettings(directory).GetSection("packageSources");
            var notice = packageSources is null ? null : ParentConfigNotice(directory, packageSources);
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
        IReadOnlyList<string> allowedLocalFeeds) =>
        CheckCore(sources, allowedHosts, allowedLocalFeeds, repoRoot: null);

    // -- Discovery: which repo-declared sources a restore would honour (ticket 32/45) --------

    /// <summary>
    /// Gathers every package source declared by a <c>nuget.config</c> that lives inside the
    /// repo tree — the config walked up from <paramref name="scanDirectory"/> <b>and</b> any
    /// config found in a subdirectory of the scan root (e.g. <c>src/nuget.config</c> or a
    /// config beside a nested <c>.sln</c>), which govern real restores in their subtree yet
    /// are never seen by an upward-only walk. Each subtree is loaded via
    /// <see cref="Settings.LoadDefaultSettings(string)"/> so NuGet's <c>&lt;clear/&gt;</c> /
    /// enabled / disabled merge semantics are preserved per subtree; results are
    /// de-duplicated by (name, source url).
    /// </summary>
    private static List<PackageSource> CollectRepoDeclaredSources(string scanDirectory, string repoRoot)
    {
        var byIdentity = new Dictionary<(string Name, string Source), PackageSource>();

        foreach (var settingsDirectory in SettingsDirectories(scanDirectory))
        {
            AddUnderRootSources(Settings.LoadDefaultSettings(settingsDirectory), repoRoot, byIdentity);
        }

        return byIdentity.Values.ToList();
    }

    /// <summary>
    /// The directories whose <c>nuget.config</c> hierarchies must be audited: the scan
    /// directory itself (upward walk) plus every subdirectory under it that declares its own
    /// <c>nuget.config</c>, skipping <c>bin</c>/<c>obj</c>/<c>.git</c> build and VCS folders.
    /// </summary>
    private static IEnumerable<string> SettingsDirectories(string scanDirectory)
    {
        var root = Path.GetFullPath(scanDirectory);
        yield return root;

        foreach (var configDirectory in FindSubtreeConfigDirectories(root))
        {
            yield return configDirectory;
        }
    }

    private static IEnumerable<string> FindSubtreeConfigDirectories(string root)
    {
        if (!Directory.Exists(root))
        {
            yield break;
        }

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            MatchCasing = MatchCasing.CaseInsensitive,
            IgnoreInaccessible = true,
            // Do NOT skip Hidden/System entries: on Unix/macOS a dot-directory (e.g.
            // .build/tools or .config) reports as Hidden, and repos legitimately keep a
            // nuget.config there. The explicit bin/obj/.git segment filter below is the only
            // intended exclusion; the default (Hidden | System) would silently miss the rest.
            AttributesToSkip = FileAttributes.None,
        };

        foreach (var configFile in Directory.EnumerateFiles(root, "nuget.config", options))
        {
            var configDirectory = Path.GetDirectoryName(configFile);
            if (configDirectory is not null
                && !PathEquals(configDirectory, root)
                && !IsExcludedPath(root, configDirectory))
            {
                yield return configDirectory;
            }
        }
    }

    /// <summary>
    /// Adds to <paramref name="acc"/> the package sources from <paramref name="settings"/>
    /// whose declaring config lives under <paramref name="repoRoot"/>, with their enabled
    /// state resolved solely from repo-declared <c>&lt;disabledPackageSources&gt;</c> — the
    /// merged <see cref="PackageSource.IsEnabled"/> flag is deliberately ignored so an
    /// auditor's machine-local <c>disabledPackageSources</c> cannot suppress a finding.
    /// <para>
    /// Merge is ENABLED-WINS across audited configs/subtrees: a source enabled by ANY
    /// repo-scoped config must be evaluated, so a disable in one subtree cannot mask the same
    /// source being enabled (and used for real restores) in another. This makes the verdict
    /// independent of the order in which the root and subtree passes are visited.
    /// </para>
    /// </summary>
    private static void AddUnderRootSources(
        ISettings settings,
        string repoRoot,
        Dictionary<(string Name, string Source), PackageSource> acc)
    {
        var repoSourceNames = UnderRootKeys(settings, "packageSources", repoRoot);
        if (repoSourceNames.Count == 0)
        {
            return;
        }

        var repoDisabledNames = UnderRootKeys(settings, "disabledPackageSources", repoRoot);

        foreach (var source in new PackageSourceProvider(settings).LoadPackageSources())
        {
            if (!repoSourceNames.Contains(source.Name))
            {
                continue;
            }

            source.IsEnabled = !repoDisabledNames.Contains(source.Name);
            var key = (source.Name, source.Source);

            // Enabled-wins: only overwrite when this pass enables the source, or when it is
            // not yet known. A disabled entry never clobbers an already-enabled one.
            if (source.IsEnabled || !acc.ContainsKey(key))
            {
                acc[key] = source;
            }
        }
    }

    private static bool IsExcludedPath(string root, string candidate)
    {
        var relative = Path.GetRelativePath(root, candidate);
        // Split on BOTH separators via an explicit array: `Split(char, char)` would bind the
        // second char to the `int count` overload (splitting on one separator only).
        return relative.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar])
            .Any(segment => segment is "bin" or "obj" or ".git");
    }

    private static bool PathEquals(string a, string b) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)),
            StringComparison.Ordinal);

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

    // -- Evaluation: per-source trust verdict (tickets 25/31/33/35) --------------------------

    /// <summary>
    /// Core loop shared by the disk and in-memory overloads. <paramref name="repoRoot"/> is
    /// the resolved repository boundary (or null when unknown, e.g. the in-memory overloads
    /// used by tests); it anchors <c>./</c>-prefixed allowlist entries to a single approved
    /// location instead of a loose trailing-segment match.
    /// </summary>
    private static List<SourceFinding> CheckCore(
        IEnumerable<PackageSource> sources,
        IReadOnlyList<string> allowedHosts,
        IReadOnlyList<string> allowedLocalFeeds,
        string? repoRoot)
    {
        var trustedHosts = BuildTrustedSet(PublicHosts, allowedHosts);
        var findings = new List<SourceFinding>();

        foreach (var source in sources)
        {
            if (!source.IsEnabled)
            {
                continue;
            }

            var finding = Evaluate(source, trustedHosts, allowedLocalFeeds, repoRoot);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }

    /// <summary>
    /// Evaluate a single enabled source. An http(s) source is checked against the trusted host
    /// set; a trusted host reached over plain http still yields a <c>warning</c> (MITM-able,
    /// cf. NuGet NU1803). A <c>file://</c> URI with a remote host, or a UNC path
    /// (<c>\\server\share</c>), is a network share masquerading as a local feed: it is trusted
    /// only when its host is allowlisted OR it matches an EXACT <c>allowedLocalFeeds</c> entry —
    /// a bare local-path entry must never satisfy it. Everything else is a genuine local folder
    /// feed checked against the allowlist. Returns null when trusted.
    /// </summary>
    private static SourceFinding? Evaluate(
        PackageSource source,
        HashSet<string> trustedHosts,
        IReadOnlyList<string> allowedLocalFeeds,
        string? repoRoot)
    {
        if (IsRemoteHttpSource(source.Source, out var host))
        {
            if (!trustedHosts.Contains(host))
            {
                return UntrustedHostFinding(source, host);
            }

            // Trusted host, but plain http is still MITM-able: nudge to https rather than
            // passing silently. An untrusted host above already took precedence (error wins).
            return IsPlainHttp(source.Source) ? PlainHttpWarning(source, host) : null;
        }

        if (IsRemoteHostFileSource(source.Source, out var fileHost))
        {
            // A remote network share is trusted only by an explicitly allowlisted host or an
            // EXACT allowlist entry. A bare local-path entry must never satisfy it (closes the
            // #33 escalation bypass); an allowlisted host is the #35 opt-in for a trusted share.
            var trusted = trustedHosts.Contains(fileHost)
                || IsExactlyAllowlisted(source.Source, allowedLocalFeeds);
            return trusted ? null : RemoteFileFeedFinding(source, fileHost);
        }

        return IsAllowedLocalFeed(source.Source, allowedLocalFeeds, repoRoot) ? null : LocalFeedFinding(source);
    }

    private static SourceFinding UntrustedHostFinding(PackageSource source, string host) =>
        new(host,
            source.Name,
            $"NuGet source '{source.Name}' ({source.Source}) uses untrusted host '{host}'. "
                + "Add it to allowedRegistryHosts in .dependably-check to permit it.");

    private static SourceFinding PlainHttpWarning(PackageSource source, string host) =>
        new(host,
            source.Name,
            $"NuGet source '{source.Name}' ({source.Source}) uses plain http on trusted host '{host}'. "
                + "Switch to https to prevent on-path injection of package content.",
            "warning");

    private static SourceFinding LocalFeedFinding(PackageSource source) =>
        new(source.Source,
            source.Name,
            $"NuGet source '{source.Name}' ({source.Source}) is a repo-declared local folder feed. "
                + "A committed local feed can smuggle tampered packages past a restore; add its path "
                + "to allowedLocalFeeds in .dependably-check to permit it.");

    private static SourceFinding RemoteFileFeedFinding(PackageSource source, string host) =>
        new(host,
            source.Name,
            $"NuGet source '{source.Name}' ({source.Source}) is a remote network feed on host "
                + $"'{host}' declared as a file/UNC path, not a local folder. A local-path entry in "
                + "allowedLocalFeeds cannot trust it; list its exact path only if you fully trust that share.");

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

    private static bool IsPlainHttp(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttp;

    /// <summary>
    /// True when <paramref name="value"/> is a file feed pointing at a REMOTE machine: a
    /// <c>file://server/share/...</c> URI or a UNC path (<c>\\server\share\...</c> or
    /// <c>//server/share/...</c>). Such sources parse as a <c>file</c> URI with a non-empty,
    /// non-loopback host. Purely local feeds (<c>file:///opt/x</c>, <c>/opt/x</c>,
    /// <c>C:\x</c>) have an empty/loopback host and return false.
    /// </summary>
    private static bool IsRemoteHostFileSource(string value, out string host)
    {
        host = string.Empty;
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && uri.IsFile
            && !uri.IsLoopback
            && !string.IsNullOrEmpty(uri.Host))
        {
            host = uri.Host;
            return true;
        }

        return false;
    }

    private static HashSet<string> BuildTrustedSet(IEnumerable<string> baseline, IEnumerable<string> extra)
    {
        var trusted = new HashSet<string>(baseline, StringComparer.OrdinalIgnoreCase);
        foreach (var value in extra)
        {
            // Trim before insertion (ticket 25): a config value padded with whitespace (e.g.
            // from a YAML parser) must still match uri.Host, which is never padded.
            var trimmed = value.Trim();
            if (!string.IsNullOrEmpty(trimmed))
            {
                trusted.Add(trimmed);
            }
        }

        return trusted;
    }

    private static bool IsAllowedLocalFeed(string sourcePath, IReadOnlyList<string> allowedFeeds, string? repoRoot)
    {
        foreach (var entry in allowedFeeds)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            var matched = IsRepoAnchoredEntry(entry)
                ? repoRoot is not null && RepoAnchoredMatches(sourcePath, entry, repoRoot)
                : LocalFeedPathMatches(sourcePath, entry);

            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when <paramref name="sourcePath"/> equals an allowlist entry exactly, comparing
    /// case-insensitively after normalising separator style and a trailing separator. Used for
    /// remote-host file/UNC sources, which a loose trailing-segment match must never trust.
    /// </summary>
    private static bool IsExactlyAllowlisted(string sourcePath, IReadOnlyList<string> allowedFeeds)
    {
        var normalizedSource = NormalizeForExactMatch(sourcePath);
        foreach (var entry in allowedFeeds)
        {
            if (!string.IsNullOrWhiteSpace(entry)
                && string.Equals(NormalizeForExactMatch(entry), normalizedSource, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string NormalizeForExactMatch(string value) =>
        value.Replace('\\', '/').TrimEnd('/');

    /// <summary>
    /// True when the allowlist entry is explicitly anchored to the repository root — it begins
    /// with a current/parent-directory segment (<c>./</c>, <c>.\</c>, <c>../</c>, <c>..\</c>).
    /// Anchored entries are resolved against the repo root and matched by canonical absolute
    /// path, so they grant only the maintainer-approved location and never a same-named folder
    /// elsewhere on disk. Bare-name entries keep the documented trailing-segment behaviour.
    /// </summary>
    private static bool IsRepoAnchoredEntry(string entry) =>
        entry.StartsWith("./", StringComparison.Ordinal)
            || entry.StartsWith(".\\", StringComparison.Ordinal)
            || entry.StartsWith("../", StringComparison.Ordinal)
            || entry.StartsWith("..\\", StringComparison.Ordinal);

    /// <summary>
    /// True when <paramref name="sourcePath"/> resolves to the exact directory named by a
    /// repo-anchored <paramref name="entry"/> (resolved against <paramref name="repoRoot"/>),
    /// comparing canonical absolute paths.
    /// </summary>
    private static bool RepoAnchoredMatches(string sourcePath, string entry, string repoRoot)
    {
        var resolvedSource = CanonicalLocalPath(sourcePath);
        if (resolvedSource is null)
        {
            return false;
        }

        var resolvedEntry = Path.GetFullPath(Path.Combine(repoRoot, entry));
        return string.Equals(
            resolvedSource.TrimEnd('/', '\\'),
            resolvedEntry.TrimEnd('/', '\\'),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Canonical absolute filesystem path for a local source, or null when the source is not a
    /// local path. Remote-host file/UNC sources are filtered out before this is reached.
    /// </summary>
    private static string? CanonicalLocalPath(string source)
    {
        if (Uri.TryCreate(source, UriKind.Absolute, out var uri))
        {
            return uri.IsFile ? Path.GetFullPath(uri.LocalPath) : null;
        }

        return Path.GetFullPath(source);
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

    // -- Repository boundary & the non-git fail-open notice (ticket 47) ----------------------

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
