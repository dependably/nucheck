using System.Text.Json;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Config;

/// <summary>A deprecation / unknown-key notice emitted while loading <c>.dependably</c> (spec §11).</summary>
public sealed record DependablyWarning(string Code, string Message);

/// <summary>
/// The shared repo-root <c>.dependably</c> config, consumed across the Dependably suite.
/// <c>.dependably-check</c> is a deprecated alias filename. nucheck reads the <c>common</c>
/// section and its own <c>nucheck</c> section (<c>nuget</c> is a deprecated section alias):
/// the six spec-§4 universal keys (<c>rules</c>, <c>exceptions</c>, <c>exclude</c>,
/// <c>failOn</c>, <c>allowedRegistryHosts</c>, <c>allowedLocalFeeds</c>) plus nucheck's own
/// <c>ignoreUnusedPackages</c>. Other sections are ignored; an unknown key warns in nucheck's
/// own section but is ignored in <c>common</c>, where it may belong to a sibling tool. See
/// docs/dependably-config-spec.md in
/// https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec.
/// </summary>
public sealed class DependablyCheckConfig
{
    /// <summary>The canonical config file name discovered by walking up the directory tree.</summary>
    public const string FileName = ".dependably";

    /// <summary>The deprecated alias filename, still read for the migration window.</summary>
    public const string DeprecatedFileName = ".dependably-check";

    /// <summary>The canonical section key for nucheck, and its deprecated alias.</summary>
    public const string SectionKey = "nucheck";
    public const string DeprecatedSectionKey = "nuget";

    /// <summary>Highest <c>.dependably</c> format version this build understands.</summary>
    public const int SupportedVersion = 1;

    /// <summary>
    /// The six spec-§4 universal keys (legal in <c>common</c> and every tool's own section)
    /// plus <c>ignoreUnusedPackages</c>, which is nucheck's own extra key.
    /// </summary>
    private static readonly string[] KnownSectionKeys =
    [
        "rules", "exceptions", "exclude", "failOn", "allowedRegistryHosts", "allowedLocalFeeds",
        "ignoreUnusedPackages",
    ];

    /// <summary>The rule-severity vocabulary (spec §4.2).</summary>
    public static readonly string[] RuleSeverityValues = ["error", "warn", "off"];

    private DependablyCheckConfig(
        IReadOnlyList<string> allowedRegistryHosts,
        IReadOnlyList<string> ignoreUnusedPackages,
        IReadOnlyList<string> allowedLocalFeeds,
        IReadOnlyList<string> exclude,
        IReadOnlyList<DependablyException> exceptions,
        string? failOnSeverity,
        int? failOnCount,
        IReadOnlyDictionary<string, string> ruleSeverities,
        IReadOnlyList<DependablyWarning> warnings)
    {
        AllowedRegistryHosts = allowedRegistryHosts;
        IgnoreUnusedPackages = ignoreUnusedPackages;
        AllowedLocalFeeds = allowedLocalFeeds;
        Exclude = exclude;
        Exceptions = exceptions;
        FailOnSeverity = failOnSeverity;
        FailOnCount = failOnCount;
        RuleSeverities = ruleSeverities;
        Warnings = warnings;
    }

    /// <summary>
    /// Bare hostnames trusted as NuGet sources (union of common + nucheck, deduped
    /// case-insensitively, stored lowercased per spec §5.1).
    /// </summary>
    public IReadOnlyList<string> AllowedRegistryHosts { get; }

    /// <summary>Package ids never reported as unused (union of common + nucheck, deduped case-insensitively).</summary>
    public IReadOnlyList<string> IgnoreUnusedPackages { get; }

    /// <summary>Repo-local feeds explicitly trusted (union of common + nucheck, deduped case-insensitively).</summary>
    public IReadOnlyList<string> AllowedLocalFeeds { get; }

    /// <summary>
    /// Glob patterns excluded from scanning (union of common + nucheck, ordinal — case-preserving,
    /// since a path is case-sensitive on the filesystems that matter). nucheck has no current
    /// consumer for this list; it is legal-and-inert here per spec §4, resolved for parity with
    /// the tool's other §5 list keys.
    /// </summary>
    public IReadOnlyList<string> Exclude { get; }

    /// <summary>Parsed <c>exceptions</c> entries (common + nucheck), suppressing specific findings (spec §6).</summary>
    public IReadOnlyList<DependablyException> Exceptions { get; }

    /// <summary>The <c>failOn.severity</c> gate from the file (CLI <c>--fail-on</c> overrides), or null.</summary>
    public string? FailOnSeverity { get; }

    /// <summary>The <c>failOn.count</c> gate from the file (CLI <c>--fail-on</c> overrides), or null.</summary>
    public int? FailOnCount { get; }

    /// <summary>
    /// Per-rule severities from the merged <c>rules</c> maps (spec §4.1): rule id →
    /// <c>error</c>/<c>warn</c>/<c>off</c>. Merged per id with the tool entry replacing
    /// <c>common</c>'s wholesale (spec §5); an entry's options object is accepted but
    /// ignored (nucheck defines no rule options yet). A CLI <c>--rule</c> overrides.
    /// </summary>
    public IReadOnlyDictionary<string, string> RuleSeverities { get; }

    /// <summary>Deprecation / unknown-key notices (stderr; never affect exit codes).</summary>
    public IReadOnlyList<DependablyWarning> Warnings { get; }

    /// <summary>An empty config, used when no file is found.</summary>
    public static DependablyCheckConfig Empty { get; } = new(
        [], [], [], [], [], null, null, new Dictionary<string, string>(), []);

    /// <summary>
    /// Loads the config. When <paramref name="explicitPath"/> is given it is read directly;
    /// otherwise <c>.dependably</c> (or the deprecated <c>.dependably-check</c>) is discovered
    /// by walking up from <paramref name="startDirectory"/>. Returns <see cref="Empty"/> when
    /// no file is found. Throws when an existing file cannot be parsed.
    /// </summary>
    public static DependablyCheckConfig Load(string? explicitPath, string startDirectory)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            if (!File.Exists(explicitPath))
            {
                throw new FileNotFoundException($"Config file not found: {explicitPath}", explicitPath);
            }

            return Parse(explicitPath, []);
        }

        var discovered = Discover(startDirectory);
        return discovered is null ? Empty : Parse(discovered, FilenameWarnings(discovered));
    }

    /// <summary>
    /// Walks up from <paramref name="startDirectory"/> looking for a shared config file.
    /// <c>.dependably</c> is preferred over the deprecated <c>.dependably-check</c> at each
    /// level. Stops at the filesystem root, or at a directory containing a <c>.git</c> entry
    /// (the repo boundary) after checking that directory.
    /// </summary>
    public static string? Discover(string startDirectory)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(startDirectory));

        while (directory is not null)
        {
            foreach (var name in new[] { FileName, DeprecatedFileName })
            {
                var candidate = Path.Combine(directory.FullName, name);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            var gitPath = Path.Combine(directory.FullName, ".git");
            if (Directory.Exists(gitPath) || File.Exists(gitPath))
            {
                return null;
            }

            directory = directory.Parent;
        }

        return null;
    }

    private static List<DependablyWarning> FilenameWarnings(string path)
    {
        var warnings = new List<DependablyWarning>();
        var dir = Path.GetDirectoryName(path)!;
        if (Path.GetFileName(path) == DeprecatedFileName)
        {
            warnings.Add(new DependablyWarning("DEPRECATED_FILENAME",
                $"{DeprecatedFileName} is deprecated; rename it to {FileName}"));
        }
        else if (File.Exists(Path.Combine(dir, DeprecatedFileName)))
        {
            warnings.Add(new DependablyWarning("BOTH_FILES_PRESENT",
                $"both {FileName} and {DeprecatedFileName} found in {dir}; using {FileName} ({DeprecatedFileName} is ignored — delete it)"));
        }

        return warnings;
    }

    private static DependablyCheckConfig Parse(string path, List<DependablyWarning> warnings)
    {
        JsonDocument document;
        try
        {
            using var stream = File.OpenRead(path);
            document = JsonDocument.Parse(stream);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Failed to parse {path}: {ex.Message}", ex);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new DependablyConfigException($"Config must be a JSON object: {path}", "CONFIG_SHAPE");
            }

            ValidateVersion(root, path);

            // Resolve the tool section: canonical `nucheck`, else the deprecated `nuget` alias.
            var hasCanonical = TryGetObject(root, SectionKey, out _);
            var hasAlias = TryGetObject(root, DeprecatedSectionKey, out _);
            var toolKey = hasCanonical ? SectionKey : (hasAlias ? DeprecatedSectionKey : SectionKey);
            if (!hasCanonical && hasAlias)
            {
                warnings.Add(new DependablyWarning("DEPRECATED_ALIAS_SECTION",
                    $"section \"{DeprecatedSectionKey}\" is deprecated; rename it to \"{SectionKey}\""));
            }
            else if (hasCanonical && hasAlias)
            {
                warnings.Add(new DependablyWarning("DEPRECATED_ALIAS_SECTION",
                    $"both \"{SectionKey}\" and \"{DeprecatedSectionKey}\" sections present; using \"{SectionKey}\""));
            }

            // Own section only: `common` is shared with every sibling tool, so a key nucheck does
            // not know there is very likely someone else's, not a typo. Same reasoning the spec
            // already applied to unknown rule ids in `common`.
            WarnUnknownKeys(root, toolKey, warnings);

            var hosts = UnionStringArray(root, toolKey, "allowedRegistryHosts", canonicalizeLowercase: true);
            var ignored = UnionStringArray(root, toolKey, "ignoreUnusedPackages");
            var localFeeds = UnionStringArray(root, toolKey, "allowedLocalFeeds");
            var exclude = UnionStringArray(root, toolKey, "exclude");

            var exceptions = new List<DependablyException>();
            exceptions.AddRange(DependablyExceptions.Parse(
                GetProperty(root, "common", "exceptions"), "common", DependablyExceptions.NuCheckSelectors, null));
            exceptions.AddRange(DependablyExceptions.Parse(
                GetProperty(root, toolKey, "exceptions"), "own", DependablyExceptions.NuCheckSelectors, DependablyExceptions.KnownRules));

            var (failOnSeverity, failOnCount) = ParseFailOn(root, toolKey);
            var ruleSeverities = ParseRules(root, toolKey);

            return new DependablyCheckConfig(
                hosts, ignored, localFeeds, exclude, exceptions, failOnSeverity, failOnCount, ruleSeverities, warnings);
        }
    }

    private static void ValidateVersion(JsonElement root, string path)
    {
        if (root.TryGetProperty("version", out var v))
        {
            if (v.ValueKind != JsonValueKind.Number || !v.TryGetInt32(out var version) || version > SupportedVersion)
            {
                throw new DependablyConfigException(
                    $"Unsupported .dependably version in {path} (this build supports up to {SupportedVersion})", "CONFIG_VERSION");
            }
        }
    }

    private static (string? severity, int? count) ParseFailOn(JsonElement root, string toolKey)
    {
        string? severity = null;
        int? count = null;

        foreach (var section in new[] { "common", toolKey })
        {
            if (GetProperty(root, section, "failOn") is not { ValueKind: JsonValueKind.Object } failOn)
            {
                continue;
            }

            if (failOn.TryGetProperty("severity", out var sevEl) && sevEl.ValueKind == JsonValueKind.String)
            {
                var level = Severity.ParseLevel(sevEl.GetString());
                if (level is null)
                {
                    throw new DependablyConfigException($"invalid failOn.severity \"{sevEl.GetString()}\"", "INVALID_FAIL_ON");
                }

                severity = level;
            }

            if (failOn.TryGetProperty("count", out var countEl))
            {
                if (countEl.ValueKind != JsonValueKind.Number || !countEl.TryGetInt32(out var c) || c < 0)
                {
                    throw new DependablyConfigException("failOn.count must be a non-negative integer", "INVALID_FAIL_ON");
                }

                count = c;
            }
        }

        return (severity, count);
    }

    /// <summary>
    /// Parse and merge the <c>rules</c> severity maps: <c>common</c> first, then the tool
    /// section replacing per rule id (spec §5). An unknown rule id is an error in the tool's
    /// OWN section (<c>UNKNOWN_RULE</c>) and tolerated in <c>common</c> (it may belong to a
    /// sibling tool). Each entry is a severity string or <c>[severity, options]</c>; the
    /// options object is accepted and ignored.
    /// </summary>
    private static Dictionary<string, string> ParseRules(JsonElement root, string toolKey)
    {
        var severities = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var section in new[] { "common", toolKey })
        {
            if (GetProperty(root, section, "rules") is not { ValueKind: JsonValueKind.Object } rules)
            {
                continue;
            }

            foreach (var rule in rules.EnumerateObject())
            {
                if (section != "common" && !DependablyExceptions.KnownRules.Contains(rule.Name))
                {
                    throw new DependablyConfigException(
                        $"Unknown rule \"{rule.Name}\" (known rules: {string.Join(", ", DependablyExceptions.KnownRules)})",
                        "UNKNOWN_RULE");
                }

                severities[rule.Name] = ParseRuleSeverity(rule.Name, rule.Value);
            }
        }

        return severities;
    }

    /// <summary>Validate one <c>rules</c> entry — <c>"warn"</c> or <c>["warn", { ... }]</c> — and return its severity.</summary>
    private static string ParseRuleSeverity(string ruleId, JsonElement entry)
    {
        var severityElement = entry;
        if (entry.ValueKind == JsonValueKind.Array)
        {
            using var items = entry.EnumerateArray();
            if (!items.MoveNext())
            {
                throw new DependablyConfigException($"Invalid rule entry for \"{ruleId}\": empty array", "INVALID_SEVERITY");
            }

            severityElement = items.Current;
            if (items.MoveNext() && items.Current.ValueKind != JsonValueKind.Object)
            {
                throw new DependablyConfigException(
                    $"Rule options for \"{ruleId}\" must be an object", "INVALID_RULE_OPTIONS");
            }
        }

        var severity = severityElement.ValueKind == JsonValueKind.String ? severityElement.GetString() : null;
        if (severity is null || !RuleSeverityValues.Contains(severity))
        {
            throw new DependablyConfigException(
                $"Invalid severity for rule \"{ruleId}\" (expected: {string.Join(", ", RuleSeverityValues)})",
                "INVALID_SEVERITY");
        }

        return severity;
    }

    private static void WarnUnknownKeys(JsonElement root, string section, List<DependablyWarning> warnings)
    {
        if (!TryGetObject(root, section, out var el))
        {
            return;
        }

        foreach (var prop in el.EnumerateObject())
        {
            if (!KnownSectionKeys.Contains(prop.Name))
            {
                warnings.Add(new DependablyWarning("UNKNOWN_KEY", $"unknown key \"{section}.{prop.Name}\" in .dependably — ignoring"));
            }
        }
    }

    // Union `common.<arrayKey>` and `<toolKey>.<arrayKey>`, deduped case-insensitively. The
    // stored spelling is the first-seen one unless `canonicalizeLowercase` is set, in which case
    // it is lowercased — spec §5.1 requires that only for `allowedRegistryHosts`; the other two
    // call sites (a filesystem-path list and nucheck's own key) keep their case as written.
    private static List<string> UnionStringArray(
        JsonElement root, string toolKey, string arrayKey, bool canonicalizeLowercase = false)
    {
        var values = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var section in new[] { "common", toolKey })
        {
            if (GetProperty(root, section, arrayKey) is not { ValueKind: JsonValueKind.Array } arr)
            {
                continue;
            }

            foreach (var element in arr.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var value = element.GetString();
                if (string.IsNullOrWhiteSpace(value) || !seen.Add(value))
                {
                    continue;
                }

                values.Add(canonicalizeLowercase ? value.ToLowerInvariant() : value);
            }
        }

        return values;
    }

    private static JsonElement? GetProperty(JsonElement root, string section, string key)
        => TryGetObject(root, section, out var sectionEl) && sectionEl.TryGetProperty(key, out var el) ? el : null;

    private static bool TryGetObject(JsonElement root, string section, out JsonElement element)
    {
        if (root.TryGetProperty(section, out var el) && el.ValueKind == JsonValueKind.Object)
        {
            element = el;
            return true;
        }

        element = default;
        return false;
    }
}
