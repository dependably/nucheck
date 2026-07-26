using System.Text.Json;
using System.Text.RegularExpressions;

namespace Dependably.NuCheck.Config;

/// <summary>
/// Raised when an <c>exceptions</c> entry in <c>.dependably</c> is malformed. Carries a
/// stable <see cref="Code"/> matching the shared spec — docs/dependably-config-spec.md §10 in
/// https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec — so the cross-language
/// conformance fixtures assert the same codes in every tool.
/// </summary>
public sealed class DependablyConfigException : Exception
{
    public DependablyConfigException(string message, string code) : base(message) => Code = code;

    public string Code { get; }
}

/// <summary>A finding to test against exceptions: a rule id plus whatever selectors it carries.</summary>
public readonly record struct ExceptionTarget(
    string Rule,
    string? Package = null,
    string? Version = null,
    string? Path = null,
    string? Symbol = null,
    string? Id = null);

/// <summary>
/// One parsed <c>.dependably</c> exception (spec §6): a rule id, at least one selector
/// (<c>package</c>/<c>path</c>/<c>symbol</c>/<c>id</c>), a mandatory <c>reason</c>, and an
/// optional <c>expires</c> date. A <c>package</c> selector may pin a version with an
/// <c>@&lt;version&gt;</c> suffix.
/// </summary>
public sealed record DependablyException(
    string Rule,
    string Reason,
    string Source,
    string? PackageName = null,
    string? PackageVersion = null,
    string? Path = null,
    string? Symbol = null,
    string? Id = null,
    DateOnly? Expires = null);

/// <summary>
/// Reference-parity port of npm-check's <c>src/exceptions.js</c>: parse/validate exception
/// entries and match findings. Kept behaviour-compatible with the shared conformance
/// fixtures under <c>conformance/dependably/</c>.
/// </summary>
public static class DependablyExceptions
{
    /// <summary>The four finding selectors, in a stable order for messages.</summary>
    public static readonly string[] Selectors = ["package", "path", "symbol", "id"];

    /// <summary>Selectors an nucheck finding can carry (spec §6.7).</summary>
    public static readonly string[] NuCheckSelectors = ["package", "id"];

    /// <summary>Rule ids nucheck emits (for own-section unknown-rule validation).</summary>
    public static readonly string[] KnownRules =
        ["vulnerable-package", "untrusted-source", "untrusted-local-feed", "unused-packages", "unverifiable-advisory", "pinned-versions"];

    private static readonly Regex ExpiresPattern = new(@"^\d{4}-\d{2}-\d{2}$", RegexOptions.Compiled);

    /// <summary>
    /// Parse and validate an <c>exceptions</c> array element.
    /// </summary>
    /// <param name="arrayElement">the <c>exceptions</c> JSON value (may be absent/undefined)</param>
    /// <param name="source"><c>own</c> enforces selector applicability + rule ids; <c>common</c> tolerates both.</param>
    /// <param name="applicableSelectors">selectors this tool's findings carry</param>
    /// <param name="knownRules">rule ids valid in the own section; null skips the check</param>
    public static IReadOnlyList<DependablyException> Parse(
        JsonElement? arrayElement,
        string source,
        IReadOnlyCollection<string> applicableSelectors,
        IReadOnlyCollection<string>? knownRules)
    {
        if (arrayElement is not { } el || el.ValueKind == JsonValueKind.Null || el.ValueKind == JsonValueKind.Undefined)
        {
            return [];
        }

        if (el.ValueKind != JsonValueKind.Array)
        {
            throw new DependablyConfigException("exceptions must be an array", "INVALID_EXCEPTIONS");
        }

        var result = new List<DependablyException>();
        var index = 0;
        foreach (var entry in el.EnumerateArray())
        {
            result.Add(ParseEntry(entry, index++, source, applicableSelectors, knownRules));
        }

        return result;
    }

    private static DependablyException ParseEntry(
        JsonElement entry,
        int index,
        string source,
        IReadOnlyCollection<string> applicableSelectors,
        IReadOnlyCollection<string>? knownRules)
    {
        if (entry.ValueKind != JsonValueKind.Object)
        {
            throw new DependablyConfigException($"exception #{index} must be an object", "INVALID_EXCEPTIONS");
        }

        var rule = GetString(entry, "rule");
        if (string.IsNullOrWhiteSpace(rule))
        {
            throw new DependablyConfigException($"exception #{index} is missing \"rule\"", "EXCEPTION_MISSING_RULE");
        }

        var reason = GetString(entry, "reason");
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DependablyConfigException(
                $"exception for rule \"{rule}\" is missing a non-empty \"reason\"", "EXCEPTION_MISSING_REASON");
        }

        ValidateSelectors(entry, rule!, source, applicableSelectors);

        var expires = ParseExpires(entry, rule!);

        if (source == "own" && knownRules is not null && !knownRules.Contains(rule))
        {
            throw new DependablyConfigException(
                $"Unknown rule \"{rule}\" in exception (known rules: {string.Join(", ", knownRules)})", "UNKNOWN_RULE");
        }

        string? packageName = null;
        string? packageVersion = null;
        if (entry.TryGetProperty("package", out _))
        {
            (packageName, packageVersion) = SplitPackage(GetString(entry, "package")!);
        }

        return new DependablyException(
            Rule: rule!,
            Reason: reason!,
            Source: source,
            PackageName: packageName,
            PackageVersion: packageVersion,
            Path: entry.TryGetProperty("path", out _) ? GetString(entry, "path") : null,
            Symbol: entry.TryGetProperty("symbol", out _) ? GetString(entry, "symbol") : null,
            Id: entry.TryGetProperty("id", out _) ? GetString(entry, "id") : null,
            Expires: expires);
    }

    /// <summary>
    /// Validates the selector properties present on an exception entry (spec §6.3-§6.4): at
    /// least one selector must be present, each present selector must be a non-empty string,
    /// and (for the tool's own section) each must be applicable to this tool's findings.
    /// </summary>
    private static void ValidateSelectors(
        JsonElement entry, string rule, string source, IReadOnlyCollection<string> applicableSelectors)
    {
        var present = Selectors.Where(s => entry.TryGetProperty(s, out _)).ToList();
        if (present.Count == 0)
        {
            throw new DependablyConfigException(
                $"exception for rule \"{rule}\" needs at least one selector ({string.Join(", ", Selectors)})",
                "EXCEPTION_NO_SELECTOR");
        }

        foreach (var sel in present)
        {
            var value = GetString(entry, sel);
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new DependablyConfigException(
                    $"exception selector \"{sel}\" for rule \"{rule}\" must be a non-empty string", "EXCEPTION_BAD_SELECTOR");
            }

            if (source == "own" && !applicableSelectors.Contains(sel))
            {
                throw new DependablyConfigException(
                    $"exception selector \"{sel}\" is not applicable to this tool (applicable: {string.Join(", ", applicableSelectors)})",
                    "EXCEPTION_BAD_SELECTOR");
            }
        }
    }

    /// <summary>Parses the optional <c>expires</c> date (spec §6.5); returns null when absent.</summary>
    private static DateOnly? ParseExpires(JsonElement entry, string rule)
    {
        if (!entry.TryGetProperty("expires", out var expEl))
        {
            return null;
        }

        var raw = expEl.ValueKind == JsonValueKind.String ? expEl.GetString() : null;
        if (raw is null || !ExpiresPattern.IsMatch(raw) || !DateOnly.TryParse(raw, out var parsed))
        {
            throw new DependablyConfigException(
                $"exception \"expires\" for rule \"{rule}\" must be a valid YYYY-MM-DD date", "EXCEPTION_BAD_EXPIRES");
        }

        return parsed;
    }

    /// <summary>Split a <c>package</c> selector into (name, version?) — version from an <c>@&lt;version&gt;</c> suffix.</summary>
    private static (string name, string? version) SplitPackage(string pkg)
    {
        var at = pkg.LastIndexOf('@');
        if (at > 0)
        {
            return (pkg[..at].ToLowerInvariant(), pkg[(at + 1)..]);
        }

        return (pkg.ToLowerInvariant(), null);
    }

    /// <summary>True when <paramref name="ex"/> has an <c>expires</c> date strictly before <paramref name="today"/>.</summary>
    public static bool IsExpired(DependablyException ex, DateOnly today)
        => ex.Expires is { } e && today > e;

    /// <summary>True when every selector present on <paramref name="ex"/> matches <paramref name="target"/> (AND).</summary>
    public static bool Matches(DependablyException ex, ExceptionTarget target)
    {
        if (ex.Rule != target.Rule)
        {
            return false;
        }

        if (ex.PackageName is not null)
        {
            if (!string.Equals(ex.PackageName, target.Package, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (ex.PackageVersion is not null && ex.PackageVersion != target.Version)
            {
                return false;
            }
        }

        if (ex.Path is not null && (target.Path is null || !MatchGlob(ex.Path, target.Path)))
        {
            return false;
        }

        if (ex.Symbol is not null && !MatchesSymbol(ex.Symbol, target.Symbol))
        {
            return false;
        }

        return ex.Id is null || ex.Id == target.Id;
    }

    private static bool MatchesSymbol(string selector, string? findingSymbol)
        => findingSymbol is not null && (findingSymbol == selector || findingSymbol.StartsWith($"{selector}.", StringComparison.Ordinal));

    /// <summary>Match a POSIX-style path against a portable glob (<c>**</c>, <c>*</c>, <c>?</c>).</summary>
    public static bool MatchGlob(string glob, string value)
        => GlobToRegex(glob).IsMatch(value.Replace('\\', '/'));

    private static Regex GlobToRegex(string glob)
    {
        var sb = new System.Text.StringBuilder("^");
        var i = 0;
        while (i < glob.Length)
        {
            var c = glob[i];
            if (c == '*' && i + 1 < glob.Length && glob[i + 1] == '*')
            {
                if (i + 2 < glob.Length && glob[i + 2] == '/')
                {
                    sb.Append("(?:.*/)?");
                    i += 3;
                }
                else if (sb.Length >= 1 && sb[^1] == '/')
                {
                    sb.Length -= 1;
                    sb.Append("(?:/.*)?");
                    i += 2;
                }
                else
                {
                    sb.Append(".*");
                    i += 2;
                }
            }
            else if (c == '*')
            {
                sb.Append("[^/]*");
                i++;
            }
            else if (c == '?')
            {
                sb.Append("[^/]");
                i++;
            }
            else
            {
                sb.Append(Regex.Escape(c.ToString()));
                i++;
            }
        }

        sb.Append('$');
        return new Regex(sb.ToString(), RegexOptions.None, TimeSpan.FromSeconds(1));
    }

    private static string? GetString(JsonElement obj, string key)
        => obj.TryGetProperty(key, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;
}
