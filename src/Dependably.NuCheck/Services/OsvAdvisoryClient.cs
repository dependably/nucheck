using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Dependably.NuCheck.Models;
using NuGet.Versioning;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Queries the public OSV.dev database (https://osv.dev) for NuGet-ecosystem
/// advisories. Unlike <see cref="GitHubAdvisoryClient"/> this needs no token. OSV
/// expresses affected versions as introduced/fixed/last_affected event ranges; those
/// are translated into the comparator syntax <see cref="VulnerabilityMatcher"/> already
/// understands, so the actual version matching stays in one place.
/// </summary>
public sealed class OsvAdvisoryClient : IAdvisorySource
{
    [SuppressMessage("Minor Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Constant public OSV.dev API endpoint.")]
    private const string QueryUrl = "https://api.osv.dev/v1/query";

    private const string NuGetEcosystem = "NuGet";

    // Cap any single backoff wait so a hostile or buggy Retry-After can't stall the CLI.
    private const int MaxBackoffSeconds = 60;
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(MaxBackoffSeconds);

    // Default number of retry attempts for transient failures.
    private const int DefaultMaxRetries = 3;

    private readonly HttpClient _http;
    private readonly int _maxRetries;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public OsvAdvisoryClient(
        HttpClient http,
        int maxRetries = DefaultMaxRetries,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _http = http;
        _maxRetries = Math.Max(0, maxRetries);
        _delay = delay ?? Task.Delay;
    }

    public async Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default)
    {
        var payload = JsonSerializer.Serialize(new
        {
            package = new { name = packageId, ecosystem = NuGetEcosystem },
        });

        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, QueryUrl)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json"),
            };
            request.Headers.TryAddWithoutValidation("User-Agent", "nucheck");

            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (attempt < _maxRetries && IsTransient(response.StatusCode))
            {
                await _delay(BackoffDelay(attempt, response), cancellationToken).ConfigureAwait(false);
                continue;
            }

            EnsureSuccess(response.StatusCode, body);
            return ParseOsv(body, packageId);
        }
    }

    /// <summary>Parse an OSV <c>/v1/query</c> response into advisories for the given package.</summary>
    public static IReadOnlyList<Advisory> ParseOsv(string body, string packageId)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Failed to parse OSV response for '{packageId}': {ex.Message}. " +
                $"Body (first 200 chars): {body[..Math.Min(200, body.Length)]}", ex);
        }

        using (document)
        {
            if (!document.RootElement.TryGetProperty("vulns", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            {
                return [];
            }

            var advisories = new List<Advisory>();
            foreach (var vuln in vulns.EnumerateArray())
            {
                var id = GetString(vuln, "id");
                var severity = SeverityFor(vuln);
                var summary = BuildSummary(id, vuln);
                var references = ExtractReferences(id, vuln);
                var advisoryId = ExtractAdvisoryId(id, vuln);
                var cve = ExtractCve(vuln);

                // Each affected interval carries its own "fixed" event, so the patched
                // version is tracked alongside the comparator it belongs to.
                foreach (var (range, fixedVersion) in AffectedRanges(vuln, packageId))
                {
                    advisories.Add(new Advisory(summary, severity, range, references, advisoryId, cve, fixedVersion));
                }
            }

            return advisories;
        }
    }

    /// <summary>
    /// The discrete advisory id: OSV's primary <c>id</c> when it is a GHSA, else a
    /// GHSA found among <c>aliases</c>, else the primary id (null when none).
    /// </summary>
    private static string? ExtractAdvisoryId(string id, JsonElement vuln)
    {
        if (id.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase))
        {
            return id;
        }

        var ghsa = Aliases(vuln).FirstOrDefault(a => a.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase));
        return ghsa ?? (string.IsNullOrEmpty(id) ? null : id);
    }

    /// <summary>The CVE id from OSV's <c>aliases</c> array, or null when none is listed.</summary>
    private static string? ExtractCve(JsonElement vuln)
        => Aliases(vuln).FirstOrDefault(a => a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase));

    private static IEnumerable<string> Aliases(JsonElement vuln)
    {
        if (!vuln.TryGetProperty("aliases", out var aliases) || aliases.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var alias in aliases.EnumerateArray())
        {
            if (alias.ValueKind == JsonValueKind.String)
            {
                yield return alias.GetString()!;
            }
        }
    }

    /// <summary>
    /// Yield a comparator string (per <see cref="VulnerabilityMatcher"/>) — paired with the
    /// first patched version for that interval, where OSV provides one — for every affected
    /// interval that applies to <paramref name="packageId"/> in the NuGet ecosystem.
    /// </summary>
    private static IEnumerable<(string Range, string? Fixed)> AffectedRanges(JsonElement vuln, string packageId)
    {
        if (!vuln.TryGetProperty("affected", out var affected) || affected.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return affected.EnumerateArray()
            .Where(entry => MatchesPackage(entry, packageId))
            .SelectMany(ComparatorsForAffected);
    }

    private static bool MatchesPackage(JsonElement entry, string packageId)
        => entry.TryGetProperty("package", out var package)
            && GetString(package, "ecosystem").Equals(NuGetEcosystem, StringComparison.OrdinalIgnoreCase)
            && GetString(package, "name").Equals(packageId, StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<(string Range, string? Fixed)> ComparatorsForAffected(JsonElement entry)
    {
        var fromRanges = RangeComparators(entry).ToList();

        // Fall back to explicit affected versions only when no ranges were present.
        return fromRanges.Count > 0 ? fromRanges : ExplicitVersionComparators(entry);
    }

    private static IEnumerable<(string Range, string? Fixed)> RangeComparators(JsonElement entry)
        => entry.TryGetProperty("ranges", out var ranges) && ranges.ValueKind == JsonValueKind.Array
            ? ranges.EnumerateArray().SelectMany(IntervalsFromEvents)
            : [];

    private static IEnumerable<(string Range, string? Fixed)> ExplicitVersionComparators(JsonElement entry)
        => entry.TryGetProperty("versions", out var versions) && versions.ValueKind == JsonValueKind.Array
            ? versions.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => ($"= {v.GetString()}", (string?)null))
            : [];

    /// <summary>
    /// Translate an OSV range's introduced/fixed/last_affected events into comparator
    /// strings, carrying the <c>fixed</c> version of each interval as its patched version.
    /// </summary>
    private static IEnumerable<(string Range, string? Fixed)> IntervalsFromEvents(JsonElement range)
    {
        // Only version-ordered ranges are comparable with NuGet.Versioning.
        var type = GetString(range, "type");
        if (!type.Equals("ECOSYSTEM", StringComparison.OrdinalIgnoreCase)
            && !type.Equals("SEMVER", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        if (!range.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        // The OSV evaluation algorithm sorts a range's events by version before pairing
        // introduced/fixed, because the events array is not guaranteed to be ordered.
        return PairIntervals(OrderedEvents(events));
    }

    private enum EventKind
    {
        Introduced,
        Fixed,
        LastAffected,
    }

    private readonly record struct RangeEvent(EventKind Kind, string? Version);

    /// <summary>Parse a range's events into a version-sorted list (per the OSV algorithm).</summary>
    private static List<RangeEvent> OrderedEvents(JsonElement events)
    {
        var parsed = new List<RangeEvent>();
        foreach (var ev in events.EnumerateArray())
        {
            if (ev.TryGetProperty("introduced", out var introduced))
            {
                parsed.Add(new RangeEvent(EventKind.Introduced, introduced.GetString()));
            }
            else if (ev.TryGetProperty("fixed", out var fixedVersion))
            {
                parsed.Add(new RangeEvent(EventKind.Fixed, fixedVersion.GetString()));
            }
            else if (ev.TryGetProperty("last_affected", out var lastAffected))
            {
                parsed.Add(new RangeEvent(EventKind.LastAffected, lastAffected.GetString()));
            }
        }

        parsed.Sort(CompareEvents);
        return parsed;
    }

    private static int CompareEvents(RangeEvent left, RangeEvent right)
    {
        var byVersion = CompareVersions(left.Version, right.Version);

        // At the same version, order introduced before fixed/last_affected so an interval
        // that both opens and closes on one version resolves to an empty (non-)range.
        return byVersion != 0 ? byVersion : ((int)left.Kind).CompareTo((int)right.Kind);
    }

    private static int CompareVersions(string? left, string? right)
    {
        var leftVersion = ParseOrNull(left);
        var rightVersion = ParseOrNull(right);

        // OSV's "0" sentinel and any unparseable value sort first (the range's start).
        if (leftVersion is null)
        {
            return rightVersion is null ? 0 : -1;
        }

        return rightVersion is null ? 1 : leftVersion.CompareTo(rightVersion);
    }

    private static NuGetVersion? ParseOrNull(string? version)
        => version is not null && version != "0" && NuGetVersion.TryParse(version, out var parsed) ? parsed : null;

    /// <summary>
    /// Walk the version-sorted events, pairing each <c>introduced</c> with the next
    /// <c>fixed</c>/<c>last_affected</c>. A redundant <c>introduced</c> that arrives while an
    /// interval is already open is ignored: within one range the lowest introduced wins until
    /// a fix closes it (per the OSV timeline), so keeping the earliest lower bound avoids both
    /// dropping the interval and over-reporting versions past the eventual fix.
    /// </summary>
    private static IEnumerable<(string Range, string? Fixed)> PairIntervals(List<RangeEvent> events)
    {
        string? lower = null;
        var open = false;
        foreach (var ev in events)
        {
            switch (ev.Kind)
            {
                case EventKind.Introduced:
                    if (!open)
                    {
                        lower = ev.Version;
                        open = true;
                    }

                    break;
                case EventKind.Fixed:
                    yield return (Comparator(lower, ev.Version, upperInclusive: false), ev.Version);
                    open = false;
                    lower = null;
                    break;
                case EventKind.LastAffected:
                    // last_affected gives an upper bound but is NOT the patched version.
                    yield return (Comparator(lower, ev.Version, upperInclusive: true), null);
                    open = false;
                    lower = null;
                    break;
            }
        }

        if (open)
        {
            yield return (Comparator(lower, upper: null, upperInclusive: false), null);
        }
    }

    private static string Comparator(string? lower, string? upper, bool upperInclusive)
    {
        var parts = new List<string>(2);

        // "0" is OSV's "from the beginning" sentinel — it adds no real lower bound.
        if (!string.IsNullOrEmpty(lower) && lower != "0")
        {
            parts.Add($">= {lower}");
        }

        if (!string.IsNullOrEmpty(upper))
        {
            parts.Add($"{(upperInclusive ? "<=" : "<")} {upper}");
        }

        // No bounds at all means every version is affected.
        return parts.Count == 0 ? ">= 0.0.0" : string.Join(", ", parts);
    }

    private static string BuildSummary(string id, JsonElement vuln)
    {
        var summary = GetString(vuln, "summary");
        if (string.IsNullOrWhiteSpace(summary))
        {
            return string.IsNullOrEmpty(id) ? "(no summary)" : id;
        }

        return string.IsNullOrEmpty(id) ? summary : $"{id}: {summary}";
    }

    private static List<string> ExtractReferences(string id, JsonElement vuln)
    {
        var references = new List<string>();
        if (!string.IsNullOrEmpty(id))
        {
            references.Add($"https://osv.dev/vulnerability/{id}");
        }

        if (vuln.TryGetProperty("references", out var refs) && refs.ValueKind == JsonValueKind.Array)
        {
            foreach (var reference in refs.EnumerateArray())
            {
                if (reference.TryGetProperty("url", out var url) && url.ValueKind == JsonValueKind.String)
                {
                    references.Add(url.GetString()!);
                }
            }
        }

        return references;
    }

    private static string NormalizeSeverity(string severity)
    {
        var normalized = severity.ToLowerInvariant();
        return normalized switch
        {
            "medium" => "moderate",
            "" => "unknown",
            _ => normalized,
        };
    }

    /// <summary>
    /// Prefer OSV's GHSA-specific <c>database_specific.severity</c> label; when it is absent,
    /// fall back to the schema's top-level <c>severity[]</c> CVSS array, deriving a band from
    /// the highest-priority CVSS score available.
    /// </summary>
    private static string SeverityFor(JsonElement vuln)
    {
        var labelled = NormalizeSeverity(GetNestedString(vuln, "database_specific", "severity"));
        return labelled != "unknown" ? labelled : CvssSeverity(vuln);
    }

    // OSV CVSS score types, most-recent first: a v4 score is preferred over v3, then v2.
    private static readonly string[] CvssTypePreference = ["CVSS_V4", "CVSS_V3", "CVSS_V2"];

    private static string CvssSeverity(JsonElement vuln)
    {
        if (!vuln.TryGetProperty("severity", out var severities) || severities.ValueKind != JsonValueKind.Array)
        {
            return "unknown";
        }

        var score = BestCvssScore(severities);
        return score is null ? "unknown" : SeverityBand(score.Value);
    }

    private static double? BestCvssScore(JsonElement severities)
    {
        foreach (var type in CvssTypePreference)
        {
            foreach (var entry in severities.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object
                    && GetString(entry, "type").Equals(type, StringComparison.OrdinalIgnoreCase)
                    && TryCvssScore(GetString(entry, "score"), out var score))
                {
                    return score;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Read a CVSS base score from an OSV <c>score</c> string: either a bare numeric value
    /// (e.g. "9.8") or a CVSS v3.x vector string, from which the base score is computed.
    /// </summary>
    private static bool TryCvssScore(string score, out double value)
    {
        if (double.TryParse(score, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
        {
            return true;
        }

        return TryComputeCvssV3BaseScore(score, out value);
    }

    private static string SeverityBand(double score) => score switch
    {
        >= 9.0 => "critical",
        >= 7.0 => "high",
        >= 4.0 => "moderate",
        > 0.0 => "low",
        _ => "unknown",
    };

    private static bool TryComputeCvssV3BaseScore(string vector, out double score)
    {
        score = 0;
        if (!vector.StartsWith("CVSS:3", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var metrics = ParseVectorMetrics(vector);
        if (!metrics.TryGetValue("AV", out var av) || !metrics.TryGetValue("AC", out var ac)
            || !metrics.TryGetValue("PR", out var pr) || !metrics.TryGetValue("UI", out var ui)
            || !metrics.TryGetValue("S", out var s) || !metrics.TryGetValue("C", out var c)
            || !metrics.TryGetValue("I", out var i) || !metrics.TryGetValue("A", out var a))
        {
            return false;
        }

        var scopeChanged = s.Equals("C", StringComparison.OrdinalIgnoreCase);
        score = CvssV3BaseScore(av, ac, pr, ui, c, i, a, scopeChanged);
        return true;
    }

    private static Dictionary<string, string> ParseVectorMetrics(string vector)
    {
        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in vector.Split('/'))
        {
            var kv = part.Split(':', 2);
            if (kv.Length == 2)
            {
                metrics[kv[0]] = kv[1];
            }
        }

        return metrics;
    }

    private static double CvssV3BaseScore(
        string av, string ac, string pr, string ui, string c, string i, string a, bool scopeChanged)
    {
        var iss = 1 - ((1 - ImpactWeight(c)) * (1 - ImpactWeight(i)) * (1 - ImpactWeight(a)));
        var impact = scopeChanged
            ? (7.52 * (iss - 0.029)) - (3.25 * Math.Pow(iss - 0.02, 15))
            : 6.42 * iss;
        if (impact <= 0)
        {
            return 0;
        }

        var exploitability = 8.22 * AttackVectorWeight(av) * AttackComplexityWeight(ac)
            * PrivilegesRequiredWeight(pr, scopeChanged) * UserInteractionWeight(ui);
        var raw = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
        return RoundUp(Math.Min(raw, 10));
    }

    private static double ImpactWeight(string metric) => metric.ToUpperInvariant() switch
    {
        "H" => 0.56,
        "L" => 0.22,
        _ => 0.0,
    };

    private static double AttackVectorWeight(string metric) => metric.ToUpperInvariant() switch
    {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => 0.0,
    };

    private static double AttackComplexityWeight(string metric)
        => metric.Equals("H", StringComparison.OrdinalIgnoreCase) ? 0.44 : 0.77;

    private static double PrivilegesRequiredWeight(string metric, bool scopeChanged) => metric.ToUpperInvariant() switch
    {
        "L" => scopeChanged ? 0.68 : 0.62,
        "H" => scopeChanged ? 0.5 : 0.27,
        _ => 0.85,
    };

    private static double UserInteractionWeight(string metric)
        => metric.Equals("R", StringComparison.OrdinalIgnoreCase) ? 0.62 : 0.85;

    // CVSS v3.1 "Roundup": round up to one decimal place.
    private static double RoundUp(double value)
    {
        var intInput = (int)Math.Round(value * 100000, MidpointRounding.AwayFromZero);
        return intInput % 10000 == 0
            ? intInput / 100000.0
            : (Math.Floor(intInput / 10000.0) + 1) / 10.0;
    }

    private static string GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : string.Empty;

    private static string GetNestedString(JsonElement element, string outer, string inner)
        => element.TryGetProperty(outer, out var nested) && nested.ValueKind == JsonValueKind.Object
            ? GetString(nested, inner)
            : string.Empty;

    private static bool IsTransient(HttpStatusCode status)
        => status == HttpStatusCode.TooManyRequests || (int)status >= (int)HttpStatusCode.InternalServerError;

    /// <summary>
    /// For 429 responses, honor the server's <c>Retry-After</c> header (delta or date form)
    /// capped at <see cref="MaxBackoff"/>; otherwise fall back to exponential backoff.
    /// </summary>
    private static TimeSpan BackoffDelay(int attempt, HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            var headerWait = ReadRetryAfterDelay(response);
            if (headerWait > TimeSpan.Zero)
            {
                return headerWait < MaxBackoff ? headerWait : MaxBackoff;
            }
        }

        return RetryDelay(attempt);
    }

    private static TimeSpan ReadRetryAfterDelay(HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter;
        if (retryAfter?.Delta is { } delta)
        {
            return delta;
        }

        if (retryAfter?.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
        }

        return TimeSpan.Zero;
    }

    // Exponential backoff starting at 4 s (2^(attempt+2)): 4 s / 8 s / 16 s = 28 s total
    // across the default 3 retries, well inside the typical OSV 429 rate-limit window.
    private static TimeSpan RetryDelay(int attempt)
    {
        var backoff = TimeSpan.FromSeconds(Math.Pow(2, attempt + 2));
        return backoff < MaxBackoff ? backoff : MaxBackoff;
    }

    private static void EnsureSuccess(HttpStatusCode status, string body)
    {
        if ((int)status is < (int)HttpStatusCode.OK or >= (int)HttpStatusCode.MultipleChoices)
        {
            var trimmed = body.Trim();
            const int maxBody = 500;
            if (trimmed.Length > maxBody)
            {
                trimmed = trimmed[..maxBody] + "…";
            }

            var detail = trimmed.Length == 0 ? string.Empty : $": {trimmed}";
            throw new InvalidOperationException($"OSV API request failed (HTTP {(int)status} {status}){detail}");
        }
    }
}
