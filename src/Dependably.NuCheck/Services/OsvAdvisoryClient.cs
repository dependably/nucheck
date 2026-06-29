using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using Dependably.NuCheck.Models;

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
                await _delay(RetryDelay(attempt), cancellationToken).ConfigureAwait(false);
                continue;
            }

            EnsureSuccess(response.StatusCode, body);
            return ParseOsv(body, packageId);
        }
    }

    /// <summary>Parse an OSV <c>/v1/query</c> response into advisories for the given package.</summary>
    public static IReadOnlyList<Advisory> ParseOsv(string body, string packageId)
    {
        using var document = JsonDocument.Parse(body);
        if (!document.RootElement.TryGetProperty("vulns", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var advisories = new List<Advisory>();
        foreach (var vuln in vulns.EnumerateArray())
        {
            var id = GetString(vuln, "id");
            var severity = NormalizeSeverity(GetNestedString(vuln, "database_specific", "severity"));
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
            yield break;
        }

        if (!range.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        string? lower = null;
        var open = false;
        foreach (var ev in events.EnumerateArray())
        {
            if (ev.TryGetProperty("introduced", out var introduced))
            {
                lower = introduced.GetString();
                open = true;
            }
            else if (ev.TryGetProperty("fixed", out var fixedVersion))
            {
                var fix = fixedVersion.GetString();
                yield return (Comparator(lower, fix, upperInclusive: false), fix);
                open = false;
                lower = null;
            }
            else if (ev.TryGetProperty("last_affected", out var lastAffected))
            {
                // last_affected gives an upper bound but is NOT the patched version.
                yield return (Comparator(lower, lastAffected.GetString(), upperInclusive: true), null);
                open = false;
                lower = null;
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

    private static TimeSpan RetryDelay(int attempt)
    {
        var backoff = TimeSpan.FromSeconds(Math.Pow(2, attempt));
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
