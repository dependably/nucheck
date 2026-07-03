using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Queries the GitHub Advisory Database for NuGet-ecosystem advisories. Uses the
/// GraphQL <c>securityVulnerabilities</c> API by default, or the REST advisories
/// API when <c>useRest</c> is set. Severities are normalised to the GraphQL vocabulary
/// (critical/high/moderate/low) so a <c>--severity</c> filter matches regardless of the
/// API's casing or its "medium" vs "moderate" spelling.
/// </summary>
public sealed class GitHubAdvisoryClient : IAdvisorySource
{
    // Fixed, well-known public GitHub API endpoints — not environment-specific, so
    // the "don't hardcode URIs" rule (S1075) does not meaningfully apply here.
    [SuppressMessage("Minor Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Constant public GitHub API endpoint.")]
    private const string GraphQlUrl = "https://api.github.com/graphql";

    [SuppressMessage("Minor Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Constant public GitHub API endpoint.")]
    private const string RestUrl = "https://api.github.com/advisories";

    // Cap any single backoff wait so a hostile or buggy Retry-After can't stall the CLI.
    private const int MaxBackoffSeconds = 60;
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(MaxBackoffSeconds);

    // Cap how much of an API error body is echoed into an exception message.
    private const int MaxErrorBodyLength = 500;

    // Default number of retry attempts for transient failures.
    private const int DefaultMaxRetries = 3;

    // Safety cap on GraphQL cursor pagination so a buggy or hostile API that never
    // clears hasNextPage (or never advances the cursor) can't loop the CLI forever.
    private const int MaxGraphQlPages = 1000;

    // Safety cap on REST Link-header pagination so a buggy or hostile API that always
    // returns a Link: rel="next" header (self-referencing or otherwise) can't loop
    // the CLI forever.
    private const int MaxRestPages = 1000;

    private readonly HttpClient _http;
    private readonly string _token;
    private readonly bool _useRest;
    private readonly int _maxRetries;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public GitHubAdvisoryClient(
        HttpClient http,
        string token,
        bool useRest = false,
        int maxRetries = DefaultMaxRetries,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _http = http;
        _token = token;
        _useRest = useRest;
        _maxRetries = Math.Max(0, maxRetries);
        _delay = delay ?? Task.Delay;
    }

    /// <inheritdoc />
    public string DisplayName => "the GitHub Advisory Database";

    public Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default)
        => _useRest ? QueryRestAsync(packageId, cancellationToken) : QueryGraphQlAsync(packageId, cancellationToken);

    /// <summary>
    /// Follow GraphQL cursor pagination for <c>securityVulnerabilities</c>. The API returns
    /// at most 100 nodes per page, so a package with more advisories than that would otherwise
    /// be silently truncated. Loop while <c>pageInfo.hasNextPage</c> is set, passing the
    /// <c>endCursor</c> as the <c>after:</c> argument, and accumulate results across pages.
    /// </summary>
    private async Task<IReadOnlyList<Advisory>> QueryGraphQlAsync(string packageId, CancellationToken cancellationToken)
    {
        var escaped = packageId.Replace("\\", "\\\\").Replace("\"", "\\\"");
        var advisories = new List<Advisory>();
        string? cursor = null;

        for (var page = 0; page < MaxGraphQlPages; page++)
        {
            var query = BuildGraphQlQuery(escaped, cursor);
            var body = await SendGraphQlAsync(query, cancellationToken).ConfigureAwait(false);
            var (pageAdvisories, hasNextPage, endCursor) = ParseGraphQlPage(body);

            advisories.AddRange(pageAdvisories);
            if (!hasNextPage || string.IsNullOrEmpty(endCursor))
            {
                break;
            }

            cursor = endCursor;
        }

        return advisories;
    }

    private Task<string> SendGraphQlAsync(string query, CancellationToken cancellationToken)
        => SendWithRetryAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, GraphQlUrl)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { query }), Encoding.UTF8, "application/json"),
            };
            AddHeaders(request);
            return request;
        }, cancellationToken);

    /// <summary>Build the securityVulnerabilities query, adding an <c>after:</c> cursor for pages after the first.</summary>
    private static string BuildGraphQlQuery(string escapedPackage, string? afterCursor)
    {
        var escapedCursor = afterCursor?.Replace("\\", "\\\\").Replace("\"", "\\\"");
        var after = string.IsNullOrEmpty(escapedCursor) ? string.Empty : $", after: \"{escapedCursor}\"";
        return
            "{ securityVulnerabilities(first: 100" + after + ", ecosystem: NUGET, package: \"" + escapedPackage + "\") " +
            "{ nodes { advisory { ghsaId summary severity identifiers { type value } references { url } } " +
            "firstPatchedVersion { identifier } vulnerableVersionRange } pageInfo { hasNextPage endCursor } } }";
    }

    /// <summary>
    /// Follow Link-header pagination for the REST advisories API. GitHub returns at most
    /// <c>per_page</c> items per response (default 30, max 100). When more pages exist the
    /// response carries a <c>Link: &lt;url&gt;; rel="next"</c> header. Loop until no next
    /// URL is present, accumulating advisories from all pages.
    /// </summary>
    private async Task<IReadOnlyList<Advisory>> QueryRestAsync(string packageId, CancellationToken cancellationToken)
    {
        string? url = $"{RestUrl}?ecosystem=nuget&affects={Uri.EscapeDataString(packageId)}&per_page=100";
        var advisories = new List<Advisory>();

        for (var page = 0; page < MaxRestPages && url is not null; page++)
        {
            string? nextUrl = null;
            var pageUrl = url;
            var body = await SendWithRetryAsync(
                () =>
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, pageUrl);
                    AddHeaders(request);
                    return request;
                },
                cancellationToken,
                onSuccess: response => nextUrl = ExtractLinkNext(response)).ConfigureAwait(false);

            advisories.AddRange(ParseRest(body, packageId));
            url = nextUrl;
        }

        return advisories;
    }

    /// <summary>
    /// Extract the URL for <c>rel="next"</c> from the <c>Link</c> response header, or null
    /// when absent. GitHub paginates REST advisory results with this header.
    /// </summary>
    private static string? ExtractLinkNext(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Link", out var values))
        {
            return null;
        }

        foreach (var header in values)
        {
            foreach (var part in header.Split(','))
            {
                var trimmed = part.Trim();
                if (!trimmed.EndsWith("; rel=\"next\"", StringComparison.Ordinal))
                {
                    continue;
                }

                var semicolon = trimmed.LastIndexOf(';');
                var urlPart = trimmed[..semicolon].Trim();
                if (urlPart.StartsWith('<') && urlPart.EndsWith('>'))
                {
                    return urlPart[1..^1];
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Send a request, retrying transient failures — HTTP 429, 5xx, and the secondary
    /// rate-limit 403 — with a Retry-After-aware exponential backoff. The request is
    /// rebuilt per attempt (an <see cref="HttpRequestMessage"/> can only be sent once).
    /// On the final attempt the response is validated by <see cref="EnsureSuccess"/>,
    /// so a persistent failure surfaces loudly rather than as an empty advisory list.
    /// <paramref name="onSuccess"/> is invoked with the live response before it is disposed,
    /// allowing callers to capture response headers (e.g. the <c>Link</c> pagination header).
    /// </summary>
    private async Task<string> SendWithRetryAsync(
        Func<HttpRequestMessage> createRequest,
        CancellationToken cancellationToken,
        Action<HttpResponseMessage>? onSuccess = null)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = createRequest();
            try
            {
                using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
                var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

                if (attempt < _maxRetries && IsTransient(response))
                {
                    await _delay(RetryDelay(response, attempt), cancellationToken).ConfigureAwait(false);
                    continue;
                }

                EnsureSuccess(response.StatusCode, body);
                onSuccess?.Invoke(response);
                return body;
            }
            catch (HttpRequestException) when (attempt < _maxRetries)
            {
                // Network-level failure (DNS, TCP reset, TLS handshake, timeout) — treat
                // as transient and retry with exponential backoff. CancellationToken
                // cancellations are not HttpRequestException so they propagate normally.
                var networkBackoff = TimeSpan.FromSeconds(Math.Pow(2, attempt));
                await _delay(networkBackoff < MaxBackoff ? networkBackoff : MaxBackoff, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Whether a response is worth retrying: rate limits and server errors.</summary>
    private static bool IsTransient(HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.TooManyRequests
            || (int)response.StatusCode >= (int)HttpStatusCode.InternalServerError)
        {
            return true;
        }

        // GitHub signals a secondary rate limit with 403 plus Retry-After or an
        // exhausted x-ratelimit-remaining; a plain 403 (bad scope) is not retryable.
        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            return response.Headers.RetryAfter is not null
                || (response.Headers.TryGetValues("x-ratelimit-remaining", out var remaining)
                    && remaining.FirstOrDefault() == "0");
        }

        return false;
    }

    /// <summary>Honour Retry-After when present, else exponential backoff (1s, 2s, 4s …), capped.</summary>
    private static TimeSpan RetryDelay(HttpResponseMessage response, int attempt)
    {
        var retryAfter = response.Headers.RetryAfter;

        // delta-seconds form: Retry-After: 30
        if (retryAfter?.Delta is { } delta && delta > TimeSpan.Zero)
        {
            return delta < MaxBackoff ? delta : MaxBackoff;
        }

        // HTTP-date form: Retry-After: Wed, 01 Jul 2026 12:00:00 GMT
        if (retryAfter?.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            if (wait > TimeSpan.Zero)
            {
                return wait < MaxBackoff ? wait : MaxBackoff;
            }
        }

        var backoff = TimeSpan.FromSeconds(Math.Pow(2, attempt));
        return backoff < MaxBackoff ? backoff : MaxBackoff;
    }

    /// <summary>Parse a GraphQL securityVulnerabilities response body into advisories.</summary>
    /// <remarks>
    /// A GraphQL response can carry HTTP 200 yet still have failed (e.g. a rate-limited
    /// or malformed query returns <c>data: null</c> with an <c>errors</c> array). Treat
    /// that as a hard failure rather than "no vulnerabilities" — otherwise a failed query
    /// is indistinguishable from a clean result and the audit silently passes.
    /// </remarks>
    public static IReadOnlyList<Advisory> ParseGraphQl(string body) => ParseGraphQlPage(body).Advisories;

    /// <summary>Parse a single GraphQL page into its advisories plus the pageInfo cursor state.</summary>
    private static GraphQlPage ParseGraphQlPage(string body)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("GitHub GraphQL API returned an unparseable response.", ex);
        }

        using (document)
        {
            return ParseGraphQlDocument(document);
        }
    }

    private static GraphQlPage ParseGraphQlDocument(JsonDocument document)
    {
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                $"GitHub GraphQL API returned an unexpected response (root is {document.RootElement.ValueKind}).");
        }

        ThrowOnGraphQlErrors(document.RootElement);

        if (!TryGetSecurityVulnerabilities(document.RootElement, out var sv)
            || !sv.TryGetProperty("nodes", out var nodes) || nodes.ValueKind != JsonValueKind.Array)
        {
            return new GraphQlPage([], false, null);
        }

        var (hasNextPage, endCursor) = ParsePageInfo(sv);
        return new GraphQlPage(ParseAdvisoryNodes(nodes), hasNextPage, endCursor);
    }

    private static void ThrowOnGraphQlErrors(JsonElement root)
    {
        if (root.TryGetProperty("errors", out var errors)
            && errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0)
        {
            var messages = string.Join("; ", errors.EnumerateArray().Select(e => GetString(e, "message")));
            throw new InvalidOperationException($"GitHub GraphQL API returned errors: {messages}");
        }
    }

    private static bool TryGetSecurityVulnerabilities(JsonElement root, out JsonElement securityVulnerabilities)
    {
        securityVulnerabilities = default;
        if (!root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object
            || !data.TryGetProperty("securityVulnerabilities", out var sv) || sv.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        securityVulnerabilities = sv;
        return true;
    }

    private static List<Advisory> ParseAdvisoryNodes(JsonElement nodes)
    {
        var advisories = new List<Advisory>();
        foreach (var node in nodes.EnumerateArray())
        {
            if (!node.TryGetProperty("advisory", out var advisory))
            {
                continue;
            }

            advisories.Add(new Advisory(
                GetString(advisory, "summary"),
                NormalizeSeverity(GetString(advisory, "severity")),
                GetString(node, "vulnerableVersionRange"),
                ExtractReferences(advisory),
                NullIfEmpty(GetString(advisory, "ghsaId")),
                ExtractCveFromIdentifiers(advisory),
                ExtractFirstPatched(node)));
        }

        return advisories;
    }

    /// <summary>Read <c>pageInfo { hasNextPage endCursor }</c>, defaulting to no further pages when absent.</summary>
    private static (bool HasNextPage, string? EndCursor) ParsePageInfo(JsonElement securityVulnerabilities)
    {
        if (!securityVulnerabilities.TryGetProperty("pageInfo", out var pageInfo) || pageInfo.ValueKind != JsonValueKind.Object)
        {
            return (false, null);
        }

        var hasNextPage = pageInfo.TryGetProperty("hasNextPage", out var next) && next.ValueKind == JsonValueKind.True;
        return (hasNextPage, NullIfEmpty(GetString(pageInfo, "endCursor")));
    }

    /// <summary>A parsed GraphQL page: its advisories plus the cursor state for fetching the next one.</summary>
    private readonly record struct GraphQlPage(IReadOnlyList<Advisory> Advisories, bool HasNextPage, string? EndCursor);

    /// <summary>
    /// Parse a REST advisories response body into advisories, emitting one <see cref="Advisory"/>
    /// per matching <c>vulnerabilities[]</c> entry. A single GitHub advisory routinely carries
    /// multiple entries for the same package — one per affected release branch — each with its
    /// own <c>vulnerable_version_range</c> and <c>first_patched_version</c>. Emitting one Advisory
    /// per entry matches the GraphQL path's per-node behaviour and avoids false-clean results for
    /// version ranges beyond the first.
    /// </summary>
    public static IReadOnlyList<Advisory> ParseRest(string body, string packageId)
    {
        using var document = JsonDocument.Parse(body);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var advisories = new List<Advisory>();
        foreach (var item in document.RootElement.EnumerateArray())
        {
            foreach (var vuln in FindVulnsForPackage(item, packageId))
            {
                advisories.Add(new Advisory(
                    GetString(item, "summary"),
                    NormalizeSeverity(GetString(item, "severity")),
                    GetString(vuln, "vulnerable_version_range"),
                    [GetString(item, "html_url")],
                    NullIfEmpty(GetString(item, "ghsa_id")),
                    NullIfEmpty(GetString(item, "cve_id")),
                    ExtractRestFirstPatched(vuln)));
            }
        }

        return advisories;
    }

    /// <summary>All <c>vulnerabilities[]</c> entries whose <c>package.name</c> matches.</summary>
    private static IEnumerable<JsonElement> FindVulnsForPackage(JsonElement advisory, string packageId)
    {
        if (!advisory.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var vuln in vulns.EnumerateArray())
        {
            if (vuln.TryGetProperty("package", out var pkg)
                && GetString(pkg, "name").Equals(packageId, StringComparison.OrdinalIgnoreCase))
            {
                yield return vuln;
            }
        }
    }

    /// <summary>The GraphQL node's <c>firstPatchedVersion.identifier</c>, or null.</summary>
    private static string? ExtractFirstPatched(JsonElement node)
        => node.TryGetProperty("firstPatchedVersion", out var fpv) && fpv.ValueKind == JsonValueKind.Object
            ? NullIfEmpty(GetString(fpv, "identifier"))
            : null;

    /// <summary>
    /// The REST <c>first_patched_version</c>, tolerating both shapes GitHub uses: a plain
    /// string (global advisories API) or a <c>{ "identifier": "x" }</c> object.
    /// </summary>
    private static string? ExtractRestFirstPatched(JsonElement vuln)
    {
        if (!vuln.TryGetProperty("first_patched_version", out var fpv))
        {
            return null;
        }

        return fpv.ValueKind switch
        {
            JsonValueKind.String => NullIfEmpty(fpv.GetString()!),
            JsonValueKind.Object => NullIfEmpty(GetString(fpv, "identifier")),
            _ => null,
        };
    }

    /// <summary>The CVE id from the GraphQL advisory's <c>identifiers</c> array, or null.</summary>
    private static string? ExtractCveFromIdentifiers(JsonElement advisory)
    {
        if (!advisory.TryGetProperty("identifiers", out var ids) || ids.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        return ids.EnumerateArray()
            .Where(identifier => GetString(identifier, "type").Equals("CVE", StringComparison.OrdinalIgnoreCase))
            .Select(identifier => NullIfEmpty(GetString(identifier, "value")))
            .FirstOrDefault();
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrEmpty(value) ? null : value;

    private static List<string> ExtractReferences(JsonElement advisory)
    {
        var references = new List<string>();
        if (advisory.TryGetProperty("references", out var refs) && refs.ValueKind == JsonValueKind.Array)
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

    private static string GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : string.Empty;

    /// <summary>
    /// Normalise a GitHub severity to the GraphQL vocabulary (critical/high/moderate/low)
    /// so that <c>--severity moderate</c> filters consistently across both API paths —
    /// the REST advisories API reports "medium" where GraphQL reports "moderate".
    /// </summary>
    private static string NormalizeSeverity(string severity)
    {
        var normalized = severity.ToLowerInvariant();
        return normalized == "medium" ? "moderate" : normalized;
    }

    /// <summary>
    /// Fail loudly on any non-success response. A swallowed error (rate limit, 5xx,
    /// auth failure) would otherwise yield an empty advisory list, making a failed
    /// query indistinguishable from a clean package and silently passing the audit.
    /// </summary>
    private static void EnsureSuccess(HttpStatusCode status, string body)
    {
        if (status == HttpStatusCode.Unauthorized)
        {
            throw new InvalidOperationException("GitHub API authentication failed (401). Check GITHUB_TOKEN.");
        }

        if ((int)status is < (int)HttpStatusCode.OK or >= (int)HttpStatusCode.MultipleChoices)
        {
            var trimmed = body.Trim();
            if (trimmed.Length > MaxErrorBodyLength)
            {
                trimmed = trimmed[..MaxErrorBodyLength] + "…";
            }

            var detail = trimmed.Length == 0 ? string.Empty : $": {trimmed}";
            throw new InvalidOperationException($"GitHub API request failed (HTTP {(int)status} {status}){detail}");
        }
    }

    private void AddHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {_token}");
        request.Headers.TryAddWithoutValidation("User-Agent", "nucheck");
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
    }
}
