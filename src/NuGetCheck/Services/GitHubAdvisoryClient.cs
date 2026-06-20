using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>
/// Queries the GitHub Advisory Database for NuGet-ecosystem advisories. Uses the
/// GraphQL <c>securityVulnerabilities</c> API by default, or the REST advisories
/// API when <c>useRest</c> is set. Severities are normalised to lower case so they
/// match a <c>--severity high</c> filter regardless of the API's casing.
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

    private readonly HttpClient _http;
    private readonly string _token;
    private readonly bool _useRest;

    public GitHubAdvisoryClient(HttpClient http, string token, bool useRest = false)
    {
        _http = http;
        _token = token;
        _useRest = useRest;
    }

    public Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default)
        => _useRest ? QueryRestAsync(packageId, cancellationToken) : QueryGraphQlAsync(packageId, cancellationToken);

    private async Task<IReadOnlyList<Advisory>> QueryGraphQlAsync(string packageId, CancellationToken cancellationToken)
    {
        var escaped = packageId.Replace("\\", "\\\\").Replace("\"", "\\\"");
        var query =
            "{ securityVulnerabilities(first: 100, ecosystem: NUGET, package: \"" + escaped + "\") " +
            "{ nodes { advisory { summary severity references { url } } vulnerableVersionRange } } }";

        using var request = new HttpRequestMessage(HttpMethod.Post, GraphQlUrl)
        {
            Content = new StringContent(JsonSerializer.Serialize(new { query }), Encoding.UTF8, "application/json"),
        };
        AddHeaders(request);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        EnsureAuthorized(response.StatusCode);
        if (!response.IsSuccessStatusCode)
        {
            return [];
        }

        return ParseGraphQl(body);
    }

    private async Task<IReadOnlyList<Advisory>> QueryRestAsync(string packageId, CancellationToken cancellationToken)
    {
        var url = $"{RestUrl}?ecosystem=nuget&affects={Uri.EscapeDataString(packageId)}";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        AddHeaders(request);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        EnsureAuthorized(response.StatusCode);
        if (!response.IsSuccessStatusCode)
        {
            return [];
        }

        return ParseRest(body, packageId);
    }

    /// <summary>Parse a GraphQL securityVulnerabilities response body into advisories.</summary>
    public static IReadOnlyList<Advisory> ParseGraphQl(string body)
    {
        using var document = JsonDocument.Parse(body);
        if (!document.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object
            || !data.TryGetProperty("securityVulnerabilities", out var sv)
            || !sv.TryGetProperty("nodes", out var nodes) || nodes.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var advisories = new List<Advisory>();
        foreach (var node in nodes.EnumerateArray())
        {
            if (!node.TryGetProperty("advisory", out var advisory))
            {
                continue;
            }

            advisories.Add(new Advisory(
                GetString(advisory, "summary"),
                GetString(advisory, "severity").ToLowerInvariant(),
                GetString(node, "vulnerableVersionRange"),
                ExtractReferences(advisory)));
        }

        return advisories;
    }

    /// <summary>Parse a REST advisories response body, keeping only the matching package's range.</summary>
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
            var range = FindRangeForPackage(item, packageId);
            if (range is null)
            {
                continue;
            }

            advisories.Add(new Advisory(
                GetString(item, "summary"),
                GetString(item, "severity").ToLowerInvariant(),
                range,
                [GetString(item, "html_url")]));
        }

        return advisories;
    }

    private static string? FindRangeForPackage(JsonElement advisory, string packageId)
    {
        if (!advisory.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var vuln in vulns.EnumerateArray())
        {
            if (vuln.TryGetProperty("package", out var pkg)
                && GetString(pkg, "name").Equals(packageId, StringComparison.OrdinalIgnoreCase))
            {
                return GetString(vuln, "vulnerable_version_range");
            }
        }

        return null;
    }

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

    private static void EnsureAuthorized(HttpStatusCode status)
    {
        if (status == HttpStatusCode.Unauthorized)
        {
            throw new InvalidOperationException("GitHub API authentication failed (401). Check GITHUB_TOKEN.");
        }
    }

    private void AddHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {_token}");
        request.Headers.TryAddWithoutValidation("User-Agent", "nuget-check");
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
    }
}
