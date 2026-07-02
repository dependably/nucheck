using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dependably.NuCheck.Services;
using Dependably.NuCheck.Tests.Fakes;

namespace Dependably.NuCheck.Tests;

public class GitHubAdvisoryClientTests
{
    private const string GraphQlBody = """
{"data":{"securityVulnerabilities":{"nodes":[
  {"advisory":{"summary":"Bad thing","severity":"HIGH","references":[{"url":"https://example/1"}]},"vulnerableVersionRange":">= 1.0.0, < 2.0.0"}
]}}}
""";

    private const string RestBody = """
[{"summary":"Bad thing","severity":"high","html_url":"https://example/2",
  "vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Newtonsoft.Json"},"vulnerable_version_range":">= 1.0.0, < 2.0.0"}]}]
""";

    [Fact]
    public async Task GraphQl_path_parses_advisories()
    {
        var client = new GitHubAdvisoryClient(new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, GraphQlBody)), "token");

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        var advisory = Assert.Single(advisories);
        Assert.Equal("Bad thing", advisory.Summary);
        Assert.Equal("high", advisory.Severity); // normalised to lower case
        Assert.Equal(">= 1.0.0, < 2.0.0", advisory.VulnerableVersionRange);
        Assert.Equal("https://example/1", Assert.Single(advisory.References));
    }

    [Fact]
    public async Task Rest_path_parses_matching_package_range()
    {
        var client = new GitHubAdvisoryClient(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, RestBody)), "token", useRest: true);

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        var advisory = Assert.Single(advisories);
        Assert.Equal("https://example/2", Assert.Single(advisory.References));
        Assert.Equal(">= 1.0.0, < 2.0.0", advisory.VulnerableVersionRange);
    }

    [Fact]
    public async Task Unauthorized_throws()
    {
        var client = new GitHubAdvisoryClient(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.Unauthorized, "{}")), "bad-token");

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAdvisoriesAsync("X"));
    }

    [Fact]
    public async Task Non_success_throws_instead_of_reporting_clean()
    {
        var client = new GitHubAdvisoryClient(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.InternalServerError, "boom")), "token",
            maxRetries: 0);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAdvisoriesAsync("X"));
        Assert.Contains("500", ex.Message);
    }

    [Fact]
    public async Task Retries_transient_failure_then_succeeds()
    {
        var calls = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            calls++;
            return calls == 1 ? (HttpStatusCode.ServiceUnavailable, "down") : (HttpStatusCode.OK, GraphQlBody);
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", delay: NoDelay);

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(2, calls);
        Assert.Single(advisories);
    }

    [Fact]
    public async Task Throws_after_exhausting_retries()
    {
        var calls = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            calls++;
            return (HttpStatusCode.ServiceUnavailable, "still down");
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", maxRetries: 2, delay: NoDelay);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAdvisoriesAsync("X"));
        Assert.Equal(3, calls); // 1 initial attempt + 2 retries
    }

    [Fact]
    public async Task Plain_403_is_not_retried()
    {
        var calls = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            calls++;
            return (HttpStatusCode.Forbidden, "insufficient scope");
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", delay: NoDelay);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAdvisoriesAsync("X"));
        Assert.Equal(1, calls); // a non-rate-limit 403 is a hard failure, not transient
    }

    private static Task NoDelay(TimeSpan _, CancellationToken __) => Task.CompletedTask;

    // ---- #12: 403 secondary rate-limit retry paths ----------------------------

    /// <summary>
    /// A custom handler that lets each call return a full <see cref="HttpResponseMessage"/>
    /// (with response headers), which the tuple-based FakeHttpMessageHandler cannot do.
    /// </summary>
    private sealed class FullResponseHandler : HttpMessageHandler
    {
        private readonly Func<int, HttpResponseMessage> _factory;
        private int _calls;

        public int Calls => _calls;

        public FullResponseHandler(Func<int, HttpResponseMessage> factory) => _factory = factory;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _calls++;
            return Task.FromResult(_factory(_calls));
        }
    }

    [Fact]
    public async Task Forbidden_with_retry_after_header_is_retried()
    {
        // Attempt 1: 403 with Retry-After: 0 (secondary rate limit) → should retry.
        // Attempt 2: 200 with valid GraphQL body → should succeed.
        var handler = new FullResponseHandler(call =>
        {
            if (call == 1)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("secondary rate limit", Encoding.UTF8, "application/json"),
                };
                response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
                return response;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(GraphQlBody, Encoding.UTF8, "application/json"),
            };
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", delay: NoDelay);

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(2, handler.Calls);
        Assert.Single(advisories);
    }

    [Fact]
    public async Task Forbidden_with_ratelimit_remaining_zero_is_retried()
    {
        // Attempt 1: 403 with x-ratelimit-remaining: 0 → should retry.
        // Attempt 2: 200 with valid GraphQL body → should succeed.
        var handler = new FullResponseHandler(call =>
        {
            if (call == 1)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("exhausted", Encoding.UTF8, "application/json"),
                };
                response.Headers.Add("x-ratelimit-remaining", "0");
                return response;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(GraphQlBody, Encoding.UTF8, "application/json"),
            };
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", delay: NoDelay);

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(2, handler.Calls);
        Assert.Single(advisories);
    }

    // ---- #11: GraphQL 'MEDIUM' → 'moderate' normalisation ---------------------

    [Fact]
    public void ParseGraphQl_normalises_medium_severity_to_moderate()
    {
        const string body = """
{"data":{"securityVulnerabilities":{"nodes":[
  {"advisory":{"summary":"Medium severity issue","severity":"MEDIUM","references":[{"url":"https://example/1"}]},"vulnerableVersionRange":">= 1.0.0, < 2.0.0"}
]}}}
""";
        var advisory = Assert.Single(GitHubAdvisoryClient.ParseGraphQl(body));
        Assert.Equal("moderate", advisory.Severity);
    }

    [Fact]
    public async Task Rate_limited_graphql_200_with_errors_throws()
    {
        const string body = """{"data":null,"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}""";
        var client = new GitHubAdvisoryClient(new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, body)), "token");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAdvisoriesAsync("X"));
        Assert.Contains("rate limit", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseGraphQl_throws_on_errors_payload()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => GitHubAdvisoryClient.ParseGraphQl("""{"errors":[{"message":"boom"}]}"""));
        Assert.Contains("boom", ex.Message);
    }

    [Fact]
    public void ParseGraphQl_returns_empty_when_data_has_no_nodes()
    {
        Assert.Empty(GitHubAdvisoryClient.ParseGraphQl("""{"data":{"securityVulnerabilities":{"nodes":[]}}}"""));
    }

    [Fact]
    public void ParseGraphQl_extracts_ghsa_id_cve_and_first_patched_version()
    {
        const string body = """
{"data":{"securityVulnerabilities":{"nodes":[
  {"advisory":{"ghsaId":"GHSA-aaaa-bbbb-cccc","summary":"Bad","severity":"HIGH",
    "identifiers":[{"type":"GHSA","value":"GHSA-aaaa-bbbb-cccc"},{"type":"CVE","value":"CVE-2024-1234"}],
    "references":[{"url":"https://example/1"}]},
   "firstPatchedVersion":{"identifier":"2.0.1"},"vulnerableVersionRange":">= 1.0.0, < 2.0.1"}
]}}}
""";
        var advisory = Assert.Single(GitHubAdvisoryClient.ParseGraphQl(body));

        Assert.Equal("GHSA-aaaa-bbbb-cccc", advisory.AdvisoryId);
        Assert.Equal("CVE-2024-1234", advisory.Cve);
        Assert.Equal("2.0.1", advisory.FixedVersion);
    }

    [Fact]
    public void ParseGraphQl_leaves_fields_null_when_absent()
    {
        // No ghsaId, no CVE identifier, no firstPatchedVersion -> all appended fields null.
        var advisory = Assert.Single(GitHubAdvisoryClient.ParseGraphQl(GraphQlBody));

        Assert.Null(advisory.AdvisoryId);
        Assert.Null(advisory.Cve);
        Assert.Null(advisory.FixedVersion);
    }

    [Fact]
    public void ParseRest_extracts_ghsa_id_cve_and_first_patched_version_string()
    {
        // The global advisories API gives first_patched_version as a plain string.
        const string body = """
[{"summary":"Bad","severity":"high","html_url":"https://example/2","ghsa_id":"GHSA-1111-2222-3333","cve_id":"CVE-2024-5678",
  "vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":"< 2.0","first_patched_version":"2.0.0"}]}]
""";
        var advisory = Assert.Single(GitHubAdvisoryClient.ParseRest(body, "Pkg"));

        Assert.Equal("GHSA-1111-2222-3333", advisory.AdvisoryId);
        Assert.Equal("CVE-2024-5678", advisory.Cve);
        Assert.Equal("2.0.0", advisory.FixedVersion);
    }

    [Fact]
    public void ParseRest_extracts_first_patched_version_object_shape()
    {
        // The repository advisories API gives first_patched_version as {identifier}.
        const string body = """
[{"summary":"Bad","severity":"low","html_url":"u","ghsa_id":"GHSA-x","cve_id":null,
  "vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":"< 3.0","first_patched_version":{"identifier":"3.0.0"}}]}]
""";
        var advisory = Assert.Single(GitHubAdvisoryClient.ParseRest(body, "Pkg"));

        Assert.Equal("3.0.0", advisory.FixedVersion);
        Assert.Null(advisory.Cve); // explicit JSON null -> left null
    }

    [Fact]
    public void ParseRest_normalises_medium_severity_to_moderate()
    {
        const string body = """
[{"summary":"x","severity":"medium","html_url":"u","vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":"< 1.0"}]}]
""";
        var advisory = Assert.Single(GitHubAdvisoryClient.ParseRest(body, "Pkg"));
        Assert.Equal("moderate", advisory.Severity);
    }

    [Fact]
    public void ParseRest_skips_advisories_without_matching_package()
    {
        const string body = """
[{"summary":"x","severity":"low","html_url":"u","vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Other"},"vulnerable_version_range":"< 1.0"}]}]
""";
        Assert.Empty(GitHubAdvisoryClient.ParseRest(body, "Newtonsoft.Json"));
    }
}
