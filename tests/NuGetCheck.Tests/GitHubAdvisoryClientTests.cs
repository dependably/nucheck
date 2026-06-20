using System.Net;
using NuGetCheck.Services;
using NuGetCheck.Tests.Fakes;

namespace NuGetCheck.Tests;

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
