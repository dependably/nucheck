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
    public async Task Non_success_returns_empty()
    {
        var client = new GitHubAdvisoryClient(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.InternalServerError, "{}")), "token");

        Assert.Empty(await client.GetAdvisoriesAsync("X"));
    }

    [Fact]
    public void ParseGraphQl_returns_empty_when_no_data()
    {
        Assert.Empty(GitHubAdvisoryClient.ParseGraphQl("""{"errors":[{"message":"boom"}]}"""));
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
