using System.Net;
using NuGet.Versioning;
using Dependably.NuCheck.Services;
using Dependably.NuCheck.Tests.Fakes;

namespace Dependably.NuCheck.Tests;

public class OsvAdvisoryClientTests
{
    private const string OneVulnBody = """
{"vulns":[
  {"id":"GHSA-aaaa-bbbb-cccc","summary":"Bad deserialization",
   "database_specific":{"severity":"HIGH"},
   "references":[{"type":"WEB","url":"https://example/advisory"}],
   "affected":[{"package":{"ecosystem":"NuGet","name":"Test.Pkg"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}
]}
""";

    [Fact]
    public void ParseOsv_maps_summary_severity_and_references()
    {
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(OneVulnBody, "Test.Pkg"));

        Assert.Equal("GHSA-aaaa-bbbb-cccc: Bad deserialization", advisory.Summary);
        Assert.Equal("high", advisory.Severity);
        Assert.Equal("< 2.0.0", advisory.VulnerableVersionRange);
        Assert.Contains("https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc", advisory.References);
        Assert.Contains("https://example/advisory", advisory.References);
    }

    [Fact]
    public void ParseOsv_extracts_advisory_id_and_fixed_version()
    {
        // The OneVulnBody has id GHSA-..., a fixed:2.0.0 event, and no aliases.
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(OneVulnBody, "Test.Pkg"));

        Assert.Equal("GHSA-aaaa-bbbb-cccc", advisory.AdvisoryId);
        Assert.Equal("2.0.0", advisory.FixedVersion);
        Assert.Null(advisory.Cve); // no CVE alias present -> left null, not fabricated
    }

    [Fact]
    public void ParseOsv_extracts_cve_from_aliases_and_ghsa_when_id_is_cve()
    {
        // OSV id is a CVE here; the GHSA lives in aliases, and so does the CVE.
        const string body = """
{"vulns":[{"id":"CVE-2024-9999","aliases":["GHSA-zzzz-yyyy-xxxx","CVE-2024-9999"],
  "affected":[{"package":{"ecosystem":"NuGet","name":"P"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));

        Assert.Equal("GHSA-zzzz-yyyy-xxxx", advisory.AdvisoryId); // prefers the GHSA alias
        Assert.Equal("CVE-2024-9999", advisory.Cve);
        Assert.Equal("1.5.0", advisory.FixedVersion);
    }

    [Fact]
    public void ParseOsv_leaves_fixed_version_null_for_last_affected_ranges()
    {
        // last_affected gives an upper bound but is NOT a patched version.
        const string body = """
{"vulns":[{"id":"GHSA-q","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.4.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Null(advisory.FixedVersion);
    }

    [Theory]
    [InlineData("1.5.0", true)]   // below the fixed 2.0.0
    [InlineData("2.0.0", false)]  // the fix
    public void ParseOsv_range_matches_via_VulnerabilityMatcher(string version, bool expected)
    {
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(OneVulnBody, "Test.Pkg"));

        Assert.Equal(expected, VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse(version), advisory.VulnerableVersionRange));
    }

    [Fact]
    public void ParseOsv_translates_introduced_and_fixed_to_comparator()
    {
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal(">= 1.0.0, < 1.5.0", advisory.VulnerableVersionRange);
    }

    [Fact]
    public void ParseOsv_translates_last_affected_to_inclusive_upper_bound()
    {
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.4.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal(">= 1.0.0, <= 1.4.0", advisory.VulnerableVersionRange);
    }

    [Fact]
    public void ParseOsv_normalises_medium_to_moderate_and_blank_to_unknown()
    {
        const string body = """
{"vulns":[
  {"id":"A","database_specific":{"severity":"MEDIUM"},"affected":[{"package":{"ecosystem":"NuGet","name":"P"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]},
  {"id":"B","affected":[{"package":{"ecosystem":"NuGet","name":"P"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}
]}
""";
        var advisories = OsvAdvisoryClient.ParseOsv(body, "P");
        Assert.Equal("moderate", advisories[0].Severity);
        Assert.Equal("unknown", advisories[1].Severity);
        // ">= 0.0.0-0" uses the minimum NuGet prerelease label (numeric 0 sorts below all
        // alphanumeric labels) so it covers every publishable version, unlike ">= 0.0.0"
        // which excludes 0.0.0-prerelease packages.
        Assert.Equal(">= 0.0.0-0", advisories[0].VulnerableVersionRange);
    }

    [Fact]
    public void ParseOsv_all_versions_sentinel_uses_unbounded_interval_not_0_0_0_floor()
    {
        // Regression for #37: an OSV interval with introduced:"0" and no fixed event used to
        // emit ">= 0.0.0" which excludes 0.0.0-prerelease packages (they sort below 0.0.0 in
        // NuGet SemVer).  The sentinel must now emit "(,)" — NuGet's native unbounded interval
        // — so that any installed version, including 0.0.0-alpha, is matched.
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));

        Assert.Equal(">= 0.0.0-0", advisory.VulnerableVersionRange);
        // Confirm the range actually matches a 0.0.0 prerelease via VulnerabilityMatcher.
        Assert.True(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("0.0.0-alpha"), advisory.VulnerableVersionRange));
        Assert.True(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("9.9.9"), advisory.VulnerableVersionRange));
    }

    [Fact]
    public void ParseOsv_uses_explicit_versions_when_no_ranges()
    {
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},"versions":["1.2.3","1.2.4"]}]}]}
""";
        var advisories = OsvAdvisoryClient.ParseOsv(body, "P");
        Assert.Equal(2, advisories.Count);
        Assert.Equal("= 1.2.3", advisories[0].VulnerableVersionRange);
        Assert.Equal("= 1.2.4", advisories[1].VulnerableVersionRange);
    }

    [Fact]
    public void ParseOsv_skips_other_ecosystems_and_packages()
    {
        const string body = """
{"vulns":[{"id":"X","affected":[
  {"package":{"ecosystem":"npm","name":"P"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]},
  {"package":{"ecosystem":"NuGet","name":"Other"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}
]}]}
""";
        Assert.Empty(OsvAdvisoryClient.ParseOsv(body, "P"));
    }

    [Fact]
    public void ParseOsv_returns_empty_when_no_vulns()
    {
        Assert.Empty(OsvAdvisoryClient.ParseOsv("{}", "P"));
    }

    [Fact]
    public async Task GetAdvisoriesAsync_parses_a_live_style_response()
    {
        var client = new OsvAdvisoryClient(new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, OneVulnBody)));

        var advisory = Assert.Single(await client.GetAdvisoriesAsync("Test.Pkg"));
        Assert.Equal("high", advisory.Severity);
    }

    [Fact]
    public async Task GetAdvisoriesAsync_throws_on_non_success()
    {
        var client = new OsvAdvisoryClient(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.BadRequest, "bad")), maxRetries: 0,
            delay: NoDelay);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAdvisoriesAsync("P"));
        Assert.Contains("400", ex.Message);
    }

    [Fact]
    public async Task GetAdvisoriesAsync_retries_transient_then_succeeds()
    {
        var calls = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            calls++;
            return calls == 1 ? (HttpStatusCode.ServiceUnavailable, "down") : (HttpStatusCode.OK, OneVulnBody);
        });
        var client = new OsvAdvisoryClient(new HttpClient(handler), delay: NoDelay);

        Assert.Single(await client.GetAdvisoriesAsync("Test.Pkg"));
        Assert.Equal(2, calls);
    }

    private static Task NoDelay(TimeSpan _, CancellationToken __) => Task.CompletedTask;
}
