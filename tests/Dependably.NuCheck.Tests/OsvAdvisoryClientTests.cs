using System.Net;
using System.Text.Json;
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
        Assert.Equal(">= 0.0.0", advisories[0].VulnerableVersionRange); // open range matches everything
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

    // --- Ticket 18: top-level CVSS severity[] fallback -------------------------------------

    [Fact]
    public void ParseOsv_derives_severity_from_cvss_v3_vector_when_database_specific_absent()
    {
        // No database_specific.severity; a top-level CVSS_V3 vector scoring 9.8 => critical.
        const string body = """
{"vulns":[{"id":"X",
  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected":[{"package":{"ecosystem":"NuGet","name":"P"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal("critical", advisory.Severity);
    }

    [Fact]
    public void ParseOsv_derives_severity_from_numeric_cvss_score()
    {
        // A bare numeric base score in the 4.0-6.9 band => moderate.
        const string body = """
{"vulns":[{"id":"X",
  "severity":[{"type":"CVSS_V3","score":"5.5"}],
  "affected":[{"package":{"ecosystem":"NuGet","name":"P"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal("moderate", advisory.Severity);
    }

    [Fact]
    public void ParseOsv_prefers_database_specific_severity_over_cvss_array()
    {
        // database_specific label wins even when a CVSS vector is also present.
        const string body = """
{"vulns":[{"id":"X","database_specific":{"severity":"LOW"},
  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected":[{"package":{"ecosystem":"NuGet","name":"P"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal("low", advisory.Severity);
    }

    [Fact]
    public void ParseOsv_prefers_cvss_v4_over_v3_in_severity_array()
    {
        // V4 (critical) is chosen ahead of a V3 entry that alone would read low.
        const string body = """
{"vulns":[{"id":"X",
  "severity":[{"type":"CVSS_V3","score":"2.0"},{"type":"CVSS_V4","score":"9.5"}],
  "affected":[{"package":{"ecosystem":"NuGet","name":"P"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal("critical", advisory.Severity);
    }

    // --- Ticket 29: unsorted / consecutive events -----------------------------------------

    [Fact]
    public void ParseOsv_sorts_unordered_events_before_pairing()
    {
        // Events arrive out of order: [fixed, introduced]. Sorting yields a single bounded
        // interval [1.0.0, 2.0.0) instead of a stray "< 2.0.0" plus an open ">= 1.0.0".
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"2.0.0"},{"introduced":"1.0.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal(">= 1.0.0, < 2.0.0", advisory.VulnerableVersionRange);
        Assert.Equal("2.0.0", advisory.FixedVersion);
    }

    [Fact]
    public void ParseOsv_collapses_consecutive_introduced_into_one_interval()
    {
        // Two 'introduced' before a single 'fixed' describe one vulnerable timeline; the
        // earliest introduced must survive, giving [1.0.0, 2.1.0) rather than dropping 1.0.0.
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"introduced":"2.0.0"},{"fixed":"2.1.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal(">= 1.0.0, < 2.1.0", advisory.VulnerableVersionRange);

        // 1.5.0 sits between the two introduced events and must be flagged (was a false negative).
        Assert.True(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("1.5.0"), advisory.VulnerableVersionRange));
        Assert.False(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("2.1.0"), advisory.VulnerableVersionRange));
    }

    [Fact]
    public void ParseOsv_keeps_distinct_fixed_branches_as_separate_intervals()
    {
        // A genuinely disjoint pair (fix, then a later reintroduction+fix) stays two intervals,
        // even when the events are shuffled in the payload.
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"1.5.0"},{"introduced":"1.0.0"},{"fixed":"2.5.0"}]}]}]}]}
""";
        var advisories = OsvAdvisoryClient.ParseOsv(body, "P");
        Assert.Equal(2, advisories.Count);
        Assert.Equal(">= 1.0.0, < 1.5.0", advisories[0].VulnerableVersionRange);
        Assert.Equal(">= 2.0.0, < 2.5.0", advisories[1].VulnerableVersionRange);
    }

    [Fact]
    public void ParseOsv_reopens_interval_when_reintroduced_at_the_fixed_boundary()
    {
        // osv.dev serves reintroductions as introduced/fixed/introduced, already sorted.
        // events:[introduced:0, fixed:1.0.0, introduced:1.0.0] means the fix at 1.0.0 was
        // immediately reintroduced at 1.0.0, so EVERYTHING is vulnerable: < 1.0.0 from the
        // first interval and >= 1.0.0 from the reopened one. The buggy code sorted the second
        // introduced ahead of the fixed, treated it as a redundant open, and emitted only
        // "< 1.0.0" — silently unflagging 1.0.0 and 2.0.0 (a fail-open under-report).
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"1.0.0"}]}]}]}]}
""";
        var advisories = OsvAdvisoryClient.ParseOsv(body, "P");
        Assert.Equal(2, advisories.Count);
        Assert.Equal("< 1.0.0", advisories[0].VulnerableVersionRange);
        Assert.Equal(">= 1.0.0", advisories[1].VulnerableVersionRange);

        // The reintroduced version and everything above it must be flagged.
        Assert.True(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("1.0.0"), advisories[1].VulnerableVersionRange));
        Assert.True(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("2.0.0"), advisories[1].VulnerableVersionRange));
    }

    [Fact]
    public void ParseOsv_introduced_and_fixed_at_same_version_alone_is_not_vulnerable()
    {
        // Guard for the reopen logic: {introduced:1.0.0},{fixed:1.0.0} with no prior interval
        // is an empty range — the introduced opens the interval that the fixed immediately
        // closes at the same version, so nothing is affected. This must NOT be misread as a
        // reintroduction (there is no earlier interval closing at 1.0.0 to reopen).
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.0.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));

        Assert.False(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("1.0.0"), advisory.VulnerableVersionRange));
        Assert.False(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("0.9.0"), advisory.VulnerableVersionRange));
        Assert.False(VulnerabilityMatcher.IsVulnerable(NuGetVersion.Parse("2.0.0"), advisory.VulnerableVersionRange));
    }

    // --- Ticket 39: ValueKind guards in event parsing ------------------------------------

    [Fact]
    public void ParseOsv_skips_event_with_null_json_value()
    {
        // introduced:null has ValueKind==Null. Old code calls GetString() and throws;
        // new code skips the null event and processes the remaining valid events.
        const string body = """
{"vulns":[{"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":null},{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal(">= 1.0.0, < 2.0.0", advisory.VulnerableVersionRange);
    }

    [Fact]
    public void ParseOsv_continues_after_non_string_event_value_in_one_vuln()
    {
        // Mixed response: first vuln has a numeric "introduced", second is well-formed.
        // Old code: GetString() on a Number throws, aborting the entire parse.
        // New code: the non-string event is skipped; both vulns produce advisories.
        const string body = """
{"vulns":[
  {"id":"X","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":42},{"fixed":"2.0.0"}]}]}]},
  {"id":"Y","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"3.0.0"}]}]}]}
]}
""";
        var advisories = OsvAdvisoryClient.ParseOsv(body, "P");
        // The well-formed advisory from "Y" must survive even when "X" has bad event data.
        Assert.Contains(advisories, a => a.VulnerableVersionRange == ">= 1.0.0, < 3.0.0");
    }

    [Fact]
    public void ParseOsv_range_with_all_malformed_events_emits_conservative_flag_not_silent_drop()
    {
        // events:[{"introduced":42}] — the only event has a Number value, not a String.
        // The ValueKind guard in OrderedEvents correctly skips it, leaving the parsed list
        // empty even though the events array is non-empty.
        // Current HEAD (silent-fail-open): OrderedEvents returns [], PairIntervals yields
        // nothing, the range produces no intervals, the vuln is silently dropped — a false
        // negative, the worst possible outcome for a vulnerability scanner.
        // Fixed code: non-empty events array + zero successfully-parsed events → emit the
        // conservative ">= 0.0.0" sentinel so the package is flagged rather than cleared.
        const string body = """
{"vulns":[{"id":"GHSA-aaaa-bbbb-0000","affected":[{"package":{"ecosystem":"NuGet","name":"P"},
  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":42}]}]}]}]}
""";
        var advisory = Assert.Single(OsvAdvisoryClient.ParseOsv(body, "P"));
        Assert.Equal(">= 0.0.0", advisory.VulnerableVersionRange);
    }

    // --- Ticket 23: exponential backoff + Retry-After support ----------------------------

    [Fact]
    public async Task GetAdvisoriesAsync_honors_retry_after_delta_on_429()
    {
        // Old code ignores Retry-After and fires all retries within 7s — under the 10-60s
        // OSV rate-limit window.  New code uses the header value as the delay.
        var delays = new List<TimeSpan>();
        var calls = 0;
        var handler = new FakeHttpMessageHandler(req =>
        {
            calls++;
            if (calls == 1)
            {
                var r = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
                r.Headers.TryAddWithoutValidation("Retry-After", "30");
                return r;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(OneVulnBody, System.Text.Encoding.UTF8, "application/json"),
            };
        });
        var client = new OsvAdvisoryClient(new HttpClient(handler),
            delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });

        Assert.Single(await client.GetAdvisoriesAsync("Test.Pkg"));
        Assert.Equal(TimeSpan.FromSeconds(30), Assert.Single(delays));
    }

    [Fact]
    public async Task GetAdvisoriesAsync_backoff_starts_at_four_seconds_for_transient_errors()
    {
        // Old code: attempt 0 → 1s, attempt 1 → 2s (total 3s after two failures).
        // New code: attempt 0 → 4s, attempt 1 → 8s, ensuring retries survive the OSV window.
        var delays = new List<TimeSpan>();
        var calls = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            calls++;
            return calls < 3
                ? (HttpStatusCode.ServiceUnavailable, "down")
                : (HttpStatusCode.OK, OneVulnBody);
        });
        var client = new OsvAdvisoryClient(new HttpClient(handler),
            delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });

        Assert.Single(await client.GetAdvisoriesAsync("Test.Pkg"));
        Assert.Equal(2, delays.Count);
        Assert.Equal(TimeSpan.FromSeconds(4), delays[0]);   // was 1s on old code
        Assert.Equal(TimeSpan.FromSeconds(8), delays[1]);   // was 2s on old code
    }

    // --- Ticket 6: guard ParseOsv against malformed JSON bodies --------------------------

    [Fact]
    public void ParseOsv_throws_informative_exception_for_malformed_json()
    {
        // Old code: raw JsonException propagates with no package context.
        // New code: wrapped as InvalidOperationException naming the package + body snippet.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            OsvAdvisoryClient.ParseOsv("<html>not json</html>", "My.Pkg"));
        Assert.Contains("My.Pkg", ex.Message);
        Assert.IsAssignableFrom<JsonException>(ex.InnerException);
    }

    [Fact]
    public async Task GetAdvisoriesAsync_wraps_malformed_json_as_InvalidOperationException()
    {
        // A 200 OK with an HTML body (e.g. from an intercepting proxy) must not surface
        // a raw JsonException — it should be wrapped so the caller gets useful context.
        var client = new OsvAdvisoryClient(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, "<html>proxy error</html>")));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetAdvisoriesAsync("My.Pkg"));
        Assert.Contains("My.Pkg", ex.Message);
        Assert.IsAssignableFrom<JsonException>(ex.InnerException);
    }

    private static Task NoDelay(TimeSpan _, CancellationToken __) => Task.CompletedTask;
}
