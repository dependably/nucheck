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
    public async Task GraphQl_path_follows_cursor_pagination_across_pages()
    {
        const string page1 = """
{"data":{"securityVulnerabilities":{"nodes":[
  {"advisory":{"summary":"First","severity":"HIGH","references":[{"url":"https://example/1"}]},"vulnerableVersionRange":">= 1.0.0, < 2.0.0"}
],"pageInfo":{"hasNextPage":true,"endCursor":"CURSOR1"}}}}
""";
        const string page2 = """
{"data":{"securityVulnerabilities":{"nodes":[
  {"advisory":{"summary":"Second","severity":"LOW","references":[{"url":"https://example/2"}]},"vulnerableVersionRange":">= 2.0.0, < 3.0.0"}
],"pageInfo":{"hasNextPage":false,"endCursor":"CURSOR2"}}}}
""";
        var requestBodies = new List<string>();
        var handler = new FakeHttpMessageHandler(request =>
        {
            requestBodies.Add(request.Content!.ReadAsStringAsync().GetAwaiter().GetResult());
            return (HttpStatusCode.OK, requestBodies.Count == 1 ? page1 : page2);
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token");

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        // Both pages are accumulated, not just the first 100-node page.
        Assert.Equal(2, advisories.Count);
        Assert.Contains(advisories, a => a.Summary == "First");
        Assert.Contains(advisories, a => a.Summary == "Second");

        // Two requests were made; the second carried the first page's endCursor as `after:`.
        Assert.Equal(2, requestBodies.Count);
        Assert.Contains("pageInfo", requestBodies[0]);
        Assert.DoesNotContain("after", requestBodies[0]);
        Assert.Contains("CURSOR1", requestBodies[1]);
    }

    [Fact]
    public async Task GraphQl_path_stops_when_has_next_page_is_false()
    {
        var calls = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            calls++;
            return (HttpStatusCode.OK, GraphQlBody); // no pageInfo -> treated as last page
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token");

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Single(advisories);
        Assert.Equal(1, calls); // a single page with no next-page cursor is not re-fetched
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

    // #16 — Retry-After HTTP-date form

    [Fact]
    public async Task Retry_After_http_date_form_is_honoured_and_capped_at_max_backoff()
    {
        // Set a Retry-After date 5 minutes in the future — well above MaxBackoff (60 s).
        // Old code skipped the date branch and used exponential backoff (1 s for attempt 0).
        // New code computes the wait from the date, clamped to MaxBackoff (60 s).
        var retryDate = DateTimeOffset.UtcNow.AddSeconds(300);
        var captured = TimeSpan.Zero;
        var calls = 0;
        var handler = new FakeHttpMessageHandler(req =>
        {
            calls++;
            if (calls == 1)
            {
                var r = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
                {
                    Content = new StringContent("{}", Encoding.UTF8, "application/json"),
                };
                r.Headers.RetryAfter = new RetryConditionHeaderValue(retryDate);
                return r;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(GraphQlBody, Encoding.UTF8, "application/json"),
            };
        });
        var client = new GitHubAdvisoryClient(
            new HttpClient(handler), "token",
            delay: (ts, _) => { captured = ts; return Task.CompletedTask; });

        await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(2, calls);
        // Old code: 1 s (2^0 backoff). New code: MaxBackoff (60 s) because 300 s > MaxBackoff.
        Assert.Equal(TimeSpan.FromSeconds(60), captured);
    }

    [Fact]
    public async Task Retry_After_http_date_form_in_the_past_falls_through_to_backoff()
    {
        // A Retry-After date already in the past has a negative computed wait; fall through
        // to exponential backoff. Old code also fell through, so both paths agree here,
        // but the assertion confirms the backoff value is used (2^0 = 1 s) rather than
        // a nonsensical zero or negative delay.
        var pastDate = DateTimeOffset.UtcNow.AddSeconds(-10);
        var captured = TimeSpan.Zero;
        var calls = 0;
        var handler = new FakeHttpMessageHandler(req =>
        {
            calls++;
            if (calls == 1)
            {
                var r = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
                {
                    Content = new StringContent("{}", Encoding.UTF8, "application/json"),
                };
                r.Headers.RetryAfter = new RetryConditionHeaderValue(pastDate);
                return r;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(GraphQlBody, Encoding.UTF8, "application/json"),
            };
        });
        var client = new GitHubAdvisoryClient(
            new HttpClient(handler), "token",
            delay: (ts, _) => { captured = ts; return Task.CompletedTask; });

        await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(TimeSpan.FromSeconds(1), captured); // 2^0 = 1 s for attempt 0
    }

    // #17 — Network-level exceptions bypass retry logic

    [Fact]
    public async Task Network_exception_on_first_attempt_is_retried_and_succeeds()
    {
        // Old code: HttpRequestException from SendAsync propagated immediately past the retry loop.
        // New code: caught when attempt < _maxRetries and retried with exponential backoff.
        var calls = 0;
        var handler = new FakeHttpMessageHandler(req =>
        {
            calls++;
            if (calls == 1)
            {
                throw new HttpRequestException("simulated network failure");
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(GraphQlBody, Encoding.UTF8, "application/json"),
            };
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", delay: NoDelay);

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(2, calls);
        Assert.Single(advisories);
    }

    [Fact]
    public async Task Network_exception_exhausting_retries_rethrows()
    {
        // All attempts fail with a network-level exception; must rethrow after retries are exhausted.
        var calls = 0;
        // Explicit Func type resolves constructor overload ambiguity: a throw-only lambda matches both
        // Func<Request,HttpResponseMessage> and Func<Request,(HttpStatusCode,string)>.
        Func<HttpRequestMessage, HttpResponseMessage> alwaysFail = _ =>
        {
            calls++;
            throw new HttpRequestException("always down");
        };
        var handler = new FakeHttpMessageHandler(alwaysFail);
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", maxRetries: 2, delay: NoDelay);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAdvisoriesAsync("X"));
        Assert.Equal(3, calls); // 1 initial + 2 retries
    }

    [Fact]
    public async Task Network_exception_mixed_with_http_transient_failure_retries_both()
    {
        // Partial-failure scenario: attempt 1 → network exception, attempt 2 → 503,
        // attempt 3 → 200. Both transient failure kinds must be retried.
        var calls = 0;
        var handler = new FakeHttpMessageHandler(req =>
        {
            calls++;
            return calls switch
            {
                1 => throw new HttpRequestException("DNS failure"),
                2 => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                {
                    Content = new StringContent("down", Encoding.UTF8, "application/json"),
                },
                _ => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(GraphQlBody, Encoding.UTF8, "application/json"),
                },
            };
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", maxRetries: 3, delay: NoDelay);

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(3, calls);
        Assert.Single(advisories);
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

    // #5 — REST Link-header pagination

    [Fact]
    public async Task Rest_follows_link_header_pagination_across_pages()
    {
        // Page 1 carries two advisories and a Link: rel="next" header pointing to page 2.
        // Page 2 carries one advisory and no Link header (last page).
        // Old code issued only a single GET and returned after the first page.
        const string page1Body = """
[{"summary":"First","severity":"high","html_url":"https://example/1",
  "vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":"< 2.0"}]},
 {"summary":"Second","severity":"low","html_url":"https://example/2",
  "vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":">= 2.0, < 3.0"}]}]
""";
        const string page2Body = """
[{"summary":"Third","severity":"moderate","html_url":"https://example/3",
  "vulnerabilities":[{"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":">= 3.0, < 4.0"}]}]
""";
        const string page2Url = "https://api.github.com/advisories?ecosystem=nuget&affects=Pkg&per_page=100&page=2";

        var requests = new List<string?>();
        var handler = new FakeHttpMessageHandler(req =>
        {
            requests.Add(req.RequestUri?.ToString());
            var isPage1 = requests.Count == 1;
            var body = isPage1 ? page1Body : page2Body;
            var r = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            if (isPage1)
            {
                r.Headers.Add("Link", $"<{page2Url}>; rel=\"next\", <https://api.github.com/advisories?page=5>; rel=\"last\"");
            }

            return r;
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", useRest: true);

        var advisories = await client.GetAdvisoriesAsync("Pkg");

        // All three advisories from both pages must be returned.
        Assert.Equal(3, advisories.Count);
        Assert.Contains(advisories, a => a.Summary == "First");
        Assert.Contains(advisories, a => a.Summary == "Second");
        Assert.Contains(advisories, a => a.Summary == "Third");

        // Two HTTP requests were made; the second used the URL from the Link header.
        Assert.Equal(2, requests.Count);
        Assert.Contains("per_page=100", requests[0], StringComparison.Ordinal);
        Assert.Equal(page2Url, requests[1]);
    }

    [Fact]
    public async Task Rest_stops_when_no_link_next_header()
    {
        // Ensure a single-page response (no Link header) does not trigger a second request.
        var calls = 0;
        var handler = new FakeHttpMessageHandler(req =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(RestBody, Encoding.UTF8, "application/json"),
            };
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", useRest: true);

        var advisories = await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.Equal(1, calls);
        Assert.Single(advisories);
    }

    [Fact]
    public async Task Rest_includes_per_page_100_on_initial_request()
    {
        string? capturedUrl = null;
        var handler = new FakeHttpMessageHandler(req =>
        {
            capturedUrl = req.RequestUri?.ToString();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("[]", Encoding.UTF8, "application/json"),
            };
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", useRest: true);

        await client.GetAdvisoriesAsync("Newtonsoft.Json");

        Assert.NotNull(capturedUrl);
        Assert.Contains("per_page=100", capturedUrl, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rest_pagination_terminates_at_cap_when_server_always_returns_link_next()
    {
        // Regression guard for unbounded REST pagination loop (fix/github-client review finding #5).
        // Without the MaxRestPages cap: while (url is not null) loops forever because the
        // fake always returns a Link: rel="next" pointing to the same URL — the test would hang.
        // With the cap: the for loop exits after MaxRestPages (1000) iterations.
        const string selfUrl = "https://api.github.com/advisories?ecosystem=nuget&affects=Pkg&per_page=100";
        var calls = 0;
        var handler = new FakeHttpMessageHandler(req =>
        {
            calls++;
            var r = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("[]", Encoding.UTF8, "application/json"),
            };
            r.Headers.Add("Link", $"<{selfUrl}>; rel=\"next\""); // self-referencing: always a next page
            return r;
        });
        var client = new GitHubAdvisoryClient(new HttpClient(handler), "token", useRest: true);

        var advisories = await client.GetAdvisoriesAsync("Pkg");

        // The call must return (not hang). Exactly MaxRestPages (1000) requests are made —
        // proving the cap was hit rather than the loop ending naturally (which would require
        // a missing Link header).
        Assert.Empty(advisories);
        Assert.Equal(1000, calls);
    }

    // #28 — REST parser emits one Advisory per vulnerabilities[] entry

    [Fact]
    public void ParseRest_emits_one_advisory_per_matching_vulnerabilities_entry()
    {
        // Old code called FindVulnForPackage which returned on the FIRST matching entry,
        // dropping additional ranges for the same package within the same advisory.
        const string body = """
[{"summary":"Multi-range","severity":"high","html_url":"https://example/ghsa","ghsa_id":"GHSA-multi","cve_id":null,
  "vulnerabilities":[
    {"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":">= 2.0, < 2.5","first_patched_version":"2.5.0"},
    {"package":{"ecosystem":"nuget","name":"Pkg"},"vulnerable_version_range":">= 3.0, < 3.2","first_patched_version":"3.2.0"},
    {"package":{"ecosystem":"nuget","name":"Other"},"vulnerable_version_range":">= 1.0, < 1.1","first_patched_version":"1.1.0"}
  ]}]
""";
        var advisories = GitHubAdvisoryClient.ParseRest(body, "Pkg");

        // Both ranges for "Pkg" must appear; the "Other" entry must be excluded.
        Assert.Equal(2, advisories.Count);
        Assert.Contains(advisories, a => a.VulnerableVersionRange == ">= 2.0, < 2.5" && a.FixedVersion == "2.5.0");
        Assert.Contains(advisories, a => a.VulnerableVersionRange == ">= 3.0, < 3.2" && a.FixedVersion == "3.2.0");
        Assert.All(advisories, a => Assert.Equal("GHSA-multi", a.AdvisoryId));
    }

    [Fact]
    public void ParseRest_single_matching_entry_still_produces_one_advisory()
    {
        // Regression guard: the refactor must not break the existing one-range path.
        var advisories = GitHubAdvisoryClient.ParseRest(RestBody, "Newtonsoft.Json");
        Assert.Single(advisories);
    }

    // #38 — ParseGraphQl safe on non-object 2xx body

    [Fact]
    public void ParseGraphQl_throws_InvalidOperationException_wrapping_JsonException_on_non_json_body()
    {
        // Old code let JsonException propagate raw; new code wraps it with a clear message.
        var ex = Assert.Throws<InvalidOperationException>(() => GitHubAdvisoryClient.ParseGraphQl("not-valid-json{{{{"));
        Assert.Contains("unparseable", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseGraphQl_throws_descriptive_exception_on_null_json_body()
    {
        // "null" is valid JSON but root is not an Object — old code throws from TryGetProperty
        // with a generic CLR message; new code throws with "unexpected response".
        var ex = Assert.Throws<InvalidOperationException>(() => GitHubAdvisoryClient.ParseGraphQl("null"));
        Assert.Contains("unexpected response", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseGraphQl_throws_descriptive_exception_on_array_json_body()
    {
        // Array root is valid JSON but not an Object — old code throws from TryGetProperty
        // with a generic CLR message; new code throws with "unexpected response".
        var ex = Assert.Throws<InvalidOperationException>(() => GitHubAdvisoryClient.ParseGraphQl("[1,2,3]"));
        Assert.Contains("unexpected response", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
