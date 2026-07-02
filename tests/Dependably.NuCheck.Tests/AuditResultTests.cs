using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Tests;

public class AuditResultTests
{
    private static AuditResult Build() => new()
    {
        TotalPackages = 1,
        Vulnerabilities =
        [
            new PackageVulnerability("Pkg", "1.0.0",
            [
                new Advisory("High issue", "high", ">= 1.0", []),
                new Advisory("Low issue", "low", ">= 1.0", []),
            ]),
        ],
    };

    [Fact]
    public void VulnerabilityCount_sums_advisories()
    {
        Assert.Equal(2, Build().VulnerabilityCount);
    }

    [Fact]
    public void FilterBySeverity_keeps_only_matching_severity()
    {
        var filtered = Build().FilterBySeverity("high");

        var vulnerability = Assert.Single(filtered.Vulnerabilities);
        var advisory = Assert.Single(vulnerability.Advisories);
        Assert.Equal("high", advisory.Severity);
        Assert.Equal(1, filtered.TotalPackages);
    }

    [Fact]
    public void FilterBySeverity_drops_packages_with_no_matches()
    {
        Assert.Empty(Build().FilterBySeverity("critical").Vulnerabilities);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void FilterBySeverity_blank_returns_same_instance(string? severity)
    {
        var result = Build();
        Assert.Same(result, result.FilterBySeverity(severity));
    }

    [Fact]
    public void HasFailures_true_for_policy_error_without_vulnerabilities()
    {
        var result = new AuditResult
        {
            TotalPackages = 1,
            Vulnerabilities = [],
            PolicyFindings = [new SourceFinding("h", "s", "m")],
        };

        Assert.Equal(1, result.PolicyErrorCount);
        Assert.True(result.HasFailures);
    }

    [Fact]
    public void HasFailures_false_when_clean()
    {
        var result = new AuditResult { TotalPackages = 1, Vulnerabilities = [], PolicyFindings = [] };
        Assert.False(result.HasFailures);
    }

    [Fact]
    public void HasFailures_false_when_only_unused_packages_found()
    {
        // Unused-package findings are advisory only and must never flip the exit code.
        var result = new AuditResult
        {
            TotalPackages = 1,
            Vulnerabilities = [],
            PolicyFindings = [],
            UnusedPackages = [new UnusedPackageFinding("Foo.Bar", "heuristic message")],
        };

        Assert.False(result.HasFailures);
        Assert.Equal(0, result.VulnerabilityCount);
        Assert.Equal(0, result.PolicyErrorCount);
        Assert.Single(result.UnusedPackages);
    }

    [Fact]
    public void FilterBySeverity_preserves_policy_findings()
    {
        var result = new AuditResult
        {
            TotalPackages = 1,
            Vulnerabilities = Build().Vulnerabilities,
            PolicyFindings = [new SourceFinding("h", "s", "m")],
        };

        var filtered = result.FilterBySeverity("high");

        Assert.Single(filtered.PolicyFindings);
    }

    // ---- the unified --fail-on gate -------------------------------------------------

    private static AuditResult WithVuln(string severity) => new()
    {
        TotalPackages = 1,
        Vulnerabilities =
        [
            new PackageVulnerability("Pkg", "1.0.0", [new Advisory("x", severity, ">= 1.0", [])]),
        ],
    };

    [Fact]
    public void GateTrips_with_no_rules_falls_back_to_default_any_failure()
    {
        // No --fail-on: a vulnerability trips, a clean result does not.
        Assert.True(WithVuln("low").GateTrips(null, null));
        Assert.False(new AuditResult { TotalPackages = 1 }.GateTrips(null, null));
    }

    [Fact]
    public void GateTrips_severity_relaxes_below_the_level()
    {
        // --fail-on severity=high ignores a moderate-only vuln for gating (exit 0) ...
        Assert.False(WithVuln("moderate").GateTrips("high", null));
        // ... but trips on a high one (exit 1).
        Assert.True(WithVuln("high").GateTrips("high", null));
        // ... and on anything above it.
        Assert.True(WithVuln("critical").GateTrips("high", null));
    }

    [Fact]
    public void GateTrips_severity_normalises_raw_finding_words()
    {
        // A raw "medium" finding ranks as moderate, so severity=high does not trip on it.
        Assert.False(WithVuln("medium").GateTrips("high", null));
    }

    [Fact]
    public void GateTrips_severity_considers_policy_findings()
    {
        // A policy finding's "error" severity maps to high, so severity=high still gates it.
        var result = new AuditResult
        {
            TotalPackages = 1,
            Vulnerabilities = [],
            PolicyFindings = [new SourceFinding("h", "s", "m")],
        };

        Assert.True(result.GateTrips("high", null));
        Assert.False(result.GateTrips("critical", null));
    }

    [Theory]
    [InlineData(0, true)]   // 2 advisories > 0  -> trip
    [InlineData(2, false)]  // 2 advisories > 2  -> no trip
    [InlineData(1, true)]   // 2 advisories > 1  -> trip
    public void GateTrips_count_trips_when_vulnerability_count_exceeds_n(int n, bool expected)
    {
        Assert.Equal(expected, Build().GateTrips(null, n));
    }

    [Fact]
    public void GateTrips_rules_are_ored_together()
    {
        // A moderate-only vuln: severity=high alone would not trip, but count=0 does.
        Assert.True(WithVuln("moderate").GateTrips("high", 0));
    }

    [Fact]
    public void GateTrips_count_only_still_gates_a_policy_error()
    {
        // Regression: a count-only gate (no severity rule) must NOT silently drop the
        // untrusted-source policy check. count=0 with zero vulnerabilities but a policy
        // error must still trip (exit 1) — the supply-chain gate stays live.
        var result = new AuditResult
        {
            TotalPackages = 1,
            Vulnerabilities = [],
            PolicyFindings = [new SourceFinding("evil.example", "s", "untrusted")],
        };

        Assert.Equal(0, result.VulnerabilityCount);
        Assert.Equal(1, result.PolicyErrorCount);
        Assert.True(result.GateTrips(null, 0));
        // A higher count threshold does not rescue a policy error either.
        Assert.True(result.GateTrips(null, 99));
    }

    [Fact]
    public void GateTrips_count_only_mixed_partial_failure_gates_on_policy_even_when_vuln_count_passes()
    {
        // Mixed batch: the vulnerability half PASSES the count threshold (2 advisories, count=5),
        // but a policy error is present. With count-only gating the policy half must still trip,
        // so the overall gate fails rather than exiting 0 on the untrusted source.
        var result = new AuditResult
        {
            TotalPackages = 2,
            Vulnerabilities = Build().Vulnerabilities, // 2 advisories
            PolicyFindings = [new SourceFinding("evil.example", "s", "untrusted")],
        };

        Assert.Equal(2, result.VulnerabilityCount);
        Assert.False(result.VulnerabilityCount > 5); // vuln half alone would not trip
        Assert.True(result.GateTrips(null, 5));       // ... but the policy error does
    }

    [Fact]
    public void GateTrips_count_only_clean_result_does_not_trip()
    {
        // No vulnerabilities under the threshold AND no policy errors: still exit 0.
        var clean = new AuditResult { TotalPackages = 1, Vulnerabilities = [], PolicyFindings = [] };
        Assert.False(clean.GateTrips(null, 0));
    }

    [Fact]
    public void GateTrips_severity_rule_still_governs_policy_errors_symmetrically()
    {
        // An explicit severity rule remains the ONLY way to relax a policy error: a policy
        // error maps to high, so severity=critical deliberately does not trip, but a
        // co-present count rule does not resurrect it via the always-on path either.
        var result = new AuditResult
        {
            TotalPackages = 1,
            Vulnerabilities = [],
            PolicyFindings = [new SourceFinding("h", "s", "m")],
        };

        Assert.False(result.GateTrips("critical", 5)); // count passes, severity relaxes policy
        Assert.True(result.GateTrips("high", 5));       // severity=high gates the policy error
    }

    [Fact]
    public void FilterBySeverity_preserves_unused_packages()
    {
        var result = new AuditResult
        {
            TotalPackages = 1,
            Vulnerabilities = Build().Vulnerabilities,
            PolicyFindings = [],
            UnusedPackages = [new UnusedPackageFinding("Foo.Bar", "msg")],
        };

        var filtered = result.FilterBySeverity("high");

        Assert.Single(filtered.UnusedPackages);
        Assert.Equal("Foo.Bar", filtered.UnusedPackages[0].Id);
    }
}
