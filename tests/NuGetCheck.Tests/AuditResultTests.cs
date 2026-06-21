using NuGetCheck.Models;

namespace NuGetCheck.Tests;

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
}
