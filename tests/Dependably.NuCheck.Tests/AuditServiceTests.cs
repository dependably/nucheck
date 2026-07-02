using NuGet.Versioning;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Services;
using Dependably.NuCheck.Tests.Fakes;

namespace Dependably.NuCheck.Tests;

public class AuditServiceTests
{
    private static readonly string[] OrderedIds = ["A", "B", "C"];

    private static PackageRef Pkg(string id, string version) => new(id, NuGetVersion.Parse(version));

    private static Advisory Advisory(string range, string severity = "high")
        => new("Summary", severity, range, ["https://example/advisory"]);

    [Fact]
    public async Task AuditAsync_reports_only_packages_in_vulnerable_range()
    {
        var source = new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>
        {
            ["Vulnerable.Pkg"] = [Advisory(">= 1.0.0, < 2.0.0")],
            ["Safe.Pkg"] = [Advisory(">= 5.0.0")], // installed version is below the range
        });

        var result = await new AuditService(source).AuditAsync(
        [
            Pkg("Vulnerable.Pkg", "1.5.0"),
            Pkg("Safe.Pkg", "1.0.0"),
            Pkg("Unknown.Pkg", "1.0.0"),
        ]);

        Assert.Equal(3, result.TotalPackages);
        var vulnerability = Assert.Single(result.Vulnerabilities);
        Assert.Equal("Vulnerable.Pkg", vulnerability.Id);
        Assert.Equal(1, result.VulnerabilityCount);
    }

    [Fact]
    public async Task AuditAsync_returns_clean_result_when_nothing_matches()
    {
        var source = new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>());

        var result = await new AuditService(source).AuditAsync([Pkg("A", "1.0.0")]);

        Assert.Empty(result.Vulnerabilities);
        Assert.Equal(0, result.VulnerabilityCount);
    }

    [Fact]
    public async Task AuditAsync_preserves_input_order_under_concurrency()
    {
        var source = new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>
        {
            ["A"] = [Advisory(">= 1.0.0")],
            ["B"] = [Advisory(">= 1.0.0")],
            ["C"] = [Advisory(">= 1.0.0")],
        });

        var result = await new AuditService(source, maxConcurrency: 8)
            .AuditAsync([Pkg("A", "1.0.0"), Pkg("B", "1.0.0"), Pkg("C", "1.0.0")]);

        Assert.Equal(OrderedIds, result.Vulnerabilities.Select(v => v.Id).ToArray());
    }

    [Fact]
    public async Task AuditAsync_propagates_a_source_failure()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new AuditService(new ThrowingSource()).AuditAsync([Pkg("Ok", "1.0.0"), Pkg("Boom", "1.0.0")]));

        Assert.Equal("query failed", ex.Message);
    }

    [Fact]
    public async Task AuditAsync_surfaces_unparseable_range_as_unverifiable_not_clean()
    {
        // Regression for #27: an advisory with an unparseable range must appear in
        // UnverifiableAdvisories, not be silently dropped (fail-open behavior).
        var source = new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>
        {
            ["Bad.Range.Pkg"] = [Advisory("~> 1.0.0")],  // tilde-range: unknown to the parser
        });

        var result = await new AuditService(source).AuditAsync([Pkg("Bad.Range.Pkg", "1.5.0")]);

        Assert.Empty(result.Vulnerabilities);
        var warning = Assert.Single(result.UnverifiableAdvisories);
        Assert.Equal("Bad.Range.Pkg", warning.PackageId);
        Assert.Equal("~> 1.0.0", warning.VulnerableVersionRange);
    }

    [Fact]
    public async Task AuditAsync_mixed_partial_failure_separates_vulnerable_and_unverifiable()
    {
        // Mixed scenario: one package vulnerable, one with unparseable range, one clean.
        // Verifies the tri-state classify runs correctly across concurrent tasks.
        var source = new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>
        {
            ["Vulnerable.Pkg"] = [Advisory(">= 1.0.0, < 2.0.0")],
            ["Unverifiable.Pkg"] = [Advisory("?? 1.0.0", "high")],  // unknown comparator
            ["Safe.Pkg"] = [Advisory(">= 9.0.0")],            // installed 1.0.0 is below range
        });

        var result = await new AuditService(source).AuditAsync(
        [
            Pkg("Vulnerable.Pkg", "1.5.0"),
            Pkg("Unverifiable.Pkg", "1.5.0"),
            Pkg("Safe.Pkg", "1.0.0"),
        ]);

        // Vulnerable goes to Vulnerabilities.
        var vuln = Assert.Single(result.Vulnerabilities);
        Assert.Equal("Vulnerable.Pkg", vuln.Id);

        // Unverifiable range goes to UnverifiableAdvisories, not silently dropped.
        var unverifiable = Assert.Single(result.UnverifiableAdvisories);
        Assert.Equal("Unverifiable.Pkg", unverifiable.PackageId);
        Assert.Equal("?? 1.0.0", unverifiable.VulnerableVersionRange);

        // Safe package produces no entry in either collection.
        Assert.DoesNotContain(result.Vulnerabilities, v => v.Id == "Safe.Pkg");
        Assert.DoesNotContain(result.UnverifiableAdvisories, u => u.PackageId == "Safe.Pkg");
    }

    [Fact]
    public async Task AuditAsync_unverifiable_advisories_do_not_set_HasFailures()
    {
        // Unverifiable ranges are advisory-only and must never trip the CI gate.
        var source = new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>
        {
            ["Bad.Range.Pkg"] = [Advisory("~> 1.0.0")],
        });

        var result = await new AuditService(source).AuditAsync([Pkg("Bad.Range.Pkg", "1.5.0")]);

        Assert.Single(result.UnverifiableAdvisories);
        Assert.False(result.HasFailures);
    }

    /// <summary>An advisory source that fails for one package, to prove the audit surfaces it.</summary>
    private sealed class ThrowingSource : IAdvisorySource
    {
        public Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default)
            => packageId == "Boom"
                ? throw new InvalidOperationException("query failed")
                : Task.FromResult<IReadOnlyList<Advisory>>([]);
    }
}
