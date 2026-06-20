using NuGet.Versioning;
using NuGetCheck.Models;
using NuGetCheck.Services;
using NuGetCheck.Tests.Fakes;

namespace NuGetCheck.Tests;

public class AuditServiceTests
{
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
}
