using System.Text.Json;
using Dependably.NuCheck.Config;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Tests;

public class ExceptionApplierTests
{
    private static IReadOnlyList<DependablyException> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return DependablyExceptions.Parse(doc.RootElement, "own", DependablyExceptions.NuCheckSelectors, DependablyExceptions.KnownRules);
    }

    private static PackageVulnerability Vuln(string id, string version, string? advisoryId)
        => new(id, version, [new Advisory("summary", "high", "< 9.9", [], AdvisoryId: advisoryId)]);

    [Fact]
    public void No_exceptions_returns_input_unchanged()
    {
        var vulns = new[] { Vuln("Foo", "1.0.0", "GHSA-x") };
        var result = ExceptionApplier.Apply(vulns, [], [], []);
        Assert.Same(vulns, result.Vulnerabilities);
        Assert.Empty(result.Notices);
    }

    [Fact]
    public void Suppresses_vulnerability_by_package_version_and_advisory_id()
    {
        var vulns = new[] { Vuln("log4net", "2.0.8", "GHSA-2cwj"), Vuln("log4net", "2.0.15", "GHSA-2cwj") };
        var exceptions = Parse("""[{ "rule": "vulnerable-package", "package": "log4net@2.0.8", "id": "GHSA-2cwj", "reason": "unreachable" }]""");

        var result = ExceptionApplier.Apply(vulns, [], [], exceptions, new DateOnly(2026, 7, 3));

        Assert.Single(result.Vulnerabilities);                       // only 2.0.15 remains
        Assert.Equal("2.0.15", result.Vulnerabilities[0].Version);
        Assert.Contains(result.Notices, n => n.Contains("1 finding(s) suppressed"));
    }

    [Fact]
    public void Suppresses_unused_package_by_name()
    {
        var unused = new[] { new UnusedPackageFinding("StyleCop.Analyzers", "unused") };
        var exceptions = Parse("""[{ "rule": "unused-packages", "package": "StyleCop.Analyzers", "reason": "analyzer" }]""");

        var result = ExceptionApplier.Apply([], unused, [], exceptions, new DateOnly(2026, 7, 3));

        Assert.Empty(result.UnusedPackages);
    }

    [Fact]
    public void Expired_exception_does_not_suppress_and_is_reported()
    {
        var vulns = new[] { Vuln("Foo", "1.0.0", "GHSA-x") };
        var exceptions = Parse("""[{ "rule": "vulnerable-package", "package": "Foo", "reason": "temp", "expires": "2000-01-01" }]""");

        var result = ExceptionApplier.Apply(vulns, [], [], exceptions, new DateOnly(2026, 7, 3));

        Assert.Single(result.Vulnerabilities);
        Assert.Contains(result.Notices, n => n.Contains("expired"));
    }

    [Fact]
    public void Unused_exception_is_reported()
    {
        var vulns = new[] { Vuln("Foo", "1.0.0", "GHSA-x") };
        var exceptions = Parse("""[{ "rule": "vulnerable-package", "package": "never-seen", "reason": "stale" }]""");

        var result = ExceptionApplier.Apply(vulns, [], [], exceptions, new DateOnly(2026, 7, 3));

        Assert.Single(result.Vulnerabilities);
        Assert.Contains(result.Notices, n => n.Contains("unused exception"));
    }

    // ---- pinned-versions suppression ----------------------------------------------

    [Fact]
    public void Suppresses_pinned_finding_by_package()
    {
        var pinned = new[] { new PinnedVersionFinding("Float.Pkg", "6.*", "app.csproj", "unpinned") };
        var exceptions = Parse("""[{ "rule": "pinned-versions", "package": "Float.Pkg", "reason": "vendor requires floating" }]""");

        var result = ExceptionApplier.Apply([], [], [], exceptions, new DateOnly(2026, 7, 3), pinned);

        Assert.Empty(result.PinnedVersionFindings);
        Assert.Contains(result.Notices, n => n.Contains("1 finding(s) suppressed"));
    }

    [Fact]
    public void Pinned_exception_with_version_pin_matches_declared_version_only()
    {
        var pinned = new[]
        {
            new PinnedVersionFinding("Float.Pkg", "6.*", "app.csproj", "unpinned"),
            new PinnedVersionFinding("Float.Pkg", "7.*", "other.csproj", "unpinned"),
        };
        var exceptions = Parse("""[{ "rule": "pinned-versions", "package": "Float.Pkg@6.*", "reason": "legacy TFM" }]""");

        var result = ExceptionApplier.Apply([], [], [], exceptions, new DateOnly(2026, 7, 3), pinned);

        var kept = Assert.Single(result.PinnedVersionFindings);
        Assert.Equal("7.*", kept.RawVersion);
    }

    [Fact]
    public void Pinned_findings_pass_through_with_no_exceptions()
    {
        var pinned = new[] { new PinnedVersionFinding("Float.Pkg", "6.*", "app.csproj", "unpinned") };

        var result = ExceptionApplier.Apply([], [], [], [], pinnedVersionFindings: pinned);

        Assert.Same(pinned, result.PinnedVersionFindings);
    }
}
