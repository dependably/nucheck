using System.Text.Json;
using NuGetCheck.Models;
using NuGetCheck.Output;

namespace NuGetCheck.Tests;

public class FormatterTests
{
    private static AuditResult VulnerableResult() => new()
    {
        TotalPackages = 2,
        Vulnerabilities =
        [
            new PackageVulnerability("Newtonsoft.Json", "11.0.2",
                [new Advisory("Denial of service", "high", ">= 1.0.0, < 13.0.1", ["https://example/1"])]),
        ],
    };

    private static AuditResult CleanResult() => new() { TotalPackages = 3, Vulnerabilities = [] };

    // One package, two advisories — exercises the package-vs-advisory count distinction
    // and carries the appended actionable fields (advisoryId / cve / fixedVersion).
    private static AuditResult ActionableResult() => new()
    {
        TotalPackages = 4,
        Vulnerabilities =
        [
            new PackageVulnerability("Newtonsoft.Json", "11.0.2",
            [
                new Advisory("Denial of service", "high", ">= 1.0.0, < 13.0.1", ["https://example/1"],
                    AdvisoryId: "GHSA-aaaa-bbbb-cccc", Cve: "CVE-2024-0001", FixedVersion: "13.0.1"),
                new Advisory("Second issue", "moderate", ">= 1.0.0, < 12.0.0", ["https://example/2"],
                    AdvisoryId: "GHSA-dddd-eeee-ffff", Cve: null, FixedVersion: "12.0.0"),
            ]),
        ],
    };

    [Fact]
    public void Json_formatter_emits_advisory_id_cve_and_fixed_version()
    {
        var output = new JsonResultFormatter().Format(ActionableResult());

        using var document = JsonDocument.Parse(output);
        var root = document.RootElement;
        // Both counts are present and explicit: 1 package, 2 advisories.
        Assert.Equal(1, root.GetProperty("vulnerablePackageCount").GetInt32());
        Assert.Equal(2, root.GetProperty("vulnerabilityCount").GetInt32());

        var issue = root.GetProperty("vulnerabilities")[0].GetProperty("issues")[0];
        Assert.Equal("GHSA-aaaa-bbbb-cccc", issue.GetProperty("advisoryId").GetString());
        Assert.Equal("CVE-2024-0001", issue.GetProperty("cve").GetString());
        Assert.Equal("13.0.1", issue.GetProperty("fixedVersion").GetString());

        // A field the source did not supply is emitted as JSON null, never fabricated.
        var second = root.GetProperty("vulnerabilities")[0].GetProperty("issues")[1];
        Assert.Equal(JsonValueKind.Null, second.GetProperty("cve").ValueKind);
    }

    [Fact]
    public void Table_formatter_shows_both_counts_and_actionable_fields()
    {
        var output = new TableResultFormatter().Format(ActionableResult());

        Assert.Contains("Vulnerable Packages:    1", output);
        Assert.Contains("Advisories Found:       2", output);
        Assert.Contains("GHSA-aaaa-bbbb-cccc", output);
        Assert.Contains("CVE-2024-0001", output);
        Assert.Contains("fixed in 13.0.1", output);
    }

    [Fact]
    public void Summary_formatter_reports_both_counts_and_fixed_version()
    {
        var output = new SummaryResultFormatter().Format(ActionableResult());

        // Headline reports both packages and advisories so it cannot contradict table/json.
        Assert.Contains("1 vulnerable package(s)", output);
        Assert.Contains("2 advisory(ies)", output);
        Assert.Contains("Fixed in:", output);
        Assert.Contains("13.0.1", output);
    }

    [Theory]
    [InlineData("json", typeof(JsonResultFormatter))]
    [InlineData("JSON", typeof(JsonResultFormatter))]
    [InlineData("table", typeof(TableResultFormatter))]
    [InlineData("summary", typeof(SummaryResultFormatter))]
    [InlineData("unknown", typeof(SummaryResultFormatter))]
    [InlineData(null, typeof(SummaryResultFormatter))]
    public void Factory_selects_formatter(string? format, Type expected)
    {
        Assert.IsType(expected, FormatterFactory.Get(format));
    }

    [Fact]
    public void Json_formatter_emits_parseable_json_with_counts()
    {
        var output = new JsonResultFormatter().Format(VulnerableResult());

        using var document = JsonDocument.Parse(output);
        Assert.Equal(2, document.RootElement.GetProperty("totalPackages").GetInt32());
        Assert.Equal(1, document.RootElement.GetProperty("vulnerabilityCount").GetInt32());
        Assert.Equal("Newtonsoft.Json",
            document.RootElement.GetProperty("vulnerabilities")[0].GetProperty("id").GetString());
    }

    [Fact]
    public void Summary_formatter_reports_clean_and_vulnerable()
    {
        Assert.Contains("All packages are secure", new SummaryResultFormatter().Format(CleanResult()));

        var vulnerable = new SummaryResultFormatter().Format(VulnerableResult());
        Assert.Contains("Newtonsoft.Json", vulnerable);
        // Headline wording changed in the P1 work to report BOTH counts explicitly
        // ("N vulnerable package(s), M advisory(ies)") so no format contradicts another.
        Assert.Contains("vulnerable package(s)", vulnerable);
        Assert.Contains("advisory(ies)", vulnerable);
    }

    [Fact]
    public void Table_formatter_reports_clean_and_vulnerable()
    {
        Assert.Contains("All packages are secure", new TableResultFormatter().Format(CleanResult()));

        var vulnerable = new TableResultFormatter().Format(VulnerableResult());
        Assert.Contains("Newtonsoft.Json", vulnerable);
        Assert.Contains("[high]", vulnerable);
    }

    private static AuditResult PolicyResult() => new()
    {
        TotalPackages = 1,
        Vulnerabilities = [],
        PolicyFindings =
        [
            new SourceFinding("nuget.evil.example", "private", "untrusted host 'nuget.evil.example'"),
        ],
    };

    [Fact]
    public void Summary_formatter_renders_policy_findings()
    {
        var output = new SummaryResultFormatter().Format(PolicyResult());

        Assert.Contains("policy finding", output);
        Assert.Contains("nuget.evil.example", output);
        Assert.Contains("[error]", output);
    }

    [Fact]
    public void Json_formatter_renders_policy_findings()
    {
        var output = new JsonResultFormatter().Format(PolicyResult());

        using var document = JsonDocument.Parse(output);
        Assert.Equal(1, document.RootElement.GetProperty("policyErrorCount").GetInt32());
        var finding = document.RootElement.GetProperty("policyFindings")[0];
        Assert.Equal("nuget.evil.example", finding.GetProperty("host").GetString());
        Assert.Equal("private", finding.GetProperty("source").GetString());
        Assert.Equal("error", finding.GetProperty("severity").GetString());
    }

    private static AuditResult UnusedResult() => new()
    {
        TotalPackages = 2,
        Vulnerabilities = [],
        PolicyFindings = [],
        UnusedPackages =
        [
            new UnusedPackageFinding("Serilog", "Package 'Serilog' does not appear to be referenced (heuristic)."),
        ],
    };

    [Fact]
    public void Summary_formatter_renders_unused_packages()
    {
        var output = new SummaryResultFormatter().Format(UnusedResult());

        Assert.Contains("Possibly unused", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("heuristic", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Serilog", output);
    }

    [Fact]
    public void Table_formatter_renders_unused_packages()
    {
        var output = new TableResultFormatter().Format(UnusedResult());

        Assert.Contains("POSSIBLY UNUSED", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("heuristic", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Serilog", output);
        // Count line shows the advisory label
        Assert.Contains("advisory only", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Json_formatter_renders_unused_packages()
    {
        var output = new JsonResultFormatter().Format(UnusedResult());

        using var document = JsonDocument.Parse(output);
        Assert.Equal(1, document.RootElement.GetProperty("unusedPackageCount").GetInt32());
        var arr = document.RootElement.GetProperty("unusedPackages");
        Assert.Equal(1, arr.GetArrayLength());
        Assert.Equal("Serilog", arr[0].GetProperty("id").GetString());
        Assert.Contains("heuristic", arr[0].GetProperty("message").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Summary_formatter_does_not_render_unused_section_when_none()
    {
        // No unused packages → the advisory section should not appear.
        var output = new SummaryResultFormatter().Format(CleanResult());
        Assert.DoesNotContain("Possibly unused", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Table_formatter_shows_zero_count_for_unused_even_when_none()
    {
        var output = new TableResultFormatter().Format(CleanResult());
        Assert.Contains("Possibly Unused:", output);
        Assert.Contains("0", output);
    }
}
