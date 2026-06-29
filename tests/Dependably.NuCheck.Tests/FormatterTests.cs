using System.Text.Json;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Output;

namespace Dependably.NuCheck.Tests;

public class FormatterTests
{
    // The JSON formatter now needs the tool version and the scanned target for the shared
    // envelope. Tests pin a fixed version/target so assertions are deterministic.
    private static JsonResultFormatter Json() => new("9.9.9", "packages.config");

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
    public void Json_envelope_has_the_six_core_keys()
    {
        using var document = JsonDocument.Parse(Json().Format(VulnerableResult()));
        var root = document.RootElement;

        Assert.Equal("nucheck", root.GetProperty("tool").GetString());
        Assert.Equal("9.9.9", root.GetProperty("toolVersion").GetString());
        Assert.Equal("1.0", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("packages.config", root.GetProperty("target").GetString());
        Assert.True(root.TryGetProperty("summary", out _));
        Assert.Equal(JsonValueKind.Array, root.GetProperty("findings").ValueKind);
    }

    [Fact]
    public void Json_summary_counts_match_findings_and_exit_code()
    {
        using var document = JsonDocument.Parse(Json().Format(ActionableResult()));
        var root = document.RootElement;
        var summary = root.GetProperty("summary");

        Assert.Equal(4, summary.GetProperty("scanned").GetInt32());                 // packages audited
        var findingsLength = root.GetProperty("findings").GetArrayLength();
        Assert.Equal(2, findingsLength);                                            // one per advisory
        Assert.Equal(findingsLength, summary.GetProperty("findings").GetInt32());   // findings == length
        Assert.Equal(1, summary.GetProperty("exitCode").GetInt32());               // vulns -> exit 1

        var bySeverity = summary.GetProperty("bySeverity");
        Assert.Equal(1, bySeverity.GetProperty("high").GetInt32());
        Assert.Equal(1, bySeverity.GetProperty("moderate").GetInt32());
        Assert.Equal(0, bySeverity.GetProperty("critical").GetInt32());

        // bySeverity buckets sum to the findings count.
        var sum = bySeverity.GetProperty("critical").GetInt32()
                  + bySeverity.GetProperty("high").GetInt32()
                  + bySeverity.GetProperty("moderate").GetInt32()
                  + bySeverity.GetProperty("low").GetInt32()
                  + bySeverity.GetProperty("info").GetInt32();
        Assert.Equal(findingsLength, sum);
    }

    [Fact]
    public void Json_vulnerability_finding_has_schema_shape_and_extra()
    {
        using var document = JsonDocument.Parse(Json().Format(ActionableResult()));
        var finding = document.RootElement.GetProperty("findings")[0];

        Assert.Equal("high", finding.GetProperty("severity").GetString());
        Assert.Equal("GHSA-aaaa-bbbb-cccc", finding.GetProperty("ruleId").GetString()); // GHSA when available
        Assert.Equal("vulnerability", finding.GetProperty("category").GetString());
        Assert.Equal("Denial of service", finding.GetProperty("message").GetString());  // advisory title
        Assert.Equal(JsonValueKind.Null, finding.GetProperty("location").ValueKind);    // not file-scoped
        Assert.Equal("upgrade to 13.0.1", finding.GetProperty("remediation").GetString());

        var extra = finding.GetProperty("extra");
        Assert.Equal("Newtonsoft.Json", extra.GetProperty("package").GetString());
        Assert.Equal("11.0.2", extra.GetProperty("installedVersion").GetString());
        Assert.Equal("13.0.1", extra.GetProperty("fixedVersion").GetString());
        Assert.Equal("GHSA-aaaa-bbbb-cccc", extra.GetProperty("advisoryId").GetString());
        Assert.Equal("CVE-2024-0001", extra.GetProperty("cve").GetString());
        Assert.Equal(">= 1.0.0, < 13.0.1", extra.GetProperty("vulnerableRange").GetString());
        Assert.Equal("https://example/1", extra.GetProperty("references")[0].GetString());

        // A field the source did not supply is emitted as JSON null, never fabricated.
        var second = document.RootElement.GetProperty("findings")[1];
        Assert.Equal(JsonValueKind.Null, second.GetProperty("extra").GetProperty("cve").ValueKind);
    }

    [Fact]
    public void Json_clean_result_has_no_findings_and_exit_zero()
    {
        using var document = JsonDocument.Parse(Json().Format(CleanResult()));
        var root = document.RootElement;

        Assert.Equal(0, root.GetProperty("findings").GetArrayLength());
        Assert.Equal(0, root.GetProperty("summary").GetProperty("findings").GetInt32());
        Assert.Equal(0, root.GetProperty("summary").GetProperty("exitCode").GetInt32());
        Assert.Equal(3, root.GetProperty("summary").GetProperty("scanned").GetInt32());
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
    [InlineData("human", typeof(SummaryResultFormatter))]
    [InlineData("unknown", typeof(SummaryResultFormatter))]
    [InlineData(null, typeof(SummaryResultFormatter))]
    public void Factory_selects_formatter(string? format, Type expected)
    {
        Assert.IsType(expected, FormatterFactory.Get(format, "9.9.9", "packages.config"));
    }

    [Fact]
    public void Summary_formatter_reports_clean_and_vulnerable()
    {
        Assert.Contains("All packages are secure", new SummaryResultFormatter().Format(CleanResult()));

        var vulnerable = new SummaryResultFormatter().Format(VulnerableResult());
        Assert.Contains("Newtonsoft.Json", vulnerable);
        // Headline wording reports BOTH counts explicitly so no format contradicts another.
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
    public void Summary_formatter_renders_policy_findings_with_ladder_severity()
    {
        var output = new SummaryResultFormatter().Format(PolicyResult());

        Assert.Contains("policy finding", output);
        Assert.Contains("nuget.evil.example", output);
        // Source-trust "error" maps onto the ladder as "high".
        Assert.Contains("[high]", output);
    }

    [Fact]
    public void Json_renders_policy_finding_as_policy_category()
    {
        using var document = JsonDocument.Parse(Json().Format(PolicyResult()));
        var root = document.RootElement;

        Assert.Equal(1, root.GetProperty("findings").GetArrayLength());
        // A policy error fails the audit -> exit 1.
        Assert.Equal(1, root.GetProperty("summary").GetProperty("exitCode").GetInt32());

        var finding = root.GetProperty("findings")[0];
        Assert.Equal("policy", finding.GetProperty("category").GetString());
        Assert.Equal("high", finding.GetProperty("severity").GetString());
        Assert.Equal("untrusted-source", finding.GetProperty("ruleId").GetString());
        Assert.Equal(JsonValueKind.Null, finding.GetProperty("location").ValueKind);
        Assert.Equal("nuget.evil.example", finding.GetProperty("extra").GetProperty("host").GetString());
        Assert.Equal("private", finding.GetProperty("extra").GetProperty("source").GetString());
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
        Assert.Contains("advisory only", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Json_renders_unused_package_as_info_finding()
    {
        using var document = JsonDocument.Parse(Json().Format(UnusedResult()));
        var root = document.RootElement;

        // Unused findings are advisory only — they never fail the audit.
        Assert.Equal(0, root.GetProperty("summary").GetProperty("exitCode").GetInt32());
        var finding = root.GetProperty("findings")[0];
        Assert.Equal("unused", finding.GetProperty("category").GetString());
        Assert.Equal("info", finding.GetProperty("severity").GetString());
        Assert.Equal("Serilog", finding.GetProperty("extra").GetProperty("package").GetString());
        Assert.Contains("heuristic", finding.GetProperty("message").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Summary_formatter_does_not_render_unused_section_when_none()
    {
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
