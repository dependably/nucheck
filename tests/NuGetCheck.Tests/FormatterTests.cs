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
        Assert.Contains("known vulnerabilities", vulnerable);
    }

    [Fact]
    public void Table_formatter_reports_clean_and_vulnerable()
    {
        Assert.Contains("All packages are secure", new TableResultFormatter().Format(CleanResult()));

        var vulnerable = new TableResultFormatter().Format(VulnerableResult());
        Assert.Contains("Newtonsoft.Json", vulnerable);
        Assert.Contains("[high]", vulnerable);
    }
}
