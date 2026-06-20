using System.Text;
using NuGetCheck.Models;

namespace NuGetCheck.Output;

/// <summary>Formats the result as a brief human-readable summary.</summary>
public sealed class SummaryResultFormatter : IResultFormatter
{
    public string Format(AuditResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"Found {result.TotalPackages} packages in audit.");

        if (result.VulnerabilityCount == 0)
        {
            builder.AppendLine("✓ All packages are secure - no known vulnerabilities found.");
            return builder.ToString();
        }

        builder.AppendLine($"⚠ Found {result.Vulnerabilities.Count} package(s) with known vulnerabilities:");
        builder.AppendLine();

        foreach (var vulnerability in result.Vulnerabilities)
        {
            builder.AppendLine($"  • {vulnerability.Id} ({vulnerability.Version})");
            var severities = string.Join(", ", vulnerability.Advisories.Select(a => a.Severity));
            builder.AppendLine($"    Issues: {vulnerability.Advisories.Count} | Severity: {severities}");
        }

        return builder.ToString();
    }
}
