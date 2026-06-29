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
        }
        else
        {
            builder.AppendLine($"⚠ Found {result.Vulnerabilities.Count} package(s) with known vulnerabilities:");
            builder.AppendLine();

            foreach (var vulnerability in result.Vulnerabilities)
            {
                builder.AppendLine($"  • {vulnerability.Id} ({vulnerability.Version})");
                var severities = string.Join(", ", vulnerability.Advisories.Select(a => a.Severity));
                builder.AppendLine($"    Issues: {vulnerability.Advisories.Count} | Severity: {severities}");
            }
        }

        AppendPolicyFindings(builder, result);
        AppendUnusedPackages(builder, result);
        return builder.ToString();
    }

    private static void AppendPolicyFindings(StringBuilder builder, AuditResult result)
    {
        if (result.PolicyFindings.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"⚠ Found {result.PolicyFindings.Count} policy finding(s):");
        foreach (var finding in result.PolicyFindings)
        {
            builder.AppendLine($"  • [{finding.Severity}] {finding.Message}");
        }
    }

    private static void AppendUnusedPackages(StringBuilder builder, AuditResult result)
    {
        if (result.UnusedPackages.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"ℹ Possibly unused packages (heuristic) — {result.UnusedPackages.Count} finding(s):");
        foreach (var finding in result.UnusedPackages)
        {
            builder.AppendLine($"  • {finding.Message}");
        }
    }
}
