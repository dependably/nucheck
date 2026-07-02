using System.Text;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Output;

/// <summary>Formats the result as a brief human-readable summary.</summary>
public sealed class SummaryResultFormatter : IResultFormatter
{
    public string Format(AuditResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"Found {result.TotalPackages} packages in audit.");

        if (result.VulnerabilityCount == 0)
        {
            if (result.HiddenAdvisoryCount > 0)
            {
                builder.AppendLine(
                    $"0 advisories at or above {result.DisplaySeverityFilter} shown; " +
                    $"{result.HiddenAdvisoryCount} advisory(ies) hidden by --severity {result.DisplaySeverityFilter}.");
            }
            else
            {
                builder.AppendLine("✓ All packages are secure - no known vulnerabilities found.");
            }
        }
        else
        {
            // Report BOTH counts so this headline cannot contradict the table/json formats,
            // which count advisories: one package can carry several advisories.
            builder.AppendLine(
                $"⚠ Found {result.VulnerablePackageCount} vulnerable package(s), " +
                $"{result.VulnerabilityCount} advisory(ies):");
            builder.AppendLine();

            foreach (var vulnerability in result.Vulnerabilities)
            {
                builder.AppendLine($"  • {vulnerability.Id} ({vulnerability.Version})");
                var severities = string.Join(", ", vulnerability.Advisories.Select(a => Severity.Normalize(a.Severity)));
                builder.AppendLine($"    Issues: {vulnerability.Advisories.Count} | Severity: {severities}");

                var fixes = vulnerability.Advisories
                    .Select(a => a.FixedVersion)
                    .Where(v => !string.IsNullOrEmpty(v))
                    .Distinct()
                    .ToList();
                if (fixes.Count > 0)
                {
                    builder.AppendLine($"    Fixed in: {string.Join(", ", fixes)}");
                }
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
            builder.AppendLine($"  • [{Severity.Normalize(finding.Severity)}] {finding.Message}");
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
