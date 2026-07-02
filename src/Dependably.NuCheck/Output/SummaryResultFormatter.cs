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
            builder.AppendLine("✓ All packages are secure - no known vulnerabilities found.");
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
        AppendUnverifiableAdvisories(builder, result);
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

    private static void AppendUnverifiableAdvisories(StringBuilder builder, AuditResult result)
    {
        if (result.UnverifiableAdvisories.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"⚠ {result.UnverifiableAdvisories.Count} unverifiable advisory range(s) — range could not be parsed, investigate manually:");
        foreach (var finding in result.UnverifiableAdvisories)
        {
            var id = string.IsNullOrEmpty(finding.AdvisoryId) ? string.Empty : $" [{finding.AdvisoryId}]";
            var sev = string.IsNullOrEmpty(finding.AdvisorySeverity) ? string.Empty : $" [{Severity.Normalize(finding.AdvisorySeverity)}]";
            builder.AppendLine($"  • {finding.PackageId}{id}{sev}: {finding.VulnerableVersionRange}");
        }
    }
}
