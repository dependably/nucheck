using System.Text;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Output;

/// <summary>Formats the result as a plain-text table.</summary>
public sealed class TableResultFormatter : IResultFormatter
{
    public string Format(AuditResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine("NUGET AUDIT RESULTS");
        builder.AppendLine("===================");
        builder.AppendLine($"Total Packages:         {result.TotalPackages}");
        builder.AppendLine($"Vulnerable Packages:    {result.VulnerablePackageCount}");
        builder.AppendLine($"Advisories Found:       {result.VulnerabilityCount}");
        builder.AppendLine($"Policy Findings:        {result.PolicyFindings.Count}");
        builder.AppendLine($"Possibly Unused:        {result.UnusedPackages.Count} (heuristic, advisory only)");
        builder.AppendLine($"Unverifiable Ranges:    {result.UnverifiableAdvisories.Count} (range not parsed — investigate)");
        builder.AppendLine("-------------------");

        AppendVulnerabilities(builder, result);
        AppendPolicyFindings(builder, result);
        AppendUnusedPackages(builder, result);
        AppendUnverifiableAdvisories(builder, result);
        return builder.ToString();
    }

    private static void AppendVulnerabilities(StringBuilder builder, AuditResult result)
    {
        if (result.Vulnerabilities.Count == 0)
        {
            builder.AppendLine("✓ All packages are secure");
            return;
        }

        var index = 1;
        foreach (var vulnerability in result.Vulnerabilities)
        {
            builder.AppendLine($"{index}. {vulnerability.Id} ({vulnerability.Version})");
            AppendAdvisories(builder, vulnerability.Advisories);
            index++;
        }
    }

    private static void AppendAdvisories(StringBuilder builder, IEnumerable<Models.Advisory> advisories)
    {
        foreach (var advisory in advisories)
        {
            builder.AppendLine($"   [{Severity.Normalize(advisory.Severity)}] {advisory.Summary}");
            var detail = AdvisoryDetail(advisory);
            if (detail.Length > 0)
            {
                builder.AppendLine($"      {detail}");
            }
        }
    }

    /// <summary>
    /// The actionable one-liner for an advisory: discrete advisory id, CVE, and the fixed
    /// version where each is known. Returns empty when the source supplied none of them.
    /// </summary>
    private static string AdvisoryDetail(Models.Advisory advisory)
    {
        var parts = new List<string>(3);
        if (!string.IsNullOrEmpty(advisory.AdvisoryId))
        {
            parts.Add(advisory.AdvisoryId);
        }

        if (!string.IsNullOrEmpty(advisory.Cve))
        {
            parts.Add(advisory.Cve);
        }

        if (!string.IsNullOrEmpty(advisory.FixedVersion))
        {
            parts.Add($"fixed in {advisory.FixedVersion}");
        }

        return string.Join(" | ", parts);
    }

    private static void AppendPolicyFindings(StringBuilder builder, AuditResult result)
    {
        if (result.PolicyFindings.Count == 0)
        {
            return;
        }

        builder.AppendLine("-------------------");
        builder.AppendLine("POLICY FINDINGS");
        foreach (var finding in result.PolicyFindings)
        {
            builder.AppendLine($"   [{Severity.Normalize(finding.Severity)}] {finding.Source} -> {finding.Host}: {finding.Message}");
        }
    }

    private static void AppendUnusedPackages(StringBuilder builder, AuditResult result)
    {
        if (result.UnusedPackages.Count == 0)
        {
            return;
        }

        builder.AppendLine("-------------------");
        builder.AppendLine("POSSIBLY UNUSED PACKAGES (HEURISTIC — ADVISORY ONLY)");
        foreach (var finding in result.UnusedPackages)
        {
            builder.AppendLine($"   {finding.Id}: {finding.Message}");
        }
    }

    private static void AppendUnverifiableAdvisories(StringBuilder builder, AuditResult result)
    {
        if (result.UnverifiableAdvisories.Count == 0)
        {
            return;
        }

        builder.AppendLine("-------------------");
        builder.AppendLine("UNVERIFIABLE ADVISORY RANGES (investigate manually — range could not be parsed)");
        foreach (var finding in result.UnverifiableAdvisories)
        {
            var id = string.IsNullOrEmpty(finding.AdvisoryId) ? string.Empty : $" [{finding.AdvisoryId}]";
            var sev = string.IsNullOrEmpty(finding.AdvisorySeverity) ? string.Empty : $" [{Severity.Normalize(finding.AdvisorySeverity)}]";
            builder.AppendLine($"   {finding.PackageId}{id}{sev}: {finding.VulnerableVersionRange}");
        }
    }
}
