using System.Text;
using NuGetCheck.Models;

namespace NuGetCheck.Output;

/// <summary>Formats the result as a plain-text table.</summary>
public sealed class TableResultFormatter : IResultFormatter
{
    public string Format(AuditResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine("NUGET AUDIT RESULTS");
        builder.AppendLine("===================");
        builder.AppendLine($"Total Packages:         {result.TotalPackages}");
        builder.AppendLine($"Vulnerabilities Found:  {result.VulnerabilityCount}");
        builder.AppendLine($"Policy Findings:        {result.PolicyFindings.Count}");
        builder.AppendLine($"Possibly Unused:        {result.UnusedPackages.Count} (heuristic, advisory only)");
        builder.AppendLine("-------------------");

        if (result.Vulnerabilities.Count == 0)
        {
            builder.AppendLine("✓ All packages are secure");
        }
        else
        {
            var index = 1;
            foreach (var vulnerability in result.Vulnerabilities)
            {
                builder.AppendLine($"{index}. {vulnerability.Id} ({vulnerability.Version})");
                foreach (var advisory in vulnerability.Advisories)
                {
                    builder.AppendLine($"   [{advisory.Severity}] {advisory.Summary}");
                }

                index++;
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

        builder.AppendLine("-------------------");
        builder.AppendLine("POLICY FINDINGS");
        foreach (var finding in result.PolicyFindings)
        {
            builder.AppendLine($"   [{finding.Severity}] {finding.Source} -> {finding.Host}: {finding.Message}");
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
}
