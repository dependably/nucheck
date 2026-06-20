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
        builder.AppendLine("-------------------");

        if (result.Vulnerabilities.Count == 0)
        {
            builder.AppendLine("✓ All packages are secure");
            return builder.ToString();
        }

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

        return builder.ToString();
    }
}
