using System.Text.Json;
using NuGetCheck.Models;

namespace NuGetCheck.Output;

/// <summary>Formats the result as indented JSON.</summary>
public sealed class JsonResultFormatter : IResultFormatter
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public string Format(AuditResult result)
    {
        var dto = new
        {
            totalPackages = result.TotalPackages,
            vulnerabilityCount = result.VulnerabilityCount,
            vulnerabilities = result.Vulnerabilities.Select(v => new
            {
                id = v.Id,
                version = v.Version,
                issues = v.Advisories.Select(a => new
                {
                    summary = a.Summary,
                    severity = a.Severity,
                    vulnerableVersionRange = a.VulnerableVersionRange,
                    references = a.References,
                }),
            }),
        };

        return JsonSerializer.Serialize(dto, Options);
    }
}
