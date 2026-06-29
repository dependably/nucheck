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
            policyErrorCount = result.PolicyErrorCount,
            unusedPackageCount = result.UnusedPackages.Count,
            // Appended (kept after the original counts) so consumers reading by name stay
            // stable. vulnerabilityCount counts advisories; this counts distinct packages.
            vulnerablePackageCount = result.VulnerablePackageCount,
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
                    // Appended actionable fields; null when the source did not supply them.
                    advisoryId = a.AdvisoryId,
                    cve = a.Cve,
                    fixedVersion = a.FixedVersion,
                }),
            }),
            policyFindings = result.PolicyFindings.Select(f => new
            {
                host = f.Host,
                source = f.Source,
                message = f.Message,
                severity = f.Severity,
            }),
            unusedPackages = result.UnusedPackages.Select(u => new
            {
                id = u.Id,
                message = u.Message,
            }),
        };

        return JsonSerializer.Serialize(dto, Options);
    }
}
