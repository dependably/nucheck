namespace NuGetCheck.Models;

/// <summary>Advisories that actually apply to an installed package version.</summary>
public sealed record PackageVulnerability(
    string Id,
    string Version,
    IReadOnlyList<Advisory> Advisories);

/// <summary>The outcome of auditing a packages file.</summary>
public sealed class AuditResult
{
    public int TotalPackages { get; init; }

    public IReadOnlyList<PackageVulnerability> Vulnerabilities { get; init; } = [];

    /// <summary>Total number of advisories across all vulnerable packages.</summary>
    public int VulnerabilityCount => Vulnerabilities.Sum(v => v.Advisories.Count);

    /// <summary>
    /// Return a copy keeping only advisories of the given severity (case-insensitive).
    /// A null/blank severity returns this result unchanged.
    /// </summary>
    public AuditResult FilterBySeverity(string? severity)
    {
        if (string.IsNullOrWhiteSpace(severity))
        {
            return this;
        }

        var filtered = Vulnerabilities
            .Select(v => v with
            {
                Advisories = v.Advisories
                    .Where(a => a.Severity.Equals(severity, StringComparison.OrdinalIgnoreCase))
                    .ToList(),
            })
            .Where(v => v.Advisories.Count > 0)
            .ToList();

        return new AuditResult { TotalPackages = TotalPackages, Vulnerabilities = filtered };
    }
}
