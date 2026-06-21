namespace NuGetCheck.Models;

/// <summary>Advisories that actually apply to an installed package version.</summary>
public sealed record PackageVulnerability(
    string Id,
    string Version,
    IReadOnlyList<Advisory> Advisories);

/// <summary>
/// A policy violation raised by a non-vulnerability check. Currently produced by the
/// source-trust check when a configured NuGet package source resolves to a host that
/// is neither a built-in public host nor explicitly allowlisted.
/// </summary>
public sealed record SourceFinding(
    string Host,
    string Source,
    string Message,
    string Severity = "error");

/// <summary>The outcome of auditing a packages file.</summary>
public sealed class AuditResult
{
    public int TotalPackages { get; init; }

    public IReadOnlyList<PackageVulnerability> Vulnerabilities { get; init; } = [];

    /// <summary>Policy findings (e.g. untrusted package sources). Empty by default.</summary>
    public IReadOnlyList<SourceFinding> PolicyFindings { get; init; } = [];

    /// <summary>Total number of advisories across all vulnerable packages.</summary>
    public int VulnerabilityCount => Vulnerabilities.Sum(v => v.Advisories.Count);

    /// <summary>Number of policy findings at error severity.</summary>
    public int PolicyErrorCount =>
        PolicyFindings.Count(f => f.Severity.Equals("error", StringComparison.OrdinalIgnoreCase));

    /// <summary>True when the audit should fail the process (a vulnerability or a policy error).</summary>
    public bool HasFailures => VulnerabilityCount > 0 || PolicyErrorCount > 0;

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

        return new AuditResult
        {
            TotalPackages = TotalPackages,
            Vulnerabilities = filtered,
            PolicyFindings = PolicyFindings,
        };
    }
}
