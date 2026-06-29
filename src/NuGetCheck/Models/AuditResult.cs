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

/// <summary>
/// An advisory-only finding indicating a package id that could not be detected in any
/// .cs source file under the scan root. This is heuristic: build-tool, analyzer, and
/// MSBuild-task packages often match. Suppress via <c>ignoreUnusedPackages</c> in
/// <c>.dependably-check</c>. Never causes the process to exit non-zero.
/// </summary>
public sealed record UnusedPackageFinding(string Id, string Message);

/// <summary>The outcome of auditing a packages file.</summary>
public sealed class AuditResult
{
    public int TotalPackages { get; init; }

    public IReadOnlyList<PackageVulnerability> Vulnerabilities { get; init; } = [];

    /// <summary>Policy findings (e.g. untrusted package sources). Empty by default.</summary>
    public IReadOnlyList<SourceFinding> PolicyFindings { get; init; } = [];

    /// <summary>
    /// Advisory-only heuristic findings for packages that appear unreferenced in source.
    /// These never cause the process to exit non-zero. Empty by default.
    /// </summary>
    public IReadOnlyList<UnusedPackageFinding> UnusedPackages { get; init; } = [];

    /// <summary>Total number of advisories across all vulnerable packages.</summary>
    public int VulnerabilityCount => Vulnerabilities.Sum(v => v.Advisories.Count);

    /// <summary>
    /// Number of distinct vulnerable packages. This differs from
    /// <see cref="VulnerabilityCount"/> (which counts advisories): one package can carry
    /// several advisories. Every formatter reports BOTH so no headline contradicts another.
    /// </summary>
    public int VulnerablePackageCount => Vulnerabilities.Count;

    /// <summary>Number of policy findings at error severity.</summary>
    public int PolicyErrorCount =>
        PolicyFindings.Count(f => f.Severity.Equals("error", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True when the audit should fail the process (a vulnerability or a policy error).
    /// Unused-package findings are advisory only and never contribute here.
    /// </summary>
    public bool HasFailures => VulnerabilityCount > 0 || PolicyErrorCount > 0;

    /// <summary>
    /// Evaluate the unified CI gate and return true when the build should fail (exit 1).
    /// <para>
    /// With NO <c>--fail-on</c> rule (<paramref name="failOnSeverity"/> and
    /// <paramref name="failOnCount"/> both null) the default holds: any vulnerability or
    /// policy error trips (<see cref="HasFailures"/>).
    /// </para>
    /// <para>
    /// With one or more rules, the gate is exactly the union (OR) of the rules — it
    /// REPLACES the default. <c>severity</c> trips when any finding (vulnerability advisory
    /// or policy finding) is at-or-above the level on the suite ladder; <c>count</c> trips
    /// when the vulnerability count exceeds N. This is what lets a user relax the gate
    /// (e.g. <c>severity=high</c> ignores moderate/low vulns for gating, though they still
    /// appear in output).
    /// </para>
    /// </summary>
    public bool GateTrips(string? failOnSeverity, int? failOnCount)
    {
        if (failOnSeverity is null && failOnCount is null)
        {
            return HasFailures;
        }

        var trips = false;

        if (failOnSeverity is not null)
        {
            trips |= MaxFindingRank() >= Severity.Rank(failOnSeverity);
        }

        if (failOnCount is not null)
        {
            trips |= VulnerabilityCount > failOnCount.Value;
        }

        return trips;
    }

    /// <summary>
    /// The highest severity rank across every gating finding — vulnerability advisories and
    /// policy findings (a policy finding's <c>error</c> severity maps to <c>high</c>).
    /// Returns 0 when there are no findings. Unused-package findings are advisory only and
    /// are never considered.
    /// </summary>
    private int MaxFindingRank()
    {
        var max = 0;

        foreach (var package in Vulnerabilities)
        {
            foreach (var advisory in package.Advisories)
            {
                max = Math.Max(max, Severity.Rank(Severity.Normalize(advisory.Severity)));
            }
        }

        foreach (var finding in PolicyFindings)
        {
            max = Math.Max(max, Severity.Rank(Severity.Normalize(finding.Severity)));
        }

        return max;
    }

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
            UnusedPackages = UnusedPackages,
        };
    }
}
