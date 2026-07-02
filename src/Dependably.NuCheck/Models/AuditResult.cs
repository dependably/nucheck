namespace Dependably.NuCheck.Models;

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

/// <summary>
/// A warning raised when an advisory's <c>VulnerableVersionRange</c> cannot be parsed by
/// <see cref="Dependably.NuCheck.Services.VulnerabilityMatcher"/>. The tool cannot confirm
/// or deny whether the installed version is affected; the advisory is surfaced here rather
/// than silently dropped. Never causes the process to exit non-zero, but should be
/// investigated manually.
/// </summary>
public sealed record UnverifiableAdvisoryFinding(
    string PackageId,
    string VulnerableVersionRange,
    string? AdvisoryId = null,
    string? AdvisorySeverity = null);

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

    /// <summary>
    /// Advisories whose version range could not be parsed by
    /// <see cref="Dependably.NuCheck.Services.VulnerabilityMatcher"/>.
    /// These may represent vulnerabilities that could not be confirmed or denied; they
    /// should be investigated manually. Never cause the process to exit non-zero. Empty by default.
    /// </summary>
    public IReadOnlyList<UnverifiableAdvisoryFinding> UnverifiableAdvisories { get; init; } = [];

    /// <summary>Total number of advisories across all vulnerable packages.</summary>
    public int VulnerabilityCount => Vulnerabilities.Sum(v => v.Advisories.Count);

    /// <summary>
    /// Count of advisories hidden by a --severity display filter. Zero when no filter is
    /// active or when all advisories pass the filter. Populated by
    /// <see cref="FilterBySeverity"/>; used by formatters so they do not print "all secure"
    /// when the filtered display shows zero advisories but hidden findings exist.
    /// </summary>
    public int HiddenAdvisoryCount { get; init; }

    /// <summary>
    /// The normalised severity level from --severity, or null when no filter is active.
    /// Populated by <see cref="FilterBySeverity"/>; used by formatters to name the filter
    /// level in the "hidden by --severity" note.
    /// </summary>
    public string? DisplaySeverityFilter { get; init; }

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
    /// With one or more rules, the gate is the union (OR) of the rules — it REPLACES the
    /// default. <c>severity</c> trips when any finding (vulnerability advisory OR policy
    /// finding) is at-or-above the level on the suite ladder, so it governs policy findings
    /// symmetrically (e.g. <c>severity=critical</c> can deliberately relax a policy error,
    /// which maps to <c>high</c>). <c>count</c> trips when the vulnerability count exceeds N;
    /// it governs vulnerabilities ONLY. This is what lets a user relax the gate
    /// (e.g. <c>severity=high</c> ignores moderate/low vulns for gating, though they still
    /// appear in output).
    /// </para>
    /// <para>
    /// Untrusted-source policy errors are a supply-chain security check and are never
    /// silently dropped: when NO <c>severity</c> rule is present to deliberately govern them
    /// (e.g. a <c>count</c>-only gate such as <c>count=0</c>), any policy error still trips.
    /// Only an explicit <c>severity</c> rule can relax policy-error gating.
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
        else
        {
            // No severity rule governs policy findings, so a count-only gate would drop them.
            // Keep untrusted-source policy errors gating — they must never be silently ungated.
            trips |= PolicyErrorCount > 0;
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
    /// Return a copy keeping only advisories at or above the given severity level on the
    /// suite ladder (<c>critical &gt; high &gt; moderate &gt; low &gt; info</c>).
    /// A null/blank or unrecognised severity returns this result unchanged (a no-op rather
    /// than silently hiding all findings).
    /// <para>
    /// The comparison uses <see cref="Severity.Rank"/> after normalisation so that raw
    /// advisory words like <c>medium</c> are treated as <c>moderate</c>, and
    /// <c>--severity high</c> correctly includes <c>critical</c> findings as well as
    /// <c>high</c> ones (rather than performing an exact-string match that would hide
    /// higher-severity advisories).
    /// </para>
    /// </summary>
    public AuditResult FilterBySeverity(string? severity)
    {
        if (string.IsNullOrWhiteSpace(severity))
        {
            return this;
        }

        // Validate/normalise the caller-supplied level: an unrecognised value returns this
        // unchanged rather than silently hiding all findings. The rank is then used for an
        // at-or-above comparison (so "medium" == "moderate", and "high" includes "critical").
        var canonical = Severity.ParseLevel(severity);
        if (canonical is null)
        {
            return this;
        }

        var filterRank = Severity.Rank(canonical);
        var filtered = Vulnerabilities
            .Select(v => v with
            {
                Advisories = v.Advisories
                    .Where(a => Severity.Rank(Severity.Normalize(a.Severity)) >= filterRank)
                    .ToList(),
            })
            .Where(v => v.Advisories.Count > 0)
            .ToList();

        var filteredAdvisoryCount = filtered.Sum(v => v.Advisories.Count);
        return new AuditResult
        {
            TotalPackages = TotalPackages,
            Vulnerabilities = filtered,
            PolicyFindings = PolicyFindings,
            UnusedPackages = UnusedPackages,
            UnverifiableAdvisories = UnverifiableAdvisories,
            HiddenAdvisoryCount = VulnerabilityCount - filteredAdvisoryCount,
            DisplaySeverityFilter = Severity.Normalize(severity),
        };
    }
}
