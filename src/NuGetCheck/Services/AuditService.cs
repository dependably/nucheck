using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>
/// Orchestrates an audit: for each installed package it pulls advisories from an
/// <see cref="IAdvisorySource"/> and keeps only those whose vulnerable range covers
/// the installed version (per <see cref="VulnerabilityMatcher"/>). Packages are queried
/// concurrently (bounded by <paramref name="maxConcurrency"/>) since each is an
/// independent network round-trip, while the reported order is kept deterministic.
/// </summary>
public sealed class AuditService
{
    private const int DefaultMaxConcurrency = 8;

    private readonly IAdvisorySource _source;
    private readonly int _maxConcurrency;

    public AuditService(IAdvisorySource source, int maxConcurrency = DefaultMaxConcurrency)
    {
        _source = source;
        _maxConcurrency = Math.Max(1, maxConcurrency);
    }

    public async Task<AuditResult> AuditAsync(
        IReadOnlyList<PackageRef> packages,
        CancellationToken cancellationToken = default)
    {
        // Results are written into a positional array so the output order matches the
        // input order regardless of which queries finish first.
        var matchedByIndex = new PackageVulnerability?[packages.Count];
        using var gate = new SemaphoreSlim(_maxConcurrency);

        var tasks = packages.Select(async (package, index) =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var advisories = await _source.GetAdvisoriesAsync(package.Id, cancellationToken).ConfigureAwait(false);
                var matched = advisories
                    .Where(a => VulnerabilityMatcher.IsVulnerable(package.Version, a.VulnerableVersionRange))
                    .ToList();

                if (matched.Count > 0)
                {
                    matchedByIndex[index] = new PackageVulnerability(package.Id, package.Version.ToString(), matched);
                }
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);

        return new AuditResult
        {
            TotalPackages = packages.Count,
            Vulnerabilities = matchedByIndex.Where(v => v is not null).Select(v => v!).ToList(),
        };
    }
}
