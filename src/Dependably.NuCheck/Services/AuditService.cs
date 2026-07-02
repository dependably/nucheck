using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

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
        // Results are written into positional arrays so the output order matches the
        // input order regardless of which queries finish first.
        var matchedByIndex = new PackageVulnerability?[packages.Count];
        var unverifiableByIndex = new List<UnverifiableAdvisoryFinding>?[packages.Count];
        using var gate = new SemaphoreSlim(_maxConcurrency);

        var tasks = packages.Select(async (package, index) =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var advisories = await _source.GetAdvisoriesAsync(package.Id, cancellationToken).ConfigureAwait(false);
                var (matched, unverifiable) = ClassifyAdvisories(package, advisories);

                if (matched.Count > 0)
                {
                    matchedByIndex[index] = new PackageVulnerability(package.Id, package.Version.ToString(), matched);
                }

                if (unverifiable.Count > 0)
                {
                    unverifiableByIndex[index] = unverifiable;
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
            UnverifiableAdvisories = unverifiableByIndex
                .Where(u => u is not null)
                .SelectMany(u => u!)
                .ToList(),
        };
    }

    /// <summary>
    /// Classifies each advisory for <paramref name="package"/> into matched vulnerabilities
    /// and advisories whose range could not be parsed. Advisories outside the vulnerable
    /// range are discarded — they are the common case and need no representation.
    /// </summary>
    private static (List<Advisory> Matched, List<UnverifiableAdvisoryFinding> Unverifiable)
        ClassifyAdvisories(PackageRef package, IReadOnlyList<Advisory> advisories)
    {
        var matched = new List<Advisory>();
        var unverifiable = new List<UnverifiableAdvisoryFinding>();

        foreach (var advisory in advisories)
        {
            switch (VulnerabilityMatcher.TryMatch(package.Version, advisory.VulnerableVersionRange))
            {
                case VulnerabilityMatchResult.Vulnerable:
                    matched.Add(advisory);
                    break;
                case VulnerabilityMatchResult.UnparseableRange:
                    unverifiable.Add(new UnverifiableAdvisoryFinding(
                        package.Id, advisory.VulnerableVersionRange, advisory.AdvisoryId));
                    break;
            }
        }

        return (matched, unverifiable);
    }
}
