using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>
/// Orchestrates an audit: for each installed package it pulls advisories from an
/// <see cref="IAdvisorySource"/> and keeps only those whose vulnerable range covers
/// the installed version (per <see cref="VulnerabilityMatcher"/>).
/// </summary>
public sealed class AuditService
{
    private readonly IAdvisorySource _source;

    public AuditService(IAdvisorySource source) => _source = source;

    public async Task<AuditResult> AuditAsync(
        IReadOnlyList<PackageRef> packages,
        CancellationToken cancellationToken = default)
    {
        var vulnerabilities = new List<PackageVulnerability>();

        foreach (var package in packages)
        {
            var advisories = await _source.GetAdvisoriesAsync(package.Id, cancellationToken).ConfigureAwait(false);
            var matched = advisories
                .Where(a => VulnerabilityMatcher.IsVulnerable(package.Version, a.VulnerableVersionRange))
                .ToList();

            if (matched.Count > 0)
            {
                vulnerabilities.Add(new PackageVulnerability(package.Id, package.Version.ToString(), matched));
            }
        }

        return new AuditResult
        {
            TotalPackages = packages.Count,
            Vulnerabilities = vulnerabilities,
        };
    }
}
