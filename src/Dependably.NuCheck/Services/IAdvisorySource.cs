using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>A source of security advisories for a NuGet package id.</summary>
public interface IAdvisorySource
{
    /// <summary>
    /// A short human-readable label for this advisory database (e.g. <c>"OSV.dev"</c>),
    /// echoed in the summary line so a clean "all secure" result names what it was checked
    /// against and is therefore verifiable.
    /// </summary>
    string DisplayName { get; }

    Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default);
}
