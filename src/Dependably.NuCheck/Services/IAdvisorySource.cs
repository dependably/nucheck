using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>A source of security advisories for a NuGet package id.</summary>
public interface IAdvisorySource
{
    Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default);
}
