using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>A source of security advisories for a NuGet package id.</summary>
public interface IAdvisorySource
{
    Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default);
}
