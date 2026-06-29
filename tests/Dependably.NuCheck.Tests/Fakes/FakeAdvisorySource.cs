using Dependably.NuCheck.Models;
using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Tests.Fakes;

/// <summary>An in-memory advisory source keyed by package id, for audit tests.</summary>
public sealed class FakeAdvisorySource : IAdvisorySource
{
    private readonly IReadOnlyDictionary<string, IReadOnlyList<Advisory>> _advisoriesById;

    public FakeAdvisorySource(IReadOnlyDictionary<string, IReadOnlyList<Advisory>> advisoriesById)
        => _advisoriesById = advisoriesById;

    public Task<IReadOnlyList<Advisory>> GetAdvisoriesAsync(string packageId, CancellationToken cancellationToken = default)
        => Task.FromResult(_advisoriesById.TryGetValue(packageId, out var advisories) ? advisories : []);
}
