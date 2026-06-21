using NuGet.Configuration;
using NuGetCheck.Models;

namespace NuGetCheck.Services;

/// <summary>
/// Inspects the effective NuGet package sources for a directory and flags any enabled
/// http(s) source whose host is neither a built-in public host nor explicitly
/// allowlisted in the shared <c>.dependably-check</c> config. Local folder feeds and
/// disabled sources are ignored.
/// </summary>
public static class SourceTrustService
{
    /// <summary>Hosts always trusted as public NuGet sources, regardless of config.</summary>
    public static readonly IReadOnlyList<string> PublicHosts = ["api.nuget.org", "nuget.org"];

    /// <summary>
    /// Returns one <see cref="SourceFinding"/> (error) per enabled http(s) package source
    /// whose host is not in the trusted set (public hosts ∪ <paramref name="allowedHosts"/>).
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(string directory, IReadOnlyList<string> allowedHosts)
    {
        var settings = Settings.LoadDefaultSettings(directory);
        var sources = new PackageSourceProvider(settings).LoadPackageSources();
        return Check(sources, allowedHosts);
    }

    /// <summary>
    /// Core logic over an already-loaded source list, testable without touching disk.
    /// </summary>
    public static IReadOnlyList<SourceFinding> Check(
        IEnumerable<PackageSource> sources,
        IReadOnlyList<string> allowedHosts)
    {
        var trusted = new HashSet<string>(PublicHosts, StringComparer.OrdinalIgnoreCase);
        foreach (var host in allowedHosts)
        {
            if (!string.IsNullOrWhiteSpace(host))
            {
                trusted.Add(host);
            }
        }

        var findings = new List<SourceFinding>();

        foreach (var source in sources)
        {
            if (!source.IsEnabled)
            {
                continue;
            }

            if (!Uri.TryCreate(source.Source, UriKind.Absolute, out var uri))
            {
                continue;
            }

            // Only network feeds carry a host worth trusting; local folder feeds are file:// paths.
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                continue;
            }

            var host = uri.Host;
            if (trusted.Contains(host))
            {
                continue;
            }

            findings.Add(new SourceFinding(
                host,
                source.Name,
                $"NuGet source '{source.Name}' ({source.Source}) uses untrusted host '{host}'. "
                    + "Add it to allowedRegistryHosts in .dependably-check to permit it."));
        }

        return findings;
    }
}
