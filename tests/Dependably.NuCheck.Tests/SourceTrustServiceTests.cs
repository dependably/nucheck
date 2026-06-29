using NuGet.Configuration;
using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Tests;

public class SourceTrustServiceTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private string NewDirWithNuGetConfig(string nugetConfigXml)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"srctrust-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        File.WriteAllText(Path.Combine(dir, "nuget.config"), nugetConfigXml);
        return dir;
    }

    /// <summary>
    /// Creates a temp directory marked as a repo root (a <c>.git</c> marker dir) and,
    /// optionally, a <c>nuget.config</c> declaring the given sources.
    /// </summary>
    private string NewRepo(string? nugetConfigXml)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"srctrust-repo-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(Path.Combine(dir, ".git"));
        _tempDirs.Add(dir);
        if (nugetConfigXml is not null)
        {
            File.WriteAllText(Path.Combine(dir, "nuget.config"), nugetConfigXml);
        }

        return dir;
    }

    [Fact]
    public void Repo_nuget_config_declaring_untrusted_host_produces_one_finding()
    {
        var dir = NewRepo("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            <add key="acme" value="https://nuget.pkg.github.com/acme/index.json" />
          </packageSources>
        </configuration>
        """);

        var finding = Assert.Single(SourceTrustService.Check(dir, []));
        Assert.Equal("nuget.pkg.github.com", finding.Host);
        Assert.Equal("acme", finding.Source);
        Assert.Equal("error", finding.Severity);
    }

    [Fact]
    public void Repo_nuget_config_declaring_only_public_host_produces_no_findings()
    {
        var dir = NewRepo("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
          </packageSources>
        </configuration>
        """);

        Assert.Empty(SourceTrustService.Check(dir, []));
    }

    [Fact]
    public void Repo_with_no_nuget_config_produces_no_findings()
    {
        // Regression guard: with no repo-declared nuget.config, the audit must not reach
        // outside the repo tree to the host machine's user/global config (which on the
        // test runner may well declare private feeds). The repo makes no source claim,
        // so there is nothing to flag.
        var dir = NewRepo(nugetConfigXml: null);

        Assert.Empty(SourceTrustService.Check(dir, []));
    }

    [Fact]
    public void Public_source_only_produces_no_findings()
    {
        var dir = NewDirWithNuGetConfig("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
          </packageSources>
        </configuration>
        """);

        Assert.Empty(SourceTrustService.Check(dir, []));
    }

    [Fact]
    public void Private_source_not_allowlisted_produces_one_error()
    {
        var dir = NewDirWithNuGetConfig("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            <add key="private" value="https://nuget.evil.example/v3/index.json" />
          </packageSources>
        </configuration>
        """);

        var finding = Assert.Single(SourceTrustService.Check(dir, []));
        Assert.Equal("nuget.evil.example", finding.Host);
        Assert.Equal("private", finding.Source);
        Assert.Equal("error", finding.Severity);
    }

    [Fact]
    public void Private_source_in_allowlist_produces_no_findings()
    {
        var dir = NewDirWithNuGetConfig("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="private" value="https://dependably.northwardlabs.ca/nuget/v3/index.json" />
          </packageSources>
        </configuration>
        """);

        Assert.Empty(SourceTrustService.Check(dir, ["dependably.northwardlabs.ca"]));
    }

    [Fact]
    public void Disabled_source_is_ignored()
    {
        var sources = new[]
        {
            new PackageSource("https://nuget.evil.example/v3/index.json", "private", isEnabled: false),
        };

        Assert.Empty(SourceTrustService.Check(sources, []));
    }

    [Fact]
    public void Local_folder_source_is_ignored()
    {
        var localPath = Path.Combine(Path.GetTempPath(), "local-feed");
        var sources = new[]
        {
            new PackageSource(localPath, "local"),
            new PackageSource("https://api.nuget.org/v3/index.json", "nuget.org"),
        };

        Assert.Empty(SourceTrustService.Check(sources, []));
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        foreach (var dir in _tempDirs)
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }
}
