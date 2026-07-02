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

    // --- Ticket 35: UNC / file:// network-share feeds -----------------------------------

    [Fact]
    public void Unc_share_feed_is_flagged_as_untrusted_network_source()
    {
        var sources = new[]
        {
            new PackageSource(@"\\evil-server\feed", "unc"),
        };

        var finding = Assert.Single(SourceTrustService.Check(sources, []));
        Assert.Equal("evil-server", finding.Host);
        Assert.Equal("unc", finding.Source);
    }

    [Fact]
    public void File_scheme_feed_with_remote_host_is_flagged()
    {
        var sources = new[]
        {
            new PackageSource("file://evil-server/feed", "filehost"),
        };

        var finding = Assert.Single(SourceTrustService.Check(sources, []));
        Assert.Equal("evil-server", finding.Host);
    }

    [Fact]
    public void Unc_share_feed_can_be_allowlisted_by_host()
    {
        var sources = new[]
        {
            new PackageSource(@"\\corp-share\feed", "corp"),
        };

        Assert.Empty(SourceTrustService.Check(sources, ["corp-share"]));
    }

    // --- Ticket 45: machine-local disabledPackageSources must not suppress findings ------

    [Fact]
    public void Machine_local_disabled_source_does_not_suppress_repo_declared_finding()
    {
        // Ancestor (machine/user) config disables "evil" by name. The repo declares "evil"
        // as an enabled untrusted source. The verdict must depend only on what the repo
        // declares, so the finding must still fire (reproducible across machines/CI).
        var outer = Path.Combine(Path.GetTempPath(), $"srctrust-outer-{Guid.NewGuid():N}");
        Directory.CreateDirectory(outer);
        _tempDirs.Add(outer);
        File.WriteAllText(Path.Combine(outer, "nuget.config"), """
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <disabledPackageSources>
            <add key="evil" value="true" />
          </disabledPackageSources>
        </configuration>
        """);

        var repo = Path.Combine(outer, "repo");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        File.WriteAllText(Path.Combine(repo, "nuget.config"), """
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            <add key="evil" value="https://nuget.evil.example/v3/index.json" />
          </packageSources>
        </configuration>
        """);

        var finding = Assert.Single(SourceTrustService.Check(repo, []));
        Assert.Equal("nuget.evil.example", finding.Host);
        Assert.Equal("evil", finding.Source);
    }

    [Fact]
    public void Repo_declared_disabled_source_is_still_suppressed()
    {
        // The complement of the reproducibility fix: a disable declared *inside the repo*
        // still counts, so the source is legitimately skipped.
        var dir = NewRepo("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            <add key="evil" value="https://nuget.evil.example/v3/index.json" />
          </packageSources>
          <disabledPackageSources>
            <add key="evil" value="true" />
          </disabledPackageSources>
        </configuration>
        """);

        Assert.Empty(SourceTrustService.Check(dir, []));
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
