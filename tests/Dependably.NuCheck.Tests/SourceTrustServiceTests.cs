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
    public void Local_folder_source_not_allowlisted_produces_one_finding()
    {
        // Regression for #33: a repo-declared local folder feed is a supply-chain smuggling
        // vector, so it must be flagged (fail-closed), not silently skipped.
        var localPath = Path.Combine(Path.GetTempPath(), "local-feed");
        var sources = new[]
        {
            new PackageSource(localPath, "local"),
            new PackageSource("https://api.nuget.org/v3/index.json", "nuget.org"),
        };

        var finding = Assert.Single(SourceTrustService.Check(sources, []));
        Assert.Equal("local", finding.Source);
        Assert.Equal("error", finding.Severity);
        Assert.Contains("local folder feed", finding.Message);
    }

    [Fact]
    public void File_uri_source_not_allowlisted_produces_one_finding()
    {
        // Regression for #33: file:// feeds are local feeds too and must be flagged.
        var sources = new[]
        {
            new PackageSource("file:///opt/evil-feed", "evil"),
            new PackageSource("https://api.nuget.org/v3/index.json", "nuget.org"),
        };

        var finding = Assert.Single(SourceTrustService.Check(sources, []));
        Assert.Equal("evil", finding.Source);
        Assert.Equal("error", finding.Severity);
    }

    [Fact]
    public void Allowlisted_local_folder_source_is_ignored()
    {
        // #33: an explicitly trusted local feed (matched by trailing path segment) passes.
        var localPath = Path.Combine(Path.GetTempPath(), "local-feed");
        var sources = new[]
        {
            new PackageSource(localPath, "local"),
        };

        Assert.Empty(SourceTrustService.Check(sources, [], ["local-feed"]));
    }

    [Fact]
    public void Allowlisted_file_uri_source_is_ignored()
    {
        var sources = new[]
        {
            new PackageSource("file:///opt/mirror", "mirror"),
        };

        Assert.Empty(SourceTrustService.Check(sources, [], ["file:///opt/mirror"]));
    }

    [Fact]
    public void Allowlist_does_not_match_a_different_similarly_named_feed()
    {
        // Guard against over-matching: "feed" must not allow "/tmp/myfeed".
        var sources = new[]
        {
            new PackageSource("/tmp/myfeed", "local"),
        };

        Assert.Single(SourceTrustService.Check(sources, [], ["feed"]));
    }

    [Fact]
    public void Repo_nuget_config_declaring_relative_local_feed_produces_one_finding()
    {
        // End-to-end for #33: a committed nuget.config pointing at a relative local folder.
        var dir = NewRepo("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            <add key="localfeed" value="./feeds" />
          </packageSources>
        </configuration>
        """);

        var finding = Assert.Single(SourceTrustService.Check(dir, []));
        Assert.Equal("localfeed", finding.Source);
        Assert.Equal("error", finding.Severity);
    }

    [Fact]
    public void Repo_nuget_config_declaring_allowlisted_relative_local_feed_produces_no_findings()
    {
        var dir = NewRepo("""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            <add key="localfeed" value="./feeds" />
          </packageSources>
        </configuration>
        """);

        Assert.Empty(SourceTrustService.Check(dir, [], ["feeds"]));
    }

    [Fact]
    public void Non_git_tree_with_parent_config_emits_visible_info_notice()
    {
        // Regression for #47: no .git boundary means parent-directory nuget.config is not
        // audited (the source-trust check would otherwise fail open silently). We must at
        // least surface a visible info finding naming the excluded config.
        var outer = Path.Combine(Path.GetTempPath(), $"srctrust-nogit-{Guid.NewGuid():N}");
        var inner = Path.Combine(outer, "src", "App");
        Directory.CreateDirectory(inner);
        _tempDirs.Add(outer);
        File.WriteAllText(Path.Combine(outer, "nuget.config"), """
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="evil" value="https://nuget.evil.example/v3/index.json" />
          </packageSources>
        </configuration>
        """);

        var findings = SourceTrustService.Check(inner, []);

        var notice = Assert.Single(findings);
        Assert.Equal("info", notice.Severity);
        Assert.Equal("parent-config", notice.Source);
        Assert.Contains("No repository boundary", notice.Message);
    }

    [Fact]
    public void Git_tree_with_parent_config_does_not_emit_parent_notice()
    {
        // The notice is only for the non-git fail-open case: with a .git boundary, a parent
        // config above the boundary is intentionally out of scope and produces no notice.
        var repo = NewRepo(nugetConfigXml: null);
        var inner = Path.Combine(repo, "src", "App");
        Directory.CreateDirectory(inner);
        File.WriteAllText(Path.Combine(repo, "nuget.config"), """
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <clear />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
          </packageSources>
        </configuration>
        """);

        // The repo-root config IS under the boundary, so it is audited normally (public host,
        // no finding) and there is no parent-config notice.
        Assert.Empty(SourceTrustService.Check(inner, []));
    }

    [Fact]
    public void Local_folder_source_is_ignored()
    {
        // Backward-compat: with the feed allowlisted, the historical "ignored" behavior holds.
        var localPath = Path.Combine(Path.GetTempPath(), "local-feed");
        var sources = new[]
        {
            new PackageSource(localPath, "local"),
            new PackageSource("https://api.nuget.org/v3/index.json", "nuget.org"),
        };

        Assert.Empty(SourceTrustService.Check(sources, [], ["local-feed"]));
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
