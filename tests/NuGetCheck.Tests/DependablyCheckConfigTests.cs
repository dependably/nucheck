using NuGetCheck.Config;

namespace NuGetCheck.Tests;

public class DependablyCheckConfigTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"depcheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    private static void Write(string dir, string contents)
        => File.WriteAllText(Path.Combine(dir, DependablyCheckConfig.FileName), contents);

    [Fact]
    public void Load_unions_common_and_nuget_hosts()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "allowedRegistryHosts": ["dependably.northwardlabs.ca"] },
          "nuget":  { "allowedRegistryHosts": ["nuget.internal.example"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("dependably.northwardlabs.ca", config.AllowedRegistryHosts);
        Assert.Contains("nuget.internal.example", config.AllowedRegistryHosts);
        Assert.Equal(2, config.AllowedRegistryHosts.Count);
    }

    [Fact]
    public void Load_tolerates_missing_sections_and_unknown_keys()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "nuget": { "allowedRegistryHosts": ["only.example"] },
          "npm":   { "allowedRegistryHosts": ["ignored.example"] },
          "extra": 42
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal(["only.example"], config.AllowedRegistryHosts);
    }

    [Fact]
    public void Load_dedupes_hosts_case_insensitively()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "allowedRegistryHosts": ["Host.Example"] },
          "nuget":  { "allowedRegistryHosts": ["host.example"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Single(config.AllowedRegistryHosts);
    }

    [Fact]
    public void Discover_walks_up_to_find_config()
    {
        var root = NewTempDir();
        Write(root, """{ "common": { "allowedRegistryHosts": ["walk.example"] } }""");
        var nested = Path.Combine(root, "a", "b", "c");
        Directory.CreateDirectory(nested);

        var config = DependablyCheckConfig.Load(null, nested);

        Assert.Equal(["walk.example"], config.AllowedRegistryHosts);
    }

    [Fact]
    public void Discover_stops_at_git_boundary()
    {
        // outer has the config; inner is a separate repo (.git) so the walk must NOT reach outer.
        var outer = NewTempDir();
        Write(outer, """{ "common": { "allowedRegistryHosts": ["should.not.see"] } }""");
        var inner = Path.Combine(outer, "repo");
        Directory.CreateDirectory(inner);
        Directory.CreateDirectory(Path.Combine(inner, ".git"));
        var nested = Path.Combine(inner, "src");
        Directory.CreateDirectory(nested);

        var config = DependablyCheckConfig.Load(null, nested);

        Assert.Empty(config.AllowedRegistryHosts);
    }

    [Fact]
    public void Load_explicit_path_wins_over_discovery()
    {
        var discoverDir = NewTempDir();
        Write(discoverDir, """{ "common": { "allowedRegistryHosts": ["discovered.example"] } }""");

        var explicitDir = NewTempDir();
        var explicitPath = Path.Combine(explicitDir, "custom.json");
        File.WriteAllText(explicitPath, """{ "nuget": { "allowedRegistryHosts": ["explicit.example"] } }""");

        var config = DependablyCheckConfig.Load(explicitPath, discoverDir);

        Assert.Equal(["explicit.example"], config.AllowedRegistryHosts);
    }

    [Fact]
    public void Load_returns_empty_when_no_config_found()
    {
        var dir = NewTempDir();
        Directory.CreateDirectory(Path.Combine(dir, ".git"));

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Empty(config.AllowedRegistryHosts);
    }

    [Fact]
    public void Load_malformed_json_throws_with_path()
    {
        var dir = NewTempDir();
        Write(dir, "{ not valid json");

        var ex = Assert.Throws<InvalidDataException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Contains(DependablyCheckConfig.FileName, ex.Message);
    }

    [Fact]
    public void Load_explicit_path_missing_throws()
    {
        Assert.Throws<FileNotFoundException>(
            () => DependablyCheckConfig.Load("/no/such/.dependably-check", NewTempDir()));
    }

    // -----------------------------------------------------------------
    // ignoreUnusedPackages
    // -----------------------------------------------------------------

    [Fact]
    public void Load_unions_common_and_nuget_ignoreUnusedPackages()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "ignoreUnusedPackages": ["StyleCop.Analyzers"] },
          "nuget":  { "ignoreUnusedPackages": ["Microsoft.CodeAnalysis.Analyzers"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("StyleCop.Analyzers", config.IgnoreUnusedPackages);
        Assert.Contains("Microsoft.CodeAnalysis.Analyzers", config.IgnoreUnusedPackages);
        Assert.Equal(2, config.IgnoreUnusedPackages.Count);
    }

    [Fact]
    public void Load_ignoreUnusedPackages_dedupes_case_insensitively()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "ignoreUnusedPackages": ["StyleCop.Analyzers"] },
          "nuget":  { "ignoreUnusedPackages": ["stylecop.analyzers"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Single(config.IgnoreUnusedPackages);
    }

    [Fact]
    public void Load_returns_empty_ignoreUnusedPackages_when_section_absent()
    {
        var dir = NewTempDir();
        Write(dir, """{ "common": { "allowedRegistryHosts": ["host.example"] } }""");

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Empty(config.IgnoreUnusedPackages);
    }

    [Fact]
    public void Empty_config_has_empty_ignoreUnusedPackages()
    {
        Assert.Empty(DependablyCheckConfig.Empty.IgnoreUnusedPackages);
    }

    [Fact]
    public void Load_ignoreUnusedPackages_from_common_only()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "ignoreUnusedPackages": ["CommonOnly.Pkg"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal(["CommonOnly.Pkg"], config.IgnoreUnusedPackages);
    }

    [Fact]
    public void Load_ignoreUnusedPackages_from_nuget_only()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "nuget": { "ignoreUnusedPackages": ["NugetOnly.Pkg"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal(["NugetOnly.Pkg"], config.IgnoreUnusedPackages);
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
