using Dependably.NuCheck.Config;

namespace Dependably.NuCheck.Tests;

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
          "common": { "allowedRegistryHosts": ["nuget.corp.example.com"] },
          "nuget":  { "allowedRegistryHosts": ["nuget.internal.example"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("nuget.corp.example.com", config.AllowedRegistryHosts);
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

    /// <summary>
    /// Spec §5.1 requires lowercase as the canonical stored form for
    /// <c>allowedRegistryHosts</c> — not merely a case-insensitive dedupe that survives with
    /// whichever spelling appeared first.
    /// </summary>
    [Fact]
    public void Load_stores_allowedRegistryHosts_lowercased()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "allowedRegistryHosts": ["Packages.Corp.Dev"] },
          "nuget":  { "allowedRegistryHosts": ["packages.corp.dev", "Feeds.Corp.Dev"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal(["packages.corp.dev", "feeds.corp.dev"], config.AllowedRegistryHosts);
    }

    /// <summary>
    /// Unlike <c>allowedRegistryHosts</c>, <c>allowedLocalFeeds</c> holds filesystem paths, which
    /// are case-sensitive on the platforms that matter — deduping still applies case-insensitively
    /// (spec §5.1's dedupe rule), but the stored spelling must be preserved, not lowercased.
    /// </summary>
    [Fact]
    public void Load_preserves_allowedLocalFeeds_casing()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "allowedLocalFeeds": ["./Local-Packages"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal(["./Local-Packages"], config.AllowedLocalFeeds);
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

    // -----------------------------------------------------------------
    // exclude (spec §4 universal key; nucheck resolves it but has no current consumer)
    // -----------------------------------------------------------------

    [Fact]
    public void Load_unions_common_and_nuget_exclude_ordinally()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common": { "exclude": ["dist/**"] },
          "nuget":  { "exclude": ["dist/**", "vendor/**"] }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal(["dist/**", "vendor/**"], config.Exclude);
    }

    [Fact]
    public void Empty_config_has_empty_exclude()
    {
        Assert.Empty(DependablyCheckConfig.Empty.Exclude);
    }

    // ---- rules severity map (spec §4.1/§5) --------------------------------------
    // These mirror the shared conformance fixtures (merge-rules-per-id,
    // validation-bad-severity, validation-unknown-rule-*) with nucheck rule ids —
    // the fixtures themselves are npm-flavoured, so like the other config-loader
    // cases they are covered natively here rather than replayed.

    [Fact]
    public void Rules_merge_per_id_tool_replaces_common_wholesale()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common":  { "rules": { "pinned-versions": "warn", "unused-packages": "warn" } },
          "nucheck": { "rules": { "pinned-versions": ["error", { "ignore": [] }] } }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal("error", config.RuleSeverities["pinned-versions"]);
        Assert.Equal("warn", config.RuleSeverities["unused-packages"]);
    }

    [Fact]
    public void Rules_off_round_trips()
    {
        var dir = NewTempDir();
        Write(dir, """
        { "nucheck": { "rules": { "pinned-versions": "off" } } }
        """);

        Assert.Equal("off", DependablyCheckConfig.Load(null, dir).RuleSeverities["pinned-versions"]);
    }

    [Fact]
    public void Rules_invalid_severity_is_INVALID_SEVERITY()
    {
        var dir = NewTempDir();
        Write(dir, """
        { "nucheck": { "rules": { "pinned-versions": "fatal" } } }
        """);

        var ex = Assert.Throws<DependablyConfigException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Equal("INVALID_SEVERITY", ex.Code);
    }

    [Fact]
    public void Rules_non_object_options_is_INVALID_RULE_OPTIONS()
    {
        var dir = NewTempDir();
        Write(dir, """
        { "nucheck": { "rules": { "pinned-versions": ["warn", 42] } } }
        """);

        var ex = Assert.Throws<DependablyConfigException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Equal("INVALID_RULE_OPTIONS", ex.Code);
    }

    [Fact]
    public void Rules_unknown_rule_in_own_section_is_UNKNOWN_RULE()
    {
        var dir = NewTempDir();
        Write(dir, """
        { "nucheck": { "rules": { "no-such-rule": "error" } } }
        """);

        var ex = Assert.Throws<DependablyConfigException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Equal("UNKNOWN_RULE", ex.Code);
    }

    [Fact]
    public void Rules_sibling_tool_rule_in_common_is_tolerated()
    {
        var dir = NewTempDir();
        Write(dir, """
        {
          "common":  { "rules": { "cyclomatic": ["error", { "max": 25 }] } },
          "nucheck": { "rules": { "pinned-versions": "warn" } }
        }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal("warn", config.RuleSeverities["pinned-versions"]);
        Assert.Equal("error", config.RuleSeverities["cyclomatic"]); // parsed, unused by nucheck
    }

    [Fact]
    public void Rules_severity_in_common_is_still_value_validated()
    {
        var dir = NewTempDir();
        Write(dir, """
        { "common": { "rules": { "cyclomatic": "fatal" } } }
        """);

        var ex = Assert.Throws<DependablyConfigException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Equal("INVALID_SEVERITY", ex.Code);
    }

    [Fact]
    public void Rules_absent_means_empty_map()
    {
        var dir = NewTempDir();
        Write(dir, """
        { "nucheck": { "allowedRegistryHosts": [] } }
        """);

        Assert.Empty(DependablyCheckConfig.Load(null, dir).RuleSeverities);
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
