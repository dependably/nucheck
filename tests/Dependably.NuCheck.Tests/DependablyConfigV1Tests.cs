using Dependably.NuCheck.Config;

namespace Dependably.NuCheck.Tests;

/// <summary>Coverage for the unified <c>.dependably</c> behaviour in nucheck's loader.</summary>
public class DependablyConfigV1Tests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private string NewRepoDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"dep-v1-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(Path.Combine(dir, ".git")); // bound the walk-up
        _tempDirs.Add(dir);
        return dir;
    }

    private static void Write(string dir, string name, string contents)
        => File.WriteAllText(Path.Combine(dir, name), contents);

    private static string[] Codes(DependablyCheckConfig c) => c.Warnings.Select(w => w.Code).ToArray();

    [Fact]
    public void Discovers_canonical_dependably_without_warning()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """{ "nucheck": { "allowedRegistryHosts": ["a.example"] } }""");

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("a.example", config.AllowedRegistryHosts);
        Assert.DoesNotContain("DEPRECATED_FILENAME", Codes(config));
        Assert.DoesNotContain("DEPRECATED_ALIAS_SECTION", Codes(config));
    }

    [Fact]
    public void Discovers_deprecated_filename_with_warning()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.DeprecatedFileName, """{ "nucheck": { "allowedRegistryHosts": ["a.example"] } }""");

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("a.example", config.AllowedRegistryHosts);
        Assert.Contains("DEPRECATED_FILENAME", Codes(config));
    }

    [Fact]
    public void Prefers_canonical_when_both_files_exist()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """{ "nucheck": { "allowedRegistryHosts": ["canonical.example"] } }""");
        Write(dir, DependablyCheckConfig.DeprecatedFileName, """{ "nucheck": { "allowedRegistryHosts": ["old.example"] } }""");

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("canonical.example", config.AllowedRegistryHosts);
        Assert.DoesNotContain("old.example", config.AllowedRegistryHosts);
        Assert.Contains("BOTH_FILES_PRESENT", Codes(config));
    }

    [Fact]
    public void Reads_nuget_alias_section_with_warning()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """{ "nuget": { "allowedRegistryHosts": ["a.example"] } }""");

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("a.example", config.AllowedRegistryHosts);
        Assert.Contains("DEPRECATED_ALIAS_SECTION", Codes(config));
    }

    [Fact]
    public void Canonical_section_wins_over_alias()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """
        { "nucheck": { "allowedRegistryHosts": ["canonical.example"] },
          "nuget":   { "allowedRegistryHosts": ["alias.example"] } }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("canonical.example", config.AllowedRegistryHosts);
        Assert.DoesNotContain("alias.example", config.AllowedRegistryHosts);
        Assert.Contains("DEPRECATED_ALIAS_SECTION", Codes(config));
    }

    [Fact]
    public void Rejects_version_above_supported()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """{ "version": 99, "nucheck": {} }""");

        var ex = Assert.Throws<DependablyConfigException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Equal("CONFIG_VERSION", ex.Code);
    }

    [Fact]
    public void Rejects_non_object_root()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """["not","an","object"]""");

        var ex = Assert.Throws<DependablyConfigException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Equal("CONFIG_SHAPE", ex.Code);
    }

    [Fact]
    public void Warns_on_unknown_key_in_section()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """{ "nucheck": { "allowedRegstryHosts": ["typo"] } }""");

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Contains("UNKNOWN_KEY", Codes(config));
    }

    [Fact]
    public void Parses_failOn_severity_and_count()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """{ "nucheck": { "failOn": { "severity": "high", "count": 3 } } }""");

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal("high", config.FailOnSeverity);
        Assert.Equal(3, config.FailOnCount);
    }

    [Fact]
    public void Parses_common_and_own_exceptions()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """
        { "common":  { "exceptions": [ { "rule": "vulnerable-package", "package": "a", "reason": "x" } ] },
          "nucheck": { "exceptions": [ { "rule": "unused-packages", "package": "b", "reason": "y" } ] } }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Equal(2, config.Exceptions.Count);
    }

    [Fact]
    public void Rejects_inapplicable_selector_in_own_section()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """
        { "nucheck": { "exceptions": [ { "rule": "unused-packages", "symbol": "T.M", "reason": "x" } ] } }
        """);

        var ex = Assert.Throws<DependablyConfigException>(() => DependablyCheckConfig.Load(null, dir));
        Assert.Equal("EXCEPTION_BAD_SELECTOR", ex.Code);
    }

    [Fact]
    public void Tolerates_unknown_rule_in_common_exception()
    {
        var dir = NewRepoDir();
        Write(dir, DependablyCheckConfig.FileName, """
        { "common": { "exceptions": [ { "rule": "cyclomatic", "package": "x", "reason": "y" } ] }, "nucheck": {} }
        """);

        var config = DependablyCheckConfig.Load(null, dir);

        Assert.Single(config.Exceptions);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        foreach (var dir in _tempDirs.Where(Directory.Exists))
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
