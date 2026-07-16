using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Tests;

/// <summary>
/// The pinned-versions rule: PackageFileReader.TryReadDeclarations exactness per
/// declaration shape, and PinnedVersionChecker severity resolution (error/warn/off).
/// </summary>
public class PinnedVersionCheckerTests : IDisposable
{
    private readonly List<string> _tempFiles = [];
    private readonly List<string> _tempDirs = [];

    // ---- TryReadDeclarations: csproj / props shapes ------------------------------

    [Fact]
    public void Exact_version_attribute_is_pinned()
    {
        var path = WriteTemp(".csproj", """
<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>
""");

        var declaration = Assert.Single(PackageFileReader.TryReadDeclarations(path)!);
        Assert.True(declaration.IsExact);
        Assert.Equal("13.0.3", declaration.RawVersion);
    }

    [Fact]
    public void Version_child_element_and_versionoverride_are_read()
    {
        var path = WriteTemp(".csproj", """
<Project>
  <ItemGroup>
    <PackageReference Include="Child.Pkg"><Version>2.*</Version></PackageReference>
    <PackageReference Include="Override.Pkg" VersionOverride="[3.0.0]" />
  </ItemGroup>
</Project>
""");

        var declarations = PackageFileReader.TryReadDeclarations(path)!;

        Assert.False(declarations.Single(d => d.Id == "Child.Pkg").IsExact);       // floating
        Assert.True(declarations.Single(d => d.Id == "Override.Pkg").IsExact);      // exact bracket
    }

    [Theory]
    [InlineData("6.*", false)]        // floating
    [InlineData("[1.0,2.0)", false)]  // range
    [InlineData("(,2.0]", false)]     // open lower bound
    [InlineData("[1.2.3]", true)]     // exact bracket range — semantically a pin
    [InlineData("1.2.3-beta.1", true)]
    [InlineData("1.8.3.1", true)]     // four-part legacy version
    public void Version_string_exactness(string version, bool expectExact)
    {
        var path = WriteTemp(".csproj", $"""
<Project><ItemGroup><PackageReference Include="Some.Pkg" Version="{version}" /></ItemGroup></Project>
""");

        var declaration = Assert.Single(PackageFileReader.TryReadDeclarations(path)!);
        Assert.Equal(expectExact, declaration.IsExact);
    }

    [Fact]
    public void Msbuild_property_version_is_skipped()
    {
        // A $(Property) version cannot be evaluated statically — skipped, not flagged,
        // matching the vulnerability audit's treatment of unresolvable versions.
        var path = WriteTemp(".csproj", """
<Project><ItemGroup><PackageReference Include="Prop.Pkg" Version="$(SharedVersion)" /></ItemGroup></Project>
""");

        Assert.Empty(PackageFileReader.TryReadDeclarations(path)!);
    }

    [Fact]
    public void Versionless_reference_with_exact_cpm_entry_is_pinned()
    {
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
<Project><ItemGroup><PackageVersion Include="Cpm.Pkg" Version="4.1.0" /></ItemGroup></Project>
""");
        var path = Path.Combine(dir, "app.csproj");
        File.WriteAllText(path, """
<Project><ItemGroup><PackageReference Include="Cpm.Pkg" /></ItemGroup></Project>
""");

        var declaration = Assert.Single(PackageFileReader.TryReadDeclarations(path)!);
        Assert.True(declaration.IsExact);
        Assert.Equal("Directory.Packages.props", declaration.Source);
    }

    [Fact]
    public void Versionless_reference_with_floating_cpm_entry_is_not_pinned()
    {
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
<Project>
  <ItemGroup>
    <PackageVersion Include="Cpm.Pkg" Version="4.1.0" />
    <PackageVersion Include="Cpm.Pkg" Version="5.*" Condition="'$(TargetFramework)' == 'net10.0'" />
  </ItemGroup>
</Project>
""");
        var path = Path.Combine(dir, "app.csproj");
        File.WriteAllText(path, """
<Project><ItemGroup><PackageReference Include="Cpm.Pkg" /></ItemGroup></Project>
""");

        // One floating conditional pin must not hide behind an exact sibling.
        var declaration = Assert.Single(PackageFileReader.TryReadDeclarations(path)!);
        Assert.False(declaration.IsExact);
    }

    [Fact]
    public void Versionless_reference_with_no_cpm_entry_is_a_finding()
    {
        var dir = NewTempDir();
        var path = Path.Combine(dir, "app.csproj");
        File.WriteAllText(path, """
<Project><ItemGroup><PackageReference Include="Nothing.Pins.Me" /></ItemGroup></Project>
""");

        var declaration = Assert.Single(PackageFileReader.TryReadDeclarations(path)!);
        Assert.False(declaration.IsExact);
        Assert.Null(declaration.RawVersion);
    }

    [Fact]
    public void Directory_packages_props_is_checked_directly()
    {
        var dir = NewTempDir();
        var path = Path.Combine(dir, "Directory.Packages.props");
        File.WriteAllText(path, """
<Project>
  <ItemGroup>
    <PackageVersion Include="Pinned.Pkg" Version="1.0.0" />
    <PackageVersion Include="Floating.Pkg" Version="2.*" />
  </ItemGroup>
</Project>
""");

        var declarations = PackageFileReader.TryReadDeclarations(path)!;

        Assert.True(declarations.Single(d => d.Id == "Pinned.Pkg").IsExact);
        Assert.False(declarations.Single(d => d.Id == "Floating.Pkg").IsExact);
    }

    [Fact]
    public void Local_packageversion_resolving_a_reference_is_not_double_counted()
    {
        var path = WriteTemp(".csproj", """
<Project>
  <ItemGroup>
    <PackageVersion Include="Local.Pkg" Version="7.*" />
    <PackageReference Include="Local.Pkg" />
  </ItemGroup>
</Project>
""");

        var declaration = Assert.Single(PackageFileReader.TryReadDeclarations(path)!);
        Assert.False(declaration.IsExact);
    }

    // ---- TryReadDeclarations: packages.config / lock file ------------------------

    [Fact]
    public void Packages_config_exact_version_is_pinned_and_range_allowedversions_is_not()
    {
        var path = WriteTemp(".config", """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Pinned.Pkg" version="1.0.0" targetFramework="net462" />
  <package id="Constrained.Pkg" version="1.0.0" allowedVersions="[1.0,2.0)" targetFramework="net462" />
  <package id="NoVersion.Pkg" targetFramework="net462" />
</packages>
""");

        var declarations = PackageFileReader.TryReadDeclarations(path)!;

        Assert.True(declarations.Single(d => d.Id == "Pinned.Pkg").IsExact);
        Assert.False(declarations.Single(d => d.Id == "Constrained.Pkg").IsExact);
        Assert.False(declarations.Single(d => d.Id == "NoVersion.Pkg").IsExact);
    }

    [Fact]
    public void Lock_file_is_not_applicable_returns_null()
    {
        var path = WriteTemp(".json", """
{
  "version": 1,
  "dependencies": {
    "net6.0": { "Newtonsoft.Json": { "type": "Direct", "requested": "[11.0.2, )", "resolved": "11.0.2", "contentHash": "abc" } }
  }
}
""");

        Assert.Null(PackageFileReader.TryReadDeclarations(path));
    }

    // ---- PinnedVersionChecker: severity resolution --------------------------------

    [Fact]
    public void Error_severity_produces_error_findings()
    {
        var path = WriteTemp(".csproj", """
<Project><ItemGroup><PackageReference Include="Float.Pkg" Version="6.*" /></ItemGroup></Project>
""");

        var finding = Assert.Single(PinnedVersionChecker.Check(path, "error"));
        Assert.Equal("error", finding.Severity);
        Assert.Contains("Float.Pkg", finding.Message);
        Assert.Contains("6.*", finding.Message);
    }

    [Fact]
    public void Warn_severity_produces_warning_findings()
    {
        var path = WriteTemp(".csproj", """
<Project><ItemGroup><PackageReference Include="Float.Pkg" Version="6.*" /></ItemGroup></Project>
""");

        var finding = Assert.Single(PinnedVersionChecker.Check(path, "warn"));
        Assert.Equal("warning", finding.Severity);
    }

    [Fact]
    public void Off_severity_skips_the_check()
    {
        var path = WriteTemp(".csproj", """
<Project><ItemGroup><PackageReference Include="Float.Pkg" Version="6.*" /></ItemGroup></Project>
""");

        Assert.Empty(PinnedVersionChecker.Check(path, "off"));
    }

    [Fact]
    public void Fully_pinned_manifest_is_clean()
    {
        var path = WriteTemp(".csproj", """
<Project><ItemGroup><PackageReference Include="Exact.Pkg" Version="1.2.3" /></ItemGroup></Project>
""");

        Assert.Empty(PinnedVersionChecker.Check(path, "error"));
    }

    [Fact]
    public void Lock_file_yields_no_findings()
    {
        var path = WriteTemp(".json", """
{ "version": 1, "dependencies": { "net6.0": { "A": { "type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0", "contentHash": "x" } } } }
""");

        Assert.Empty(PinnedVersionChecker.Check(path, "error"));
    }

    private string WriteTemp(string extension, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"nucheck-{Guid.NewGuid():N}{extension}");
        File.WriteAllText(path, content);
        _tempFiles.Add(path);
        return path;
    }

    private string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"nucheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        foreach (var file in _tempFiles.Where(File.Exists))
        {
            File.Delete(file);
        }

        foreach (var dir in _tempDirs.Where(Directory.Exists))
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
