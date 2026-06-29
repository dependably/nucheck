using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Tests;

public class PackageFileReaderTests : IDisposable
{
    private readonly List<string> _tempFiles = [];
    private readonly List<string> _tempDirs = [];

    [Fact]
    public void Read_parses_packages_config_including_four_part_versions()
    {
        var path = WriteTemp(".config", """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="11.0.2" targetFramework="net462" />
  <package id="Bouncy.Castle" version="1.8.3.1" targetFramework="net462" />
</packages>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "Newtonsoft.Json" && p.Version.ToString() == "11.0.2");
        // The four-part version that npm semver could not handle.
        Assert.Contains(packages, p => p.Id == "Bouncy.Castle" && p.Version.ToString() == "1.8.3.1");
    }

    [Fact]
    public void Read_parses_packages_lock_json()
    {
        var path = WriteTemp(".json", """
{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[11.0.2, )", "resolved": "11.0.2", "contentHash": "abc" }
    }
  }
}
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
        Assert.Equal("11.0.2", package.Version.ToString());
    }

    [Fact]
    public void Read_throws_for_missing_file()
    {
        Assert.Throws<FileNotFoundException>(() => PackageFileReader.Read("/no/such/file.config"));
    }

    [Fact]
    public void Read_throws_invalid_data_for_malformed_config()
    {
        var path = WriteTemp(".config", "<packages><unclosed>");
        Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_reports_zero_for_valid_but_empty_packages_config()
    {
        // A real, recognised packages.config with no entries must still be treated as
        // an empty audit (0 packages) — only UNRECOGNISED formats error.
        var path = WriteTemp(".config", """
<?xml version="1.0" encoding="utf-8"?>
<packages>
</packages>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Empty(packages);
    }

    [Fact]
    public void Read_recognises_packages_config_by_root_not_extension()
    {
        // Content-based recognition: a <packages> root parses even with an odd name.
        var path = WriteTemp(".xml", """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="11.0.2" targetFramework="net462" />
</packages>
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
    }

    // Wave 2 change: Central Package Management and bare <PackageReference> are now
    // SUPPORTED. The two tests below previously asserted these formats THREW
    // "Unsupported manifest" (Wave 1, fail-closed). They are now positive tests proving
    // the formats parse.
    [Fact]
    public void Read_parses_directory_packages_props_as_central_versions()
    {
        // Central Package Management file: a <Project> root whose <PackageVersion>
        // entries ARE the package set to audit.
        var path = WriteTemp(".props", """
<?xml version="1.0" encoding="utf-8"?>
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="11.0.2" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
        Assert.Equal("11.0.2", package.Version.ToString());
    }

    [Fact]
    public void Read_parses_csproj_packagereference()
    {
        // A <Project>-rooted .csproj with a bare <PackageReference> is now audited.
        var path = WriteTemp(".csproj", """
<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="11.0.2" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
        Assert.Equal("11.0.2", package.Version.ToString());
    }

    [Fact]
    public void Read_fails_closed_on_unknown_non_xml_file()
    {
        var path = WriteTemp(".txt", "this is not a manifest");

        var ex = Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
        Assert.Contains("Unsupported manifest", ex.Message);
    }

    [Fact]
    public void Read_throws_for_malformed_json()
    {
        var path = WriteTemp(".json", "{ not valid json");

        Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_throws_for_json_that_is_not_a_lock_file()
    {
        // Valid JSON, but not a lock file — must NOT silently report 0 packages.
        var path = WriteTemp(".json", """{ "foo": "bar" }""");

        Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_reports_zero_for_valid_but_empty_lock_file()
    {
        var path = WriteTemp(".json", """{ "version": 1, "dependencies": {} }""");

        var packages = PackageFileReader.Read(path);

        Assert.Empty(packages);
    }

    // --- Wave 2: <PackageReference> + Central Package Management (.csproj / .props) ---

    [Fact]
    public void Read_parses_packagereference_version_attribute()
    {
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="1.2.3" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_parses_packagereference_version_child_element()
    {
        // The <Version> child-element form instead of the attribute.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X">
      <Version>1.2.3</Version>
    </PackageReference>
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_resolves_cpm_version_from_directory_packages_props()
    {
        // Central Package Management: csproj has a versionless <PackageReference>; the
        // version comes from a Directory.Packages.props beside it (walked up the tree).
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.2.3" />
  </ItemGroup>
</Project>
""");
        var csproj = Path.Combine(dir, "foo.csproj");
        File.WriteAllText(csproj, """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(csproj));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_directory_packages_props_directly_returns_its_version_set()
    {
        var path = WriteTemp(".props", """
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
    <PackageVersion Include="Y" Version="2.0.0" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Id == "Y" && p.Version.ToString() == "2.0.0");
    }

    [Fact]
    public void Read_audits_version_range_at_lower_bound()
    {
        // A version range is audited at its declared LOWER BOUND (conservative).
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="[1.0.0,2.0.0)" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.0.0", package.Version.ToString());
    }

    [Fact]
    public void Read_project_with_no_packagereferences_returns_empty_not_error()
    {
        // A clean <Project> with zero packages is an empty audit, NOT an error.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>
""");

        Assert.Empty(PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_skips_unresolvable_version_but_returns_siblings()
    {
        // A reference whose version cannot be determined is skipped; siblings remain.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Good" Version="1.2.3" />
    <PackageReference Include="Unversioned" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("Good", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_uses_version_override_attribute()
    {
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" VersionOverride="3.1.0" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("3.1.0", package.Version.ToString());
    }

    private string WriteTemp(string extension, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}{extension}");
        File.WriteAllText(path, content);
        _tempFiles.Add(path);
        return path;
    }

    private string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        foreach (var file in _tempFiles)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }

        foreach (var dir in _tempDirs)
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }
}
