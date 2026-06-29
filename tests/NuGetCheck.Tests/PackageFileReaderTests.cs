using NuGetCheck.Services;

namespace NuGetCheck.Tests;

public class PackageFileReaderTests : IDisposable
{
    private readonly List<string> _tempFiles = [];

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

    [Fact]
    public void Read_fails_closed_on_directory_packages_props()
    {
        // Central Package Management file: a <Project> root, NOT a manifest we parse.
        // This must error rather than silently report "0 packages / all secure".
        var path = WriteTemp(".props", """
<?xml version="1.0" encoding="utf-8"?>
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="11.0.2" />
  </ItemGroup>
</Project>
""");

        var ex = Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
        Assert.Contains("Unsupported manifest", ex.Message);
    }

    [Fact]
    public void Read_fails_closed_on_csproj_packagereference()
    {
        // A <Project>-rooted .csproj with bare <PackageReference> is not yet supported.
        var path = WriteTemp(".csproj", """
<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="11.0.2" />
  </ItemGroup>
</Project>
""");

        var ex = Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
        Assert.Contains("Unsupported manifest", ex.Message);
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

    private string WriteTemp(string extension, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}{extension}");
        File.WriteAllText(path, content);
        _tempFiles.Add(path);
        return path;
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
    }
}
