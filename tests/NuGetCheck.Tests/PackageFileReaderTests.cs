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

    private string WriteTemp(string extension, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}{extension}");
        File.WriteAllText(path, content);
        _tempFiles.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var file in _tempFiles)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }
    }
}
