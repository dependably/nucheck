using NuGetCheck.Cli;
using NuGetCheck.Models;
using NuGetCheck.Services;
using NuGetCheck.Tests.Fakes;

namespace NuGetCheck.Tests;

/// <summary>
/// Exercises the Program entry point. These tests redirect Console and mutate the
/// GITHUB_TOKEN env var, so they run in a non-parallel collection.
/// </summary>
[Collection("Console")]
public class ProgramTests : IDisposable
{
    private readonly TextWriter _originalOut = Console.Out;
    private readonly TextWriter _originalError = Console.Error;
    private readonly List<string> _tempDirs = [];

    private static FakeAdvisorySource Source(params (string Id, Advisory Advisory)[] entries)
    {
        var map = new Dictionary<string, IReadOnlyList<Advisory>>();
        foreach (var (id, advisory) in entries)
        {
            map[id] = [advisory];
        }

        return new FakeAdvisorySource(map);
    }

    private static (int Exit, string Out, string Error) Run(string[] args, Func<CliOptions, IAdvisorySource>? factory)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        Console.SetOut(stdout);
        Console.SetError(stderr);
        var exit = Program.RunAsync(args, factory).GetAwaiter().GetResult();
        return (exit, stdout.ToString(), stderr.ToString());
    }

    [Fact]
    public void Help_prints_usage_and_exits_zero()
    {
        var (exit, output, _) = Run(["--help"], _ => Source());
        Assert.Equal(0, exit);
        Assert.Contains("Usage:", output);
    }

    [Fact]
    public void Missing_path_exits_one()
    {
        var (exit, _, error) = Run([], _ => Source());
        Assert.Equal(1, exit);
        Assert.Contains("path to a packages file", error);
    }

    [Fact]
    public void Missing_token_exits_one()
    {
        var original = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);
        try
        {
            // No factory -> Program tries to build the real GitHub source and stops on the missing token.
            var (exit, _, error) = Run(["whatever.config"], null);
            Assert.Equal(1, exit);
            Assert.Contains("GITHUB_TOKEN", error);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GITHUB_TOKEN", original);
        }
    }

    [Fact]
    public void Clean_audit_exits_zero()
    {
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");
        var (exit, output, _) = Run([path], _ => Source());
        Assert.Equal(0, exit);
        Assert.Contains("secure", output);
    }

    [Fact]
    public void Vulnerable_audit_exits_one()
    {
        var path = WritePackagesConfig("Vulnerable.Pkg", "1.5.0");
        var source = Source(("Vulnerable.Pkg", new Advisory("Boom", "high", ">= 1.0.0, < 2.0.0", ["u"])));

        var (exit, output, _) = Run([path, "--format", "json"], _ => source);

        Assert.Equal(1, exit);
        Assert.Contains("Vulnerable.Pkg", output);
    }

    [Fact]
    public void Untrusted_source_fails_clean_audit()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);

        File.WriteAllText(Path.Combine(dir, "nuget.config"), """
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="private" value="https://nuget.evil.example/v3/index.json" />
  </packageSources>
</configuration>
""");
        var path = Path.Combine(dir, "packages.config");
        File.WriteAllText(path, """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Safe.Pkg" version="1.0.0" targetFramework="net462" />
</packages>
""");

        var (exit, output, _) = Run([path, "--format", "json"], _ => Source());

        Assert.Equal(1, exit);
        Assert.Contains("nuget.evil.example", output);
    }

    [Fact]
    public void Unknown_flag_exits_one_with_usage_error()
    {
        // A bogus flag alongside a valid manifest must NOT silently exit 0.
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");
        var (exit, output, error) = Run([path, "--bogus"], _ => Source());

        Assert.Equal(1, exit);
        Assert.Contains("unknown option: '--bogus'", error);
        Assert.Contains("Usage:", output);
    }

    [Fact]
    public void File_error_exits_one()
    {
        var (exit, _, error) = Run(["/no/such/file.config"], _ => Source());
        Assert.Equal(1, exit);
        Assert.Contains("Error:", error);
    }

    private string WritePackagesConfig(string id, string version)
    {
        // Place the manifest in its own directory with an isolating nuget.config so the
        // source-trust policy check sees only nuget.org, independent of the machine's
        // ambient NuGet configuration.
        var dir = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);

        File.WriteAllText(Path.Combine(dir, "nuget.config"), """
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
""");

        var path = Path.Combine(dir, "packages.config");
        File.WriteAllText(path, $"""
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="{id}" version="{version}" targetFramework="net462" />
</packages>
""");
        return path;
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        Console.SetOut(_originalOut);
        Console.SetError(_originalError);
        foreach (var dir in _tempDirs)
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }
}
