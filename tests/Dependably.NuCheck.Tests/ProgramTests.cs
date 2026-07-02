using Dependably.NuCheck.Cli;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Services;
using Dependably.NuCheck.Tests.Fakes;

namespace Dependably.NuCheck.Tests;

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
    public void Version_prints_and_exits_zero()
    {
        var (exit, output, _) = Run(["--version"], _ => Source());
        Assert.Equal(0, exit);
        Assert.Contains("nucheck", output);
    }

    [Fact]
    public void Missing_path_is_usage_error_exits_two()
    {
        // Suite convention: a missing manifest argument is a usage error -> exit 2.
        var (exit, _, error) = Run([], _ => Source());
        Assert.Equal(2, exit);
        Assert.Contains("path to a packages file", error);
    }

    [Fact]
    public void Missing_token_exits_two()
    {
        var original = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);
        try
        {
            // No factory -> Program tries to build the real GitHub source and stops on the
            // missing token. A missing-credential operational error is exit 2, not 1.
            var (exit, _, error) = Run(["whatever.config"], null);
            Assert.Equal(2, exit);
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
    public void Fail_on_severity_high_ignores_moderate_vuln_for_gating()
    {
        // The default would trip on any vuln; --fail-on severity=high relaxes the gate so a
        // moderate-only finding no longer fails the build (it still appears in the output).
        var path = WritePackagesConfig("Moderate.Pkg", "1.5.0");
        var source = Source(("Moderate.Pkg", new Advisory("Meh", "moderate", ">= 1.0.0, < 2.0.0", ["u"])));

        var (exit, output, _) = Run([path, "--fail-on", "severity=high", "--format", "json"], _ => source);

        Assert.Equal(0, exit);
        Assert.Contains("Moderate.Pkg", output);            // still printed
        Assert.Contains("\"exitCode\": 0", output);          // JSON mirrors the real exit code
    }

    [Fact]
    public void Fail_on_severity_high_still_trips_on_high_vuln()
    {
        var path = WritePackagesConfig("High.Pkg", "1.5.0");
        var source = Source(("High.Pkg", new Advisory("Boom", "high", ">= 1.0.0, < 2.0.0", ["u"])));

        var (exit, _, _) = Run([path, "--fail-on", "severity=high"], _ => source);

        Assert.Equal(1, exit);
    }

    [Fact]
    public void Fail_on_count_trips_when_vulnerability_count_exceeds_threshold()
    {
        var path = WritePackagesConfig("Vuln.Pkg", "1.5.0");
        var source = Source(("Vuln.Pkg", new Advisory("Boom", "high", ">= 1.0.0, < 2.0.0", ["u"])));

        // One advisory: count=1 (>1 is false) does not trip; count=0 (>0 is true) does.
        Assert.Equal(0, Run([path, "--fail-on", "count=1"], _ => source).Exit);
        Assert.Equal(1, Run([path, "--fail-on", "count=0"], _ => source).Exit);
    }

    [Fact]
    public void Fail_on_bad_value_is_usage_error_exits_two()
    {
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");
        var (exit, output, error) = Run([path, "--fail-on", "severity=bogus"], _ => Source());

        Assert.Equal(2, exit);
        Assert.Contains("--fail-on", error);
        Assert.Contains("Usage:", output);
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
    public void Unknown_flag_is_usage_error_exits_two()
    {
        // A bogus flag alongside a valid manifest must NOT silently exit 0; a usage error
        // is exit 2 under the suite convention (was 1 before the P1 alignment).
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");
        var (exit, output, error) = Run([path, "--bogus"], _ => Source());

        Assert.Equal(2, exit);
        Assert.Contains("unknown option: '--bogus'", error);
        Assert.Contains("Usage:", output);
    }

    [Fact]
    public void File_error_is_operational_error_exits_two()
    {
        // A missing/unreadable manifest is an operational error -> exit 2 (was 1).
        var (exit, _, error) = Run(["/no/such/file.config"], _ => Source());
        Assert.Equal(2, exit);
        Assert.Contains("Error:", error);
    }

    [Fact]
    public void Unsupported_manifest_is_operational_error_exits_two()
    {
        // Junk that is recognised as neither packages.config/.lock.json nor a project
        // file is an operational error (the scanner refuses to fail open) -> exit 2.
        var dir = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        var path = Path.Combine(dir, "garbage.txt");
        File.WriteAllText(path, "this is not a manifest");

        var (exit, _, error) = Run([path], _ => Source());
        Assert.Equal(2, exit);
        Assert.Contains("Error:", error);
    }

    // ---- #20 / #48 (consolidated): unknown --source value exits 2 ---------------

    [Fact]
    public void Unknown_source_value_is_operational_error_exits_two()
    {
        // --source bogus → CreateSource hits the default branch, writes an error, returns null.
        // RunAsync maps null source → ExitError (2).
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");

        // factory: null so CreateSource() is invoked with the real options.
        var (exit, _, error) = Run([path, "--source", "bogus"], null);

        Assert.Equal(2, exit);
        Assert.Contains("unknown --source", error, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("bogus", error);
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
