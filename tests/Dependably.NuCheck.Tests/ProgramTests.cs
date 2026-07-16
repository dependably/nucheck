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
    public void Explicit_github_source_without_token_exits_two()
    {
        var original = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);
        try
        {
            // An EXPLICIT '--source github' with no token is a usage error, not a silent
            // downgrade — the user asked specifically for the GitHub Advisory Database. exit 2.
            var (exit, _, error) = Run(["--source", "github", "whatever.config"], null);
            Assert.Equal(2, exit);
            Assert.Contains("GITHUB_TOKEN", error);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GITHUB_TOKEN", original);
        }
    }

    [Fact]
    public void Missing_token_without_explicit_source_falls_back_to_osv_with_notice()
    {
        // Regression for #57: the default (implicit github) source with no GITHUB_TOKEN must
        // NOT hard-fail. It falls back to OSV.dev with a one-line stderr notice so a first run
        // works out of the box. Using a nonexistent manifest keeps the test off the network:
        // the OSV client is constructed but the file read fails before any HTTP call, so we
        // assert on the notice (and the ABSENCE of the old hard token error) rather than exit.
        var original = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);
        try
        {
            var (_, _, error) = Run(["whatever.config"], null);

            // New behaviour: a fallback notice mentioning OSV is printed to stderr...
            Assert.Contains("OSV", error, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("falling back", error, StringComparison.OrdinalIgnoreCase);
            // ...and the old hard "GITHUB_TOKEN ... is not set" error is NOT emitted.
            Assert.DoesNotContain("GITHUB_TOKEN environment variable is not set", error);
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
    public void Clean_audit_summary_echoes_manifest_and_advisory_source()
    {
        // #58: the summary line must name the manifest that was read and the advisory source it
        // was checked against, so a clean "all secure" result is verifiable.
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");
        var source = new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>())
        {
            DisplayName = "OSV.dev",
        };

        var (exit, output, _) = Run([path], _ => source);

        Assert.Equal(0, exit);
        Assert.Contains("Audited 1 packages (packages.config) against OSV.dev.", output);
        Assert.DoesNotContain("Found 1 packages in audit", output);
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
    public void Severity_filter_high_includes_critical_findings()
    {
        // Regression: --severity high performed an exact match, so a critical advisory was
        // hidden from output while GateTrips still tripped, causing the tool to print "all
        // secure" with exit 1. The filter must be at-or-above so critical is included.
        var path = WritePackagesConfig("Critical.Pkg", "1.5.0");
        var source = Source(
            ("Critical.Pkg", new Advisory("Severe", "critical", ">= 1.0.0, < 2.0.0", ["u"])));

        var (exit, output, _) = Run([path, "--severity", "high", "--format", "json"], _ => source);

        Assert.Equal(1, exit);
        Assert.Contains("Critical.Pkg", output); // must appear in filtered output
        Assert.Contains("critical", output);
    }

    [Fact]
    public void Severity_filter_high_excludes_moderate_findings()
    {
        // Moderate advisories are below high on the ladder; --severity high must filter them out.
        var path = WritePackagesConfig("Moderate.Pkg", "1.5.0");
        var source = Source(
            ("Moderate.Pkg", new Advisory("Meh", "moderate", ">= 1.0.0, < 2.0.0", ["u"])));

        // Gate still trips (default any-vuln rule), but filtered output has no moderate.
        var (exit, output, _) = Run([path, "--severity", "high", "--format", "json"], _ => source);

        Assert.Equal(1, exit);
        Assert.DoesNotContain("Moderate.Pkg", output);
    }

    [Fact]
    public void Severity_bogus_value_is_usage_error_exits_two()
    {
        // --severity bogus was silently accepted before the fix; now it is a usage error.
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");
        var (exit, output, error) = Run([path, "--severity", "bogus"], _ => Source());

        Assert.Equal(2, exit);
        Assert.Contains("--severity", error);
        Assert.Contains("Usage:", output);
    }

    [Fact]
    public void Severity_filter_high_moderate_only_summary_shows_hidden_count_not_all_secure()
    {
        // Regression (#1): when --severity high hides ALL advisories (e.g. only moderate
        // findings) but GateTrips still fires on the unfiltered result, the summary formatter
        // must NOT print "all secure" — that contradicts exit 1.  It must instead report how
        // many advisories were hidden by the display filter.
        var path = WritePackagesConfig("Moderate.Pkg", "1.5.0");
        var source = Source(
            ("Moderate.Pkg", new Advisory("Meh", "moderate", ">= 1.0.0, < 2.0.0", ["u"])));

        // Default format is "human" (SummaryResultFormatter).
        var (exit, output, _) = Run([path, "--severity", "high"], _ => source);

        Assert.Equal(1, exit);
        Assert.DoesNotContain("All packages are secure", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("hidden by --severity high", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("1 advisory(ies)", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Severity_filter_high_moderate_only_table_shows_hidden_count_not_all_secure()
    {
        // Same scenario via --format table (TableResultFormatter).
        var path = WritePackagesConfig("Moderate.Pkg", "1.5.0");
        var source = Source(
            ("Moderate.Pkg", new Advisory("Meh", "moderate", ">= 1.0.0, < 2.0.0", ["u"])));

        var (exit, output, _) = Run([path, "--severity", "high", "--format", "table"], _ => source);

        Assert.Equal(1, exit);
        Assert.DoesNotContain("All packages are secure", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("hidden by --severity high", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("1 advisory(ies)", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Severity_filter_high_mixed_critical_and_moderate_shows_only_critical()
    {
        // Mixed partial-failure scenario: one critical advisory and one moderate advisory on
        // the SAME package. --severity high must keep the critical (at-or-above) and drop
        // the moderate. Gate trips on the unfiltered result; display shows only critical.
        var path = WritePackagesConfig("Mixed.Pkg", "1.5.0");
        var criticalAdvisory = new Advisory("CVE-2025-CRIT", "critical", ">= 1.0.0, < 2.0.0", ["u"]);

        // FakeAdvisorySource maps one package id → list of advisories; build the source
        // directly so Mixed.Pkg gets both advisories.
        var map = new Dictionary<string, IReadOnlyList<Advisory>>
        {
            ["Mixed.Pkg"] =
            [
                criticalAdvisory,
                new Advisory("CVE-2025-MOD", "moderate", ">= 1.0.0, < 2.0.0", ["u"]),
            ],
        };
        var source = new FakeAdvisorySource(map);

        var (exit, output, _) = Run([path, "--severity", "high", "--format", "json"], _ => source);

        Assert.Equal(1, exit);
        Assert.Contains("CVE-2025-CRIT", output);
        Assert.DoesNotContain("CVE-2025-MOD", output);
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
        var dir = Path.Combine(Path.GetTempPath(), $"nucheck-{Guid.NewGuid():N}");
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
    public void Unparseable_advisory_range_surfaces_unverifiable_warning_in_cli_output()
    {
        // Regression for #27 (composition): AuditService collects UnverifiableAdvisories,
        // but Program must wire them into the composed AuditResult.  Without that copy the
        // formatter receives an empty list and the warning is silently invisible end-to-end.
        var path = WritePackagesConfig("Boom.Pkg", "1.5.0");
        // "~> 1.0.0" is a Bundler-style tilde range the parser does not understand.
        var source = Source(("Boom.Pkg", new Advisory("Bad range advisory", "high", "~> 1.0.0", ["u"])));

        var (exit, output, _) = Run([path, "--format", "json"], _ => source);

        // Unverifiable ranges are advisory only — they never fail the build.
        Assert.Equal(0, exit);
        // The finding must be visible in the output (the whole point of #27).
        Assert.Contains("unverifiable-range", output);
        Assert.Contains("Boom.Pkg", output);
    }

    [Fact]
    public void Severity_filter_does_not_suppress_unverifiable_advisory_warnings()
    {
        // Regression for #27 (FilterBySeverity): --severity is a display filter that narrows
        // vulnerability findings, but must NOT drop UnverifiableAdvisories from the result
        // passed to the formatter.
        var path = WritePackagesConfig("Boom.Pkg", "1.5.0");
        var source = Source(("Boom.Pkg", new Advisory("Bad range advisory", "high", "~> 1.0.0", ["u"])));

        var (exit, output, _) = Run([path, "--format", "json", "--severity", "high"], _ => source);

        Assert.Equal(0, exit);
        Assert.Contains("unverifiable-range", output);
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
        var dir = Path.Combine(Path.GetTempPath(), $"nucheck-{Guid.NewGuid():N}");
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

    // ---- pinned-versions rule end-to-end -------------------------------------------

    [Fact]
    public void Unpinned_version_fails_the_audit_by_default()
    {
        var path = WriteFloatingCsproj();

        var (exit, output, _) = Run([path, "--format", "json"], _ => Source());

        Assert.Equal(1, exit);
        Assert.Contains("pinned-versions", output);
        Assert.Contains("Float.Pkg", output);
    }

    [Fact]
    public void Config_warn_override_reports_without_gating()
    {
        var path = WriteFloatingCsproj();
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, ".dependably"),
            """{ "nucheck": { "rules": { "pinned-versions": "warn" } } }""");

        var (exit, output, _) = Run([path, "--format", "json"], _ => Source());

        Assert.Equal(0, exit);
        Assert.Contains("pinned-versions", output);   // still reported, as low severity
        Assert.Contains("\"low\"", output);
    }

    [Fact]
    public void Config_off_override_drops_the_finding_entirely()
    {
        var path = WriteFloatingCsproj();
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, ".dependably"),
            """{ "nucheck": { "rules": { "pinned-versions": "off" } } }""");

        var (exit, output, _) = Run([path, "--format", "json"], _ => Source());

        Assert.Equal(0, exit);
        Assert.DoesNotContain("pinned-versions", output);
    }

    [Fact]
    public void Common_section_rules_are_honoured()
    {
        var path = WriteFloatingCsproj();
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, ".dependably"),
            """{ "common": { "rules": { "pinned-versions": "warn" } } }""");

        var (exit, _, _) = Run([path], _ => Source());

        Assert.Equal(0, exit);
    }

    [Fact]
    public void Cli_rule_override_beats_the_config()
    {
        var path = WriteFloatingCsproj();
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, ".dependably"),
            """{ "nucheck": { "rules": { "pinned-versions": "error" } } }""");

        var (exit, _, _) = Run([path, "--rule", "pinned-versions:warn"], _ => Source());

        Assert.Equal(0, exit);
    }

    [Fact]
    public void Invalid_rule_flag_is_usage_error_exits_two()
    {
        var path = WriteFloatingCsproj();

        var (exit, _, error) = Run([path, "--rule", "pinned-versions:fatal"], _ => Source());

        Assert.Equal(2, exit);
        Assert.Contains("--rule", error);
    }

    [Fact]
    public void Pinned_exception_suppresses_the_finding()
    {
        var path = WriteFloatingCsproj();
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, ".dependably"),
            """{ "nucheck": { "exceptions": [{ "rule": "pinned-versions", "package": "Float.Pkg", "reason": "vendor requires floating" }] } }""");

        var (exit, _, error) = Run([path], _ => Source());

        Assert.Equal(0, exit);
        Assert.Contains("suppressed", error);
    }

    [Fact]
    public void Lock_file_audit_is_unaffected_by_the_pinned_rule()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"nucheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        WriteIsolatingNugetConfig(dir);
        var path = Path.Combine(dir, "packages.lock.json");
        File.WriteAllText(path, """
{
  "version": 1,
  "dependencies": {
    "net6.0": { "Safe.Pkg": { "type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0", "contentHash": "abc" } }
  }
}
""");

        var (exit, output, _) = Run([path, "--format", "json"], _ => Source());

        Assert.Equal(0, exit);
        Assert.DoesNotContain("pinned-versions", output);
    }

    /// <summary>A csproj with one floating PackageReference, in an isolated temp dir.</summary>
    private string WriteFloatingCsproj()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"nucheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        WriteIsolatingNugetConfig(dir);
        // A .git marker stops .dependably discovery from walking above the temp dir.
        Directory.CreateDirectory(Path.Combine(dir, ".git"));

        var path = Path.Combine(dir, "app.csproj");
        File.WriteAllText(path, """
<Project><ItemGroup><PackageReference Include="Float.Pkg" Version="6.*" /></ItemGroup></Project>
""");
        return path;
    }

    private static void WriteIsolatingNugetConfig(string dir)
        => File.WriteAllText(Path.Combine(dir, "nuget.config"), """
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
""");

    private string WritePackagesConfig(string id, string version)
    {
        // Place the manifest in its own directory with an isolating nuget.config so the
        // source-trust policy check sees only nuget.org, independent of the machine's
        // ambient NuGet configuration.
        var dir = Path.Combine(Path.GetTempPath(), $"nucheck-{Guid.NewGuid():N}");
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
