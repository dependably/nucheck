using System.Reflection;
using Dependably.NuCheck.Cli;
using Dependably.NuCheck.Config;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Output;
using Dependably.NuCheck.Services;

namespace Dependably.NuCheck;

public static class Program
{
    /// <summary>Process exit codes, per the Dependably suite convention.</summary>
    private const int ExitClean = 0;          // no findings
    private const int ExitFindings = 1;       // vulnerabilities or policy errors (block)
    private const int ExitError = 2;          // usage error OR operational/internal error

    /// <summary>
    /// Top-level entry point. Wraps <see cref="RunAsync"/> so that ANY unexpected
    /// exception — even one escaping outside the inner try (e.g. config load, source
    /// construction) — is mapped to the operational-error exit code (2) rather than
    /// crashing with a stack trace.
    /// </summary>
    public static async Task<int> Main(string[] args)
    {
        try
        {
            return await RunAsync(args).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return ExitError;
        }
    }

    /// <summary>
    /// Runs the audit and returns the process exit code: 0 clean, 1 when vulnerabilities
    /// or policy errors are found (block), 2 for a usage error (bad flag / missing
    /// manifest) or an operational error (unreadable/unsupported manifest, scan failure,
    /// internal exception). <c>--help</c>/<c>--version</c> exit 0.
    /// <paramref name="sourceFactory"/> lets tests inject a fake advisory source instead
    /// of hitting a live database.
    /// </summary>
    public static async Task<int> RunAsync(string[] args, Func<CliOptions, IAdvisorySource>? sourceFactory = null)
    {
        var options = CliOptions.Parse(args);

        if (options.ShowHelp)
        {
            Console.WriteLine(HelpText);
            return ExitClean;
        }

        if (options.ShowVersion)
        {
            Console.WriteLine(VersionText);
            return ExitClean;
        }

        if (options.Error is not null)
        {
            // Usage error (unknown/invalid flag) -> exit 2.
            Console.Error.WriteLine($"Error: {options.Error}");
            Console.WriteLine(HelpText);
            return ExitError;
        }

        if (options.FilePath is null)
        {
            // Usage error (missing manifest argument) -> exit 2.
            Console.Error.WriteLine("Error: path to a packages file is required.");
            Console.WriteLine(HelpText);
            return ExitError;
        }

        var source = sourceFactory is not null ? sourceFactory(options) : CreateSource(options);
        if (source is null)
        {
            // Unknown --source / missing token: an operational/usage error -> exit 2.
            return ExitError;
        }

        try
        {
            var packages = PackageFileReader.Read(options.FilePath);
            if (options.Verbose)
            {
                Console.Error.WriteLine($"Read {packages.Count} package(s) from {options.FilePath}");
            }

            var audit = await new AuditService(source).AuditAsync(packages).ConfigureAwait(false);

            var checkDirectory = ResolveCheckDirectory(options.FilePath);
            var config = DependablyCheckConfig.Load(options.ConfigPath, checkDirectory);
            if (options.Verbose)
            {
                Console.Error.WriteLine(
                    $"Trusted registry hosts: {string.Join(", ", SourceTrustService.PublicHosts.Concat(config.AllowedRegistryHosts))}");
            }

            var policyFindings = SourceTrustService.Check(
                checkDirectory, config.AllowedRegistryHosts, config.AllowedLocalFeeds);
            var unusedPackages = UnusedPackageService.Check(checkDirectory, config.IgnoreUnusedPackages);
            var result = new AuditResult
            {
                TotalPackages = audit.TotalPackages,
                Vulnerabilities = audit.Vulnerabilities,
                PolicyFindings = policyFindings,
                UnusedPackages = unusedPackages,
                UnverifiableAdvisories = audit.UnverifiableAdvisories,
            };

            // The CI gate (--fail-on, or the default any-vuln-or-policy rule) always
            // evaluates the UNFILTERED result so a display filter cannot hide a failure.
            var exitCode = result.GateTrips(options.FailOnSeverity, options.FailOnCount) ? ExitFindings : ExitClean;

            // --severity is a DISPLAY filter only: it narrows what is printed, never the gate.
            // The formatter is handed the real exit code so JSON's summary.exitCode matches.
            var display = result.FilterBySeverity(options.Severity);
            Console.WriteLine(FormatterFactory.Get(options.Format, ToolVersion, options.FilePath, exitCode, options.Severity).Format(display));

            return exitCode;
        }
        catch (Exception ex)
        {
            // Operational error: unreadable/bad/unsupported manifest, scan failure, etc. -> exit 2.
            Console.Error.WriteLine($"Error: {ex.Message}");
            return ExitError;
        }
    }

    /// <summary>The tool name and version (assembly informational version, sans build metadata).</summary>
    private static string VersionText => $"nucheck {ToolVersion}";

    /// <summary>The bare semver version string (no tool name, no "+&lt;git sha&gt;" suffix).</summary>
    private static string ToolVersion
    {
        get
        {
            var assembly = typeof(Program).Assembly;
            var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            var version = informational ?? assembly.GetName().Version?.ToString() ?? "unknown";

            // Strip any "+<git sha>" source-revision suffix the SDK appends.
            var plus = version.IndexOf('+');
            if (plus >= 0)
            {
                version = version[..plus];
            }

            return version;
        }
    }

    /// <summary>
    /// The directory whose effective NuGet sources are checked: the directory of the
    /// audited file, falling back to the current directory.
    /// </summary>
    private static string ResolveCheckDirectory(string filePath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(filePath));
        return string.IsNullOrEmpty(directory) ? Directory.GetCurrentDirectory() : directory;
    }

    private static IAdvisorySource? CreateSource(CliOptions options)
    {
        switch (options.Source.ToLowerInvariant())
        {
            case "osv":
                return new OsvAdvisoryClient(new HttpClient());

            case "github":
                return CreateGitHubSource(options);

            default:
                Console.Error.WriteLine($"Error: unknown --source '{options.Source}'. Use 'github' or 'osv'.");
                return null;
        }
    }

    private static GitHubAdvisoryClient? CreateGitHubSource(CliOptions options)
    {
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (string.IsNullOrWhiteSpace(token))
        {
            Console.Error.WriteLine("Error: GITHUB_TOKEN environment variable is not set.");
            Console.Error.WriteLine("Create a token at https://github.com/settings/tokens and export GITHUB_TOKEN,");
            Console.Error.WriteLine("or use '--source osv' to query OSV.dev without a token.");
            return null;
        }

        return new GitHubAdvisoryClient(new HttpClient(), token, options.UseRest);
    }

    private const string HelpText = """
nucheck - NuGet vulnerability auditor

Usage:
  nucheck <path-to-packages-file> [options]

Arguments:
  <path-to-packages-file>    Path to packages.config, packages.lock.json, or a
                             .csproj / Directory.Packages.props
                             (PackageReference / Central Package Management).
                             Note: .csproj / .props are parsed statically (no MSBuild
                             evaluation); version ranges & floating versions are audited
                             at their declared LOWER BOUND, not the restored version. For
                             exact resolved versions, point at a packages.lock.json.

Options:
  --source <name>            Advisory source: github (default), osv
  --format <type>            Output format: human, table, json (default: human)
  --severity <level>         Filter by severity: critical, high, moderate, low, info
  --config <path>            Path to a .dependably-check config file. When omitted, the
                             file is discovered by walking up from the audited file's directory.
  --fail-on <key>=<value>    CI gate (repeatable). Without it, ANY vulnerability or policy
                             error fails the build (exit 1) — the default. Each rule below
                             REPLACES that default; the build fails if ANY rule trips:
                               severity=<critical|high|moderate|low|info>
                                     fail only when a finding is at-or-above this level
                                     (relaxes/raises the gate, e.g. severity=high ignores
                                     moderate/low vulns for gating — they still print).
                               count=<N>
                                     fail when the vulnerability count exceeds N. This rule
                                     governs vulnerabilities only; policy errors (see below)
                                     still gate, so count=0 fails on any vulnerability OR any
                                     untrusted source.
                             Policy errors are only relaxed by an explicit severity rule
                             (which governs policy findings too, e.g. severity=critical).
                             Distinct from --severity, which only filters what is printed.
  --rest                     Use the GitHub REST API instead of GraphQL (github source)
  --verbose, -v              Write progress to stderr
  --help, -h                 Show this help message
  --version                  Print the tool version and exit

Policy checks:
  In addition to vulnerabilities, nucheck flags any configured NuGet package
  source whose host is not public (api.nuget.org / nuget.org) and not allowlisted
  in .dependably-check (common.allowedRegistryHosts ∪ nuget.allowedRegistryHosts).
  An untrusted source is an error and exits non-zero.

  Local folder feeds (relative paths or file:// URIs) declared inside the repo
  are also errors by default, because a committed feed can smuggle tampered
  packages past a restore. Trust one explicitly via allowedLocalFeeds:

    {
      "common": { "allowedLocalFeeds": ["./local-packages"] },
      "nuget":  { "allowedLocalFeeds": ["file:///opt/mirror"] }
    }

  When nucheck cannot find a repository boundary (.git), NuGet config in parent
  directories is not audited; nucheck then emits an info finding naming the
  excluded config so the fail-open is visible.

Unused-package check (advisory only, never exits non-zero):
  nucheck heuristically detects packages declared as direct <PackageReference>
  in *.csproj files under the scan root (the audited file's directory) whose
  namespace does not appear in any .cs source file. Build-tool, analyzer, MSBuild-
  task, and PrivateAssets packages commonly trigger false positives. Suppress
  individual packages via ignoreUnusedPackages in .dependably-check:

    {
      "common": { "ignoreUnusedPackages": ["StyleCop.Analyzers"] },
      "nuget":  { "ignoreUnusedPackages": ["Microsoft.CodeAnalysis.Analyzers"] }
    }

Environment Variables:
  GITHUB_TOKEN               GitHub personal access token (required for the github source)

Examples:
  nucheck ./packages.config
  nucheck ./packages.lock.json --source osv --format json
  nucheck ./packages.config --severity high
  nucheck ./packages.config --config ./.dependably-check
  nucheck ./packages.config --fail-on severity=high   # ignore moderate/low for gating
  nucheck ./packages.config --fail-on count=0         # fail on any vulnerability
""";
}
