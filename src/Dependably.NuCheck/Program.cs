using System.Reflection;
using Dependably.NuCheck.Cli;
using Dependably.NuCheck.Config;
using Dependably.NuCheck.Facts;
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

        if (options.Facts)
        {
            // Facts mode branches BEFORE any advisory source exists: no network, no
            // GITHUB_TOKEN notice, no gate. Exit 0 on a successful scan, 2 for a
            // missing/unreadable target (an operational error — no help text).
            if (options.FilePath is null)
            {
                Console.Error.WriteLine("Error: --facts requires a target directory.");
                Console.WriteLine(HelpText);
                return ExitError;
            }

            return FactsCommand.Run(options.FilePath, ToolVersion, options.Roots, options.Verbose, Console.Out, Console.Error);
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

            // Surface .dependably deprecation / unknown-key notices (never gating).
            foreach (var warning in config.Warnings)
            {
                Console.Error.WriteLine($".dependably: {warning.Message}");
            }

            if (options.Verbose)
            {
                Console.Error.WriteLine(
                    $"Trusted registry hosts: {string.Join(", ", SourceTrustService.PublicHosts.Concat(config.AllowedRegistryHosts))}");
            }

            var policyFindings = SourceTrustService.Check(
                checkDirectory, config.AllowedRegistryHosts, config.AllowedLocalFeeds);
            var unusedPackages = UnusedPackageService.Check(checkDirectory, config.IgnoreUnusedPackages);

            // The pinned-versions rule: error by default, resolved CLI --rule > config
            // rules map > built-in (flags > files). "off" skips the check entirely.
            var pinnedSeverity = options.RuleOverrides.TryGetValue(PinnedVersionChecker.RuleId, out var cliSeverity)
                ? cliSeverity
                : config.RuleSeverities.GetValueOrDefault(PinnedVersionChecker.RuleId, PinnedVersionChecker.DefaultSeverity);
            var pinnedFindings = PinnedVersionChecker.Check(options.FilePath, pinnedSeverity);

            // Apply .dependably exceptions: suppress specific findings so they no longer gate
            // (spec §6). Suppressed counts and unused/expired entries are reported on stderr.
            var suppression = ExceptionApplier.Apply(
                audit.Vulnerabilities, unusedPackages, audit.UnverifiableAdvisories, config.Exceptions,
                pinnedVersionFindings: pinnedFindings);
            foreach (var note in suppression.Notices)
            {
                Console.Error.WriteLine($".dependably: {note}");
            }

            var result = new AuditResult
            {
                TotalPackages = audit.TotalPackages,
                Vulnerabilities = suppression.Vulnerabilities,
                PolicyFindings = policyFindings,
                PinnedVersionFindings = suppression.PinnedVersionFindings,
                UnusedPackages = suppression.UnusedPackages,
                UnverifiableAdvisories = suppression.UnverifiableAdvisories,
            };

            // Config `failOn` feeds the gate; a CLI `--fail-on` overrides it (flags > files).
            var failOnSeverity = options.FailOnSeverity ?? config.FailOnSeverity;
            var failOnCount = options.FailOnCount ?? config.FailOnCount;

            // The CI gate (--fail-on, or the default any-vuln-or-policy rule) always
            // evaluates the UNFILTERED result so a display filter cannot hide a failure.
            var exitCode = result.GateTrips(failOnSeverity, failOnCount) ? ExitFindings : ExitClean;

            // --severity is a DISPLAY filter only: it narrows what is printed, never the gate.
            // The formatter is handed the real exit code so JSON's summary.exitCode matches.
            var display = result.FilterBySeverity(options.Severity);
            Console.WriteLine(FormatterFactory
                .Get(options.Format, ToolVersion, options.FilePath, exitCode, options.Severity, source.DisplayName)
                .Format(display));

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

    private static IAdvisorySource? CreateGitHubSource(CliOptions options)
    {
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (string.IsNullOrWhiteSpace(token))
        {
            // No token AND the user did not ask for GitHub explicitly (the "github" source is
            // just the default): fall back to the zero-credential OSV.dev source with a one-line
            // stderr notice so a first run works out of the box instead of hard-failing.
            if (!options.SourceSpecified)
            {
                Console.Error.WriteLine(
                    "Notice: GITHUB_TOKEN is not set; falling back to OSV.dev (no token required). "
                    + "Pass '--source github' to require the GitHub Advisory Database.");
                return new OsvAdvisoryClient(new HttpClient());
            }

            // Explicit '--source github' with no token: this is a usage error, not a silent
            // downgrade — the user asked specifically for the GitHub Advisory Database.
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
  nucheck --facts <directory> [--roots <a,b,...>] [--verbose]

Arguments:
  <path-to-packages-file>    Path to packages.config, packages.lock.json, or a
                             .csproj / Directory.Packages.props
                             (PackageReference / Central Package Management).
                             Note: .csproj / .props are parsed statically (no MSBuild
                             evaluation); version ranges & floating versions are audited
                             at their declared LOWER BOUND, not the restored version. For
                             exact resolved versions, point at a packages.lock.json.
  <directory>                With --facts: the source tree to describe.

Options:
  --facts                    Emit a JSON "facts" document describing the .NET source
                             tree at <directory> instead of auditing a manifest: the
                             projects and their PackageReferences, each restore
                             artefact's resolved closure, the namespaces read from each
                             package's assemblies, every C# file's using directives and
                             qualified identifiers, and the type/member references of
                             each built output assembly. Facts, not findings: no
                             advisories, no severities, no verdicts; nothing is gated
                             and no network is touched. Exits 0 on a successful scan
                             (paths it could not read are listed in `unanalyzable`),
                             2 for a missing or unreadable <directory>. --fail-on,
                             --severity, --source, --rule, --rest, --config and
                             --format are inert in this mode.
  --roots <a,b,...>          Facts mode only (repeatable, comma-separated). Extra top-level
                             identifier roots to keep fully-qualified uses for, in addition
                             to the roots the tree's own artefacts reveal (published as
                             source.qualifiedRoots). A package absent from every readable
                             restore artefact — an un-restored tree, no lock file — would
                             otherwise lose its `Foo.Bar.Client.Send(...)`-style uses that
                             have no using directive. A dotted name is reduced to its
                             first segment (Amazon.S3 -> Amazon).
  --source <name>            Advisory source: github (default), osv
  --format <type>            Output format: human, table, json (default: human)
  --severity <level>         Filter by severity: critical, high, moderate, low, info
  --config <path>            Path to a .dependably config file (.dependably-check is a
                             deprecated alias). When omitted, it is discovered by walking up
                             from the audited file's directory to the repo root.
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
  --rule <id>:<severity>     Override a rule's severity for this run (repeatable), e.g.
                             --rule pinned-versions:warn. Severity is error, warn, or off;
                             takes precedence over the .dependably rules map (flags > files).
  --rest                     Use the GitHub REST API instead of GraphQL (github source)
  --verbose, -v              Write progress to stderr
  --help, -h                 Show this help message
  --version                  Print the tool version and exit

Policy checks:
  In addition to vulnerabilities, nucheck flags any configured NuGet package
  source whose host is not public (api.nuget.org / nuget.org) and not allowlisted
  in .dependably (the union of the common.allowedRegistryHosts and
  nucheck.allowedRegistryHosts lists).
  An untrusted source is an error and exits non-zero.

  Local folder feeds (relative paths or file:// URIs) declared inside the repo
  are also errors by default, because a committed feed can smuggle tampered
  packages past a restore. Trust one explicitly via allowedLocalFeeds:

    {
      "common":  { "allowedLocalFeeds": ["./local-packages"] },
      "nucheck": { "allowedLocalFeeds": ["file:///opt/mirror"] }
    }

  When nucheck cannot find a repository boundary (.git), NuGet config in parent
  directories is not audited; nucheck then emits an info finding naming the
  excluded config so the fail-open is visible.

Pinned-versions check (error by default — gates the build):
  Every declared package version must be an exact pin. Floating versions (6.*),
  ranges ([1.0,2.0)), a range-carrying allowedVersions in packages.config, and a
  version-less <PackageReference> with no Central Package Management entry are
  findings; the exact bracket range [1.2.3] counts as pinned. NOT applicable to
  packages.lock.json — a lock file's resolved versions are exact by definition.
  Relax per repo via .dependably rules (error / warn / off; warn reports without
  gating, off disables the check), or per run with --rule:

    {
      "nucheck": { "rules": { "pinned-versions": "warn" } }
    }

  Suppress a specific finding instead with an exceptions entry
  (rule "pinned-versions", selector package, optionally @<declared-version>).

Unused-package check (advisory only, never exits non-zero):
  nucheck heuristically detects packages declared as direct <PackageReference>
  in *.csproj files under the scan root (the audited file's directory) whose
  namespace does not appear in any .cs source file. This is a heuristic and false
  positives are common: a package's namespace often differs from its package ID,
  packages consumed only via dependency-injection extension methods, and transitive
  or native runtime assets legitimately show no direct namespace usage. Build-tool,
  analyzer, MSBuild-task, PrivateAssets, and *.runtime.* / native-asset packages are
  suppressed automatically; suppress anything else via ignoreUnusedPackages in
  .dependably:

    {
      "common":  { "ignoreUnusedPackages": ["StyleCop.Analyzers"] },
      "nucheck": { "ignoreUnusedPackages": ["Microsoft.CodeAnalysis.Analyzers"] }
    }

Exceptions (standardized .dependably suppression):
  Suppress specific findings so they no longer fail the build, without disabling a
  check wholesale. Each entry needs a rule id, at least one selector (nucheck matches
  package and id), and a non-empty reason; an optional expires (YYYY-MM-DD) makes it
  inert afterward. Suppressed findings are removed from the gate; unused and expired
  exceptions are reported on stderr.

    {
      "nucheck": {
        "exceptions": [
          { "rule": "vulnerable-package", "package": "log4net@2.0.8", "id": "GHSA-2cwj-8chv-9pp9",
            "reason": "sink unreachable; upgrade blocked", "expires": "2026-09-30" },
          { "rule": "unused-packages", "package": "Microsoft.SourceLink.GitHub",
            "reason": "build-time only, no runtime namespace" }
        ],
        "failOn": { "severity": "high" }
      }
    }

Environment Variables:
  GITHUB_TOKEN               GitHub personal access token for the github source. When unset
                             and no --source is given, nucheck falls back to OSV.dev (which
                             needs no token) with a one-line stderr notice.

Examples:
  nucheck ./packages.config
  nucheck ./packages.lock.json --source osv --format json
  nucheck ./packages.config --severity high
  nucheck ./packages.config --config ./.dependably
  nucheck ./packages.config --fail-on severity=high   # ignore moderate/low for gating
  nucheck ./packages.config --fail-on count=0         # fail on any vulnerability
  nucheck --facts ./src > facts.json                  # language facts, no audit
  nucheck --facts ./src --roots Amazon,Fabrikam       # keep Amazon.* / Fabrikam.* qualified uses too
""";
}
