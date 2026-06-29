using NuGetCheck.Cli;
using NuGetCheck.Config;
using NuGetCheck.Models;
using NuGetCheck.Output;
using NuGetCheck.Services;

namespace NuGetCheck;

public static class Program
{
    public static Task<int> Main(string[] args) => RunAsync(args);

    /// <summary>
    /// Runs the audit and returns the process exit code (1 when vulnerabilities are
    /// found or an error occurs, 0 otherwise). <paramref name="sourceFactory"/> lets
    /// tests inject a fake advisory source instead of hitting a live database.
    /// </summary>
    public static async Task<int> RunAsync(string[] args, Func<CliOptions, IAdvisorySource>? sourceFactory = null)
    {
        var options = CliOptions.Parse(args);

        if (options.ShowHelp)
        {
            Console.WriteLine(HelpText);
            return 0;
        }

        if (options.FilePath is null)
        {
            Console.Error.WriteLine("Error: path to a packages file is required.");
            Console.WriteLine(HelpText);
            return 1;
        }

        var source = sourceFactory is not null ? sourceFactory(options) : CreateSource(options);
        if (source is null)
        {
            return 1;
        }

        try
        {
            var packages = PackageFileReader.Read(options.FilePath);
            if (options.Verbose)
            {
                Console.Error.WriteLine($"Read {packages.Count} package(s) from {options.FilePath}");
            }

            var result = await new AuditService(source).AuditAsync(packages).ConfigureAwait(false);
            result = result.FilterBySeverity(options.Severity);

            var checkDirectory = ResolveCheckDirectory(options.FilePath);
            var config = DependablyCheckConfig.Load(options.ConfigPath, checkDirectory);
            if (options.Verbose)
            {
                Console.Error.WriteLine(
                    $"Trusted registry hosts: {string.Join(", ", SourceTrustService.PublicHosts.Concat(config.AllowedRegistryHosts))}");
            }

            var policyFindings = SourceTrustService.Check(checkDirectory, config.AllowedRegistryHosts);
            var unusedPackages = UnusedPackageService.Check(checkDirectory, config.IgnoreUnusedPackages);
            result = new AuditResult
            {
                TotalPackages = result.TotalPackages,
                Vulnerabilities = result.Vulnerabilities,
                PolicyFindings = policyFindings,
                UnusedPackages = unusedPackages,
            };

            Console.WriteLine(FormatterFactory.Get(options.Format).Format(result));
            return result.HasFailures ? 1 : 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
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
nuget-check - NuGet vulnerability auditor

Usage:
  nuget-check <path-to-packages-file> [options]

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
  --format <type>            Output format: summary, table, json (default: summary)
  --severity <level>         Filter by severity: critical, high, moderate, low
  --config <path>            Path to a .dependably-check config file. When omitted, the
                             file is discovered by walking up from the current directory.
  --rest                     Use the GitHub REST API instead of GraphQL (github source)
  --verbose, -v              Write progress to stderr
  --help, -h                 Show this help message

Policy checks:
  In addition to vulnerabilities, nuget-check flags any configured NuGet package
  source whose host is not public (api.nuget.org / nuget.org) and not allowlisted
  in .dependably-check (common.allowedRegistryHosts ∪ nuget.allowedRegistryHosts).
  An untrusted source is an error and exits non-zero.

Unused-package check (advisory only, never exits non-zero):
  nuget-check heuristically detects packages declared as direct <PackageReference>
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
  nuget-check ./packages.config
  nuget-check ./packages.lock.json --source osv --format json
  nuget-check ./packages.config --severity high
  nuget-check ./packages.config --config ./.dependably-check
""";
}
