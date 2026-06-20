using NuGetCheck.Cli;
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

            Console.WriteLine(FormatterFactory.Get(options.Format).Format(result));
            return result.VulnerabilityCount > 0 ? 1 : 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
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
  <path-to-packages-file>    Path to packages.config or packages.lock.json

Options:
  --source <name>            Advisory source: github (default), osv
  --format <type>            Output format: summary, table, json (default: summary)
  --severity <level>         Filter by severity: critical, high, moderate, low
  --rest                     Use the GitHub REST API instead of GraphQL (github source)
  --verbose, -v              Write progress to stderr
  --help, -h                 Show this help message

Environment Variables:
  GITHUB_TOKEN               GitHub personal access token (required for the github source)

Examples:
  nuget-check ./packages.config
  nuget-check ./packages.lock.json --source osv --format json
  nuget-check ./packages.config --severity high
""";
}
