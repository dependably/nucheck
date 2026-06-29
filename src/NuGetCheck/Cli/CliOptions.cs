namespace NuGetCheck.Cli;

/// <summary>
/// Parsed command-line options. The parser is table-driven (no growing if/else
/// chain and no loop-counter mutation) so it stays simple and easy to test.
/// </summary>
public sealed class CliOptions
{
    private static readonly Dictionary<string, Action<CliOptions, string>> ValueFlags = new(StringComparer.Ordinal)
    {
        ["--format"] = (o, v) => o.Format = v,
        ["--severity"] = (o, v) => o.Severity = v,
        ["--source"] = (o, v) => o.Source = v,
        ["--config"] = (o, v) => o.ConfigPath = v,
    };

    private static readonly Dictionary<string, Action<CliOptions>> BoolFlags = new(StringComparer.Ordinal)
    {
        ["--rest"] = o => o.UseRest = true,
        ["--verbose"] = o => o.Verbose = true,
        ["-v"] = o => o.Verbose = true,
        ["--help"] = o => o.ShowHelp = true,
        ["-h"] = o => o.ShowHelp = true,
        ["--version"] = o => o.ShowVersion = true,
    };

    public string? FilePath { get; private set; }

    public string Format { get; private set; } = "human";

    public string? Severity { get; private set; }

    /// <summary>Advisory source: "github" (default, needs GITHUB_TOKEN) or "osv" (no token).</summary>
    public string Source { get; private set; } = "github";

    /// <summary>
    /// Explicit path to a <c>.dependably-check</c> config file. When null, the file is
    /// discovered by walking up from the current directory.
    /// </summary>
    public string? ConfigPath { get; private set; }

    public bool UseRest { get; private set; }

    public bool Verbose { get; private set; }

    public bool ShowHelp { get; private set; }

    /// <summary>True when <c>--version</c> was passed: print the version and exit 0.</summary>
    public bool ShowVersion { get; private set; }

    /// <summary>
    /// A usage error produced while parsing (e.g. an unknown option), or null when the
    /// arguments parsed cleanly. The first error wins. <see cref="Program"/> routes a
    /// non-null value through the usage-error path (message to stderr, help, exit 1).
    /// </summary>
    public string? Error { get; private set; }

    public static CliOptions Parse(IEnumerable<string> args)
    {
        var options = new CliOptions();
        var queue = new Queue<string>(args);

        while (queue.Count > 0)
        {
            var arg = queue.Dequeue();

            if (ValueFlags.TryGetValue(arg, out var setValue))
            {
                if (queue.Count > 0)
                {
                    setValue(options, queue.Dequeue());
                }
            }
            else if (BoolFlags.TryGetValue(arg, out var setBool))
            {
                setBool(options);
            }
            else if (arg.StartsWith('-'))
            {
                // An unrecognized -/-- token is a typo or an unsupported flag; reject it
                // (first error wins) rather than silently dropping it and exiting 0.
                options.Error ??= $"unknown option: '{arg}'";
            }
            else if (options.FilePath is null)
            {
                options.FilePath = arg;
            }
        }

        return options;
    }
}
