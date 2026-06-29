namespace Dependably.NuCheck.Cli;

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
        ["--fail-on"] = (o, v) => o.ApplyFailOn(v),
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

    /// <summary>
    /// The CI gate level set by <c>--fail-on severity=&lt;level&gt;</c>: a normalised ladder
    /// word, or null when the severity gate was not configured. When set, the build fails
    /// only if a finding is at-or-above this level (this RELAXES or RAISES the gate; the
    /// display <see cref="Severity"/> filter is separate and never affects the gate).
    /// </summary>
    public string? FailOnSeverity { get; private set; }

    /// <summary>
    /// The CI gate count set by <c>--fail-on count=&lt;N&gt;</c>: fail when the total
    /// vulnerability finding count exceeds <c>N</c>, or null when not configured.
    /// </summary>
    public int? FailOnCount { get; private set; }

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

    /// <summary>
    /// Apply one repeatable <c>--fail-on &lt;key&gt;=&lt;value&gt;</c> gate rule. Recognises
    /// <c>severity=&lt;critical|high|moderate|low|info&gt;</c> and <c>count=&lt;N&gt;</c>.
    /// A missing <c>=</c>, an unknown key, or an out-of-range value is a usage error
    /// (the first such error wins, routed through the exit-2 path like any other).
    /// </summary>
    private void ApplyFailOn(string spec)
    {
        var separator = spec.IndexOf('=');
        if (separator <= 0 || separator == spec.Length - 1)
        {
            Error ??= $"invalid --fail-on '{spec}': expected <key>=<value> (e.g. severity=high or count=0)";
            return;
        }

        var key = spec[..separator].Trim().ToLowerInvariant();
        var value = spec[(separator + 1)..].Trim();

        switch (key)
        {
            case "severity":
                var level = Models.Severity.ParseLevel(value);
                if (level is null)
                {
                    Error ??= $"invalid --fail-on severity '{value}': use critical, high, moderate, low, or info";
                    return;
                }

                FailOnSeverity = level;
                break;

            case "count":
                if (!int.TryParse(value, out var count) || count < 0)
                {
                    Error ??= $"invalid --fail-on count '{value}': expected a non-negative integer";
                    return;
                }

                FailOnCount = count;
                break;

            default:
                Error ??= $"unknown --fail-on key '{key}': use severity or count";
                break;
        }
    }
}
