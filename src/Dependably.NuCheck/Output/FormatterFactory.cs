namespace Dependably.NuCheck.Output;

/// <summary>
/// Selects an <see cref="IResultFormatter"/> by token. <c>human</c> (the default) and
/// <c>json</c> are the suite-standard tokens; <c>table</c> is kept as an extra option.
/// The JSON formatter needs the tool version and the scanned target for the shared envelope.
/// </summary>
public static class FormatterFactory
{
    /// <summary>The set of format tokens recognised by the factory.</summary>
    internal static readonly string[] ValidFormats = ["human", "table", "json"];

    /// <param name="severityFilter">
    /// The active <c>--severity</c> display filter (a normalised ladder word), or
    /// <c>null</c> when no display filter is in effect. Passed to text formatters so
    /// they can suppress the misleading "all secure" checkmark when the filter removed
    /// advisories from the displayed result.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="format"/> is not one of the recognised tokens
    /// (<c>human</c>, <c>table</c>, <c>json</c>). In production, <see cref="CliOptions"/>
    /// rejects unknown tokens before this is called; the exception is a defensive API guard.
    /// </exception>
    /// <param name="advisorySource">
    /// The advisory database label (e.g. <c>OSV.dev</c>) echoed by the text formatters so a
    /// clean result names the source it was checked against. Optional.
    /// </param>
    public static IResultFormatter Get(
        string? format,
        string toolVersion,
        string target,
        int? exitCode = null,
        string? severityFilter = null,
        string? advisorySource = null) =>
        format?.Trim().ToLowerInvariant() switch
        {
            "json" => new JsonResultFormatter(toolVersion, target, exitCode),
            "table" => new TableResultFormatter(severityFilter, exitCode ?? 0, target, advisorySource),
            "human" or null => new SummaryResultFormatter(severityFilter, exitCode ?? 0, target, advisorySource),
            _ => throw new ArgumentException(
                $"Unknown --format '{format}': use {string.Join(", ", ValidFormats)}."),
        };
}
