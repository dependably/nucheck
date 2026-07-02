namespace Dependably.NuCheck.Output;

/// <summary>
/// Selects an <see cref="IResultFormatter"/> by token. <c>human</c> (the default) and
/// <c>json</c> are the suite-standard tokens; <c>table</c> is kept as an extra option.
/// The JSON formatter needs the tool version and the scanned target for the shared envelope.
/// </summary>
public static class FormatterFactory
{
    /// <param name="severityFilter">
    /// The active <c>--severity</c> display filter (a normalised ladder word), or
    /// <c>null</c> when no display filter is in effect. Passed to text formatters so
    /// they can suppress the misleading "all secure" checkmark when the filter removed
    /// advisories from the displayed result.
    /// </param>
    public static IResultFormatter Get(
        string? format,
        string toolVersion,
        string target,
        int? exitCode = null,
        string? severityFilter = null) =>
        format?.Trim().ToLowerInvariant() switch
        {
            "json" => new JsonResultFormatter(toolVersion, target, exitCode),
            "table" => new TableResultFormatter(severityFilter),
            _ => new SummaryResultFormatter(severityFilter),
        };
}
