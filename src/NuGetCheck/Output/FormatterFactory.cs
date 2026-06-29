namespace NuGetCheck.Output;

/// <summary>
/// Selects an <see cref="IResultFormatter"/> by token. <c>human</c> (the default) and
/// <c>json</c> are the suite-standard tokens; <c>table</c> is kept as an extra option.
/// The JSON formatter needs the tool version and the scanned target for the shared envelope.
/// </summary>
public static class FormatterFactory
{
    public static IResultFormatter Get(string? format, string toolVersion, string target) =>
        format?.ToLowerInvariant() switch
        {
            "json" => new JsonResultFormatter(toolVersion, target),
            "table" => new TableResultFormatter(),
            _ => new SummaryResultFormatter(),
        };
}
