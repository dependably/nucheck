namespace NuGetCheck.Output;

/// <summary>Selects an <see cref="IResultFormatter"/> by name (defaults to summary).</summary>
public static class FormatterFactory
{
    public static IResultFormatter Get(string? format) => (format?.ToLowerInvariant()) switch
    {
        "json" => new JsonResultFormatter(),
        "table" => new TableResultFormatter(),
        _ => new SummaryResultFormatter(),
    };
}
