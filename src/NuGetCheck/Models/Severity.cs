namespace NuGetCheck.Models;

/// <summary>
/// The single Dependably-suite severity ladder, plus the mapping from each tool's
/// raw vocabulary onto it. The ladder, highest to lowest:
/// <c>critical &gt; high &gt; moderate &gt; low &gt; info</c>.
/// </summary>
/// <remarks>
/// nuget-check mapping (per the shared schema v1): keep critical/high/moderate/low;
/// normalise <c>medium</c>→<c>moderate</c>; <c>unknown</c> (or anything unrecognised)
/// →<c>info</c>. Source-trust policy findings carry severity <c>error</c>, which maps to
/// <c>high</c> (their nature). Used by every formatter so the suite speaks one language.
/// </remarks>
public static class Severity
{
    public const string Critical = "critical";
    public const string High = "high";
    public const string Moderate = "moderate";
    public const string Low = "low";
    public const string Info = "info";

    /// <summary>Map a raw severity word onto the ladder. Null/blank/unknown → <c>info</c>.</summary>
    public static string Normalize(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        "critical" => Critical,
        "high" => High,
        "moderate" or "medium" => Moderate,
        "low" => Low,
        "error" => High,      // source-trust policy findings
        "warning" => Low,
        _ => Info,            // "unknown", null, blank, or anything unrecognised
    };
}
