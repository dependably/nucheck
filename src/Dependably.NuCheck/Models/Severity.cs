namespace Dependably.NuCheck.Models;

/// <summary>
/// The single Dependably-suite severity ladder, plus the mapping from each tool's
/// raw vocabulary onto it. The ladder, highest to lowest:
/// <c>critical &gt; high &gt; moderate &gt; low &gt; info</c>.
/// </summary>
/// <remarks>
/// nucheck mapping (per the shared schema v1): keep critical/high/moderate/low;
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

    /// <summary>
    /// Numeric rank for at-or-above comparisons (the CI gate). Higher = more severe:
    /// <c>critical</c>=5, <c>high</c>=4, <c>moderate</c>=3, <c>low</c>=2, <c>info</c>=1.
    /// Expects an already-normalised ladder word; anything else ranks as <c>info</c>.
    /// </summary>
    public static int Rank(string normalized) => normalized switch
    {
        Critical => 5,
        High => 4,
        Moderate => 3,
        Low => 2,
        _ => 1,               // info
    };

    /// <summary>
    /// Parse a gate level for <c>--fail-on severity=&lt;level&gt;</c>. Accepts the five
    /// ladder words (plus <c>medium</c> as an alias for <c>moderate</c>) and returns the
    /// canonical word; returns <c>null</c> for anything else so the caller can raise a
    /// usage error. Unlike <see cref="Normalize"/>, this does NOT swallow a typo into
    /// <c>info</c> — an invalid gate level must be rejected, not silently accepted.
    /// </summary>
    public static string? ParseLevel(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        "critical" => Critical,
        "high" => High,
        "moderate" or "medium" => Moderate,
        "low" => Low,
        "info" => Info,
        _ => null,
    };
}
