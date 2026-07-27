using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Tests;

public class SeverityTests
{
    [Theory]
    [InlineData("critical", "critical")]
    [InlineData("high", "high")]
    [InlineData("moderate", "moderate")]
    [InlineData("medium", "moderate")]   // normalised onto the ladder
    [InlineData("low", "low")]
    [InlineData("unknown", "info")]
    [InlineData("error", "high")]        // source-trust policy findings
    [InlineData("warning", "moderate")]  // spec §4.2 alias
    [InlineData("warn", "moderate")]     // spec §4.2 alias
    [InlineData("HIGH", "high")]          // case-insensitive
    [InlineData("  moderate ", "moderate")] // trimmed
    [InlineData("", "info")]
    [InlineData(null, "info")]
    [InlineData("totally-bogus", "info")]
    public void Normalize_maps_onto_the_ladder(string? raw, string expected)
    {
        Assert.Equal(expected, Severity.Normalize(raw));
    }

    [Fact]
    public void Rank_orders_the_ladder_highest_to_lowest()
    {
        Assert.True(Severity.Rank(Severity.Critical) > Severity.Rank(Severity.High));
        Assert.True(Severity.Rank(Severity.High) > Severity.Rank(Severity.Moderate));
        Assert.True(Severity.Rank(Severity.Moderate) > Severity.Rank(Severity.Low));
        Assert.True(Severity.Rank(Severity.Low) > Severity.Rank(Severity.Info));
    }

    [Theory]
    [InlineData("critical", "critical")]
    [InlineData("high", "high")]
    [InlineData("moderate", "moderate")]
    [InlineData("medium", "moderate")]   // alias
    [InlineData("low", "low")]
    [InlineData("info", "info")]
    [InlineData("error", "high")]        // spec §4.2 alias
    [InlineData("warning", "moderate")]  // spec §4.2 alias
    [InlineData("warn", "moderate")]     // spec §4.2 alias
    [InlineData("HIGH", "high")]          // case-insensitive
    [InlineData(" high ", "high")]        // trimmed
    public void ParseLevel_accepts_ladder_words(string raw, string expected)
    {
        Assert.Equal(expected, Severity.ParseLevel(raw));
    }

    [Theory]
    [InlineData("bogus")]
    [InlineData("")]
    [InlineData(null)]
    public void ParseLevel_rejects_non_ladder_words(string? raw)
    {
        Assert.Null(Severity.ParseLevel(raw));
    }
}
