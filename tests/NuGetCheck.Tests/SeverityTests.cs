using NuGetCheck.Models;

namespace NuGetCheck.Tests;

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
    [InlineData("HIGH", "high")]          // case-insensitive
    [InlineData("  moderate ", "moderate")] // trimmed
    [InlineData("", "info")]
    [InlineData(null, "info")]
    [InlineData("totally-bogus", "info")]
    public void Normalize_maps_onto_the_ladder(string? raw, string expected)
    {
        Assert.Equal(expected, Severity.Normalize(raw));
    }
}
