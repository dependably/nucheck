namespace NuGetCheck.Models;

/// <summary>A single security advisory returned by the GitHub Advisory Database.</summary>
public sealed record Advisory(
    string Summary,
    string Severity,
    string VulnerableVersionRange,
    IReadOnlyList<string> References);
