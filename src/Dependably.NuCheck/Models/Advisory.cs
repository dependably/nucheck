namespace Dependably.NuCheck.Models;

/// <summary>A single security advisory returned by an advisory source (GitHub or OSV).</summary>
/// <remarks>
/// The first four members are the original shape. <see cref="AdvisoryId"/>,
/// <see cref="Cve"/>, and <see cref="FixedVersion"/> are <b>appended</b> (not reordered)
/// so JSON/positional consumers stay stable; each is null when the source does not
/// supply it (never fabricated).
/// </remarks>
public sealed record Advisory(
    string Summary,
    string Severity,
    string VulnerableVersionRange,
    IReadOnlyList<string> References,
    string? AdvisoryId = null,
    string? Cve = null,
    string? FixedVersion = null);
