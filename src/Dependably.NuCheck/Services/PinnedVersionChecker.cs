using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// The cross-tool <c>pinned-versions</c> rule: every declared package version must be an
/// exact pin. Error by default (gates the run — suite parity with npm-check / pycheck);
/// the <c>.dependably</c> <c>rules</c> map or <c>--rule pinned-versions:&lt;severity&gt;</c>
/// downgrades findings to warnings (reported, never gate) or turns the check off. Lock
/// files are inherently exact, so the rule is a no-op for a <c>packages.lock.json</c>.
/// </summary>
public static class PinnedVersionChecker
{
    /// <summary>The rule id, as registered in the shared <c>.dependably</c> rule registry.</summary>
    public const string RuleId = "pinned-versions";

    /// <summary>The built-in default severity (spec §4.1: error gates the run).</summary>
    public const string DefaultSeverity = "error";

    /// <summary>
    /// Check the manifest's declared versions at the given rule severity
    /// (<c>error</c> / <c>warn</c> / <c>off</c>). Returns no findings when the severity is
    /// <c>off</c> or the rule is not applicable (a lock file).
    /// </summary>
    public static IReadOnlyList<PinnedVersionFinding> Check(string filePath, string severity)
    {
        if (severity.Equals("off", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        var declarations = PackageFileReader.TryReadDeclarations(filePath);
        if (declarations is null)
        {
            return [];
        }

        // The finding severity vocabulary matches SourceFinding ("error"/"warning") so the
        // shared ladder maps it: error → high, warning → low.
        var findingSeverity = severity.Equals("warn", StringComparison.OrdinalIgnoreCase) ? "warning" : "error";

        return declarations
            .Where(d => !d.IsExact)
            .Select(d => new PinnedVersionFinding(
                d.Id,
                d.RawVersion,
                d.Source,
                Message(d),
                findingSeverity))
            .ToList();
    }

    private static string Message(PackageDeclaration declaration) => declaration.RawVersion is null
        ? $"'{declaration.Id}' has no declared version ({declaration.Source}) — pin an exact version, "
          + "or set nucheck.rules[\"pinned-versions\"] in .dependably"
        : $"'{declaration.Id}' is not pinned to an exact version: '{declaration.RawVersion}' ({declaration.Source}) — "
          + "pin an exact version, or set nucheck.rules[\"pinned-versions\"] in .dependably";
}
