using Dependably.NuCheck.Config;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Services;

/// <summary>
/// Applies the resolved <c>.dependably</c> exceptions to nucheck's findings: suppresses
/// matched vulnerability advisories, unused-package findings, and unverifiable-advisory
/// findings so they no longer gate the run (spec §6). Suppressed findings are removed from
/// the gating result; unused and expired exceptions are reported so they don't rot.
/// </summary>
public static class ExceptionApplier
{
    public sealed record Result(
        IReadOnlyList<PackageVulnerability> Vulnerabilities,
        IReadOnlyList<UnusedPackageFinding> UnusedPackages,
        IReadOnlyList<UnverifiableAdvisoryFinding> UnverifiableAdvisories,
        IReadOnlyList<PinnedVersionFinding> PinnedVersionFindings,
        IReadOnlyList<string> Notices);

    public static Result Apply(
        IReadOnlyList<PackageVulnerability> vulnerabilities,
        IReadOnlyList<UnusedPackageFinding> unusedPackages,
        IReadOnlyList<UnverifiableAdvisoryFinding> unverifiableAdvisories,
        IReadOnlyList<DependablyException> exceptions,
        DateOnly? todayOverride = null,
        IReadOnlyList<PinnedVersionFinding>? pinnedVersionFindings = null)
    {
        pinnedVersionFindings ??= [];
        if (exceptions.Count == 0)
        {
            return new Result(vulnerabilities, unusedPackages, unverifiableAdvisories, pinnedVersionFindings, []);
        }

        var today = todayOverride ?? DateOnly.FromDateTime(DateTime.UtcNow);
        var live = exceptions.Where(e => !DependablyExceptions.IsExpired(e, today)).ToList();
        var expired = exceptions.Where(e => DependablyExceptions.IsExpired(e, today)).ToList();
        var used = new HashSet<DependablyException>();
        var suppressed = 0;

        var keptVulns = new List<PackageVulnerability>();
        foreach (var pv in vulnerabilities)
        {
            var keptAdvisories = new List<Advisory>();
            foreach (var advisory in pv.Advisories)
            {
                var target = new ExceptionTarget("vulnerable-package", Package: pv.Id, Version: pv.Version, Id: advisory.AdvisoryId);
                var hit = live.FirstOrDefault(e => DependablyExceptions.Matches(e, target));
                if (hit is not null)
                {
                    used.Add(hit);
                    suppressed++;
                }
                else
                {
                    keptAdvisories.Add(advisory);
                }
            }

            if (keptAdvisories.Count > 0)
            {
                keptVulns.Add(pv with { Advisories = keptAdvisories });
            }
        }

        var keptUnused = Filter(unusedPackages, live, used, ref suppressed,
            f => new ExceptionTarget("unused-packages", Package: f.Id));
        var keptUnverifiable = Filter(unverifiableAdvisories, live, used, ref suppressed,
            f => new ExceptionTarget("unverifiable-advisory", Package: f.PackageId, Id: f.AdvisoryId));
        var keptPinned = Filter(pinnedVersionFindings, live, used, ref suppressed,
            f => new ExceptionTarget("pinned-versions", Package: f.Id, Version: f.RawVersion));

        var notices = new List<string>();
        if (suppressed > 0)
        {
            notices.Add($"{suppressed} finding(s) suppressed by exceptions");
        }

        foreach (var ex in live.Where(e => !used.Contains(e)))
        {
            notices.Add($"unused exception for rule \"{ex.Rule}\" — {ex.Reason}");
        }

        foreach (var ex in expired)
        {
            notices.Add($"exception expired {ex.Expires:yyyy-MM-dd} for rule \"{ex.Rule}\" — {ex.Reason}");
        }

        return new Result(keptVulns, keptUnused, keptUnverifiable, keptPinned, notices);
    }

    private static List<T> Filter<T>(
        IReadOnlyList<T> findings,
        List<DependablyException> live,
        HashSet<DependablyException> used,
        ref int suppressed,
        Func<T, ExceptionTarget> toTarget)
    {
        var kept = new List<T>();
        foreach (var finding in findings)
        {
            var hit = live.FirstOrDefault(e => DependablyExceptions.Matches(e, toTarget(finding)));
            if (hit is not null)
            {
                used.Add(hit);
                suppressed++;
            }
            else
            {
                kept.Add(finding);
            }
        }

        return kept;
    }
}
