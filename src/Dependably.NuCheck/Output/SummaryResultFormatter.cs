using System.Text;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Output;

/// <summary>Formats the result as a brief human-readable summary.</summary>
public sealed class SummaryResultFormatter : IResultFormatter
{
    private readonly string? _severityFilter;
    private readonly int _exitCode;
    private readonly string? _manifestName;
    private readonly string? _advisorySource;

    /// <param name="severityFilter">
    /// The active <c>--severity</c> display filter (a normalised ladder word), or
    /// <c>null</c> when no filter is in effect. When set, the "all secure" message
    /// is replaced with an accurate qualified message so it cannot contradict the
    /// process exit code when other-severity advisories caused the gate to trip.
    /// </param>
    /// <param name="exitCode">
    /// The real process exit code the gate produced. The "all secure" checkmark is
    /// only printed when this is <c>0</c>, so the summary can never claim success
    /// beside a non-zero exit (e.g. an <c>info</c>-severity policy finding that a
    /// <c>--fail-on severity=info</c> rule gated).
    /// </param>
    /// <param name="target">
    /// The audited manifest path; its file name is echoed in the summary line so a clean
    /// result names what was audited (e.g. <c>packages.lock.json</c>). Optional.
    /// </param>
    /// <param name="advisorySource">
    /// The advisory database label (e.g. <c>OSV.dev</c>) echoed in the summary line so the
    /// "all secure" result is verifiable — it names the source it was checked against. Optional.
    /// </param>
    public SummaryResultFormatter(
        string? severityFilter = null,
        int exitCode = 0,
        string? target = null,
        string? advisorySource = null)
    {
        _severityFilter = severityFilter;
        _exitCode = exitCode;
        _manifestName = string.IsNullOrEmpty(target) ? null : Path.GetFileName(target);
        _advisorySource = string.IsNullOrEmpty(advisorySource) ? null : advisorySource;
    }

    public string Format(AuditResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine(AuditedLine(result.TotalPackages));

        if (result.VulnerabilityCount == 0)
        {
            AppendNoVulnerabilities(builder, result);
        }
        else
        {
            // Report BOTH counts so this headline cannot contradict the table/json formats,
            // which count advisories: one package can carry several advisories.
            builder.AppendLine(
                $"⚠ Found {result.VulnerablePackageCount} vulnerable package(s), " +
                $"{result.VulnerabilityCount} advisory(ies):");
            builder.AppendLine();

            foreach (var vulnerability in result.Vulnerabilities)
            {
                builder.AppendLine($"  • {vulnerability.Id} ({vulnerability.Version})");
                var severities = string.Join(", ", vulnerability.Advisories.Select(a => Severity.Normalize(a.Severity)));
                builder.AppendLine($"    Issues: {vulnerability.Advisories.Count} | Severity: {severities}");

                var fixes = vulnerability.Advisories
                    .Select(a => a.FixedVersion)
                    .Where(v => !string.IsNullOrEmpty(v))
                    .Distinct()
                    .ToList();
                if (fixes.Count > 0)
                {
                    builder.AppendLine($"    Fixed in: {string.Join(", ", fixes.Select(TextSanitizer.Sanitize))}");
                }
            }
        }

        AppendPolicyFindings(builder, result);
        AppendPinnedVersionFindings(builder, result);
        AppendUnusedPackages(builder, result);
        AppendUnverifiableAdvisories(builder, result);
        return builder.ToString();
    }

    /// <summary>
    /// The opening line: how many packages were audited, and — when known — the manifest that
    /// was read and the advisory source it was checked against, so a clean result is verifiable
    /// (e.g. <c>Audited 72 packages (packages.lock.json) against OSV.dev.</c>).
    /// </summary>
    private string AuditedLine(int totalPackages)
    {
        var manifest = _manifestName is null
            ? string.Empty
            : $" ({TextSanitizer.Sanitize(_manifestName)})";
        var source = _advisorySource is null
            ? string.Empty
            : $" against {TextSanitizer.Sanitize(_advisorySource)}";
        return $"Audited {totalPackages} packages{manifest}{source}.";
    }

    /// <summary>
    /// Emit the appropriate "no advisory" line when the vulnerability count is zero.
    /// When a severity filter is active the all-secure message is replaced with a
    /// qualified note so it cannot contradict a non-zero process exit code caused by
    /// advisories at other severities. When policy errors are present the checkmark is
    /// suppressed entirely — the POLICY FINDINGS block below already covers that state.
    /// </summary>
    private void AppendNoVulnerabilities(StringBuilder builder, AuditResult result)
    {
        // A --severity filter hid real advisories: report the exact hidden count so the
        // output cannot read "all secure" beside a non-zero exit.
        if (result.HiddenAdvisoryCount > 0)
        {
            builder.AppendLine(
                $"0 advisories at or above {result.DisplaySeverityFilter} shown; " +
                $"{result.HiddenAdvisoryCount} advisory(ies) hidden by --severity {result.DisplaySeverityFilter}.");
            return;
        }

        // Filter active but nothing was hidden (no advisories at all): still qualify.
        if (_severityFilter is not null)
        {
            builder.AppendLine($"No advisories matching severity '{_severityFilter}' (others may exist — see exit code)");
            return;
        }

        // The all-clear checkmark is only honest when the process is exiting 0 and there
        // are no policy/pinned findings to show below. A non-zero exit (e.g. an
        // info-severity parent-config notice gated by --fail-on severity=info) or any such
        // finding must suppress it so the summary never contradicts the exit code.
        if (_exitCode != 0 || result.PolicyFindings.Count > 0 || result.PinnedVersionFindings.Count > 0)
        {
            return;
        }

        builder.AppendLine("✓ All packages are secure - no known vulnerabilities found.");
    }

    private static void AppendPolicyFindings(StringBuilder builder, AuditResult result)
    {
        if (result.PolicyFindings.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"⚠ Found {result.PolicyFindings.Count} policy finding(s):");
        foreach (var finding in result.PolicyFindings)
        {
            builder.AppendLine($"  • [{Severity.Normalize(finding.Severity)}] {TextSanitizer.Sanitize(finding.Message)}");
        }
    }

    private static void AppendPinnedVersionFindings(StringBuilder builder, AuditResult result)
    {
        if (result.PinnedVersionFindings.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"⚠ Found {result.PinnedVersionFindings.Count} unpinned package version(s):");
        foreach (var finding in result.PinnedVersionFindings)
        {
            builder.AppendLine($"  • [{Severity.Normalize(finding.Severity)}] {TextSanitizer.Sanitize(finding.Message)}");
        }
    }

    private static void AppendUnusedPackages(StringBuilder builder, AuditResult result)
    {
        var count = result.UnusedPackages.Count;
        if (count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"ℹ Possibly unused packages (heuristic) — {count} {(count == 1 ? "finding" : "findings")}:");

        // Each line carries only the variable data (id, installed version, declaring project);
        // the repeated heuristic caveat is printed ONCE below as a section footer.
        foreach (var finding in result.UnusedPackages)
        {
            builder.AppendLine($"  • {UnusedPackageText.Label(finding)} — not referenced in any .cs file");
        }

        builder.AppendLine();
        builder.AppendLine($"  {TextSanitizer.Sanitize(UnusedPackageService.HeuristicCaveat)}");
        builder.AppendLine("  Advisory only — does not affect the exit code.");
    }

    private static void AppendUnverifiableAdvisories(StringBuilder builder, AuditResult result)
    {
        if (result.UnverifiableAdvisories.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"⚠ {result.UnverifiableAdvisories.Count} unverifiable advisory range(s) — range could not be parsed, investigate manually:");
        foreach (var finding in result.UnverifiableAdvisories)
        {
            var id = string.IsNullOrEmpty(finding.AdvisoryId) ? string.Empty : $" [{TextSanitizer.Sanitize(finding.AdvisoryId)}]";
            var sev = string.IsNullOrEmpty(finding.AdvisorySeverity) ? string.Empty : $" [{Severity.Normalize(finding.AdvisorySeverity)}]";
            builder.AppendLine($"  • {TextSanitizer.Sanitize(finding.PackageId)}{id}{sev}: {TextSanitizer.Sanitize(finding.VulnerableVersionRange)}");
        }
    }
}
