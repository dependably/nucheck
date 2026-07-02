using System.Text;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Output;

/// <summary>Formats the result as a brief human-readable summary.</summary>
public sealed class SummaryResultFormatter : IResultFormatter
{
    private readonly string? _severityFilter;

    /// <param name="severityFilter">
    /// The active <c>--severity</c> display filter (a normalised ladder word), or
    /// <c>null</c> when no filter is in effect. When set, the "all secure" message
    /// is replaced with an accurate qualified message so it cannot contradict the
    /// process exit code when other-severity advisories caused the gate to trip.
    /// </param>
    public SummaryResultFormatter(string? severityFilter = null)
    {
        _severityFilter = severityFilter;
    }

    public string Format(AuditResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"Found {result.TotalPackages} packages in audit.");

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
        AppendUnusedPackages(builder, result);
        AppendUnverifiableAdvisories(builder, result);
        return builder.ToString();
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

        // No filter, but policy errors tripped the gate: suppress the checkmark — the
        // POLICY FINDINGS block below already covers that failing state.
        if (result.PolicyErrorCount > 0)
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

    private static void AppendUnusedPackages(StringBuilder builder, AuditResult result)
    {
        if (result.UnusedPackages.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine($"ℹ Possibly unused packages (heuristic) — {result.UnusedPackages.Count} finding(s):");
        foreach (var finding in result.UnusedPackages)
        {
            builder.AppendLine($"  • {TextSanitizer.Sanitize(finding.Message)}");
        }
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
