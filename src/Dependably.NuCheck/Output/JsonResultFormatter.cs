using System.Text.Json;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Output;

/// <summary>
/// Emits the shared Dependably finding JSON schema v1 envelope (one object on stdout).
/// The six core keys (<c>tool/toolVersion/schemaVersion/target/summary/findings</c>) are
/// uniform across the suite; vulnerability/policy/unused details live under each finding's
/// <c>extra</c>. <c>findings</c> is the complete list — never truncated.
/// </summary>
public sealed class JsonResultFormatter : IResultFormatter
{
    private const string ToolName = "nucheck";
    private const string SchemaVersion = "1.0";

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private readonly string _toolVersion;
    private readonly string _target;
    private readonly int? _exitCode;

    /// <param name="exitCode">
    /// The real process exit code to embed in <c>summary.exitCode</c>. When null (the
    /// default), it is derived from <see cref="AuditResult.HasFailures"/> — but the CI gate
    /// can diverge from that (a relaxed <c>--fail-on severity</c>, or a <c>--severity</c>
    /// display filter), so <see cref="Program"/> passes the gate's decision explicitly to
    /// keep <c>summary.exitCode</c> equal to the actual exit code.
    /// </param>
    public JsonResultFormatter(string toolVersion, string target, int? exitCode = null)
    {
        _toolVersion = toolVersion;
        _target = target;
        _exitCode = exitCode;
    }

    public string Format(AuditResult result)
    {
        var findings = new List<(string Severity, object Finding)>();

        // Vulnerability findings — one per advisory, advisory data under `extra`.
        foreach (var package in result.Vulnerabilities)
        {
            foreach (var advisory in package.Advisories)
            {
                var severity = Severity.Normalize(advisory.Severity);
                findings.Add((severity, new
                {
                    severity,
                    // ruleId = the advisory id (GHSA) when available, else the CVE, else a stable id.
                    ruleId = advisory.AdvisoryId ?? advisory.Cve ?? "nuget-vulnerability",
                    category = "vulnerability",
                    message = advisory.Summary,           // the advisory title
                    location = (object?)null,             // package vulns are not file-scoped
                    remediation = string.IsNullOrEmpty(advisory.FixedVersion)
                        ? null
                        : $"upgrade to {advisory.FixedVersion}",
                    extra = new
                    {
                        package = package.Id,
                        installedVersion = package.Version,
                        fixedVersion = advisory.FixedVersion,
                        advisoryId = advisory.AdvisoryId,
                        cve = advisory.Cve,
                        vulnerableRange = advisory.VulnerableVersionRange,
                        references = advisory.References,
                    },
                }));
            }
        }

        // Source-trust POLICY findings (untrusted package source).
        foreach (var finding in result.PolicyFindings)
        {
            var severity = Severity.Normalize(finding.Severity);
            findings.Add((severity, new
            {
                severity,
                ruleId = "untrusted-source",
                category = "policy",
                message = finding.Message,
                location = (object?)null,
                remediation = (string?)null,
                extra = new
                {
                    host = finding.Host,
                    source = finding.Source,
                },
            }));
        }

        // Unused-package findings (heuristic, advisory only — always `info`).
        foreach (var unused in result.UnusedPackages)
        {
            findings.Add((Severity.Info, new
            {
                severity = Severity.Info,
                ruleId = "unused-package",
                category = "unused",
                message = unused.Message,
                location = (object?)null,
                remediation = (string?)null,
                extra = new
                {
                    package = unused.Id,
                },
            }));
        }

        // The JSON is only emitted on the success path. Program passes the gate's real exit
        // code; when absent we fall back to the default rule (1 on any vuln or policy error).
        var exitCode = _exitCode ?? (result.HasFailures ? 1 : 0);

        var envelope = new
        {
            tool = ToolName,
            toolVersion = _toolVersion,
            schemaVersion = SchemaVersion,
            target = _target,
            summary = new
            {
                scanned = result.TotalPackages,
                findings = findings.Count,
                bySeverity = new
                {
                    critical = findings.Count(f => f.Severity == Severity.Critical),
                    high = findings.Count(f => f.Severity == Severity.High),
                    moderate = findings.Count(f => f.Severity == Severity.Moderate),
                    low = findings.Count(f => f.Severity == Severity.Low),
                    info = findings.Count(f => f.Severity == Severity.Info),
                },
                exitCode,
            },
            findings = findings.Select(f => f.Finding),
        };

        return JsonSerializer.Serialize(envelope, Options);
    }
}
