# Architecture & internals

`nuget-check` is a small, dependency-injected console app. The flow is:

```
args ──▶ CliOptions.Parse ──▶ PackageFileReader.Read ──▶ AuditService.AuditAsync ──▶ IResultFormatter.Format ──▶ stdout
                                                              │
                                                              ├─ IAdvisorySource.GetAdvisoriesAsync   (GitHubAdvisoryClient)
                                                              └─ VulnerabilityMatcher.IsVulnerable     (NuGet.Versioning)
```

Exit code (Dependably suite convention): `0` clean; `1` when `AuditResult.HasFailures`
(a vulnerability or a policy error); `2` for a usage error (bad/unknown flag, missing
manifest argument) or an operational error (unreadable/unsupported manifest, scan
failure, internal exception). `--help` / `--version` exit `0`.

## Key types (`namespace NuGetCheck`)

### `Cli.CliOptions`
Table-driven argument parser. `Parse(IEnumerable<string>)` returns the options
(`FilePath`, `Format`, `Severity`, `UseRest`, `Verbose`, `ShowHelp`, `ShowVersion`). No growing
if/else chain and no loop-counter mutation, so it stays simple and testable.

### `Services.PackageFileReader`
`Read(string path)` → `IReadOnlyList<PackageRef>`. Dispatches on extension:
- `.json` → `NuGet.ProjectModel.PackagesLockFileFormat` (packages.lock.json)
- otherwise → `NuGet.Packaging.PackagesConfigReader` (packages.config)

Throws `FileNotFoundException` (missing) / `InvalidDataException` (malformed).

### `Services.VulnerabilityMatcher` — the correctness core
`IsVulnerable(NuGetVersion version, string range)` and the underlying
`TranslateRange(string)`:
- Native NuGet interval notation (`[1.0,2.0)`) → `VersionRange.Parse`.
- GitHub comparator syntax (`>= 1.0.0, < 2.0.0`, `= 1.0.0`, `<= 2.3.1`) → built
  into a `VersionRange` with the right inclusive/exclusive bounds.
- Parses versions with `NuGetVersion.Parse`, so 4-part versions like `1.8.3.1`
  work — the cases npm `semver` got wrong.

### `Services.IAdvisorySource` / `GitHubAdvisoryClient`
`GetAdvisoriesAsync(packageId)` → `IReadOnlyList<Advisory>`. The GitHub client
queries the GraphQL `securityVulnerabilities` API (ecosystem `NUGET`) by default,
or the REST advisories API with `--rest`. Severities are normalised to lower case.
A `401` throws (bad/absent `GITHUB_TOKEN`); other non-success responses return an
empty list. The `ParseGraphQl` / `ParseRest` static helpers are pure and unit-tested.

### `Services.AuditService`
`AuditAsync(IReadOnlyList<PackageRef>)` → `AuditResult`. For each package it pulls
advisories from the injected `IAdvisorySource` and keeps only those the matcher
says apply to the installed version. Decoupled from file IO and HTTP, so it's
tested with an in-memory `FakeAdvisorySource`.

### `Models`
- `PackageRef(string Id, NuGetVersion Version)`
- `Advisory(string Summary, string Severity, string VulnerableVersionRange, IReadOnlyList<string> References, string? AdvisoryId = null, string? Cve = null, string? FixedVersion = null)`
  — the last three are appended actionable fields (GHSA id, CVE, first patched version),
  populated from GitHub (`ghsaId` / `identifiers` / `firstPatchedVersion`) and OSV
  (`aliases` / `affected[].ranges[].events[].fixed`); null where the source omits them.
- `PackageVulnerability(string Id, string Version, IReadOnlyList<Advisory> Advisories)`
- `AuditResult { TotalPackages, Vulnerabilities, VulnerabilityCount, VulnerablePackageCount }`
  with `FilterBySeverity(string?)`. `VulnerabilityCount` counts advisories;
  `VulnerablePackageCount` counts distinct packages — every formatter reports both.

- `Severity` (static) — the suite severity ladder `critical > high > moderate > low > info`
  and `Normalize(string?)`, which maps each raw word onto it (`medium`→`moderate`,
  `unknown`/blank/unrecognised→`info`, and the policy word `error`→`high`). Every formatter
  routes severities through it so the suite speaks one language.

### `Output`
`IResultFormatter` with `Summary` (the `human` default), `Table`, and `Json`
implementations, selected by `FormatterFactory.Get(format, toolVersion, target)`
(defaults to the human formatter; the JSON formatter needs the version + target for the
envelope).

`JsonResultFormatter` emits the **shared Dependably finding schema v1** envelope: one JSON
object with the six uniform core keys `tool` / `toolVersion` / `schemaVersion` (`"1.0"`) /
`target` / `summary` / `findings`. `summary` carries `scanned` (packages audited),
`findings` (== `findings.length`), `bySeverity` (the five ladder buckets), and `exitCode`
(the real process exit code). Each `findings[]` entry is the schema Finding shape
(`severity`, `ruleId`, `category`, `message`, `location`, `remediation`, `extra`):
- vulnerabilities → `category: "vulnerability"`, `ruleId` = GHSA (else CVE), `location: null`,
  advisory data under `extra` (`package`, `installedVersion`, `fixedVersion`, `advisoryId`,
  `cve`, `vulnerableRange`, `references`);
- untrusted sources → `category: "policy"` (`extra.host` / `extra.source`);
- heuristic unused packages → `category: "unused"`, always `info`.

## Testing

xUnit + coverlet. HTTP is faked via `FakeHttpMessageHandler`; the advisory source
via `FakeAdvisorySource`. Coverage is emitted as OpenCover (for SonarQube) and
Cobertura (for GitLab) per `coverlet.runsettings`.
