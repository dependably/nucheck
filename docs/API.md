# Architecture & internals

`nuget-check` is a small, dependency-injected console app. The flow is:

```
args ──▶ CliOptions.Parse ──▶ PackageFileReader.Read ──▶ AuditService.AuditAsync ──▶ IResultFormatter.Format ──▶ stdout
                                                              │
                                                              ├─ IAdvisorySource.GetAdvisoriesAsync   (GitHubAdvisoryClient)
                                                              └─ VulnerabilityMatcher.IsVulnerable     (NuGet.Versioning)
```

Exit code: `1` if `AuditResult.VulnerabilityCount > 0` or an error is thrown, else `0`.

## Key types (`namespace NuGetCheck`)

### `Cli.CliOptions`
Table-driven argument parser. `Parse(IEnumerable<string>)` returns the options
(`FilePath`, `Format`, `Severity`, `UseRest`, `Verbose`, `ShowHelp`). No growing
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
- `Advisory(string Summary, string Severity, string VulnerableVersionRange, IReadOnlyList<string> References)`
- `PackageVulnerability(string Id, string Version, IReadOnlyList<Advisory> Advisories)`
- `AuditResult { TotalPackages, Vulnerabilities, VulnerabilityCount }` with
  `FilterBySeverity(string?)`.

### `Output`
`IResultFormatter` with `Summary`/`Table`/`Json` implementations, selected by
`FormatterFactory.Get(format)` (defaults to summary).

## Testing

xUnit + coverlet. HTTP is faked via `FakeHttpMessageHandler`; the advisory source
via `FakeAdvisorySource`. Coverage is emitted as OpenCover (for SonarQube) and
Cobertura (for GitLab) per `coverlet.runsettings`.
