# nucheck

A native **.NET global tool** that audits NuGet dependencies for known
vulnerabilities — like `npm audit`, but for the .NET ecosystem.

`nucheck` reads your installed packages (`packages.config`, `packages.lock.json`,
or a `.csproj` / `Directory.Packages.props` using `<PackageReference>` / Central Package
Management), queries the [GitHub Advisory Database](https://github.com/advisories)
for the **NuGet** ecosystem, and reports any package whose installed version falls
within a known vulnerable range.

Unlike a JavaScript port, it uses the real **`NuGet.Versioning`** comparer, so it
correctly handles NuGet's 4-part versions (e.g. `1.8.3.1`) and interval ranges
(e.g. `[1.0,2.0)`) that npm's `semver` cannot represent.

## Features

- **Native .NET** — installs and runs as a `dotnet tool`, no Node required.
- **Correct version matching** via `NuGet.Versioning` (4-part versions, intervals).
- **Authoritative data** from the GitHub Advisory Database (GraphQL by default, REST via `--rest`).
- **Manifest support**: `packages.config` (XML), `packages.lock.json`, and `<Project>`-rooted
  `.csproj` / `.props` carrying `<PackageReference>` / `<PackageVersion>` (Central Package
  Management, including `Directory.Packages.props`). The `.csproj` / `.props` reader is a
  static parse — no MSBuild evaluation (properties, `Condition`s, imports, SDK-implicit
  packages are not expanded) — and version ranges / floating versions are audited at their
  declared **lower bound**, not the version a restore would resolve. For exact resolved
  versions, point the tool at a `packages.lock.json`.
- **Output formats**: `human` (default), `table`, `json`. `--format json` emits the shared
  Dependably finding schema v1 envelope (see [JSON output](#json-output)) so any suite tool's
  JSON parses the same way.
- **Severity filtering**: `--severity critical|high|moderate|low` — a DISPLAY filter that
  narrows what is printed. It is distinct from the CI gate (`--fail-on`) and never changes
  the exit code.
- **Unified CI gate**: `--fail-on <key>=<value>` (repeatable) — the one suite-wide gate
  mechanism. `severity=<level>` fails only on findings at-or-above a level (relax/raise the
  gate); `count=<N>` fails when the vulnerability count exceeds N. See
  [CI gate](#ci-gate--fail-on).
- **Source-trust policy**: flags any configured NuGet package source whose host is not
  public (`api.nuget.org` / `nuget.org`) and not allowlisted in `.dependably-check`.
- **Unused-package check (advisory)**: heuristically detects direct `<PackageReference>`
  packages whose namespace does not appear in `.cs` source files. Never exits non-zero.
  Dev/build/analyzer-only references (`PrivateAssets="all"`, analyzer/build-only
  `Include`/`ExcludeAssets`, and a built-in allowlist of common analyzer/source-generator
  packages) are excluded by default. Further suppressible per-package via
  `ignoreUnusedPackages` in `.dependably-check`.
- **Shared config**: reads the repo-root `.dependably-check` (JSON), discovered by walking
  up the directory tree, or pointed at explicitly with `--config`.
- **Actionable advisories**: each finding carries its discrete advisory id (GHSA), CVE
  (where available), and the **fixed version** to upgrade to — surfaced in `table` and
  `json`, with the fix mentioned in `human`. Populated from both GitHub and OSV.
- **CI-friendly exit codes** (Dependably suite convention): `0` clean · `1` vulnerability
  or policy finding (block) · `2` usage error (bad/unknown flag, missing manifest argument)
  or operational error (unreadable/unsupported manifest, scan failure, internal exception).
  `--help` and `--version` exit `0`.

## Requirements

- .NET SDK 10.0+ (the tool targets `net10.0`).
- An advisory source:
  - **`--source github`** (default): a GitHub personal access token in the `GITHUB_TOKEN`
    environment variable (the GitHub Advisory API requires authentication). Create one at
    <https://github.com/settings/tokens> — no scopes are needed for public advisory data.
  - **`--source osv`**: queries the public [OSV.dev](https://osv.dev) database — **no token required**.

## Installation

**Once published to nuget.org**, install `Dependably.NuCheck` as a global tool
straight from the public feed:

```bash
dotnet tool install --global Dependably.NuCheck
```

**From source (works today)** — build the package locally and install it from a local
feed:

```bash
dotnet pack src/Dependably.NuCheck/Dependably.NuCheck.csproj -c Release -o artifacts
dotnet tool install --global --add-source ./artifacts Dependably.NuCheck
```

Then the `nucheck` command is on your PATH:

```bash
export GITHUB_TOKEN=your_token
nucheck ./packages.config
```

> ### Heads-up: source-trust policy fails the build on private feeds by default
>
> `nucheck` audits the NuGet package sources configured for the audited project and,
> **by default, FAILS (exits non-zero) on any source whose host is not public**
> (`api.nuget.org` / `nuget.org`) and not allowlisted. If your project restores from a
> private, company, GitHub Packages, or Azure Artifacts feed, permit it **before** you
> run by adding its host to `allowedRegistryHosts` in a `.dependably-check` file at your
> repo root:
>
> ```json
> {
>   "common": { "allowedRegistryHosts": ["nuget.mycompany.com"] }
> }
> ```
>
> This is intentional, on-by-default behavior — see
> [Source-trust policy & `.dependably-check`](#source-trust-policy--dependably-check)
> for the full rules.

## Usage

```
nucheck <path-to-packages-file> [options]

Arguments:
  <path-to-packages-file>    Path to packages.config, packages.lock.json, or a
                             .csproj / Directory.Packages.props (PackageReference /
                             Central Package Management). .csproj / .props are parsed
                             statically (no MSBuild evaluation); version ranges &
                             floating versions are audited at their declared LOWER
                             BOUND. For exact resolved versions, use a packages.lock.json.

Options:
  --source <name>            Advisory source: github (default), osv
  --format <type>            Output format: human, table, json (default: human)
  --severity <level>         Filter by severity: critical, high, moderate, low
  --config <path>            Path to a .dependably-check config file (otherwise discovered)
  --fail-on <key>=<value>    CI gate (repeatable): severity=<level> or count=<N>
  --rest                     Use the GitHub REST API instead of GraphQL (github source)
  --verbose, -v              Write progress to stderr
  --help, -h                 Show help
  --version                  Print the tool version and exit

Environment:
  GITHUB_TOKEN               GitHub personal access token (required for the github source)
```

### Source-trust policy & `.dependably-check`

Beyond known vulnerabilities, `nucheck` audits the **NuGet package sources declared
within the repository** — the `nuget.config` files from the audited path up to and
including the repo root. The host machine's user/global NuGet configuration is
intentionally **out of scope** so the verdict is reproducible and machine-independent
(the same repo passes or fails identically on every machine and in CI, and auditing a
stranger's repo never flags your personal feeds). A repo that declares no `nuget.config`
makes no untrusted-source claim and produces no findings. Every enabled `http(s)` source
whose host is neither a built-in public host (`api.nuget.org`, `nuget.org`) nor
explicitly allowlisted is reported as a **policy error**, and the process exits
non-zero. Local folder feeds and disabled sources are ignored.

Allowlist private/internal registries in a repo-root `.dependably-check` file (JSON),
shared across the Dependably checker tools. This tool reads the union of
`common.allowedRegistryHosts` and `nuget.allowedRegistryHosts` (bare hostnames):

```json
{
  "common": { "allowedRegistryHosts": ["dependably.northwardlabs.ca"] },
  "nuget":  { "allowedRegistryHosts": [] }
}
```

The file is discovered by walking up from the current directory (stopping at the repo
root, i.e. a directory containing `.git`), or pointed at explicitly with `--config`.

### Unused-package check

`nucheck` also heuristically scans for `<PackageReference>` entries in `*.csproj`
files (and `Directory.Packages.props`) under the audited file's directory that do not
appear to be referenced in any `.cs` source file. This surfaces potentially dead
dependencies that can be removed to reduce attack surface and build times.

**This check is advisory only — it never causes the process to exit non-zero.** The
heuristic has real false-positive risk: build-tool, analyzer, MSBuild-task, and
`PrivateAssets` packages have no runtime namespace, and packages whose NuGet id differs
from their namespace root will also be flagged erroneously.

To keep the signal trustworthy, references that are *expected* to have no runtime
namespace are excluded by default and never reported:

- references marked as not flowing to consumers via MSBuild asset metadata —
  `PrivateAssets="all"` (attribute or child element), `ExcludeAssets` dropping
  `runtime`/`compile`, or `IncludeAssets` limited to analyzer/build assets; and
- a small built-in allowlist of build/analyzer/source-generator packages that authors
  often add without `PrivateAssets`: ids ending in `.Analyzers` / `.SourceGenerators`,
  `StyleCop.Analyzers`, `Microsoft.CodeAnalysis.Analyzers`,
  `Microsoft.CodeAnalysis.NetAnalyzers`, `Microsoft.NET.Test.Sdk`, `coverlet.collector`,
  `coverlet.msbuild`, `Nullable`, `PolySharp`, `GitVersion.MsBuild`, and
  `Microsoft.SourceLink.*`.

Suppress remaining false positives per-package via `ignoreUnusedPackages` in
`.dependably-check` (union of `common` and `nuget` sections):

```json
{
  "common": { "ignoreUnusedPackages": ["StyleCop.Analyzers", "SonarAnalyzer.CSharp"] },
  "nuget":  { "ignoreUnusedPackages": ["Microsoft.CodeAnalysis.Analyzers"] }
}
```

### Examples

```bash
# Default human-readable output
nucheck ./packages.config

# OSV.dev source — no GITHUB_TOKEN needed
nucheck ./packages.lock.json --source osv

# JSON output (for piping into other tools / CI)
nucheck ./packages.lock.json --format json

# Only high-severity findings, table layout
nucheck ./packages.config --format table --severity high
```

### JSON output

`--format json` writes **one** JSON object to stdout (progress/errors go to stderr),
following the shared **Dependably finding schema v1** so every tool in the suite parses
the same way. The six core keys — `tool`, `toolVersion`, `schemaVersion`, `target`,
`summary`, `findings` — are uniform; tool-specific data lives under each finding's `extra`.

```json
{
  "tool": "nucheck",
  "toolVersion": "1.1.1",
  "schemaVersion": "1.0",
  "target": "packages.config",
  "summary": {
    "scanned": 1,
    "findings": 1,
    "bySeverity": { "critical": 0, "high": 1, "moderate": 0, "low": 0, "info": 0 },
    "exitCode": 1
  },
  "findings": [
    {
      "severity": "high",
      "ruleId": "GHSA-5crp-9r3c-p9vr",
      "category": "vulnerability",
      "message": "GHSA-5crp-9r3c-p9vr: Improper Handling of Exceptional Conditions in Newtonsoft.Json",
      "location": null,
      "remediation": "upgrade to 13.0.1",
      "extra": {
        "package": "Newtonsoft.Json",
        "installedVersion": "11.0.2",
        "fixedVersion": "13.0.1",
        "advisoryId": "GHSA-5crp-9r3c-p9vr",
        "cve": "CVE-2024-21907",
        "vulnerableRange": "< 13.0.1",
        "references": ["https://osv.dev/vulnerability/GHSA-5crp-9r3c-p9vr"]
      }
    }
  ]
}
```

Notes:

- `summary.scanned` = number of packages audited; `summary.findings` always equals
  `findings.length` (the JSON list is never truncated); `summary.exitCode` equals the real
  process exit code (`0`/`1`/`2`).
- `severity` is always one of the suite ladder strings `critical | high | moderate | low | info`.
  nuget mapping: `critical/high/moderate/low` kept, `medium`→`moderate`, `unknown`→`info`.
  These same words are used in the `human` and `table` outputs.
- Finding `category` is `vulnerability` (an advisory), `policy` (an untrusted package source —
  `extra` carries `host`/`source`), or `unused` (a heuristic unused-package finding, always
  `info`). For a vulnerability, `ruleId` is the GHSA id when available (else the CVE);
  `location` is `null` because package findings are not file-scoped.

### CI gate (`--fail-on`)

`--fail-on <key>=<value>` is the single, suite-wide CI gate. It is **repeatable**, and the
process exits `1` if **any** rule trips:

| Rule | Trips when |
| ---- | ---------- |
| `severity=<critical\|high\|moderate\|low\|info>` | a finding's severity is **at-or-above** the level on the suite ladder. A relaxed level (e.g. `severity=high`) ignores moderate/low vulnerabilities **for gating** — they still appear in the output. A policy finding (untrusted source) carries `error` severity, which maps to `high`. |
| `count=<N>` | the total **vulnerability** count exceeds `N` (e.g. `count=0` fails on any vulnerability). |

With **no** `--fail-on`, the default holds: **any** vulnerability or policy error fails the
build (exit `1`). Supplying `--fail-on` **replaces** that default with the union of the
rules you give.

`--fail-on` is the gate; `--severity` is only a display filter. They are independent — a
`--severity` filter narrows what is printed but never changes the exit code, and the JSON
`summary.exitCode` always equals the real process exit code.

```bash
# Only fail the build on high/critical vulnerabilities (ignore moderate/low for gating)
nucheck ./packages.lock.json --fail-on severity=high

# Tolerate up to 3 known vulnerabilities before failing
nucheck ./packages.lock.json --fail-on count=3

# Combine: fail on any critical, OR on more than 5 findings total
nucheck ./packages.lock.json --fail-on severity=critical --fail-on count=5
```

Exit codes wire straight into a CI gate:

| Code | Meaning |
| ---- | ------- |
| `0`  | Clean — no gating findings (also `--help` / `--version`). |
| `1`  | A gating finding (a vulnerability or policy error by default, or whatever `--fail-on` selects) — block the build. |
| `2`  | Usage error (bad/unknown flag, bad `--fail-on` value, missing manifest argument) or operational error (unreadable/unsupported manifest, scan failure, internal exception). |

## Building from source

```bash
git clone https://github.com/dependably/nucheck.git
cd nucheck
dotnet build Dependably.NuCheck.slnx -c Release
dotnet test  Dependably.NuCheck.slnx -c Release        # run the xUnit suite
dotnet run --project src/Dependably.NuCheck -- ./examples/packages.config
```

Pack the tool locally:

```bash
dotnet pack src/Dependably.NuCheck/Dependably.NuCheck.csproj -c Release -o artifacts
dotnet tool install --global --add-source ./artifacts Dependably.NuCheck
```

## Project layout

```
src/Dependably.NuCheck/        # the tool
  Program.cs           # CLI entry point + orchestration
  Cli/CliOptions.cs    # argument parsing
  Services/            # PackageFileReader, GitHubAdvisoryClient, VulnerabilityMatcher, AuditService
  Output/              # human / table / json formatters
  Models/              # PackageRef, Advisory, AuditResult, Severity (the suite ladder)
tests/Dependably.NuCheck.Tests # xUnit tests (fakes for HttpClient + advisory source)
```

See [docs/API.md](docs/API.md) for the internal architecture and the key types.

## License

Apache-2.0 — see [LICENSE](LICENSE).
