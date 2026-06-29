# nuget-check

A native **.NET global tool** that audits NuGet dependencies for known
vulnerabilities — like `npm audit`, but for the .NET ecosystem.

`nuget-check` reads your installed packages (`packages.config`, `packages.lock.json`,
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
- **Output formats**: `summary` (default), `table`, `json`.
- **Severity filtering**: `--severity critical|high|moderate|low`.
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
- **CI-friendly**: exits `1` when any vulnerability OR any policy error is found, `0` otherwise.

## Requirements

- .NET SDK 10.0+ (the tool targets `net10.0`).
- An advisory source:
  - **`--source github`** (default): a GitHub personal access token in the `GITHUB_TOKEN`
    environment variable (the GitHub Advisory API requires authentication). Create one at
    <https://github.com/settings/tokens> — no scopes are needed for public advisory data.
  - **`--source osv`**: queries the public [OSV.dev](https://osv.dev) database — **no token required**.

## Installation

**Once published to nuget.org**, install `Dependably.NuGetCheck` as a global tool
straight from the public feed:

```bash
dotnet tool install --global Dependably.NuGetCheck
```

**From source (works today)** — build the package locally and install it from a local
feed:

```bash
dotnet pack src/NuGetCheck/NuGetCheck.csproj -c Release -o artifacts
dotnet tool install --global --add-source ./artifacts Dependably.NuGetCheck
```

Then the `nuget-check` command is on your PATH:

```bash
export GITHUB_TOKEN=your_token
nuget-check ./packages.config
```

> ### Heads-up: source-trust policy fails the build on private feeds by default
>
> `nuget-check` audits the NuGet package sources configured for the audited project and,
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
nuget-check <path-to-packages-file> [options]

Arguments:
  <path-to-packages-file>    Path to packages.config, packages.lock.json, or a
                             .csproj / Directory.Packages.props (PackageReference /
                             Central Package Management). .csproj / .props are parsed
                             statically (no MSBuild evaluation); version ranges &
                             floating versions are audited at their declared LOWER
                             BOUND. For exact resolved versions, use a packages.lock.json.

Options:
  --source <name>            Advisory source: github (default), osv
  --format <type>            Output format: summary, table, json (default: summary)
  --severity <level>         Filter by severity: critical, high, moderate, low
  --config <path>            Path to a .dependably-check config file (otherwise discovered)
  --rest                     Use the GitHub REST API instead of GraphQL (github source)
  --verbose, -v              Write progress to stderr
  --help, -h                 Show help

Environment:
  GITHUB_TOKEN               GitHub personal access token (required for the github source)
```

### Source-trust policy & `.dependably-check`

Beyond known vulnerabilities, `nuget-check` audits the **NuGet package sources declared
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

`nuget-check` also heuristically scans for `<PackageReference>` entries in `*.csproj`
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
# Default summary
nuget-check ./packages.config

# OSV.dev source — no GITHUB_TOKEN needed
nuget-check ./packages.lock.json --source osv

# JSON output (for piping into other tools / CI)
nuget-check ./packages.lock.json --format json

# Only high-severity findings, table layout
nuget-check ./packages.config --format table --severity high
```

Exit code is `1` when vulnerabilities are found (or on error) and `0` when the
project is clean — wire it straight into a CI gate.

## Building from source

```bash
git clone https://github.com/dependably/nuget-check.git
cd nuget-check
dotnet build NuGetCheck.slnx -c Release
dotnet test  NuGetCheck.slnx -c Release        # run the xUnit suite
dotnet run --project src/NuGetCheck -- ./examples/packages.config
```

Pack the tool locally:

```bash
dotnet pack src/NuGetCheck/NuGetCheck.csproj -c Release -o artifacts
dotnet tool install --global --add-source ./artifacts Dependably.NuGetCheck
```

## Project layout

```
src/NuGetCheck/        # the tool
  Program.cs           # CLI entry point + orchestration
  Cli/CliOptions.cs    # argument parsing
  Services/            # PackageFileReader, GitHubAdvisoryClient, VulnerabilityMatcher, AuditService
  Output/              # summary / table / json formatters
  Models/              # PackageRef, Advisory, AuditResult
tests/NuGetCheck.Tests # xUnit tests (fakes for HttpClient + advisory source)
```

See [docs/API.md](docs/API.md) for the internal architecture and the key types.

## License

Apache-2.0 — see [LICENSE](LICENSE).
