# Changelog

All notable changes to `nucheck` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Repo-declared local folder feeds are now fail-closed (BREAKING default-gate change).**
  The source-trust check previously ignored local folder feeds; it now reports every enabled
  repo-declared local feed — a relative path, an absolute path, or a `file://` URI — as a
  policy **error** unless its path is listed in the new `allowedLocalFeeds` allowlist
  (`common` ∪ `nuget` sections of `.dependably-check`). A committed folder feed can serve
  tampered `.nupkg` files that a restore honours without touching any registry, so trusting
  it must be an explicit, reviewed decision. Repos that declare a local feed will now fail CI
  until the feed is allowlisted.
- **Hardened `allowedLocalFeeds` against two allowlist bypasses.** (1) Entries prefixed with
  `./` (or `../`) are anchored to the repo root and matched by canonical absolute path, so
  `./local-packages` grants only `<repo>/local-packages` and never a same-named feed elsewhere
  in the tree (bare-name entries keep the looser trailing-segment match). (2) A remote-host
  `file://server/share/...` URI or a UNC path (`\\server\share\...`) is a network share, not a
  local folder, and can no longer be satisfied by a plain local-path entry: such a feed is
  flagged unless an allowlist entry names its **exact** full path. This closes a path where a
  malicious `nuget.config` edit could redirect an "allowlisted local feed" to an
  attacker-controlled remote share.
- **Non-git checkouts surface unaudited parent `nuget.config` (#47).** When no repository
  boundary (`.git`) can be located, package sources declared in parent directories are out of
  audit scope even though a restore would still honour them; `nucheck` now emits a visible
  `info` finding naming those excluded config files instead of silently failing open.

### Changed

- **Renamed to `Dependably.NuCheck` (command `nucheck`).** The NuGet package id changes
  from `Dependably.NuGetCheck` to `Dependably.NuCheck`, the global-tool command from
  `nuget-check` to `nucheck`, and the C# root namespace from `NuGetCheck` to
  `Dependably.NuCheck`. Reinstall with `dotnet tool install -g Dependably.NuCheck` and
  invoke as `nucheck`.
- **`--format json` now emits the shared Dependably finding schema v1 envelope.** This is a
  **breaking** change to the JSON shape. The output is one object with the suite-uniform core
  keys `tool` / `toolVersion` / `schemaVersion` (`"1.0"`) / `target` / `summary` / `findings`.
  `summary` reports `scanned` (packages audited), `findings` (== `findings.length`),
  `bySeverity` (the five ladder buckets), and `exitCode` (the real process exit code). Each
  finding follows the schema Finding shape; vulnerability advisory data moves under
  `extra` (`package`, `installedVersion`, `fixedVersion`, `advisoryId`, `cve`,
  `vulnerableRange`, `references`). Untrusted package sources are `category: "policy"`
  findings and heuristic unused packages are `category: "unused"` (`info`).
- **One severity ladder across the suite:** `critical > high > moderate > low > info`. nuget
  severities map onto it (`medium`→`moderate`, `unknown`→`info`; the policy word `error`→`high`).
  The `human` and `table` outputs print the ladder words too.
- **`--format` token renamed `summary` → `human`** (the default). `table` and `json` are
  unchanged. Any unrecognised token still falls back to the human formatter.

### Added

- **Unified `--fail-on <key>=<value>` CI gate (repeatable).** The single suite-wide gate
  mechanism. `severity=<critical|high|moderate|low|info>` fails the build only on findings
  at-or-above the level (relax or raise the gate — relaxed-out vulnerabilities still print);
  `count=<N>` fails when the vulnerability count exceeds `N`. Multiple rules are OR-ed. With
  no `--fail-on`, the default is unchanged — any vulnerability or policy error fails (exit
  `1`). A bad key/value is a usage error (exit `2`). `--severity` remains a **display
  filter** only and no longer influences the exit code; the gate always evaluates the full,
  unfiltered result, and the JSON `summary.exitCode` mirrors the real process exit code.

- **Unused-package check (advisory only).** `nucheck` now heuristically detects
  NuGet packages declared as direct `<PackageReference>` entries in `*.csproj` files
  (and `Directory.Packages.props` for central package management) under the audited
  file's directory whose namespace cannot be found in any `.cs` source file. Findings
  appear in all three output formats as a clearly-labelled advisory section
  ("Possibly unused packages — heuristic"). This check reads **direct** package
  references only, never the transitive lock-file closure, to avoid false-positives on
  transitively-resolved deps.

  The check is **advisory only**: it never changes the process exit code. Build-tool,
  analyzer, MSBuild-task, and `PrivateAssets` packages commonly produce false positives
  because they have no runtime namespace. Suppress individual packages via
  `ignoreUnusedPackages` in `.dependably-check` (union of `common` and `nuget`
  sections, same pattern as `allowedRegistryHosts`):

  ```json
  {
    "common": { "ignoreUnusedPackages": ["StyleCop.Analyzers"] },
    "nuget":  { "ignoreUnusedPackages": ["Microsoft.CodeAnalysis.Analyzers"] }
  }
  ```

## [1.1.0] - 2026-06-21

### Added

- **Source-trust policy check.** `nucheck` now audits the effective NuGet package
  sources for the audited file's directory (resolved via the native `NuGet.Configuration`
  API) and flags any enabled `http(s)` source whose host is neither a built-in public host
  (`api.nuget.org` / `nuget.org`) nor explicitly allowlisted. An untrusted source is an
  error and makes the process exit non-zero; local folder feeds and disabled sources are
  ignored. Findings surface in all three output formats (a `policyFindings` array in JSON).
- **Shared `.dependably-check` config.** A repo-root JSON config (shared across the
  Dependably checker tools) supplies allowlisted registry hosts via the union of
  `common.allowedRegistryHosts` and `nuget.allowedRegistryHosts`. It is discovered by
  walking up from the current directory (stopping at the repo root), or pointed at
  explicitly with the new `--config <path>` flag.

- **`--source osv` advisory source.** Audit against the public [OSV.dev](https://osv.dev)
  database with no token required, as an alternative to the default GitHub Advisory source.
  OSV introduced/fixed/last_affected ranges are translated into the comparator syntax the
  existing `VulnerabilityMatcher` understands, so version matching stays centralized.

### Supply chain

- **Signed build provenance (SLSA Build L2).** Released `.nupkg` artifacts are now
  packed and published from GitHub Actions with keyless (OIDC/sigstore) SLSA build
  provenance attesting how and where they were built. Consumers can verify the
  downloaded package with
  `gh attestation verify <file>.nupkg -R dependably/nucheck`.

## [1.0.0] - 2026-06-19

Initial release: a native .NET global tool (`Dependably.NuGetCheck`, command
`nuget-check`) that audits `packages.config` / `packages.lock.json` against the GitHub
Advisory Database, matching installed versions with the real `NuGet.Versioning` comparer
(4-part versions and interval ranges, where a JavaScript `semver` port is wrong).

### Reliability

- **API failures never report a clean audit.** A non-success HTTP response or a GraphQL
  `200` carrying an `errors` payload throws and exits non-zero rather than returning an
  empty advisory list — a failed query can no longer be mistaken for "no vulnerabilities".
- **Transient failures are retried** (HTTP 429, 5xx, and the secondary rate-limit 403)
  with a `Retry-After`-aware exponential backoff, capped per wait.
- **Packages are queried concurrently** (bounded) since each is an independent network
  round-trip; the reported order stays deterministic.

### Correctness

- **Consistent severity filtering** across API paths: REST's `medium` is normalised to
  the GraphQL `moderate`, so `--severity moderate` works with and without `--rest`.

### Supply chain

- **Dependencies are pinned** with a committed `packages.lock.json`; CI restores in locked
  mode so a drifted or tampered transitive dependency fails the build.

### Packaging

- Published as a `dotnet tool` (`PackAsTool`); metadata includes `PackageProjectUrl`.
