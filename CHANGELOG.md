# Changelog

All notable changes to `nuget-check` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0]

### Added

- **Source-trust policy check.** `nuget-check` now audits the effective NuGet package
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
