# Changelog

All notable changes to `nuget-check` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-19

Initial release: a native .NET global tool (`MoonlitLabs.NuGetCheck`, command
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
