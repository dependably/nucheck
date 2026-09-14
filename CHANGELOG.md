# Changelog

All notable changes to `nucheck` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-09-13

### Added

- **`--facts <directory>` — a JSON "facts" document describing a .NET source tree, for
  other tools to consume.** It states the projects and their `PackageReference`s (with
  line numbers and the test-project marker — `<IsTestProject>` or the test-framework
  package id, never a directory name), the resolved closure each `obj/project.assets.json`
  / `packages.lock.json` records and the dependency edges among it, the namespaces read
  out of each package's own assemblies with `System.Reflection.Metadata`, every C# file's
  `using` directives (global/static/alias, and `#if`-disabled ones flagged) and qualified
  identifiers from a parse-only Roslyn scan, the type/member references in each built
  output assembly, and what each `*.deps.json` says lands next to the binary. Same envelope
  identity as the findings document (`tool`/`toolVersion`/`schemaVersion`/`target`/
  `summary`) with `findings` replaced by the fact sections and an explicit
  `documentType: "facts"` discriminator; the findings envelope is unchanged (no
  `documentType` means "findings document").

  **Facts are not findings, and this is the ownership rule the mode exists for**: the
  check tool owns *language facts* (AST usings, qualified identifiers, artefact and
  lockfile parsing, DLL namespace reads, IL member references, line locations); the
  consumer — sbom-reach, in the Dependably suite — owns *verdicts* (reachable /
  not-observed / unknown, confidence, dev-only, runtime presence, symbol intersection).
  Nothing verdict-shaped is in the document: no `status`, no `confidence`, no purls, no
  SBOM, no `bomRef`. The precedent is pycheck 1.4.0's `--imports`: a report, not a gate
  (a successful scan exits `0`; only a missing or unreadable target exits `2`; `--fail-on`,
  `--severity`, `--source`, `--rule`, `--rest`, `--config` and `--format` are inert), with
  `unanalyzable[]` as a load-bearing part of the contract — every file, directory,
  assembly, restore artefact or deps file the scan could not read is listed with a kind and
  a reason, because "nothing references X" is only evidence when the search ran over
  every file. A namespace is **never** inferred from a package id: when no assembly of a
  package can be read its `namespaces` key is omitted, so an un-restored tree yields no
  namespace for any package rather than a guess that is wrong for whole families
  (`AWSSDK.*` → `Amazon.*`). Absent means "could not tell", an explicit `null` states an
  absence, and an empty list is a fact ("enumerated, found none").

  The fact-gathering code is MOVED from sbom-reach's .NET sidecar
  (`sidecar/dotnet/SbomReach.Analyzer.CSharp` at commit `44e9252`): `AssetsReader`,
  `DepsReader`, `LicenseReader`, `NamespaceMap`, `ProjectDiscovery` and `UsingScanner`
  verbatim in logic (their diagnostics sink is now the structured `unanalyzable` list),
  plus `IlReferenceReader`, the metadata-enumeration third of the sidecar's `IlAnalyzer`.
  The sidecar's verdict half (`Analyzer`, `IlAnalyzer`'s merge/intersection,
  `ProjectScopes`, the wire protocol) stays where the verdicts live. No network, no
  `GITHUB_TOKEN`: the mode branches before any advisory source is created. A consumer
  probes for it by running it — an older nucheck answers `Error: unknown option: '--facts'`
  and exits `2`.

  Shape notes that came out of adversarial review before release: `packages[]` is keyed
  by **id + version** and `projects[].closure` is `[{ id, version }]`, because one tree can
  resolve two versions of one id in different projects and a consumer whose dedup key
  carries the version must see both, each with its own assemblies/namespaces/license read
  from its own package folder. A **symlinked directory is never followed** (a loop would
  enumerate without end; a link out of the tree would scan foreign code) and is reported
  as `{ kind: "directory", reason: "symlinked directory not followed" }`. A DLL the
  artefact lists but the package folder lacks is reported (`listed in assets but not
  present in package folder`) rather than silently skipped, so a `namespaces` list built
  from its siblings is not mistaken for the complete set. `runtimeOutput` is omitted, not
  `[]`, when every `*.deps.json` under `bin/` is unparseable. `unanalyzable[].reason` is
  path-free (fixed phrases for filesystem failures, parser positions kept) and
  `unanalyzable[].file` is relative to the target whenever the path is under it.
  `summary.packagesWithNamespaces` counts only non-empty DLL-read lists.

- **`--roots <a,b,...>`** (facts mode; repeatable, comma-separated) extends
  `source.qualifiedRoots` before the scan. The documented limitation it exists for: a
  fully-qualified use with no `using` directive (`Foo.Bar.Client.Send(...)`) is only
  recorded when its first segment is a root the tree itself reveals — a namespace read
  from a package assembly, or an id in a restore artefact or project file — so a package
  in no readable artefact (an un-restored tree with no lock file, or one the consumer
  knows about only from an SBOM) loses those uses with no way to recover them from the
  document. `--roots` is how the consumer asks; the applied set is published either way.

### Changed

- The tool package now carries Roslyn (`Microsoft.CodeAnalysis.CSharp` 4.11.0, with
  `Microsoft.CodeAnalysis`) for the parse-only C# scan: the `.nupkg` grows from 3.3 MB to
  10.1 MB, with satellite resource languages trimmed to `en` so the two Roslyn assemblies
  are the whole of the increase. Both `packages.lock.json` files record the new transitive
  closure (CI restores `--locked-mode`).

## [2.1.0] - 2026-08-13

### Added

- **`pinned-versions` rule — unpinned package versions now fail the build by default.**
  Every declared version must be an exact pin: floating versions (`6.*`), ranges
  (`[1.0,2.0)`), a range-carrying `allowedVersions` in `packages.config`, and a
  version-less `<PackageReference>` with no Central Package Management entry are error
  findings (exit 1); the exact bracket range `[1.2.3]` counts as pinned, and MSBuild
  property versions (`$(...)`) are skipped (static parse, no MSBuild evaluation). Not
  applicable to `packages.lock.json` — a lock file's resolved versions are exact by
  definition. Suite parity with npm-check 1.8.0 / pycheck 1.3.0: the shared rule id means
  one `common.rules["pinned-versions"]` entry in `.dependably` governs all three tools.

- **The `.dependably` `rules` severity map is now parsed and applied.** Previously
  whitelisted but ignored, per-rule severities (`error` / `warn` / `off`) resolve with the
  suite merge rule (per rule id, the `nucheck` section replacing `common` wholesale);
  `warn` findings are reported (ladder severity `low`) but never gate, `off` skips the
  check. Unknown rule ids in nucheck's own section are `UNKNOWN_RULE`; invalid severities
  are `INVALID_SEVERITY`.

- **`--rule <id>:<severity>` CLI flag** (repeatable) overrides the config's `rules` map for
  one run — e.g. `--rule pinned-versions:warn`. Unknown ids and bad severities are usage
  errors (exit 2).

- Pinned-versions findings are suppressible per package via the standard `exceptions`
  grammar (`{ "rule": "pinned-versions", "package": "Foo.Bar", ... }`, optionally
  `@<declared-version>`), and the pre-commit hook now also audits the repo's own two
  `.csproj` files so the new rule is dogfooded.

### Changed

- The `.dependably` conformance corpus is now vendored from the dependably-spec repository
  rather than from npm-check, with the upstream commit recorded in
  `tests/Dependably.NuCheck.Tests/conformance/VENDOR.md`. The fixtures themselves are
  unchanged; the provenance is now explicit, so drift between the suite's vendored copies is
  visible.

- The corpus is re-pinned to the spec commit that introduces the conformance vocabulary
  binding (§12), and the adapter replaying it now drives `DependablyCheckConfig.Load` — the
  entry point the CLI itself uses — instead of reaching past it into the exception parser and
  matcher. Cases are materialized into a throwaway repository and resolved through real
  discovery, real section merge, the real exception applier and the real gate, so a defect in
  the loader can no longer hide behind green primitives. Coverage goes from 12 cases to 16
  replayed plus 3 recorded as known divergences, each asserted to still fail so the entry
  cannot outlive the defect.

### Fixed

- **`allowedRegistryHosts` now stores its canonical spelling lowercased, per spec §5.1.**
  `UnionStringArray` deduped the merged `common` + `nucheck` list case-insensitively but kept
  whichever spelling appeared first, so `Packages.Corp.Dev` from `common` survived verbatim
  instead of collapsing to `packages.corp.dev` — a config that spelled the same host two ways
  ended up with two distinct-looking allowlist entries downstream. The other two list keys that
  share the same helper, `ignoreUnusedPackages` and `allowedLocalFeeds`, are unaffected: the
  spec names only `allowedRegistryHosts` for lowercase canonicalization, and `allowedLocalFeeds`
  holds filesystem paths, which are case-sensitive on the platforms that matter.

- **The merged `exclude` list is now surfaced off `DependablyCheckConfig.Exclude`.** It was
  already accepted without warning (see the entry below), but the loader resolved nothing for
  it, so a case pinning `resolved.exclude` had nothing to assert against. `exclude` now unions
  `common` and `nucheck` ordinally — case-preserving, since these are glob patterns — the same
  way the other three spec §5 list keys are resolved.

- **`failOn.severity` (and `--fail-on severity=`) now accepts the spec §4.2 aliases `error`,
  `warning`, and `warn`.** `Severity.ParseLevel` previously recognized only the five ladder
  words plus `medium`, so a config spelling the gate level as `warning` — the form the spec's
  own examples and several corpus cases use — made the whole `.dependably` file unloadable
  with `INVALID_FAIL_ON` instead of gating at `moderate`. `warning`/`warn` now normalize and
  parse to `moderate` (not the `low` they previously normalized to under `Severity.Normalize`,
  which was itself a spec violation), and `error` parses to `high` alongside the mapping
  `Severity.Normalize` already gave it.

- **`exclude` in nucheck's own section no longer emits a spurious `UNKNOWN_KEY`.** It is one of
  the six keys spec §4 declares legal in `common` and in every tool's own section with identical
  semantics; nucheck's known-keys list had omitted it, so a spec-legal `nucheck.exclude` entry
  warned as if it were a typo. nucheck has no current use for the key — it is legal and inert
  here, per the spec — but it must not warn.

- **An unknown key in the `common` section no longer emits `UNKNOWN_KEY`.** `common` is shared
  with every tool in the suite, so a key nucheck does not recognize is usually a sibling tool's
  legitimate setting rather than a typo — warning about it made a correct config noisier the
  more suite tools a repo used. The warning still fires for nucheck's own section, where an
  unrecognized key really is a typo. This matches the handling unknown *rule ids* in `common`
  already had, and follows the spec clarification made when the shared contract was extracted
  to its own repository.

## [2.0.1] - 2026-07-03

### Added

- **Pre-commit dogfooding.** The tracked `.githooks/pre-commit` hook now dogfoods nucheck
  against its own two `packages.lock.json` files (`--source osv --fail-on severity=high`,
  a hard gate) and cross-dogfoods the sibling Dependably `.NET` tools — `cslint --sast
  --global` and `codemetrics ./src` — against this repo's own C# source (also hard gates;
  skipped with a warning, not a failure, when a sibling tool isn't installed globally). A
  root `.dependably` config documents the private registry proxy
  (`dependably.northwardlabs.ca`) as an `allowedRegistryHosts` entry for suite consistency.

- **Unified `.dependably` config + exceptions.** nucheck now reads the canonical
  `.dependably` file (the deprecated `.dependably-check` filename is still read with a
  one-line stderr notice; `.dependably` wins when both exist) and its own `nucheck` section
  (the `nuget` section is a deprecated alias). New standardized `exceptions` grammar lets you
  suppress a *specific* finding — `{ rule, package?|id?, reason, expires? }` — so it no longer
  fails the build, without disabling a whole check; unused and expired exceptions are reported
  on stderr. A file-level `failOn` (`severity` / `count`) gate is honored, with a CLI
  `--fail-on` overriding it. Config `version` and shape are validated, and unknown keys in a
  read section warn. Mirrors npm-check's reference implementation and is verified against the
  shared cross-language conformance fixtures.

### Fixed

- **Unused-package heuristic now recognizes MSBuild implicit `<Using Include="...">`
  items.** A package referenced only via a project-level implicit using (e.g. test
  projects declaring `<Using Include="Xunit" />` instead of a literal `using Xunit;` in
  every file) was previously misreported as unused; `xunit.runner.visualstudio` — a
  test-discovery package with no directly-callable API — is now also allow-listed, the
  same class as the existing `Microsoft.NET.Test.Sdk` entry. Found by dogfooding nucheck
  on its own test project.

## [2.0.0] - 2026-07-02

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
  unchanged. **Breaking:** an unrecognised `--format` token is now a usage error (exit 2);
  previously it silently fell back to the human formatter. Scripts relying on the silent
  fallback must be updated to pass a valid token (`human`, `table`, or `json`).
- **Breaking:** an unrecognised `--severity` token is now a usage error (exit 2); previously
  it may have silently passed through. Valid levels are `critical`, `high`, `moderate`,
  `low`, `info`.
- **`--severity` filter emits a qualified message when no advisories match.** When zero
  advisories match the active `--severity` filter (but other-severity advisories may still
  trip the exit-code gate), the "all packages are secure" message is replaced with
  "No advisories matching severity '&lt;level&gt;' (others may exist — see exit code)" in both
  the `human` and `table` formats so the display never contradicts a non-zero exit code.
- **Advisory text is sanitized against control-character injection.** ANSI escape
  sequences, carriage returns, and other C0/C1 control characters in advisory fields
  (summary, advisory id, CVE, fixed version, source-trust host/message) are replaced with
  spaces before they reach any output formatter, preventing terminal-escape injection from
  a malicious advisory payload.
- **`human` format suppresses the "all packages are secure" checkmark when policy errors
  are present.** When vulnerabilities are zero but a source-trust policy error trips
  the gate (exit 1), the human (summary) formatter now omits the misleading checkmark,
  matching the existing behaviour of the `table` formatter.

### Fixed

- **The "✓ All packages are secure" line can no longer print beside a non-zero exit.** The
  `human` and `table` formatters now decide the all-clear checkmark from the real process
  exit code (and the presence of any policy finding), not just from the error-severity policy
  count. Previously an `info`-severity policy finding gated by `--fail-on severity=info` (such
  as the non-git parent-config notice) exited 1 while the output still claimed success.

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
- **Non-git checkouts surface unaudited parent `nuget.config`.** When no repository
  boundary (`.git`) can be located, package sources declared in parent directories are out of
  audit scope even though a restore would still honour them; `nucheck` now emits a visible
  `info` finding naming those excluded config files instead of silently failing open.

### Supply chain

- **Keyless publishing to nuget.org via Trusted Publishing (OIDC).** The GitHub Actions
  release workflow no longer relies on a long-lived `NUGET_API_KEY` secret; it exchanges a
  GitHub OIDC token for a short-lived, single-use nuget.org key at publish time, removing a
  stored credential that could leak or need rotation.

## [1.1.1] - 2026-06-21

Released under the previous package id `Dependably.NuGetCheck` (command `nuget-check`); no
functional changes were recorded separately from 1.1.0. Superseded by 2.0.0, which renames
the package to `Dependably.NuCheck` (command `nucheck`).

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

[Unreleased]: https://github.com/dependably/nucheck/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/dependably/nucheck/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/dependably/nucheck/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/dependably/nucheck/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/dependably/nucheck/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/dependably/nucheck/releases/tag/v1.1.0
