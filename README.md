# nucheck

Audit your .NET NuGet dependencies for known vulnerabilities — like `npm audit`, for .NET.

`nucheck` reads your installed packages (`packages.config`, `packages.lock.json`, or a
`.csproj` / `Directory.Packages.props`), checks them against the
[GitHub Advisory Database](https://github.com/advisories) (or [OSV.dev](https://osv.dev)),
and reports any package whose installed version has a known vulnerability. It uses the real
`NuGet.Versioning` comparer, so NuGet's 4-part versions (`1.8.3.1`) and interval ranges
(`[1.0,2.0)`) are matched correctly.

## Install

Requires the .NET SDK 8.0 or later.

```bash
dotnet tool install --global Dependably.NuCheck
```

This puts the `nucheck` command on your PATH.

## Usage

```bash
export GITHUB_TOKEN=your_token        # or use --source osv (no token needed)
nucheck ./packages.config
```

```
nucheck <path-to-packages-file> [options]

  --source <name>       Advisory source: github (default), osv
  --format <type>       Output: human (default), table, json
  --severity <level>    Show only: critical, high, moderate, low, info
  --fail-on <k>=<v>     CI gate: severity=<level> or count=<N> (repeatable)
  --config <path>       Path to a .dependably config file (.dependably-check: deprecated alias)
  --rest                Use the GitHub REST API instead of GraphQL
  --verbose, -v         Write progress to stderr
  --help, -h            Show full help
  --version             Print the version
```

The GitHub source needs a token in `GITHUB_TOKEN` (create one at
<https://github.com/settings/tokens> — no scopes required); `--source osv` needs none.
On a first run with no `GITHUB_TOKEN` set and no `--source` given, `nucheck` falls back
to OSV.dev automatically (printing a one-line notice to stderr) so it works out of the box;
pass `--source github` to require the GitHub Advisory Database and fail if the token is missing.

Point `nucheck` at a `packages.lock.json` for exact resolved versions. A `.csproj` /
`.props` is parsed statically (no MSBuild evaluation) and audited at each dependency's
declared lower bound.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Clean — no findings (also `--help` / `--version`). |
| `1`  | A vulnerability or policy finding — block the build. |
| `2`  | Usage error (bad flag, missing/unreadable manifest) or scan failure. |

By default, **any** vulnerability, untrusted package source, or unpinned package version
fails the build. Change the gate with `--fail-on` — e.g. `--fail-on severity=high` (ignore
moderate/low) or `--fail-on count=0`. `--severity` only filters what is printed; it never
changes the exit code.

## Extra checks

Beyond vulnerabilities, `nucheck` also reports:

- **Untrusted package sources** — any NuGet source declared in your repo whose host isn't
  public (`nuget.org`), plus any local folder feed, unless allowlisted. This **fails the
  build by default**: if you restore from a private, company, or Azure Artifacts feed,
  allowlist it first (see below).
- **Unpinned package versions** (`pinned-versions`) — every declared version must be an
  exact pin. Floating versions (`6.*`), ranges (`[1.0,2.0)`), a range-carrying
  `allowedVersions` in `packages.config`, and a version-less `<PackageReference>` with no
  Central Package Management entry are findings; the exact bracket range `[1.2.3]` counts
  as pinned. **Fails the build by default** (error), so a pre-commit hook or CI job
  actually gates drift — the same cross-tool rule id as npm-check and pycheck, so one
  `common.rules["pinned-versions"]` entry in `.dependably` governs the whole suite. Not
  applicable to `packages.lock.json` (a lock file's resolved versions are exact by
  definition). Relax it per repo via `rules` (below) or per run with
  `--rule pinned-versions:warn`.
- **Possibly-unused packages** — direct `<PackageReference>`s whose namespace never appears
  in your `.cs` files. Advisory only; never fails the build.

Configure both in a `.dependably` JSON file at your repo root (the shared Dependably-suite
config; `.dependably-check` is a deprecated alias filename). nucheck reads the `common`
section and its own `nucheck` section (`nuget` is a deprecated section alias):

```json
{
  "common": {
    "allowedRegistryHosts": ["nuget.internal.example.com"],
    "allowedLocalFeeds": ["./local-packages"],
    "ignoreUnusedPackages": ["StyleCop.Analyzers"]
  }
}
```

### Rule severities

The `rules` map sets a per-rule severity: `error` gates the run (exit 1), `warn` reports
without gating, and `off` drops the rule's findings entirely (unlike an exception, which
suppresses one specific finding). Entries merge per rule id (`common` first, the `nucheck`
section replacing wholesale); the repeatable CLI `--rule <id>:<severity>` flag overrides
the file for one run. `pinned-versions` (default `error`) is currently the severity-driven
rule:

```json
{
  "nucheck": { "rules": { "pinned-versions": "warn" } }
}
```

### Exceptions

To silence a *specific* finding without disabling a whole check, add an `exceptions` entry —
a rule id, at least one selector (`package` / `id`), and a required `reason`; an optional
`expires` (`YYYY-MM-DD`) makes it inert afterward. Suppressed findings no longer fail the
build; unused and expired exceptions are reported on stderr.

```json
{
  "nucheck": {
    "failOn": { "severity": "high" },
    "exceptions": [
      { "rule": "vulnerable-package", "package": "log4net@2.0.8", "id": "GHSA-2cwj-8chv-9pp9",
        "reason": "sink unreachable; upgrade blocked", "expires": "2026-09-30" },
      { "rule": "unused-packages", "package": "Microsoft.SourceLink.GitHub",
        "reason": "build-time only, no runtime namespace" }
    ]
  }
}
```

Run `nucheck --help` for the complete policy rules and the JSON output schema.

## JSON output

`--format json` writes one object to stdout following the shared Dependably finding schema
(`tool`, `toolVersion`, `schemaVersion`, `target`, `summary`, `findings`), so every tool in
the suite parses the same way.

## License

Apache-2.0 — see [LICENSE](LICENSE).
