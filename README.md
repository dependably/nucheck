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
  --config <path>       Path to a .dependably-check config file
  --rest                Use the GitHub REST API instead of GraphQL
  --verbose, -v         Write progress to stderr
  --help, -h            Show full help
  --version             Print the version
```

The GitHub source needs a token in `GITHUB_TOKEN` (create one at
<https://github.com/settings/tokens> — no scopes required); `--source osv` needs none.

Point `nucheck` at a `packages.lock.json` for exact resolved versions. A `.csproj` /
`.props` is parsed statically (no MSBuild evaluation) and audited at each dependency's
declared lower bound.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Clean — no findings (also `--help` / `--version`). |
| `1`  | A vulnerability or policy finding — block the build. |
| `2`  | Usage error (bad flag, missing/unreadable manifest) or scan failure. |

By default, **any** vulnerability or untrusted package source fails the build. Change the
gate with `--fail-on` — e.g. `--fail-on severity=high` (ignore moderate/low) or
`--fail-on count=0`. `--severity` only filters what is printed; it never changes the exit
code.

## Extra checks

Beyond vulnerabilities, `nucheck` also reports:

- **Untrusted package sources** — any NuGet source declared in your repo whose host isn't
  public (`nuget.org`), plus any local folder feed, unless allowlisted. This **fails the
  build by default**: if you restore from a private, company, or Azure Artifacts feed,
  allowlist it first (see below).
- **Possibly-unused packages** — direct `<PackageReference>`s whose namespace never appears
  in your `.cs` files. Advisory only; never fails the build.

Configure both in a `.dependably-check` JSON file at your repo root:

```json
{
  "common": {
    "allowedRegistryHosts": ["nuget.internal.example.com"],
    "allowedLocalFeeds": ["./local-packages"],
    "ignoreUnusedPackages": ["StyleCop.Analyzers"]
  }
}
```

Run `nucheck --help` for the complete policy rules and the JSON output schema.

## JSON output

`--format json` writes one object to stdout following the shared Dependably finding schema
(`tool`, `toolVersion`, `schemaVersion`, `target`, `summary`, `findings`), so every tool in
the suite parses the same way.

## Build from source

```bash
git clone https://github.com/dependably/nucheck.git
cd nucheck
dotnet build Dependably.NuCheck.slnx -c Release
dotnet test  Dependably.NuCheck.slnx -c Release
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
