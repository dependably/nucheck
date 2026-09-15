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
nucheck --facts <directory> [--roots <a,b,...>] [--verbose]

  --source <name>       Advisory source: github (default), osv
  --format <type>       Output: human (default), table, json
  --severity <level>    Show only: critical, high, moderate, low, info
  --fail-on <k>=<v>     CI gate: severity=<level> or count=<N> (repeatable)
  --config <path>       Path to a .dependably config file (.dependably-check: deprecated alias)
  --rest                Use the GitHub REST API instead of GraphQL
  --facts               Emit a JSON facts document for the .NET source tree at <directory>
                        instead of auditing a manifest (see "Facts" below)
  --roots <a,b,...>     Facts mode only (repeatable, comma-separated). Extra top-level
                        identifier roots to keep fully-qualified uses for, on top of the
                        ones the tree's own artefacts reveal (see "Why --roots" below)
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

`--facts` is a report, not a gate: a successful scan exits `0` — even when the document
lists paths it could not read in `unanalyzable` — and only a missing or unreadable target
directory exits `2`. There is no exit `1` in facts mode.

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

## Facts (`--facts`)

`--facts <directory>` exports what a .NET source tree *is*, as data for another tool: the
projects and their `PackageReference`s, the resolved closure each restore artefact records,
the namespaces read out of each package's assemblies, every C# file's `using` directives
and qualified identifiers, and the type and member references of each built output
assembly. Nothing is audited and nothing is gated: a successful scan always exits `0`. It
needs no token and touches no network.

```bash
nucheck --facts ./src > facts.json
nucheck --facts ./src --verbose                  # progress on stderr; stdout stays pure JSON
nucheck --facts ./src --roots Amazon,Fabrikam    # also keep Amazon.* / Fabrikam.* qualified uses
```

nucheck reports **.NET language and packaging facts only**. It knows nothing about
vulnerabilities, purls or SBOMs, and it draws no conclusions: whether a package is
reachable, how confident to be, which package a `using` "belongs to", whether a package is
dev-only, or whether an unreferenced package still ships — those are the consumer's
verdicts (sbom-reach's, in the Dependably suite), and the document deliberately has no
field to carry them.

### Facts are not findings

A `using` directive has no severity — "`App/Program.cs` imports `Newtonsoft.Json` on
line 1" is not a problem to fix — so squeezing it into the findings envelope's `findings`
array would be a lie, and would let `--fail-on` gate CI on ordinary imports. `--facts`
therefore emits a **sibling document type**, following pycheck's `--imports`: the same
envelope identity every Dependably tool shares (`tool`, `toolVersion`, `schemaVersion`,
`target`, `summary`), with `findings` replaced by the fact sections, and an explicit
`documentType: "facts"` discriminator so a consumer never has to guess the payload from
whichever key happens to be present. A document with no `documentType` is a findings
document — the findings envelope is unchanged.

`--fail-on`, `--severity`, `--source`, `--rule`, `--rest`, `--config` and `--format` are
accepted but inert in this mode. A consumer probes for the mode itself by running it: a
nucheck older than 2.2.0 answers `Error: unknown option: '--facts'` on stderr and exits
`2`. Anything finer-grained than "does this build have `--facts` at all" is answered by
the document, not by a second process launch — see below.

### `schemaVersion` and `capabilities`

**`schemaVersion` describes the document's SHAPE, and nothing else.**

- A newer **MINOR** is **additive**: keys were added, and every key an older 1.x document
  carried still exists and still means the same thing. A consumer written against an older
  minor **proceeds unchanged** — note the new keys if it likes, ignore them otherwise.
- A newer **MAJOR** means a key was **renamed, removed, or redefined**. A consumer written
  against the older major must **refuse the document** rather than read it optimistically.
- The facts document's version is its own. It is **not** the tool version, and **not** the
  findings document's `schemaVersion` (a separate document with a separate shape, still
  `1.0`).

**`capabilities` names behaviours the shape cannot reveal.** A version number cannot say
how an *existing* field is filled: nucheck 2.3.0's IL normalizations added no key — they
changed which spellings appear inside `il[].references[]` — so 2.2.0 and 2.3.0 emit the
same schema, and `--facts` shipped in 2.2.0 while those normalizations shipped in 2.3.0.
A consumer that needs them therefore cannot get its answer from `schemaVersion`, and
parsing `--version` makes correctness depend on a second process launch that can fail (and
on nucheck's release history, which a fork, a backport or a dev build does not share).
The document states its own behaviours instead:

```json
"capabilities": ["il-accessor-names", "il-generic-arity"]
```

| Capability | What the emitting build does |
| ---------- | ---------------------------- |
| `il-accessor-names` | `il[].references[]` records a compiled property/indexer/event accessor (`get_Foo`) **additionally** under its natural source-level name (`Foo`). The raw accessor spelling is still reported; nothing is replaced. |
| `il-generic-arity` | `il[].references[]` records a generic type **additionally** with its metadata arity suffix stripped (`` List`1 `` → `List`), for `il-type-ref` entries and the type half of `il-member-ref` entries. |

**An absent `capabilities` is not an empty one.** A `schemaVersion` `1.0` document predates
the field: it says *nothing* about what its build does, so treat it as "cannot tell" —
the same rule this document applies to every omitted key. A present `[]` is a build that
declares no capability.

**A newly added FIELD is not a capability.** The minor bump announces it and the key is
either in the document or it is not, so listing it here would only grow a second changelog
to drift out of date. `capabilities` stays a short negotiation surface for behaviour that
is otherwise invisible.

### The document

For a tree with an `App` project (four direct references, a restore artefact) and a `Lib`
project (one reference, no artefact), scanned **before** `dotnet restore` — so the
artefact's `packageFolders` points nowhere and no package assembly is readable — the
document is (trimmed):

```json
{
  "tool": "nucheck",
  "toolVersion": "2.4.0",
  "schemaVersion": "1.1",
  "documentType": "facts",
  "capabilities": ["il-accessor-names", "il-generic-arity"],
  "target": "./csharp-app",
  "summary": {
    "projects": 2, "filesScanned": 3, "assembliesRead": 0,
    "packages": 5, "packagesWithNamespaces": 0, "unanalyzable": 0, "exitCode": 0
  },
  "projects": [
    {
      "path": "App/App.csproj",
      "isTestProject": false,
      "testMarker": null,
      "directReferences": [
        { "id": "Newtonsoft.Json", "file": "App/App.csproj", "line": 7 },
        { "id": "Serilog", "file": "App/App.csproj", "line": 8 }
      ],
      "assets": { "file": "App/obj/project.assets.json", "kind": "assets" },
      "closure": [
        { "id": "CsvHelper", "version": "27.0.0" },
        { "id": "Microsoft.Bcl.AsyncInterfaces", "version": "5.0.0" },
        { "id": "Newtonsoft.Json", "version": "12.0.1" },
        { "id": "Polly", "version": "7.2.0" },
        { "id": "Serilog", "version": "2.10.0" }
      ],
      "outputAssembly": null
    },
    {
      "path": "Lib/Lib.csproj",
      "isTestProject": false,
      "testMarker": null,
      "directReferences": [{ "id": "Newtonsoft.Json", "file": "Lib/Lib.csproj", "line": 7 }],
      "assets": null,
      "outputAssembly": null
    }
  ],
  "centralPackageVersions": [
    { "id": "Newtonsoft.Json", "file": "Directory.Packages.props", "line": 6 }
  ],
  "packages": [
    {
      "id": "CsvHelper",
      "version": "27.0.0",
      "assemblies": ["CsvHelper"],
      "dependencies": ["Microsoft.Bcl.AsyncInterfaces"]
    },
    { "id": "Newtonsoft.Json", "version": "12.0.1", "assemblies": ["Newtonsoft.Json"], "dependencies": [] }
  ],
  "packageFolders": [{ "path": "/nonexistent/fixture-global-packages", "readable": false }],
  "source": {
    "qualifiedRoots": ["CsvHelper", "Microsoft", "Newtonsoft", "Polly", "Serilog"],
    "files": [
      {
        "file": "App/Program.cs",
        "project": "App/App.csproj",
        "usings": [
          { "namespace": "Newtonsoft.Json", "line": 1, "global": false, "static": false, "alias": null, "disabled": false },
          { "namespace": "CsvHelper", "line": 4, "global": false, "static": false, "alias": null, "disabled": true }
        ],
        "qualified": [
          { "namespace": "Serilog.Log.Information", "line": 15, "snippet": "Serilog.Log.Information" }
        ]
      },
      { "file": "Lib/Parser.cs", "project": "Lib/Lib.csproj", "usings": [], "qualified": [] }
    ]
  },
  "il": [],
  "unanalyzable": []
}
```

Every path is relative to `target`, with `/` separators. The document is deterministic:
the same tree produces the same bytes, and nothing in it depends on filesystem iteration
order. The findings envelope's `summary.exitCode` convention carries over — it is the
process exit code, `0` for every successful scan.

| Section | What it states |
| ------- | -------------- |
| `projects[]` | Every `.csproj`, sorted by path. `testMarker` is what made it a test project — `"<IsTestProject>"` for the explicit MSBuild property, else the id of the test-framework package it references — and **never a directory name**; `null` when it is not one. `directReferences` are its `<PackageReference>`s with line numbers. `assets` names the restore artefact read (`obj/project.assets.json` → `"assets"`, `packages.lock.json` → `"lock"`), `null` when neither exists; `closure` is every package (`id` + `version`) that artefact resolved. `outputAssembly` is the project's own built DLL under `bin/`, `null` when none. `runtimeOutput` lists, per readable `*.deps.json` under `bin/`, the packages that contribute a runtime assembly to that output — the ones on disk next to the binary whether or not anything references them. |
| `centralPackageVersions[]` | `<PackageVersion>` entries from `Directory.Packages.props`, with lines. |
| `packages[]` | The merged closure across all projects, **one entry per id + version**, sorted by id then version. A tree can resolve two versions of one id (App on 12.0.1, a test project on 13.0.3 — separate artefacts), and each is its own entry with its own facts read from its own package folder. `assemblies` are the simple names of the DLLs the package ships under `lib/` or `ref/`; `namespaces` are the namespaces of its public types **read from those assemblies**; `dependencies` are the ids its artefact entry depends on, as written (an id may be absent from `packages` when a TFM-conditional edge did not resolve — reported, not filtered); `license` is the SPDX expression from its own `.nuspec`. |
| `packageFolders[]` | The global-packages folders the artefacts name, and whether each exists. |
| `source.files[]` | **Every C# file that was read**, sorted, attributed to the innermost project whose directory contains it (`null` under no project). A file with no usings is still listed — "read, found nothing" is a different fact from "never read". `usings` carry `global`/`static`/`alias`, and `disabled: true` for a directive inside an `#if` region the parser skipped (a TFM-conditional using — a fact about the file, flagged so the consumer can weigh it). `qualified` are fully-qualified identifier prefixes (`Serilog.Log.Information`) whose first segment is in `qualifiedRoots`. |
| `source.qualifiedRoots` | The roots qualified identifiers were kept for: first segments of every DLL-read namespace, of every closure or declared package id, and of every `--roots` entry. Made visible so a consumer knows what `qualified` could contain — see "Why `--roots`" below. |
| `il[]` | One entry per built project: the distinct `il-type-ref` / `il-member-ref` entries in its output assembly's metadata tables, each naming the fully-qualified symbol and the assembly that defines it. Reference evidence read with `System.Reflection.Metadata` (nothing is loaded or executed) — not a call graph, and not a proof of execution. Joining `assembly` to `packages[].assemblies` is the consumer's step. |
| `unanalyzable[]` | Every path the scan could not read, as `{ "file", "kind", "reason" }` — a worked example of every `kind` is below. |

Generated files (`*.g.cs`, `*.Designer.cs`, `*.generated.cs`) and `bin/`, `obj/`,
`node_modules/`, `.git/`, `.vs/` and other dot-directories are not scanned. A **symlinked
directory is never followed** — a link back into the tree would enumerate the same files
without end, and a link out of it would scan code that is not the target — and is
reported in `unanalyzable` instead (below).

**Why `--roots`.** `qualified` is deliberately filtered: recording every dotted identifier
in a code base would swamp the document with `Console.WriteLine`-style noise, so a
qualified use is kept only when its first segment is in `qualifiedRoots`, and that set is
derived from what the tree itself reveals — the namespaces read from package assemblies
and the ids in its restore artefacts and project files. The limitation is the flip side:
a package that appears in **no readable artefact** (an un-restored tree with no lock file,
or a package the consumer knows about from an SBOM but the tree never names) contributes
no root, so a fully-qualified use of it with no `using` directive —
`Foo.Bar.Client.Send(...)` — is not recorded, and nothing in the document can recover it
afterwards. `--roots <a,b,...>` (repeatable, comma-separated) EXTENDS the set before the
scan; a dotted entry is reduced to its first segment (`Amazon.S3` → `Amazon`). The applied
set is always published, so a consumer can see exactly which roots the `qualified` lists
were filtered on and re-run with more if a package it cares about is missing.

**Absent, `null` and empty are three different statements.** A key that is *omitted* means
the tool could not determine it: `packages[].namespaces` when no assembly of the package
could be read, `packages[].assemblies` when the artefact never enumerated the files (a
lock file names the closure, not its contents), `packages[].license` when there is no
readable expression, `projects[].closure` when there was no readable artefact, and
`projects[].runtimeOutput` when nothing was built or when every `*.deps.json` present is
unparseable. An explicit `null` states an absence (`testMarker`, `alias`, `assets`,
`outputAssembly`, `project`). A present-and-empty list is a fact: `namespaces: []` means
the package's assemblies were read and expose no public namespace, or it has no assemblies
at all (see `assemblies` — an analyzer- or targets-only package), so C# source provably
cannot reference it; `summary.packagesWithNamespaces` counts only packages whose list is
present **and** non-empty. In particular, **a namespace is never inferred from a package id** — the convention
holds for most packages and is wrong for whole families (`AWSSDK.*` ships `Amazon.*`,
`Microsoft.CodeAnalysis.Workspaces.MSBuild` ships `Microsoft.CodeAnalysis.MSBuild`), and a
consumer handed the guess would search for a namespace the package never had, find nothing,
and conclude "unused" about a package the code demonstrably imports.

**Restore and build first for the richest document.** Without `dotnet restore` there is no
`obj/project.assets.json`: `closure`, `dependencies` and `assemblies` fall back to
`packages.lock.json` where one exists, and no package assembly is readable, so
`namespaces` is omitted for every package. Without `dotnet build` there is no `bin/`:
`il` is empty and `runtimeOutput` is omitted.

### `unanalyzable`

Every path the scan could not read appears in `unanalyzable` with a `kind` and a `reason`,
and is counted in `summary`. It is part of the contract, not an afterthought: "nothing
references X" is only evidence when the search actually ran over every file, so a consumer
must weaken every negative it draws from a document whose `unanalyzable` is non-empty. A
scan that hits one still succeeds and reports everything else.

```json
"unanalyzable": [
  { "file": "App/obj/project.assets.json", "kind": "assets", "reason": "unparseable assets file: 'n' is an invalid start of a value. Path: $ | LineNumber: 0 | BytePositionInLine: 2." },
  { "file": "App/bin/Debug/net8.0/App.deps.json", "kind": "deps", "reason": "unparseable deps file: ..." },
  { "file": "Lib/bin/Debug/net8.0/Lib.dll", "kind": "assembly", "reason": "could not read IL metadata: not a valid PE/metadata image" },
  { "file": "/home/me/.nuget/packages/acme.widgets/1.0.0/lib/netstandard2.0/Acme.Widgets.Extras.dll", "kind": "assembly", "reason": "listed in assets but not present in package folder" },
  { "file": "Broken.csproj",  "kind": "file",      "reason": "unparseable project file: Unexpected end of file has occurred. Line 1, position 30." },
  { "file": "vendor/Gone.cs", "kind": "file",      "reason": "unreadable: not found" },
  { "file": "private",        "kind": "directory", "reason": "unlistable directory: access denied" },
  { "file": "vendor",         "kind": "directory", "reason": "symlinked directory not followed" }
]
```

`kind` is one of `file` (a C# file, project file or `.nuspec`), `directory` (a directory
the walk could not list, or a symlinked directory it refused to follow — every file
inside it is then in no list at all), `assembly` (a package or output DLL whose metadata
could not be read, or one the artefact lists that the package folder lacks), `assets` (an
unparseable `project.assets.json` or `packages.lock.json`) or `deps` (an unparseable
`*.deps.json`). `file` is relative to the target whenever the path is under it; a
package-cache assembly or `.nuspec` outside the tree keeps its absolute path (POSIX
separators). `reason` says how far the tool got and carries **nothing machine-specific**:
a filesystem failure is a fixed phrase (`not found`, `access denied`), never the raw
exception text with the machine's path in it; a parser failure keeps its position inside
the document. An unparseable artefact leaves its project's `closure` omitted rather than
empty, an unreadable package assembly leaves that package's `namespaces` omitted, and a
listed-but-missing assembly means the `namespaces` read from its siblings are not the
package's complete set — the failure is never read as "nothing there".

## License

Apache-2.0 — see [LICENSE](LICENSE).
