# `.dependably` conformance fixtures

Language-neutral test cases that pin the behavior in
[`docs/dependably-config-spec.md`](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec/-/blob/main/docs/dependably-config-spec.md). Every Dependably
tool (npm-check in JS; nucheck, cslint, codemetrics and pdbcheck in C#; pycheck in Python)
vendors this directory and runs each case through a thin per-language adapter. Same fixtures,
one contract, three runtimes — this is what keeps the implementations from drifting.

## Two kinds of case

**Vocabulary-bound** cases carry `"tool": "$any"`. Nothing in them is spelled in one tool's
words: the section key, the alias key and the rule ids are placeholders that the adapter
replaces with its own names before the case runs. These are replayed by every tool, as that
tool. 17 of the 29 cases are of this kind.

**Tool-specific** cases name a tool in their `tool` field and carry literal vocabulary. They
are listed, with the reason each is not `$any`, in
[Tool-specific cases](#tool-specific-cases) below. An adapter for a different tool replays
their grammar only: selectors are validated before the expiry format is, so replaying a
`package`-selector case under a tool that emits no `package` raises a selector error and
fails a case that is actually passing. Applicability is per-tool and belongs in that tool's
own tests.

## Binding the vocabulary

Spec §12 is normative; this is the operational summary an adapter implements.

An adapter supplies a **binding map** from placeholder to its own name, then walks the case's
`files`, `cli`, `findings` and `expect` subtrees replacing every string — object key or string
value — that is exactly a placeholder. Substitution is whole-string only. A placeholder is
never a fragment inside a longer string, so no adapter needs a tokenizer, and `$rule1` can
never accidentally match inside `$rule10`.

| Placeholder | Bind it to |
|-------------|------------|
| `$tool` | your tool's canonical section key — the same string as its command name |
| `$alias` | your tool's deprecated alias section key, if it has one |
| `$rule1` | any rule id from your tool's own rule-id registry |
| `$rule2` | a second rule id from that registry, different from `$rule1` |
| `$foreignRule` | a rule id from some *other* tool's registry that yours does not define |
| `$unknownRule` | a rule id no tool defines — `"no-such-rule"` is a safe choice |
| `$foreignKey` | a config key another tool defines (spec §7.1) and yours does not |

`$schema` is a real configuration key, not a placeholder. Leave it alone.

Worked example, `pdbcheck`:

```json
{
  "$tool": "pdbcheck",
  "$rule1": "missing-pdb",
  "$rule2": "source-link-unreachable",
  "$foreignRule": "cyclomatic",
  "$unknownRule": "no-such-rule",
  "$foreignKey": "ignoreUnusedPackages"
}
```

`pdbcheck` has no alias section key, so it binds no `$alias` and skips the two cases that
require one. `nucheck` binds `"$alias": "nuget"` and runs them.

Two rules an adapter **must** follow:

- **Fail on an unbindable placeholder.** Do not replay a case with a placeholder left in it.
  An unbound `$tool` becomes an unknown top-level section, which the spec requires be ignored
  silently — the case would pass while asserting nothing.
- **Report every skip.** See below.

## Declaring applicability

Not every behavior exists in every tool. A `$any` case may carry a `requires` array of
capability tokens:

```json
"requires": ["alias"]
```

| Capability | Your tool has |
|------------|---------------|
| `alias` | a deprecated alias section key in spec §3.3 |
| `packageSelector` | findings that carry a `package` |
| `pathSelector` | findings that carry a `path` |
| `symbolSelector` | findings that carry a `symbol` |
| `idSelector` | findings that carry an `id` |

An adapter whose tool lacks a listed capability **skips the case and says so**, naming the
case and the unmet capability in its output. A silent pass is exactly the failure this field
exists to prevent — a corpus that reports 29 green while running 12 is worse than one that
reports 12.

A case may instead carry `appliesTo`, an array of tool names, when it is genuinely about
named tools rather than about a capability. Prefer `requires`: a capability list stays correct
when a tool joins the suite, a name list does not.

## What is actually executed

Historically, not much. Every adapter in the suite collects two filename prefixes,
`exceptions-` and `validation-exception-`, which is 12 of the 29 cases. The other 17 — the
`discovery-`, `sections-`, `merge-` families and the non-exception `validation-` ones — were
replayed by nothing, and npm-check has no adapter at all.

The reason was never that those cases were wrong. It was that they were authored in
npm-check's words, so replaying one as pycheck failed on the section key before it reached
the behavior under test. Vocabulary binding removes that blocker: all 17 are now `$any` and
an adapter that implements the binding map above can run them as itself.

Implementing binding is the remaining work, and it is per-repository. Until an adapter widens
its collection beyond the two exception prefixes, those 17 cases still document the contract
rather than enforcing it. A case added here does not become a test until an adapter collects
it.

Nothing here breaks on sync. The 12 cases adapters run today are byte-for-byte unchanged, and
the 17 that changed were run by nothing. The order to finish the job is:

1. Every adapter grows a binding map and a skip-with-report path, and widens collection to all
   five filename groups. Each repository can do this independently; the corpus needs no change.
2. Once every adapter binds, the tool-specific 12 convert to `$any` here — a single spec-repo
   change that every adapter picks up on its next deliberate sync.

The one thing to check while doing step 1: an adapter that deserializes `tool` into a closed
set of tool names, rather than a string, must learn `$any` before it can load the corpus at
all. Filtering by filename before deserializing avoids the question.

## Tool-specific cases

These 12 are not `$any`. They are also, not coincidentally, exactly the 12 that adapters run
today: converting them would change bytes those adapters already read, so they stay literal
until every adapter carries a binder. Several are independently tool-specific for the reason
given.

| Case | Tool | Why it is not `$any` |
|------|------|----------------------|
| `exceptions-common-and-tool-union` | cslint | executed by every adapter today; convert once adapters bind |
| `exceptions-expired` | npm-check | executed by every adapter today; convert once adapters bind |
| `exceptions-id-advisory` | nucheck | pins an advisory-id selector against a vulnerability rule; needs `idSelector` and a rule whose findings carry GHSA ids |
| `exceptions-package-selector` | npm-check | executed by every adapter today; convert once adapters bind |
| `exceptions-package-version-pin` | nucheck | the `@version` pin needs a package-scoped rule whose findings carry a resolved version |
| `exceptions-path-and-symbol-and` | codemetrics | AND-matching needs one rule emitting both a `path` and a `symbol`; most tools emit only one |
| `exceptions-suppressed-still-counted` | npm-check | executed by every adapter today; convert once adapters bind |
| `exceptions-unused-warns` | npm-check | executed by every adapter today; convert once adapters bind |
| `validation-exception-bad-expires` | npm-check | executed by every adapter today; convert once adapters bind |
| `validation-exception-bad-selector-own-section` | npm-check | asserts a selector the tool never emits; which selector that is differs per tool |
| `validation-exception-missing-reason` | npm-check | executed by every adapter today; convert once adapters bind |
| `validation-exception-no-selector` | npm-check | executed by every adapter today; convert once adapters bind |

## Layout

- `cases/*.json` — one case per file.
- Cases are grouped by prefix: `discovery-*`, `sections-*`, `merge-*`, `exceptions-*`, `validation-*`.

## Case format

```jsonc
{
  "name": "merge-rules-per-id",
  "description": "Human summary of what this pins.",
  "tool": "$any",                   // "$any" = vocabulary-bound; or a tool name for a
                                    // tool-specific case
  "requires": ["alias"],            // optional: capabilities the replaying tool must have
  "appliesTo": ["nucheck"],         // optional escape hatch: explicit tool allowlist
  "today": "2026-07-03",            // fixed clock, for expiry determinism (optional)

  "files": {                        // written verbatim into a temp repo dir (a `.git`
    ".dependably": {                // dir is created so discovery stops at the boundary)
      "$tool": { "rules": { "$rule1": "error" } }
    }
  },
  "cli": { "config": null },        // optional: explicit --config <path> relative to the dir
  "startDir": null,                 // optional: subdir to begin the walk-up from (default: repo root)

  "findings": [                     // optional: synthetic findings fed to the matcher
    { "rule": "$rule1", "package": "esbuild", "path": "a.js", "symbol": null, "id": null }
  ],

  "expect": {
    "error": null,                  // null, or a spec §10 error code string
    "selectedFile": ".dependably",  // which file discovery picked (discovery cases)
    "warnings": ["DEPRECATED_FILENAME"],   // set of spec §11 warning codes (order-insensitive)

    "resolved": {                   // subset assertions on the merged config (present keys only)
      "rules": { "$rule1": "error" },
      "exclude": ["a/**", "b/**"],
      "allowedRegistryHosts": ["packages.dependably.dev"],
      "failOn": { "severity": "high", "count": 10 }
    },

    "suppressedFindings": [0],      // indices into `findings` that were suppressed
    "gated": false,                 // did the run trip its gate after suppression?
    "unusedExceptions": [1],        // indices into the resolved exceptions list
    "expiredExceptions": []
  }
}
```

An adapter reads a case, skips it if `requires`/`appliesTo` exclude its tool, binds the
placeholders, materializes `files` into a temp directory (adding an empty `.git/` so the
walk-up stops there), runs the tool's config load + (for `findings` cases) exception matcher
against the fixed `today`, and asserts each present `expect.*` key. Absent `expect` keys are
not asserted, so a case can target one axis without over-constraining.

## Warning and error codes

See spec §10 (errors) and §11 (warnings). Adapters map their tool's human messages to these
stable codes for assertion.

## Adding a case

Keep each case focused on one behavior. Write it as `$any` unless it genuinely cannot be —
and if it cannot, add a row to the tool-specific table above saying why, or the corpus
validator rejects it. Prefer the portable glob subset (`**`, `*`, `?`). Use `today` whenever
`expires` is involved so the case is stable over time.
