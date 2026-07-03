# `.dependably` conformance fixtures

Language-neutral test cases that pin the behavior in
[`docs/dependably-config-spec.md`](../../docs/dependably-config-spec.md). Every Dependably
tool (npm-check in JS, nucheck/cslint/codemetrics in C#, pycheck in Python) vendors this
directory and runs each case through a thin per-language adapter. Same fixtures, one
contract, three runtimes — this is what keeps the implementations from drifting.

## Layout

- `cases/*.json` — one case per file.
- Cases are grouped by prefix: `discovery-*`, `sections-*`, `merge-*`, `exceptions-*`, `validation-*`.

## Case format

```jsonc
{
  "name": "merge-rules-per-id",
  "description": "Human summary of what this pins.",
  "tool": "npm-check",              // which tool's resolution to exercise
  "today": "2026-07-03",           // fixed clock, for expiry determinism (optional)

  "files": {                        // written verbatim into a temp repo dir (a `.git`
    ".dependably": { /* object */ } // dir is created so discovery stops at the boundary)
  },
  "cli": { "config": null },        // optional: explicit --config <path> relative to the dir
  "startDir": null,                 // optional: subdir to begin the walk-up from (default: repo root)

  "findings": [                     // optional: synthetic findings fed to the matcher
    { "rule": "install-scripts", "package": "esbuild", "path": "a.js", "symbol": null, "id": null }
  ],

  "expect": {
    "error": null,                  // null, or a spec §10 error code string
    "selectedFile": ".dependably",  // which file discovery picked (discovery cases)
    "warnings": ["DEPRECATED_FILENAME"],   // set of spec §11 warning codes (order-insensitive)

    "resolved": {                   // subset assertions on the merged config (present keys only)
      "rules": { "no-git-deps": "error" },
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

An adapter reads a case, materializes `files` into a temp directory (adding an empty `.git/`
so the walk-up stops there), runs the tool's config load + (for `findings` cases) exception
matcher against the fixed `today`, and asserts each present `expect.*` key. Absent
`expect` keys are not asserted, so a case can target one axis without over-constraining.

## Warning and error codes

See spec §10 (errors) and §11 (warnings). Adapters map their tool's human messages to these
stable codes for assertion.

## Adding a case

Keep each case focused on one behavior. Prefer the portable glob subset (`**`, `*`, `?`).
Use `today` whenever `expires` is involved so the case is stable over time.
