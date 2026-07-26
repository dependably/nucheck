# Vendored conformance corpus

Copied from the Dependably spec repository. Do not edit these files here — a change made in
this copy is invisible to every other tool and will be overwritten by the next sync. Change
the spec repository instead, then re-run the sync.

| | |
|---|---|
| Source | https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec.git |
| Ref | `main` |
| Commit | `55ba249cce35473690942e5842c2753eee10c4a2` |
| Committed | 2026-07-26T09:10:53-07:00 |

Re-sync with:

```bash
git clone --depth 1 https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec.git /tmp/dependably-spec
/tmp/dependably-spec/tools/vendor.sh tests/Dependably.NuCheck.Tests/conformance main
```

`corpus.sha256` beside this file records a checksum for every vendored file, written at
copy time. CI verifies the copy against it without needing to reach this repository, so drift
is caught on every pipeline rather than only when someone thinks to look.

A newer upstream commit is not automatically a problem: this copy pins the contract version
this tool is tested against. Update deliberately, and re-run the tool's test suite.
