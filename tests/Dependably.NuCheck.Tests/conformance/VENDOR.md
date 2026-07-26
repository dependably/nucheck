# Vendored conformance corpus

Copied from the Dependably spec repository. Do not edit these files here — a change made in
this copy is invisible to every other tool and will be overwritten by the next sync. Change
the spec repository instead, then re-run the sync.

| | |
|---|---|
| Source | https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec |
| Ref | `main` |
| Commit | `aa8782989ffd87ea66b65e677c2e7dbd739e0ccf` |

Re-sync with:

```bash
git clone --depth 1 https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec /tmp/dependably-spec
/tmp/dependably-spec/tools/vendor.sh tests/Dependably.NuCheck.Tests/conformance main
```

A newer upstream commit is not automatically a problem: this copy pins the contract version
this tool is tested against. Update deliberately, and re-run the test suite.
