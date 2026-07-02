# Examples

These files are **intentional demo fixtures** for trying out `nucheck` — not real
projects, and not dependencies of this tool.

- **`packages.config`** pins a handful of packages to deliberately **old, known-vulnerable
  versions** (e.g. `Newtonsoft.Json 11.0.2`, `log4net 2.0.8`) so a run produces visible
  findings. A dependency scanner pointed at this repo may flag these — that is expected;
  they exist only to demonstrate `nucheck`'s output and are never restored or built.

Try it:

```bash
export GITHUB_TOKEN=your_token          # or use --source osv (no token)
nucheck ./examples/packages.config
nucheck ./examples/packages.config --source osv --format table
```
