# Contributing to nucheck

Thanks for contributing! This is a native .NET tool — here's how to get set up.

## Prerequisites

- .NET SDK **10.0+** (`dotnet --version`).
- A `GITHUB_TOKEN` env var if you want to run the tool end-to-end against the live
  Advisory API (not needed for the unit tests, which fake all HTTP).

## Setup

```bash
git clone https://github.com/dependably/nucheck.git
cd nucheck
git config core.hooksPath .githooks   # install the pre-commit hook
dotnet restore Dependably.NuCheck.slnx
```

Dependencies restore from public `nuget.org` only (see `NuGet.config`), so no
private-feed auth is needed to build.

## Day-to-day

```bash
dotnet build Dependably.NuCheck.slnx -c Release
dotnet test  Dependably.NuCheck.slnx -c Release
dotnet format Dependably.NuCheck.slnx --verify-no-changes   # style gate (CI runs this)
dotnet run --project src/Dependably.NuCheck -- ./examples/packages.config
```

Coverage locally:

```bash
dotnet test Dependably.NuCheck.slnx -c Release \
  --settings coverlet.runsettings --collect:"XPlat Code Coverage" --results-directory ./coverage
```

## Guidelines

- **Format**: `dotnet format` must report no changes — it's a hard CI gate.
- **Tests**: add/extend xUnit tests for any behavior change; keep line coverage
  ≥ 80% (the project sits well above that). Fake HTTP with `FakeHttpMessageHandler`
  and the advisory source with `FakeAdvisorySource` — don't hit the network in tests.
- **Keep functions small**: SonarQube gates cognitive complexity; the parser and
  matcher are deliberately table-/switch-driven to stay simple.
- **Architecture**: see [docs/API.md](docs/API.md). New manifest formats go in
  `PackageFileReader`; new advisory sources implement `IAdvisorySource`.

## Pull requests

`main` is protected. Branch, push, and open a merge request. The MR pipeline runs
build + tests + `dotnet format`; SonarQube analysis runs on `main` after merge.

## License

By contributing you agree your contributions are licensed under the Apache License, Version 2.0.
