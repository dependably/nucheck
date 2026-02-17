# nuget-audit

A command-line tool that audits NuGet packages for known vulnerabilities, similar to `npm audit`.

## Purpose

**nuget-audit** scans your NuGet project dependencies (defined in `packages.config`) against GitHub's Vulnerability Database to identify known security vulnerabilities. This enables .NET developers to proactively discover and address security issues in their project dependencies.

## Features

- **Vulnerability Detection**: Identifies known vulnerabilities in your NuGet packages
- **Semantic Versioning Support**: Uses semver matching to determine if installed versions are affected by vulnerabilities
- **GitHub Integration**: Queries the official GitHub Vulnerability Database for authoritative vulnerability data
- **Detailed Reporting**: Displays vulnerability summaries, severity levels, and reference links
- **Two Query Modes**: Supports both GraphQL (default) and REST API modes for flexibility

## Installation

```bash
npm install -g nuget-audit
```

Or install locally in your project:

```bash
npm install nuget-audit
```

## Usage

### Basic Usage

```bash
nuget-audit <path-to-packages.config>
```

Example:

```bash
nuget-audit ./packages.config
```

### Output

The tool will report:
- Total number of packages found
- Status for each package (vulnerable or safe)
- For vulnerabilities: summary, severity level, and reference URLs

Example output:

```
Found 5 packages in ./packages.config

=== Vulnerability found for SomePackage (1.0.0) ===
- Remote Code Execution vulnerability (Severity: high)
  * https://github.com/advisories/GHSA-xxxx-yyyy-zzzz

✓ SafePackage (2.1.0) - no known vulnerabilities
```

## Configuration

### GitHub API Authentication

The tool uses GitHub's API to query vulnerabilities. You must set the `GITHUB_TOKEN` environment variable:

```bash
export GITHUB_TOKEN=your_github_personal_access_token
nuget-audit ./packages.config
```

Generate a token at: https://github.com/settings/tokens

### API Mode

By default, the tool uses GitHub's GraphQL API. To use the REST API instead, set the `USE_REST` environment variable:

```bash
USE_REST=true nuget-audit ./packages.config
```

## Requirements

- Node.js 12.x or higher
- A `packages.config` file from your .NET project
- GitHub personal access token for API authentication

## Dependencies

- `node-fetch`: HTTP client for API requests
- `xml2js`: XML parsing for packages.config
- `semver`: Semantic version matching

## License

MIT
