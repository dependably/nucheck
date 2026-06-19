# nuget-check

A command-line tool and Node.js library that audits NuGet packages for known vulnerabilities, similar to `npm audit`.

## Purpose

**nuget-check** scans your NuGet project dependencies (defined in `packages.config` or `packages.lock.json`) against GitHub's Vulnerability Database to identify known security vulnerabilities. This enables .NET developers to proactively discover and address security issues in their project dependencies.

## Features

- **Vulnerability Detection**: Identifies known vulnerabilities in your NuGet packages
- **Semantic Versioning Support**: Uses semver matching to determine if installed versions are affected by vulnerabilities
- **GitHub Integration**: Queries the official GitHub Vulnerability Database for authoritative vulnerability data
- **Detailed Reporting**: Multiple output formats (summary, table, JSON)
- **Query Modes**: Supports both GraphQL (default) and REST API modes
- **Flexible Output**: Format results as summary, table, or JSON
- **Caching**: In-memory and optional file-based caching to reduce API calls
- **Structured Logging**: Debug-friendly logging with configurable levels
- **Configuration Files**: Load options from `.nuget-checkrc.json`
- **Severity Filtering**: Filter vulnerabilities by severity level
- **packages.lock.json Support**: Works with both packages.config (XML) and packages.lock.json (JSON)

## Installation

### Global (CLI)

```bash
npm install -g @moonlitlabs/nuget-check
nuget-check ./packages.config
```

### Local (Project)

```bash
npm install @moonlitlabs/nuget-check
```

### Development

```bash
git clone https://gitlab.northwardlabs.ca/moonlitlabs/nuget-check.git
cd nuget-check
npm install
npm test
```

## Quick Start

### 1. Set GitHub Token

```bash
export GITHUB_TOKEN=your_github_personal_access_token
```

### 2. Run Audit

```bash
nuget-check ./packages.config
```

### 3. Check Results

The tool will report:
- Total number of packages found
- Packages with vulnerabilities and their details
- Severity levels for each vulnerability
- Reference links for more information

## Usage

### Basic Command

```bash
nuget-check <path-to-packages-file> [options]
```

### Examples

```bash
# Basic audit with summary output
nuget-check ./packages.config

# JSON output for parsing
nuget-check ./packages.config --format json

# Table output for readability
nuget-check ./packages.config --format table

# Filter by severity
nuget-check ./packages.config --severity high

# Enable caching and verbose logging
nuget-check ./packages.config --cache --log-level debug

# Use REST API instead of GraphQL
nuget-check ./packages.config --rest

# Load options from config file
nuget-check ./packages.config --config ./.nuget-checkrc.json
```

### CLI Options

```
--format <type>            Output format: summary, table, json (default: summary)
--severity <level>         Filter by severity: high, medium, low
--cache                    Enable caching of vulnerability data
--no-cache                 Disable caching
--log-level <level>        Logging level: debug, info, warn, error (default: info)
--verbose, -v              Enable verbose output
--config <path>            Path to .nuget-checkrc.json config file
--rest                     Use REST API instead of GraphQL
--help, -h                 Show help message
```

### Example Output

#### Summary Format (default)
```
Found 8 packages in ./packages.config
⚠ Found 3 package(s) with known vulnerabilities:

  • Newtonsoft.Json (11.0.2)
    Issues: 1 | Severity: high

  • log4net (2.0.8)
    Issues: 2 | Severity: high, medium
```

#### Table Format
```
┌─ NUGET AUDIT RESULTS ─────────────────────────────────┐
│ Total Packages: 8                                       │
│ Vulnerabilities Found: 3                                │
├────────────────────────────────────────────────────────┤
│ 1. Newtonsoft.Json (11.0.2)                            │
│    [HIGH] Remote code execution vulnerability          │
```

#### JSON Format
```json
{
  "totalPackages": 8,
  "vulnerabilities": [
    {
      "id": "Newtonsoft.Json",
      "version": "11.0.2",
      "issues": [
        {
          "summary": "Remote code execution",
          "severity": "high"
        }
      ]
    }
  ],
  "vulnerabilityCount": 3
}
```

## Configuration

### Environment Variables

- **GITHUB_TOKEN** (required): Your GitHub personal access token
  - Get one at: https://github.com/settings/tokens
  - Required scopes: `security_events` (or full `public_repo` access)

- **USE_REST** (optional): Set to `true` to use REST API instead of GraphQL

### Configuration File (.nuget-checkrc.json)

Create a `.nuget-checkrc.json` in your project root:

```json
{
  "format": "summary",
  "severity": null,
  "cache": true,
  "logLevel": "info",
  "verbose": false,
  "useRest": false
}
```

CLI arguments override configuration file settings.

### GitHub Token Setup

#### On macOS/Linux:

```bash
# 1. Create token at https://github.com/settings/tokens
# 2. Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export GITHUB_TOKEN=ghp_your_token_here

# 3. Reload shell
source ~/.bashrc
```

#### On Windows (PowerShell):

```powershell
# 1. Create token at https://github.com/settings/tokens
# 2. Set environment variable
$env:GITHUB_TOKEN="ghp_your_token_here"

# 3. For persistent storage
[Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "ghp_your_token_here", "User")
```

## Programmatic Usage

See [docs/API.md](./docs/API.md) for complete API documentation.

### Basic Example

```javascript
const { audit } = require('@moonlitlabs/nuget-check');

process.env.GITHUB_TOKEN = 'your_token';

audit('./packages.config', {
  logLevel: 'info',
  enableCache: true
}).then(results => {
  console.log(`Found ${results.vulnerabilityCount} vulnerabilities`);
  process.exit(results.vulnerabilityCount > 0 ? 1 : 0);
}).catch(err => {
  console.error('Audit failed:', err);
  process.exit(1);
});
```

## Requirements

- Node.js 12.x or higher
- npm or yarn
- GitHub personal access token
- `packages.config` or `packages.lock.json` file

## Dependencies

- `node-fetch`: HTTP client for API requests
- `xml2js`: XML parsing for packages.config
- `semver`: Semantic version matching

## Troubleshooting

### GITHUB_TOKEN not set

```
Error: GITHUB_TOKEN environment variable is not set
```

**Solution:** Set your GitHub token
```bash
export GITHUB_TOKEN=your_token
```

### 401 Unauthorized

```
GitHub API authentication failed. Check GITHUB_TOKEN.
```

**Solution:**
1. Verify your token is valid at https://github.com/settings/tokens
2. Check token has required permissions
3. Token may have expired - generate a new one

### Failed to read packages.config

```
Error: File not found: ./packages.config
```

**Solution:**
1. Verify the file path is correct
2. Use absolute path if needed: `nuget-check /full/path/to/packages.config`
3. Check file exists: `ls packages.config`

### GitHub API rate limits

```
GitHub API error: 403
```

**Solution:**
- Authenticated requests have higher limits (5,000 per hour)
- Use `--cache` flag to avoid repeated queries
- Consider staggering audits over time

### No vulnerabilities detected

This is good! It means:
- All packages are up to date
- No known vulnerabilities exist in the database
- Continue monitoring for new vulnerabilities

## Development

### Running Tests

```bash
npm test              # Run all tests
npm run test:watch   # Run tests in watch mode
```

### Building

No build step required. The project runs directly with Node.js.

### Project Structure

```
nuget-check/
├── index.js              # Core audit logic
├── cli.js                # CLI entry point
├── package.json          # Dependencies
├── jest.config.js        # Test configuration
├── utils/
│   ├── logger.js         # Structured logging
│   ├── cache.js          # Vulnerability caching
│   ├── config.js         # Configuration loader
│   └── formatters.js     # Output formatters
├── tests/                # Test suite
├── docs/
│   └── API.md           # API documentation
├── examples/
│   └── packages.config  # Example package file
├── README.md            # This file
├── CONTRIBUTING.md      # Contributing guide
└── LICENSE              # MIT License
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

MIT - See [LICENSE](./LICENSE) file for details

## Changelog

### Version 1.0.0 (Initial Release)

- Core vulnerability audit functionality
- GraphQL and REST API support
- Multiple output formats
- Configuration file support
- Caching system
- Structured logging
- Comprehensive documentation
- Full test suite

## Support

- **Issues:** Report bugs at https://gitlab.northwardlabs.ca/moonlitlabs/nuget-check/-/issues
- **Questions:** Ask at https://gitlab.northwardlabs.ca/moonlitlabs/nuget-check/-/issues
- **Security:** Report vulnerabilities privately at security@example.com

## Related Projects

- [npm audit](https://docs.npmjs.com/cli/audit) - Similar tool for npm packages
- [GitHub Security Advisory Database](https://github.com/advisories) - Vulnerability source
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) - Comprehensive dependency scanner

---

**Made with ❤️ for .NET developers**
