# API Documentation

## Overview

nuget-audit provides a Node.js API for programmatically auditing NuGet package dependencies for known vulnerabilities.

## Installation

```bash
npm install nuget-audit
```

## Basic Usage

```javascript
const { audit } = require('nuget-audit');

// Set GitHub token
process.env.GITHUB_TOKEN = 'your_token_here';

// Run audit
audit('./packages.config').catch(err => {
  console.error('Audit failed:', err);
  process.exit(1);
});
```

## API Functions

### `audit(filePath, options)`

Audits a packages.config or packages.lock.json file for vulnerabilities.

**Parameters:**
- `filePath` (string): Path to packages.config or packages.lock.json
- `options` (Object, optional): Configuration options
  - `logLevel` (string): Log level - 'debug', 'info', 'warn', 'error' (default: 'info')
  - `enableCache` (boolean): Enable in-memory caching (default: false)
  - `fileCacheEnabled` (boolean): Enable file-based caching (default: false)
  - `verbose` (boolean): Enable verbose output (default: false)

**Returns:** Promise<Object>
- `totalPackages` (number): Total number of packages audited
- `vulnerabilities` (Array): List of packages with vulnerabilities
- `vulnerabilityCount` (number): Total number of vulnerabilities found

**Example:**

```javascript
const { audit } = require('nuget-audit');

process.env.GITHUB_TOKEN = 'ghp_your_token';

audit('./packages.config', {
  logLevel: 'info',
  enableCache: true
}).then(results => {
  console.log(`Found ${results.vulnerabilityCount} vulnerabilities`);
  results.vulnerabilities.forEach(vuln => {
    console.log(`${vuln.id}@${vuln.version}:`);
    vuln.issues.forEach(issue => {
      console.log(`  - ${issue.summary} (${issue.severity})`);
    });
  });
}).catch(err => {
  console.error('Audit failed:', err);
});
```

### `readPackagesFile(filePath)`

Reads and parses a packages.config or packages.lock.json file.

**Parameters:**
- `filePath` (string): Path to the packages file

**Returns:** Promise<Array<Object>>
- Each object contains:
  - `id` (string): Package ID
  - `version` (string): Package version

**Throws:** Error if file not found or invalid format

**Example:**

```javascript
const { readPackagesFile } = require('nuget-audit');

readPackagesFile('./packages.config').then(packages => {
  packages.forEach(pkg => {
    console.log(`${pkg.id}@${pkg.version}`);
  });
}).catch(err => {
  console.error('Error reading packages:', err);
});
```

### `queryVulnerability(packageId, version)`

Queries the GitHub Vulnerability Database for a specific package.

**Parameters:**
- `packageId` (string): NuGet package ID
- `version` (string): Package version

**Returns:** Promise<Object|null>
- Returns null if no vulnerabilities found
- Returns array of vulnerability objects with:
  - `advisory.summary` (string): Vulnerability description
  - `advisory.severity` (string): Severity level
  - `advisory.references` (Array): Reference URLs
  - `vulnerableVersionRange` (string): Affected version range

**Example:**

```javascript
const { queryVulnerability } = require('nuget-audit');

process.env.GITHUB_TOKEN = 'ghp_your_token';

queryVulnerability('Newtonsoft.Json', '11.0.2').then(vulns => {
  if (vulns) {
    console.log('Vulnerabilities found:');
    vulns.forEach(v => {
      console.log(`- ${v.advisory.summary}`);
    });
  } else {
    console.log('No vulnerabilities found');
  }
}).catch(err => {
  console.error('Query failed:', err);
});
```

### `queryVulnerabilityREST(packageId, version)`

Queries using GitHub's REST API (alternative to GraphQL).

**Parameters:**
- `packageId` (string): NuGet package ID
- `version` (string): Package version

**Returns:** Promise<Object|null>

**Example:**

```javascript
const { queryVulnerabilityREST } = require('nuget-audit');

process.env.GITHUB_TOKEN = 'ghp_your_token';

queryVulnerabilityREST('log4net', '2.0.8').then(vulns => {
  console.log(vulns);
}).catch(err => {
  console.error('REST query failed:', err);
});
```

### `initialize(options)`

Initialize the audit system with configuration options.

**Parameters:**
- `options` (Object):
  - `logLevel` (string): Set logging level
  - `enableCache` (boolean): Enable caching

**Example:**

```javascript
const { initialize, audit } = require('nuget-audit');

initialize({
  logLevel: 'debug',
  enableCache: true
});

audit('./packages.config');
```

## Configuration Options

### Environment Variables

- `GITHUB_TOKEN` (required): GitHub personal access token
- `USE_REST` (optional): Set to 'true' to use REST API instead of GraphQL

### Configuration File (.nuget-auditrc.json)

Create a `.nuget-auditrc.json` file in your project root:

```json
{
  "format": "json",
  "severity": null,
  "cache": true,
  "logLevel": "info",
  "verbose": false,
  "useRest": false
}
```

Options:
- `format`: Output format (json, table, summary)
- `severity`: Filter by severity (high, medium, low, or null for all)
- `cache`: Enable caching (true/false)
- `logLevel`: Logging level (debug, info, warn, error)
- `verbose`: Verbose output (true/false)
- `useRest`: Use REST API (true/false)

## Caching

The caching system supports both in-memory and file-based caching:

**In-Memory Cache:**
- Stores results for the duration of the audit
- Reduces API calls for duplicate packages

**File-Based Cache:**
- Persists results in `.nuget-audit-cache/` directory
- Results expire after 24 hours
- Useful for recurring audits

**Example:**

```javascript
const { audit } = require('nuget-audit');

process.env.GITHUB_TOKEN = 'ghp_your_token';

audit('./packages.config', {
  enableCache: true,
  fileCacheEnabled: true  // Enable persistent caching
});
```

## Error Handling

```javascript
const { audit } = require('nuget-audit');

audit('./packages.config').catch(err => {
  if (err.message.includes('File not found')) {
    console.error('Package file does not exist');
  } else if (err.message.includes('Failed to parse')) {
    console.error('Invalid package file format');
  } else {
    console.error('Unexpected error:', err);
  }
  process.exit(1);
});
```

## Logging

The logger provides structured logging with different levels:

```javascript
const logger = require('./utils/logger');

logger.debug('module-name', 'Debug message');
logger.info('module-name', 'Info message');
logger.warn('module-name', 'Warning message');
logger.error('module-name', 'Error message');
```

Set log level programmatically:

```javascript
const logger = require('./utils/logger');
logger.setLogLevel('debug');
```

## Output Formatting

Supported output formats:

**Summary (default):**
```
Found 5 packages in audit.
⚠ Found 2 package(s) with known vulnerabilities:

  • Newtonsoft.Json (11.0.2)
    Issues: 1 | Severity: high
```

**Table:**
```
┌─ NUGET AUDIT RESULTS ─────────────────────────────────┐
│ Total Packages: 5                                       │
│ Vulnerabilities Found: 2                                │
├────────────────────────────────────────────────────────┤
│ 1. Newtonsoft.Json (11.0.2)                            │
│    [HIGH] Vulnerable to injection attacks              │
```

**JSON:**
```json
{
  "totalPackages": 5,
  "vulnerabilities": [...],
  "vulnerabilityCount": 2
}
```

## License

MIT
