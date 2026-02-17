#!/usr/bin/env node

const path = require('path');
const fs = require('fs');
const { audit } = require('./index');
const config = require('./utils/config');
const { getFormatter } = require('./utils/formatters');

/**
 * Parse CLI arguments
 * @param {Array} args - Process arguments
 * @returns {Object} Parsed arguments
 */
function parseArgs(args) {
  const parsed = {
    filePath: null,
    format: 'summary',
    severity: null,
    cache: false,
    logLevel: 'info',
    verbose: false,
    useRest: false,
    configFile: '.nuget-auditrc.json'
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--format' && args[i + 1]) {
      parsed.format = args[++i];
    } else if (arg === '--severity' && args[i + 1]) {
      parsed.severity = args[++i];
    } else if (arg === '--cache') {
      parsed.cache = true;
    } else if (arg === '--no-cache') {
      parsed.cache = false;
    } else if (arg === '--log-level' && args[i + 1]) {
      parsed.logLevel = args[++i];
    } else if (arg === '--verbose' || arg === '-v') {
      parsed.verbose = true;
    } else if (arg === '--config' && args[i + 1]) {
      parsed.configFile = args[++i];
    } else if (arg === '--rest') {
      parsed.useRest = true;
    } else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (!arg.startsWith('-') && !parsed.filePath) {
      parsed.filePath = arg;
    }
  }

  return parsed;
}

/**
 * Print help message
 */
function printHelp() {
  console.log(`
nuget-audit - NuGet vulnerability auditor

Usage:
  nuget-audit <path-to-packages-file> [options]

Arguments:
  <path-to-packages-file>    Path to packages.config or packages.lock.json

Options:
  --format <type>            Output format: summary, table, json (default: summary)
  --severity <level>         Filter by severity: high, medium, low
  --cache                    Enable caching of vulnerability data
  --log-level <level>        Logging level: debug, info, warn, error (default: info)
  --verbose, -v              Enable verbose output
  --config <path>            Path to .nuget-auditrc.json config file
  --rest                     Use REST API instead of GraphQL
  --help, -h                 Show this help message

Environment Variables:
  GITHUB_TOKEN               GitHub personal access token (required)
  USE_REST                   Use REST API when true (overrides --rest flag)

Examples:
  nuget-audit ./packages.config
  nuget-audit ./packages.lock.json --format json
  nuget-audit ./packages.config --cache --log-level debug
  nuget-audit ./packages.config --severity high
  `);
}

/**
 * Format and print results
 * @param {Object} results - Audit results
 * @param {string} format - Output format
 * @param {string} severity - Severity filter
 */
function printResults(results, format, severity) {
  // Filter by severity if specified
  let filteredResults = results;
  if (severity) {
    filteredResults = {
      ...results,
      vulnerabilities: results.vulnerabilities.map(vuln => ({
        ...vuln,
        issues: vuln.issues.filter(issue => issue.severity === severity)
      })).filter(vuln => vuln.issues.length > 0),
      vulnerabilityCount: results.vulnerabilities
        .flatMap(v => v.issues)
        .filter(issue => issue.severity === severity)
        .length
    };
  }

  const formatter = getFormatter(format);

  if (format === 'json') {
    console.log(formatter([], filteredResults));
  } else {
    process.stdout.write(formatter([], filteredResults));
  }
}

/**
 * Main entry point
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    printHelp();
    process.exit(1);
  }

  // Parse CLI arguments
  const cliArgs = parseArgs(args);

  if (!cliArgs.filePath) {
    console.error('Error: Path to packages file is required');
    process.exit(1);
  }

  // Check for GitHub token
  if (!process.env.GITHUB_TOKEN) {
    console.error('Error: GITHUB_TOKEN environment variable is not set');
    console.error('Please set GITHUB_TOKEN to your GitHub personal access token');
    console.error('Get a token at: https://github.com/settings/tokens');
    process.exit(1);
  }

  // Merge with config file
  const mergedConfig = config.mergeConfig(cliArgs, cliArgs.configFile);

  // Validate configuration
  const errors = config.validate(mergedConfig);
  if (errors.length > 0) {
    console.error('Configuration errors:');
    errors.forEach(err => console.error(`  - ${err}`));
    process.exit(1);
  }

  // Run audit
  const configPath = path.resolve(cliArgs.filePath);

  try {
    const auditOptions = {
      logLevel: mergedConfig.logLevel,
      enableCache: mergedConfig.cache,
      fileCacheEnabled: mergedConfig.cache,
      verbose: mergedConfig.verbose
    };

    if (mergedConfig.useRest) {
      process.env.USE_REST = 'true';
    }

    const results = await audit(configPath, auditOptions);
    printResults(results, mergedConfig.format, mergedConfig.severity);

    // Exit with error code if vulnerabilities found
    if (results.vulnerabilityCount > 0) {
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
