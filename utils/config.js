/**
 * Configuration loader and merger
 * Loads options from .nuget-checkrc.json if it exists
 */

const fs = require('fs');
const path = require('path');

/**
 * Load configuration from .nuget-checkrc.json
 * @param {string} configPath - Path to config file (defaults to current directory)
 * @returns {Object} Configuration object
 */
function loadConfig(configPath = '.nuget-checkrc.json') {
  const fullPath = path.resolve(configPath);

  try {
    if (fs.existsSync(fullPath)) {
      const data = fs.readFileSync(fullPath, 'utf-8');
      return JSON.parse(data);
    }
  } catch {
    // Silently ignore config load errors
  }

  return {};
}

/**
 * Merge CLI arguments with config file options
 * CLI arguments take precedence over config file
 * @param {Object} cliArgs - CLI arguments
 * @param {string} configFile - Path to config file
 * @returns {Object} Merged configuration
 */
function mergeConfig(cliArgs, configFile = '.nuget-checkrc.json') {
  const fileConfig = loadConfig(configFile);

  return {
    format: cliArgs.format || fileConfig.format || 'summary',
    severity: cliArgs.severity || fileConfig.severity || null,
    cache: cliArgs.cache !== undefined ? cliArgs.cache : (fileConfig.cache !== undefined ? fileConfig.cache : false),
    logLevel: cliArgs.logLevel || fileConfig.logLevel || 'info',
    verbose: cliArgs.verbose || fileConfig.verbose || false,
    useRest: cliArgs.useRest !== undefined ? cliArgs.useRest : (fileConfig.useRest !== undefined ? fileConfig.useRest : false)
  };
}

/**
 * Get default configuration
 * @returns {Object} Default configuration
 */
function getDefaults() {
  return {
    format: 'summary',
    severity: null,
    cache: false,
    logLevel: 'info',
    verbose: false,
    useRest: false
  };
}

/**
 * Validate configuration
 * @param {Object} config - Configuration to validate
 * @returns {Array} Array of validation errors (empty if valid)
 */
function validate(config) {
  const errors = [];

  if (config.format && !['json', 'table', 'summary'].includes(config.format)) {
    errors.push(`Invalid format: ${config.format}. Must be one of: json, table, summary`);
  }

  if (config.severity && !['high', 'medium', 'low'].includes(config.severity)) {
    errors.push(`Invalid severity: ${config.severity}. Must be one of: high, medium, low`);
  }

  if (config.logLevel && !['debug', 'info', 'warn', 'error'].includes(config.logLevel)) {
    errors.push(`Invalid logLevel: ${config.logLevel}. Must be one of: debug, info, warn, error`);
  }

  return errors;
}

module.exports = {
  loadConfig,
  mergeConfig,
  getDefaults,
  validate
};
