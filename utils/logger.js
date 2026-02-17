/**
 * Structured logging utility with configurable log levels.
 * Supports: debug, info, warn, error
 */

const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

let currentLogLevel = LOG_LEVELS.info; // Default level

/**
 * Set the current log level
 * @param {string} level - One of: debug, info, warn, error
 */
function setLogLevel(level) {
  if (level in LOG_LEVELS) {
    currentLogLevel = LOG_LEVELS[level];
  }
}

/**
 * Format log message with timestamp and context
 * @param {string} level - Log level (debug, info, warn, error)
 * @param {string} context - Context/module name
 * @param {string} message - The log message
 * @returns {string} Formatted log message
 */
function formatLogMessage(level, context, message) {
  const timestamp = new Date().toISOString();
  const levelUpper = level.toUpperCase().padEnd(5);
  return `[${timestamp}] [${levelUpper}] [${context}] ${message}`;
}

/**
 * Log a debug message
 * @param {string} context - Context/module name
 * @param {string} message - The log message
 */
function debug(context, message) {
  if (currentLogLevel <= LOG_LEVELS.debug) {
    console.log(formatLogMessage('debug', context, message));
  }
}

/**
 * Log an info message
 * @param {string} context - Context/module name
 * @param {string} message - The log message
 */
function info(context, message) {
  if (currentLogLevel <= LOG_LEVELS.info) {
    console.log(formatLogMessage('info', context, message));
  }
}

/**
 * Log a warning message
 * @param {string} context - Context/module name
 * @param {string} message - The log message
 */
function warn(context, message) {
  if (currentLogLevel <= LOG_LEVELS.warn) {
    console.warn(formatLogMessage('warn', context, message));
  }
}

/**
 * Log an error message
 * @param {string} context - Context/module name
 * @param {string} message - The log message
 */
function error(context, message) {
  if (currentLogLevel <= LOG_LEVELS.error) {
    console.error(formatLogMessage('error', context, message));
  }
}

module.exports = {
  setLogLevel,
  debug,
  info,
  warn,
  error
};
