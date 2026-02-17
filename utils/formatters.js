/**
 * Output formatters for different display modes
 */

/**
 * Format as JSON
 * @param {Array} packages - List of packages checked
 * @param {Object} results - Results with vulnerabilities
 * @returns {string} JSON formatted output
 */
function formatJSON(packages, results) {
  return JSON.stringify(results, null, 2);
}

/**
 * Format as table (text)
 * @param {Array} packages - List of packages checked
 * @param {Object} results - Results with vulnerabilities
 * @returns {string} Table formatted output
 */
function formatTable(packages, results) {
  let output = '\n┌─ NUGET AUDIT RESULTS ─────────────────────────────────┐\n';
  output += `│ Total Packages: ${String(results.totalPackages).padEnd(38)}│\n`;
  output += `│ Vulnerabilities Found: ${String(results.vulnerabilityCount).padEnd(31)}│\n`;
  output += '├────────────────────────────────────────────────────────┤\n';

  if (results.vulnerabilities.length === 0) {
    output += '│ ✓ All packages are secure                              │\n';
  } else {
    results.vulnerabilities.forEach((vuln, idx) => {
      output += `│ ${idx + 1}. ${vuln.id} (${vuln.version})${' '.repeat(Math.max(0, 47 - (vuln.id.length + vuln.version.length + 5)))}│\n`;
      vuln.issues.forEach(issue => {
        const severity = `[${issue.severity}]`.padEnd(7);
        output += `│    ${severity} ${issue.summary.substring(0, 42)}│\n`;
      });
    });
  }

  output += '└────────────────────────────────────────────────────────┘\n';
  return output;
}

/**
 * Format as summary (brief text)
 * @param {Array} packages - List of packages checked
 * @param {Object} results - Results with vulnerabilities
 * @returns {string} Summary formatted output
 */
function formatSummary(packages, results) {
  let output = `\nFound ${results.totalPackages} packages in audit.\n`;

  if (results.vulnerabilityCount === 0) {
    output += '✓ All packages are secure - no known vulnerabilities found.\n';
  } else {
    output += `⚠ Found ${results.vulnerabilityCount} package(s) with known vulnerabilities:\n\n`;
    results.vulnerabilities.forEach(vuln => {
      output += `  • ${vuln.id} (${vuln.version})\n`;
      output += `    Issues: ${vuln.issues.length} | Severity: ${vuln.issues.map(i => i.severity).join(', ')}\n`;
    });
  }

  output += '\n';
  return output;
}

/**
 * Get formatter function by name
 * @param {string} format - Format type: json, table, summary
 * @returns {Function} Formatter function
 */
function getFormatter(format = 'summary') {
  switch (format.toLowerCase()) {
    case 'json':
      return formatJSON;
    case 'table':
      return formatTable;
    case 'summary':
    default:
      return formatSummary;
  }
}

module.exports = {
  formatJSON,
  formatTable,
  formatSummary,
  getFormatter
};
