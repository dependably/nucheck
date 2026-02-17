const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
const xml2js = require('xml2js');
const semver = require('semver');
const logger = require('./utils/logger');
const VulnerabilityCache = require('./utils/cache');

// Global cache instance
let cache = null;

/**
 * Initialize the audit system with options
 * @param {Object} options - Configuration options
 */
function initialize(options = {}) {
  if (options.logLevel) {
    logger.setLogLevel(options.logLevel);
  }

  if (options.enableCache) {
    cache = new VulnerabilityCache(options.fileCacheEnabled || false);
  }
}

/**
 * Reads a NuGet packages.config or packages.lock.json file
 * @param {string} filePath Path to packages file
 * @returns {Promise<Array<{ id: string, version: string }>>}
 * @throws {Error} If file doesn't exist or can't be parsed
 */
async function readPackagesFile(filePath) {
  // Validate input file exists
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  logger.debug('readPackagesFile', `Reading packages from ${filePath}`);

  const ext = path.extname(filePath).toLowerCase();

  try {
    if (ext === '.json') {
      // Parse packages.lock.json
      const data = fs.readFileSync(filePath, 'utf-8');
      const lockFile = JSON.parse(data);

      const packages = [];
      if (lockFile.dependencies) {
        Object.entries(lockFile.dependencies).forEach(([id, versionData]) => {
          packages.push({
            id: id,
            version: versionData.version || versionData
          });
        });
      }

      logger.debug('readPackagesFile', `Parsed ${packages.length} packages from packages.lock.json`);
      return packages;
    } else {
      // Parse packages.config (XML)
      const data = fs.readFileSync(filePath, 'utf-8');
      const parser = new xml2js.Parser();

      let result;
      try {
        result = await parser.parseStringPromise(data);
      } catch (err) {
        throw new Error(`Failed to parse XML: ${err.message}`);
      }

      const packages = result.packages.package || [];
      const parsed = packages.map(pkg => ({
        id: pkg.$.id,
        version: pkg.$.version
      }));

      logger.debug('readPackagesFile', `Parsed ${parsed.length} packages from packages.config`);
      return parsed;
    }
  } catch (err) {
    logger.error('readPackagesFile', `Error reading packages file: ${err.message}`);
    throw err;
  }
}

/**
 * Backward compatibility wrapper
 * @deprecated Use readPackagesFile instead
 */
async function readPackagesConfig(filePath) {
  return readPackagesFile(filePath);
}

/**
 * Queries GitHub REST API for vulnerability data
 * @param {string} packageId NuGet package ID
 * @param {string} version NuGet package version
 * @returns {Promise<Object|null>} Vulnerability data or null
 */
async function queryVulnerabilityREST(packageId, version) {
  logger.debug('queryVulnerabilityREST', `Querying REST API for ${packageId}@${version}`);

  try {
    const response = await fetch(
      `https://api.github.com/advisories?package_ecosystem=npm&package_name=${encodeURIComponent(packageId)}`,
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'Authorization': `Bearer ${process.env.GITHUB_TOKEN}`
        }
      }
    );

    if (!response.ok) {
      if (response.status === 401) {
        logger.warn('queryVulnerabilityREST', 'GitHub API authentication failed. Check GITHUB_TOKEN.');
      }
      return null;
    }

    const advisories = await response.json();
    if (!Array.isArray(advisories) || advisories.length === 0) {
      return null;
    }

    // Filter by version
    const matches = advisories.filter(advisory => {
      const range = advisory.vulnerable_version_range || '*';
      return semver.satisfies(version, range);
    });

    if (matches.length === 0) return null;

    return matches.map(adv => ({
      advisory: {
        summary: adv.summary,
        severity: adv.severity || 'unknown',
        references: [{ url: adv.html_url }]
      },
      vulnerableVersionRange: adv.vulnerable_version_range
    }));
  } catch (err) {
    logger.error('queryVulnerabilityREST', `REST API error: ${err.message}`);
    return null;
  }
}

/**
 * Queries the GitHub Vulnerability Database for a given package
 * @param {string} packageId NuGet package ID
 * @param {string} version NuGet package version
 * @returns {Promise<Object|null>} Vulnerability data or null if none found
 */
async function queryVulnerability(packageId, version) {
  // Check cache first
  if (cache) {
    const cached = cache.get(packageId, version);
    if (cached !== null) {
      logger.debug('queryVulnerability', `Cache hit for ${packageId}@${version}`);
      return cached;
    }
  }

  // Decide whether to use GraphQL or REST based on env var
  if (process.env.USE_REST === 'true') {
    const result = await queryVulnerabilityREST(packageId, version);
    if (cache) {
      cache.set(packageId, version, result);
    }
    return result;
  }

  const query = `{
    securityVulnerabilities(first: 10, package: {ecosystem: "NuGet", name: "${packageId}"}) {
      nodes {
        advisory {
          summary
          severity
          references {
            url
          }
        }
        vulnerableVersionRange
      }
    }
  }`;

  logger.debug('queryVulnerability', `Querying GraphQL for ${packageId}@${version}`);

  try {
    const response = await fetch('https://api.github.com/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GITHUB_TOKEN}`
      },
      body: JSON.stringify({ query })
    });

    if (!response.ok) {
      if (response.status === 401) {
        logger.warn('queryVulnerability', 'GitHub API authentication failed. Check GITHUB_TOKEN.');
      } else {
        logger.warn('queryVulnerability', `GitHub API error: ${response.status}`);
      }
      return null;
    }

    const json = await response.json();

    if (json.errors) {
      logger.warn('queryVulnerability', `GraphQL error: ${json.errors.map(e => e.message).join(', ')}`);
      return null;
    }

    const nodes = json.data?.securityVulnerabilities?.nodes;
    if (!nodes || nodes.length === 0) {
      return null;
    }

    // Filter by version range
    const matches = nodes.filter(node => semver.satisfies(version, node.vulnerableVersionRange));
    const result = matches.length > 0 ? matches : null;

    // Cache the result
    if (cache) {
      cache.set(packageId, version, result);
    }

    return result;
  } catch (err) {
    logger.error('queryVulnerability', `API request failed: ${err.message}`);
    return null;
  }
}

/**
 * Audits a packages file for vulnerabilities
 * @param {string} filePath Path to packages.config or packages.lock.json
 * @param {Object} options - Audit options
 * @returns {Promise<Object>} Audit results
 */
async function audit(filePath, options = {}) {
  initialize(options);

  logger.info('audit', `Starting vulnerability audit for ${filePath}`);

  let packages;
  try {
    packages = await readPackagesFile(filePath);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  console.log(`Found ${packages.length} packages in ${filePath}`);

  const results = {
    totalPackages: packages.length,
    vulnerabilities: [],
    vulnerabilityCount: 0
  };

  for (const pkg of packages) {
    const vuln = await queryVulnerability(pkg.id, pkg.version);

    if (vuln) {
      console.log(`\n=== Vulnerability found for ${pkg.id} (${pkg.version}) ===`);
      const issues = vuln.map(v => ({
        summary: v.advisory.summary,
        severity: v.advisory.severity
      }));

      vuln.forEach(v => {
        console.log(`- ${v.advisory.summary} (Severity: ${v.advisory.severity})`);
        v.advisory.references.forEach(r => console.log(`  * ${r.url}`));
      });

      results.vulnerabilities.push({
        id: pkg.id,
        version: pkg.version,
        issues: issues
      });
      results.vulnerabilityCount += vuln.length;
    } else {
      console.log(`✓ ${pkg.id} (${pkg.version}) - no known vulnerabilities`);
    }
  }

  logger.info('audit', `Audit complete. Found ${results.vulnerabilityCount} vulnerabilities in ${results.vulnerabilities.length} package(s)`);

  return results;
}

module.exports = {
  audit,
  readPackagesFile,
  readPackagesConfig,
  queryVulnerability,
  queryVulnerabilityREST,
  initialize
};
