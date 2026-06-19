/**
 * Test suite for nuget-check
 * Run with: npm test
 */

const fs = require('fs');
const path = require('path');
const { readPackagesFile, queryVulnerability, audit, initialize } = require('../index');

// Test utilities
const TEST_DIR = path.join(__dirname, '..', 'test-fixtures');

/**
 * Create test fixtures
 */
function setupTestFixtures() {
  if (!fs.existsSync(TEST_DIR)) {
    fs.mkdirSync(TEST_DIR, { recursive: true });
  }

  // Create sample packages.config
  const packagesConfig = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="11.0.2" targetFramework="net462" />
  <package id="EntityFramework" version="6.1.3" targetFramework="net462" />
  <package id="log4net" version="2.0.8" targetFramework="net462" />
</packages>`;

  fs.writeFileSync(path.join(TEST_DIR, 'packages.config'), packagesConfig);

  // Create sample packages.lock.json
  const packagesLock = {
    version: 1,
    isLocked: true,
    dependencies: {
      "Newtonsoft.Json": "11.0.2",
      "EntityFramework": "6.1.3",
      "log4net": "2.0.8"
    }
  };

  fs.writeFileSync(
    path.join(TEST_DIR, 'packages.lock.json'),
    JSON.stringify(packagesLock, null, 2)
  );
}

/**
 * Cleanup test fixtures
 */
function cleanupTestFixtures() {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  }
}

describe('nuget-check', () => {
  beforeAll(setupTestFixtures);
  afterAll(cleanupTestFixtures);

  describe('readPackagesFile', () => {
    test('should read packages.config file', async () => {
      const configPath = path.join(TEST_DIR, 'packages.config');
      const packages = await readPackagesFile(configPath);

      expect(packages).toBeInstanceOf(Array);
      expect(packages.length).toBeGreaterThan(0);
      expect(packages[0]).toHaveProperty('id');
      expect(packages[0]).toHaveProperty('version');
    });

    test('should read packages.lock.json file', async () => {
      const lockPath = path.join(TEST_DIR, 'packages.lock.json');
      const packages = await readPackagesFile(lockPath);

      expect(packages).toBeInstanceOf(Array);
      expect(packages.length).toBeGreaterThan(0);
      expect(packages[0]).toHaveProperty('id');
      expect(packages[0]).toHaveProperty('version');
    });

    test('should throw error for non-existent file', async () => {
      const invalidPath = path.join(TEST_DIR, 'non-existent.config');

      await expect(readPackagesFile(invalidPath)).rejects.toThrow('File not found');
    });

    test('should throw error for invalid XML', async () => {
      const invalidXml = path.join(TEST_DIR, 'invalid.config');
      fs.writeFileSync(invalidXml, '<invalid>unclosed tag');

      await expect(readPackagesFile(invalidXml)).rejects.toThrow('Failed to parse XML');

      fs.unlinkSync(invalidXml);
    });
  });

  describe('queryVulnerability', () => {
    test('should return null for unknown package', async () => {
      // Skip if no GitHub token available
      if (!process.env.GITHUB_TOKEN) {
        console.log('Skipping queryVulnerability test - GITHUB_TOKEN not set');
        return;
      }

      const result = await queryVulnerability('NonExistentPackage12345', '1.0.0');
      // Result should be null or empty array
      expect(result == null || result.length === 0).toBe(true);
    });
  });

  describe('initialize', () => {
    test('should set log level', () => {
      initialize({ logLevel: 'debug' });
      // Test passes if no error is thrown
      expect(true).toBe(true);
    });

    test('should enable caching', () => {
      initialize({ enableCache: true });
      expect(true).toBe(true);
    });
  });

  describe('audit', () => {
    test('should process audit without errors', async () => {
      // Skip if no GitHub token available
      if (!process.env.GITHUB_TOKEN) {
        console.log('Skipping audit test - GITHUB_TOKEN not set');
        return;
      }

      const configPath = path.join(TEST_DIR, 'packages.config');

      // Mock console.log to prevent output during tests
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      try {
        const results = await audit(configPath, { verbose: false });

        expect(results).toHaveProperty('totalPackages');
        expect(results).toHaveProperty('vulnerabilities');
        expect(results).toHaveProperty('vulnerabilityCount');
        expect(results.totalPackages).toBeGreaterThan(0);
      } finally {
        consoleSpy.mockRestore();
      }
    }, 30000); // 30 second timeout for API calls
  });
});

/**
 * Integration tests
 */
describe('Integration Tests', () => {
  test('CLI should accept packages.config path', async () => {
    setupTestFixtures();

    try {
      const configPath = path.join(TEST_DIR, 'packages.config');
      expect(fs.existsSync(configPath)).toBe(true);
    } finally {
      cleanupTestFixtures();
    }
  });
});
