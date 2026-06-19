/**
 * Caching mechanism for vulnerability queries
 * Supports both in-memory and optional file-based caching
 */

const fs = require('fs');
const path = require('path');

class VulnerabilityCache {
  constructor(enableFileCache = false) {
    this.memory = new Map();
    this.enableFileCache = enableFileCache;
    this.cacheDir = path.join(process.cwd(), '.nuget-check-cache');

    if (enableFileCache) {
      this._ensureCacheDir();
    }
  }

  /**
   * Generate cache key from package ID and version
   * @param {string} packageId - NuGet package ID
   * @param {string} version - Package version
   * @returns {string} Cache key
   */
  _getCacheKey(packageId, version) {
    return `${packageId}@${version}`;
  }

  /**
   * Ensure cache directory exists
   * @private
   */
  _ensureCacheDir() {
    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  /**
   * Get cached vulnerability data
   * @param {string} packageId - NuGet package ID
   * @param {string} version - Package version
   * @returns {Object|null} Cached data or null
   */
  get(packageId, version) {
    const key = this._getCacheKey(packageId, version);

    // Check memory cache first
    if (this.memory.has(key)) {
      return this.memory.get(key);
    }

    // Check file cache if enabled
    if (this.enableFileCache) {
      const filePath = path.join(this.cacheDir, `${key}.json`);
      try {
        if (fs.existsSync(filePath)) {
          const data = fs.readFileSync(filePath, 'utf-8');
          const cached = JSON.parse(data);

          // Check if cache is still valid (24 hours)
          if (Date.now() - cached.timestamp < 24 * 60 * 60 * 1000) {
            this.memory.set(key, cached.data);
            return cached.data;
          } else {
            // Cache expired, delete it
            fs.unlinkSync(filePath);
          }
        }
      } catch {
        // Ignore cache read errors
      }
    }

    return null;
  }

  /**
   * Set cached vulnerability data
   * @param {string} packageId - NuGet package ID
   * @param {string} version - Package version
   * @param {Object} data - Data to cache
   */
  set(packageId, version, data) {
    const key = this._getCacheKey(packageId, version);

    // Store in memory cache
    this.memory.set(key, data);

    // Store in file cache if enabled
    if (this.enableFileCache) {
      const filePath = path.join(this.cacheDir, `${key}.json`);
      try {
        const cacheEntry = {
          timestamp: Date.now(),
          data: data
        };
        fs.writeFileSync(filePath, JSON.stringify(cacheEntry, null, 2));
      } catch {
        // Ignore cache write errors
      }
    }
  }

  /**
   * Clear all cached data
   */
  clear() {
    this.memory.clear();

    if (this.enableFileCache && fs.existsSync(this.cacheDir)) {
      try {
        fs.rmSync(this.cacheDir, { recursive: true, force: true });
      } catch {
        // Ignore clear errors
      }
    }
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache stats
   */
  getStats() {
    return {
      memoryCacheSize: this.memory.size,
      filesCacheDir: this.cacheDir,
      fileCacheEnabled: this.enableFileCache
    };
  }
}

module.exports = VulnerabilityCache;
