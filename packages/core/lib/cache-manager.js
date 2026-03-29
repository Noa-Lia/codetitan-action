/**
 * Cache Manager
 *
 * Smart caching system using file fingerprints to avoid re-analyzing unchanged files.
 * Provides 10-100x speed improvement on subsequent runs.
 *
 * Features:
 * - Content-based fingerprinting (hash of file content)
 * - Metadata tracking (file size, mtime, etc.)
 * - TTL-based expiration
 * - Cache hit/miss statistics
 * - Automatic cache invalidation
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const DEFAULT_CACHE_VERSION = 'analysis-v8';

class CacheManager {
  constructor(options = {}) {
    this.cacheDir = options.cacheDir || path.join(process.cwd(), '.codetitan', 'cache');
    this.ttl = options.ttl || 86400000; // 24 hours in ms
    this.enabled = options.enabled !== false;
    this.version = options.version || DEFAULT_CACHE_VERSION;

    // Statistics
    this.stats = {
      hits: 0,
      misses: 0,
      saves: 0,
      evictions: 0
    };

    // In-memory cache (for this session)
    this.memoryCache = new Map();
  }

  /**
   * Initialize cache directory
   */
  async initialize() {
    if (!this.enabled) return;

    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
    } catch (error) {
      console.error('[CacheManager] Failed to create cache directory:', error);
      this.enabled = false;
    }
  }

  /**
   * Get cached analysis result for a file
   *
   * @param {string} filePath - Path to file
   * @returns {Promise<Object|null>} Cached result or null
   */
  async get(filePath) {
    if (!this.enabled) return null;

    try {
      // Generate cache key
      const cacheKey = await this.generateCacheKey(filePath);

      // Check memory cache first
      if (this.memoryCache.has(cacheKey)) {
        this.stats.hits++;
        return this.memoryCache.get(cacheKey);
      }

      // Check disk cache
      const cachePath = this.getCachePath(cacheKey);
      const cached = await this.readCache(cachePath);

      if (cached) {
        // Validate cache is still fresh
        if (await this.isValid(cached, filePath)) {
          this.stats.hits++;
          this.memoryCache.set(cacheKey, cached.data);
          return cached.data;
        } else {
          // Cache is stale, remove it
          await this.evict(cacheKey);
        }
      }

      this.stats.misses++;
      return null;

    } catch (error) {
      this.stats.misses++;
      return null;
    }
  }

  /**
   * Save analysis result to cache
   *
   * @param {string} filePath - Path to file
   * @param {Object} data - Analysis result
   */
  async set(filePath, data) {
    if (!this.enabled) return;

    try {
      const cacheKey = await this.generateCacheKey(filePath);
      const stats = await fs.stat(filePath);

      const cacheEntry = {
        data,
        metadata: {
          filePath,
          size: stats.size,
          mtime: stats.mtime.getTime(),
          cachedAt: Date.now(),
          fingerprint: cacheKey,
          version: this.version
        }
      };

      // Save to memory cache
      this.memoryCache.set(cacheKey, data);

      // Save to disk cache
      const cachePath = this.getCachePath(cacheKey);
      await fs.writeFile(cachePath, JSON.stringify(cacheEntry), 'utf8');

      this.stats.saves++;

    } catch (error) {
      console.error('[CacheManager] Failed to save cache:', error);
    }
  }

  /**
   * Generate cache key (fingerprint) for a file
   *
   * Uses content hash for most accurate cache invalidation
   */
  async generateCacheKey(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const hash = crypto.createHash('sha256');
      hash.update(this.version);
      hash.update(content);
      hash.update(filePath); // Include path for uniqueness
      return hash.digest('hex');
    } catch (error) {
      // Fallback to path-based key
      const hash = crypto.createHash('sha256');
      hash.update(this.version);
      hash.update(filePath);
      return hash.digest('hex');
    }
  }

  /**
   * Check if cached entry is still valid
   */
  async isValid(cached, filePath) {
    try {
      if (cached?.metadata?.version !== this.version) {
        return false;
      }

      const stats = await fs.stat(filePath);

      // Check if file modified time changed
      if (stats.mtime.getTime() !== cached.metadata.mtime) {
        return false;
      }

      // Check if file size changed
      if (stats.size !== cached.metadata.size) {
        return false;
      }

      // Check TTL
      const age = Date.now() - cached.metadata.cachedAt;
      if (age > this.ttl) {
        return false;
      }

      return true;

    } catch (error) {
      // File doesn't exist or can't be accessed
      return false;
    }
  }

  /**
   * Read cache entry from disk
   */
  async readCache(cachePath) {
    try {
      const content = await fs.readFile(cachePath, 'utf8');
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }

  /**
   * Get cache file path for a key
   */
  getCachePath(cacheKey) {
    return path.join(this.cacheDir, `${cacheKey}.json`);
  }

  /**
   * Evict a cache entry
   */
  async evict(cacheKey) {
    try {
      this.memoryCache.delete(cacheKey);
      const cachePath = this.getCachePath(cacheKey);
      await fs.unlink(cachePath);
      this.stats.evictions++;
    } catch (error) {
      // Ignore errors (file might not exist)
    }
  }

  /**
   * Clear all cache
   */
  async clear() {
    try {
      this.memoryCache.clear();

      const files = await fs.readdir(this.cacheDir);
      await Promise.all(
        files.map(file => fs.unlink(path.join(this.cacheDir, file)))
      );

      this.stats.evictions += files.length;

    } catch (error) {
      console.error('[CacheManager] Failed to clear cache:', error);
    }
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    const hitRate = total > 0 ? (this.stats.hits / total * 100).toFixed(2) : 0;

    return {
      ...this.stats,
      total,
      hitRate: parseFloat(hitRate),
      memoryEntries: this.memoryCache.size
    };
  }

  /**
   * Get cache size on disk
   */
  async getCacheSize() {
    try {
      const files = await fs.readdir(this.cacheDir);
      let totalSize = 0;

      for (const file of files) {
        const stats = await fs.stat(path.join(this.cacheDir, file));
        totalSize += stats.size;
      }

      return {
        files: files.length,
        bytes: totalSize,
        human: this.formatBytes(totalSize)
      };

    } catch (error) {
      return { files: 0, bytes: 0, human: '0 B' };
    }
  }

  /**
   * Format bytes to human-readable string
   */
  formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
  }

  /**
   * Clean up expired cache entries
   */
  async cleanup() {
    try {
      const files = await fs.readdir(this.cacheDir);
      let cleaned = 0;

      for (const file of files) {
        const cachePath = path.join(this.cacheDir, file);
        const cached = await this.readCache(cachePath);

        if (cached) {
          const age = Date.now() - cached.metadata.cachedAt;
          if (age > this.ttl) {
            await fs.unlink(cachePath);
            cleaned++;
          }
        }
      }

      this.stats.evictions += cleaned;
      return cleaned;

    } catch (error) {
      console.error('[CacheManager] Cleanup failed:', error);
      return 0;
    }
  }
}

module.exports = CacheManager;
