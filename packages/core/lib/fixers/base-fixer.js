/**
 * Base Fixer Class
 *
 * Abstract base class for all automated fixers.
 * Provides backup/rollback, confidence scoring, and safe application.
 *
 * Features:
 * - Automatic file backups before modification
 * - Rollback capability if fixes fail
 * - Confidence scoring (0-100)
 * - Dry-run mode for preview
 * - Atomic operations (all-or-nothing)
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class BaseFixer {
  constructor(options = {}) {
    this.name = this.constructor.name;
    this.dryRun = options.dryRun || false;
    this.backupDir = options.backupDir || path.join(process.cwd(), '.codetitan', 'backups');
    this.minConfidence = options.minConfidence || 75;

    // Statistics
    this.stats = {
      attempted: 0,
      successful: 0,
      failed: 0,
      skipped: 0,
      totalConfidence: 0
    };

    // Backup tracking
    this.backups = new Map();
  }

  /**
   * Apply fixes to findings
   *
   * @param {Array} findings - Findings to fix
   * @returns {Promise<Object>} Fix results
   */
  async applyFixes(findings) {
    const results = {
      fixed: [],
      skipped: [],
      failed: [],
      backups: []
    };

    // Group findings by file
    const fileGroups = this.groupByFile(findings);

    for (const [filePath, fileFindings] of Object.entries(fileGroups)) {
      try {
        // Read file content
        const content = await fs.readFile(filePath, 'utf8');

        // Create backup
        const backupPath = await this.createBackup(filePath, content);
        results.backups.push(backupPath);

        // Apply fixes for this file
        const fixResult = await this.fixFile(filePath, content, fileFindings);

        if (fixResult.success) {
          // Write fixed content (unless dry-run)
          if (!this.dryRun) {
            await fs.writeFile(filePath, fixResult.content, 'utf8');
          }

          results.fixed.push(...fixResult.fixed);
          this.stats.successful += fixResult.fixed.length;
        } else {
          results.failed.push(...fixResult.failed);
          this.stats.failed += fixResult.failed.length;
        }

        results.skipped.push(...(fixResult.skipped || []));
        this.stats.skipped += (fixResult.skipped || []).length;

      } catch (error) {
        console.error(`[${this.name}] Error fixing ${filePath}:`, error.message);
        results.failed.push({
          file: filePath,
          error: error.message
        });
        this.stats.failed++;
      }
    }

    return results;
  }

  /**
   * Fix a single file
   * Must be implemented by subclasses
   *
   * @param {string} filePath - File path
   * @param {string} content - File content
   * @param {Array} findings - Findings for this file
   * @returns {Promise<Object>} Fix result
   */
  async fixFile(filePath, content, findings) {
    throw new Error('fixFile() must be implemented by subclass');
  }

  /**
   * Calculate confidence score for a fix
   *
   * @param {Object} finding - The finding to fix
   * @param {Object} context - Additional context
   * @returns {number} Confidence score (0-100)
   */
  calculateConfidence(finding, context = {}) {
    // Base confidence starts at 50
    let confidence = 50;

    // Higher confidence for well-defined patterns
    if (finding.category && finding.line && finding.column) {
      confidence += 20;
    }

    // Higher confidence if we have code context
    if (finding.context && finding.context.length > 0) {
      confidence += 15;
    }

    // Higher confidence for specific categories
    const highConfidenceCategories = ['SYNC_IO', 'COMMAND_EXEC', 'MISSING_HEADER'];
    if (highConfidenceCategories.includes(finding.category)) {
      confidence += 15;
    }

    return Math.min(100, confidence);
  }

  /**
   * Create backup of file
   *
   * @param {string} filePath - File to backup
   * @param {string} content - File content
   * @returns {Promise<string>} Backup file path
   */
  async createBackup(filePath, content) {
    // Generate backup filename with timestamp and hash
    const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
    const hash = crypto.createHash('md5').update(content).digest('hex').substr(0, 8);
    const basename = path.basename(filePath);
    const backupName = `${basename}.${timestamp}.${hash}.bak`;
    const backupPath = path.join(this.backupDir, backupName);

    // Ensure backup directory exists
    await fs.mkdir(this.backupDir, { recursive: true });

    // Write backup
    await fs.writeFile(backupPath, content, 'utf8');

    // Track backup
    this.backups.set(filePath, backupPath);

    return backupPath;
  }

  /**
   * Rollback a file to its backup
   *
   * @param {string} filePath - File to rollback
   * @returns {Promise<boolean>} Success
   */
  async rollback(filePath) {
    const backupPath = this.backups.get(filePath);

    if (!backupPath) {
      throw new Error(`No backup found for ${filePath}`);
    }

    try {
      const backupContent = await fs.readFile(backupPath, 'utf8');
      await fs.writeFile(filePath, backupContent, 'utf8');
      return true;
    } catch (error) {
      console.error(`[${this.name}] Rollback failed for ${filePath}:`, error.message);
      return false;
    }
  }

  /**
   * Rollback all files
   *
   * @returns {Promise<Object>} Rollback results
   */
  async rollbackAll() {
    const results = {
      successful: [],
      failed: []
    };

    for (const [filePath, backupPath] of this.backups.entries()) {
      try {
        await this.rollback(filePath);
        results.successful.push(filePath);
      } catch (error) {
        results.failed.push({
          file: filePath,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Group findings by file
   *
   * @param {Array} findings - All findings
   * @returns {Object} Findings grouped by file path
   */
  groupByFile(findings) {
    const groups = {};

    for (const finding of findings) {
      const file = finding.file;
      if (!groups[file]) {
        groups[file] = [];
      }
      groups[file].push(finding);
    }

    return groups;
  }

  /**
   * Sort findings by line number (descending)
   * This allows us to fix from bottom to top, avoiding line number shifts
   *
   * @param {Array} findings - Findings to sort
   * @returns {Array} Sorted findings
   */
  sortByLineDescending(findings) {
    return findings.sort((a, b) => {
      if (b.line !== a.line) {
        return b.line - a.line;
      }
      return (b.column || 0) - (a.column || 0);
    });
  }

  /**
   * Get statistics
   *
   * @returns {Object} Statistics
   */
  getStats() {
    const avgConfidence = this.stats.attempted > 0
      ? Math.round(this.stats.totalConfidence / this.stats.attempted)
      : 0;

    return {
      ...this.stats,
      avgConfidence,
      successRate: this.stats.attempted > 0
        ? Math.round((this.stats.successful / this.stats.attempted) * 100)
        : 0
    };
  }

  /**
   * Clean up old backups
   *
   * @param {number} maxAge - Max age in milliseconds
   * @returns {Promise<number>} Number of backups cleaned
   */
  async cleanupBackups(maxAge = 86400000) { // 24 hours default
    try {
      const files = await fs.readdir(this.backupDir);
      const now = Date.now();
      let cleaned = 0;

      for (const file of files) {
        const filePath = path.join(this.backupDir, file);
        const stats = await fs.stat(filePath);

        if (now - stats.mtimeMs > maxAge) {
          await fs.unlink(filePath);
          cleaned++;
        }
      }

      return cleaned;
    } catch (error) {
      console.error(`[${this.name}] Cleanup failed:`, error.message);
      return 0;
    }
  }
}

module.exports = BaseFixer;
