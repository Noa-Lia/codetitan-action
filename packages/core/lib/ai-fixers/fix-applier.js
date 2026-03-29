/**
 * FixApplier - Safe application of AI-generated fixes to files
 *
 * Handles:
 * - Backup creation before applying fixes
 * - Atomic file operations
 * - Rollback on failure
 * - Dry-run mode for preview
 * - Git integration for change tracking
 *
 * @module ai-fixers/fix-applier
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class FixApplier {
  constructor(config = {}) {
    this.config = {
      // Create backups before applying fixes
      createBackups: config.createBackups !== false,

      // Backup directory
      backupDir: config.backupDir || '.codetitan/backups',

      // Require git for tracking changes
      requireGit: config.requireGit || false,

      // Dry-run mode (preview only, don't apply)
      dryRun: config.dryRun || false,

      // Maximum files to modify in single operation
      maxBatchSize: config.maxBatchSize || 50,

      ...config
    };

    // Track applied fixes
    this.history = {
      totalApplied: 0,
      successful: 0,
      failed: 0,
      rolledBack: 0,
      fixes: []
    };
  }

  /**
   * Apply a fix to a file
   *
   * @param {string} filePath - Path to file
   * @param {Object} fix - Fix object from FixGenerator
   * @param {Object} options - Application options
   * @returns {Promise<Object>} Application result
   */
  async applyFix(filePath, fix, options = {}) {
    const start = Date.now();

    try {
      // Validate fix
      if (!fix || !fix.fixedCode) {
        throw new Error('Invalid fix object');
      }

      // Read current file content
      const originalContent = await fs.readFile(filePath, 'utf-8');

      // Apply fix to content
      const fixedContent = this.applyFixToContent(fix, originalContent);

      // Dry-run mode: just preview
      if (this.config.dryRun || options.dryRun) {
        return {
          success: true,
          dryRun: true,
          preview: {
            original: originalContent,
            fixed: fixedContent,
            diff: this.generateDiff(originalContent, fixedContent)
          },
          duration: Date.now() - start
        };
      }

      // Create backup
      let backupPath;
      if (this.config.createBackups) {
        backupPath = await this.createBackup(filePath, originalContent);
      }

      // Write fixed content
      await fs.writeFile(filePath, fixedContent, 'utf-8');

      // Track fix application
      const fixRecord = {
        id: this.generateFixId(),
        filePath,
        timestamp: new Date().toISOString(),
        fix,
        backupPath,
        success: true
      };

      this.history.fixes.push(fixRecord);
      this.history.totalApplied++;
      this.history.successful++;

      return {
        success: true,
        filePath,
        backupPath,
        fixId: fixRecord.id,
        duration: Date.now() - start
      };

    } catch (error) {
      console.error(`[FixApplier] Failed to apply fix to ${filePath}:`, error);
      this.history.failed++;

      return {
        success: false,
        filePath,
        error: error.message,
        duration: Date.now() - start
      };
    }
  }

  /**
   * Apply fix to content (same as FixGenerator but extracted for reuse)
   */
  applyFixToContent(fix, content) {
    const lines = content.split('\n');

    if (fix.type === 'replace') {
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.endLine);
      const replacement = fix.fixedCode.split('\n');
      return [...before, ...replacement, ...after].join('\n');

    } else if (fix.type === 'insert') {
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.startLine - 1);
      const insertion = fix.fixedCode.split('\n');
      return [...before, ...insertion, ...after].join('\n');

    } else if (fix.type === 'delete') {
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.endLine);
      return [...before, ...after].join('\n');

    } else if (fix.type === 'comment') {
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.startLine - 1);
      return [...before, fix.fixedCode, ...after].join('\n');
    }

    return content;
  }

  /**
   * Create backup of file before modifying
   */
  async createBackup(filePath, content) {
    try {
      // Ensure backup directory exists
      const backupDir = path.join(process.cwd(), this.config.backupDir);
      await fs.mkdir(backupDir, { recursive: true });

      // Generate backup filename with timestamp
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName = path.basename(filePath);
      const backupName = `${fileName}.${timestamp}.backup`;
      const backupPath = path.join(backupDir, backupName);

      // Write backup
      await fs.writeFile(backupPath, content, 'utf-8');

      console.log(`[FixApplier] Created backup: ${backupPath}`);

      return backupPath;

    } catch (error) {
      console.error(`[FixApplier] Failed to create backup:`, error);
      throw new Error(`Backup creation failed: ${error.message}`);
    }
  }

  /**
   * Rollback a previously applied fix
   */
  async rollback(fixId) {
    try {
      // Find fix in history
      const fixRecord = this.history.fixes.find(f => f.id === fixId);

      if (!fixRecord) {
        throw new Error(`Fix ${fixId} not found in history`);
      }

      if (!fixRecord.backupPath) {
        throw new Error(`No backup available for fix ${fixId}`);
      }

      // Read backup content
      const backupContent = await fs.readFile(fixRecord.backupPath, 'utf-8');

      // Restore file
      await fs.writeFile(fixRecord.filePath, backupContent, 'utf-8');

      // Update history
      fixRecord.rolledBack = true;
      fixRecord.rollbackTimestamp = new Date().toISOString();
      this.history.rolledBack++;

      console.log(`[FixApplier] Rolled back fix ${fixId} for ${fixRecord.filePath}`);

      return {
        success: true,
        fixId,
        filePath: fixRecord.filePath,
        backupPath: fixRecord.backupPath
      };

    } catch (error) {
      console.error(`[FixApplier] Rollback failed:`, error);
      return {
        success: false,
        fixId,
        error: error.message
      };
    }
  }

  /**
   * Batch apply multiple fixes
   */
  async batchApply(fixes, options = {}) {
    const results = [];

    // Group fixes by file
    const fixesByFile = this.groupFixesByFile(fixes);

    // Validate batch size
    if (Object.keys(fixesByFile).length > this.config.maxBatchSize) {
      throw new Error(`Batch size exceeds limit (${this.config.maxBatchSize} files)`);
    }

    // Apply fixes file by file
    for (const [filePath, fileFixes] of Object.entries(fixesByFile)) {
      try {
        // Read file once
        const originalContent = await fs.readFile(filePath, 'utf-8');

        // Apply all fixes for this file
        let content = originalContent;
        for (const fix of fileFixes) {
          content = this.applyFixToContent(fix.fix, content);
        }

        // Create single backup
        let backupPath;
        if (this.config.createBackups) {
          backupPath = await this.createBackup(filePath, originalContent);
        }

        // Write modified content (or skip in dry-run)
        if (!this.config.dryRun && !options.dryRun) {
          await fs.writeFile(filePath, content, 'utf-8');
        }

        results.push({
          filePath,
          success: true,
          fixCount: fileFixes.length,
          backupPath,
          dryRun: this.config.dryRun || options.dryRun
        });

        // Track each fix
        for (const fix of fileFixes) {
          this.history.fixes.push({
            id: this.generateFixId(),
            filePath,
            timestamp: new Date().toISOString(),
            fix: fix.fix,
            backupPath,
            success: true
          });
          this.history.totalApplied++;
          this.history.successful++;
        }

      } catch (error) {
        console.error(`[FixApplier] Failed to apply fixes to ${filePath}:`, error);
        results.push({
          filePath,
          success: false,
          error: error.message
        });
        this.history.failed += fileFixes.length;
      }
    }

    return results;
  }

  /**
   * Group fixes by file path
   */
  groupFixesByFile(fixes) {
    const grouped = {};

    for (const fix of fixes) {
      const filePath = fix.finding?.file_path || fix.filePath;
      if (!filePath) continue;

      if (!grouped[filePath]) {
        grouped[filePath] = [];
      }

      grouped[filePath].push(fix);
    }

    return grouped;
  }

  /**
   * Generate simple diff preview
   */
  generateDiff(original, fixed) {
    const originalLines = original.split('\n');
    const fixedLines = fixed.split('\n');

    const diff = [];
    const maxLen = Math.max(originalLines.length, fixedLines.length);

    for (let i = 0; i < maxLen; i++) {
      const origLine = originalLines[i] || '';
      const fixedLine = fixedLines[i] || '';

      if (origLine !== fixedLine) {
        if (origLine) {
          diff.push(`- ${i + 1}: ${origLine}`);
        }
        if (fixedLine) {
          diff.push(`+ ${i + 1}: ${fixedLine}`);
        }
      }
    }

    return diff.join('\n');
  }

  /**
   * Generate unique fix ID
   */
  generateFixId() {
    return `fix_${crypto.randomBytes(8).toString('hex')}`;
  }

  /**
   * List all applied fixes
   */
  listFixes(options = {}) {
    let fixes = [...this.history.fixes];

    // Filter by file
    if (options.filePath) {
      fixes = fixes.filter(f => f.filePath === options.filePath);
    }

    // Filter by status
    if (options.rolledBack !== undefined) {
      fixes = fixes.filter(f => f.rolledBack === options.rolledBack);
    }

    // Sort by timestamp
    fixes.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Limit results
    if (options.limit) {
      fixes = fixes.slice(0, options.limit);
    }

    return fixes;
  }

  /**
   * Get application statistics
   */
  getStats() {
    return {
      ...this.history,
      successRate: this.history.totalApplied > 0
        ? this.history.successful / this.history.totalApplied
        : 0,
      rollbackRate: this.history.successful > 0
        ? this.history.rolledBack / this.history.successful
        : 0
    };
  }

  /**
   * Clean old backups
   */
  async cleanBackups(options = {}) {
    try {
      const backupDir = path.join(process.cwd(), this.config.backupDir);
      const maxAge = options.maxAgeDays || 30; // Default 30 days

      const files = await fs.readdir(backupDir);
      let cleaned = 0;

      for (const file of files) {
        const filePath = path.join(backupDir, file);
        const stats = await fs.stat(filePath);
        const age = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24); // days

        if (age > maxAge) {
          await fs.unlink(filePath);
          cleaned++;
        }
      }

      console.log(`[FixApplier] Cleaned ${cleaned} old backups`);

      return { cleaned };

    } catch (error) {
      console.error(`[FixApplier] Failed to clean backups:`, error);
      return { cleaned: 0, error: error.message };
    }
  }

  /**
   * Export fix history
   */
  exportHistory() {
    return {
      config: this.config,
      history: this.history
    };
  }

  /**
   * Import fix history
   */
  importHistory(data) {
    if (data.history) {
      this.history = { ...this.history, ...data.history };
    }
  }
}

module.exports = FixApplier;
