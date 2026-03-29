/**
 * Automated Code Fixers
 * TITAN MODE Level 4: AI-powered and rule-based code fixes
 *
 * Applies safe, high-confidence fixes to common code issues
 */

const fs = require('fs').promises;
const path = require('path');
const GitIntegration = require('../git-integration');
const FixVerifier = require('./fix-verifier');
const ConfidenceScorer = require('./confidence-scorer');

class AutoFixer {
  constructor(config = {}) {
    this.config = {
      minConfidence: config.minConfidence || 0.90, // Increased from 0.80 to 0.90
      dryRun: config.dryRun || false,
      createBackup: config.createBackup !== false,
      verbose: config.verbose || false,
      autoCommit: config.autoCommit || false,
      createBranch: config.createBranch || false,
      projectPath: config.projectPath || process.cwd(),
      enableVerification: config.enableVerification !== false,
      verificationOptions: config.verificationOptions || {},
      useAdvancedConfidence: config.useAdvancedConfidence !== false,
      ...config
    };

    this.stats = {
      attempted: 0,
      succeeded: 0,
      failed: 0,
      skipped: 0,
      verified: 0,
      verificationFailed: 0
    };

    this.fixResults = [];

    // Initialize git integration if auto-commit is enabled
    if (this.config.autoCommit) {
      this.gitIntegration = new GitIntegration({
        dryRun: this.config.dryRun,
        verbose: this.config.verbose,
        createBranch: this.config.createBranch
      });
    }

    // Initialize fix verifier if verification is enabled
    if (this.config.enableVerification) {
      this.verifier = new FixVerifier({
        enableAstValidation: true,
        enableTestExecution: false, // Disabled by default for performance
        enableRollback: !this.config.dryRun,
        ...this.config.verificationOptions
      });
    }

    // Initialize confidence scorer
    if (this.config.useAdvancedConfidence) {
      this.confidenceScorer = new ConfidenceScorer();
    }
  }

  /**
   * Apply fix to a finding
   */
  async applyFix(finding) {
    this.stats.attempted++;

    // Calculate enhanced confidence if scorer is available
    let effectiveConfidence = finding.confidence || 0.7;

    if (this.confidenceScorer) {
      const confidenceResult = this.confidenceScorer.calculateConfidence(finding, {
        complexity: finding.complexity,
        fileType: path.extname(finding.filePath || finding.file),
        otherIssues: finding.relatedIssues || []
      });

      effectiveConfidence = confidenceResult.score;

      if (this.config.verbose) {
        console.log(`📊 Confidence: ${(effectiveConfidence * 100).toFixed(1)}% (${confidenceResult.level})`);
      }
    }

    // Check confidence threshold
    if (effectiveConfidence < this.config.minConfidence) {
      if (this.config.verbose) {
        console.log(`⏭️  Skipped ${finding.category} (confidence ${(effectiveConfidence * 100).toFixed(0)}% < ${(this.config.minConfidence * 100).toFixed(0)}%)`);
      }
      this.stats.skipped++;
      return { success: false, reason: 'low_confidence', confidence: effectiveConfidence };
    }

    // Update finding with effective confidence
    finding.effectiveConfidence = effectiveConfidence;

    // Get fixer for this category
    const fixer = this.getFixer(finding.category);
    if (!fixer) {
      if (this.config.verbose) {
        console.log(`⏭️  No fixer available for ${finding.category}`);
      }
      this.stats.skipped++;
      return { success: false, reason: 'no_fixer' };
    }

    // Read original content for verification and rollback
    let originalContent = null;
    if (this.config.enableVerification && !this.config.dryRun) {
      try {
        originalContent = await fs.readFile(finding.filePath, 'utf-8');
      } catch (error) {
        if (this.config.verbose) {
          console.warn(`⚠️  Could not read original content: ${error.message}`);
        }
      }
    }

    try {
      // Create backup if enabled
      if (this.config.createBackup && !this.config.dryRun) {
        await this.createBackup(finding.filePath);
      }

      // Apply the fix
      const result = await fixer.fix(finding, this.config);

      if (result.success) {
        // Verify the fix if verification is enabled
        if (this.config.enableVerification && !this.config.dryRun) {
          const verificationResult = await this.verifier.verifyFix({
            filePath: finding.filePath,
            type: finding.category,
            originalContent
          });

          this.stats.verified++;

          if (!verificationResult.passed) {
            this.stats.verificationFailed++;
            this.stats.failed++;

            if (this.config.verbose) {
              console.log(`❌ Fix verification failed for ${finding.category} in ${finding.filePath}`);
              verificationResult.errors.forEach(err => {
                console.log(`   • ${err.type}: ${err.message}`);
              });
              if (verificationResult.rolledBack) {
                console.log(`   ⏪ Auto-rollback applied`);
              }
            }

            return {
              success: false,
              error: 'Verification failed',
              verificationResult
            };
          }

          if (this.config.verbose) {
            console.log(`✅ Fixed ${finding.category} in ${finding.filePath}:${finding.line} (verified)`);
          }
        } else {
          if (this.config.verbose) {
            console.log(`✅ Fixed ${finding.category} in ${finding.filePath}:${finding.line}`);
          }
        }

        this.stats.succeeded++;
      } else {
        this.stats.failed++;
        if (this.config.verbose) {
          console.log(`❌ Failed to fix ${finding.category}: ${result.error}`);
        }
      }

      // Store result with finding reference for git commit
      const fixResult = {
        ...result,
        finding,
        filePath: finding.filePath
      };
      this.fixResults.push(fixResult);

      return result;

    } catch (error) {
      this.stats.failed++;
      if (this.config.verbose) {
        console.error(`❌ Error fixing ${finding.category}:`, error.message);
      }
      return { success: false, error: error.message };
    }
  }

  /**
   * Get fixer for a category
   */
  getFixer(category) {
    const fixers = {
      'HARDCODED_SECRET': require('./hardcoded-secret-fixer'),
      'SQL_INJECTION': require('./sql-injection-fixer'),
      'XSS': require('./xss-fixer'),
      'SYNC_IO': require('./sync-io-fixer'),
      'MISSING_DOCS': require('./missing-docs-fixer'),
      'COMMAND_EXEC': require('./command-exec-fixer'),
      'MAGIC_NUMBER': require('./magic-number-fixer')
    };

    return fixers[category] || null;
  }

  /**
   * Create backup of file
   */
  async createBackup(filePath) {
    const backupPath = `${filePath}.backup`;
    await fs.copyFile(filePath, backupPath);
    return backupPath;
  }

  /**
   * Restore from backup
   */
  async restoreBackup(filePath) {
    const backupPath = `${filePath}.backup`;
    await fs.copyFile(backupPath, filePath);
    await fs.unlink(backupPath);
  }

  /**
   * Commit all successful fixes to git
   */
  async commitAllFixes() {
    if (!this.config.autoCommit) {
      return {
        success: false,
        reason: 'auto_commit_disabled',
        message: 'Auto-commit is not enabled'
      };
    }

    if (this.fixResults.length === 0) {
      return {
        success: false,
        reason: 'no_fixes',
        message: 'No fixes to commit'
      };
    }

    if (this.config.verbose) {
      console.log('\n🔄 Committing fixes to git...');
    }

    try {
      const commitResult = await this.gitIntegration.commitFixes(
        this.fixResults,
        { projectPath: this.config.projectPath }
      );

      if (commitResult.success) {
        if (this.config.verbose) {
          console.log(`\n✅ Git commit created successfully!`);
          if (commitResult.commitHash) {
            console.log(`   Commit: ${commitResult.commitHash}`);
          }
          if (commitResult.branch) {
            console.log(`   Branch: ${commitResult.branch}`);
          }
          console.log(`   Files: ${commitResult.filesStaged}`);
          console.log(`   Fixes: ${commitResult.fixesApplied}`);
        }
      } else {
        if (this.config.verbose) {
          console.log(`\n⚠️  Git commit skipped: ${commitResult.message}`);
        }
      }

      return commitResult;

    } catch (error) {
      if (this.config.verbose) {
        console.error(`\n❌ Git commit failed:`, error.message);
      }
      return {
        success: false,
        reason: 'git_error',
        message: error.message
      };
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    const stats = {
      ...this.stats,
      successRate: this.stats.attempted > 0
        ? (this.stats.succeeded / this.stats.attempted * 100).toFixed(1) + '%'
        : '0%'
    };

    // Add verification stats if verifier is enabled
    if (this.verifier) {
      stats.verification = this.verifier.getStats();
    }

    return stats;
  }

  /**
   * Get verification report
   */
  getVerificationReport() {
    if (!this.verifier) {
      return null;
    }
    return this.verifier.getReport();
  }

  /**
   * Get all fix results
   */
  getFixResults() {
    return this.fixResults;
  }

  /**
   * Reset fixer state
   */
  reset() {
    this.stats = {
      attempted: 0,
      succeeded: 0,
      failed: 0,
      skipped: 0
    };
    this.fixResults = [];
    if (this.gitIntegration) {
      this.gitIntegration.resetStats();
    }
  }
}

module.exports = AutoFixer;
