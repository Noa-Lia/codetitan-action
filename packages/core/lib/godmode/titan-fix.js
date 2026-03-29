/**
 * TITAN MODE Level 4: AI-Powered Adaptive Fixers
 *
 * Integrates multi-AI fix generation with TITAN MODE Level 4.
 * Automatically generates and applies fixes for common code issues.
 *
 * Capabilities:
 * - AI-generated fixes for SYNC_IO, HARDCODED_SECRET, SQL_INJECTION, etc.
 * - Confidence-based fix application (only apply high-confidence fixes)
 * - Automated testing after fix application
 * - Rollback on test failure
 * - Batch fix processing
 *
 * @module godmode/level4-ai-fixers
 */

const { AIProviderManager } = require('../ai-providers');
const { FixGenerator, FixApplier } = require('../ai-fixers');
const { ConfidenceScorer } = require('../ai-providers');
const fs = require('fs').promises;

class Level4AIFixers {
  constructor(config = {}) {
    this.config = {
      // Minimum confidence to auto-apply fixes
      minConfidence: config.minConfidence || 75,

      // Preferred AI provider for fix generation
      preferredProvider: config.preferredProvider || 'gpt-5-codex',

      // Run tests after applying fixes
      runTests: config.runTests !== false,

      // Rollback on test failure
      rollbackOnFailure: config.rollbackOnFailure !== false,

      // Maximum fixes to apply in one run
      maxFixesPerRun: config.maxFixesPerRun || 50,

      // Categories to auto-fix
      autoFixCategories: config.autoFixCategories || [
        'SYNC_IO',
        'HARDCODED_SECRET',
        'MISSING_AUTH',
        'WEAK_CRYPTO',
        'MAGIC_NUMBER',
        'UNUSED_VARIABLE'
      ],

      ...config
    };

    this.aiManager = new AIProviderManager();
    this.fixGenerator = new FixGenerator(this.aiManager, {
      preferredProvider: this.config.preferredProvider
    });
    this.fixApplier = new FixApplier({
      createBackups: true
    });
    this.confidenceScorer = new ConfidenceScorer();

    this.stats = {
      fixesGenerated: 0,
      fixesApplied: 0,
      fixesRolledBack: 0,
      totalCost: 0,
      testsPassed: 0,
      testsFailed: 0
    };
  }

  /**
   * Run Level 4 AI-powered fixes on analysis findings
   */
  async runLevel4Fixes(findings, options = {}) {
    console.log('[TITAN MODE Level 4] AI-Powered Adaptive Fixers\n');

    // Filter findings that are fixable
    const fixable = this.filterFixableFindings(findings);

    console.log(`[Level 4] Found ${fixable.length} fixable issues`);

    if (fixable.length === 0) {
      return {
        success: true,
        fixesApplied: 0,
        message: 'No fixable issues found'
      };
    }

    // Generate and apply fixes
    const results = [];

    for (const finding of fixable.slice(0, this.config.maxFixesPerRun)) {
      const result = await this.processFixForFinding(finding, options);
      results.push(result);

      if (result.applied) {
        this.stats.fixesApplied++;
      }
      if (result.rolledBack) {
        this.stats.fixesRolledBack++;
      }

      this.stats.totalCost += result.cost || 0;
    }

    // Summary
    const summary = {
      total: fixable.length,
      processed: results.length,
      applied: results.filter(r => r.applied).length,
      rolledBack: results.filter(r => r.rolledBack).length,
      failed: results.filter(r => !r.success).length,
      cost: this.stats.totalCost,
      results
    };

    console.log(`\n[Level 4] Summary:`);
    console.log(`   Fixes applied: ${summary.applied}`);
    console.log(`   Rolled back: ${summary.rolledBack}`);
    console.log(`   Failed: ${summary.failed}`);
    console.log(`   Cost: $${summary.cost.toFixed(4)}`);

    return summary;
  }

  /**
   * Filter findings that can be auto-fixed
   */
  filterFixableFindings(findings) {
    return findings.filter(finding => {
      // Must be in auto-fix categories
      if (!this.config.autoFixCategories.some(cat => finding.category.includes(cat))) {
        return false;
      }

      // Score confidence
      const confidence = this.confidenceScorer.score(finding);

      // Must meet minimum confidence
      if (confidence.score < this.config.minConfidence) {
        return false;
      }

      return true;
    });
  }

  /**
   * Process a single finding: generate fix, apply, test, rollback if needed
   */
  async processFixForFinding(finding, options = {}) {
    console.log(`\n[Level 4] Processing: ${finding.category} in ${finding.file_path}:${finding.line_number}`);

    const result = {
      finding,
      success: false,
      generated: false,
      applied: false,
      tested: false,
      testsPassed: false,
      rolledBack: false,
      cost: 0
    };

    try {
      // Read file content
      const content = await fs.readFile(finding.file_path, 'utf-8');

      // Generate fix using AI
      console.log(`   Generating AI fix (${this.config.preferredProvider})...`);
      const fixResult = await this.fixGenerator.generateFix(finding, content);

      result.cost = fixResult.fix?.cost || 0;
      this.stats.fixesGenerated++;

      if (!fixResult.success || !fixResult.fix.verified) {
        result.error = fixResult.error || 'Fix verification failed';
        console.log(`   ✗ Fix generation failed: ${result.error}`);
        return result;
      }

      result.generated = true;
      result.fix = fixResult.fix;

      console.log(`   ✓ Fix generated and verified`);
      console.log(`   Type: ${fixResult.fix.type}`);
      console.log(`   Explanation: ${fixResult.fix.explanation}`);

      // Apply fix
      console.log(`   Applying fix...`);
      const applyResult = await this.fixApplier.applyFix(
        finding.file_path,
        fixResult.fix
      );

      if (!applyResult.success) {
        result.error = applyResult.error;
        console.log(`   ✗ Fix application failed: ${result.error}`);
        return result;
      }

      result.applied = true;
      result.backupPath = applyResult.backupPath;
      result.fixId = applyResult.fixId;

      console.log(`   ✓ Fix applied (backup: ${applyResult.backupPath})`);

      // Run tests if enabled
      if (this.config.runTests) {
        console.log(`   Running tests...`);
        const testResult = await this.runTests(finding.file_path);

        result.tested = true;
        result.testsPassed = testResult.passed;

        if (testResult.passed) {
          console.log(`   ✓ Tests passed`);
          this.stats.testsPassed++;
          result.success = true;
        } else {
          console.log(`   ✗ Tests failed: ${testResult.error}`);
          this.stats.testsFailed++;

          // Rollback if configured
          if (this.config.rollbackOnFailure) {
            console.log(`   Rolling back fix...`);
            const rollbackResult = await this.fixApplier.rollback(result.fixId);

            if (rollbackResult.success) {
              result.rolledBack = true;
              console.log(`   ✓ Fix rolled back`);
            } else {
              console.log(`   ✗ Rollback failed: ${rollbackResult.error}`);
            }
          }
        }
      } else {
        // No testing, assume success
        result.success = true;
      }

      return result;

    } catch (error) {
      result.error = error.message;
      console.log(`   ✗ Error: ${error.message}`);
      return result;
    }
  }

  /**
   * Run tests for a file using the detected test framework.
   */
  async runTests(filePath) {
    const projectRoot = this.config.projectRoot || process.cwd();
    const TestRunnerDetector = require('../test-runner-detector');
    const TestExecutor = require('../test-executor');
    const detector = new TestRunnerDetector(projectRoot);
    const executor = new TestExecutor(projectRoot, detector);

    try {
      const result = await executor.runRelated(filePath, { timeout: 60000 });
      return {
        passed: result.failed === 0,
        output: result.output,
        details: result
      };
    } catch (err) {
      return { passed: false, output: err.message, error: true };
    }
  }

  /**
   * Get Level 4 statistics
   */
  getStats() {
    return {
      ...this.stats,
      successRate: this.stats.fixesApplied > 0
        ? (this.stats.fixesApplied - this.stats.fixesRolledBack) / this.stats.fixesApplied
        : 0,
      avgCostPerFix: this.stats.fixesGenerated > 0
        ? this.stats.totalCost / this.stats.fixesGenerated
        : 0
    };
  }
}

module.exports = Level4AIFixers;
