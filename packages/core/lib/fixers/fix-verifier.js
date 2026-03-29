/**
 * Fix Verification System
 *
 * Validates fixes after application to ensure code quality and correctness.
 *
 * Features:
 * - AST validation for syntax errors
 * - Test execution for modified files
 * - Auto-rollback on verification failure
 * - Detailed verification reports
 */

const { parse } = require('@babel/parser');
const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');

class FixVerifier {
  constructor(options = {}) {
    this.options = {
      enableAstValidation: options.enableAstValidation !== false,
      enableTestExecution: options.enableTestExecution !== false,
      enableRollback: options.enableRollback !== false,
      testCommand: options.testCommand || 'npm test',
      testTimeout: options.testTimeout || 60000,
      backupDir: options.backupDir || '.backup',
      ...options
    };

    this.verificationResults = [];
    this.stats = {
      totalVerified: 0,
      passed: 0,
      failed: 0,
      rolledBack: 0
    };
  }

  /**
   * Verify a fix after it's been applied
   * @param {Object} fix - The fix that was applied
   * @param {string} fix.filePath - Path to the modified file
   * @param {string} fix.type - Type of fix applied
   * @param {string} fix.originalContent - Original file content (for rollback)
   * @returns {Promise<Object>} Verification result
   */
  async verifyFix(fix) {
    const result = {
      filePath: fix.filePath,
      fixType: fix.type,
      timestamp: new Date().toISOString(),
      checks: {
        ast: null,
        syntax: null,
        tests: null
      },
      passed: false,
      errors: [],
      rolledBack: false
    };

    try {
      // Step 1: AST Validation
      if (this.options.enableAstValidation) {
        result.checks.ast = await this.validateAst(fix.filePath);
        if (!result.checks.ast.valid) {
          result.errors.push({
            type: 'AST_VALIDATION',
            message: result.checks.ast.error
          });
        }
      }

      // Step 2: Syntax Check
      if (this.options.enableAstValidation) {
        result.checks.syntax = await this.checkSyntax(fix.filePath);
        if (!result.checks.syntax.valid) {
          result.errors.push({
            type: 'SYNTAX_ERROR',
            message: result.checks.syntax.error
          });
        }
      }

      // Step 3: Run Tests (if available)
      if (this.options.enableTestExecution) {
        result.checks.tests = await this.runTests(fix.filePath);
        if (result.checks.tests && !result.checks.tests.passed) {
          result.errors.push({
            type: 'TEST_FAILURE',
            message: result.checks.tests.error
          });
        }
      }

      // Determine if verification passed
      result.passed = result.errors.length === 0;

      // Step 4: Auto-rollback if verification failed
      if (!result.passed && this.options.enableRollback && fix.originalContent) {
        await this.rollback(fix.filePath, fix.originalContent);
        result.rolledBack = true;
        this.stats.rolledBack++;
      }

      // Update stats
      this.stats.totalVerified++;
      if (result.passed) {
        this.stats.passed++;
      } else {
        this.stats.failed++;
      }

      this.verificationResults.push(result);
      return result;

    } catch (error) {
      result.errors.push({
        type: 'VERIFICATION_ERROR',
        message: error.message
      });
      result.passed = false;
      this.stats.failed++;
      this.verificationResults.push(result);
      return result;
    }
  }

  /**
   * Validate AST of a file
   * @param {string} filePath - Path to the file
   * @returns {Promise<Object>} AST validation result
   */
  async validateAst(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const ext = path.extname(filePath);

      // Determine parser plugins based on file extension
      const plugins = ['jsx', 'classProperties', 'objectRestSpread'];
      if (ext === '.ts' || ext === '.tsx') {
        plugins.push('typescript');
      }
      if (ext === '.tsx' || ext === '.jsx') {
        plugins.push('jsx');
      }

      // Parse the file
      parse(content, {
        sourceType: 'module',
        plugins,
        errorRecovery: false
      });

      return {
        valid: true,
        message: 'AST validation passed'
      };

    } catch (error) {
      return {
        valid: false,
        error: error.message,
        location: error.loc
      };
    }
  }

  /**
   * Check basic syntax using Node.js
   * @param {string} filePath - Path to the file
   * @returns {Promise<Object>} Syntax check result
   */
  async checkSyntax(filePath) {
    try {
      const ext = path.extname(filePath);

      // Only check .js files with Node.js
      if (ext === '.js') {
        const content = await fs.readFile(filePath, 'utf-8');

        // Try to compile the code
        try {
          new Function(content); // This will catch basic syntax errors
        } catch (syntaxError) {
          return {
            valid: false,
            error: syntaxError.message
          };
        }
      }

      return {
        valid: true,
        message: 'Syntax check passed'
      };

    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }

  /**
   * Run tests for a specific file using the detected test framework.
   * @param {string} filePath - Path to the file
   * @returns {Promise<Object>} Test execution result
   */
  async runTests(filePath) {
    const projectRoot = this.options.projectRoot || process.cwd();
    const TestRunnerDetector = require('../test-runner-detector');
    const TestExecutor = require('../test-executor');
    const detector = new TestRunnerDetector(projectRoot);
    const executor = new TestExecutor(projectRoot, detector);

    try {
      const result = await executor.runRelated(filePath, {
        timeout: this.options.testTimeout || 60000
      });
      return {
        passed: result.failed === 0 && !result.noTests,
        skipped: result.noTests || false,
        message: result.noTests ? 'No related tests found' : undefined,
        output: result.output,
        details: result
      };
    } catch (error) {
      return {
        skipped: true,
        message: `Test execution error: ${error.message}`
      };
    }
  }

  /**
   * Find test file for a given source file
   * @param {string} filePath - Source file path
   * @returns {string|null} Test file path
   */
  findTestFile(filePath) {
    const dir = path.dirname(filePath);
    const basename = path.basename(filePath, path.extname(filePath));
    const ext = path.extname(filePath);

    // Common test file patterns
    const patterns = [
      path.join(dir, '__tests__', `${basename}.test${ext}`),
      path.join(dir, '__tests__', `${basename}.spec${ext}`),
      path.join(dir, `${basename}.test${ext}`),
      path.join(dir, `${basename}.spec${ext}`)
    ];

    // Return first matching pattern
    for (const pattern of patterns) {
      return pattern; // We'll check existence in runTests
    }

    return null;
  }

  /**
   * Rollback a file to its original content
   * @param {string} filePath - Path to the file
   * @param {string} originalContent - Original content to restore
   * @returns {Promise<void>}
   */
  async rollback(filePath, originalContent) {
    try {
      await fs.writeFile(filePath, originalContent, 'utf-8');
      console.log(`⏪ Rolled back ${filePath}`);
    } catch (error) {
      console.error(`❌ Failed to rollback ${filePath}:`, error.message);
      throw error;
    }
  }

  /**
   * Verify multiple fixes in batch
   * @param {Array} fixes - Array of fixes to verify
   * @returns {Promise<Array>} Array of verification results
   */
  async verifyBatch(fixes) {
    const results = [];

    for (const fix of fixes) {
      const result = await this.verifyFix(fix);
      results.push(result);
    }

    return results;
  }

  /**
   * Get verification statistics
   * @returns {Object} Statistics object
   */
  getStats() {
    return {
      ...this.stats,
      successRate: this.stats.totalVerified > 0
        ? ((this.stats.passed / this.stats.totalVerified) * 100).toFixed(1)
        : 0
    };
  }

  /**
   * Get detailed verification report
   * @returns {Object} Detailed report
   */
  getReport() {
    return {
      stats: this.getStats(),
      results: this.verificationResults,
      failedFixes: this.verificationResults.filter(r => !r.passed),
      rolledBackFixes: this.verificationResults.filter(r => r.rolledBack)
    };
  }

  /**
   * Reset verifier state
   */
  reset() {
    this.verificationResults = [];
    this.stats = {
      totalVerified: 0,
      passed: 0,
      failed: 0,
      rolledBack: 0
    };
  }

  /**
   * Print verification summary
   */
  printSummary() {
    const stats = this.getStats();

    console.log('\n' + '─'.repeat(60));
    console.log('📋 Fix Verification Summary');
    console.log('─'.repeat(60));
    console.log(`   Total Verified:  ${stats.totalVerified}`);
    console.log(`   ✅ Passed:        ${stats.passed}`);
    console.log(`   ❌ Failed:        ${stats.failed}`);
    console.log(`   ⏪ Rolled Back:   ${stats.rolledBack}`);
    console.log(`   Success Rate:    ${stats.successRate}%`);
    console.log('─'.repeat(60));

    // Print failed fixes details
    if (stats.failed > 0) {
      console.log('\n❌ Failed Verifications:');
      this.verificationResults
        .filter(r => !r.passed)
        .forEach(r => {
          console.log(`   ${r.filePath}`);
          r.errors.forEach(e => {
            console.log(`      • ${e.type}: ${e.message}`);
          });
        });
    }
  }
}

module.exports = FixVerifier;
