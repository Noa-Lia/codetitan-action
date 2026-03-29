'use strict';

const fs = require('fs').promises;
const path = require('path');

/**
 * ArenaJudge — evaluates a single contender's fix quality.
 * Separated from TitanArena for testability.
 */
class ArenaJudge {
  constructor(projectRoot, config = {}) {
    this.projectRoot = projectRoot || process.cwd();
    this.config = {
      weights: {
        testScore: 0.40,
        qualityDelta: 0.25,
        securityClean: 0.20,
        confidenceScore: 0.15,
      },
      ...config
    };
  }

  /**
   * Full evaluation of a fix in a worktree.
   * @param {string} originalCode
   * @param {string} fixedCode
   * @param {string} filePath - Relative file path within the project
   * @param {string} worktreePath - Absolute path to git worktree root
   * @param {Object} [options]
   * @param {Function} [options.runTests] - Override test runner (for testing)
   * @returns {Promise<Object>} Evaluation result with score
   */
  async evaluate(originalCode, fixedCode, filePath, worktreePath, options = {}) {
    const result = {
      testsPass: false,
      testResults: { passed: 0, failed: 0, total: 0 },
      findingsBefore: 0,
      findingsAfter: 0,
      qualityDelta: 0,
      newSecurityIssues: [],
      syntaxValid: false,
      performanceDelta: null,
      score: 0
    };

    // 1. Syntax check first — fastest gate
    const syntaxResult = await this.checkSyntax(fixedCode, filePath, worktreePath);
    result.syntaxValid = syntaxResult.valid;
    if (!syntaxResult.valid) {
      result.score = 0;
      result.syntaxErrors = syntaxResult.errors;
      return result;
    }

    // 2. Run tests in the worktree
    let testResults;
    if (options.runTests) {
      testResults = await options.runTests(filePath, worktreePath);
    } else {
      testResults = await this.runTests(filePath, worktreePath);
    }
    result.testResults = testResults;
    result.testsPass = testResults.failed === 0 && !testResults.noTests;

    // 3. Run domain analysis on original vs fixed
    const [beforeFindings, afterFindings] = await Promise.all([
      this.runAnalysis(filePath, originalCode),
      this.runAnalysis(filePath, fixedCode)
    ]);
    result.findingsBefore = beforeFindings.total;
    result.findingsAfter = afterFindings.total;
    result.qualityDelta = beforeFindings.total - afterFindings.total; // positive = improved

    // 4. Security check on the new code
    result.newSecurityIssues = await this.runSecurityCheck(fixedCode, filePath, beforeFindings);

    // 5. Calculate composite score
    result.score = this.calculateScore(result);

    return result;
  }

  /**
   * Runs domain-analyzers.js on a piece of code.
   */
  async runAnalysis(filePath, code) {
    try {
      const { analyzeDomain } = require('./domain-analyzers');
      const domains = ['security-god', 'performance-god', 'refactoring-god'];
      let total = 0;
      const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

      for (const domain of domains) {
        const findings = analyzeDomain(domain, filePath, code, this.projectRoot);
        const issues = findings?.issues || findings || [];
        total += issues.length;
        for (const issue of issues) {
          const sev = issue.severity || 'LOW';
          bySeverity[sev] = (bySeverity[sev] || 0) + 1;
        }
      }

      return { total, bySeverity };
    } catch {
      return { total: 0, bySeverity: {} };
    }
  }

  /**
   * Finds new security issues introduced by the fix (not present in original).
   */
  async runSecurityCheck(fixedCode, filePath, beforeFindings) {
    try {
      const { analyzeDomain } = require('./domain-analyzers');
      const afterIssues = analyzeDomain('security-god', filePath, fixedCode, this.projectRoot);
      const issues = afterIssues?.issues || afterIssues || [];

      // Return CRITICAL/HIGH issues that look new
      const serious = issues.filter(i =>
        i.severity === 'CRITICAL' || i.severity === 'HIGH'
      );

      // Simple heuristic: if after has more HIGH/CRITICAL than before, report delta
      const beforeCount = (beforeFindings?.bySeverity?.CRITICAL || 0) +
                          (beforeFindings?.bySeverity?.HIGH || 0);
      const afterCount = serious.length;

      if (afterCount > beforeCount) {
        return serious.slice(0, afterCount - beforeCount).map(i => i.message || i.id || 'unknown');
      }
      return [];
    } catch {
      return [];
    }
  }

  /**
   * Runs tests related to the changed file inside the worktree.
   */
  async runTests(filePath, worktreePath) {
    const TestRunnerDetector = require('./test-runner-detector');
    const TestExecutor = require('./test-executor');
    const detector = new TestRunnerDetector(worktreePath);
    const executor = new TestExecutor(worktreePath, detector);

    try {
      const absFilePath = path.join(worktreePath, filePath);
      const result = await executor.runRelated(absFilePath, { timeout: 90000 });
      return {
        passed: result.passed || 0,
        failed: result.failed || 0,
        total: result.total || 0,
        noTests: result.noTests || false,
        output: result.output || ''
      };
    } catch (err) {
      return { passed: 0, failed: 0, total: 0, noTests: true, error: err.message };
    }
  }

  /**
   * Validates syntax of fixed code.
   */
  async checkSyntax(code, filePath, worktreePath) {
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'].includes(ext)) {
      return { valid: true, errors: [] };
    }
    try {
      const { parse } = require('@babel/parser');
      parse(code, {
        sourceType: 'unambiguous',
        plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties']
      });
      return { valid: true, errors: [] };
    } catch (err) {
      return { valid: false, errors: [err.message] };
    }
  }

  /**
   * Weighted composite score: 0.0 – 1.0
   */
  calculateScore(evaluation) {
    const w = this.config.weights;

    // testScore: 1 if all pass (or no tests found), 0 if any fail
    const testScore = evaluation.testsPass || evaluation.testResults?.noTests ? 1.0 : 0.0;

    // qualityDelta: normalise to 0–1, capped
    const rawDelta = evaluation.qualityDelta;
    const qualityScore = rawDelta > 0
      ? Math.min(1.0, rawDelta / 5)   // up to 5 fewer findings = full score
      : rawDelta === 0 ? 0.5           // neutral
      : 0.0;                           // regression

    // securityClean: 1 if no new security issues
    const securityScore = evaluation.newSecurityIssues.length === 0 ? 1.0 : 0.0;

    // confidenceScore: placeholder — real value injected by TitanArena after ML scoring
    const confidenceScore = evaluation.confidenceScore != null ? evaluation.confidenceScore : 0.5;

    const total =
      testScore        * w.testScore +
      qualityScore     * w.qualityDelta +
      securityScore    * w.securityClean +
      confidenceScore  * w.confidenceScore;

    return Math.round(total * 1000) / 1000; // 3 decimal places
  }
}

module.exports = ArenaJudge;
