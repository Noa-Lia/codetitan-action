/**
 * CI/CD Outcome Recorder
 *
 * Automatically records outcomes from CI/CD pipelines:
 * - Test results (unit, integration, e2e)
 * - Build results (syntax, compilation)
 * - Deployment results (smoke tests, health checks)
 * - Production monitoring (error rates, performance)
 *
 * Supports multiple CI platforms:
 * - GitHub Actions
 * - GitLab CI
 * - Jenkins
 * - CircleCI
 * - Travis CI
 *
 * @module ci-outcome-recorder
 */

const { createClient } = require('@supabase/supabase-js');
const fs = require('fs').promises;
const path = require('path');

class CIOutcomeRecorder {
  constructor(config = {}) {
    this.config = {
      supabaseUrl: config.supabaseUrl || process.env.SUPABASE_URL,
      supabaseKey: config.supabaseKey || process.env.SUPABASE_SERVICE_KEY,
      runId: config.runId,
      projectId: config.projectId,
      verbose: config.verbose || false,
      ...config
    };

    // Initialize Supabase client
    if (this.config.supabaseUrl && this.config.supabaseKey) {
      this.supabase = createClient(
        this.config.supabaseUrl,
        this.config.supabaseKey
      );
    }

    this.stats = {
      outcomesRecorded: 0,
      testsProcessed: 0,
      buildsProcessed: 0,
      deploymentsProcessed: 0,
      errors: 0
    };
  }

  /**
   * Record test results and map to confidence scores
   *
   * @param {Object} testResults - Test results from CI
   * @returns {Promise<Object>} Recording results
   */
  async recordTestResults(testResults) {
    this.log('📊 Recording test results...');

    const {
      runId = this.config.runId,
      projectId = this.config.projectId,
      results = [],
      summary = {},
      format = 'jest' // jest, mocha, pytest, etc.
    } = testResults;

    if (!runId || !projectId) {
      throw new Error('runId and projectId are required');
    }

    const outcomes = [];

    // Get confidence scores for this run
    const { data: scores, error: scoresError } = await this.supabase
      .from('confidence_scores')
      .select('*')
      .eq('run_id', runId)
      .eq('fix_applied', true);

    if (scoresError) {
      this.log(`⚠️  Could not fetch confidence scores: ${scoresError.message}`, 'error');
      return { recorded: 0, error: scoresError.message };
    }

    if (!scores || scores.length === 0) {
      this.log('⚠️  No confidence scores found for this run');
      return { recorded: 0, message: 'No confidence scores to validate' };
    }

    this.log(`Found ${scores.length} confidence scores to validate`);

    // Parse test results based on format
    const parsedResults = this.parseTestResults(results, format);

    // Map test results to confidence scores
    for (const score of scores) {
      const testResult = this.findMatchingTest(score, parsedResults);

      if (testResult) {
        const outcome = {
          confidence_score_id: score.id,
          finding_id: score.finding_id,
          outcome_type: testResult.passed ? 'FIX_VALIDATED' : 'FIX_FAILED',
          outcome_status: testResult.passed ? 'SUCCESS' : 'FAILURE',
          was_correct: testResult.passed, // If test passed, fix was correct
          fix_worked: testResult.passed,
          introduced_bugs: !testResult.passed,
          syntax_valid: !testResult.syntaxError,
          tests_passed: testResult.passed,
          build_succeeded: true, // If we got to tests, build succeeded
          validation_method: 'ci_cd',
          time_to_outcome_ms: testResult.duration || null,
          impact_assessment: {
            test_name: testResult.name,
            test_file: testResult.file,
            test_suite: testResult.suite,
            error_message: testResult.error || null
          }
        };

        outcomes.push(outcome);
        this.stats.testsProcessed++;
      }
    }

    // For scores without matching tests, record general outcome
    for (const score of scores) {
      const hasOutcome = outcomes.find(o => o.confidence_score_id === score.id);
      if (!hasOutcome) {
        // No specific test, use overall test suite result
        const allTestsPassed = summary.passed === summary.total;

        outcomes.push({
          confidence_score_id: score.id,
          finding_id: score.finding_id,
          outcome_type: 'TEST_SUITE_RAN',
          outcome_status: allTestsPassed ? 'SUCCESS' : 'PARTIAL',
          was_correct: allTestsPassed ? true : null, // Uncertain
          fix_worked: allTestsPassed ? true : null,
          introduced_bugs: false,
          syntax_valid: true,
          tests_passed: allTestsPassed,
          build_succeeded: true,
          validation_method: 'ci_cd',
          impact_assessment: {
            total_tests: summary.total,
            passed_tests: summary.passed,
            failed_tests: summary.failed
          }
        });
      }
    }

    // Insert outcomes
    if (outcomes.length > 0) {
      const { data, error } = await this.supabase
        .from('confidence_outcomes')
        .insert(outcomes)
        .select();

      if (error) {
        this.log(`❌ Failed to record outcomes: ${error.message}`, 'error');
        this.stats.errors++;
        return { recorded: 0, error: error.message };
      }

      this.stats.outcomesRecorded += outcomes.length;
      this.log(`✅ Recorded ${outcomes.length} test outcomes`);

      return {
        recorded: outcomes.length,
        outcomes: data
      };
    }

    return { recorded: 0 };
  }

  /**
   * Record build results
   *
   * @param {Object} buildResults - Build results from CI
   * @returns {Promise<Object>} Recording results
   */
  async recordBuildResults(buildResults) {
    this.log('🔨 Recording build results...');

    const {
      runId = this.config.runId,
      projectId = this.config.projectId,
      success,
      errors = [],
      warnings = [],
      duration
    } = buildResults;

    if (!runId || !projectId) {
      throw new Error('runId and projectId are required');
    }

    // Get confidence scores for this run
    const { data: scores, error: scoresError } = await this.supabase
      .from('confidence_scores')
      .select('*')
      .eq('run_id', runId)
      .eq('fix_applied', true);

    if (scoresError || !scores || scores.length === 0) {
      return { recorded: 0 };
    }

    const outcomes = [];

    // Map build errors to confidence scores
    for (const score of scores) {
      const relevantErrors = errors.filter(err =>
        err.file === score.file_path &&
        Math.abs(err.line - score.line_number) < 5 // Within 5 lines
      );

      const hasError = relevantErrors.length > 0;

      outcomes.push({
        confidence_score_id: score.id,
        finding_id: score.finding_id,
        outcome_type: hasError ? 'BUILD_FAILED' : 'BUILD_PASSED',
        outcome_status: hasError ? 'FAILURE' : 'SUCCESS',
        was_correct: !hasError, // If no build error, fix was correct
        fix_worked: !hasError,
        introduced_bugs: hasError,
        syntax_valid: !hasError,
        tests_passed: null, // Not tested yet
        build_succeeded: !hasError,
        validation_method: 'ci_cd',
        time_to_outcome_ms: duration,
        impact_assessment: {
          build_errors: relevantErrors.length,
          error_messages: relevantErrors.map(e => e.message)
        }
      });

      this.stats.buildsProcessed++;
    }

    if (outcomes.length > 0) {
      const { data, error } = await this.supabase
        .from('confidence_outcomes')
        .insert(outcomes)
        .select();

      if (error) {
        this.stats.errors++;
        return { recorded: 0, error: error.message };
      }

      this.stats.outcomesRecorded += outcomes.length;
      this.log(`✅ Recorded ${outcomes.length} build outcomes`);

      return { recorded: outcomes.length, outcomes: data };
    }

    return { recorded: 0 };
  }

  /**
   * Record deployment results (staging/production)
   *
   * @param {Object} deploymentResults - Deployment results
   * @returns {Promise<Object>} Recording results
   */
  async recordDeploymentResults(deploymentResults) {
    this.log('🚀 Recording deployment results...');

    const {
      runId = this.config.runId,
      projectId = this.config.projectId,
      environment,
      success,
      smokeTests = [],
      healthChecks = [],
      errorRate = null,
      latency = null,
      duration
    } = deploymentResults;

    if (!runId || !projectId) {
      throw new Error('runId and projectId are required');
    }

    const { data: scores, error: scoresError } = await this.supabase
      .from('confidence_scores')
      .select('*')
      .eq('run_id', runId)
      .eq('fix_applied', true);

    if (scoresError || !scores || scores.length === 0) {
      return { recorded: 0 };
    }

    const outcomes = [];
    const allSmokeTestsPassed = smokeTests.every(t => t.passed);
    const allHealthChecksPassed = healthChecks.every(h => h.healthy);

    for (const score of scores) {
      outcomes.push({
        confidence_score_id: score.id,
        finding_id: score.finding_id,
        outcome_type: `DEPLOYED_${environment.toUpperCase()}`,
        outcome_status: success && allSmokeTestsPassed && allHealthChecksPassed ? 'SUCCESS' : 'FAILURE',
        was_correct: success && allSmokeTestsPassed,
        fix_worked: success && allSmokeTestsPassed,
        introduced_bugs: !allHealthChecksPassed,
        syntax_valid: true,
        tests_passed: allSmokeTestsPassed,
        build_succeeded: true,
        validation_method: 'production_monitoring',
        time_to_outcome_ms: duration,
        impact_assessment: {
          environment,
          smoke_tests_passed: smokeTests.filter(t => t.passed).length,
          smoke_tests_total: smokeTests.length,
          health_checks_passed: healthChecks.filter(h => h.healthy).length,
          health_checks_total: healthChecks.length,
          error_rate: errorRate,
          latency_p95: latency
        }
      });

      this.stats.deploymentsProcessed++;
    }

    if (outcomes.length > 0) {
      const { data, error } = await this.supabase
        .from('confidence_outcomes')
        .insert(outcomes)
        .select();

      if (error) {
        this.stats.errors++;
        return { recorded: 0, error: error.message };
      }

      this.stats.outcomesRecorded += outcomes.length;
      this.log(`✅ Recorded ${outcomes.length} deployment outcomes`);

      return { recorded: outcomes.length, outcomes: data };
    }

    return { recorded: 0 };
  }

  /**
   * Load test results from file
   *
   * @param {string} filePath - Path to test results file
   * @param {string} format - Format (jest, mocha, junit, etc.)
   * @returns {Promise<Object>} Parsed test results
   */
  async loadTestResults(filePath, format = 'jest') {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const results = JSON.parse(content);

      return this.parseTestResults(results, format);
    } catch (error) {
      this.log(`❌ Failed to load test results: ${error.message}`, 'error');
      throw error;
    }
  }

  /**
   * Parse test results based on format
   *
   * @param {Object|Array} results - Raw test results
   * @param {string} format - Test framework format
   * @returns {Array} Normalized test results
   */
  parseTestResults(results, format) {
    switch (format.toLowerCase()) {
      case 'jest':
        return this.parseJestResults(results);
      case 'mocha':
        return this.parseMochaResults(results);
      case 'junit':
        return this.parseJUnitResults(results);
      case 'pytest':
        return this.parsePytestResults(results);
      default:
        return this.parseGenericResults(results);
    }
  }

  /**
   * Parse Jest test results
   */
  parseJestResults(results) {
    const parsed = [];

    if (results.testResults) {
      for (const testFile of results.testResults) {
        for (const testCase of testFile.assertionResults || []) {
          parsed.push({
            name: testCase.title,
            file: testFile.name,
            suite: testCase.ancestorTitles?.join(' > '),
            passed: testCase.status === 'passed',
            duration: testCase.duration,
            error: testCase.failureMessages?.join('\n'),
            syntaxError: false
          });
        }
      }
    }

    return parsed;
  }

  /**
   * Parse Mocha test results
   */
  parseMochaResults(results) {
    const parsed = [];

    if (results.tests) {
      for (const test of results.tests) {
        parsed.push({
          name: test.title,
          file: test.file,
          suite: test.fullTitle,
          passed: test.state === 'passed',
          duration: test.duration,
          error: test.err?.message,
          syntaxError: false
        });
      }
    }

    return parsed;
  }

  /**
   * Parse JUnit XML results
   */
  parseJUnitResults(results) {
    // Simplified - would need XML parser for full implementation
    return this.parseGenericResults(results);
  }

  /**
   * Parse pytest results
   */
  parsePytestResults(results) {
    const parsed = [];

    if (results.tests) {
      for (const test of results.tests) {
        parsed.push({
          name: test.nodeid,
          file: test.location?.[0],
          suite: test.location?.[2],
          passed: test.outcome === 'passed',
          duration: test.duration,
          error: test.longrepr,
          syntaxError: false
        });
      }
    }

    return parsed;
  }

  /**
   * Parse generic test results
   */
  parseGenericResults(results) {
    if (Array.isArray(results)) {
      return results.map(r => ({
        name: r.name || r.test || 'unknown',
        file: r.file || r.filePath,
        suite: r.suite || r.describe,
        passed: r.passed || r.status === 'passed',
        duration: r.duration || r.time,
        error: r.error || r.message,
        syntaxError: false
      }));
    }

    return [];
  }

  /**
   * Find test matching a confidence score
   *
   * @param {Object} score - Confidence score
   * @param {Array} tests - Parsed test results
   * @returns {Object|null} Matching test or null
   */
  findMatchingTest(score, tests) {
    // Try exact file match first
    const fileMatches = tests.filter(t =>
      t.file && score.file_path && t.file.includes(path.basename(score.file_path))
    );

    if (fileMatches.length === 1) {
      return fileMatches[0];
    }

    // Try category-based matching
    const categoryKeywords = {
      'SQL_INJECTION': ['sql', 'injection', 'query', 'database'],
      'XSS': ['xss', 'escape', 'sanitize', 'html'],
      'COMMAND_EXEC': ['command', 'exec', 'shell'],
      'HARDCODED_SECRET': ['secret', 'key', 'token', 'password']
    };

    const keywords = categoryKeywords[score.category] || [];

    for (const test of tests) {
      const testName = (test.name + test.suite + test.file).toLowerCase();
      if (keywords.some(kw => testName.includes(kw))) {
        return test;
      }
    }

    return null;
  }

  /**
   * Detect CI platform
   */
  static detectPlatform() {
    if (process.env.GITHUB_ACTIONS) return 'github';
    if (process.env.GITLAB_CI) return 'gitlab';
    if (process.env.JENKINS_URL) return 'jenkins';
    if (process.env.CIRCLECI) return 'circleci';
    if (process.env.TRAVIS) return 'travis';
    return 'unknown';
  }

  /**
   * Get CI environment info
   */
  static getCIInfo() {
    const platform = CIOutcomeRecorder.detectPlatform();

    const info = {
      platform,
      branch: process.env.GITHUB_REF || process.env.CI_COMMIT_REF_NAME || process.env.GIT_BRANCH,
      commit: process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || process.env.GIT_COMMIT,
      buildNumber: process.env.GITHUB_RUN_NUMBER || process.env.CI_PIPELINE_ID || process.env.BUILD_NUMBER,
      buildUrl: process.env.GITHUB_SERVER_URL ?
        `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` :
        process.env.CI_PIPELINE_URL || process.env.BUILD_URL,
      isPR: !!process.env.GITHUB_HEAD_REF || !!process.env.CI_MERGE_REQUEST_ID,
      prNumber: process.env.GITHUB_PR_NUMBER || process.env.CI_MERGE_REQUEST_IID
    };

    return info;
  }

  /**
   * Log message
   */
  log(message, level = 'info') {
    if (this.config.verbose || level === 'error') {
      const prefix = level === 'error' ? '❌' : 'ℹ️';
      console.log(`${prefix} [CIOutcomeRecorder] ${message}`);
    }
  }

  /**
   * Get recorder statistics
   */
  getStats() {
    return { ...this.stats };
  }
}

module.exports = CIOutcomeRecorder;
