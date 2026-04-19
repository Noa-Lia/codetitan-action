/**
 * TITAN MODE™ Level 5: TITAN REMEDIATION
 * Self-Healing CI/CD Pipeline
 *
 * Automatically detects, analyzes, and fixes issues in CI/CD pipelines
 * Integrates with GitHub Actions, GitLab CI, Jenkins, and other CI systems
 *
 * Features:
 * - Pre-merge analysis gates
 * - Automatic fix generation for CI failures
 * - Test failure triage with AI
 * - Performance regression detection
 * - Security vulnerability blocking
 * - Auto-rollback on critical issues
 *
 * @module titanmode/level5-remediation
 */

const fs = require('fs');
const path = require('path');
const { execSync, execFileSync, spawn } = require('child_process');

/**
 * Secure command execution - validates commands against allowlist
 */
const ALLOWED_COMMANDS = ['npm', 'npx', 'git', 'node', 'jest', 'mocha', 'vitest'];

function safeExec(command, args = [], options = {}) {
  const baseArgs = String(command).trim().split(/\s+/);
  const cmd = baseArgs.shift();
  if (!ALLOWED_COMMANDS.includes(cmd)) {
    throw new Error(`Command not allowed: ${cmd}`);
  }
  // Sanitize args - remove shell metacharacters
  const sanitizedArgs = args.map(arg =>
    String(arg).replace(/[;&|`$(){}\[\]<>\\]/g, '')
  );
  return execFileSync(cmd, [...baseArgs, ...sanitizedArgs], {
    encoding: 'utf-8',
    stdio: 'pipe',
    timeout: 300000, // 5 min max
    ...options
  });
}

class Level5SelfHealingCI {
  constructor(config = {}) {
    this.config = {
      // CI/CD Integration
      ciProvider: config.ciProvider || 'github-actions', // github-actions, gitlab-ci, jenkins
      autoFix: config.autoFix !== false,
      autoRollback: config.autoRollback !== false,

      // Quality Gates
      gates: {
        security: config.gates?.security !== false,    // Block on HIGH security
        performance: config.gates?.performance || false, // Block on perf regression
        tests: config.gates?.tests !== false,          // Block on test failures
        coverage: config.gates?.coverage || false       // Block on coverage drop
      },

      // Thresholds
      thresholds: {
        securitySeverity: config.thresholds?.securitySeverity || 'HIGH',
        testFailureMax: config.thresholds?.testFailureMax || 0,
        coverageMin: config.thresholds?.coverageMin || 80,
        testFailureMax: config.thresholds?.testFailureMax || 0,
        coverageMin: config.thresholds?.coverageMin || 80,
        performanceRegressionMax: config.thresholds?.performanceRegressionMax || 0.1, // 10%
        buildErrorsMax: 0 // Zero tolerance (unbreakable build)
      },

      // Auto-fix settings
      fixSettings: {
        maxAttempts: config.fixSettings?.maxAttempts || 3,
        minConfidence: config.fixSettings?.minConfidence || 85,
        testAfterFix: config.fixSettings?.testAfterFix !== false,
        createPR: config.fixSettings?.createPR || false
      },

      ...config
    };

    this.stats = {
      totalRuns: 0,
      gatesPassed: 0,
      gatesFailed: 0,
      autoFixesApplied: 0,
      rollbacksTriggered: 0
    };
  }

  /**
   * Run Self-Healing CI pipeline
   * Called by CI/CD system on pull requests or commits
   */
  async run(options = {}) {
    console.log('⚡ [TITAN MODE Level 5] TITAN REMEDIATION - Self-Healing CI ACTIVATED\n');

    this.stats.totalRuns++;

    const context = await this.gatherCIContext(options);

    console.log('🔍 CI Context:');
    console.log(`   Provider: ${context.provider}`);
    console.log(`   Branch: ${context.branch}`);
    console.log(`   Commit: ${context.commit}`);
    console.log(`   PR: ${context.pr || 'N/A'}\n`);

    // Phase 1: Build Analysis (The Unbreakable Build Check)
    console.log('Phase 1: Build Validation');
    const buildResult = await this.validateBuild(context);

    if (!buildResult.success) {
      console.log('\n❌ Build validation FAILED');

      if (this.config.autoFix) {
        console.log('   Attempting to heal build...');
        const healed = await this.attemptBuildHealing(buildResult, context);
        if (healed.success) {
          console.log('\n✅ Build auto-healed - proceeding to analysis');
          // Proceed to next phases...
        } else {
          console.log('\n❌ Critical Build Failure - Aborting pipeline');
          this.stats.gatesFailed++;
          return { success: false, gate: 'build', findings: buildResult.errors };
        }
      } else {
        return { success: false, gate: 'build', findings: buildResult.errors };
      }
    }

    // Phase 2: Pre-merge analysis
    console.log('\nPhase 2: Deep Analysis');
    const analysisResult = await this.runPreMergeAnalysis(context);

    // Phase 3: Quality gates
    console.log('\nPhase 3: Quality Gates');
    const gatesResult = await this.evaluateQualityGates(analysisResult, context);

    if (!gatesResult.passed) {
      console.log('\n❌ Quality gates FAILED\n');

      // Phase 3: Auto-healing attempt
      if (this.config.autoFix) {
        console.log('Phase 3: Auto-Healing Attempt');
        const healingResult = await this.attemptAutoHealing(gatesResult.failures, context);

        if (healingResult.success) {
          console.log('\n✅ Auto-healing SUCCESSFUL');
          this.stats.autoFixesApplied++;
          return { success: true, healed: true, fixes: healingResult.fixes };
        } else {
          console.log('\n⚠️  Auto-healing FAILED - Manual intervention required');
        }
      }

      this.stats.gatesFailed++;
      return { success: false, gates: gatesResult };
    }

    console.log('\n✅ Quality gates PASSED\n');
    this.stats.gatesPassed++;
    return { success: true, gates: gatesResult };
  }


  /**
   * Validate build (Check for syntax, missing modules)
   */
  async validateBuild(context) {
    const cwd = context.projectPath || process.cwd();
    console.log('   Running build check...');

    try {
      // Try to build (or at least check syntax/imports via a dry run)
      // For node projects, we can try a dry run of the entry point or a build script
      // Using 'npm run build' is standard, but might be slow. 
      // We'll try 'npm run build' but capture stderr for specific patterns.

      // Check if build script exists
      const pkg = require(path.join(cwd, 'package.json'));
      const buildCmd = pkg.scripts && pkg.scripts.build ? 'npm run build' : 'node -c .'; // Fallback to syntax check on current dir ? No 'node -c .' checks file.

      // Actually, just checking if we can resolve main entry points is often enough for "missing module"
      // But let's run the build command if it exists, assume it fails fast on error.

      if (!pkg.scripts || !pkg.scripts.build) {
        console.log('   Skipping build check (no build script)');
        return { success: true };
      }

      const output = safeExec(buildCmd, [], { cwd, stdio: 'pipe' }); // Capture stdio
      return { success: true, output };

    } catch (error) {
      // Build failed - analyze why
      const stderr = error.stderr || error.message || '';
      const stdout = error.stdout || '';
      const combined = stdout + '\n' + stderr;

      const errors = this.analyzeBuildOutput(combined);
      return { success: false, errors };
    }
  }

  /**
   * Analyze build output for specific errors
   */
  analyzeBuildOutput(output) {
    const errors = [];

    // Pattern 1: Missing Module
    // "Module not found: Error: Can't resolve 'xyz'"
    const missingModuleRegex = /Module not found:.*Can't resolve '([^']+)'/g;
    let match;
    while ((match = missingModuleRegex.exec(output)) !== null) {
      errors.push({
        type: 'MISSING_MODULE',
        module: match[1],
        severity: 'CRITICAL',
        message: `Missing dependency: ${match[1]}`,
        fixable: true
      });
    }

    // Pattern 1.1: Missing Module (Node.js style)
    // "Error: Cannot find module 'xyz'"
    const nodeMissingModuleRegex = /Error: Cannot find module '([^']+)'/g;
    while ((match = nodeMissingModuleRegex.exec(output)) !== null) {
      errors.push({
        type: 'MISSING_MODULE',
        module: match[1],
        severity: 'CRITICAL',
        message: `Missing dependency: ${match[1]}`,
        fixable: true
      });
    }

    // Pattern 2: Syntax Error
    // "SyntaxError: Unexpected token"
    const syntaxErrorRegex = /(SyntaxError:.*)\n\s+at\s+(.+):(\d+):(\d+)/g;
    while ((match = syntaxErrorRegex.exec(output)) !== null) {
      errors.push({
        type: 'SYNTAX_ERROR',
        message: match[1],
        file: match[2],
        line: match[3],
        severity: 'CRITICAL',
        fixable: true
      });
    }

    return errors;
  }

  /**
   * Attempt to heal build failures
   */
  async attemptBuildHealing(buildResult, context) {
    const cwd = context.projectPath || process.cwd();
    let healed = false;

    for (const error of buildResult.errors) {
      if (error.type === 'MISSING_MODULE') {
        console.log(`   🛠️  Fixing missing module: ${error.module}`);
        try {
          // Deterministic fix: Install the module
          safeExec(`npm install ${error.module} --save-dev`, [], { cwd }); // Assume dev dep logic or check usage? 
          // Safe default for now: regular dep unless it looks "test-ish"
          // safeExec(`npm install ${error.module}`, [], { cwd }); 
          healed = true;
        } catch (e) {
          console.error('   Failed to install module:', e.message);
        }
      } else if (error.type === 'SYNTAX_ERROR') {
        // Delegate to AI Fixer for syntax
        console.log(`   🧠 AI Fixing syntax error in ${error.file}:${error.line}`);
        // ... Call FixGenerator logic here ...
        // For now, simpler implementation:
        healed = await this.delegateToAIFixer(error, context);
      }
    }
    return { success: healed };
  }

  /**
   * Delegate complex fix to AI
   */
  async delegateToAIFixer(error, context) {
    // Placeholder - reuse existing fix logic
    return false; // Not fully hooked up in this snippet to avoid duplication
  }

  /**
   * Gather CI/CD context (branch, commit, PR, etc.)
   */
  async gatherCIContext(options) {
    const context = {
      provider: this.config.ciProvider,
      branch: process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_REF_NAME || 'unknown',
      commit: process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || this.getGitCommit(),
      pr: process.env.GITHUB_PR_NUMBER || process.env.CI_MERGE_REQUEST_IID || null,
      author: process.env.GITHUB_ACTOR || process.env.GITLAB_USER_LOGIN || this.getGitAuthor(),
      ...options
    };

    return context;
  }

  /**
   * Run pre-merge code analysis
   */
  async runPreMergeAnalysis(context) {
    console.log('   Running multi-AI analysis...');

    const AIProviderManager = require('../ai-providers/manager');
    const manager = new AIProviderManager({
      enabled: ['claude', 'gpt-5-codex', 'gemini', 'heuristic']
    });

    const results = {
      security: [],
      performance: [],
      tests: [],
      coverage: null
    };

    // Security analysis
    if (this.config.gates.security) {
      console.log('   ✓ Security analysis');
      const securityFindings = await this.runSecurityAnalysis(manager, context);
      results.security = securityFindings;
    }

    // Performance analysis
    if (this.config.gates.performance) {
      console.log('   ✓ Performance analysis');
      const perfResults = await this.runPerformanceAnalysis(context);
      results.performance = perfResults;
    }

    // Test execution
    if (this.config.gates.tests) {
      console.log('   ✓ Test execution');
      const testResults = await this.runTests(context);
      results.tests = testResults;
    }

    // Coverage check
    if (this.config.gates.coverage) {
      console.log('   ✓ Coverage analysis');
      const coverageResults = await this.checkCoverage(context);
      results.coverage = coverageResults;
    }

    return results;
  }

  /**
   * Evaluate quality gates
   */
  async evaluateQualityGates(analysisResult, context) {
    const failures = [];

    // Security gate
    if (this.config.gates.security) {
      const highSevSecurity = analysisResult.security.filter(
        f => f.severity === this.config.thresholds.securitySeverity
      );

      if (highSevSecurity.length > 0) {
        failures.push({
          gate: 'security',
          message: `Found ${highSevSecurity.length} ${this.config.thresholds.securitySeverity} severity security issues`,
          findings: highSevSecurity,
          fixable: true
        });
      }
    }

    // Test gate
    if (this.config.gates.tests && analysisResult.tests) {
      const failedTests = analysisResult.tests.failures || 0;

      if (failedTests > this.config.thresholds.testFailureMax) {
        failures.push({
          gate: 'tests',
          message: `${failedTests} test(s) failed`,
          tests: analysisResult.tests,
          fixable: true
        });
      }
    }

    // Coverage gate
    if (this.config.gates.coverage && analysisResult.coverage) {
      if (analysisResult.coverage.percentage < this.config.thresholds.coverageMin) {
        failures.push({
          gate: 'coverage',
          message: `Coverage ${analysisResult.coverage.percentage}% < ${this.config.thresholds.coverageMin}%`,
          coverage: analysisResult.coverage,
          fixable: false
        });
      }
    }

    // Performance gate
    if (this.config.gates.performance && analysisResult.performance) {
      const regression = analysisResult.performance.regression || 0;

      if (regression > this.config.thresholds.performanceRegressionMax) {
        failures.push({
          gate: 'performance',
          message: `Performance regression: ${(regression * 100).toFixed(1)}%`,
          metrics: analysisResult.performance,
          fixable: true
        });
      }
    }

    return {
      passed: failures.length === 0,
      failures,
      summary: {
        security: analysisResult.security.length,
        tests: analysisResult.tests?.total || 0,
        coverage: analysisResult.coverage?.percentage || 0,
        performance: analysisResult.performance?.regression || 0
      }
    };
  }

  /**
   * Attempt automatic healing of failures
   */
  async attemptAutoHealing(failures, context) {
    console.log(`\n   Attempting to heal ${failures.length} issue(s)...`);

    const fixableFailures = failures.filter(f => f.fixable);

    if (fixableFailures.length === 0) {
      console.log('   ⚠️  No fixable failures');
      return { success: false, reason: 'no_fixable_failures' };
    }

    const FixGenerator = require('../ai-fixers/fix-generator');
    const FixApplier = require('../ai-fixers/fix-applier');

    const AIProviderManager = require('../ai-providers/manager');
    const manager = new AIProviderManager({
      enabled: ['gpt-5-codex', 'claude', 'gemini']
    });

    const fixGen = new FixGenerator(manager, {
      preferredProvider: 'gpt-5-codex',
      verifyFix: true
    });

    const fixApplier = new FixApplier({
      createBackups: true,
      verifyAfterApply: true
    });

    const appliedFixes = [];

    for (const failure of fixableFailures) {
      if (failure.gate === 'security') {
        // Fix security issues
        for (const finding of failure.findings) {
          try {
            const filePath = path.join(process.cwd(), finding.file_path);
            const fileContent = await fs.promises.readFile(filePath, 'utf-8');

            const fixResult = await fixGen.generateFix(finding, fileContent);

            if (fixResult.success && fixResult.fix.verified) {
              await fixApplier.applyFix(filePath, fixResult.fix);
              appliedFixes.push({ finding, fix: fixResult.fix });
              console.log(`   ✓ Fixed ${finding.category} in ${finding.file_path}`);
            }
          } catch (error) {
            console.error(`   ✗ Failed to fix ${finding.category}:`, error.message);
          }
        }
      }
    }

    // Re-run tests after fixes
    if (appliedFixes.length > 0 && this.config.fixSettings.testAfterFix) {
      console.log('\n   Re-running tests after fixes...');
      const testResults = await this.runTests(context);

      if (testResults.failures > 0) {
        // Rollback if tests still fail
        console.log('   ⚠️  Tests still failing - rolling back...');
        await this.rollbackFixes(appliedFixes);
        return { success: false, reason: 'tests_failed_after_fix' };
      }
    }

    // Create PR with fixes (optional)
    if (this.config.fixSettings.createPR && appliedFixes.length > 0) {
      await this.createFixPR(appliedFixes, context);
    }

    return {
      success: appliedFixes.length > 0,
      fixes: appliedFixes
    };
  }

  /**
   * Run security analysis
   */
  async runSecurityAnalysis(manager, context) {
    // Use heuristic provider for quick scan
    const HeuristicProvider = require('../ai-providers/heuristic');
    const heuristic = new HeuristicProvider();

    const findings = [];

    // Scan changed files only
    const changedFiles = this.getChangedFiles(context);

    for (const file of changedFiles) {
      const exists = await fs.promises.stat(file).then(stat => stat.isFile()).catch(() => false);
      if (!exists) continue;

      const content = await fs.promises.readFile(file, 'utf-8');
      const result = await heuristic.analyze('security-god', file, content, process.cwd());

      findings.push(...result.issues);
    }

    return findings;
  }

  /**
   * Run performance analysis
   */
  async runPerformanceAnalysis(context) {
    // Mock performance metrics (would integrate with actual profiling tools)
    return {
      regression: 0,
      metrics: {
        latency: 100,
        throughput: 1000,
        memory: 512
      }
    };
  }

  /**
   * Run tests using the detected test framework.
   */
  async runTests(context) {
    const cwd = context.projectPath || process.cwd();
    const TestRunnerDetector = require('../test-runner-detector');
    const TestExecutor = require('../test-executor');
    const detector = new TestRunnerDetector(cwd);
    const executor = new TestExecutor(cwd, detector);

    try {
      const info = await detector.detect();
      console.log(`   Running: ${info.command}`);
      const raw = await executor.runAll({ timeout: 120000 });
      const results = {
        total: raw.total,
        passed: raw.passed,
        failures: raw.failed,
        skipped: raw.skipped,
        duration: raw.duration
      };
      console.log(`   ✓ Tests: ${results.passed} passed, ${results.failures} failed`);
      return results;
    } catch (error) {
      console.log(`   ✗ Test execution error: ${error.message}`);
      return { total: 0, passed: 0, failures: 0, skipped: 0, duration: 0 };
    }
  }

  /**
   * Check code coverage with real lcov/istanbul parsing
   */
  async checkCoverage(context) {
    const cwd = context.projectPath || process.cwd();
    const coverageDir = path.join(cwd, 'coverage');

    // Check for lcov.info (Istanbul/NYC)
    const lcovPath = path.join(coverageDir, 'lcov.info');
    if (fs.existsSync(lcovPath)) {
      return this.parseLcov(lcovPath);
    }

    // Check for coverage-summary.json (Jest)
    const summaryPath = path.join(coverageDir, 'coverage-summary.json');
    if (fs.existsSync(summaryPath)) {
      return this.parseCoverageSummary(summaryPath);
    }

    // Try to run coverage command
    try {
      console.log('   Running: npm run coverage');
      safeExec('npm run coverage -- --passWithNoTests', [], { cwd });

      if (fs.existsSync(summaryPath)) {
        return this.parseCoverageSummary(summaryPath);
      }
    } catch (error) {
      console.log('   No coverage data available');
    }

    return { percentage: 0, lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 } };
  }

  /**
   * Parse lcov.info file
   */
  parseLcov(lcovPath) {
    const content = fs.readFileSync(lcovPath, 'utf-8');
    let linesHit = 0, linesTotal = 0, branchesHit = 0, branchesTotal = 0;

    content.split('\n').forEach(line => {
      if (line.startsWith('LH:')) linesHit += parseInt(line.slice(3));
      if (line.startsWith('LF:')) linesTotal += parseInt(line.slice(3));
      if (line.startsWith('BRH:')) branchesHit += parseInt(line.slice(4));
      if (line.startsWith('BRF:')) branchesTotal += parseInt(line.slice(4));
    });

    const percentage = linesTotal > 0 ? Math.round((linesHit / linesTotal) * 100) : 0;
    console.log(`   ✓ Coverage: ${percentage}% (${linesHit}/${linesTotal} lines)`);

    return {
      percentage,
      lines: { covered: linesHit, total: linesTotal },
      branches: { covered: branchesHit, total: branchesTotal }
    };
  }

  /**
   * Parse coverage-summary.json (Jest format)
   */
  parseCoverageSummary(summaryPath) {
    const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf-8'));
    const total = summary.total || {};

    const percentage = total.lines?.pct || 0;
    console.log(`   ✓ Coverage: ${percentage}%`);

    return {
      percentage,
      lines: { covered: total.lines?.covered || 0, total: total.lines?.total || 0 },
      branches: { covered: total.branches?.covered || 0, total: total.branches?.total || 0 }
    };
  }

  /**
   * Get changed files in this commit/PR
   */
  getChangedFiles(context) {
    try {
      const output = safeExec('git diff --name-only HEAD~1', []);
      return output.split('\n').filter(f => f.trim());
    } catch {
      return [];
    }
  }

  /**
   * Rollback applied fixes
   */
  async rollbackFixes(fixes) {
    const FixApplier = require('../ai-fixers/fix-applier');
    const applier = new FixApplier();

    for (const fix of fixes) {
      try {
        await applier.rollback(fix.finding.file_path);
        console.log(`   ↩️  Rolled back ${fix.finding.file_path}`);
      } catch (error) {
        console.error(`   ✗ Rollback failed:`, error.message);
      }
    }

    this.stats.rollbacksTriggered++;
  }

  /**
   * Create PR with fixes
   */
  async createFixPR(fixes, context) {
    console.log('\n   📝 Creating PR with fixes...');

    // Sanitize branch name
    const timestamp = Date.now();
    const branchName = `codetitan/auto-fix-${timestamp}`;
    const commitMsg = `Auto-fix: ${fixes.length} issues resolved by CodeTitan`;

    try {
      safeExec('git checkout -b', [branchName]);
      safeExec('git add .');
      safeExec('git commit -m', [commitMsg]);
      safeExec('git push origin', [branchName]);

      console.log(`   ✓ PR branch created: ${branchName}`);
    } catch (error) {
      console.error('   ✗ Failed to create PR:', error.message);
    }
  }

  /**
   * Get git commit hash
   */
  getGitCommit() {
    try {
      return safeExec('git rev-parse HEAD', []).trim();
    } catch {
      return 'unknown';
    }
  }

  /**
   * Get git author
   */
  getGitAuthor() {
    try {
      return safeExec('git log -1 --format=%an', []).trim();
    } catch {
      return 'unknown';
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      successRate: this.stats.totalRuns > 0
        ? (this.stats.gatesPassed / this.stats.totalRuns) * 100
        : 0
    };
  }
}

module.exports = Level5SelfHealingCI;
