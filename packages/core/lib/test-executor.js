'use strict';

const { exec } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');

/**
 * Runs tests and parses results from any supported framework.
 */
class TestExecutor {
  constructor(projectRoot, detector) {
    this.projectRoot = projectRoot || process.cwd();
    this.detector = detector;
  }

  /**
   * Runs the full test suite.
   * @param {Object} [options]
   * @param {number} [options.timeout=120000]
   * @returns {Promise<Object>} { passed, failed, skipped, total, duration, output, details }
   */
  async runAll(options = {}) {
    const info = await this.detector.detect();
    const { stdout, stderr, timedOut } = await this.runWithTimeout(
      info.command,
      options.timeout || 120000
    );
    const output = stdout + (stderr ? `\nSTDERR:\n${stderr}` : '');
    return {
      ...this.parseResults(stdout, stderr, info.framework),
      output,
      timedOut: timedOut || false,
      framework: info.framework,
      command: info.command
    };
  }

  /**
   * Runs only tests related to a specific file.
   * @param {string} filePath
   * @param {Object} [options]
   * @param {number} [options.timeout=60000]
   * @returns {Promise<Object>}
   */
  async runRelated(filePath, options = {}) {
    const info = await this.detector.detect();
    const relatedTests = this.detector.getRelatedTests(filePath, info.framework);

    if (relatedTests.length === 0) {
      return {
        passed: 0, failed: 0, skipped: 0, total: 0,
        duration: 0, output: 'No related tests found',
        noTests: true, framework: info.framework
      };
    }

    const command = this._buildRelatedCommand(info.framework, relatedTests, filePath);
    const { stdout, stderr, timedOut } = await this.runWithTimeout(
      command,
      options.timeout || 60000
    );
    const output = stdout + (stderr ? `\nSTDERR:\n${stderr}` : '');
    return {
      ...this.parseResults(stdout, stderr, info.framework),
      output,
      timedOut: timedOut || false,
      framework: info.framework,
      command,
      relatedTests
    };
  }

  /**
   * Builds the command to run tests related to a specific file.
   */
  _buildRelatedCommand(framework, relatedTests, filePath) {
    const absPath = path.isAbsolute(filePath)
      ? filePath
      : path.join(this.projectRoot, filePath);
    const basename = path.basename(absPath, path.extname(absPath));

    switch (framework) {
      case 'jest':
        // Use --testPathPattern to match related test files
        return `npx jest --json --passWithNoTests --forceExit --testPathPattern="${basename}"`;
      case 'vitest':
        return `npx vitest run --reporter=json ${relatedTests.join(' ')}`;
      case 'mocha':
        return `npx mocha --reporter json ${relatedTests.join(' ')}`;
      case 'pytest':
        return `python -m pytest --tb=short -q ${relatedTests.join(' ')}`;
      case 'go': {
        // Go: run tests in the same package directory
        const dir = path.relative(this.projectRoot, path.dirname(absPath)) || '.';
        return `go test -json ./${dir.replace(/\\/g, '/')}`;
      }
      default:
        return 'npm test';
    }
  }

  /**
   * Executes a command with a timeout.
   * @param {string} command
   * @param {number} [timeoutMs=120000]
   * @returns {Promise<{ stdout, stderr, timedOut, exitCode }>}
   */
  runWithTimeout(command, timeoutMs = 120000) {
    return new Promise((resolve) => {
      let didTimeout = false;

      const child = exec(
        command,
        { cwd: this.projectRoot, maxBuffer: 10 * 1024 * 1024 },
        (err, stdout, stderr) => {
          if (didTimeout) {
            resolve({ stdout: stdout || '', stderr: stderr || '', timedOut: true, exitCode: null });
          } else {
            resolve({
              stdout: stdout || '',
              stderr: stderr || '',
              timedOut: false,
              exitCode: err ? err.code : 0
            });
          }
        }
      );

      const timer = setTimeout(() => {
        didTimeout = true;
        try {
          if (process.platform === 'win32' && child.pid) {
            // On Windows, exec() spawns via cmd.exe which doesn't propagate kills
            require('child_process').execSync(`taskkill /F /T /PID ${child.pid}`, { stdio: 'ignore' });
          } else {
            child.kill('SIGKILL');
          }
        } catch { /* ignore */ }
        // Force-resolve in case the callback never fires
        setTimeout(() => resolve({ stdout: '', stderr: '', timedOut: true, exitCode: null }), 500);
      }, timeoutMs);

      child.on('close', () => clearTimeout(timer));
    });
  }

  /**
   * Parses test output from any supported framework.
   * @param {string} stdout
   * @param {string} stderr
   * @param {string} framework
   * @returns {{ passed, failed, skipped, total, duration, details }}
   */
  parseResults(stdout, stderr, framework) {
    const base = { passed: 0, failed: 0, skipped: 0, total: 0, duration: 0, details: [] };

    try {
      switch (framework) {
        case 'jest':
          return this._parseJest(stdout, stderr, base);
        case 'vitest':
          return this._parseVitest(stdout, stderr, base);
        case 'mocha':
          return this._parseMocha(stdout, stderr, base);
        case 'pytest':
          return this._parsePytest(stdout, stderr, base);
        case 'go':
          return this._parseGoTest(stdout, stderr, base);
        default:
          return this._parseFallback(stdout, stderr, base);
      }
    } catch {
      return this._parseFallback(stdout, stderr, base);
    }
  }

  _parseJest(stdout, stderr, base) {
    // Jest outputs a JSON object — find the opening brace of the top-level object
    const combined = stdout + '\n' + stderr;

    // Try known entry-points in order of specificity
    const markers = ['{"numTotalTestSuites"', '{"numTotalTests"'];
    for (const marker of markers) {
      const idx = combined.indexOf(marker);
      if (idx === -1) continue;
      try {
        const json = JSON.parse(combined.slice(idx));
        const details = (json.testResults || []).flatMap(suite =>
          (suite.testResults || []).map(t => ({
            name: t.fullName || t.title,
            status: t.status,
            duration: t.duration
          }))
        );
        return {
          passed: json.numPassedTests || 0,
          failed: json.numFailedTests || 0,
          skipped: json.numPendingTests || 0,
          total: json.numTotalTests || 0,
          duration: (json.testResults || []).reduce(
            (s, r) => s + ((r.endTime || 0) - (r.startTime || 0)), 0
          ),
          details
        };
      } catch { /* try next marker */ }
    }

    // Last resort: try parsing the entire stdout as JSON
    try {
      const json = JSON.parse(stdout.trim());
      if (json.numPassedTests !== undefined || json.numTotalTests !== undefined) {
        return {
          passed: json.numPassedTests || 0,
          failed: json.numFailedTests || 0,
          skipped: json.numPendingTests || 0,
          total: json.numTotalTests || 0,
          duration: 0,
          details: []
        };
      }
    } catch { /* fall through */ }

    return this._parseFallback(stdout, stderr, base);
  }

  _parseVitest(stdout, stderr, base) {
    try {
      const json = JSON.parse(stdout);
      return {
        passed: json.numPassedTests || 0,
        failed: json.numFailedTests || 0,
        skipped: json.numSkippedTests || 0,
        total: json.numTotalTests || 0,
        duration: json.testResults?.reduce((s, r) => s + (r.duration || 0), 0) || 0,
        details: []
      };
    } catch {
      return this._parseFallback(stdout, stderr, base);
    }
  }

  _parseMocha(stdout, stderr, base) {
    try {
      const json = JSON.parse(stdout);
      const stats = json.stats || {};
      return {
        passed: stats.passes || 0,
        failed: stats.failures || 0,
        skipped: stats.pending || 0,
        total: stats.tests || (stats.passes || 0) + (stats.failures || 0),
        duration: stats.duration || 0,
        details: (json.failures || []).map(f => ({
          name: f.fullTitle,
          status: 'failed',
          error: f.err?.message
        }))
      };
    } catch {
      return this._parseFallback(stdout, stderr, base);
    }
  }

  _parsePytest(stdout, stderr, base) {
    const combined = stdout + '\n' + stderr;
    const result = { ...base };

    // "5 passed, 2 failed, 1 warning"
    const passMatch = combined.match(/(\d+)\s+passed/);
    const failMatch = combined.match(/(\d+)\s+failed/);
    const skipMatch = combined.match(/(\d+)\s+(?:skipped|xfailed|xpassed)/);
    const errMatch = combined.match(/(\d+)\s+error/);

    if (passMatch) result.passed = parseInt(passMatch[1]);
    if (failMatch) result.failed = parseInt(failMatch[1]);
    if (skipMatch) result.skipped = parseInt(skipMatch[1]);
    if (errMatch) result.failed += parseInt(errMatch[1]);
    result.total = result.passed + result.failed + result.skipped;

    // Duration: "in 0.42s"
    const durMatch = combined.match(/in\s+([\d.]+)s/);
    if (durMatch) result.duration = Math.round(parseFloat(durMatch[1]) * 1000);

    return result;
  }

  _parseGoTest(stdout, stderr, base) {
    const result = { ...base };
    const lines = (stdout + '\n' + stderr).split('\n');

    for (const line of lines) {
      try {
        const ev = JSON.parse(line);
        if (ev.Action === 'pass' && ev.Test) result.passed++;
        else if (ev.Action === 'fail' && ev.Test) result.failed++;
        else if (ev.Action === 'skip' && ev.Test) result.skipped++;
        if (ev.Elapsed) result.duration += Math.round(ev.Elapsed * 1000);
      } catch { /* skip non-JSON lines */ }
    }

    result.total = result.passed + result.failed + result.skipped;
    return result;
  }

  _parseFallback(stdout, stderr, base) {
    const combined = stdout + '\n' + stderr;
    const result = { ...base };

    const passMatch = combined.match(/(\d+)\s*pass(?:ed|ing)?/i);
    const failMatch = combined.match(/(\d+)\s*fail(?:ed|ing)?/i);
    const skipMatch = combined.match(/(\d+)\s*skip(?:ped)?/i);

    if (passMatch) result.passed = parseInt(passMatch[1]);
    if (failMatch) result.failed = parseInt(failMatch[1]);
    if (skipMatch) result.skipped = parseInt(skipMatch[1]);
    result.total = result.passed + result.failed + result.skipped;

    return result;
  }

  /**
   * Validates syntax of a file without running tests.
   * @param {string} filePath
   * @returns {Promise<{ valid: boolean, errors: string[] }>}
   */
  async checkSyntax(filePath) {
    const absPath = path.isAbsolute(filePath)
      ? filePath
      : path.join(this.projectRoot, filePath);

    const ext = path.extname(absPath).toLowerCase();

    if (['.js', '.jsx', '.mjs', '.cjs'].includes(ext)) {
      return this._checkJsSyntax(absPath);
    }
    if (['.ts', '.tsx'].includes(ext)) {
      return this._checkTsSyntax(absPath);
    }
    if (ext === '.py') {
      return this._checkPythonSyntax(absPath);
    }
    if (ext === '.go') {
      return this._checkGoSyntax(absPath);
    }

    // Unknown extension — assume valid
    return { valid: true, errors: [] };
  }

  async _checkJsSyntax(filePath) {
    try {
      const { parse } = require('@babel/parser');
      const code = await fs.readFile(filePath, 'utf-8');
      parse(code, {
        sourceType: 'unambiguous',
        plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties']
      });
      return { valid: true, errors: [] };
    } catch (err) {
      return { valid: false, errors: [err.message] };
    }
  }

  async _checkTsSyntax(filePath) {
    // Use @babel/parser with typescript plugin (already works for .ts)
    return this._checkJsSyntax(filePath);
  }

  async _checkPythonSyntax(filePath) {
    const { stdout, stderr } = await this.runWithTimeout(
      `python -c "import ast; ast.parse(open(${JSON.stringify(filePath)}).read())"`,
      10000
    );
    const errors = stderr.trim();
    return {
      valid: !errors,
      errors: errors ? [errors] : []
    };
  }

  async _checkGoSyntax(filePath) {
    const dir = path.dirname(filePath);
    const { stderr } = await this.runWithTimeout(
      `go vet ${JSON.stringify(filePath)}`,
      15000
    );
    const errors = stderr.trim();
    return {
      valid: !errors,
      errors: errors ? [errors] : []
    };
  }
}

module.exports = TestExecutor;
