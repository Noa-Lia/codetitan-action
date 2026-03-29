'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Detects which test framework a project uses and how to run it.
 * Detection order:
 *   1. package.json scripts.test
 *   2. Config files on disk
 *   3. devDependencies
 *   4. Fallback
 */
class TestRunnerDetector {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
  }

  async detect() {
    const pkg = this._readPackageJson();

    // 1. Check scripts.test
    const scriptResult = this._detectFromScript(pkg);
    if (scriptResult) return scriptResult;

    // 2. Check config files
    const configResult = this._detectFromConfigFiles(this.projectRoot);
    if (configResult) return configResult;

    // 3. Check devDependencies
    const depResult = this._detectFromDependencies(pkg);
    if (depResult) return depResult;

    // 4. Monorepo workspace scan
    const wsResult = this._detectFromWorkspaces(pkg);
    if (wsResult) return wsResult;

    // 5. Fallback
    return {
      framework: 'unknown',
      command: 'npm test',
      configFile: null,
      outputFormat: 'text'
    };
  }

  _readPackageJsonAt(dir) {
    try {
      return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8'));
    } catch {
      return {};
    }
  }

  _detectFromWorkspaces(pkg) {
    const workspaces = pkg?.workspaces;
    if (!workspaces) return null;

    // workspaces can be an array or { packages: [...] }
    const patterns = Array.isArray(workspaces) ? workspaces : (workspaces.packages || []);
    if (!patterns.length) return null;

    // Enumerate candidate directories
    const candidates = [];
    for (const pattern of patterns) {
      // Support simple globs like "packages/*" or "apps/*"
      const parts = pattern.split('/');
      if (parts.length === 2 && parts[1] === '*') {
        const parentDir = path.join(this.projectRoot, parts[0]);
        try {
          const entries = fs.readdirSync(parentDir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isDirectory()) {
              candidates.push(path.join(parentDir, entry.name));
            }
          }
        } catch { /* directory doesn't exist */ }
      } else {
        // Literal path
        candidates.push(path.join(this.projectRoot, pattern));
      }
    }

    // Try each workspace sub-directory
    for (const dir of candidates) {
      const subPkg = this._readPackageJsonAt(dir);
      const result =
        this._detectFromScript(subPkg) ||
        this._detectFromConfigFiles(dir) ||
        this._detectFromDependencies(subPkg);

      if (result && result.framework !== 'unknown') {
        return {
          ...result,
          workspaceDir: dir,
          workspaceName: subPkg?.name || path.basename(dir),
          // Prefix command with cd so it runs in the right directory
          command: `cd "${dir.replace(/\\/g, '/')}" && ${result.command}`,
        };
      }
    }

    return null;
  }

  _readPackageJson() {
    try {
      const pkgPath = path.join(this.projectRoot, 'package.json');
      return JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    } catch {
      return {};
    }
  }

  _detectFromScript(pkg) {
    const testScript = pkg?.scripts?.test || '';

    if (/\bjest\b/.test(testScript)) {
      return this._makeResult('jest', null);
    }
    if (/\bvitest\b/.test(testScript)) {
      return this._makeResult('vitest', null);
    }
    if (/\bmocha\b/.test(testScript)) {
      return this._makeResult('mocha', null);
    }
    if (/\bpytest\b|python -m pytest/.test(testScript)) {
      return this._makeResult('pytest', null);
    }
    if (/\bgo test\b/.test(testScript)) {
      return this._makeResult('go', null);
    }
    if (/\bcargo test\b/.test(testScript)) {
      return this._makeResult('cargo', null);
    }
    return null;
  }

  _detectFromConfigFiles(dir) {
    const root = dir || this.projectRoot;
    const checks = [
      { files: ['jest.config.js', 'jest.config.ts', 'jest.config.mjs', 'jest.config.cjs'], framework: 'jest' },
      { files: ['.mocharc.yml', '.mocharc.yaml', '.mocharc.json', '.mocharc.js', '.mocharc.cjs'], framework: 'mocha' },
      { files: ['vitest.config.js', 'vitest.config.ts', 'vitest.config.mjs'], framework: 'vitest' },
      { files: ['pytest.ini', 'conftest.py'], framework: 'pytest' },
      { files: ['go.mod'], framework: 'go' },
      { files: ['Cargo.toml'], framework: 'cargo' },
    ];

    for (const { files, framework } of checks) {
      for (const file of files) {
        const fullPath = path.join(root, file);
        if (fs.existsSync(fullPath)) {
          // For pytest: also check pyproject.toml has [tool.pytest]
          if (framework === 'pytest' && file !== 'conftest.py' && file !== 'pytest.ini') continue;
          return this._makeResult(framework, file);
        }
      }
    }

    // pyproject.toml with [tool.pytest]
    const pyprojectPath = path.join(root, 'pyproject.toml');
    if (fs.existsSync(pyprojectPath)) {
      try {
        const content = fs.readFileSync(pyprojectPath, 'utf-8');
        if (content.includes('[tool.pytest') || content.includes('[tool.pytest.ini_options]')) {
          return this._makeResult('pytest', 'pyproject.toml');
        }
      } catch { /* ignore */ }
    }

    return null;
  }

  _detectFromDependencies(pkg) {
    const deps = {
      ...pkg?.dependencies,
      ...pkg?.devDependencies
    };

    if (!deps) return null;

    if (deps['jest'] || deps['ts-jest'] || deps['babel-jest']) return this._makeResult('jest', null);
    if (deps['vitest']) return this._makeResult('vitest', null);
    if (deps['mocha']) return this._makeResult('mocha', null);
    if (deps['jasmine']) return this._makeResult('jasmine', null);

    return null;
  }

  _makeResult(framework, configFile) {
    return {
      framework,
      command: this.getRunCommand(framework),
      configFile,
      outputFormat: this._outputFormat(framework)
    };
  }

  _outputFormat(framework) {
    const jsonFrameworks = ['jest', 'vitest', 'mocha', 'go'];
    return jsonFrameworks.includes(framework) ? 'json' : 'text';
  }

  /**
   * Returns the exact shell command to run tests for a given framework.
   * @param {string} framework
   * @param {Object} [options]
   * @returns {string}
   */
  getRunCommand(framework, options = {}) {
    switch (framework) {
      case 'jest':
        return 'npx jest --json --passWithNoTests --forceExit';
      case 'vitest':
        return 'npx vitest run --reporter=json';
      case 'mocha':
        return 'npx mocha --reporter json';
      case 'pytest':
        return 'python -m pytest --tb=short -q';
      case 'go':
        return 'go test -json ./...';
      case 'cargo':
        return 'cargo test';
      case 'jasmine':
        return 'npx jasmine --filter=""';
      default:
        return 'npm test';
    }
  }

  /**
   * Finds test files related to a given source file.
   * @param {string} filePath - Absolute or relative path to the source file
   * @param {string} framework
   * @returns {string[]} Array of candidate test file paths that exist
   */
  getRelatedTests(filePath, framework) {
    const absPath = path.isAbsolute(filePath)
      ? filePath
      : path.join(this.projectRoot, filePath);

    const dir = path.dirname(absPath);
    const basename = path.basename(absPath, path.extname(absPath));
    const ext = path.extname(absPath);

    const candidates = [];

    if (framework === 'pytest' || ext === '.py') {
      // Python conventions
      candidates.push(
        path.join(dir, `test_${basename}.py`),
        path.join(dir, `${basename}_test.py`),
        path.join(dir, '__tests__', `test_${basename}.py`),
        path.join(path.dirname(dir), 'tests', `test_${basename}.py`),
        path.join(this.projectRoot, 'tests', `test_${basename}.py`)
      );
    } else if (framework === 'go' || ext === '.go') {
      // Go: <basename>_test.go in same directory
      candidates.push(path.join(dir, `${basename}_test.go`));
    } else {
      // JS/TS conventions
      const jsExts = [ext, '.js', '.ts', '.jsx', '.tsx'];
      for (const e of [...new Set(jsExts)]) {
        candidates.push(
          path.join(dir, '__tests__', `${basename}.test${e}`),
          path.join(dir, '__tests__', `${basename}.spec${e}`),
          path.join(dir, `${basename}.test${e}`),
          path.join(dir, `${basename}.spec${e}`),
          path.join(dir, 'test', `${basename}${e}`),
          path.join(dir, 'tests', `${basename}${e}`),
          // Also check package root __tests__/ (common monorepo layout)
          path.join(this.projectRoot, '__tests__', `${basename}.test${e}`),
          path.join(this.projectRoot, '__tests__', `${basename}.spec${e}`)
        );
      }
    }

    return candidates.filter(p => fs.existsSync(p));
  }
}

module.exports = TestRunnerDetector;
