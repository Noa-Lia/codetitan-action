'use strict';

const { EventEmitter } = require('events');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync, execFileSync, exec } = require('child_process');

const ArenaJudge = require('./arena-judge');
const GitWorktreeManager = require('./git-worktree-manager');
const TestRunnerDetector = require('./test-runner-detector');
const TestExecutor = require('./test-executor');

/**
 * TitanArena — competing AI fixes tested in isolated git worktrees.
 *
 * Flow:
 *   compete(finding, fileContent) →
 *     1. Generate N fixes in parallel (one per AI provider)
 *     2. Create isolated git worktree per contender
 *     3. Apply fix + run tests + run analysis in each worktree
 *     4. Score each contender (tests + quality + security + confidence)
 *     5. Pick winner, optionally auto-apply
 *     6. Cleanup worktrees
 */
class TitanArena extends EventEmitter {
  constructor(config = {}) {
    super();

    this.config = {
      projectRoot: config.projectRoot || process.cwd(),
      maxContenders: config.maxContenders || 3,
      testTimeout: config.testTimeout || 120000,
      minPassScore: config.minPassScore || 0.6,
      autoApplyThreshold: config.autoApplyThreshold || 0.95,
      arenaDir: config.arenaDir || '.codetitan/arena',
      dryRun: config.dryRun || false,
      verbose: config.verbose || false,
      ...config
    };

    this.judge = new ArenaJudge(this.config.projectRoot, {
      weights: this.config.weights
    });
    this.worktreeManager = config.worktreeManager || new GitWorktreeManager({
      repoPath: this.config.projectRoot,
      workspaceDir: this.config.arenaDir,
      logger: console
    });

    // Created worktrees to cleanup later
    this._worktrees = [];
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * Run the arena competition for a single finding.
   *
   * @param {Object} finding - CodeTitan finding object
   * @param {string} fileContent - Current content of the file
   * @param {Object} [options]
   * @param {string[]} [options.providers] - AI providers to use
   * @param {boolean} [options.dryRun]
   * @param {Function} [options.generateFix] - Override fix generator (for testing)
   * @returns {Promise<{ winner, contenders, applied }>}
   */
  async compete(finding, fileContent, options = {}) {
    const dryRun = options.dryRun ?? this.config.dryRun;
    this._log(`Arena: competing for ${finding.category || finding.id} in ${finding.file_path || 'unknown'}`);

    const contenders = [];
    let winner = null;
    let applied = false;

    try {
      // 1. Generate fixes from N providers
      const fixes = await this._generateFixes(finding, fileContent, options);
      if (fixes.length === 0) {
        this.emit('no-fixes', { finding });
        return { winner: null, contenders: [], applied: false };
      }

      // 2. Evaluate each fix in its own worktree
      for (const fix of fixes) {
        const contender = await this._evaluateContender(fix, finding, fileContent, options);
        contenders.push(contender);
        this.emit('contender-evaluated', contender);
        this._log(`  [${fix.provider}] score=${contender.score.toFixed(3)} tests=${contender.evaluation?.testsPass}`);
      }

      // 3. Pick winner
      contenders.sort((a, b) => b.score - a.score);
      const best = contenders[0];

      if (best.score >= this.config.minPassScore) {
        winner = best;
        this.emit('winner-selected', winner);
        this._log(`  Winner: ${winner.provider} (score=${winner.score.toFixed(3)})`);

        // 4. Apply if above threshold and not dry-run
        if (!dryRun && winner.score >= this.config.autoApplyThreshold) {
          applied = await this._applyWinner(winner, finding.file_path);
        } else if (!dryRun) {
          this._log(`  Score ${winner.score.toFixed(3)} < autoApplyThreshold ${this.config.autoApplyThreshold} — suggest only`);
        }
      } else {
        this._log(`  All contenders below minPassScore (${this.config.minPassScore}) — rejecting all`);
        this.emit('all-rejected', { contenders, finding });
      }

    } finally {
      await this._cleanupWorktrees();
    }

    return { winner, contenders, applied };
  }

  // ─── Fix Generation ────────────────────────────────────────────────────────

  async _generateFixes(finding, fileContent, options) {
    const providers = options.providers || this._availableProviders();
    const limit = Math.min(providers.length, this.config.maxContenders);
    const selected = providers.slice(0, limit);

    this._log(`  Generating fixes from: ${selected.join(', ')}`);

    // Generate in parallel
    const results = await Promise.allSettled(
      selected.map(provider => this._generateFixForProvider(finding, fileContent, provider, options))
    );

    return results
      .filter(r => r.status === 'fulfilled' && r.value)
      .map(r => r.value);
  }

  async _generateFixForProvider(finding, fileContent, provider, options) {
    try {
      // Allow override for testing
      if (options.generateFix) {
        const fix = await options.generateFix(finding, fileContent, provider);
        return fix ? { ...fix, provider } : null;
      }

      // Real path: use FixGenerator
      const { AIProviderManager } = require('./ai-providers');
      const { FixGenerator } = require('./ai-fixers');
      const aiManager = new AIProviderManager();
      const generator = new FixGenerator(aiManager, { preferredProvider: provider });

      const result = await generator.generateFix(finding, fileContent, { provider });
      if (!result.success) return null;

      return {
        provider,
        code: result.fix?.fixedContent || fileContent,
        fix: result.fix,
        cost: result.cost || 0
      };
    } catch (err) {
      this._log(`  [${provider}] fix generation failed: ${err.message}`);
      return null;
    }
  }

  _availableProviders() {
    try {
      const { AIProviderManager } = require('./ai-providers');
      const mgr = new AIProviderManager();
      const available = mgr.getAvailableProviders().map(p => p.name);
      // Always include at least heuristic
      if (available.length === 0) return ['heuristic'];
      return available;
    } catch {
      return ['heuristic'];
    }
  }

  // ─── Worktree Management ───────────────────────────────────────────────────

  /**
   * Creates an isolated git worktree for a contender.
   * @param {string} name - Contender name (provider id)
   * @returns {Promise<{ path: string, cleanup: Function }>}
   */
  async createWorktree(name) {
    const handle = this.worktreeManager.createWorktree({
      name,
      baseDir: this.config.arenaDir
    });

    if (handle.mode === 'directory_copy' && handle.fallbackReason) {
      this._log(`  Worktree creation failed (${handle.fallbackReason}), falling back to directory copy`);
    }

    this._worktrees.push(handle);
    return {
      path: handle.path,
      mode: handle.mode,
      cleanup: () => this.worktreeManager.removeWorktree(handle)
    };
  }

  async _removeDir(dirPath) {
    try {
      await fs.rm(dirPath, { recursive: true, force: true });
    } catch { /* ignore */ }
  }

  async _cleanupWorktrees() {
    for (const wt of this._worktrees) {
      try {
        this.worktreeManager.removeWorktree(wt);
      } catch {
        const p = typeof wt === 'string' ? wt : wt.path;
        await this._removeDir(p);
      }
    }
    this._worktrees = [];
  }

  // ─── Evaluation ────────────────────────────────────────────────────────────

  async _evaluateContender(fix, finding, originalCode, options) {
    const contender = {
      provider: fix.provider,
      code: fix.code,
      fix: fix.fix,
      cost: fix.cost || 0,
      score: 0,
      evaluation: null,
      worktreePath: null
    };

    const filePath = finding.file_path || '';
    let worktreeHandle = null;

    try {
      // Create isolated worktree
      worktreeHandle = await this.createWorktree(fix.provider);
      contender.worktreePath = worktreeHandle.path;

      // Write the fixed code into the worktree
      if (filePath) {
        const dest = path.join(worktreeHandle.path, filePath);
        await fs.mkdir(path.dirname(dest), { recursive: true });
        await fs.writeFile(dest, fix.code, 'utf-8');
      }

      // Evaluate
      const evaluation = await this.judge.evaluate(
        originalCode,
        fix.code,
        filePath,
        worktreeHandle.path,
        options
      );

      contender.evaluation = evaluation;
      contender.score = evaluation.score;

    } catch (err) {
      this._log(`  [${fix.provider}] evaluation error: ${err.message}`);
      contender.error = err.message;
      contender.score = 0;
    }

    return contender;
  }

  // ─── Apply Winner ──────────────────────────────────────────────────────────

  async _applyWinner(winner, filePath) {
    if (!filePath) return false;

    try {
      const { FixApplier } = require('./ai-fixers');
      const applier = new FixApplier({ createBackups: true });
      const result = await applier.applyFix(
        path.join(this.config.projectRoot, filePath),
        winner.fix || { fixedContent: winner.code, fixType: 'replace' }
      );
      if (result.success) {
        this._log(`  Applied winner from ${winner.provider} to ${filePath}`);
        this.emit('winner-applied', { winner, filePath });
        return true;
      }
    } catch (err) {
      this._log(`  Apply failed: ${err.message}`);
    }
    return false;
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  _log(msg) {
    if (this.config.verbose) console.log(msg);
  }
}

module.exports = TitanArena;
