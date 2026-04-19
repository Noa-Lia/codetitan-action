/**
 * Fix Ensemble Verification System
 * 
 * Multi-AI consensus for high-risk fixes:
 * - Queries multiple AI providers for fix verification
 * - Calculates consensus score
 * - Provides rollback protection via git hooks
 * - Supports dry-run simulation
 * 
 * @module fix-ensemble
 */

const { execSync, execFileSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');
const GitWorktreeManager = require('./git-worktree-manager');

/**
 * Consensus thresholds
 */
const CONSENSUS_THRESHOLDS = {
    AUTO_APPLY: 0.9,    // 90% of models agree
    SUGGEST: 0.7,       // 70% of models agree
    REVIEW: 0.5,        // 50% of models agree
    REJECT: 0.0,        // Below 50%
};

/**
 * Risk levels for fixes
 */
const RISK_LEVELS = {
    CRITICAL: {
        minProviders: 3,
        requiredConsensus: 0.95,
        requiresDryRun: true,
        requiresBackup: true,
    },
    HIGH: {
        minProviders: 2,
        requiredConsensus: 0.85,
        requiresDryRun: true,
        requiresBackup: true,
    },
    MEDIUM: {
        minProviders: 2,
        requiredConsensus: 0.75,
        requiresDryRun: false,
        requiresBackup: true,
    },
    LOW: {
        minProviders: 1,
        requiredConsensus: 0.6,
        requiresDryRun: false,
        requiresBackup: false,
    },
};

/**
 * AI Provider Interface
 */
class AIProviderAdapter {
    constructor(name, config = {}) {
        this.name = name;
        this.config = config;
        this.available = true;
    }

    /**
     * Verify a fix with this provider
     */
    async verifyFix(fix, context) {
        throw new Error('verifyFix must be implemented');
    }

    /**
     * Get provider status
     */
    isAvailable() {
        return this.available;
    }
}

/**
 * Mock AI Provider for testing
 */
class MockAIProvider extends AIProviderAdapter {
    constructor(name, successRate = 0.8) {
        super(name);
        this.successRate = successRate;
    }

    async verifyFix(fix, context) {
        // Simulate verification delay
        await new Promise(r => setTimeout(r, 100 + Math.random() * 200));

        const agrees = Math.random() < this.successRate;
        const confidence = agrees
            ? 0.7 + Math.random() * 0.3
            : 0.2 + Math.random() * 0.3;

        return {
            provider: this.name,
            agrees,
            confidence,
            reasoning: agrees
                ? 'Fix appears correct and safe to apply'
                : 'Fix may have unintended side effects',
            suggestions: agrees ? [] : ['Consider adding error handling'],
        };
    }
}

/**
 * Git Operations Helper
 */
class GitHelper {
    constructor(repoPath = '.') {
        this.repoPath = repoPath;
        this.worktreeManager = new GitWorktreeManager({
            repoPath,
            workspaceDir: '.codetitan/worktrees',
            logger: console
        });
    }

    /**
     * Check if in a git repository
     */
    isGitRepo() {
        try {
            execSync('git rev-parse --git-dir', {
                cwd: this.repoPath,
                stdio: 'pipe'
            });
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Get current branch
     */
    getCurrentBranch() {
        try {
            return execSync('git rev-parse --abbrev-ref HEAD', {
                cwd: this.repoPath,
                encoding: 'utf8',
                stdio: 'pipe'
            }).trim();
        } catch {
            return null;
        }
    }

    /**
     * Check for uncommitted changes
     */
    hasUncommittedChanges() {
        try {
            const output = execSync('git status --porcelain', {
                cwd: this.repoPath,
                encoding: 'utf8',
                stdio: 'pipe'
            });
            return output.trim().length > 0;
        } catch {
            return true;
        }
    }

    /**
     * Create a backup stash
     */
    createBackup(message = 'CodeTitan fix backup') {
        try {
            const result = execFileSync('git', ['stash', 'push', '-m', message], {
                cwd: this.repoPath,
                encoding: 'utf8'
            });
            return result.includes('Saved');
        } catch {
            return false;
        }
    }

    /**
     * Restore from backup stash
     */
    restoreBackup() {
        try {
            execSync('git stash pop', {
                cwd: this.repoPath,
                encoding: 'utf8'
            });
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Create a commit for the fix
     */
    commitFix(files, message) {
        try {
            // Stage files
            for (const file of files) {
                execFileSync('git', ['add', '--', file], {
                    cwd: this.repoPath,
                    encoding: 'utf8'
                });
            }

            // Commit
            execFileSync('git', ['commit', '-m', message], {
                cwd: this.repoPath,
                encoding: 'utf8'
            });

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Revert last commit
     */
    revertLastCommit() {
        try {
            execSync('git reset --hard HEAD~1', {
                cwd: this.repoPath,
                encoding: 'utf8'
            });
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Create a rollback hook
     */
    createRollbackHook(fixId, files) {
        const hookPath = path.join(this.repoPath, '.git', 'hooks', 'codetitan-rollback.json');
        const hookData = {
            fixId,
            files,
            timestamp: new Date().toISOString(),
            rollbackCommand: 'git reset --hard HEAD~1',
        };

        fs.writeFileSync(hookPath, JSON.stringify(hookData, null, 2));
        return hookPath;
    }

    /**
     * Create a detached git worktree at the given path.
     * @param {string} worktreePath - Absolute path for the new worktree
     * @param {Object} [options]
     * @returns {string} worktreePath
     */
    createWorktree(worktreePath, options = {}) {
        if (typeof worktreePath === 'object' && worktreePath !== null) {
            return this.worktreeManager.createWorktree(worktreePath);
        }

        const absolutePath = path.resolve(this.repoPath, worktreePath);
        const relativeBaseDir = path.relative(this.repoPath, path.dirname(absolutePath));
        return this.worktreeManager.createWorktree({
            name: path.basename(absolutePath),
            baseDir: relativeBaseDir,
            targetPath: absolutePath,
            ref: options.ref,
            fallbackToCopy: options.fallbackToCopy
        });
    }

    /**
     * Remove a git worktree by path.
     * @param {string} worktreePath
     */
    removeWorktree(worktreePath) {
        try {
            this.worktreeManager.removeWorktree(worktreePath);
        } catch {
            // Worktree may already be gone
        }
    }

    /**
     * List all git worktrees.
     * @returns {Array<{ path: string, branch: string, head: string }>}
     */
    listWorktrees() {
        return this.worktreeManager.listWorktrees();
    }

    promoteFiles(worktreePath, files) {
        return this.worktreeManager.promoteFiles(worktreePath, files);
    }

    captureDiff(worktreePath, options = {}) {
        return this.worktreeManager.captureDiff(worktreePath, options);
    }

    toRepoRelativePath(filePath) {
        return this.worktreeManager.toRepoRelativePath(filePath);
    }

    _parseWorktreeList(output) {
        const worktrees = [];
        let current = {};
        for (const line of output.split('\n')) {
            if (line.startsWith('worktree ')) {
                if (current.path) worktrees.push(current);
                current = { path: line.slice(9).trim(), branch: null, head: null };
            } else if (line.startsWith('HEAD ')) {
                current.head = line.slice(5).trim();
            } else if (line.startsWith('branch ')) {
                current.branch = line.slice(7).trim();
            }
        }
        if (current.path) worktrees.push(current);
        return worktrees;
    }
}

/**
 * Dry Run Simulator
 */
class DryRunSimulator {
    constructor() {
        this.changes = [];
    }

    /**
     * Simulate applying a fix
     */
    simulate(fix, code) {
        const result = {
            fixId: fix.id,
            originalCode: code,
            modifiedCode: null,
            changes: [],
            wouldCompile: true,
            potentialIssues: [],
        };

        try {
            // Apply the fix to a copy
            let modifiedCode = code;

            if (fix.replacement) {
                modifiedCode = code.replace(fix.original || fix.snippet, fix.replacement);
                result.changes.push({
                    type: 'replace',
                    from: fix.original || fix.snippet,
                    to: fix.replacement,
                    line: fix.line,
                });
            }

            result.modifiedCode = modifiedCode;

            // Check for potential issues
            result.potentialIssues = this.detectIssues(code, modifiedCode, fix);

            // Check if it would compile (basic syntax check)
            result.wouldCompile = this.wouldCompile(modifiedCode);

        } catch (error) {
            result.error = error.message;
            result.wouldCompile = false;
        }

        this.changes.push(result);
        return result;
    }

    /**
     * Detect potential issues with the fix
     */
    detectIssues(original, modified, fix) {
        const issues = [];

        // Check if fix removes too much code
        if (modified.length < original.length * 0.5) {
            issues.push({
                severity: 'HIGH',
                message: 'Fix removes more than 50% of the code',
            });
        }

        // Check if fix adds potentially dangerous patterns
        const dangerPatterns = [
            { pattern: /eval\(/g, message: 'Fix introduces eval()' },
            { pattern: /Function\(/g, message: 'Fix introduces Function constructor' },
            { pattern: /innerHTML\s*=/g, message: 'Fix introduces innerHTML assignment' },
        ];

        for (const { pattern, message } of dangerPatterns) {
            if (pattern.test(modified) && !pattern.test(original)) {
                issues.push({ severity: 'CRITICAL', message });
            }
        }

        // Check for unbalanced brackets
        const brackets = { '(': ')', '[': ']', '{': '}' };
        const stack = [];
        for (const char of modified) {
            if ('([{'.includes(char)) stack.push(brackets[char]);
            if (')]}'.includes(char)) {
                if (stack.pop() !== char) {
                    issues.push({
                        severity: 'HIGH',
                        message: 'Fix creates unbalanced brackets',
                    });
                    break;
                }
            }
        }

        return issues;
    }

    /**
     * Basic compile check (syntax validation)
     */
    wouldCompile(code) {
        try {
            // Parse as JavaScript without executing the code.
            new vm.Script(code);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Get simulation summary
     */
    getSummary() {
        return {
            totalSimulated: this.changes.length,
            wouldCompile: this.changes.filter(c => c.wouldCompile).length,
            withIssues: this.changes.filter(c => c.potentialIssues.length > 0).length,
            critical: this.changes.filter(c =>
                c.potentialIssues.some(i => i.severity === 'CRITICAL')
            ).length,
        };
    }

    /**
     * Clear simulation history
     */
    clear() {
        this.changes = [];
    }
}

/**
 * Fix Ensemble Verifier - Main Class
 */
class FixEnsembleVerifier {
    constructor(config = {}) {
        this.config = {
            minProviders: config.minProviders || 2,
            consensusThreshold: config.consensusThreshold || 0.75,
            timeout: config.timeout || 30000,
            ...config,
        };

        // AI providers for verification
        this.providers = [];

        // Git helper
        this.git = new GitHelper(config.repoPath);

        // Dry run simulator
        this.simulator = new DryRunSimulator();

        // Verification history
        this.history = new Map();

        // Add mock providers for testing if none provided
        if (!config.providers || config.providers.length === 0) {
            this.providers = [
                new MockAIProvider('claude', 0.85),
                new MockAIProvider('gpt-4', 0.80),
                new MockAIProvider('gemini', 0.75),
            ];
        } else {
            this.providers = config.providers;
        }
    }

    /**
     * Add an AI provider
     */
    addProvider(provider) {
        this.providers.push(provider);
    }

    /**
     * Remove an AI provider
     */
    removeProvider(name) {
        this.providers = this.providers.filter(p => p.name !== name);
    }

    /**
     * Verify a fix with ensemble consensus
     */
    async verifyFix(fix, context = {}) {
        const fixId = fix.id || crypto.randomUUID();
        const riskLevel = this.assessRisk(fix);
        const riskConfig = RISK_LEVELS[riskLevel];

        // Check provider availability
        const availableProviders = this.providers.filter(p => p.isAvailable());

        if (availableProviders.length < riskConfig.minProviders) {
            return {
                fixId,
                verified: false,
                error: `Insufficient providers: ${availableProviders.length} < ${riskConfig.minProviders}`,
                riskLevel,
            };
        }

        // Run dry-run simulation if required
        let dryRunResult = null;
        if (riskConfig.requiresDryRun && context.code) {
            dryRunResult = this.simulator.simulate(fix, context.code);

            if (!dryRunResult.wouldCompile) {
                return {
                    fixId,
                    verified: false,
                    error: 'Fix would cause syntax errors',
                    dryRun: dryRunResult,
                    riskLevel,
                };
            }

            if (dryRunResult.potentialIssues.some(i => i.severity === 'CRITICAL')) {
                return {
                    fixId,
                    verified: false,
                    error: 'Fix introduces critical issues',
                    dryRun: dryRunResult,
                    riskLevel,
                };
            }
        }

        // Query providers in parallel
        const verifications = await Promise.allSettled(
            availableProviders.map(provider =>
                Promise.race([
                    provider.verifyFix(fix, context),
                    new Promise((_, reject) =>
                        setTimeout(() => reject(new Error('Timeout')), this.config.timeout)
                    ),
                ])
            )
        );

        // Collect results
        const results = verifications
            .filter(v => v.status === 'fulfilled')
            .map(v => v.value);

        if (results.length < riskConfig.minProviders) {
            return {
                fixId,
                verified: false,
                error: `Too few successful verifications: ${results.length}`,
                riskLevel,
            };
        }

        // Calculate consensus
        const agrees = results.filter(r => r.agrees).length;
        const consensus = agrees / results.length;
        const avgConfidence = results.reduce((sum, r) => sum + r.confidence, 0) / results.length;

        // Determine action
        let action;
        if (consensus >= CONSENSUS_THRESHOLDS.AUTO_APPLY && consensus >= riskConfig.requiredConsensus) {
            action = 'AUTO_APPLY';
        } else if (consensus >= CONSENSUS_THRESHOLDS.SUGGEST) {
            action = 'SUGGEST';
        } else if (consensus >= CONSENSUS_THRESHOLDS.REVIEW) {
            action = 'REVIEW';
        } else {
            action = 'REJECT';
        }

        // Collect suggestions
        const suggestions = results
            .flatMap(r => r.suggestions || [])
            .filter((s, i, arr) => arr.indexOf(s) === i);

        const verification = {
            fixId,
            verified: action === 'AUTO_APPLY' || action === 'SUGGEST',
            action,
            consensus,
            confidence: avgConfidence,
            results,
            suggestions,
            dryRun: dryRunResult,
            riskLevel,
            timestamp: new Date().toISOString(),
        };

        // Store in history
        this.history.set(fixId, verification);

        return verification;
    }

    /**
     * Assess risk level of a fix
     */
    assessRisk(fix) {
        // Critical if security-related
        if (fix.category?.toLowerCase().includes('security')) {
            return 'CRITICAL';
        }

        // High if affects multiple files or large changes
        if (fix.affectedFiles?.length > 1) {
            return 'HIGH';
        }

        // Medium for most code changes
        if (fix.severity === 'HIGH' || fix.impact > 7) {
            return 'HIGH';
        }

        if (fix.severity === 'MEDIUM' || fix.impact > 4) {
            return 'MEDIUM';
        }

        return 'LOW';
    }

    resolveFixFiles(fix, context = {}) {
        const candidates = fix.files || [context.filePath];
        return candidates.filter(Boolean);
    }

    applyFixReplacement(filePath, fix) {
        if (!fix.replacement || !fs.existsSync(filePath)) {
            return false;
        }

        const content = fs.readFileSync(filePath, 'utf8');
        const newContent = content.replace(
            fix.original || fix.snippet,
            fix.replacement
        );
        fs.writeFileSync(filePath, newContent, 'utf8');
        return true;
    }

    /**
     * Apply a verified fix with rollback protection
     */
    async applyFix(fix, verification, context = {}) {
        if (!verification.verified) {
            throw new Error('Cannot apply unverified fix');
        }

        const files = fix.files || [context.filePath];
        const riskConfig = RISK_LEVELS[verification.riskLevel];
        const useDirectMode = context.direct === true || context.mode === 'direct';
        const shouldPromote = context.promote === true;
        const keepWorktree = context.keepWorktree ?? !shouldPromote;

        // Create backup if required
        let backupCreated = false;
        if (useDirectMode && riskConfig.requiresBackup && this.git.isGitRepo()) {
            backupCreated = this.git.createBackup(`Pre-fix backup: ${fix.id}`);
        }

        let worktreeHandle = null;
        try {
            if (!useDirectMode) {
                const resolvedFiles = this.resolveFixFiles(fix, context).map(file => this.git.toRepoRelativePath(file));
                worktreeHandle = this.git.createWorktree({
                    name: `fix-${fix.id || 'candidate'}`,
                    baseDir: '.codetitan/worktrees/fixes'
                });

                for (const relativeFile of resolvedFiles) {
                    const worktreeFilePath = path.join(worktreeHandle.path, relativeFile);
                    const applied = this.applyFixReplacement(worktreeFilePath, fix);
                    if (!applied) {
                        throw new Error(`Unable to apply fix in isolated worktree: ${relativeFile}`);
                    }
                }

                const diffSummary = this.git.captureDiff(worktreeHandle, { files: resolvedFiles });

                if (shouldPromote) {
                    if (context.validationPassed !== true) {
                        throw new Error('Promotion requires validationPassed=true');
                    }
                    if (context.diffReviewed !== true) {
                        throw new Error('Promotion requires diffReviewed=true');
                    }

                    this.git.promoteFiles(worktreeHandle, resolvedFiles);

                    if (this.git.isGitRepo()) {
                        this.git.createRollbackHook(fix.id, resolvedFiles);
                    }

                    if (context.autoCommit && this.git.isGitRepo()) {
                        const message = `fix: ${fix.message || fix.id}\n\nPromoted from isolated worktree with ${Math.round(verification.consensus * 100)}% consensus`;
                        this.git.commitFix(resolvedFiles, message);
                    }
                }

                return {
                    success: true,
                    fixId: fix.id,
                    files: resolvedFiles,
                    backupCreated: false,
                    committed: shouldPromote && context.autoCommit || false,
                    direct: false,
                    workspaceMode: worktreeHandle.mode,
                    worktreePath: worktreeHandle.path,
                    promoted: shouldPromote,
                    validationRequiredForPromotion: true,
                    diffSummary: {
                        filesChanged: diffSummary.filesChanged,
                        lines: diffSummary.lines
                    },
                    cleanupPending: keepWorktree
                };
            }

            // Apply the fix
            for (const file of files) {
                if (this.applyFixReplacement(file, fix)) {
                    continue;
                }
            }

            // Create rollback hook
            if (this.git.isGitRepo()) {
                this.git.createRollbackHook(fix.id, files);
            }

            // Commit if auto-commit enabled
            if (context.autoCommit && this.git.isGitRepo()) {
                const message = `fix: ${fix.message || fix.id}\n\nApplied by CodeTitan with ${Math.round(verification.consensus * 100)}% consensus`;
                this.git.commitFix(files, message);
            }

            return {
                success: true,
                fixId: fix.id,
                files,
                backupCreated,
                committed: context.autoCommit || false,
                direct: true,
                workspaceMode: 'direct',
                promoted: true,
                unsafeDirect: true
            };

        } catch (error) {
            // Rollback on failure
            if (backupCreated) {
                this.git.restoreBackup();
            }

            if (worktreeHandle && !context.keepWorktreeOnFailure) {
                try {
                    this.git.removeWorktree(worktreeHandle);
                } catch {
                    // Ignore cleanup failures on rollback path.
                }
            }

            return {
                success: false,
                fixId: fix.id,
                error: error.message,
                rolledBack: backupCreated,
                direct: useDirectMode,
                worktreePath: worktreeHandle ? worktreeHandle.path : null
            };
        } finally {
            if (worktreeHandle && shouldPromote) {
                try {
                    this.git.removeWorktree(worktreeHandle);
                } catch {
                    // Ignore cleanup failures after promotion.
                }
            }
        }
    }

    /**
     * Rollback a previously applied fix
     */
    rollback(fixId) {
        const verification = this.history.get(fixId);

        if (!verification) {
            return { success: false, error: 'Fix not found in history' };
        }

        if (this.git.isGitRepo()) {
            const success = this.git.revertLastCommit();
            return { success, fixId };
        }

        return { success: false, error: 'Not a git repository' };
    }

    /**
     * Get verification statistics
     */
    getStats() {
        const verifications = Array.from(this.history.values());

        return {
            total: verifications.length,
            verified: verifications.filter(v => v.verified).length,
            rejected: verifications.filter(v => !v.verified).length,
            avgConsensus: verifications.length > 0
                ? verifications.reduce((sum, v) => sum + v.consensus, 0) / verifications.length
                : 0,
            byAction: {
                AUTO_APPLY: verifications.filter(v => v.action === 'AUTO_APPLY').length,
                SUGGEST: verifications.filter(v => v.action === 'SUGGEST').length,
                REVIEW: verifications.filter(v => v.action === 'REVIEW').length,
                REJECT: verifications.filter(v => v.action === 'REJECT').length,
            },
            byRisk: {
                CRITICAL: verifications.filter(v => v.riskLevel === 'CRITICAL').length,
                HIGH: verifications.filter(v => v.riskLevel === 'HIGH').length,
                MEDIUM: verifications.filter(v => v.riskLevel === 'MEDIUM').length,
                LOW: verifications.filter(v => v.riskLevel === 'LOW').length,
            },
        };
    }

    /**
     * Clear history
     */
    clearHistory() {
        this.history.clear();
        this.simulator.clear();
    }
}

module.exports = {
    FixEnsembleVerifier,
    AIProviderAdapter,
    MockAIProvider,
    GitHelper,
    DryRunSimulator,
    CONSENSUS_THRESHOLDS,
    RISK_LEVELS,
};
