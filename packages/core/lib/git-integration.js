/**
 * Git Integration for Auto-Fixer
 * TITAN MODE Level 5: Self-Healing CI Integration
 *
 * Automatically commits fixed files with intelligent commit messages.
 *
 * Features:
 * - Detects if directory is a git repository
 * - Stages only files that were fixed (not all changes)
 * - Generates semantic commit messages with stats
 * - Supports dry-run mode (preview without committing)
 * - Handles git errors gracefully
 * - Tracks commit metadata for reporting
 *
 * Usage:
 *   const git = new GitIntegration({ dryRun: false });
 *   await git.commitFixes(fixes, { verbose: true });
 */

const simpleGit = require('simple-git');
const path = require('path');

class GitIntegration {
  constructor(config = {}) {
    this.config = {
      dryRun: config.dryRun || false,
      verbose: config.verbose || false,
      createBranch: config.createBranch || false,
      branchPrefix: config.branchPrefix || 'codetitan/auto-fixes',
      ...config
    };

    this.stats = {
      filesStaged: 0,
      commitCreated: false,
      commitHash: null,
      branchCreated: null
    };
  }

  /**
   * Check if the directory is a git repository
   */
  async isGitRepository(projectPath) {
    try {
      const git = simpleGit(projectPath);
      await git.status();
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get current git status
   */
  async getStatus(projectPath) {
    const git = simpleGit(projectPath);
    return await git.status();
  }

  /**
   * Commit auto-fixed files with intelligent commit message
   *
   * @param {Array} fixes - Array of fix results from AutoFixer
   * @param {Object} options - Commit options
   * @returns {Object} Commit result with metadata
   */
  async commitFixes(fixes, options = {}) {
    const projectPath = options.projectPath || process.cwd();
    const git = simpleGit(projectPath);

    // 1. Verify it's a git repository
    if (!(await this.isGitRepository(projectPath))) {
      if (this.config.verbose) {
        console.log('⏭️  Not a git repository, skipping commit');
      }
      return {
        success: false,
        reason: 'not_a_git_repository',
        message: 'Directory is not a git repository'
      };
    }

    // 2. Filter successful fixes
    const successfulFixes = fixes.filter(f => f.success);

    if (successfulFixes.length === 0) {
      if (this.config.verbose) {
        console.log('⏭️  No successful fixes to commit');
      }
      return {
        success: false,
        reason: 'no_fixes',
        message: 'No successful fixes to commit'
      };
    }

    // 3. Extract unique file paths
    const filePaths = [...new Set(
      successfulFixes.map(f => f.finding?.filePath || f.filePath).filter(Boolean)
    )];

    if (filePaths.length === 0) {
      return {
        success: false,
        reason: 'no_files',
        message: 'No file paths found in fixes'
      };
    }

    // 4. Create new branch if requested
    if (this.config.createBranch && !this.config.dryRun) {
      const branchName = `${this.config.branchPrefix}-${Date.now()}`;
      try {
        await git.checkoutLocalBranch(branchName);
        this.stats.branchCreated = branchName;
        if (this.config.verbose) {
          console.log(`🌿 Created branch: ${branchName}`);
        }
      } catch (error) {
        if (this.config.verbose) {
          console.error(`❌ Failed to create branch: ${error.message}`);
        }
      }
    }

    // 5. Stage fixed files
    try {
      if (!this.config.dryRun) {
        // Convert absolute paths to relative paths
        const relativePaths = filePaths.map(fp =>
          path.relative(projectPath, fp)
        );

        await git.add(relativePaths);
        this.stats.filesStaged = relativePaths.length;

        if (this.config.verbose) {
          console.log(`📦 Staged ${relativePaths.length} file(s):`);
          relativePaths.forEach(fp => console.log(`   - ${fp}`));
        }
      } else {
        if (this.config.verbose) {
          console.log(`📦 [DRY RUN] Would stage ${filePaths.length} file(s)`);
        }
      }
    } catch (error) {
      return {
        success: false,
        reason: 'git_add_failed',
        message: `Failed to stage files: ${error.message}`,
        error: error.message
      };
    }

    // 6. Generate commit message
    const commitMessage = this.generateCommitMessage(successfulFixes);

    if (this.config.verbose) {
      console.log('\n📝 Commit message:');
      console.log('─'.repeat(60));
      console.log(commitMessage);
      console.log('─'.repeat(60));
    }

    // 7. Create commit
    if (!this.config.dryRun) {
      try {
        const commitResult = await git.commit(commitMessage);
        this.stats.commitCreated = true;
        this.stats.commitHash = commitResult.commit;

        if (this.config.verbose) {
          console.log(`✅ Commit created: ${commitResult.commit}`);
        }

        return {
          success: true,
          commitHash: commitResult.commit,
          branch: this.stats.branchCreated,
          filesStaged: this.stats.filesStaged,
          fixesApplied: successfulFixes.length,
          message: commitMessage
        };

      } catch (error) {
        return {
          success: false,
          reason: 'git_commit_failed',
          message: `Failed to create commit: ${error.message}`,
          error: error.message
        };
      }
    } else {
      // Dry run - just return what would happen
      return {
        success: true,
        dryRun: true,
        filesStaged: filePaths.length,
        fixesApplied: successfulFixes.length,
        message: commitMessage,
        preview: 'Commit would be created (dry run mode)'
      };
    }
  }

  /**
   * Generate intelligent commit message based on fixes applied
   */
  generateCommitMessage(fixes) {
    // Group fixes by category
    const categories = {};
    fixes.forEach(fix => {
      const category = fix.finding?.category || 'UNKNOWN';
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(fix);
    });

    // Count by category
    const categoryCounts = Object.entries(categories).map(([cat, fixes]) => ({
      category: cat,
      count: fixes.length,
      confidence: fixes.reduce((sum, f) => sum + (f.confidence || 0.8), 0) / fixes.length
    }));

    // Sort by count descending
    categoryCounts.sort((a, b) => b.count - a.count);

    // Calculate overall stats
    const totalFixes = fixes.length;
    const avgConfidence = fixes.reduce((sum, f) => sum + (f.confidence || 0.8), 0) / totalFixes;
    const uniqueFiles = [...new Set(fixes.map(f => f.finding?.filePath || f.filePath))].length;

    // Build commit message
    const lines = [];

    // Title
    lines.push(`🔧 Auto-fix: Applied ${totalFixes} automated code improvement${totalFixes > 1 ? 's' : ''}`);
    lines.push('');

    // Details by category
    lines.push('Details:');
    categoryCounts.forEach(({ category, count }) => {
      const categoryName = this.getCategoryDisplayName(category);
      lines.push(`- ${categoryName}: ${count} fix${count > 1 ? 'es' : ''}`);
    });
    lines.push('');

    // Files modified
    lines.push(`Files modified: ${uniqueFiles}`);
    lines.push(`Avg confidence: ${(avgConfidence * 100).toFixed(1)}%`);
    lines.push('');

    // Footer
    lines.push('🤖 Generated with CodeTitan Auto-Fixer');
    lines.push('https://github.com/your-org/codetitan');

    return lines.join('\n');
  }

  /**
   * Get human-readable category names
   */
  getCategoryDisplayName(category) {
    const categoryNames = {
      'SYNC_IO': 'Async I/O conversions',
      'COMMAND_EXEC': 'Command execution security',
      'MAGIC_NUMBER': 'Magic number extraction',
      'HARDCODED_SECRET': 'Hardcoded secret removal',
      'SQL_INJECTION': 'SQL injection prevention',
      'XSS': 'XSS vulnerability fixes',
      'MISSING_DOCS': 'Documentation additions',
      'COMPLEX_CONDITION': 'Complex condition refactoring',
      'MISSING_TESTS': 'Test generation',
      'UNUSED_IMPORTS': 'Unused import removal',
      'CONSOLE_LOG': 'Logging improvements'
    };

    return categoryNames[category] || category;
  }

  /**
   * Get commit statistics
   */
  getStats() {
    return {
      ...this.stats
    };
  }

  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      filesStaged: 0,
      commitCreated: false,
      commitHash: null,
      branchCreated: null
    };
  }
}

module.exports = GitIntegration;
