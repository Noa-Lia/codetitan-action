'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

function createHandleId() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  return `wt-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

function slugifyName(value) {
  return String(value || 'workspace')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'workspace';
}

class GitWorktreeManager {
  constructor(options = {}) {
    this.repoPath = path.resolve(options.repoPath || process.cwd());
    this.workspaceDir = options.workspaceDir || '.codetitan/worktrees';
    this.workspaceRoot = this.resolvePathInsideRepo(this.workspaceDir);
    this.logger = options.logger || console;
    this.fallbackToCopy = options.fallbackToCopy !== false;
    this.handles = new Map();
  }

  resolvePathInsideRepo(targetPath = '.') {
    const absolutePath = path.resolve(this.repoPath, targetPath);
    const relativePath = path.relative(this.repoPath, absolutePath);

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      throw new Error(`Path escapes repository root: ${targetPath}`);
    }

    return absolutePath;
  }

  assertManagedPath(targetPath) {
    const absolutePath = path.resolve(targetPath);
    const relativePath = path.relative(this.workspaceRoot, absolutePath);

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      throw new Error(`Managed path escapes workspace root: ${targetPath}`);
    }

    return absolutePath;
  }

  isGitRepository() {
    try {
      execFileSync('git', ['rev-parse', '--git-dir'], {
        cwd: this.repoPath,
        stdio: 'pipe'
      });
      return true;
    } catch {
      return false;
    }
  }

  getHead(cwd = this.repoPath) {
    try {
      return execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd,
        encoding: 'utf8',
        stdio: 'pipe'
      }).trim();
    } catch {
      return null;
    }
  }

  getCurrentBranch(cwd = this.repoPath) {
    try {
      return execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
        cwd,
        encoding: 'utf8',
        stdio: 'pipe'
      }).trim();
    } catch {
      return null;
    }
  }

  listWorktrees() {
    try {
      const output = execFileSync('git', ['worktree', 'list', '--porcelain'], {
        cwd: this.repoPath,
        encoding: 'utf8',
        stdio: 'pipe'
      });

      const worktrees = [];
      let current = {};
      output.split('\n').forEach(line => {
        if (line.startsWith('worktree ')) {
          if (current.path) {
            worktrees.push(current);
          }
          current = { path: line.slice(9).trim(), branch: null, head: null };
        } else if (line.startsWith('HEAD ')) {
          current.head = line.slice(5).trim();
        } else if (line.startsWith('branch ')) {
          current.branch = line.slice(7).trim();
        }
      });

      if (current.path) {
        worktrees.push(current);
      }

      return worktrees;
    } catch {
      return [];
    }
  }

  createWorktree(options = {}) {
    const name = slugifyName(options.name || 'workspace');
    const baseDir = options.baseDir || this.workspaceDir;
    const fallbackToCopy = options.fallbackToCopy ?? this.fallbackToCopy;
    const ref = options.ref || 'HEAD';
    const baseRoot = this.resolvePathInsideRepo(baseDir);
    const explicitTargetPath = options.targetPath
      ? this.resolvePathInsideRepo(path.relative(this.repoPath, path.resolve(this.repoPath, options.targetPath)))
      : null;
    const handle = {
      id: createHandleId(),
      name,
      mode: null,
      path: explicitTargetPath || path.join(baseRoot, `${name}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`),
      repoPath: this.repoPath,
      baseDir,
      ref,
      head: null,
      branch: null,
      createdAt: new Date().toISOString(),
      fallbackReason: null
    };

    fs.mkdirSync(baseRoot, { recursive: true });

    if (this.isGitRepository()) {
      try {
        execFileSync('git', ['worktree', 'add', '--detach', handle.path, ref], {
          cwd: this.repoPath,
          stdio: 'pipe'
        });
        handle.mode = 'git_worktree';
        handle.head = this.getHead(handle.path);
        handle.branch = this.getCurrentBranch(handle.path);
        this.handles.set(handle.id, handle);
        return { ...handle };
      } catch (error) {
        if (!fallbackToCopy) {
          throw error;
        }
        handle.fallbackReason = error.message;
      }
    } else if (!fallbackToCopy) {
      throw new Error('Repository is not a git repository and fallback copy mode is disabled');
    }

    this.copyProjectTo(handle.path);
    handle.mode = 'directory_copy';
    handle.head = this.getHead(this.repoPath);
    handle.branch = this.getCurrentBranch(this.repoPath);
    this.handles.set(handle.id, handle);
    return { ...handle };
  }

  copyProjectTo(destinationPath) {
    fs.mkdirSync(destinationPath, { recursive: true });

    if (this.isGitRepository()) {
      try {
        const tracked = execFileSync('git', ['ls-files', '-z'], {
          cwd: this.repoPath,
          encoding: 'utf8',
          stdio: 'pipe'
        });
        tracked.split('\0').filter(Boolean).forEach(filePath => {
          const source = path.join(this.repoPath, filePath);
          const destination = path.join(destinationPath, filePath);
          if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
            return;
          }
          fs.mkdirSync(path.dirname(destination), { recursive: true });
          fs.copyFileSync(source, destination);
        });
        return;
      } catch {
        // Fall through to a conservative directory copy.
      }
    }

    this.copyDirectoryRecursive(this.repoPath, destinationPath);
  }

  copyDirectoryRecursive(sourceRoot, destinationRoot) {
    const ignoredNames = new Set([
      '.git',
      '.codetitan',
      'node_modules',
      '.tool-bridge-backups'
    ]);

    const walk = (sourcePath, destinationPath) => {
      fs.mkdirSync(destinationPath, { recursive: true });

      fs.readdirSync(sourcePath, { withFileTypes: true }).forEach(entry => {
        if (ignoredNames.has(entry.name)) {
          return;
        }

        const absoluteSource = path.join(sourcePath, entry.name);
        const absoluteDestination = path.join(destinationPath, entry.name);

        if (entry.isDirectory()) {
          walk(absoluteSource, absoluteDestination);
          return;
        }

        if (!entry.isFile()) {
          return;
        }

        fs.mkdirSync(path.dirname(absoluteDestination), { recursive: true });
        fs.copyFileSync(absoluteSource, absoluteDestination);
      });
    };

    walk(sourceRoot, destinationRoot);
  }

  normalizeHandle(handleOrPath) {
    if (!handleOrPath) {
      throw new Error('Worktree handle or path is required');
    }

    if (typeof handleOrPath === 'string') {
      if (this.handles.has(handleOrPath)) {
        return this.handles.get(handleOrPath);
      }

      const existing = Array.from(this.handles.values()).find(handle => handle.path === path.resolve(handleOrPath));
      if (existing) {
        return existing;
      }

      return {
        id: null,
        path: path.resolve(handleOrPath),
        mode: this.isGitRepository() ? 'git_worktree' : 'directory_copy'
      };
    }

    if (handleOrPath.id && this.handles.has(handleOrPath.id)) {
      return this.handles.get(handleOrPath.id);
    }

    if (handleOrPath.path) {
      return {
        ...handleOrPath,
        path: path.resolve(handleOrPath.path)
      };
    }

    throw new Error('Invalid worktree handle');
  }

  removeWorktree(handleOrPath) {
    const handle = this.normalizeHandle(handleOrPath);
    const absolutePath = this.assertManagedPath(handle.path);
    let removedViaGit = false;

    if (handle.mode === 'git_worktree' && this.isGitRepository()) {
      try {
        execFileSync('git', ['worktree', 'remove', '--force', absolutePath], {
          cwd: this.repoPath,
          stdio: 'pipe'
        });
        removedViaGit = true;
      } catch {
        removedViaGit = false;
      }
    }

    if (!removedViaGit && fs.existsSync(absolutePath)) {
      fs.rmSync(absolutePath, { recursive: true, force: true });
    }

    if (handle.id) {
      this.handles.delete(handle.id);
    }

    return {
      success: true,
      path: absolutePath,
      mode: handle.mode,
      removedViaGit
    };
  }

  cleanupAll() {
    const handles = Array.from(this.handles.values());
    return handles.map(handle => this.removeWorktree(handle));
  }

  toRepoRelativePath(filePath) {
    const absolutePath = path.isAbsolute(filePath)
      ? path.resolve(filePath)
      : this.resolvePathInsideRepo(filePath);
    const relativePath = path.relative(this.repoPath, absolutePath);

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      throw new Error(`File escapes repository root: ${filePath}`);
    }

    return relativePath.split(path.sep).join('/');
  }

  promoteFiles(handleOrPath, files = []) {
    const handle = this.normalizeHandle(handleOrPath);
    const absoluteWorktreePath = this.assertManagedPath(handle.path);
    const relativeFiles = files.map(filePath => this.toRepoRelativePath(filePath));

    relativeFiles.forEach(relativePath => {
      const source = path.resolve(absoluteWorktreePath, relativePath);
      const destination = path.resolve(this.repoPath, relativePath);

      if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
        throw new Error(`Worktree file not found for promotion: ${relativePath}`);
      }

      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(source, destination);
    });

    return {
      success: true,
      path: absoluteWorktreePath,
      files: relativeFiles
    };
  }

  captureDiff(handleOrPath, options = {}) {
    const handle = this.normalizeHandle(handleOrPath);
    const cwd = this.assertManagedPath(handle.path);
    const args = ['diff', '--no-ext-diff', `--unified=${Math.max(0, Number(options.unified) || 3)}`];
    const files = Array.isArray(options.files) ? options.files.map(filePath => this.toRepoRelativePath(filePath)) : [];

    if (files.length > 0) {
      args.push('--', ...files);
    }

    try {
      const diff = execFileSync('git', args, {
        cwd,
        encoding: 'utf8',
        stdio: 'pipe'
      });

      return {
        success: true,
        diff,
        filesChanged: (diff.match(/^diff --git /gm) || []).length,
        lines: diff ? diff.split('\n').length : 0
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        diff: '',
        filesChanged: 0,
        lines: 0
      };
    }
  }
}

module.exports = GitWorktreeManager;
