'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SUPPORTED_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.cjs',
  '.mjs'
]);

const CONTEXT_ROOT_FILES = [
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'tsconfig.json',
  'jsconfig.json',
  'next.config.js',
  'next.config.ts',
  '.codetitanignore'
];

function normalizePath(filePath) {
  const resolved = path.resolve(filePath);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function isSupportedSourceFile(filePath) {
  return SUPPORTED_EXTENSIONS.has(path.extname(String(filePath || '')).toLowerCase());
}

function getCommandCwd(targetPath) {
  const resolved = path.resolve(targetPath);
  try {
    return fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
  } catch (_) {
    return path.dirname(resolved);
  }
}

function runGit(args, cwd) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8'
  });

  return {
    status: typeof result.status === 'number' ? result.status : 1,
    stdout: String(result.stdout || ''),
    stderr: String(result.stderr || '')
  };
}

function resolveGitRoot(targetPath) {
  const cwd = getCommandCwd(targetPath);
  const result = runGit(['rev-parse', '--show-toplevel'], cwd);

  if (result.status !== 0 || !result.stdout.trim()) {
    throw new Error(`changed-only requires a git repository. ${result.stderr.trim() || 'git rev-parse failed.'}`.trim());
  }

  return path.resolve(result.stdout.trim());
}

function buildDiffSpec(baseRef) {
  const normalized = String(baseRef || '').trim();
  return normalized ? `${normalized}...HEAD` : 'HEAD';
}

function getScopePath(gitRoot, targetPath) {
  const resolvedTarget = path.resolve(targetPath);
  const relativePath = path.relative(gitRoot, resolvedTarget);
  if (!relativePath || relativePath === '') {
    return '.';
  }
  return relativePath.replace(/\\/g, '/');
}

function parseChangedFileLines(output, gitRoot) {
  const files = [];
  const seen = new Set();

  for (const line of String(output || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    const absolutePath = path.resolve(gitRoot, trimmed);
    const key = normalizePath(absolutePath);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    files.push(absolutePath);
  }

  return files;
}

function listChangedFiles(targetPath, options = {}) {
  const gitRoot = options.gitRoot ? path.resolve(options.gitRoot) : resolveGitRoot(targetPath);
  const scopePath = getScopePath(gitRoot, targetPath);
  let diffSpec = buildDiffSpec(options.baseRef);

  let diffResult = runGit(
    ['diff', '--name-only', '--diff-filter=ACMRTUXB', diffSpec, '--', scopePath],
    gitRoot
  );

  if (diffResult.status !== 0 && !String(options.baseRef || '').trim()) {
    diffSpec = 'WORKTREE';
    diffResult = {
      status: 0,
      stdout: '',
      stderr: diffResult.stderr
    };
  }

  if (diffResult.status !== 0) {
    throw new Error(`Unable to enumerate changed files. ${diffResult.stderr.trim() || 'git diff failed.'}`.trim());
  }

  const untrackedResult = runGit(
    ['ls-files', '--others', '--exclude-standard', '--', scopePath],
    gitRoot
  );

  const candidates = [
    ...parseChangedFileLines(diffResult.stdout, gitRoot),
    ...(untrackedResult.status === 0 ? parseChangedFileLines(untrackedResult.stdout, gitRoot) : [])
  ];

  const seen = new Set();
  const changedFiles = [];

  for (const filePath of candidates) {
    const key = normalizePath(filePath);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);

    if (!fs.existsSync(filePath)) {
      continue;
    }

    let stat;
    try {
      stat = fs.statSync(filePath);
    } catch (_) {
      continue;
    }

    if (!stat.isFile() || !isSupportedSourceFile(filePath)) {
      continue;
    }

    changedFiles.push(path.resolve(filePath));
  }

  return {
    gitRoot,
    scopePath,
    diffSpec,
    changedFiles
  };
}

function copyFilePreservingStructure(projectRoot, workspaceRoot, filePath) {
  const relativePath = path.relative(projectRoot, filePath);
  const destinationPath = path.join(workspaceRoot, relativePath);
  fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
  fs.copyFileSync(filePath, destinationPath);
}

function createChangedFilesWorkspace(projectRoot, changedFiles, options = {}) {
  const rootPath = path.resolve(projectRoot);
  const workspaceRoot = options.workspaceRoot || fs.mkdtempSync(path.join(os.tmpdir(), 'codetitan-changed-'));

  for (const filePath of changedFiles) {
    copyFilePreservingStructure(rootPath, workspaceRoot, filePath);
  }

  for (const fileName of CONTEXT_ROOT_FILES) {
    const sourcePath = path.join(rootPath, fileName);
    if (!fs.existsSync(sourcePath)) {
      continue;
    }
    const stat = fs.statSync(sourcePath);
    if (!stat.isFile()) {
      continue;
    }
    copyFilePreservingStructure(rootPath, workspaceRoot, sourcePath);
  }

  return workspaceRoot;
}

module.exports = {
  normalizePath,
  isSupportedSourceFile,
  resolveGitRoot,
  listChangedFiles,
  createChangedFilesWorkspace
};
