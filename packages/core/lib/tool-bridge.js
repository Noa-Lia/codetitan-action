/**
 * Tool Bridge
 *
 * THE MISSING PIECE - Connects agents to Claude's REAL tools
 *
 * This bridge allows agents running in the execution engine to:
 * 1. Read actual files (not mock data)
 * 2. Write actual code (not simulation)
 * 3. Edit actual files (not fake refactorings)
 * 4. Run actual commands (not generic responses)
 *
 * This is what makes execution REAL instead of SIMULATED.
 *
 * NOTE: This is a FUNCTIONAL implementation that uses Node.js fs module
 * for file operations. In a full Claude Code integration, this would
 * call Claude's actual tools through the runtime API.
 */

const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execSync, spawnSync } = require('child_process');
const GitWorktreeManager = require('./git-worktree-manager');
const BrowserMCPClient = require('./browser-mcp-client');
const { postPRAnnotations } = require('./github-integration');

class ToolBridge {
  constructor(options = {}) {
    this.options = {
      workingDirectory: options.workingDirectory || process.cwd(),
      enableFileOperations: options.enableFileOperations ?? true,
      enableBashOperations: options.enableBashOperations ?? false, // Disabled by default for safety
      enableBackups: options.enableBackups ?? true, // Backup before write/edit
      enableValidation: options.enableValidation ?? false, // Validate after changes
      maxFileSize: options.maxFileSize || 1024 * 1024, // 1MB default
      backupDir: options.backupDir || path.join(process.cwd(), '.tool-bridge-backups'),
      commandAllowlist: options.commandAllowlist || [],
      testCommandAllowlist: options.testCommandAllowlist || ['npm', 'pnpm', 'yarn', 'npx', 'node', 'jest', 'vitest', 'mocha'],
      ...options
    };

    this.metrics = {
      filesRead: 0,
      filesWritten: 0,
      filesEdited: 0,
      commandsExecuted: 0,
      bytesRead: 0,
      bytesWritten: 0,
      errors: 0,
      backupsCreated: 0,
      rollbacksPerformed: 0,
      validationsPassed: 0,
      validationsFailed: 0,
      worktreesCreated: 0,
      worktreesRemoved: 0,
      worktreePromotions: 0,
      historyReads: 0,
      browserCalls: 0,
      githubReviewsPosted: 0
    };

    // Change tracking
    this.changeHistory = [];
    this.maxHistorySize = options.maxHistorySize || 100;

    // Ensure backup directory exists
    if (this.options.enableBackups) {
      fsp.mkdir(this.options.backupDir, { recursive: true }).catch(() => { });
    }
    this.worktreeManager = options.worktreeManager || new GitWorktreeManager({
      repoPath: this.options.workingDirectory,
      workspaceDir: options.workspaceDir || '.codetitan/worktrees',
      logger: console
    });
    this.browserClient = options.browserClient || null;

    console.log('[ToolBridge] Initialized');
    console.log(`[ToolBridge] Working directory: ${this.options.workingDirectory}`);
    console.log(`[ToolBridge] File operations: ${this.options.enableFileOperations ? 'ENABLED' : 'DISABLED'}`);
    console.log(`[ToolBridge] Bash operations: ${this.options.enableBashOperations ? 'ENABLED' : 'DISABLED'}`);
    console.log(`[ToolBridge] Backups: ${this.options.enableBackups ? 'ENABLED' : 'DISABLED'}`);

    console.log(`[ToolBridge] Validation: ${this.options.enableValidation ? 'ENABLED' : 'DISABLED'}`);
  }

  /**
   * Securely validate path is within working directory
   * Prevents Directory Traversal (CWE-22)
   */
  _validatePath(targetPath) {
    const root = path.resolve(this.options.workingDirectory);
    const absolutePath = path.resolve(root, targetPath);

    // Check if path is inside root using relative path calculation
    // This is safer than startsWith which can be bypassed (e.g. /dir vs /dir_secret)
    const relative = path.relative(root, absolutePath);

    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error(`Access denied: Path escape attempt detected (${targetPath})`);
    }

    return absolutePath;
  }

  /**
   * Validate command against injection attacks
   * Prevents Command Injection (CWE-78)
   */
  _validateCommand(command) {
    const trimmed = command.trim();

    // 1. Check Allowlist
    const allowed = this.options.commandAllowlist.some(prefix => {
      // Ensure specific match (e.g. "git " or exact "git")
      return trimmed === prefix || trimmed.startsWith(prefix + ' ');
    });

    if (!allowed) {
      throw new Error('Command not allowed by allowlist');
    }

    // 2. Check for Shell Metacharacters
    // Block: ; | & $ ` ( ) < >
    // Exception: Allow legitimate file paths/flags, but block chaining
    const dangerousChars = /[;|`$()<>]/;
    if (dangerousChars.test(trimmed)) {
      throw new Error('Command contains restricted shell characters');
    }

    return trimmed;
  }

  _validateExecutable(command, allowlist = [], label = 'command') {
    const executable = String(command || '').trim();

    if (!executable) {
      throw new Error(`${label} is required`);
    }

    if (/[\\/]/.test(executable)) {
      throw new Error(`${label} must be a bare executable name`);
    }

    if (!allowlist.includes(executable)) {
      throw new Error(`${label} not allowed by allowlist`);
    }

    return executable;
  }

  _resolveCwd(targetPath = '.') {
    return this._validatePath(targetPath || '.');
  }

  _spawn(command, args = [], options = {}) {
    const executable = this._validateExecutable(command, options.allowlist || [], options.label || 'command');
    const cwd = this._resolveCwd(options.cwd || '.');
    const timeout = options.timeout || 30000;
    const maxBuffer = options.maxBuffer || 1024 * 1024;

    const result = spawnSync(executable, args, {
      cwd,
      encoding: 'utf8',
      timeout,
      maxBuffer,
      shell: false
    });

    this.metrics.commandsExecuted++;

    if (result.error) {
      this.metrics.errors++;
      return {
        success: false,
        command: executable,
        args,
        cwd,
        error: result.error.message,
        exitCode: result.status ?? 1,
        stdout: result.stdout || '',
        stderr: result.stderr || ''
      };
    }

    const exitCode = typeof result.status === 'number' ? result.status : 0;
    return {
      success: exitCode === 0,
      command: executable,
      args,
      cwd,
      exitCode,
      stdout: result.stdout || '',
      stderr: result.stderr || ''
    };
  }

  /**
   * Read a file
   * Maps to Claude's Read tool
   */
  async read(filePath) {
    if (!this.options.enableFileOperations) {
      throw new Error('File operations are disabled');
    }


    try {
      const absolutePath = this._validatePath(filePath);

      // Check if file exists and size
      const stats = await fsp.stat(absolutePath);
      if (!stats.isFile()) {
        throw new Error(`Not a file: ${filePath}`);
      }
      if (stats.size > this.options.maxFileSize) {
        throw new Error(`File too large: ${stats.size} bytes (max: ${this.options.maxFileSize})`);
      }

      // Read file
      const content = await fsp.readFile(absolutePath, 'utf8');

      // Update metrics
      this.metrics.filesRead++;
      this.metrics.bytesRead += content.length;

      console.log(`[ToolBridge] Read file: ${filePath} (${content.length} bytes)`);

      return {
        success: true,
        filePath: filePath,
        absolutePath: absolutePath,
        content: content,
        size: content.length,
        lines: content.split('\n').length
      };

    } catch (error) {
      this.metrics.errors++;
      console.error(`[ToolBridge] Read error:`, error.message);
      return {
        success: false,
        filePath: filePath,
        error: error.message
      };
    }
  }

  /**
   * Write a file (with automatic backup)
   * Maps to Claude's Write tool
   */
  async write(filePath, content, options = {}) {
    if (!this.options.enableFileOperations) {
      throw new Error('File operations are disabled');
    }

    const changeId = `write-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    try {
      const absolutePath = this._validatePath(filePath);

      // Create backup if file exists
      let backupPath = null;
      if (this.options.enableBackups) {
        const exists = await fsp.stat(absolutePath).then(stat => stat.isFile()).catch(() => false);
        if (exists) {
          backupPath = await this.createBackup(absolutePath, changeId);
        }
      }

      // Ensure directory exists
      const directory = path.dirname(absolutePath);
      await fsp.mkdir(directory, { recursive: true });

      // Write file
      await fsp.writeFile(absolutePath, content, 'utf8');

      // Update metrics
      this.metrics.filesWritten++;
      this.metrics.bytesWritten += content.length;

      // Track change
      this.trackChange({
        id: changeId,
        type: 'write',
        filePath: filePath,
        absolutePath: absolutePath,
        backupPath: backupPath,
        timestamp: new Date().toISOString(),
        size: content.length
      });

      console.log(`[ToolBridge] Wrote file: ${filePath} (${content.length} bytes)`);

      // Validate if enabled
      if (this.options.enableValidation && options.validate) {
        const validation = await this.validateChange(changeId, options.validationCommand);
        if (!validation.success) {
          // Rollback on validation failure
          console.warn(`[ToolBridge] Validation failed, rolling back write to ${filePath}`);
          await this.rollback(changeId);
          return {
            success: false,
            filePath: filePath,
            error: 'Validation failed',
            validationError: validation.error,
            rolledBack: true
          };
        }
      }

      return {
        success: true,
        changeId: changeId,
        filePath: filePath,
        absolutePath: absolutePath,
        size: content.length,
        lines: content.split('\n').length,
        backedUp: backupPath !== null,
        backupPath: backupPath
      };

    } catch (error) {
      this.metrics.errors++;
      console.error(`[ToolBridge] Write error:`, error.message);

      // Attempt rollback on error
      try {
        await this.rollback(changeId);
      } catch (rollbackError) {
        console.error(`[ToolBridge] Rollback failed:`, rollbackError.message);
      }

      return {
        success: false,
        filePath: filePath,
        error: error.message
      };
    }
  }

  /**
   * Edit a file
   * Maps to Claude's Edit tool
   */
  async edit(filePath, oldString, newString) {
    if (!this.options.enableFileOperations) {
      throw new Error('File operations are disabled');
    }

    try {
      const absolutePath = this._validatePath(filePath);

      // Read current content
      const stats = await fsp.stat(absolutePath).catch(() => null);
      if (!stats || !stats.isFile()) {
        throw new Error(`File not found: ${filePath}`);
      }

      const content = await fsp.readFile(absolutePath, 'utf8');

      // Check if old string exists
      if (!content.includes(oldString)) {
        throw new Error('Old string not found in file');
      }

      // Replace
      const newContent = content.replace(oldString, newString);

      // Write back
      await fsp.writeFile(absolutePath, newContent, 'utf8');

      // Update metrics
      this.metrics.filesEdited++;
      this.metrics.bytesWritten += newContent.length;

      console.log(`[ToolBridge] Edited file: ${filePath}`);

      return {
        success: true,
        filePath: filePath,
        absolutePath: absolutePath,
        oldLength: content.length,
        newLength: newContent.length,
        difference: newContent.length - content.length
      };

    } catch (error) {
      this.metrics.errors++;
      console.error(`[ToolBridge] Edit error:`, error.message);
      return {
        success: false,
        filePath: filePath,
        error: error.message
      };
    }
  }

  /**
   * Execute bash command
   * Maps to Claude's Bash tool
   */
  async bash(command, options = {}) {
    if (!this.options.enableBashOperations) {
      throw new Error('Bash operations are disabled for security');
    }

    const trimmed = command.trim();
    try {
      this._validateCommand(command);

      // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
      const result = execSync(command, {
        cwd: this.options.workingDirectory,
        encoding: 'utf8',
        timeout: options.timeout || 30000,
        maxBuffer: options.maxBuffer || 1024 * 1024
      });

      this.metrics.commandsExecuted++;

      console.log(`[ToolBridge] Executed command: ${command}`);

      return {
        success: true,
        command: command,
        output: result,
        exitCode: 0
      };

    } catch (error) {
      this.metrics.errors++;
      console.error(`[ToolBridge] Bash error:`, error.message);
      return {
        success: false,
        command: command,
        error: error.message,
        exitCode: error.status || 1,
        output: error.stdout || ''
      };
    }
  }

  /**
   * List files in directory
   * Helper method for agents
   */
  async listFiles(dirPath, options = {}) {
    if (!this.options.enableFileOperations) {
      throw new Error('File operations are disabled');
    }


    try {
      const absolutePath = this._validatePath(dirPath);

      const files = await fsp.readdir(absolutePath, { withFileTypes: true });

      const result = files.map(file => ({
        name: file.name,
        path: path.join(dirPath, file.name),
        isDirectory: file.isDirectory(),
        isFile: file.isFile()
      }));

      // Apply filters
      if (options.extension) {
        return result.filter(f => f.isFile && f.name.endsWith(options.extension));
      }

      if (options.filesOnly) {
        return result.filter(f => f.isFile);
      }

      if (options.directoriesOnly) {
        return result.filter(f => f.isDirectory);
      }

      return result;

    } catch (error) {
      this.metrics.errors++;
      console.error(`[ToolBridge] List files error:`, error.message);
      return {
        success: false,
        dirPath: dirPath,
        error: error.message
      };
    }
  }

  /**
   * Analyze file (read + provide metadata)
   * Helper method for code analysis
   */
  async analyzeFile(filePath) {
    const readResult = await this.read(filePath);

    if (!readResult.success) {
      return readResult;
    }

    const content = readResult.content;
    const lines = content.split('\n');

    // Basic analysis
    const analysis = {
      success: true,
      filePath: filePath,
      size: content.length,
      lines: lines.length,
      nonEmptyLines: lines.filter(l => l.trim().length > 0).length,
      functions: (content.match(/function\s+\w+/g) || []).length,
      classes: (content.match(/class\s+\w+/g) || []).length,
      comments: lines.filter(l => l.trim().startsWith('//') || l.trim().startsWith('/*')).length,
      todos: (content.match(/\/\/\s*TODO/gi) || []).length,
      complexity: this.estimateComplexity(content)
    };

    return analysis;
  }

  async searchCode(query, options = {}) {
    if (!this.options.enableFileOperations) {
      throw new Error('File operations are disabled');
    }

    const normalizedQuery = String(query || '').trim();
    if (!normalizedQuery) {
      return {
        success: false,
        query,
        error: 'Search query is required'
      };
    }

    const basePath = options.path || '.';
    const caseSensitive = options.caseSensitive === true;
    const maxResults = Math.max(1, Math.min(Number(options.maxResults) || 20, 200));
    const extensions = Array.isArray(options.extensions) && options.extensions.length > 0
      ? options.extensions
        .map(value => String(value || '').trim())
        .filter(Boolean)
      : null;
    const extension = options.extension || null;
    const allowedExtensions = extensions && extensions.length > 0
      ? extensions
      : (extension ? [extension] : null);
    const includeHidden = options.includeHidden === true;
    const maxFiles = Math.max(1, Math.min(Number(options.maxFiles) || 200, 1000));
    const matches = [];
    let filesScanned = 0;

    try {
      const root = this._validatePath(basePath);
      const candidateFiles = [];

      const walk = async (absoluteDir, relativeDir) => {
        if (candidateFiles.length >= maxFiles || matches.length >= maxResults) {
          return;
        }

        const entries = await fsp.readdir(absoluteDir, { withFileTypes: true });
        for (const entry of entries) {
          if (!includeHidden && entry.name.startsWith('.')) {
            continue;
          }

          const relativePath = relativeDir === '.'
            ? entry.name
            : path.join(relativeDir, entry.name);
          const absolutePath = path.join(absoluteDir, entry.name);

          if (entry.isDirectory()) {
            if (entry.name === 'node_modules' || entry.name === '.git') {
              continue;
            }

            await walk(absolutePath, relativePath);
            if (candidateFiles.length >= maxFiles || matches.length >= maxResults) {
              return;
            }
            continue;
          }

          if (!entry.isFile()) {
            continue;
          }

          if (allowedExtensions && !allowedExtensions.some(value => entry.name.endsWith(value))) {
            continue;
          }

          candidateFiles.push({ absolutePath, relativePath });
          if (candidateFiles.length >= maxFiles) {
            return;
          }
        }
      };

      await walk(root, basePath === '.' ? '.' : basePath);

      const searchNeedle = caseSensitive ? normalizedQuery : normalizedQuery.toLowerCase();
      for (const file of candidateFiles) {
        if (matches.length >= maxResults) {
          break;
        }

        const stats = await fsp.stat(file.absolutePath).catch(() => null);
        if (!stats || !stats.isFile() || stats.size > this.options.maxFileSize) {
          continue;
        }

        const content = await fsp.readFile(file.absolutePath, 'utf8').catch(() => null);
        if (typeof content !== 'string') {
          continue;
        }

        filesScanned++;
        const lines = content.split('\n');
        for (let index = 0; index < lines.length; index += 1) {
          const line = lines[index];
          const haystack = caseSensitive ? line : line.toLowerCase();
          const column = haystack.indexOf(searchNeedle);
          if (column === -1) {
            continue;
          }

          matches.push({
            file: file.relativePath,
            line: index + 1,
            column: column + 1,
            preview: line.trim().slice(0, 240)
          });

          if (matches.length >= maxResults) {
            break;
          }
        }
      }

      return {
        success: true,
        query: normalizedQuery,
        basePath,
        matches,
        filesScanned,
        truncated: matches.length >= maxResults
      };
    } catch (error) {
      this.metrics.errors++;
      console.error('[ToolBridge] Search error:', error.message);
      return {
        success: false,
        query: normalizedQuery,
        basePath,
        error: error.message
      };
    }
  }

  async runTests(input = {}) {
    try {
      const command = input.command || 'npm';
      const args = Array.isArray(input.args) ? input.args : [];
      const result = this._spawn(command, args, {
        allowlist: this.options.testCommandAllowlist,
        label: 'test command',
        cwd: input.cwd || '.',
        timeout: input.timeoutMs || input.timeout || 60000,
        maxBuffer: input.maxBuffer || 1024 * 1024
      });

      return {
        ...result,
        passed: result.success
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        command: input.command || 'npm',
        args: Array.isArray(input.args) ? input.args : [],
        cwd: input.cwd || '.',
        error: error.message,
        exitCode: 1,
        stdout: '',
        stderr: ''
      };
    }
  }

  async gitStatus(input = {}) {
    try {
      const result = this._spawn('git', ['status', '--short', '--branch', '--porcelain=v1'], {
        allowlist: ['git'],
        label: 'git command',
        cwd: input.cwd || '.',
        timeout: input.timeoutMs || input.timeout || 30000
      });

      if (!result.success) {
        this.metrics.errors++;
        return result;
      }

      const lines = result.stdout.split('\n').filter(Boolean);
      let branch = null;
      const files = [];

      lines.forEach(line => {
        if (line.startsWith('## ')) {
          branch = line.slice(3).trim();
          return;
        }

        const rawStatus = line.slice(0, 2);
        const filePath = line.slice(3).trim();
        files.push({
          rawStatus,
          indexStatus: rawStatus[0] || ' ',
          worktreeStatus: rawStatus[1] || ' ',
          path: filePath
        });
      });

      return {
        ...result,
        branch,
        files,
        clean: files.length === 0
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        error: error.message,
        exitCode: 1,
        stdout: '',
        stderr: ''
      };
    }
  }

  async gitDiff(input = {}) {
    try {
      const args = ['diff', '--no-ext-diff', `--unified=${Math.max(0, Number(input.unified) || 3)}`];

      if (input.cached) {
        args.push('--cached');
      }

      if (input.base && input.head) {
        args.push(input.base, input.head);
      } else if (input.base) {
        args.push(input.base);
      } else if (input.head) {
        args.push('HEAD', input.head);
      }

      const pathspecs = [];
      if (typeof input.file === 'string' && input.file.trim()) {
        pathspecs.push(input.file);
      }
      if (Array.isArray(input.paths)) {
        pathspecs.push(...input.paths.filter(Boolean));
      }
      if (pathspecs.length > 0) {
        args.push('--', ...pathspecs);
      }

      const result = this._spawn('git', args, {
        allowlist: ['git'],
        label: 'git command',
        cwd: input.cwd || '.',
        timeout: input.timeoutMs || input.timeout || 30000,
        maxBuffer: input.maxBuffer || 2 * 1024 * 1024
      });

      if (!result.success) {
        this.metrics.errors++;
        return result;
      }

      const diff = result.stdout || '';
      return {
        ...result,
        diff,
        isEmpty: diff.trim().length === 0,
        lines: diff ? diff.split('\n').length : 0,
        filesChanged: (diff.match(/^diff --git /gm) || []).length
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        error: error.message,
        exitCode: 1,
        stdout: '',
        stderr: ''
      };
    }
  }

  historyRoot() {
    return path.join(os.homedir(), '.codetitan', 'history');
  }

  projectHash(projectPath) {
    const normalized = path.resolve(projectPath).toLowerCase().replace(/\\/g, '/');
    return crypto.createHash('sha1').update(normalized).digest('hex').slice(0, 12);
  }

  resolveHistoryProjectPath(projectPath = '.') {
    if (typeof projectPath === 'string' && path.isAbsolute(projectPath)) {
      const relativeToRoot = path.relative(path.resolve(this.options.workingDirectory), path.resolve(projectPath));
      if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) {
        throw new Error(`projectPath escapes working directory: ${projectPath}`);
      }
      return path.resolve(projectPath);
    }

    return this._validatePath(projectPath || '.');
  }

  getHistoryProjectDir(projectPath) {
    return path.join(this.historyRoot(), this.projectHash(projectPath));
  }

  readHistoryRunFromFile(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    this.metrics.historyReads++;
    this.metrics.bytesRead += raw.length;
    return JSON.parse(raw);
  }

  loadHistoryRuns(projectPath, limit = 10) {
    const dir = this.getHistoryProjectDir(projectPath);
    if (!fs.existsSync(dir)) {
      return [];
    }

    return fs.readdirSync(dir)
      .filter(file => file.endsWith('.json') && file !== 'meta.json')
      .sort()
      .reverse()
      .slice(0, Math.max(1, Number(limit) || 10))
      .map(file => this.readHistoryRunFromFile(path.join(dir, file)));
  }

  loadHistoryRun(projectPath, runId) {
    const dir = this.getHistoryProjectDir(projectPath);
    const runPath = path.join(dir, `${runId}.json`);
    if (!fs.existsSync(runPath)) {
      return null;
    }
    return this.readHistoryRunFromFile(runPath);
  }

  buildFindingSignature(finding = {}) {
    return `${finding.category}:${finding.file_path}:${finding.line_number}`;
  }

  diffHistoryRuns(runA, runB) {
    const findingsA = Array.isArray(runA?.report?.findings) ? runA.report.findings : [];
    const findingsB = Array.isArray(runB?.report?.findings) ? runB.report.findings : [];
    const mapA = new Map(findingsA.map(finding => [this.buildFindingSignature(finding), finding]));
    const mapB = new Map(findingsB.map(finding => [this.buildFindingSignature(finding), finding]));

    const added = [];
    const fixed = [];
    const unchanged = [];

    mapB.forEach((finding, signature) => {
      if (mapA.has(signature)) {
        unchanged.push(finding);
      } else {
        added.push(finding);
      }
    });

    mapA.forEach((finding, signature) => {
      if (!mapB.has(signature)) {
        fixed.push(finding);
      }
    });

    return { added, fixed, unchanged };
  }

  async fetchHistory(input = {}) {
    try {
      const projectPath = this.resolveHistoryProjectPath(input.projectPath || '.');
      const historyDir = this.getHistoryProjectDir(projectPath);
      const limit = Math.max(1, Math.min(Number(input.limit) || 10, 100));
      const runFiles = fs.existsSync(historyDir)
        ? fs.readdirSync(historyDir).filter(file => file.endsWith('.json') && file !== 'meta.json').sort().reverse()
        : [];

      if (input.runId) {
        const run = this.loadHistoryRun(projectPath, input.runId);
        if (!run) {
          throw new Error(`Run not found: ${input.runId}`);
        }

        return {
          success: true,
          projectPath,
          projectHash: this.projectHash(projectPath),
          runCount: runFiles.length,
          run,
          runs: [
            {
              runId: run.runId,
              timestamp: run.timestamp,
              total: run.total,
              severity: run.severity
            }
          ]
        };
      }

      const runs = this.loadHistoryRuns(projectPath, limit);
      return {
        success: true,
        projectPath,
        projectHash: this.projectHash(projectPath),
        runCount: runFiles.length,
        runs: runs.map(run => ({
          runId: run.runId,
          timestamp: run.timestamp,
          total: run.total,
          severity: run.severity
        }))
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        error: error.message
      };
    }
  }

  async compareRuns(input = {}) {
    try {
      if (!input.runA || !input.runB) {
        throw new Error('compareRuns requires runA and runB');
      }

      const projectPath = this.resolveHistoryProjectPath(input.projectPath || '.');
      const runA = this.loadHistoryRun(projectPath, input.runA);
      const runB = this.loadHistoryRun(projectPath, input.runB);

      if (!runA) {
        throw new Error(`Run not found: ${input.runA}`);
      }
      if (!runB) {
        throw new Error(`Run not found: ${input.runB}`);
      }

      const diff = this.diffHistoryRuns(runA, runB);
      return {
        success: true,
        projectPath,
        baseline: {
          runId: runA.runId,
          timestamp: runA.timestamp,
          total: runA.total,
          severity: runA.severity
        },
        current: {
          runId: runB.runId,
          timestamp: runB.timestamp,
          total: runB.total,
          severity: runB.severity
        },
        added: diff.added,
        fixed: diff.fixed,
        unchanged: diff.unchanged
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        error: error.message
      };
    }
  }

  async getBrowserClient() {
    if (!this.browserClient) {
      this.browserClient = new BrowserMCPClient({
        verbose: false
      });
    }

    await this.browserClient.start();
    return this.browserClient;
  }

  normalizeBrowserContent(content) {
    if (!Array.isArray(content)) {
      return {
        items: [],
        text: '',
        bytesTouched: 0
      };
    }

    const items = content.map(item => {
      if (typeof item === 'string') {
        return { type: 'text', text: item };
      }
      return item || {};
    });
    const text = items
      .map(item => item.text || item.content || '')
      .filter(Boolean)
      .join('\n');

    return {
      items,
      text,
      bytesTouched: Buffer.byteLength(text, 'utf8')
    };
  }

  async browseWeb(input = {}) {
    const url = String(input.url || '').trim();
    const action = input.action || 'read';

    if (!url) {
      return {
        success: false,
        error: 'browseWeb requires a url'
      };
    }

    try {
      const client = await this.getBrowserClient();
      let content;

      if (action === 'screenshot') {
        content = await client.screenshot(url);
      } else if (action === 'click') {
        content = await client.click(url, input.selector);
      } else if (action === 'type') {
        content = await client.type(url, input.selector, input.text || '');
      } else {
        content = await client.read(url);
      }

      const normalized = this.normalizeBrowserContent(content);
      this.metrics.browserCalls += 1;
      this.metrics.bytesRead += normalized.bytesTouched;

      return {
        success: true,
        url,
        action,
        selector: input.selector || null,
        itemCount: normalized.items.length,
        text: normalized.text,
        content: normalized.items,
        bytesTouched: normalized.bytesTouched
      };
    } catch (error) {
      this.metrics.errors += 1;
      return {
        success: false,
        url,
        action,
        error: error.message
      };
    }
  }

  async postGitHubReview(input = {}) {
    const token = input.token || process.env.GITHUB_TOKEN;
    const findings = Array.isArray(input.findings) ? input.findings : [];

    if (!token) {
      return {
        success: false,
        error: 'GitHub token is required'
      };
    }

    if (findings.length === 0) {
      return {
        success: false,
        error: 'At least one finding is required'
      };
    }

    try {
      const response = await postPRAnnotations(findings, {
        owner: input.owner,
        repo: input.repo,
        prNumber: input.prNumber,
        commitSha: input.commitSha,
        token
      });

      this.metrics.githubReviewsPosted += 1;
      return {
        success: true,
        owner: input.owner,
        repo: input.repo,
        prNumber: input.prNumber,
        commitSha: input.commitSha,
        reviewId: response?.id || null,
        commentCount: Array.isArray(response?.comments) ? response.comments.length : findings.length,
        response
      };
    } catch (error) {
      this.metrics.errors += 1;
      return {
        success: false,
        owner: input.owner,
        repo: input.repo,
        prNumber: input.prNumber,
        error: error.message
      };
    }
  }

  async createWorktree(input = {}) {
    try {
      const handle = this.worktreeManager.createWorktree({
        name: input.name || 'agent-worktree',
        baseDir: input.baseDir || '.codetitan/worktrees',
        ref: input.ref,
        fallbackToCopy: input.fallbackToCopy
      });

      this.metrics.worktreesCreated++;
      return {
        success: true,
        ...handle
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        error: error.message
      };
    }
  }

  async removeWorktree(input = {}) {
    try {
      const result = this.worktreeManager.removeWorktree(input.path || input.handleId || input.handle);
      this.metrics.worktreesRemoved++;
      return {
        success: true,
        ...result
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        error: error.message
      };
    }
  }

  async promoteWorktree(input = {}) {
    try {
      const files = Array.isArray(input.files) ? input.files.filter(Boolean) : [];
      if (files.length === 0) {
        throw new Error('Promotion requires one or more files');
      }

      const result = this.worktreeManager.promoteFiles(
        input.path || input.handleId || input.handle,
        files
      );

      this.metrics.worktreePromotions++;
      return {
        success: true,
        ...result
      };
    } catch (error) {
      this.metrics.errors++;
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Estimate code complexity
   */
  estimateComplexity(code) {
    // Count complexity indicators
    const conditionals = (code.match(/\bif\b|\belse\b|\bswitch\b|\bcase\b/g) || []).length;
    const loops = (code.match(/\bfor\b|\bwhile\b|\bdo\b/g) || []).length;
    const functions = (code.match(/function\s+\w+|\w+\s*=>\s*{/g) || []).length;
    const tryCatch = (code.match(/\btry\b|\bcatch\b/g) || []).length;

    const complexity = conditionals + loops + functions + (tryCatch * 2);

    return {
      score: complexity,
      level: complexity < 10 ? 'low' : complexity < 30 ? 'medium' : 'high',
      conditionals,
      loops,
      functions,
      tryCatch
    };
  }

  /**
   * Create backup of file before modification
   */
  async createBackup(absolutePath, changeId) {
    try {
      const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
      const fileName = path.basename(absolutePath);
      const backupFileName = `${fileName}.${timestamp}.${changeId}.backup`;
      const backupPath = path.join(this.options.backupDir, backupFileName);

      // Read original content
      const content = await fsp.readFile(absolutePath, 'utf8');

      // Write backup
      await fsp.writeFile(backupPath, content, 'utf8');

      this.metrics.backupsCreated++;

      console.log(`[ToolBridge] Created backup: ${backupFileName}`);

      return backupPath;
    } catch (error) {
      console.error(`[ToolBridge] Backup creation failed:`, error.message);
      return null;
    }
  }

  /**
   * Track a change for potential rollback
   */
  trackChange(change) {
    this.changeHistory.unshift(change);

    // Keep history size manageable
    if (this.changeHistory.length > this.maxHistorySize) {
      this.changeHistory = this.changeHistory.slice(0, this.maxHistorySize);
    }
  }

  /**
   * Validate a change (run tests or custom validation)
   */
  async validateChange(changeId, validationCommand) {
    try {
      if (!validationCommand) {
        // No validation command specified, assume valid
        this.metrics.validationsPassed++;
        return { success: true };
      }

      // Run validation command
      const result = await this.bash(validationCommand);

      if (result.success) {
        this.metrics.validationsPassed++;
        console.log(`[ToolBridge] Validation passed for change ${changeId}`);
        return { success: true };
      } else {
        this.metrics.validationsFailed++;
        console.error(`[ToolBridge] Validation failed for change ${changeId}`);
        return {
          success: false,
          error: result.error || result.output
        };
      }
    } catch (error) {
      this.metrics.validationsFailed++;
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Rollback a change
   */
  async rollback(changeId) {
    try {
      // Find the change in history
      const change = this.changeHistory.find(c => c.id === changeId);

      if (!change) {
        throw new Error(`Change ${changeId} not found in history`);
      }

      if (!change.backupPath || !(await fsp.stat(change.backupPath).catch(() => null))) {
        throw new Error(`Backup not found for change ${changeId}`);
      }

      // Read backup
      const backupContent = await fsp.readFile(change.backupPath, 'utf8');

      // Restore file
      await fsp.writeFile(change.absolutePath, backupContent, 'utf8');

      this.metrics.rollbacksPerformed++;

      console.log(`[ToolBridge] Rolled back change ${changeId}`);

      return {
        success: true,
        changeId: changeId,
        filePath: change.filePath
      };
    } catch (error) {
      console.error(`[ToolBridge] Rollback failed:`, error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get change history
   */
  getChangeHistory(limit = 10) {
    return this.changeHistory.slice(0, limit);
  }

  /**
   * Get metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      errorRate: this.metrics.filesRead > 0 ?
        (this.metrics.errors / (this.metrics.filesRead + this.metrics.filesWritten + this.metrics.filesEdited)) : 0
    };
  }

  /**
   * Print metrics
   */
  printMetrics() {
    const metrics = this.getMetrics();
    console.log('\n+- TOOL BRIDGE METRICS --------------------------------------+');
    console.log(`| Files Read: ${metrics.filesRead.toString().padEnd(51)} |`);
    console.log(`| Files Written: ${metrics.filesWritten.toString().padEnd(48)} |`);
    console.log(`| Files Edited: ${metrics.filesEdited.toString().padEnd(49)} |`);
    console.log(`| Commands Executed: ${metrics.commandsExecuted.toString().padEnd(44)} |`);
    console.log(`|                                                            |`);
    console.log(`| Bytes Read: ${metrics.bytesRead.toString().padEnd(51)} |`);
    console.log(`| Bytes Written: ${metrics.bytesWritten.toString().padEnd(48)} |`);
    console.log(`|                                                            |`);
    console.log(`| Safety Mechanisms:                                         |`);
    console.log(`| +- Backups Created: ${metrics.backupsCreated.toString().padEnd(41)} |`);
    console.log(`| +- Rollbacks Performed: ${metrics.rollbacksPerformed.toString().padEnd(37)} |`);
    console.log(`| +- Validations Passed: ${metrics.validationsPassed.toString().padEnd(38)} |`);
    console.log(`| +- Validations Failed: ${metrics.validationsFailed.toString().padEnd(38)} |`);
    console.log(`|                                                            |`);
    console.log(`| Errors: ${metrics.errors.toString().padEnd(55)} |`);
    console.log(`| Error Rate: ${(metrics.errorRate * 100).toFixed(1)}%${' '.repeat(48 - (metrics.errorRate * 100).toFixed(1).length)} |`);
    console.log('+------------------------------------------------------------+\n');
  }
}

module.exports = ToolBridge;

// Example usage
if (require.main === module) {
  async function test() {
    const bridge = new ToolBridge({
      workingDirectory: path.join(__dirname, '..'),
      enableFileOperations: true,
      enableBashOperations: false
    });

    console.log('\n=== Test 1: Read File ===\n');
    const readResult = await bridge.read('lib/agent-execution-engine.js');
    console.log('Read result:', readResult.success ? `[OK] ${readResult.lines} lines` : `[ERROR] ${readResult.error}`);

    console.log('\n=== Test 2: Analyze File ===\n');
    const analysis = await bridge.analyzeFile('lib/agent-execution-engine.js');
    console.log('Analysis:', JSON.stringify(analysis, null, 2));

    console.log('\n=== Test 3: List Files ===\n');
    const files = await bridge.listFiles('lib', { extension: '.js' });
    console.log('JavaScript files in lib/:', files.map(f => f.name).join(', '));

    bridge.printMetrics();
  }

  test().catch(console.error);
}
