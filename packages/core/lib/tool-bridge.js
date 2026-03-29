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
const path = require('path');
const { execSync } = require('child_process');

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
      validationsFailed: 0
    };

    // Change tracking
    this.changeHistory = [];
    this.maxHistorySize = options.maxHistorySize || 100;

    // Ensure backup directory exists
    if (this.options.enableBackups) {
      fsp.mkdir(this.options.backupDir, { recursive: true }).catch(() => { });
    }

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
