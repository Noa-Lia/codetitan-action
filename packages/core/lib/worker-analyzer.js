/**
 * Worker Analyzer
 *
 * Worker thread that performs actual file analysis.
 * Runs in parallel with other workers for maximum performance.
 *
 * Enhanced with comprehensive error handling and graceful shutdown.
 */

const { parentPort, workerData } = require('worker_threads');
const fs = require('fs').promises;
const path = require('path');

// Import domain analyzer
const { analyzeDomain } = require('./domain-analyzers');

class WorkerAnalyzer {
  constructor() {
    // Verify parentPort is available
    if (!parentPort) {
      console.error('[Worker] ERROR: parentPort is not available');
      process.exit(1);
    }

    // Worker metadata
    this.workerId = workerData?.workerId || process.pid;
    this.isShuttingDown = false;
    this.activeAnalysis = null;

    // Domain analyzers are functions, not classes
    this.domains = ['security-god', 'performance-god', 'test-god', 'refactoring-god', 'documentation-god'];

    // Setup error handlers BEFORE any other initialization
    this.setupErrorHandlers();

    // Listen for messages from parent
    parentPort.on('message', (msg) => this.handleMessage(msg));

    // Handle parent disconnect
    parentPort.on('close', () => {
      this.log('Parent port closed, shutting down gracefully');
      this.gracefulShutdown();
    });

    // Signal ready
    this.sendMessage({ type: 'ready', workerId: this.workerId });
  }

  /**
   * Setup comprehensive error handlers
   */
  setupErrorHandlers() {
    // Catch uncaught exceptions
    process.on('uncaughtException', (error) => {
      this.logError('Uncaught Exception', error);
      this.sendMessage({
        type: 'fatal_error',
        workerId: this.workerId,
        error: {
          type: 'uncaughtException',
          message: error.message,
          stack: error.stack,
          activeAnalysis: this.activeAnalysis
        }
      });
      // Don't exit immediately - let parent decide
      const exitTimer = setTimeout(() => process.exit(1), 1000);
      exitTimer.unref?.();
    });

    // Catch unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      this.logError('Unhandled Rejection', reason);
      this.sendMessage({
        type: 'fatal_error',
        workerId: this.workerId,
        error: {
          type: 'unhandledRejection',
          message: reason?.message || String(reason),
          stack: reason?.stack,
          activeAnalysis: this.activeAnalysis
        }
      });
    });

    // Catch warnings
    process.on('warning', (warning) => {
      this.log(`Warning: ${warning.name}: ${warning.message}`);
    });

    // Handle termination signals
    process.on('SIGTERM', () => {
      this.log('Received SIGTERM, shutting down gracefully');
      this.gracefulShutdown();
    });

    process.on('SIGINT', () => {
      this.log('Received SIGINT, shutting down gracefully');
      this.gracefulShutdown();
    });
  }

  /**
   * Safe message sending with error handling
   */
  sendMessage(message) {
    try {
      if (parentPort && !this.isShuttingDown) {
        parentPort.postMessage(message);
      }
    } catch (error) {
      this.logError('Failed to send message', error);
    }
  }

  /**
   * Log message with worker ID
   */
  log(message) {
    console.log(`[Worker ${this.workerId}] ${message}`);
  }

  /**
   * Log error with context
   */
  logError(context, error) {
    console.error(`[Worker ${this.workerId}] ERROR [${context}]:`, error?.message || error);
    if (error?.stack) {
      console.error(error.stack);
    }
  }

  /**
   * Graceful shutdown
   */
  gracefulShutdown() {
    if (this.isShuttingDown) {
      return;
    }

    this.log('Initiating graceful shutdown');

    // Send shutdown confirmation
    this.sendMessage({
      type: 'shutdown_complete',
      workerId: this.workerId
    });

    this.isShuttingDown = true;

    // Give time for message to send, then exit cleanly
    const shutdownTimer = setTimeout(() => {
      this.log('Shutdown complete');
      process.exit(0);
    }, 100);
    shutdownTimer.unref?.();
  }

  /**
   * Handle message from main thread
   */
  async handleMessage(message) {
    try {
      // Ignore messages during shutdown
      if (this.isShuttingDown) {
        return;
      }

      switch (message.type) {
        case 'analyze':
          await this.analyzeBatch(message.batch, message.options);
          break;

        case 'shutdown':
          this.gracefulShutdown();
          break;

        case 'ping':
          this.sendMessage({ type: 'pong', workerId: this.workerId });
          break;

        default:
          this.log(`Unknown message type: ${message.type}`);
      }
    } catch (error) {
      this.logError('Message handling', error);
      this.sendMessage({
        type: 'error',
        workerId: this.workerId,
        error: {
          message: error.message,
          stack: error.stack,
          messageType: message.type
        }
      });
    }
  }

  /**
   * Analyze a batch of files
   */
  async analyzeBatch(batch, options = {}) {
    if (!batch || !batch.files || !Array.isArray(batch.files)) {
      this.logError('Invalid batch', new Error('Batch must have a files array'));
      this.sendMessage({
        type: 'error',
        workerId: this.workerId,
        error: {
          message: 'Invalid batch format',
          batchId: batch?.id
        }
      });
      return;
    }

    const findings = [];
    let filesProcessed = 0;
    let filesFailed = 0;

    const batchStart = Date.now();
    this.activeAnalysis = {
      batchId: batch.id,
      totalFiles: batch.files.length,
      startTime: batchStart
    };

    const perFileTimeout = options.perFileTimeout || 30000;
    const maxBytesPerFile = options.maxBytesPerFile || 750 * 1024;

    try {
      for (const filePath of batch.files) {
        // Check if shutting down
        if (this.isShuttingDown) {
          this.log('Aborting batch analysis due to shutdown');
          break;
        }

        if (options.maxDurationMs && Date.now() - batchStart > options.maxDurationMs) {
          this.log(`Aborting batch ${batch.id} due to maxDurationMs`);
          break;
        }

        try {
          // Track current file for error reporting
          this.activeAnalysis.currentFile = filePath;

          // Size guardrail before reading
          try {
            const stat = await fs.stat(filePath);
            if (stat.size > maxBytesPerFile) {
              this.sendMessage({
                type: 'progress',
                workerId: this.workerId,
                file: filePath,
                findings: [],
                progress: {
                  current: filesProcessed,
                  total: batch.files.length
                },
                skipped: true,
                reason: 'file_too_large',
                size: stat.size,
                maxSize: maxBytesPerFile
              });
              filesProcessed++;
              continue;
            }
          } catch (statErr) {
            this.logError(`Stat failed for ${filePath}`, statErr);
          }

          // Analyze single file with timeout
          let timeoutHandle;
          const timeoutPromise = new Promise((_, reject) => {
            timeoutHandle = setTimeout(() => reject(new Error('File analysis timeout')), perFileTimeout);
            timeoutHandle.unref?.();
          });

          let fileFindings;
          try {
            fileFindings = await Promise.race([
              this.analyzeFile(filePath, options),
              timeoutPromise
            ]);
          } finally {
            if (timeoutHandle) {
              clearTimeout(timeoutHandle);
            }
          }

          findings.push(...fileFindings);
          filesProcessed++;

          // Report progress for each file
          this.sendMessage({
            type: 'progress',
            workerId: this.workerId,
            file: filePath,
            findings: fileFindings,
            progress: {
              current: filesProcessed,
              total: batch.files.length
            }
          });

        } catch (error) {
          filesFailed++;
          this.logError(`File analysis [${filePath}]`, error);

          // Report file error with more context
          this.sendMessage({
            type: 'error',
            workerId: this.workerId,
            file: filePath,
            error: {
              message: error.message,
              stack: error.stack,
              type: error.name
            }
          });
        }
      }

      // Clear active analysis
      this.activeAnalysis = null;

      // Send batch results back
      this.sendMessage({
        type: 'result',
        workerId: this.workerId,
        data: {
          batchId: batch.id,
          filesProcessed,
          filesFailed,
          findingsCount: findings.length,
          findings,
          duration: Date.now() - batchStart
        }
      });
      this.activeAnalysis = null;

    } catch (error) {
      this.logError('Batch analysis', error);
      this.activeAnalysis = null;

      this.sendMessage({
        type: 'error',
        workerId: this.workerId,
        error: {
          message: error.message,
          stack: error.stack,
          batch: batch.id,
          filesProcessed,
          filesFailed
        }
      });
    }
  }

  /**
   * Analyze a single file
   */
  async analyzeFile(filePath, options = {}) {
    // Read file content
    const content = await fs.readFile(filePath, 'utf8');

    // Get file extension
    const ext = path.extname(filePath);

    // Skip if not a code file
    if (!this.isCodeFile(ext)) {
      return [];
    }

    // Get project root (go up to find nearest package.json or git root)
    const projectRoot = options.projectRoot || process.cwd();

    // Run all domain analyzers using the domain-analyzers module
    const findings = [];

    for (const domain of this.domains) {
      try {
        const result = analyzeDomain(domain, filePath, content, projectRoot);

        // Transform issues to standard format with metadata
        if (result && result.issues) {
          const transformedIssues = result.issues.map(issue => ({
            category: issue.category || issue.id,  // Support both formats
            severity: issue.severity,
            message: issue.message,
            file: filePath,
            line: issue.line,
            column: issue.column,
            endLine: issue.endLine,
            endColumn: issue.endColumn,
            snippet: issue.snippet,
            context: issue.context || [],
            impact: issue.impact,
            timestamp: new Date().toISOString()
          }));

          findings.push(...transformedIssues);
        }
      } catch (error) {
        // Log error but continue with other domains
        console.error(`[Worker] Error analyzing ${domain} for ${filePath}:`, error.message);
      }
    }

    return findings;
  }

  /**
   * Check if file is a code file
   */
  isCodeFile(ext) {
    const codeExtensions = [
      '.js', '.jsx', '.ts', '.tsx',
      '.py', '.rb', '.java', '.go',
      '.rs', '.c', '.cpp', '.cs',
      '.php', '.swift', '.kt', '.scala'
    ];

    return codeExtensions.includes(ext.toLowerCase());
  }
}

// Initialize worker if running as main
if (require.main === module) {
  new WorkerAnalyzer();
}

module.exports = WorkerAnalyzer;
