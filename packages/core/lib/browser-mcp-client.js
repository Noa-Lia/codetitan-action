/**
 * Browser MCP Client for CodeTitan
 * Spawns and communicates with the Browser MCP server
 */

const { spawn } = require('child_process');
const path = require('path');
const { EventEmitter } = require('events');

class BrowserMCPClient extends EventEmitter {
  constructor(options = {}) {
    super();
    this.serverPath = options.serverPath || path.join(__dirname, '../../mcp-browser/build/index.js');
    this.verbose = options.verbose !== false;
    this.process = null;
    this.ready = false;
    this.messageId = 0;
    this.pendingRequests = new Map();
    this.requestTimeouts = new Map();
    this.startupTimeout = null;
    this.stopTimeout = null;
    this.buffer = '';
  }

  /**
   * Start the MCP server process
   */
  async start() {
    if (this.process) {
      if (this.verbose) console.log('[Browser MCP] Already running');
      return;
    }

    if (this.verbose) {
      console.log('[Browser MCP] Starting server...');
      console.log(`[Browser MCP] Server path: ${this.serverPath}`);
    }

    return new Promise((resolve, reject) => {
      try {
        const clearStartupTimeout = () => {
          if (this.startupTimeout) {
            clearTimeout(this.startupTimeout);
            this.startupTimeout = null;
          }
        };

        this.process = spawn('node', [this.serverPath], {
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...process.env }
        });

        // Handle server stdout (JSON-RPC responses)
        this.process.stdout.on('data', (data) => {
          this.buffer += data.toString();
          this.processBuffer();
        });

        // Handle server stderr (logs)
        this.process.stderr.on('data', (data) => {
          const message = data.toString().trim();
          if (this.verbose && message) {
            console.log(`[Browser MCP] ${message}`);
          }

          // Check if server is ready
          if (message.includes('Browser MCP Server running')) {
            clearStartupTimeout();
            this.ready = true;
            resolve();
          }
        });

        // Handle process exit
        this.process.on('exit', (code) => {
          clearStartupTimeout();
          if (this.stopTimeout) {
            clearTimeout(this.stopTimeout);
            this.stopTimeout = null;
          }
          if (this.verbose) {
            console.log(`[Browser MCP] Server exited with code ${code}`);
          }
          this.process = null;
          this.ready = false;
        });

        // Handle errors
        this.process.on('error', (error) => {
          clearStartupTimeout();
          console.error('[Browser MCP] Process error:', error.message);
          reject(error);
        });

        // Set timeout for startup
        this.startupTimeout = setTimeout(() => {
          this.startupTimeout = null;
          if (!this.ready) {
            console.warn('[Browser MCP] Server startup timeout - proceeding anyway');
            resolve();
          }
        }, 5000);
        this.startupTimeout.unref?.();

      } catch (error) {
        console.error('[Browser MCP] Failed to start:', error.message);
        reject(error);
      }
    });
  }

  /**
   * Process buffered JSON-RPC messages
   */
  processBuffer() {
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || ''; // Keep incomplete line in buffer

    for (const line of lines) {
      if (!line.trim()) continue;

      try {
        const message = JSON.parse(line);

        if (message.id && this.pendingRequests.has(message.id)) {
          const { resolve, reject } = this.pendingRequests.get(message.id);
          this.pendingRequests.delete(message.id);
          const timeoutHandle = this.requestTimeouts.get(message.id);
          if (timeoutHandle) {
            clearTimeout(timeoutHandle);
            this.requestTimeouts.delete(message.id);
          }

          if (message.error) {
            reject(new Error(message.error.message || 'MCP Error'));
          } else {
            resolve(message.result);
          }
        }
      } catch (error) {
        if (this.verbose) {
          console.error('[Browser MCP] Failed to parse message:', line);
        }
      }
    }
  }

  /**
   * Send JSON-RPC request to server
   */
  async sendRequest(method, params = {}) {
    if (!this.process) {
      throw new Error('Browser MCP server is not running. Call start() first.');
    }

    const id = ++this.messageId;
    const request = {
      jsonrpc: '2.0',
      id,
      method,
      params
    };

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });

      this.process.stdin.write(JSON.stringify(request) + '\n');

      // Set timeout
      const timeoutHandle = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          this.requestTimeouts.delete(id);
          reject(new Error(`Request timeout: ${method}`));
        }
      }, 60000); // 60 second timeout for browser operations
      timeoutHandle.unref?.();
      this.requestTimeouts.set(id, timeoutHandle);
    });
  }

  /**
   * List available tools
   */
  async listTools() {
    const result = await this.sendRequest('tools/list');
    return result.tools || [];
  }

  /**
   * Call a tool
   */
  async callTool(name, args) {
    const result = await this.sendRequest('tools/call', {
      name,
      arguments: args
    });
    return result;
  }

  /**
   * Browse a webpage
   */
  async browse(url, options = {}) {
    const args = {
      url,
      action: options.action || 'read',
      selector: options.selector,
      text: options.text
    };

    const result = await this.callTool('browse', args);

    if (result.isError) {
      throw new Error(result.content[0]?.text || 'Browse failed');
    }

    return result.content;
  }

  /**
   * Read webpage content
   */
  async read(url) {
    return this.browse(url, { action: 'read' });
  }

  /**
   * Take screenshot
   */
  async screenshot(url) {
    return this.browse(url, { action: 'screenshot' });
  }

  /**
   * Click element
   */
  async click(url, selector) {
    return this.browse(url, { action: 'click', selector });
  }

  /**
   * Type text
   */
  async type(url, selector, text) {
    return this.browse(url, { action: 'type', selector, text });
  }

  /**
   * Stop the MCP server
   */
  async stop() {
    if (!this.process) {
      return;
    }

    if (this.verbose) {
      console.log('[Browser MCP] Stopping server...');
    }

    return new Promise((resolve) => {
      const process = this.process;

      if (this.startupTimeout) {
        clearTimeout(this.startupTimeout);
        this.startupTimeout = null;
      }

      for (const timeoutHandle of this.requestTimeouts.values()) {
        clearTimeout(timeoutHandle);
      }
      this.requestTimeouts.clear();
      this.pendingRequests.clear();

      process.once('exit', () => {
        if (this.stopTimeout) {
          clearTimeout(this.stopTimeout);
          this.stopTimeout = null;
        }
        this.process = null;
        this.ready = false;
        resolve();
      });

      process.kill('SIGTERM');

      // Force kill after 5 seconds
      this.stopTimeout = setTimeout(() => {
        if (this.process === process) {
          process.kill('SIGKILL');
        }
      }, 5000);
      this.stopTimeout.unref?.();
    });
  }
}

module.exports = BrowserMCPClient;
