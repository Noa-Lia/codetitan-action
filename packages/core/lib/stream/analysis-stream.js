/**
 * AnalysisStream - Real-time streaming of analysis progress and results
 *
 * Provides:
 * - File-by-file progress updates
 * - Live finding streaming
 * - Cost and token tracking in real-time
 * - Provider performance metrics
 *
 * Supports:
 * - Server-Sent Events (SSE) for HTTP streaming
 * - EventEmitter for in-process streaming
 * - WebSocket for bi-directional communication
 *
 * @module stream/analysis-stream
 */

const EventEmitter = require('events');

class AnalysisStream extends EventEmitter {
  constructor(config = {}) {
    super();

    this.config = {
      // Enable progress updates
      enableProgress: config.enableProgress !== false,

      // Progress update frequency (ms)
      progressInterval: config.progressInterval || 100,

      // Enable finding streaming (emit as found)
      streamFindings: config.streamFindings !== false,

      // Enable cost tracking
      trackCosts: config.trackCosts !== false,

      // Buffer size before flushing
      bufferSize: config.bufferSize || 10,

      ...config
    };

    // Stream state
    this.state = {
      active: false,
      startTime: null,
      endTime: null,
      filesProcessed: 0,
      totalFiles: 0,
      currentFile: null,
      findingsCount: 0,
      totalCost: 0,
      providers: {}
    };

    // Buffered events
    this.buffer = [];
  }

  /**
   * Start streaming session
   */
  start(options = {}) {
    this.state = {
      active: true,
      startTime: Date.now(),
      endTime: null,
      filesProcessed: 0,
      totalFiles: options.totalFiles || 0,
      currentFile: null,
      findingsCount: 0,
      totalCost: 0,
      providers: {}
    };

    this.emit('start', {
      timestamp: new Date().toISOString(),
      totalFiles: this.state.totalFiles
    });

    return this;
  }

  /**
   * Update progress
   */
  updateProgress(file, status = 'processing') {
    if (!this.state.active) return;

    this.state.currentFile = file;

    if (status === 'completed') {
      this.state.filesProcessed++;
    }

    const progress = {
      timestamp: new Date().toISOString(),
      file,
      status,
      filesProcessed: this.state.filesProcessed,
      totalFiles: this.state.totalFiles,
      percentage: this.state.totalFiles > 0
        ? Math.round((this.state.filesProcessed / this.state.totalFiles) * 100)
        : 0,
      elapsed: Date.now() - this.state.startTime,
      estimatedRemaining: this.estimateRemainingTime()
    };

    this.emit('progress', progress);

    return this;
  }

  /**
   * Stream a finding
   */
  streamFinding(finding, metadata = {}) {
    if (!this.state.active || !this.config.streamFindings) return;

    this.state.findingsCount++;

    // Update provider stats
    if (metadata.provider) {
      if (!this.state.providers[metadata.provider]) {
        this.state.providers[metadata.provider] = {
          count: 0,
          cost: 0,
          tokens: { input: 0, output: 0, cached: 0 }
        };
      }

      this.state.providers[metadata.provider].count++;

      if (metadata.costUSD) {
        this.state.providers[metadata.provider].cost += metadata.costUSD;
        this.state.totalCost += metadata.costUSD;
      }

      if (metadata.tokensUsed) {
        const tokens = this.state.providers[metadata.provider].tokens;
        tokens.input += metadata.tokensUsed.input || 0;
        tokens.output += metadata.tokensUsed.output || 0;
        tokens.cached += metadata.tokensUsed.cached || 0;
      }
    }

    const event = {
      timestamp: new Date().toISOString(),
      finding,
      metadata,
      totalFindings: this.state.findingsCount,
      totalCost: this.state.totalCost
    };

    this.emit('finding', event);

    // Buffer for batch processing
    this.buffer.push(event);
    if (this.buffer.length >= this.config.bufferSize) {
      this.flush();
    }

    return this;
  }

  /**
   * Stream multiple findings at once
   */
  streamFindings(findings, metadata = {}) {
    for (const finding of findings) {
      this.streamFinding(finding, metadata);
    }
    return this;
  }

  /**
   * Update cost tracking
   */
  updateCost(costUSD, provider, tokensUsed = {}) {
    if (!this.state.active || !this.config.trackCosts) return;

    this.state.totalCost += costUSD;

    if (provider) {
      if (!this.state.providers[provider]) {
        this.state.providers[provider] = {
          count: 0,
          cost: 0,
          tokens: { input: 0, output: 0, cached: 0 }
        };
      }

      this.state.providers[provider].cost += costUSD;
      const tokens = this.state.providers[provider].tokens;
      tokens.input += tokensUsed.input || 0;
      tokens.output += tokensUsed.output || 0;
      tokens.cached += tokensUsed.cached || 0;
    }

    this.emit('cost', {
      timestamp: new Date().toISOString(),
      costUSD,
      provider,
      tokensUsed,
      totalCost: this.state.totalCost
    });

    return this;
  }

  /**
   * Report an error
   */
  error(error, context = {}) {
    this.emit('error', {
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : error,
      stack: error instanceof Error ? error.stack : undefined,
      context
    });

    return this;
  }

  /**
   * End streaming session
   */
  end(summary = {}) {
    if (!this.state.active) return;

    this.state.active = false;
    this.state.endTime = Date.now();

    // Flush remaining buffer
    this.flush();

    const finalSummary = {
      timestamp: new Date().toISOString(),
      duration: this.state.endTime - this.state.startTime,
      filesProcessed: this.state.filesProcessed,
      totalFiles: this.state.totalFiles,
      findingsCount: this.state.findingsCount,
      totalCost: this.state.totalCost,
      providers: this.state.providers,
      ...summary
    };

    this.emit('end', finalSummary);

    return finalSummary;
  }

  /**
   * Flush buffered events
   */
  flush() {
    if (this.buffer.length === 0) return;

    this.emit('batch', {
      timestamp: new Date().toISOString(),
      findings: this.buffer,
      count: this.buffer.length
    });

    this.buffer = [];
  }

  /**
   * Estimate remaining time
   */
  estimateRemainingTime() {
    if (this.state.filesProcessed === 0 || this.state.totalFiles === 0) {
      return null;
    }

    const elapsed = Date.now() - this.state.startTime;
    const avgTimePerFile = elapsed / this.state.filesProcessed;
    const remaining = this.state.totalFiles - this.state.filesProcessed;

    return Math.round(avgTimePerFile * remaining);
  }

  /**
   * Get current state snapshot
   */
  getState() {
    return {
      ...this.state,
      elapsed: this.state.startTime ? Date.now() - this.state.startTime : 0,
      estimatedRemaining: this.estimateRemainingTime()
    };
  }

  /**
   * Create SSE (Server-Sent Events) response handler
   */
  toSSE(res) {
    // Set SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // Send events as SSE
    const sendEvent = (event, data) => {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // Wire up event handlers
    this.on('start', data => sendEvent('start', data));
    this.on('progress', data => sendEvent('progress', data));
    this.on('finding', data => sendEvent('finding', data));
    this.on('batch', data => sendEvent('batch', data));
    this.on('cost', data => sendEvent('cost', data));
    this.on('error', data => sendEvent('error', data));
    this.on('end', data => {
      sendEvent('end', data);
      res.end();
    });

    // Handle client disconnect
    res.on('close', () => {
      this.removeAllListeners();
    });

    return this;
  }

  /**
   * Create WebSocket handler
   */
  toWebSocket(ws) {
    // Send events via WebSocket
    const sendEvent = (event, data) => {
      ws.send(JSON.stringify({ event, data }));
    };

    // Wire up event handlers
    this.on('start', data => sendEvent('start', data));
    this.on('progress', data => sendEvent('progress', data));
    this.on('finding', data => sendEvent('finding', data));
    this.on('batch', data => sendEvent('batch', data));
    this.on('cost', data => sendEvent('cost', data));
    this.on('error', data => sendEvent('error', data));
    this.on('end', data => {
      sendEvent('end', data);
      ws.close();
    });

    // Handle disconnect
    ws.on('close', () => {
      this.removeAllListeners();
    });

    return this;
  }

  /**
   * Create console progress display
   */
  toConsole() {
    const progressChars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let frame = 0;

    this.on('start', data => {
      console.log(`\n🚀 Analysis started (${data.totalFiles} files)`);
    });

    this.on('progress', data => {
      const spinner = progressChars[frame % progressChars.length];
      frame++;

      process.stdout.write(`\r${spinner} ${data.percentage}% | ${data.filesProcessed}/${data.totalFiles} files | ${data.file}`);
    });

    this.on('finding', data => {
      console.log(`\n   ${data.finding.severity} | ${data.finding.category} | ${data.finding.file_path}:${data.finding.line_number}`);
    });

    this.on('cost', data => {
      if (data.costUSD > 0.01) {
        console.log(`\n   💰 Cost: $${this.state.totalCost.toFixed(4)} (${data.provider})`);
      }
    });

    this.on('error', data => {
      console.error(`\n   ❌ Error: ${data.error}`);
    });

    this.on('end', data => {
      console.log(`\n\n✅ Analysis complete!`);
      console.log(`   Files: ${data.filesProcessed}`);
      console.log(`   Findings: ${data.findingsCount}`);
      console.log(`   Duration: ${(data.duration / 1000).toFixed(1)}s`);
      console.log(`   Cost: $${data.totalCost.toFixed(4)}`);
      console.log(`\n   Providers:`);
      for (const [provider, stats] of Object.entries(data.providers)) {
        console.log(`     ${provider}: ${stats.count} findings, $${stats.cost.toFixed(4)}`);
      }
      console.log('');
    });

    return this;
  }
}

module.exports = AnalysisStream;
