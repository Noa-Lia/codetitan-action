/**
 * Progress Tracker
 *
 * Real-time progress tracking with WebSocket integration.
 * Provides live updates to dashboard and CLI.
 *
 * Features:
 * - Real-time progress events
 * - ETA calculation
 * - Throughput monitoring
 * - Dashboard WebSocket integration
 * - CLI progress bar integration
 */

const EventEmitter = require('events');

class ProgressTracker extends EventEmitter {
  constructor(options = {}) {
    super();

    this.totalFiles = 0;
    this.processedFiles = 0;
    this.totalFindings = 0;
    this.startTime = null;
    this.currentFile = null;

    // Performance metrics
    this.metrics = {
      filesPerSecond: 0,
      findingsPerSecond: 0,
      avgTimePerFile: 0,
      estimatedCompletion: null
    };

    // Category breakdown
    this.findingsByCategory = {};
    this.findingsBySeverity = {
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };

    // WebSocket dashboard connection (optional)
    this.dashboard = options.dashboard || null;

    // Update interval (ms)
    this.updateInterval = options.updateInterval || 100;
    this.lastUpdate = 0;
  }

  /**
   * Start tracking
   */
  start(totalFiles) {
    this.totalFiles = totalFiles;
    this.processedFiles = 0;
    this.totalFindings = 0;
    this.startTime = Date.now();
    this.currentFile = null;

    this.emit('start', {
      totalFiles: this.totalFiles,
      startTime: this.startTime
    });

    // Broadcast to dashboard
    this.broadcastToDashboard('analysis_started', {
      totalFiles: this.totalFiles,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Update progress for a file
   */
  updateFile(filePath, findings = []) {
    this.processedFiles++;
    this.currentFile = filePath;
    this.totalFindings += findings.length;

    // Update category breakdown
    findings.forEach(finding => {
      this.findingsByCategory[finding.category] =
        (this.findingsByCategory[finding.category] || 0) + 1;

      if (finding.severity) {
        this.findingsBySeverity[finding.severity] =
          (this.findingsBySeverity[finding.severity] || 0) + 1;
      }
    });

    // Calculate metrics
    this.calculateMetrics();

    // Throttle updates to avoid flooding
    const now = Date.now();
    if (now - this.lastUpdate >= this.updateInterval) {
      this.emitProgress();
      this.lastUpdate = now;
    }

    // Broadcast significant findings to dashboard
    findings.forEach(finding => {
      if (finding.severity === 'HIGH') {
        this.broadcastToDashboard('finding_detected', {
          category: finding.category,
          severity: finding.severity,
          file: filePath,
          line: finding.line,
          message: finding.message
        });
      }
    });
  }

  /**
   * Calculate performance metrics
   */
  calculateMetrics() {
    const elapsed = (Date.now() - this.startTime) / 1000; // seconds

    if (elapsed > 0) {
      this.metrics.filesPerSecond = (this.processedFiles / elapsed).toFixed(2);
      this.metrics.findingsPerSecond = (this.totalFindings / elapsed).toFixed(2);
      this.metrics.avgTimePerFile = Math.round((elapsed / this.processedFiles) * 1000); // ms
    }

    // Calculate ETA
    if (this.processedFiles > 0) {
      const avgTimePerFile = elapsed / this.processedFiles;
      const remainingFiles = this.totalFiles - this.processedFiles;
      const estimatedSeconds = remainingFiles * avgTimePerFile;

      this.metrics.estimatedCompletion = new Date(Date.now() + estimatedSeconds * 1000);
    }
  }

  /**
   * Emit progress event
   */
  emitProgress() {
    const progress = {
      filesProcessed: this.processedFiles,
      totalFiles: this.totalFiles,
      percentage: Math.round((this.processedFiles / this.totalFiles) * 100),
      currentFile: this.currentFile,
      totalFindings: this.totalFindings,
      findingsByCategory: this.findingsByCategory,
      findingsBySeverity: this.findingsBySeverity,
      metrics: this.metrics
    };

    this.emit('progress', progress);

    // Broadcast to dashboard
    this.broadcastToDashboard('analysis_progress', {
      filesAnalyzed: this.processedFiles,
      totalFiles: this.totalFiles,
      percentage: progress.percentage,
      findingsCount: this.totalFindings,
      currentFile: this.currentFile
    });
  }

  /**
   * Complete tracking
   */
  complete(results) {
    const duration = Date.now() - this.startTime;

    const summary = {
      filesProcessed: this.processedFiles,
      totalFindings: this.totalFindings,
      findingsByCategory: this.findingsByCategory,
      findingsBySeverity: this.findingsBySeverity,
      duration,
      metrics: this.metrics,
      ...results
    };

    this.emit('complete', summary);

    // Broadcast to dashboard
    this.broadcastToDashboard('analysis_completed', {
      filesAnalyzed: this.processedFiles,
      findingsCount: this.totalFindings,
      duration,
      timestamp: new Date().toISOString()
    });

    return summary;
  }

  /**
   * Report an error
   */
  error(filePath, error) {
    this.emit('error', {
      file: filePath,
      error: error.message || error
    });

    // Broadcast to dashboard
    this.broadcastToDashboard('analysis_error', {
      file: filePath,
      error: error.message || error,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Broadcast event to dashboard
   */
  broadcastToDashboard(event, data) {
    if (this.dashboard && typeof this.dashboard.broadcast === 'function') {
      this.dashboard.broadcast(event, data);
    }
  }

  /**
   * Get current progress
   */
  getProgress() {
    return {
      filesProcessed: this.processedFiles,
      totalFiles: this.totalFiles,
      percentage: Math.round((this.processedFiles / this.totalFiles) * 100),
      currentFile: this.currentFile,
      totalFindings: this.totalFindings,
      findingsByCategory: this.findingsByCategory,
      findingsBySeverity: this.findingsBySeverity,
      metrics: this.metrics,
      elapsed: Date.now() - this.startTime
    };
  }

  /**
   * Format time remaining as human-readable string
   */
  formatTimeRemaining() {
    if (!this.metrics.estimatedCompletion) {
      return 'Calculating...';
    }

    const remaining = this.metrics.estimatedCompletion.getTime() - Date.now();
    const seconds = Math.round(remaining / 1000);

    if (seconds < 60) {
      return `${seconds}s`;
    } else if (seconds < 3600) {
      const minutes = Math.floor(seconds / 60);
      const secs = seconds % 60;
      return `${minutes}m ${secs}s`;
    } else {
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      return `${hours}h ${minutes}m`;
    }
  }

  /**
   * Get progress bar string for CLI
   */
  getProgressBar(width = 40) {
    const percentage = this.processedFiles / this.totalFiles;
    const filled = Math.round(width * percentage);
    const empty = width - filled;

    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    const percent = Math.round(percentage * 100);

    return `${bar} ${percent}%`;
  }

  /**
   * Reset tracker
   */
  reset() {
    this.totalFiles = 0;
    this.processedFiles = 0;
    this.totalFindings = 0;
    this.startTime = null;
    this.currentFile = null;
    this.findingsByCategory = {};
    this.findingsBySeverity = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    this.metrics = {
      filesPerSecond: 0,
      findingsPerSecond: 0,
      avgTimePerFile: 0,
      estimatedCompletion: null
    };
  }
}

module.exports = ProgressTracker;
