/**
 * Performance God Agent
 *
 * Tier 2 Domain God specializing in performance optimization and bottleneck detection.
 * Wraps domain-analyzers.js performance heuristics with enhanced reporting and auto-fix capabilities.
 */

const path = require('path');
const { analyzeDomain } = require('../domain-analyzers');
const ToolBridge = require('../tool-bridge');

class PerformanceGodAgent {
  constructor(options = {}) {
    this.options = {
      projectRoot: options.projectRoot || process.cwd(),
      enableAutoFix: options.enableAutoFix || false,
      ...options
    };

    this.toolBridge = new ToolBridge({
      workingDirectory: this.options.projectRoot,
      enableFileOperations: true,
      enableBackups: true
    });

    this.capabilities = [
      'bottleneck_detection',
      'n_plus_one_detection',
      'sync_io_detection',
      'memory_leak_detection',
      'optimization'
    ];

    this.metrics = {
      filesAnalyzed: 0,
      bottlenecksFound: 0,
      criticalIssues: 0,
      optimizationsRecommended: 0
    };
  }

  /**
   * Main analysis method - scans a file for performance issues
   * @param {string} filePath - Path to file (relative or absolute)
   * @returns {Promise<object>} Performance analysis results
   */
  async analyzeFile(filePath) {
    const absolutePath = path.isAbsolute(filePath)
      ? filePath
      : path.join(this.options.projectRoot, filePath);

    try {
      // Read file content
      const readResult = await this.toolBridge.read(path.relative(this.options.projectRoot, absolutePath));

      if (!readResult.success) {
        return {
          success: false,
          file: filePath,
          error: readResult.error
        };
      }

      const content = readResult.content;

      // Run performance analysis using existing domain analyzer
      const analysis = analyzeDomain('performance-god', absolutePath, content, this.options.projectRoot);

      // Update metrics
      this.metrics.filesAnalyzed++;
      this.metrics.bottlenecksFound += analysis.issues.length;
      this.metrics.criticalIssues += analysis.issues.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').length;
      this.metrics.optimizationsRecommended += analysis.issues.length;

      // Categorize issues by type
      const categorized = this.categorizeIssues(analysis.issues);

      return {
        success: true,
        agent: 'performance-god',
        file: filePath,
        absolutePath: absolutePath,
        summary: {
          totalIssues: analysis.issues.length,
          critical: analysis.issues.filter(i => i.severity === 'CRITICAL').length,
          high: analysis.issues.filter(i => i.severity === 'HIGH').length,
          medium: analysis.issues.filter(i => i.severity === 'MEDIUM').length,
          low: analysis.issues.filter(i => i.severity === 'LOW').length
        },
        issues: analysis.issues,
        categorized: categorized,
        metadata: analysis.metadata,
        linesAnalyzed: analysis.linesAnalyzed,
        executionTime: analysis.executionTime
      };

    } catch (error) {
      return {
        success: false,
        agent: 'performance-god',
        file: filePath,
        error: error.message
      };
    }
  }

  /**
   * Scan entire directory for performance issues
   * @param {string} directoryPath - Directory to scan
   * @param {object} options - Scan options
   * @returns {Promise<object>} Aggregated performance report
   */
  async scanDirectory(directoryPath, options = {}) {
    const {
      maxFiles = 100,
      filePattern = /\.(js|ts|jsx|tsx|py|php|java|rb|go)$/
    } = options;

    const fs = require('fs').promises;
    const files = [];

    // Recursive file discovery
    async function walkDir(dir) {
      if (files.length >= maxFiles) return;

      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (files.length >= maxFiles) break;

        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          // Skip node_modules, .git, etc
          if (!entry.name.startsWith('.') && entry.name !== 'node_modules') {
            await walkDir(fullPath);
          }
        } else if (entry.isFile() && filePattern.test(entry.name)) {
          files.push(fullPath);
        }
      }
    }

    await walkDir(directoryPath);

    // Analyze each file
    const results = [];
    for (const file of files) {
      const result = await this.analyzeFile(file);
      if (result.success && result.issues.length > 0) {
        results.push(result);
      }
    }

    // Aggregate results
    return {
      success: true,
      agent: 'performance-god',
      directory: directoryPath,
      filesScanned: files.length,
      filesWithIssues: results.length,
      totalIssues: results.reduce((sum, r) => sum + r.issues.length, 0),
      summary: {
        critical: results.reduce((sum, r) => sum + r.summary.critical, 0),
        high: results.reduce((sum, r) => sum + r.summary.high, 0),
        medium: results.reduce((sum, r) => sum + r.summary.medium, 0),
        low: results.reduce((sum, r) => sum + r.summary.low, 0)
      },
      results: results,
      metrics: { ...this.metrics }
    };
  }

  /**
   * Categorize issues by performance type
   */
  categorizeIssues(issues) {
    const categories = {};

    issues.forEach(issue => {
      const category = issue.category || 'UNKNOWN';
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(issue);
    });

    return categories;
  }

  /**
   * Get top N most critical issues across all scanned files
   */
  getTopIssues(n = 10) {
    // This would be enhanced to track issues across scans
    return {
      message: 'Top issues tracking not yet implemented in this version'
    };
  }

  /**
   * Generate performance report
   */
  generateReport(scanResults) {
    const { summary, filesScanned, filesWithIssues, totalIssues } = scanResults;

    const report = {
      title: 'Performance God Analysis Report',
      timestamp: new Date().toISOString(),
      agent: 'performance-god',
      tier: 2,

      overview: {
        filesScanned,
        filesWithIssues,
        totalBottlenecks: totalIssues,
        criticalBottlenecks: summary.critical,
        highBottlenecks: summary.high,
        performanceGrade: this.calculatePerformanceGrade(summary)
      },

      breakdown: summary,

      recommendations: this.generateRecommendations(summary),

      metrics: { ...this.metrics }
    };

    return report;
  }

  /**
   * Calculate performance grade (A-F) based on bottlenecks found
   * Lower issues = higher grade (opposite of security)
   */
  calculatePerformanceGrade(summary) {
    const score = 100 - (
      summary.critical * 15 +
      summary.high * 8 +
      summary.medium * 4 +
      summary.low * 1
    );

    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate performance recommendations
   */
  generateRecommendations(summary) {
    const recommendations = [];

    if (summary.critical > 0) {
      recommendations.push({
        priority: 'URGENT',
        action: `Fix ${summary.critical} CRITICAL performance bottlenecks immediately`,
        impact: 'Significant latency reduction, improved throughput, better user experience',
        effort: 'Hours to days'
      });
    }

    if (summary.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Address ${summary.high} HIGH impact performance issues`,
        impact: 'Notable speed improvements, reduced resource consumption',
        effort: 'Days to week'
      });
    }

    if (summary.medium > 5) {
      recommendations.push({
        priority: 'MEDIUM',
        action: `Optimize ${summary.medium} MEDIUM performance issues`,
        impact: 'Incremental improvements, better scalability',
        effort: 'Week to weeks'
      });
    }

    if (summary.low > 10) {
      recommendations.push({
        priority: 'LOW',
        action: `Clean up ${summary.low} minor performance issues`,
        impact: 'Code quality, marginal performance gains',
        effort: 'Quick wins for optimization'
      });
    }

    return recommendations;
  }

  /**
   * Get agent metrics
   */
  getMetrics() {
    return { ...this.metrics };
  }

  /**
   * Reset metrics
   */
  resetMetrics() {
    this.metrics = {
      filesAnalyzed: 0,
      bottlenecksFound: 0,
      criticalIssues: 0,
      optimizationsRecommended: 0
    };
  }
}

module.exports = PerformanceGodAgent;
