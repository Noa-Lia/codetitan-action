/**
 * Refactoring God Agent
 *
 * Tier 2 Domain God specializing in code quality, refactoring opportunities, and technical debt detection.
 * Wraps domain-analyzers.js refactoring heuristics with enhanced reporting and auto-fix capabilities.
 */

const path = require('path');
const { analyzeDomain } = require('../domain-analyzers');
const ToolBridge = require('../tool-bridge');

class RefactoringGodAgent {
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
      'dead_code_detection',
      'duplication_detection',
      'complexity_analysis',
      'extract_method',
      'inline_variable',
      'code_quality_analysis'
    ];

    this.metrics = {
      filesAnalyzed: 0,
      codeSmells: 0,
      refactoringsRecommended: 0,
      fixesApplied: 0
    };
  }

  /**
   * Main analysis method - scans a file for refactoring opportunities
   * @param {string} filePath - Path to file (relative or absolute)
   * @returns {Promise<object>} Refactoring analysis results
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

      // Run refactoring analysis using existing domain analyzer
      const analysis = analyzeDomain('refactoring-god', absolutePath, content, this.options.projectRoot);

      // Update metrics
      this.metrics.filesAnalyzed++;
      this.metrics.codeSmells += analysis.issues.length;
      this.metrics.refactoringsRecommended += analysis.issues.filter(i => i.severity === 'HIGH' || i.severity === 'MEDIUM').length;

      // Categorize issues by type
      const categorized = this.categorizeIssues(analysis.issues);

      return {
        success: true,
        agent: 'refactoring-god',
        file: filePath,
        absolutePath: absolutePath,
        summary: {
          totalIssues: analysis.issues.length,
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
        agent: 'refactoring-god',
        file: filePath,
        error: error.message
      };
    }
  }

  /**
   * Scan entire directory for refactoring opportunities
   * @param {string} directoryPath - Directory to scan
   * @param {object} options - Scan options
   * @returns {Promise<object>} Aggregated refactoring report
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
      agent: 'refactoring-god',
      directory: directoryPath,
      filesScanned: files.length,
      filesWithIssues: results.length,
      totalIssues: results.reduce((sum, r) => sum + r.issues.length, 0),
      summary: {
        high: results.reduce((sum, r) => sum + r.summary.high, 0),
        medium: results.reduce((sum, r) => sum + r.summary.medium, 0),
        low: results.reduce((sum, r) => sum + r.summary.low, 0)
      },
      results: results,
      metrics: { ...this.metrics }
    };
  }

  /**
   * Categorize issues by refactoring type
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
   * Get top N most critical code smells across all scanned files
   */
  getTopIssues(n = 10) {
    // This would be enhanced to track issues across scans
    return {
      message: 'Top issues tracking not yet implemented in this version'
    };
  }

  /**
   * Generate refactoring report
   */
  generateReport(scanResults) {
    const { summary, filesScanned, filesWithIssues, totalIssues } = scanResults;

    const report = {
      title: 'Refactoring God Analysis Report',
      timestamp: new Date().toISOString(),
      agent: 'refactoring-god',
      tier: 2,

      overview: {
        filesScanned,
        filesWithIssues,
        totalCodeSmells: totalIssues,
        highPriorityIssues: summary.high,
        mediumPriorityIssues: summary.medium,
        lowPriorityIssues: summary.low,
        codeQualityGrade: this.calculateCodeQualityGrade(summary)
      },

      breakdown: summary,

      recommendations: this.generateRecommendations(summary),

      metrics: { ...this.metrics }
    };

    return report;
  }

  /**
   * Calculate code quality grade (A-F) based on code smells found
   */
  calculateCodeQualityGrade(summary) {
    // Fewer code smells = higher grade
    const totalSmells = summary.high + summary.medium + summary.low;

    if (totalSmells === 0) return 'A+';

    const score = 100 - (
      summary.high * 15 +
      summary.medium * 7 +
      summary.low * 2
    );

    if (score >= 95) return 'A';
    if (score >= 85) return 'B';
    if (score >= 75) return 'C';
    if (score >= 65) return 'D';
    return 'F';
  }

  /**
   * Generate refactoring recommendations
   */
  generateRecommendations(summary) {
    const recommendations = [];

    if (summary.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Address ${summary.high} high-priority code quality issues`,
        impact: 'Significant improvement in code maintainability and readability',
        effort: 'Days to week'
      });
    }

    if (summary.medium > 5) {
      recommendations.push({
        priority: 'MEDIUM',
        action: `Refactor ${summary.medium} medium-priority code smells`,
        impact: 'Improved code organization and reduced technical debt',
        effort: 'Week to weeks'
      });
    }

    if (summary.low > 10) {
      recommendations.push({
        priority: 'LOW',
        action: `Clean up ${summary.low} minor code quality issues`,
        impact: 'Enhanced code consistency and developer experience',
        effort: 'Quick wins for code quality improvements'
      });
    }

    if (recommendations.length === 0) {
      recommendations.push({
        priority: 'INFO',
        action: 'Excellent! No significant code quality issues found',
        impact: 'Code meets high quality standards',
        effort: 'Minimal - maintain current practices'
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
      codeSmells: 0,
      refactoringsRecommended: 0,
      fixesApplied: 0
    };
  }
}

module.exports = RefactoringGodAgent;
