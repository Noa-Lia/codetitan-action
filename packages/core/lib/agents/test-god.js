/**
 * Test God Agent
 *
 * Tier 2 Domain God specializing in test coverage detection and test quality analysis.
 * Wraps domain-analyzers.js testing heuristics with enhanced reporting and test generation capabilities.
 */

const path = require('path');
const { analyzeDomain } = require('../domain-analyzers');
const ToolBridge = require('../tool-bridge');

class TestGodAgent {
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
      'missing_tests_detection',
      'coverage_analysis',
      'test_generation',
      'mutation_testing',
      'focused_test_detection'
    ];

    this.metrics = {
      filesAnalyzed: 0,
      missingTests: 0,
      focusedTests: 0,
      testCoverageGrade: null
    };
  }

  /**
   * Main analysis method - scans a file for testing gaps and issues
   * @param {string} filePath - Path to file (relative or absolute)
   * @returns {Promise<object>} Testing analysis results
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

      // Run testing analysis using existing domain analyzer
      const analysis = analyzeDomain('test-god', absolutePath, content, this.options.projectRoot);

      // Update metrics
      this.metrics.filesAnalyzed++;
      this.metrics.missingTests += analysis.issues.filter(i => i.category === 'MISSING_TESTS').length;
      this.metrics.focusedTests += analysis.issues.filter(i => i.category === 'FOCUSED_TEST').length;

      // Categorize issues by type
      const categorized = this.categorizeIssues(analysis.issues);

      return {
        success: true,
        agent: 'test-god',
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
        agent: 'test-god',
        file: filePath,
        error: error.message
      };
    }
  }

  /**
   * Scan entire directory for testing issues
   * @param {string} directoryPath - Directory to scan
   * @param {object} options - Scan options
   * @returns {Promise<object>} Aggregated testing report
   */
  async scanDirectory(directoryPath, options = {}) {
    const {
      maxFiles = 100,
      filePattern = /\.(js|ts|jsx|tsx|py|php|java|rb|go)$/,
      excludeTests = false
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
          // Optionally exclude test files themselves
          if (excludeTests && /(\.test\.|\.spec\.|__tests__)/.test(entry.name)) {
            continue;
          }
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
      agent: 'test-god',
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
   * Categorize issues by testing category
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
   * Generate testing report
   */
  generateReport(scanResults) {
    const { summary, filesScanned, filesWithIssues, totalIssues } = scanResults;

    const report = {
      title: 'Test God Analysis Report',
      timestamp: new Date().toISOString(),
      agent: 'test-god',
      tier: 2,

      overview: {
        filesScanned,
        filesWithIssues,
        totalTestingIssues: totalIssues,
        criticalIssues: summary.critical,
        highIssues: summary.high,
        testCoverageGrade: this.calculateTestGrade(summary, filesScanned, filesWithIssues)
      },

      breakdown: summary,

      recommendations: this.generateRecommendations(summary, filesScanned, filesWithIssues),

      metrics: { ...this.metrics }
    };

    return report;
  }

  /**
   * Calculate test coverage grade (A-F) based on missing tests and issues
   * Higher coverage (fewer missing tests) = better grade
   */
  calculateTestGrade(summary, filesScanned, filesWithIssues) {
    // Calculate test coverage as inverse of issues-to-files ratio
    const missingTestRatio = filesWithIssues / Math.max(filesScanned, 1);

    // Score: Start at 100, deduct points for issues
    const score = 100 - (
      summary.critical * 25 +
      summary.high * 15 +
      summary.medium * 8 +
      summary.low * 2
    ) - (missingTestRatio * 30);

    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate testing recommendations
   */
  generateRecommendations(summary, filesScanned, filesWithIssues) {
    const recommendations = [];

    if (summary.critical > 0) {
      recommendations.push({
        priority: 'URGENT',
        action: `Address ${summary.critical} CRITICAL testing issues immediately`,
        impact: 'Tests may be failing or skipping critical test coverage',
        effort: 'Hours to days'
      });
    }

    if (summary.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Fix ${summary.high} HIGH severity testing issues`,
        impact: 'Focused tests or missing companion test files',
        effort: 'Days to week'
      });
    }

    const missingTestRatio = filesWithIssues / Math.max(filesScanned, 1);
    if (missingTestRatio > 0.5) {
      recommendations.push({
        priority: 'HIGH',
        action: `Improve test coverage: ${Math.round((1 - missingTestRatio) * 100)}% of files lack tests`,
        impact: 'Insufficient test coverage increases bug risk',
        effort: 'Weeks to implement comprehensive test suite'
      });
    } else if (missingTestRatio > 0.3) {
      recommendations.push({
        priority: 'MEDIUM',
        action: `Enhance test coverage: ${filesWithIssues} files need test attention`,
        impact: 'Moderate test coverage gaps',
        effort: 'Week to weeks'
      });
    }

    if (summary.medium > 5) {
      recommendations.push({
        priority: 'MEDIUM',
        action: `Remediate ${summary.medium} MEDIUM severity testing issues`,
        impact: 'Improves test quality and reduces technical debt',
        effort: 'Week to weeks'
      });
    }

    if (summary.low > 10) {
      recommendations.push({
        priority: 'LOW',
        action: `Clean up ${summary.low} minor testing issues`,
        impact: 'Testing hygiene and best practices',
        effort: 'Quick wins for test quality'
      });
    }

    if (filesScanned > 0 && filesWithIssues === 0) {
      recommendations.push({
        priority: 'INFO',
        action: 'Excellent test coverage detected!',
        impact: 'Strong testing practices in place',
        effort: 'Maintain current standards'
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
      missingTests: 0,
      focusedTests: 0,
      testCoverageGrade: null
    };
  }
}

module.exports = TestGodAgent;
