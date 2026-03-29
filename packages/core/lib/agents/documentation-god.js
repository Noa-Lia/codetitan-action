/**
 * Documentation God Agent
 *
 * Tier 2 Domain God specializing in documentation detection and auto-generation.
 * Wraps domain-analyzers.js documentation heuristics with enhanced reporting and auto-fix capabilities.
 */

const path = require('path');
const { analyzeDomain } = require('../domain-analyzers');
const ToolBridge = require('../tool-bridge');

class DocumentationGodAgent {
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
      'missing_docs_detection',
      'jsdoc_generation',
      'api_documentation',
      'readme_generation',
      'auto_fix',
      'documentation_analysis'
    ];

    this.metrics = {
      filesAnalyzed: 0,
      missingDocs: 0,
      documentationCoverage: 0,
      fixesApplied: 0
    };
  }

  /**
   * Main analysis method - scans a file for missing documentation
   * @param {string} filePath - Path to file (relative or absolute)
   * @returns {Promise<object>} Documentation analysis results
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

      // Run documentation analysis using existing domain analyzer
      const analysis = analyzeDomain('documentation-god', absolutePath, content, this.options.projectRoot);

      // Update metrics
      this.metrics.filesAnalyzed++;
      this.metrics.missingDocs += analysis.issues.length;

      // Calculate documentation coverage
      const totalItems = analysis.issues.length + (analysis.metadata?.documentedSymbols || 0);
      const documented = analysis.metadata?.documentedSymbols || 0;
      const coverage = totalItems > 0 ? (documented / totalItems) * 100 : 100;
      this.metrics.documentationCoverage = coverage;

      // Categorize issues by type
      const categorized = this.categorizeIssues(analysis.issues);

      return {
        success: true,
        agent: 'documentation-god',
        file: filePath,
        absolutePath: absolutePath,
        summary: {
          totalIssues: analysis.issues.length,
          critical: analysis.issues.filter(i => i.severity === 'CRITICAL').length,
          high: analysis.issues.filter(i => i.severity === 'HIGH').length,
          medium: analysis.issues.filter(i => i.severity === 'MEDIUM').length,
          low: analysis.issues.filter(i => i.severity === 'LOW').length,
          coverage: coverage.toFixed(1)
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
        agent: 'documentation-god',
        file: filePath,
        error: error.message
      };
    }
  }

  /**
   * Scan entire directory for documentation issues
   * @param {string} directoryPath - Directory to scan
   * @param {object} options - Scan options
   * @returns {Promise<object>} Aggregated documentation report
   */
  async scanDirectory(directoryPath, options = {}) {
    const {
      maxFiles = 100,
      filePattern = /\.(js|ts|jsx|tsx|py|php|java|rb|go|rs)$/
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
    let totalDocumented = 0;
    let totalSymbols = 0;

    for (const file of files) {
      const result = await this.analyzeFile(file);
      if (result.success) {
        results.push(result);

        // Track overall documentation coverage
        const documented = result.metadata?.documentedSymbols || 0;
        const total = result.issues.length + documented;
        totalDocumented += documented;
        totalSymbols += total;
      }
    }

    const overallCoverage = totalSymbols > 0 ? (totalDocumented / totalSymbols) * 100 : 100;

    // Aggregate results
    return {
      success: true,
      agent: 'documentation-god',
      directory: directoryPath,
      filesScanned: files.length,
      filesWithIssues: results.filter(r => r.issues.length > 0).length,
      totalIssues: results.reduce((sum, r) => sum + r.issues.length, 0),
      overallCoverage: overallCoverage.toFixed(1),
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
   * Categorize issues by documentation type
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
   * Get top N most critical documentation gaps across all scanned files
   */
  getTopIssues(n = 10) {
    // This would be enhanced to track issues across scans
    return {
      message: 'Top issues tracking not yet implemented in this version'
    };
  }

  /**
   * Generate documentation report
   */
  generateReport(scanResults) {
    const { summary, filesScanned, filesWithIssues, totalIssues, overallCoverage } = scanResults;

    const report = {
      title: 'Documentation God Analysis Report',
      timestamp: new Date().toISOString(),
      agent: 'documentation-god',
      tier: 2,

      overview: {
        filesScanned,
        filesWithIssues,
        totalDocumentationGaps: totalIssues,
        criticalGaps: summary.critical,
        highPriorityGaps: summary.high,
        documentationCoverage: overallCoverage,
        documentationGrade: this.calculateDocumentationGrade(overallCoverage)
      },

      breakdown: summary,

      recommendations: this.generateRecommendations(summary, overallCoverage),

      metrics: { ...this.metrics }
    };

    return report;
  }

  /**
   * Calculate documentation grade (A-F) based on coverage
   */
  calculateDocumentationGrade(coverage) {
    const score = parseFloat(coverage);

    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate documentation recommendations
   */
  generateRecommendations(summary, coverage) {
    const recommendations = [];
    const coverageNum = parseFloat(coverage);

    if (summary.critical > 0) {
      recommendations.push({
        priority: 'URGENT',
        action: `Document ${summary.critical} CRITICAL public APIs immediately`,
        impact: 'Missing public API documentation blocks adoption and integration',
        effort: 'Hours to days'
      });
    }

    if (summary.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Add documentation for ${summary.high} HIGH priority items`,
        impact: 'Improves developer experience and reduces support burden',
        effort: 'Days to week'
      });
    }

    if (coverageNum < 70) {
      recommendations.push({
        priority: 'MEDIUM',
        action: `Improve documentation coverage from ${coverage}% to at least 70%`,
        impact: 'Better maintainability and onboarding experience',
        effort: 'Week to weeks'
      });
    }

    if (summary.medium > 5) {
      recommendations.push({
        priority: 'MEDIUM',
        action: `Document ${summary.medium} MEDIUM priority functions and classes`,
        impact: 'Reduces cognitive load for future maintenance',
        effort: 'Week to weeks'
      });
    }

    if (summary.low > 10) {
      recommendations.push({
        priority: 'LOW',
        action: `Add inline comments for ${summary.low} minor items`,
        impact: 'Documentation hygiene, easier code review',
        effort: 'Quick wins for documentation quality'
      });
    }

    if (coverageNum >= 80) {
      recommendations.push({
        priority: 'INFO',
        action: 'Excellent documentation coverage! Consider adding examples and tutorials',
        impact: 'Enhanced developer experience',
        effort: 'Optional enhancement'
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
      missingDocs: 0,
      documentationCoverage: 0,
      fixesApplied: 0
    };
  }
}

module.exports = DocumentationGodAgent;
