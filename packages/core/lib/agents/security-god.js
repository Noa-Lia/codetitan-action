/**
 * Security God Agent
 *
 * Tier 2 Domain God specializing in vulnerability detection and security remediation.
 * Wraps domain-analyzers.js security heuristics with enhanced reporting and auto-fix capabilities.
 */

const path = require('path');
const { analyzeDomain } = require('../domain-analyzers');
const ToolBridge = require('../tool-bridge');

class SecurityGodAgent {
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
      'vulnerability_detection',
      'sql_injection_detection',
      'xss_detection',
      'secrets_scanning',
      'command_injection_detection',
      'auto_fix',
      'security_analysis'
    ];

    this.metrics = {
      filesScanned: 0,
      vulnerabilitiesFound: 0,
      criticalIssues: 0,
      fixesApplied: 0
    };
  }

  /**
   * Main analysis method - scans a file for security vulnerabilities
   * @param {string} filePath - Path to file (relative or absolute)
   * @returns {Promise<object>} Security analysis results
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

      // Run security analysis using existing domain analyzer
      const analysis = analyzeDomain('security-god', absolutePath, content, this.options.projectRoot);

      // Update metrics
      this.metrics.filesScanned++;
      this.metrics.vulnerabilitiesFound += analysis.issues.length;
      this.metrics.criticalIssues += analysis.issues.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').length;

      // Categorize issues by type
      const categorized = this.categorizeIssues(analysis.issues);

      return {
        success: true,
        agent: 'security-god',
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
        agent: 'security-god',
        file: filePath,
        error: error.message
      };
    }
  }

  /**
   * Scan entire directory for security issues
   * @param {string} directoryPath - Directory to scan
   * @param {object} options - Scan options
   * @returns {Promise<object>} Aggregated security report
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
      agent: 'security-god',
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
   * Categorize issues by vulnerability type
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
   * Generate security report
   */
  generateReport(scanResults) {
    const { summary, filesScanned, filesWithIssues, totalIssues } = scanResults;

    const report = {
      title: 'Security God Analysis Report',
      timestamp: new Date().toISOString(),
      agent: 'security-god',
      tier: 2,

      overview: {
        filesScanned,
        filesWithIssues,
        totalVulnerabilities: totalIssues,
        criticalVulnerabilities: summary.critical,
        highVulnerabilities: summary.high,
        securityGrade: this.calculateSecurityGrade(summary)
      },

      breakdown: summary,

      recommendations: this.generateRecommendations(summary),

      metrics: { ...this.metrics }
    };

    return report;
  }

  /**
   * Calculate security grade (A-F) based on vulnerabilities found
   */
  calculateSecurityGrade(summary) {
    const score = 100 - (
      summary.critical * 20 +
      summary.high * 10 +
      summary.medium * 5 +
      summary.low * 1
    );

    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate security recommendations
   */
  generateRecommendations(summary) {
    const recommendations = [];

    if (summary.critical > 0) {
      recommendations.push({
        priority: 'URGENT',
        action: `Fix ${summary.critical} CRITICAL vulnerabilities immediately`,
        impact: 'System compromise, data breach, production outage',
        effort: 'Hours to days'
      });
    }

    if (summary.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Address ${summary.high} HIGH severity vulnerabilities`,
        impact: 'Exploitation likely, significant security risk',
        effort: 'Days to week'
      });
    }

    if (summary.medium > 5) {
      recommendations.push({
        priority: 'MEDIUM',
        action: `Remediate ${summary.medium} MEDIUM severity issues`,
        impact: 'Reduces attack surface, improves security posture',
        effort: 'Week to weeks'
      });
    }

    if (summary.low > 10) {
      recommendations.push({
        priority: 'LOW',
        action: `Clean up ${summary.low} minor security issues`,
        impact: 'Security hygiene, defense in depth',
        effort: 'Quick wins for security hardening'
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
      filesScanned: 0,
      vulnerabilitiesFound: 0,
      criticalIssues: 0,
      fixesApplied: 0
    };
  }
}

module.exports = SecurityGodAgent;
