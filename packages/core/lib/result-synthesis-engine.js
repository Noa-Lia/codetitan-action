/**
 * Result Synthesis Engine
 *
 * Aggregates findings from 50+ agents across 5 Domain Titans.
 * Deduplicates issues, prioritizes by severity x impact, and generates unified reports.
 *
 * Phase 3 Component 2
 */

class ResultSynthesisEngine {
  constructor() {
    // Severity weights for prioritization
    this.severityWeights = {
      CRITICAL: 100,
      HIGH: 50,
      MEDIUM: 20,
      LOW: 5
    };

    // Domain names (human-readable)
    this.domainNames = {
      'security-god': 'Security',
      'performance-god': 'Performance',
      'test-god': 'Testing',
      'refactoring-god': 'Code Quality',
      'documentation-god': 'Documentation'
    };

    // Collected data
    this.findings = [];
    this.rawResults = [];
  }

  /**
   * Main synthesis method: aggregate and prioritize all findings
   */
  async synthesize(rawResults) {
    console.log(`\n[LINK] Synthesizing results from ${rawResults.length} agent executions...`);

    this.rawResults = rawResults;

    try {
      // Step 1: Collect all findings from all agents
      const allFindings = this.collectFindings(rawResults);
      console.log(`   Collected ${allFindings.length} total findings`);

      // Step 2: Deduplicate identical issues
      const uniqueFindings = this.deduplicateFindings(allFindings);
      console.log(`   Deduplicated to ${uniqueFindings.length} unique findings`);

      // Step 3: Prioritize by severity x impact
      const prioritized = this.prioritizeFindings(uniqueFindings);
      console.log(`   Prioritized findings by severity and impact`);

      // Step 4: Generate comprehensive report
      const report = this.generateReport(prioritized, rawResults);
      console.log(`   Generated unified report`);

      return report;

    } catch (error) {
      console.error(`[ERROR] Synthesis failed:`, error);
      throw error;
    }
  }

  /**
   * Collect all findings from raw agent results
   */
  collectFindings(rawResults) {
    const allFindings = [];

    for (const result of rawResults) {
      // Skip error results
      if (result.error) {
        continue;
      }

      // Extract findings from result
      if (result.findings && result.findings.issues) {
        result.findings.issues.forEach(issue => {
          allFindings.push({
            ...issue,
            domain: result.god,
            domainName: this.domainNames[result.god] || result.god,
            file: result.file
          });
        });
      }
    }

    return allFindings;
  }

  /**
   * Deduplicate findings
   * Two findings are considered duplicates if they have:
   * - Same file
   * - Same line
   * - Same category
   */
  deduplicateFindings(findings) {
    const seen = new Map();
    const unique = [];

    for (const finding of findings) {
      // Create unique key: file:line:category
      const key = `${finding.file}:${finding.line}:${finding.category}`;

      if (!seen.has(key)) {
        seen.set(key, true);
        unique.push(finding);
      } else {
        // Track that we found a duplicate
        // (could be useful for confidence scoring later)
      }
    }

    return unique;
  }

  /**
   * Prioritize findings by severity x impact
   * Higher severity and higher impact -> higher priority
   */
  prioritizeFindings(findings) {
    return findings.sort((a, b) => {
      const scoreA = this.severityWeights[a.severity] * (a.impact || 1);
      const scoreB = this.severityWeights[b.severity] * (b.impact || 1);
      return scoreB - scoreA; // Descending order
    });
  }

  /**
   * Generate comprehensive report
   */
  generateReport(findings, rawResults) {
    // Group findings by severity
    const bySeverity = this.groupBySeverity(findings);

    // Group findings by domain
    const byDomain = this.groupByDomain(findings);

    // Group findings by file
    const byFile = this.groupByFile(findings);

    const { totalFiles, totalLinesAnalyzed } = this.getUniqueFileStats(rawResults);

    // Calculate summary statistics
    const summary = {
      totalFindings: findings.length,
      critical: bySeverity.CRITICAL?.length || 0,
      high: bySeverity.HIGH?.length || 0,
      medium: bySeverity.MEDIUM?.length || 0,
      low: bySeverity.LOW?.length || 0,
      totalFiles,
      filesWithIssues: new Set(findings.map(f => f.file)).size,
      totalLinesAnalyzed
    };

    // Domain breakdown
    const domainSummary = {};
    for (const god of Object.keys(this.domainNames)) {
      domainSummary[god] = byDomain[god]?.length || 0;
    }

    // Generate actionable recommendations
    const recommendations = this.generateRecommendations(findings, bySeverity, byDomain);

    // Top issues (highest priority)
    const topIssues = findings.slice(0, 10);

    return {
      summary,
      domainSummary,
      findings,
      bySeverity,
      byDomain,
      byFile,
      topIssues,
      recommendations,
      metrics: this.calculateMetrics(findings, rawResults)
    };
  }

  /**
   * Group findings by severity
   */
  groupBySeverity(findings) {
    return findings.reduce((acc, finding) => {
      const severity = finding.severity || 'MEDIUM';
      if (!acc[severity]) {
        acc[severity] = [];
      }
      acc[severity].push(finding);
      return acc;
    }, {});
  }

  /**
   * Group findings by domain
   */
  groupByDomain(findings) {
    return findings.reduce((acc, finding) => {
      const domain = finding.domain;
      if (!acc[domain]) {
        acc[domain] = [];
      }
      acc[domain].push(finding);
      return acc;
    }, {});
  }

  /**
   * Group findings by file
   */
  groupByFile(findings) {
    return findings.reduce((acc, finding) => {
      const file = finding.file;
      if (!acc[file]) {
        acc[file] = [];
      }
      acc[file].push(finding);
      return acc;
    }, {});
  }

  /**
   * Generate actionable recommendations
   */
  generateRecommendations(findings, bySeverity, byDomain) {
    const recommendations = [];

    // Critical issues first
    const criticalCount = bySeverity.CRITICAL?.length || 0;
    if (criticalCount > 0) {
      recommendations.push({
        priority: 'URGENT',
        action: `Fix ${criticalCount} critical issue${criticalCount > 1 ? 's' : ''} immediately`,
        impact: 'High security/stability risk',
        effort: 'Varies by issue'
      });
    }

    // High severity issues
    const highCount = bySeverity.HIGH?.length || 0;
    if (highCount > 5) {
      recommendations.push({
        priority: 'HIGH',
        action: `Address ${highCount} high-severity issues`,
        impact: 'Significant quality/security improvement',
        effort: 'Multiple days'
      });
    }

    // Domain-specific recommendations
    Object.entries(byDomain).forEach(([domain, domainFindings]) => {
      if (domainFindings.length > 10) {
        const domainName = this.domainNames[domain] || domain;
        const topCategory = this.getTopCategory(domainFindings);
        recommendations.push({
          priority: 'MEDIUM',
          action: `Focus on ${domainName}: ${domainFindings.length} issues found`,
          impact: `Improve ${domainName.toLowerCase()}`,
          effort: 'Several days',
          topIssue: topCategory
        });
      }
    });

    // Low-hanging fruit (many low-severity issues)
    const lowCount = bySeverity.LOW?.length || 0;
    if (lowCount > 20) {
      recommendations.push({
        priority: 'LOW',
        action: `Clean up ${lowCount} minor issues for code hygiene`,
        impact: 'Improved maintainability',
        effort: 'Quick wins, good for junior devs'
      });
    }

    // If very few issues, celebrate!
    if (findings.length < 10) {
      recommendations.push({
        priority: 'INFO',
        action: 'Excellent code quality! Only minor improvements needed.',
        impact: 'Maintain current standards',
        effort: 'Minimal'
      });
    }

    return recommendations;
  }

  /**
   * Get most common category in domain findings
   */
  getTopCategory(findings) {
    const categoryCounts = findings.reduce((acc, f) => {
      acc[f.category] = (acc[f.category] || 0) + 1;
      return acc;
    }, {});

    const sortedCategories = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1]);

    return sortedCategories[0] ? sortedCategories[0][0] : 'Unknown';
  }

  /**
   * Calculate quality metrics
   */
  calculateMetrics(findings, rawResults) {
    const { totalLinesAnalyzed: totalLines } = this.getUniqueFileStats(rawResults);
    const issuesPerKLOC = totalLines > 0 ? (findings.length / (totalLines / 1000)) : 0;

    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;

    // Quality score (0-100)
    // Perfect score = 100, decreases with issues
    const criticalPenalty = criticalCount * 10;
    const highPenalty = highCount * 5;
    const mediumPenalty = findings.filter(f => f.severity === 'MEDIUM').length * 2;
    const lowPenalty = findings.filter(f => f.severity === 'LOW').length * 0.5;

    const totalPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty;
    const qualityScore = Math.max(0, 100 - totalPenalty);

    return {
      totalLines,
      issuesPerKLOC: issuesPerKLOC.toFixed(2),
      qualityScore: qualityScore.toFixed(1),
      criticalDensity: totalLines > 0 ? (criticalCount / (totalLines / 1000)).toFixed(2) : 0,
      healthGrade: this.calculateHealthGrade(qualityScore)
    };
  }

  /**
   * Calculate health grade (A-F) based on quality score
   */
  calculateHealthGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Compute unique file counts and line totals.
   * Raw results may contain multiple entries per file (one per domain).
   */
  getUniqueFileStats(rawResults) {
    const fileLines = new Map();

    for (const result of rawResults || []) {
      const file = result?.file;
      if (!file || fileLines.has(file)) continue;
      const lines = result.findings?.linesAnalyzed || 0;
      fileLines.set(file, lines);
    }

    const totalLinesAnalyzed = Array.from(fileLines.values())
      .reduce((sum, lines) => sum + lines, 0);

    return {
      totalFiles: fileLines.size,
      totalLinesAnalyzed
    };
  }

  /**
   * Export report as JSON
   */
  toJSON(report) {
    return JSON.stringify(report, null, 2);
  }

  /**
   * Export report as Markdown
   */
  toMarkdown(report) {
    let md = '# Codebase Analysis Report\n\n';

    // Summary
    md += '## Summary\n\n';
    md += `- **Total Findings**: ${report.summary.totalFindings}\n`;
    md += `- **Critical**: 🔴 ${report.summary.critical}\n`;
    md += `- **High**: 🟠 ${report.summary.high}\n`;
    md += `- **Medium**: 🟡 ${report.summary.medium}\n`;
    md += `- **Low**: 🟢 ${report.summary.low}\n`;
    md += `- **Files Analyzed**: ${report.summary.totalFiles}\n`;
    md += `- **Files with Issues**: ${report.summary.filesWithIssues}\n`;
    md += `- **Quality Score**: ${report.metrics.qualityScore}/100 (Grade: ${report.metrics.healthGrade})\n\n`;

    // Domain breakdown
    md += '## Findings by Domain\n\n';
    Object.entries(report.domainSummary).forEach(([god, count]) => {
      const domainName = this.domainNames[god] || god;
      md += `- **${domainName}**: ${count} issues\n`;
    });
    md += '\n';

    // Recommendations
    md += '## Recommendations\n\n';
    report.recommendations.forEach((rec, i) => {
      md += `### ${i + 1}. ${rec.action}\n`;
      md += `- **Priority**: ${rec.priority}\n`;
      md += `- **Impact**: ${rec.impact}\n`;
      md += `- **Effort**: ${rec.effort}\n`;
      if (rec.topIssue) {
        md += `- **Top Issue**: ${rec.topIssue}\n`;
      }
      md += '\n';
    });

    // Top issues
    md += '## Top 10 Issues\n\n';
    report.topIssues.forEach((issue, i) => {
      md += `### ${i + 1}. ${issue.message}\n`;
      md += `- **File**: \`${issue.file}\`\n`;
      md += `- **Line**: ${issue.line}\n`;
      md += `- **Severity**: ${issue.severity}\n`;
      md += `- **Domain**: ${issue.domainName}\n`;
      md += `- **Category**: ${issue.category}\n\n`;
    });

    return md;
  }
}

module.exports = ResultSynthesisEngine;
