/**
 * TITAN MODE™ Level 3: REPORTING & INSIGHTS
 * Generate reports in multiple formats with actionable insights
 *
 * Provides:
 * - JSON, Markdown, HTML, SARIF report formats
 * - Trend analysis
 * - Prioritized recommendations
 * - CI/CD integration output
 *
 * @module titanmode/level3-reporting
 */

const fs = require('fs');
const path = require('path');
const TitanDetect = require('./titan-detect');

class Level3Reporting {
    constructor(config = {}) {
        this.config = {
            outputDir: config.outputDir || '.codetitan',
            formats: config.formats || ['json', 'markdown'],
            includeSnippets: config.includeSnippets !== false,
            groupBy: config.groupBy || 'severity', // severity, category, file
            maxIssuesPerFile: config.maxIssuesPerFile || 100,
            ...config,
        };

        this.titanDetect = new TitanDetect(config);
    }

    /**
     * Analyze and generate reports
     */
    async analyzeAndReport(projectPath) {
        console.log('⚡ [TITAN MODE Level 3] REPORTING & INSIGHTS');
        console.log(`   Output formats: ${this.config.formats.join(', ')}\n`);

        // Run Level 2 analysis
        const results = await this.titanDetect.analyze(projectPath);

        // Generate reports in requested formats
        const reports = {};

        for (const format of this.config.formats) {
            const report = await this.generateReport(results, format);
            reports[format] = report;

            // Save to file
            const outputPath = this.saveReport(report, format, projectPath);
            console.log(`   ✓ ${format.toUpperCase()} report: ${outputPath}`);
        }

        // Generate insights
        const insights = this.generateInsights(results);

        console.log('\n📊 Analysis Summary:');
        console.log(`   Files: ${results.metrics.totalFiles}`);
        console.log(`   Lines: ${results.metrics.totalLines}`);
        console.log(`   Issues: ${results.issues.length}`);
        console.log(`   Critical: ${results.summary.criticalCount}`);
        console.log(`   High: ${results.summary.highCount}`);

        return {
            results,
            reports,
            insights,
        };
    }

    /**
     * Generate report in specified format
     */
    async generateReport(results, format) {
        switch (format) {
            case 'json':
                return this.generateJSONReport(results);
            case 'markdown':
                return this.generateMarkdownReport(results);
            case 'html':
                return this.generateHTMLReport(results);
            case 'sarif':
                return this.generateSARIFReport(results);
            default:
                throw new Error(`Unknown format: ${format}`);
        }
    }

    /**
     * Generate JSON report
     */
    generateJSONReport(results) {
        return JSON.stringify({
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            projectPath: results.projectPath,
            metrics: results.metrics,
            summary: results.summary,
            issues: results.issues.slice(0, this.config.maxIssuesPerFile * 10),
            insights: this.generateInsights(results),
        }, null, 2);
    }

    /**
     * Generate Markdown report
     */
    generateMarkdownReport(results) {
        const lines = [];

        lines.push('# CodeTitan Analysis Report');
        lines.push(`\n*Generated: ${new Date().toISOString()}*\n`);

        // Summary
        lines.push('## Summary\n');
        lines.push(`| Metric | Value |`);
        lines.push(`|--------|-------|`);
        lines.push(`| Files Analyzed | ${results.metrics.totalFiles} |`);
        lines.push(`| Total Lines | ${results.metrics.totalLines.toLocaleString()} |`);
        lines.push(`| Total Issues | ${results.issues.length} |`);
        lines.push(`| Critical | ${results.summary.criticalCount} |`);
        lines.push(`| High | ${results.summary.highCount} |`);
        lines.push(`| Medium | ${results.summary.mediumCount} |`);
        lines.push(`| Low | ${results.summary.lowCount} |`);

        // Issues by severity
        if (results.summary.criticalCount > 0) {
            lines.push('\n## 🔴 Critical Issues\n');
            this.addIssueSection(lines, results.issues.filter(i => i.severity === 'CRITICAL'));
        }

        if (results.summary.highCount > 0) {
            lines.push('\n## 🟠 High Severity Issues\n');
            this.addIssueSection(lines, results.issues.filter(i => i.severity === 'HIGH'));
        }

        if (results.summary.mediumCount > 0) {
            lines.push('\n## 🟡 Medium Severity Issues\n');
            this.addIssueSection(lines, results.issues.filter(i => i.severity === 'MEDIUM').slice(0, 20));
        }

        // Insights
        const insights = this.generateInsights(results);
        lines.push('\n## 💡 Insights & Recommendations\n');
        insights.recommendations.forEach((rec, i) => {
            lines.push(`${i + 1}. **${rec.title}**: ${rec.description}`);
        });

        // Footer
        lines.push('\n---');
        lines.push('*Report generated by CodeTitan Titan Mode*');

        return lines.join('\n');
    }

    /**
     * Add issue section to markdown
     */
    addIssueSection(lines, issues) {
        issues.slice(0, 20).forEach(issue => {
            lines.push(`### ${issue.rule_id || issue.type}`);
            lines.push(`- **File**: \`${issue.relativePath || issue.file}\`:${issue.line}`);
            lines.push(`- **Message**: ${issue.message}`);
            if (issue.cwe) lines.push(`- **CWE**: ${issue.cwe}`);
            if (issue.snippet) lines.push(`- **Code**: \`${issue.snippet}\``);
            lines.push('');
        });
    }

    /**
     * Generate HTML report
     */
    generateHTMLReport(results) {
        const insights = this.generateInsights(results);

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CodeTitan Analysis Report</title>
  <style>
    :root { --bg: #0d1117; --card: #161b22; --text: #c9d1d9; --accent: #58a6ff; --critical: #f85149; --high: #db6d28; --medium: #d29922; --low: #3fb950; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: var(--accent); }
    .card { background: var(--card); border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }
    .stat { text-align: center; padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; }
    .stat-value { font-size: 2rem; font-weight: bold; }
    .critical { color: var(--critical); }
    .high { color: var(--high); }
    .medium { color: var(--medium); }
    .low { color: var(--low); }
    .issue { background: rgba(255,255,255,0.03); padding: 1rem; margin: 0.5rem 0; border-radius: 4px; border-left: 4px solid; }
    .issue.severity-CRITICAL { border-color: var(--critical); }
    .issue.severity-HIGH { border-color: var(--high); }
    .issue.severity-MEDIUM { border-color: var(--medium); }
    .issue.severity-LOW { border-color: var(--low); }
    code { background: rgba(0,0,0,0.3); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.9em; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ CodeTitan Analysis Report</h1>
    <p>Generated: ${new Date().toISOString()}</p>
    
    <div class="card">
      <h2>Summary</h2>
      <div class="stats">
        <div class="stat"><div class="stat-value">${results.metrics.totalFiles}</div><div>Files</div></div>
        <div class="stat"><div class="stat-value">${results.metrics.totalLines.toLocaleString()}</div><div>Lines</div></div>
        <div class="stat"><div class="stat-value critical">${results.summary.criticalCount}</div><div>Critical</div></div>
        <div class="stat"><div class="stat-value high">${results.summary.highCount}</div><div>High</div></div>
        <div class="stat"><div class="stat-value medium">${results.summary.mediumCount}</div><div>Medium</div></div>
        <div class="stat"><div class="stat-value low">${results.summary.lowCount}</div><div>Low</div></div>
      </div>
    </div>
    
    <div class="card">
      <h2>Issues</h2>
      ${results.issues.slice(0, 50).map(issue => `
        <div class="issue severity-${issue.severity}">
          <strong>${issue.rule_id || issue.type}</strong> (${issue.severity})
          <br><code>${issue.relativePath || issue.file}:${issue.line}</code>
          <br>${issue.message}
        </div>
      `).join('')}
    </div>
    
    <div class="card">
      <h2>💡 Recommendations</h2>
      <ol>
        ${insights.recommendations.map(rec => `<li><strong>${rec.title}</strong>: ${rec.description}</li>`).join('')}
      </ol>
    </div>
  </div>
</body>
</html>`;
    }

    /**
     * Generate SARIF report (standard format for CI/CD)
     */
    generateSARIFReport(results) {
        const sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: [{
                tool: {
                    driver: {
                        name: "CodeTitan",
                        version: "1.0.0",
                        informationUri: "https://codetitan.dev",
                        rules: this.extractRulesForSARIF(),
                    }
                },
                results: results.issues.slice(0, 500).map(issue => ({
                    ruleId: issue.rule_id || issue.type,
                    level: this.severityToSARIF(issue.severity),
                    message: { text: issue.message },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: issue.relativePath || issue.file },
                            region: { startLine: issue.line, startColumn: issue.column || 1 }
                        }
                    }],
                })),
            }]
        };

        return JSON.stringify(sarif, null, 2);
    }

    /**
     * Extract rules for SARIF
     */
    extractRulesForSARIF() {
        const allRules = [
            ...TitanDetect.SECURITY_RULES,
            ...TitanDetect.PERFORMANCE_RULES,
            ...TitanDetect.QUALITY_RULES,
        ];

        return allRules.map(rule => ({
            id: rule.id,
            name: rule.name,
            shortDescription: { text: rule.message },
            defaultConfiguration: {
                level: this.severityToSARIF(rule.severity),
            },
        }));
    }

    /**
     * Convert severity to SARIF level
     */
    severityToSARIF(severity) {
        const map = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' };
        return map[severity] || 'none';
    }

    /**
     * Generate actionable insights
     */
    generateInsights(results) {
        const recommendations = [];
        const { summary, metrics, issues } = results;

        // Security recommendations
        if (summary.byCategory?.security > 0) {
            recommendations.push({
                priority: 'CRITICAL',
                title: 'Address Security Vulnerabilities',
                description: `Found ${summary.byCategory.security} security issues. Fix these before deployment.`,
                effort: 'high',
            });
        }

        // Performance recommendations
        if (summary.byCategory?.performance > 5) {
            recommendations.push({
                priority: 'HIGH',
                title: 'Optimize Performance Patterns',
                description: `Detected ${summary.byCategory.performance} performance anti-patterns that could impact user experience.`,
                effort: 'medium',
            });
        }

        // Complexity
        if (metrics.averageComplexity > 15) {
            recommendations.push({
                priority: 'MEDIUM',
                title: 'Reduce Code Complexity',
                description: `Average complexity is ${metrics.averageComplexity}. Consider refactoring functions over 10 complexity.`,
                effort: 'medium',
            });
        }

        // Large files
        const largeFiles = issues.filter(i => i.rule_id === 'QUAL-002').length;
        if (largeFiles > 3) {
            recommendations.push({
                priority: 'LOW',
                title: 'Split Large Files',
                description: `${largeFiles} files exceed 500 lines. Consider splitting for maintainability.`,
                effort: 'low',
            });
        }

        // Test coverage hint
        if (metrics.totalFiles > 50 && !issues.some(i => i.file.includes('test'))) {
            recommendations.push({
                priority: 'MEDIUM',
                title: 'Add Test Coverage',
                description: 'No test files detected. Consider adding unit tests for critical paths.',
                effort: 'high',
            });
        }

        return {
            score: this.calculateHealthScore(results),
            recommendations: recommendations.sort((a, b) => {
                const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
                return order[a.priority] - order[b.priority];
            }),
            trending: 'N/A (first scan)',
        };
    }

    /**
     * Calculate overall health score
     */
    calculateHealthScore(results) {
        let score = 100;

        // Deduct for issues
        score -= results.summary.criticalCount * 15;
        score -= results.summary.highCount * 8;
        score -= results.summary.mediumCount * 3;
        score -= results.summary.lowCount * 1;

        // Bonus for good practices
        if (results.metrics.averageComplexity < 10) score += 5;
        if (results.metrics.totalFunctions > 0) score += 5;

        return Math.max(0, Math.min(100, Math.round(score)));
    }

    /**
     * Save report to file
     */
    saveReport(content, format, projectPath) {
        const outputDir = path.join(projectPath, this.config.outputDir);

        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const extensions = { json: 'json', markdown: 'md', html: 'html', sarif: 'sarif' };
        const filename = `report.${extensions[format] || format}`;
        const outputPath = path.join(outputDir, filename);

        fs.writeFileSync(outputPath, content);

        return outputPath;
    }
}

module.exports = Level3Reporting;
