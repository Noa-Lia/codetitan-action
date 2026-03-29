/**
 * Visual Analysis Report Generator
 * 
 * Generates visual reports for code analysis:
 * - Mermaid sequence diagrams for data flow
 * - Dependency graphs
 * - HTML/PDF export for compliance
 * 
 * @module visual-report-generator
 */

const fs = require('fs');
const path = require('path');

/**
 * Mermaid diagram generator
 */
class MermaidGenerator {
    /**
     * Generate a data flow sequence diagram
     */
    generateDataFlowDiagram(flows) {
        const lines = ['sequenceDiagram'];
        lines.push('    participant U as User Input');
        lines.push('    participant C as Code');
        lines.push('    participant S as Sink');

        for (const flow of flows) {
            if (flow.type === 'source') {
                lines.push(`    U->>C: ${this.escape(flow.source)} → ${flow.variable}`);
            } else if (flow.type === 'sink') {
                lines.push(`    C->>S: ${flow.variable} → ${this.escape(flow.sinkType)}`);
                lines.push(`    Note over S: ${flow.line ? `Line ${flow.line}` : 'Vulnerable'}`);
            }
        }

        return lines.join('\n');
    }

    /**
     * Generate a dependency graph
     */
    generateDependencyGraph(dependencies) {
        const lines = ['graph TD'];

        for (const [file, deps] of Object.entries(dependencies)) {
            const fileId = this.toId(file);

            for (const dep of deps) {
                const depId = this.toId(dep);
                lines.push(`    ${fileId}[${this.escape(path.basename(file))}] --> ${depId}[${this.escape(path.basename(dep))}]`);
            }
        }

        return lines.join('\n');
    }

    /**
     * Generate a call graph
     */
    generateCallGraph(callGraph) {
        const lines = ['graph LR'];

        for (const [caller, callees] of Object.entries(callGraph)) {
            const callerId = this.toId(caller);

            for (const callee of callees) {
                const calleeId = this.toId(callee);
                lines.push(`    ${callerId}((${this.escape(caller)})) --> ${calleeId}((${this.escape(callee)}))`);
            }
        }

        return lines.join('\n');
    }

    /**
     * Generate findings by severity chart
     */
    generateSeverityPieChart(findings) {
        const counts = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
        };

        for (const finding of findings) {
            counts[finding.severity] = (counts[finding.severity] || 0) + 1;
        }

        const lines = ['pie title Findings by Severity'];
        for (const [severity, count] of Object.entries(counts)) {
            if (count > 0) {
                lines.push(`    "${severity}" : ${count}`);
            }
        }

        return lines.join('\n');
    }

    /**
     * Generate category distribution chart
     */
    generateCategoryChart(findings) {
        const counts = {};

        for (const finding of findings) {
            counts[finding.category] = (counts[finding.category] || 0) + 1;
        }

        const lines = ['pie title Findings by Category'];
        for (const [category, count] of Object.entries(counts)) {
            lines.push(`    "${category}" : ${count}`);
        }

        return lines.join('\n');
    }

    /**
     * Escape special characters for Mermaid
     */
    escape(str) {
        if (!str) return '';
        return String(str)
            .replace(/"/g, "'")
            .replace(/[<>]/g, '')
            .substring(0, 50);
    }

    /**
     * Convert string to valid Mermaid ID
     */
    toId(str) {
        return str.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 20);
    }
}

/**
 * HTML Report Generator
 */
class HTMLReportGenerator {
    constructor(options = {}) {
        this.options = {
            title: options.title || 'CodeTitan Analysis Report',
            logo: options.logo || null,
            theme: options.theme || 'dark',
            ...options,
        };
        this.mermaid = new MermaidGenerator();
    }

    /**
     * Generate complete HTML report
     */
    generate(analysisResult) {
        const {
            findings = [],
            dataFlows = [],
            callGraph = {},
            dependencies = {},
            metadata = {},
        } = analysisResult;

        const summary = this.generateSummary(findings, metadata);
        const diagrams = this.generateDiagrams(findings, dataFlows, callGraph, dependencies);
        const findingsTable = this.generateFindingsTable(findings);
        const recommendations = this.generateRecommendations(findings);

        return this.renderHTML({
            summary,
            diagrams,
            findingsTable,
            recommendations,
            metadata,
        });
    }

    /**
     * Generate executive summary
     */
    generateSummary(findings, metadata) {
        const bySeverity = {
            CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
            HIGH: findings.filter(f => f.severity === 'HIGH').length,
            MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
            LOW: findings.filter(f => f.severity === 'LOW').length,
        };

        const riskScore = this.calculateRiskScore(bySeverity);
        const riskLevel = riskScore >= 80 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : 'LOW';

        return {
            totalFindings: findings.length,
            bySeverity,
            riskScore,
            riskLevel,
            analyzedAt: metadata.timestamp || new Date().toISOString(),
            filesAnalyzed: metadata.filesAnalyzed || 0,
            linesAnalyzed: metadata.linesAnalyzed || 0,
        };
    }

    /**
     * Calculate overall risk score
     */
    calculateRiskScore(bySeverity) {
        const weights = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 2 };
        let score = 0;

        for (const [severity, count] of Object.entries(bySeverity)) {
            score += (weights[severity] || 0) * count;
        }

        return Math.min(100, score);
    }

    /**
     * Generate diagrams section
     */
    generateDiagrams(findings, dataFlows, callGraph, dependencies) {
        const diagrams = [];

        // Severity pie chart
        if (findings.length > 0) {
            diagrams.push({
                title: 'Findings by Severity',
                type: 'pie',
                mermaid: this.mermaid.generateSeverityPieChart(findings),
            });

            diagrams.push({
                title: 'Findings by Category',
                type: 'pie',
                mermaid: this.mermaid.generateCategoryChart(findings),
            });
        }

        // Data flow diagram
        if (dataFlows.length > 0) {
            diagrams.push({
                title: 'Data Flow Analysis',
                type: 'sequence',
                mermaid: this.mermaid.generateDataFlowDiagram(dataFlows),
            });
        }

        // Call graph
        if (Object.keys(callGraph).length > 0) {
            diagrams.push({
                title: 'Call Graph',
                type: 'graph',
                mermaid: this.mermaid.generateCallGraph(callGraph),
            });
        }

        // Dependency graph
        if (Object.keys(dependencies).length > 0) {
            diagrams.push({
                title: 'File Dependencies',
                type: 'graph',
                mermaid: this.mermaid.generateDependencyGraph(dependencies),
            });
        }

        return diagrams;
    }

    /**
     * Generate findings table
     */
    generateFindingsTable(findings) {
        return findings.map((f, i) => ({
            id: i + 1,
            severity: f.severity,
            category: f.category,
            message: f.message,
            file: f.file || 'N/A',
            line: f.line || 'N/A',
            cwe: f.cwe || 'N/A',
            confidence: f.confidence || 'N/A',
        }));
    }

    /**
     * Generate recommendations
     */
    generateRecommendations(findings) {
        const recommendations = [];
        const seen = new Set();

        for (const finding of findings) {
            if (finding.remediation && !seen.has(finding.category)) {
                recommendations.push({
                    category: finding.category,
                    severity: finding.severity,
                    recommendation: finding.remediation,
                    count: findings.filter(f => f.category === finding.category).length,
                });
                seen.add(finding.category);
            }
        }

        return recommendations.sort((a, b) => {
            const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
            return severityOrder[a.severity] - severityOrder[b.severity];
        });
    }

    /**
     * Render HTML template
     */
    renderHTML({ summary, diagrams, findingsTable, recommendations, metadata }) {
        const isDark = this.options.theme === 'dark';
        const colors = isDark ? {
            bg: '#0f172a',
            card: '#1e293b',
            text: '#e2e8f0',
            textMuted: '#94a3b8',
            border: '#334155',
            critical: '#ef4444',
            high: '#f97316',
            medium: '#eab308',
            low: '#3b82f6',
        } : {
            bg: '#f8fafc',
            card: '#ffffff',
            text: '#1e293b',
            textMuted: '#64748b',
            border: '#e2e8f0',
            critical: '#dc2626',
            high: '#ea580c',
            medium: '#ca8a04',
            low: '#2563eb',
        };

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${this.options.title}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: ${colors.bg};
            color: ${colors.text};
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid ${colors.border};
        }
        .header h1 { font-size: 1.75rem; font-weight: 700; }
        .header .meta { color: ${colors.textMuted}; font-size: 0.875rem; }
        .card {
            background: ${colors.card};
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid ${colors.border};
        }
        .card-title {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .summary-stat {
            text-align: center;
            padding: 1rem;
            background: ${isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.02)'};
            border-radius: 0.5rem;
        }
        .summary-stat .value { font-size: 2rem; font-weight: 700; }
        .summary-stat .label { color: ${colors.textMuted}; font-size: 0.875rem; }
        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-CRITICAL { background: ${colors.critical}; color: white; }
        .severity-HIGH { background: ${colors.high}; color: white; }
        .severity-MEDIUM { background: ${colors.medium}; color: ${isDark ? 'black' : 'white'}; }
        .severity-LOW { background: ${colors.low}; color: white; }
        .diagram { margin: 1rem 0; }
        .diagram-title { font-weight: 600; margin-bottom: 0.5rem; }
        .mermaid { background: ${isDark ? '#1e293b' : '#f1f5f9'}; padding: 1rem; border-radius: 0.5rem; }
        table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid ${colors.border}; }
        th { font-weight: 600; color: ${colors.textMuted}; }
        tr:hover { background: ${isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)'}; }
        .risk-score {
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, ${summary.riskLevel === 'CRITICAL' ? colors.critical : summary.riskLevel === 'HIGH' ? colors.high : summary.riskLevel === 'MEDIUM' ? colors.medium : colors.low} 0%, ${colors.text} 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .recommendation { padding: 1rem; background: ${isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.02)'}; border-radius: 0.5rem; margin-bottom: 0.75rem; }
        .recommendation-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
        .footer { text-align: center; color: ${colors.textMuted}; font-size: 0.75rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid ${colors.border}; }
        @media print {
            .container { max-width: none; }
            .card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ ${this.options.title}</h1>
                <div class="meta">Generated on ${new Date(summary.analyzedAt).toLocaleString()}</div>
            </div>
            <div style="text-align: right;">
                <div class="risk-score">${summary.riskScore}</div>
                <span class="severity-badge severity-${summary.riskLevel}">${summary.riskLevel} Risk</span>
            </div>
        </div>

        <div class="card">
            <div class="card-title">📊 Executive Summary</div>
            <div class="summary-grid">
                <div class="summary-stat">
                    <div class="value">${summary.totalFindings}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="summary-stat">
                    <div class="value" style="color: ${colors.critical}">${summary.bySeverity.CRITICAL}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-stat">
                    <div class="value" style="color: ${colors.high}">${summary.bySeverity.HIGH}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-stat">
                    <div class="value" style="color: ${colors.medium}">${summary.bySeverity.MEDIUM}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-stat">
                    <div class="value" style="color: ${colors.low}">${summary.bySeverity.LOW}</div>
                    <div class="label">Low</div>
                </div>
                <div class="summary-stat">
                    <div class="value">${summary.filesAnalyzed}</div>
                    <div class="label">Files Analyzed</div>
                </div>
            </div>
        </div>

        ${diagrams.length > 0 ? `
        <div class="card">
            <div class="card-title">📈 Visual Analysis</div>
            ${diagrams.map(d => `
                <div class="diagram">
                    <div class="diagram-title">${d.title}</div>
                    <div class="mermaid">${d.mermaid}</div>
                </div>
            `).join('')}
        </div>
        ` : ''}

        ${findingsTable.length > 0 ? `
        <div class="card">
            <div class="card-title">🔍 Detailed Findings</div>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Message</th>
                        <th>Location</th>
                        <th>CWE</th>
                    </tr>
                </thead>
                <tbody>
                    ${findingsTable.slice(0, 50).map(f => `
                        <tr>
                            <td>${f.id}</td>
                            <td><span class="severity-badge severity-${f.severity}">${f.severity}</span></td>
                            <td>${f.category}</td>
                            <td>${f.message?.substring(0, 80) || 'N/A'}${f.message?.length > 80 ? '...' : ''}</td>
                            <td>${f.file}:${f.line}</td>
                            <td>${f.cwe}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            ${findingsTable.length > 50 ? `<p style="color: ${colors.textMuted}; margin-top: 1rem; font-size: 0.875rem;">Showing 50 of ${findingsTable.length} findings</p>` : ''}
        </div>
        ` : ''}

        ${recommendations.length > 0 ? `
        <div class="card">
            <div class="card-title">💡 Recommendations</div>
            ${recommendations.slice(0, 10).map(r => `
                <div class="recommendation">
                    <div class="recommendation-header">
                        <span><strong>${r.category}</strong> (${r.count} findings)</span>
                        <span class="severity-badge severity-${r.severity}">${r.severity}</span>
                    </div>
                    <div>${r.recommendation}</div>
                </div>
            `).join('')}
        </div>
        ` : ''}

        <div class="footer">
            Generated by CodeTitan | ${new Date().getFullYear()} | Powered by AI-driven security analysis
        </div>
    </div>

    <script>
        mermaid.initialize({ 
            startOnLoad: true, 
            theme: '${isDark ? 'dark' : 'default'}',
            securityLevel: 'loose'
        });
    </script>
</body>
</html>`;
    }

    /**
     * Save report to file
     */
    async save(analysisResult, outputPath) {
        const html = this.generate(analysisResult);
        await fs.promises.writeFile(outputPath, html, 'utf8');
        return outputPath;
    }
}

/**
 * PDF Report Generator (uses headless browser)
 */
class PDFReportGenerator {
    constructor(options = {}) {
        this.htmlGenerator = new HTMLReportGenerator(options);
        this.options = options;
    }

    /**
     * Generate PDF report
     */
    async generate(analysisResult, outputPath) {
        // Generate HTML first
        const html = this.htmlGenerator.generate(analysisResult);
        const htmlPath = outputPath.replace(/\.pdf$/, '.html');
        await fs.promises.writeFile(htmlPath, html, 'utf8');

        // Try to use puppeteer if available
        try {
            const puppeteer = require('puppeteer');
            const browser = await puppeteer.launch({ headless: 'new' });
            const page = await browser.newPage();

            await page.setContent(html, { waitUntil: 'networkidle0' });
            await page.pdf({
                path: outputPath,
                format: 'A4',
                printBackground: true,
                margin: { top: '1cm', right: '1cm', bottom: '1cm', left: '1cm' },
            });

            await browser.close();

            // Clean up HTML
            await fs.promises.unlink(htmlPath).catch(() => { });

            return outputPath;
        } catch (error) {
            // Fallback: just return HTML path
            console.warn('PDF generation requires puppeteer. Returning HTML instead.');
            return htmlPath;
        }
    }
}

/**
 * JSON Report Generator
 */
class JSONReportGenerator {
    generate(analysisResult) {
        return JSON.stringify({
            timestamp: new Date().toISOString(),
            version: '1.0',
            ...analysisResult,
        }, null, 2);
    }

    async save(analysisResult, outputPath) {
        const json = this.generate(analysisResult);
        await fs.promises.writeFile(outputPath, json, 'utf8');
        return outputPath;
    }
}

/**
 * SARIF Report Generator (for GitHub integration)
 */
class SARIFReportGenerator {
    generate(analysisResult) {
        const { findings = [], metadata = {} } = analysisResult;

        return {
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            version: '2.1.0',
            runs: [{
                tool: {
                    driver: {
                        name: 'CodeTitan',
                        version: metadata.version || '1.0.0',
                        informationUri: 'https://codetitan.dev',
                        rules: this.extractRules(findings),
                    },
                },
                results: findings.map((f, i) => ({
                    ruleId: f.ruleId || `CT${String(i).padStart(4, '0')}`,
                    level: this.mapSeverity(f.severity),
                    message: { text: f.message },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: f.file || 'unknown' },
                            region: {
                                startLine: f.line || 1,
                                startColumn: f.column || 1,
                            },
                        },
                    }],
                })),
            }],
        };
    }

    extractRules(findings) {
        const rules = new Map();

        for (const f of findings) {
            const ruleId = f.ruleId || f.category;
            if (!rules.has(ruleId)) {
                rules.set(ruleId, {
                    id: ruleId,
                    name: f.ruleName || f.category,
                    shortDescription: { text: f.message?.substring(0, 100) },
                    fullDescription: { text: f.description || f.message },
                    defaultConfiguration: { level: this.mapSeverity(f.severity) },
                    properties: {
                        tags: [f.category],
                        cwe: f.cwe,
                    },
                });
            }
        }

        return Array.from(rules.values());
    }

    mapSeverity(severity) {
        const map = {
            CRITICAL: 'error',
            HIGH: 'error',
            MEDIUM: 'warning',
            LOW: 'note',
        };
        return map[severity] || 'none';
    }

    async save(analysisResult, outputPath) {
        const sarif = this.generate(analysisResult);
        await fs.promises.writeFile(outputPath, JSON.stringify(sarif, null, 2), 'utf8');
        return outputPath;
    }
}

/**
 * Visual Report Generator Factory
 */
class VisualReportGenerator {
    constructor(options = {}) {
        this.generators = {
            html: new HTMLReportGenerator(options),
            pdf: new PDFReportGenerator(options),
            json: new JSONReportGenerator(),
            sarif: new SARIFReportGenerator(),
        };
        this.mermaid = new MermaidGenerator();
    }

    /**
     * Generate report in specified format
     */
    async generate(analysisResult, format = 'html', outputPath = null) {
        const generator = this.generators[format];

        if (!generator) {
            throw new Error(`Unknown format: ${format}. Supported: html, pdf, json, sarif`);
        }

        if (outputPath) {
            return generator.save(analysisResult, outputPath);
        }

        return generator.generate(analysisResult);
    }

    /**
     * Generate all formats
     */
    async generateAll(analysisResult, outputDir) {
        const baseName = `codetitan-report-${Date.now()}`;
        const results = {};

        for (const format of ['html', 'json', 'sarif']) {
            const ext = format === 'sarif' ? 'sarif.json' : format;
            const outputPath = path.join(outputDir, `${baseName}.${ext}`);
            results[format] = await this.generate(analysisResult, format, outputPath);
        }

        return results;
    }
}

module.exports = {
    VisualReportGenerator,
    HTMLReportGenerator,
    PDFReportGenerator,
    JSONReportGenerator,
    SARIFReportGenerator,
    MermaidGenerator,
};
