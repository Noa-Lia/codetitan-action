/**
 * TITAN MODE™ Level 2: RULE MATCHING ENGINE
 * Advanced pattern detection and rule-based analysis
 *
 * Provides:
 * - Security vulnerability detection
 * - Performance anti-pattern matching
 * - Code quality rules
 * - Custom rule support
 *
 * @module titanmode/level2-rule-matching
 */

const TitanScan = require('./titan-scan');

/**
 * Built-in security rules
 */
const SECURITY_RULES = [
    {
        id: 'SEC-001',
        name: 'no-eval',
        severity: 'CRITICAL',
        category: 'security',
        pattern: /\beval\s*\(/,
        message: 'eval() is dangerous and can lead to code injection',
        cwe: 'CWE-95',
    },
    {
        id: 'SEC-002',
        name: 'no-innerhtml',
        severity: 'HIGH',
        category: 'security',
        pattern: /\.innerHTML\s*=/,
        message: 'innerHTML can lead to XSS vulnerabilities',
        cwe: 'CWE-79',
    },
    {
        id: 'SEC-003',
        name: 'no-dangerously-set-html',
        severity: 'HIGH',
        category: 'security',
        pattern: /dangerouslySetInnerHTML/,
        message: 'dangerouslySetInnerHTML can lead to XSS vulnerabilities',
        cwe: 'CWE-79',
    },
    {
        id: 'SEC-004',
        name: 'no-hardcoded-secret',
        severity: 'CRITICAL',
        category: 'security',
        pattern: /(?:password|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{8,}['"]/i,
        message: 'Possible hardcoded secret detected',
        cwe: 'CWE-798',
    },
    {
        id: 'SEC-005',
        name: 'no-sql-injection',
        severity: 'CRITICAL',
        category: 'security',
        pattern: /(?:query|execute)\s*\(\s*[`'"].*\$\{/,
        message: 'Possible SQL injection via string interpolation',
        cwe: 'CWE-89',
    },
    {
        id: 'SEC-006',
        name: 'no-document-write',
        severity: 'MEDIUM',
        category: 'security',
        pattern: /document\.write\s*\(/,
        message: 'document.write can be exploited for XSS',
        cwe: 'CWE-79',
    },
    {
        id: 'SEC-007',
        name: 'no-child-process-exec',
        severity: 'HIGH',
        category: 'security',
        pattern: /child_process.*exec\s*\(/,
        message: 'Command execution can lead to injection attacks',
        cwe: 'CWE-78',
    },
];

/**
 * Built-in performance rules
 */
const PERFORMANCE_RULES = [
    {
        id: 'PERF-001',
        name: 'no-sync-fs',
        severity: 'MEDIUM',
        category: 'performance',
        pattern: /\b(?:readFileSync|writeFileSync|appendFileSync|existsSync)\s*\(/,
        message: 'Synchronous file operations block the event loop',
    },
    {
        id: 'PERF-002',
        name: 'no-nested-await-in-loop',
        severity: 'HIGH',
        category: 'performance',
        pattern: /for\s*\([^)]*\)\s*\{[^}]*await\s+/,
        message: 'Await in loop causes sequential execution; consider Promise.all',
    },
    {
        id: 'PERF-003',
        name: 'prefer-const',
        severity: 'LOW',
        category: 'performance',
        pattern: /\blet\s+\w+\s*=\s*[^;]+;\s*(?:\/\/[^\n]*\n\s*)*[^=\n]*(?!\s*=)/,
        message: 'Variable never reassigned; use const instead of let',
    },
    {
        id: 'PERF-004',
        name: 'no-large-json-parse',
        severity: 'MEDIUM',
        category: 'performance',
        pattern: /JSON\.parse\s*\(\s*(?:fs\.readFileSync|await\s+fs\.promises\.readFile)/,
        message: 'Large JSON parsing can block main thread; consider streaming',
    },
];

/**
 * Built-in quality rules
 */
const QUALITY_RULES = [
    {
        id: 'QUAL-001',
        name: 'max-function-lines',
        severity: 'MEDIUM',
        category: 'maintainability',
        pattern: null, // AST-based
        threshold: 50,
        message: 'Function exceeds 50 lines; consider breaking it up',
    },
    {
        id: 'QUAL-002',
        name: 'max-file-lines',
        severity: 'LOW',
        category: 'maintainability',
        pattern: null,
        threshold: 500,
        message: 'File exceeds 500 lines; consider splitting',
    },
    {
        id: 'QUAL-003',
        name: 'no-deep-nesting',
        severity: 'MEDIUM',
        category: 'maintainability',
        pattern: /^\s{16,}(?:if|for|while|switch)/m,
        message: 'Deep nesting detected; consider early returns or extraction',
    },
    {
        id: 'QUAL-004',
        name: 'no-duplicate-imports',
        severity: 'LOW',
        category: 'maintainability',
        pattern: null, // AST-based
        message: 'Duplicate import detected',
    },
];

class TitanDetect {
    constructor(config = {}) {
        this.config = {
            enableSecurity: config.enableSecurity !== false,
            enablePerformance: config.enablePerformance !== false,
            enableQuality: config.enableQuality !== false,
            customRules: config.customRules || [],
            severityThreshold: config.severityThreshold || 'INFO', // INFO, LOW, MEDIUM, HIGH, CRITICAL
            ...config,
        };

        this.titanScan = new TitanScan(config);
        this.rules = this.buildRuleSet();

        this.stats = {
            rulesChecked: 0,
            issuesFound: 0,
            byCategory: {},
            bySeverity: {},
        };
    }

    /**
     * Build the active rule set
     */
    buildRuleSet() {
        const rules = [];

        if (this.config.enableSecurity) rules.push(...SECURITY_RULES);
        if (this.config.enablePerformance) rules.push(...PERFORMANCE_RULES);
        if (this.config.enableQuality) rules.push(...QUALITY_RULES);

        rules.push(...this.config.customRules);

        return rules;
    }

    /**
     * Analyze project with rule matching
     */
    async analyze(projectPath) {
        console.log('⚡ [TITAN MODE Level 2] RULE MATCHING ENGINE');
        console.log(`   ${this.rules.length} rules loaded\n`);

        // First, run TITAN SCAN analysis
        const scanResults = await this.titanScan.analyze(projectPath);

        // Apply rule matching to each file
        const allIssues = [...scanResults.issues];

        for (const file of scanResults.files) {
            const fileIssues = await this.matchRules(file);
            allIssues.push(...fileIssues);
            this.stats.issuesFound += fileIssues.length;
        }

        // Apply AST-based rules
        const astIssues = this.applyASTRules(scanResults.files);
        allIssues.push(...astIssues);

        // Categorize and sort issues
        const categorizedIssues = this.categorizeIssues(allIssues);

        // Filter by severity threshold
        const filteredIssues = this.filterBySeverity(categorizedIssues);

        console.log(`\n   ✓ ${this.rules.length} rules checked`);
        console.log(`   ✓ ${filteredIssues.length} issues above threshold\n`);

        return {
            ...scanResults,
            issues: filteredIssues,
            ruleStats: this.getStats(),
            summary: this.generateSummary(filteredIssues),
        };
    }

    /**
     * Match rules against a file
     */
    async matchRules(fileResult) {
        const issues = [];
        const content = require('fs').readFileSync(fileResult.path, 'utf-8');
        const lines = content.split('\n');

        for (const rule of this.rules) {
            if (!rule.pattern) continue; // Skip AST-based rules

            this.stats.rulesChecked++;

            lines.forEach((line, idx) => {
                if (rule.pattern.test(line)) {
                    issues.push({
                        id: `${rule.id}-${fileResult.path}-${idx + 1}`,
                        rule_id: rule.id,
                        rule_name: rule.name,
                        type: rule.name,
                        severity: rule.severity,
                        category: rule.category,
                        message: rule.message,
                        file: fileResult.path,
                        relativePath: fileResult.relativePath,
                        line: idx + 1,
                        column: line.search(rule.pattern),
                        cwe: rule.cwe,
                        snippet: line.trim().slice(0, 100),
                    });

                    // Update stats
                    this.stats.byCategory[rule.category] = (this.stats.byCategory[rule.category] || 0) + 1;
                    this.stats.bySeverity[rule.severity] = (this.stats.bySeverity[rule.severity] || 0) + 1;
                }
            });
        }

        return issues;
    }

    /**
     * Apply AST-based rules
     */
    applyASTRules(files) {
        const issues = [];

        for (const file of files) {
            // Max file lines check
            if (file.metrics.lines > 500) {
                issues.push({
                    rule_id: 'QUAL-002',
                    severity: 'LOW',
                    category: 'maintainability',
                    message: `File has ${file.metrics.lines} lines (max: 500)`,
                    file: file.path,
                    line: 1,
                });
            }

            // High complexity check
            if (file.metrics.complexity > 20) {
                issues.push({
                    rule_id: 'QUAL-005',
                    severity: 'MEDIUM',
                    category: 'maintainability',
                    message: `High cyclomatic complexity: ${file.metrics.complexity}`,
                    file: file.path,
                    line: 1,
                });
            }
        }

        return issues;
    }

    /**
     * Categorize and deduplicate issues
     */
    categorizeIssues(issues) {
        // Deduplicate by unique key
        const seen = new Set();
        const deduplicated = issues.filter(issue => {
            const key = `${issue.rule_id || issue.type}-${issue.file}-${issue.line}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        // Sort by severity
        const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        deduplicated.sort((a, b) =>
            (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
        );

        return deduplicated;
    }

    /**
     * Filter issues by severity threshold
     */
    filterBySeverity(issues) {
        const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        const threshold = severityOrder[this.config.severityThreshold] || 4;

        return issues.filter(issue =>
            (severityOrder[issue.severity] || 5) <= threshold
        );
    }

    /**
     * Generate summary of findings
     */
    generateSummary(issues) {
        const bySeverity = {};
        const byCategory = {};

        issues.forEach(issue => {
            bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
            byCategory[issue.category] = (byCategory[issue.category] || 0) + 1;
        });

        return {
            total: issues.length,
            bySeverity,
            byCategory,
            criticalCount: bySeverity.CRITICAL || 0,
            highCount: bySeverity.HIGH || 0,
            mediumCount: bySeverity.MEDIUM || 0,
            lowCount: bySeverity.LOW || 0,
        };
    }

    /**
     * Add custom rule
     */
    addRule(rule) {
        this.rules.push(rule);
    }

    /**
     * Get statistics
     */
    getStats() {
        return {
            ...this.stats,
            rulesLoaded: this.rules.length,
        };
    }
}

// Export rules for external use
TitanDetect.SECURITY_RULES = SECURITY_RULES;
TitanDetect.PERFORMANCE_RULES = PERFORMANCE_RULES;
TitanDetect.QUALITY_RULES = QUALITY_RULES;

module.exports = TitanDetect;
