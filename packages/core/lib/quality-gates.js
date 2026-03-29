/**
 * Quality Gates
 * 
 * CI/CD blocking system that prevents merging code that doesn't meet
 * quality thresholds. Essential for SonarQube parity.
 * 
 * @module quality-gates
 */

/**
 * Default quality gate profiles
 */
const GATE_PROFILES = {
    // Strict - No new issues allowed
    STRICT: {
        name: 'Strict',
        description: 'No new issues allowed - maximum quality enforcement',
        conditions: {
            newCriticalIssues: { max: 0, failOn: 'ANY' },
            newHighIssues: { max: 0, failOn: 'ANY' },
            newMediumIssues: { max: 5, failOn: 'EXCEED' },
            duplicatedLines: { max: 3, failOn: 'PERCENTAGE' },
            codeCoverage: { min: 80, failOn: 'BELOW' },
            securityHotspots: { max: 0, failOn: 'UNREVIEWED' },
            technicalDebt: { max: 30, failOn: 'MINUTES' },
        },
    },

    // Recommended - Balanced quality/velocity
    RECOMMENDED: {
        name: 'Recommended',
        description: 'Balanced quality and development velocity',
        conditions: {
            newCriticalIssues: { max: 0, failOn: 'ANY' },
            newHighIssues: { max: 2, failOn: 'EXCEED' },
            newMediumIssues: { max: 10, failOn: 'EXCEED' },
            duplicatedLines: { max: 5, failOn: 'PERCENTAGE' },
            codeCoverage: { min: 70, failOn: 'BELOW' },
            securityHotspots: { max: 3, failOn: 'UNREVIEWED' },
            technicalDebt: { max: 60, failOn: 'MINUTES' },
        },
    },

    // Relaxed - Focus on critical issues only
    RELAXED: {
        name: 'Relaxed',
        description: 'Focus on critical security issues only',
        conditions: {
            newCriticalIssues: { max: 0, failOn: 'ANY' },
            newHighIssues: { max: 5, failOn: 'EXCEED' },
            codeCoverage: { min: 50, failOn: 'BELOW' },
        },
    },

    // Security Only - Just security issues
    SECURITY_ONLY: {
        name: 'Security Only',
        description: 'Block only on security vulnerabilities',
        conditions: {
            newCriticalIssues: { max: 0, failOn: 'ANY' },
            newHighIssues: { max: 0, failOn: 'ANY' },
            securityHotspots: { max: 0, failOn: 'UNREVIEWED' },
        },
    },
};

/**
 * Severity order for comparison
 */
const SEVERITY_ORDER = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0,
};

/**
 * Quality Gate Condition Result
 */
class ConditionResult {
    constructor(conditionName, passed, actual, threshold, operator) {
        this.conditionName = conditionName;
        this.passed = passed;
        this.actual = actual;
        this.threshold = threshold;
        this.operator = operator;
    }

    toJSON() {
        return {
            name: this.conditionName,
            status: this.passed ? 'PASSED' : 'FAILED',
            actual: this.actual,
            threshold: this.threshold,
            operator: this.operator,
        };
    }
}

/**
 * Quality Gate Result
 */
class QualityGateResult {
    constructor(profileName) {
        this.profileName = profileName;
        this.status = 'PASSED';
        this.conditions = [];
        this.timestamp = new Date().toISOString();
        this.analysisId = null;
    }

    addCondition(result) {
        this.conditions.push(result);
        if (!result.passed) {
            this.status = 'FAILED';
        }
    }

    setWarning() {
        if (this.status === 'PASSED') {
            this.status = 'WARNING';
        }
    }

    toJSON() {
        return {
            status: this.status,
            profile: this.profileName,
            timestamp: this.timestamp,
            analysisId: this.analysisId,
            conditions: this.conditions.map(c => c.toJSON()),
            summary: {
                total: this.conditions.length,
                passed: this.conditions.filter(c => c.passed).length,
                failed: this.conditions.filter(c => !c.passed).length,
            },
        };
    }

    /**
     * Get CLI-friendly summary
     */
    toCliOutput() {
        const icon = this.status === 'PASSED' ? '✅' : this.status === 'WARNING' ? '⚠️' : '❌';
        const lines = [
            `${icon} Quality Gate: ${this.status}`,
            `   Profile: ${this.profileName}`,
            '',
        ];

        this.conditions.forEach(c => {
            const status = c.passed ? '✓' : '✗';
            const comparison = c.operator === 'max' ? '≤' : '≥';
            lines.push(`   ${status} ${c.conditionName}: ${c.actual} (threshold: ${comparison} ${c.threshold})`);
        });

        return lines.join('\n');
    }
}

/**
 * Count issues by severity
 */
function countBySeverity(issues) {
    const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0,
    };

    issues.forEach(issue => {
        const severity = issue.severity?.toUpperCase() || 'MEDIUM';
        if (counts.hasOwnProperty(severity)) {
            counts[severity]++;
        }
    });

    return counts;
}

/**
 * Count security-specific issues
 */
function countSecurityIssues(issues) {
    const securityCategories = [
        'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'CODE_EXECUTION',
        'PATH_TRAVERSAL', 'SSRF', 'OPEN_REDIRECT', 'HARDCODED_SECRET',
        'TAINTED_SQL_INJECTION', 'TAINTED_XSS', 'TAINTED_COMMAND_INJECTION',
    ];

    return issues.filter(issue =>
        securityCategories.some(cat => issue.category?.includes(cat))
    ).length;
}

/**
 * Calculate technical debt in minutes
 */
function calculateTechnicalDebt(issues) {
    const debtPerSeverity = {
        CRITICAL: 60,  // 1 hour
        HIGH: 30,      // 30 min
        MEDIUM: 15,    // 15 min
        LOW: 5,        // 5 min
        INFO: 1,       // 1 min
    };

    return issues.reduce((total, issue) => {
        const severity = issue.severity?.toUpperCase() || 'MEDIUM';
        return total + (debtPerSeverity[severity] || 10);
    }, 0);
}

/**
 * Evaluate a single condition
 */
function evaluateCondition(conditionName, config, metrics) {
    const { max, min, failOn } = config;

    let actual = 0;
    let threshold = max ?? min ?? 0;
    let operator = max !== undefined ? 'max' : 'min';
    let metricAvailable = true;

    switch (conditionName) {
        case 'newCriticalIssues':
            actual = metrics.severityCounts.CRITICAL;
            break;
        case 'newHighIssues':
            actual = metrics.severityCounts.HIGH;
            break;
        case 'newMediumIssues':
            actual = metrics.severityCounts.MEDIUM;
            break;
        case 'newLowIssues':
            actual = metrics.severityCounts.LOW;
            break;
        case 'duplicatedLines':
            actual = metrics.duplicatedLinesPercent ?? 0;
            metricAvailable = metrics.duplicatedLinesPercent !== null && metrics.duplicatedLinesPercent !== undefined;
            break;
        case 'codeCoverage':
            actual = metrics.codeCoverage ?? 0;
            operator = 'min';
            threshold = min;
            // Skip this check if codeCoverage was not provided
            metricAvailable = metrics.codeCoverage !== null && metrics.codeCoverage !== undefined;
            break;
        case 'securityHotspots':
            actual = metrics.securityIssues;
            break;
        case 'technicalDebt':
            actual = metrics.technicalDebtMinutes;
            break;
        default:
            actual = 0;
    }

    let passed = true;

    // If metric is not available, skip this condition (pass by default)
    if (!metricAvailable) {
        passed = true;
    } else if (operator === 'max') {
        passed = actual <= threshold;
    } else {
        passed = actual >= threshold;
    }

    return new ConditionResult(conditionName, passed, actual, threshold, operator);
}


/**
 * Run quality gate evaluation
 * 
 * @param {Array} issues - Array of analysis findings
 * @param {Object} options - Configuration options
 * @returns {QualityGateResult}
 */
function evaluateQualityGate(issues, options = {}) {
    const {
        profile = 'RECOMMENDED',
        customConditions = null,
        baselineIssues = [],
        codeCoverage = null,
        duplicatedLinesPercent = null,
    } = options;

    // Get the profile
    const gateProfile = customConditions || GATE_PROFILES[profile] || GATE_PROFILES.RECOMMENDED;
    const result = new QualityGateResult(gateProfile.name);

    // Calculate new issues (diff from baseline)
    const newIssues = baselineIssues.length > 0
        ? issues.filter(issue => !baselineIssues.some(base =>
            base.line === issue.line &&
            base.category === issue.category &&
            base.message === issue.message
        ))
        : issues;

    // Calculate metrics
    const metrics = {
        severityCounts: countBySeverity(newIssues),
        securityIssues: countSecurityIssues(newIssues),
        technicalDebtMinutes: calculateTechnicalDebt(newIssues),
        codeCoverage: codeCoverage,
        duplicatedLinesPercent: duplicatedLinesPercent,
        totalIssues: newIssues.length,
    };

    // Evaluate each condition
    Object.entries(gateProfile.conditions).forEach(([conditionName, config]) => {
        const conditionResult = evaluateCondition(conditionName, config, metrics);
        result.addCondition(conditionResult);
    });

    return result;
}

/**
 * Create a custom quality gate profile
 */
function createCustomProfile(name, description, conditions) {
    return {
        name,
        description,
        conditions,
    };
}

/**
 * Validate a quality gate configuration
 */
function validateGateConfig(config) {
    const errors = [];

    if (!config.name || typeof config.name !== 'string') {
        errors.push('Profile must have a name');
    }

    if (!config.conditions || typeof config.conditions !== 'object') {
        errors.push('Profile must have conditions');
    } else {
        Object.entries(config.conditions).forEach(([key, value]) => {
            if (value.max === undefined && value.min === undefined) {
                errors.push(`Condition "${key}" must have max or min threshold`);
            }
        });
    }

    return {
        valid: errors.length === 0,
        errors,
    };
}

/**
 * Get exit code for CI/CD integration
 */
function getExitCode(result) {
    switch (result.status) {
        case 'PASSED':
            return 0;
        case 'WARNING':
            return 0; // Warnings don't fail the build
        case 'FAILED':
            return 1;
        default:
            return 1;
    }
}

/**
 * Format result for GitHub Actions
 */
function formatForGitHubActions(result) {
    const output = [];

    // Set output variables
    output.push(`::set-output name=quality_gate_status::${result.status}`);
    output.push(`::set-output name=conditions_passed::${result.summary.passed}`);
    output.push(`::set-output name=conditions_failed::${result.summary.failed}`);

    // Add annotations for failed conditions
    result.conditions.forEach(condition => {
        if (!condition.passed) {
            output.push(
                `::error title=Quality Gate Failed::${condition.name}: ${condition.actual} (allowed: ${condition.threshold})`
            );
        }
    });

    return output.join('\n');
}

/**
 * Format result for GitLab CI
 */
function formatForGitLabCI(result) {
    return {
        quality_gate: {
            status: result.status.toLowerCase(),
            profile: result.profileName,
            timestamp: result.timestamp,
            metrics: result.conditions.reduce((acc, c) => {
                acc[c.conditionName] = {
                    value: c.actual,
                    threshold: c.threshold,
                    status: c.passed ? 'ok' : 'failed',
                };
                return acc;
            }, {}),
        },
    };
}

module.exports = {
    evaluateQualityGate,
    createCustomProfile,
    validateGateConfig,
    getExitCode,
    formatForGitHubActions,
    formatForGitLabCI,
    GATE_PROFILES,
    SEVERITY_ORDER,
    QualityGateResult,
    ConditionResult,
    // Utility functions
    countBySeverity,
    countSecurityIssues,
    calculateTechnicalDebt,
};
