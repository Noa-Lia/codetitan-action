/**
 * Approval Gate - Safety Module for CodeTitan
 * 
 * Centralized logic for determining when human approval is required.
 * This is a critical safety feature that ensures customers feel in control.
 * 
 * Customer Value: "Nothing gets auto-applied unless I explicitly opt in."
 */

/**
 * Risk levels for different operations
 */
const RISK_LEVELS = {
    LOW: 1,      // Documentation changes, formatting
    MEDIUM: 2,   // Logic changes with high confidence
    HIGH: 3,     // Security-related changes
    CRITICAL: 4  // Breaking changes, deletions
};

/**
 * Default approval policies by context
 */
const DEFAULT_POLICIES = {
    cli: {
        autoApprove: false,
        minConfidenceForAuto: 95,
        maxRiskLevel: RISK_LEVELS.LOW,
        requiresExplicitOptIn: true
    },
    vscode: {
        autoApprove: false,
        minConfidenceForAuto: 90,
        maxRiskLevel: RISK_LEVELS.MEDIUM,
        requiresExplicitOptIn: true,
        showPreview: true
    },
    githubAction: {
        autoApprove: false,
        minConfidenceForAuto: 95,
        maxRiskLevel: RISK_LEVELS.LOW,
        requiresExplicitOptIn: true,
        createPRInstead: true
    },
    dashboard: {
        autoApprove: false,
        showConfirmation: true,
        requiresExplicitOptIn: true
    }
};

/**
 * Categories that always require human approval regardless of confidence
 */
const ALWAYS_REQUIRE_APPROVAL = [
    'SECURITY',
    'AUTHENTICATION',
    'AUTHORIZATION',
    'DATA_DELETION',
    'DATABASE_SCHEMA',
    'PAYMENT_PROCESSING',
    'PII_HANDLING',
    'ENCRYPTION'
];

class ApprovalGate {
    constructor(config = {}) {
        this.policies = { ...DEFAULT_POLICIES, ...config.policies };
        this.overrides = config.overrides || {};
        this.auditLog = config.auditLog || null;
    }

    /**
     * Determine if a fix requires human approval
     * @param {Object} fix - The proposed fix
     * @param {string} context - Where the fix is being applied (cli, vscode, githubAction, dashboard)
     * @param {Object} userPreferences - User-specific preferences
     * @returns {Object} { requiresApproval, reason, riskLevel, recommendation }
     */
    evaluateFix(fix, context = 'cli', userPreferences = {}) {
        const policy = this.policies[context] || this.policies.cli;
        const result = {
            requiresApproval: true,
            reasons: [],
            riskLevel: RISK_LEVELS.LOW,
            recommendation: 'review'
        };

        // Check if category always requires approval
        if (ALWAYS_REQUIRE_APPROVAL.includes(fix.category?.toUpperCase())) {
            result.reasons.push(`Category '${fix.category}' always requires human approval`);
            result.riskLevel = RISK_LEVELS.CRITICAL;
            result.recommendation = 'manual_review_required';
            return result;
        }

        // Calculate risk level based on fix properties
        result.riskLevel = this.calculateRiskLevel(fix);

        // Check confidence threshold
        const confidence = fix.confidence || 0;
        if (confidence < policy.minConfidenceForAuto) {
            result.reasons.push(`Confidence ${Math.round(confidence * 100)}% below threshold ${policy.minConfidenceForAuto}%`);
        }

        // Check risk level
        if (result.riskLevel > policy.maxRiskLevel) {
            result.reasons.push(`Risk level ${result.riskLevel} exceeds policy max ${policy.maxRiskLevel}`);
        }

        // Check if user has explicitly opted in to auto-apply
        if (policy.requiresExplicitOptIn && !userPreferences.autoApplyEnabled) {
            result.reasons.push('Auto-apply requires explicit user opt-in');
        }

        // Check for destructive operations
        if (fix.type === 'delete' || fix.isDestructive) {
            result.reasons.push('Destructive operations require approval');
            result.riskLevel = Math.max(result.riskLevel, RISK_LEVELS.HIGH);
        }

        // User overrides
        if (this.overrides[fix.file]) {
            const override = this.overrides[fix.file];
            if (override.alwaysApprove) {
                result.requiresApproval = true;
                result.reasons.push(`File '${fix.file}' has manual override requiring approval`);
            }
        }

        // Determine final approval requirement
        result.requiresApproval = result.reasons.length > 0 || !policy.autoApprove;

        // Set recommendation
        if (!result.requiresApproval) {
            result.recommendation = 'auto_apply';
        } else if (result.riskLevel >= RISK_LEVELS.HIGH) {
            result.recommendation = 'senior_review';
        } else if (confidence >= 0.9) {
            result.recommendation = 'quick_review';
        } else {
            result.recommendation = 'detailed_review';
        }

        // Log the evaluation
        if (this.auditLog) {
            this.auditLog.log({
                type: 'APPROVAL_GATE_EVALUATION',
                fix: { file: fix.file, category: fix.category, confidence },
                context,
                result,
                timestamp: new Date().toISOString()
            });
        }

        return result;
    }

    /**
     * Calculate risk level for a fix
     */
    calculateRiskLevel(fix) {
        let risk = RISK_LEVELS.LOW;

        // Security-related categories are high risk
        if (['security', 'vulnerability', 'injection', 'xss'].some(
            k => fix.category?.toLowerCase().includes(k)
        )) {
            risk = RISK_LEVELS.HIGH;
        }

        // Changes to core infrastructure files
        if (['package.json', 'tsconfig.json', '.env', 'Dockerfile', 'docker-compose.yml'].some(
            f => fix.file?.includes(f)
        )) {
            risk = Math.max(risk, RISK_LEVELS.MEDIUM);
        }

        // Database/migration changes
        if (fix.file?.includes('migration') || fix.file?.includes('schema')) {
            risk = RISK_LEVELS.CRITICAL;
        }

        // Multi-line changes increase risk
        if (fix.linesChanged > 10) {
            risk = Math.max(risk, RISK_LEVELS.MEDIUM);
        }

        return risk;
    }

    /**
     * Batch evaluate multiple fixes
     */
    evaluateBatch(fixes, context, userPreferences = {}) {
        const results = fixes.map(fix => ({
            fix,
            evaluation: this.evaluateFix(fix, context, userPreferences)
        }));

        const summary = {
            total: fixes.length,
            autoApprovable: results.filter(r => !r.evaluation.requiresApproval).length,
            requiresApproval: results.filter(r => r.evaluation.requiresApproval).length,
            byRiskLevel: {
                low: results.filter(r => r.evaluation.riskLevel === RISK_LEVELS.LOW).length,
                medium: results.filter(r => r.evaluation.riskLevel === RISK_LEVELS.MEDIUM).length,
                high: results.filter(r => r.evaluation.riskLevel === RISK_LEVELS.HIGH).length,
                critical: results.filter(r => r.evaluation.riskLevel === RISK_LEVELS.CRITICAL).length
            }
        };

        return { results, summary };
    }

    /**
     * Generate a human-readable approval request
     */
    generateApprovalRequest(fix, evaluation) {
        const lines = [
            `## Approval Required`,
            ``,
            `**File:** \`${fix.file}\``,
            `**Category:** ${fix.category}`,
            `**Confidence:** ${Math.round((fix.confidence || 0) * 100)}%`,
            `**Risk Level:** ${['Low', 'Medium', 'High', 'Critical'][evaluation.riskLevel - 1]}`,
            ``,
            `### Reasons for Approval Requirement:`,
            ...evaluation.reasons.map(r => `- ${r}`),
            ``,
            `### Recommendation: ${evaluation.recommendation.replace(/_/g, ' ')}`,
            ``,
            `---`,
            `*Please review and approve or reject this change.*`
        ];

        return lines.join('\n');
    }
}

module.exports = { ApprovalGate, RISK_LEVELS, ALWAYS_REQUIRE_APPROVAL };
