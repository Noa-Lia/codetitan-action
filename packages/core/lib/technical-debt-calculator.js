/**
 * Technical Debt Calculator
 * 
 * Calculates technical debt metrics including maintainability index,
 * time-to-fix estimates, and debt ratio for project health assessment.
 * 
 * @module technical-debt-calculator
 */

/**
 * Time estimates (in minutes) for fixing issues by severity
 */
const FIX_TIME_ESTIMATES = {
    CRITICAL: 120,  // 2 hours
    HIGH: 60,       // 1 hour
    MEDIUM: 30,     // 30 minutes
    LOW: 15,        // 15 minutes
    INFO: 5,        // 5 minutes
};

/**
 * Complexity to time multipliers
 */
const COMPLEXITY_MULTIPLIERS = {
    security: 1.5,
    performance: 1.2,
    memory: 1.3,
    async: 1.4,
    error_handling: 1.0,
    code_smells: 0.8,
    testing: 0.7,
    documentation: 0.5,
    naming: 0.3,
};

/**
 * Calculate maintainability index (0-100)
 * Based on Halstead Volume, Cyclomatic Complexity, and LOC
 * Simplified version using available metrics
 */
function calculateMaintainabilityIndex(metrics) {
    const {
        linesOfCode = 1000,
        cyclomaticComplexity = 10,
        commentRatio = 0.2,
        duplicateRatio = 0.05,
        issueCount = 0,
    } = metrics;

    // Base score starts at 100
    let score = 100;

    // Penalize for high complexity (max -30)
    const complexityPenalty = Math.min(30, cyclomaticComplexity * 0.5);
    score -= complexityPenalty;

    // Penalize for low comment ratio (max -10)
    if (commentRatio < 0.1) {
        score -= (0.1 - commentRatio) * 100;
    }

    // Penalize for duplication (max -20)
    score -= Math.min(20, duplicateRatio * 100);

    // Penalize for issue density (issues per 1000 LOC, max -20)
    const issueDensity = (issueCount / linesOfCode) * 1000;
    score -= Math.min(20, issueDensity * 2);

    // Clamp to 0-100
    return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Get maintainability rating from index
 */
function getMaintainabilityRating(index) {
    if (index >= 80) return { rating: 'A', label: 'Excellent', color: 'green' };
    if (index >= 60) return { rating: 'B', label: 'Good', color: 'lightgreen' };
    if (index >= 40) return { rating: 'C', label: 'Moderate', color: 'yellow' };
    if (index >= 20) return { rating: 'D', label: 'Poor', color: 'orange' };
    return { rating: 'E', label: 'Critical', color: 'red' };
}

/**
 * Calculate time to fix for a single issue
 * @param {Object} issue - CodeTitan finding
 * @returns {number} Minutes to fix
 */
function calculateFixTime(issue) {
    const basetime = FIX_TIME_ESTIMATES[issue.severity?.toUpperCase()] || 15;
    const categoryMultiplier = COMPLEXITY_MULTIPLIERS[issue.category] || 1.0;

    return Math.round(basetime * categoryMultiplier);
}

/**
 * Calculate total technical debt
 * @param {Object[]} findings - CodeTitan findings array
 * @returns {Object} Debt metrics
 */
function calculateTotalDebt(findings) {
    let totalMinutes = 0;
    const byCategory = {};
    const bySeverity = {};

    for (const finding of findings) {
        const fixTime = calculateFixTime(finding);
        totalMinutes += fixTime;

        // Aggregate by category
        const cat = finding.category || 'other';
        byCategory[cat] = (byCategory[cat] || 0) + fixTime;

        // Aggregate by severity
        const sev = finding.severity?.toUpperCase() || 'LOW';
        bySeverity[sev] = (bySeverity[sev] || 0) + fixTime;
    }

    // Convert to hours/days
    const hours = totalMinutes / 60;
    const days = hours / 8; // 8-hour workday

    return {
        totalMinutes,
        totalHours: Math.round(hours * 10) / 10,
        totalDays: Math.round(days * 10) / 10,
        byCategory,
        bySeverity,
        issueCount: findings.length
    };
}

/**
 * Calculate debt ratio (debt time / development time)
 * @param {number} debtMinutes - Total debt in minutes
 * @param {number} linesOfCode - Total LOC
 * @param {number} avgLOCPerHour - Average lines written per hour
 * @returns {number} Debt ratio (0.0-1.0+)
 */
function calculateDebtRatio(debtMinutes, linesOfCode, avgLOCPerHour = 50) {
    const devMinutes = (linesOfCode / avgLOCPerHour) * 60;
    return Math.round((debtMinutes / devMinutes) * 100) / 100;
}

/**
 * Get debt rating from ratio
 */
function getDebtRating(ratio) {
    if (ratio <= 0.05) return { rating: 'A', label: 'Minimal', color: 'green' };
    if (ratio <= 0.10) return { rating: 'B', label: 'Acceptable', color: 'lightgreen' };
    if (ratio <= 0.20) return { rating: 'C', label: 'Moderate', color: 'yellow' };
    if (ratio <= 0.50) return { rating: 'D', label: 'High', color: 'orange' };
    return { rating: 'E', label: 'Critical', color: 'red' };
}

/**
 * Technical Debt Calculator class
 */
class TechnicalDebtCalculator {
    constructor(options = {}) {
        this.avgLOCPerHour = options.avgLOCPerHour || 50;
    }

    /**
     * Calculate full debt report
     * @param {Object[]} findings - CodeTitan findings
     * @param {Object} projectMetrics - Project metrics (LOC, complexity, etc.)
     * @returns {Object} Comprehensive debt report
     */
    calculate(findings, projectMetrics = {}) {
        const debt = calculateTotalDebt(findings);
        const maintainabilityIndex = calculateMaintainabilityIndex({
            ...projectMetrics,
            issueCount: findings.length
        });
        const maintainability = getMaintainabilityRating(maintainabilityIndex);

        const linesOfCode = projectMetrics.linesOfCode || 10000;
        const debtRatio = calculateDebtRatio(debt.totalMinutes, linesOfCode, this.avgLOCPerHour);
        const debtRating = getDebtRating(debtRatio);

        // Identify top debt contributors
        const topContributors = Object.entries(debt.byCategory)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([category, minutes]) => ({
                category,
                minutes,
                hours: Math.round(minutes / 60 * 10) / 10,
                percentage: Math.round((minutes / debt.totalMinutes) * 100)
            }));

        // Sprint planning recommendations
        const sprintRecommendations = this.generateSprintPlan(findings, debt);

        return {
            summary: {
                issueCount: findings.length,
                totalDebt: `${debt.totalHours}h (${debt.totalDays} days)`,
                maintainabilityIndex,
                maintainabilityRating: maintainability.rating,
                debtRatio,
                debtRating: debtRating.rating
            },
            maintainability: {
                index: maintainabilityIndex,
                ...maintainability
            },
            debt: {
                ...debt,
                ratio: debtRatio,
                ...debtRating
            },
            topContributors,
            sprintRecommendations,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Generate sprint planning recommendations
     */
    generateSprintPlan(findings, debt) {
        // Prioritize by severity and fix time
        const prioritized = [...findings]
            .map(f => ({ ...f, fixTime: calculateFixTime(f) }))
            .sort((a, b) => {
                const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
                const aSev = severityOrder[a.severity?.toUpperCase()] ?? 5;
                const bSev = severityOrder[b.severity?.toUpperCase()] ?? 5;
                if (aSev !== bSev) return aSev - bSev;
                return b.fixTime - a.fixTime; // Higher impact first within severity
            });

        // Sprint = 40 hours of debt work max (1 week @ 50% capacity)
        const sprintBudget = 40 * 60; // 40 hours in minutes
        let remaining = sprintBudget;
        const sprintItems = [];

        for (const item of prioritized) {
            if (item.fixTime <= remaining) {
                sprintItems.push({
                    ruleId: item.ruleId,
                    file: item.file,
                    severity: item.severity,
                    estimatedTime: `${item.fixTime}m`
                });
                remaining -= item.fixTime;
            }
            if (sprintItems.length >= 20) break; // Cap at 20 items per sprint
        }

        return {
            budgetHours: 40,
            itemCount: sprintItems.length,
            timeAllocated: `${Math.round((sprintBudget - remaining) / 60)}h`,
            items: sprintItems
        };
    }
}

module.exports = {
    TechnicalDebtCalculator,
    calculateMaintainabilityIndex,
    getMaintainabilityRating,
    calculateFixTime,
    calculateTotalDebt,
    calculateDebtRatio,
    getDebtRating,
    FIX_TIME_ESTIMATES,
    COMPLEXITY_MULTIPLIERS
};
