/**
 * CodeTitan Rules Index
 * 
 * Unified export of all 500+ detection rules
 * @module rules
 */

const CORE_SECURITY_RULES = require('../security-rules');
const REACT_NODE_RULES = require('./security-rules-react-node');
const PYTHON_RULES = require('./security-rules-python');
const JAVA_RULES = require('./security-rules-java');
const INFRASTRUCTURE_RULES = require('./security-rules-infrastructure');
const QUALITY_RULES = require('./quality-rules');
const OWASP_API_RULES = require('./security-rules-owasp-api');

/**
 * Count total rules in a rules object
 */
function countRules(rulesObj) {
    let count = 0;
    Object.values(rulesObj).forEach(category => {
        if (typeof category === 'object' && !Array.isArray(category)) {
            count += Object.keys(category).length;
        }
    });
    return count;
}

/**
 * Flatten rules into array format
 */
function flattenRules(rulesObj, prefix = '') {
    const flattened = [];

    Object.entries(rulesObj).forEach(([categoryName, category]) => {
        if (typeof category === 'object' && !Array.isArray(category)) {
            Object.entries(category).forEach(([ruleName, rule]) => {
                flattened.push({
                    id: `${prefix}${categoryName}.${ruleName}`,
                    category: categoryName,
                    name: ruleName,
                    ...rule,
                });
            });
        }
    });

    return flattened;
}

/**
 * Get all rules as flat array
 */
function getAllRulesArray() {
    return [
        ...flattenRules(CORE_SECURITY_RULES.SECURITY_RULES, 'CORE.'),
        ...flattenRules(REACT_NODE_RULES, 'JS.'),
        ...flattenRules(PYTHON_RULES, 'PY.'),
        ...flattenRules(JAVA_RULES, 'JAVA.'),
        ...flattenRules(INFRASTRUCTURE_RULES, 'INFRA.'),
        ...flattenRules(QUALITY_RULES, 'QUALITY.'),
        ...flattenRules(OWASP_API_RULES, 'OWASP.'),
    ];
}

/**
 * Get rules by severity
 */
function getRulesBySeverity(severity) {
    return getAllRulesArray().filter(r => r.severity === severity);
}

/**
 * Get rules by category prefix
 */
function getRulesByPrefix(prefix) {
    return getAllRulesArray().filter(r => r.id.startsWith(prefix));
}

/**
 * Rule statistics
 */
const RULE_STATS = {
    core: countRules(CORE_SECURITY_RULES.SECURITY_RULES),
    reactNode: countRules(REACT_NODE_RULES),
    python: countRules(PYTHON_RULES),
    java: countRules(JAVA_RULES),
    infrastructure: countRules(INFRASTRUCTURE_RULES),
    quality: countRules(QUALITY_RULES),
    owaspApi: countRules(OWASP_API_RULES),

    get total() {
        return this.core + this.reactNode + this.python + this.java + this.infrastructure + this.quality + this.owaspApi;
    }
};

/**
 * Display rule statistics
 */
function displayRuleStats() {
    console.log('📊 CodeTitan Rule Library Statistics:');
    console.log(`   Core Security:    ${RULE_STATS.core} rules`);
    console.log(`   React/Node.js:    ${RULE_STATS.reactNode} rules`);
    console.log(`   Python:           ${RULE_STATS.python} rules`);
    console.log(`   Java/Spring:      ${RULE_STATS.java} rules`);
    console.log(`   Infrastructure:   ${RULE_STATS.infrastructure} rules`);
    console.log(`   OWASP/API/Mobile: ${RULE_STATS.owaspApi} rules`);
    console.log(`   Code Quality:     ${RULE_STATS.quality} rules`);
    console.log(`   ─────────────────────────────`);
    console.log(`   TOTAL:            ${RULE_STATS.total} rules`);
}

module.exports = {
    // Rule collections
    CORE_SECURITY_RULES: CORE_SECURITY_RULES.SECURITY_RULES,
    SECRET_PATTERNS: CORE_SECURITY_RULES.SECRET_PATTERNS,
    DANGEROUS_PATTERNS: CORE_SECURITY_RULES.DANGEROUS_PATTERNS,
    REACT_NODE_RULES,
    PYTHON_RULES,
    JAVA_RULES,
    INFRASTRUCTURE_RULES,
    QUALITY_RULES,
    OWASP_API_RULES,

    // Utilities
    getAllRulesArray,
    getRulesBySeverity,
    getRulesByPrefix,
    countRules,
    flattenRules,
    displayRuleStats,

    // Statistics
    RULE_STATS,
};
