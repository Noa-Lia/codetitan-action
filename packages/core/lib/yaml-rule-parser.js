/**
 * Custom YAML Rule Parser
 * 
 * Enables users to define custom security rules in YAML format,
 * compatible with Semgrep rule syntax for easy migration.
 * 
 * @module yaml-rule-parser
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * Parse YAML content (simple parser without external dependencies)
 */
function parseYAML(content) {
    const lines = content.split('\n');
    const result = {};
    const stack = [{ obj: result, indent: -1 }];
    let currentArray = null;
    let currentArrayKey = null;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        // Skip empty lines and comments
        if (!trimmed || trimmed.startsWith('#')) continue;

        // Calculate indentation
        const indent = line.search(/\S/);

        // Check for array item
        if (trimmed.startsWith('- ')) {
            const value = trimmed.substring(2).trim();

            // Pop stack to correct level
            while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
                stack.pop();
            }

            const parent = stack[stack.length - 1].obj;
            if (currentArrayKey && Array.isArray(parent[currentArrayKey])) {
                if (value.includes(':')) {
                    const obj = {};
                    const [k, v] = value.split(':').map(s => s.trim());
                    obj[k] = v.replace(/^["']|["']$/g, '');
                    parent[currentArrayKey].push(obj);
                } else {
                    parent[currentArrayKey].push(value.replace(/^["']|["']$/g, ''));
                }
            }
            continue;
        }

        // Check for key: value
        const colonIndex = trimmed.indexOf(':');
        if (colonIndex > 0) {
            const key = trimmed.substring(0, colonIndex).trim();
            const value = trimmed.substring(colonIndex + 1).trim();

            // Pop stack to correct level
            while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
                stack.pop();
            }

            const parent = stack[stack.length - 1].obj;

            if (value === '' || value === '|' || value === '>') {
                // Nested object or multiline
                parent[key] = value === '' ? {} : '';
                if (value === '') {
                    stack.push({ obj: parent[key], indent });
                }
            } else if (value.startsWith('[') && value.endsWith(']')) {
                // Inline array
                parent[key] = value
                    .slice(1, -1)
                    .split(',')
                    .map(s => s.trim().replace(/^["']|["']$/g, ''));
            } else {
                // Simple value
                parent[key] = value.replace(/^["']|["']$/g, '');

                // Check if next line is array
                if (i + 1 < lines.length) {
                    const nextLine = lines[i + 1].trim();
                    if (nextLine.startsWith('- ')) {
                        parent[key] = [];
                        currentArrayKey = key;
                        stack.push({ obj: parent, indent });
                    }
                }
            }
        }
    }

    return result;
}

/**
 * Convert parsed YAML rule to CodeTitan format
 */
function convertToCodeTitanRule(yamlRule) {
    const rule = {
        id: yamlRule.id || `custom/${Date.now()}`,
        severity: mapSeverity(yamlRule.severity),
        message: yamlRule.message || 'Custom rule violation',
        cwe: yamlRule.metadata?.cwe || '',
        category: yamlRule.metadata?.category || 'custom',
        languages: yamlRule.languages || ['javascript'],
        enabled: true,
        source: 'custom-yaml'
    };

    // Convert pattern
    if (yamlRule.pattern) {
        rule.pattern = createPatternMatcher(yamlRule.pattern);
        rule.patternStr = yamlRule.pattern;
    }

    if (yamlRule.patterns) {
        rule.patterns = yamlRule.patterns.map(p => ({
            pattern: p.pattern,
            patternNot: p['pattern-not'],
            patternInside: p['pattern-inside']
        }));
    }

    // Add fix if available
    if (yamlRule.fix) {
        rule.fix = yamlRule.fix;
    }

    // Add metadata
    if (yamlRule.metadata) {
        rule.metadata = {
            ...yamlRule.metadata,
            references: yamlRule.metadata.references || [],
            owasp: yamlRule.metadata.owasp || [],
            confidence: yamlRule.metadata.confidence || 'MEDIUM'
        };
    }

    return rule;
}

/**
 * Map severity levels
 */
function mapSeverity(severity) {
    const mapping = {
        'ERROR': 'CRITICAL',
        'WARNING': 'HIGH',
        'INFO': 'MEDIUM',
        'error': 'CRITICAL',
        'warning': 'HIGH',
        'info': 'MEDIUM',
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW'
    };
    return mapping[severity] || 'MEDIUM';
}

/**
 * Create pattern matcher function from pattern string
 */
function createPatternMatcher(patternStr) {
    // Simple pattern matching - converts Semgrep-like patterns to regex
    let regexStr = patternStr
        // Escape special regex characters
        .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        // Convert ... (ellipsis) to wildcard
        .replace(/\\\.\\\.\\\./g, '[\\s\\S]*?')
        // Convert $VAR to capture group
        .replace(/\\\$([A-Z_][A-Z0-9_]*)/g, '([\\w.]+)');

    try {
        return new RegExp(regexStr, 'gm');
    } catch (e) {
        return null;
    }
}

/**
 * Custom YAML Rule Parser class
 */
class YAMLRuleParser {
    constructor(options = {}) {
        this.rulesDir = options.rulesDir || '.codetitan/rules';
        this.rules = new Map();
        this.loaded = false;
    }

    /**
     * Parse a single YAML rule file
     */
    async parseFile(filePath) {
        const content = await fs.readFile(filePath, 'utf-8');
        const parsed = parseYAML(content);

        const rules = [];

        // Handle single rule or rules array
        if (parsed.rules && Array.isArray(parsed.rules)) {
            for (const rule of parsed.rules) {
                rules.push(convertToCodeTitanRule(rule));
            }
        } else if (parsed.id) {
            rules.push(convertToCodeTitanRule(parsed));
        }

        return rules;
    }

    /**
     * Parse YAML content directly
     */
    parseContent(content) {
        const parsed = parseYAML(content);
        const rules = [];

        if (parsed.rules && Array.isArray(parsed.rules)) {
            for (const rule of parsed.rules) {
                rules.push(convertToCodeTitanRule(rule));
            }
        } else if (parsed.id) {
            rules.push(convertToCodeTitanRule(parsed));
        }

        return rules;
    }

    /**
     * Load all rules from rules directory
     */
    async loadRulesFromDir(dir = null) {
        const rulesDir = dir || this.rulesDir;
        const rules = [];

        try {
            const files = await fs.readdir(rulesDir);
            const yamlFiles = files.filter(f =>
                f.endsWith('.yaml') || f.endsWith('.yml')
            );

            for (const file of yamlFiles) {
                try {
                    const filePath = path.join(rulesDir, file);
                    const fileRules = await this.parseFile(filePath);
                    rules.push(...fileRules);
                } catch (e) {
                    console.warn(`Failed to parse ${file}: ${e.message}`);
                }
            }
        } catch (e) {
            // Directory doesn't exist
        }

        // Store rules
        for (const rule of rules) {
            this.rules.set(rule.id, rule);
        }

        this.loaded = true;
        return rules;
    }

    /**
     * Get loaded rule by ID
     */
    getRule(id) {
        return this.rules.get(id);
    }

    /**
     * Get all loaded rules
     */
    getAllRules() {
        return Array.from(this.rules.values());
    }

    /**
     * Match rules against code
     */
    matchCode(code, language = 'javascript') {
        const findings = [];
        const lines = code.split('\n');

        for (const rule of this.rules.values()) {
            // Check language match
            if (rule.languages && !rule.languages.includes(language)) {
                continue;
            }

            // Check pattern match
            if (rule.pattern) {
                const regex = typeof rule.pattern === 'string'
                    ? createPatternMatcher(rule.pattern)
                    : rule.pattern;

                if (regex) {
                    let match;
                    while ((match = regex.exec(code)) !== null) {
                        const lineNumber = code.substring(0, match.index).split('\n').length;
                        findings.push({
                            ruleId: rule.id,
                            severity: rule.severity,
                            message: rule.message,
                            file: '',
                            line: lineNumber,
                            match: match[0].substring(0, 100),
                            source: 'custom-yaml',
                            fix: rule.fix
                        });
                    }
                }
            }
        }

        return findings;
    }

    /**
     * Validate rule structure
     */
    validateRule(rule) {
        const errors = [];

        if (!rule.id) {
            errors.push('Rule must have an id');
        }

        if (!rule.message) {
            errors.push('Rule must have a message');
        }

        if (!rule.pattern && !rule.patterns) {
            errors.push('Rule must have a pattern or patterns');
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }
}

/**
 * Example YAML rule format
 */
const EXAMPLE_RULE = `
# CodeTitan Custom Rule Format (Semgrep-compatible)
rules:
  - id: custom/hardcoded-password
    severity: ERROR
    message: Hardcoded password detected
    languages: [javascript, typescript]
    pattern: password = "$PASSWORD"
    metadata:
      category: security
      cwe: CWE-798
      owasp: [A07:2021]
      confidence: HIGH
    fix: "Use environment variables instead"
`;

module.exports = {
    YAMLRuleParser,
    parseYAML,
    convertToCodeTitanRule,
    createPatternMatcher,
    EXAMPLE_RULE
};
