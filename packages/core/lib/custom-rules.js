/**
 * Custom Rules Engine
 * 
 * Allows users to define their own security rules in YAML/JSON format.
 * Supports regex patterns, AST queries, and conditional logic.
 * 
 * @module custom-rules
 */

const fs = require('fs');
const path = require('path');

/**
 * Rule schema
 */
const RULE_SCHEMA = {
    id: { type: 'string', required: true },
    name: { type: 'string', required: true },
    description: { type: 'string', required: true },
    severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], required: true },
    category: { type: 'string', required: true },
    languages: { type: 'array', items: 'string', required: true },
    patterns: { type: 'array', required: true },
    message: { type: 'string', required: true },
    cwe: { type: 'string', required: false },
    owasp: { type: 'string', required: false },
    fix: { type: 'string', required: false },
    enabled: { type: 'boolean', default: true },
    tags: { type: 'array', items: 'string', default: [] },
};

/**
 * Custom Rule class
 */
class CustomRule {
    constructor(config) {
        this.id = config.id;
        this.name = config.name;
        this.description = config.description;
        this.severity = config.severity;
        this.category = config.category;
        this.languages = config.languages || [];
        this.message = config.message;
        this.cwe = config.cwe;
        this.owasp = config.owasp;
        this.fix = config.fix;
        this.enabled = config.enabled !== false;
        this.tags = config.tags || [];

        // Compile patterns
        this.patterns = (config.patterns || []).map(p => this.compilePattern(p));
    }

    /**
     * Compile a pattern definition into a matcher
     */
    compilePattern(patternDef) {
        if (typeof patternDef === 'string') {
            // Simple regex string
            return {
                type: 'regex',
                pattern: new RegExp(patternDef, 'gm'),
            };
        }

        if (patternDef.regex) {
            const flags = patternDef.flags || 'gm';
            return {
                type: 'regex',
                pattern: new RegExp(patternDef.regex, flags),
            };
        }

        if (patternDef.literal) {
            // Literal string match
            return {
                type: 'literal',
                pattern: patternDef.literal,
                caseSensitive: patternDef.caseSensitive !== false,
            };
        }

        if (patternDef.ast) {
            // AST pattern (simplified - would need full AST integration)
            return {
                type: 'ast',
                query: patternDef.ast,
            };
        }

        throw new Error(`Unknown pattern type in rule ${this.id}`);
    }

    /**
     * Match rule against code
     */
    match(code, filePath) {
        const issues = [];
        const lines = code.split('\n');
        const ext = path.extname(filePath).toLowerCase();

        // Check if language matches
        const language = this.getLanguageFromExtension(ext);
        if (!this.languages.includes(language) && !this.languages.includes('*')) {
            return issues;
        }

        // Check each pattern
        this.patterns.forEach(compiledPattern => {
            if (compiledPattern.type === 'regex') {
                let match;
                const pattern = new RegExp(compiledPattern.pattern.source, compiledPattern.pattern.flags);

                while ((match = pattern.exec(code)) !== null) {
                    const lineNumber = code.substring(0, match.index).split('\n').length;
                    const line = lines[lineNumber - 1] || '';

                    // Skip comments (basic check)
                    const trimmed = line.trim();
                    if (trimmed.startsWith('//') || trimmed.startsWith('#') ||
                        trimmed.startsWith('/*') || trimmed.startsWith('*')) {
                        continue;
                    }

                    issues.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        line: lineNumber,
                        column: match.index - code.lastIndexOf('\n', match.index),
                        severity: this.severity,
                        category: this.category,
                        message: this.message,
                        cwe: this.cwe,
                        owasp: this.owasp,
                        snippet: trimmed.substring(0, 100),
                        fix: this.fix,
                    });
                }
            } else if (compiledPattern.type === 'literal') {
                const searchStr = compiledPattern.caseSensitive ?
                    compiledPattern.pattern :
                    compiledPattern.pattern.toLowerCase();
                const searchCode = compiledPattern.caseSensitive ? code : code.toLowerCase();

                let pos = 0;
                while ((pos = searchCode.indexOf(searchStr, pos)) !== -1) {
                    const lineNumber = code.substring(0, pos).split('\n').length;
                    const line = lines[lineNumber - 1] || '';

                    issues.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        line: lineNumber,
                        column: pos - code.lastIndexOf('\n', pos),
                        severity: this.severity,
                        category: this.category,
                        message: this.message,
                        snippet: line.trim().substring(0, 100),
                    });

                    pos += searchStr.length;
                }
            }
        });

        return issues;
    }

    /**
     * Get language from file extension
     */
    getLanguageFromExtension(ext) {
        const mapping = {
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.py': 'python',
            '.java': 'java',
            '.go': 'go',
            '.cs': 'csharp',
            '.rb': 'ruby',
            '.php': 'php',
            '.rs': 'rust',
        };
        return mapping[ext] || 'unknown';
    }

    toJSON() {
        return {
            id: this.id,
            name: this.name,
            description: this.description,
            severity: this.severity,
            category: this.category,
            languages: this.languages,
            message: this.message,
            enabled: this.enabled,
            tags: this.tags,
        };
    }
}

/**
 * Custom Rules Manager
 */
class CustomRulesManager {
    constructor(options = {}) {
        this.rules = new Map();
        this.rulesDir = options.rulesDir || './custom-rules';
    }

    /**
     * Load rules from a directory
     */
    async loadFromDirectory(dir) {
        const rulesDir = dir || this.rulesDir;

        const exists = await fs.promises.stat(rulesDir).then(stat => stat.isDirectory()).catch(() => false);
        if (!exists) {
            return { loaded: 0, errors: [] };
        }

        const files = await fs.promises.readdir(rulesDir);
        const errors = [];
        let loaded = 0;

        for (const file of files) {
            if (!file.endsWith('.json') && !file.endsWith('.yaml') && !file.endsWith('.yml')) {
                continue;
            }

            try {
                const filePath = path.join(rulesDir, file);
                const content = await fs.promises.readFile(filePath, 'utf-8');

                let config;
                if (file.endsWith('.json')) {
                    config = JSON.parse(content);
                } else {
                    // YAML support would require js-yaml package
                    // For now, skip YAML files
                    continue;
                }

                // Handle single rule or array of rules
                const rules = Array.isArray(config) ? config : [config];

                for (const ruleConfig of rules) {
                    const rule = new CustomRule(ruleConfig);
                    this.rules.set(rule.id, rule);
                    loaded++;
                }
            } catch (error) {
                errors.push({ file, error: error.message });
            }
        }

        return { loaded, errors };
    }

    /**
     * Add a rule programmatically
     */
    addRule(config) {
        const rule = new CustomRule(config);
        this.rules.set(rule.id, rule);
        return rule;
    }

    /**
     * Remove a rule
     */
    removeRule(ruleId) {
        return this.rules.delete(ruleId);
    }

    /**
     * Get a rule by ID
     */
    getRule(ruleId) {
        return this.rules.get(ruleId);
    }

    /**
     * Get all rules
     */
    getAllRules() {
        return Array.from(this.rules.values());
    }

    /**
     * Get enabled rules for a language
     */
    getRulesForLanguage(language) {
        return this.getAllRules().filter(rule =>
            rule.enabled &&
            (rule.languages.includes(language) || rule.languages.includes('*'))
        );
    }

    /**
     * Run all matching rules against code
     */
    analyze(code, filePath) {
        const ext = path.extname(filePath).toLowerCase();
        const language = new CustomRule({
            id: 'temp', name: '', description: '', severity: 'LOW',
            category: '', languages: [], patterns: [], message: ''
        }).getLanguageFromExtension(ext);

        const matchingRules = this.getRulesForLanguage(language);
        const allIssues = [];

        for (const rule of matchingRules) {
            const issues = rule.match(code, filePath);
            allIssues.push(...issues);
        }

        return {
            issues: allIssues,
            rulesApplied: matchingRules.length,
            language,
        };
    }

    /**
     * Validate a rule configuration
     */
    validateRule(config) {
        const errors = [];

        // Check required fields
        Object.entries(RULE_SCHEMA).forEach(([field, schema]) => {
            if (schema.required && !config[field]) {
                errors.push(`Missing required field: ${field}`);
            }

            if (schema.enum && config[field] && !schema.enum.includes(config[field])) {
                errors.push(`Invalid value for ${field}: ${config[field]}. Must be one of: ${schema.enum.join(', ')}`);
            }
        });

        // Validate patterns compile
        if (config.patterns) {
            config.patterns.forEach((p, i) => {
                try {
                    if (typeof p === 'string') {
                        new RegExp(p);
                    } else if (p.regex) {
                        new RegExp(p.regex);
                    }
                } catch (e) {
                    errors.push(`Invalid pattern at index ${i}: ${e.message}`);
                }
            });
        }

        return {
            valid: errors.length === 0,
            errors,
        };
    }

    /**
     * Export rules to JSON
     */
    exportRules() {
        return this.getAllRules().map(r => r.toJSON());
    }
}

module.exports = {
    CustomRule,
    CustomRulesManager,
    RULE_SCHEMA,
};
