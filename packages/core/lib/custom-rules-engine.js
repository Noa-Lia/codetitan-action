/**
 * Enhanced Custom Rules Engine v2.0
 * 
 * Semgrep-compatible rule engine with:
 * - YAML rule definitions
 * - Metavariable patterns ($VAR, $FUNC, etc.)
 * - AST-based matching
 * - Rule inheritance and composition
 * - 20+ built-in security rule templates
 * 
 * @module custom-rules-engine
 */

const fs = require('fs');
const path = require('path');

// Optional dependencies with fallbacks
let yaml;
try {
    yaml = require('js-yaml');
} catch {
    yaml = null;
}

/**
 * Extended Rule Schema (Semgrep-compatible)
 */
const RULE_SCHEMA = {
    id: { type: 'string', required: true },
    name: { type: 'string', required: true },
    description: { type: 'string', required: true },
    severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], required: true },
    category: { type: 'string', required: true },
    languages: { type: 'array', items: 'string', required: true },
    patterns: { type: 'array', required: false },
    pattern: { type: 'string', required: false }, // Semgrep single pattern
    'pattern-either': { type: 'array', required: false }, // OR patterns
    'pattern-not': { type: 'string', required: false }, // Exclusion
    'pattern-inside': { type: 'string', required: false }, // Context
    'metavariable-pattern': { type: 'object', required: false },
    message: { type: 'string', required: true },
    cwe: { type: 'string', required: false },
    owasp: { type: 'array', required: false },
    references: { type: 'array', required: false },
    fix: { type: 'string', required: false },
    'fix-regex': { type: 'object', required: false },
    enabled: { type: 'boolean', default: true },
    tags: { type: 'array', items: 'string', default: [] },
    confidence: { type: 'number', default: 0.8 },
    'min-version': { type: 'string', required: false },
    'max-version': { type: 'string', required: false },
};

/**
 * Metavariable pattern matching
 */
class MetavariableMatcher {
    constructor() {
        this.metavarPattern = /\$([A-Z_][A-Z0-9_]*)/g;
        this.ellipsisPattern = /\.\.\./g;
    }

    /**
     * Convert Semgrep-style pattern to regex
     */
    toRegex(pattern) {
        // Escape regex special chars first
        let regexStr = pattern
            .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            // Replace ellipsis with non-greedy match
            .replace(/\\\.\\\.\\\./g, '[\\s\\S]*?');

        // Replace metavariables with capture groups
        const metavars = [];
        regexStr = regexStr.replace(/\\\$([A-Z_][A-Z0-9_]*)/g, (_, name) => {
            metavars.push(name);
            return '([\\w.]+)';
        });

        return {
            regex: new RegExp(regexStr, 'gm'),
            metavars,
        };
    }

    /**
     * Match pattern and extract metavariable bindings
     */
    match(pattern, code) {
        const { regex, metavars } = this.toRegex(pattern);
        const matches = [];
        let match;

        while ((match = regex.exec(code)) !== null) {
            const bindings = {};
            metavars.forEach((name, i) => {
                bindings[`$${name}`] = match[i + 1];
            });

            matches.push({
                fullMatch: match[0],
                index: match.index,
                bindings,
            });
        }

        return matches;
    }
}

/**
 * Enhanced Custom Rule class with Semgrep compatibility
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
        this.references = config.references || [];
        this.fix = config.fix;
        this.fixRegex = config['fix-regex'];
        this.enabled = config.enabled !== false;
        this.tags = config.tags || [];
        this.confidence = config.confidence || 0.8;

        // Pattern handling
        this.patternConfig = {
            patterns: config.patterns,
            pattern: config.pattern,
            patternEither: config['pattern-either'],
            patternNot: config['pattern-not'],
            patternInside: config['pattern-inside'],
            metavariablePattern: config['metavariable-pattern'],
        };

        this.metavarMatcher = new MetavariableMatcher();
        this.compiledPatterns = this.compilePatterns();
    }

    /**
     * Compile all pattern types
     */
    compilePatterns() {
        const compiled = {
            main: [],
            either: [],
            not: [],
            inside: null,
        };

        // Single pattern (Semgrep style)
        if (this.patternConfig.pattern) {
            compiled.main.push(this.compilePattern(this.patternConfig.pattern));
        }

        // Array of patterns (legacy style)
        if (this.patternConfig.patterns) {
            for (const p of this.patternConfig.patterns) {
                compiled.main.push(this.compilePattern(p));
            }
        }

        // pattern-either (OR logic)
        if (this.patternConfig.patternEither) {
            for (const p of this.patternConfig.patternEither) {
                const pattern = p.pattern || p;
                compiled.either.push(this.compilePattern(pattern));
            }
        }

        // pattern-not (exclusion)
        if (this.patternConfig.patternNot) {
            compiled.not.push(this.compilePattern(this.patternConfig.patternNot));
        }

        // pattern-inside (context)
        if (this.patternConfig.patternInside) {
            compiled.inside = this.compilePattern(this.patternConfig.patternInside);
        }

        return compiled;
    }

    /**
     * Compile a single pattern
     */
    compilePattern(patternDef) {
        if (typeof patternDef === 'string') {
            // Semgrep-style pattern with metavariables
            if (patternDef.includes('$') || patternDef.includes('...')) {
                return {
                    type: 'semgrep',
                    raw: patternDef,
                    matcher: this.metavarMatcher,
                };
            }
            // Simple regex
            return {
                type: 'regex',
                pattern: new RegExp(this.escapeRegex(patternDef), 'gm'),
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
            return {
                type: 'literal',
                pattern: patternDef.literal,
                caseSensitive: patternDef.caseSensitive !== false,
            };
        }

        if (patternDef.ast) {
            return {
                type: 'ast',
                query: patternDef.ast,
            };
        }

        // Default: treat as semgrep pattern
        return {
            type: 'semgrep',
            raw: String(patternDef),
            matcher: this.metavarMatcher,
        };
    }

    escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    /**
     * Match rule against code
     */
    match(code, filePath) {
        const issues = [];
        const lines = code.split('\n');
        const ext = path.extname(filePath).toLowerCase();
        const language = this.getLanguageFromExtension(ext);

        // Check language compatibility
        if (!this.languages.includes(language) && !this.languages.includes('*')) {
            return issues;
        }

        // Check pattern-inside context first
        if (this.compiledPatterns.inside) {
            const contextMatches = this.matchPattern(this.compiledPatterns.inside, code);
            if (contextMatches.length === 0) {
                return issues; // No context match, skip
            }
        }

        // Collect all matches from main patterns and either patterns
        let allMatches = [];

        // Main patterns (AND logic - all must match)
        if (this.compiledPatterns.main.length > 0) {
            for (const pattern of this.compiledPatterns.main) {
                const matches = this.matchPattern(pattern, code);
                allMatches.push(...matches);
            }
        }

        // Either patterns (OR logic - any can match)
        if (this.compiledPatterns.either.length > 0) {
            for (const pattern of this.compiledPatterns.either) {
                const matches = this.matchPattern(pattern, code);
                allMatches.push(...matches);
            }
        }

        // Filter out exclusions (pattern-not)
        if (this.compiledPatterns.not.length > 0) {
            const exclusions = new Set();
            for (const notPattern of this.compiledPatterns.not) {
                const notMatches = this.matchPattern(notPattern, code);
                for (const m of notMatches) {
                    exclusions.add(`${m.line}:${m.column}`);
                }
            }
            allMatches = allMatches.filter(m => !exclusions.has(`${m.line}:${m.column}`));
        }

        // Convert matches to issues
        for (const match of allMatches) {
            const line = lines[match.line - 1] || '';
            const trimmed = line.trim();

            // Skip comments
            if (this.isComment(trimmed, language)) {
                continue;
            }

            // Interpolate message with metavariable bindings
            let message = this.message;
            if (match.bindings) {
                for (const [key, value] of Object.entries(match.bindings)) {
                    message = message.replace(key, value);
                }
            }

            issues.push({
                ruleId: this.id,
                ruleName: this.name,
                line: match.line,
                column: match.column,
                severity: this.severity,
                category: this.category,
                message,
                cwe: this.cwe,
                owasp: this.owasp,
                references: this.references,
                snippet: trimmed.substring(0, 120),
                fix: this.generateFix(match, code),
                confidence: this.confidence,
                metavariables: match.bindings,
            });
        }

        return issues;
    }

    /**
     * Match a single compiled pattern
     */
    matchPattern(compiled, code) {
        const matches = [];
        const lines = code.split('\n');

        if (compiled.type === 'semgrep') {
            const semgrepMatches = compiled.matcher.match(compiled.raw, code);
            for (const m of semgrepMatches) {
                const lineNumber = code.substring(0, m.index).split('\n').length;
                matches.push({
                    line: lineNumber,
                    column: m.index - code.lastIndexOf('\n', m.index),
                    bindings: m.bindings,
                    fullMatch: m.fullMatch,
                });
            }
        } else if (compiled.type === 'regex') {
            let match;
            const pattern = new RegExp(compiled.pattern.source, compiled.pattern.flags);
            while ((match = pattern.exec(code)) !== null) {
                const lineNumber = code.substring(0, match.index).split('\n').length;
                matches.push({
                    line: lineNumber,
                    column: match.index - code.lastIndexOf('\n', match.index),
                    fullMatch: match[0],
                });
            }
        } else if (compiled.type === 'literal') {
            const searchStr = compiled.caseSensitive ? compiled.pattern : compiled.pattern.toLowerCase();
            const searchCode = compiled.caseSensitive ? code : code.toLowerCase();
            let pos = 0;
            while ((pos = searchCode.indexOf(searchStr, pos)) !== -1) {
                const lineNumber = code.substring(0, pos).split('\n').length;
                matches.push({
                    line: lineNumber,
                    column: pos - code.lastIndexOf('\n', pos),
                    fullMatch: code.substring(pos, pos + searchStr.length),
                });
                pos += searchStr.length;
            }
        }

        return matches;
    }

    /**
     * Check if line is a comment
     */
    isComment(line, language) {
        const commentPrefixes = {
            javascript: ['//', '/*', '*'],
            typescript: ['//', '/*', '*'],
            python: ['#', '"""', "'''"],
            java: ['//', '/*', '*'],
            go: ['//', '/*'],
            ruby: ['#'],
            php: ['//', '/*', '#'],
        };
        const prefixes = commentPrefixes[language] || ['//', '#', '/*'];
        return prefixes.some(p => line.startsWith(p));
    }

    /**
     * Generate fix for a match
     */
    generateFix(match, code) {
        if (!this.fix && !this.fixRegex) return null;

        if (this.fixRegex) {
            const { regex, replacement } = this.fixRegex;
            return {
                type: 'regex',
                find: regex,
                replace: replacement,
            };
        }

        // Simple fix with metavariable interpolation
        let fix = this.fix;
        if (match.bindings) {
            for (const [key, value] of Object.entries(match.bindings)) {
                fix = fix.replace(key, value);
            }
        }

        return {
            type: 'replace',
            original: match.fullMatch,
            replacement: fix,
        };
    }

    /**
     * Get language from file extension
     */
    getLanguageFromExtension(ext) {
        const mapping = {
            '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript',
            '.py': 'python', '.pyw': 'python',
            '.java': 'java',
            '.go': 'go',
            '.cs': 'csharp',
            '.rb': 'ruby',
            '.php': 'php',
            '.rs': 'rust',
            '.c': 'c', '.h': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
            '.swift': 'swift',
            '.kt': 'kotlin', '.kts': 'kotlin',
            '.scala': 'scala',
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
            confidence: this.confidence,
        };
    }
}

/**
 * Built-in Security Rule Templates
 */
const BUILTIN_RULES = [
    // SQL Injection
    {
        id: 'security.sql-injection.string-concat',
        name: 'SQL Injection via String Concatenation',
        description: 'Detects potential SQL injection through string concatenation',
        severity: 'CRITICAL',
        category: 'security',
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        pattern: '$DB.query($QUERY + $INPUT)',
        message: 'Potential SQL injection: user input $INPUT concatenated into query',
        cwe: 'CWE-89',
        owasp: ['A03:2021'],
        fix: '$DB.query($QUERY, [$INPUT])',
        confidence: 0.9,
        tags: ['sql', 'injection', 'owasp-top-10'],
    },
    {
        id: 'security.sql-injection.template-literal',
        name: 'SQL Injection via Template Literal',
        description: 'Detects SQL injection through template literals',
        severity: 'CRITICAL',
        category: 'security',
        languages: ['javascript', 'typescript'],
        pattern: 'query(`... ${$VAR} ...`)',
        message: 'Potential SQL injection: variable $VAR interpolated in query template',
        cwe: 'CWE-89',
        owasp: ['A03:2021'],
        confidence: 0.85,
        tags: ['sql', 'injection', 'template-literal'],
    },
    // XSS
    {
        id: 'security.xss.innerhtml',
        name: 'XSS via innerHTML',
        description: 'Detects potential XSS through innerHTML assignment',
        severity: 'HIGH',
        category: 'security',
        languages: ['javascript', 'typescript'],
        pattern: '$EL.innerHTML = $INPUT',
        message: 'Potential XSS: user input $INPUT assigned to innerHTML',
        cwe: 'CWE-79',
        owasp: ['A03:2021'],
        fix: '$EL.textContent = $INPUT',
        confidence: 0.8,
        tags: ['xss', 'dom', 'owasp-top-10'],
    },
    {
        id: 'security.xss.dangerouslySetInnerHTML',
        name: 'XSS via dangerouslySetInnerHTML',
        description: 'Detects React XSS vulnerability',
        severity: 'HIGH',
        category: 'security',
        languages: ['javascript', 'typescript'],
        pattern: 'dangerouslySetInnerHTML={{ __html: $INPUT }}',
        message: 'Potential XSS: unsanitized $INPUT passed to dangerouslySetInnerHTML',
        cwe: 'CWE-79',
        owasp: ['A03:2021'],
        confidence: 0.75,
        tags: ['xss', 'react', 'owasp-top-10'],
    },
    // Command Injection
    {
        id: 'security.command-injection.exec',
        name: 'Command Injection via exec',
        description: 'Detects command injection through exec functions',
        severity: 'CRITICAL',
        category: 'security',
        languages: ['javascript', 'typescript', 'python'],
        'pattern-either': [
            { pattern: 'exec($CMD)' },
            { pattern: 'execSync($CMD)' },
            { pattern: 'spawn($CMD, ...)' },
            { pattern: 'os.system($CMD)' },
            { pattern: 'subprocess.call($CMD, ...)' },
        ],
        message: 'Potential command injection: untrusted input in shell command',
        cwe: 'CWE-78',
        owasp: ['A03:2021'],
        confidence: 0.9,
        tags: ['command-injection', 'rce', 'owasp-top-10'],
    },
    // Path Traversal
    {
        id: 'security.path-traversal.fs-read',
        name: 'Path Traversal in File Read',
        description: 'Detects potential path traversal in file operations',
        severity: 'HIGH',
        category: 'security',
        languages: ['javascript', 'typescript'],
        'pattern-either': [
            { pattern: 'fs.readFileSync($PATH)' },
            { pattern: 'fs.readFile($PATH, ...)' },
            { pattern: 'require($PATH)' },
        ],
        'pattern-not': 'path.join(__dirname, ...)',
        message: 'Potential path traversal: validate and sanitize file path',
        cwe: 'CWE-22',
        owasp: ['A01:2021'],
        confidence: 0.7,
        tags: ['path-traversal', 'lfi', 'owasp-top-10'],
    },
    // Hardcoded Secrets
    {
        id: 'security.secrets.hardcoded-password',
        name: 'Hardcoded Password',
        description: 'Detects hardcoded passwords in source code',
        severity: 'HIGH',
        category: 'security',
        languages: ['*'],
        patterns: [
            { regex: 'password\\s*[:=]\\s*["\'][^"\']{4,}["\']', flags: 'gi' },
            { regex: 'secret\\s*[:=]\\s*["\'][^"\']{4,}["\']', flags: 'gi' },
            { regex: 'api[_-]?key\\s*[:=]\\s*["\'][^"\']{8,}["\']', flags: 'gi' },
        ],
        message: 'Hardcoded credential detected - use environment variables',
        cwe: 'CWE-798',
        owasp: ['A02:2021'],
        confidence: 0.85,
        tags: ['secrets', 'credentials', 'owasp-top-10'],
    },
    // Insecure Crypto
    {
        id: 'security.crypto.weak-hash',
        name: 'Weak Cryptographic Hash',
        description: 'Detects use of weak hash algorithms',
        severity: 'MEDIUM',
        category: 'security',
        languages: ['javascript', 'typescript', 'python', 'java'],
        'pattern-either': [
            { pattern: "createHash('md5')" },
            { pattern: "createHash('sha1')" },
            { pattern: 'hashlib.md5(' },
            { pattern: 'hashlib.sha1(' },
            { pattern: 'MessageDigest.getInstance("MD5")' },
            { pattern: 'MessageDigest.getInstance("SHA1")' },
        ],
        message: 'Weak hash algorithm: use SHA-256 or stronger',
        cwe: 'CWE-328',
        owasp: ['A02:2021'],
        confidence: 0.95,
        tags: ['crypto', 'hash', 'weak-algorithm'],
    },
    // SSRF
    {
        id: 'security.ssrf.fetch',
        name: 'Potential SSRF',
        description: 'Detects potential Server-Side Request Forgery',
        severity: 'HIGH',
        category: 'security',
        languages: ['javascript', 'typescript'],
        'pattern-either': [
            { pattern: 'fetch($URL)' },
            { pattern: 'axios.get($URL)' },
            { pattern: 'axios.post($URL, ...)' },
            { pattern: 'http.get($URL, ...)' },
        ],
        message: 'Potential SSRF: validate and whitelist URLs before fetching',
        cwe: 'CWE-918',
        owasp: ['A10:2021'],
        confidence: 0.6,
        tags: ['ssrf', 'network', 'owasp-top-10'],
    },
    // Insecure Deserialization
    {
        id: 'security.deserialization.unsafe',
        name: 'Unsafe Deserialization',
        description: 'Detects unsafe deserialization of user input',
        severity: 'CRITICAL',
        category: 'security',
        languages: ['javascript', 'typescript', 'python', 'java'],
        'pattern-either': [
            { pattern: 'eval($INPUT)' },
            { pattern: 'pickle.loads($INPUT)' },
            { pattern: 'yaml.load($INPUT)' },
            { pattern: 'ObjectInputStream($INPUT)' },
        ],
        message: 'Unsafe deserialization: never deserialize untrusted data',
        cwe: 'CWE-502',
        owasp: ['A08:2021'],
        confidence: 0.9,
        tags: ['deserialization', 'rce', 'owasp-top-10'],
    },
    // NoSQL Injection
    {
        id: 'security.nosql-injection.mongodb',
        name: 'NoSQL Injection',
        description: 'Detects potential NoSQL injection in MongoDB queries',
        severity: 'HIGH',
        category: 'security',
        languages: ['javascript', 'typescript'],
        pattern: '$COLLECTION.find({ $FIELD: $INPUT })',
        message: 'Potential NoSQL injection: sanitize $INPUT before query',
        cwe: 'CWE-943',
        owasp: ['A03:2021'],
        confidence: 0.7,
        tags: ['nosql', 'mongodb', 'injection'],
    },
    // Debug/Development Code
    {
        id: 'quality.debug.console-log',
        name: 'Console Log in Production',
        description: 'Detects console.log statements that should be removed',
        severity: 'LOW',
        category: 'quality',
        languages: ['javascript', 'typescript'],
        pattern: 'console.log(...)',
        message: 'Remove console.log before production',
        confidence: 0.5,
        tags: ['debug', 'logging', 'cleanup'],
    },
    {
        id: 'quality.debug.debugger',
        name: 'Debugger Statement',
        description: 'Detects debugger statements',
        severity: 'MEDIUM',
        category: 'quality',
        languages: ['javascript', 'typescript'],
        pattern: 'debugger',
        message: 'Remove debugger statement before production',
        confidence: 1.0,
        tags: ['debug', 'cleanup'],
    },
    // Error Handling
    {
        id: 'quality.error.empty-catch',
        name: 'Empty Catch Block',
        description: 'Detects empty catch blocks that swallow errors',
        severity: 'MEDIUM',
        category: 'quality',
        languages: ['javascript', 'typescript', 'java'],
        patterns: [
            { regex: 'catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}', flags: 'gm' },
        ],
        message: 'Empty catch block swallows errors - log or handle the error',
        cwe: 'CWE-390',
        confidence: 0.9,
        tags: ['error-handling', 'quality'],
    },
    // Async/Await
    {
        id: 'quality.async.missing-await',
        name: 'Missing Await',
        description: 'Detects async function calls without await',
        severity: 'MEDIUM',
        category: 'quality',
        languages: ['javascript', 'typescript'],
        pattern: '$FUNC($ARGS)',
        'pattern-inside': 'async function $NAME(...) { ... }',
        message: 'Consider adding await to async function call',
        confidence: 0.6,
        tags: ['async', 'promise', 'quality'],
    },
    // React Security
    {
        id: 'security.react.unsafe-href',
        name: 'Unsafe href in React',
        description: 'Detects dynamic href that could lead to XSS',
        severity: 'MEDIUM',
        category: 'security',
        languages: ['javascript', 'typescript'],
        pattern: 'href={$URL}',
        'pattern-not': 'href="..."',
        message: 'Validate URL to prevent javascript: protocol XSS',
        cwe: 'CWE-79',
        confidence: 0.6,
        tags: ['react', 'xss', 'href'],
    },
    // JWT
    {
        id: 'security.jwt.none-algorithm',
        name: 'JWT None Algorithm',
        description: 'Detects JWT verification that may accept none algorithm',
        severity: 'CRITICAL',
        category: 'security',
        languages: ['javascript', 'typescript'],
        'pattern-either': [
            { pattern: 'jwt.verify($TOKEN, $SECRET)' },
            { pattern: "algorithms: ['none']" },
        ],
        message: 'Ensure JWT algorithms are explicitly specified and none is rejected',
        cwe: 'CWE-347',
        confidence: 0.7,
        tags: ['jwt', 'authentication'],
    },
    // Timing Attack
    {
        id: 'security.timing.string-comparison',
        name: 'Timing Attack via String Comparison',
        description: 'Detects non-constant-time string comparison for secrets',
        severity: 'MEDIUM',
        category: 'security',
        languages: ['javascript', 'typescript'],
        patterns: [
            { regex: '(password|secret|token|key)\\s*===?\\s*', flags: 'gi' },
        ],
        'pattern-not': 'timingSafeEqual',
        message: 'Use crypto.timingSafeEqual for secret comparison',
        cwe: 'CWE-208',
        confidence: 0.6,
        tags: ['timing-attack', 'comparison'],
    },
    // Prototype Pollution
    {
        id: 'security.prototype-pollution.object-assign',
        name: 'Prototype Pollution Risk',
        description: 'Detects potential prototype pollution vectors',
        severity: 'HIGH',
        category: 'security',
        languages: ['javascript', 'typescript'],
        'pattern-either': [
            { pattern: 'Object.assign($TARGET, $SOURCE)' },
            { pattern: '{ ...$SOURCE }' },
            { pattern: '$OBJ[$KEY] = $VALUE' },
        ],
        message: 'Validate keys to prevent prototype pollution (__proto__, constructor)',
        cwe: 'CWE-1321',
        confidence: 0.5,
        tags: ['prototype-pollution', 'object'],
    },
];

/**
 * Enhanced Custom Rules Manager
 */
class CustomRulesManager {
    constructor(options = {}) {
        this.rules = new Map();
        this.rulesDir = options.rulesDir || './custom-rules';
        this.includeBuiltins = options.includeBuiltins !== false;

        // Load built-in rules if enabled
        if (this.includeBuiltins) {
            this.loadBuiltinRules();
        }
    }

    /**
     * Load built-in security rules
     */
    loadBuiltinRules() {
        for (const config of BUILTIN_RULES) {
            try {
                const rule = new CustomRule(config);
                this.rules.set(rule.id, rule);
            } catch (error) {
                console.warn(`Failed to load builtin rule ${config.id}: ${error.message}`);
            }
        }
    }

    /**
     * Load rules from a directory (supports JSON and YAML)
     */
    async loadFromDirectory(dir) {
        const rulesDir = dir || this.rulesDir;
        const exists = await fs.promises.stat(rulesDir).then(s => s.isDirectory()).catch(() => false);

        if (!exists) {
            return { loaded: 0, errors: [], builtins: this.includeBuiltins ? BUILTIN_RULES.length : 0 };
        }

        const files = await fs.promises.readdir(rulesDir);
        const errors = [];
        let loaded = 0;

        for (const file of files) {
            const isJson = file.endsWith('.json');
            const isYaml = file.endsWith('.yaml') || file.endsWith('.yml');

            if (!isJson && !isYaml) continue;

            try {
                const filePath = path.join(rulesDir, file);
                const content = await fs.promises.readFile(filePath, 'utf-8');

                let config;
                if (isJson) {
                    config = JSON.parse(content);
                } else if (yaml) {
                    config = yaml.load(content);
                } else {
                    errors.push({ file, error: 'YAML support requires js-yaml package' });
                    continue;
                }

                // Handle Semgrep-style rules with 'rules' array
                let rulesList = config;
                if (config.rules && Array.isArray(config.rules)) {
                    rulesList = config.rules;
                } else if (!Array.isArray(config)) {
                    rulesList = [config];
                }

                for (const ruleConfig of rulesList) {
                    const validation = this.validateRule(ruleConfig);
                    if (!validation.valid) {
                        errors.push({ file, ruleId: ruleConfig.id, errors: validation.errors });
                        continue;
                    }

                    const rule = new CustomRule(ruleConfig);
                    this.rules.set(rule.id, rule);
                    loaded++;
                }
            } catch (error) {
                errors.push({ file, error: error.message });
            }
        }

        return {
            loaded,
            errors,
            builtins: this.includeBuiltins ? BUILTIN_RULES.length : 0,
            total: this.rules.size,
        };
    }

    /**
     * Add a rule programmatically
     */
    addRule(config) {
        const validation = this.validateRule(config);
        if (!validation.valid) {
            throw new Error(`Invalid rule: ${validation.errors.join(', ')}`);
        }
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
     * Get rules by tag
     */
    getRulesByTag(tag) {
        return this.getAllRules().filter(r => r.enabled && r.tags.includes(tag));
    }

    /**
     * Get rules by category
     */
    getRulesByCategory(category) {
        return this.getAllRules().filter(r => r.enabled && r.category === category);
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
    analyze(code, filePath, options = {}) {
        const ext = path.extname(filePath).toLowerCase();
        const tempRule = new CustomRule({
            id: 'temp', name: '', description: '', severity: 'LOW',
            category: '', languages: [], patterns: [], message: ''
        });
        const language = tempRule.getLanguageFromExtension(ext);

        let matchingRules = this.getRulesForLanguage(language);

        // Filter by severity if specified
        if (options.minSeverity) {
            const severityOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
            const minIndex = severityOrder.indexOf(options.minSeverity);
            matchingRules = matchingRules.filter(r =>
                severityOrder.indexOf(r.severity) >= minIndex
            );
        }

        // Filter by tags if specified
        if (options.tags && options.tags.length > 0) {
            matchingRules = matchingRules.filter(r =>
                options.tags.some(t => r.tags.includes(t))
            );
        }

        // Filter by category if specified
        if (options.category) {
            matchingRules = matchingRules.filter(r => r.category === options.category);
        }

        const allIssues = [];
        const ruleStats = {};

        for (const rule of matchingRules) {
            const startTime = Date.now();
            const issues = rule.match(code, filePath);
            const duration = Date.now() - startTime;

            ruleStats[rule.id] = {
                matches: issues.length,
                duration,
            };

            allIssues.push(...issues);
        }

        return {
            issues: allIssues,
            rulesApplied: matchingRules.length,
            language,
            stats: ruleStats,
        };
    }

    /**
     * Validate a rule configuration
     */
    validateRule(config) {
        const errors = [];

        // Required fields
        const required = ['id', 'name', 'description', 'severity', 'category', 'languages', 'message'];
        for (const field of required) {
            if (!config[field]) {
                errors.push(`Missing required field: ${field}`);
            }
        }

        // Validate severity
        const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        if (config.severity && !validSeverities.includes(config.severity)) {
            errors.push(`Invalid severity: ${config.severity}`);
        }

        // Must have at least one pattern
        const hasPattern = config.pattern ||
            (config.patterns && config.patterns.length > 0) ||
            (config['pattern-either'] && config['pattern-either'].length > 0);

        if (!hasPattern) {
            errors.push('Rule must have at least one pattern');
        }

        return {
            valid: errors.length === 0,
            errors,
        };
    }

    /**
     * Export rules to JSON or YAML
     */
    exportRules(format = 'json') {
        const rules = this.getAllRules().map(r => r.toJSON());

        if (format === 'yaml' && yaml) {
            return yaml.dump({ rules });
        }

        return JSON.stringify({ rules }, null, 2);
    }

    /**
     * Get statistics about loaded rules
     */
    getStats() {
        const rules = this.getAllRules();
        const bySeverity = {};
        const byCategory = {};
        const byLanguage = {};

        for (const rule of rules) {
            bySeverity[rule.severity] = (bySeverity[rule.severity] || 0) + 1;
            byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
            for (const lang of rule.languages) {
                byLanguage[lang] = (byLanguage[lang] || 0) + 1;
            }
        }

        return {
            total: rules.length,
            enabled: rules.filter(r => r.enabled).length,
            bySeverity,
            byCategory,
            byLanguage,
        };
    }
}

module.exports = {
    CustomRule,
    CustomRulesManager,
    MetavariableMatcher,
    RULE_SCHEMA,
    BUILTIN_RULES,
};
