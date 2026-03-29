/**
 * Go Security Analyzer
 * 
 * Security analysis for Go code.
 * Uses regex-based detection for common vulnerability patterns.
 * 
 * @module go-analyzer
 */

/**
 * Go-specific security rules
 */
const GO_SECURITY_RULES = {
    // SQL Injection
    SQL_INJECTION: {
        patterns: [
            /db\.(?:Query|Exec|QueryRow)\s*\([^)]*\+/,
            /fmt\.Sprintf\s*\(\s*["']SELECT\s/i,
            /fmt\.Sprintf\s*\(\s*["']INSERT\s/i,
            /fmt\.Sprintf\s*\(\s*["']UPDATE\s/i,
            /fmt\.Sprintf\s*\(\s*["']DELETE\s/i,
            /Sprintf\s*\([^)]*%s[^)]*\)/,  // Format string with %s in SQL context
        ],
        severity: 'CRITICAL',
        category: 'SQL_INJECTION',
        message: 'Potential SQL injection - use parameterized queries with $1, $2...',
        cwe: 'CWE-89',
    },

    // Command Injection
    COMMAND_INJECTION: {
        patterns: [
            /exec\.Command\s*\(\s*[^)]*\+/,
            /exec\.Command\s*\(\s*["']\s*bash["']\s*,\s*["']-c["']\s*,/,
            /exec\.Command\s*\(\s*["']\s*sh["']\s*,\s*["']-c["']\s*,/,
            /os\.StartProcess\s*\([^)]*\+/,
        ],
        severity: 'CRITICAL',
        category: 'COMMAND_INJECTION',
        message: 'Potential command injection - avoid shell wrappers, use argument arrays',
        cwe: 'CWE-78',
    },

    // Path Traversal
    PATH_TRAVERSAL: {
        patterns: [
            /os\.Open\s*\(\s*[^)]*\+/,
            /os\.Create\s*\(\s*[^)]*\+/,
            /ioutil\.ReadFile\s*\(\s*[^)]*\+/,
            /ioutil\.WriteFile\s*\(\s*[^)]*\+/,
            /filepath\.Join\s*\([^)]*\+/,
            /http\.ServeFile\s*\([^)]*\+/,
        ],
        severity: 'HIGH',
        category: 'PATH_TRAVERSAL',
        message: 'Potential path traversal - use filepath.Clean and validate paths',
        cwe: 'CWE-22',
    },

    // SSRF
    SSRF: {
        patterns: [
            /http\.Get\s*\(\s*[^)]*\+/,
            /http\.Post\s*\(\s*[^)]*\+/,
            /http\.NewRequest\s*\([^,]+,\s*[^)]*\+/,
            /client\.Get\s*\(\s*[^)]*\+/,
        ],
        severity: 'HIGH',
        category: 'SSRF',
        message: 'Potential SSRF - validate and whitelist URLs',
        cwe: 'CWE-918',
    },

    // Weak Crypto
    WEAK_CRYPTO: {
        patterns: [
            /crypto\/md5/,
            /md5\.New\s*\(\s*\)/,
            /crypto\/sha1/,
            /sha1\.New\s*\(\s*\)/,
            /crypto\/des/,
            /crypto\/rc4/,
        ],
        severity: 'HIGH',
        category: 'WEAK_CRYPTO',
        message: 'Weak cryptographic algorithm - use SHA-256+ or AES-GCM',
        cwe: 'CWE-327',
    },

    // Insecure Random
    INSECURE_RANDOM: {
        patterns: [
            /math\/rand/,
            /rand\.Int\s*\(\s*\)/,
            /rand\.Intn\s*\(/,
            /rand\.Read\s*\(/,
        ],
        severity: 'MEDIUM',
        category: 'INSECURE_RANDOM',
        message: 'Insecure random for security context - use crypto/rand',
        cwe: 'CWE-330',
    },

    // Hardcoded Secrets
    HARDCODED_SECRET: {
        patterns: [
            /(?:password|passwd|pwd|secret|apikey|api_key|token)\s*(?:=|:=)\s*["'][^"']{8,}["']/i,
            /const\s+\w*(?:Password|Secret|ApiKey|Token)\w*\s*=\s*["']/i,
            /var\s+\w*(?:Password|Secret|ApiKey|Token)\w*\s*=\s*["']/i,
        ],
        severity: 'CRITICAL',
        category: 'HARDCODED_SECRET',
        message: 'Hardcoded secret detected - use environment variables',
        cwe: 'CWE-798',
    },

    // Open Redirect
    OPEN_REDIRECT: {
        patterns: [
            /http\.Redirect\s*\([^)]*r\.URL\.Query\(\)/,
            /http\.Redirect\s*\([^)]*r\.FormValue/,
            /http\.Redirect\s*\([^)]*\+/,
        ],
        severity: 'MEDIUM',
        category: 'OPEN_REDIRECT',
        message: 'Potential open redirect - validate redirect URLs',
        cwe: 'CWE-601',
    },

    // XSS in Templates
    XSS: {
        patterns: [
            /template\.HTML\s*\(/,
            /\.Funcs\s*\(\s*template\.FuncMap\s*\{\s*["']safe["']/,
        ],
        severity: 'HIGH',
        category: 'XSS',
        message: 'Potential XSS - avoid template.HTML with untrusted data',
        cwe: 'CWE-79',
    },

    // Insecure TLS
    INSECURE_TLS: {
        patterns: [
            /InsecureSkipVerify\s*:\s*true/,
            /MinVersion\s*:\s*tls\.VersionSSL30/,
            /MinVersion\s*:\s*tls\.VersionTLS10/,
        ],
        severity: 'HIGH',
        category: 'INSECURE_TLS',
        message: 'Insecure TLS configuration - enable certificate verification and use TLS 1.2+',
        cwe: 'CWE-295',
    },

    // Sensitive Data Exposure
    SENSITIVE_LOGGING: {
        patterns: [
            /log\.(?:Print|Printf|Println)\s*\([^)]*(?:password|secret|token|key)/i,
            /fmt\.(?:Print|Printf|Println)\s*\([^)]*(?:password|secret|token|key)/i,
        ],
        severity: 'MEDIUM',
        category: 'SENSITIVE_DATA_EXPOSURE',
        message: 'Potential sensitive data in logs - avoid logging secrets',
        cwe: 'CWE-532',
    },

    // Race Condition
    RACE_CONDITION: {
        patterns: [
            /go\s+func\s*\([^)]*\)\s*\{[^}]*\+\+/,
            /go\s+\w+\s*\([^)]*\)[^;]*\+\+/,
        ],
        severity: 'MEDIUM',
        category: 'RACE_CONDITION',
        message: 'Potential race condition - use sync/atomic or mutex',
        cwe: 'CWE-362',
    },

    // Gin Framework Specific
    GIN_DEBUG_MODE: {
        patterns: [
            /gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)/,
            /gin\.Default\s*\(\s*\)(?!.*gin\.SetMode.*ReleaseMode)/,
        ],
        severity: 'LOW',
        category: 'DEBUG_MODE',
        message: 'Gin running in debug mode - use gin.ReleaseMode in production',
        cwe: 'CWE-489',
    },

    // Unsafe Pointer
    UNSAFE_POINTER: {
        patterns: [
            /unsafe\.Pointer/,
            /import\s+["']unsafe["']/,
        ],
        severity: 'MEDIUM',
        category: 'UNSAFE_CODE',
        message: 'Unsafe pointer usage - ensure proper bounds checking',
        cwe: 'CWE-787',
    },

    // XML Parsing
    XXE: {
        patterns: [
            /xml\.NewDecoder\s*\(/,
            /xml\.Unmarshal\s*\(/,
        ],
        severity: 'MEDIUM',
        category: 'XXE',
        message: 'XML parsing detected - ensure DTD processing is disabled',
        cwe: 'CWE-611',
    },
};

/**
 * Analyze Go code for security issues
 * 
 * @param {string} code - The Go source code to analyze
 * @param {string} filePath - Path to the file being analyzed
 * @returns {Object} Analysis results with issues and metadata
 */
function analyzeGo(code, filePath) {
    const issues = [];
    const lines = code.split('\n');

    Object.entries(GO_SECURITY_RULES).forEach(([ruleId, rule]) => {
        rule.patterns.forEach(pattern => {
            lines.forEach((line, index) => {
                const trimmedLine = line.trim();

                // Skip comments
                if (trimmedLine.startsWith('//')) {
                    return;
                }

                if (pattern.test(line)) {
                    issues.push({
                        line: index + 1,
                        column: line.search(pattern) + 1,
                        severity: rule.severity,
                        category: rule.category,
                        message: rule.message,
                        cwe: rule.cwe,
                        snippet: trimmedLine.substring(0, 100),
                        ruleId,
                    });
                }
            });
        });
    });

    // Deduplicate
    const uniqueIssues = [];
    const seen = new Set();

    issues.forEach(issue => {
        const key = `${issue.line}-${issue.category}`;
        if (!seen.has(key)) {
            seen.add(key);
            uniqueIssues.push(issue);
        }
    });

    return {
        issues: uniqueIssues,
        language: 'go',
        rulesApplied: Object.keys(GO_SECURITY_RULES).length,
        filePath,
    };
}

/**
 * Get all Go security rules
 */
function getGoSecurityRules() {
    return Object.entries(GO_SECURITY_RULES).map(([id, rule]) => ({
        id,
        category: rule.category,
        severity: rule.severity,
        message: rule.message,
        cwe: rule.cwe,
        patternCount: rule.patterns.length,
    }));
}

module.exports = {
    analyzeGo,
    getGoSecurityRules,
    GO_SECURITY_RULES,
};
