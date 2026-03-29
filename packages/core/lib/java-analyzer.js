/**
 * Java Security Analyzer
 * 
 * Comprehensive security analysis for Java code.
 * Uses regex-based detection for common vulnerability patterns.
 * 
 * @module java-analyzer
 */

/**
 * Java-specific security rules
 */
const JAVA_SECURITY_RULES = {
    // SQL Injection
    SQL_INJECTION: {
        patterns: [
            // String concatenation in SQL
            /Statement\s*\.\s*execute(?:Query|Update)?\s*\(\s*[^)]*\+/,
            /createQuery\s*\(\s*[^)]*\+/,
            /createNativeQuery\s*\(\s*[^)]*\+/,
            /PreparedStatement.*\+\s*(?:request|input|param|user)/,
            // Direct string interpolation
            /\"SELECT\s+[^\"]*\"\s*\+\s*\w+/i,
            /\"INSERT\s+[^\"]*\"\s*\+\s*\w+/i,
            /\"UPDATE\s+[^\"]*\"\s*\+\s*\w+/i,
            /\"DELETE\s+[^\"]*\"\s*\+\s*\w+/i,
        ],
        severity: 'CRITICAL',
        category: 'SQL_INJECTION',
        message: 'Potential SQL injection - use parameterized queries with PreparedStatement',
        cwe: 'CWE-89',
    },

    // Command Injection
    COMMAND_INJECTION: {
        patterns: [
            /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*[^)]*\+/,
            /ProcessBuilder\s*\(\s*[^)]*\+/,
            /Runtime\.getRuntime\(\)\.exec\(\s*(?:request|input|param|user)/,
        ],
        severity: 'CRITICAL',
        category: 'COMMAND_INJECTION',
        message: 'Potential command injection - validate and sanitize input',
        cwe: 'CWE-78',
    },

    // Path Traversal
    PATH_TRAVERSAL: {
        patterns: [
            /new\s+File\s*\(\s*[^)]*\+/,
            /new\s+FileInputStream\s*\(\s*[^)]*\+/,
            /new\s+FileOutputStream\s*\(\s*[^)]*\+/,
            /Paths\s*\.\s*get\s*\(\s*[^)]*\+/,
            /\.\s*getResourceAsStream\s*\(\s*[^)]*\+/,
        ],
        severity: 'HIGH',
        category: 'PATH_TRAVERSAL',
        message: 'Potential path traversal - validate file paths and use canonical paths',
        cwe: 'CWE-22',
    },

    // XSS in JSP/Servlet
    XSS: {
        patterns: [
            /out\s*\.\s*print(?:ln)?\s*\(\s*request\s*\.\s*getParameter/,
            /response\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*print(?:ln)?\s*\([^)]*request/,
            /\$\{param\.\w+\}/,  // JSP EL without escaping
            /<%=\s*request\.getParameter/,  // JSP scriptlet
        ],
        severity: 'HIGH',
        category: 'XSS',
        message: 'Potential XSS - encode output using OWASP encoder or JSTL escapeXml',
        cwe: 'CWE-79',
    },

    // LDAP Injection
    LDAP_INJECTION: {
        patterns: [
            /search\s*\(\s*[^,]*\+/,
            /DirContext.*search.*\+\s*\w+/,
            /InitialDirContext.*search/,
            /[\"']\\\(.*=[\"']\s*\+\s*/,  // LDAP filter concatenation
        ],
        severity: 'HIGH',
        category: 'LDAP_INJECTION',
        message: 'Potential LDAP injection - use parameterized LDAP queries',
        cwe: 'CWE-90',
    },

    // XXE (XML External Entity)
    XXE: {
        patterns: [
            /XMLInputFactory\s*\.\s*newInstance\s*\(\s*\)/,
            /DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)/,
            /SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)/,
            /TransformerFactory\s*\.\s*newInstance\s*\(\s*\)/,
            // Without disable features
        ],
        severity: 'HIGH',
        category: 'XXE',
        message: 'XML parser may be vulnerable to XXE - disable external entities and DTDs',
        cwe: 'CWE-611',
    },

    // Insecure Deserialization
    INSECURE_DESERIALIZATION: {
        patterns: [
            /ObjectInputStream\s*\.\s*readObject\s*\(/,
            /XMLDecoder\s*\.\s*readObject\s*\(/,
            /new\s+ObjectInputStream\s*\([^)]*request/,
            /readObject\s*\(\s*\)/,
        ],
        severity: 'CRITICAL',
        category: 'INSECURE_DESERIALIZATION',
        message: 'Insecure deserialization - validate input or use safe alternatives like JSON',
        cwe: 'CWE-502',
    },

    // Weak Cryptography
    WEAK_CRYPTO: {
        patterns: [
            /Cipher\s*\.\s*getInstance\s*\(\s*["'](?:DES|RC2|RC4|Blowfish)["']/i,
            /Cipher\s*\.\s*getInstance\s*\(\s*["'][^"']*\/ECB\/["']/,  // ECB mode
            /MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/i,
            /SecretKeySpec.*"DES"/,
        ],
        severity: 'HIGH',
        category: 'WEAK_CRYPTO',
        message: 'Weak cryptographic algorithm - use AES-256-GCM or SHA-256+',
        cwe: 'CWE-327',
    },

    // Hardcoded Secrets
    HARDCODED_SECRET: {
        patterns: [
            /(?:password|passwd|pwd|secret|apikey|api_key|token|auth)\s*=\s*["'][^"']{8,}["']/i,
            /private\s+(?:static\s+)?(?:final\s+)?String\s+(?:PASSWORD|SECRET|API_KEY|TOKEN)\s*=/i,
            /\.setPassword\s*\(\s*["'][^"']+["']\s*\)/,
            /\.setApiKey\s*\(\s*["'][^"']+["']\s*\)/,
        ],
        severity: 'CRITICAL',
        category: 'HARDCODED_SECRET',
        message: 'Hardcoded secret detected - use environment variables or secure vault',
        cwe: 'CWE-798',
    },

    // SSRF (Server-Side Request Forgery)
    SSRF: {
        patterns: [
            /new\s+URL\s*\(\s*[^)]*\+/,
            /HttpURLConnection.*openConnection\s*\(\s*\)/,
            /HttpClient.*execute\s*\(\s*[^)]*\+/,
            /RestTemplate.*getForObject\s*\([^)]*\+/,
            /WebClient.*get\s*\(\s*[^)]*\+/,
        ],
        severity: 'HIGH',
        category: 'SSRF',
        message: 'Potential SSRF - validate and whitelist URLs',
        cwe: 'CWE-918',
    },

    // Open Redirect
    OPEN_REDIRECT: {
        patterns: [
            /response\s*\.\s*sendRedirect\s*\(\s*request\s*\.\s*getParameter/,
            /response\s*\.\s*sendRedirect\s*\(\s*[^)]*\+/,
            /HttpServletResponse.*sendRedirect.*request/,
        ],
        severity: 'MEDIUM',
        category: 'OPEN_REDIRECT',
        message: 'Potential open redirect - validate redirect URLs against whitelist',
        cwe: 'CWE-601',
    },

    // Insecure Random
    INSECURE_RANDOM: {
        patterns: [
            /new\s+Random\s*\(\s*\)/,
            /Math\s*\.\s*random\s*\(\s*\)/,
            /java\.util\.Random/,
        ],
        severity: 'MEDIUM',
        category: 'INSECURE_RANDOM',
        message: 'Insecure random for security context - use SecureRandom',
        cwe: 'CWE-330',
    },

    // Missing Input Validation
    MISSING_VALIDATION: {
        patterns: [
            /request\s*\.\s*getParameter\s*\([^)]+\)\s*;(?!\s*(?:if|validate|check|sanitize))/,
            /getParameter\s*\(\s*["'][^"']+["']\s*\)\s*\./,
        ],
        severity: 'MEDIUM',
        category: 'MISSING_VALIDATION',
        message: 'Input used without validation - validate and sanitize user input',
        cwe: 'CWE-20',
    },

    // SQL Injection with JDBC
    JDBC_INJECTION: {
        patterns: [
            /Statement\s+\w+\s*=\s*connection\.createStatement\s*\(\s*\)/,
            /String\s+\w*(?:sql|query)\w*\s*=\s*["'].*['"]\s*\+/i,
        ],
        severity: 'CRITICAL',
        category: 'SQL_INJECTION',
        message: 'Use PreparedStatement instead of Statement for dynamic queries',
        cwe: 'CWE-89',
    },

    // Log Injection
    LOG_INJECTION: {
        patterns: [
            /(?:logger|log)\s*\.\s*(?:info|debug|warn|error)\s*\(\s*[^)]*request\.getParameter/,
            /System\s*\.\s*out\s*\.\s*println\s*\(\s*request/,
        ],
        severity: 'MEDIUM',
        category: 'LOG_INJECTION',
        message: 'Potential log injection - sanitize user input before logging',
        cwe: 'CWE-117',
    },

    // SpringBoot Specific
    SPRING_SECURITY: {
        patterns: [
            /\.csrf\(\)\s*\.\s*disable\s*\(\s*\)/,  // CSRF disabled
            /\.cors\(\)\s*\.\s*disable\s*\(\s*\)/,  // CORS disabled
            /permitAll\s*\(\s*\)\s*\.\s*anyRequest/,  // Everything permitted
            /antMatchers\s*\(\s*["']\/\*\*["']\s*\)\s*\.\s*permitAll/,  // /** permitted
        ],
        severity: 'HIGH',
        category: 'SECURITY_MISCONFIGURATION',
        message: 'Spring Security misconfiguration detected - review security settings',
        cwe: 'CWE-16',
    },

    // Hibernate HQL Injection
    HQL_INJECTION: {
        patterns: [
            /createQuery\s*\(\s*["'].*["']\s*\+\s*\w+/,
            /session\s*\.\s*createQuery\s*\(\s*[^)]*\+/,
            /entityManager\s*\.\s*createQuery\s*\(\s*[^)]*\+/,
        ],
        severity: 'CRITICAL',
        category: 'SQL_INJECTION',
        message: 'HQL/JPQL injection - use parameterized queries with setParameter()',
        cwe: 'CWE-89',
    },

    // File Upload
    UNSAFE_FILE_UPLOAD: {
        patterns: [
            /MultipartFile.*getOriginalFilename\s*\(\s*\)/,
            /getOriginalFilename\s*\(\s*\)(?!.*(?:sanitize|validate|filter))/,
            /transferTo\s*\(\s*new\s+File\s*\(\s*[^)]*getOriginalFilename/,
        ],
        severity: 'HIGH',
        category: 'UNSAFE_FILE_UPLOAD',
        message: 'Unsafe file upload - validate file type and sanitize filename',
        cwe: 'CWE-434',
    },
};

/**
 * Analyze Java code for security issues
 * 
 * @param {string} code - The Java source code to analyze
 * @param {string} filePath - Path to the file being analyzed
 * @returns {Object} Analysis results with issues and metadata
 */
function analyzeJava(code, filePath) {
    const issues = [];
    const lines = code.split('\n');

    // Check each rule
    Object.entries(JAVA_SECURITY_RULES).forEach(([ruleId, rule]) => {
        rule.patterns.forEach(pattern => {
            // Check line by line
            lines.forEach((line, index) => {
                // Skip comments
                const trimmedLine = line.trim();
                if (trimmedLine.startsWith('//') || trimmedLine.startsWith('*') || trimmedLine.startsWith('/*')) {
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

            // Also check multi-line patterns
            if (pattern.test(code)) {
                // Find the approximate line number for multi-line matches
                const match = code.match(pattern);
                if (match && match.index !== undefined) {
                    const beforeMatch = code.substring(0, match.index);
                    const lineNumber = beforeMatch.split('\n').length;

                    // Get the matched line and check if it's a comment
                    const matchedLine = lines[lineNumber - 1] || '';
                    const trimmedMatchedLine = matchedLine.trim();
                    if (trimmedMatchedLine.startsWith('//') ||
                        trimmedMatchedLine.startsWith('*') ||
                        trimmedMatchedLine.startsWith('/*')) {
                        return; // Skip comments
                    }

                    // Check if we already found this issue
                    const alreadyFound = issues.some(i =>
                        i.category === rule.category &&
                        Math.abs(i.line - lineNumber) < 3
                    );

                    if (!alreadyFound) {
                        issues.push({
                            line: lineNumber,
                            column: 0,
                            severity: rule.severity,
                            category: rule.category,
                            message: rule.message,
                            cwe: rule.cwe,
                            snippet: match[0].substring(0, 80),
                            ruleId,
                        });
                    }
                }
            }
        });
    });

    // Deduplicate issues (same line, same category)
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
        language: 'java',
        rulesApplied: Object.keys(JAVA_SECURITY_RULES).length,
        filePath,
    };
}

/**
 * Get all Java security rules
 */
function getJavaSecurityRules() {
    return Object.entries(JAVA_SECURITY_RULES).map(([id, rule]) => ({
        id,
        category: rule.category,
        severity: rule.severity,
        message: rule.message,
        cwe: rule.cwe,
        patternCount: rule.patterns.length,
    }));
}

module.exports = {
    analyzeJava,
    getJavaSecurityRules,
    JAVA_SECURITY_RULES,
};
