/**
 * C# Security Analyzer
 * 
 * Comprehensive security analysis for C#/.NET code.
 * Covers ASP.NET Core, Entity Framework, and common .NET patterns.
 * 
 * @module csharp-analyzer
 */

/**
 * C#-specific security rules
 */
const CSHARP_SECURITY_RULES = {
    // SQL Injection
    SQL_INJECTION: {
        patterns: [
            /SqlCommand\s*\([^)]*\+/,
            /ExecuteSqlRaw\s*\([^)]*\+/,
            /ExecuteSqlRawAsync\s*\([^)]*\+/,
            /FromSqlRaw\s*\([^)]*\+/,
            /\$"SELECT\s+.*\{/i,  // Interpolated SQL
            /\$"INSERT\s+.*\{/i,
            /\$"UPDATE\s+.*\{/i,
            /\$"DELETE\s+.*\{/i,
            /string\.Format\s*\(\s*"SELECT/i,
            /string\.Format\s*\(\s*"INSERT/i,
        ],
        severity: 'CRITICAL',
        category: 'SQL_INJECTION',
        message: 'Potential SQL injection - use parameterized queries or Entity Framework LINQ',
        cwe: 'CWE-89',
    },

    // Command Injection
    COMMAND_INJECTION: {
        patterns: [
            /Process\.Start\s*\([^)]*\+/,
            /ProcessStartInfo\s*\{[^}]*FileName\s*=\s*[^}]*\+/,
            /cmd\.exe\s*[^)]*\+/,
            /powershell\s*[^)]*\+/,
        ],
        severity: 'CRITICAL',
        category: 'COMMAND_INJECTION',
        message: 'Potential command injection - validate and sanitize input',
        cwe: 'CWE-78',
    },

    // Path Traversal
    PATH_TRAVERSAL: {
        patterns: [
            /File\.(?:Read|Write|Open|Delete|Copy|Move)\w*\s*\([^)]*\+/,
            /Path\.Combine\s*\([^)]*\+/,
            /Directory\.(?:Create|Delete|Move)\w*\s*\([^)]*\+/,
            /StreamReader\s*\([^)]*\+/,
            /StreamWriter\s*\([^)]*\+/,
        ],
        severity: 'HIGH',
        category: 'PATH_TRAVERSAL',
        message: 'Potential path traversal - use Path.GetFullPath and validate against base directory',
        cwe: 'CWE-22',
    },

    // XSS in ASP.NET
    XSS: {
        patterns: [
            /Html\.Raw\s*\(/,
            /@Html\.Raw\s*\(/,
            /Response\.Write\s*\([^)]*Request/,
            /ViewBag\.\w+\s*=\s*Request/,
            /ViewData\[.*\]\s*=\s*Request/,
        ],
        severity: 'HIGH',
        category: 'XSS',
        message: 'Potential XSS - avoid Html.Raw with user input, use HtmlEncoder',
        cwe: 'CWE-79',
    },

    // Insecure Deserialization
    INSECURE_DESERIALIZATION: {
        patterns: [
            /BinaryFormatter\s*\(\s*\)/,
            /\.Deserialize\s*\(/,
            /JsonConvert\.DeserializeObject<object>/,
            /XmlSerializer.*Deserialize/,
            /TypeNameHandling\.(?:All|Auto|Objects|Arrays)/,
        ],
        severity: 'CRITICAL',
        category: 'INSECURE_DESERIALIZATION',
        message: 'Insecure deserialization - avoid BinaryFormatter, use safe JSON settings',
        cwe: 'CWE-502',
    },

    // XXE
    XXE: {
        patterns: [
            /XmlDocument\s*\(\s*\)/,
            /XmlReader\.Create\s*\(/,
            /XmlTextReader\s*\(/,
            /DtdProcessing\s*=\s*DtdProcessing\.Parse/,
            /ProhibitDtd\s*=\s*false/,
        ],
        severity: 'HIGH',
        category: 'XXE',
        message: 'Potential XXE - disable DTD processing and external entities',
        cwe: 'CWE-611',
    },

    // Weak Crypto
    WEAK_CRYPTO: {
        patterns: [
            /MD5\.Create\s*\(\s*\)/,
            /SHA1\.Create\s*\(\s*\)/,
            /DES\.Create\s*\(\s*\)/,
            /TripleDES\.Create\s*\(\s*\)/,
            /RijndaelManaged.*Mode\s*=\s*CipherMode\.ECB/,
            /new\s+MD5CryptoServiceProvider/,
            /new\s+SHA1CryptoServiceProvider/,
        ],
        severity: 'HIGH',
        category: 'WEAK_CRYPTO',
        message: 'Weak cryptographic algorithm - use SHA256+ and AES-GCM',
        cwe: 'CWE-327',
    },

    // Hardcoded Secrets
    HARDCODED_SECRET: {
        patterns: [
            /(?:password|passwd|pwd|secret|apikey|api_key|connectionstring)\s*=\s*["'][^"']{8,}["']/i,
            /private\s+(?:const|static|readonly)?\s+string\s+\w*(?:Password|Secret|ApiKey|Token)\w*\s*=/i,
            /\.UseSqlServer\s*\(\s*["'][^"']+["']\s*\)/,
        ],
        severity: 'CRITICAL',
        category: 'HARDCODED_SECRET',
        message: 'Hardcoded secret detected - use User Secrets, Azure Key Vault, or environment variables',
        cwe: 'CWE-798',
    },

    // SSRF
    SSRF: {
        patterns: [
            /HttpClient.*GetAsync\s*\([^)]*\+/,
            /HttpClient.*PostAsync\s*\([^)]*\+/,
            /WebRequest\.Create\s*\([^)]*\+/,
            /new\s+Uri\s*\([^)]*\+/,
        ],
        severity: 'HIGH',
        category: 'SSRF',
        message: 'Potential SSRF - validate and whitelist URLs',
        cwe: 'CWE-918',
    },

    // Open Redirect
    OPEN_REDIRECT: {
        patterns: [
            /Redirect\s*\(\s*Request\.Query/,
            /Redirect\s*\([^)]*\+/,
            /RedirectToAction\s*\([^)]*returnUrl/i,
            /LocalRedirect\s*\(\s*returnUrl/,
        ],
        severity: 'MEDIUM',
        category: 'OPEN_REDIRECT',
        message: 'Potential open redirect - use Url.IsLocalUrl() to validate',
        cwe: 'CWE-601',
    },

    // LDAP Injection
    LDAP_INJECTION: {
        patterns: [
            /DirectorySearcher.*Filter\s*=\s*[^;]*\+/,
            /DirectoryEntry\s*\([^)]*\+/,
            /\(\w+={0}\)/,  // LDAP filter with format string
        ],
        severity: 'HIGH',
        category: 'LDAP_INJECTION',
        message: 'Potential LDAP injection - sanitize special characters',
        cwe: 'CWE-90',
    },

    // Insecure Random
    INSECURE_RANDOM: {
        patterns: [
            /new\s+Random\s*\(\s*\)/,
            /Random\s*\(\s*\)\.Next/,
        ],
        severity: 'MEDIUM',
        category: 'INSECURE_RANDOM',
        message: 'Insecure random for security context - use RandomNumberGenerator',
        cwe: 'CWE-330',
    },

    // ASP.NET Core Security
    ASPNET_SECURITY: {
        patterns: [
            /\.AllowAnyOrigin\s*\(\s*\)/,  // CORS misconfiguration
            /\.DisableAntiforgery\s*\(\s*\)/,
            /\[ValidateAntiForgeryToken\].*\[HttpPost\]/,  // Missing if not present
            /options\.Cookie\.SecurePolicy\s*=\s*CookieSecurePolicy\.(?:None|SameAsRequest)/,
            /options\.Cookie\.HttpOnly\s*=\s*false/,
        ],
        severity: 'HIGH',
        category: 'SECURITY_MISCONFIGURATION',
        message: 'ASP.NET Core security misconfiguration detected',
        cwe: 'CWE-16',
    },

    // Entity Framework Issues
    EF_ISSUES: {
        patterns: [
            /\.Include\s*\(\s*[^)]*\+/,
            /\.FromSqlInterpolated\s*\(\s*\$"/,  // May be safe but review
        ],
        severity: 'MEDIUM',
        category: 'DATA_EXPOSURE',
        message: 'Review Entity Framework query for potential data exposure',
        cwe: 'CWE-200',
    },

    // Regex DoS
    REGEX_DOS: {
        patterns: [
            /new\s+Regex\s*\([^)]*\+/,
            /Regex\.(?:Match|Replace|IsMatch)\s*\([^,]+,\s*[^)]*\+/,
        ],
        severity: 'MEDIUM',
        category: 'REGEX_DOS',
        message: 'Dynamic regex may be vulnerable to ReDoS - validate pattern',
        cwe: 'CWE-1333',
    },

    // Sensitive Logging
    SENSITIVE_LOGGING: {
        patterns: [
            /(?:_logger|Logger|Log)\.(?:Log|Info|Debug|Error|Warning)\s*\([^)]*(?:password|secret|token|key)/i,
            /Console\.WriteLine\s*\([^)]*(?:password|secret|token)/i,
        ],
        severity: 'MEDIUM',
        category: 'SENSITIVE_DATA_EXPOSURE',
        message: 'Potential sensitive data in logs',
        cwe: 'CWE-532',
    },

    // Mass Assignment
    MASS_ASSIGNMENT: {
        patterns: [
            /\[Bind\s*\(\s*\)\]/,  // Empty Bind attribute
            /TryUpdateModelAsync\s*\(/,
            /UpdateModel\s*\(/,
        ],
        severity: 'MEDIUM',
        category: 'MASS_ASSIGNMENT',
        message: 'Potential mass assignment vulnerability - use DTOs or explicit binding',
        cwe: 'CWE-915',
    },

    // Insecure Cookie
    INSECURE_COOKIE: {
        patterns: [
            /CookieOptions\s*\{[^}]*Secure\s*=\s*false/,
            /CookieOptions\s*\{[^}]*HttpOnly\s*=\s*false/,
            /Response\.Cookies\.Append\s*\([^)]*(?!Secure)/,
        ],
        severity: 'MEDIUM',
        category: 'INSECURE_COOKIE',
        message: 'Insecure cookie configuration - set Secure and HttpOnly',
        cwe: 'CWE-614',
    },
};

/**
 * Analyze C# code for security issues
 */
function analyzeCSharp(code, filePath) {
    const issues = [];
    const lines = code.split('\n');

    Object.entries(CSHARP_SECURITY_RULES).forEach(([ruleId, rule]) => {
        rule.patterns.forEach(pattern => {
            lines.forEach((line, index) => {
                const trimmedLine = line.trim();

                // Skip comments
                if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || trimmedLine.startsWith('*')) {
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
        language: 'csharp',
        rulesApplied: Object.keys(CSHARP_SECURITY_RULES).length,
        filePath,
    };
}

/**
 * Get all C# security rules
 */
function getCSharpSecurityRules() {
    return Object.entries(CSHARP_SECURITY_RULES).map(([id, rule]) => ({
        id,
        category: rule.category,
        severity: rule.severity,
        message: rule.message,
        cwe: rule.cwe,
        patternCount: rule.patterns.length,
    }));
}

module.exports = {
    analyzeCSharp,
    getCSharpSecurityRules,
    CSHARP_SECURITY_RULES,
};
