/**
 * Expanded Security Rules - 50+ Detection Patterns
 * 
 * Comprehensive security detection rules for AST analyzer
 * @module security-rules
 */

/**
 * All security rules organized by category
 */
const SECURITY_RULES = {

    // ==================== CODE EXECUTION ====================
    CODE_EXECUTION: {
        eval: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'eval() executes arbitrary code - use JSON.parse or specific parsers',
            cwe: 'CWE-95',
        },
        functionConstructor: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'Function constructor executes arbitrary code',
            cwe: 'CWE-95',
        },
        implicitEval: {
            severity: 'HIGH',
            impact: 7,
            message: 'setTimeout/setInterval with string executes code like eval()',
            cwe: 'CWE-95',
        },
        vmRunInContext: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'vm.runInContext can execute untrusted code',
            cwe: 'CWE-94',
        },
        vmRunInNewContext: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'vm.runInNewContext can execute untrusted code',
            cwe: 'CWE-94',
        },
        vmScript: {
            severity: 'HIGH',
            impact: 8,
            message: 'vm.Script can compile and execute untrusted code',
            cwe: 'CWE-94',
        },
    },

    // ==================== COMMAND INJECTION ====================
    COMMAND_INJECTION: {
        exec: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'child_process.exec with dynamic input - command injection risk',
            cwe: 'CWE-78',
        },
        execSync: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'child_process.execSync with dynamic input - command injection risk',
            cwe: 'CWE-78',
        },
        spawn: {
            severity: 'HIGH',
            impact: 8,
            message: 'child_process.spawn - validate shell commands',
            cwe: 'CWE-78',
        },
        shellTrue: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'spawn with shell:true enables shell injection',
            cwe: 'CWE-78',
        },
    },

    // ==================== SQL INJECTION ====================
    SQL_INJECTION: {
        templateLiteral: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'SQL with template literal interpolation - use parameterized queries',
            cwe: 'CWE-89',
        },
        stringConcat: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'SQL with string concatenation - use parameterized queries',
            cwe: 'CWE-89',
        },
        rawQuery: {
            severity: 'HIGH',
            impact: 8,
            message: 'Raw SQL query execution - prefer ORM methods',
            cwe: 'CWE-89',
        },
    },

    // ==================== XSS ====================
    XSS: {
        innerHTML: {
            severity: 'HIGH',
            impact: 8,
            message: 'innerHTML with dynamic content - sanitize or use textContent',
            cwe: 'CWE-79',
        },
        outerHTML: {
            severity: 'HIGH',
            impact: 8,
            message: 'outerHTML with dynamic content - sanitize to prevent XSS',
            cwe: 'CWE-79',
        },
        documentWrite: {
            severity: 'HIGH',
            impact: 8,
            message: 'document.write can lead to XSS and performance issues',
            cwe: 'CWE-79',
        },
        insertAdjacentHTML: {
            severity: 'HIGH',
            impact: 8,
            message: 'insertAdjacentHTML with dynamic content - sanitize input',
            cwe: 'CWE-79',
        },
        dangerouslySetInnerHTML: {
            severity: 'HIGH',
            impact: 8,
            message: 'dangerouslySetInnerHTML bypasses React XSS protection - sanitize',
            cwe: 'CWE-79',
        },
    },

    // ==================== PATH TRAVERSAL ====================
    PATH_TRAVERSAL: {
        dynamicPath: {
            severity: 'HIGH',
            impact: 8,
            message: 'File operation with dynamic path - validate to prevent traversal',
            cwe: 'CWE-22',
        },
        userInputPath: {
            severity: 'CRITICAL',
            impact: 9,
            message: 'File path from user input - sanitize with path.basename or resolve',
            cwe: 'CWE-22',
        },
        dotDotSlash: {
            severity: 'HIGH',
            impact: 8,
            message: 'Potential path traversal pattern detected',
            cwe: 'CWE-22',
        },
    },

    // ==================== PROTOTYPE POLLUTION ====================
    PROTOTYPE_POLLUTION: {
        protoAssignment: {
            severity: 'HIGH',
            impact: 8,
            message: 'Direct __proto__ assignment enables prototype pollution',
            cwe: 'CWE-1321',
        },
        constructorProto: {
            severity: 'HIGH',
            impact: 8,
            message: 'constructor.prototype access can lead to prototype pollution',
            cwe: 'CWE-1321',
        },
        objectMerge: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'Object merge without key filtering may allow prototype pollution',
            cwe: 'CWE-1321',
        },
        deepMerge: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'Deep object merge without validation - check for __proto__',
            cwe: 'CWE-1321',
        },
    },

    // ==================== SSRF ====================
    SSRF: {
        dynamicUrl: {
            severity: 'HIGH',
            impact: 8,
            message: 'HTTP request with dynamic URL - validate against SSRF',
            cwe: 'CWE-918',
        },
        internalNetwork: {
            severity: 'CRITICAL',
            impact: 9,
            message: 'Request to internal network address - potential SSRF',
            cwe: 'CWE-918',
        },
        redirectFollow: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'Following redirects can lead to SSRF via redirect chains',
            cwe: 'CWE-918',
        },
    },

    // ==================== OPEN REDIRECT ====================
    OPEN_REDIRECT: {
        locationAssignment: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'Dynamic location assignment - validate URL to prevent redirect',
            cwe: 'CWE-601',
        },
        windowOpen: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'window.open with dynamic URL - validate origin',
            cwe: 'CWE-601',
        },
        redirectMethod: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'Server redirect with user input - validate destination URL',
            cwe: 'CWE-601',
        },
    },

    // ==================== CRYPTOGRAPHY ====================
    WEAK_CRYPTO: {
        md5: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'MD5 is cryptographically broken - use SHA-256 or better',
            cwe: 'CWE-328',
        },
        sha1: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'SHA1 has known collisions - use SHA-256 or better',
            cwe: 'CWE-328',
        },
        weakKey: {
            severity: 'HIGH',
            impact: 7,
            message: 'Cryptographic key length too short - use 2048+ bits for RSA',
            cwe: 'CWE-326',
        },
        insecureRandom: {
            severity: 'HIGH',
            impact: 7,
            message: 'Math.random is not cryptographically secure - use crypto.randomBytes',
            cwe: 'CWE-338',
        },
        ecbMode: {
            severity: 'HIGH',
            impact: 7,
            message: 'ECB mode is insecure - use CBC, GCM, or CTR',
            cwe: 'CWE-327',
        },
        staticIV: {
            severity: 'HIGH',
            impact: 7,
            message: 'Static IV weakens encryption - generate random IV per operation',
            cwe: 'CWE-329',
        },
        noMAC: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'Encryption without authentication - use AEAD modes like GCM',
            cwe: 'CWE-353',
        },
    },

    // ==================== SECRETS ====================
    HARDCODED_SECRETS: {
        password: {
            severity: 'HIGH',
            impact: 9,
            message: 'Hardcoded password - move to environment variable or vault',
            cwe: 'CWE-798',
        },
        apiKey: {
            severity: 'HIGH',
            impact: 9,
            message: 'Hardcoded API key - move to environment variable or vault',
            cwe: 'CWE-798',
        },
        privateKey: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'Hardcoded private key - CRITICAL security issue',
            cwe: 'CWE-798',
        },
        jwtSecret: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'Hardcoded JWT secret allows token forgery',
            cwe: 'CWE-798',
        },
        databaseUrl: {
            severity: 'HIGH',
            impact: 8,
            message: 'Hardcoded database credentials - move to environment variable',
            cwe: 'CWE-798',
        },
    },

    // ==================== INSECURE TRANSPORT ====================
    INSECURE_TRANSPORT: {
        http: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'HTTP request without TLS - use HTTPS for secure transport',
            cwe: 'CWE-319',
        },
        noTlsVerify: {
            severity: 'HIGH',
            impact: 7,
            message: 'TLS certificate verification disabled - enables MITM attacks',
            cwe: 'CWE-295',
        },
        insecureCiphers: {
            severity: 'HIGH',
            impact: 7,
            message: 'Insecure TLS cipher suite - use modern ciphers',
            cwe: 'CWE-327',
        },
    },

    // ==================== DESERIALIZATION ====================
    INSECURE_DESERIALIZATION: {
        jsonParse: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'JSON.parse of untrusted data - validate structure',
            cwe: 'CWE-502',
        },
        nodeSerialize: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'node-serialize is vulnerable to RCE - do not use',
            cwe: 'CWE-502',
        },
        yamlLoad: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'yaml.load with untrusted data - use yaml.safeLoad',
            cwe: 'CWE-502',
        },
    },

    // ==================== NOSQL INJECTION ====================
    NOSQL_INJECTION: {
        mongoQuery: {
            severity: 'HIGH',
            impact: 8,
            message: 'MongoDB query with user input - sanitize operators like $where',
            cwe: 'CWE-943',
        },
        whereOperator: {
            severity: 'CRITICAL',
            impact: 9,
            message: '$where operator with dynamic content enables code execution',
            cwe: 'CWE-943',
        },
        regexInjection: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'User input in $regex - validate to prevent ReDoS',
            cwe: 'CWE-943',
        },
    },

    // ==================== XML INJECTION ====================
    XXE: {
        externalEntities: {
            severity: 'CRITICAL',
            impact: 9,
            message: 'XML parser with external entities enabled - disable DTD',
            cwe: 'CWE-611',
        },
        dtdProcessing: {
            severity: 'HIGH',
            impact: 8,
            message: 'DTD processing enabled - may allow XXE attacks',
            cwe: 'CWE-611',
        },
    },

    // ==================== LDAP INJECTION ====================
    LDAP_INJECTION: {
        unescapedInput: {
            severity: 'HIGH',
            impact: 8,
            message: 'LDAP query with unescaped user input - escape special characters',
            cwe: 'CWE-90',
        },
    },

    // ==================== REGEX ====================
    REGEX_DOS: {
        catastrophicBacktracking: {
            severity: 'HIGH',
            impact: 7,
            message: 'Regex pattern vulnerable to ReDoS - simplify or use timeout',
            cwe: 'CWE-1333',
        },
        userInputRegex: {
            severity: 'HIGH',
            impact: 7,
            message: 'User input used in regex - escape special characters',
            cwe: 'CWE-1333',
        },
    },

    // ==================== AUTHENTICATION ====================
    AUTH: {
        weakPassword: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'Weak password policy - require strong passwords',
            cwe: 'CWE-521',
        },
        plaintextPassword: {
            severity: 'CRITICAL',
            impact: 10,
            message: 'Password stored in plaintext - use bcrypt or argon2',
            cwe: 'CWE-256',
        },
        missingRateLimit: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'Authentication without rate limiting - add brute force protection',
            cwe: 'CWE-307',
        },
        insufficientHashing: {
            severity: 'HIGH',
            impact: 7,
            message: 'Insufficient password hashing rounds - use 10+ bcrypt rounds',
            cwe: 'CWE-916',
        },
    },

    // ==================== SESSION ====================
    SESSION: {
        insecureCookie: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'Session cookie missing Secure flag - add secure: true',
            cwe: 'CWE-614',
        },
        missingHttpOnly: {
            severity: 'MEDIUM',
            impact: 6,
            message: 'Cookie missing HttpOnly flag - add httpOnly: true',
            cwe: 'CWE-1004',
        },
        missingSameSite: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'Cookie missing SameSite attribute - add sameSite: strict',
            cwe: 'CWE-352',
        },
        sessionFixation: {
            severity: 'HIGH',
            impact: 7,
            message: 'Session ID not regenerated after login - prevent fixation',
            cwe: 'CWE-384',
        },
    },

    // ==================== LOGGING ====================
    LOGGING: {
        sensitiveData: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'Logging sensitive data (passwords, tokens) - redact before logging',
            cwe: 'CWE-532',
        },
        stackTraceExposure: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'Stack trace sent to client - hide in production',
            cwe: 'CWE-209',
        },
    },

    // ==================== MISCELLANEOUS ====================
    MISC: {
        debugEnabled: {
            severity: 'MEDIUM',
            impact: 5,
            message: 'Debug mode enabled in production - disable for security',
            cwe: 'CWE-489',
        },
        dangerousConst: {
            severity: 'LOW',
            impact: 3,
            message: 'Dangerous pattern detected - review for security implications',
            cwe: '',
        },
    },
};

/**
 * Secret patterns for detection
 */
const SECRET_PATTERNS = [
    // API Keys
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
    { name: 'AWS Secret Key', pattern: /[A-Za-z0-9/+=]{40}/ },
    { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/ },
    { name: 'GitHub OAuth', pattern: /gho_[a-zA-Z0-9]{36}/ },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/ },
    { name: 'Stripe Live Key', pattern: /sk_live_[0-9a-zA-Z]{24}/ },
    { name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24}/ },
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/ },
    { name: 'SendGrid Key', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
    { name: 'Twilio Key', pattern: /SK[0-9a-fA-F]{32}/ },
    { name: 'NPM Token', pattern: /npm_[A-Za-z0-9]{36}/ },
    { name: 'Discord Token', pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/ },
    { name: 'Heroku API', pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/ },

    // Private Keys
    { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/ },
    { name: 'OpenSSH Private Key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/ },
    { name: 'PGP Private Key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/ },
    { name: 'EC Private Key', pattern: /-----BEGIN EC PRIVATE KEY-----/ },

    // JWT
    { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/ },

    // Generic patterns
    { name: 'Generic Secret', pattern: /(password|secret|token|api.?key|auth)\s*[:=]\s*['"`][^'"`]{12,}['"`]/i },
    { name: 'Base64 Secret', pattern: /[A-Za-z0-9+/]{40,}={0,2}/ },
];

/**
 * Dangerous patterns by category
 */
const DANGEROUS_PATTERNS = {
    // Methods that can execute code
    CODE_EXEC_METHODS: ['eval', 'Function', 'setTimeout', 'setInterval'],

    // Command execution
    COMMAND_METHODS: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'],

    // SQL methods
    SQL_METHODS: ['query', 'execute', 'raw', 'prepare', 'runSql', '$queryRaw', '$executeRaw'],

    // File system sync methods  
    SYNC_FS: ['readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync',
        'mkdirSync', 'readdirSync', 'unlinkSync', 'rmdirSync', 'renameSync',
        'copyFileSync', 'accessSync', 'statSync', 'lstatSync'],

    // File system async methods that need path validation
    FS_PATH_METHODS: ['readFile', 'writeFile', 'appendFile', 'unlink', 'rmdir',
        'readdir', 'stat', 'access', 'open', 'rename', 'copyFile',
        'createReadStream', 'createWriteStream'],

    // Weak hash algorithms
    WEAK_ALGORITHMS: ['md5', 'sha1', 'md4', 'md2', 'ripemd', 'ripemd160'],

    // XSS sinks
    XSS_SINKS: ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write'],

    // Prototype pollution
    PROTO_KEYS: ['__proto__', 'constructor', 'prototype'],

    // MongoDB operators that allow code execution
    MONGO_DANGEROUS: ['$where', '$function', '$accumulator'],
};

module.exports = {
    SECURITY_RULES,
    SECRET_PATTERNS,
    DANGEROUS_PATTERNS,

    // Helper to count rules
    getRuleCount() {
        let count = 0;
        Object.values(SECURITY_RULES).forEach(category => {
            count += Object.keys(category).length;
        });
        return count;
    },
};
