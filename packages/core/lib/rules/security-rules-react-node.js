/**
 * Expanded Security Rules Library - 200+ Rules
 * 
 * React, Node.js, Express, and Modern JavaScript patterns
 * @module security-rules-react-node
 */

const REACT_NODE_RULES = {
    // ==================== REACT SECURITY ====================
    REACT: {
        dangerouslySetInnerHTML: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-79',
            message: 'dangerouslySetInnerHTML bypasses React XSS protection - sanitize with DOMPurify',
        },
        unsafeLifecycleMethod: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-749',
            message: 'Unsafe lifecycle method UNSAFE_componentWillMount/Update - migrate to hooks',
        },
        findDOMNode: {
            severity: 'LOW', impact: 3, cwe: 'CWE-749',
            message: 'findDOMNode is deprecated - use ref instead',
        },
        stringRefUsage: {
            severity: 'LOW', impact: 3, cwe: 'CWE-749',
            message: 'String refs are deprecated - use createRef or useRef',
        },
        unsanitizedHref: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-79',
            message: 'javascript: URLs in href can execute code - validate URLs',
        },
        stateDirectMutation: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-362',
            message: 'Direct state mutation detected - use setState or useState setter',
        },
        missingKeyProp: {
            severity: 'LOW', impact: 2, cwe: '',
            message: 'List items missing key prop - add unique key for performance',
        },
        unsafeTargetBlank: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-1022',
            message: 'target="_blank" without rel="noopener" - add rel="noopener noreferrer"',
        },
        iframeSandbox: {
            severity: 'MEDIUM', impact: 6, cwe: 'CWE-1021',
            message: 'iframe without sandbox attribute - add sandbox for security',
        },
        propsSpread: {
            severity: 'LOW', impact: 3, cwe: 'CWE-915',
            message: 'Spreading props may pass unexpected values - destructure explicitly',
        },
        evalInJSX: {
            severity: 'CRITICAL', impact: 10, cwe: 'CWE-95',
            message: 'eval() in JSX context - remove immediately',
        },
        useEffectCleanup: {
            severity: 'LOW', impact: 3, cwe: 'CWE-404',
            message: 'useEffect with subscriptions should return cleanup function',
        },
    },

    // ==================== EXPRESS SECURITY ====================
    EXPRESS: {
        noHelmet: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-693',
            message: 'Express app without helmet middleware - add helmet() for security headers',
        },
        noCSRF: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-352',
            message: 'No CSRF protection - add csurf middleware',
        },
        noCORS: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-346',
            message: 'CORS not configured - add cors() with specific origins',
        },
        wildcardCORS: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-346',
            message: 'CORS allows all origins (*) - specify allowed origins explicitly',
        },
        noRateLimit: {
            severity: 'MEDIUM', impact: 6, cwe: 'CWE-307',
            message: 'No rate limiting - add express-rate-limit middleware',
        },
        sessionInsecure: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-614',
            message: 'Session cookie without secure flag - add secure: true in production',
        },
        bodyParserLimit: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-400',
            message: 'Body parser without size limit - add limit option to prevent DoS',
        },
        staticPath: {
            severity: 'MEDIUM', impact: 6, cwe: 'CWE-22',
            message: 'express.static with user path - validate path to prevent traversal',
        },
        errorExposure: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-209',
            message: 'Error details sent to client - hide stack traces in production',
        },
        trustProxy: {
            severity: 'LOW', impact: 3, cwe: 'CWE-346',
            message: 'trust proxy not configured - set for correct client IP behind proxy',
        },
        routeWildcard: {
            severity: 'LOW', impact: 3, cwe: 'CWE-200',
            message: 'Wildcard route may expose unintended endpoints',
        },
    },

    // ==================== NODE.JS CORE ====================
    NODE: {
        processEnv: {
            severity: 'LOW', impact: 3, cwe: 'CWE-526',
            message: 'Direct process.env access - use config module for type safety',
        },
        unsafeUnserialize: {
            severity: 'CRITICAL', impact: 10, cwe: 'CWE-502',
            message: 'node-serialize/unserialize is vulnerable to RCE - remove immediately',
        },
        bufferNoEncoding: {
            severity: 'LOW', impact: 3, cwe: 'CWE-838',
            message: 'Buffer without encoding may cause issues - specify encoding explicitly',
        },
        requireDynamic: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-94',
            message: 'require() with dynamic path - may allow arbitrary module loading',
        },
        fsPermissions: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-732',
            message: 'File created with permissive mode - use restrictive permissions',
        },
        childProcessShell: {
            severity: 'CRITICAL', impact: 10, cwe: 'CWE-78',
            message: 'child_process with shell=true - vulnerable to command injection',
        },
        httpCreateServer: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-319',
            message: 'HTTP server without TLS - use HTTPS in production',
        },
        weakTLS: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-327',
            message: 'TLS with weak protocol version - use TLSv1.2 or higher',
        },
        noTimeout: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-400',
            message: 'Server without request timeout - add timeout to prevent slowloris',
        },
        uncaughtException: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-755',
            message: 'No uncaughtException handler - add to prevent crash',
        },
        unhandledRejection: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-755',
            message: 'No unhandledRejection handler - add to catch async errors',
        },
    },

    // ==================== JWT/AUTH ====================
    JWT: {
        noneAlgorithm: {
            severity: 'CRITICAL', impact: 10, cwe: 'CWE-327',
            message: 'JWT with "none" algorithm - always require algorithm',
        },
        weakSecret: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-326',
            message: 'JWT secret too short - use 256+ bits for HS256',
        },
        noExpiry: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-613',
            message: 'JWT without expiration - add exp claim',
        },
        algorithmConfusion: {
            severity: 'CRITICAL', impact: 10, cwe: 'CWE-327',
            message: 'JWT algorithm not verified - specify algorithms array',
        },
        publicKeyLeak: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-200',
            message: 'JWT public key in code - use environment variable',
        },
        tokenInURL: {
            severity: 'MEDIUM', impact: 6, cwe: 'CWE-598',
            message: 'JWT in URL query parameter - use Authorization header',
        },
        noAudience: {
            severity: 'LOW', impact: 4, cwe: 'CWE-287',
            message: 'JWT without audience verification - add aud claim',
        },
        noIssuer: {
            severity: 'LOW', impact: 4, cwe: 'CWE-287',
            message: 'JWT without issuer verification - add iss claim',
        },
    },

    // ==================== DATABASE ====================
    DATABASE: {
        mongoNoAuth: {
            severity: 'CRITICAL', impact: 10, cwe: 'CWE-306',
            message: 'MongoDB connection without authentication',
        },
        mongoURI: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-798',
            message: 'MongoDB URI with credentials in code - use environment variable',
        },
        pgSSL: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-319',
            message: 'PostgreSQL connection without SSL - add ssl: true',
        },
        redisNoAuth: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-306',
            message: 'Redis connection without password',
        },
        sqliteInMemory: {
            severity: 'LOW', impact: 2, cwe: '',
            message: 'SQLite in-memory database - data lost on restart',
        },
        poolExhaustion: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-400',
            message: 'No connection pool limit - add max connections',
        },
        escapingMissing: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-89',
            message: 'Query without parameter escaping - use parameterized queries',
        },
        ormRawQuery: {
            severity: 'MEDIUM', impact: 6, cwe: 'CWE-89',
            message: 'ORM raw query - prefer model methods',
        },
    },

    // ==================== API SECURITY ====================
    API: {
        noAuthentication: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-306',
            message: 'API endpoint without authentication middleware',
        },
        sensitiveEndpoint: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-200',
            message: 'Sensitive data endpoint - ensure proper authorization',
        },
        massAssignment: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-915',
            message: 'Spread operator for DB update - whitelist allowed fields',
        },
        verboseErrors: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-209',
            message: 'API returns verbose errors - hide implementation details',
        },
        noInputValidation: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-20',
            message: 'No input validation - add validation middleware',
        },
        idEnumeration: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-200',
            message: 'Sequential IDs enable enumeration - use UUIDs',
        },
        noOutputEncoding: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-116',
            message: 'API response not encoded - ensure proper Content-Type',
        },
        openRedirect: {
            severity: 'MEDIUM', impact: 6, cwe: 'CWE-601',
            message: 'Redirect URL from user input - validate against whitelist',
        },
    },

    // ==================== NEXT.JS SPECIFIC ====================
    NEXTJS: {
        apiRouteNoAuth: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-306',
            message: 'Next.js API route without authentication check',
        },
        ssrInject: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-79',
            message: 'User input in getServerSideProps without sanitization',
        },
        imageOptimization: {
            severity: 'MEDIUM', impact: 4, cwe: 'CWE-918',
            message: 'Next/image with external domains - configure remotePatterns',
        },
        middlewareBypass: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-284',
            message: 'API route may bypass middleware - verify matcher config',
        },
        envExposure: {
            severity: 'HIGH', impact: 8, cwe: 'CWE-200',
            message: 'Server env exposed to client - use NEXT_PUBLIC_ prefix only for public vars',
        },
        rscPayload: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-200',
            message: 'React Server Component may leak sensitive data to client',
        },
    },

    // ==================== WEBSOCKET ====================
    WEBSOCKET: {
        noOriginCheck: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-346',
            message: 'WebSocket without origin validation - check Origin header',
        },
        noAuth: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-306',
            message: 'WebSocket without authentication',
        },
        messageInjection: {
            severity: 'HIGH', impact: 7, cwe: 'CWE-94',
            message: 'WebSocket message eval - validate and parse JSON safely',
        },
        broadcastSensitive: {
            severity: 'MEDIUM', impact: 5, cwe: 'CWE-200',
            message: 'Broadcasting sensitive data to all clients - filter by authorization',
        },
    },
};

module.exports = REACT_NODE_RULES;
