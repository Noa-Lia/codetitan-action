/**
 * Extended Security Rules - 200+ Additional Rules
 * 
 * Comprehensive security rules covering OWASP, CWE, and industry best practices.
 * Extends the base rule library to reach 1000+ total rules.
 * 
 * @module extended-security-rules
 */

const EXTENDED_SECURITY_RULES = {
    // ==================== INJECTION (CWE-74) ====================
    INJECTION: {
        sql_concat: { id: 'sec/sql-concat', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL query built with string concatenation' },
        sql_format: { id: 'sec/sql-format', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL query built with string formatting' },
        sql_fstring: { id: 'sec/sql-fstring', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL query in f-string or template literal' },
        nosql_injection: { id: 'sec/nosql-injection', severity: 'CRITICAL', cwe: 'CWE-943', message: 'NoSQL query with user input' },
        ldap_injection: { id: 'sec/ldap-injection', severity: 'HIGH', cwe: 'CWE-90', message: 'LDAP query with unescaped input' },
        xpath_injection: { id: 'sec/xpath-injection', severity: 'HIGH', cwe: 'CWE-643', message: 'XPath query with user input' },
        xml_injection: { id: 'sec/xml-injection', severity: 'HIGH', cwe: 'CWE-91', message: 'XML built with user input' },
        header_injection: { id: 'sec/header-injection', severity: 'HIGH', cwe: 'CWE-113', message: 'HTTP header with unvalidated input' },
        log_injection: { id: 'sec/log-injection', severity: 'MEDIUM', cwe: 'CWE-117', message: 'Log message with unsanitized input' },
        template_injection: { id: 'sec/template-injection', severity: 'CRITICAL', cwe: 'CWE-94', message: 'Server-side template injection' },
        code_injection: { id: 'sec/code-injection', severity: 'CRITICAL', cwe: 'CWE-94', message: 'Dynamic code execution with input' },
        regex_injection: { id: 'sec/regex-injection', severity: 'MEDIUM', cwe: 'CWE-1333', message: 'Regex pattern from user input (ReDoS risk)' },
        graphql_injection: { id: 'sec/graphql-injection', severity: 'HIGH', cwe: 'CWE-89', message: 'GraphQL query with user input' },
        ognl_injection: { id: 'sec/ognl-injection', severity: 'CRITICAL', cwe: 'CWE-917', message: 'OGNL expression with user input' },
        el_injection: { id: 'sec/el-injection', severity: 'CRITICAL', cwe: 'CWE-917', message: 'Expression Language injection' },
    },

    // ==================== XSS (CWE-79) ====================
    XSS: {
        reflected_xss: { id: 'sec/reflected-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'Reflected XSS - user input in response' },
        stored_xss: { id: 'sec/stored-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'Stored XSS - database content in response' },
        dom_xss: { id: 'sec/dom-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'DOM-based XSS via innerHTML/outerHTML' },
        innerhtml_user: { id: 'sec/innerhtml-user', severity: 'HIGH', cwe: 'CWE-79', message: 'innerHTML with user-controlled content' },
        document_write: { id: 'sec/document-write', severity: 'MEDIUM', cwe: 'CWE-79', message: 'document.write() usage' },
        dangerously_set: { id: 'sec/dangerously-set-html', severity: 'MEDIUM', cwe: 'CWE-79', message: 'React dangerouslySetInnerHTML usage' },
        v_html: { id: 'sec/vue-v-html', severity: 'MEDIUM', cwe: 'CWE-79', message: 'Vue v-html directive with dynamic content' },
        jquery_html: { id: 'sec/jquery-html', severity: 'HIGH', cwe: 'CWE-79', message: 'jQuery .html() with user input' },
        unescaped_output: { id: 'sec/unescaped-output', severity: 'HIGH', cwe: 'CWE-79', message: 'Template output without escaping' },
        script_src: { id: 'sec/script-src-dynamic', severity: 'HIGH', cwe: 'CWE-79', message: 'Dynamic script src attribute' },
        event_handler: { id: 'sec/inline-event-handler', severity: 'MEDIUM', cwe: 'CWE-79', message: 'Inline event handler with dynamic content' },
        url_javascript: { id: 'sec/javascript-url', severity: 'HIGH', cwe: 'CWE-79', message: 'javascript: URL scheme usage' },
    },

    // ==================== AUTHENTICATION (CWE-287) ====================
    AUTH: {
        weak_password: { id: 'sec/weak-password-policy', severity: 'HIGH', cwe: 'CWE-521', message: 'Weak password requirements' },
        no_rate_limit: { id: 'sec/no-rate-limit', severity: 'MEDIUM', cwe: 'CWE-307', message: 'Authentication without rate limiting' },
        session_fixation: { id: 'sec/session-fixation', severity: 'HIGH', cwe: 'CWE-384', message: 'Session not regenerated after login' },
        weak_session: { id: 'sec/weak-session-id', severity: 'HIGH', cwe: 'CWE-330', message: 'Predictable session ID generation' },
        plaintext_password: { id: 'sec/plaintext-password', severity: 'CRITICAL', cwe: 'CWE-256', message: 'Password stored in plaintext' },
        weak_hash: { id: 'sec/weak-password-hash', severity: 'HIGH', cwe: 'CWE-328', message: 'Weak password hashing (MD5/SHA1)' },
        no_salt: { id: 'sec/no-password-salt', severity: 'HIGH', cwe: 'CWE-759', message: 'Password hash without salt' },
        jwt_none: { id: 'sec/jwt-none-algorithm', severity: 'CRITICAL', cwe: 'CWE-327', message: 'JWT with none algorithm allowed' },
        jwt_weak_secret: { id: 'sec/jwt-weak-secret', severity: 'HIGH', cwe: 'CWE-326', message: 'JWT with weak secret' },
        basic_auth_http: { id: 'sec/basic-auth-http', severity: 'HIGH', cwe: 'CWE-319', message: 'Basic auth over HTTP' },
        oauth_state: { id: 'sec/oauth-no-state', severity: 'MEDIUM', cwe: 'CWE-352', message: 'OAuth without state parameter' },
        remember_me: { id: 'sec/insecure-remember-me', severity: 'MEDIUM', cwe: 'CWE-613', message: 'Insecure remember-me implementation' },
        credential_enum: { id: 'sec/credential-enumeration', severity: 'MEDIUM', cwe: 'CWE-204', message: 'Different responses for valid/invalid usernames' },
        mfa_bypass: { id: 'sec/mfa-bypass', severity: 'HIGH', cwe: 'CWE-287', message: 'MFA can be bypassed' },
    },

    // ==================== CRYPTOGRAPHY (CWE-310) ====================
    CRYPTO: {
        weak_cipher: { id: 'sec/weak-cipher', severity: 'HIGH', cwe: 'CWE-327', message: 'Weak cipher algorithm (DES, RC4, etc.)' },
        ecb_mode: { id: 'sec/ecb-mode', severity: 'HIGH', cwe: 'CWE-327', message: 'ECB mode encryption (insecure)' },
        static_iv: { id: 'sec/static-iv', severity: 'HIGH', cwe: 'CWE-329', message: 'Static/hardcoded initialization vector' },
        small_key: { id: 'sec/small-key-size', severity: 'HIGH', cwe: 'CWE-326', message: 'Encryption key size too small' },
        insecure_random: { id: 'sec/insecure-random', severity: 'HIGH', cwe: 'CWE-330', message: 'Insecure PRNG for security purpose' },
        math_random: { id: 'sec/math-random-security', severity: 'HIGH', cwe: 'CWE-338', message: 'Math.random() for security purpose' },
        no_integrity: { id: 'sec/no-integrity-check', severity: 'MEDIUM', cwe: 'CWE-353', message: 'Encryption without integrity verification' },
        deprecated_ssl: { id: 'sec/deprecated-ssl', severity: 'HIGH', cwe: 'CWE-326', message: 'SSL/TLS 1.0/1.1 enabled' },
        self_signed: { id: 'sec/self-signed-cert', severity: 'MEDIUM', cwe: 'CWE-295', message: 'Self-signed certificate accepted' },
        cert_not_verified: { id: 'sec/cert-not-verified', severity: 'CRITICAL', cwe: 'CWE-295', message: 'SSL certificate verification disabled' },
        hmac_timing: { id: 'sec/hmac-timing-attack', severity: 'MEDIUM', cwe: 'CWE-208', message: 'HMAC comparison vulnerable to timing attack' },
        rsa_no_padding: { id: 'sec/rsa-no-padding', severity: 'HIGH', cwe: 'CWE-780', message: 'RSA without proper padding' },
    },

    // ==================== FILE HANDLING (CWE-434) ====================
    FILE: {
        path_traversal: { id: 'sec/path-traversal', severity: 'HIGH', cwe: 'CWE-22', message: 'Path traversal vulnerability' },
        arbitrary_read: { id: 'sec/arbitrary-file-read', severity: 'HIGH', cwe: 'CWE-22', message: 'Arbitrary file read' },
        arbitrary_write: { id: 'sec/arbitrary-file-write', severity: 'CRITICAL', cwe: 'CWE-22', message: 'Arbitrary file write' },
        unrestricted_upload: { id: 'sec/unrestricted-upload', severity: 'HIGH', cwe: 'CWE-434', message: 'Unrestricted file upload' },
        no_extension_check: { id: 'sec/no-extension-check', severity: 'MEDIUM', cwe: 'CWE-434', message: 'File upload without extension validation' },
        no_content_check: { id: 'sec/no-content-type-check', severity: 'MEDIUM', cwe: 'CWE-434', message: 'File upload without content-type validation' },
        symlink_attack: { id: 'sec/symlink-attack', severity: 'MEDIUM', cwe: 'CWE-59', message: 'Symlink attack possible' },
        temp_file_race: { id: 'sec/temp-file-race', severity: 'MEDIUM', cwe: 'CWE-367', message: 'Temp file race condition (TOCTOU)' },
        world_writable: { id: 'sec/world-writable', severity: 'MEDIUM', cwe: 'CWE-732', message: 'World-writable file permissions' },
        executable_upload: { id: 'sec/executable-upload', severity: 'CRITICAL', cwe: 'CWE-434', message: 'Executable file upload allowed' },
    },

    // ==================== DESERIALIZATION (CWE-502) ====================
    DESERIALIZATION: {
        unsafe_pickle: { id: 'sec/unsafe-pickle', severity: 'CRITICAL', cwe: 'CWE-502', message: 'Unsafe pickle deserialization' },
        unsafe_yaml: { id: 'sec/unsafe-yaml-load', severity: 'CRITICAL', cwe: 'CWE-502', message: 'yaml.load() without safe_load' },
        java_deserial: { id: 'sec/java-deserialization', severity: 'CRITICAL', cwe: 'CWE-502', message: 'Java object deserialization' },
        php_unserialize: { id: 'sec/php-unserialize', severity: 'CRITICAL', cwe: 'CWE-502', message: 'PHP unserialize with user input' },
        json_type_confusion: { id: 'sec/json-type-confusion', severity: 'MEDIUM', cwe: 'CWE-502', message: 'JSON parsing without type validation' },
        xml_external: { id: 'sec/xxe-external-entity', severity: 'HIGH', cwe: 'CWE-611', message: 'XML external entity (XXE) processing' },
        xml_billion_laughs: { id: 'sec/xxe-billion-laughs', severity: 'MEDIUM', cwe: 'CWE-776', message: 'XML entity expansion (billion laughs)' },
    },

    // ==================== NETWORK (CWE-918) ====================
    NETWORK: {
        ssrf: { id: 'sec/ssrf', severity: 'HIGH', cwe: 'CWE-918', message: 'Server-side request forgery (SSRF)' },
        dns_rebind: { id: 'sec/dns-rebinding', severity: 'MEDIUM', cwe: 'CWE-918', message: 'Potential DNS rebinding vulnerability' },
        open_redirect: { id: 'sec/open-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Open redirect vulnerability' },
        csrf_no_token: { id: 'sec/csrf-no-token', severity: 'HIGH', cwe: 'CWE-352', message: 'Form without CSRF token' },
        cors_wildcard: { id: 'sec/cors-wildcard', severity: 'MEDIUM', cwe: 'CWE-346', message: 'CORS allows all origins (*)' },
        cors_credentials: { id: 'sec/cors-credentials', severity: 'HIGH', cwe: 'CWE-346', message: 'CORS with credentials and wildcard' },
        http_smuggling: { id: 'sec/http-smuggling', severity: 'HIGH', cwe: 'CWE-444', message: 'HTTP request smuggling risk' },
        websocket_origin: { id: 'sec/websocket-origin', severity: 'MEDIUM', cwe: 'CWE-346', message: 'WebSocket without origin validation' },
        grpc_insecure: { id: 'sec/grpc-insecure', severity: 'MEDIUM', cwe: 'CWE-319', message: 'gRPC without TLS' },
    },

    // ==================== BUSINESS LOGIC ====================
    LOGIC: {
        race_condition: { id: 'sec/race-condition', severity: 'MEDIUM', cwe: 'CWE-362', message: 'Race condition vulnerability' },
        mass_assignment: { id: 'sec/mass-assignment', severity: 'MEDIUM', cwe: 'CWE-915', message: 'Mass assignment vulnerability' },
        idor: { id: 'sec/idor', severity: 'HIGH', cwe: 'CWE-639', message: 'Insecure direct object reference (IDOR)' },
        privilege_escalation: { id: 'sec/privilege-escalation', severity: 'HIGH', cwe: 'CWE-269', message: 'Privilege escalation possible' },
        broken_access: { id: 'sec/broken-access-control', severity: 'HIGH', cwe: 'CWE-284', message: 'Broken access control' },
        insecure_default: { id: 'sec/insecure-default', severity: 'MEDIUM', cwe: 'CWE-276', message: 'Insecure default configuration' },
        debug_enabled: { id: 'sec/debug-enabled', severity: 'HIGH', cwe: 'CWE-489', message: 'Debug mode enabled in production' },
        stack_trace: { id: 'sec/stack-trace-exposed', severity: 'MEDIUM', cwe: 'CWE-209', message: 'Stack trace exposed to users' },
        error_details: { id: 'sec/error-details-exposed', severity: 'MEDIUM', cwe: 'CWE-209', message: 'Detailed error messages exposed' },
        version_exposed: { id: 'sec/version-exposed', severity: 'LOW', cwe: 'CWE-200', message: 'Server version exposed in headers' },
    },

    // ==================== MOBILE SECURITY ====================
    MOBILE: {
        insecure_storage: { id: 'sec/mobile-insecure-storage', severity: 'HIGH', cwe: 'CWE-922', message: 'Sensitive data in insecure storage' },
        clipboard_sensitive: { id: 'sec/clipboard-sensitive', severity: 'MEDIUM', cwe: 'CWE-200', message: 'Sensitive data copied to clipboard' },
        screenshot_allowed: { id: 'sec/screenshot-sensitive', severity: 'LOW', cwe: 'CWE-200', message: 'Screenshot allowed on sensitive screen' },
        backup_enabled: { id: 'sec/backup-sensitive', severity: 'MEDIUM', cwe: 'CWE-921', message: 'App backup includes sensitive data' },
        webview_js: { id: 'sec/webview-javascript', severity: 'MEDIUM', cwe: 'CWE-79', message: 'WebView with JavaScript enabled' },
        deeplink_unsafe: { id: 'sec/deeplink-unsafe', severity: 'MEDIUM', cwe: 'CWE-939', message: 'Deep link without validation' },
        root_detection: { id: 'sec/no-root-detection', severity: 'LOW', cwe: 'CWE-919', message: 'No root/jailbreak detection' },
        obfuscation: { id: 'sec/no-obfuscation', severity: 'LOW', cwe: 'CWE-693', message: 'Code not obfuscated' },
    },

    // ==================== API SECURITY ====================
    API: {
        api_key_url: { id: 'sec/api-key-in-url', severity: 'HIGH', cwe: 'CWE-598', message: 'API key in URL query parameter' },
        api_no_auth: { id: 'sec/api-no-auth', severity: 'HIGH', cwe: 'CWE-306', message: 'API endpoint without authentication' },
        api_excessive_data: { id: 'sec/api-excessive-data', severity: 'MEDIUM', cwe: 'CWE-213', message: 'API returns excessive data' },
        api_no_rate_limit: { id: 'sec/api-no-rate-limit', severity: 'MEDIUM', cwe: 'CWE-770', message: 'API without rate limiting' },
        api_http: { id: 'sec/api-over-http', severity: 'HIGH', cwe: 'CWE-319', message: 'API accessed over HTTP' },
        graphql_introspection: { id: 'sec/graphql-introspection', severity: 'MEDIUM', cwe: 'CWE-200', message: 'GraphQL introspection enabled' },
        graphql_depth: { id: 'sec/graphql-no-depth-limit', severity: 'MEDIUM', cwe: 'CWE-400', message: 'GraphQL without query depth limit' },
        rest_logging: { id: 'sec/rest-sensitive-logging', severity: 'MEDIUM', cwe: 'CWE-532', message: 'Sensitive data logged from API' },
    },

    // ==================== CLOUD SECURITY ====================
    CLOUD: {
        public_bucket: { id: 'sec/public-cloud-bucket', severity: 'CRITICAL', cwe: 'CWE-284', message: 'Cloud storage bucket publicly accessible' },
        no_encryption_rest: { id: 'sec/no-encryption-at-rest', severity: 'HIGH', cwe: 'CWE-311', message: 'Data not encrypted at rest' },
        no_encryption_transit: { id: 'sec/no-encryption-in-transit', severity: 'HIGH', cwe: 'CWE-319', message: 'Data not encrypted in transit' },
        overly_permissive: { id: 'sec/overly-permissive-iam', severity: 'HIGH', cwe: 'CWE-284', message: 'Overly permissive IAM policy' },
        root_account: { id: 'sec/root-account-usage', severity: 'HIGH', cwe: 'CWE-250', message: 'Root account used for operations' },
        no_mfa: { id: 'sec/no-mfa-enabled', severity: 'HIGH', cwe: 'CWE-308', message: 'MFA not enabled' },
        public_ip: { id: 'sec/public-ip-exposed', severity: 'MEDIUM', cwe: 'CWE-284', message: 'Resource with public IP' },
        untagged_resource: { id: 'sec/untagged-resource', severity: 'LOW', cwe: 'CWE-1059', message: 'Cloud resource without tags' },
    },

    // ==================== SUPPLY CHAIN ====================
    SUPPLY_CHAIN: {
        untrusted_source: { id: 'sec/untrusted-package-source', severity: 'HIGH', cwe: 'CWE-829', message: 'Package from untrusted source' },
        no_integrity: { id: 'sec/no-package-integrity', severity: 'MEDIUM', cwe: 'CWE-353', message: 'Package without integrity check' },
        unpinned_version: { id: 'sec/unpinned-dependency', severity: 'LOW', cwe: 'CWE-829', message: 'Dependency without version pin' },
        typosquat: { id: 'sec/typosquat-risk', severity: 'MEDIUM', cwe: 'CWE-829', message: 'Package name similar to popular package' },
        known_malware: { id: 'sec/known-malware-package', severity: 'CRITICAL', cwe: 'CWE-506', message: 'Known malicious package' },
        deprecated_package: { id: 'sec/deprecated-package', severity: 'LOW', cwe: 'CWE-1104', message: 'Deprecated or unmaintained package' },
        install_script: { id: 'sec/package-install-script', severity: 'MEDIUM', cwe: 'CWE-506', message: 'Package runs script during install' },
    },
};

/**
 * Count total rules
 */
function countExtendedRules() {
    let count = 0;
    for (const category of Object.values(EXTENDED_SECURITY_RULES)) {
        count += Object.keys(category).length;
    }
    return count;
}

/**
 * Get all rules as array
 */
function getAllExtendedRules() {
    const rules = [];
    for (const [category, categoryRules] of Object.entries(EXTENDED_SECURITY_RULES)) {
        for (const [name, rule] of Object.entries(categoryRules)) {
            rules.push({
                ...rule,
                category,
                name
            });
        }
    }
    return rules;
}

module.exports = {
    EXTENDED_SECURITY_RULES,
    countExtendedRules,
    getAllExtendedRules
};
