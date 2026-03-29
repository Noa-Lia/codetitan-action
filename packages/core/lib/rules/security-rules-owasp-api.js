/**
 * OWASP API Security & Mobile Rules - 100+ Rules
 * OWASP Top 10, API Security Top 10, and Mobile patterns
 * @module security-rules-owasp-api
 */

const OWASP_API_RULES = {
    // ==================== OWASP TOP 10 2021 ====================
    OWASP_TOP_10: {
        // A01 Broken Access Control
        a01_missing_access_control: { severity: 'HIGH', impact: 8, cwe: 'CWE-284', message: 'Missing access control check' },
        a01_idor: { severity: 'HIGH', impact: 8, cwe: 'CWE-639', message: 'Insecure Direct Object Reference - validate ownership' },
        a01_path_traversal: { severity: 'HIGH', impact: 8, cwe: 'CWE-22', message: 'Path traversal vulnerability' },
        a01_privilege_escalation: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-269', message: 'Privilege escalation possible' },
        a01_cors_misconfigured: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-346', message: 'CORS misconfiguration' },

        // A02 Cryptographic Failures
        a02_weak_encryption: { severity: 'HIGH', impact: 7, cwe: 'CWE-327', message: 'Weak encryption algorithm' },
        a02_no_encryption: { severity: 'HIGH', impact: 8, cwe: 'CWE-311', message: 'Sensitive data not encrypted' },
        a02_weak_hash: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-328', message: 'Weak hash function for passwords' },
        a02_hardcoded_key: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Hardcoded cryptographic key' },
        a02_insufficient_entropy: { severity: 'HIGH', impact: 7, cwe: 'CWE-330', message: 'Insufficient entropy in random generation' },

        // A03 Injection
        a03_sql_injection: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-89', message: 'SQL injection vulnerability' },
        a03_nosql_injection: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-943', message: 'NoSQL injection vulnerability' },
        a03_command_injection: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-78', message: 'Command injection vulnerability' },
        a03_ldap_injection: { severity: 'HIGH', impact: 8, cwe: 'CWE-90', message: 'LDAP injection vulnerability' },
        a03_xpath_injection: { severity: 'HIGH', impact: 8, cwe: 'CWE-643', message: 'XPath injection vulnerability' },

        // A04 Insecure Design
        a04_no_rate_limit: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-770', message: 'No rate limiting implemented' },
        a04_no_captcha: { severity: 'LOW', impact: 3, cwe: 'CWE-307', message: 'No CAPTCHA for sensitive actions' },
        a04_no_2fa: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-308', message: 'No multi-factor authentication option' },
        a04_weak_recovery: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-640', message: 'Weak password recovery mechanism' },

        // A05 Security Misconfiguration
        a05_debug_enabled: { severity: 'HIGH', impact: 7, cwe: 'CWE-489', message: 'Debug mode enabled in production' },
        a05_default_credentials: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Default credentials in use' },
        a05_unnecessary_features: { severity: 'LOW', impact: 3, cwe: 'CWE-1188', message: 'Unnecessary features enabled' },
        a05_verbose_errors: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-209', message: 'Verbose error messages expose info' },
        a05_missing_headers: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-693', message: 'Missing security headers' },

        // A06 Vulnerable Components
        a06_outdated_dependency: { severity: 'HIGH', impact: 7, cwe: 'CWE-1035', message: 'Outdated and vulnerable dependency' },
        a06_unmaintained: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Unmaintained package dependency' },

        // A07 Auth Failures
        a07_weak_password: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-521', message: 'Weak password policy' },
        a07_brute_force: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-307', message: 'No brute force protection' },
        a07_session_fixation: { severity: 'HIGH', impact: 7, cwe: 'CWE-384', message: 'Session fixation vulnerability' },
        a07_insecure_session: { severity: 'HIGH', impact: 7, cwe: 'CWE-614', message: 'Insecure session management' },

        // A08 Integrity Failures
        a08_no_signature: { severity: 'HIGH', impact: 7, cwe: 'CWE-354', message: 'Data integrity not verified' },
        a08_unsafe_deserialize: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-502', message: 'Unsafe deserialization' },

        // A09 Logging Failures
        a09_no_logging: { severity: 'MEDIUM', impact: 4, cwe: 'CWE-778', message: 'Security events not logged' },
        a09_sensitive_log: { severity: 'HIGH', impact: 7, cwe: 'CWE-532', message: 'Sensitive data in logs' },

        // A10 SSRF
        a10_ssrf: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'Server-Side Request Forgery' },
        a10_open_redirect: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-601', message: 'Open redirect vulnerability' },
    },

    // ==================== OWASP API TOP 10 2023 ====================
    API_TOP_10: {
        // API1 BOLA
        api1_bola: { severity: 'HIGH', impact: 8, cwe: 'CWE-639', message: 'Broken Object Level Authorization' },
        api1_uuid_enumerable: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-200', message: 'Predictable resource IDs' },

        // API2 Broken Authentication
        api2_weak_token: { severity: 'HIGH', impact: 7, cwe: 'CWE-287', message: 'Weak authentication tokens' },
        api2_no_token_rotation: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-613', message: 'No token rotation policy' },
        api2_jwt_alg_none: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-327', message: 'JWT allows none algorithm' },

        // API3 BOPLA
        api3_bopla: { severity: 'HIGH', impact: 8, cwe: 'CWE-285', message: 'Broken Object Property Level Authorization' },
        api3_mass_assignment: { severity: 'HIGH', impact: 7, cwe: 'CWE-915', message: 'Mass assignment vulnerability' },
        api3_excessive_data: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-200', message: 'API returns excessive data' },

        // API4 Resource Consumption
        api4_no_pagination: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-770', message: 'API without pagination' },
        api4_no_rate_limit: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-770', message: 'No API rate limiting' },
        api4_file_upload: { severity: 'HIGH', impact: 7, cwe: 'CWE-434', message: 'Unrestricted file upload' },

        // API5 BFLA
        api5_bfla: { severity: 'HIGH', impact: 8, cwe: 'CWE-285', message: 'Broken Function Level Authorization' },
        api5_admin_exposure: { severity: 'HIGH', impact: 8, cwe: 'CWE-269', message: 'Admin functions exposed' },

        // API6 Unrestricted Access to Sensitive Business Flows
        api6_no_captcha: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-307', message: 'Sensitive flow without CAPTCHA' },
        api6_automation_abuse: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-799', message: 'Flow vulnerable to automation abuse' },

        // API7 Server Side Request Forgery
        api7_ssrf: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'API endpoint vulnerable to SSRF' },
        api7_internal_scan: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'Can scan internal network' },

        // API8 Security Misconfiguration
        api8_cors_wide: { severity: 'HIGH', impact: 7, cwe: 'CWE-346', message: 'Overly permissive CORS' },
        api8_tls_weak: { severity: 'HIGH', impact: 7, cwe: 'CWE-327', message: 'Weak TLS configuration' },
        api8_missing_headers: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-693', message: 'Missing security headers' },

        // API9 Improper Inventory Management
        api9_undocumented: { severity: 'LOW', impact: 3, cwe: '', message: 'Undocumented API endpoint' },
        api9_deprecated: { severity: 'LOW', impact: 3, cwe: '', message: 'Deprecated API still accessible' },
        api9_shadow_api: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Shadow API detected' },

        // API10 Unsafe Consumption
        api10_no_validation: { severity: 'HIGH', impact: 7, cwe: 'CWE-20', message: 'API response not validated' },
        api10_redirect_follow: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-601', message: 'Blindly follows redirects' },
    },

    // ==================== GRAPHQL SECURITY ====================
    GRAPHQL: {
        introspection: { severity: 'LOW', impact: 3, cwe: 'CWE-200', message: 'GraphQL introspection enabled in production' },
        depth_limit: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-400', message: 'No query depth limiting' },
        complexity_limit: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-400', message: 'No query complexity limiting' },
        batch_attack: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-307', message: 'Vulnerable to batching attacks' },
        alias_abuse: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-307', message: 'Vulnerable to alias-based rate limit bypass' },
        injection: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'Resolver vulnerable to injection' },
        auth_bypass: { severity: 'HIGH', impact: 8, cwe: 'CWE-284', message: 'Authorization bypass in resolver' },
    },

    // ==================== MOBILE SECURITY (React Native/Flutter) ====================
    MOBILE: {
        insecure_storage: { severity: 'HIGH', impact: 7, cwe: 'CWE-922', message: 'Sensitive data in insecure storage' },
        certificate_pinning: { severity: 'HIGH', impact: 7, cwe: 'CWE-295', message: 'No certificate pinning' },
        debug_build: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-489', message: 'Debug build in production' },
        root_detection: { severity: 'LOW', impact: 3, cwe: '', message: 'No root/jailbreak detection' },
        hardcoded_secret: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Secret hardcoded in app' },
        weak_biometric: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-287', message: 'Weak biometric implementation' },
        clipboard_sensitive: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-200', message: 'Sensitive data copied to clipboard' },
        screenshot_allowed: { severity: 'LOW', impact: 3, cwe: 'CWE-200', message: 'Screenshots allowed for sensitive screens' },
        webview_js: { severity: 'HIGH', impact: 7, cwe: 'CWE-749', message: 'WebView with JavaScript enabled' },
        deep_link: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-601', message: 'Insecure deep link handling' },
    },

    // ==================== WEBSOCKET SECURITY ====================
    WEBSOCKET: {
        no_auth: { severity: 'HIGH', impact: 7, cwe: 'CWE-306', message: 'WebSocket without authentication' },
        no_origin: { severity: 'HIGH', impact: 7, cwe: 'CWE-346', message: 'No origin validation' },
        message_size: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-400', message: 'No message size limit' },
        broadcast: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-200', message: 'Sensitive data broadcast' },
        rate_limit: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-770', message: 'No rate limiting on messages' },
    },
};

module.exports = OWASP_API_RULES;
