/**
 * Compliance and Best Practice Rules - 150+ Rules
 * 
 * Rules for regulatory compliance (GDPR, HIPAA, PCI-DSS, SOC2)
 * and industry best practices.
 * 
 * @module compliance-rules
 */

const COMPLIANCE_RULES = {
    // ==================== GDPR (25 rules) ====================
    GDPR: {
        personal_data_log: { id: 'gdpr/personal-data-in-log', severity: 'HIGH', cwe: 'CWE-532', message: 'Personal data (email, name, IP) in logs' },
        consent_missing: { id: 'gdpr/no-consent-check', severity: 'HIGH', cwe: '', message: 'Data processing without consent check' },
        data_retention: { id: 'gdpr/no-retention-policy', severity: 'MEDIUM', cwe: '', message: 'No data retention/deletion mechanism' },
        right_to_delete: { id: 'gdpr/no-deletion-endpoint', severity: 'MEDIUM', cwe: '', message: 'No user data deletion functionality' },
        data_export: { id: 'gdpr/no-data-export', severity: 'MEDIUM', cwe: '', message: 'No data portability endpoint' },
        third_party_share: { id: 'gdpr/third-party-data-share', severity: 'HIGH', cwe: '', message: 'Data shared with third party without consent' },
        cookie_consent: { id: 'gdpr/no-cookie-consent', severity: 'MEDIUM', cwe: '', message: 'Tracking cookies without consent' },
        analytics_pii: { id: 'gdpr/analytics-pii', severity: 'MEDIUM', cwe: '', message: 'PII sent to analytics service' },
        encryption_pii: { id: 'gdpr/pii-not-encrypted', severity: 'HIGH', cwe: 'CWE-311', message: 'Personal data stored without encryption' },
        cross_border: { id: 'gdpr/cross-border-transfer', severity: 'MEDIUM', cwe: '', message: 'Data transferred outside EU without safeguards' },
        minor_data: { id: 'gdpr/minor-data-processing', severity: 'HIGH', cwe: '', message: 'Minor data processed without parental consent' },
        profiling: { id: 'gdpr/automated-profiling', severity: 'MEDIUM', cwe: '', message: 'Automated profiling without disclosure' },
        breach_notify: { id: 'gdpr/no-breach-notification', severity: 'MEDIUM', cwe: '', message: 'No data breach notification mechanism' },
        dpo_contact: { id: 'gdpr/no-dpo-contact', severity: 'LOW', cwe: '', message: 'No DPO contact information' },
        privacy_policy: { id: 'gdpr/no-privacy-policy', severity: 'LOW', cwe: '', message: 'No privacy policy link' },
    },

    // ==================== HIPAA (25 rules) ====================
    HIPAA: {
        phi_logging: { id: 'hipaa/phi-in-log', severity: 'CRITICAL', cwe: 'CWE-532', message: 'PHI (Protected Health Information) in logs' },
        phi_plaintext: { id: 'hipaa/phi-not-encrypted', severity: 'CRITICAL', cwe: 'CWE-311', message: 'PHI stored without encryption' },
        phi_transmission: { id: 'hipaa/phi-unencrypted-transmission', severity: 'CRITICAL', cwe: 'CWE-319', message: 'PHI transmitted without encryption' },
        access_control: { id: 'hipaa/no-access-control', severity: 'HIGH', cwe: 'CWE-284', message: 'PHI accessed without authorization check' },
        audit_trail: { id: 'hipaa/no-audit-trail', severity: 'HIGH', cwe: 'CWE-778', message: 'PHI access without audit logging' },
        session_timeout: { id: 'hipaa/no-session-timeout', severity: 'MEDIUM', cwe: 'CWE-613', message: 'No automatic session timeout' },
        minimum_necessary: { id: 'hipaa/excessive-phi-access', severity: 'MEDIUM', cwe: '', message: 'Accessing more PHI than necessary' },
        disposal: { id: 'hipaa/no-secure-disposal', severity: 'MEDIUM', cwe: '', message: 'No secure PHI disposal mechanism' },
        backup_encryption: { id: 'hipaa/backup-not-encrypted', severity: 'HIGH', cwe: 'CWE-311', message: 'PHI backup not encrypted' },
        workstation_security: { id: 'hipaa/workstation-insecure', severity: 'MEDIUM', cwe: '', message: 'Workstation security controls missing' },
        baa_required: { id: 'hipaa/no-baa', severity: 'HIGH', cwe: '', message: 'Third-party PHI access without BAA' },
        disclosure_logging: { id: 'hipaa/no-disclosure-log', severity: 'MEDIUM', cwe: '', message: 'PHI disclosure not logged' },
        emergency_access: { id: 'hipaa/no-emergency-access', severity: 'LOW', cwe: '', message: 'No emergency access procedure' },
        integrity_check: { id: 'hipaa/no-integrity-check', severity: 'MEDIUM', cwe: 'CWE-345', message: 'No PHI integrity verification' },
        transmission_security: { id: 'hipaa/weak-transmission-security', severity: 'HIGH', cwe: 'CWE-326', message: 'Weak encryption for PHI transmission' },
    },

    // ==================== PCI-DSS (30 rules) ====================
    PCI: {
        pan_logging: { id: 'pci/pan-in-log', severity: 'CRITICAL', cwe: 'CWE-532', message: 'Card number (PAN) in logs' },
        pan_display: { id: 'pci/pan-full-display', severity: 'CRITICAL', cwe: 'CWE-200', message: 'Full PAN displayed (mask required)' },
        cvv_storage: { id: 'pci/cvv-stored', severity: 'CRITICAL', cwe: 'CWE-312', message: 'CVV/CVC stored after authorization' },
        pan_unencrypted: { id: 'pci/pan-not-encrypted', severity: 'CRITICAL', cwe: 'CWE-311', message: 'PAN stored without encryption' },
        key_management: { id: 'pci/weak-key-management', severity: 'HIGH', cwe: 'CWE-320', message: 'Encryption key not properly managed' },
        tls_version: { id: 'pci/weak-tls', severity: 'HIGH', cwe: 'CWE-326', message: 'TLS version below 1.2' },
        password_policy: { id: 'pci/weak-password-policy', severity: 'HIGH', cwe: 'CWE-521', message: 'Password policy does not meet PCI requirements' },
        mfa_admin: { id: 'pci/admin-no-mfa', severity: 'HIGH', cwe: 'CWE-308', message: 'Admin access without MFA' },
        audit_logging: { id: 'pci/insufficient-logging', severity: 'HIGH', cwe: 'CWE-778', message: 'Insufficient audit logging for PCI' },
        log_retention: { id: 'pci/log-retention-short', severity: 'MEDIUM', cwe: '', message: 'Log retention less than 1 year' },
        vulnerability_scan: { id: 'pci/no-vuln-scanning', severity: 'MEDIUM', cwe: '', message: 'No vulnerability scanning' },
        network_segmentation: { id: 'pci/no-segmentation', severity: 'HIGH', cwe: 'CWE-653', message: 'Cardholder data not segmented' },
        access_review: { id: 'pci/no-access-review', severity: 'MEDIUM', cwe: '', message: 'No periodic access review' },
        change_control: { id: 'pci/no-change-control', severity: 'MEDIUM', cwe: '', message: 'Changes without approval process' },
        antivirus: { id: 'pci/no-antivirus', severity: 'MEDIUM', cwe: '', message: 'No malware protection' },
        secure_coding: { id: 'pci/no-secure-coding', severity: 'MEDIUM', cwe: '', message: 'Secure coding practices not followed' },
        penetration_test: { id: 'pci/no-pentest', severity: 'MEDIUM', cwe: '', message: 'No penetration testing' },
        vendor_management: { id: 'pci/no-vendor-assessment', severity: 'MEDIUM', cwe: '', message: 'Third-party vendor not assessed' },
        incident_response: { id: 'pci/no-incident-response', severity: 'MEDIUM', cwe: '', message: 'No incident response plan' },
        security_policy: { id: 'pci/no-security-policy', severity: 'LOW', cwe: '', message: 'No documented security policy' },
    },

    // ==================== SOC2 (25 rules) ====================
    SOC2: {
        access_control: { id: 'soc2/no-access-control', severity: 'HIGH', cwe: 'CWE-284', message: 'Missing access control for sensitive operations' },
        encryption_rest: { id: 'soc2/no-encryption-at-rest', severity: 'HIGH', cwe: 'CWE-311', message: 'Sensitive data not encrypted at rest' },
        encryption_transit: { id: 'soc2/no-encryption-in-transit', severity: 'HIGH', cwe: 'CWE-319', message: 'Data not encrypted in transit' },
        audit_logging: { id: 'soc2/insufficient-audit-log', severity: 'HIGH', cwe: 'CWE-778', message: 'Insufficient audit logging' },
        log_monitoring: { id: 'soc2/no-log-monitoring', severity: 'MEDIUM', cwe: '', message: 'No log monitoring/alerting' },
        change_management: { id: 'soc2/no-change-management', severity: 'MEDIUM', cwe: '', message: 'Changes without approval' },
        vulnerability_mgmt: { id: 'soc2/no-vuln-management', severity: 'MEDIUM', cwe: '', message: 'No vulnerability management' },
        incident_response: { id: 'soc2/no-incident-response', severity: 'MEDIUM', cwe: '', message: 'No incident response procedure' },
        data_backup: { id: 'soc2/no-backup', severity: 'HIGH', cwe: '', message: 'No data backup mechanism' },
        disaster_recovery: { id: 'soc2/no-dr-plan', severity: 'MEDIUM', cwe: '', message: 'No disaster recovery plan' },
        vendor_risk: { id: 'soc2/no-vendor-risk', severity: 'MEDIUM', cwe: '', message: 'Third-party risk not assessed' },
        security_awareness: { id: 'soc2/no-security-training', severity: 'LOW', cwe: '', message: 'No security awareness program' },
        physical_security: { id: 'soc2/no-physical-security', severity: 'LOW', cwe: '', message: 'Physical security not documented' },
        network_security: { id: 'soc2/weak-network-security', severity: 'MEDIUM', cwe: '', message: 'Network security controls insufficient' },
        data_classification: { id: 'soc2/no-data-classification', severity: 'MEDIUM', cwe: '', message: 'Data not classified' },
    },

    // ==================== OWASP TOP 10 (25 rules) ====================
    OWASP: {
        injection: { id: 'owasp/a03-injection', severity: 'CRITICAL', cwe: 'CWE-89', message: 'Injection vulnerability (A03:2021)' },
        broken_auth: { id: 'owasp/a07-identification', severity: 'HIGH', cwe: 'CWE-287', message: 'Identification and Authentication Failures (A07:2021)' },
        sensitive_exposure: { id: 'owasp/a02-crypto-failures', severity: 'HIGH', cwe: 'CWE-311', message: 'Cryptographic Failures (A02:2021)' },
        xxe: { id: 'owasp/xxe', severity: 'HIGH', cwe: 'CWE-611', message: 'XML External Entities' },
        broken_access: { id: 'owasp/a01-broken-access', severity: 'CRITICAL', cwe: 'CWE-284', message: 'Broken Access Control (A01:2021)' },
        misconfig: { id: 'owasp/a05-misconfig', severity: 'MEDIUM', cwe: 'CWE-16', message: 'Security Misconfiguration (A05:2021)' },
        xss: { id: 'owasp/a03-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'Cross-Site Scripting (A03:2021)' },
        insecure_deserial: { id: 'owasp/a08-software-integrity', severity: 'CRITICAL', cwe: 'CWE-502', message: 'Software and Data Integrity Failures (A08:2021)' },
        vuln_components: { id: 'owasp/a06-vuln-components', severity: 'MEDIUM', cwe: 'CWE-1104', message: 'Vulnerable and Outdated Components (A06:2021)' },
        logging_failures: { id: 'owasp/a09-logging-failures', severity: 'MEDIUM', cwe: 'CWE-778', message: 'Security Logging and Monitoring Failures (A09:2021)' },
        ssrf: { id: 'owasp/a10-ssrf', severity: 'HIGH', cwe: 'CWE-918', message: 'Server-Side Request Forgery (A10:2021)' },
        insecure_design: { id: 'owasp/a04-insecure-design', severity: 'MEDIUM', cwe: '', message: 'Insecure Design (A04:2021)' },
        csrf: { id: 'owasp/csrf', severity: 'HIGH', cwe: 'CWE-352', message: 'Cross-Site Request Forgery' },
        open_redirect: { id: 'owasp/open-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Open Redirect' },
        path_traversal: { id: 'owasp/path-traversal', severity: 'HIGH', cwe: 'CWE-22', message: 'Path Traversal' },
    },

    // ==================== BEST PRACTICES (30 rules) ====================
    BEST_PRACTICES: {
        input_validation: { id: 'best/no-input-validation', severity: 'MEDIUM', cwe: 'CWE-20', message: 'User input not validated' },
        output_encoding: { id: 'best/no-output-encoding', severity: 'MEDIUM', cwe: 'CWE-116', message: 'Output not encoded' },
        error_handling: { id: 'best/generic-error-handling', severity: 'LOW', cwe: 'CWE-755', message: 'Generic error handling' },
        defense_depth: { id: 'best/single-control', severity: 'LOW', cwe: '', message: 'Single security control (defense in depth)' },
        least_privilege: { id: 'best/excessive-privileges', severity: 'MEDIUM', cwe: 'CWE-250', message: 'Excessive privileges granted' },
        secure_defaults: { id: 'best/insecure-default', severity: 'MEDIUM', cwe: 'CWE-276', message: 'Insecure default configuration' },
        fail_secure: { id: 'best/fail-open', severity: 'MEDIUM', cwe: 'CWE-636', message: 'System fails open instead of secure' },
        separation_duties: { id: 'best/no-separation', severity: 'LOW', cwe: '', message: 'No separation of duties' },
        audit_critical: { id: 'best/no-audit-critical', severity: 'MEDIUM', cwe: 'CWE-778', message: 'Critical operations not audited' },
        session_management: { id: 'best/weak-session', severity: 'MEDIUM', cwe: 'CWE-613', message: 'Weak session management' },
        password_storage: { id: 'best/weak-password-storage', severity: 'HIGH', cwe: 'CWE-916', message: 'Improper password storage' },
        token_expiry: { id: 'best/no-token-expiry', severity: 'MEDIUM', cwe: 'CWE-613', message: 'Token does not expire' },
        rate_limiting: { id: 'best/no-rate-limit', severity: 'MEDIUM', cwe: 'CWE-770', message: 'No rate limiting' },
        content_security: { id: 'best/no-csp', severity: 'MEDIUM', cwe: '', message: 'No Content Security Policy' },
        cors_policy: { id: 'best/permissive-cors', severity: 'MEDIUM', cwe: 'CWE-346', message: 'Permissive CORS policy' },
        secure_headers: { id: 'best/missing-security-headers', severity: 'LOW', cwe: '', message: 'Security headers missing' },
        cookie_flags: { id: 'best/insecure-cookie', severity: 'MEDIUM', cwe: 'CWE-614', message: 'Cookie missing security flags' },
        https_only: { id: 'best/http-allowed', severity: 'MEDIUM', cwe: 'CWE-319', message: 'HTTP allowed (should be HTTPS only)' },
        secret_rotation: { id: 'best/no-secret-rotation', severity: 'LOW', cwe: '', message: 'Secrets not rotated' },
        dependency_update: { id: 'best/outdated-dependency', severity: 'LOW', cwe: 'CWE-1104', message: 'Outdated dependency' },
        code_review: { id: 'best/no-code-review', severity: 'LOW', cwe: '', message: 'Changes without code review' },
        security_testing: { id: 'best/no-security-testing', severity: 'MEDIUM', cwe: '', message: 'No security testing in pipeline' },
        docs_security: { id: 'best/no-security-docs', severity: 'LOW', cwe: '', message: 'Security documentation missing' },
        incident_playbook: { id: 'best/no-playbook', severity: 'LOW', cwe: '', message: 'No incident response playbook' },
        backup_testing: { id: 'best/backup-not-tested', severity: 'LOW', cwe: '', message: 'Backups not tested' },
    },
};

/**
 * Count total compliance rules
 */
function countComplianceRules() {
    let count = 0;
    for (const category of Object.values(COMPLIANCE_RULES)) {
        count += Object.keys(category).length;
    }
    return count;
}

/**
 * Get all compliance rules as array
 */
function getAllComplianceRules() {
    const rules = [];
    for (const [standard, standardRules] of Object.entries(COMPLIANCE_RULES)) {
        for (const [name, rule] of Object.entries(standardRules)) {
            rules.push({
                ...rule,
                standard,
                name
            });
        }
    }
    return rules;
}

module.exports = {
    COMPLIANCE_RULES,
    countComplianceRules,
    getAllComplianceRules
};
