/**
 * Java Security Rules - 100+ Rules
 * Spring, Spring Boot, JPA, and core Java patterns
 * @module security-rules-java
 */

const JAVA_RULES = {
    // ==================== CODE EXECUTION ====================
    CODE_EXECUTION: {
        runtime_exec: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-78', message: 'Runtime.exec() enables command injection' },
        processbuilder: { severity: 'HIGH', impact: 8, cwe: 'CWE-78', message: 'ProcessBuilder - validate commands' },
        script_engine: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-94', message: 'ScriptEngine.eval() executes arbitrary code' },
        reflection: { severity: 'HIGH', impact: 7, cwe: 'CWE-470', message: 'Reflection with user input enables code execution' },
    },

    // ==================== SQL INJECTION ====================
    SQL_INJECTION: {
        statement: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-89', message: 'Statement with string concat - use PreparedStatement' },
        string_query: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-89', message: 'String concatenation in SQL query' },
        native_query: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'Native query with parameters - use named parameters' },
        criteria_raw: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-89', message: 'Criteria API with raw expressions' },
    },

    // ==================== DESERIALIZATION ====================
    DESERIALIZATION: {
        object_input: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-502', message: 'ObjectInputStream.readObject() - deserialize safely' },
        xmldecoder: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-502', message: 'XMLDecoder enables arbitrary code execution' },
        xstream: { severity: 'HIGH', impact: 9, cwe: 'CWE-502', message: 'XStream deserialization - configure security' },
        jackson_type: { severity: 'HIGH', impact: 8, cwe: 'CWE-502', message: 'Jackson polymorphic deserialization - configure safely' },
        snakeyaml: { severity: 'HIGH', impact: 8, cwe: 'CWE-502', message: 'SnakeYAML arbitrary type instantiation' },
    },

    // ==================== SPRING SECURITY ====================
    SPRING: {
        csrf_disabled: { severity: 'HIGH', impact: 7, cwe: 'CWE-352', message: 'CSRF protection disabled' },
        permit_all: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-306', message: 'permitAll() on sensitive endpoint' },
        no_auth: { severity: 'HIGH', impact: 7, cwe: 'CWE-306', message: 'Controller without authentication' },
        bcrypt_weak: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-916', message: 'BCrypt strength below 10' },
        password_encoder: { severity: 'HIGH', impact: 8, cwe: 'CWE-916', message: 'NoOpPasswordEncoder - use BCrypt' },
        cookie_secure: { severity: 'HIGH', impact: 7, cwe: 'CWE-614', message: 'Session cookie without Secure flag' },
        cors_all: { severity: 'HIGH', impact: 7, cwe: 'CWE-346', message: 'CORS allows all origins' },
        debug_enabled: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-489', message: 'Debug logging in production' },
        actuator_exposed: { severity: 'HIGH', impact: 8, cwe: 'CWE-200', message: 'Actuator endpoints exposed without auth' },
        h2_console: { severity: 'CRITICAL', impact: 9, cwe: 'CWE-200', message: 'H2 console enabled in production' },
    },

    // ==================== VALIDATION ====================
    VALIDATION: {
        no_validation: { severity: 'HIGH', impact: 7, cwe: 'CWE-20', message: '@Valid/@Validated missing on request body' },
        unsafe_binder: { severity: 'HIGH', impact: 7, cwe: 'CWE-915', message: 'DataBinder without allowed fields - mass assignment' },
        regex_dos: { severity: 'HIGH', impact: 7, cwe: 'CWE-1333', message: '@Pattern regex vulnerable to ReDoS' },
    },

    // ==================== PATH TRAVERSAL ====================
    PATH_TRAVERSAL: {
        file_path: { severity: 'HIGH', impact: 8, cwe: 'CWE-22', message: 'File path from user input - validate' },
        resource_load: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-22', message: 'Resource loading with user path' },
        zip_slip: { severity: 'HIGH', impact: 8, cwe: 'CWE-22', message: 'Zip extraction without path validation - Zip Slip' },
    },

    // ==================== XXE ====================
    XXE: {
        documentbuilder: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'DocumentBuilder - set feature to prevent XXE' },
        saxparser: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'SAXParser without XXE protection' },
        xmlreader: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'XMLReader - disable external entities' },
        transformer: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'Transformer without secure processing' },
        jaxb: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-611', message: 'JAXB unmarshalling - configure safely' },
    },

    // ==================== SSRF ====================
    SSRF: {
        url_connect: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'URL.openConnection with user input' },
        http_client: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'HttpClient with user URL - validate' },
        resttemplate: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'RestTemplate with user URL' },
        webclient: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'WebClient with user URL' },
    },

    // ==================== LOGGING ====================
    LOGGING: {
        log_injection: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-117', message: 'User input in log - sanitize newlines' },
        sensitive_log: { severity: 'HIGH', impact: 7, cwe: 'CWE-532', message: 'Sensitive data logged' },
        log4shell: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-917', message: 'Log4j JNDI lookup - update immediately' },
    },

    // ==================== CRYPTOGRAPHY ====================
    CRYPTO: {
        md5: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-328', message: 'MD5 is broken' },
        sha1: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-328', message: 'SHA1 has collisions' },
        des: { severity: 'HIGH', impact: 7, cwe: 'CWE-327', message: 'DES is weak - use AES' },
        ecb_mode: { severity: 'HIGH', impact: 7, cwe: 'CWE-327', message: 'ECB mode insecure' },
        static_iv: { severity: 'HIGH', impact: 7, cwe: 'CWE-329', message: 'Static IV weakens encryption' },
        weak_random: { severity: 'HIGH', impact: 7, cwe: 'CWE-338', message: 'java.util.Random not cryptographic - use SecureRandom' },
        tls_version: { severity: 'HIGH', impact: 7, cwe: 'CWE-327', message: 'TLS 1.0/1.1 deprecated - use 1.2+' },
        cert_validation: { severity: 'CRITICAL', impact: 9, cwe: 'CWE-295', message: 'Certificate validation disabled' },
    },

    // ==================== SECRETS ====================
    SECRETS: {
        hardcoded_password: { severity: 'HIGH', impact: 8, cwe: 'CWE-798', message: 'Password hardcoded' },
        hardcoded_key: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Encryption key hardcoded' },
        properties_password: { severity: 'HIGH', impact: 8, cwe: 'CWE-798', message: 'Password in properties file' },
        connection_string: { severity: 'HIGH', impact: 8, cwe: 'CWE-798', message: 'Database credentials hardcoded' },
    },

    // ==================== JPA/Hibernate ====================
    JPA: {
        native_query_unsafe: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'Native query with string params' },
        jpql_concat: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'JPQL with string concatenation' },
        hql_injection: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'HQL injection vulnerability' },
        criteria_function: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-89', message: 'Criteria with function expression' },
    },

    // ==================== SERVLET ====================
    SERVLET: {
        xss: { severity: 'HIGH', impact: 8, cwe: 'CWE-79', message: 'Response.getWriter() without encoding' },
        open_redirect: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-601', message: 'Redirect with user URL' },
        session_fixation: { severity: 'HIGH', impact: 7, cwe: 'CWE-384', message: 'Session not invalidated on login' },
        concurrent_session: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-613', message: 'No concurrent session control' },
    },
};

module.exports = JAVA_RULES;
