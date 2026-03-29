/**
 * Python Security Rules - 100+ Rules
 * Django, Flask, FastAPI, and core Python patterns
 * @module security-rules-python
 */

const PYTHON_RULES = {
    // ==================== CODE EXECUTION ====================
    CODE_EXECUTION: {
        eval: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-95', message: 'eval() executes arbitrary code' },
        exec: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-95', message: 'exec() executes arbitrary code' },
        compile: { severity: 'HIGH', impact: 8, cwe: 'CWE-95', message: 'compile() can execute code dynamically' },
        importlib: { severity: 'HIGH', impact: 7, cwe: 'CWE-94', message: 'Dynamic import with user input' },
        __import__: { severity: 'HIGH', impact: 7, cwe: 'CWE-94', message: '__import__ with dynamic module name' },
        getattr: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-94', message: 'getattr with user-controlled attribute name' },
    },

    // ==================== COMMAND INJECTION ====================
    COMMAND_INJECTION: {
        subprocess_shell: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-78', message: 'subprocess with shell=True enables injection' },
        os_system: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-78', message: 'os.system() executes shell commands' },
        os_popen: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-78', message: 'os.popen() executes shell commands' },
        commands: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-78', message: 'commands module is deprecated and unsafe' },
    },

    // ==================== SQL INJECTION ====================
    SQL_INJECTION: {
        raw_query: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-89', message: 'Raw SQL with string formatting - use parameterized queries' },
        format_string: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-89', message: 'SQL with .format() - use parameterized queries' },
        fstring_sql: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-89', message: 'SQL f-string interpolation - use parameterized queries' },
        cursor_execute: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'cursor.execute with string concat - use placeholders' },
    },

    // ==================== DESERIALIZATION ====================
    DESERIALIZATION: {
        pickle: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-502', message: 'pickle.loads can execute arbitrary code' },
        yaml_load: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-502', message: 'yaml.load unsafe - use yaml.safe_load' },
        marshal: { severity: 'HIGH', impact: 8, cwe: 'CWE-502', message: 'marshal.loads with untrusted data' },
        shelve: { severity: 'HIGH', impact: 8, cwe: 'CWE-502', message: 'shelve uses pickle internally' },
    },

    // ==================== PATH TRAVERSAL ====================
    PATH_TRAVERSAL: {
        open_path: { severity: 'HIGH', impact: 8, cwe: 'CWE-22', message: 'open() with user input - validate path' },
        path_join: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-22', message: 'os.path.join with user input - use realpath' },
        send_file: { severity: 'HIGH', impact: 8, cwe: 'CWE-22', message: 'send_file with user path - validate base directory' },
    },

    // ==================== DJANGO SECURITY ====================
    DJANGO: {
        debug_true: { severity: 'HIGH', impact: 7, cwe: 'CWE-489', message: 'DEBUG = True in production' },
        secret_key_hardcoded: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'SECRET_KEY hardcoded in settings' },
        csrf_exempt: { severity: 'HIGH', impact: 7, cwe: 'CWE-352', message: '@csrf_exempt disables CSRF protection' },
        mark_safe: { severity: 'HIGH', impact: 8, cwe: 'CWE-79', message: 'mark_safe with user input - sanitize first' },
        raw_sql: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'RawSQL/raw() with user input' },
        extra_where: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: '.extra(where=...) with user input' },
        allowed_hosts_all: { severity: 'HIGH', impact: 7, cwe: 'CWE-346', message: "ALLOWED_HOSTS = ['*'] allows host header attacks" },
        no_password_validation: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-521', message: 'No password validators configured' },
        session_no_expire: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-613', message: 'Session never expires - set SESSION_COOKIE_AGE' },
        clickjacking_middleware: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-1021', message: 'XFrameOptionsMiddleware not enabled' },
    },

    // ==================== FLASK SECURITY ====================
    FLASK: {
        debug_true: { severity: 'HIGH', impact: 7, cwe: 'CWE-489', message: 'Flask debug mode in production' },
        secret_key_weak: { severity: 'HIGH', impact: 8, cwe: 'CWE-326', message: 'Flask SECRET_KEY too short or predictable' },
        no_csrf: { severity: 'HIGH', impact: 7, cwe: 'CWE-352', message: 'No Flask-WTF CSRF protection' },
        render_template_string: { severity: 'HIGH', impact: 8, cwe: 'CWE-94', message: 'render_template_string with user input - SSTI risk' },
        jinja_autoescape: { severity: 'HIGH', impact: 8, cwe: 'CWE-79', message: 'Jinja autoescape disabled' },
        send_from_directory: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-22', message: 'send_from_directory - validate filename' },
        session_permanent: { severity: 'LOW', impact: 3, cwe: 'CWE-613', message: 'Permanent session without expiry' },
    },

    // ==================== FASTAPI SECURITY ====================
    FASTAPI: {
        no_cors: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-346', message: 'CORS not configured' },
        wildcard_cors: { severity: 'HIGH', impact: 7, cwe: 'CWE-346', message: 'CORS allows all origins' },
        no_rate_limit: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-307', message: 'No rate limiting configured' },
        no_auth: { severity: 'HIGH', impact: 7, cwe: 'CWE-306', message: 'Endpoint without authentication' },
        query_injection: { severity: 'HIGH', impact: 8, cwe: 'CWE-89', message: 'Database query with unsanitized input' },
    },

    // ==================== CRYPTOGRAPHY ====================
    CRYPTO: {
        md5: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-328', message: 'MD5 is broken - use SHA-256+' },
        sha1: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-328', message: 'SHA1 has collisions - use SHA-256+' },
        weak_random: { severity: 'HIGH', impact: 7, cwe: 'CWE-338', message: 'random module not cryptographic - use secrets' },
        weak_bcrypt_rounds: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-916', message: 'bcrypt rounds too low - use 12+' },
        ecb_mode: { severity: 'HIGH', impact: 7, cwe: 'CWE-327', message: 'AES ECB mode insecure - use CBC/GCM' },
        static_iv: { severity: 'HIGH', impact: 7, cwe: 'CWE-329', message: 'Static IV weakens encryption' },
        hardcoded_key: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Encryption key hardcoded in source' },
    },

    // ==================== SSRF ====================
    SSRF: {
        requests_url: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'requests.get with user URL - validate domain' },
        urllib_open: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'urllib.urlopen with user input' },
        aiohttp_url: { severity: 'HIGH', impact: 8, cwe: 'CWE-918', message: 'aiohttp request with user URL' },
    },

    // ==================== LOGGING ====================
    LOGGING: {
        password_log: { severity: 'HIGH', impact: 7, cwe: 'CWE-532', message: 'Password logged - mask sensitive data' },
        token_log: { severity: 'HIGH', impact: 7, cwe: 'CWE-532', message: 'Token logged - mask sensitive data' },
        credit_card_log: { severity: 'CRITICAL', impact: 9, cwe: 'CWE-532', message: 'Credit card data logged' },
    },

    // ==================== XML ====================
    XML: {
        etree_parse: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'xml.etree vulnerable to XXE - use defusedxml' },
        minidom: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'xml.dom.minidom vulnerable to XXE' },
        pulldom: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'xml.dom.pulldom vulnerable to XXE' },
        sax: { severity: 'HIGH', impact: 8, cwe: 'CWE-611', message: 'xml.sax vulnerable to XXE' },
        lxml: { severity: 'MEDIUM', impact: 6, cwe: 'CWE-611', message: 'lxml.etree - disable external entities' },
    },

    // ==================== REGEX ====================
    REGEX: {
        redos: { severity: 'HIGH', impact: 7, cwe: 'CWE-1333', message: 'Regex pattern vulnerable to ReDoS' },
        user_regex: { severity: 'HIGH', impact: 7, cwe: 'CWE-1333', message: 'User input in regex - escape special chars' },
    },

    // ==================== HARDCODED SECRETS ====================
    SECRETS: {
        aws_key: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'AWS key hardcoded' },
        api_key: { severity: 'HIGH', impact: 8, cwe: 'CWE-798', message: 'API key hardcoded' },
        password: { severity: 'HIGH', impact: 8, cwe: 'CWE-798', message: 'Password hardcoded' },
        database_url: { severity: 'HIGH', impact: 8, cwe: 'CWE-798', message: 'Database URL with credentials hardcoded' },
        jwt_secret: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'JWT secret hardcoded' },
    },
};

module.exports = PYTHON_RULES;
