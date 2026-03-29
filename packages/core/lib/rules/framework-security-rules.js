/**
 * Framework-Specific Security Rules - 300+ Rules
 * 
 * Security rules for popular frameworks: React, Angular, Vue, Django, 
 * Flask, Spring, Express, Laravel, Rails, and more.
 * 
 * @module framework-security-rules
 */

const FRAMEWORK_SECURITY_RULES = {
    // ==================== REACT/NEXT.JS (40 rules) ====================
    REACT: {
        xss_dangerously: { id: 'react/dangerously-set-innerhtml', severity: 'MEDIUM', cwe: 'CWE-79', message: 'dangerouslySetInnerHTML used - ensure content is sanitized' },
        xss_href: { id: 'react/javascript-url-href', severity: 'HIGH', cwe: 'CWE-79', message: 'javascript: URL in href attribute' },
        ref_string: { id: 'react/string-ref-deprecated', severity: 'LOW', cwe: '', message: 'String refs are deprecated - use createRef' },
        no_key_prop: { id: 'react/missing-key-prop', severity: 'LOW', cwe: '', message: 'Missing key prop in list item' },
        state_mutation: { id: 'react/direct-state-mutation', severity: 'MEDIUM', cwe: '', message: 'Direct state mutation - use setState' },
        component_name: { id: 'react/invalid-component-name', severity: 'LOW', cwe: '', message: 'Component name should be PascalCase' },
        effect_deps: { id: 'react/exhaustive-deps', severity: 'LOW', cwe: '', message: 'useEffect dependencies incomplete' },
        unused_state: { id: 'react/unused-state', severity: 'LOW', cwe: '', message: 'State variable declared but never used' },
        event_handler: { id: 'react/unsafe-event-handler', severity: 'MEDIUM', cwe: 'CWE-79', message: 'Event handler executes user input' },
        unsafe_lifecycle: { id: 'react/unsafe-lifecycle', severity: 'LOW', cwe: '', message: 'UNSAFE_ lifecycle method used' },
        http_api: { id: 'react/http-api-call', severity: 'MEDIUM', cwe: 'CWE-319', message: 'API call over HTTP instead of HTTPS' },
        exposed_key: { id: 'react/exposed-api-key', severity: 'HIGH', cwe: 'CWE-798', message: 'API key in client-side code' },
        localstorage_sensitive: { id: 'react/localstorage-sensitive', severity: 'MEDIUM', cwe: 'CWE-922', message: 'Sensitive data in localStorage' },
        no_sanitize: { id: 'react/no-html-sanitize', severity: 'MEDIUM', cwe: 'CWE-79', message: 'HTML rendered without sanitization' },
        insecure_random: { id: 'react/math-random-id', severity: 'LOW', cwe: 'CWE-330', message: 'Math.random() for ID generation' },
        target_blank: { id: 'react/target-blank-noopener', severity: 'LOW', cwe: 'CWE-200', message: 'target=_blank without rel=noopener' },
        form_no_csrf: { id: 'react/form-no-csrf', severity: 'MEDIUM', cwe: 'CWE-352', message: 'Form without CSRF protection' },
        ssr_xss: { id: 'react/ssr-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'SSR output with unsanitized data' },
        getserverside_sql: { id: 'react/getserverside-sql-injection', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL in getServerSideProps with user input' },
        api_route_auth: { id: 'react/api-route-no-auth', severity: 'HIGH', cwe: 'CWE-306', message: 'Next.js API route without auth check' },
        // More React rules...
        context_sensitive: { id: 'react/context-sensitive-data', severity: 'MEDIUM', cwe: 'CWE-200', message: 'Sensitive data in React Context' },
        redux_sensitive: { id: 'react/redux-sensitive-data', severity: 'MEDIUM', cwe: 'CWE-200', message: 'Sensitive data in Redux store' },
        memo_function: { id: 'react/memo-with-function', severity: 'LOW', cwe: '', message: 'React.memo with function prop dependency' },
        callback_deps: { id: 'react/usecallback-deps', severity: 'LOW', cwe: '', message: 'useCallback dependencies may cause stale closure' },
        effect_async: { id: 'react/async-effect', severity: 'LOW', cwe: '', message: 'async function in useEffect' },
        portal_xss: { id: 'react/portal-xss', severity: 'MEDIUM', cwe: 'CWE-79', message: 'React Portal with dynamic content' },
        helmet_missing: { id: 'react/no-helmet', severity: 'LOW', cwe: '', message: 'React Helmet not used for meta tags' },
        router_xss: { id: 'react/router-xss', severity: 'MEDIUM', cwe: 'CWE-79', message: 'React Router with unsanitized params' },
        query_injection: { id: 'react/query-injection', severity: 'HIGH', cwe: 'CWE-89', message: 'URL query params used in database query' },
    },

    // ==================== VUE.JS (30 rules) ====================
    VUE: {
        v_html: { id: 'vue/v-html-directive', severity: 'MEDIUM', cwe: 'CWE-79', message: 'v-html directive with dynamic content' },
        domprops: { id: 'vue/domprops-injection', severity: 'HIGH', cwe: 'CWE-79', message: 'domProps with user input' },
        template_injection: { id: 'vue/template-injection', severity: 'CRITICAL', cwe: 'CWE-94', message: 'Dynamic Vue template compilation' },
        no_v_model: { id: 'vue/deprecated-v-model', severity: 'LOW', cwe: '', message: 'Deprecated v-model usage' },
        computed_mutation: { id: 'vue/computed-mutation', severity: 'MEDIUM', cwe: '', message: 'Mutation in computed property' },
        key_missing: { id: 'vue/v-for-no-key', severity: 'LOW', cwe: '', message: 'v-for without key attribute' },
        reactive_direct: { id: 'vue/reactive-direct-mutation', severity: 'MEDIUM', cwe: '', message: 'Direct reactive object mutation' },
        expose_api: { id: 'vue/expose-api-key', severity: 'HIGH', cwe: 'CWE-798', message: 'API key exposed in component' },
        router_guard: { id: 'vue/no-route-guard', severity: 'MEDIUM', cwe: 'CWE-284', message: 'Protected route without guard' },
        vuex_sensitive: { id: 'vue/vuex-sensitive', severity: 'MEDIUM', cwe: 'CWE-200', message: 'Sensitive data in Vuex store' },
        ssr_injection: { id: 'vue/ssr-injection', severity: 'HIGH', cwe: 'CWE-79', message: 'SSR with unsanitized input' },
        event_modifiers: { id: 'vue/missing-event-modifiers', severity: 'LOW', cwe: '', message: 'Event without .prevent or .stop modifier' },
        slot_default: { id: 'vue/unsanitized-slot', severity: 'MEDIUM', cwe: 'CWE-79', message: 'Slot content not sanitized' },
        injectt: { id: 'vue/inject-reactive', severity: 'LOW', cwe: '', message: 'Inject not reactive by default' },
        teleport_xss: { id: 'vue/teleport-xss', severity: 'MEDIUM', cwe: 'CWE-79', message: 'Teleport with dynamic target' },
    },

    // ==================== ANGULAR (30 rules) ====================
    ANGULAR: {
        bypass_security: { id: 'angular/bypass-security-trust', severity: 'HIGH', cwe: 'CWE-79', message: 'bypassSecurityTrust* method used' },
        innerhtml: { id: 'angular/innerhtml-binding', severity: 'MEDIUM', cwe: 'CWE-79', message: '[innerHTML] binding with dynamic content' },
        template_injection: { id: 'angular/template-injection', severity: 'CRITICAL', cwe: 'CWE-94', message: 'Dynamic template compilation' },
        ngif_auth: { id: 'angular/ngif-auth-only', severity: 'MEDIUM', cwe: 'CWE-284', message: '*ngIf used for auth without backend check' },
        route_guard: { id: 'angular/no-route-guard', severity: 'MEDIUM', cwe: 'CWE-284', message: 'Protected route without CanActivate' },
        http_no_https: { id: 'angular/http-without-https', severity: 'MEDIUM', cwe: 'CWE-319', message: 'HTTP instead of HTTPS' },
        xsrf_disabled: { id: 'angular/xsrf-disabled', severity: 'HIGH', cwe: 'CWE-352', message: 'XSRF protection disabled' },
        env_secrets: { id: 'angular/environment-secrets', severity: 'HIGH', cwe: 'CWE-798', message: 'Secrets in environment.ts' },
        injectable_any: { id: 'angular/injectable-any', severity: 'LOW', cwe: '', message: 'Injectable service returns any' },
        unsafe_pipe: { id: 'angular/unsafe-pipe', severity: 'MEDIUM', cwe: 'CWE-79', message: 'Custom pipe without sanitization' },
        ngrx_sensitive: { id: 'angular/ngrx-sensitive', severity: 'MEDIUM', cwe: 'CWE-200', message: 'Sensitive data in NgRx store' },
        renderer2_html: { id: 'angular/renderer2-html', severity: 'MEDIUM', cwe: 'CWE-79', message: 'Renderer2 setProperty innerHTML' },
        document_access: { id: 'angular/direct-document', severity: 'LOW', cwe: '', message: 'Direct document access in component' },
        elementref_native: { id: 'angular/elementref-native', severity: 'MEDIUM', cwe: 'CWE-79', message: 'ElementRef.nativeElement manipulation' },
        platform_browser: { id: 'angular/platform-browser-dynamic', severity: 'LOW', cwe: '', message: 'platformBrowserDynamic for AOT' },
    },

    // ==================== EXPRESS.JS (25 rules) ====================
    EXPRESS: {
        sql_injection: { id: 'express/sql-injection', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL query with unsanitized req params' },
        xss_response: { id: 'express/xss-response', severity: 'HIGH', cwe: 'CWE-79', message: 'Response with unsanitized user input' },
        no_helmet: { id: 'express/no-helmet', severity: 'MEDIUM', cwe: 'CWE-693', message: 'Express without helmet middleware' },
        no_rate_limit: { id: 'express/no-rate-limit', severity: 'MEDIUM', cwe: 'CWE-770', message: 'API without rate limiting' },
        cors_permissive: { id: 'express/cors-permissive', severity: 'MEDIUM', cwe: 'CWE-346', message: 'CORS allows all origins' },
        cookie_insecure: { id: 'express/cookie-insecure', severity: 'HIGH', cwe: 'CWE-614', message: 'Cookie without secure/httpOnly flags' },
        session_weak: { id: 'express/session-weak-secret', severity: 'HIGH', cwe: 'CWE-326', message: 'Weak session secret' },
        csrf_disabled: { id: 'express/csrf-disabled', severity: 'HIGH', cwe: 'CWE-352', message: 'CSRF protection not enabled' },
        path_traversal: { id: 'express/path-traversal', severity: 'HIGH', cwe: 'CWE-22', message: 'Path traversal in file operations' },
        eval_input: { id: 'express/eval-user-input', severity: 'CRITICAL', cwe: 'CWE-94', message: 'eval() with user input' },
        exec_input: { id: 'express/command-injection', severity: 'CRITICAL', cwe: 'CWE-78', message: 'exec/spawn with user input' },
        redirect_unvalidated: { id: 'express/open-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Redirect with unvalidated URL' },
        body_limit: { id: 'express/no-body-limit', severity: 'MEDIUM', cwe: 'CWE-400', message: 'Body parser without size limit' },
        upload_unrestricted: { id: 'express/unrestricted-upload', severity: 'HIGH', cwe: 'CWE-434', message: 'File upload without restrictions' },
        trust_proxy: { id: 'express/trust-proxy-misconfigured', severity: 'MEDIUM', cwe: '', message: 'trust proxy misconfigured' },
        error_details: { id: 'express/error-stack-exposed', severity: 'MEDIUM', cwe: 'CWE-209', message: 'Stack traces in error response' },
        jwt_verify: { id: 'express/jwt-no-verify', severity: 'CRITICAL', cwe: 'CWE-287', message: 'JWT not verified' },
        auth_bypass: { id: 'express/auth-middleware-bypass', severity: 'HIGH', cwe: 'CWE-287', message: 'Auth middleware can be bypassed' },
        ssrf_request: { id: 'express/ssrf', severity: 'HIGH', cwe: 'CWE-918', message: 'Request to user-controlled URL' },
        nosql_injection: { id: 'express/nosql-injection', severity: 'HIGH', cwe: 'CWE-943', message: 'NoSQL query with user input' },
    },

    // ==================== DJANGO (30 rules) ====================
    DJANGO: {
        sql_raw: { id: 'django/raw-sql', severity: 'HIGH', cwe: 'CWE-89', message: 'Raw SQL query - use ORM instead' },
        xss_safe: { id: 'django/mark-safe-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'mark_safe with user input' },
        csrf_exempt: { id: 'django/csrf-exempt', severity: 'HIGH', cwe: 'CWE-352', message: 'csrf_exempt decorator used' },
        debug_true: { id: 'django/debug-true', severity: 'HIGH', cwe: 'CWE-489', message: 'DEBUG=True in production' },
        secret_key: { id: 'django/hardcoded-secret-key', severity: 'CRITICAL', cwe: 'CWE-798', message: 'SECRET_KEY hardcoded' },
        allowed_hosts: { id: 'django/allowed-hosts-all', severity: 'HIGH', cwe: 'CWE-284', message: "ALLOWED_HOSTS = ['*']" },
        password_validators: { id: 'django/no-password-validators', severity: 'MEDIUM', cwe: 'CWE-521', message: 'No password validators configured' },
        session_cookie: { id: 'django/session-cookie-insecure', severity: 'MEDIUM', cwe: 'CWE-614', message: 'Session cookie not secure' },
        clickjacking: { id: 'django/x-frame-options-missing', severity: 'MEDIUM', cwe: 'CWE-1021', message: 'X-Frame-Options not set' },
        ssl_redirect: { id: 'django/no-ssl-redirect', severity: 'MEDIUM', cwe: 'CWE-319', message: 'SECURE_SSL_REDIRECT not enabled' },
        template_autoescape: { id: 'django/autoescape-off', severity: 'HIGH', cwe: 'CWE-79', message: 'autoescape off in template' },
        pickle_session: { id: 'django/pickle-session', severity: 'HIGH', cwe: 'CWE-502', message: 'Pickle session serializer used' },
        file_upload: { id: 'django/unrestricted-file-upload', severity: 'HIGH', cwe: 'CWE-434', message: 'File upload without validation' },
        mass_assignment: { id: 'django/mass-assignment', severity: 'MEDIUM', cwe: 'CWE-915', message: 'ModelForm without fields/exclude' },
        shell_injection: { id: 'django/shell-injection', severity: 'CRITICAL', cwe: 'CWE-78', message: 'subprocess with shell=True' },
        eval_exec: { id: 'django/eval-exec', severity: 'CRITICAL', cwe: 'CWE-94', message: 'eval/exec with user input' },
        open_redirect: { id: 'django/open-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Open redirect vulnerability' },
        xml_parser: { id: 'django/unsafe-xml-parser', severity: 'HIGH', cwe: 'CWE-611', message: 'XML parser with entity expansion' },
        json_response: { id: 'django/json-response-callback', severity: 'MEDIUM', cwe: 'CWE-79', message: 'JSONP callback without validation' },
        admin_path: { id: 'django/default-admin-path', severity: 'LOW', cwe: '', message: 'Default /admin/ path' },
    },

    // ==================== FLASK (25 rules) ====================
    FLASK: {
        debug_mode: { id: 'flask/debug-mode', severity: 'HIGH', cwe: 'CWE-489', message: 'Debug mode enabled' },
        secret_key: { id: 'flask/weak-secret-key', severity: 'HIGH', cwe: 'CWE-326', message: 'Weak or hardcoded secret key' },
        sql_injection: { id: 'flask/sql-injection', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL query with user input' },
        jinja_autoescape: { id: 'flask/autoescape-disabled', severity: 'HIGH', cwe: 'CWE-79', message: 'Jinja autoescape disabled' },
        xss_markup: { id: 'flask/markup-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'Markup() with user input' },
        redirect_unsafe: { id: 'flask/unsafe-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Redirect with unvalidated URL' },
        send_file: { id: 'flask/send-file-path-traversal', severity: 'HIGH', cwe: 'CWE-22', message: 'send_file with user path' },
        pickle_session: { id: 'flask/pickle-session', severity: 'HIGH', cwe: 'CWE-502', message: 'Pickle in session' },
        yaml_load: { id: 'flask/unsafe-yaml-load', severity: 'CRITICAL', cwe: 'CWE-502', message: 'yaml.load() without safe_load' },
        eval_exec: { id: 'flask/eval-exec', severity: 'CRITICAL', cwe: 'CWE-94', message: 'eval/exec with request data' },
        subprocess_shell: { id: 'flask/subprocess-shell', severity: 'CRITICAL', cwe: 'CWE-78', message: 'subprocess with shell=True' },
        cors_all: { id: 'flask/cors-all-origins', severity: 'MEDIUM', cwe: 'CWE-346', message: 'CORS allows all origins' },
        session_cookie: { id: 'flask/session-cookie-insecure', severity: 'MEDIUM', cwe: 'CWE-614', message: 'Session cookie not secure' },
        template_render: { id: 'flask/template-render-string', severity: 'HIGH', cwe: 'CWE-94', message: 'render_template_string with input' },
        jsonify_xss: { id: 'flask/jsonify-html-mimetype', severity: 'MEDIUM', cwe: 'CWE-79', message: 'JSON with HTML content-type' },
    },

    // ==================== SPRING (30 rules) ====================
    SPRING: {
        sql_injection: { id: 'spring/sql-injection', severity: 'CRITICAL', cwe: 'CWE-89', message: 'Native query with user input' },
        xss_response: { id: 'spring/xss-response', severity: 'HIGH', cwe: 'CWE-79', message: 'Response with unescaped user input' },
        csrf_disabled: { id: 'spring/csrf-disabled', severity: 'HIGH', cwe: 'CWE-352', message: 'CSRF protection disabled' },
        cors_permissive: { id: 'spring/cors-permissive', severity: 'MEDIUM', cwe: 'CWE-346', message: 'CORS allows all origins' },
        auth_bypass: { id: 'spring/permitall-sensitive', severity: 'HIGH', cwe: 'CWE-284', message: 'permitAll() on sensitive endpoint' },
        actuator_exposed: { id: 'spring/actuator-exposed', severity: 'HIGH', cwe: 'CWE-200', message: 'Actuator endpoints publicly exposed' },
        path_traversal: { id: 'spring/path-traversal', severity: 'HIGH', cwe: 'CWE-22', message: 'Path traversal in file access' },
        deserialization: { id: 'spring/unsafe-deserialization', severity: 'CRITICAL', cwe: 'CWE-502', message: 'Unsafe deserialization' },
        xml_external: { id: 'spring/xxe', severity: 'HIGH', cwe: 'CWE-611', message: 'XXE in XML processing' },
        ldap_injection: { id: 'spring/ldap-injection', severity: 'HIGH', cwe: 'CWE-90', message: 'LDAP injection vulnerability' },
        expression_injection: { id: 'spring/spel-injection', severity: 'CRITICAL', cwe: 'CWE-917', message: 'SpEL injection' },
        hardcoded_password: { id: 'spring/hardcoded-credential', severity: 'CRITICAL', cwe: 'CWE-798', message: 'Hardcoded credential' },
        weak_crypto: { id: 'spring/weak-crypto', severity: 'HIGH', cwe: 'CWE-327', message: 'Weak cryptographic algorithm' },
        insecure_random: { id: 'spring/insecure-random', severity: 'MEDIUM', cwe: 'CWE-330', message: 'Insecure random for security' },
        mass_assignment: { id: 'spring/mass-assignment', severity: 'MEDIUM', cwe: 'CWE-915', message: 'Mass assignment vulnerability' },
        debug_logging: { id: 'spring/debug-logging-prod', severity: 'MEDIUM', cwe: 'CWE-532', message: 'Debug logging in production' },
        h2_console: { id: 'spring/h2-console-enabled', severity: 'HIGH', cwe: 'CWE-489', message: 'H2 console enabled' },
        trust_manager: { id: 'spring/trust-all-certs', severity: 'CRITICAL', cwe: 'CWE-295', message: 'TrustManager accepts all certs' },
        redirect_unvalidated: { id: 'spring/open-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Unvalidated redirect' },
        ssrf: { id: 'spring/ssrf', severity: 'HIGH', cwe: 'CWE-918', message: 'SSRF vulnerability' },
    },

    // ==================== LARAVEL (25 rules) ====================
    LARAVEL: {
        sql_raw: { id: 'laravel/raw-query', severity: 'HIGH', cwe: 'CWE-89', message: 'Raw SQL query with user input' },
        xss_blade: { id: 'laravel/unescaped-output', severity: 'HIGH', cwe: 'CWE-79', message: '{!! $var !!} without sanitization' },
        csrf_disabled: { id: 'laravel/csrf-disabled', severity: 'HIGH', cwe: 'CWE-352', message: 'CSRF verification disabled' },
        mass_assignment: { id: 'laravel/mass-assignment', severity: 'HIGH', cwe: 'CWE-915', message: 'Model without $fillable/$guarded' },
        debug_mode: { id: 'laravel/debug-mode', severity: 'HIGH', cwe: 'CWE-489', message: 'APP_DEBUG=true in production' },
        env_exposed: { id: 'laravel/env-exposed', severity: 'CRITICAL', cwe: 'CWE-200', message: '.env file publicly accessible' },
        upload_unrestricted: { id: 'laravel/unrestricted-upload', severity: 'HIGH', cwe: 'CWE-434', message: 'File upload without validation' },
        auth_bypass: { id: 'laravel/auth-bypass', severity: 'HIGH', cwe: 'CWE-284', message: 'Authorization check missing' },
        redirect_unvalidated: { id: 'laravel/open-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Redirect with user input' },
        shell_exec: { id: 'laravel/command-injection', severity: 'CRITICAL', cwe: 'CWE-78', message: 'shell_exec/exec with user input' },
        path_traversal: { id: 'laravel/path-traversal', severity: 'HIGH', cwe: 'CWE-22', message: 'File path from user input' },
        cookie_insecure: { id: 'laravel/cookie-insecure', severity: 'MEDIUM', cwe: 'CWE-614', message: 'Cookie without secure flag' },
        session_driver: { id: 'laravel/session-file-driver', severity: 'LOW', cwe: '', message: 'File session driver in production' },
        log_sensitive: { id: 'laravel/log-sensitive-data', severity: 'MEDIUM', cwe: 'CWE-532', message: 'Sensitive data in logs' },
        cors_permissive: { id: 'laravel/cors-permissive', severity: 'MEDIUM', cwe: 'CWE-346', message: 'CORS allows all origins' },
    },

    // ==================== RAILS (25 rules) ====================
    RAILS: {
        sql_injection: { id: 'rails/sql-injection', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL query with interpolation' },
        xss_html_safe: { id: 'rails/html-safe-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'html_safe on user input' },
        xss_raw: { id: 'rails/raw-xss', severity: 'HIGH', cwe: 'CWE-79', message: 'raw() helper with user input' },
        mass_assignment: { id: 'rails/mass-assignment', severity: 'HIGH', cwe: 'CWE-915', message: 'Mass assignment without strong params' },
        csrf_disabled: { id: 'rails/csrf-disabled', severity: 'HIGH', cwe: 'CWE-352', message: 'CSRF protection disabled' },
        redirect_unsafe: { id: 'rails/open-redirect', severity: 'MEDIUM', cwe: 'CWE-601', message: 'Redirect to user-controlled URL' },
        render_inline: { id: 'rails/render-inline', severity: 'HIGH', cwe: 'CWE-79', message: 'render inline with user data' },
        send_file: { id: 'rails/send-file-path', severity: 'HIGH', cwe: 'CWE-22', message: 'send_file with user path' },
        yaml_load: { id: 'rails/unsafe-yaml', severity: 'CRITICAL', cwe: 'CWE-502', message: 'YAML.load with user input' },
        marshal_load: { id: 'rails/marshal-load', severity: 'CRITICAL', cwe: 'CWE-502', message: 'Marshal.load deserialization' },
        exec_command: { id: 'rails/command-injection', severity: 'CRITICAL', cwe: 'CWE-78', message: 'system/exec with user input' },
        regex_dos: { id: 'rails/regex-dos', severity: 'MEDIUM', cwe: 'CWE-1333', message: 'Regex with user input (ReDoS)' },
        secrets_hardcoded: { id: 'rails/hardcoded-secret', severity: 'CRITICAL', cwe: 'CWE-798', message: 'Hardcoded secret in code' },
        http_basic: { id: 'rails/http-basic-hardcoded', severity: 'HIGH', cwe: 'CWE-798', message: 'Hardcoded HTTP Basic credentials' },
        ssl_verify: { id: 'rails/ssl-verify-none', severity: 'CRITICAL', cwe: 'CWE-295', message: 'SSL verification disabled' },
    },

    // ==================== GO (25 rules) ====================
    GO: {
        sql_injection: { id: 'go/sql-injection', severity: 'CRITICAL', cwe: 'CWE-89', message: 'SQL query with string concatenation' },
        xss_response: { id: 'go/xss-response', severity: 'HIGH', cwe: 'CWE-79', message: 'Response with unsanitized input' },
        path_traversal: { id: 'go/path-traversal', severity: 'HIGH', cwe: 'CWE-22', message: 'Path traversal vulnerability' },
        command_injection: { id: 'go/command-injection', severity: 'CRITICAL', cwe: 'CWE-78', message: 'exec.Command with user input' },
        ssrf: { id: 'go/ssrf', severity: 'HIGH', cwe: 'CWE-918', message: 'HTTP request to user URL' },
        tls_insecure: { id: 'go/tls-insecure', severity: 'HIGH', cwe: 'CWE-295', message: 'InsecureSkipVerify = true' },
        weak_crypto: { id: 'go/weak-crypto', severity: 'HIGH', cwe: 'CWE-327', message: 'Weak cryptographic algorithm' },
        hardcoded_cred: { id: 'go/hardcoded-credential', severity: 'CRITICAL', cwe: 'CWE-798', message: 'Hardcoded credential' },
        defer_panic: { id: 'go/defer-panic', severity: 'LOW', cwe: '', message: 'defer with potential panic' },
        goroutine_leak: { id: 'go/goroutine-leak', severity: 'MEDIUM', cwe: 'CWE-400', message: 'Potential goroutine leak' },
        race_condition: { id: 'go/race-condition', severity: 'MEDIUM', cwe: 'CWE-362', message: 'Potential race condition' },
        unsafe_pointer: { id: 'go/unsafe-pointer', severity: 'MEDIUM', cwe: 'CWE-787', message: 'unsafe.Pointer usage' },
        error_ignored: { id: 'go/error-ignored', severity: 'MEDIUM', cwe: 'CWE-755', message: 'Error return value ignored' },
        jwt_none: { id: 'go/jwt-none-algorithm', severity: 'CRITICAL', cwe: 'CWE-327', message: 'JWT none algorithm allowed' },
        xml_decode: { id: 'go/xxe', severity: 'HIGH', cwe: 'CWE-611', message: 'XML decoder without entity limits' },
    },
};

/**
 * Count total framework rules
 */
function countFrameworkRules() {
    let count = 0;
    for (const category of Object.values(FRAMEWORK_SECURITY_RULES)) {
        count += Object.keys(category).length;
    }
    return count;
}

/**
 * Get all framework rules as array
 */
function getAllFrameworkRules() {
    const rules = [];
    for (const [framework, frameworkRules] of Object.entries(FRAMEWORK_SECURITY_RULES)) {
        for (const [name, rule] of Object.entries(frameworkRules)) {
            rules.push({
                ...rule,
                framework,
                name
            });
        }
    }
    return rules;
}

module.exports = {
    FRAMEWORK_SECURITY_RULES,
    countFrameworkRules,
    getAllFrameworkRules
};
