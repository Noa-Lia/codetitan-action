/**
 * Python Security Analyzer
 * 
 * Regex-based security detection for Python code
 * Detects common vulnerabilities in Python applications
 * 
 * @module python-analyzer
 */

const fs = require('fs');
const path = require('path');

/**
 * Python security rules
 */
const PYTHON_RULES = {
    CODE_EXECUTION: [
        {
            id: 'EVAL_USAGE',
            pattern: /\beval\s*\(/,
            severity: 'CRITICAL',
            message: 'eval() executes arbitrary code - avoid or use ast.literal_eval',
            impact: 10,
            cwe: 'CWE-95',
        },
        {
            id: 'EXEC_USAGE',
            pattern: /\bexec\s*\(/,
            severity: 'CRITICAL',
            message: 'exec() executes arbitrary Python code',
            impact: 10,
            cwe: 'CWE-95',
        },
        {
            id: 'COMPILE_USAGE',
            pattern: /\bcompile\s*\([^)]+,\s*[^)]+,\s*['"]exec['"]/,
            severity: 'HIGH',
            message: 'compile() with exec mode can execute arbitrary code',
            impact: 8,
            cwe: 'CWE-95',
        },
    ],

    COMMAND_INJECTION: [
        {
            id: 'OS_SYSTEM',
            pattern: /\bos\.system\s*\(/,
            severity: 'CRITICAL',
            message: 'os.system() is vulnerable to command injection - use subprocess with shell=False',
            impact: 10,
            cwe: 'CWE-78',
        },
        {
            id: 'OS_POPEN',
            pattern: /\bos\.popen\s*\(/,
            severity: 'CRITICAL',
            message: 'os.popen() is vulnerable to command injection - use subprocess',
            impact: 10,
            cwe: 'CWE-78',
        },
        {
            id: 'SUBPROCESS_SHELL',
            pattern: /subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True/,
            severity: 'CRITICAL',
            message: 'subprocess with shell=True enables command injection',
            impact: 10,
            cwe: 'CWE-78',
        },
        {
            id: 'COMMANDS_MODULE',
            pattern: /\bcommands\.(getoutput|getstatusoutput)\s*\(/,
            severity: 'CRITICAL',
            message: 'commands module is deprecated and vulnerable - use subprocess',
            impact: 9,
            cwe: 'CWE-78',
        },
    ],

    SQL_INJECTION: [
        {
            id: 'SQL_FORMAT_STRING',
            pattern: /execute\s*\(\s*["'][^"']*%s[^"']*["']\s*%/,
            severity: 'CRITICAL',
            message: 'SQL query with string formatting - use parameterized queries',
            impact: 10,
            cwe: 'CWE-89',
        },
        {
            id: 'SQL_FSTRING',
            pattern: /execute\s*\(\s*f["'][^"']*{[^}]+}[^"']*["']/,
            severity: 'CRITICAL',
            message: 'SQL query with f-string - use parameterized queries',
            impact: 10,
            cwe: 'CWE-89',
        },
        {
            id: 'SQL_CONCAT',
            pattern: /execute\s*\(\s*["'][^"']+["']\s*\+/,
            severity: 'CRITICAL',
            message: 'SQL query with string concatenation - use parameterized queries',
            impact: 10,
            cwe: 'CWE-89',
        },
        {
            id: 'RAW_SQL',
            pattern: /\.raw\s*\(\s*f?["'][^"']*{/,
            severity: 'CRITICAL',
            message: 'Raw SQL with interpolation - use parameterized queries',
            impact: 10,
            cwe: 'CWE-89',
        },
    ],

    XSS: [
        {
            id: 'MARK_SAFE',
            pattern: /mark_safe\s*\(/,
            severity: 'HIGH',
            message: 'mark_safe() bypasses Django XSS protection - ensure input is sanitized',
            impact: 8,
            cwe: 'CWE-79',
        },
        {
            id: 'SAFESTRING',
            pattern: /SafeString\s*\(/,
            severity: 'HIGH',
            message: 'SafeString bypasses XSS protection - ensure input is sanitized',
            impact: 8,
            cwe: 'CWE-79',
        },
        {
            id: 'AUTOESCAPE_OFF',
            pattern: /autoescape\s*(off|false|False)/,
            severity: 'HIGH',
            message: 'Autoescape disabled - XSS vulnerability',
            impact: 8,
            cwe: 'CWE-79',
        },
    ],

    DESERIALIZATION: [
        {
            id: 'PICKLE_LOAD',
            pattern: /pickle\.(load|loads)\s*\(/,
            severity: 'CRITICAL',
            message: 'pickle can execute arbitrary code on untrusted data',
            impact: 10,
            cwe: 'CWE-502',
        },
        {
            id: 'CPICKLE',
            pattern: /cPickle\.(load|loads)\s*\(/,
            severity: 'CRITICAL',
            message: 'cPickle can execute arbitrary code on untrusted data',
            impact: 10,
            cwe: 'CWE-502',
        },
        {
            id: 'YAML_LOAD',
            pattern: /yaml\.load\s*\([^)]*Loader\s*=\s*None/,
            severity: 'CRITICAL',
            message: 'yaml.load without SafeLoader can execute arbitrary code',
            impact: 10,
            cwe: 'CWE-502',
        },
        {
            id: 'YAML_UNSAFE',
            pattern: /yaml\.unsafe_load\s*\(/,
            severity: 'CRITICAL',
            message: 'yaml.unsafe_load executes arbitrary code',
            impact: 10,
            cwe: 'CWE-502',
        },
        {
            id: 'MARSHAL_LOADS',
            pattern: /marshal\.loads?\s*\(/,
            severity: 'HIGH',
            message: 'marshal can execute arbitrary code on untrusted data',
            impact: 8,
            cwe: 'CWE-502',
        },
        {
            id: 'SHELVE_OPEN',
            pattern: /shelve\.open\s*\(/,
            severity: 'HIGH',
            message: 'shelve uses pickle internally - vulnerable to code execution',
            impact: 8,
            cwe: 'CWE-502',
        },
    ],

    PATH_TRAVERSAL: [
        {
            id: 'OPEN_USER_INPUT',
            pattern: /open\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[\+,]/,
            severity: 'HIGH',
            message: 'File open with variable path - validate to prevent path traversal',
            impact: 8,
            cwe: 'CWE-22',
        },
        {
            id: 'FSTRING_PATH',
            pattern: /open\s*\(\s*f["']/,
            severity: 'HIGH',
            message: 'File open with f-string path - validate to prevent traversal',
            impact: 8,
            cwe: 'CWE-22',
        },
        {
            id: 'SEND_FILE_UNSAFE',
            pattern: /send_file\s*\([^)]*\.\.\//,
            severity: 'HIGH',
            message: 'send_file with path traversal pattern detected',
            impact: 8,
            cwe: 'CWE-22',
        },
    ],

    SECRETS: [
        {
            id: 'HARDCODED_PASSWORD',
            pattern: /(password|passwd|pwd)\s*=\s*["'][^"']{8,}["']/i,
            severity: 'HIGH',
            message: 'Hardcoded password - use environment variables',
            impact: 9,
            cwe: 'CWE-798',
        },
        {
            id: 'HARDCODED_SECRET',
            pattern: /(secret|api_key|apikey|token|auth)\s*=\s*["'][^"']{8,}["']/i,
            severity: 'HIGH',
            message: 'Hardcoded secret - use environment variables',
            impact: 9,
            cwe: 'CWE-798',
        },
        {
            id: 'AWS_KEY',
            pattern: /AKIA[0-9A-Z]{16}/,
            severity: 'CRITICAL',
            message: 'AWS Access Key detected in code',
            impact: 10,
            cwe: 'CWE-798',
        },
        {
            id: 'PRIVATE_KEY',
            pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
            severity: 'CRITICAL',
            message: 'Private key in source code',
            impact: 10,
            cwe: 'CWE-798',
        },
    ],

    CRYPTO: [
        {
            id: 'MD5_HASH',
            pattern: /hashlib\.md5\s*\(/,
            severity: 'MEDIUM',
            message: 'MD5 is cryptographically weak - use SHA-256+',
            impact: 6,
            cwe: 'CWE-328',
        },
        {
            id: 'SHA1_HASH',
            pattern: /hashlib\.sha1\s*\(/,
            severity: 'MEDIUM',
            message: 'SHA1 has known weaknesses - use SHA-256+',
            impact: 6,
            cwe: 'CWE-328',
        },
        {
            id: 'RANDOM_SECURITY',
            pattern: /random\.(random|randint|choice|randrange)\s*\(/,
            severity: 'MEDIUM',
            message: 'random module is not cryptographically secure - use secrets module',
            impact: 5,
            cwe: 'CWE-338',
            context: 'security',
        },
        {
            id: 'DES_USAGE',
            pattern: /DES\.(new|encrypt|decrypt)/,
            severity: 'HIGH',
            message: 'DES is broken - use AES-256',
            impact: 7,
            cwe: 'CWE-327',
        },
    ],

    SSRF: [
        {
            id: 'REQUESTS_USER_URL',
            pattern: /requests\.(get|post|put|delete|patch)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*/,
            severity: 'MEDIUM',
            message: 'HTTP request with variable URL - validate to prevent SSRF',
            impact: 6,
            cwe: 'CWE-918',
        },
        {
            id: 'URLLIB_USER_URL',
            pattern: /urllib\.request\.urlopen\s*\(\s*[a-zA-Z_]/,
            severity: 'MEDIUM',
            message: 'URL open with variable - validate to prevent SSRF',
            impact: 6,
            cwe: 'CWE-918',
        },
    ],

    FLASK: [
        {
            id: 'DEBUG_TRUE',
            pattern: /app\.run\s*\([^)]*debug\s*=\s*True/,
            severity: 'HIGH',
            message: 'Flask debug mode in production enables code execution',
            impact: 8,
            cwe: 'CWE-489',
        },
        {
            id: 'SECRET_KEY_HARDCODED',
            pattern: /SECRET_KEY\s*=\s*["'][^"']+["']/,
            severity: 'HIGH',
            message: 'Hardcoded Flask SECRET_KEY - use environment variable',
            impact: 8,
            cwe: 'CWE-798',
        },
    ],

    DJANGO: [
        {
            id: 'DEBUG_TRUE',
            pattern: /DEBUG\s*=\s*True/,
            severity: 'HIGH',
            message: 'Django DEBUG=True in production exposes sensitive info',
            impact: 7,
            cwe: 'CWE-489',
        },
        {
            id: 'ALLOWED_HOSTS_EMPTY',
            pattern: /ALLOWED_HOSTS\s*=\s*\[\s*\]/,
            severity: 'MEDIUM',
            message: 'Empty ALLOWED_HOSTS can lead to host header attacks',
            impact: 5,
            cwe: 'CWE-644',
        },
        {
            id: 'CSRF_EXEMPT',
            pattern: /@csrf_exempt/,
            severity: 'MEDIUM',
            message: 'CSRF protection disabled - ensure endpoint is safe',
            impact: 6,
            cwe: 'CWE-352',
        },
    ],

    REGEX: [
        {
            id: 'REGEX_USER_INPUT',
            pattern: /re\.(match|search|findall|sub)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,/,
            severity: 'MEDIUM',
            message: 'Regex with user input - escape to prevent ReDoS',
            impact: 5,
            cwe: 'CWE-1333',
        },
    ],

    ASSERT: [
        {
            id: 'ASSERT_SECURITY',
            pattern: /assert\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(==|!=|is|in)/,
            severity: 'LOW',
            message: 'assert can be disabled with -O flag - use proper validation',
            impact: 4,
            cwe: 'CWE-617',
        },
    ],

    TEMPFILE: [
        {
            id: 'MKTEMP_USAGE',
            pattern: /tempfile\.mktemp\s*\(/,
            severity: 'MEDIUM',
            message: 'mktemp is deprecated and insecure - use mkstemp',
            impact: 5,
            cwe: 'CWE-377',
        },
    ],

    XML: [
        {
            id: 'ETREE_PARSE',
            pattern: /etree\.(parse|fromstring)\s*\(/,
            severity: 'HIGH',
            message: 'XML parsing vulnerable to XXE - use defusedxml',
            impact: 8,
            cwe: 'CWE-611',
        },
        {
            id: 'MINIDOM_PARSE',
            pattern: /minidom\.parse\s*\(/,
            severity: 'HIGH',
            message: 'XML parsing vulnerable to XXE - use defusedxml',
            impact: 8,
            cwe: 'CWE-611',
        },
        {
            id: 'SAX_PARSE',
            pattern: /sax\.parse\s*\(/,
            severity: 'HIGH',
            message: 'SAX parser vulnerable to XXE - use defusedxml',
            impact: 8,
            cwe: 'CWE-611',
        },
    ],
};

/**
 * Get context lines around a line
 */
function getContextLines(lines, index, size = 2) {
    const start = Math.max(0, index - size);
    const end = Math.min(lines.length, index + size + 1);
    return lines.slice(start, end);
}

/**
 * Analyze Python code
 */
function analyzePython(code, filePath, projectRoot = '.') {
    const lines = code.split('\n');
    const findings = [];

    // Check each line against all rules
    lines.forEach((line, index) => {
        const lineNum = index + 1;
        const trimmedLine = line.trim();

        // Skip comments
        if (trimmedLine.startsWith('#')) return;

        // Skip empty lines
        if (!trimmedLine) return;

        // Check all rule categories
        Object.entries(PYTHON_RULES).forEach(([category, rules]) => {
            rules.forEach(rule => {
                const match = rule.pattern.exec(line);
                if (match) {
                    findings.push({
                        line: lineNum,
                        column: match.index,
                        endLine: lineNum,
                        endColumn: match.index + match[0].length,
                        severity: rule.severity,
                        category: rule.id,
                        message: rule.message,
                        impact: rule.impact,
                        snippet: trimmedLine,
                        context: getContextLines(lines, index, 2),
                        cwe: rule.cwe,
                        language: 'python',
                    });
                }
            });
        });
    });

    return {
        issues: findings,
        linesAnalyzed: lines.length,
        language: 'python',
        rulesApplied: Object.values(PYTHON_RULES).flat().length,
    };
}

/**
 * Analyze Python file
 */
async function analyzePythonFile(filePath) {
    const code = await fs.promises.readFile(filePath, 'utf-8');
    const result = analyzePython(code, filePath);
    result.file = filePath;
    return result;
}

/**
 * Find Python files in directory
 */
async function findPythonFiles(dir, files = []) {
    const items = await fs.promises.readdir(dir);

    for (const item of items) {
        if (item === 'node_modules' || item === '__pycache__' ||
            item === 'venv' || item === '.venv' || item.startsWith('.')) continue;

        const fullPath = path.join(dir, item);
        const stat = await fs.promises.stat(fullPath);

        if (stat.isDirectory()) {
            await findPythonFiles(fullPath, files);
        } else if (item.endsWith('.py')) {
            files.push(fullPath);
        }
    }

    return files;
}

/**
 * Get rule count
 */
function getRuleCount() {
    return Object.values(PYTHON_RULES).flat().length;
}

module.exports = {
    analyzePython,
    analyzePythonFile,
    findPythonFiles,
    getRuleCount,
    PYTHON_RULES,
};
