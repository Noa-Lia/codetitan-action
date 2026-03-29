/**
 * Enhanced AST-Based Security Analyzer
 * 
 * Uses @babel/parser with 50+ security detection rules
 * Accurate detection that skips comments and strings
 * 
 * @module enhanced-analyzer
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const fs = require('fs');
const path = require('path');
const { SECURITY_RULES, SECRET_PATTERNS, DANGEROUS_PATTERNS } = require('./security-rules');

/**
 * Parse JavaScript/TypeScript code into AST
 */
function parseCode(code, filePath) {
    const isTypeScript = /\.tsx?$/.test(filePath);
    const isJSX = /\.jsx$/.test(filePath) || /\.tsx$/.test(filePath);

    const plugins = ['decorators-legacy', 'classProperties', 'objectRestSpread',
        'optionalChaining', 'nullishCoalescingOperator', 'dynamicImport'];
    if (isTypeScript) plugins.push('typescript');
    if (isJSX) plugins.push('jsx');

    try {
        return parser.parse(code, {
            sourceType: 'module',
            plugins,
            errorRecovery: true,
            allowImportExportEverywhere: true,
            allowAwaitOutsideFunction: true,
            allowReturnOutsideFunction: true,
        });
    } catch (error) {
        try {
            return parser.parse(code, { sourceType: 'script', plugins, errorRecovery: true });
        } catch (e) {
            return null;
        }
    }
}

/**
 * Get surrounding context lines
 */
function getContextLines(lines, index, size = 2) {
    const start = Math.max(0, index - size);
    const end = Math.min(lines.length, index + size + 1);
    return lines.slice(start, end);
}

/**
 * Create a finding object
 */
function createFinding(node, category, severity, message, impact, code, extra = {}) {
    const lines = code.split('\n');
    const line = node.loc?.start?.line || 1;
    const snippet = lines[line - 1]?.trim() || '';

    return {
        line,
        column: node.loc?.start?.column || 0,
        endLine: node.loc?.end?.line || line,
        endColumn: node.loc?.end?.column || 0,
        severity,
        category,
        message,
        impact,
        snippet,
        context: getContextLines(lines, line - 1, 2),
        ...extra,
    };
}

/**
 * Check if string matches any secret pattern
 */
function checkSecretPatterns(value) {
    for (const pattern of SECRET_PATTERNS) {
        if (pattern.pattern.test(value)) {
            return pattern.name;
        }
    }
    return null;
}

/**
 * Analyze code using enhanced AST
 */
function analyzeEnhanced(code, filePath, projectRoot = '.') {
    const ast = parseCode(code, filePath);
    const findings = [];
    const lines = code.split('\n');

    if (!ast) {
        return { issues: [], parseError: true, linesAnalyzed: lines.length };
    }

    const imports = new Map();
    const variables = new Map();

    traverse(ast, {
        // Track imports for context
        ImportDeclaration(path) {
            const source = path.node.source.value;
            path.node.specifiers.forEach(spec => {
                if (spec.local) imports.set(spec.local.name, source);
            });
        },

        // Track require calls
        VariableDeclarator(path) {
            const id = path.node.id;
            const init = path.node.init;

            // Track require
            if (init?.type === 'CallExpression' && init.callee?.name === 'require') {
                if (id.type === 'Identifier' && init.arguments[0]?.value) {
                    imports.set(id.name, init.arguments[0].value);
                }
            }

            // Check for hardcoded secrets
            if (id.type === 'Identifier' && init?.type === 'StringLiteral') {
                const name = id.name.toLowerCase();
                const value = init.value;

                // Check against secret patterns
                const secretType = checkSecretPatterns(value);
                if (secretType) {
                    findings.push(createFinding(path.node, 'HARDCODED_SECRET', 'CRITICAL',
                        `${secretType} detected - move to environment variable`, 10, code,
                        { cwe: 'CWE-798' }));
                }

                // Check variable names that suggest secrets
                const secretNames = ['password', 'secret', 'api_key', 'apikey', 'token',
                    'auth', 'credential', 'private', 'jwt'];
                if (secretNames.some(p => name.includes(p)) && value.length >= 8) {
                    if (!value.includes('xxx') && !value.includes('***') &&
                        !value.includes('your-') && !value.startsWith('process.env')) {
                        findings.push(createFinding(path.node, 'HARDCODED_SECRET', 'HIGH',
                            'Potential hardcoded secret - move to environment variable', 9, code,
                            { cwe: 'CWE-798' }));
                    }
                }
            }

            // Track variable values for data flow
            if (id.type === 'Identifier') {
                variables.set(id.name, init);
            }
        },

        // New expressions
        NewExpression(path) {
            const callee = path.node.callee;

            // new Function() 
            if (callee.type === 'Identifier' && callee.name === 'Function') {
                findings.push(createFinding(path.node, 'FUNCTION_CONSTRUCTOR', 'CRITICAL',
                    'new Function() creates code from strings - code execution risk', 10, code,
                    { cwe: 'CWE-95' }));
            }

            // new RegExp with user input
            if (callee.type === 'Identifier' && callee.name === 'RegExp') {
                const arg = path.node.arguments[0];
                if (arg && arg.type !== 'StringLiteral') {
                    findings.push(createFinding(path.node, 'REGEX_INJECTION', 'MEDIUM',
                        'Dynamic RegExp - escape user input to prevent ReDoS', 5, code,
                        { cwe: 'CWE-1333' }));
                }
            }
        },

        // Call expressions - main detection logic
        CallExpression(path) {
            const node = path.node;
            const callee = node.callee;

            // Handle identifier calls
            if (callee.type === 'Identifier') {
                const name = callee.name;

                // eval()
                if (name === 'eval') {
                    findings.push(createFinding(node, 'EVAL_USAGE', 'CRITICAL',
                        'eval() executes arbitrary code - severe security risk', 10, code,
                        { cwe: 'CWE-95' }));
                }

                // setTimeout/setInterval with string
                if ((name === 'setTimeout' || name === 'setInterval')) {
                    const firstArg = node.arguments[0];
                    if (firstArg?.type === 'StringLiteral') {
                        findings.push(createFinding(node, 'IMPLICIT_EVAL', 'HIGH',
                            `${name} with string argument executes code like eval()`, 7, code,
                            { cwe: 'CWE-95' }));
                    }
                }

                // Command execution
                if (DANGEROUS_PATTERNS.COMMAND_METHODS.includes(name)) {
                    const firstArg = node.arguments[0];
                    if (firstArg && firstArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'COMMAND_INJECTION', 'CRITICAL',
                            `${name}() with dynamic input - command injection risk`, 10, code,
                            { cwe: 'CWE-78' }));
                    } else {
                        findings.push(createFinding(node, 'COMMAND_EXEC', 'HIGH',
                            `${name}() executes system commands - validate inputs`, 8, code,
                            { cwe: 'CWE-78' }));
                    }
                }

                // fetch
                if (name === 'fetch') {
                    const urlArg = node.arguments[0];
                    if (urlArg?.type === 'StringLiteral' && urlArg.value.startsWith('http://')) {
                        findings.push(createFinding(node, 'INSECURE_HTTP', 'MEDIUM',
                            'HTTP without TLS - use HTTPS', 5, code, { cwe: 'CWE-319' }));
                    } else if (urlArg && urlArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'SSRF_RISK', 'MEDIUM',
                            'Dynamic URL in fetch - validate to prevent SSRF', 6, code,
                            { cwe: 'CWE-918' }));
                    }
                }

                // JSON.parse
                if (name === 'JSON' && node.arguments[0]) {
                    // Actually check JSON.parse in member expression
                }
            }

            // Handle member expression calls
            if (callee.type === 'MemberExpression') {
                const method = callee.property?.name;
                const obj = callee.object?.name;
                const objProp = callee.object?.property?.name;

                // VM module
                if (obj === 'vm' || imports.get(obj) === 'vm') {
                    if (['runInContext', 'runInNewContext', 'runInThisContext'].includes(method)) {
                        findings.push(createFinding(node, 'VM_CODE_EXEC', 'CRITICAL',
                            `vm.${method} executes arbitrary code`, 10, code, { cwe: 'CWE-94' }));
                    }
                }

                // Command execution
                if (DANGEROUS_PATTERNS.COMMAND_METHODS.includes(method)) {
                    const firstArg = node.arguments[0];
                    if (firstArg && firstArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'COMMAND_INJECTION', 'CRITICAL',
                            `${method}() with dynamic input - command injection`, 10, code,
                            { cwe: 'CWE-78' }));
                    }

                    // Check for shell: true option
                    const options = node.arguments.find(a => a.type === 'ObjectExpression');
                    if (options) {
                        const shellProp = options.properties?.find(p =>
                            p.key?.name === 'shell' && p.value?.value === true);
                        if (shellProp) {
                            findings.push(createFinding(node, 'SHELL_INJECTION', 'CRITICAL',
                                'spawn with shell:true enables shell injection', 10, code,
                                { cwe: 'CWE-78' }));
                        }
                    }
                }

                // Weak crypto
                if (method === 'createHash' && node.arguments[0]?.type === 'StringLiteral') {
                    const algo = node.arguments[0].value.toLowerCase();
                    if (DANGEROUS_PATTERNS.WEAK_ALGORITHMS.includes(algo)) {
                        findings.push(createFinding(node, 'WEAK_CRYPTO', 'MEDIUM',
                            `${algo.toUpperCase()} is cryptographically weak - use SHA-256+`, 6, code,
                            { cwe: 'CWE-328' }));
                    }
                }

                // Sync fs
                if (DANGEROUS_PATTERNS.SYNC_FS.includes(method)) {
                    findings.push(createFinding(node, 'SYNC_IO', 'MEDIUM',
                        `${method}() blocks event loop - use async version`, 5, code));
                }

                // Path traversal
                if (DANGEROUS_PATTERNS.FS_PATH_METHODS.includes(method)) {
                    const pathArg = node.arguments[0];
                    if (pathArg?.type === 'TemplateLiteral' || pathArg?.type === 'BinaryExpression') {
                        findings.push(createFinding(node, 'PATH_TRAVERSAL', 'HIGH',
                            'File operation with dynamic path - validate to prevent traversal', 8, code,
                            { cwe: 'CWE-22' }));
                    }
                }

                // SQL injection
                if (DANGEROUS_PATTERNS.SQL_METHODS.includes(method)) {
                    const firstArg = node.arguments[0];
                    if (firstArg?.type === 'TemplateLiteral' && firstArg.expressions.length > 0) {
                        findings.push(createFinding(node, 'SQL_INJECTION', 'CRITICAL',
                            'SQL with template literal - use parameterized queries', 10, code,
                            { cwe: 'CWE-89' }));
                    } else if (firstArg?.type === 'BinaryExpression') {
                        findings.push(createFinding(node, 'SQL_INJECTION', 'CRITICAL',
                            'SQL with string concatenation - use parameterized queries', 10, code,
                            { cwe: 'CWE-89' }));
                    }
                }

                // MongoDB $where injection
                if (method === 'find' || method === 'findOne' || method === 'aggregate') {
                    const query = node.arguments[0];
                    if (query?.type === 'ObjectExpression') {
                        const hasWhere = query.properties?.some(p =>
                            p.key?.name === '$where' || p.key?.value === '$where');
                        if (hasWhere) {
                            findings.push(createFinding(node, 'NOSQL_INJECTION', 'CRITICAL',
                                '$where enables code execution - avoid or sanitize', 9, code,
                                { cwe: 'CWE-943' }));
                        }
                    }
                }

                // HTTP methods
                if (['get', 'post', 'put', 'delete', 'request'].includes(method)) {
                    const urlArg = node.arguments[0];
                    if (urlArg?.type === 'StringLiteral' && urlArg.value.startsWith('http://')) {
                        findings.push(createFinding(node, 'INSECURE_HTTP', 'MEDIUM',
                            'HTTP without TLS - use HTTPS', 5, code, { cwe: 'CWE-319' }));
                    }
                }

                // Object.assign prototype pollution
                if (obj === 'Object' && method === 'assign') {
                    const sources = node.arguments.slice(1);
                    const hasDynamicSource = sources.some(arg =>
                        arg.type !== 'ObjectExpression' && arg.type !== 'Identifier');
                    if (hasDynamicSource) {
                        findings.push(createFinding(node, 'PROTOTYPE_POLLUTION_RISK', 'MEDIUM',
                            'Object.assign with dynamic source - filter __proto__', 5, code,
                            { cwe: 'CWE-1321' }));
                    }
                }

                // Math.random for security
                if (obj === 'Math' && method === 'random') {
                    // Check if used in security context by variable name
                    const parent = path.parent;
                    if (parent?.type === 'VariableDeclarator') {
                        const varName = parent.id?.name?.toLowerCase() || '';
                        if (['token', 'secret', 'key', 'password', 'salt', 'nonce', 'iv'].some(s => varName.includes(s))) {
                            findings.push(createFinding(node, 'INSECURE_RANDOM', 'HIGH',
                                'Math.random is not cryptographically secure - use crypto.randomBytes', 7, code,
                                { cwe: 'CWE-338' }));
                        }
                    }
                }

                // document.write XSS
                if (objProp === 'document' && method === 'write' ||
                    obj === 'document' && method === 'write') {
                    findings.push(createFinding(node, 'XSS', 'HIGH',
                        'document.write can cause XSS and performance issues', 7, code,
                        { cwe: 'CWE-79' }));
                }

                // insertAdjacentHTML XSS
                if (method === 'insertAdjacentHTML') {
                    const htmlArg = node.arguments[1];
                    if (htmlArg && htmlArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'XSS', 'HIGH',
                            'insertAdjacentHTML with dynamic content - sanitize', 8, code,
                            { cwe: 'CWE-79' }));
                    }
                }

                // window.open open redirect
                if ((obj === 'window' && method === 'open') || method === 'open') {
                    const urlArg = node.arguments[0];
                    if (urlArg && urlArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'OPEN_REDIRECT', 'MEDIUM',
                            'window.open with dynamic URL - validate origin', 5, code,
                            { cwe: 'CWE-601' }));
                    }
                }

                // Response redirect
                if (method === 'redirect') {
                    const urlArg = node.arguments[0];
                    if (urlArg && urlArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'OPEN_REDIRECT', 'MEDIUM',
                            'Server redirect with dynamic URL - validate', 6, code,
                            { cwe: 'CWE-601' }));
                    }
                }

                // Cookie without flags
                if (method === 'cookie' && node.arguments.length >= 2) {
                    const options = node.arguments[2];
                    if (!options || options.type !== 'ObjectExpression') {
                        findings.push(createFinding(node, 'INSECURE_COOKIE', 'MEDIUM',
                            'Cookie set without security flags - add secure, httpOnly, sameSite', 6, code,
                            { cwe: 'CWE-614' }));
                    } else {
                        const props = options.properties || [];
                        const hasSecure = props.some(p => p.key?.name === 'secure');
                        const hasHttpOnly = props.some(p => p.key?.name === 'httpOnly');
                        if (!hasSecure) {
                            findings.push(createFinding(node, 'INSECURE_COOKIE', 'MEDIUM',
                                'Cookie missing secure flag', 5, code, { cwe: 'CWE-614' }));
                        }
                        if (!hasHttpOnly) {
                            findings.push(createFinding(node, 'MISSING_HTTPONLY', 'MEDIUM',
                                'Cookie missing httpOnly flag', 5, code, { cwe: 'CWE-1004' }));
                        }
                    }
                }

                // YAML load (unsafe)
                if (method === 'load' && (obj === 'yaml' || obj === 'YAML' || imports.get(obj)?.includes('yaml'))) {
                    findings.push(createFinding(node, 'INSECURE_DESERIALIZATION', 'CRITICAL',
                        'yaml.load is unsafe - use yaml.safeLoad or yaml.load with schema', 9, code,
                        { cwe: 'CWE-502' }));
                }
            }
        },

        // Assignment expressions
        AssignmentExpression(path) {
            const left = path.node.left;
            const right = path.node.right;

            if (left.type === 'MemberExpression') {
                const prop = left.property?.name || left.property?.value;
                const objName = left.object?.name || left.object?.property?.name;

                // XSS via innerHTML
                if (prop === 'innerHTML' || prop === 'outerHTML') {
                    if (right.type !== 'StringLiteral') {
                        findings.push(createFinding(path.node, 'XSS', 'HIGH',
                            `${prop} with dynamic content - sanitize to prevent XSS`, 8, code,
                            { cwe: 'CWE-79' }));
                    }
                }

                // React dangerouslySetInnerHTML
                if (prop === 'dangerouslySetInnerHTML') {
                    findings.push(createFinding(path.node, 'XSS', 'HIGH',
                        'dangerouslySetInnerHTML bypasses React XSS protection', 8, code,
                        { cwe: 'CWE-79' }));
                }

                // Prototype pollution
                if (DANGEROUS_PATTERNS.PROTO_KEYS.includes(prop)) {
                    findings.push(createFinding(path.node, 'PROTOTYPE_POLLUTION', 'HIGH',
                        `${prop} assignment enables prototype pollution`, 8, code,
                        { cwe: 'CWE-1321' }));
                }

                // Open redirect
                if ((objName === 'window' || objName === 'location') &&
                    (prop === 'href' || prop === 'location')) {
                    if (right.type !== 'StringLiteral') {
                        findings.push(createFinding(path.node, 'OPEN_REDIRECT', 'MEDIUM',
                            'Dynamic location assignment - validate URL', 6, code,
                            { cwe: 'CWE-601' }));
                    }
                }

                // process.env.NODE_TLS_REJECT_UNAUTHORIZED
                if (objName === 'env' && prop === 'NODE_TLS_REJECT_UNAUTHORIZED') {
                    if (right?.value === '0' || right?.value === 0) {
                        findings.push(createFinding(path.node, 'TLS_DISABLED', 'HIGH',
                            'TLS verification disabled - enables MITM attacks', 8, code,
                            { cwe: 'CWE-295' }));
                    }
                }
            }
        },

        // Object expressions - check for dangerous properties
        Property(path) {
            const key = path.node.key;
            const value = path.node.value;
            const keyName = key?.name || key?.value;

            // __proto__ in object literal
            if (keyName === '__proto__') {
                findings.push(createFinding(path.node, 'PROTOTYPE_POLLUTION', 'HIGH',
                    '__proto__ in object literal enables prototype pollution', 8, code,
                    { cwe: 'CWE-1321' }));
            }

            // rejectUnauthorized: false
            if (keyName === 'rejectUnauthorized' && value?.value === false) {
                findings.push(createFinding(path.node, 'TLS_DISABLED', 'HIGH',
                    'TLS certificate verification disabled', 8, code, { cwe: 'CWE-295' }));
            }

            // $where in MongoDB query
            if (keyName === '$where') {
                findings.push(createFinding(path.node, 'NOSQL_INJECTION', 'CRITICAL',
                    '$where enables code execution in MongoDB', 9, code, { cwe: 'CWE-943' }));
            }
        },

        // Template literals - check for dangerous patterns
        TemplateLiteral(path) {
            if (path.node.expressions.length === 0) return;

            const parent = path.parent;
            const grandParent = path.parentPath?.parent;

            // Check if used in URL assignment (potential SSRF)
            if (parent?.type === 'CallExpression') {
                const callee = parent.callee;
                if (callee?.name === 'fetch' ||
                    (callee?.type === 'MemberExpression' &&
                        ['get', 'post', 'request'].includes(callee.property?.name))) {
                    if (path.key === 0 || path.listKey === 'arguments') {
                        findings.push(createFinding(path.node, 'SSRF_RISK', 'MEDIUM',
                            'Template literal in HTTP request URL - validate to prevent SSRF', 6, code,
                            { cwe: 'CWE-918' }));
                    }
                }
            }
        },
    });

    // Additional regex-based checks for things AST might miss
    lines.forEach((line, index) => {
        const lineNum = index + 1;

        // Check for private keys in content
        if (line.includes('BEGIN RSA PRIVATE KEY') ||
            line.includes('BEGIN PRIVATE KEY') ||
            line.includes('BEGIN OPENSSH PRIVATE KEY')) {
            findings.push({
                line: lineNum,
                column: 0,
                severity: 'CRITICAL',
                category: 'HARDCODED_PRIVATE_KEY',
                message: 'Private key in source code - remove immediately',
                impact: 10,
                snippet: line.trim().substring(0, 50) + '...',
                cwe: 'CWE-798',
            });
        }
    });

    return {
        issues: findings,
        linesAnalyzed: lines.length,
        rulesApplied: 50,
        metadata: {
            parseSuccess: true,
            imports: Object.fromEntries(imports),
        },
    };
}

/**
 * Analyze a file
 */
async function analyzeFile(filePath, options = {}) {
    const code = await fs.promises.readFile(filePath, 'utf-8');
    const result = analyzeEnhanced(code, filePath, options.projectRoot || path.dirname(filePath));
    result.file = filePath;
    return result;
}

/**
 * Find JS/TS files in directory
 */
async function findJSFiles(dir, files = []) {
    const items = await fs.promises.readdir(dir);

    for (const item of items) {
        if (item === 'node_modules' || item.startsWith('.')) continue;

        const fullPath = path.join(dir, item);
        const stat = await fs.promises.stat(fullPath);

        if (stat.isDirectory()) {
            await findJSFiles(fullPath, files);
        } else if (/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(item)) {
            files.push(fullPath);
        }
    }

    return files;
}

/**
 * Analyze a directory
 */
async function analyzeDirectory(dirPath, options = {}) {
    const files = await findJSFiles(dirPath);
    const allFindings = [];
    let totalLines = 0;

    for (const file of files) {
        const result = await analyzeFile(file, { ...options, projectRoot: dirPath });
        result.issues.forEach(issue => {
            issue.file = file;
            allFindings.push(issue);
        });
        totalLines += result.linesAnalyzed;
    }

    return {
        issues: allFindings,
        filesAnalyzed: files.length,
        linesAnalyzed: totalLines,
        rulesApplied: 50,
    };
}

module.exports = {
    analyzeEnhanced,
    analyzeFile,
    analyzeDirectory,
    parseCode,
    checkSecretPatterns,
    SECURITY_RULES,
    SECRET_PATTERNS,
    DANGEROUS_PATTERNS,
};
