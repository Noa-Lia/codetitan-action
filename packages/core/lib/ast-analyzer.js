/**
 * AST-Based Security Analyzer
 * 
 * Uses @babel/parser and @babel/traverse for accurate detection
 * that skips comments and strings, reducing false positives.
 * 
 * @module ast-analyzer
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const fs = require('fs');
const path = require('path');

/**
 * Security rules configuration
 */
const SECURITY_RULES = {
    COMMAND_EXECUTION: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'],
    SQL_METHODS: ['query', 'execute', 'raw', 'prepare'],
    SYNC_FS: ['readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync', 'mkdirSync', 'readdirSync'],
    WEAK_ALGORITHMS: ['md5', 'sha1', 'md4', 'md2', 'ripemd'],
    FS_METHODS: ['readFile', 'writeFile', 'unlink', 'rmdir', 'readdir', 'stat', 'access', 'open', 'createReadStream', 'createWriteStream'],
};

/**
 * Parse JavaScript/TypeScript code into AST
 */
function parseCode(code, filePath) {
    const isTypeScript = /\.tsx?$/.test(filePath);
    const isJSX = /\.jsx$/.test(filePath) || /\.tsx$/.test(filePath);

    const plugins = ['decorators-legacy', 'classProperties', 'objectRestSpread'];
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
            return parser.parse(code, {
                sourceType: 'script',
                plugins,
                errorRecovery: true,
            });
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
 * Create a finding object with location info
 */
function createFinding(node, category, severity, message, impact, code) {
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
    };
}

/**
 * Analyze code using AST
 */
function analyzeWithAST(code, filePath, projectRoot = '.') {
    const ast = parseCode(code, filePath);
    const findings = [];
    const lines = code.split('\n');

    if (!ast) {
        return { issues: [], parseError: true, linesAnalyzed: lines.length };
    }

    const imports = new Map();

    traverse(ast, {
        // Track imports
        ImportDeclaration(path) {
            const source = path.node.source.value;
            path.node.specifiers.forEach(spec => {
                if (spec.local) {
                    imports.set(spec.local.name, source);
                }
            });
        },

        // New expressions (new Function)
        NewExpression(path) {
            const callee = path.node.callee;
            if (callee.type === 'Identifier' && callee.name === 'Function') {
                findings.push(createFinding(path.node, 'FUNCTION_CONSTRUCTOR', 'CRITICAL',
                    'new Function() creates code from strings - security risk', 10, code));
            }
        },

        // All call expressions handled here
        CallExpression(path) {
            const node = path.node;
            const callee = node.callee;

            // Handle identifier calls (eval, setTimeout, etc.)
            if (callee.type === 'Identifier') {
                const name = callee.name;

                // eval()
                if (name === 'eval') {
                    findings.push(createFinding(node, 'EVAL_USAGE', 'CRITICAL',
                        'eval() executes arbitrary code - severe security risk', 10, code));
                }

                // setTimeout/setInterval with string
                if ((name === 'setTimeout' || name === 'setInterval') &&
                    node.arguments[0]?.type === 'StringLiteral') {
                    findings.push(createFinding(node, 'IMPLICIT_EVAL', 'HIGH',
                        `${name} with string argument executes code like eval()`, 7, code));
                }

                // require tracking
                if (name === 'require' && node.arguments[0]?.value) {
                    const parent = path.parent;
                    if (parent.type === 'VariableDeclarator') {
                        imports.set(parent.id.name, node.arguments[0].value);
                    }
                }

                // Command execution (exec, spawn, etc.)
                if (SECURITY_RULES.COMMAND_EXECUTION.includes(name)) {
                    const firstArg = node.arguments[0];
                    if (firstArg && firstArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'COMMAND_INJECTION', 'CRITICAL',
                            `${name}() with dynamic input - potential command injection`, 10, code));
                    } else {
                        findings.push(createFinding(node, 'COMMAND_EXEC', 'HIGH',
                            `${name}() executes system commands - validate inputs carefully`, 8, code));
                    }
                }

                // fetch with http://
                if (name === 'fetch') {
                    const urlArg = node.arguments[0];
                    if (urlArg?.type === 'StringLiteral' && urlArg.value.startsWith('http://')) {
                        findings.push(createFinding(node, 'INSECURE_HTTP', 'MEDIUM',
                            'HTTP request without TLS - use HTTPS for secure data transfer', 5, code));
                    }
                }
            }

            // Handle member expression calls (fs.readFileSync, db.query, etc.)
            if (callee.type === 'MemberExpression') {
                const method = callee.property?.name;
                const obj = callee.object?.name;

                // Command execution methods
                if (SECURITY_RULES.COMMAND_EXECUTION.includes(method)) {
                    const firstArg = node.arguments[0];
                    if (firstArg && firstArg.type !== 'StringLiteral') {
                        findings.push(createFinding(node, 'COMMAND_INJECTION', 'CRITICAL',
                            `${method}() with dynamic input - potential command injection`, 10, code));
                    }
                }

                // Weak crypto
                if (method === 'createHash' && node.arguments[0]?.type === 'StringLiteral') {
                    const algo = node.arguments[0].value.toLowerCase();
                    if (SECURITY_RULES.WEAK_ALGORITHMS.includes(algo)) {
                        findings.push(createFinding(node, 'WEAK_CRYPTO', 'MEDIUM',
                            `${algo.toUpperCase()} is cryptographically weak - use SHA-256 or better`, 6, code));
                    }
                }

                // Sync fs operations
                if (SECURITY_RULES.SYNC_FS.includes(method)) {
                    findings.push(createFinding(node, 'SYNC_IO', 'MEDIUM',
                        `${method}() blocks event loop - use async version`, 5, code));
                }

                // SQL injection
                if (SECURITY_RULES.SQL_METHODS.includes(method)) {
                    const firstArg = node.arguments[0];
                    if (firstArg?.type === 'TemplateLiteral' && firstArg.expressions.length > 0) {
                        findings.push(createFinding(node, 'SQL_INJECTION', 'CRITICAL',
                            'SQL query with template literal interpolation - use parameterized queries', 10, code));
                    } else if (firstArg?.type === 'BinaryExpression') {
                        findings.push(createFinding(node, 'SQL_INJECTION', 'CRITICAL',
                            'SQL query with string concatenation - use parameterized queries', 10, code));
                    }
                }

                // Path traversal
                if (SECURITY_RULES.FS_METHODS.includes(method)) {
                    const pathArg = node.arguments[0];
                    if (pathArg?.type === 'TemplateLiteral' || pathArg?.type === 'BinaryExpression') {
                        findings.push(createFinding(node, 'PATH_TRAVERSAL', 'HIGH',
                            'File operation with dynamic path - validate and sanitize to prevent traversal', 8, code));
                    }
                }

                // HTTP methods
                if (['get', 'post', 'put', 'delete', 'request'].includes(method)) {
                    const urlArg = node.arguments[0];
                    if (urlArg?.type === 'StringLiteral' && urlArg.value.startsWith('http://')) {
                        findings.push(createFinding(node, 'INSECURE_HTTP', 'MEDIUM',
                            'HTTP request without TLS - use HTTPS for secure data transfer', 5, code));
                    }
                }

                // Object.assign prototype pollution risk
                if (obj === 'Object' && method === 'assign') {
                    const sources = node.arguments.slice(1);
                    if (sources.some(arg => arg.type !== 'ObjectExpression' && arg.type !== 'Identifier')) {
                        findings.push(createFinding(node, 'PROTOTYPE_POLLUTION_RISK', 'MEDIUM',
                            'Object.assign with dynamic source - validate to prevent prototype pollution', 5, code));
                    }
                }
            }
        },

        // All assignment expressions handled here
        AssignmentExpression(path) {
            const left = path.node.left;
            const right = path.node.right;

            if (left.type === 'MemberExpression') {
                const prop = left.property?.name || left.property?.value;

                // innerHTML/outerHTML XSS
                if (prop === 'innerHTML' || prop === 'outerHTML') {
                    if (right.type !== 'StringLiteral') {
                        findings.push(createFinding(path.node, 'XSS', 'HIGH',
                            `${prop} with dynamic content - sanitize to prevent XSS`, 8, code));
                    }
                }

                // __proto__ prototype pollution
                if (prop === '__proto__') {
                    findings.push(createFinding(path.node, 'PROTOTYPE_POLLUTION', 'HIGH',
                        'Direct __proto__ assignment enables prototype pollution', 8, code));
                }

                // Open redirect via location
                const objName = left.object?.name || left.object?.property?.name;
                if ((objName === 'window' || objName === 'location') &&
                    (prop === 'href' || prop === 'location')) {
                    if (right.type !== 'StringLiteral') {
                        findings.push(createFinding(path.node, 'OPEN_REDIRECT', 'MEDIUM',
                            'Location assignment with dynamic value - validate URL to prevent open redirect', 6, code));
                    }
                }
            }
        },

        // Variable declarations - check for hardcoded secrets
        VariableDeclarator(path) {
            const id = path.node.id;
            const init = path.node.init;

            if (id.type === 'Identifier' && init?.type === 'StringLiteral') {
                const name = id.name.toLowerCase();
                const value = init.value;

                const secretPatterns = ['password', 'secret', 'api_key', 'apikey', 'api-key',
                    'token', 'auth', 'credential', 'private_key'];

                if (secretPatterns.some(p => name.includes(p)) && value.length >= 8) {
                    if (!value.includes('xxx') && !value.includes('***') &&
                        !value.includes('your-') && !value.startsWith('process.env')) {
                        findings.push(createFinding(path.node, 'HARDCODED_SECRET', 'HIGH',
                            'Potential hardcoded secret - move to environment variable', 9, code));
                    }
                }
            }
        },
    });

    return {
        issues: findings,
        linesAnalyzed: lines.length,
        metadata: {
            parseSuccess: true,
            imports: Object.fromEntries(imports),
        },
        executionTime: 0,
    };
}

/**
 * Analyze a file or directory
 */
async function analyze(targetPath, options = {}) {
    const stats = await fs.promises.stat(targetPath);

    if (stats.isFile()) {
        const code = await fs.promises.readFile(targetPath, 'utf-8');
        return analyzeWithAST(code, targetPath, options.projectRoot || path.dirname(targetPath));
    }

    if (stats.isDirectory()) {
        const allFindings = [];
        const files = await findJSFiles(targetPath);

        for (const file of files) {
            const code = await fs.promises.readFile(file, 'utf-8');
            const result = analyzeWithAST(code, file, options.projectRoot || targetPath);
            result.issues.forEach(issue => {
                issue.file = file;
                allFindings.push(issue);
            });
        }

        return {
            issues: allFindings,
            filesAnalyzed: files.length,
        };
    }
}

/**
 * Find all JS/TS files in directory
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

module.exports = {
    analyzeWithAST,
    analyze,
    parseCode,
    SECURITY_RULES,
};
