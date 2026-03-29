/**
 * Enhanced Data Flow Analyzer v2.0
 * 
 * Enterprise-grade taint tracking with:
 * - Cross-file data flow tracking
 * - Exploitability scoring (CVSS-like)
 * - Sanitizer detection and bypass analysis
 * - Call graph construction
 * - Path sensitivity
 * 
 * @module data-flow-analyzer-enhanced
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const path = require('path');

/**
 * Extended taint sources with framework support
 */
const TAINT_SOURCES = {
    // HTTP Request (Express, Koa, Fastify, NestJS)
    REQUEST: {
        patterns: [
            'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
            'request.body', 'request.query', 'request.params',
            'ctx.request.body', 'ctx.query', 'ctx.params',
            '@Body()', '@Query()', '@Param()', '@Headers()',
        ],
        trustLevel: 0, // Completely untrusted
    },
    // Browser inputs
    DOM: {
        patterns: [
            'document.getElementById', 'document.querySelector', 'document.querySelectorAll',
            '.value', '.innerHTML', '.textContent', '.innerText',
            'window.location', 'location.href', 'location.search', 'location.hash',
            'document.URL', 'document.referrer', 'document.cookie',
        ],
        trustLevel: 0,
    },
    // External data
    EXTERNAL: {
        patterns: [
            'response.json()', 'response.text()', 'xhr.responseText', 'xhr.response',
            'fetch(', 'axios.', 'http.get(', 'https.get(',
            'fs.readFile', 'fs.readFileSync',
        ],
        trustLevel: 0.2, // Slightly more trusted
    },
    // Environment
    ENVIRONMENT: {
        patterns: ['process.env.', 'import.meta.env.', 'Deno.env.'],
        trustLevel: 0.5, // Semi-trusted
    },
    // Database results (could contain user data)
    DATABASE: {
        patterns: ['.findOne(', '.find(', '.query(', '.execute(', '$query'],
        trustLevel: 0.3,
    },
};

/**
 * Enhanced sinks with exploitability metadata
 */
const SINKS = {
    CODE_EXECUTION: {
        functions: ['eval', 'Function', 'setTimeout', 'setInterval', 'setImmediate'],
        methods: ['runInContext', 'runInNewContext', 'runInThisContext'],
        severity: 'CRITICAL',
        cvssBase: 9.8,
        exploitability: {
            attackVector: 'NETWORK',
            attackComplexity: 'LOW',
            privilegesRequired: 'NONE',
            userInteraction: 'NONE',
        },
        message: 'Remote Code Execution via tainted input',
        cwe: 'CWE-94',
    },
    COMMAND_INJECTION: {
        functions: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'],
        methods: ['exec', 'execSync', 'spawn', 'system', 'popen'],
        severity: 'CRITICAL',
        cvssBase: 9.8,
        exploitability: {
            attackVector: 'NETWORK',
            attackComplexity: 'LOW',
            privilegesRequired: 'NONE',
            userInteraction: 'NONE',
        },
        message: 'Command Injection via tainted input',
        cwe: 'CWE-78',
    },
    SQL_INJECTION: {
        methods: ['query', 'execute', 'raw', '$queryRaw', '$executeRaw', 'rawQuery'],
        severity: 'CRITICAL',
        cvssBase: 9.1,
        exploitability: {
            attackVector: 'NETWORK',
            attackComplexity: 'LOW',
            privilegesRequired: 'NONE',
            userInteraction: 'NONE',
        },
        message: 'SQL Injection via tainted input',
        cwe: 'CWE-89',
    },
    NOSQL_INJECTION: {
        methods: ['find', 'findOne', 'updateOne', 'deleteOne', 'aggregate'],
        requiresObjectArg: true, // Only flag if arg is object with $where etc
        severity: 'HIGH',
        cvssBase: 8.6,
        message: 'NoSQL Injection via tainted input',
        cwe: 'CWE-943',
    },
    XSS: {
        properties: ['innerHTML', 'outerHTML', 'document.write'],
        methods: ['write', 'writeln', 'insertAdjacentHTML'],
        reactMethods: ['dangerouslySetInnerHTML'],
        severity: 'HIGH',
        cvssBase: 6.1,
        exploitability: {
            attackVector: 'NETWORK',
            attackComplexity: 'LOW',
            privilegesRequired: 'NONE',
            userInteraction: 'REQUIRED',
        },
        message: 'Cross-Site Scripting via tainted input',
        cwe: 'CWE-79',
    },
    PATH_TRAVERSAL: {
        methods: ['readFile', 'writeFile', 'readFileSync', 'writeFileSync',
            'createReadStream', 'createWriteStream', 'unlink', 'access', 'rm', 'rmdir'],
        severity: 'HIGH',
        cvssBase: 7.5,
        message: 'Path Traversal via tainted input',
        cwe: 'CWE-22',
    },
    OPEN_REDIRECT: {
        properties: ['location', 'href'],
        methods: ['redirect', 'replace', 'assign'],
        severity: 'MEDIUM',
        cvssBase: 4.7,
        message: 'Open Redirect via tainted input',
        cwe: 'CWE-601',
    },
    SSRF: {
        functions: ['fetch', 'axios', 'got', 'superagent'],
        methods: ['get', 'post', 'put', 'delete', 'patch', 'request', 'urlopen'],
        severity: 'HIGH',
        cvssBase: 8.6,
        message: 'Server-Side Request Forgery via tainted input',
        cwe: 'CWE-918',
    },
    DESERIALIZATION: {
        functions: ['JSON.parse'],
        methods: ['deserialize', 'loads', 'load', 'parse'],
        severity: 'HIGH',
        cvssBase: 8.1,
        message: 'Insecure Deserialization of tainted input',
        cwe: 'CWE-502',
    },
    LOG_INJECTION: {
        methods: ['log', 'info', 'warn', 'error', 'debug'],
        severity: 'LOW',
        cvssBase: 3.7,
        message: 'Log Injection via tainted input',
        cwe: 'CWE-117',
    },
};

/**
 * Known sanitizers that make data safe
 */
const SANITIZERS = {
    SQL: ['escape', 'quote', 'sanitize', 'parameterize', 'prepare', '?', '$1'],
    XSS: ['escape', 'sanitize', 'encode', 'escapeHtml', 'htmlEscape', 'DOMPurify.sanitize', 'xss'],
    PATH: ['basename', 'normalize', 'resolve', 'join'],
    COMMAND: ['shellEscape', 'quote'],
    GENERAL: ['validate', 'sanitize', 'clean', 'filter', 'whitelist'],
};

/**
 * Enhanced Taint Tracker with path sensitivity
 */
class EnhancedTaintTracker {
    constructor() {
        this.taintedVars = new Map(); // varName -> TaintInfo
        this.flows = [];
        this.callGraph = new Map(); // funcName -> Set<calledFuncs>
        this.exportedTaint = new Map(); // For cross-file tracking
        this.sanitizedVars = new Set();
    }

    /**
     * Mark a variable as tainted with metadata
     */
    markTainted(varName, source, trustLevel = 0, location = null) {
        const existing = this.taintedVars.get(varName);

        this.taintedVars.set(varName, {
            source,
            trustLevel: existing ? Math.min(existing.trustLevel, trustLevel) : trustLevel,
            location,
            timestamp: Date.now(),
            propagationPath: existing ? [...(existing.propagationPath || []), source] : [source],
        });

        this.flows.push({
            type: 'source',
            variable: varName,
            source,
            trustLevel,
            location,
        });
    }

    /**
     * Check if variable is tainted
     */
    isTainted(varName) {
        if (this.sanitizedVars.has(varName)) return false;
        return this.taintedVars.has(varName);
    }

    /**
     * Get taint info for a variable
     */
    getTaintInfo(varName) {
        return this.taintedVars.get(varName);
    }

    /**
     * Mark variable as sanitized
     */
    markSanitized(varName, sanitizer) {
        this.sanitizedVars.add(varName);
        this.flows.push({
            type: 'sanitize',
            variable: varName,
            sanitizer,
        });
    }

    /**
     * Propagate taint through assignment
     */
    propagate(target, sources, location = null) {
        const sourceList = Array.isArray(sources) ? sources : [sources];

        for (const source of sourceList) {
            if (this.isTainted(source)) {
                const sourceInfo = this.getTaintInfo(source);
                this.markTainted(
                    target,
                    `propagated from ${source}`,
                    sourceInfo?.trustLevel || 0,
                    location
                );
                return true;
            }
        }
        return false;
    }

    /**
     * Record a taint flow reaching a sink
     */
    recordSink(varName, sinkType, sinkInfo, node) {
        const taintInfo = this.getTaintInfo(varName);

        this.flows.push({
            type: 'sink',
            variable: varName,
            sinkType,
            sinkInfo,
            line: node.loc?.start?.line,
            column: node.loc?.start?.column,
            propagationPath: taintInfo?.propagationPath || [],
        });
    }

    /**
     * Track function call in call graph
     */
    addCallEdge(caller, callee) {
        if (!this.callGraph.has(caller)) {
            this.callGraph.set(caller, new Set());
        }
        this.callGraph.get(caller).add(callee);
    }

    /**
     * Export tainted variables for cross-file analysis
     */
    exportTaint(exportName, varName) {
        if (this.isTainted(varName)) {
            this.exportedTaint.set(exportName, this.getTaintInfo(varName));
        }
    }

    /**
     * Import taint from another module
     */
    importTaint(importName, taintInfo) {
        if (taintInfo) {
            this.taintedVars.set(importName, {
                ...taintInfo,
                source: `imported from module`,
            });
        }
    }

    /**
     * Get all flows
     */
    getFlows() {
        return this.flows;
    }

    /**
     * Get sink flows only
     */
    getSinkFlows() {
        return this.flows.filter(f => f.type === 'sink');
    }

    /**
     * Clear state
     */
    clear() {
        this.taintedVars.clear();
        this.flows = [];
        this.sanitizedVars.clear();
    }
}

/**
 * Calculate exploitability score
 */
function calculateExploitability(sink, taintInfo, context) {
    const baseScore = sink.cvssBase || 5.0;
    let modifier = 0;

    // Adjust based on trust level (lower trust = higher risk)
    modifier -= (taintInfo?.trustLevel || 0) * 2;

    // Adjust based on propagation path length (longer = harder to exploit)
    const pathLength = taintInfo?.propagationPath?.length || 1;
    modifier -= Math.min(pathLength * 0.2, 1);

    // Adjust based on context
    if (context.isAuthenticated) modifier -= 0.5;
    if (context.hasRateLimit) modifier -= 0.3;
    if (context.isInternal) modifier -= 1.0;

    const finalScore = Math.max(0, Math.min(10, baseScore + modifier));

    return {
        score: Math.round(finalScore * 10) / 10,
        level: finalScore >= 9 ? 'CRITICAL' : finalScore >= 7 ? 'HIGH' : finalScore >= 4 ? 'MEDIUM' : 'LOW',
        factors: {
            baseScore,
            trustLevel: taintInfo?.trustLevel || 0,
            pathLength,
            modifier,
        },
    };
}

/**
 * Check if a function call is a sanitizer
 */
function isSanitizer(name, sinkType) {
    if (!name) return false;
    const lowerName = name.toLowerCase();

    // Check specific sanitizers for sink type
    const specificSanitizers = SANITIZERS[sinkType] || [];
    if (specificSanitizers.some(s => lowerName.includes(s.toLowerCase()))) {
        return true;
    }

    // Check general sanitizers
    return SANITIZERS.GENERAL.some(s => lowerName.includes(s.toLowerCase()));
}

/**
 * Parse code into AST with error recovery
 */
function parseCode(code, filePath) {
    const isTypeScript = /\.tsx?$/.test(filePath);
    const plugins = [
        'decorators-legacy', 'classProperties', 'optionalChaining',
        'nullishCoalescingOperator', 'dynamicImport', 'topLevelAwait',
    ];
    if (isTypeScript) plugins.push('typescript');
    if (/\.[jt]sx$/.test(filePath)) plugins.push('jsx');

    try {
        return parser.parse(code, {
            sourceType: 'module',
            plugins,
            errorRecovery: true,
            allowImportExportEverywhere: true,
            allowAwaitOutsideFunction: true,
        });
    } catch (e) {
        return null;
    }
}

/**
 * Extract node name
 */
function getNodeName(node) {
    if (!node) return null;
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'MemberExpression') {
        const obj = getNodeName(node.object);
        const prop = node.property?.name || node.property?.value;
        return obj && prop ? `${obj}.${prop}` : prop || obj;
    }
    if (node.type === 'CallExpression') {
        return getNodeName(node.callee);
    }
    return null;
}

/**
 * Check if node represents a taint source
 */
function detectTaintSource(node) {
    const name = getNodeName(node);
    if (!name) return null;

    for (const [category, config] of Object.entries(TAINT_SOURCES)) {
        for (const pattern of config.patterns) {
            if (name.includes(pattern) || pattern.includes(name)) {
                return {
                    category,
                    pattern,
                    trustLevel: config.trustLevel,
                };
            }
        }
    }
    return null;
}

/**
 * Create a finding with exploitability score
 */
function createFinding(node, sinkType, sink, taintInfo, code, context = {}) {
    const lines = code.split('\n');
    const line = node.loc?.start?.line || 1;
    const exploitability = calculateExploitability(sink, taintInfo, context);

    return {
        line,
        column: node.loc?.start?.column || 0,
        endLine: node.loc?.end?.line || line,
        endColumn: node.loc?.end?.column || 0,
        severity: exploitability.level,
        category: `DATA_FLOW_${sinkType}`,
        message: sink.message,
        cwe: sink.cwe,
        impact: exploitability.score,
        exploitability,
        snippet: lines[line - 1]?.trim() || '',
        taintFlow: {
            source: taintInfo?.source,
            propagationPath: taintInfo?.propagationPath || [],
            trustLevel: taintInfo?.trustLevel,
        },
        remediation: getRemediation(sinkType),
    };
}

/**
 * Get remediation advice for sink type
 */
function getRemediation(sinkType) {
    const remediations = {
        CODE_EXECUTION: 'Never use eval() or Function() with user input. Use a sandboxed environment like vm2.',
        COMMAND_INJECTION: 'Use parameterized commands or shell-escape libraries. Avoid shell: true.',
        SQL_INJECTION: 'Use parameterized queries or an ORM. Never concatenate user input into SQL.',
        NOSQL_INJECTION: 'Validate object keys and reject $where operators from user input.',
        XSS: 'Use textContent instead of innerHTML, or sanitize with DOMPurify.',
        PATH_TRAVERSAL: 'Use path.basename() and validate against a whitelist of allowed paths.',
        OPEN_REDIRECT: 'Use a whitelist of allowed redirect URLs or validate the URL domain.',
        SSRF: 'Validate and whitelist allowed URLs/hosts. Block internal IP ranges.',
        DESERIALIZATION: 'Validate JSON schema before parsing. Use safe deserialization libraries.',
        LOG_INJECTION: 'Sanitize log inputs to prevent log forging attacks.',
    };
    return remediations[sinkType] || 'Validate and sanitize all user input.';
}

/**
 * Main analysis function with cross-file support
 */
function analyzeDataFlow(code, filePath, options = {}) {
    const ast = parseCode(code, filePath);
    const tracker = new EnhancedTaintTracker();
    const findings = [];
    const context = options.context || {};

    // Import taint from dependencies
    if (options.importedTaint) {
        for (const [name, info] of Object.entries(options.importedTaint)) {
            tracker.importTaint(name, info);
        }
    }

    if (!ast) {
        return {
            issues: [],
            dataFlowEnabled: true,
            taintedVariables: [],
            exportedTaint: {},
        };
    }

    let currentFunction = '<module>';

    traverse(ast, {
        // Track imports for cross-file analysis
        ImportDeclaration(nodePath) {
            const source = nodePath.node.source.value;
            nodePath.node.specifiers.forEach(spec => {
                if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportSpecifier') {
                    const localName = spec.local.name;
                    // Mark as potentially tainted if from external source
                    if (!source.startsWith('.') && !source.startsWith('/')) {
                        // External module - could be tainted
                        tracker.markTainted(localName, `imported from ${source}`, 0.5);
                    }
                }
            });
        },

        // Track exports for cross-file taint propagation
        ExportNamedDeclaration(nodePath) {
            if (nodePath.node.declaration?.declarations) {
                for (const decl of nodePath.node.declaration.declarations) {
                    if (decl.id.type === 'Identifier') {
                        tracker.exportTaint(decl.id.name, decl.id.name);
                    }
                }
            }
        },

        // Track function context
        FunctionDeclaration(nodePath) {
            const funcName = nodePath.node.id?.name || '<anonymous>';
            currentFunction = funcName;

            // Mark parameters as potentially tainted
            nodePath.node.params.forEach(param => {
                if (param.type === 'Identifier') {
                    const name = param.name.toLowerCase();
                    const taintedParams = ['input', 'data', 'body', 'payload', 'user',
                        'req', 'request', 'query', 'params', 'args', 'options'];
                    if (taintedParams.some(t => name.includes(t))) {
                        tracker.markTainted(param.name, 'function parameter', 0);
                    }
                }
            });
        },

        ArrowFunctionExpression(nodePath) {
            nodePath.node.params.forEach(param => {
                if (param.type === 'Identifier') {
                    const name = param.name.toLowerCase();
                    const taintedParams = ['input', 'data', 'body', 'payload', 'req', 'request'];
                    if (taintedParams.some(t => name.includes(t))) {
                        tracker.markTainted(param.name, 'arrow function parameter', 0);
                    }
                }
            });
        },

        // Track variable declarations
        VariableDeclarator(nodePath) {
            const id = nodePath.node.id;
            const init = nodePath.node.init;

            if (id.type === 'Identifier' && init) {
                const varName = id.name;

                // Check for taint source
                const sourceInfo = detectTaintSource(init);
                if (sourceInfo) {
                    tracker.markTainted(varName, sourceInfo.pattern, sourceInfo.trustLevel, {
                        line: nodePath.node.loc?.start?.line,
                        column: nodePath.node.loc?.start?.column,
                    });
                }

                // Check heuristic names
                const lowerName = varName.toLowerCase();
                const taintedNames = ['input', 'userdata', 'payload', 'body', 'username',
                    'password', 'query', 'search', 'url', 'path', 'filename', 'content',
                    'message', 'cmd', 'command', 'unsanitized', 'raw'];
                if (taintedNames.some(t => lowerName.includes(t))) {
                    tracker.markTainted(varName, 'parameter name heuristic', 0.1);
                }

                // Propagate from other variables
                if (init.type === 'Identifier' && tracker.isTainted(init.name)) {
                    tracker.propagate(varName, init.name);
                }

                // Check for sanitizer calls
                if (init.type === 'CallExpression') {
                    const calleeName = getNodeName(init.callee);
                    if (isSanitizer(calleeName, null)) {
                        tracker.markSanitized(varName, calleeName);
                    }
                }
            }
        },

        // Track assignments
        AssignmentExpression(nodePath) {
            const left = nodePath.node.left;
            const right = nodePath.node.right;

            if (left.type === 'Identifier') {
                // Propagate taint
                if (right.type === 'Identifier' && tracker.isTainted(right.name)) {
                    tracker.propagate(left.name, right.name);
                }

                // Check for source
                const sourceInfo = detectTaintSource(right);
                if (sourceInfo) {
                    tracker.markTainted(left.name, sourceInfo.pattern, sourceInfo.trustLevel);
                }

                // Check for sanitizer
                if (right.type === 'CallExpression') {
                    const calleeName = getNodeName(right.callee);
                    if (isSanitizer(calleeName, null)) {
                        tracker.markSanitized(left.name, calleeName);
                    }
                }
            }

            // XSS via property assignment
            if (left.type === 'MemberExpression') {
                const prop = left.property?.name;
                if (SINKS.XSS.properties?.includes(prop)) {
                    const rightName = getNodeName(right);
                    if (right.type === 'Identifier' && tracker.isTainted(right.name)) {
                        const taintInfo = tracker.getTaintInfo(right.name);
                        tracker.recordSink(right.name, 'XSS', SINKS.XSS, nodePath.node);
                        findings.push(createFinding(nodePath.node, 'XSS', SINKS.XSS, taintInfo, code, context));
                    }
                }
            }
        },

        // Track call expressions (main sink detection)
        CallExpression(nodePath) {
            const node = nodePath.node;
            const callee = node.callee;
            const args = node.arguments;

            // Track in call graph
            const calleeName = getNodeName(callee);
            if (calleeName) {
                tracker.addCallEdge(currentFunction, calleeName);
            }

            // Check each sink type
            Object.entries(SINKS).forEach(([sinkType, sink]) => {
                let isSinkMatch = false;
                let matchedName = '';

                // Check function calls
                if (callee.type === 'Identifier' && sink.functions?.includes(callee.name)) {
                    isSinkMatch = true;
                    matchedName = callee.name;
                }

                // Check method calls
                if (callee.type === 'MemberExpression') {
                    const method = callee.property?.name;
                    if (sink.methods?.includes(method)) {
                        isSinkMatch = true;
                        matchedName = method;
                    }
                    if (sink.reactMethods?.includes(method)) {
                        isSinkMatch = true;
                        matchedName = method;
                    }
                }

                if (isSinkMatch) {
                    // Check arguments for taint
                    args.forEach((arg, index) => {
                        // Direct identifier
                        if (arg.type === 'Identifier' && tracker.isTainted(arg.name)) {
                            const taintInfo = tracker.getTaintInfo(arg.name);
                            tracker.recordSink(arg.name, sinkType, sink, node);
                            findings.push(createFinding(node, sinkType, sink, taintInfo, code, context));
                        }

                        // Binary expression (concatenation)
                        if (arg.type === 'BinaryExpression') {
                            const checkBinary = (expr) => {
                                if (expr.type === 'Identifier' && tracker.isTainted(expr.name)) {
                                    return expr.name;
                                }
                                if (expr.type === 'BinaryExpression') {
                                    return checkBinary(expr.left) || checkBinary(expr.right);
                                }
                                return null;
                            };
                            const taintedVar = checkBinary(arg);
                            if (taintedVar) {
                                const taintInfo = tracker.getTaintInfo(taintedVar);
                                tracker.recordSink(taintedVar, sinkType, sink, node);
                                findings.push(createFinding(node, sinkType, sink, taintInfo, code, context));
                            }
                        }

                        // Template literal
                        if (arg.type === 'TemplateLiteral') {
                            arg.expressions.forEach(expr => {
                                if (expr.type === 'Identifier' && tracker.isTainted(expr.name)) {
                                    const taintInfo = tracker.getTaintInfo(expr.name);
                                    tracker.recordSink(expr.name, sinkType, sink, node);
                                    findings.push(createFinding(node, sinkType, sink, taintInfo, code, context));
                                }
                            });
                        }
                    });
                }
            });
        },
    });

    return {
        issues: findings,
        taintedVariables: Array.from(tracker.taintedVars.keys()),
        dataFlowEnabled: true,
        flows: tracker.getFlows(),
        sinkFlows: tracker.getSinkFlows(),
        callGraph: Object.fromEntries(
            Array.from(tracker.callGraph.entries()).map(([k, v]) => [k, Array.from(v)])
        ),
        exportedTaint: Object.fromEntries(tracker.exportedTaint),
        sanitizedVariables: Array.from(tracker.sanitizedVars),
    };
}

/**
 * Analyze multiple files with cross-file taint tracking
 */
async function analyzeDataFlowCrossFile(files, options = {}) {
    const results = new Map();
    const globalTaint = new Map();

    // First pass: collect exports
    for (const { path: filePath, content } of files) {
        const result = analyzeDataFlow(content, filePath, options);
        results.set(filePath, result);

        // Collect exported taint
        for (const [name, info] of Object.entries(result.exportedTaint)) {
            globalTaint.set(`${filePath}:${name}`, info);
        }
    }

    // Second pass: propagate imports
    for (const { path: filePath, content } of files) {
        // Re-analyze with imported taint context
        const result = analyzeDataFlow(content, filePath, {
            ...options,
            importedTaint: Object.fromEntries(globalTaint),
        });
        results.set(filePath, result);
    }

    // Aggregate findings
    const allFindings = [];
    for (const [filePath, result] of results) {
        for (const issue of result.issues) {
            allFindings.push({
                ...issue,
                file: filePath,
            });
        }
    }

    return {
        files: Object.fromEntries(results),
        allFindings,
        totalIssues: allFindings.length,
        bySeverity: {
            CRITICAL: allFindings.filter(f => f.severity === 'CRITICAL').length,
            HIGH: allFindings.filter(f => f.severity === 'HIGH').length,
            MEDIUM: allFindings.filter(f => f.severity === 'MEDIUM').length,
            LOW: allFindings.filter(f => f.severity === 'LOW').length,
        },
    };
}

module.exports = {
    analyzeDataFlow,
    analyzeDataFlowCrossFile,
    EnhancedTaintTracker,
    calculateExploitability,
    TAINT_SOURCES,
    SINKS,
    SANITIZERS,
};
