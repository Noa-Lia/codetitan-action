/**
 * Data Flow Analyzer
 * 
 * Tracks tainted user input through code to detect
 * when untrusted data reaches security-sensitive sinks.
 * 
 * @module data-flow-analyzer
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

/**
 * Sources of tainted data (user input)
 */
const TAINT_SOURCES = [
    // Express request
    'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
    'request.body', 'request.query', 'request.params',
    // URL/location
    'window.location', 'location.href', 'location.search', 'location.hash',
    'document.location', 'document.URL', 'document.referrer',
    // DOM input
    'document.getElementById', 'document.querySelector',
    '.value', '.innerHTML', '.textContent',
    // URL params
    'URLSearchParams', 'URL',
    // Fetch/XHR response
    'response.json', 'response.text', 'xhr.responseText',
    // Environment (partial trust)
    'process.env',
    // Function parameters with common names
    'userInput', 'input', 'data', 'payload', 'body',
    'username', 'password', 'email', 'query', 'search',
    'url', 'path', 'filename', 'file', 'upload',
    'content', 'message', 'text', 'html', 'cmd', 'command',
];

/**
 * Security-sensitive sinks where tainted data is dangerous
 */
const SINKS = {
    CODE_EXECUTION: {
        functions: ['eval', 'Function', 'setTimeout', 'setInterval'],
        methods: ['runInContext', 'runInNewContext', 'runInThisContext'],
        severity: 'CRITICAL',
        message: 'Tainted data in code execution',
    },
    COMMAND_INJECTION: {
        functions: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile'],
        methods: ['exec', 'execSync', 'spawn', 'system'],
        severity: 'CRITICAL',
        message: 'Tainted data in shell command',
    },
    SQL_INJECTION: {
        methods: ['query', 'execute', 'raw', '$queryRaw', '$executeRaw'],
        severity: 'CRITICAL',
        message: 'Tainted data in SQL query',
    },
    XSS: {
        properties: ['innerHTML', 'outerHTML'],
        methods: ['write', 'writeln', 'insertAdjacentHTML'],
        severity: 'HIGH',
        message: 'Tainted data in DOM manipulation',
    },
    PATH_TRAVERSAL: {
        methods: ['readFile', 'writeFile', 'readFileSync', 'writeFileSync',
            'createReadStream', 'createWriteStream', 'unlink', 'access'],
        severity: 'HIGH',
        message: 'Tainted data in file path',
    },
    OPEN_REDIRECT: {
        properties: ['location', 'href'],
        methods: ['redirect', 'replace'],
        severity: 'MEDIUM',
        message: 'Tainted data in redirect URL',
    },
    SSRF: {
        functions: ['fetch'],
        methods: ['get', 'post', 'put', 'delete', 'request', 'urlopen'],
        severity: 'HIGH',
        message: 'Tainted data in HTTP request URL',
    },
};

/**
 * Track tainted variables through code
 */
class TaintTracker {
    constructor() {
        this.taintedVars = new Set();
        this.flows = [];
    }

    /**
     * Mark a variable as tainted
     */
    markTainted(varName, source) {
        this.taintedVars.add(varName);
        this.flows.push({
            type: 'source',
            variable: varName,
            source,
        });
    }

    /**
     * Check if a variable is tainted
     */
    isTainted(varName) {
        return this.taintedVars.has(varName);
    }

    /**
     * Propagate taint from assignment
     */
    propagate(target, sources) {
        const sourceNames = Array.isArray(sources) ? sources : [sources];
        if (sourceNames.some(s => this.isTainted(s))) {
            this.markTainted(target, `propagated from ${sourceNames.join(', ')}`);
            return true;
        }
        return false;
    }

    /**
     * Record a flow to a sink
     */
    recordSink(varName, sink, node) {
        this.flows.push({
            type: 'sink',
            variable: varName,
            sink,
            line: node.loc?.start?.line,
        });
    }

    /**
     * Get all tainted flows
     */
    getFlows() {
        return this.flows;
    }

    /**
     * Clear taint tracking
     */
    clear() {
        this.taintedVars.clear();
        this.flows = [];
    }
}

/**
 * Parse code into AST
 */
function parseCode(code, filePath) {
    const isTypeScript = /\.tsx?$/.test(filePath);
    const plugins = ['decorators-legacy', 'classProperties', 'optionalChaining', 'nullishCoalescingOperator'];
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
 * Create a finding for tainted flow
 */
function createFinding(node, category, severity, message, taintFlow, code) {
    const lines = code.split('\n');
    const line = node.loc?.start?.line || 1;

    return {
        line,
        column: node.loc?.start?.column || 0,
        endLine: node.loc?.end?.line || line,
        endColumn: node.loc?.end?.column || 0,
        severity,
        category: `TAINTED_${category}`,
        message,
        impact: severity === 'CRITICAL' ? 10 : severity === 'HIGH' ? 8 : 6,
        snippet: lines[line - 1]?.trim() || '',
        taintFlow,
    };
}

/**
 * Extract variable names from AST node
 */
function getNodeName(node) {
    if (!node) return null;

    if (node.type === 'Identifier') {
        return node.name;
    }
    if (node.type === 'MemberExpression') {
        const obj = getNodeName(node.object);
        const prop = node.property?.name || node.property?.value;
        return obj && prop ? `${obj}.${prop}` : prop || obj;
    }
    return null;
}

/**
 * Check if node is a taint source
 */
function isTaintSource(node) {
    const name = getNodeName(node);
    if (!name) return false;

    return TAINT_SOURCES.some(source =>
        name === source || name.includes(source) || source.includes(name)
    );
}

/**
 * Analyze data flow for security issues
 */
function analyzeDataFlow(code, filePath) {
    const ast = parseCode(code, filePath);
    const tracker = new TaintTracker();
    const findings = [];

    if (!ast) {
        return { issues: [], dataFlowEnabled: true };
    }

    traverse(ast, {
        // Track variable declarations with taint sources
        VariableDeclarator(path) {
            const id = path.node.id;
            const init = path.node.init;

            if (id.type === 'Identifier' && init) {
                const varName = id.name;

                // Check if initialized from taint source
                if (isTaintSource(init)) {
                    tracker.markTainted(varName, getNodeName(init));
                }

                // Check common tainted variable names
                const lowerName = varName.toLowerCase();
                const taintedNames = ['input', 'userdata', 'payload', 'body', 'username',
                    'password', 'query', 'search', 'url', 'path',
                    'filename', 'content', 'message', 'cmd', 'command'];
                if (taintedNames.some(t => lowerName.includes(t))) {
                    tracker.markTainted(varName, 'parameter name heuristic');
                }

                // Propagate taint from other variables
                if (init.type === 'Identifier' && tracker.isTainted(init.name)) {
                    tracker.markTainted(varName, `assigned from ${init.name}`);
                }
            }
        },

        // Track function parameters (often user input)
        FunctionDeclaration(path) {
            path.node.params.forEach(param => {
                if (param.type === 'Identifier') {
                    const name = param.name.toLowerCase();
                    const taintedParams = ['input', 'data', 'body', 'payload', 'user',
                        'req', 'request', 'query', 'params'];
                    if (taintedParams.some(t => name.includes(t))) {
                        tracker.markTainted(param.name, 'function parameter');
                    }
                }
            });
        },

        // Track assignments that propagate taint
        AssignmentExpression(path) {
            const left = path.node.left;
            const right = path.node.right;

            if (left.type === 'Identifier') {
                // Check if RHS is tainted
                if (right.type === 'Identifier' && tracker.isTainted(right.name)) {
                    tracker.markTainted(left.name, `assigned from ${right.name}`);
                }

                // Check if RHS is a taint source
                if (isTaintSource(right)) {
                    tracker.markTainted(left.name, getNodeName(right));
                }
            }

            // Check for tainted data reaching XSS sinks
            if (left.type === 'MemberExpression') {
                const prop = left.property?.name;
                if (SINKS.XSS.properties.includes(prop)) {
                    const rightName = getNodeName(right);
                    if (right.type === 'Identifier' && tracker.isTainted(right.name)) {
                        findings.push(createFinding(path.node, 'XSS', 'HIGH',
                            `User input flows to ${prop} - XSS vulnerability`,
                            { source: right.name, sink: prop }, code));
                    }
                }
            }
        },

        // Track call expressions with tainted arguments
        CallExpression(path) {
            const node = path.node;
            const callee = node.callee;
            const args = node.arguments;

            // Check for tainted arguments reaching sinks
            Object.entries(SINKS).forEach(([sinkType, sink]) => {
                let matches = false;
                let sinkName = '';

                // Check function calls
                if (callee.type === 'Identifier') {
                    if (sink.functions?.includes(callee.name)) {
                        matches = true;
                        sinkName = callee.name;
                    }
                }

                // Check method calls
                if (callee.type === 'MemberExpression') {
                    const method = callee.property?.name;
                    if (sink.methods?.includes(method)) {
                        matches = true;
                        sinkName = method;
                    }
                }

                if (matches) {
                    // Check if any argument is tainted
                    args.forEach((arg, index) => {
                        if (arg.type === 'Identifier' && tracker.isTainted(arg.name)) {
                            findings.push(createFinding(node, sinkType, sink.severity,
                                `${sink.message}: ${arg.name} → ${sinkName}()`,
                                { source: arg.name, sink: sinkName }, code));
                        }
                        // Check template literals with tainted expressions
                        if (arg.type === 'TemplateLiteral') {
                            arg.expressions.forEach(expr => {
                                if (expr.type === 'Identifier' && tracker.isTainted(expr.name)) {
                                    findings.push(createFinding(node, sinkType, sink.severity,
                                        `${sink.message}: ${expr.name} in template → ${sinkName}()`,
                                        { source: expr.name, sink: sinkName }, code));
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
        taintedVariables: Array.from(tracker.taintedVars),
        dataFlowEnabled: true,
        flows: tracker.getFlows(),
    };
}

module.exports = {
    analyzeDataFlow,
    TaintTracker,
    TAINT_SOURCES,
    SINKS,
};
