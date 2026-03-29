/**
 * Titan AI Review
 * 
 * AI-powered semantic code analysis that dramatically reduces false positives
 * by understanding code context, sanitization, and real exploitability.
 * 
 * This is CodeTitan's UNIQUE DIFFERENTIATOR - something SonarQube cannot do.
 * 
 * @module titan-ai-review
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const { analyzeDataFlow, TaintTracker, TAINT_SOURCES, SINKS } = require('./data-flow-analyzer');

/**
 * Known sanitizer functions that neutralize taint
 * When data passes through these, it becomes safe
 */
const SANITIZERS = {
    // Type coercion (prevents injection)
    TYPE_COERCION: {
        functions: ['parseInt', 'parseFloat', 'Number', 'Boolean'],
        description: 'Type coercion removes string injection risk',
        neutralizes: ['SQL_INJECTION', 'COMMAND_INJECTION', 'XSS', 'CODE_EXECUTION'],
    },
    // SQL parameterization
    PARAMETERIZATION: {
        patterns: [/\$\d+/, /\?\s*,/, /:\w+/],
        methods: ['prepare', 'parameterize', 'escape'],
        description: 'Parameterized queries prevent SQL injection',
        neutralizes: ['SQL_INJECTION'],
    },
    // HTML encoding
    HTML_ENCODING: {
        functions: ['encodeURIComponent', 'encodeURI', 'escape'],
        methods: ['htmlEncode', 'escapeHtml', 'sanitize', 'encode', 'escape'],
        libraries: ['DOMPurify', 'xss', 'sanitize-html', 'he', 'entities'],
        description: 'HTML encoding prevents XSS',
        neutralizes: ['XSS'],
    },
    // Path normalization
    PATH_SANITIZATION: {
        methods: ['normalize', 'resolve', 'basename', 'join'],
        checks: ['path.join', 'path.resolve', 'path.normalize'],
        description: 'Path normalization prevents traversal',
        neutralizes: ['PATH_TRAVERSAL'],
    },
    // Shell escaping
    SHELL_ESCAPE: {
        methods: ['shellEscape', 'escapeShell', 'quote'],
        libraries: ['shell-escape', 'shell-quote'],
        description: 'Shell escaping prevents command injection',
        neutralizes: ['COMMAND_INJECTION'],
    },
    // URL validation
    URL_VALIDATION: {
        checks: ['startsWith', 'match', 'test', 'includes'],
        patterns: [/^https?:\/\//, /\.includes\(['"]https?/],
        description: 'URL validation prevents SSRF/Open Redirect',
        neutralizes: ['SSRF', 'OPEN_REDIRECT'],
    },
};

/**
 * Safe contexts where vulnerabilities are less exploitable
 */
const SAFE_CONTEXTS = {
    TEST_FILES: {
        patterns: [/\.test\.[jt]sx?$/, /\.spec\.[jt]sx?$/, /__tests__/, /test\//, /tests\//],
        reductionFactor: 0.2, // Reduce severity by 80%
        reason: 'Test code is not deployed to production',
    },
    CONFIG_FILES: {
        patterns: [/config\.[jt]sx?$/, /\.config\.[jt]sx?$/, /settings\.[jt]sx?$/],
        reductionFactor: 0.5,
        reason: 'Configuration files typically use trusted data',
    },
    BUILD_SCRIPTS: {
        patterns: [/scripts\//, /build\//, /webpack/, /rollup/, /vite/],
        reductionFactor: 0.3,
        reason: 'Build scripts run in trusted environment',
    },
    MIGRATIONS: {
        patterns: [/migrations?\//, /seeds?\//, /fixtures?\//],
        reductionFactor: 0.4,
        reason: 'Database migrations use controlled data',
    },
};

/**
 * Confidence explanations for human-readable reasoning
 */
const CONFIDENCE_FACTORS = {
    DIRECT_USER_INPUT: { weight: 1.0, description: 'Direct user input (e.g., req.body)' },
    INDIRECT_PROPAGATION: { weight: 0.8, description: 'Indirectly tainted via assignment' },
    HEURISTIC_NAME: { weight: 0.5, description: 'Variable name suggests user input' },
    SANITIZED: { weight: 0.1, description: 'Data appears to be sanitized' },
    SAFE_CONTEXT: { weight: 0.3, description: 'Code is in a low-risk context' },
    HIGH_SIGNAL_SINK: { weight: 1.0, description: 'Sink has high exploit potential' },
};

/**
 * Smart finding with enhanced context
 */
class SmartFinding {
    constructor(rawFinding, context) {
        this.raw = rawFinding;
        this.context = context;
        this.confidence = 1.0;
        this.reasons = [];
        this.isFalsePositive = false;
        this.exploitability = 'HIGH';
        this.sanitizers = [];
    }

    addReason(reason, confidenceAdjustment) {
        this.reasons.push(reason);
        this.confidence *= confidenceAdjustment;
        if (this.confidence < 0.3) {
            this.isFalsePositive = true;
        }
    }

    toJSON() {
        return {
            ...this.raw,
            titanReview: {
                confidence: Math.round(this.confidence * 100) / 100,
                isFalsePositive: this.isFalsePositive,
                exploitability: this.exploitability,
                reasons: this.reasons,
                sanitizers: this.sanitizers,
                recommendation: this.getRecommendation(),
            },
        };
    }

    getRecommendation() {
        if (this.isFalsePositive) {
            return 'This appears to be a false positive. Review the sanitization applied.';
        }
        if (this.confidence < 0.5) {
            return 'Low confidence finding. Consider manual review.';
        }
        if (this.confidence < 0.7) {
            return 'Medium confidence. Verify the data flow path.';
        }
        return 'High confidence finding. Fix recommended.';
    }
}

/**
 * Parse code and extract AST context
 */
function parseCode(code, filePath) {
    const isTypeScript = /\.tsx?$/.test(filePath);
    const plugins = [
        'decorators-legacy', 'classProperties', 'optionalChaining',
        'nullishCoalescingOperator', 'classPrivateProperties', 'classPrivateMethods',
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
 * Analyze code context for a given line
 */
function analyzeContext(ast, code, lineNumber, filePath) {
    const context = {
        isTestFile: false,
        isConfigFile: false,
        isBuildScript: false,
        inTryCatch: false,
        inIfStatement: false,
        hasSanitizer: false,
        sanitizerType: null,
        nearbyValidation: false,
        functionName: null,
        className: null,
    };

    // Check file-level context
    Object.entries(SAFE_CONTEXTS).forEach(([key, ctx]) => {
        if (ctx.patterns.some(p => p.test(filePath))) {
            context[`is${key.charAt(0) + key.slice(1).toLowerCase().replace(/_/g, '')}`] = true;
        }
    });

    if (!ast) return context;

    // Traverse to find context at the line
    traverse(ast, {
        enter(path) {
            const loc = path.node.loc;
            if (!loc) return;

            const startLine = loc.start.line;
            const endLine = loc.end.line;

            // Check if this node contains our target line
            if (startLine <= lineNumber && lineNumber <= endLine) {
                // Check for try-catch
                if (path.node.type === 'TryStatement') {
                    context.inTryCatch = true;
                }

                // Check for if statement (validation check)
                if (path.node.type === 'IfStatement') {
                    context.inIfStatement = true;
                    // Check for validation patterns in condition
                    const condCode = code.slice(path.node.test.start, path.node.test.end);
                    if (/typeof|instanceof|\.length|\.test|\.match|startsWith|includes/.test(condCode)) {
                        context.nearbyValidation = true;
                    }
                }

                // Get function/method context
                if (path.node.type === 'FunctionDeclaration' && path.node.id) {
                    context.functionName = path.node.id.name;
                }
                if (path.node.type === 'ClassDeclaration' && path.node.id) {
                    context.className = path.node.id.name;
                }
            }
        },
    });

    return context;
}

/**
 * Check if data goes through a sanitizer before reaching sink
 */
function checkSanitization(ast, code, varName, sinkLine) {
    const sanitizationInfo = {
        isSanitized: false,
        sanitizerType: null,
        sanitizerLine: null,
        sanitizerName: null,
    };

    if (!ast) return sanitizationInfo;

    traverse(ast, {
        CallExpression(path) {
            const loc = path.node.loc;
            if (!loc || loc.start.line >= sinkLine) return;

            const callee = path.node.callee;
            const args = path.node.arguments;

            // Check if our variable is being sanitized
            const containsVar = args.some(arg => {
                if (arg.type === 'Identifier') return arg.name === varName;
                return false;
            });

            if (!containsVar) return;

            // Check against known sanitizers
            Object.entries(SANITIZERS).forEach(([type, sanitizer]) => {
                // Check function names
                if (callee.type === 'Identifier' && sanitizer.functions?.includes(callee.name)) {
                    sanitizationInfo.isSanitized = true;
                    sanitizationInfo.sanitizerType = type;
                    sanitizationInfo.sanitizerLine = loc.start.line;
                    sanitizationInfo.sanitizerName = callee.name;
                }

                // Check method calls
                if (callee.type === 'MemberExpression') {
                    const method = callee.property?.name;
                    if (sanitizer.methods?.includes(method)) {
                        sanitizationInfo.isSanitized = true;
                        sanitizationInfo.sanitizerType = type;
                        sanitizationInfo.sanitizerLine = loc.start.line;
                        sanitizationInfo.sanitizerName = method;
                    }
                }
            });
        },
    });

    return sanitizationInfo;
}

/**
 * Calculate exploit difficulty score (0-1, higher = harder to exploit)
 */
function calculateExploitDifficulty(finding, context, sanitization) {
    let difficulty = 0;

    // Sanitization greatly increases difficulty
    if (sanitization.isSanitized) {
        difficulty += 0.7;
    }

    // Context factors
    if (context.isTestFile) difficulty += 0.8;
    if (context.isConfigFile) difficulty += 0.5;
    if (context.isBuildScript) difficulty += 0.6;
    if (context.inIfStatement && context.nearbyValidation) difficulty += 0.3;
    if (context.inTryCatch) difficulty += 0.1;

    // Type-based factors
    if (finding.category === 'TAINTED_OPEN_REDIRECT') difficulty += 0.2; // Often false positives
    if (finding.category === 'TAINTED_SSRF') difficulty += 0.1;

    return Math.min(difficulty, 1);
}

/**
 * Main Titan AI Review function
 * Analyzes code with semantic understanding to reduce false positives
 */
function titanAIReview(code, filePath, options = {}) {
    const {
        includeRaw = false,
        confidenceThreshold = 0.3,
        verboseExplanations = true,
    } = options;

    // First, run standard data flow analysis
    const dataFlowResults = analyzeDataFlow(code, filePath);
    const ast = parseCode(code, filePath);

    // Enhance each finding with AI review
    const enhancedFindings = dataFlowResults.issues.map(finding => {
        const smartFinding = new SmartFinding(finding, {
            filePath,
            originalSeverity: finding.severity,
        });

        // Get context for the finding
        const context = analyzeContext(ast, code, finding.line, filePath);

        // Check for sanitization
        const varName = finding.taintFlow?.source;
        const sanitization = varName
            ? checkSanitization(ast, code, varName, finding.line)
            : { isSanitized: false };

        // Apply sanitization reduction
        if (sanitization.isSanitized) {
            const sanitizerInfo = SANITIZERS[sanitization.sanitizerType];
            const category = finding.category.replace('TAINTED_', '');

            if (sanitizerInfo?.neutralizes?.includes(category)) {
                smartFinding.addReason(
                    `${sanitization.sanitizerName}() sanitizes this data (${sanitizerInfo.description})`,
                    CONFIDENCE_FACTORS.SANITIZED.weight
                );
                smartFinding.sanitizers.push(sanitization.sanitizerName);
            } else {
                smartFinding.addReason(
                    `Partial sanitization via ${sanitization.sanitizerName}() detected`,
                    0.5
                );
            }
        }

        // Apply context-based reduction
        Object.entries(SAFE_CONTEXTS).forEach(([key, ctx]) => {
            if (ctx.patterns.some(p => p.test(filePath))) {
                smartFinding.addReason(ctx.reason, ctx.reductionFactor);
            }
        });

        // Calculate exploitability
        const exploitDifficulty = calculateExploitDifficulty(finding, context, sanitization);
        if (exploitDifficulty > 0.7) {
            smartFinding.exploitability = 'LOW';
            smartFinding.addReason('Exploit difficulty is high due to multiple mitigations', 0.4);
        } else if (exploitDifficulty > 0.4) {
            smartFinding.exploitability = 'MEDIUM';
        }

        // Add validation context
        if (context.nearbyValidation) {
            smartFinding.addReason('Nearby validation check detected', 0.7);
        }

        return smartFinding;
    });

    // Filter out likely false positives
    const truePosFindings = enhancedFindings.filter(f => !f.isFalsePositive);
    const falsePositives = enhancedFindings.filter(f => f.isFalsePositive);

    // Calculate DX score metrics
    const totalFindings = enhancedFindings.length;
    const falsePositiveRate = totalFindings > 0
        ? (falsePositives.length / totalFindings) * 100
        : 0;
    const avgConfidence = enhancedFindings.length > 0
        ? enhancedFindings.reduce((sum, f) => sum + f.confidence, 0) / enhancedFindings.length
        : 1;

    return {
        // Primary output - filtered, high-confidence findings
        issues: truePosFindings.map(f => f.toJSON()),

        // False positives (for review/tuning)
        suppressedFindings: includeRaw ? falsePositives.map(f => f.toJSON()) : [],

        // Metrics
        metrics: {
            totalRawFindings: totalFindings,
            truePositives: truePosFindings.length,
            likelyFalsePositives: falsePositives.length,
            falsePositiveReductionRate: Math.round(falsePositiveRate),
            averageConfidence: Math.round(avgConfidence * 100),
        },

        // Data flow info (for debugging/visualization)
        dataFlow: {
            taintedVariables: dataFlowResults.taintedVariables,
            flows: dataFlowResults.flows,
        },

        // Feature flag
        titanAIReviewEnabled: true,
    };
}

/**
 * Calculate Developer Experience (DX) Score
 * A unique metric that measures tool effectiveness
 */
function calculateDXScore(analysisResults, options = {}) {
    const { recentHistory = [] } = options;

    // Base metrics
    const falsePositiveRate = analysisResults.metrics.falsePositiveReductionRate;
    const avgConfidence = analysisResults.metrics.averageConfidence;

    // DX Score components (0-100)
    const scores = {
        accuracy: Math.max(0, 100 - falsePositiveRate * 2), // Penalize false positives
        confidence: avgConfidence,
        signalToNoise: analysisResults.issues.length > 0
            ? Math.min(100, (analysisResults.metrics.truePositives / (analysisResults.metrics.totalRawFindings || 1)) * 100)
            : 100,
    };

    // Weighted average
    const dxScore = Math.round(
        scores.accuracy * 0.4 +
        scores.confidence * 0.3 +
        scores.signalToNoise * 0.3
    );

    return {
        score: dxScore,
        breakdown: scores,
        grade: dxScore >= 90 ? 'A' : dxScore >= 80 ? 'B' : dxScore >= 70 ? 'C' : dxScore >= 60 ? 'D' : 'F',
        recommendations: generateDXRecommendations(scores, analysisResults),
    };
}

/**
 * Generate recommendations to improve DX score
 */
function generateDXRecommendations(scores, results) {
    const recommendations = [];

    if (scores.accuracy < 80) {
        recommendations.push({
            area: 'False Positive Reduction',
            suggestion: 'Consider adding custom sanitizer patterns for your codebase',
            priority: 'HIGH',
        });
    }

    if (scores.signalToNoise < 70) {
        recommendations.push({
            area: 'Signal Quality',
            suggestion: 'Review suppressed findings to tune detection rules',
            priority: 'MEDIUM',
        });
    }

    if (results.issues.some(i => i.titanReview?.confidence < 0.5)) {
        recommendations.push({
            area: 'Confidence',
            suggestion: 'Low-confidence findings may need manual verification',
            priority: 'LOW',
        });
    }

    return recommendations;
}

module.exports = {
    titanAIReview,
    calculateDXScore,
    SANITIZERS,
    SAFE_CONTEXTS,
    CONFIDENCE_FACTORS,
    SmartFinding,
};
