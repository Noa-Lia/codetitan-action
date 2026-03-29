/**
 * Auto-Test Generator
 * 
 * Automatically generates unit tests for uncovered functions:
 * - Analyzes function signatures and types
 * - Discovers edge cases from code patterns
 * - Generates tests for Jest, Mocha, or Pytest
 * - Integrates with AI for intelligent test scenarios
 * 
 * @module auto-test-generator
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

/**
 * Test frameworks configuration
 */
const FRAMEWORKS = {
    jest: {
        import: '',
        describe: 'describe',
        it: 'it',
        expect: 'expect',
        beforeEach: 'beforeEach',
        afterEach: 'afterEach',
        mock: 'jest.fn()',
    },
    mocha: {
        import: "const { expect } = require('chai');",
        describe: 'describe',
        it: 'it',
        expect: 'expect',
        beforeEach: 'beforeEach',
        afterEach: 'afterEach',
        mock: 'sinon.stub()',
    },
    vitest: {
        import: "import { describe, it, expect, beforeEach, vi } from 'vitest';",
        describe: 'describe',
        it: 'it',
        expect: 'expect',
        beforeEach: 'beforeEach',
        afterEach: 'afterEach',
        mock: 'vi.fn()',
    },
    pytest: {
        import: 'import pytest',
        describe: 'class Test',
        it: 'def test_',
        expect: 'assert',
        beforeEach: '@pytest.fixture',
        mock: 'mocker.patch',
    },
};

/**
 * Common edge case patterns
 */
const EDGE_CASES = {
    string: ['', ' ', 'null', 'undefined', 'very long string '.repeat(100), '<script>alert("xss")</script>', '🚀 emoji', "single'quote", 'double"quote'],
    number: [0, -1, 1, -0, Infinity, -Infinity, NaN, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.1 + 0.2],
    array: [[], [null], [undefined], new Array(1000).fill(0), [1, 'mixed', true, null]],
    object: [{}, { nested: { deep: { value: 1 } } }, null, Object.create(null)],
    boolean: [true, false],
    function: [() => { }, async () => { }, function* () { }],
};

/**
 * Extract function information from AST
 */
class FunctionExtractor {
    constructor() {
        this.functions = [];
    }

    /**
     * Parse code and extract functions
     */
    extract(code, filePath) {
        const isTypeScript = /\.tsx?$/.test(filePath);
        this.functions = [];

        try {
            const ast = parser.parse(code, {
                sourceType: 'module',
                plugins: [
                    'decorators-legacy',
                    'classProperties',
                    'optionalChaining',
                    'nullishCoalescingOperator',
                    ...(isTypeScript ? ['typescript'] : []),
                    ...(/\.[jt]sx$/.test(filePath) ? ['jsx'] : []),
                ],
                errorRecovery: true,
            });

            traverse(ast, {
                FunctionDeclaration: (path) => {
                    this.functions.push(this.extractFunctionInfo(path.node, code));
                },
                ArrowFunctionExpression: (path) => {
                    if (path.parent.type === 'VariableDeclarator') {
                        const name = path.parent.id?.name;
                        if (name) {
                            this.functions.push(this.extractFunctionInfo(path.node, code, name));
                        }
                    }
                },
                ClassMethod: (path) => {
                    const className = path.parentPath.parent.id?.name || 'Class';
                    const methodName = path.node.key?.name;
                    if (methodName && !['constructor'].includes(methodName)) {
                        this.functions.push(this.extractMethodInfo(path.node, code, className, methodName));
                    }
                },
            });
        } catch (error) {
            console.error('Parse error:', error.message);
        }

        return this.functions;
    }

    /**
     * Extract function information
     */
    extractFunctionInfo(node, code, name = null) {
        const funcName = name || node.id?.name || 'anonymous';
        const params = this.extractParams(node.params);
        const isAsync = node.async || false;
        const isGenerator = node.generator || false;

        // Extract return type if TypeScript
        const returnType = node.returnType?.typeAnnotation?.type || null;

        // Get function body for analysis
        const bodyStart = node.body.start;
        const bodyEnd = node.body.end;
        const body = code.substring(bodyStart, bodyEnd);

        // Analyze function complexity
        const complexity = this.analyzeComplexity(body);

        // Detect side effects
        const sideEffects = this.detectSideEffects(body);

        return {
            name: funcName,
            params,
            isAsync,
            isGenerator,
            returnType,
            complexity,
            sideEffects,
            loc: node.loc,
            hasReturn: body.includes('return'),
            throwsError: body.includes('throw'),
        };
    }

    /**
     * Extract class method information
     */
    extractMethodInfo(node, code, className, methodName) {
        const info = this.extractFunctionInfo(node, code, methodName);
        info.className = className;
        info.isStatic = node.static || false;
        info.kind = node.kind; // 'method', 'get', 'set'
        return info;
    }

    /**
     * Extract parameter information
     */
    extractParams(params) {
        return params.map(param => {
            if (param.type === 'Identifier') {
                return {
                    name: param.name,
                    type: param.typeAnnotation?.typeAnnotation?.type || 'any',
                    optional: false,
                    defaultValue: null,
                };
            }
            if (param.type === 'AssignmentPattern') {
                return {
                    name: param.left?.name,
                    type: param.left?.typeAnnotation?.typeAnnotation?.type || 'any',
                    optional: true,
                    defaultValue: this.extractDefault(param.right),
                };
            }
            if (param.type === 'RestElement') {
                return {
                    name: param.argument?.name,
                    type: 'rest',
                    optional: true,
                    isRest: true,
                };
            }
            if (param.type === 'ObjectPattern') {
                return {
                    name: 'options',
                    type: 'object',
                    properties: param.properties.map(p => p.key?.name).filter(Boolean),
                };
            }
            return { name: 'unknown', type: 'unknown' };
        });
    }

    /**
     * Extract default value as string
     */
    extractDefault(node) {
        if (!node) return null;
        if (node.type === 'NumericLiteral') return node.value;
        if (node.type === 'StringLiteral') return `'${node.value}'`;
        if (node.type === 'BooleanLiteral') return node.value;
        if (node.type === 'NullLiteral') return null;
        if (node.type === 'ArrayExpression') return '[]';
        if (node.type === 'ObjectExpression') return '{}';
        return null;
    }

    /**
     * Analyze function complexity
     */
    analyzeComplexity(body) {
        let complexity = 1;

        // Count decision points
        const patterns = [
            /\bif\s*\(/g,
            /\belse\s+if\s*\(/g,
            /\bfor\s*\(/g,
            /\bwhile\s*\(/g,
            /\bcase\s+/g,
            /\bcatch\s*\(/g,
            /\?\s*[^:]/g, // ternary
            /\|\|/g,
            /&&/g,
        ];

        for (const pattern of patterns) {
            const matches = body.match(pattern);
            if (matches) complexity += matches.length;
        }

        return complexity;
    }

    /**
     * Detect side effects
     */
    detectSideEffects(body) {
        const effects = [];

        if (/console\.\w+/.test(body)) effects.push('console');
        if (/fs\./.test(body)) effects.push('filesystem');
        if (/fetch\(|axios\.|http\./i.test(body)) effects.push('network');
        if (/\.(save|insert|update|delete|remove)\(/i.test(body)) effects.push('database');
        if (/localStorage|sessionStorage/.test(body)) effects.push('storage');
        if (/document\.|window\./.test(body)) effects.push('dom');
        if (/process\.exit/.test(body)) effects.push('exit');

        return effects;
    }
}

/**
 * Test Case Generator
 */
class TestCaseGenerator {
    constructor(options = {}) {
        this.framework = options.framework || 'jest';
        this.config = FRAMEWORKS[this.framework];
        this.aiProvider = options.aiProvider || null;
    }

    /**
     * Generate test cases for a function
     */
    async generateTests(funcInfo, options = {}) {
        const testCases = [];

        // Basic happy path test
        testCases.push(this.generateHappyPath(funcInfo));

        // Edge case tests based on parameters
        for (const param of funcInfo.params) {
            const edgeCases = this.generateEdgeCases(funcInfo, param);
            testCases.push(...edgeCases);
        }

        // Error handling tests
        if (funcInfo.throwsError) {
            testCases.push(this.generateErrorTest(funcInfo));
        }

        // Async tests
        if (funcInfo.isAsync) {
            testCases.push(...this.generateAsyncTests(funcInfo));
        }

        // Boundary tests based on complexity
        if (funcInfo.complexity > 3) {
            testCases.push(...this.generateBoundaryTests(funcInfo));
        }

        // AI-enhanced tests if provider available
        if (this.aiProvider && options.useAI) {
            const aiTests = await this.generateAITests(funcInfo);
            testCases.push(...aiTests);
        }

        return testCases;
    }

    /**
     * Generate happy path test
     */
    generateHappyPath(funcInfo) {
        const args = funcInfo.params.map(p => this.getDefaultValue(p)).join(', ');
        const callExpr = funcInfo.className
            ? `new ${funcInfo.className}().${funcInfo.name}(${args})`
            : `${funcInfo.name}(${args})`;

        return {
            name: `should work with valid inputs`,
            type: 'happy_path',
            code: funcInfo.isAsync
                ? `await ${this.config.expect}(${callExpr}).resolves.toBeDefined();`
                : `${this.config.expect}(${callExpr}).toBeDefined();`,
        };
    }

    /**
     * Generate edge case tests for a parameter
     */
    generateEdgeCases(funcInfo, param) {
        const cases = [];
        const edgeValues = this.getEdgeValues(param);

        for (const { value, description } of edgeValues) {
            const args = funcInfo.params.map(p =>
                p.name === param.name ? value : this.getDefaultValue(p)
            ).join(', ');

            const callExpr = funcInfo.className
                ? `new ${funcInfo.className}().${funcInfo.name}(${args})`
                : `${funcInfo.name}(${args})`;

            cases.push({
                name: `should handle ${param.name} as ${description}`,
                type: 'edge_case',
                param: param.name,
                value,
                code: `${this.config.expect}(() => ${callExpr}).not.toThrow();`,
            });
        }

        return cases.slice(0, 5); // Limit to 5 edge cases per param
    }

    /**
     * Get edge values based on parameter type
     */
    getEdgeValues(param) {
        const type = this.inferType(param);
        const edges = [];

        switch (type) {
            case 'string':
                edges.push({ value: "''", description: 'empty string' });
                edges.push({ value: "null", description: 'null' });
                edges.push({ value: "undefined", description: 'undefined' });
                break;
            case 'number':
                edges.push({ value: '0', description: 'zero' });
                edges.push({ value: '-1', description: 'negative' });
                edges.push({ value: 'NaN', description: 'NaN' });
                edges.push({ value: 'Infinity', description: 'infinity' });
                break;
            case 'array':
                edges.push({ value: '[]', description: 'empty array' });
                edges.push({ value: '[null]', description: 'array with null' });
                break;
            case 'object':
                edges.push({ value: '{}', description: 'empty object' });
                edges.push({ value: 'null', description: 'null' });
                break;
            case 'boolean':
                edges.push({ value: 'true', description: 'true' });
                edges.push({ value: 'false', description: 'false' });
                break;
            default:
                edges.push({ value: 'null', description: 'null' });
                edges.push({ value: 'undefined', description: 'undefined' });
        }

        return edges;
    }

    /**
     * Infer type from parameter info
     */
    inferType(param) {
        if (param.type !== 'any' && param.type !== 'unknown') {
            return param.type.toLowerCase();
        }

        // Infer from name
        const name = param.name.toLowerCase();
        if (name.includes('name') || name.includes('str') || name.includes('text') || name.includes('message')) {
            return 'string';
        }
        if (name.includes('count') || name.includes('num') || name.includes('index') || name.includes('size')) {
            return 'number';
        }
        if (name.includes('list') || name.includes('items') || name.includes('array')) {
            return 'array';
        }
        if (name.includes('options') || name.includes('config') || name.includes('data')) {
            return 'object';
        }
        if (name.includes('enabled') || name.includes('is') || name.includes('has') || name.includes('should')) {
            return 'boolean';
        }

        return 'unknown';
    }

    /**
     * Get default value for a parameter
     */
    getDefaultValue(param) {
        if (param.defaultValue !== null && param.defaultValue !== undefined) {
            return String(param.defaultValue);
        }

        const type = this.inferType(param);
        switch (type) {
            case 'string': return "'test'";
            case 'number': return '1';
            case 'array': return '[]';
            case 'object': return '{}';
            case 'boolean': return 'true';
            case 'function': return '() => {}';
            default: return 'undefined';
        }
    }

    /**
     * Generate error handling test
     */
    generateErrorTest(funcInfo) {
        const invalidArgs = funcInfo.params.map(() => 'null').join(', ');
        const callExpr = funcInfo.className
            ? `new ${funcInfo.className}().${funcInfo.name}(${invalidArgs})`
            : `${funcInfo.name}(${invalidArgs})`;

        return {
            name: 'should throw error with invalid inputs',
            type: 'error',
            code: `${this.config.expect}(() => ${callExpr}).toThrow();`,
        };
    }

    /**
     * Generate async-specific tests
     */
    generateAsyncTests(funcInfo) {
        return [
            {
                name: 'should return a promise',
                type: 'async',
                code: `${this.config.expect}(${funcInfo.name}()).toBeInstanceOf(Promise);`,
            },
            {
                name: 'should resolve without errors',
                type: 'async',
                code: `await ${this.config.expect}(${funcInfo.name}()).resolves.not.toThrow();`,
            },
        ];
    }

    /**
     * Generate boundary tests for complex functions
     */
    generateBoundaryTests(funcInfo) {
        return [
            {
                name: 'should handle concurrent calls',
                type: 'boundary',
                code: `const results = await Promise.all([${funcInfo.name}(), ${funcInfo.name}(), ${funcInfo.name}()]);
${this.config.expect}(results).toHaveLength(3);`,
            },
        ];
    }

    /**
     * Generate AI-enhanced tests (placeholder for AI integration)
     */
    async generateAITests(funcInfo) {
        // This would call an AI provider to generate intelligent tests
        // For now, return empty array
        return [];
    }

    /**
     * Format tests into a complete test file
     */
    formatTestFile(funcInfo, testCases, options = {}) {
        const lines = [];

        // Imports
        if (this.config.import) {
            lines.push(this.config.import);
        }

        // Import the module under test
        const modulePath = options.modulePath || `./${options.fileName?.replace(/\.[jt]sx?$/, '')}`;
        if (funcInfo.className) {
            lines.push(`const { ${funcInfo.className} } = require('${modulePath}');`);
        } else {
            lines.push(`const { ${funcInfo.name} } = require('${modulePath}');`);
        }

        lines.push('');

        // Test suite
        const suiteName = funcInfo.className
            ? `${funcInfo.className}.${funcInfo.name}`
            : funcInfo.name;

        lines.push(`${this.config.describe}('${suiteName}', () => {`);

        for (const testCase of testCases) {
            lines.push(`  ${this.config.it}('${testCase.name}', ${funcInfo.isAsync ? 'async ' : ''}() => {`);
            lines.push(`    ${testCase.code}`);
            lines.push('  });');
            lines.push('');
        }

        lines.push('});');

        return lines.join('\n');
    }
}

/**
 * Auto-Test Generator - Main Class
 */
class AutoTestGenerator {
    constructor(options = {}) {
        this.extractor = new FunctionExtractor();
        this.generator = new TestCaseGenerator({
            framework: options.framework || 'jest',
            aiProvider: options.aiProvider,
        });
        this.options = options;
    }

    /**
     * Generate tests for a file
     */
    async generateForFile(code, filePath, options = {}) {
        // Extract functions
        const functions = this.extractor.extract(code, filePath);

        if (functions.length === 0) {
            return { tests: [], coverage: 0 };
        }

        // Generate tests for each function
        const allTests = [];

        for (const funcInfo of functions) {
            // Skip private-looking functions
            if (funcInfo.name.startsWith('_') && !options.includePrivate) {
                continue;
            }

            const testCases = await this.generator.generateTests(funcInfo, {
                useAI: options.useAI,
            });

            const testFile = this.generator.formatTestFile(funcInfo, testCases, {
                modulePath: options.modulePath,
                fileName: filePath.split(/[/\\]/).pop(),
            });

            allTests.push({
                functionName: funcInfo.name,
                className: funcInfo.className,
                testCases: testCases.length,
                complexity: funcInfo.complexity,
                testFile,
            });
        }

        return {
            tests: allTests,
            functionsFound: functions.length,
            testsGenerated: allTests.reduce((sum, t) => sum + t.testCases, 0),
            estimatedCoverage: this.estimateCoverage(allTests),
        };
    }

    /**
     * Estimate coverage from generated tests
     */
    estimateCoverage(tests) {
        // Simple heuristic: each test covers ~10-20 lines
        const avgLinesPerTest = 15;
        const totalTests = tests.reduce((sum, t) => sum + t.testCases, 0);
        // Assume average function is ~20 lines
        const estimatedLines = tests.length * 20;

        const coverage = Math.min(100, (totalTests * avgLinesPerTest / estimatedLines) * 100);
        return Math.round(coverage);
    }

    /**
     * Generate test file path
     */
    getTestFilePath(filePath, options = {}) {
        const dir = options.testDir || '__tests__';
        const fileName = filePath.split(/[/\\]/).pop();
        const testFileName = fileName.replace(/\.([jt]sx?)$/, '.test.$1');
        return `${dir}/${testFileName}`;
    }
}

module.exports = {
    AutoTestGenerator,
    FunctionExtractor,
    TestCaseGenerator,
    FRAMEWORKS,
    EDGE_CASES,
};
