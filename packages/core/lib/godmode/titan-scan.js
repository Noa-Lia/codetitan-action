/**
 * TITAN MODE™ Level 1: BASIC ANALYSIS ENGINE
 * Foundation for all higher levels
 *
 * Provides core code scanning capabilities:
 * - File discovery and parsing
 * - AST generation for supported languages
 * - Basic pattern detection
 * - Metrics collection (LOC, complexity, etc.)
 *
 * @module titanmode/level1-basic-analysis
 */

const fs = require('fs');
const path = require('path');
const { parse } = require('@babel/parser');

const SUPPORTED_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

const IGNORE_PATTERNS = [
    'node_modules',
    '.git',
    'dist',
    'build',
    'coverage',
    '.next',
    '__pycache__',
    'vendor',
];

class Level1BasicAnalysis {
    constructor(config = {}) {
        this.config = {
            extensions: config.extensions || SUPPORTED_EXTENSIONS,
            ignorePatterns: config.ignorePatterns || IGNORE_PATTERNS,
            maxFileSize: config.maxFileSize || 1024 * 1024, // 1MB
            collectMetrics: config.collectMetrics !== false,
            parseAST: config.parseAST !== false,
            ...config,
        };

        this.stats = {
            filesScanned: 0,
            linesOfCode: 0,
            parseErrors: 0,
            scanTimeMs: 0,
        };
    }

    /**
     * Analyze a project directory
     * @param {string} projectPath - Path to analyze
     * @returns {object} Analysis results
     */
    async analyze(projectPath) {
        console.log('⚡ [TITAN MODE Level 1] BASIC ANALYSIS ENGINE');
        console.log(`   Analyzing: ${projectPath}\n`);

        const startTime = Date.now();

        // Discover files
        const files = this.discoverFiles(projectPath);
        console.log(`   Found ${files.length} files to analyze`);

        // Analyze each file
        const results = {
            projectPath,
            files: [],
            metrics: {
                totalFiles: files.length,
                totalLines: 0,
                totalFunctions: 0,
                totalClasses: 0,
                averageComplexity: 0,
                languageBreakdown: {},
            },
            issues: [],
        };

        for (const file of files) {
            try {
                const fileResult = await this.analyzeFile(file);
                results.files.push(fileResult);

                // Aggregate metrics
                results.metrics.totalLines += fileResult.metrics.lines;
                results.metrics.totalFunctions += fileResult.metrics.functions;
                results.metrics.totalClasses += fileResult.metrics.classes;

                // Language breakdown
                const ext = path.extname(file);
                results.metrics.languageBreakdown[ext] = (results.metrics.languageBreakdown[ext] || 0) + 1;

                // Collect issues
                results.issues.push(...fileResult.issues);

                this.stats.filesScanned++;
                this.stats.linesOfCode += fileResult.metrics.lines;
            } catch (error) {
                this.stats.parseErrors++;
                console.error(`   Error analyzing ${file}: ${error.message}`);
            }
        }

        // Calculate averages
        if (results.files.length > 0) {
            const totalComplexity = results.files.reduce((sum, f) => sum + f.metrics.complexity, 0);
            results.metrics.averageComplexity = Math.round(totalComplexity / results.files.length * 10) / 10;
        }

        this.stats.scanTimeMs = Date.now() - startTime;

        console.log(`\n   ✓ Analysis complete in ${this.stats.scanTimeMs}ms`);
        console.log(`   ✓ ${this.stats.linesOfCode} lines of code`);
        console.log(`   ✓ ${results.issues.length} issues found\n`);

        return results;
    }

    /**
     * Discover all analyzable files in a directory
     */
    discoverFiles(dirPath, files = []) {
        try {
            const entries = fs.readdirSync(dirPath, { withFileTypes: true });

            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry.name);

                // Skip ignored patterns
                if (this.config.ignorePatterns.some(pattern => entry.name === pattern || entry.name.startsWith('.'))) {
                    continue;
                }

                if (entry.isDirectory()) {
                    this.discoverFiles(fullPath, files);
                } else if (this.config.extensions.includes(path.extname(entry.name))) {
                    // Check file size
                    const stats = fs.statSync(fullPath);
                    if (stats.size <= this.config.maxFileSize) {
                        files.push(fullPath);
                    }
                }
            }
        } catch (error) {
            // Skip inaccessible directories
        }

        return files;
    }

    /**
     * Analyze a single file
     */
    async analyzeFile(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');
        const ext = path.extname(filePath);

        const result = {
            path: filePath,
            relativePath: path.relative(process.cwd(), filePath),
            extension: ext,
            metrics: {
                lines: lines.length,
                codeLines: this.countCodeLines(lines),
                commentLines: this.countCommentLines(lines),
                blankLines: this.countBlankLines(lines),
                functions: 0,
                classes: 0,
                complexity: 1,
                imports: 0,
                exports: 0,
            },
            issues: [],
            ast: null,
        };

        // Parse AST if enabled
        if (this.config.parseAST && ['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
            try {
                const ast = this.parseFile(content, ext);
                result.metrics = { ...result.metrics, ...this.extractMetricsFromAST(ast) };

                // Basic issue detection
                result.issues = this.detectIssues(ast, content, filePath);
            } catch (error) {
                result.issues.push({
                    type: 'parse-error',
                    severity: 'LOW',
                    message: `Failed to parse: ${error.message}`,
                    file: filePath,
                    line: error.loc?.line || 1,
                });
            }
        }

        return result;
    }

    /**
     * Parse file content into AST
     */
    parseFile(content, ext) {
        const isTypeScript = ext === '.ts' || ext === '.tsx';
        const isJSX = ext === '.jsx' || ext === '.tsx';

        return parse(content, {
            sourceType: 'module',
            plugins: [
                isTypeScript && 'typescript',
                isJSX && 'jsx',
                'decorators-legacy',
                'classProperties',
                'objectRestSpread',
            ].filter(Boolean),
            errorRecovery: true,
        });
    }

    /**
     * Extract metrics from AST
     */
    extractMetricsFromAST(ast) {
        const metrics = {
            functions: 0,
            classes: 0,
            complexity: 1,
            imports: 0,
            exports: 0,
        };

        const visit = (node) => {
            if (!node || typeof node !== 'object') return;

            switch (node.type) {
                case 'FunctionDeclaration':
                case 'FunctionExpression':
                case 'ArrowFunctionExpression':
                    metrics.functions++;
                    break;
                case 'ClassDeclaration':
                case 'ClassExpression':
                    metrics.classes++;
                    break;
                case 'ImportDeclaration':
                    metrics.imports++;
                    break;
                case 'ExportDefaultDeclaration':
                case 'ExportNamedDeclaration':
                    metrics.exports++;
                    break;
                // Complexity indicators
                case 'IfStatement':
                case 'ConditionalExpression':
                case 'SwitchCase':
                case 'ForStatement':
                case 'ForInStatement':
                case 'ForOfStatement':
                case 'WhileStatement':
                case 'DoWhileStatement':
                case 'CatchClause':
                case 'LogicalExpression':
                    metrics.complexity++;
                    break;
            }

            // Recursively visit children
            for (const key of Object.keys(node)) {
                const child = node[key];
                if (Array.isArray(child)) {
                    child.forEach(visit);
                } else if (child && typeof child === 'object') {
                    visit(child);
                }
            }
        };

        if (ast.program?.body) {
            ast.program.body.forEach(visit);
        }

        return metrics;
    }

    /**
     * Detect basic issues in code
     */
    detectIssues(ast, content, filePath) {
        const issues = [];
        const lines = content.split('\n');

        // Check for common patterns
        lines.forEach((line, idx) => {
            const lineNum = idx + 1;

            // console.log detection
            if (/\bconsole\.(log|debug|info)\s*\(/.test(line) && !filePath.includes('test')) {
                issues.push({
                    type: 'debug-statement',
                    severity: 'LOW',
                    category: 'maintainability',
                    message: 'Console statement should be removed in production',
                    file: filePath,
                    line: lineNum,
                    column: line.indexOf('console'),
                    rule_id: 'no-console',
                });
            }

            // TODO/FIXME detection
            if (/\/\/\s*(TODO|FIXME|HACK|XXX)/i.test(line)) {
                issues.push({
                    type: 'todo-comment',
                    severity: 'INFO',
                    category: 'maintainability',
                    message: 'Unresolved TODO/FIXME comment',
                    file: filePath,
                    line: lineNum,
                    column: line.indexOf('//'),
                    rule_id: 'no-todo',
                });
            }

            // Magic numbers (not 0, 1, -1, common ports)
            const magicMatch = line.match(/[^a-zA-Z_](\d{3,})[^a-zA-Z_\d\.]/);
            if (magicMatch && ![3000, 3001, 8080, 443, 80, 1000, 1024].includes(parseInt(magicMatch[1]))) {
                issues.push({
                    type: 'magic-number',
                    severity: 'LOW',
                    category: 'maintainability',
                    message: `Magic number ${magicMatch[1]} should be a named constant`,
                    file: filePath,
                    line: lineNum,
                    rule_id: 'no-magic-numbers',
                });
            }

            // Long lines
            if (line.length > 120) {
                issues.push({
                    type: 'long-line',
                    severity: 'INFO',
                    category: 'style',
                    message: `Line exceeds 120 characters (${line.length})`,
                    file: filePath,
                    line: lineNum,
                    rule_id: 'max-len',
                });
            }
        });

        return issues;
    }

    // Helper methods
    countCodeLines(lines) {
        return lines.filter(line => {
            const trimmed = line.trim();
            return trimmed && !trimmed.startsWith('//') && !trimmed.startsWith('/*') && !trimmed.startsWith('*');
        }).length;
    }

    countCommentLines(lines) {
        return lines.filter(line => {
            const trimmed = line.trim();
            return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
        }).length;
    }

    countBlankLines(lines) {
        return lines.filter(line => !line.trim()).length;
    }

    /**
     * Get analysis statistics
     */
    getStats() {
        return { ...this.stats };
    }
}

module.exports = Level1BasicAnalysis;
