/**
 * Coverage Parser
 * 
 * Parses code coverage reports (lcov, cobertura) to identify untested code.
 * Integrates with CodeTitan analysis to prioritize findings in uncovered areas.
 * 
 * @module coverage-parser
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * Coverage data structure
 * @typedef {Object} FileCoverage
 * @property {string} file - File path
 * @property {number} lines - Total lines
 * @property {number} coveredLines - Covered lines
 * @property {number} percentage - Coverage percentage
 * @property {number[]} uncoveredLines - Line numbers not covered
 * @property {Object[]} functions - Function coverage data
 */

/**
 * Parse LCOV format coverage report
 * @param {string} lcovPath - Path to lcov.info file
 * @returns {Promise<Map<string, FileCoverage>>} Coverage data by file
 */
async function parseLcov(lcovPath) {
    const content = await fs.readFile(lcovPath, 'utf-8');
    const coverage = new Map();

    let currentFile = null;
    let currentData = null;

    const lines = content.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();

        if (trimmed.startsWith('SF:')) {
            // Source file
            currentFile = trimmed.substring(3);
            currentData = {
                file: currentFile,
                lines: 0,
                coveredLines: 0,
                percentage: 0,
                uncoveredLines: [],
                functions: [],
                branches: { total: 0, covered: 0 }
            };
        } else if (trimmed.startsWith('DA:')) {
            // Line data: DA:line,hit_count
            const [lineNum, hits] = trimmed.substring(3).split(',').map(Number);
            currentData.lines++;
            if (hits > 0) {
                currentData.coveredLines++;
            } else {
                currentData.uncoveredLines.push(lineNum);
            }
        } else if (trimmed.startsWith('FN:')) {
            // Function: FN:line,name
            const [lineNum, name] = trimmed.substring(3).split(',');
            currentData.functions.push({
                name,
                line: parseInt(lineNum, 10),
                hits: 0
            });
        } else if (trimmed.startsWith('FNDA:')) {
            // Function hits: FNDA:hits,name
            const [hits, name] = trimmed.substring(5).split(',');
            const fn = currentData.functions.find(f => f.name === name);
            if (fn) {
                fn.hits = parseInt(hits, 10);
            }
        } else if (trimmed.startsWith('BRDA:')) {
            // Branch data: BRDA:line,block,branch,taken
            const parts = trimmed.substring(5).split(',');
            currentData.branches.total++;
            if (parts[3] !== '-' && parseInt(parts[3], 10) > 0) {
                currentData.branches.covered++;
            }
        } else if (trimmed === 'end_of_record') {
            if (currentFile && currentData) {
                currentData.percentage = currentData.lines > 0
                    ? Math.round((currentData.coveredLines / currentData.lines) * 100)
                    : 100;
                coverage.set(currentFile, currentData);
            }
            currentFile = null;
            currentData = null;
        }
    }

    return coverage;
}

/**
 * Parse Cobertura XML format coverage report
 * @param {string} xmlPath - Path to cobertura.xml file
 * @returns {Promise<Map<string, FileCoverage>>} Coverage data by file
 */
async function parseCobertura(xmlPath) {
    const content = await fs.readFile(xmlPath, 'utf-8');
    const coverage = new Map();

    // Simple XML parsing (no external dependencies)
    const packageMatches = content.matchAll(/<package[^>]*>([\s\S]*?)<\/package>/g);

    for (const packageMatch of packageMatches) {
        const packageContent = packageMatch[1];
        const classMatches = packageContent.matchAll(/<class[^>]*filename="([^"]+)"[^>]*>([\s\S]*?)<\/class>/g);

        for (const classMatch of classMatches) {
            const filename = classMatch[1];
            const classContent = classMatch[2];

            const fileData = {
                file: filename,
                lines: 0,
                coveredLines: 0,
                percentage: 0,
                uncoveredLines: [],
                functions: [],
                branches: { total: 0, covered: 0 }
            };

            // Parse line coverage
            const lineMatches = classContent.matchAll(/<line\s+number="(\d+)"[^>]*hits="(\d+)"[^>]*\/>/g);
            for (const lineMatch of lineMatches) {
                const lineNum = parseInt(lineMatch[1], 10);
                const hits = parseInt(lineMatch[2], 10);
                fileData.lines++;
                if (hits > 0) {
                    fileData.coveredLines++;
                } else {
                    fileData.uncoveredLines.push(lineNum);
                }
            }

            // Parse method coverage
            const methodMatches = classContent.matchAll(/<method\s+name="([^"]+)"[^>]*line="(\d+)"[^>]*>/g);
            for (const methodMatch of methodMatches) {
                fileData.functions.push({
                    name: methodMatch[1],
                    line: parseInt(methodMatch[2], 10),
                    hits: 0 // Would need to parse nested lines
                });
            }

            fileData.percentage = fileData.lines > 0
                ? Math.round((fileData.coveredLines / fileData.lines) * 100)
                : 100;

            coverage.set(filename, fileData);
        }
    }

    return coverage;
}

/**
 * Auto-detect and parse coverage file
 * @param {string} coveragePath - Path to coverage file
 * @returns {Promise<Map<string, FileCoverage>>} Coverage data
 */
async function parseCoverage(coveragePath) {
    const ext = path.extname(coveragePath).toLowerCase();
    const filename = path.basename(coveragePath).toLowerCase();

    if (ext === '.xml' || filename.includes('cobertura')) {
        return parseCobertura(coveragePath);
    } else if (filename.includes('lcov') || ext === '.info') {
        return parseLcov(coveragePath);
    }

    // Try to detect from content
    const content = await fs.readFile(coveragePath, 'utf-8');
    if (content.includes('<?xml') || content.includes('<coverage')) {
        return parseCobertura(coveragePath);
    }

    return parseLcov(coveragePath);
}

/**
 * Find coverage files in a project
 * @param {string} projectPath - Project root path
 * @returns {Promise<string[]>} Found coverage file paths
 */
async function findCoverageFiles(projectPath) {
    const coverageFiles = [];
    const commonPaths = [
        'coverage/lcov.info',
        'coverage/cobertura.xml',
        'coverage/coverage.xml',
        'coverage/clover.xml',
        'lcov.info',
        'coverage.xml',
        'test-results/coverage.xml',
        '.nyc_output/lcov.info',
        'target/site/cobertura/coverage.xml', // Maven
        'htmlcov/lcov.info', // Python
        'cover/lcov.info', // Go
    ];

    for (const relativePath of commonPaths) {
        const fullPath = path.join(projectPath, relativePath);
        try {
            await fs.access(fullPath);
            coverageFiles.push(fullPath);
        } catch {
            // File doesn't exist
        }
    }

    return coverageFiles;
}

/**
 * Coverage Parser class for integration with CodeTitan
 */
class CoverageParser {
    constructor(options = {}) {
        this.minCoverage = options.minCoverage || 80;
        this.failOnLow = options.failOnLow ?? false;
    }

    /**
     * Scan project for coverage data
     * @param {string} projectPath - Project root
     * @returns {Promise<Object>} Coverage analysis results
     */
    async scan(projectPath) {
        const coverageFiles = await findCoverageFiles(projectPath);

        if (coverageFiles.length === 0) {
            return {
                found: false,
                message: 'No coverage files found. Run tests with coverage enabled.',
                suggestions: [
                    'npm test -- --coverage (Jest)',
                    'npx nyc npm test (NYC)',
                    'pytest --cov=. (Python)',
                    'go test -coverprofile=cover.out (Go)',
                ]
            };
        }

        // Parse all found coverage files
        const allCoverage = new Map();
        for (const file of coverageFiles) {
            try {
                const coverage = await parseCoverage(file);
                for (const [filename, data] of coverage) {
                    allCoverage.set(filename, data);
                }
            } catch (error) {
                console.warn(`Failed to parse ${file}: ${error.message}`);
            }
        }

        // Calculate summary
        let totalLines = 0;
        let totalCovered = 0;
        const lowCoverageFiles = [];
        const uncoveredFunctions = [];

        for (const [filename, data] of allCoverage) {
            totalLines += data.lines;
            totalCovered += data.coveredLines;

            if (data.percentage < this.minCoverage) {
                lowCoverageFiles.push({
                    file: filename,
                    coverage: data.percentage,
                    uncoveredLines: data.uncoveredLines.length
                });
            }

            // Find uncovered functions
            for (const fn of data.functions) {
                if (fn.hits === 0) {
                    uncoveredFunctions.push({
                        file: filename,
                        function: fn.name,
                        line: fn.line
                    });
                }
            }
        }

        const overallCoverage = totalLines > 0
            ? Math.round((totalCovered / totalLines) * 100)
            : 0;

        // Sort by lowest coverage first
        lowCoverageFiles.sort((a, b) => a.coverage - b.coverage);

        return {
            found: true,
            files: coverageFiles,
            summary: {
                totalFiles: allCoverage.size,
                totalLines,
                coveredLines: totalCovered,
                overallCoverage,
                meetsThreshold: overallCoverage >= this.minCoverage
            },
            lowCoverageFiles: lowCoverageFiles.slice(0, 20), // Top 20
            uncoveredFunctions: uncoveredFunctions.slice(0, 50), // Top 50
            coverage: allCoverage
        };
    }

    /**
     * Generate findings for uncovered complex code
     * @param {Object} coverageData - Coverage scan results
     * @returns {Object[]} CodeTitan findings
     */
    generateFindings(coverageData) {
        const findings = [];

        if (!coverageData.found) {
            findings.push({
                ruleId: 'coverage/no-coverage-data',
                severity: 'info',
                message: 'No code coverage data found',
                suggestion: coverageData.message,
                category: 'coverage'
            });
            return findings;
        }

        // Overall coverage warning
        if (!coverageData.summary.meetsThreshold) {
            findings.push({
                ruleId: 'coverage/below-threshold',
                severity: 'warning',
                message: `Code coverage (${coverageData.summary.overallCoverage}%) is below threshold (${this.minCoverage}%)`,
                category: 'coverage',
                metrics: coverageData.summary
            });
        }

        // Low coverage files
        for (const file of coverageData.lowCoverageFiles) {
            findings.push({
                ruleId: 'coverage/low-file-coverage',
                severity: file.coverage < 50 ? 'warning' : 'info',
                file: file.file,
                message: `File has ${file.coverage}% coverage (${file.uncoveredLines} lines uncovered)`,
                category: 'coverage'
            });
        }

        // Uncovered functions (potential risk)
        for (const fn of coverageData.uncoveredFunctions.slice(0, 10)) {
            findings.push({
                ruleId: 'coverage/uncovered-function',
                severity: 'info',
                file: fn.file,
                line: fn.line,
                message: `Function '${fn.function}' has no test coverage`,
                category: 'coverage'
            });
        }

        return findings;
    }
}

module.exports = {
    CoverageParser,
    parseLcov,
    parseCobertura,
    parseCoverage,
    findCoverageFiles
};
