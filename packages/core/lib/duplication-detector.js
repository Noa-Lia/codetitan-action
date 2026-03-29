/**
 * Duplication Detector
 * 
 * Detects code duplication (clones) across files using token-based similarity.
 * Identifies DRY violations and copy-paste code patterns.
 * 
 * @module duplication-detector
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

/**
 * Token types for normalization
 */
const TOKEN_TYPES = {
    IDENTIFIER: 'ID',
    STRING: 'STR',
    NUMBER: 'NUM',
    OPERATOR: 'OP',
    KEYWORD: 'KW',
    PUNCTUATION: 'PUNCT',
    WHITESPACE: 'WS',
    COMMENT: 'COMMENT'
};

/**
 * Language keywords for detection
 */
const KEYWORDS = {
    javascript: new Set([
        'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue',
        'debugger', 'default', 'delete', 'do', 'else', 'export', 'extends', 'false',
        'finally', 'for', 'function', 'if', 'import', 'in', 'instanceof', 'let',
        'new', 'null', 'return', 'static', 'super', 'switch', 'this', 'throw',
        'true', 'try', 'typeof', 'undefined', 'var', 'void', 'while', 'with', 'yield'
    ]),
    python: new Set([
        'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break',
        'class', 'continue', 'def', 'del', 'elif', 'else', 'except', 'finally',
        'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal',
        'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield'
    ]),
    java: new Set([
        'abstract', 'assert', 'boolean', 'break', 'byte', 'case', 'catch', 'char',
        'class', 'const', 'continue', 'default', 'do', 'double', 'else', 'enum',
        'extends', 'final', 'finally', 'float', 'for', 'goto', 'if', 'implements',
        'import', 'instanceof', 'int', 'interface', 'long', 'native', 'new', 'package',
        'private', 'protected', 'public', 'return', 'short', 'static', 'strictfp',
        'super', 'switch', 'synchronized', 'this', 'throw', 'throws', 'transient',
        'try', 'void', 'volatile', 'while'
    ])
};

/**
 * Tokenize source code for comparison
 * @param {string} code - Source code
 * @param {string} language - Programming language
 * @returns {string[]} Normalized tokens
 */
function tokenize(code, language = 'javascript') {
    const keywords = KEYWORDS[language] || KEYWORDS.javascript;
    const tokens = [];

    // Remove comments first
    let cleanCode = code
        .replace(/\/\*[\s\S]*?\*\//g, '') // Block comments
        .replace(/\/\/.*/g, '')           // Line comments
        .replace(/#.*/g, '');             // Python comments

    // Simple tokenizer using regex
    const tokenPattern = /([a-zA-Z_$][a-zA-Z0-9_$]*)|("(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')|(`(?:[^`\\]|\\.)*`)|(\d+(?:\.\d+)?)|([+\-*/%=<>!&|^~?:]+)|([{}()\[\];,.])/g;

    let match;
    while ((match = tokenPattern.exec(cleanCode)) !== null) {
        const token = match[0];

        if (match[1]) {
            // Identifier or keyword
            if (keywords.has(token)) {
                tokens.push(`KW:${token}`);
            } else {
                tokens.push('ID'); // Normalize identifiers
            }
        } else if (match[2] || match[3] || match[4]) {
            // String literals
            tokens.push('STR');
        } else if (match[5]) {
            // Numbers
            tokens.push('NUM');
        } else if (match[6]) {
            // Operators
            tokens.push(`OP:${token}`);
        } else if (match[7]) {
            // Punctuation
            tokens.push(`P:${token}`);
        }
    }

    return tokens;
}

/**
 * Create hash for a token sequence
 * @param {string[]} tokens - Token array
 * @returns {string} MD5 hash
 */
function hashTokens(tokens) {
    return crypto.createHash('md5').update(tokens.join('|')).digest('hex');
}

/**
 * Extract code blocks from source
 * @param {string} code - Source code
 * @param {number} minLines - Minimum lines for a block
 * @returns {Object[]} Code blocks with line info
 */
function extractBlocks(code, minLines = 5) {
    const lines = code.split('\n');
    const blocks = [];

    // Extract function/method bodies and statement sequences
    let currentBlock = [];
    let blockStartLine = 0;
    let braceDepth = 0;
    let inBlock = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        // Skip empty lines and single-line comments
        if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) {
            continue;
        }

        // Track brace depth for block detection
        const openBraces = (line.match(/{/g) || []).length;
        const closeBraces = (line.match(/}/g) || []).length;

        if (!inBlock && openBraces > 0) {
            inBlock = true;
            blockStartLine = i + 1;
            currentBlock = [line];
            braceDepth = openBraces - closeBraces;
        } else if (inBlock) {
            currentBlock.push(line);
            braceDepth += openBraces - closeBraces;

            if (braceDepth <= 0) {
                if (currentBlock.length >= minLines) {
                    blocks.push({
                        startLine: blockStartLine,
                        endLine: i + 1,
                        lines: currentBlock.length,
                        content: currentBlock.join('\n')
                    });
                }
                inBlock = false;
                currentBlock = [];
            }
        }
    }

    // Also extract sliding window blocks for sequence detection
    const windowSize = minLines;
    for (let i = 0; i <= lines.length - windowSize; i++) {
        const blockLines = lines.slice(i, i + windowSize);
        const content = blockLines.join('\n').trim();

        // Skip if mostly empty or comments
        const nonEmptyLines = blockLines.filter(l => l.trim() && !l.trim().startsWith('//') && !l.trim().startsWith('#'));
        if (nonEmptyLines.length < Math.ceil(windowSize * 0.6)) {
            continue;
        }

        blocks.push({
            startLine: i + 1,
            endLine: i + windowSize,
            lines: windowSize,
            content
        });
    }

    return blocks;
}

/**
 * Clone detection result
 * @typedef {Object} CloneResult
 * @property {string} file1 - First file path
 * @property {string} file2 - Second file path
 * @property {number} startLine1 - Start line in file1
 * @property {number} startLine2 - Start line in file2
 * @property {number} lines - Number of duplicate lines
 * @property {number} similarity - Similarity percentage
 * @property {string} type - Clone type (exact, near, semantic)
 */

/**
 * Duplication Detector class
 */
class DuplicationDetector {
    constructor(options = {}) {
        this.minLines = options.minLines || 5;
        this.minSimilarity = options.minSimilarity || 80;
        this.ignorePatterns = options.ignorePatterns || [
            /node_modules/,
            /\.min\./,
            /\.bundle\./,
            /dist\//,
            /build\//,
            /vendor\//
        ];
    }

    /**
     * Detect language from file extension
     * @param {string} filePath - File path
     * @returns {string} Language identifier
     */
    detectLanguage(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        const langMap = {
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'javascript',
            '.py': 'python',
            '.java': 'java',
            '.cs': 'java', // Similar keyword set
            '.go': 'javascript' // Similar enough
        };
        return langMap[ext] || 'javascript';
    }

    /**
     * Check if file should be ignored
     * @param {string} filePath - File path
     * @returns {boolean} Should ignore
     */
    shouldIgnore(filePath) {
        return this.ignorePatterns.some(pattern => pattern.test(filePath));
    }

    /**
     * Scan project for code duplications
     * @param {string} projectPath - Project root
     * @param {string[]} files - Optional specific files to scan
     * @returns {Promise<Object>} Duplication analysis results
     */
    async scan(projectPath, files = null) {
        const startTime = Date.now();

        // Get files to scan
        let filesToScan = files;
        if (!filesToScan) {
            filesToScan = await this.findSourceFiles(projectPath);
        }

        // Filter ignored files
        filesToScan = filesToScan.filter(f => !this.shouldIgnore(f));

        // Build token database
        const fileData = new Map();
        const blockHashes = new Map(); // hash -> [{file, block}]

        for (const filePath of filesToScan) {
            try {
                const content = await fs.readFile(filePath, 'utf-8');
                const language = this.detectLanguage(filePath);
                const blocks = extractBlocks(content, this.minLines);

                fileData.set(filePath, { content, language, blocks });

                // Hash each block for fast comparison
                for (const block of blocks) {
                    const tokens = tokenize(block.content, language);
                    if (tokens.length < 10) continue; // Skip tiny blocks

                    const hash = hashTokens(tokens);
                    if (!blockHashes.has(hash)) {
                        blockHashes.set(hash, []);
                    }
                    blockHashes.get(hash).push({ file: filePath, block, tokens });
                }
            } catch (error) {
                // Skip unreadable files
            }
        }

        // Find duplicates (blocks with same hash)
        const clones = [];
        const seenPairs = new Set();

        for (const [hash, matches] of blockHashes) {
            if (matches.length < 2) continue;

            // Compare all pairs
            for (let i = 0; i < matches.length; i++) {
                for (let j = i + 1; j < matches.length; j++) {
                    const m1 = matches[i];
                    const m2 = matches[j];

                    // Skip if same file and overlapping lines
                    if (m1.file === m2.file) {
                        const overlap = !(m1.block.endLine < m2.block.startLine ||
                            m2.block.endLine < m1.block.startLine);
                        if (overlap) continue;
                    }

                    // Create unique pair key
                    const pairKey = [
                        `${m1.file}:${m1.block.startLine}`,
                        `${m2.file}:${m2.block.startLine}`
                    ].sort().join('|');

                    if (seenPairs.has(pairKey)) continue;
                    seenPairs.add(pairKey);

                    clones.push({
                        file1: m1.file,
                        file2: m2.file,
                        startLine1: m1.block.startLine,
                        endLine1: m1.block.endLine,
                        startLine2: m2.block.startLine,
                        endLine2: m2.block.endLine,
                        lines: m1.block.lines,
                        similarity: 100, // Exact token match
                        type: m1.file === m2.file ? 'internal' : 'cross-file'
                    });
                }
            }
        }

        // Calculate summary metrics
        const totalDuplicateLines = clones.reduce((sum, c) => sum + c.lines, 0);

        // Sort by lines (largest duplication first)
        clones.sort((a, b) => b.lines - a.lines);

        return {
            scannedFiles: filesToScan.length,
            totalClones: clones.length,
            totalDuplicateLines,
            duplicateBlocks: Math.min(clones.length, 50), // Cap at 50
            clones: clones.slice(0, 50),
            analysisTime: Date.now() - startTime,
            summary: {
                crossFileClones: clones.filter(c => c.type === 'cross-file').length,
                internalClones: clones.filter(c => c.type === 'internal').length
            }
        };
    }

    /**
     * Find source files in project
     * @param {string} projectPath - Project root
     * @returns {Promise<string[]>} Source file paths
     */
    async findSourceFiles(projectPath) {
        const files = [];
        const extensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.cs', '.go']);

        async function walk(dir) {
            try {
                const entries = await fs.readdir(dir, { withFileTypes: true });

                for (const entry of entries) {
                    const fullPath = path.join(dir, entry.name);

                    if (entry.isDirectory()) {
                        // Skip common non-source directories
                        if (['node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__', '.next'].includes(entry.name)) {
                            continue;
                        }
                        await walk(fullPath);
                    } else if (entry.isFile()) {
                        const ext = path.extname(entry.name).toLowerCase();
                        if (extensions.has(ext)) {
                            files.push(fullPath);
                        }
                    }
                }
            } catch (error) {
                // Skip inaccessible directories
            }
        }

        await walk(projectPath);
        return files;
    }

    /**
     * Generate CodeTitan findings from duplication results
     * @param {Object} results - Scan results
     * @returns {Object[]} CodeTitan findings
     */
    generateFindings(results) {
        const findings = [];

        if (results.totalClones === 0) {
            return findings;
        }

        // Overall duplication summary
        if (results.totalClones > 10) {
            findings.push({
                ruleId: 'duplication/high-duplication',
                severity: 'warning',
                message: `Found ${results.totalClones} code duplications (${results.totalDuplicateLines} duplicate lines)`,
                category: 'duplication',
                suggestion: 'Consider refactoring duplicate code into shared functions or modules'
            });
        }

        // Individual clone findings (top 10)
        for (const clone of results.clones.slice(0, 10)) {
            const isInternal = clone.file1 === clone.file2;

            findings.push({
                ruleId: isInternal ? 'duplication/internal-clone' : 'duplication/cross-file-clone',
                severity: clone.lines >= 20 ? 'warning' : 'info',
                file: clone.file1,
                line: clone.startLine1,
                message: isInternal
                    ? `Code block duplicated within file (lines ${clone.startLine1}-${clone.endLine1} ≈ ${clone.startLine2}-${clone.endLine2})`
                    : `Code block duplicated from ${path.basename(clone.file2)}:${clone.startLine2}`,
                category: 'duplication',
                relatedFile: clone.file2,
                relatedLine: clone.startLine2,
                duplicateLines: clone.lines
            });
        }

        return findings;
    }
}

module.exports = {
    DuplicationDetector,
    tokenize,
    extractBlocks,
    hashTokens
};
