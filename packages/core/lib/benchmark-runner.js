/**
 * OWASP Benchmark Runner & Comparison Tool
 * 
 * Runs CodeTitan against industry standard benchmarks:
 * - OWASP Benchmark (Java)
 * - Juliet Test Suite
 * - Custom vulnerability samples
 * 
 * Compares detection rates with Semgrep, CodeQL, and other tools.
 * 
 * @module benchmark-runner
 */

const fs = require('fs');
const path = require('path');

/**
 * Benchmark metrics
 */
class BenchmarkMetrics {
    constructor() {
        this.reset();
    }

    reset() {
        this.truePositives = 0;
        this.falsePositives = 0;
        this.trueNegatives = 0;
        this.falseNegatives = 0;
        this.byCategory = new Map();
        this.byCWE = new Map();
        this.detectionTimes = [];
    }

    /**
     * Record a detection result
     */
    record(expected, detected, category = null, cwe = null, time = 0) {
        if (expected && detected) {
            this.truePositives++;
        } else if (!expected && detected) {
            this.falsePositives++;
        } else if (!expected && !detected) {
            this.trueNegatives++;
        } else {
            this.falseNegatives++;
        }

        // Track by category
        if (category) {
            if (!this.byCategory.has(category)) {
                this.byCategory.set(category, { tp: 0, fp: 0, tn: 0, fn: 0 });
            }
            const cat = this.byCategory.get(category);
            if (expected && detected) cat.tp++;
            else if (!expected && detected) cat.fp++;
            else if (!expected && !detected) cat.tn++;
            else cat.fn++;
        }

        // Track by CWE
        if (cwe) {
            if (!this.byCWE.has(cwe)) {
                this.byCWE.set(cwe, { tp: 0, fp: 0, tn: 0, fn: 0 });
            }
            const c = this.byCWE.get(cwe);
            if (expected && detected) c.tp++;
            else if (!expected && detected) c.fp++;
            else if (!expected && !detected) c.tn++;
            else c.fn++;
        }

        // Track time
        if (time > 0) {
            this.detectionTimes.push(time);
        }
    }

    /**
     * Calculate precision (true positives / all positives detected)
     */
    getPrecision() {
        const total = this.truePositives + this.falsePositives;
        return total > 0 ? this.truePositives / total : 0;
    }

    /**
     * Calculate recall (true positives / all actual positives)
     */
    getRecall() {
        const total = this.truePositives + this.falseNegatives;
        return total > 0 ? this.truePositives / total : 0;
    }

    /**
     * Calculate F1 score (harmonic mean of precision and recall)
     */
    getF1Score() {
        const precision = this.getPrecision();
        const recall = this.getRecall();
        if (precision + recall === 0) return 0;
        return (2 * precision * recall) / (precision + recall);
    }

    /**
     * Calculate accuracy
     */
    getAccuracy() {
        const total = this.truePositives + this.falsePositives +
            this.trueNegatives + this.falseNegatives;
        return total > 0 ? (this.truePositives + this.trueNegatives) / total : 0;
    }

    /**
     * Get Youden score (for OWASP compatibility)
     */
    getYoudenScore() {
        const tpr = this.getRecall(); // True Positive Rate
        const fpr = this.getFalsePositiveRate();
        return tpr - fpr;
    }

    /**
     * Get false positive rate
     */
    getFalsePositiveRate() {
        const total = this.falsePositives + this.trueNegatives;
        return total > 0 ? this.falsePositives / total : 0;
    }

    /**
     * Get average detection time
     */
    getAverageTime() {
        if (this.detectionTimes.length === 0) return 0;
        return this.detectionTimes.reduce((a, b) => a + b, 0) / this.detectionTimes.length;
    }

    /**
     * Get summary object
     */
    getSummary() {
        return {
            truePositives: this.truePositives,
            falsePositives: this.falsePositives,
            trueNegatives: this.trueNegatives,
            falseNegatives: this.falseNegatives,
            precision: Math.round(this.getPrecision() * 1000) / 10,
            recall: Math.round(this.getRecall() * 1000) / 10,
            f1Score: Math.round(this.getF1Score() * 1000) / 10,
            accuracy: Math.round(this.getAccuracy() * 1000) / 10,
            youdenScore: Math.round(this.getYoudenScore() * 1000) / 10,
            falsePositiveRate: Math.round(this.getFalsePositiveRate() * 1000) / 10,
            averageTimeMs: Math.round(this.getAverageTime()),
            byCategory: Object.fromEntries(this.byCategory),
            byCWE: Object.fromEntries(this.byCWE),
        };
    }
}

/**
 * Built-in vulnerability test cases
 */
const VULNERABILITY_SAMPLES = {
    'SQL_INJECTION': {
        vulnerable: [
            {
                code: `const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);`,
                description: 'Direct string concatenation in SQL query',
            },
            {
                code: `db.query(\`SELECT * FROM users WHERE email = '\${email}'\`);`,
                description: 'Template literal SQL injection',
            },
            {
                code: `const sql = "DELETE FROM orders WHERE id = " + req.body.orderId;`,
                description: 'User input in DELETE query',
            },
        ],
        safe: [
            {
                code: `db.query("SELECT * FROM users WHERE id = ?", [userId]);`,
                description: 'Parameterized query',
            },
            {
                code: `prisma.user.findUnique({ where: { id: userId } });`,
                description: 'ORM query',
            },
        ],
        cwe: 'CWE-89',
    },
    'XSS': {
        vulnerable: [
            {
                code: `element.innerHTML = userInput;`,
                description: 'Direct innerHTML assignment',
            },
            {
                code: `document.write(searchQuery);`,
                description: 'document.write with user input',
            },
            {
                code: `<div dangerouslySetInnerHTML={{ __html: content }} />`,
                description: 'React dangerouslySetInnerHTML',
            },
        ],
        safe: [
            {
                code: `element.textContent = userInput;`,
                description: 'textContent (auto-escaped)',
            },
            {
                code: `element.innerHTML = DOMPurify.sanitize(userInput);`,
                description: 'DOMPurify sanitization',
            },
        ],
        cwe: 'CWE-79',
    },
    'COMMAND_INJECTION': {
        vulnerable: [
            {
                code: `exec("ping " + host);`,
                description: 'Direct command injection',
            },
            {
                code: `execSync(\`rm -rf \${userPath}\`);`,
                description: 'Template literal in exec',
            },
        ],
        safe: [
            {
                code: `spawn("ping", [host], { shell: false });`,
                description: 'spawn with arguments array',
            },
            {
                code: `execFile("ping", [escapedHost]);`,
                description: 'execFile with escaped input',
            },
        ],
        cwe: 'CWE-78',
    },
    'PATH_TRAVERSAL': {
        vulnerable: [
            {
                code: `fs.readFileSync("/uploads/" + filename);`,
                description: 'Path traversal via filename',
            },
            {
                code: `const file = req.query.file;
fs.writeFileSync(file, data);`,
                description: 'Arbitrary file write',
            },
        ],
        safe: [
            {
                code: `const safeName = path.basename(filename);
fs.readFileSync(path.join("/uploads", safeName));`,
                description: 'path.basename sanitization',
            },
        ],
        cwe: 'CWE-22',
    },
    'SSRF': {
        vulnerable: [
            {
                code: `fetch(req.body.url);`,
                description: 'Direct SSRF',
            },
            {
                code: `axios.get(userProvidedUrl);`,
                description: 'User-controlled URL',
            },
        ],
        safe: [
            {
                code: `const allowed = ['api.example.com'];
if (allowed.includes(new URL(url).hostname)) fetch(url);`,
                description: 'URL whitelist',
            },
        ],
        cwe: 'CWE-918',
    },
    'HARDCODED_SECRETS': {
        vulnerable: [
            {
                code: `const apiKey = "sk_live_abc123xyz";`,
                description: 'Hardcoded API key',
            },
            {
                code: `const password = "admin123";`,
                description: 'Hardcoded password',
            },
            {
                code: `const AWS_SECRET = "AWS_ACCESS_KEY_PLACEHOLDER";`,
                description: 'Hardcoded AWS key',
            },
        ],
        safe: [
            {
                code: `const apiKey = process.env.API_KEY;`,
                description: 'Environment variable',
            },
        ],
        cwe: 'CWE-798',
    },
};

/**
 * Benchmark Runner
 */
class BenchmarkRunner {
    constructor(analyzer) {
        this.analyzer = analyzer;
        this.metrics = new BenchmarkMetrics();
    }

    /**
     * Run built-in vulnerability samples benchmark
     */
    async runBuiltinBenchmark() {
        this.metrics.reset();
        const results = {
            categories: {},
            summary: null,
        };

        for (const [category, samples] of Object.entries(VULNERABILITY_SAMPLES)) {
            const categoryMetrics = new BenchmarkMetrics();

            // Test vulnerable samples (should detect)
            for (const sample of samples.vulnerable) {
                const start = Date.now();
                const detected = await this.detectVulnerability(sample.code, category);
                const time = Date.now() - start;

                categoryMetrics.record(true, detected, category, samples.cwe, time);
                this.metrics.record(true, detected, category, samples.cwe, time);
            }

            // Test safe samples (should NOT detect)
            for (const sample of samples.safe) {
                const start = Date.now();
                const detected = await this.detectVulnerability(sample.code, category);
                const time = Date.now() - start;

                categoryMetrics.record(false, detected, category, samples.cwe, time);
                this.metrics.record(false, detected, category, samples.cwe, time);
            }

            results.categories[category] = categoryMetrics.getSummary();
        }

        results.summary = this.metrics.getSummary();
        return results;
    }

    /**
     * Detect vulnerability in code sample
     */
    async detectVulnerability(code, category) {
        try {
            const result = await this.analyzer.analyze(code, 'sample.js', {
                level: 6,
                categories: [category.toLowerCase()],
            });

            return result.issues && result.issues.length > 0;
        } catch (error) {
            console.error('Detection error:', error.message);
            return false;
        }
    }

    /**
     * Run OWASP Benchmark (if downloaded)
     */
    async runOWASPBenchmark(benchmarkPath) {
        if (!fs.existsSync(benchmarkPath)) {
            return {
                error: 'OWASP Benchmark not found. Download from: https://github.com/OWASP-Benchmark/BenchmarkJava',
            };
        }

        this.metrics.reset();

        // Load expected results
        const expectedResultsPath = path.join(benchmarkPath, 'expectedresults-1.2.csv');
        const expectedResults = await this.loadOWASPExpectedResults(expectedResultsPath);

        // Scan source files
        const srcPath = path.join(benchmarkPath, 'src/main/java/org/owasp/benchmark/testcode');
        const files = this.getJavaFiles(srcPath);

        console.log(`Running OWASP Benchmark on ${files.length} test cases...`);

        for (const file of files) {
            const testName = path.basename(file, '.java');
            const expected = expectedResults.get(testName);

            if (expected === undefined) continue;

            const code = fs.readFileSync(file, 'utf8');
            const start = Date.now();

            const result = await this.analyzer.analyze(code, file, { level: 6 });
            const detected = result.issues && result.issues.length > 0;
            const time = Date.now() - start;

            this.metrics.record(expected, detected, expected.category, expected.cwe, time);
        }

        return this.metrics.getSummary();
    }

    /**
     * Load OWASP expected results from CSV
     */
    async loadOWASPExpectedResults(csvPath) {
        const results = new Map();

        if (!fs.existsSync(csvPath)) return results;

        const content = fs.readFileSync(csvPath, 'utf8');
        const lines = content.split('\n').slice(1); // Skip header

        for (const line of lines) {
            const parts = line.split(',');
            if (parts.length >= 4) {
                const testName = parts[0].trim();
                const category = parts[2].trim();
                const vulnType = parts[3].trim() === 'true';

                results.set(testName, {
                    isVulnerable: vulnType,
                    category,
                    cwe: this.mapOWASPCategory(category),
                });
            }
        }

        return results;
    }

    /**
     * Map OWASP category to CWE
     */
    mapOWASPCategory(category) {
        const mapping = {
            'cmdi': 'CWE-78',
            'crypto': 'CWE-327',
            'hash': 'CWE-328',
            'ldapi': 'CWE-90',
            'pathtraver': 'CWE-22',
            'securecookie': 'CWE-614',
            'sqli': 'CWE-89',
            'trustbound': 'CWE-501',
            'weakrand': 'CWE-330',
            'xpathi': 'CWE-643',
            'xss': 'CWE-79',
        };
        return mapping[category] || 'Unknown';
    }

    /**
     * Get Java files from directory
     */
    getJavaFiles(dir) {
        const files = [];

        if (!fs.existsSync(dir)) return files;

        const entries = fs.readdirSync(dir);
        for (const entry of entries) {
            const fullPath = path.join(dir, entry);
            const stat = fs.statSync(fullPath);

            if (stat.isDirectory()) {
                files.push(...this.getJavaFiles(fullPath));
            } else if (entry.endsWith('.java')) {
                files.push(fullPath);
            }
        }

        return files;
    }

    /**
     * Compare with other tools
     */
    generateComparisonReport(codetitanResults, otherTools = {}) {
        const tools = {
            CodeTitan: codetitanResults,
            ...otherTools,
        };

        // Industry averages (from published benchmarks)
        const industryAverages = {
            'Semgrep': { precision: 72, recall: 68, f1Score: 70 },
            'CodeQL': { precision: 78, recall: 75, f1Score: 76 },
            'SonarQube': { precision: 65, recall: 60, f1Score: 62 },
            'Checkmarx': { precision: 70, recall: 72, f1Score: 71 },
            'Fortify': { precision: 68, recall: 74, f1Score: 71 },
        };

        return {
            codetitan: codetitanResults,
            industryComparison: industryAverages,
            ranking: this.calculateRanking(codetitanResults, industryAverages),
        };
    }

    /**
     * Calculate ranking among tools
     */
    calculateRanking(codetitanResults, industryAverages) {
        const scores = [
            { tool: 'CodeTitan', f1Score: codetitanResults.f1Score },
            ...Object.entries(industryAverages).map(([tool, data]) => ({
                tool,
                f1Score: data.f1Score,
            })),
        ];

        scores.sort((a, b) => b.f1Score - a.f1Score);

        return scores.map((s, i) => ({
            rank: i + 1,
            tool: s.tool,
            f1Score: s.f1Score,
        }));
    }

    /**
     * Generate markdown report
     */
    generateMarkdownReport(results) {
        const lines = [
            '# CodeTitan Benchmark Results',
            '',
            `*Generated: ${new Date().toISOString()}*`,
            '',
            '## Summary',
            '',
            '| Metric | Value |',
            '|:-------|------:|',
            `| True Positives | ${results.truePositives} |`,
            `| False Positives | ${results.falsePositives} |`,
            `| True Negatives | ${results.trueNegatives} |`,
            `| False Negatives | ${results.falseNegatives} |`,
            `| **Precision** | **${results.precision}%** |`,
            `| **Recall** | **${results.recall}%** |`,
            `| **F1 Score** | **${results.f1Score}%** |`,
            `| Accuracy | ${results.accuracy}% |`,
            `| Youden Score | ${results.youdenScore}% |`,
            `| False Positive Rate | ${results.falsePositiveRate}% |`,
            `| Avg Detection Time | ${results.averageTimeMs}ms |`,
            '',
            '## Results by Category',
            '',
            '| Category | TP | FP | TN | FN | Precision | Recall |',
            '|:---------|---:|---:|---:|---:|----------:|-------:|',
        ];

        for (const [category, data] of Object.entries(results.byCategory)) {
            const precision = data.tp + data.fp > 0
                ? Math.round(data.tp / (data.tp + data.fp) * 100)
                : 0;
            const recall = data.tp + data.fn > 0
                ? Math.round(data.tp / (data.tp + data.fn) * 100)
                : 0;

            lines.push(`| ${category} | ${data.tp} | ${data.fp} | ${data.tn} | ${data.fn} | ${precision}% | ${recall}% |`);
        }

        lines.push('');
        lines.push('## Industry Comparison');
        lines.push('');
        lines.push('| Tool | F1 Score | Status |');
        lines.push('|:-----|:---------|:-------|');
        lines.push(`| **CodeTitan** | **${results.f1Score}%** | This Report |`);
        lines.push('| Semgrep | ~70% | Published Avg |');
        lines.push('| CodeQL | ~76% | Published Avg |');
        lines.push('| SonarQube | ~62% | Published Avg |');

        return lines.join('\n');
    }
}

module.exports = {
    BenchmarkRunner,
    BenchmarkMetrics,
    VULNERABILITY_SAMPLES,
};
