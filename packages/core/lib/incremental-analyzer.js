/**
 * Incremental Analyzer
 * 
 * High-performance incremental analysis that only processes changed files.
 * Uses file hash caching and parallel workers for speed.
 * 
 * Target: <10s per 1000 lines of code
 * 
 * @module incremental-analyzer
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const { analyzeDomain } = require('./domain-analyzers');

/**
 * File hash cache for tracking changes
 */
class FileHashCache {
    constructor(cacheDir = '.codetitan-cache') {
        this.cacheDir = cacheDir;
        this.cachePath = path.join(cacheDir, 'file-hashes.json');
        this.cache = new Map();
        this.loaded = false;
    }

    /**
     * Load cache from disk
     */
    async load() {
        if (this.loaded) return;

        try {
            await fs.mkdir(this.cacheDir, { recursive: true });
            const data = await fs.readFile(this.cachePath, 'utf-8');
            const parsed = JSON.parse(data);
            this.cache = new Map(Object.entries(parsed));
            this.loaded = true;
        } catch (e) {
            // Cache doesn't exist yet
            this.cache = new Map();
            this.loaded = true;
        }
    }

    /**
     * Save cache to disk
     */
    async save() {
        const data = Object.fromEntries(this.cache);
        await fs.writeFile(this.cachePath, JSON.stringify(data, null, 2));
    }

    /**
     * Calculate file hash
     */
    async getFileHash(filePath) {
        const content = await fs.readFile(filePath);
        return crypto.createHash('md5').update(content).digest('hex');
    }

    /**
     * Check if file has changed
     */
    async hasChanged(filePath) {
        await this.load();

        try {
            const currentHash = await this.getFileHash(filePath);
            const cachedHash = this.cache.get(filePath);
            return currentHash !== cachedHash;
        } catch (e) {
            return true; // Assume changed if error
        }
    }

    /**
     * Update hash for file
     */
    async updateHash(filePath) {
        await this.load();
        const hash = await this.getFileHash(filePath);
        this.cache.set(filePath, hash);
    }

    /**
     * Get all changed files from a list
     */
    async getChangedFiles(files) {
        await this.load();

        const changedFiles = [];

        for (const file of files) {
            if (await this.hasChanged(file)) {
                changedFiles.push(file);
            }
        }

        return changedFiles;
    }

    /**
     * Clear cache
     */
    clear() {
        this.cache.clear();
    }
}

/**
 * Result cache for storing analysis results
 */
class ResultCache {
    constructor(cacheDir = '.codetitan-cache') {
        this.cacheDir = cacheDir;
        this.cachePath = path.join(cacheDir, 'results-cache.json');
        this.cache = new Map();
        this.loaded = false;
        this.maxAge = 24 * 60 * 60 * 1000; // 24 hours
    }

    async load() {
        if (this.loaded) return;

        try {
            await fs.mkdir(this.cacheDir, { recursive: true });
            const data = await fs.readFile(this.cachePath, 'utf-8');
            const parsed = JSON.parse(data);
            this.cache = new Map(Object.entries(parsed));
            this.loaded = true;
        } catch (e) {
            this.cache = new Map();
            this.loaded = true;
        }
    }

    async save() {
        // Clean expired entries
        const now = Date.now();
        for (const [key, value] of this.cache.entries()) {
            if (now - value.timestamp > this.maxAge) {
                this.cache.delete(key);
            }
        }

        const data = Object.fromEntries(this.cache);
        await fs.writeFile(this.cachePath, JSON.stringify(data, null, 2));
    }

    get(filePath, fileHash) {
        const cached = this.cache.get(filePath);
        if (cached && cached.hash === fileHash) {
            return cached.findings;
        }
        return null;
    }

    set(filePath, fileHash, findings) {
        this.cache.set(filePath, {
            hash: fileHash,
            findings,
            timestamp: Date.now()
        });
    }
}

/**
 * Worker pool for parallel analysis
 */
class WorkerPool {
    constructor(workerScript, poolSize = null) {
        this.workerScript = workerScript;
        this.poolSize = poolSize || Math.max(1, os.cpus().length - 1);
        this.workers = [];
        this.queue = [];
        this.activeWorkers = 0;
    }

    /**
     * Execute task in worker pool
     */
    async execute(data) {
        return new Promise((resolve, reject) => {
            const task = { data, resolve, reject };

            if (this.activeWorkers < this.poolSize) {
                this.runTask(task);
            } else {
                this.queue.push(task);
            }
        });
    }

    /**
     * Run task in a worker
     */
    runTask(task) {
        this.activeWorkers++;

        const worker = new Worker(this.workerScript, {
            workerData: task.data
        });

        worker.on('message', (result) => {
            task.resolve(result);
            this.activeWorkers--;
            this.processQueue();
            worker.terminate();
        });

        worker.on('error', (error) => {
            task.reject(error);
            this.activeWorkers--;
            this.processQueue();
            worker.terminate();
        });
    }

    /**
     * Process queued tasks
     */
    processQueue() {
        while (this.queue.length > 0 && this.activeWorkers < this.poolSize) {
            const task = this.queue.shift();
            this.runTask(task);
        }
    }

    /**
     * Terminate all workers
     */
    terminate() {
        for (const worker of this.workers) {
            worker.terminate();
        }
        this.workers = [];
    }
}

/**
 * Incremental Analyzer
 */
class IncrementalAnalyzer {
    constructor(options = {}) {
        this.fileHashCache = new FileHashCache(options.cacheDir);
        this.resultCache = new ResultCache(options.cacheDir);
        this.batchSize = options.batchSize || 50;
        this.concurrency = options.concurrency || os.cpus().length;
        this.stats = {
            totalFiles: 0,
            analyzedFiles: 0,
            cachedResults: 0,
            skippedFiles: 0,
            startTime: 0,
            endTime: 0
        };
    }

    /**
     * Find all analyzable files in project
     */
    async findFiles(projectPath, options = {}) {
        const extensions = options.extensions || [
            '.js', '.jsx', '.ts', '.tsx',
            '.py', '.java', '.go', '.cs',
            '.rb', '.php', '.yaml', '.yml',
            '.tf', '.json', '.xml'
        ];

        const exclude = options.exclude || [
            'node_modules', '.git', 'dist', 'build',
            'coverage', '.next', '__pycache__', 'vendor'
        ];

        const files = [];

        async function walk(dir) {
            try {
                const entries = await fs.readdir(dir, { withFileTypes: true });

                for (const entry of entries) {
                    const fullPath = path.join(dir, entry.name);

                    if (entry.isDirectory()) {
                        if (!exclude.includes(entry.name)) {
                            await walk(fullPath);
                        }
                    } else if (entry.isFile()) {
                        const ext = path.extname(entry.name).toLowerCase();
                        if (extensions.includes(ext)) {
                            files.push(fullPath);
                        }
                    }
                }
            } catch (e) {
                // Skip inaccessible directories
            }
        }

        await walk(projectPath);
        return files;
    }

    /**
     * Analyze single file using full domain analyzers
     */
    async analyzeFile(filePath, rules = []) {
        const findings = [];
        try {
            const content = await fs.readFile(filePath, 'utf-8');
            const projectRoot = path.resolve(filePath, '..', '..', '..');
            const domains = ['security-god', 'performance-god', 'test-god', 'refactoring-god', 'documentation-god'];

            for (const domain of domains) {
                try {
                    const result = analyzeDomain(domain, filePath, content, projectRoot);
                    if (result && result.issues) {
                        for (const issue of result.issues) {
                            findings.push({
                                ruleId: issue.category || 'unknown',
                                severity: issue.severity || 'LOW',
                                message: issue.message || '',
                                file: filePath,
                                line: issue.line || 1,
                                column: issue.column || 0,
                                category: issue.category,
                                snippet: issue.snippet || '',
                                impact: issue.impact,
                            });
                        }
                    }
                } catch (_domainErr) {
                    // Continue with other domains if one fails
                }
            }
        } catch (e) {
            // Skip unreadable files
        }
        return findings;
    }

    /**
     * Analyze files in parallel batches
     */
    async analyzeFilesBatch(files, rules = []) {
        const allFindings = [];
        const batchSize = this.batchSize;

        for (let i = 0; i < files.length; i += batchSize) {
            const batch = files.slice(i, i + batchSize);

            // Process batch in parallel
            const batchResults = await Promise.all(
                batch.map(file => this.analyzeFile(file, rules))
            );

            for (const findings of batchResults) {
                allFindings.push(...findings);
            }
        }

        return allFindings;
    }

    /**
     * Run incremental analysis
     */
    async analyze(projectPath, options = {}) {
        this.stats.startTime = Date.now();

        // Load caches
        await this.fileHashCache.load();
        await this.resultCache.load();

        // Find all files
        const allFiles = await this.findFiles(projectPath, options);
        this.stats.totalFiles = allFiles.length;

        // Get only changed files
        const changedFiles = options.force
            ? allFiles
            : await this.fileHashCache.getChangedFiles(allFiles);

        this.stats.skippedFiles = allFiles.length - changedFiles.length;

        // Collect cached results for unchanged files
        const cachedFindings = [];
        for (const file of allFiles) {
            if (!changedFiles.includes(file)) {
                const hash = await this.fileHashCache.getFileHash(file);
                const cached = this.resultCache.get(file, hash);
                if (cached) {
                    cachedFindings.push(...cached);
                    this.stats.cachedResults++;
                }
            }
        }

        // Analyze changed files
        const newFindings = await this.analyzeFilesBatch(changedFiles, options.rules);
        this.stats.analyzedFiles = changedFiles.length;

        // Optional cross-file taint pass (runs across all files, not just changed)
        if (options.crossFileTaint !== false && allFiles.length > 0) {
            try {
                const { analyzeCrossFileTaint } = require('./cross-file-taint');
                const crossFileFindings = await analyzeCrossFileTaint(projectPath, allFiles, options);
                newFindings.push(...crossFileFindings);
            } catch (_) {}
        }

        // Update caches
        for (const file of changedFiles) {
            await this.fileHashCache.updateHash(file);
            const fileFindings = newFindings.filter(f => f.file === file);
            const hash = await this.fileHashCache.getFileHash(file);
            this.resultCache.set(file, hash, fileFindings);
        }

        // Save caches
        await this.fileHashCache.save();
        await this.resultCache.save();

        this.stats.endTime = Date.now();

        // Combine results
        const allFindings = [...cachedFindings, ...newFindings];

        return {
            findings: allFindings,
            stats: {
                ...this.stats,
                duration: this.stats.endTime - this.stats.startTime,
                filesPerSecond: changedFiles.length / ((this.stats.endTime - this.stats.startTime) / 1000),
            },
            summary: {
                critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
                high: allFindings.filter(f => f.severity === 'HIGH').length,
                medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
                low: allFindings.filter(f => f.severity === 'LOW').length,
                total: allFindings.length
            }
        };
    }

    /**
     * Get performance report
     */
    getPerformanceReport() {
        const duration = this.stats.endTime - this.stats.startTime;
        const fps = this.stats.analyzedFiles / (duration / 1000);

        return {
            duration: `${duration}ms`,
            totalFiles: this.stats.totalFiles,
            analyzedFiles: this.stats.analyzedFiles,
            cachedResults: this.stats.cachedResults,
            skippedFiles: this.stats.skippedFiles,
            filesPerSecond: fps.toFixed(2),
            cacheHitRate: `${((this.stats.skippedFiles / this.stats.totalFiles) * 100).toFixed(1)}%`
        };
    }
}

module.exports = {
    IncrementalAnalyzer,
    FileHashCache,
    ResultCache,
    WorkerPool
};
