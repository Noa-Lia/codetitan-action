/**
 * Dependency Scanner
 * 
 * Scans project dependencies for known vulnerabilities using OSV (Open Source Vulnerabilities) API.
 * Supports: npm (package.json), pip (requirements.txt), Maven (pom.xml)
 * 
 * @module dependency-scanner
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * OSV API endpoint for vulnerability queries
 */
const OSV_API_URL = 'https://api.osv.dev/v1/query';
const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

/**
 * Severity mapping for CVSS scores
 */
const SEVERITY_MAP = {
    CRITICAL: { min: 9.0, max: 10.0 },
    HIGH: { min: 7.0, max: 8.9 },
    MEDIUM: { min: 4.0, max: 6.9 },
    LOW: { min: 0.1, max: 3.9 },
};

/**
 * Get severity from CVSS score
 */
function getSeverityFromCVSS(score) {
    if (!score || score === 0) return 'MEDIUM';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

/**
 * Parse package-lock.json for exact resolved versions (npm lockfile v2/v3)
 */
async function parsePackageLockJson(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        const lock = JSON.parse(content);
        const exactVersions = new Map(); // name -> exact version

        // v2/v3 format: "packages" field with "node_modules/pkgname" keys
        if (lock.packages) {
            for (const [key, entry] of Object.entries(lock.packages)) {
                if (!key || !entry.version) continue;
                // key is like "node_modules/express" or "node_modules/foo/node_modules/bar"
                const name = key.replace(/^node_modules\//, '').replace(/\/node_modules\/.*$/, '');
                // Only store top-level (no nested node_modules in key = one slash max)
                if (key.indexOf('/node_modules/', 'node_modules/'.length) === -1) {
                    exactVersions.set(name, entry.version);
                }
            }
        }
        // v1 format: "dependencies" field
        if (lock.dependencies) {
            for (const [name, entry] of Object.entries(lock.dependencies)) {
                if (entry.version && !exactVersions.has(name)) {
                    exactVersions.set(name, entry.version);
                }
            }
        }
        return exactVersions;
    } catch (_e) {
        return new Map();
    }
}

/**
 * Parse package.json for npm dependencies
 */
async function parsePackageJson(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        const pkg = JSON.parse(content);
        const deps = [];

        // Try to get exact versions from package-lock.json
        const lockPath = path.join(path.dirname(filePath), 'package-lock.json');
        const exactVersions = await parsePackageLockJson(lockPath);

        const addDeps = (depObj, type) => {
            if (!depObj) return;
            Object.entries(depObj).forEach(([name, version]) => {
                // Use exact version from lockfile if available, else strip range specifiers
                const cleanVersion = exactVersions.get(name) || version.replace(/^[\^~>=<]+/, '').split(' ')[0];
                deps.push({
                    name,
                    version: cleanVersion,
                    type,
                    ecosystem: 'npm',
                });
            });
        };

        addDeps(pkg.dependencies, 'runtime');
        addDeps(pkg.devDependencies, 'dev');
        addDeps(pkg.peerDependencies, 'peer');
        addDeps(pkg.optionalDependencies, 'optional');

        return deps;
    } catch (error) {
        console.error(`Failed to parse ${filePath}:`, error.message);
        return [];
    }
}

/**
 * Parse requirements.txt for Python dependencies
 */
async function parseRequirementsTxt(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        const deps = [];

        content.split('\n').forEach(line => {
            line = line.trim();
            // Skip comments and empty lines
            if (!line || line.startsWith('#') || line.startsWith('-')) return;

            // Parse package==version, package>=version, package~=version
            const match = line.match(/^([a-zA-Z0-9_-]+)(?:[=<>~!]+)?([\d.]+)?/);
            if (match) {
                deps.push({
                    name: match[1],
                    version: match[2] || 'latest',
                    type: 'runtime',
                    ecosystem: 'PyPI',
                });
            }
        });

        return deps;
    } catch (error) {
        console.error(`Failed to parse ${filePath}:`, error.message);
        return [];
    }
}

/**
 * Parse pom.xml for Maven dependencies (simplified)
 */
async function parsePomXml(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        const deps = [];

        // Simple regex parsing (production should use proper XML parser)
        const depPattern = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
        let match;

        while ((match = depPattern.exec(content)) !== null) {
            deps.push({
                name: `${match[1]}:${match[2]}`,
                version: match[3] || 'latest',
                type: 'runtime',
                ecosystem: 'Maven',
            });
        }

        return deps;
    } catch (error) {
        console.error(`Failed to parse ${filePath}:`, error.message);
        return [];
    }
}

/**
 * Parse Gemfile.lock for Ruby dependencies
 */
async function parseGemfileLock(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        const deps = [];

        // Match gem entries with versions
        const gemPattern = /^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)/gm;
        let match;

        while ((match = gemPattern.exec(content)) !== null) {
            deps.push({
                name: match[1],
                version: match[2],
                type: 'runtime',
                ecosystem: 'RubyGems',
            });
        }

        return deps;
    } catch (error) {
        console.error(`Failed to parse ${filePath}:`, error.message);
        return [];
    }
}

/**
 * Parse go.mod for Go dependencies
 */
async function parseGoMod(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        const deps = [];

        // Match require statements
        const lines = content.split('\n');
        let inRequire = false;

        for (const line of lines) {
            const trimmed = line.trim();

            if (trimmed.startsWith('require (')) {
                inRequire = true;
                continue;
            }
            if (trimmed === ')') {
                inRequire = false;
                continue;
            }

            if (inRequire || trimmed.startsWith('require ')) {
                const match = trimmed.match(/([^\s]+)\s+v?([^\s]+)/);
                if (match && !match[1].startsWith('//')) {
                    deps.push({
                        name: match[1],
                        version: match[2].replace(/^v/, ''),
                        type: 'runtime',
                        ecosystem: 'Go',
                    });
                }
            }
        }

        return deps;
    } catch (error) {
        console.error(`Failed to parse ${filePath}:`, error.message);
        return [];
    }
}

/**
 * Query OSV API for vulnerabilities
 */
async function queryOSV(ecosystem, packageName, version) {
    try {
        const response = await fetch(OSV_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                package: {
                    name: packageName,
                    ecosystem: ecosystem,
                },
                version: version,
            }),
        });

        if (!response.ok) {
            return { vulns: [] };
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error(`OSV query failed for ${packageName}:`, error.message);
        return { vulns: [] };
    }
}

/**
 * Batch query OSV API for multiple packages
 */
async function batchQueryOSV(packages) {
    try {
        const queries = packages.map(pkg => ({
            package: {
                name: pkg.name,
                ecosystem: pkg.ecosystem,
            },
            version: pkg.version,
        }));

        const response = await fetch(OSV_BATCH_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ queries }),
        });

        if (!response.ok) {
            return { results: packages.map(() => ({ vulns: [] })) };
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('OSV batch query failed:', error.message);
        return { results: packages.map(() => ({ vulns: [] })) };
    }
}

/**
 * Convert OSV vulnerability to CodeTitan finding
 */
function vulnerabilityToFinding(vuln, pkg, manifestPath) {
    // Extract CVSS score
    let cvssScore = 0;
    let severity = 'MEDIUM';

    if (vuln.severity && vuln.severity.length > 0) {
        const cvss = vuln.severity.find(s => s.type === 'CVSS_V3') || vuln.severity[0];
        cvssScore = cvss.score || 0;
        severity = getSeverityFromCVSS(cvssScore);
    } else if (vuln.database_specific?.severity) {
        severity = vuln.database_specific.severity.toUpperCase();
    }

    // Get fixed version
    const fixedVersions = [];
    if (vuln.affected) {
        vuln.affected.forEach(affected => {
            if (affected.ranges) {
                affected.ranges.forEach(range => {
                    range.events?.forEach(event => {
                        if (event.fixed) {
                            fixedVersions.push(event.fixed);
                        }
                    });
                });
            }
        });
    }

    return {
        id: `DEP-${vuln.id}`,
        type: 'vulnerability',
        category: 'DEPENDENCY',
        severity,
        message: vuln.summary || `Vulnerability in ${pkg.name}@${pkg.version}`,
        description: vuln.details || vuln.summary,
        file: manifestPath,
        line: 1,
        package: pkg.name,
        installedVersion: pkg.version,
        fixedVersion: fixedVersions[0] || null,
        cve: vuln.aliases?.find(a => a.startsWith('CVE-')) || null,
        osvId: vuln.id,
        cvssScore,
        references: vuln.references?.map(r => r.url) || [],
        autoFixable: fixedVersions.length > 0,
        fix: fixedVersions.length > 0
            ? { type: 'upgrade', targetVersion: fixedVersions[0] }
            : null,
        reachable: null,
        reachabilityNote: 'Not yet analyzed',
        reachabilityConfidence: null,
    };
}

/**
 * Find dependency manifests in project
 */
async function findManifests(projectPath) {
    const manifests = [];
    const manifestTypes = [
        { file: 'package.json', parser: parsePackageJson },
        { file: 'requirements.txt', parser: parseRequirementsTxt },
        { file: 'pom.xml', parser: parsePomXml },
        { file: 'Gemfile.lock', parser: parseGemfileLock },
        { file: 'go.mod', parser: parseGoMod },
    ];

    // Check root directory
    for (const { file, parser } of manifestTypes) {
        const filePath = path.join(projectPath, file);
        try {
            await fs.access(filePath);
            manifests.push({ path: filePath, parser, type: file });
        } catch {
            // File doesn't exist
        }
    }

    // Also check common subdirectories
    const subdirs = ['packages', 'apps', 'services', 'api', 'frontend', 'backend'];
    for (const subdir of subdirs) {
        const subdirPath = path.join(projectPath, subdir);
        try {
            const entries = await fs.readdir(subdirPath, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.isDirectory()) {
                    for (const { file, parser } of manifestTypes) {
                        const filePath = path.join(subdirPath, entry.name, file);
                        try {
                            await fs.access(filePath);
                            manifests.push({ path: filePath, parser, type: file });
                        } catch {
                            // File doesn't exist
                        }
                    }
                }
            }
        } catch {
            // Subdirectory doesn't exist
        }
    }

    return manifests;
}

/**
 * Parse ALL dependencies (direct + transitive) from a package-lock.json.
 * Uses the "packages" map (npm lockfile v2/v3) which includes every installed
 * package at every nesting level — i.e., the full resolved dependency tree.
 *
 * Returns an array of { name, version, ecosystem, type, transitiveVia }
 * where transitiveVia is the shortest parent path string, e.g. "express > qs".
 */
async function parseTransitiveDeps(lockfilePath) {
    try {
        const content = await fs.readFile(lockfilePath, 'utf8');
        const lock = JSON.parse(content);
        const deps = [];

        if (lock.packages) {
            for (const [key, entry] of Object.entries(lock.packages)) {
                if (!key || !entry.version) continue;
                // key examples:
                //   "node_modules/express"                        → direct
                //   "node_modules/express/node_modules/qs"        → transitive via express
                //   "node_modules/foo/node_modules/bar/node_modules/baz" → deep transitive
                const segments = key.split('/node_modules/');
                const name = segments[segments.length - 1];
                const isDirect = segments.length === 2; // "node_modules/<name>"
                const transitiveVia = isDirect
                    ? null
                    : segments.slice(1, segments.length - 1).join(' > ');

                deps.push({
                    name,
                    version: entry.version,
                    ecosystem: 'npm',
                    type: entry.dev ? 'dev' : 'runtime',
                    isDirect,
                    transitiveVia,
                });
            }
        } else if (lock.dependencies) {
            // v1 lockfile — only direct deps available
            for (const [name, entry] of Object.entries(lock.dependencies)) {
                if (!entry.version) continue;
                deps.push({ name, version: entry.version, ecosystem: 'npm', type: 'runtime', isDirect: true, transitiveVia: null });
            }
        }

        return deps;
    } catch (_e) {
        return [];
    }
}

/**
 * Main dependency scanner class
 */
class DependencyScanner {
    constructor(options = {}) {
        this.batchSize = options.batchSize || 50;
        this.includeDevDeps = options.includeDevDeps ?? true;
        this.failOnSeverity = options.failOnSeverity || 'HIGH';
    }

    /**
     * Scan project for dependency vulnerabilities
     * @param {string} projectPath
     * @param {object} [options]
     * @param {boolean} [options.reachability=true] - Set false to skip reachability analysis
     */
    async scan(projectPath, options = {}) {
        console.log('🔍 Scanning dependencies for vulnerabilities...');

        const results = {
            manifests: [],
            dependencies: [],
            vulnerabilities: [],
            findings: [],
            summary: {
                totalDependencies: 0,
                vulnerableDependencies: 0,
                totalVulnerabilities: 0,
                bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
            },
        };

        // Find all manifests
        const manifests = await findManifests(projectPath);
        results.manifests = manifests.map(m => m.path);

        if (manifests.length === 0) {
            console.log('   No dependency manifests found');
            return results;
        }

        console.log(`   Found ${manifests.length} manifest(s)`);

        // Parse all dependencies
        for (const manifest of manifests) {
            const deps = await manifest.parser(manifest.path);

            // Filter dev deps if configured
            const filteredDeps = this.includeDevDeps
                ? deps
                : deps.filter(d => d.type !== 'dev');

            results.dependencies.push(...filteredDeps.map(d => ({
                ...d,
                manifest: manifest.path,
            })));
        }

        results.summary.totalDependencies = results.dependencies.length;
        console.log(`   Scanning ${results.dependencies.length} dependencies...`);

        // Query OSV in batches
        const vulnerablePackages = new Set();

        for (let i = 0; i < results.dependencies.length; i += this.batchSize) {
            const batch = results.dependencies.slice(i, i + this.batchSize);
            const batchResults = await batchQueryOSV(batch);

            if (batchResults.results) {
                batchResults.results.forEach((result, idx) => {
                    const pkg = batch[idx];
                    if (result.vulns && result.vulns.length > 0) {
                        vulnerablePackages.add(pkg.name);

                        result.vulns.forEach(vuln => {
                            const finding = vulnerabilityToFinding(vuln, pkg, pkg.manifest);
                            results.vulnerabilities.push(vuln);
                            results.findings.push(finding);
                            results.summary.bySeverity[finding.severity]++;
                        });
                    }
                });
            }
        }

        results.summary.vulnerableDependencies = vulnerablePackages.size;
        results.summary.totalVulnerabilities = results.findings.length;

        console.log(`   Found ${results.findings.length} vulnerabilities in ${vulnerablePackages.size} packages`);

        // Reachability analysis — opt-out with options.reachability === false
        if (options.reachability !== false && results.findings.length > 0) {
            const { SCAReachabilityAnalyzer } = require('./sca-reachability');
            const reachability = new SCAReachabilityAnalyzer();
            const sourceFiles = await this.findSourceFiles(projectPath);
            console.log(`   Running reachability analysis across ${sourceFiles.length} source file(s)...`);
            results.findings = await reachability.analyzeReachability(results.findings, sourceFiles);
            results.summary.reachableVulnerabilities = results.findings.filter(f => f.reachable === true).length;
            results.summary.unreachableVulnerabilities = results.findings.filter(f => f.reachable === false).length;
            console.log(`   Reachable: ${results.summary.reachableVulnerabilities}, Unreachable/unconfirmed: ${results.summary.unreachableVulnerabilities}`);
        }

        return results;
    }

    /**
     * Discover source files in the project for reachability analysis.
     * Returns .js .ts .jsx .tsx .mjs .cjs .py .go files, skipping node_modules / .git / dist.
     *
     * @param {string} projectPath
     * @returns {Promise<string[]>}
     */
    /**
     * Scan ALL dependencies (direct + transitive) from package-lock.json.
     * Much broader than scan() — checks every package in the resolved tree.
     *
     * @param {string} projectPath
     * @returns {Promise<{findings: object[], summary: object}>}
     */
    async scanTransitive(projectPath) {
        const lockPath = path.join(projectPath, 'package-lock.json');
        const allDeps = await parseTransitiveDeps(lockPath);
        if (allDeps.length === 0) {
            return { findings: [], summary: { total: 0, direct: 0, transitive: 0, bySeverity: {} } };
        }

        // Batch OSV query — same as scan() but over all deps
        const findings = [];
        for (let i = 0; i < allDeps.length; i += this.batchSize) {
            const batch = allDeps.slice(i, i + this.batchSize);
            try {
                const vulns = await batchQueryOSV(batch);
                for (let j = 0; j < vulns.length; j++) {
                    const vulnList = vulns[j]?.vulns || [];
                    const dep = batch[j];
                    for (const vuln of vulnList) {
                        const sev = getSeverityFromCVSS(vuln.database_specific?.severity || 0);
                        findings.push({
                            ...vulnerabilityToFinding(vuln, dep, lockPath),
                            isDirect: dep.isDirect,
                            transitiveVia: dep.transitiveVia,
                            transitiveChain: dep.transitiveVia
                                ? `${dep.transitiveVia} > ${dep.name}`
                                : dep.name,
                        });
                    }
                }
            } catch (_e) { /* skip failed batch */ }
        }

        const direct = findings.filter(f => f.isDirect).length;
        const transitive = findings.filter(f => !f.isDirect).length;
        const bySeverity = {};
        for (const f of findings) {
            bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
        }

        return {
            findings,
            summary: {
                total: findings.length,
                direct,
                transitive,
                totalPackagesScanned: allDeps.length,
                bySeverity,
            },
        };
    }

    async findSourceFiles(projectPath) {
        const SOURCE_EXTS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py', '.go']);
        const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', 'vendor']);
        const files = [];

        async function walk(dir) {
            let entries;
            try {
                entries = await fs.readdir(dir, { withFileTypes: true });
            } catch {
                return;
            }
            for (const entry of entries) {
                if (SKIP_DIRS.has(entry.name)) continue;
                const fullPath = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    await walk(fullPath);
                } else if (entry.isFile() && SOURCE_EXTS.has(path.extname(entry.name))) {
                    files.push(fullPath);
                }
            }
        }

        await walk(projectPath);
        return files;
    }

    /**
     * Generate fix suggestions for vulnerable dependencies
     */
    generateFixes(findings) {
        return findings
            .filter(f => f.autoFixable && f.fix)
            .map(f => ({
                package: f.package,
                currentVersion: f.installedVersion,
                fixedVersion: f.fix.targetVersion,
                manifest: f.file,
                severity: f.severity,
                cve: f.cve,
            }));
    }
}

module.exports = {
    DependencyScanner,
    parsePackageLockJson,
    parseTransitiveDeps,
    parsePackageJson,
    parseRequirementsTxt,
    parsePomXml,
    parseGemfileLock,
    parseGoMod,
    queryOSV,
    batchQueryOSV,
    findManifests,
    getSeverityFromCVSS,
};
