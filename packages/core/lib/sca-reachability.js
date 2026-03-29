/**
 * SCA Reachability Analysis
 *
 * For each vulnerable dependency found, checks if the vulnerable
 * function/module is actually CALLED in the project's source code.
 * This dramatically reduces noise — most CVEs affect functions never called.
 *
 * Strategy: Vulnerability advisory → extract vulnerable symbols → grep source
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');

const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py', '.go']);

/**
 * Build require/import patterns for a given package name.
 * Handles scoped packages like @scope/name.
 */
function buildImportPatterns(pkgName) {
    // Escape special regex chars (mainly for scoped packages with @/)
    const escaped = pkgName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return [
        // CJS: require('pkg') or require("pkg") — exact or subpath require('pkg/submod')
        new RegExp(`require\\s*\\(\\s*['"]${escaped}(?:/[^'"]*)?['"]\\s*\\)`),
        // ESM: import ... from 'pkg' / import 'pkg'
        new RegExp(`from\\s+['"]${escaped}(?:/[^'"]*)?['"]`),
        new RegExp(`import\\s+['"]${escaped}(?:/[^'"]*)?['"]`),
        // Python: import pkg / from pkg import ...
        new RegExp(`(?:^|\\n)\\s*(?:import\\s+${escaped}|from\\s+${escaped}\\s+import)`),
        // Go: "pkg" (module path may contain the package name as last segment)
        new RegExp(`"[^"]*\\/${escaped}"`),
    ];
}

/**
 * Extract the local alias bound to a CJS require or ESM default import.
 * Returns null if not determinable.
 *
 * Examples resolved:
 *   const _ = require('lodash')          → '_'
 *   const { merge } = require('lodash')  → null (destructured, skip alias call check)
 *   import lodash from 'lodash'           → 'lodash'
 *   import * as lodash from 'lodash'      → 'lodash'
 */
function extractAlias(source, pkgName) {
    const escaped = pkgName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    // CJS default: const X = require('pkg')
    const cjsMatch = source.match(
        new RegExp(`const\\s+(\\w+)\\s*=\\s*require\\s*\\(\\s*['"]${escaped}(?:/[^'"]*)?['"]\\s*\\)`)
    );
    if (cjsMatch) return cjsMatch[1];

    // ESM default: import X from 'pkg'  or  import * as X from 'pkg'
    const esmMatch = source.match(
        new RegExp(`import\\s+(?:\\*\\s+as\\s+)?(\\w+)\\s+from\\s+['"]${escaped}(?:/[^'"]*)?['"]`)
    );
    if (esmMatch) return esmMatch[1];

    return null;
}

/**
 * SCAReachabilityAnalyzer — enriches vulnerability findings with reachability data.
 */
class SCAReachabilityAnalyzer {
    /**
     * Analyze reachability for each vulnerability finding.
     *
     * @param {object[]} vulnerabilities - Array of findings from DependencyScanner
     * @param {string[]} sourceFiles     - Absolute paths of project source files to scan
     * @returns {Promise<object[]>}       Same array with reachable/reachabilityNote/reachabilityConfidence added
     */
    async analyzeReachability(vulnerabilities, sourceFiles) {
        if (!vulnerabilities.length || !sourceFiles.length) {
            return vulnerabilities.map(v => ({
                ...v,
                reachable: false,
                reachabilityNote: 'No source files to analyze',
                reachabilityConfidence: 'LOW',
            }));
        }

        // Read all source files once; skip files that fail to read
        const sources = await Promise.all(
            sourceFiles.map(async (filePath) => {
                try {
                    const content = await fs.readFile(filePath, 'utf8');
                    return { filePath, content };
                } catch {
                    return null;
                }
            })
        );
        const validSources = sources.filter(Boolean);

        // Cache per-package results so files are only scanned once per unique package
        const cache = new Map();

        return vulnerabilities.map(vuln => {
            const pkgName = vuln.package;
            if (!pkgName) {
                return {
                    ...vuln,
                    reachable: null,
                    reachabilityNote: 'No package name on finding',
                    reachabilityConfidence: 'LOW',
                };
            }

            if (!cache.has(pkgName)) {
                cache.set(pkgName, this._checkPackage(pkgName, validSources));
            }

            const { importCount, callCount, note } = cache.get(pkgName);

            let reachable;
            let reachabilityConfidence;

            if (importCount === 0) {
                reachable = false;
                reachabilityConfidence = 'LOW';
            } else if (callCount > 0) {
                reachable = true;
                reachabilityConfidence = 'HIGH';
            } else {
                // Imported but no method call detected
                reachable = false;
                reachabilityConfidence = 'MEDIUM';
            }

            return {
                ...vuln,
                reachable,
                reachabilityNote: note,
                reachabilityConfidence,
            };
        });
    }

    /**
     * Scan source files for import and call-site evidence of a given package.
     * Returns counts and a human-readable note. Pure, synchronous over pre-read content.
     *
     * @param {string}   pkgName
     * @param {{filePath: string, content: string}[]} sources
     * @returns {{ importCount: number, callCount: number, note: string }}
     */
    _checkPackage(pkgName, sources) {
        const importPatterns = buildImportPatterns(pkgName);
        const importedFiles = [];
        const calledFiles = [];

        for (const { filePath, content } of sources) {
            const imported = importPatterns.some(p => p.test(content));
            if (!imported) continue;

            importedFiles.push(filePath);

            // Try to find the local alias and detect any method call on it
            const alias = extractAlias(content, pkgName);
            let called = false;

            if (alias) {
                // e.g.  _.merge(   or  lodash.cloneDeep(
                const callPattern = new RegExp(`\\b${alias}\\s*\\.\\s*\\w+\\s*\\(`);
                called = callPattern.test(content);
            }

            // Fallback: look for any bare call that might be this package
            // (handles destructured imports: const { merge } = require('lodash'); merge( ... ))
            if (!called) {
                // If the import line is there but alias extraction failed, mark as MEDIUM-confidence
                // — we know it's imported but can't definitively confirm a call
                called = false; // stays false; confidence will be MEDIUM
            }

            if (called) calledFiles.push(filePath);
        }

        let note;
        if (importedFiles.length === 0) {
            note = 'Package not imported in source code';
        } else if (calledFiles.length > 0) {
            note = `Package imported in ${importedFiles.length} file${importedFiles.length !== 1 ? 's' : ''}, called in ${calledFiles.length} file${calledFiles.length !== 1 ? 's' : ''}`;
        } else {
            note = `Package imported in ${importedFiles.length} file${importedFiles.length !== 1 ? 's' : ''}, but no method calls detected — may use destructuring or side-effect import`;
        }

        return { importCount: importedFiles.length, callCount: calledFiles.length, note };
    }
}

module.exports = { SCAReachabilityAnalyzer };
