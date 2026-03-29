/**
 * Cross-File Analyzer
 * 
 * Tracks data and security issues across module boundaries
 * by parsing imports and building a dependency graph.
 * 
 * @module cross-file-analyzer
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const fs = require('fs');
const path = require('path');

/**
 * Dependency Graph Node
 */
class ModuleNode {
    constructor(filePath) {
        this.filePath = filePath;
        this.imports = new Map();  // module -> imported names
        this.exports = new Map();  // exported name -> type
        this.dependencies = [];    // files this module depends on
        this.dependents = [];      // files that depend on this module
        this.findings = [];        // security findings in this file
    }
}

/**
 * Cross-File Analyzer
 */
class CrossFileAnalyzer {
    constructor(projectRoot) {
        this.projectRoot = projectRoot;
        this.modules = new Map();  // filePath -> ModuleNode
        this.exportedFunctions = new Map();  // qualified name -> metadata
        this.securityExports = new Set();   // functions that return/expose sensitive data
    }

    /**
     * Parse a file and extract imports/exports
     */
    async parseModule(filePath) {
        if (this.modules.has(filePath)) {
            return this.modules.get(filePath);
        }

        let code;
        try {
            code = await fs.promises.readFile(filePath, 'utf-8');
        } catch (e) {
            return null;
        }

        const node = new ModuleNode(filePath);

        let ast;
        try {
            ast = parser.parse(code, {
                sourceType: 'module',
                plugins: ['typescript', 'jsx', 'decorators-legacy', 'classProperties'],
                errorRecovery: true,
            });
        } catch (e) {
            this.modules.set(filePath, node);
            return node;
        }

        traverse(ast, {
            // ES6 imports
            ImportDeclaration: (path) => {
                const source = path.node.source.value;
                const importedNames = [];

                path.node.specifiers.forEach(spec => {
                    if (spec.type === 'ImportDefaultSpecifier') {
                        importedNames.push({ local: spec.local.name, imported: 'default' });
                    } else if (spec.type === 'ImportSpecifier') {
                        importedNames.push({
                            local: spec.local.name,
                            imported: spec.imported?.name || spec.local.name,
                        });
                    } else if (spec.type === 'ImportNamespaceSpecifier') {
                        importedNames.push({ local: spec.local.name, imported: '*' });
                    }
                });

                node.imports.set(source, importedNames);

                // Resolve to actual file path
                const resolvedPath = this.resolveImport(source, filePath);
                if (resolvedPath) {
                    node.dependencies.push(resolvedPath);
                }
            },

            // CommonJS require
            CallExpression: (path) => {
                if (path.node.callee.name === 'require' &&
                    path.node.arguments[0]?.type === 'StringLiteral') {
                    const source = path.node.arguments[0].value;
                    const resolvedPath = this.resolveImport(source, filePath);

                    if (resolvedPath && !node.dependencies.includes(resolvedPath)) {
                        node.dependencies.push(resolvedPath);
                    }

                    // Track what's imported
                    const parent = path.parent;
                    if (parent.type === 'VariableDeclarator') {
                        if (parent.id.type === 'Identifier') {
                            node.imports.set(source, [{ local: parent.id.name, imported: 'default' }]);
                        } else if (parent.id.type === 'ObjectPattern') {
                            const names = parent.id.properties.map(p => ({
                                local: p.value?.name || p.key.name,
                                imported: p.key.name,
                            }));
                            node.imports.set(source, names);
                        }
                    }
                }
            },

            // ES6 exports
            ExportNamedDeclaration: (path) => {
                const decl = path.node.declaration;
                if (decl?.type === 'FunctionDeclaration') {
                    node.exports.set(decl.id.name, 'function');
                    this.exportedFunctions.set(`${filePath}:${decl.id.name}`, {
                        file: filePath,
                        name: decl.id.name,
                        type: 'function',
                    });
                } else if (decl?.type === 'VariableDeclaration') {
                    decl.declarations.forEach(d => {
                        if (d.id.type === 'Identifier') {
                            node.exports.set(d.id.name, 'variable');
                        }
                    });
                }
            },

            ExportDefaultDeclaration: (path) => {
                const decl = path.node.declaration;
                if (decl.type === 'FunctionDeclaration') {
                    node.exports.set('default', 'function');
                } else if (decl.type === 'ClassDeclaration') {
                    node.exports.set('default', 'class');
                }
            },

            // module.exports
            AssignmentExpression: (path) => {
                const left = path.node.left;
                if (left.type === 'MemberExpression') {
                    const obj = left.object?.name;
                    const prop = left.property?.name;

                    if (obj === 'module' && prop === 'exports') {
                        node.exports.set('default', 'object');
                    } else if (obj === 'exports') {
                        node.exports.set(prop, 'property');
                    }
                }
            },
        });

        this.modules.set(filePath, node);
        return node;
    }

    /**
     * Resolve import path to file path
     */
    resolveImport(importPath, fromFile) {
        // Skip node_modules
        if (!importPath.startsWith('.') && !importPath.startsWith('/')) {
            return null;
        }

        const dir = path.dirname(fromFile);
        let resolved = path.resolve(dir, importPath);

        // Try various extensions
        const extensions = ['.js', '.ts', '.jsx', '.tsx', '/index.js', '/index.ts'];

        if (fs.existsSync(resolved)) {
            return resolved;
        }

        for (const ext of extensions) {
            const withExt = resolved + ext;
            if (fs.existsSync(withExt)) {
                return withExt;
            }
        }

        return null;
    }

    /**
     * Build dependency graph for entire project
     */
    async buildDependencyGraph(entryPoints = []) {
        const files = entryPoints.length > 0
            ? entryPoints
            : await this.findJSFiles(this.projectRoot);

        // Parse all files
        await Promise.all(files.map(file => this.parseModule(file)));

        // Build reverse dependencies
        this.modules.forEach((node, filePath) => {
            node.dependencies.forEach(dep => {
                const depNode = this.modules.get(dep);
                if (depNode && !depNode.dependents.includes(filePath)) {
                    depNode.dependents.push(filePath);
                }
            });
        });

        return {
            totalModules: this.modules.size,
            totalExports: this.exportedFunctions.size,
        };
    }

    /**
     * Find JS/TS files
     */
    async findJSFiles(dir, files = []) {
        try {
            const items = await fs.promises.readdir(dir);

            for (const item of items) {
                if (item === 'node_modules' || item.startsWith('.')) continue;

                const fullPath = path.join(dir, item);
                const stat = await fs.promises.stat(fullPath);

                if (stat.isDirectory()) {
                    await this.findJSFiles(fullPath, files);
                } else if (/\.(js|jsx|ts|tsx|mjs)$/.test(item)) {
                    files.push(fullPath);
                }
            }
        } catch (e) {
            // Skip inaccessible directories
        }

        return files;
    }

    /**
     * Get module information
     */
    getModuleInfo(filePath) {
        const node = this.modules.get(filePath);
        if (!node) return null;

        return {
            imports: Object.fromEntries(node.imports),
            exports: Object.fromEntries(node.exports),
            dependencies: node.dependencies,
            dependents: node.dependents,
        };
    }

    /**
     * Find modules that use a specific export
     */
    findUsages(exportName, sourceFile) {
        const usages = [];

        this.modules.forEach((node, filePath) => {
            if (filePath === sourceFile) return;

            node.imports.forEach((names, importSource) => {
                const resolvedSource = this.resolveImport(importSource, filePath);
                if (resolvedSource === sourceFile) {
                    const used = names.find(n =>
                        n.imported === exportName || n.imported === '*' || n.imported === 'default'
                    );
                    if (used) {
                        usages.push({
                            file: filePath,
                            localName: used.local,
                            importedAs: used.imported,
                        });
                    }
                }
            });
        });

        return usages;
    }

    /**
     * Analyze cross-file security issues
     */
    analyzeCrossFileSecurity() {
        const findings = [];

        // Check for dangerous exports being used across files
        this.exportedFunctions.forEach((info, key) => {
            const usages = this.findUsages(info.name, info.file);

            // Track if dangerous functions are re-exported or used widely
            if (usages.length > 3) {
                // High usage - if it has a security issue, impact is amplified
                findings.push({
                    type: 'HIGH_IMPACT_EXPORT',
                    file: info.file,
                    export: info.name,
                    usageCount: usages.length,
                    usedIn: usages.map(u => u.file),
                    message: `Function "${info.name}" is used in ${usages.length} files - security issues here have wide impact`,
                });
            }
        });

        // Check for circular dependencies (can hide issues)
        this.modules.forEach((node, filePath) => {
            node.dependencies.forEach(dep => {
                const depNode = this.modules.get(dep);
                if (depNode?.dependencies.includes(filePath)) {
                    findings.push({
                        type: 'CIRCULAR_DEPENDENCY',
                        files: [filePath, dep],
                        message: 'Circular dependency detected - can hide security issues',
                    });
                }
            });
        });

        return findings;
    }

    /**
     * Get dependents for a specific module
     */
    getDependents(filePath) {
        const node = this.modules.get(filePath);
        return node ? node.dependents : [];
    }

    /**
     * Get statistics (alias for getStats for tests)
     */
    getStatistics() {
        return this.getStats();
    }

    /**
     * Find all circular dependencies
     */
    findCircularDependencies() {
        const circular = [];
        this.modules.forEach((node, filePath) => {
            node.dependencies.forEach(dep => {
                const depNode = this.modules.get(dep);
                if (depNode?.dependencies.includes(filePath)) {
                    // Check if we already have this pair (avoid duplicates like A-B and B-A)
                    const exists = circular.some(c =>
                        (c[0] === filePath && c[1] === dep) ||
                        (c[0] === dep && c[1] === filePath)
                    );
                    if (!exists) {
                        circular.push([filePath, dep]);
                    }
                }
            });
        });
        return circular;
    }

    /**
     * Get modules with no dependents (orphans)
     */
    getOrphanedModules() {
        const orphans = [];
        this.modules.forEach((node, filePath) => {
            // Check if it has no dependents and isn't an entry point (heuristic)
            if (node.dependents.length === 0) {
                orphans.push(filePath);
            }
        });
        return orphans;
    }

    /**
     * Get highly connected modules (hubs)
     */
    getHighlyConnectedModules(threshold = 5) {
        const hubs = [];
        this.modules.forEach((node, filePath) => {
            const connections = node.dependencies.length + node.dependents.length;
            if (connections >= threshold) {
                hubs.push({
                    file: filePath,
                    connections,
                    dependencies: node.dependencies.length,
                    dependents: node.dependents.length
                });
            }
        });
        return hubs;
    }

    /**
     * Get statistics
     */
    getStats() {
        let totalImports = 0;
        let totalExports = 0;

        this.modules.forEach(node => {
            totalImports += node.imports.size;
            totalExports += node.exports.size;
        });

        return {
            totalModules: this.modules.size,
            totalImports: totalImports,
            totalExports: totalExports,
            totalDependencies: this.modules.size, // Approximation or 0 if not tracked separately
            exportedFunctions: this.exportedFunctions.size,
        };
    }
}

module.exports = {
    CrossFileAnalyzer,
    ModuleNode,
};
