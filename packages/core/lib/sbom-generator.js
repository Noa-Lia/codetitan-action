/**
 * SBOM Generator
 * 
 * Generates Software Bill of Materials in CycloneDX and SPDX formats.
 * Essential for supply chain security and compliance.
 * 
 * @module sbom-generator
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

/**
 * Supported SBOM formats
 */
const FORMATS = {
    CYCLONEDX_JSON: 'cyclonedx-json',
    CYCLONEDX_XML: 'cyclonedx-xml',
    SPDX_JSON: 'spdx-json',
};

/**
 * Parse package.json for npm dependencies
 */
async function parseNpmManifest(projectPath) {
    const pkgPath = path.join(projectPath, 'package.json');
    try {
        const content = await fs.readFile(pkgPath, 'utf-8');
        const pkg = JSON.parse(content);

        const components = [];

        // Production dependencies
        if (pkg.dependencies) {
            for (const [name, version] of Object.entries(pkg.dependencies)) {
                components.push({
                    type: 'library',
                    name,
                    version: version.replace(/^[\^~>=<]/, ''),
                    purl: `pkg:npm/${name}@${version.replace(/^[\^~>=<]/, '')}`,
                    scope: 'required',
                    ecosystem: 'npm'
                });
            }
        }

        // Dev dependencies
        if (pkg.devDependencies) {
            for (const [name, version] of Object.entries(pkg.devDependencies)) {
                components.push({
                    type: 'library',
                    name,
                    version: version.replace(/^[\^~>=<]/, ''),
                    purl: `pkg:npm/${name}@${version.replace(/^[\^~>=<]/, '')}`,
                    scope: 'optional',
                    ecosystem: 'npm'
                });
            }
        }

        return {
            name: pkg.name || 'unknown',
            version: pkg.version || '0.0.0',
            components
        };
    } catch (error) {
        return null;
    }
}

/**
 * Parse requirements.txt for Python dependencies
 */
async function parsePythonManifest(projectPath) {
    const reqPath = path.join(projectPath, 'requirements.txt');
    try {
        const content = await fs.readFile(reqPath, 'utf-8');
        const components = [];

        for (const line of content.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;

            const match = trimmed.match(/^([a-zA-Z0-9_-]+)([=<>!~]+)?(.+)?$/);
            if (match) {
                const name = match[1];
                const version = match[3] || 'latest';
                components.push({
                    type: 'library',
                    name,
                    version,
                    purl: `pkg:pypi/${name}@${version}`,
                    scope: 'required',
                    ecosystem: 'pypi'
                });
            }
        }

        return { name: 'python-project', version: '1.0.0', components };
    } catch (error) {
        return null;
    }
}

/**
 * Generate CycloneDX 1.5 JSON format
 */
function generateCycloneDX(projectInfo, components) {
    const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        serialNumber,
        version: 1,
        metadata: {
            timestamp: new Date().toISOString(),
            tools: [{
                vendor: 'CodeTitan',
                name: 'CodeTitan SBOM Generator',
                version: '1.0.0'
            }],
            component: {
                type: 'application',
                name: projectInfo.name,
                version: projectInfo.version
            }
        },
        components: components.map((c, i) => ({
            'bom-ref': `component-${i}`,
            type: c.type,
            name: c.name,
            version: c.version,
            purl: c.purl,
            scope: c.scope,
            properties: [
                { name: 'ecosystem', value: c.ecosystem }
            ]
        }))
    };
}

/**
 * Generate SPDX 2.3 JSON format
 */
function generateSPDX(projectInfo, components) {
    const documentNamespace = `https://codetitan.dev/spdx/${projectInfo.name}-${Date.now()}`;

    return {
        spdxVersion: 'SPDX-2.3',
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: `${projectInfo.name}-sbom`,
        documentNamespace,
        creationInfo: {
            created: new Date().toISOString(),
            creators: ['Tool: CodeTitan-1.0.0']
        },
        packages: [
            {
                SPDXID: 'SPDXRef-RootPackage',
                name: projectInfo.name,
                versionInfo: projectInfo.version,
                downloadLocation: 'NOASSERTION',
                filesAnalyzed: false
            },
            ...components.map((c, i) => ({
                SPDXID: `SPDXRef-Package-${i}`,
                name: c.name,
                versionInfo: c.version,
                downloadLocation: 'NOASSERTION',
                externalRefs: [{
                    referenceCategory: 'PACKAGE-MANAGER',
                    referenceType: 'purl',
                    referenceLocator: c.purl
                }]
            }))
        ],
        relationships: components.map((c, i) => ({
            spdxElementId: 'SPDXRef-RootPackage',
            relatedSpdxElement: `SPDXRef-Package-${i}`,
            relationshipType: c.scope === 'required' ? 'DEPENDS_ON' : 'DEV_DEPENDENCY_OF'
        }))
    };
}

/**
 * SBOM Generator class
 */
class SBOMGenerator {
    constructor(options = {}) {
        this.format = options.format || FORMATS.CYCLONEDX_JSON;
        this.includeDevDeps = options.includeDevDeps ?? true;
    }

    /**
     * Generate SBOM for a project
     * @param {string} projectPath - Project root
     * @returns {Promise<Object>} SBOM data
     */
    async generate(projectPath) {
        const allComponents = [];
        let projectInfo = { name: 'unknown', version: '0.0.0' };

        // Try npm
        const npmData = await parseNpmManifest(projectPath);
        if (npmData) {
            projectInfo = { name: npmData.name, version: npmData.version };
            allComponents.push(...npmData.components.filter(c =>
                this.includeDevDeps || c.scope === 'required'
            ));
        }

        // Try Python
        const pyData = await parsePythonManifest(projectPath);
        if (pyData) {
            if (projectInfo.name === 'unknown') {
                projectInfo = { name: pyData.name, version: pyData.version };
            }
            allComponents.push(...pyData.components);
        }

        // Generate in requested format
        let sbom;
        switch (this.format) {
            case FORMATS.SPDX_JSON:
                sbom = generateSPDX(projectInfo, allComponents);
                break;
            case FORMATS.CYCLONEDX_JSON:
            default:
                sbom = generateCycloneDX(projectInfo, allComponents);
                break;
        }

        return {
            format: this.format,
            componentCount: allComponents.length,
            sbom
        };
    }

    /**
     * Generate and save SBOM to file
     * @param {string} projectPath - Project root
     * @param {string} outputPath - Output file path
     */
    async generateAndSave(projectPath, outputPath) {
        const result = await this.generate(projectPath);
        await fs.writeFile(outputPath, JSON.stringify(result.sbom, null, 2));
        return {
            ...result,
            savedTo: outputPath
        };
    }
}

module.exports = {
    SBOMGenerator,
    FORMATS,
    parseNpmManifest,
    parsePythonManifest,
    generateCycloneDX,
    generateSPDX
};
