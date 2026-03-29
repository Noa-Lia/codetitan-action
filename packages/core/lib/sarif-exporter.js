/**
 * SARIF Exporter
 * 
 * Exports CodeTitan findings in SARIF 2.1.0 format for GitHub Code Scanning
 * and IDE integration.
 * 
 * @module sarif-exporter
 */

const path = require('path');

/**
 * SARIF 2.1.0 schema version
 */
const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

/**
 * Map CodeTitan severity to SARIF level
 */
function mapSeverity(severity) {
    const mapping = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'none',
    };
    return mapping[severity?.toUpperCase()] || 'warning';
}

/**
 * Map severity to SARIF security-severity score
 */
function mapSecuritySeverity(severity) {
    const mapping = {
        'CRITICAL': 9.0,
        'HIGH': 7.0,
        'MEDIUM': 5.0,
        'LOW': 3.0,
        'INFO': 1.0,
    };
    return mapping[severity?.toUpperCase()] || 5.0;
}

/**
 * Extract unique rules from findings
 */
function extractRules(findings) {
    const rulesMap = new Map();

    for (const finding of findings) {
        if (!rulesMap.has(finding.ruleId)) {
            rulesMap.set(finding.ruleId, {
                id: finding.ruleId,
                name: finding.ruleId.replace(/[/-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                shortDescription: {
                    text: finding.message || finding.ruleId
                },
                fullDescription: {
                    text: finding.message || finding.ruleId
                },
                helpUri: `https://docs.codetitan.dev/rules/${finding.ruleId.replace(/\//g, '-')}`,
                properties: {
                    category: finding.category || 'security',
                    severity: finding.severity,
                    'security-severity': mapSecuritySeverity(finding.severity).toString(),
                    ...(finding.cwe && { cwe: finding.cwe })
                }
            });
        }
    }

    return Array.from(rulesMap.values());
}

/**
 * Convert findings to SARIF results
 */
function convertToResults(findings, baseDir = '') {
    return findings.map((finding, index) => {
        const result = {
            ruleId: finding.ruleId,
            ruleIndex: index,
            level: mapSeverity(finding.severity),
            message: {
                text: finding.message
            },
            locations: [{
                physicalLocation: {
                    artifactLocation: {
                        uri: finding.file ?
                            path.relative(baseDir, finding.file).replace(/\\/g, '/') :
                            'unknown',
                        uriBaseId: '%SRCROOT%'
                    },
                    region: {
                        startLine: finding.line || 1,
                        startColumn: finding.column || 1,
                        endLine: finding.endLine || finding.line || 1,
                        endColumn: finding.endColumn || 1
                    }
                }
            }]
        };

        // Add fix if available
        if (finding.fix) {
            result.fixes = [{
                description: {
                    text: `Apply suggested fix: ${finding.fix}`
                }
            }];
        }

        // Add code flow for taint tracking
        if (finding.dataFlow) {
            result.codeFlows = [{
                threadFlows: [{
                    locations: finding.dataFlow.map((step, i) => ({
                        location: {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: path.relative(baseDir, step.file).replace(/\\/g, '/')
                                },
                                region: {
                                    startLine: step.line
                                }
                            },
                            message: {
                                text: step.message || `Step ${i + 1}`
                            }
                        }
                    }))
                }]
            }];
        }

        return result;
    });
}

/**
 * Generate SARIF report
 */
function generateSARIF(findings, options = {}) {
    const {
        toolName = 'CodeTitan',
        toolVersion = '3.0.0',
        baseDir = process.cwd(),
        includeArtifacts = false
    } = options;

    const rules = extractRules(findings);
    const results = convertToResults(findings, baseDir);

    // Build rule index map for results
    const ruleIndexMap = new Map();
    rules.forEach((rule, index) => {
        ruleIndexMap.set(rule.id, index);
    });

    // Update rule indices in results
    results.forEach(result => {
        result.ruleIndex = ruleIndexMap.get(result.ruleId) || 0;
    });

    const sarif = {
        $schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: [{
            tool: {
                driver: {
                    name: toolName,
                    version: toolVersion,
                    informationUri: 'https://codetitan.dev',
                    rules: rules
                }
            },
            results: results,
            invocations: [{
                executionSuccessful: true,
                endTimeUtc: new Date().toISOString()
            }]
        }]
    };

    // Optionally include artifact list
    if (includeArtifacts) {
        const artifacts = new Set();
        findings.forEach(f => {
            if (f.file) {
                artifacts.add(path.relative(baseDir, f.file).replace(/\\/g, '/'));
            }
        });

        sarif.runs[0].artifacts = Array.from(artifacts).map(uri => ({
            location: {
                uri,
                uriBaseId: '%SRCROOT%'
            }
        }));
    }

    return sarif;
}

/**
 * SARIF Exporter class
 */
class SARIFExporter {
    constructor(options = {}) {
        this.toolName = options.toolName || 'CodeTitan';
        this.toolVersion = options.toolVersion || '3.0.0';
        this.baseDir = options.baseDir || process.cwd();
    }

    /**
     * Export findings to SARIF format
     */
    export(findings) {
        return generateSARIF(findings, {
            toolName: this.toolName,
            toolVersion: this.toolVersion,
            baseDir: this.baseDir
        });
    }

    /**
     * Export to JSON string
     */
    exportJSON(findings, pretty = true) {
        const sarif = this.export(findings);
        return pretty ? JSON.stringify(sarif, null, 2) : JSON.stringify(sarif);
    }

    /**
     * Validate SARIF structure
     */
    validate(sarif) {
        const errors = [];

        if (!sarif.$schema) {
            errors.push('Missing $schema');
        }
        if (sarif.version !== SARIF_VERSION) {
            errors.push(`Invalid version: ${sarif.version}`);
        }
        if (!sarif.runs || !Array.isArray(sarif.runs)) {
            errors.push('Missing or invalid runs array');
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }
}

module.exports = {
    SARIFExporter,
    generateSARIF,
    mapSeverity,
    mapSecuritySeverity,
    extractRules,
    SARIF_VERSION
};
