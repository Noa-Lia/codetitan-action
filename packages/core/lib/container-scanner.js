/**
 * Container Scanner
 * 
 * Analyzes Dockerfiles and container configurations for security issues.
 * Detects misconfigurations, vulnerabilities, and best practice violations.
 * 
 * @module container-scanner
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * Container security rules (30+ rules)
 */
const CONTAINER_RULES = {
    // ==================== USER & PERMISSIONS ====================
    USER: {
        root_user: {
            id: 'container/root-user',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /^USER\s+(root|0)\s*$/mi,
            message: 'Container runs as root user - use non-root user for security',
            fix: 'USER nonroot'
        },
        no_user: {
            id: 'container/no-user',
            severity: 'MEDIUM',
            cwe: 'CWE-250',
            check: (content) => !content.match(/^USER\s+/mi),
            message: 'No USER instruction - container will run as root by default',
            fix: 'Add USER instruction with non-root user'
        },
        sudo_installed: {
            id: 'container/sudo-installed',
            severity: 'MEDIUM',
            cwe: 'CWE-250',
            pattern: /apt-get\s+install.*\bsudo\b|apk\s+add.*\bsudo\b|yum\s+install.*\bsudo\b/i,
            message: 'sudo installed in container - unnecessary privilege escalation vector'
        },
    },

    // ==================== IMAGE SECURITY ====================
    IMAGE: {
        latest_tag: {
            id: 'container/latest-tag',
            severity: 'HIGH',
            cwe: 'CWE-829',
            pattern: /^FROM\s+\S+:latest\s*$/mi,
            message: 'Using :latest tag - pin to specific version for reproducibility'
        },
        no_tag: {
            id: 'container/no-tag',
            severity: 'HIGH',
            cwe: 'CWE-829',
            pattern: /^FROM\s+([a-z0-9/_-]+)\s*$/mi,
            message: 'No tag specified - will use :latest implicitly'
        },
        untrusted_base: {
            id: 'container/untrusted-base',
            severity: 'MEDIUM',
            cwe: 'CWE-829',
            pattern: /^FROM\s+(?!(?:alpine|ubuntu|debian|node|python|golang|rust|nginx|redis|postgres|mysql|mongo|mcr\.microsoft|gcr\.io|ghcr\.io|docker\.io\/library))/mi,
            message: 'Using potentially untrusted base image - prefer official images'
        },
        privileged_base: {
            id: 'container/privileged-base',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /^FROM.*\/(root|admin|privileged)/mi,
            message: 'Base image name suggests privileged access'
        },
    },

    // ==================== SECRETS & CREDENTIALS ====================
    SECRETS: {
        env_password: {
            id: 'container/env-password',
            severity: 'CRITICAL',
            cwe: 'CWE-798',
            pattern: /^ENV\s+\w*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY)\w*\s*=\s*\S+/mi,
            message: 'Hardcoded secret in ENV instruction - use runtime secrets'
        },
        arg_secret: {
            id: 'container/arg-secret',
            severity: 'HIGH',
            cwe: 'CWE-798',
            pattern: /^ARG\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*=/mi,
            message: 'Secret passed as build argument - visible in image history'
        },
        copy_private_key: {
            id: 'container/copy-private-key',
            severity: 'CRITICAL',
            cwe: 'CWE-798',
            pattern: /^(COPY|ADD)\s+.*\.(pem|key|p12|pfx|jks)/mi,
            message: 'Private key copied into image - use secrets management'
        },
        copy_env_file: {
            id: 'container/copy-env-file',
            severity: 'HIGH',
            cwe: 'CWE-798',
            pattern: /^(COPY|ADD)\s+\.env/mi,
            message: '.env file copied into image - secrets may be exposed'
        },
        curl_auth: {
            id: 'container/curl-with-auth',
            severity: 'HIGH',
            cwe: 'CWE-798',
            pattern: /curl.*(-u|--user)\s+\S+:\S+/i,
            message: 'Credentials in curl command - visible in image layers'
        },
    },

    // ==================== NETWORK & PORTS ====================
    NETWORK: {
        expose_22: {
            id: 'container/expose-ssh',
            severity: 'MEDIUM',
            cwe: 'CWE-284',
            pattern: /^EXPOSE\s+22\b/mi,
            message: 'SSH port exposed - containers should not run SSH daemon'
        },
        expose_many: {
            id: 'container/expose-many-ports',
            severity: 'LOW',
            cwe: 'CWE-284',
            check: (content) => (content.match(/^EXPOSE\s+/gmi) || []).length > 5,
            message: 'Many ports exposed - review if all are necessary'
        },
        privileged_port: {
            id: 'container/privileged-port',
            severity: 'LOW',
            cwe: 'CWE-284',
            pattern: /^EXPOSE\s+([1-9]|[1-9][0-9]|[1-9][0-9]{2}|10[0-1][0-9]|102[0-3])\b/mi,
            message: 'Privileged port (<1024) exposed - requires root'
        },
    },

    // ==================== PACKAGE MANAGEMENT ====================
    PACKAGES: {
        apt_no_version: {
            id: 'container/apt-no-version',
            severity: 'LOW',
            cwe: 'CWE-829',
            pattern: /apt-get\s+install(?!.*=)/i,
            message: 'Package installed without version pinning'
        },
        no_cache_cleanup: {
            id: 'container/no-cache-cleanup',
            severity: 'LOW',
            cwe: '',
            check: (content) => content.includes('apt-get install') && !content.includes('rm -rf /var/lib/apt'),
            message: 'apt cache not cleaned - increases image size'
        },
        pip_no_version: {
            id: 'container/pip-no-version',
            severity: 'LOW',
            cwe: 'CWE-829',
            pattern: /pip\s+install(?!.*==)/i,
            message: 'Python package installed without version pinning'
        },
        npm_install_dev: {
            id: 'container/npm-dev-deps',
            severity: 'LOW',
            cwe: '',
            check: (content) => content.includes('npm install') && !content.includes('--production') && !content.includes('--omit=dev'),
            message: 'npm install may include dev dependencies - use --omit=dev'
        },
    },

    // ==================== FILE OPERATIONS ====================
    FILES: {
        add_remote: {
            id: 'container/add-remote',
            severity: 'HIGH',
            cwe: 'CWE-829',
            pattern: /^ADD\s+https?:\/\//mi,
            message: 'ADD with remote URL - use COPY + curl for verification'
        },
        add_tar: {
            id: 'container/add-tar',
            severity: 'MEDIUM',
            cwe: 'CWE-829',
            pattern: /^ADD\s+\S+\.(tar|tar\.gz|tgz|tar\.bz2)\s/mi,
            message: 'ADD auto-extracts archives - be cautious of archive contents'
        },
        copy_all: {
            id: 'container/copy-all',
            severity: 'MEDIUM',
            cwe: 'CWE-200',
            pattern: /^COPY\s+\.\s+/mi,
            message: 'COPY . copies everything - use .dockerignore or specific paths'
        },
        chmod_777: {
            id: 'container/chmod-777',
            severity: 'HIGH',
            cwe: 'CWE-732',
            pattern: /chmod\s+777/i,
            message: 'chmod 777 gives everyone full access - use least privilege'
        },
        workdir_not_absolute: {
            id: 'container/workdir-relative',
            severity: 'LOW',
            cwe: '',
            pattern: /^WORKDIR\s+(?!\/)/mi,
            message: 'WORKDIR should use absolute path'
        },
    },

    // ==================== BUILD PRACTICES ====================
    BUILD: {
        multiple_cmd: {
            id: 'container/multiple-cmd',
            severity: 'LOW',
            cwe: '',
            check: (content) => (content.match(/^CMD\s+/gmi) || []).length > 1,
            message: 'Multiple CMD instructions - only last one takes effect'
        },
        multiple_entrypoint: {
            id: 'container/multiple-entrypoint',
            severity: 'LOW',
            cwe: '',
            check: (content) => (content.match(/^ENTRYPOINT\s+/gmi) || []).length > 1,
            message: 'Multiple ENTRYPOINT instructions - only last one takes effect'
        },
        shell_form: {
            id: 'container/shell-form-cmd',
            severity: 'LOW',
            cwe: '',
            pattern: /^(CMD|ENTRYPOINT)\s+(?!\[)/mi,
            message: 'CMD/ENTRYPOINT in shell form - prefer exec form ["cmd", "arg"]'
        },
        no_healthcheck: {
            id: 'container/no-healthcheck',
            severity: 'LOW',
            cwe: '',
            check: (content) => !content.match(/^HEALTHCHECK\s+/mi),
            message: 'No HEALTHCHECK defined - add for container orchestration'
        },
        healthcheck_none: {
            id: 'container/healthcheck-disabled',
            severity: 'MEDIUM',
            cwe: '',
            pattern: /^HEALTHCHECK\s+NONE/mi,
            message: 'HEALTHCHECK disabled - container health unknown'
        },
    },

    // ==================== SECURITY HARDENING ====================
    HARDENING: {
        setuid_binary: {
            id: 'container/setuid-binary',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /chmod\s+[u\+]*s|chmod\s+[0-7]?[4-7][0-7]{2}/i,
            message: 'setuid/setgid bit set - potential privilege escalation'
        },
        curl_bash: {
            id: 'container/curl-bash',
            severity: 'HIGH',
            cwe: 'CWE-829',
            pattern: /curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh/i,
            message: 'Piping curl/wget to shell - verify script integrity first'
        },
        apk_no_cache: {
            id: 'container/apk-no-cache',
            severity: 'LOW',
            cwe: '',
            check: (content) => content.includes('apk add') && !content.includes('--no-cache'),
            message: 'apk add without --no-cache - increases image size'
        },
    },
};

/**
 * Parse Dockerfile and extract instructions
 */
function parseDockerfile(content) {
    const instructions = [];
    const lines = content.split('\n');
    let currentInstruction = null;
    let startLine = 0;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();

        // Skip comments and empty lines
        if (!trimmed || trimmed.startsWith('#')) continue;

        // Check for line continuation
        if (currentInstruction && lines[i - 1]?.trimEnd().endsWith('\\')) {
            currentInstruction.content += '\n' + line;
            currentInstruction.endLine = i + 1;
            continue;
        }

        // Parse instruction
        const match = trimmed.match(/^([A-Z]+)\s+(.*)/);
        if (match) {
            if (currentInstruction) {
                instructions.push(currentInstruction);
            }
            currentInstruction = {
                instruction: match[1],
                args: match[2],
                content: line,
                startLine: i + 1,
                endLine: i + 1
            };
        }
    }

    if (currentInstruction) {
        instructions.push(currentInstruction);
    }

    return instructions;
}

/**
 * Container Scanner class
 */
class ContainerScanner {
    constructor(options = {}) {
        this.rules = CONTAINER_RULES;
        this.severityFilter = options.severityFilter || ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    }

    /**
     * Scan Dockerfile content
     */
    scanContent(content, filePath = 'Dockerfile') {
        const findings = [];
        const instructions = parseDockerfile(content);

        // Check each rule category
        for (const [category, rules] of Object.entries(this.rules)) {
            for (const [ruleName, rule] of Object.entries(rules)) {
                if (!this.severityFilter.includes(rule.severity)) continue;

                let matches = [];

                if (rule.pattern) {
                    const regex = new RegExp(rule.pattern.source, rule.pattern.flags + 'g');
                    let match;
                    while ((match = regex.exec(content)) !== null) {
                        // Find line number
                        const lineNumber = content.substring(0, match.index).split('\n').length;
                        matches.push({ line: lineNumber, match: match[0] });
                    }
                }

                if (rule.check && rule.check(content)) {
                    matches.push({ line: 1, match: 'file' });
                }

                for (const m of matches) {
                    findings.push({
                        ruleId: rule.id,
                        category: `container/${category.toLowerCase()}`,
                        severity: rule.severity,
                        cwe: rule.cwe || '',
                        file: filePath,
                        line: m.line,
                        message: rule.message,
                        fix: rule.fix,
                        match: m.match.substring(0, 100)
                    });
                }
            }
        }

        return findings;
    }

    /**
     * Scan Dockerfile at path
     */
    async scanFile(filePath) {
        const content = await fs.readFile(filePath, 'utf-8');
        return this.scanContent(content, filePath);
    }

    /**
     * Find and scan all Dockerfiles in project
     */
    async scanProject(projectPath) {
        const dockerfiles = [];
        const allFindings = [];

        // Common Dockerfile locations
        const candidates = [
            'Dockerfile',
            'dockerfile',
            'Dockerfile.dev',
            'Dockerfile.prod',
            'Dockerfile.test',
            'docker/Dockerfile',
            '.docker/Dockerfile',
        ];

        for (const candidate of candidates) {
            const fullPath = path.join(projectPath, candidate);
            try {
                await fs.access(fullPath);
                dockerfiles.push(fullPath);
            } catch {
                // File doesn't exist
            }
        }

        // Scan each Dockerfile
        for (const dockerfile of dockerfiles) {
            const findings = await this.scanFile(dockerfile);
            allFindings.push(...findings);
        }

        return {
            dockerfilesScanned: dockerfiles.length,
            dockerfiles,
            findings: allFindings,
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
     * Get rule count
     */
    getRuleCount() {
        let count = 0;
        for (const category of Object.values(this.rules)) {
            count += Object.keys(category).length;
        }
        return count;
    }
}

module.exports = {
    ContainerScanner,
    CONTAINER_RULES,
    parseDockerfile
};
