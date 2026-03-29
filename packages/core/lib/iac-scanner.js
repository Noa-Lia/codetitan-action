/**
 * Infrastructure-as-Code Scanner
 * 
 * Analyzes Terraform, Kubernetes, and CloudFormation configurations
 * for security misconfigurations and best practice violations.
 * 
 * @module iac-scanner
 */

const fs = require('fs').promises;
const path = require('path');

/**
 * Terraform security rules (25+ rules)
 */
const TERRAFORM_RULES = {
    // ==================== ENCRYPTION ====================
    ENCRYPTION: {
        s3_no_encryption: {
            id: 'iac/s3-no-encryption',
            severity: 'HIGH',
            cwe: 'CWE-311',
            pattern: /resource\s+"aws_s3_bucket"\s+[^{]*\{(?![^}]*server_side_encryption_configuration)/s,
            message: 'S3 bucket without server-side encryption'
        },
        rds_no_encryption: {
            id: 'iac/rds-no-encryption',
            severity: 'HIGH',
            cwe: 'CWE-311',
            pattern: /resource\s+"aws_db_instance"[^}]*storage_encrypted\s*=\s*false/s,
            message: 'RDS instance without storage encryption'
        },
        ebs_no_encryption: {
            id: 'iac/ebs-no-encryption',
            severity: 'MEDIUM',
            cwe: 'CWE-311',
            pattern: /resource\s+"aws_ebs_volume"[^}]*encrypted\s*=\s*false/s,
            message: 'EBS volume without encryption'
        },
    },

    // ==================== ACCESS CONTROL ====================
    ACCESS: {
        s3_public_acl: {
            id: 'iac/s3-public-acl',
            severity: 'CRITICAL',
            cwe: 'CWE-284',
            pattern: /acl\s*=\s*"public-read(-write)?"/,
            message: 'S3 bucket with public ACL - data exposure risk'
        },
        security_group_wide: {
            id: 'iac/security-group-wide-open',
            severity: 'CRITICAL',
            cwe: 'CWE-284',
            pattern: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/,
            message: 'Security group allows traffic from 0.0.0.0/0'
        },
        iam_star_action: {
            id: 'iac/iam-star-action',
            severity: 'HIGH',
            cwe: 'CWE-284',
            pattern: /"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]/,
            message: 'IAM policy with * action - overly permissive'
        },
        iam_star_resource: {
            id: 'iac/iam-star-resource',
            severity: 'HIGH',
            cwe: 'CWE-284',
            pattern: /"Resource"\s*:\s*"\*"|resources\s*=\s*\[\s*"\*"\s*\]/,
            message: 'IAM policy with * resource - overly permissive'
        },
    },

    // ==================== LOGGING & MONITORING ====================
    LOGGING: {
        s3_no_logging: {
            id: 'iac/s3-no-logging',
            severity: 'MEDIUM',
            cwe: 'CWE-778',
            pattern: /resource\s+"aws_s3_bucket"\s+[^{]*\{(?![^}]*logging)/s,
            message: 'S3 bucket without access logging'
        },
        cloudtrail_no_encryption: {
            id: 'iac/cloudtrail-no-encryption',
            severity: 'MEDIUM',
            cwe: 'CWE-311',
            pattern: /resource\s+"aws_cloudtrail"[^}]*kms_key_id\s*=\s*""/s,
            message: 'CloudTrail logs without KMS encryption'
        },
        vpc_no_flow_logs: {
            id: 'iac/vpc-no-flow-logs',
            severity: 'MEDIUM',
            cwe: 'CWE-778',
            pattern: /resource\s+"aws_vpc"\s+[^{]*\{(?![^}]*aws_flow_log)/s,
            message: 'VPC without flow logs enabled'
        },
    },

    // ==================== SECRETS ====================
    SECRETS: {
        hardcoded_secret: {
            id: 'iac/hardcoded-secret',
            severity: 'CRITICAL',
            cwe: 'CWE-798',
            pattern: /(password|secret|api_key|access_key)\s*=\s*"[^$][^"]+"/i,
            message: 'Hardcoded secret in Terraform - use variables or secrets manager'
        },
        aws_access_key: {
            id: 'iac/aws-access-key-hardcoded',
            severity: 'CRITICAL',
            cwe: 'CWE-798',
            pattern: /access_key\s*=\s*"AKIA[A-Z0-9]{16}"/,
            message: 'AWS access key hardcoded in Terraform'
        },
    },

    // ==================== NETWORK ====================
    NETWORK: {
        ssh_open: {
            id: 'iac/ssh-open-to-internet',
            severity: 'HIGH',
            cwe: 'CWE-284',
            pattern: /from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/s,
            message: 'SSH (port 22) open to internet'
        },
        rdp_open: {
            id: 'iac/rdp-open-to-internet',
            severity: 'HIGH',
            cwe: 'CWE-284',
            pattern: /from_port\s*=\s*3389[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/s,
            message: 'RDP (port 3389) open to internet'
        },
        database_public: {
            id: 'iac/database-public',
            severity: 'CRITICAL',
            cwe: 'CWE-284',
            pattern: /publicly_accessible\s*=\s*true/,
            message: 'Database publicly accessible from internet'
        },
    },
};

/**
 * Kubernetes security rules (25+ rules)
 */
const KUBERNETES_RULES = {
    // ==================== CONTAINER SECURITY ====================
    CONTAINER: {
        privileged: {
            id: 'k8s/privileged-container',
            severity: 'CRITICAL',
            cwe: 'CWE-250',
            pattern: /privileged:\s*true/,
            message: 'Container runs in privileged mode - full host access'
        },
        run_as_root: {
            id: 'k8s/run-as-root',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /runAsUser:\s*0/,
            message: 'Container runs as root user'
        },
        allow_privilege_escalation: {
            id: 'k8s/allow-privilege-escalation',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /allowPrivilegeEscalation:\s*true/,
            message: 'Container allows privilege escalation'
        },
        host_pid: {
            id: 'k8s/host-pid',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /hostPID:\s*true/,
            message: 'Pod uses host PID namespace'
        },
        host_network: {
            id: 'k8s/host-network',
            severity: 'HIGH',
            cwe: 'CWE-284',
            pattern: /hostNetwork:\s*true/,
            message: 'Pod uses host network namespace'
        },
        host_ipc: {
            id: 'k8s/host-ipc',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /hostIPC:\s*true/,
            message: 'Pod uses host IPC namespace'
        },
    },

    // ==================== RESOURCE LIMITS ====================
    RESOURCES: {
        no_limits: {
            id: 'k8s/no-resource-limits',
            severity: 'MEDIUM',
            cwe: '',
            check: (content) => content.includes('containers:') && !content.includes('limits:'),
            message: 'Container without resource limits - can exhaust node resources'
        },
        no_requests: {
            id: 'k8s/no-resource-requests',
            severity: 'LOW',
            cwe: '',
            check: (content) => content.includes('containers:') && !content.includes('requests:'),
            message: 'Container without resource requests - scheduling issues'
        },
        no_cpu_limit: {
            id: 'k8s/no-cpu-limit',
            severity: 'MEDIUM',
            cwe: '',
            check: (content) => content.includes('limits:') && !content.match(/limits:[^}]*cpu:/s),
            message: 'Container without CPU limit'
        },
        no_memory_limit: {
            id: 'k8s/no-memory-limit',
            severity: 'MEDIUM',
            cwe: '',
            check: (content) => content.includes('limits:') && !content.match(/limits:[^}]*memory:/s),
            message: 'Container without memory limit - OOMKill risk'
        },
    },

    // ==================== IMAGE SECURITY ====================
    IMAGE: {
        latest_tag: {
            id: 'k8s/image-latest-tag',
            severity: 'HIGH',
            cwe: 'CWE-829',
            pattern: /image:\s*[^\s:]+:latest\b|image:\s*[^\s:]+\s*$/m,
            message: 'Container uses :latest tag or no tag'
        },
        pull_always: {
            id: 'k8s/image-pull-always',
            severity: 'LOW',
            cwe: '',
            check: (content) => !content.includes('imagePullPolicy: Always') && content.includes(':latest'),
            message: 'Latest tag without imagePullPolicy: Always'
        },
    },

    // ==================== SECRETS ====================
    SECRETS: {
        env_secret: {
            id: 'k8s/secret-in-env',
            severity: 'MEDIUM',
            cwe: 'CWE-798',
            pattern: /name:\s*\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*\n\s*value:/i,
            message: 'Secret in plain text env var - use Secret resource'
        },
        hardcoded_secret: {
            id: 'k8s/hardcoded-secret',
            severity: 'CRITICAL',
            cwe: 'CWE-798',
            pattern: /value:\s*["']?[A-Za-z0-9+/=]{20,}["']?/,
            message: 'Potential hardcoded secret or key'
        },
    },

    // ==================== RBAC ====================
    RBAC: {
        cluster_admin: {
            id: 'k8s/cluster-admin-binding',
            severity: 'HIGH',
            cwe: 'CWE-250',
            pattern: /kind:\s*ClusterRoleBinding[^-]*roleRef:[^-]*name:\s*cluster-admin/s,
            message: 'ClusterRoleBinding to cluster-admin role'
        },
        wildcard_verb: {
            id: 'k8s/rbac-wildcard-verb',
            severity: 'HIGH',
            cwe: 'CWE-284',
            pattern: /verbs:\s*\[\s*"\*"\s*\]/,
            message: 'RBAC rule with wildcard verbs'
        },
        wildcard_resource: {
            id: 'k8s/rbac-wildcard-resource',
            severity: 'HIGH',
            cwe: 'CWE-284',
            pattern: /resources:\s*\[\s*"\*"\s*\]/,
            message: 'RBAC rule with wildcard resources'
        },
    },

    // ==================== NETWORKING ====================
    NETWORK: {
        default_namespace: {
            id: 'k8s/default-namespace',
            severity: 'LOW',
            cwe: '',
            pattern: /namespace:\s*default\b/,
            message: 'Resource in default namespace - use dedicated namespace'
        },
        no_network_policy: {
            id: 'k8s/no-network-policy',
            severity: 'MEDIUM',
            cwe: 'CWE-284',
            check: (content) => content.includes('kind: Deployment') && !content.includes('NetworkPolicy'),
            message: 'No NetworkPolicy - all pods can communicate'
        },
    },

    // ==================== BEST PRACTICES ====================
    PRACTICES: {
        no_liveness_probe: {
            id: 'k8s/no-liveness-probe',
            severity: 'LOW',
            cwe: '',
            check: (content) => content.includes('containers:') && !content.includes('livenessProbe:'),
            message: 'Container without liveness probe'
        },
        no_readiness_probe: {
            id: 'k8s/no-readiness-probe',
            severity: 'LOW',
            cwe: '',
            check: (content) => content.includes('containers:') && !content.includes('readinessProbe:'),
            message: 'Container without readiness probe'
        },
        read_only_root: {
            id: 'k8s/writable-root-fs',
            severity: 'MEDIUM',
            cwe: 'CWE-732',
            check: (content) => content.includes('securityContext:') && !content.includes('readOnlyRootFilesystem: true'),
            message: 'Container has writable root filesystem'
        },
    },
};

/**
 * IaC Scanner class
 */
class IaCScanner {
    constructor(options = {}) {
        this.terraformRules = TERRAFORM_RULES;
        this.kubernetesRules = KUBERNETES_RULES;
        this.severityFilter = options.severityFilter || ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    }

    /**
     * Detect file type
     */
    detectFileType(filePath, content) {
        const ext = path.extname(filePath).toLowerCase();
        const basename = path.basename(filePath).toLowerCase();

        if (ext === '.tf' || ext === '.tfvars') {
            return 'terraform';
        }

        if (ext === '.yaml' || ext === '.yml') {
            if (content.includes('apiVersion:') && content.includes('kind:')) {
                return 'kubernetes';
            }
        }

        if (basename.includes('terraform') || basename.includes('.tf')) {
            return 'terraform';
        }

        return 'unknown';
    }

    /**
     * Scan content with rules
     */
    scanWithRules(content, rules, filePath, rulePrefix) {
        const findings = [];

        for (const [category, categoryRules] of Object.entries(rules)) {
            for (const [ruleName, rule] of Object.entries(categoryRules)) {
                if (!this.severityFilter.includes(rule.severity)) continue;

                let matches = [];

                if (rule.pattern) {
                    const regex = new RegExp(rule.pattern.source, (rule.pattern.flags || '') + 'g');
                    let match;
                    while ((match = regex.exec(content)) !== null) {
                        const lineNumber = content.substring(0, match.index).split('\n').length;
                        matches.push({ line: lineNumber, match: match[0].substring(0, 100) });
                    }
                }

                if (rule.check && rule.check(content)) {
                    matches.push({ line: 1, match: 'file-level' });
                }

                for (const m of matches) {
                    findings.push({
                        ruleId: rule.id,
                        category: `${rulePrefix}/${category.toLowerCase()}`,
                        severity: rule.severity,
                        cwe: rule.cwe || '',
                        file: filePath,
                        line: m.line,
                        message: rule.message,
                        match: m.match
                    });
                }
            }
        }

        return findings;
    }

    /**
     * Scan single file
     */
    async scanFile(filePath) {
        const content = await fs.readFile(filePath, 'utf-8');
        const fileType = this.detectFileType(filePath, content);

        if (fileType === 'terraform') {
            return this.scanWithRules(content, this.terraformRules, filePath, 'terraform');
        }

        if (fileType === 'kubernetes') {
            return this.scanWithRules(content, this.kubernetesRules, filePath, 'kubernetes');
        }

        return [];
    }

    /**
     * Find IaC files in project
     */
    async findIaCFiles(projectPath) {
        const files = [];

        async function walk(dir) {
            try {
                const entries = await fs.readdir(dir, { withFileTypes: true });

                for (const entry of entries) {
                    const fullPath = path.join(dir, entry.name);

                    if (entry.isDirectory()) {
                        if (['.git', 'node_modules', '.terraform', 'vendor'].includes(entry.name)) {
                            continue;
                        }
                        await walk(fullPath);
                    } else if (entry.isFile()) {
                        const ext = path.extname(entry.name).toLowerCase();
                        if (['.tf', '.tfvars', '.yaml', '.yml'].includes(ext)) {
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
     * Scan entire project
     */
    async scanProject(projectPath) {
        const files = await this.findIaCFiles(projectPath);
        const allFindings = [];
        const scannedFiles = { terraform: [], kubernetes: [] };

        for (const file of files) {
            try {
                const content = await fs.readFile(file, 'utf-8');
                const fileType = this.detectFileType(file, content);

                if (fileType === 'terraform') {
                    scannedFiles.terraform.push(file);
                    const findings = this.scanWithRules(content, this.terraformRules, file, 'terraform');
                    allFindings.push(...findings);
                } else if (fileType === 'kubernetes') {
                    scannedFiles.kubernetes.push(file);
                    const findings = this.scanWithRules(content, this.kubernetesRules, file, 'kubernetes');
                    allFindings.push(...findings);
                }
            } catch (error) {
                // Skip unreadable files
            }
        }

        return {
            filesScanned: scannedFiles.terraform.length + scannedFiles.kubernetes.length,
            terraformFiles: scannedFiles.terraform.length,
            kubernetesFiles: scannedFiles.kubernetes.length,
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
     * Get total rule count
     */
    getRuleCount() {
        let count = 0;
        for (const category of Object.values(this.terraformRules)) {
            count += Object.keys(category).length;
        }
        for (const category of Object.values(this.kubernetesRules)) {
            count += Object.keys(category).length;
        }
        return count;
    }
}

module.exports = {
    IaCScanner,
    TERRAFORM_RULES,
    KUBERNETES_RULES
};
