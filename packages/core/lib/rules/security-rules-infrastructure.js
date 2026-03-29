/**
 * Infrastructure & Cloud Security Rules - 100+ Rules
 * Docker, Kubernetes, Terraform, AWS, and cloud-native patterns
 * @module security-rules-infrastructure
 */

const INFRASTRUCTURE_RULES = {
    // ==================== DOCKER ====================
    DOCKER: {
        root_user: { severity: 'HIGH', impact: 7, cwe: 'CWE-250', message: 'Container running as root - add USER directive' },
        latest_tag: { severity: 'MEDIUM', impact: 5, cwe: '', message: ':latest tag is unpredictable - use specific version' },
        add_vs_copy: { severity: 'LOW', impact: 2, cwe: '', message: 'Prefer COPY over ADD unless extracting tar' },
        expose_all: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-200', message: 'Exposing all ports - be explicit' },
        env_secrets: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Secret in ENV - use secret management' },
        no_healthcheck: { severity: 'LOW', impact: 3, cwe: '', message: 'Missing HEALTHCHECK instruction' },
        sudo_install: { severity: 'MEDIUM', impact: 4, cwe: 'CWE-250', message: 'sudo in RUN - not needed as root' },
        apt_cache: { severity: 'LOW', impact: 2, cwe: '', message: 'Apt cache not cleaned - increases image size' },
        curl_pipe_bash: { severity: 'HIGH', impact: 7, cwe: 'CWE-494', message: 'curl | bash is dangerous - verify downloads' },
        privileged: { severity: 'CRITICAL', impact: 9, cwe: 'CWE-250', message: '--privileged grants all capabilities' },
        no_readonly: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-732', message: 'Consider read-only root filesystem' },
    },

    // ==================== KUBERNETES ====================
    KUBERNETES: {
        privileged_pod: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-250', message: 'privileged: true - container can escape' },
        host_network: { severity: 'HIGH', impact: 8, cwe: 'CWE-420', message: 'hostNetwork shares host network namespace' },
        host_pid: { severity: 'HIGH', impact: 8, cwe: 'CWE-250', message: 'hostPID shares host process namespace' },
        host_ipc: { severity: 'HIGH', impact: 7, cwe: 'CWE-250', message: 'hostIPC shares host IPC namespace' },
        run_as_root: { severity: 'HIGH', impact: 7, cwe: 'CWE-250', message: 'runAsUser: 0 runs as root' },
        no_security_context: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-250', message: 'Missing securityContext' },
        no_resource_limits: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-400', message: 'Missing resource limits - DoS risk' },
        latest_image: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Image using :latest tag' },
        secret_env: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Secret in env - use secretKeyRef' },
        no_network_policy: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-284', message: 'No NetworkPolicy - pod can reach any pod' },
        default_sa: { severity: 'LOW', impact: 3, cwe: '', message: 'Using default ServiceAccount' },
        mount_serviceaccount: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'ServiceAccount token auto-mounted' },
        allow_privilege_escalation: { severity: 'HIGH', impact: 7, cwe: 'CWE-250', message: 'allowPrivilegeEscalation not false' },
        no_readonly_root: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-732', message: 'readOnlyRootFilesystem not true' },
        capabilities_add: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-250', message: 'Adding Linux capabilities' },
        sys_admin_cap: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-250', message: 'SYS_ADMIN capability is dangerous' },
    },

    // ==================== TERRAFORM/IaC ====================
    TERRAFORM: {
        s3_public: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-732', message: 'S3 bucket is publicly accessible' },
        s3_no_encryption: { severity: 'HIGH', impact: 7, cwe: 'CWE-311', message: 'S3 bucket without encryption' },
        s3_no_logging: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-778', message: 'S3 bucket without access logging' },
        s3_no_versioning: { severity: 'LOW', impact: 3, cwe: '', message: 'S3 bucket without versioning' },
        sg_wide_open: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-284', message: 'Security group allows 0.0.0.0/0' },
        sg_all_ports: { severity: 'HIGH', impact: 8, cwe: 'CWE-284', message: 'Security group allows all ports' },
        rds_public: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-732', message: 'RDS instance is publicly accessible' },
        rds_no_encryption: { severity: 'HIGH', impact: 7, cwe: 'CWE-311', message: 'RDS without encryption at rest' },
        rds_no_iam_auth: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'RDS without IAM authentication' },
        ec2_no_vpc: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'EC2 in classic network mode' },
        ec2_imdsv1: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'EC2 allows IMDSv1 - require IMDSv2' },
        iam_wildcard: { severity: 'HIGH', impact: 8, cwe: 'CWE-732', message: 'IAM policy with * resource' },
        iam_admin: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-732', message: 'IAM policy grants admin access' },
        kms_rotation: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'KMS key without rotation enabled' },
        cloudtrail_disabled: { severity: 'HIGH', impact: 7, cwe: 'CWE-778', message: 'CloudTrail logging not enabled' },
        hardcoded_secret: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Secret hardcoded in Terraform' },
    },

    // ==================== AWS ====================
    AWS: {
        access_key_embedded: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'AWS access key in code' },
        secret_key_embedded: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'AWS secret key in code' },
        assume_role_missing: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Using long-term credentials instead of AssumeRole' },
        mfa_delete_disabled: { severity: 'LOW', impact: 3, cwe: '', message: 'MFA Delete not enabled on S3' },
        ssl_policy_old: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-327', message: 'ELB using outdated SSL policy' },
        ebs_unencrypted: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-311', message: 'EBS volume not encrypted' },
        lambda_public: { severity: 'HIGH', impact: 7, cwe: 'CWE-284', message: 'Lambda function is publicly invokable' },
        api_gw_no_auth: { severity: 'HIGH', impact: 7, cwe: 'CWE-306', message: 'API Gateway without authentication' },
        sns_public: { severity: 'HIGH', impact: 7, cwe: 'CWE-732', message: 'SNS topic is publicly accessible' },
        sqs_public: { severity: 'HIGH', impact: 7, cwe: 'CWE-732', message: 'SQS queue is publicly accessible' },
    },

    // ==================== CI/CD ====================
    CICD: {
        secrets_in_logs: { severity: 'HIGH', impact: 8, cwe: 'CWE-532', message: 'Secrets may be logged in CI output' },
        insecure_checkout: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Repository checkout without SHA pinning' },
        script_injection: { severity: 'HIGH', impact: 8, cwe: 'CWE-94', message: 'User input in workflow script' },
        pull_request_target: { severity: 'HIGH', impact: 8, cwe: '', message: 'pull_request_target with checkout is dangerous' },
        self_hosted_runner: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Self-hosted runner may persist data' },
        write_all_permissions: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-732', message: 'Workflow has write-all permissions' },
        no_pin_versions: { severity: 'LOW', impact: 3, cwe: '', message: 'Action version not pinned to SHA' },
        artifact_upload: { severity: 'LOW', impact: 3, cwe: '', message: 'Artifact may contain sensitive data' },
    },

    // ==================== NGINX/Apache ====================
    WEBSERVER: {
        server_tokens: { severity: 'LOW', impact: 2, cwe: 'CWE-200', message: 'Server version exposed - disable server_tokens' },
        directory_listing: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-548', message: 'Directory listing enabled' },
        no_ssl: { severity: 'HIGH', impact: 7, cwe: 'CWE-319', message: 'HTTP without TLS redirect' },
        weak_ssl: { severity: 'HIGH', impact: 7, cwe: 'CWE-327', message: 'Weak SSL/TLS configuration' },
        no_hsts: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-523', message: 'HSTS header not configured' },
        csp_missing: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-1021', message: 'Content-Security-Policy not set' },
        x_frame_missing: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-1021', message: 'X-Frame-Options not set' },
        cors_wildcard: { severity: 'HIGH', impact: 7, cwe: 'CWE-346', message: 'CORS allows all origins' },
    },

    // ==================== SECRETS MANAGEMENT ====================
    SECRETS: {
        plaintext_password: { severity: 'HIGH', impact: 8, cwe: 'CWE-256', message: 'Password stored in plaintext config' },
        git_credentials: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Git credentials in repository' },
        dotenv_committed: { severity: 'HIGH', impact: 8, cwe: 'CWE-798', message: '.env file committed to repo' },
        private_key: { severity: 'CRITICAL', impact: 10, cwe: 'CWE-798', message: 'Private key in repository' },
        api_key_url: { severity: 'HIGH', impact: 8, cwe: 'CWE-598', message: 'API key in URL parameter' },
        jwt_secret_weak: { severity: 'HIGH', impact: 8, cwe: 'CWE-326', message: 'JWT secret is weak or predictable' },
    },
};

module.exports = INFRASTRUCTURE_RULES;
