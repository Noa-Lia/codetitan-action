/**
 * Domain analyzers for concrete static heuristics.
 * Converts the marketing-level "Domain Titans" into deterministic detectors.
 */

const fs = require('fs');
const path = require('path');
const { analyzeTaint } = require('./taint-analyzer');
const { analyzeSupplyChain } = require('./supply-chain-analyzer');
const { analyzeRust } = require('./rust-analyzer');
const { analyzeJavaSecurity } = require('./java-security-analyzer');
const { analyzePhpSecurity } = require('./php-security-analyzer');
const { analyzeCSharpSecurity } = require('./csharp-security-analyzer');
const { EXTENDED_SECURITY_RULES } = require('./security-rules-extended');

const TEST_FILE_REGEX = /(?:[/\\](?:tests?|__tests__|__mocks__|benchmarks?|bench|perf|perfs|fixtures?|e2e|integration)(?:[/\\]|$)|(?:^|[/\\])test_[^/\\]+\.[^.]+$|[._-](?:test|spec|tests|bench|benchmark|perf)\.[^.]+$|jest\.setup\.[jt]s$|vitest\.setup\.[jt]s$)/i;
// Matches benchmark/fixture dirs that should be fully excluded from secrets scanning
const BENCH_DIR_REGEX = /[/\\](?:benchmarks?|bench)[/\\]/i;
// Engine infrastructure files and build scripts that intentionally call exec/spawn as part of their function
// Also covers: node-compat / polyfill implementation files (e.g. bun's src/js/node/), scripts/ dirs (build tooling),
// codegen/ dirs, and misctools/ (code generators / release tooling)
const INFRA_EXEC_FILE_REGEX = /(?:fixers[\\/](?:command-exec-fixer|xss-fixer|fix-verifier)|tool-bridge|test-executor|benchmark-runner|supply-chain-analyzer)\.[jt]s$|(?:^|[/\\])(?:Makefile|Gruntfile|Gulpfile|Jakefile)\.[jt]s$|[/\\](?:src[/\\]js[/\\]node|polyfills?|compat|node-compat|codegen|misctools)[/\\]|[/\\]scripts[/\\][^/\\]+\.[jt]s$/i;
// Minified/bundled dist files — findings in these are always FPs (they reflect source, not user code)
const MINIFIED_FILE_REGEX = /(?:\.min\.[jt]s$|[/\\](?:dist|build|out|\.next|client-dist|min)[/\\])/i;
const COMMENT_REGEX = /^\s*(?:\/\/|#|\/\*|\*|"""|''')/;
const DOC_FILE_REGEX = /(\.md$|\.mdx$|[/\\]examples[/\\]|[/\\]docs[/\\]|[/\\]blog[/\\]|[/\\]fixtures[/\\])/i;
const EXAMPLE_CONFIG_FILE_REGEX = /(?:\.example\.|\.sample\.|\.template\.)/i;
const MINIFIED_LINE_LENGTH = 500;
const SECRET_ENTROPY_FLOOR = 3.0;
// Matches RHS that is a dynamic value (env var, function call, template literal with ${}), not a plain hardcoded string
const DYNAMIC_RHS_REGEX = /process\.env\.|crypto\.|randomBytes|generateKey|uuid|nanoid|\$\{/i;
const SAFE_EXEC_REDIRECTION_SUFFIX_REGEX = /\s*(?:2>\/dev\/null|2>&1|\|\|\s*true)\s*/g;
const DANGEROUS_STATIC_COMMAND_REGEX = /\b(?:rm|bash|sh|sudo|curl|wget|ssh|scp|powershell|cmd(?:\.exe)?)\b/i;
const STATIC_EXEC_LITERAL_REGEX = /(?:child_process\.|(?<![.#\w]))(exec|execSync)\s*\(\s*(['"`])((?:\\.|(?!\2).)*)\2/;
const SPAWN_CALL_PREFIX_REGEX = /(?:child_process\.|(?<![.#\w]))(spawn|spawnSync)\s*\(\s*([^,]+?)\s*,\s*/;
const COMMAND_IDENTIFIER_ARG_REGEX = /(?:child_process\.|(?<![.#\w]))(exec|execSync)\s*\(\s*([A-Za-z_$][\w$]*)\b/;
const SECRET_PATTERN_DEFINITION_REGEX = /\b(?:regex|pattern)\s*:\s*\/.+\/[dgimsuy]*\s*(?:[,}]|$)/;
const SENSITIVE_LOG_IDENTIFIER_REGEX = /\b(?:password|passwd|token|secret|apiKey|api_key|authToken|authorization)\b/i;
const SENSITIVE_TEMPLATE_INTERPOLATION_REGEX = /\$\{[^}]*\b(?:password|passwd|token|secret|apiKey|api_key|authToken|authorization)\b[^}]*}/i;
const SENSITIVE_ENV_ACCESS_REGEX = /process\.env\.[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|API_KEY|APIKEY|AUTHORIZATION|AUTH_TOKEN|ACCESS_KEY)[A-Z0-9_]*/i;

// ── Named secret patterns (high precision) ─────────────────────────────────
const SECRET_PATTERNS = [
  // ── Original 15 patterns ────────────────────────────────────────────────
  { id: 'AWS_ACCESS_KEY',      severity: 'CRITICAL', impact: 10, pattern: /\bAKIA[0-9A-Z]{16}\b/,                              message: 'AWS Access Key ID detected.' },
  { id: 'AWS_SECRET_KEY',      severity: 'CRITICAL', impact: 10, pattern: /aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['"`][A-Za-z0-9/+]{40}['"`]/i, message: 'AWS Secret Access Key detected.' },
  { id: 'GITHUB_TOKEN',        severity: 'CRITICAL', impact: 10, pattern: /\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b/,     message: 'GitHub personal access or OAuth token detected.' },
  { id: 'STRIPE_KEY',          severity: 'CRITICAL', impact: 10, pattern: /\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b/,      message: 'Stripe API key detected.' },
  { id: 'OPENAI_KEY',          severity: 'CRITICAL', impact: 10, pattern: /\bsk-[A-Za-z0-9]{20,}\b/,                           message: 'OpenAI API key detected.' },
  { id: 'ANTHROPIC_KEY',       severity: 'CRITICAL', impact: 10, pattern: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/,                    message: 'Anthropic API key detected.' },
  { id: 'SLACK_TOKEN',         severity: 'CRITICAL', impact: 9,  pattern: /\bxox[bpoas]-[0-9A-Za-z\-]{10,}\b/,                 message: 'Slack API token detected.' },
  { id: 'SENDGRID_KEY',        severity: 'HIGH',     impact: 9,  pattern: /\bSG\.[A-Za-z0-9\-_]{22,}\b/,                       message: 'SendGrid API key detected.' },
  { id: 'TWILIO_KEY',          severity: 'HIGH',     impact: 9,  pattern: /\bAC[0-9a-fA-F]{32}\b/,                             message: 'Twilio Account SID detected.' },
  { id: 'GCP_SERVICE_ACCOUNT', severity: 'CRITICAL', impact: 10, pattern: /"type"\s*:\s*"service_account"/,                     message: 'GCP service account JSON detected.' },
  { id: 'PRIVATE_KEY_PEM',     severity: 'CRITICAL', impact: 10, pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,           message: 'Private key (PEM) detected.' },
  { id: 'BASIC_AUTH_URL',      severity: 'HIGH',     impact: 8,  pattern: /https?:\/\/[^\/@\s]{1,64}:[^\/@\s]{1,64}@/,         message: 'Credentials embedded in URL detected.' },
  { id: 'JWT_SECRET',          severity: 'HIGH',     impact: 9,  pattern: /jwt[_-]?secret\s*[:=]\s*['"`][^'"`]{16,}['"`]/i,    message: 'JWT secret hardcoded; move to environment variable.' },
  { id: 'DB_PASSWORD',         severity: 'HIGH',     impact: 9,  pattern: /(?:db|database|postgres|mysql|mongo)[_-]?(?:url|password|passwd|pwd)\s*[:=]\s*['"`][^'"`]{8,}['"`]/i, message: 'Database password or connection string hardcoded.' },
  { id: 'GENERIC_SECRET',      severity: 'HIGH',     impact: 10, pattern: /(api[_-]?key|secret|token|password)\s*[:=]\s*['"`][^'"`]{12,}['"`]/i,          message: 'Potential hardcoded credential; move secrets into environment variables or a vault.' },

  // ── Cloud Providers ──────────────────────────────────────────────────────
  { id: 'AWS_SESSION_TOKEN',       severity: 'CRITICAL', impact: 10, pattern: /\bAsia[A-Z0-9]{16}\b/,                                                                                                               message: 'AWS Session Token detected.' }, // gitleaks-derived
  { id: 'AZURE_STORAGE_KEY',       severity: 'CRITICAL', impact: 10, pattern: /(?:DefaultEndpointsProtocol|AccountKey)=[A-Za-z0-9+/=]{44,}/,                                                                       message: 'Azure Storage Account key or connection string detected.' }, // gitleaks-derived
  { id: 'AZURE_CLIENT_SECRET',     severity: 'CRITICAL', impact: 10, pattern: /(?:azure|az)[_-]?(?:client[_-]?)?secret\s*[:=]\s*['"`][0-9A-Za-z~._\-]{34,}['"`]/i,                                               message: 'Azure client secret hardcoded; rotate immediately.' }, // gitleaks-derived
  { id: 'DIGITALOCEAN_TOKEN',      severity: 'CRITICAL', impact: 10, pattern: /\bdop_v1_[A-Za-z0-9]{64}\b/,                                                                                                         message: 'DigitalOcean personal access token detected.' }, // gitleaks-derived
  { id: 'CLOUDFLARE_API_TOKEN',    severity: 'CRITICAL', impact: 10, pattern: /(?:cloudflare|cf)[_-]?(?:api[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9_\-]{40}['"`]/i,                                                 message: 'Cloudflare API token hardcoded; revoke and rotate.' }, // gitleaks-derived
  { id: 'CLOUDFLARE_GLOBAL_KEY',   severity: 'CRITICAL', impact: 10, pattern: /(?:cloudflare|cf)[_-]?(?:global[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"`][0-9a-f]{37}['"`]/i,                                        message: 'Cloudflare Global API key detected; use scoped API tokens instead.' }, // gitleaks-derived
  { id: 'GCP_API_KEY',             severity: 'HIGH',     impact: 9,  pattern: /\bAIza[A-Za-z0-9\-_]{35}\b/,                                                                                                         message: 'GCP/Firebase API key (AIza prefix) detected.' }, // gitleaks-derived
  { id: 'HEROKU_API_KEY',          severity: 'HIGH',     impact: 9,  pattern: /(?:heroku)[_-]?(?:api[_-]?)?key\s*[:=]\s*['"`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]/i,             message: 'Heroku API key detected.' }, // gitleaks-derived
  { id: 'LINODE_ACCESS_TOKEN',     severity: 'HIGH',     impact: 9,  pattern: /(?:linode)[_-]?(?:access[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9]{64}['"`]/i,                                                         message: 'Linode personal access token detected.' }, // gitleaks-derived

  // ── Developer Tools ──────────────────────────────────────────────────────
  { id: 'NPM_TOKEN',               severity: 'CRITICAL', impact: 10, pattern: /\bnpm_[A-Za-z0-9]{36}\b/,                                                                                                             message: 'npm publish token detected.' }, // gitleaks-derived
  { id: 'PYPI_TOKEN',              severity: 'CRITICAL', impact: 10, pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b/,                                                                                       message: 'PyPI upload token detected.' }, // gitleaks-derived
  { id: 'GITLAB_TOKEN',            severity: 'CRITICAL', impact: 10, pattern: /\bglpat-[A-Za-z0-9\-_]{20}\b/,                                                                                                       message: 'GitLab personal access token detected.' }, // gitleaks-derived
  { id: 'GITLAB_PIPELINE_TOKEN',   severity: 'HIGH',     impact: 9,  pattern: /\bglcbt-[A-Za-z0-9\-_]{20}\b|\bglptt-[A-Za-z0-9\-_]{20}\b/,                                                                       message: 'GitLab CI/CD or project trigger token detected.' }, // gitleaks-derived
  { id: 'BITBUCKET_APP_PASSWORD',  severity: 'HIGH',     impact: 9,  pattern: /bitbucket[_\-. ]?(?:app[_-]?password|token)\s*[:=]\s*['"`][A-Za-z0-9+/=]{20,}['"`]/i,                                             message: 'Bitbucket app password or access token detected.' }, // gitleaks-derived
  { id: 'DOCKER_HUB_PAT',          severity: 'HIGH',     impact: 9,  pattern: /\bdckr_pat_[A-Za-z0-9\-_]{27}\b/,                                                                                                   message: 'Docker Hub personal access token detected.' }, // gitleaks-derived
  { id: 'TERRAFORM_CLOUD_TOKEN',   severity: 'CRITICAL', impact: 10, pattern: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{67}\b/,                                                                                 message: 'Terraform Cloud / Terraform Enterprise API token detected.' }, // gitleaks-derived
  { id: 'GITHUB_FINE_GRAINED_PAT', severity: 'CRITICAL', impact: 10, pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/,                                                                                                   message: 'GitHub fine-grained personal access token detected.' }, // gitleaks-derived
  { id: 'GITHUB_APP_TOKEN',        severity: 'CRITICAL', impact: 10, pattern: /\bghu_[A-Za-z0-9]{36}\b|\bghr_[A-Za-z0-9]{36}\b/,                                                                                 message: 'GitHub App user-to-server or refresh token detected.' }, // gitleaks-derived
  { id: 'JFROG_ACCESS_TOKEN',      severity: 'HIGH',     impact: 9,  pattern: /(?:jfrog|artifactory)[_-]?(?:access[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9\-_]{64,}['"`]/i,                                        message: 'JFrog Artifactory access token detected.' }, // gitleaks-derived

  // ── Payment & Finance ────────────────────────────────────────────────────
  { id: 'SHOPIFY_ACCESS_TOKEN',    severity: 'CRITICAL', impact: 10, pattern: /\bshpat_[A-Za-z0-9]{32}\b/,                                                                                                         message: 'Shopify admin API access token detected.' }, // gitleaks-derived
  { id: 'SHOPIFY_PRIVATE_APP',     severity: 'CRITICAL', impact: 10, pattern: /\bshppa_[A-Za-z0-9]{32}\b/,                                                                                                         message: 'Shopify private app password detected.' }, // gitleaks-derived
  { id: 'SHOPIFY_SHARED_SECRET',   severity: 'HIGH',     impact: 9,  pattern: /\bshpss_[A-Za-z0-9]{32}\b/,                                                                                                         message: 'Shopify shared secret detected.' }, // gitleaks-derived
  { id: 'SQUARE_ACCESS_TOKEN',     severity: 'CRITICAL', impact: 10, pattern: /\bEAAAE[A-Za-z0-9\-_]{60,}\b/,                                                                                                     message: 'Square production access token detected.' }, // gitleaks-derived
  { id: 'SQUARE_SANDBOX_TOKEN',    severity: 'HIGH',     impact: 8,  pattern: /\bEAAAA[A-Za-z0-9\-_]{60,}\b/,                                                                                                     message: 'Square sandbox access token detected.' }, // gitleaks-derived
  { id: 'PAYPAL_BRAINTREE_TOKEN',  severity: 'CRITICAL', impact: 10, pattern: /access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}/,                                                                       message: 'PayPal / Braintree production access token detected.' }, // gitleaks-derived
  { id: 'RAZORPAY_KEY',            severity: 'HIGH',     impact: 9,  pattern: /\brzp_(?:live|test)_[A-Za-z0-9]{14,}\b/,                                                                                           message: 'Razorpay API key detected.' }, // gitleaks-derived

  // ── Communication & Messaging ────────────────────────────────────────────
  { id: 'TELEGRAM_BOT_TOKEN',      severity: 'CRITICAL', impact: 9,  pattern: /\b\d{8,10}:[A-Za-z0-9\-_]{35}\b/,                                                                                                 message: 'Telegram bot token detected.' }, // gitleaks-derived
  { id: 'DISCORD_BOT_TOKEN',       severity: 'CRITICAL', impact: 9,  pattern: /\b[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}\b/,                                                               message: 'Discord bot token detected.' }, // gitleaks-derived
  { id: 'DISCORD_WEBHOOK',         severity: 'HIGH',     impact: 8,  pattern: /discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,19}\/[A-Za-z0-9\-_]{68}/,                                                           message: 'Discord webhook URL with token detected.' }, // gitleaks-derived
  { id: 'MAILGUN_API_KEY',         severity: 'HIGH',     impact: 9,  pattern: /\bkey-[0-9a-zA-Z]{32}\b/,                                                                                                         message: 'Mailgun API key detected.' }, // gitleaks-derived
  { id: 'MAILCHIMP_API_KEY',       severity: 'HIGH',     impact: 9,  pattern: /\b[0-9a-f]{32}-us\d{1,2}\b/,                                                                                                       message: 'Mailchimp API key detected.' }, // gitleaks-derived
  { id: 'HUBSPOT_API_KEY',         severity: 'HIGH',     impact: 9,  pattern: /(?:hubspot)[_-]?(?:api[_-]?)?key\s*[:=]\s*['"`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]/i,           message: 'HubSpot API key detected.' }, // gitleaks-derived
  { id: 'ZENDESK_API_TOKEN',       severity: 'HIGH',     impact: 9,  pattern: /(?:zendesk)[_-]?(?:api[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9]{40,}['"`]/i,                                                       message: 'Zendesk API token detected.' }, // gitleaks-derived
  { id: 'INTERCOM_ACCESS_TOKEN',   severity: 'HIGH',     impact: 9,  pattern: /(?:intercom)[_-]?(?:access[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9]{60,}['"`]/i,                                                   message: 'Intercom access token detected.' }, // gitleaks-derived
  { id: 'TWILIO_AUTH_TOKEN',       severity: 'CRITICAL', impact: 10, pattern: /(?:twilio)[_-]?auth[_-]?token\s*[:=]\s*['"`][0-9a-f]{32}['"`]/i,                                                                 message: 'Twilio Auth Token detected.' }, // gitleaks-derived

  // ── Infrastructure & Secrets Management ─────────────────────────────────
  { id: 'VAULT_TOKEN',             severity: 'CRITICAL', impact: 10, pattern: /\bhvs\.[A-Za-z0-9]{24,}\b|\bs\.[A-Za-z0-9]{24,}\b/,                                                                               message: 'HashiCorp Vault token detected.' }, // gitleaks-derived
  { id: 'VAULT_BATCH_TOKEN',       severity: 'CRITICAL', impact: 10, pattern: /\bhvb\.[A-Za-z0-9]{24,}\b/,                                                                                                       message: 'HashiCorp Vault batch token detected.' }, // gitleaks-derived
  { id: 'OPENSSH_PRIVATE_KEY',     severity: 'CRITICAL', impact: 10, pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/,                                                                                             message: 'OpenSSH private key detected.' }, // gitleaks-derived
  { id: 'PGP_PRIVATE_KEY',         severity: 'CRITICAL', impact: 10, pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,                                                                                           message: 'PGP private key block detected.' }, // gitleaks-derived
  { id: 'AGE_SECRET_KEY',          severity: 'CRITICAL', impact: 10, pattern: /AGE-SECRET-KEY-1[A-Z0-9]{58}/,                                                                                                     message: 'Age encryption identity (secret key) detected.' }, // gitleaks-derived
  { id: 'KUBERNETES_SECRET',       severity: 'HIGH',     impact: 9,  pattern: /(?:kubectl|k8s|kubernetes)[_-]?(?:token|secret|password)\s*[:=]\s*['"`][^'"`]{16,}['"`]/i,                                       message: 'Kubernetes credential hardcoded; use a Secret resource or vault.' }, // gitleaks-derived
  { id: 'SSH_DSA_PRIVATE_KEY',     severity: 'CRITICAL', impact: 10, pattern: /-----BEGIN DSA PRIVATE KEY-----/,                                                                                                 message: 'DSA private key detected.' }, // gitleaks-derived

  // ── Monitoring & Observability ───────────────────────────────────────────
  { id: 'DATADOG_API_KEY',         severity: 'HIGH',     impact: 9,  pattern: /(?:datadog|dd)[_-]?api[_-]?key\s*[:=]\s*['"`][a-f0-9]{32}['"`]/i,                                                               message: 'Datadog API key detected.' }, // gitleaks-derived
  { id: 'DATADOG_APP_KEY',         severity: 'HIGH',     impact: 9,  pattern: /(?:datadog|dd)[_-]?app[_-]?key\s*[:=]\s*['"`][a-f0-9]{40}['"`]/i,                                                               message: 'Datadog application key detected.' }, // gitleaks-derived
  { id: 'NEWRELIC_LICENSE_KEY',    severity: 'HIGH',     impact: 9,  pattern: /(?:new[_-]?relic)[_-]?(?:license[_-]?)?key\s*[:=]\s*['"`][A-Za-z0-9]{40}['"`]/i,                                               message: 'New Relic license key detected.' }, // gitleaks-derived
  { id: 'NEWRELIC_INSIGHTS_KEY',   severity: 'HIGH',     impact: 8,  pattern: /(?:new[_-]?relic)[_-]?(?:insights[_-]?)?(?:insert|query)[_-]?key\s*[:=]\s*['"`][A-Za-z0-9]{32,}['"`]/i,                       message: 'New Relic Insights insert/query key detected.' }, // gitleaks-derived
  { id: 'SENTRY_AUTH_TOKEN',       severity: 'CRITICAL', impact: 10, pattern: /\bsntrys_[A-Za-z0-9]{64}\b/,                                                                                                     message: 'Sentry auth token detected.' }, // gitleaks-derived
  { id: 'SENTRY_LEGACY_TOKEN',     severity: 'HIGH',     impact: 9,  pattern: /(?:sentry)[_-]?(?:auth[_-]?)?token\s*[:=]\s*['"`][a-f0-9]{64}['"`]/i,                                                           message: 'Sentry legacy auth token detected.' }, // gitleaks-derived
  { id: 'GRAFANA_API_KEY',         severity: 'HIGH',     impact: 9,  pattern: /\beyJrIjoi[A-Za-z0-9+/=]{40,}\b/,                                                                                                 message: 'Grafana API key (base64-encoded) detected.' }, // gitleaks-derived
  { id: 'ELASTIC_API_KEY',         severity: 'CRITICAL', impact: 10, pattern: /(?:elastic(?:search)?|es)[_-]?(?:api[_-]?)?key\s*[:=]\s*['"`][A-Za-z0-9\-_=]{40,}['"`]/i,                                     message: 'Elasticsearch / Elastic Cloud API key detected.' }, // gitleaks-derived
  { id: 'SPLUNK_HEC_TOKEN',        severity: 'HIGH',     impact: 9,  pattern: /(?:splunk)[_-]?(?:hec[_-]?)?token\s*[:=]\s*['"`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]/i,       message: 'Splunk HEC token detected.' }, // gitleaks-derived

  // ── OAuth / Social ───────────────────────────────────────────────────────
  { id: 'FACEBOOK_ACCESS_TOKEN',   severity: 'HIGH',     impact: 9,  pattern: /\bEAAC[A-Za-z0-9]{80,}\b/,                                                                                                       message: 'Facebook / Meta access token detected.' }, // gitleaks-derived
  { id: 'TWITTER_BEARER_TOKEN',    severity: 'HIGH',     impact: 9,  pattern: /\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,}\b/,                                                                                     message: 'Twitter / X bearer token detected.' }, // gitleaks-derived
  { id: 'LINKEDIN_CLIENT_SECRET',  severity: 'HIGH',     impact: 8,  pattern: /(?:linkedin)[_-]?client[_-]?secret\s*[:=]\s*['"`][A-Za-z0-9]{16}['"`]/i,                                                       message: 'LinkedIn OAuth client secret detected.' }, // gitleaks-derived
  { id: 'GOOGLE_OAUTH_SECRET',     severity: 'CRITICAL', impact: 10, pattern: /GOCSPX-[A-Za-z0-9\-_]{28}/,                                                                                                     message: 'Google OAuth client secret detected.' }, // gitleaks-derived
  { id: 'SPOTIFY_CLIENT_SECRET',   severity: 'HIGH',     impact: 8,  pattern: /(?:spotify)[_-]?client[_-]?secret\s*[:=]\s*['"`][A-Za-z0-9]{32}['"`]/i,                                                         message: 'Spotify client secret detected.' }, // gitleaks-derived
];

const PLACEHOLDER_REGEX = /YOUR_|your[-_\w]*here|xxxx|xxx|<[A-Z_]+>|_PLACEHOLDER_|sk-test|pk_test|example|dummy|fake|mock|replace|change[_-]?me|todo|test-key|ct_key_|super-secret-token/i;

/**
 * Calculate Shannon entropy for a string (bits per character).
 * High entropy (>4.5) for long strings is a strong secret signal.
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check if a value looks like a high-entropy secret (not a URL, prose, or placeholder).
 */
function looksLikeSecret(val) {
  if (!val || val.length < 20) return false;
  if (PLACEHOLDER_REGEX.test(val)) return false;
  // URLs are not secrets
  if (/^https?:\/\//.test(val)) return false;
  if (looksLikeConfigUrlAssignment(val)) return false;
  if (looksLikeGeneratedCharset(val)) return false;
  if (looksLikeRouteOrRegexPattern(val)) return false;
  // HTTP ETags — bare inner value after quote-stripping: <hex>-<base64> or W/"<hex>-<base64>"
  if (/^(W\/)?"?[0-9a-f]+-[A-Za-z0-9+/]+=*"?$/.test(val)) return false;
  // Prose messages
  if ((val.match(/ /g) || []).length > 3) return false;
  if (/^[A-Za-z][A-Za-z .'":,!?-]+$/.test(val)) return false;
  return shannonEntropy(val) > 4.5;
}

function extractAssignedStringLiteral(line, minimumLength = 8) {
  const match = /[:=]\s*['"`]([^'"`]+)['"`]/.exec(line);
  if (!match || !match[1] || match[1].length < minimumLength) {
    return null;
  }

  return match[1];
}

function hasLowSecretEntropy(val) {
  return shannonEntropy(val) < SECRET_ENTROPY_FLOOR;
}

function looksLikeGeneratedCharset(val) {
  return /^[A-Za-z0-9+/=_-]+$/.test(val)
    && /ABCDEFGHIJKLMNOPQRSTUVWXYZ/.test(val)
    && /abcdefghijklmnopqrstuvwxyz/.test(val)
    && /0123456789/.test(val);
}

function looksLikeRouteOrRegexPattern(val) {
  return /[\\/]/.test(val) && /(?:\(\?:|\(\?!|\\\.|\.\*|\|)/.test(val);
}

function looksLikeConfigUrlAssignment(val) {
  return /^[A-Z0-9_]+=https?:\/\//.test(val);
}

function stripQuotedStrings(line) {
  return line.replace(/(['"`])(?:\\.|(?!\1)[\s\S])*?\1/g, '\'\'');
}

function isSensitiveConsoleLog(line) {
  if (!/console\.(?:log|info|debug)\s*\(/.test(line)) return false;
  if (SENSITIVE_TEMPLATE_INTERPOLATION_REGEX.test(line)) return true;

  const codeWithoutStrings = stripQuotedStrings(line);
  if (SENSITIVE_ENV_ACCESS_REGEX.test(codeWithoutStrings)) return true;

  return SENSITIVE_LOG_IDENTIFIER_REGEX.test(codeWithoutStrings);
}

/**
 * Detect file language from extension.
 * @param {string} filePath
 * @returns {'js'|'ts'|'python'|'go'|'other'}
 */
function detectLanguage(filePath) {
  const ext = (filePath.split('.').pop() || '').toLowerCase();
  if (['ts', 'tsx'].includes(ext)) return 'ts';
  if (['js', 'jsx', 'mjs', 'cjs'].includes(ext)) return 'js';
  if (ext === 'py') return 'python';
  if (ext === 'go') return 'go';
  if (ext === 'rs') return 'rust';
  if (ext === 'java') return 'java';
  if (ext === 'php') return 'php';
  if (ext === 'cs') return 'csharp';
  return 'other';
}

/**
 * Strip TypeScript-specific syntax to prevent false positives.
 * Removes: type annotations (: Type), type assertions (as Type),
 * interface/type declarations, generic angle brackets in non-JSX files.
 * This is best-effort, not a full parser.
 */
function stripTypeScriptSyntax(content) {
  return content
    // Remove interface and type alias declarations
    .replace(/^\s*(?:export\s+)?(?:interface|type)\s+\w[\s\S]*?(?=\n(?:export|const|let|var|function|class|import|\/\/|$))/gm, '')
    // Remove type annotations after parameter/variable names: `: SomeType`
    .replace(/:\s*[A-Z]\w*(?:<[^>]*>)?(?:\s*[|&]\s*\w+(?:<[^>]*>)?)*/g, '')
    // Remove `as Type` assertions
    .replace(/\bas\s+[A-Z]\w*(?:<[^>]*>)?/g, '')
    // Remove generic type parameters from function signatures: `function foo<T>(`
    .replace(/<[A-Z]\w*(?:\s*,\s*[A-Z]\w*)*>/g, '')
    // Remove `!` non-null assertions
    .replace(/(\w)!/g, '$1');
}

/**
 * Analyze a file for a specific domain god and return structured findings.
 * @param {string} god - Domain identifier (e.g. security-god).
 * @param {string} filePath - Absolute path to file.
 * @param {string} content - File contents.
 * @param {string} projectRoot - Root path of project being analyzed.
 */
// Hard ceiling: files larger than this are bundled/generated artifacts — skip entirely
const MAX_ANALYSIS_LINES = 5000;
const MAX_ANALYSIS_BYTES = 500_000; // 500 KB

function analyzeDomain(god, filePath, content, projectRoot) {
  const start = Date.now();

  // Guard: skip oversized files before doing any work — they are always bundled/generated
  if (content.length > MAX_ANALYSIS_BYTES) {
    return { issues: [], linesAnalyzed: 0, metadata: {}, executionTime: Date.now() - start };
  }

  const language = detectLanguage(filePath);

  // Strip TypeScript syntax before heuristic analysis to prevent false positives
  // from type annotations that look like code (e.g. `: string` matching patterns)
  const analysisContent = language === 'ts' ? stripTypeScriptSyntax(content) : content;

  const lines = analysisContent.split(/\r?\n/);

  // Guard: also enforce a line count ceiling (catches files with very long lines)
  if (lines.length > MAX_ANALYSIS_LINES) {
    return { issues: [], linesAnalyzed: 0, metadata: {}, executionTime: Date.now() - start };
  }
  const context = buildContext(lines, filePath, projectRoot, analysisContent);
  // Attach language for language-specific rules
  context.language = language;
  let issues = [];

  switch (god) {
    case 'security-god':
      issues = detectSecurityIssues(context);
      break;
    case 'performance-god':
      issues = detectPerformanceIssues(context);
      break;
    case 'test-god':
      issues = detectTestingGaps(context);
      break;
    case 'refactoring-god':
      issues = detectRefactoringHotspots(context);
      break;
    case 'documentation-god':
      issues = detectDocumentationGaps(context);
      break;
    default:
      issues = [];
  }

  return {
    issues,
    linesAnalyzed: lines.length,
    metadata: {
      nonEmptyLines: context.nonEmptyLines,
      commentLines: context.commentLines,
      exportedSymbols: context.exportedSymbols,
      hasTests: context.hasCompanionTest
    },
    executionTime: Date.now() - start
  };
}

function buildContext(lines, filePath, projectRoot, content) {
  const trimmedLines = lines.map(line => line.trim());
  const commentLines = trimmedLines.filter(line => COMMENT_REGEX.test(line)).length;
  const nonEmptyLines = trimmedLines.filter(line => line.length > 0).length;
  const exportedSymbols = detectExportedSymbols(content);
  const hasCompanionTest = lookForCompanionTests(filePath, projectRoot);

  return {
    filePath,
    projectRoot,
    lines,
    trimmedLines,
    commentLines,
    nonEmptyLines,
    exportedSymbols,
    hasCompanionTest,
    content
  };
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getCallWindow(lines, startIndex, maxLines = 6) {
  const collected = [];
  let parenBalance = 0;
  let started = false;

  for (let i = startIndex; i < Math.min(lines.length, startIndex + maxLines); i++) {
    const line = lines[i];
    collected.push(line);

    for (const char of line) {
      if (char === '(') {
        parenBalance++;
        started = true;
      } else if (char === ')') {
        parenBalance = Math.max(0, parenBalance - 1);
      }
    }

    if (started && parenBalance === 0 && /[);]/.test(line)) {
      break;
    }
  }

  return collected.join(' ');
}

function extractStaticCommandLiteral(expression) {
  const trimmed = expression.trim();
  if (trimmed.length < 2) return null;

  const quote = trimmed[0];
  if ((quote !== '\'' && quote !== '"' && quote !== '`') || trimmed[trimmed.length - 1] !== quote) {
    return null;
  }

  const rawCommand = trimmed.slice(1, -1);
  if (quote === '`' && rawCommand.includes('${')) {
    return null;
  }

  return rawCommand;
}

function isSafeStaticExecProbe(line) {
  const literalMatch = STATIC_EXEC_LITERAL_REGEX.exec(line);
  if (!literalMatch) return false;

  const [, , quote, rawCommand] = literalMatch;
  if (quote === '`' && rawCommand.includes('${')) {
    return false;
  }

  const normalizedCommand = rawCommand
    .replace(SAFE_EXEC_REDIRECTION_SUFFIX_REGEX, ' ')
    .trim();

  if (!normalizedCommand) return false;
  if (/[|&;<>$`]/.test(normalizedCommand)) return false;
  if (DANGEROUS_STATIC_COMMAND_REGEX.test(normalizedCommand)) return false;

  return true;
}

function isFunctionLikeDefinition(line) {
  const normalized = line.trim();
  // Bare function call shaped like a definition: `spawn(cmd, args) {`
  if (/^(?:async\s+)?(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\)\s*\{?$/.test(normalized)) return true;
  if (/^(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{?$/.test(normalized)) return true;
  // Named function declarations: `function spawn(`, `export function spawn(`, `export async function spawn(`
  if (/^(?:export\s+)?(?:async\s+)?function\s+(?:exec|execSync|spawn|spawnSync)\b/.test(normalized)) return true;
  // Private class methods: `async #spawn(`, `#spawn(`
  if (/^(?:async\s+)?#(?:exec|execSync|spawn|spawnSync)\s*\(/.test(normalized)) return true;
  return false;
}

function isSafeProcessExecPathAlias(lines, index, variableName) {
  const assignmentRegex = new RegExp(`\\b${escapeRegExp(variableName)}\\b\\s*=`);
  const safeAssignmentRegex = new RegExp(`^(?:(?:const|let|var)\\s+)?${escapeRegExp(variableName)}\\s*=\\s*process\\.execPath\\s*;?$`);
  const compoundAssignmentRegex = new RegExp(`\\b${escapeRegExp(variableName)}\\b\\s*[+\\-*/%]=`);
  const scanStart = Math.max(0, index - 12);
  let safeAssignments = 0;

  for (let i = scanStart; i < index; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || COMMENT_REGEX.test(trimmed)) continue;
    if (compoundAssignmentRegex.test(trimmed)) return false;
    if (!assignmentRegex.test(trimmed)) continue;
    if (!safeAssignmentRegex.test(trimmed)) return false;
    safeAssignments++;
  }

  return safeAssignments > 0;
}

function isSafeSpawnCommandExpression(lines, index, expression) {
  const trimmed = expression.trim();
  if (!trimmed) return false;

  const staticCommand = extractStaticCommandLiteral(trimmed);
  if (staticCommand !== null) {
    const normalizedCommand = staticCommand.trim();
    if (!normalizedCommand) return false;
    if (/[|&;<>$`]/.test(normalizedCommand)) return false;
    if (DANGEROUS_STATIC_COMMAND_REGEX.test(normalizedCommand)) return false;
    return true;
  }

  if (trimmed === 'process.execPath') {
    return true;
  }

  if (!/^[A-Za-z_$][\w$]*$/.test(trimmed)) {
    return false;
  }

  return isSafeProcessExecPathAlias(lines, index, trimmed);
}

function extractArgvCommandArrayExpression(expression) {
  const trimmed = expression.trim();
  const bracketMatch = /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\[\s*0\s*\]$/.exec(trimmed);
  if (bracketMatch) {
    return bracketMatch[1];
  }

  const atMatch = /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.at\(\s*0\s*\)$/.exec(trimmed);
  if (atMatch) {
    return atMatch[1];
  }

  return null;
}

function extractArrayFirstElement(expression) {
  const trimmed = expression.trim();
  const firstElementMatch = /^\[\s*([^,\]]+)/.exec(trimmed);
  return firstElementMatch ? firstElementMatch[1].trim() : null;
}

function isSafeBashScriptArgExpression(expression) {
  const trimmed = expression.trim();
  const staticCommand = extractStaticCommandLiteral(trimmed);
  if (staticCommand !== null) {
    const normalizedCommand = staticCommand.trim();
    if (!normalizedCommand || normalizedCommand.startsWith('-')) return false;
    if (/[|&;<>$`]/.test(normalizedCommand)) return false;
    return true;
  }

  return /^[A-Za-z_$][\w$]*(?:Script|Path|File)$/.test(trimmed);
}

function isSafeShellToolSpawnArgvCall(commandExpression, argsExpression) {
  const staticCommand = extractStaticCommandLiteral(commandExpression.trim());
  if (staticCommand === null) return false;

  const normalizedCommand = staticCommand.trim().toLowerCase();
  if (normalizedCommand === 'ssh') {
    return argsExpression.trim().startsWith('[');
  }

  if (normalizedCommand !== 'bash' && normalizedCommand !== 'sh') {
    return false;
  }

  const firstArg = extractArrayFirstElement(argsExpression);
  if (!firstArg || /^['"`]-/.test(firstArg)) {
    return false;
  }

  return isSafeBashScriptArgExpression(firstArg);
}

function isSafeSharedArgvDecomposition(commandExpression, argsExpression) {
  const arrayExpression = extractArgvCommandArrayExpression(commandExpression);
  if (!arrayExpression) {
    return false;
  }

  const trimmedArgs = argsExpression.trim();
  const slicePattern = new RegExp(`^${escapeRegExp(arrayExpression)}\\.slice\\(\\s*1\\s*(?:,\\s*\\d+\\s*)?\\)(?=[,)\\s]|$)`);
  return slicePattern.test(trimmedArgs);
}

function isSafeSpawnArgvCall(lines, index) {
  const callWindow = getCallWindow(lines, index);
  const callMatch = SPAWN_CALL_PREFIX_REGEX.exec(callWindow);
  if (!callMatch) return false;

  const commandExpression = callMatch[2];
  const argsExpression = callWindow.slice(callMatch.index + callMatch[0].length).trim();
  const safeSharedArgvDecomposition = isSafeSharedArgvDecomposition(commandExpression, argsExpression);

  if (/shell\s*:\s*true/.test(callWindow)) return false;

  // Static literal command + static array args: no injection vector regardless of command name
  // e.g. spawn("powershell", [...]) or spawn("git", ["push"]) — both args are compile-time constants
  const staticCmd = extractStaticCommandLiteral(commandExpression.trim());
  if (staticCmd !== null && argsExpression.trim().startsWith('[')) return true;

  // Variable command + static array args with only safe flag-style elements: no shell injection risk
  // e.g. spawn(exe, ["--version"]) — variable command but args are hardcoded flags, no user input
  if (argsExpression.trim().startsWith('[') && /^\[\s*['"`][^'"`]*['"`](?:\s*,\s*['"`][^'"`]*['"`])*\s*\]/.test(argsExpression.trim())) return true;

  // Spawn wrapper passthrough: both command and args are bare parameter-like identifiers
  // e.g. spawnSync(cmd, args, {...}) — this is a thin wrapper forwarding its own args, not user input
  const cmdTrimmed = commandExpression.trim();
  const argsTrimmed = argsExpression.trim();
  if (/^[a-z][A-Za-z]*$/.test(cmdTrimmed) && /^(?:args|argv)\b/.test(argsTrimmed)) return true;

  if (!isSafeSpawnCommandExpression(lines, index, commandExpression)
    && !isSafeShellToolSpawnArgvCall(commandExpression, argsExpression)
    && !safeSharedArgvDecomposition) return false;
  if (!safeSharedArgvDecomposition
    && !/^(?:\[|(?:args|argv)\b|[A-Za-z_$][\w$]*(?:Args|Argv|argv|args)\b)/.test(argsExpression)) return false;

  return true;
}

function parseStringLiteralAssignment(line, variableName) {
  const trimmed = line.trim();
  if (!trimmed || COMMENT_REGEX.test(trimmed)) {
    return { assigned: false, dynamic: false, value: null };
  }

  const assignmentRegex = new RegExp(`^(?:(?:const|let|var)\\s+)?${escapeRegExp(variableName)}\\s*=\\s*(.+?)\\s*;?$`);
  const match = assignmentRegex.exec(trimmed);
  if (!match) {
    return { assigned: false, dynamic: false, value: null };
  }

  const rhs = match[1].trim();
  if (rhs.length < 2) {
    return { assigned: true, dynamic: true, value: null };
  }

  const quote = rhs[0];
  if ((quote === '\'' || quote === '"') && rhs[rhs.length - 1] === quote) {
    return { assigned: true, dynamic: false, value: rhs.slice(1, -1) };
  }

  return { assigned: true, dynamic: true, value: null };
}

function isSafeLiteralAllowlistedExec(lines, index) {
  const callWindow = getCallWindow(lines, index);
  const identifierMatch = COMMAND_IDENTIFIER_ARG_REGEX.exec(callWindow);
  if (!identifierMatch) return false;

  const variableName = identifierMatch[2];
  const compoundAssignmentRegex = new RegExp(`\\b${escapeRegExp(variableName)}\\b\\s*[+\\-*/%]=`);
  const scanStart = Math.max(0, index - 12);
  let literalAssignments = 0;

  for (let i = scanStart; i < index; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || COMMENT_REGEX.test(trimmed)) continue;
    if (compoundAssignmentRegex.test(trimmed)) return false;

    const parsed = parseStringLiteralAssignment(lines[i], variableName);
    if (!parsed.assigned) continue;
    if (parsed.dynamic || !parsed.value) return false;

    const normalizedCommand = parsed.value
      .replace(SAFE_EXEC_REDIRECTION_SUFFIX_REGEX, ' ')
      .trim();

    if (!normalizedCommand) return false;
    if (/[|&;<>$`]/.test(normalizedCommand)) return false;
    if (DANGEROUS_STATIC_COMMAND_REGEX.test(normalizedCommand)) return false;

    literalAssignments++;
  }

  return literalAssignments > 0;
}

function detectSecurityIssues(context) {
  const issues = [];

  const rules = [
    {
      id: 'EVAL_USAGE',
      severity: 'HIGH',
      pattern: /\beval\s*\(/,
      message: 'Avoid dynamic evaluation; prefer safer parsing or explicit logic.',
      impact: 8,
      skipDoc: true,  // don't fire in blog/docs/examples showing bad patterns
      skipTest: true  // test files legitimately exercise dynamic evaluation paths
    },
    {
      id: 'FUNCTION_CONSTRUCTOR',
      severity: 'HIGH',
      pattern: /\bnew\s+Function\s*\(/,
      message: 'Dynamic Function constructor executes arbitrary code.',
      impact: 8,
      skipTest: true
    },
    {
      id: 'COMMAND_EXEC',
      severity: 'HIGH',
      // Require child_process. prefix OR that exec/spawn is NOT preceded by a dot or # (method/private method call)
      pattern: /(?:child_process\.|(?<![.#\w]))(exec|execSync|spawn|spawnSync)\s*\(/,
      message: 'Command execution opens the door to injection attacks. Validate or sandbox inputs.',
      impact: 9,
      skipTest: true  // test files use exec/spawn to run the CLI under test
    },
    {
      id: 'INSECURE_HTTP',
      severity: 'MEDIUM',
      // Exclude localhost/127.0.0.1/::1 — HTTP is fine for local dev/test traffic
      pattern: /(fetch|axios\.get|axios\.post|axios\.request)\s*\(\s*['"]http:\/\/(?!localhost[:/]|127\.0\.0\.1[:/]|\[::1\])/,
      message: 'HTTP request to external URL detected. Prefer HTTPS to protect data in transit.',
      impact: 5
    },
    // Note: hardcoded secrets are detected below by SECRET_PATTERNS + entropy scan
    {
      id: 'DISABLE_LINT_SECURITY',
      severity: 'MEDIUM',
      pattern: /eslint-disable-(next-line|line)\s+(no-eval|security\/\w+)/,
      message: 'Security lint rule disabled. Ensure there is a reviewed justification.',
      impact: 6
    }
  ];

  const normalizedFilePath = context.filePath.replace(/\\/g, '/');
  const isTestFile = TEST_FILE_REGEX.test(normalizedFilePath);
  const isBenchDir = BENCH_DIR_REGEX.test(normalizedFilePath);
  const isDocFile = DOC_FILE_REGEX.test(normalizedFilePath);
  const isExampleConfigFile = EXAMPLE_CONFIG_FILE_REGEX.test(normalizedFilePath);
  const isInfraExecFile = INFRA_EXEC_FILE_REGEX.test(normalizedFilePath);
  const isMinifiedFile = MINIFIED_FILE_REGEX.test(normalizedFilePath);
  const isRuleMetadataLine = (value) => /\b(?:pattern|message|description|scenario|fix|why|badCode|goodCode|code)\s*:/.test(value);

  context.lines.forEach((line, index) => {
    const normalized = line.trim();

    // Skip pure comment lines for all security rules
    if (COMMENT_REGEX.test(normalized)) return;
    if (isRuleMetadataLine(normalized)) return;
    if (line.length > MINIFIED_LINE_LENGTH) return;

    rules.forEach(rule => {
      // Use exec() to get match position
      const match = rule.pattern.exec(line);
      if (!match) return;

      // ── Skip minified/dist files — vendored, not user-owned code ───────────
      if (isMinifiedFile) return;

      // ── Per-rule test-file skip ──────────────────────────────────────────
      if (rule.skipTest && isTestFile) return;

      // ── Per-rule doc-file skip ───────────────────────────────────────────
      if (rule.skipDoc && isDocFile) return;
      if (isExampleConfigFile && !['HIGH', 'CRITICAL'].includes(rule.severity)) return;
      if (rule.id === 'COMMAND_EXEC' && (
        isFunctionLikeDefinition(line)
        || isSafeStaticExecProbe(line)
        || isSafeSpawnArgvCall(context.lines, index)
        || isSafeLiteralAllowlistedExec(context.lines, index)
        || isInfraExecFile  // engine infra files intentionally call exec
        || isMinifiedFile   // minified/dist files are not user-owned code
      )) return;
      const column = match.index;
      const matchLength = match[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: rule.severity,
        category: rule.id,
        message: rule.message,
        impact: rule.impact,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    });

    // ── Additional security heuristics ──────────────────────────────────────
    // Prototype pollution
    const protoPollutionMatch = /(?:__proto__|constructor\.prototype|Object\.prototype)\s*\[/.exec(line);
    if (protoPollutionMatch && !COMMENT_REGEX.test(normalized)) {
      issues.push(formatIssue({
        line: index + 1, column: protoPollutionMatch.index,
        endLine: index + 1, endColumn: protoPollutionMatch.index + protoPollutionMatch[0].length,
        severity: 'HIGH', category: 'PROTOTYPE_POLLUTION',
        message: 'Prototype pollution: dynamic property assignment on __proto__ or Object.prototype.',
        impact: 8, snippet: normalized, context: getContextLines(context.lines, index, 2)
      }));
    }

    // Regex injection — user data in RegExp constructor
    const regexInjMatch = /new\s+RegExp\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|process\.argv|userInput)/.exec(line);
    if (regexInjMatch && !COMMENT_REGEX.test(normalized)) {
      issues.push(formatIssue({
        line: index + 1, column: regexInjMatch.index,
        endLine: index + 1, endColumn: regexInjMatch.index + regexInjMatch[0].length,
        severity: 'HIGH', category: 'REGEX_INJECTION',
        message: 'User input passed to RegExp constructor — ReDoS or regex injection risk.',
        impact: 7, snippet: normalized, context: getContextLines(context.lines, index, 2)
      }));
    }

    // Timing attack: non-constant-time string compare for secrets
    const timingMatch = /(?:password|token|secret|apiKey|api_key|hash)\s*===?\s*(?:req\.|request\.|input\.|params\.)/.exec(line);
    if (timingMatch && !COMMENT_REGEX.test(normalized)) {
      issues.push(formatIssue({
        line: index + 1, column: timingMatch.index,
        endLine: index + 1, endColumn: timingMatch.index + timingMatch[0].length,
        severity: 'MEDIUM', category: 'TIMING_ATTACK',
        message: 'String comparison of secret/token may be vulnerable to timing attack. Use crypto.timingSafeEqual().',
        impact: 6, snippet: normalized, context: getContextLines(context.lines, index, 2)
      }));
    }

    // Unsigned JWT algorithm
    const unsignedAlgorithmPattern = new RegExp(
      ['alg.*' + 'no' + 'ne', 'algorithm.*' + 'no' + 'ne', `["']` + 'no' + 'ne' + `["']`].join('|'),
      'i'
    );
    const authTokenPattern = new RegExp(['jw' + 't', 'sign', 'verify', 'decode'].join('|'), 'i');
    const unsignedAlgorithmMatch = unsignedAlgorithmPattern.exec(line);
    if (unsignedAlgorithmMatch && authTokenPattern.test(line) && !COMMENT_REGEX.test(normalized)) {
      issues.push(formatIssue({
        line: index + 1, column: unsignedAlgorithmMatch.index,
        endLine: index + 1, endColumn: unsignedAlgorithmMatch.index + unsignedAlgorithmMatch[0].length,
        severity: 'CRITICAL', category: 'JWT_NONE_ALGORITHM',
        message: 'Unsigned JWT algorithm allows forged tokens without signature verification.',
        impact: 10, snippet: normalized, context: getContextLines(context.lines, index, 2)
      }));
    }

    // XXE: XML parser without disabling external entities
    const xxeMatch = /new\s+(?:DOMParser|XMLParser|xml2js|libxmljs|sax)\s*\(|parseFromString\s*\(/.exec(line);
    if (xxeMatch && !COMMENT_REGEX.test(normalized) && !isTestFile) {
      // Only flag if there's no entity disabling nearby
      const ctxBlock = context.lines.slice(Math.max(0, index - 5), index + 5).join('\n');
      if (!/(noent|allowExternalEntities.*false|resolveExternalEntities.*false|FEATURE_EXTERNAL_GENERAL_ENTITIES)/.test(ctxBlock)) {
        issues.push(formatIssue({
          line: index + 1, column: xxeMatch.index,
          endLine: index + 1, endColumn: xxeMatch.index + xxeMatch[0].length,
          severity: 'MEDIUM', category: 'POTENTIAL_XXE',
          message: 'XML parser usage detected — ensure external entity resolution is disabled to prevent XXE.',
          impact: 7, snippet: normalized, context: getContextLines(context.lines, index, 2)
        }));
      }
    }

    // Check for weak hash (MD5)
    const md5Pattern = /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/;
    const md5Match = md5Pattern.exec(line);
    if (md5Match) {
      const column = md5Match.index;
      const matchLength = md5Match[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: 'MEDIUM',
        category: 'WEAK_HASH',
        message: 'MD5 is considered insecure for cryptographic purposes.',
        impact: 6,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    }
  });

  // ── Named secret pattern + entropy scan ───────────────────────────────────
  if (!isDocFile) {
    // Track found categories to deduplicate (one finding per pattern per file)
    const foundSecretCategories = new Set();

    context.lines.forEach((line, index) => {
      if (COMMENT_REGEX.test(line.trim())) return;
      if (line.length > MINIFIED_LINE_LENGTH) return;
      if (DYNAMIC_RHS_REGEX.test(line)) return;
      if (SECRET_PATTERN_DEFINITION_REGEX.test(line)) return;
      // Skip error/log message lines — they mention "token"/"password" in messages, not assignments
      if (/(?:throw|Error\(|console\.|log\(|warn\(|debug\(|info\()/.test(line)) return;
      let matchedNamedSecret = false;

      for (const rule of SECRET_PATTERNS) {
        if (foundSecretCategories.has(rule.id)) continue;
        if (isMinifiedFile) continue; // dist/bundled files contain vendored code — never surface secrets from them
        if (isBenchDir) continue; // bench dirs contain bundled fixtures — always FPs for secrets
        if (isTestFile && rule.severity !== 'CRITICAL') continue; // test files only surface CRITICAL secrets
        if (isExampleConfigFile && !['HIGH', 'CRITICAL'].includes(rule.severity)) continue;
        const match = rule.pattern.exec(line);
        if (!match) continue;
        const assignedSecretValue = extractAssignedStringLiteral(line);
        if (assignedSecretValue) {
          if (PLACEHOLDER_REGEX.test(assignedSecretValue)) continue;
          if (hasLowSecretEntropy(assignedSecretValue)) continue;
        }

        // For GENERIC_SECRET, apply extra FP guards
        if (rule.id === 'GENERIC_SECRET') {
          const rhsMatch = line.match(/[:=]\s*['"`]([^'"`]{12,})['"`]/);
          if (rhsMatch) {
            const val = rhsMatch[1];
            if (PLACEHOLDER_REGEX.test(val)) continue;
            if ((val.match(/ /g) || []).length > 2) continue;
            if (/^[A-Za-z][A-Za-z .'":,!?-]+$/.test(val)) continue;
          }
        }

        foundSecretCategories.add(rule.id);
        matchedNamedSecret = true;
        const column = match.index;
        issues.push(formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + match[0].length,
          severity: rule.severity,
          category: 'HARDCODED_SECRET',
          message: rule.message,
          impact: rule.impact,
          snippet: line.trim(),
          context: getContextLines(context.lines, index, 2)
        }));
        break; // one finding per line per priority order
      }

      // Entropy scan: find quoted strings ≥ 20 chars with high entropy
      if (matchedNamedSecret || isTestFile || isBenchDir || isExampleConfigFile) return;
      const quotedStrings = line.matchAll(/['"`]([^'"`\s]{20,})['"`]/g);
      for (const qm of quotedStrings) {
        const val = qm[1];
        if (PLACEHOLDER_REGEX.test(val)) continue;
        if (/[()[\]{}:;,%/]/.test(val)) continue; // paths, URLs, module names, etc.
        if (/^[a-z]+[A-Z]+[0-9]*[$_]*$/.test(val) && val.length > 30) continue; // sequential char enumerations (abcde...XYZ0-9$_)
        if (/[^\x00-\x7F]/.test(val) && /_/.test(val)) continue; // non-ASCII underscore-delimited strings (locale word lists, e.g. month names)
        if (!looksLikeSecret(val)) continue;
        if (foundSecretCategories.has('HIGH_ENTROPY_SECRET')) continue;
        foundSecretCategories.add('HIGH_ENTROPY_SECRET');
        issues.push(formatIssue({
          line: index + 1,
          column: qm.index,
          endLine: index + 1,
          endColumn: qm.index + qm[0].length,
          severity: 'HIGH',
          category: 'HARDCODED_SECRET',
          message: `High-entropy string detected (entropy=${shannonEntropy(val).toFixed(2)}); may be a hardcoded secret.`,
          impact: 8,
          snippet: line.trim(),
          context: getContextLines(context.lines, index, 2)
        }));
      }
    });
  }

  // ── Python-specific security rules ──────────────────────────────────────
  if (context.language === 'python' && !isTestFile && !isDocFile) {
    const pyRules = [
      { pattern: /\beval\s*\(/, category: 'EVAL_USAGE', severity: 'HIGH', impact: 8, message: 'Avoid eval() in Python; use ast.literal_eval() for safe data parsing.' },
      { pattern: /\bexec\s*\(/, category: 'COMMAND_EXEC', severity: 'HIGH', impact: 9, message: 'exec() executes arbitrary code; avoid or sanitize all inputs strictly.' },
      { pattern: /\bos\.system\s*\(/, category: 'COMMAND_EXEC', severity: 'HIGH', impact: 9, message: 'os.system() is vulnerable to shell injection; use subprocess with a list of args.' },
      { pattern: /\bsubprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True/, category: 'COMMAND_EXEC', severity: 'HIGH', impact: 9, message: 'subprocess with shell=True is vulnerable to injection; use shell=False with a list.' },
      { pattern: /\bpickle\.loads?\s*\(/, category: 'INSECURE_DESERIALIZATION', severity: 'HIGH', impact: 9, message: 'pickle.load() can execute arbitrary code; never unpickle untrusted data.' },
      { pattern: /\byaml\.load\s*\((?!.*Loader)/, category: 'INSECURE_DESERIALIZATION', severity: 'HIGH', impact: 8, message: 'yaml.load() without Loader is unsafe; use yaml.safe_load() instead.' },
      { pattern: /\bcursor\.execute\s*\(\s*[f'""].*%.*['""]\s*%/, category: 'SQL_INJECTION', severity: 'HIGH', impact: 10, message: 'String-formatted SQL query; use parameterized queries (?, %s) instead.' },
      { pattern: /\bcursor\.execute\s*\(\s*f['"]/, category: 'SQL_INJECTION', severity: 'HIGH', impact: 10, message: 'f-string interpolated SQL query is vulnerable to SQL injection.' },
      { pattern: /\b__import__\s*\(/, category: 'DYNAMIC_IMPORT', severity: 'MEDIUM', impact: 7, message: '__import__() with dynamic strings can load arbitrary modules.' },
      { pattern: /\bgetattr\s*\(\s*\w+\s*,\s*(?:request|input|argv|environ)/, category: 'DYNAMIC_ATTRIBUTE', severity: 'HIGH', impact: 8, message: 'Dynamic attribute access from user input can lead to property injection.' },
    ];

    context.lines.forEach((line, index) => {
      const normalized = line.trim();
      if (!normalized || /^\s*#/.test(normalized)) return; // skip comments

      for (const rule of pyRules) {
        const match = rule.pattern.exec(line);
        if (!match) continue;
        const col = match.index;
        issues.push(formatIssue({
          line: index + 1, column: col, endLine: index + 1, endColumn: col + match[0].length,
          severity: rule.severity, category: rule.category, message: rule.message,
          impact: rule.impact, snippet: normalized, context: getContextLines(context.lines, index, 2)
        }));
        break; // one finding per line
      }
    });
  }

  // ── Go-specific security rules ────────────────────────────────────────────
  if (context.language === 'go' && !isTestFile && !isDocFile) {
    const goRules = [
      { pattern: /\bexec\.Command\s*\(\s*(?:cmd|command|input|args|userInput|req)/, category: 'COMMAND_EXEC', severity: 'HIGH', impact: 9, message: 'exec.Command with user-controlled input is vulnerable to command injection.' },
      { pattern: /\bfmt\.Sprintf\s*\(.*(?:query|sql|SELECT|INSERT|UPDATE|DELETE)/, category: 'SQL_INJECTION', severity: 'HIGH', impact: 10, message: 'fmt.Sprintf used to build SQL query; use parameterized queries (?, $1) instead.' },
      { pattern: /os\.Getenv\s*\(\s*["']\w*(?:SECRET|KEY|PASSWORD|TOKEN|API)/, category: 'HARDCODED_SECRET', severity: 'MEDIUM', impact: 6, message: 'Consider using a secrets manager instead of bare environment variable access for credentials.' },
    ];

    context.lines.forEach((line, index) => {
      const normalized = line.trim();
      if (!normalized || /^\s*\/\//.test(normalized)) return;

      for (const rule of goRules) {
        const match = rule.pattern.exec(line);
        if (!match) continue;
        const col = match.index;
        issues.push(formatIssue({
          line: index + 1, column: col, endLine: index + 1, endColumn: col + match[0].length,
          severity: rule.severity, category: rule.category, message: rule.message,
          impact: rule.impact, snippet: normalized, context: getContextLines(context.lines, index, 2)
        }));
        break;
      }
    });
  }

  // ── Rust-specific security rules ─────────────────────────────────────────
  if (context.language === 'rust' && !isTestFile && !isDocFile) {
    try {
      const rustIssues = analyzeRust(context.content, context.filePath);
      for (const r of rustIssues) {
        issues.push(formatIssue({
          line: r.line, column: r.column || 0,
          endLine: r.endLine || r.line, endColumn: r.endColumn || 0,
          severity: r.severity, category: r.category, message: r.message,
          impact: r.impact, snippet: r.snippet,
          context: getContextLines(context.lines, r.line - 1, 2)
        }));
      }
    } catch (_) {}
  }

  // ── Java / PHP / C# security rules ───────────────────────────────────────
  if (!isTestFile && !isDocFile) {
    const langAnalyzers = [
      { lang: 'java', fn: analyzeJavaSecurity },
      { lang: 'php', fn: analyzePhpSecurity },
      { lang: 'csharp', fn: analyzeCSharpSecurity },
    ];
    for (const { lang, fn } of langAnalyzers) {
      if (context.language !== lang) continue;
      try {
        const langIssues = fn(context.content, context.filePath);
        for (const r of langIssues) {
          issues.push(formatIssue({
            line: r.line, column: r.column || 0,
            endLine: r.endLine || r.line, endColumn: r.endColumn || 0,
            severity: r.severity, category: r.category, message: r.message,
            impact: r.impact, snippet: r.snippet,
            context: getContextLines(context.lines, r.line - 1, 2)
          }));
        }
      } catch (_) {}
    }
  }

  // ── AI-generated code risk rules ─────────────────────────────────────────
  // Targets patterns that LLMs produce frequently but that are insecure or broken.
  if (!isTestFile && !isDocFile && !isInfraExecFile && !isMinifiedFile) {
    const aiRules = [
      {
        id: 'AI_CODE_RISK_EMPTY_CATCH',
        severity: 'MEDIUM',
        pattern: /catch\s*\([^)]*\)\s*\{\s*\}/,
        message: 'Empty catch block swallows errors — a common LLM pattern. Add error handling or logging.',
        impact: 6
      },
      {
        id: 'AI_CODE_RISK_PERMISSIVE_CORS',
        severity: 'HIGH',
        pattern: /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['"`]\*['"`]/,
        message: 'Wildcard CORS origin (*) allows any domain to access this resource. Restrict to trusted origins.',
        impact: 8
      },
      {
        id: 'AI_CODE_RISK_DEFAULT_CREDENTIALS',
        severity: 'CRITICAL',
        pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"`](?:admin|password|123456|test|root|letmein|welcome|changeme|default)['"`]/i,
        message: 'Default or example credential detected — frequently inserted by AI code generators.',
        impact: 10
      },
      {
        id: 'AI_CODE_RISK_CONSOLE_SENSITIVE',
        severity: 'HIGH',
        pattern: /console\.(?:log|info|debug)\s*\(/,
        message: 'Sensitive data logged to console — AI models often insert debug logging around credentials.',
        impact: 8
      },
      {
        id: 'AI_CODE_RISK_TODO_SECURITY',
        severity: 'MEDIUM',
        pattern: /\/\/\s*(?:TODO|FIXME|HACK)\s*[:\-]?\s*.*(?:auth|security|validat|sanitiz|permiss|encrypt|secret|token)/i,
        message: 'Security-critical TODO/FIXME — AI-generated placeholders in auth/security paths must be resolved.',
        impact: 7
      },
      {
        id: 'AI_CODE_RISK_HARDCODED_IV',
        severity: 'HIGH',
        pattern: /(?:iv|nonce|salt)\s*[:=]\s*(?:Buffer\.from\s*\(\s*['"`][A-Fa-f0-9]{16,}['"`]|['"`][A-Fa-f0-9]{16,}['"`])/,
        message: 'Hardcoded IV/nonce/salt for cryptographic operation. Always generate these randomly.',
        impact: 9
      },
      {
        id: 'AI_CODE_RISK_SKIP_SSL_VERIFY',
        severity: 'HIGH',
        pattern: /(?:rejectUnauthorized|verify)\s*[:=]\s*false/,
        message: 'SSL/TLS verification disabled — dangerous in production, often added by AI for "quick testing".',
        impact: 9
      }
    ];

    let inBlockComment = false;
    context.lines.forEach((line, index) => {
      const normalized = line.trim();
      if (!normalized) return;
      // Track multi-line block comment state (handles JSDoc /** ... */ blocks)
      if (inBlockComment) {
        if (normalized.includes('*/')) inBlockComment = false;
        return;
      }
      if (normalized.startsWith('/*')) {
        if (!normalized.includes('*/')) inBlockComment = true;
        return;
      }
      if (COMMENT_REGEX.test(normalized)) return;

      for (const rule of aiRules) {
        if (isTestFile) continue; // AI pattern rules fire heavily in test files — almost always FPs
        if (isMinifiedFile) continue; // dist/bundled files contain vendored code — not user-authored
        const match = rule.pattern.exec(line);
        if (!match) continue;
        if (rule.id === 'AI_CODE_RISK_CONSOLE_SENSITIVE' && !isSensitiveConsoleLog(line)) continue;
        const col = match.index;
        issues.push(formatIssue({
          line: index + 1, column: col, endLine: index + 1, endColumn: col + match[0].length,
          severity: rule.severity, category: rule.id, message: rule.message,
          impact: rule.impact, snippet: normalized, context: getContextLines(context.lines, index, 2)
        }));
        break; // one finding per line
      }
    });
  }

  // ── Taint analysis (source → sink data flow) ─────────────────────────────
  if (!isTestFile && !isDocFile && !isInfraExecFile) {
    try {
      const taintIssues = analyzeTaint(context.filePath, context.content);
      for (const t of taintIssues) {
        issues.push(formatIssue({
          line: t.line,
          column: t.column || 0,
          endLine: t.line,
          endColumn: (t.column || 0) + (t.snippet?.length || 0),
          severity: t.severity,
          category: t.category,
          message: t.message,
          impact: t.impact,
          snippet: t.snippet,
          context: getContextLines(context.lines, t.line - 1, 2)
        }));
      }
    } catch (_) {
      // Taint analysis is best-effort — never crash the main scan
    }
  }

  // ── Python taint analysis ──────────────────────────────────────────────────
  if (!isTestFile && !isDocFile && context.filePath.endsWith('.py')) {
    try {
      const pythonTaintIssues = analyzePythonTaint(context.content, context.filePath);
      for (const t of pythonTaintIssues) {
        issues.push(formatIssue({
          line: t.line, column: t.column || 0,
          endLine: t.line, endColumn: (t.column || 0) + (t.snippet?.length || 0),
          severity: t.severity, category: t.category, message: t.message,
          impact: t.impact, snippet: t.snippet,
          context: getContextLines(context.lines, t.line - 1, 2)
        }));
      }
    } catch (_) {
      // Best-effort
    }
  }

  // ── Supply chain / malicious pattern analysis ─────────────────────────────
  // Detects obfuscation, exfiltration channels, Trojan Source, dynamic require
  try {
    const scIssues = analyzeSupplyChain(context.filePath, context.content);
    for (const sc of scIssues) {
      issues.push(formatIssue({
        line: sc.line,
        column: sc.column || 0,
        endLine: sc.endLine || sc.line,
        endColumn: sc.endColumn || (sc.column || 0) + (sc.snippet?.length || 0),
        severity: sc.severity,
        category: sc.category,
        message: sc.message,
        impact: sc.impact,
        snippet: sc.snippet,
        context: getContextLines(context.lines, sc.line - 1, 2)
      }));
    }
  } catch (_) {
    // Supply chain analysis is best-effort — never crash the main scan
  }

  // ── Extended security rules (120 additional patterns) ────────────────────
  context.lines.forEach((line, index) => {
    const normalized = line.trim();
    if (!normalized || COMMENT_REGEX.test(normalized)) return;

    EXTENDED_SECURITY_RULES.forEach(rule => {
      if (rule.skipTest && isTestFile) return;
      if (rule.skipDoc && isDocFile) return;
      if (isInfraExecFile) return; // engine infra files intentionally contain dangerous patterns
      if (rule.filePathPattern && !rule.filePathPattern.test(context.filePath)) return;
      if (isRuleMetadataLine(normalized)) return;

      // fileGuard: a regex that, if it matches the whole file, suppresses the rule.
      // Use this to avoid false positives when a mitigation exists elsewhere in the file.
      if (rule.fileGuard && rule.fileGuard.test(context.content)) return;

      const match = rule.pattern.exec(line);
      if (!match) return;

      const column = match.index;
      const matchLength = match[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: rule.severity,
        category: rule.id,
        message: rule.message,
        impact: rule.impact,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    });
  });

  return issues;
}

/**
 * Lightweight Python taint analysis for Flask/FastAPI/Django.
 * Tracks user-controlled data from HTTP sources to dangerous sinks.
 */
function analyzePythonTaint(content, filePath) {
  const issues = [];
  const lines = content.split(/\r?\n/);

  const PY_SOURCES = [
    /\brequest\.(args|form|json|data|values|files|cookies|headers|environ)\b/,
    /\brequest\.get\s*\(/,
    /os\.environ\.get\s*\(/,
    /os\.getenv\s*\(/,
    /\binput\s*\(/,
    /sys\.argv\b/,
  ];

  const PY_SINKS = [
    { pattern: /\bexecute\s*\(/, category: 'TAINT_SQL_INJECTION', severity: 'HIGH', impact: 9, message: 'Python: tainted user input in SQL execute() — use parameterized queries.' },
    { pattern: /\bexecutemany\s*\(/, category: 'TAINT_SQL_INJECTION', severity: 'HIGH', impact: 9, message: 'Python: tainted user input in SQL executemany() — use parameterized queries.' },
    { pattern: /\bos\.system\s*\(|\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(/, category: 'TAINT_COMMAND_INJECTION', severity: 'HIGH', impact: 10, message: 'Python: tainted user input in subprocess/os.system — command injection risk.' },
    { pattern: /\beval\s*\(/, category: 'TAINT_EVAL', severity: 'HIGH', impact: 10, message: 'Python: tainted user input in eval().' },
    { pattern: /\bexec\s*\(/, category: 'TAINT_EVAL', severity: 'HIGH', impact: 9, message: 'Python: tainted user input in exec().' },
    { pattern: /\bopen\s*\(/, category: 'TAINT_PATH_TRAVERSAL', severity: 'HIGH', impact: 9, message: 'Python: tainted user input in open() — path traversal risk.' },
    { pattern: /\brender_template_string\s*\(/, category: 'TAINT_TEMPLATE_INJECTION', severity: 'CRITICAL', impact: 10, message: 'Python: tainted user input in render_template_string — SSTI vulnerability.' },
    { pattern: /\bpickle\.loads?\s*\(/, category: 'TAINT_INSECURE_DESERIALIZATION', severity: 'CRITICAL', impact: 10, message: 'Python: tainted user input in pickle.load — arbitrary code execution.' },
  ];

  const PY_SANITIZERS = [
    /\bint\s*\(/, /\bfloat\s*\(/, /\bstr\s*\(/, /\babs\s*\(/,
    /\.strip\s*\(/, /\bescape\s*\(/, /\bquote\s*\(/, /\bmarkup\s*\(/i,
    /\bvalidat/i, /\bsanit/i, /\bwhitelist\b/i, /\ballowlist\b/i,
    /,\s*\(.*\)\s*$/,  // tuple param style: cursor.execute("... %s", (val,))
    /\bsafe_load\b/,
  ];

  const taintedVars = new Set();
  const taintedLineMap = new Map();

  // Pass 1: find tainted sources
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    for (const src of PY_SOURCES) {
      if (!src.test(line)) continue;
      const m = line.match(/\b(\w+)\s*=\s*.+/);
      if (m && m[1] !== 'if' && m[1] !== 'while') {
        taintedVars.add(m[1]);
        taintedLineMap.set(m[1], idx + 1);
      }
    }
  });

  if (taintedVars.size === 0) return issues;

  // Pass 2: alias propagation (3 rounds)
  for (let r = 0; r < 3; r++) {
    lines.forEach((line, idx) => {
      const m = line.match(/\b(\w+)\s*=\s*(\w+)\s*(?:$|[+\-*\/\s\[{])/);
      if (m && taintedVars.has(m[2]) && !taintedVars.has(m[1])) {
        taintedVars.add(m[1]);
        taintedLineMap.set(m[1], idx + 1);
      }
      // f-string: x = f"...{tainted}..."
      const fstr = line.match(/\b(\w+)\s*=\s*f["'][^"']*\{(\w+)\}/);
      if (fstr && taintedVars.has(fstr[2]) && !taintedVars.has(fstr[1])) {
        taintedVars.add(fstr[1]);
        taintedLineMap.set(fstr[1], idx + 1);
      }
    });
  }

  // Pass 3: sink scan
  const seen = new Set();
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || seen.has(idx)) return;
    for (const sink of PY_SINKS) {
      if (!sink.pattern.test(line)) continue;
      const foundVar = [...taintedVars].find(v => new RegExp(`\\b${v}\\b`).test(line));
      if (!foundVar) continue;
      if (PY_SANITIZERS.some(s => s.test(line))) continue;
      const ctx = lines.slice(Math.max(0, idx - 3), idx).join('\n');
      if (PY_SANITIZERS.some(s => s.test(ctx)) && new RegExp(`\\b${foundVar}\\b`).test(ctx)) continue;
      issues.push({
        line: idx + 1, column: 0,
        severity: sink.severity, category: sink.category,
        message: `${sink.message} Variable \`${foundVar}\` from user input (line ${taintedLineMap.get(foundVar) || '?'}).`,
        impact: sink.impact, snippet: trimmed,
      });
      seen.add(idx);
      break;
    }
  });

  return issues;
}

function detectPerformanceIssues(context) {
  const issues = [];
  const nestedLoopRegex = /for\s*\(.*\)\s*{[\s\S]{0,300}?for\s*\(/;
  const nestedWhileRegex = /while\s*\(.*\)\s*{[\s\S]{0,300}?while\s*\(/;

  context.lines.forEach((line, index) => {
    const normalized = line.trim();

    // Sync I/O detection
    const syncIoPattern = /fs\.(readFileSync|writeFileSync|appendFileSync)/;
    const syncIoMatch = syncIoPattern.exec(line);
    if (syncIoMatch) {
      const column = syncIoMatch.index;
      const matchLength = syncIoMatch[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: 'MEDIUM',
        category: 'SYNC_IO',
        message: 'Synchronous fs operation blocks the event loop. Consider async alternatives.',
        impact: 4,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    }

    // Sync file parse detection
    const syncFileParsePattern = /JSON\.parse\s*\(\s*fs\.readFileSync/;
    const syncFileParseMatch = syncFileParsePattern.exec(line);
    if (syncFileParseMatch) {
      const column = syncFileParseMatch.index;
      const matchLength = syncFileParseMatch[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: 'MEDIUM',
        category: 'SYNC_FILE_PARSE',
        message: 'Parsing large files synchronously can block the event loop.',
        impact: 7,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    }

    // Await in loop detection
    const awaitInLoopPattern1 = /await\s+.*for\s*\(/;
    const awaitInLoopPattern2 = /for\s*\(.*\)\s*{[^}]*await/;
    const awaitInLoopMatch = awaitInLoopPattern1.exec(line) || awaitInLoopPattern2.exec(line);
    if (awaitInLoopMatch) {
      const column = awaitInLoopMatch.index;
      const matchLength = awaitInLoopMatch[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: 'MEDIUM',
        category: 'AWAIT_IN_LOOP',
        message: 'Await inside loops runs sequentially; batch with Promise.all if possible.',
        impact: 5,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    }

    // Async timeout detection
    const asyncTimeoutPattern = /setTimeout\s*\(\s*async\s/;
    const asyncTimeoutMatch = asyncTimeoutPattern.exec(line);
    if (asyncTimeoutMatch && /await/.test(line)) {
      const column = asyncTimeoutMatch.index;
      const matchLength = asyncTimeoutMatch[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: 'LOW',
        category: 'ASYNC_TIMEOUT',
        message: 'Async logic inside setTimeout can hide rejections; ensure errors surface.',
        impact: 2,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    }
  });

  const content = context.content;
  const nestedLoopMatch = nestedLoopRegex.exec(content) || nestedWhileRegex.exec(content);
  if (nestedLoopMatch) {
    const firstLine = getLineNumber(context.content, nestedLoopMatch.index);
    const lineContent = context.lines[firstLine - 1] || '';
    const column = lineContent.indexOf(nestedLoopMatch[0].substring(0, 10)); // Find approximate column

    issues.push(formatIssue({
      line: firstLine,
      column: column >= 0 ? column : 0,
      endLine: firstLine,
      endColumn: column >= 0 ? column + 10 : 10,
      severity: 'MEDIUM',
      category: 'NESTED_LOOPS',
      message: 'Nested loops detected; confirm complexity is acceptable for expected data size.',
      impact: 6,
      snippet: context.lines[firstLine - 1]?.trim() || '',
      context: getContextLines(context.lines, firstLine - 1, 2)
    }));
  }

  return issues;
}

function detectTestingGaps(context) {
  const issues = [];
  const isTestFile = TEST_FILE_REGEX.test(context.filePath);

  context.lines.forEach((line, index) => {
    const normalized = line.trim();

    // Focused test detection (.only)
    const focusedTestPattern = /\.only\s*\(/;
    const focusedTestMatch = focusedTestPattern.exec(line);
    if (isTestFile && focusedTestMatch) {
      const column = focusedTestMatch.index;
      const matchLength = focusedTestMatch[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: 'HIGH',
        category: 'FOCUSED_TEST',
        message: 'Remove .only() to avoid skipping other tests.',
        impact: 7,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    }

    // TODO test detection
    const todoTestPattern = /TODO:?[\s-]*add tests/i;
    const todoTestMatch = todoTestPattern.exec(line);
    if (!isTestFile && todoTestMatch) {
      const column = todoTestMatch.index;
      const matchLength = todoTestMatch[0].length;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: column + matchLength,
        severity: 'MEDIUM',
        category: 'TODO_TESTS',
        message: 'TODO indicates missing test coverage.',
        impact: 4,
        snippet: normalized,
        context: getContextLines(context.lines, index, 2)
      }));
    }
  });

  if (!isTestFile && context.exportedSymbols.length > 0 && context.lines.length > 40 && !context.hasCompanionTest) {
    issues.push(formatIssue({
      line: 1,
      column: 0,
      endLine: 1,
      endColumn: 0,
      severity: 'MEDIUM',
      category: 'MISSING_TESTS',
      message: `No companion test file found for exported module "${context.exportedSymbols[0]}".`,
      impact: 5,
      snippet: path.basename(context.filePath),
      context: getContextLines(context.lines, 0, 2)
    }));
  }

  return issues;
}

function detectRefactoringHotspots(context) {
  const issues = [];
  const { lines } = context;

  if (lines.length > 400) {
    issues.push(formatIssue({
      line: 1,
      column: 0,
      endLine: 1,
      endColumn: 0,
      severity: 'MEDIUM',
      category: 'FILE_TOO_LONG',
      message: `File is ${lines.length} lines. Consider splitting responsibilities.`,
      impact: 6,
      snippet: path.basename(context.filePath),
      context: getContextLines(lines, 0, 2)
    }));
  }

  let longLineCount = 0;
  lines.forEach((line, index) => {
    if (line.length > 140 && longLineCount < 3) {
      // Find where the line exceeds 140 chars
      const column = 140;
      longLineCount++;

      issues.push(formatIssue({
        line: index + 1,
        column,
        endLine: index + 1,
        endColumn: line.length,
        severity: 'LOW',
        category: 'LONG_LINE',
        message: 'Line exceeds 140 characters; break into smaller pieces for readability.',
        impact: 2,
        snippet: line.trim(),
        context: getContextLines(lines, index, 2)
      }));
    }
  });

  detectLongFunctions(lines).forEach(fnIssue => issues.push(fnIssue));

  return issues;
}

function detectDocumentationGaps(context) {
  const issues = [];
  const { commentLines, nonEmptyLines, exportedSymbols } = context;
  const commentRatio = nonEmptyLines === 0 ? 0 : commentLines / nonEmptyLines;

  if (exportedSymbols.length > 0 && commentRatio < 0.04 && nonEmptyLines > 50) {
    issues.push(formatIssue({
      line: 1,
      column: 0,
      endLine: 1,
      endColumn: 0,
      severity: 'MEDIUM',
      category: 'POOR_DOCUMENTATION',
      message: 'Exported module lacks inline documentation. Add JSDoc or doc comments for maintainability.',
      impact: 4,
      snippet: exportedSymbols[0],
      context: getContextLines(context.lines, 0, 2)
    }));
  }

  if (/README|docs|\.md$/i.test(context.filePath)) {
    return issues;
  }

  const firstCodeLine = context.trimmedLines.findIndex(line => line && !COMMENT_REGEX.test(line));
  if (firstCodeLine > 0 && !COMMENT_REGEX.test(context.trimmedLines[firstCodeLine - 1] || '')) {
    const actualLine = context.lines[firstCodeLine] || '';

    issues.push(formatIssue({
      line: firstCodeLine + 1,
      column: 0,
      endLine: firstCodeLine + 1,
      endColumn: actualLine.length,
      severity: 'LOW',
      category: 'MISSING_HEADER',
      message: 'Consider adding a module header comment to describe purpose and usage.',
      impact: 2,
      snippet: context.trimmedLines[firstCodeLine] || '',
      context: getContextLines(context.lines, firstCodeLine, 2)
    }));
  }

  return issues;
}

function detectLongFunctions(lines) {
  const issues = [];
  let depth = 0;
  let tracking = null;

  lines.forEach((line, index) => {
    const openBraces = (line.match(/{/g) || []).length;
    const closeBraces = (line.match(/}/g) || []).length;

    const functionPattern = /(function\s+\w+\s*\(|=\s*\(.*\)\s*=>\s*{)/;
    const functionMatch = functionPattern.exec(line);

    if (!tracking && functionMatch) {
      tracking = {
        startLine: index + 1,
        depthAtStart: depth + openBraces - closeBraces,
        column: functionMatch.index,
        matchLength: functionMatch[0].length
      };
    }

    depth += openBraces - closeBraces;

    if (tracking && depth <= tracking.depthAtStart) {
      const length = index + 1 - tracking.startLine;
      if (length > 80) {
        issues.push(formatIssue({
          line: tracking.startLine,
          column: tracking.column,
          endLine: tracking.startLine,
          endColumn: tracking.column + tracking.matchLength,
          severity: 'MEDIUM',
          category: 'LONG_FUNCTION',
          message: `Function spans ${length} lines. Break it into focused helpers.`,
          impact: 4,
          snippet: lines[tracking.startLine - 1]?.trim() || '',
          context: getContextLines(lines, tracking.startLine - 1, 2)
        }));
      }
      tracking = null;
    }
  });

  return issues;
}

function detectExportedSymbols(content) {
  const exports = [];
  const defaultExportMatch = content.match(/export\s+default\s+(\w+)/);
  if (defaultExportMatch) {
    exports.push(defaultExportMatch[1]);
  }

  const namedExportRegex = /export\s+(?:const|function|class)\s+(\w+)/g;
  let match;
  while ((match = namedExportRegex.exec(content))) {
    exports.push(match[1]);
  }

  const moduleExportsMatch = content.match(/module\.exports\s*=\s*(\w+)/);
  if (moduleExportsMatch) {
    exports.push(moduleExportsMatch[1]);
  }

  return [...new Set(exports)];
}

function lookForCompanionTests(filePath, projectRoot) {
  try {
    if (!projectRoot) return false;
    if (TEST_FILE_REGEX.test(filePath)) return true;

    const { dir, name, ext } = path.parse(filePath);
    const candidateNames = [
      `${name}.test${ext}`,
      `${name}.spec${ext}`,
      `${name}.tests${ext}`,
      `${name}.test${ext.replace('.', '')}`,
      `${name}.spec${ext.replace('.', '')}`
    ];

    for (const candidate of candidateNames) {
      const sameDir = path.join(dir, candidate);
      if (fs.existsSync(sameDir)) {
        return true;
      }

      const testsDir = path.join(dir, '__tests__', candidate);
      if (fs.existsSync(testsDir)) {
        return true;
      }
    }
  } catch (_) {
    return false;
  }

  return false;
}

function formatIssue({ line, column, endLine, endColumn, severity, category, message, impact, snippet, context }) {
  return {
    line,
    column: column !== undefined ? column : 0,
    endLine: endLine || line,
    endColumn: endColumn !== undefined ? endColumn : (column !== undefined ? column + (snippet?.length || 0) : 0),
    severity,
    category,
    message,
    impact,
    snippet,
    context: context || []
  };
}

/**
 * Get context lines around a specific line (N lines before and after)
 */
function getContextLines(lines, lineIndex, contextSize = 2) {
  const start = Math.max(0, lineIndex - contextSize);
  const end = Math.min(lines.length, lineIndex + contextSize + 1);
  return lines.slice(start, end);
}

function getLineNumber(content, index) {
  const prefix = content.slice(0, index);
  return prefix.split(/\r?\n/).length;
}

module.exports = {
  analyzeDomain,
  detectSecurityIssues,
  detectPerformanceIssues,
  detectQualityIssues: detectRefactoringHotspots,
  detectTestingIssues: detectTestingGaps,
  detectDocumentationIssues: detectDocumentationGaps,
};
