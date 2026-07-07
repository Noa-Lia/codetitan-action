/**
 * Domain analyzers for concrete static heuristics.
 * Converts the marketing-level "Domain Titans" into deterministic detectors.
 */

const fs = require("fs");
const path = require("path");
const { analyzeTaint } = require("./taint-analyzer");
const { analyzeSupplyChain } = require("./supply-chain-analyzer");
const { analyzeRust } = require("./rust-analyzer");
const { analyzeJavaSecurity } = require("./java-security-analyzer");
const { analyzePhpSecurity } = require("./php-security-analyzer");
const { analyzeCSharpSecurity } = require("./csharp-security-analyzer");
const { EXTENDED_SECURITY_RULES } = require("./security-rules-extended");

const TEST_FILE_REGEX =
  /(?:[/\\](?:tests?|__tests__|__mocks__|benchmarks?|bench|perf|perfs|fixtures?|e2e|integration)(?:[/\\]|$)|(?:^|[/\\])test_[^/\\]+\.[^.]+$|[._-](?:test|spec|tests|bench|benchmark|perf|poku)\.[^.]+$|jest\.setup\.[jt]s$|vitest\.setup\.[jt]s$)/i;
// Matches benchmark/fixture dirs that should be fully excluded from secrets scanning
const BENCH_DIR_REGEX = /[/\\](?:benchmarks?|bench)[/\\]/i;
// Engine infrastructure files and build scripts that intentionally call exec/spawn as part of their function
// Also covers: node-compat / polyfill implementation files (e.g. bun's src/js/node/), scripts/ dirs (build tooling),
// codegen/ dirs, and misctools/ (code generators / release tooling)
const INFRA_EXEC_FILE_REGEX =
  /(?:fixers[\\/](?:command-exec-fixer|xss-fixer|fix-verifier)|tool-bridge|test-executor|benchmark-runner|supply-chain-analyzer|action-kit|actions-shim)\.[jt]s$|(?:^|[/\\])(?:Makefile|Gruntfile|Gulpfile|Jakefile)\.[jt]s$|[/\\](?:src[/\\]js[/\\]node|polyfills?|compat|node-compat|codegen|misctools)[/\\]|[/\\]scripts[/\\][^/\\]+\.[jt]s$|[/\\][^/\\]+-cli[/\\]src[/\\]|[/\\](?:e2e|integration)-(?:test-runner|tests?)[/\\]|[/\\][^/\\]+-test-runner[/\\]/i;
// Minified/bundled dist files — findings in these are always FPs (they reflect source, not user code)
const MINIFIED_FILE_REGEX =
  /(?:\.min\.[jt]s$|[/\\](?:dist|build|out|\.next|client-dist|min)[/\\])/i;
const COMMENT_REGEX = /^\s*(?:\/\/|#|\/\*|\*|"""|''')/;
const DOC_FILE_REGEX =
  /(\.md$|\.mdx$|[/\\]examples[/\\]|[/\\]docs[/\\]|[/\\]blog[/\\]|[/\\]fixtures[/\\])/i;
const EXAMPLE_CONFIG_FILE_REGEX = /(?:\.example\.|\.sample\.|\.template\.)/i;
// i18n/locale/translation files are pure text data, not code. Any pattern-match
// rule firing on the content (entropy scan, default-credential string match,
// etc.) is structurally an FP. Closes Plane FPs P2 + P3 (~27 firings) from
// Phase 1 Week 2 measurement (`docs/plans/2026-05-10-engine-fp-baseline-week2.md`).
const LOCALE_FILE_REGEX = /[/\\](?:locales?|i18n|translations?|messages)[/\\]/i;
// Vendored PWA bundles under `public/` — generated service workers (Workbox,
// firebase-messaging-sw), content-hashed runtime bundles, precache manifests.
// Pattern-match rules firing on the content are structurally FPs (vendored
// library code, not user-authored). Closes Plane FP P6 (Workbox postMessage)
// from Phase 1 Week 2; likely affects more across customer-shape repos.
const VENDORED_BUNDLE_REGEX =
  /(?:^|[/\\])public[/\\](?:workbox|sw|service-worker|precache-manifest|firebase-messaging-sw)[A-Za-z0-9_.-]*\.[mc]?js$|(?:^|[/\\])public[/\\][A-Za-z0-9_-]+-[a-f0-9]{8,}\.[mc]?js$/i;
// Seed scripts, fixture files, sample-data generators. Credentials and high-
// entropy IDs in these files are by-design (test data, demo content, DB
// bootstrap), not real secrets. Closes Cal.com FP CC1 (scripts/seed.ts), and
// Documenso FPs D1 (packages/prisma/seed/users.ts) + D3 (generate-sample-data.ts)
// from Phase 1 Week 2. Filename-form is strict (must start with seed/fixture/
// sample-data, or end with .fixture(s).ts / -fixture(s).ts / generate-seed.ts)
// to avoid suppressing real source like `src/utils/seeded-random.ts`.
const SEED_FIXTURE_FILE_REGEX =
  /(?:^|[/\\])(?:seed[s]?|fixtures?|sample[-_]data)(?:[/\\])|(?:^|[/\\])(?:seed[s]?|fixtures?|sample[-_]data)\.[mc]?[jt]sx?$|(?:^|[/\\])generate-(?:seed[s]?|sample[-_]data|fixtures?)[A-Za-z0-9_.-]*\.[mc]?[jt]sx?$|\.fixtures?\.[mc]?[jt]sx?$|-fixtures?\.[mc]?[jt]sx?$/i;
const MINIFIED_LINE_LENGTH = 500;
const SECRET_ENTROPY_FLOOR = 3.0;
// Matches RHS that is a dynamic value (env var, function call, template literal with ${}), not a plain hardcoded string
const DYNAMIC_RHS_REGEX =
  /process\.env\.|crypto\.|randomBytes|generateKey|uuid|nanoid|\$\{/i;
const SAFE_EXEC_REDIRECTION_SUFFIX_REGEX =
  /\s*(?:2>\/dev\/null|2>&1|\|\|\s*true)\s*/g;
const DANGEROUS_STATIC_COMMAND_REGEX =
  /\b(?:rm|bash|sh|sudo|curl|wget|ssh|scp|powershell|cmd(?:\.exe)?)\b/i;
const STATIC_EXEC_LITERAL_REGEX =
  /(?:child_process\.|(?<![.#\w]))(exec|execSync)\s*\(\s*(['"`])((?:\\.|(?!\2).)*)\2/;
const SPAWN_CALL_PREFIX_REGEX =
  /(?:child_process\.|(?<![.#\w]))(spawn|spawnSync)\s*\(\s*([^,]+?)\s*,\s*/;
const COMMAND_IDENTIFIER_ARG_REGEX =
  /(?:child_process\.|(?<![.#\w]))(exec|execSync)\s*\(\s*([A-Za-z_$][\w$]*)\b/;
const SECRET_PATTERN_DEFINITION_REGEX =
  /\b(?:regex|pattern)\s*:\s*\/.+\/[dgimsuy]*\s*(?:[,}]|$)/;
const SENSITIVE_LOG_IDENTIFIER_REGEX =
  /\b(?:password|passwd|token|secret|apiKey|api_key|authToken|authorization)\b/i;
const SENSITIVE_TEMPLATE_INTERPOLATION_REGEX =
  /\$\{[^}]*\b(?:password|passwd|token|secret|apiKey|api_key|authToken|authorization)\b[^}]*}/i;
const SENSITIVE_ENV_ACCESS_REGEX =
  /process\.env\.[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|API_KEY|APIKEY|AUTHORIZATION|AUTH_TOKEN|ACCESS_KEY)[A-Z0-9_]*/i;
// T2 (cold-audit sweep 2026-06-10): build-metadata env vars read as sensitive
// only because a tool name embeds a keyword — secretlint's
// `process.env.SECRETLINT_VERSION` contains "SECRET" but is a version string.
// A _VERSION/_BUILD/_COMMIT/_SHA/_REVISION suffix marks metadata, not
// credential material.
const ENV_METADATA_SUFFIX_REGEX = /_(?:VERSION|BUILD|COMMIT|SHA|REVISION)$/i;
// T2 (NodeSecure/cli loggers): `i18n.getTokenSync(token, ...)` logs a UI
// translation string — the `token` identifier is a translation KEY, not an
// auth credential. Scoped to the `i18n.`-qualified call shape so a real
// `auth.getToken()` result being logged still fires.
const I18N_GET_TOKEN_CALL_REGEX = /\bi18n\s*\.\s*getTokens?(?:Sync)?\s*\(/;
const SENSITIVE_LOG_IDENTIFIER_EXCEPT_TOKEN_REGEX =
  /\b(?:password|passwd|secret|apiKey|api_key|authToken|authorization)\b/i;

// Matches log-adjacent outer calls that wrap a redaction helper whose last
// argument is a redaction-flag string literal. The helper redacts before the
// log call ever sees the secret value:
//   console.log(wrapParam('password', options.password, true, 'secret'))
//     → prints '***** [password]' — no secret in output
// The outer-call anchor (console.* / logger.* / bare log() etc.) is mandatory
// so we don't suppress unrelated calls like `Schema.field({ type: 'secret' })`.
const REDACTED_LOG_CALL_REGEX =
  /\b(?:console\.(?:log|info|debug|warn|error)|logger(?:\.(?:log|info|debug|warn|error|trace))?|log|info|debug|warn)\s*\(\s*[A-Za-z_$][\w$]*\s*\([^)]*,\s*['"`](?:secret|redacted|mask(?:ed)?|hidden|private|censored|sensitive|obfuscated)['"`]\s*\)/;

// ── Named secret patterns (high precision) ─────────────────────────────────
const SECRET_PATTERNS = [
  // ── Original 15 patterns ────────────────────────────────────────────────
  {
    id: "AWS_ACCESS_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    message: "AWS Access Key ID detected.",
  },
  {
    id: "AWS_SECRET_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['"`][A-Za-z0-9/+]{40}['"`]/i,
    message: "AWS Secret Access Key detected.",
  },
  {
    id: "GITHUB_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b/,
    message: "GitHub personal access or OAuth token detected.",
  },
  {
    id: "STRIPE_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b/,
    message: "Stripe API key detected.",
  },
  {
    id: "OPENAI_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bsk-[A-Za-z0-9]{20,}\b/,
    message: "OpenAI API key detected.",
  },
  {
    id: "ANTHROPIC_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/,
    message: "Anthropic API key detected.",
  },
  {
    id: "SLACK_TOKEN",
    severity: "CRITICAL",
    impact: 9,
    pattern: /\bxox[bpoas]-[0-9A-Za-z\-]{10,}\b/,
    message: "Slack API token detected.",
  },
  {
    id: "SENDGRID_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /\bSG\.[A-Za-z0-9\-_]{22,}\b/,
    message: "SendGrid API key detected.",
  },
  {
    id: "TWILIO_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /\bAC[0-9a-fA-F]{32}\b/,
    message: "Twilio Account SID detected.",
  },
  {
    id: "GCP_SERVICE_ACCOUNT",
    severity: "CRITICAL",
    impact: 10,
    pattern: /"type"\s*:\s*"service_account"/,
    message: "GCP service account JSON detected.",
  },
  {
    id: "PRIVATE_KEY_PEM",
    severity: "CRITICAL",
    impact: 10,
    pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,
    message: "Private key (PEM) detected.",
  },
  {
    id: "BASIC_AUTH_URL",
    severity: "HIGH",
    impact: 8,
    pattern: /https?:\/\/[^\/@\s]{1,64}:[^\/@\s]{1,64}@/,
    message: "Credentials embedded in URL detected.",
  },
  {
    id: "JWT_SECRET",
    severity: "HIGH",
    impact: 9,
    pattern: /jwt[_-]?secret\s*[:=]\s*['"`][^'"`]{16,}['"`]/i,
    message: "JWT secret hardcoded; move to environment variable.",
  },
  {
    id: "DB_PASSWORD",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:db|database|postgres|mysql|mongo)[_-]?(?:url|password|passwd|pwd)\s*[:=]\s*['"`][^'"`]{8,}['"`]/i,
    message: "Database password or connection string hardcoded.",
  },
  {
    id: "GENERIC_SECRET",
    severity: "HIGH",
    impact: 10,
    pattern:
      /(api[_-]?key|secret|token|password)\s*[:=]\s*['"`][^'"`]{12,}['"`]/i,
    message:
      "Potential hardcoded credential; move secrets into environment variables or a vault.",
  },

  // ── Cloud Providers ──────────────────────────────────────────────────────
  {
    id: "AWS_SESSION_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bAsia[A-Z0-9]{16}\b/,
    message: "AWS Session Token detected.",
  }, // gitleaks-derived
  {
    id: "AZURE_STORAGE_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /(?:DefaultEndpointsProtocol|AccountKey)=[A-Za-z0-9+/=]{44,}/,
    message: "Azure Storage Account key or connection string detected.",
  }, // gitleaks-derived
  {
    id: "AZURE_CLIENT_SECRET",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /(?:azure|az)[_-]?(?:client[_-]?)?secret\s*[:=]\s*['"`][0-9A-Za-z~._\-]{34,}['"`]/i,
    message: "Azure client secret hardcoded; rotate immediately.",
  }, // gitleaks-derived
  {
    id: "DIGITALOCEAN_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bdop_v1_[A-Za-z0-9]{64}\b/,
    message: "DigitalOcean personal access token detected.",
  }, // gitleaks-derived
  {
    id: "CLOUDFLARE_API_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /(?:cloudflare|cf)[_-]?(?:api[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9_\-]{40}['"`]/i,
    message: "Cloudflare API token hardcoded; revoke and rotate.",
  }, // gitleaks-derived
  {
    id: "CLOUDFLARE_GLOBAL_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /(?:cloudflare|cf)[_-]?(?:global[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"`][0-9a-f]{37}['"`]/i,
    message:
      "Cloudflare Global API key detected; use scoped API tokens instead.",
  }, // gitleaks-derived
  {
    id: "GCP_API_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /\bAIza[A-Za-z0-9\-_]{35}\b/,
    message: "GCP/Firebase API key (AIza prefix) detected.",
  }, // gitleaks-derived
  {
    id: "HEROKU_API_KEY",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:heroku)[_-]?(?:api[_-]?)?key\s*[:=]\s*['"`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]/i,
    message: "Heroku API key detected.",
  }, // gitleaks-derived
  {
    id: "LINODE_ACCESS_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:linode)[_-]?(?:access[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9]{64}['"`]/i,
    message: "Linode personal access token detected.",
  }, // gitleaks-derived

  // ── Developer Tools ──────────────────────────────────────────────────────
  {
    id: "NPM_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
    message: "npm publish token detected.",
  }, // gitleaks-derived
  {
    id: "PYPI_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b/,
    message: "PyPI upload token detected.",
  }, // gitleaks-derived
  {
    id: "GITLAB_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bglpat-[A-Za-z0-9\-_]{20}\b/,
    message: "GitLab personal access token detected.",
  }, // gitleaks-derived
  {
    id: "GITLAB_PIPELINE_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern: /\bglcbt-[A-Za-z0-9\-_]{20}\b|\bglptt-[A-Za-z0-9\-_]{20}\b/,
    message: "GitLab CI/CD or project trigger token detected.",
  }, // gitleaks-derived
  {
    id: "BITBUCKET_APP_PASSWORD",
    severity: "HIGH",
    impact: 9,
    pattern:
      /bitbucket[_\-. ]?(?:app[_-]?password|token)\s*[:=]\s*['"`][A-Za-z0-9+/=]{20,}['"`]/i,
    message: "Bitbucket app password or access token detected.",
  }, // gitleaks-derived
  {
    id: "DOCKER_HUB_PAT",
    severity: "HIGH",
    impact: 9,
    pattern: /\bdckr_pat_[A-Za-z0-9\-_]{27}\b/,
    message: "Docker Hub personal access token detected.",
  }, // gitleaks-derived
  {
    id: "TERRAFORM_CLOUD_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{67}\b/,
    message: "Terraform Cloud / Terraform Enterprise API token detected.",
  }, // gitleaks-derived
  {
    id: "GITHUB_FINE_GRAINED_PAT",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/,
    message: "GitHub fine-grained personal access token detected.",
  }, // gitleaks-derived
  {
    id: "GITHUB_APP_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bghu_[A-Za-z0-9]{36}\b|\bghr_[A-Za-z0-9]{36}\b/,
    message: "GitHub App user-to-server or refresh token detected.",
  }, // gitleaks-derived
  {
    id: "JFROG_ACCESS_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:jfrog|artifactory)[_-]?(?:access[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9\-_]{64,}['"`]/i,
    message: "JFrog Artifactory access token detected.",
  }, // gitleaks-derived

  // ── Payment & Finance ────────────────────────────────────────────────────
  {
    id: "SHOPIFY_ACCESS_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bshpat_[A-Za-z0-9]{32}\b/,
    message: "Shopify admin API access token detected.",
  }, // gitleaks-derived
  {
    id: "SHOPIFY_PRIVATE_APP",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bshppa_[A-Za-z0-9]{32}\b/,
    message: "Shopify private app password detected.",
  }, // gitleaks-derived
  {
    id: "SHOPIFY_SHARED_SECRET",
    severity: "HIGH",
    impact: 9,
    pattern: /\bshpss_[A-Za-z0-9]{32}\b/,
    message: "Shopify shared secret detected.",
  }, // gitleaks-derived
  {
    id: "SQUARE_ACCESS_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bEAAAE[A-Za-z0-9\-_]{60,}\b/,
    message: "Square production access token detected.",
  }, // gitleaks-derived
  {
    id: "SQUARE_SANDBOX_TOKEN",
    severity: "HIGH",
    impact: 8,
    pattern: /\bEAAAA[A-Za-z0-9\-_]{60,}\b/,
    message: "Square sandbox access token detected.",
  }, // gitleaks-derived
  {
    id: "PAYPAL_BRAINTREE_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}/,
    message: "PayPal / Braintree production access token detected.",
  }, // gitleaks-derived
  {
    id: "RAZORPAY_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /\brzp_(?:live|test)_[A-Za-z0-9]{14,}\b/,
    message: "Razorpay API key detected.",
  }, // gitleaks-derived

  // ── Communication & Messaging ────────────────────────────────────────────
  {
    id: "TELEGRAM_BOT_TOKEN",
    severity: "CRITICAL",
    impact: 9,
    pattern: /\b\d{8,10}:[A-Za-z0-9\-_]{35}\b/,
    message: "Telegram bot token detected.",
  }, // gitleaks-derived
  {
    id: "DISCORD_BOT_TOKEN",
    severity: "CRITICAL",
    impact: 9,
    pattern: /\b[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}\b/,
    message: "Discord bot token detected.",
  }, // gitleaks-derived
  {
    id: "DISCORD_WEBHOOK",
    severity: "HIGH",
    impact: 8,
    pattern:
      /discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,19}\/[A-Za-z0-9\-_]{68}/,
    message: "Discord webhook URL with token detected.",
  }, // gitleaks-derived
  {
    id: "MAILGUN_API_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /\bkey-[0-9a-zA-Z]{32}\b/,
    message: "Mailgun API key detected.",
  }, // gitleaks-derived
  {
    id: "MAILCHIMP_API_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /\b[0-9a-f]{32}-us\d{1,2}\b/,
    message: "Mailchimp API key detected.",
  }, // gitleaks-derived
  {
    id: "HUBSPOT_API_KEY",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:hubspot)[_-]?(?:api[_-]?)?key\s*[:=]\s*['"`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]/i,
    message: "HubSpot API key detected.",
  }, // gitleaks-derived
  {
    id: "ZENDESK_API_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:zendesk)[_-]?(?:api[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9]{40,}['"`]/i,
    message: "Zendesk API token detected.",
  }, // gitleaks-derived
  {
    id: "INTERCOM_ACCESS_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:intercom)[_-]?(?:access[_-]?)?token\s*[:=]\s*['"`][A-Za-z0-9]{60,}['"`]/i,
    message: "Intercom access token detected.",
  }, // gitleaks-derived
  {
    id: "TWILIO_AUTH_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /(?:twilio)[_-]?auth[_-]?token\s*[:=]\s*['"`][0-9a-f]{32}['"`]/i,
    message: "Twilio Auth Token detected.",
  }, // gitleaks-derived

  // ── Infrastructure & Secrets Management ─────────────────────────────────
  // Real Vault tokens are always stored as string literals. Require a quote
  // (single/double/backtick) immediately before the prefix so we don't match
  // JS property accesses like `s.someMethodNameWhichHappensToBeLong()`.
  {
    id: "VAULT_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /['"`](?:hvs|s)\.[A-Za-z0-9]{24,}['"`]/,
    message: "HashiCorp Vault token detected.",
  }, // gitleaks-derived
  {
    id: "VAULT_BATCH_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /['"`]hvb\.[A-Za-z0-9]{24,}['"`]/,
    message: "HashiCorp Vault batch token detected.",
  }, // gitleaks-derived
  {
    id: "OPENSSH_PRIVATE_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    message: "OpenSSH private key detected.",
  }, // gitleaks-derived
  {
    id: "PGP_PRIVATE_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    message: "PGP private key block detected.",
  }, // gitleaks-derived
  {
    id: "AGE_SECRET_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /AGE-SECRET-KEY-1[A-Z0-9]{58}/,
    message: "Age encryption identity (secret key) detected.",
  }, // gitleaks-derived
  {
    id: "KUBERNETES_SECRET",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:kubectl|k8s|kubernetes)[_-]?(?:token|secret|password)\s*[:=]\s*['"`][^'"`]{16,}['"`]/i,
    message: "Kubernetes credential hardcoded; use a Secret resource or vault.",
  }, // gitleaks-derived
  {
    id: "SSH_DSA_PRIVATE_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern: /-----BEGIN DSA PRIVATE KEY-----/,
    message: "DSA private key detected.",
  }, // gitleaks-derived

  // ── Monitoring & Observability ───────────────────────────────────────────
  {
    id: "DATADOG_API_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /(?:datadog|dd)[_-]?api[_-]?key\s*[:=]\s*['"`][a-f0-9]{32}['"`]/i,
    message: "Datadog API key detected.",
  }, // gitleaks-derived
  {
    id: "DATADOG_APP_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /(?:datadog|dd)[_-]?app[_-]?key\s*[:=]\s*['"`][a-f0-9]{40}['"`]/i,
    message: "Datadog application key detected.",
  }, // gitleaks-derived
  {
    id: "NEWRELIC_LICENSE_KEY",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:new[_-]?relic)[_-]?(?:license[_-]?)?key\s*[:=]\s*['"`][A-Za-z0-9]{40}['"`]/i,
    message: "New Relic license key detected.",
  }, // gitleaks-derived
  {
    id: "NEWRELIC_INSIGHTS_KEY",
    severity: "HIGH",
    impact: 8,
    pattern:
      /(?:new[_-]?relic)[_-]?(?:insights[_-]?)?(?:insert|query)[_-]?key\s*[:=]\s*['"`][A-Za-z0-9]{32,}['"`]/i,
    message: "New Relic Insights insert/query key detected.",
  }, // gitleaks-derived
  {
    id: "SENTRY_AUTH_TOKEN",
    severity: "CRITICAL",
    impact: 10,
    pattern: /\bsntrys_[A-Za-z0-9]{64}\b/,
    message: "Sentry auth token detected.",
  }, // gitleaks-derived
  {
    id: "SENTRY_LEGACY_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:sentry)[_-]?(?:auth[_-]?)?token\s*[:=]\s*['"`][a-f0-9]{64}['"`]/i,
    message: "Sentry legacy auth token detected.",
  }, // gitleaks-derived
  {
    id: "GRAFANA_API_KEY",
    severity: "HIGH",
    impact: 9,
    pattern: /\beyJrIjoi[A-Za-z0-9+/=]{40,}\b/,
    message: "Grafana API key (base64-encoded) detected.",
  }, // gitleaks-derived
  {
    id: "ELASTIC_API_KEY",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /(?:elastic(?:search)?|es)[_-]?(?:api[_-]?)?key\s*[:=]\s*['"`][A-Za-z0-9\-_=]{40,}['"`]/i,
    message: "Elasticsearch / Elastic Cloud API key detected.",
  }, // gitleaks-derived
  {
    id: "SPLUNK_HEC_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern:
      /(?:splunk)[_-]?(?:hec[_-]?)?token\s*[:=]\s*['"`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]/i,
    message: "Splunk HEC token detected.",
  }, // gitleaks-derived

  // ── OAuth / Social ───────────────────────────────────────────────────────
  {
    id: "FACEBOOK_ACCESS_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern: /\bEAAC[A-Za-z0-9]{80,}\b/,
    message: "Facebook / Meta access token detected.",
  }, // gitleaks-derived
  {
    id: "TWITTER_BEARER_TOKEN",
    severity: "HIGH",
    impact: 9,
    pattern: /\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,}\b/,
    message: "Twitter / X bearer token detected.",
  }, // gitleaks-derived
  {
    id: "LINKEDIN_CLIENT_SECRET",
    severity: "HIGH",
    impact: 8,
    pattern:
      /(?:linkedin)[_-]?client[_-]?secret\s*[:=]\s*['"`][A-Za-z0-9]{16}['"`]/i,
    message: "LinkedIn OAuth client secret detected.",
  }, // gitleaks-derived
  {
    id: "GOOGLE_OAUTH_SECRET",
    severity: "CRITICAL",
    impact: 10,
    pattern: /GOCSPX-[A-Za-z0-9\-_]{28}/,
    message: "Google OAuth client secret detected.",
  }, // gitleaks-derived
  {
    id: "SPOTIFY_CLIENT_SECRET",
    severity: "HIGH",
    impact: 8,
    pattern:
      /(?:spotify)[_-]?client[_-]?secret\s*[:=]\s*['"`][A-Za-z0-9]{32}['"`]/i,
    message: "Spotify client secret detected.",
  }, // gitleaks-derived
];

const PLACEHOLDER_REGEX =
  /YOUR_|your[-_\w]*here|xxxx|xxx|<[A-Z_]+>|_PLACEHOLDER_|sk-test|pk_test|example|dummy|fake|mock|replace|change[_-]?me|todo|test-key|ct_key_|super-secret-token|TEST_KEY|randomString/i;

// Marker-string secrets: constants whose VALUE is the same shape as an
// enum/marker/error code — e.g. `const INVALID_API_KEY = "INVALID_API_KEY"`,
// `refresh_token: "refresh_token"`, `access_token: "ACCESS_TOKEN"`. These
// are labels, not credentials. Two shapes cover the common cases:
//   - All-caps snake: `^[A-Z][A-Z0-9_]+$` (2+ chars after first letter)
//   - Lowercase snake with no digits: `^[a-z][a-z_]+$` (length < 30)
// Length bound keeps this from matching long real secrets that happen to be
// all-caps or all-lowercase.
const MARKER_STRING_REGEX = /^(?:[A-Z][A-Z0-9_]{2,39}|[a-z][a-z_]{2,29})$/;

// Documented public/example tokens that are NOT live credentials. Keyed on the
// matched token's structural shape, never on the repo. Covers AWS's own
// documented example access key (suffix EXAMPLE) and the placeholder family.
// Closes self-detection on secret-scanner allowlists (secretlint) + public
// well-known tokens (2026-05-30 partner scan).
function isWellKnownExampleSecret(token) {
  if (!token) return false;
  // AWS's documented example key, e.g. AKIAIOSFODNN7EXAMPLE — the literal AWS
  // docs use everywhere. Any AKIA...EXAMPLE is documentation, not a credential.
  if (/^AKIA[0-9A-Z]+EXAMPLE$/.test(token)) return true;
  // The token IS a placeholder/example string. Must be a WHOLE-TOKEN match,
  // anchored — NOT an unanchored substring scan. (Reverted 2026-05-31 audit:
  // the old unanchored PLACEHOLDER_REGEX.test(token) suppressed REAL secrets
  // whose random body merely contained "mock"/"fake"/"test"/"example"
  // — e.g. a Stripe-live-prefixed key with "mock" mid-body — across 9
  // provider families. (Example spelled generically on purpose: the literal
  // string tripped GitHub push protection on every downstream mirror/consumer
  // of shipped core source — 2026-06-01 mirror-push incident.) A
  // security guard must FAIL OPEN: only suppress when the token is ENTIRELY a
  // placeholder. docs/plans/2026-05-31-fp-arc-audit-findings.md)
  if (
    /^(?:YOUR_[A-Z_]*|<[A-Z_]+>|x{3,}|change[_-]?me|placeholder|example|dummy|fake|mock|test[-_]?key)$/i.test(
      token,
    )
  ) {
    return true;
  }
  return false;
}

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
  if (looksLikeRegexSourceString(val)) return false; // T3
  // HTTP ETags — bare inner value after quote-stripping: <hex>-<base64> or W/"<hex>-<base64>"
  if (/^(W\/)?"?[0-9a-f]+-[A-Za-z0-9+/]+=*"?$/.test(val)) return false;
  // Prose messages
  if ((val.match(/ /g) || []).length > 3) return false;
  if (/^[A-Za-z][A-Za-z .'":,!?-]+$/.test(val)) return false;
  // T8 (cold-audit sweep 2026-06-10, read-frog FPs): natural-language text in
  // dense scripts is entropy-rich — a Chinese sample-translation or prompt
  // string clears the 4.5 Shannon floor without containing any credential.
  // Real secret material is ASCII (base64/hex/token alphabets), so meaningful
  // non-ASCII presence marks prose, not a secret. Ratio (not any-single-char)
  // so an ASCII token pasted next to one accented char still scans.
  const nonAsciiCount = (val.match(/[^\x20-\x7e]/g) || []).length;
  if (nonAsciiCount / val.length > 0.2) return false;
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
  if (!/^[A-Za-z0-9+/=_-]+$/.test(val)) return false;
  const hasUpperAZ = /ABCDEFGHIJKLMNOPQRSTUVWXYZ/.test(val);
  const hasLowerAZ = /abcdefghijklmnopqrstuvwxyz/.test(val);
  const hasDigits09 = /0123456789|1234567890/.test(val);
  return hasUpperAZ && hasLowerAZ && hasDigits09;
}

function looksLikeRouteOrRegexPattern(val) {
  return /[\\/]/.test(val) && /(?:\(\?:|\(\?!|\\\.|\.\*|\|)/.test(val);
}

// T3 (cold-audit sweep 2026-06-10, secretlint): secret-DETECTION-rule source
// assigns regex snippets to keyword-named consts — `const SECRET =
// "[-_.~a-z0-9]{40}"` in secretlint-rule-azure/src/index.ts:27. A character
// class immediately followed by a counted quantifier is regex source, not
// credential material — real secrets are drawn from base64/hex/token
// alphabets that exclude `[` and `{`.
function looksLikeRegexSourceString(val) {
  return /\[[^\]]+\]\s*\{\d+(?:,\d*)?\}/.test(val);
}

function looksLikeConfigUrlAssignment(val) {
  return /^[A-Z0-9_]+=https?:\/\//.test(val);
}

function stripQuotedStrings(line) {
  return line.replace(/(['"`])(?:\\.|(?!\1)[\s\S])*?\1/g, "''");
}

// SQL_INJECTION_STRING_FORMAT refinement. Returns true ONLY if the line has at
// least one ${...} interpolation AND every interpolation is a compile-time
// constant identifier — an UPPER_SNAKE constant (${MAX_ROWS}, ${SCHEMA_VERSION})
// or a const-map / property access rooted at one (${TABLE_NAMES[t]},
// ${COLUMNS.id}). These are developer-controlled schema metadata, never user
// input, so the template literal is not injectable. ANY interpolation that is
// NOT a constant identifier (a bare lowercase local like ${tableName}, a
// member chain like ${req.query.t}, or a call like ${fn(x)}) makes this return
// false — the finding keeps firing. Deliberately conservative: an FP is
// tolerable, an SQL-injection false negative is not.
function allSqlInterpolationsAreConstantIdentifiers(line) {
  const interps = line.match(/\$\{([^}]*)\}/g);
  if (!interps || interps.length === 0) return false;
  // An interpolation body is "constant" iff it starts with an UPPER_SNAKE
  // identifier (>=2 chars, all uppercase/digit/underscore) optionally followed
  // by a [index] or .prop chain whose own root segments are also UPPER_SNAKE or
  // a short lowercase index var inside []. We require the ROOT to be UPPER_SNAKE.
  const CONST_INTERP =
    /^\s*[A-Z][A-Z0-9_]+(?:\s*\[\s*[A-Za-z_$][\w$]*\s*\]|\s*\.\s*[A-Za-z_$][\w$]*)*\s*$/;
  return interps.every((raw) => {
    const body = raw.slice(2, -1); // strip ${ and }
    return CONST_INTERP.test(body);
  });
}

function isSensitiveConsoleLog(line) {
  if (!/console\.(?:log|info|debug)\s*\(/.test(line)) return false;
  // Early-out: if the call wraps a redaction helper with a redaction flag
  // literal, the secret is masked before reaching the log output.
  if (REDACTED_LOG_CALL_REGEX.test(line)) return false;
  if (SENSITIVE_TEMPLATE_INTERPOLATION_REGEX.test(line)) return true;

  const codeWithoutStrings = stripQuotedStrings(line);
  // T2: scan ALL sensitive-looking env accesses; only metadata-suffixed names
  // (SECRETLINT_VERSION, FOO_TOKEN_SHA) are exempt — any non-metadata access
  // on the same line still fires.
  const envAccesses =
    codeWithoutStrings.match(
      new RegExp(SENSITIVE_ENV_ACCESS_REGEX.source, "gi"),
    ) || [];
  if (envAccesses.some((name) => !ENV_METADATA_SUFFIX_REGEX.test(name))) {
    return true;
  }

  // T2: i18n translation-key lookups — suppress ONLY when `token` is the sole
  // sensitive identifier on the line; password/secret/apiKey alongside the
  // i18n call still fires.
  if (
    I18N_GET_TOKEN_CALL_REGEX.test(codeWithoutStrings) &&
    !SENSITIVE_LOG_IDENTIFIER_EXCEPT_TOKEN_REGEX.test(codeWithoutStrings)
  ) {
    return false;
  }

  return SENSITIVE_LOG_IDENTIFIER_REGEX.test(codeWithoutStrings);
}

/**
 * Detect file language from extension.
 * @param {string} filePath
 * @returns {'js'|'ts'|'python'|'go'|'other'}
 */
function detectLanguage(filePath) {
  const ext = (filePath.split(".").pop() || "").toLowerCase();
  if (["ts", "tsx"].includes(ext)) return "ts";
  if (["js", "jsx", "mjs", "cjs"].includes(ext)) return "js";
  if (ext === "py") return "python";
  if (ext === "go") return "go";
  if (ext === "rs") return "rust";
  if (ext === "java") return "java";
  if (ext === "php") return "php";
  if (ext === "cs") return "csharp";
  return "other";
}

/**
 * Check whether a `codetitan-suppress` directive (or recognized tool-suppression
 * comment) is present in the source-line window adjacent to `index`. Used by
 * every security-rule emission site so the suppression contract is honored
 * uniformly across loops.
 *
 * Default behavior: scan the previous line only, for exact `codetitan-suppress:
 * <id>` matches where `id ∈ ids`. Options:
 *
 * - `sameLine` — also scan `lines[index]`. Used by the empty-catch site.
 * - `nextLine` — also scan `lines[index + 1]`. Used by the empty-catch site.
 * - `requireLineCommentPrefix` — the codetitan-suppress token must follow `//`
 *   on the same line. Preserves the existing empty-catch contract.
 * - `allowAnyCodetitan` — match `codetitan-suppress: <any-non-space-token>`,
 *   not just ids in `ids`. Used only by the extended-rules site so custom
 *   markers like `codetitan-suppress: my-custom-marker` keep working.
 * - `includeToolSuppressions` — additionally match recognized
 *   `biome-ignore` / `eslint-disable` comments. Used only by the extended-rules
 *   site.
 *
 * Ids are escaped before being interpolated into regexes; callers can pass a
 * single id string or an array.
 *
 * @param {string[]} lines  source lines (1-indexed match comes from `index`)
 * @param {number} index    the 0-based line index of the would-be finding
 * @param {string|string[]} [ids]  id(s) to match exactly after `codetitan-suppress:`
 * @param {object} [options]
 */
function hasSuppressionDirective(lines, index, ids = [], options = {}) {
  const {
    sameLine = false,
    nextLine = false,
    requireLineCommentPrefix = false,
    allowAnyCodetitan = false,
    includeToolSuppressions = false,
  } = options;

  const window = [];
  window.push(lines[index - 1] || "");
  if (sameLine) window.push(lines[index] || "");
  if (nextLine) window.push(lines[index + 1] || "");
  const haystack = window.join("\n");

  if (includeToolSuppressions) {
    const TOOL_RE =
      /(?:biome-ignore\s+lint(?:\/[A-Za-z]+)*\/(?:noDangerouslySetInnerHtml|noGlobalEval|noExplicitAny|security\/[A-Za-z]+)|eslint-disable(?:-next-line|-line)?\s+(?:react\/no-danger|security\/detect-[A-Za-z-]+|no-eval|no-script-url))/;
    if (TOOL_RE.test(haystack)) return true;
  }

  const prefix = requireLineCommentPrefix ? "\\/\\/\\s*" : "";

  if (allowAnyCodetitan) {
    const ANY_RE = new RegExp(`${prefix}codetitan-suppress:\\s*\\S+`);
    if (ANY_RE.test(haystack)) return true;
  }

  const idList = Array.isArray(ids) ? ids : [ids];
  for (const id of idList) {
    if (!id) continue;
    const escaped = String(id).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const ID_RE = new RegExp(`${prefix}codetitan-suppress:\\s*${escaped}\\b`);
    if (ID_RE.test(haystack)) return true;
  }
  return false;
}

/**
 * Classify a file path against the suppression-relevant regex set in one pass.
 * Every security loop inside `detectSecurityIssues` consumed the same flags
 * inline before — this consolidates that into one helper so detectors can share
 * the result and future loops don't drift on which flags they consult.
 * Pure: depends only on the input path + module-level regex constants.
 */
function getSecurityFileFlags(filePath) {
  const normalizedFilePath = filePath.replace(/\\/g, "/");
  return {
    normalizedFilePath,
    isTestFile: TEST_FILE_REGEX.test(normalizedFilePath),
    isBenchDir: BENCH_DIR_REGEX.test(normalizedFilePath),
    isDocFile: DOC_FILE_REGEX.test(normalizedFilePath),
    isExampleConfigFile: EXAMPLE_CONFIG_FILE_REGEX.test(normalizedFilePath),
    isInfraExecFile: INFRA_EXEC_FILE_REGEX.test(normalizedFilePath),
    isMinifiedFile: MINIFIED_FILE_REGEX.test(normalizedFilePath),
    isLocaleFile: LOCALE_FILE_REGEX.test(normalizedFilePath),
    isVendoredBundle: VENDORED_BUNDLE_REGEX.test(normalizedFilePath),
    isSeedFixtureFile: SEED_FIXTURE_FILE_REGEX.test(normalizedFilePath),
  };
}

/**
 * Strip TypeScript-specific syntax to prevent false positives.
 * Removes: type annotations (: Type), type assertions (as Type),
 * interface/type declarations, generic angle brackets in non-JSX files.
 * This is best-effort, not a full parser.
 */
function stripTypeScriptSyntax(content) {
  // Preserve source line numbers: when removing multi-line constructs we replace
  // them with N-1 blank lines so rule matches on later code still report the
  // correct source line. Single-line replacements (`: Type`, `as Type`, `<T>`,
  // `x!`) don't add or remove newlines, so line count is preserved naturally.
  const preserveLines = (match) =>
    "\n".repeat((match.match(/\n/g) || []).length);
  // The earlier broad regex for `interface|type` declaration bodies could greedily
  // eat the `/**` openers of nested JSDoc inside a `type Foo = { ... }` block while
  // leaving the `*/` closers intact, breaking downstream multi-line comment tracking
  // (real fallout: console.log inside a JSDoc code-fence on `got` flagged as a HIGH
  // sensitive-console FP). Drop that pass — the per-line type-annotation strips
  // below cover the actual FP cases (e.g. `: SomeType` matching code patterns).
  return (
    content
      // Remove type annotations after parameter/variable names: `: SomeType`
      .replace(/:\s*[A-Z]\w*(?:<[^>]*>)?(?:\s*[|&]\s*\w+(?:<[^>]*>)?)*/g, "")
      // Remove `as Type` assertions
      .replace(/\bas\s+[A-Z]\w*(?:<[^>]*>)?/g, "")
      // Remove generic type parameters from function signatures: `function foo<T>(`
      .replace(/<[A-Z]\w*(?:\s*,\s*[A-Z]\w*)*>/g, "")
      // Remove `!` non-null assertions
      .replace(/(\w)!/g, "$1")
  );
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
    return {
      issues: [],
      linesAnalyzed: 0,
      metadata: {},
      executionTime: Date.now() - start,
    };
  }

  const language = detectLanguage(filePath);

  // Strip TypeScript syntax before heuristic analysis to prevent false positives
  // from type annotations that look like code (e.g. `: string` matching patterns)
  const analysisContent =
    language === "ts" ? stripTypeScriptSyntax(content) : content;

  const lines = analysisContent.split(/\r?\n/);

  // Guard: also enforce a line count ceiling (catches files with very long lines)
  if (lines.length > MAX_ANALYSIS_LINES) {
    return {
      issues: [],
      linesAnalyzed: 0,
      metadata: {},
      executionTime: Date.now() - start,
    };
  }
  const context = buildContext(lines, filePath, projectRoot, analysisContent);
  // Attach language for language-specific rules
  context.language = language;
  let issues = [];

  switch (god) {
    case "security-god":
      issues = detectSecurityIssues(context);
      break;
    case "performance-god":
      issues = detectPerformanceIssues(context);
      break;
    case "test-god":
      issues = detectTestingGaps(context);
      break;
    case "refactoring-god":
      issues = detectRefactoringHotspots(context);
      break;
    case "documentation-god":
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
      hasTests: context.hasCompanionTest,
    },
    executionTime: Date.now() - start,
  };
}

function buildContext(lines, filePath, projectRoot, content) {
  const trimmedLines = lines.map((line) => line.trim());
  const commentLines = trimmedLines.filter((line) =>
    COMMENT_REGEX.test(line),
  ).length;
  const nonEmptyLines = trimmedLines.filter((line) => line.length > 0).length;
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
    content,
  };
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getCallWindow(lines, startIndex, maxLines = 6) {
  const collected = [];
  let parenBalance = 0;
  let started = false;

  for (
    let i = startIndex;
    i < Math.min(lines.length, startIndex + maxLines);
    i++
  ) {
    const line = lines[i];
    collected.push(line);

    for (const char of line) {
      if (char === "(") {
        parenBalance++;
        started = true;
      } else if (char === ")") {
        parenBalance = Math.max(0, parenBalance - 1);
      }
    }

    if (started && parenBalance === 0 && /[);]/.test(line)) {
      break;
    }
  }

  return collected.join(" ");
}

function extractStaticCommandLiteral(expression) {
  const trimmed = expression.trim();
  if (trimmed.length < 2) return null;

  const quote = trimmed[0];
  if (
    (quote !== "'" && quote !== '"' && quote !== "`") ||
    trimmed[trimmed.length - 1] !== quote
  ) {
    return null;
  }

  const rawCommand = trimmed.slice(1, -1);
  if (quote === "`" && rawCommand.includes("${")) {
    return null;
  }

  return rawCommand;
}

function isSafeStaticExecProbe(line) {
  const literalMatch = STATIC_EXEC_LITERAL_REGEX.exec(line);
  if (!literalMatch) return false;

  const [, , quote, rawCommand] = literalMatch;
  if (quote === "`" && rawCommand.includes("${")) {
    return false;
  }

  const normalizedCommand = rawCommand
    .replace(SAFE_EXEC_REDIRECTION_SUFFIX_REGEX, " ")
    .trim();

  if (!normalizedCommand) return false;
  if (/[|&;<>$`]/.test(normalizedCommand)) return false;
  if (DANGEROUS_STATIC_COMMAND_REGEX.test(normalizedCommand)) return false;

  return true;
}

// Matches the specific bundler / CJS-ESM interop idioms that use `eval` only
// to bypass static analysis by tools like webpack/esbuild. Recognized shapes:
//   eval('require.main === module')
//   eval(`require('../package.json')`)
//   eval("require('path').join(...)")
//   eval('__filename')  — webpack/ncc module-identity check
//   eval('__dirname')   — same class, sibling literal
// Always a quoted literal argument with no interpolation; body is either a
// `require`/`require.main` reference or a bare module-identity literal.
// Everything else still fires EVAL_USAGE.
function isStaticLiteralEval(line) {
  const m = /\beval\s*\(\s*(['"`])((?:\\.|(?!\1)[\s\S])*)\1\s*\)/.exec(line);
  if (!m) return false;
  const [, quote, body] = m;
  if (quote === "`" && body.includes("${")) return false;
  if (/\brequire\s*(?:\(|\.main\b)/.test(body)) return true;
  if (/^(?:__filename|__dirname)$/.test(body.trim())) return true;
  return false;
}

// EVAL_USAGE member-access guard. The base pattern /\beval\s*\(/ matches `.eval(`
// member calls (e.g. `poly.monomial.eval(x)`, `this.eval(...)`) — a method named
// `eval`, NOT the JS global `eval()`. Suppress those, EXCEPT when the receiver is
// the global object itself (window/globalThis/self/global.eval == real eval).
// Strings are already stripped by the caller before this fires, so a quoted
// ".eval(" cannot reach here. Structural property: a `.` immediately before
// `eval` (a non-global member access) is not dynamic evaluation.
function isMemberAccessEval(line) {
  const code = stripQuotedStrings(line);
  // Real global eval reached via a global receiver — keep firing.
  if (/\b(?:window|globalThis|self|global)\s*\.\s*eval\s*\(/.test(code)) {
    return false;
  }
  // NOTE: a previous "if stripping strings removes all eval( → suppress (prose)"
  // branch was REVERTED 2026-05-31 — it hid a real `${eval(userInput)}` inside a
  // template literal (stripQuotedStrings eats the whole backtick span incl. the
  // live call). A security guard must FAIL OPEN. The MikroORM help-text FP it
  // chased is tolerable; an eval FN is not. (audit: docs/plans/2026-05-31-fp-arc-audit-findings.md)
  // `.eval(` or `#eval(` with no global receiver = a method named eval.
  // Only a guard if there is NO bare global `eval(` elsewhere on the line.
  const hasMemberEval = /[.#]\s*eval\s*\(/.test(code);
  const hasGlobalEval = /(?<![.#\w])eval\s*\(/.test(code);
  return hasMemberEval && !hasGlobalEval;
}

function isFunctionLikeDefinition(line) {
  const normalized = line.trim();
  // Bare function call shaped like a definition: `spawn(cmd, args) {`
  if (
    /^(?:async\s+)?(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\)\s*\{?$/.test(
      normalized,
    )
  )
    return true;
  if (/^(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{?$/.test(normalized))
    return true;
  // Named function declarations: `function spawn(`, `export function spawn(`, `export async function spawn(`
  if (
    /^(?:export\s+)?(?:async\s+)?function\s+(?:exec|execSync|spawn|spawnSync)\b/.test(
      normalized,
    )
  )
    return true;
  // Private class methods: `async #spawn(`, `#spawn(`
  if (/^(?:async\s+)?#(?:exec|execSync|spawn|spawnSync)\s*\(/.test(normalized))
    return true;
  return false;
}

function isSafeProcessExecPathAlias(lines, index, variableName) {
  const assignmentRegex = new RegExp(
    `\\b${escapeRegExp(variableName)}\\b\\s*=`,
  );
  const safeAssignmentRegex = new RegExp(
    `^(?:(?:const|let|var)\\s+)?${escapeRegExp(variableName)}\\s*=\\s*process\\.execPath\\s*;?$`,
  );
  const compoundAssignmentRegex = new RegExp(
    `\\b${escapeRegExp(variableName)}\\b\\s*[+\\-*/%]=`,
  );
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

  if (trimmed === "process.execPath") {
    return true;
  }

  if (!/^[A-Za-z_$][\w$]*$/.test(trimmed)) {
    return false;
  }

  return isSafeProcessExecPathAlias(lines, index, trimmed);
}

function extractArgvCommandArrayExpression(expression) {
  const trimmed = expression.trim();
  const bracketMatch =
    /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\[\s*0\s*\]$/.exec(trimmed);
  if (bracketMatch) {
    return bracketMatch[1];
  }

  const atMatch =
    /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.at\(\s*0\s*\)$/.exec(trimmed);
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
    if (!normalizedCommand || normalizedCommand.startsWith("-")) return false;
    if (/[|&;<>$`]/.test(normalizedCommand)) return false;
    return true;
  }

  return /^[A-Za-z_$][\w$]*(?:Script|Path|File)$/.test(trimmed);
}

function isSafeShellToolSpawnArgvCall(commandExpression, argsExpression) {
  const staticCommand = extractStaticCommandLiteral(commandExpression.trim());
  if (staticCommand === null) return false;

  const normalizedCommand = staticCommand.trim().toLowerCase();
  if (normalizedCommand === "ssh") {
    return argsExpression.trim().startsWith("[");
  }

  if (normalizedCommand !== "bash" && normalizedCommand !== "sh") {
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
  const slicePattern = new RegExp(
    `^${escapeRegExp(arrayExpression)}\\.slice\\(\\s*1\\s*(?:,\\s*\\d+\\s*)?\\)(?=[,)\\s]|$)`,
  );
  return slicePattern.test(trimmedArgs);
}

function isSafeSpawnArgvCall(lines, index) {
  const callWindow = getCallWindow(lines, index);
  const callMatch = SPAWN_CALL_PREFIX_REGEX.exec(callWindow);
  if (!callMatch) return false;

  const commandExpression = callMatch[2];
  const argsExpression = callWindow
    .slice(callMatch.index + callMatch[0].length)
    .trim();
  const safeSharedArgvDecomposition = isSafeSharedArgvDecomposition(
    commandExpression,
    argsExpression,
  );

  if (/shell\s*:\s*true/.test(callWindow)) return false;

  // Static literal command + static array args: no injection vector regardless of command name
  // e.g. spawn("powershell", [...]) or spawn("git", ["push"]) — both args are compile-time constants
  const staticCmd = extractStaticCommandLiteral(commandExpression.trim());
  if (staticCmd !== null && argsExpression.trim().startsWith("[")) return true;

  // Variable command + static array args with only safe flag-style elements: no shell injection risk
  // e.g. spawn(exe, ["--version"]) — variable command but args are hardcoded flags, no user input
  if (
    argsExpression.trim().startsWith("[") &&
    /^\[\s*['"`][^'"`]*['"`](?:\s*,\s*['"`][^'"`]*['"`])*\s*\]/.test(
      argsExpression.trim(),
    )
  )
    return true;

  // Spawn wrapper passthrough: both command and args are bare parameter-like identifiers
  // e.g. spawnSync(cmd, args, {...}) — this is a thin wrapper forwarding its own args, not user input
  const cmdTrimmed = commandExpression.trim();
  const argsTrimmed = argsExpression.trim();
  if (
    /^[a-z][A-Za-z]*$/.test(cmdTrimmed) &&
    /^(?:args|argv)\b/.test(argsTrimmed)
  )
    return true;

  if (
    !isSafeSpawnCommandExpression(lines, index, commandExpression) &&
    !isSafeShellToolSpawnArgvCall(commandExpression, argsExpression) &&
    !safeSharedArgvDecomposition
  )
    return false;
  if (
    !safeSharedArgvDecomposition &&
    !/^(?:\[|(?:args|argv)\b|[A-Za-z_$][\w$]*(?:Args|Argv|argv|args)\b)/.test(
      argsExpression,
    )
  )
    return false;

  return true;
}

function parseStringLiteralAssignment(line, variableName) {
  const trimmed = line.trim();
  if (!trimmed || COMMENT_REGEX.test(trimmed)) {
    return { assigned: false, dynamic: false, value: null };
  }

  const assignmentRegex = new RegExp(
    `^(?:(?:const|let|var)\\s+)?${escapeRegExp(variableName)}\\s*=\\s*(.+?)\\s*;?$`,
  );
  const match = assignmentRegex.exec(trimmed);
  if (!match) {
    return { assigned: false, dynamic: false, value: null };
  }

  const rhs = match[1].trim();
  if (rhs.length < 2) {
    return { assigned: true, dynamic: true, value: null };
  }

  const quote = rhs[0];
  if ((quote === "'" || quote === '"') && rhs[rhs.length - 1] === quote) {
    return { assigned: true, dynamic: false, value: rhs.slice(1, -1) };
  }

  return { assigned: true, dynamic: true, value: null };
}

function isSafeLiteralAllowlistedExec(lines, index) {
  const callWindow = getCallWindow(lines, index);
  const identifierMatch = COMMAND_IDENTIFIER_ARG_REGEX.exec(callWindow);
  if (!identifierMatch) return false;

  const variableName = identifierMatch[2];
  const compoundAssignmentRegex = new RegExp(
    `\\b${escapeRegExp(variableName)}\\b\\s*[+\\-*/%]=`,
  );
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
      .replace(SAFE_EXEC_REDIRECTION_SUFFIX_REGEX, " ")
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
      id: "EVAL_USAGE",
      severity: "HIGH",
      pattern: /\beval\s*\(/,
      message:
        "Avoid dynamic evaluation; prefer safer parsing or explicit logic.",
      impact: 8,
      skipDoc: true, // don't fire in blog/docs/examples showing bad patterns
      skipTest: true, // test files legitimately exercise dynamic evaluation paths
    },
    {
      id: "FUNCTION_CONSTRUCTOR",
      severity: "HIGH",
      pattern: /\bnew\s+Function\s*\(/,
      message: "Dynamic Function constructor executes arbitrary code.",
      impact: 8,
      skipTest: true,
    },
    {
      id: "COMMAND_EXEC",
      severity: "HIGH",
      // Require child_process. prefix OR that exec/spawn is NOT preceded by a dot or # (method/private method call)
      pattern:
        /(?:child_process\.|(?<![.#\w]))(exec|execSync|spawn|spawnSync)\s*\(/,
      message:
        "Command execution opens the door to injection attacks. Validate or sandbox inputs.",
      impact: 9,
      skipTest: true, // test files use exec/spawn to run the CLI under test
    },
    {
      id: "INSECURE_HTTP",
      severity: "MEDIUM",
      // Exclude localhost/127.0.0.1/::1 — HTTP is fine for local dev/test traffic
      pattern:
        /(fetch|axios\.get|axios\.post|axios\.request)\s*\(\s*['"]http:\/\/(?!localhost[:/]|127\.0\.0\.1[:/]|\[::1\])/,
      message:
        "HTTP request to external URL detected. Prefer HTTPS to protect data in transit.",
      impact: 5,
    },
    // Note: hardcoded secrets are detected below by SECRET_PATTERNS + entropy scan
    {
      id: "DISABLE_LINT_SECURITY",
      severity: "MEDIUM",
      pattern: /eslint-disable-(next-line|line)\s+(no-eval|security\/\w+)/,
      message:
        "Security lint rule disabled. Ensure there is a reviewed justification.",
      impact: 6,
    },
  ];

  const {
    normalizedFilePath,
    isTestFile,
    isBenchDir,
    isDocFile,
    isExampleConfigFile,
    isInfraExecFile,
    isMinifiedFile,
    isLocaleFile,
    isVendoredBundle,
    isSeedFixtureFile,
  } = getSecurityFileFlags(context.filePath);
  // True for lines that look like rule metadata rather than executable code.
  // Covers three shapes:
  //   1. Key-value rule entries: `pattern: /.../`, `message: '...'`, `name: 'eval()'`.
  //   2. Leading-quoted pattern-list entries: `'eval(',` or `"exec("` — common in
  //      rule-definition arrays that enumerate dangerous tokens as strings.
  //   3. Documentation / message strings in positional Rule factory args:
  //      `'Avoid eval() / Function constructor. It is unsafe and breaks CSP.',`
  //      These are prose descriptions that mention dangerous APIs, not calls.
  const isRuleMetadataLine = (value) =>
    /\b(?:pattern|message|description|scenario|fix|why|badCode|goodCode|code|name|title|label|id)\s*:/.test(
      value,
    ) ||
    /^\s*['"`][\w$]*\s*[\(\[{.]/.test(value) ||
    /^\s*['"`][A-Z][^'"`]{10,}['"`]\s*,\s*$/.test(value);

  context.lines.forEach((line, index) => {
    const normalized = line.trim();

    // Skip pure comment lines for all security rules
    if (COMMENT_REGEX.test(normalized)) return;
    if (isRuleMetadataLine(normalized)) return;
    if (line.length > MINIFIED_LINE_LENGTH) return;

    rules.forEach((rule) => {
      // Use exec() to get match position
      const match = rule.pattern.exec(line);
      if (!match) return;

      // ── Per-rule codetitan-suppress directive on previous line ──────────
      // The maintainer has reviewed this pattern and explicitly opted out.
      // Tied to rule.id (not generic \S+) so the audit trail names which
      // rule was suppressed; matches what users write in practice, e.g.
      //   // codetitan-suppress: COMMAND_EXEC
      //   const child = spawn(step.command, { shell: true });
      if (hasSuppressionDirective(context.lines, index, rule.id)) return;

      // ── Skip minified/dist files — vendored, not user-owned code ───────────
      if (isMinifiedFile) return;

      // ── Per-rule test-file skip ──────────────────────────────────────────
      if (rule.skipTest && isTestFile) return;

      // ── Per-rule doc-file skip ───────────────────────────────────────────
      if (rule.skipDoc && isDocFile) return;
      if (isExampleConfigFile && !["HIGH", "CRITICAL"].includes(rule.severity))
        return;
      if (
        rule.id === "COMMAND_EXEC" &&
        (isFunctionLikeDefinition(line) ||
          isSafeStaticExecProbe(line) ||
          isSafeSpawnArgvCall(context.lines, index) ||
          isSafeLiteralAllowlistedExec(context.lines, index) ||
          isInfraExecFile || // engine infra files intentionally call exec
          isMinifiedFile || // minified/dist files are not user-owned code
          // No child_process import → exec() is almost always a SQLite-shaped
          // execute(), a TypeScript interface method signature, or a custom
          // method named `exec`. Mirrors taint-analyzer.js's CHILD_PROCESS_
          // IMPORT_REGEX gate on TAINT_COMMAND_INJECTION; closes Remix
          // adapter.ts:32 (DatabaseSync.exec interface) + Drizzle bun-sqlite
          // session.ts:45 (Bun SQLite exec method) FPs from 2026-05-10
          // re-baseline.
          !/require\s*\(\s*['"`](?:node:)?child_process['"`]\s*\)|from\s+['"`](?:node:)?child_process['"`]|import\s+['"`](?:node:)?child_process['"`]/.test(
            context.content,
          ))
      )
        return;
      // eval('literal') and eval(`literal ${nothing} else`) are bundler/CJS-ESM
      // workarounds, not dynamic eval. Suppress when the argument is a single
      // quoted literal with no interpolation.
      if (rule.id === "EVAL_USAGE" && isStaticLiteralEval(line)) return;
      // Member-access `.eval(` (e.g. poly.monomial.eval(x), this.eval(...)) is
      // a method named eval, not the JS global — suppress unless the receiver
      // is the global object. Closes noble-curves / MikroORM / dotenvx FPs
      // (2026-05-30 partner-scan audit).
      if (rule.id === "EVAL_USAGE" && isMemberAccessEval(line)) return;
      // G3a guard (2026-05-19): EVAL_USAGE / COMMAND_EXEC fire on Flask's
      // documented lifecycle APIs (PYTHONSTARTUP exec in `flask shell`,
      // from_pyfile config loader). Both are framework-controlled paths,
      // not user-derived. Closes Codex baseline FPs at flask/cli.py:1023
      // and flask/config.py:209.
      // Source: docs/plans/2026-05-19-lang-canary-baseline.md Recommended Step 1-2.
      if (rule.id === "EVAL_USAGE" || rule.id === "COMMAND_EXEC") {
        // Wider backward window (10 lines) to catch enclosing function
        // signatures like `def from_pyfile(...)`; tighter forward window
        // (3 lines) to keep guard scope local.
        const wstart = Math.max(0, index - 10);
        const wend = Math.min(context.lines.length - 1, index + 3);
        for (let i = wstart; i <= wend; i++) {
          if (/\bPYTHONSTARTUP\b/.test(context.lines[i])) return;
          if (/\bfrom_pyfile\b|\bfrom_file\b/.test(context.lines[i])) return;
        }
      }
      const column = match.index;
      const matchLength = match[0].length;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: rule.severity,
          category: rule.id,
          message: rule.message,
          impact: rule.impact,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    });

    // ── Additional security heuristics ──────────────────────────────────────
    // Prototype pollution
    const protoPollutionMatch =
      /(?:__proto__|constructor\.prototype|Object\.prototype)\s*\[/.exec(line);
    if (
      protoPollutionMatch &&
      !COMMENT_REGEX.test(normalized) &&
      !hasSuppressionDirective(context.lines, index, "PROTOTYPE_POLLUTION")
    ) {
      issues.push(
        formatIssue({
          line: index + 1,
          column: protoPollutionMatch.index,
          endLine: index + 1,
          endColumn: protoPollutionMatch.index + protoPollutionMatch[0].length,
          severity: "HIGH",
          category: "PROTOTYPE_POLLUTION",
          message:
            "Prototype pollution: dynamic property assignment on __proto__ or Object.prototype.",
          impact: 8,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // Regex injection — user data in RegExp constructor.
    // Skip in benchmark / CI-script paths: `process.argv` here is a
    // developer-supplied filter pattern, not an HTTP-request vector.
    const isBenchOrScriptPath =
      /(?:^|\/)(?:scripts|benchmarks?|bench)\//.test(normalizedFilePath) ||
      /\.bench\.[jt]sx?$/.test(normalizedFilePath);
    const regexInjMatch = !isBenchOrScriptPath
      ? /new\s+RegExp\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|process\.argv|userInput)/.exec(
          line,
        )
      : null;
    if (
      regexInjMatch &&
      !COMMENT_REGEX.test(normalized) &&
      !hasSuppressionDirective(context.lines, index, "REGEX_INJECTION")
    ) {
      issues.push(
        formatIssue({
          line: index + 1,
          column: regexInjMatch.index,
          endLine: index + 1,
          endColumn: regexInjMatch.index + regexInjMatch[0].length,
          severity: "HIGH",
          category: "REGEX_INJECTION",
          message:
            "User input passed to RegExp constructor — ReDoS or regex injection risk.",
          impact: 7,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // Timing attack: non-constant-time string compare for secrets
    const timingMatch =
      /(?:password|token|secret|apiKey|api_key|hash)\s*===?\s*(?:req\.|request\.|input\.|params\.)/.exec(
        line,
      );
    if (
      timingMatch &&
      !COMMENT_REGEX.test(normalized) &&
      !hasSuppressionDirective(context.lines, index, "TIMING_ATTACK")
    ) {
      issues.push(
        formatIssue({
          line: index + 1,
          column: timingMatch.index,
          endLine: index + 1,
          endColumn: timingMatch.index + timingMatch[0].length,
          severity: "MEDIUM",
          category: "TIMING_ATTACK",
          message:
            "String comparison of secret/token may be vulnerable to timing attack. Use crypto.timingSafeEqual().",
          impact: 6,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // Unsigned JWT algorithm ("none" algorithm).
    //
    // Historical rule fired when a line contained BOTH "none" (any context)
    // AND /sign|verify|decode|jwt/i (any context). Both conditions matched
    // on innocuous React JSX — `userSelect: "none"` + a `designer` var in
    // the same style block, or `textDecoration: 'none'` on a `<Link>Sign
    // In</Link>` button. That's not JWT code.
    //
    // Fix: require the "none" token to co-occur with a JWT-library call
    // (`jwt.sign`, `jwt.verify`, `jwt.decode`, `jose.jwt*`) or a clear
    // algorithm-config keyword (`alg:`, `algorithm:`) on the same line.
    // Bare `sign`/`verify` as words (word-boundary flanked) don't count.
    const unsignedAlgorithmPattern = new RegExp(
      [
        "\\balg\\b\\s*[:=]\\s*[\"']" + "no" + "ne[\"']",
        "\\balgorithm\\b\\s*[:=]\\s*[\"']" + "no" + "ne[\"']",
        "\\balgorithms?\\b\\s*[:=]\\s*\\[\\s*[\"']" + "no" + "ne[\"']",
      ].join("|"),
      "i",
    );
    const authTokenPattern = new RegExp(
      [
        "\\bjwt\\.(?:sign|verify|decode)\\b",
        "\\bjose\\.[A-Za-z]*(?:sign|verify|decode)",
        "\\bjsonwebtoken\\b",
      ].join("|"),
      "i",
    );
    const unsignedAlgorithmMatch = unsignedAlgorithmPattern.exec(line);
    if (
      unsignedAlgorithmMatch &&
      authTokenPattern.test(line) &&
      !COMMENT_REGEX.test(normalized) &&
      !hasSuppressionDirective(context.lines, index, "JWT_NONE_ALGORITHM")
    ) {
      issues.push(
        formatIssue({
          line: index + 1,
          column: unsignedAlgorithmMatch.index,
          endLine: index + 1,
          endColumn:
            unsignedAlgorithmMatch.index + unsignedAlgorithmMatch[0].length,
          severity: "CRITICAL",
          category: "JWT_NONE_ALGORITHM",
          message:
            "Unsigned JWT algorithm allows forged tokens without signature verification.",
          impact: 10,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // XXE: XML parser without disabling external entities.
    //
    // `fast-xml-parser` (the npm package) does NOT implement entity resolution
    // at all — it cannot be vulnerable to XXE by construction. If the file
    // imports it, suppress the XMLParser match regardless of nearby flags.
    //
    // Browser DOMParser with `text/html` MIME type does not perform entity
    // resolution either — that's XML-only behavior. HTML parsing of untrusted
    // input is its own risk (XSS via innerHTML sinks), but not XXE. Suppress
    // when the parseFromString call passes a literal "text/html" as 2nd arg.
    const xxeMatch =
      /new\s+(?:DOMParser|XMLParser|xml2js|libxmljs|sax)\s*\(|parseFromString\s*\(/.exec(
        line,
      );
    const importsFastXmlParser =
      /from\s+['"]fast-xml-parser['"]|require\s*\(\s*['"]fast-xml-parser['"]/.test(
        context.content,
      );
    // Look ahead a small window — typical pattern splits `new DOMParser()` and
    // `parser.parseFromString(input, "text/html")` across 1-3 lines. Allow the
    // 2nd arg to sit after arbitrary text (not just `[^)]*`) so nested calls
    // like `parser.parseFromString(node.getText(), "text/html")` don't trip
    // the closing paren before we reach the MIME-type argument.
    const xxeWindow = context.lines
      .slice(index, Math.min(context.lines.length, index + 4))
      .join("\n");
    const isHtmlParse =
      /parseFromString\s*\([\s\S]{0,200}?['"`]text\/html['"`]/.test(xxeWindow);
    // The WHATWG **browser** DOMParser cannot resolve external entities — so it
    // is not an XXE sink. But a SERVER-SIDE DOMParser (e.g.
    // `new (require('@xmldom/xmldom').DOMParser)()` / `import {DOMParser} from
    // 'xmldom'`) CAN, depending on version/config. So this is an ALLOWLIST keyed
    // on a POSITIVE browser signal, NOT a blocklist — a security guard must FAIL
    // OPEN. (Reverted 2026-05-31 audit: the old "suppress unless a known server
    // lib token is present" blocklist suppressed real server-xmldom XXE because
    // it didn't recognize the lib. docs/plans/2026-05-31-fp-arc-audit-findings.md)
    //
    // Positive browser signal: a bare `new DOMParser()` (the global, no
    // module-qualified receiver) AND no server XML-lib import anywhere in the
    // file. If the file imports/requires any server XML parser (incl. a
    // DOMParser pulled from xmldom/jsdom/@xmldom), we do NOT treat it as the
    // browser global → keep firing. Closes the Astro/deep-chat browser-DOMParser
    // FPs while NOT hiding server xmldom.
    // Match the server-XML-lib specifier across ALL import forms, not just
    // `require("x")` / `from "x"`. Codex F3 re-attack (2026-05-31) found that
    // `await import("@xmldom/xmldom")` and `require(`@xmldom/xmldom`)` named the
    // server lib DIRECTLY yet slipped past the old regex (no `import(` branch,
    // no backtick specifier) → isBrowserDomParser went true → real server XXE
    // suppressed. Widening the import matcher is strictly FAIL-OPEN (it makes
    // the browser-suppression fire LESS often), so it cannot add an FN; the only
    // cost is a tolerable FP if a file lazy-imports a server XML lib AND also
    // uses a true browser DOMParser elsewhere. Quote class is ['"`] for the
    // call forms; `from` keeps ['"] (backtick is invalid in a static `from`).
    const SERVER_XML_LIB =
      /(?:@?xmldom(?:\/xmldom)?|jsdom|libxmljs2?|xml2js|sax|node-expat|fast-xml-parser)/;
    const importsServerXmlLib = new RegExp(
      "(?:\\b(?:require|import)\\s*\\(\\s*['\"`]|\\bfrom\\s+['\"])" +
        SERVER_XML_LIB.source +
        "['\"`]",
    ).test(context.content);
    const bareBrowserDomParser =
      /\bnew\s+DOMParser\s*\(/.test(xxeWindow) &&
      !/[.\])]\s*DOMParser\b|DOMParser\s*[:=]/.test(xxeWindow); // not a member/aliased DOMParser
    // A second, distinct server-XML constructor in the window is independent
    // evidence of real XML parsing — do NOT let the browser-DOMParser signal
    // mask it (fail open).
    const hasOtherServerXmlCtor =
      /\bnew\s+(?:XMLParser|libxmljs2?|xml2js|sax)\b|\.(?:parseXml|parseXmlString)\s*\(/.test(
        xxeWindow,
      );
    const isBrowserDomParser =
      bareBrowserDomParser && !importsServerXmlLib && !hasOtherServerXmlCtor;
    if (
      xxeMatch &&
      !isHtmlParse &&
      !isBrowserDomParser &&
      !COMMENT_REGEX.test(normalized) &&
      !isTestFile &&
      !importsFastXmlParser &&
      !hasSuppressionDirective(context.lines, index, "POTENTIAL_XXE")
    ) {
      // Only flag if there's no entity disabling nearby
      const ctxBlock = context.lines
        .slice(Math.max(0, index - 5), index + 5)
        .join("\n");
      if (
        !/(noent|allowExternalEntities.*false|resolveExternalEntities.*false|FEATURE_EXTERNAL_GENERAL_ENTITIES)/.test(
          ctxBlock,
        )
      ) {
        issues.push(
          formatIssue({
            line: index + 1,
            column: xxeMatch.index,
            endLine: index + 1,
            endColumn: xxeMatch.index + xxeMatch[0].length,
            severity: "MEDIUM",
            category: "POTENTIAL_XXE",
            message:
              "XML parser usage detected — ensure external entity resolution is disabled to prevent XXE.",
            impact: 7,
            snippet: normalized,
            context: getContextLines(context.lines, index, 2),
          }),
        );
      }
    }

    // Check for weak hash (MD5) — only flag when the file also mentions an
    // auth/crypto concern. Syntactically md5 is md5; semantically it's a
    // security issue only in auth/session/signature flows. Non-crypto uses
    // (cache keys, dedup tokenization, ETag-like fingerprints) are safe and
    // common — flagging them makes the rule ~80% FP on dogfood.
    const md5Pattern = /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/;
    const md5Match = md5Pattern.exec(line);
    if (md5Match) {
      // Crypto-context discriminators. Word-boundary match across whole file.
      // Intentionally excludes "token" alone — too overloaded (lex tokens,
      // payment tokens, GitHub/API tokens, cancellation tokens). Qualified
      // auth-token names (authToken, sessionToken, bearer) match instead.
      const CRYPTO_CONTEXT =
        /\b(password|session|jwt|hmac|signature|apiKey|apiSecret|hashPassword|signPayload|authToken|sessionToken|sessionKey|bearer)\b/i;
      const inCryptoContext = CRYPTO_CONTEXT.test(context.content);
      // Known non-crypto uses of md5 on a line-by-line basis:
      //   - Gravatar / email-hash canonicalization (md5 of lowercased email)
      //   - Cache keys / ETags / fingerprints on content
      // These are deterministic identifiers, not credentials.
      const isEmailMd5 =
        /\bmd5[^)]*\)\s*\.update\s*\([^)]*\b(?:email|emailAddress|gravatar|md5Email|emailMd5)\b/i.test(
          line,
        );
      const isFingerprintMd5 =
        /\b(?:fingerprint|cacheKey|etag|contentHash|checksum|dedupe(?:Key|Hash)?)\b/i.test(
          line,
        );

      if (
        inCryptoContext &&
        !isEmailMd5 &&
        !isFingerprintMd5 &&
        !hasSuppressionDirective(context.lines, index, "WEAK_HASH")
      ) {
        const column = md5Match.index;
        const matchLength = md5Match[0].length;

        issues.push(
          formatIssue({
            line: index + 1,
            column,
            endLine: index + 1,
            endColumn: column + matchLength,
            severity: "MEDIUM",
            category: "WEAK_HASH",
            message:
              "MD5 used in a file with auth/crypto terms — MD5 is broken for cryptographic purposes. Use SHA-256 or bcrypt/argon2 for passwords.",
            impact: 6,
            snippet: normalized,
            context: getContextLines(context.lines, index, 2),
          }),
        );
      }
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
      if (/(?:throw|Error\(|console\.|log\(|warn\(|debug\(|info\()/.test(line))
        return;
      let matchedNamedSecret = false;

      // ── codetitan-suppress directive on previous line ───────────────────
      // Two checks: by surfaced category (HARDCODED_SECRET — what users see
      // in reports and write in suppress comments) AND by rule.id (the
      // specific pattern like STRIPE_KEY for finer-grained audit trails).
      // Category-level returns from the line callback so the entropy fallback
      // below is also covered; rule.id-level `continue`s the named loop so a
      // STRIPE_KEY suppression does not silence a different secret family.
      if (hasSuppressionDirective(context.lines, index, "HARDCODED_SECRET"))
        return;

      for (const rule of SECRET_PATTERNS) {
        if (foundSecretCategories.has(rule.id)) continue;
        if (hasSuppressionDirective(context.lines, index, rule.id)) continue;
        if (isMinifiedFile) continue; // dist/bundled files contain vendored code — never surface secrets from them
        if (isBenchDir) continue; // bench dirs contain bundled fixtures — always FPs for secrets
        if (isTestFile) continue; // test files suppress ALL secret severities (loosened 2026-05-11)
        if (isLocaleFile) continue; // i18n/locale files are pure UI text; entropy + keyword scans on translations are structural FPs (Plane FPs P2 + P3, 2026-05-12)
        if (isVendoredBundle) continue; // vendored PWA bundles (Workbox, etc) under public/ — library code not user-authored (Plane FP P6, 2026-05-12)
        if (isSeedFixtureFile) continue; // seed/fixture/sample-data files — credentials and high-entropy IDs by design (Cal.com CC1, Documenso D1+D3, 2026-05-12)
        // Policy change 2026-05-11: previously surfaced CRITICAL secrets in
        // test files (PRIVATE_KEY_PEM, GITHUB_TOKEN, etc.) on the theory that
        // "real prod keys do leak via test fixtures." In practice, measured
        // FPs at octokit-rest test/integration/authentication.test.ts:163
        // (deliberately-generated test RSA keys) caused customer-visible
        // noise. The rare prod-key-in-test leak is better caught by git
        // pre-commit hooks scanning staged content + secret-rotation
        // policies, not by SAST flagging every test fixture.
        // See docs/plans/2026-05-11-engine-fp-baseline.md.
        if (
          isExampleConfigFile &&
          !["HIGH", "CRITICAL"].includes(rule.severity)
        )
          continue;
        const match = rule.pattern.exec(line);
        if (!match) continue;
        // OpenAPI / JSON-schema / TypeScript-decorator example fields:
        // `example: "<token-shape string>"` and `default: "<token-shape>"` are
        // schema documentation metadata, not real credentials. Same for
        // @ApiProperty({ example: "..." }) decorator arguments. Suppress here
        // before checking the assigned value. Also covers the nested-object
        // form `@ApiProperty({ example: { clientSecret: "..." } })` — backward
        // window detects the enclosing example/@ApiProperty on a prior line.
        const isOpenApiFile =
          /\bApiProperty|swagger|openapi|@ApiProperty|@Schema/i.test(
            context.content,
          );
        if (isOpenApiFile) {
          if (
            /(?:^|[\s{,(])(?:example|default|defaultValue|sample|mock)\s*:\s*['"`{[]/.test(
              line,
            )
          )
            continue;
          const openApiBackWindow = context.lines
            .slice(Math.max(0, index - 4), index)
            .join("\n");
          if (
            /@ApiProperty\s*\(|(?:^|[\s{,(])(?:example|default|defaultValue|sample|mock)\s*:\s*\{/.test(
              openApiBackWindow,
            )
          )
            continue;
        }
        // Generated `.env`-template strings: an outer-quoted envelope holds
        // a `KEY="<value>"` pair where the value is a non-credential URI
        // (file:, loopback hosts, etc.). Catches lines like
        // `content += 'DATABASE_URL="file:./db.sqlite"';` where
        // extractAssignedStringLiteral would return only `DATABASE_URL=`.
        // Measured 2026-05-10: create-t3-app cli/src/installers/envVars.ts FP.
        if (/=\s*"file:[^"]+"/i.test(line)) continue;
        if (
          /=\s*"(?:postgres(?:ql)?|mysql|mongodb|redis):\/\/[^"@]*@(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^"]*"/i.test(
            line,
          )
        )
          continue;

        const assignedSecretValue = extractAssignedStringLiteral(line);
        if (assignedSecretValue) {
          if (PLACEHOLDER_REGEX.test(assignedSecretValue)) continue;
          if (MARKER_STRING_REGEX.test(assignedSecretValue)) continue;
          if (hasLowSecretEntropy(assignedSecretValue)) continue;
          if (looksLikeRegexSourceString(assignedSecretValue)) continue; // T3
          if (/^file:/i.test(assignedSecretValue)) continue;
          if (
            /^(?:postgres(?:ql)?|mysql|mongodb|redis):\/\/[^@]*@(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?\b/i.test(
              assignedSecretValue,
            )
          )
            continue;
        }

        // For GENERIC_SECRET, apply extra FP guards
        if (rule.id === "GENERIC_SECRET") {
          const rhsMatch = line.match(/[:=]\s*['"`]([^'"`]{12,})['"`]/);
          if (rhsMatch) {
            const val = rhsMatch[1];
            if (PLACEHOLDER_REGEX.test(val)) continue;
            if (MARKER_STRING_REGEX.test(val)) continue;
            if ((val.match(/ /g) || []).length > 2) continue;
            if (/^[A-Za-z][A-Za-z .'":,!?-]+$/.test(val)) continue;
          }
          // Algolia search-only API keys are public by design — embedded in
          // client-side code so the docs site can do search. The shape is
          // `{ appId: "...", apiKey: "..." }` (or `applicationId:` variant).
          // When the same const/object literal contains an appId field,
          // suppress the apiKey match. Measured 2026-05-10: create-t3-app
          // www/src/config.ts FP.
          const algoliaWindow = context.lines
            .slice(
              Math.max(0, index - 4),
              Math.min(context.lines.length, index + 5),
            )
            .join("\n");
          if (
            /\b(?:appId|applicationId|ALGOLIA)\b/.test(algoliaWindow) &&
            /\bapiKey\s*:/.test(line)
          )
            continue;
        }

        // Example/placeholder guard applied to the MATCHED TOKEN itself, not
        // just to an assigned literal. The placeholder check above only ran on
        // extractAssignedStringLiteral (a key="value" shape), so a documented
        // example token inside an ARRAY/allowlist — e.g. ["AKIAIOSFODNN7EXAMPLE"]
        // — bypassed it and fired. Suppress AWS's documented example key
        // (AKIA...EXAMPLE) and any matched token that is itself a placeholder.
        // Closes secretlint (AWS EXAMPLE key in its own allowlist) + read-frog
        // public-token FPs from the 2026-05-30 partner scan.
        if (isWellKnownExampleSecret(match[0])) {
          break;
        }

        foundSecretCategories.add(rule.id);
        matchedNamedSecret = true;
        const column = match.index;
        issues.push(
          formatIssue({
            line: index + 1,
            column,
            endLine: index + 1,
            endColumn: column + match[0].length,
            severity: rule.severity,
            category: "HARDCODED_SECRET",
            message: rule.message,
            impact: rule.impact,
            snippet: line.trim(),
            context: getContextLines(context.lines, index, 2),
          }),
        );
        break; // one finding per line per priority order
      }

      // Entropy scan: find quoted strings ≥ 20 chars with high entropy
      if (
        matchedNamedSecret ||
        isTestFile ||
        isBenchDir ||
        isExampleConfigFile ||
        isLocaleFile ||
        isVendoredBundle ||
        isSeedFixtureFile
      )
        return;
      // JSX `data-*=` attributes hold third-party publishable IDs (Plausible,
      // Meticulous, PostHog, Segment, etc.) that happen to be high-entropy
      // by design. Attribute name prefix `data-` is the convention.
      if (/\bdata-[a-z][a-z0-9-]*\s*=\s*['"`]/.test(line)) return;
      // OpenAPI nested example blocks: `@ApiProperty({ example: { k: "..." } })`.
      // Entropy scan would hit the inner string without this — the SECRET_PATTERNS
      // loop above suppresses the named-secret form; this mirrors it for entropy.
      const openApiBackWindow = context.lines
        .slice(Math.max(0, index - 4), index)
        .join("\n");
      if (
        /\bApiProperty|swagger|openapi|@ApiProperty|@Schema/i.test(
          context.content,
        ) &&
        /@ApiProperty\s*\(|(?:^|[\s{,(])(?:example|default|defaultValue|sample|mock)\s*:\s*\{/.test(
          openApiBackWindow,
        )
      )
        return;
      // nanoid `customAlphabet(alphabet, size)` takes a high-entropy alphabet
      // string as its first argument. The alphabet may sit on the same line
      // or on the next line in a multi-line call. Suppress the entropy scan
      // when the import or call is in scope.
      if (/\bcustomAlphabet\s*\(/.test(line)) return;
      const customAlphabetBackWindow = context.lines
        .slice(Math.max(0, index - 2), index)
        .join("\n");
      if (/\bcustomAlphabet\s*\(\s*$/.test(customAlphabetBackWindow)) return;
      const quotedStrings = line.matchAll(/['"`]([^'"`\s]{20,})['"`]/g);
      for (const qm of quotedStrings) {
        const val = qm[1];
        if (PLACEHOLDER_REGEX.test(val)) continue;
        if (/[()[\]{}:;,%/]/.test(val)) continue; // paths, URLs, module names, etc.
        if (/^[a-z]+[A-Z]+[0-9]*[$_]*$/.test(val) && val.length > 30) continue; // sequential char enumerations (abcde...XYZ0-9$_)
        if (/[^\x00-\x7F]/.test(val) && /_/.test(val)) continue; // non-ASCII underscore-delimited strings (locale word lists, e.g. month names)
        if (/^phc_[A-Za-z0-9]+$/.test(val)) continue; // PostHog publishable client key — designed to ship in browser bundle
        if (/^s2s\.[a-z0-9]+\.[a-z0-9]+$/i.test(val)) continue; // Jitsu server-to-server publishable telemetry key — designed to ship in browser bundle (Cal.com FP CC3, 2026-05-12)
        if (/^\d+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(val))
          continue; // Google OAuth client ID — public by OAuth spec (Plane FP P4, 2026-05-12). Anchored at end to prevent attacker-domain suffix tricks.
        // Google Client Secret form-placeholder (Plane FP v5-A, 2026-05-13).
        // Two-condition skip: line context is `placeholder:` field assignment AND
        // value matches GOCSPX-shape (lenient on typo neighbors per Plane's GOCShX-:
        // [Ss] covers case typos, [PpHh] covers P/H swap typo).
        // The GOOGLE_OAUTH_SECRET named pattern at line 159 still fires on real
        // GOCSPX- assignments outside placeholder context — see test cases.
        if (
          /^\s*placeholder:\s*['"`]/.test(line) &&
          /^GOC[Ss][PpHh]X-[A-Za-z0-9_-]+$/.test(val)
        )
          continue;
        if (!looksLikeSecret(val)) continue;
        if (foundSecretCategories.has("HIGH_ENTROPY_SECRET")) continue;
        foundSecretCategories.add("HIGH_ENTROPY_SECRET");
        issues.push(
          formatIssue({
            line: index + 1,
            column: qm.index,
            endLine: index + 1,
            endColumn: qm.index + qm[0].length,
            severity: "HIGH",
            category: "HARDCODED_SECRET",
            message: `High-entropy string detected (entropy=${shannonEntropy(val).toFixed(2)}); may be a hardcoded secret.`,
            impact: 8,
            snippet: line.trim(),
            context: getContextLines(context.lines, index, 2),
          }),
        );
      }
    });
  }

  // ── Python-specific security rules ──────────────────────────────────────
  if (context.language === "python" && !isTestFile && !isDocFile) {
    const pyRules = [
      {
        pattern: /\beval\s*\(/,
        category: "EVAL_USAGE",
        severity: "HIGH",
        impact: 8,
        message:
          "Avoid eval() in Python; use ast.literal_eval() for safe data parsing.",
        // G3a guard (2026-05-19): suppress when PYTHONSTARTUP appears in
        // ±10-line backward / ±3-line forward context — this is the Flask
        // shell's documented behavior of executing the user's local
        // startup script, not request-derived code execution. Wider back
        // window catches enclosing function signatures.
        // Closes Codex FP at flask/cli.py:1023.
        // Source: docs/plans/2026-05-19-lang-canary-baseline.md Recommended Step 1.
        guard: (line, idx, lines) => {
          const start = Math.max(0, idx - 10);
          const end = Math.min(lines.length - 1, idx + 3);
          for (let i = start; i <= end; i++) {
            if (/\bPYTHONSTARTUP\b/.test(lines[i])) return true;
          }
          return false;
        },
      },
      {
        pattern: /\bexec\s*\(/,
        category: "COMMAND_EXEC",
        severity: "HIGH",
        impact: 9,
        message:
          "exec() executes arbitrary code; avoid or sanitize all inputs strictly.",
        // G3a + G3b guards (2026-05-19): suppress when PYTHONSTARTUP is in
        // context (Flask shell lifecycle) OR when the surrounding code is
        // a from_pyfile/from_file framework config loader. Closes Codex
        // FPs at flask/cli.py:1023 (PYTHONSTARTUP) and flask/config.py:209
        // (from_pyfile is Flask's documented config mechanism, not RCE).
        // Source: docs/plans/2026-05-19-lang-canary-baseline.md Recommended Step 1.
        // Wider backward window (10 lines) to catch enclosing function
        // signature like `def from_pyfile(...)`; tighter forward window
        // (3 lines) to keep guard scope local.
        guard: (line, idx, lines) => {
          const start = Math.max(0, idx - 10);
          const end = Math.min(lines.length - 1, idx + 3);
          for (let i = start; i <= end; i++) {
            if (/\bPYTHONSTARTUP\b/.test(lines[i])) return true;
            if (/\bfrom_pyfile\b|\bfrom_file\b/.test(lines[i])) return true;
          }
          return false;
        },
      },
      {
        pattern: /\bos\.system\s*\(/,
        category: "COMMAND_EXEC",
        severity: "HIGH",
        impact: 9,
        message:
          "os.system() is vulnerable to shell injection; use subprocess with a list of args.",
      },
      {
        pattern: /\bsubprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True/,
        category: "COMMAND_EXEC",
        severity: "HIGH",
        impact: 9,
        message:
          "subprocess with shell=True is vulnerable to injection; use shell=False with a list.",
      },
      {
        pattern: /\bpickle\.loads?\s*\(/,
        category: "INSECURE_DESERIALIZATION",
        severity: "HIGH",
        impact: 9,
        message:
          "pickle.load() can execute arbitrary code; never unpickle untrusted data.",
      },
      {
        // R1 (2026-05-19): yaml.load is unsafe by default. Pre-fix regex used
        // `(?!.*Loader)` which incorrectly SUPPRESSED `yaml.load(d, Loader=yaml.Loader)`
        // (the explicitly dangerous form). Replaced with a positive-match shape:
        // emit if the call does NOT contain SafeLoader or safe_load on the same line.
        // Also catches yaml.unsafe_load() (added in PyYAML 5.1 as an explicit
        // opt-in to the previous default).
        // CVE class: pre-PyYAML-5.1 default-loader RCEs (CWE-502).
        // Source: docs/plans/2026-05-19-lang-canary-adversarial-fn-opus.md §7 Tier-1 #3.
        pattern: /\byaml\.(?:unsafe_load|load)\s*\(/,
        category: "INSECURE_DESERIALIZATION",
        severity: "HIGH",
        impact: 8,
        message:
          "yaml.load()/yaml.unsafe_load() can execute arbitrary code via tagged YAML; use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
        guard: (line) => {
          // Suppress only when the call site explicitly opts into SafeLoader
          // — both `yaml.safe_load(...)` and `yaml.load(..., Loader=yaml.SafeLoader)`
          // are safe. `Loader=yaml.Loader` / `Loader=Loader` / no `Loader=` are unsafe.
          if (/\byaml\.safe_load\s*\(/.test(line)) return true;
          if (/\bLoader\s*=\s*(?:yaml\.)?SafeLoader\b/.test(line)) return true;
          // FullLoader is also documented as safer than Loader (post-5.1 default).
          if (/\bLoader\s*=\s*(?:yaml\.)?FullLoader\b/.test(line)) return true;
          return false;
        },
      },
      {
        pattern: /\bcursor\.execute\s*\(\s*[f'""].*%.*['""]\s*%/,
        category: "SQL_INJECTION",
        severity: "HIGH",
        impact: 10,
        message:
          "String-formatted SQL query; use parameterized queries (?, %s) instead.",
      },
      {
        pattern: /\bcursor\.execute\s*\(\s*f['"]/,
        category: "SQL_INJECTION",
        severity: "HIGH",
        impact: 10,
        message:
          "f-string interpolated SQL query is vulnerable to SQL injection.",
      },
      {
        pattern: /\b__import__\s*\(/,
        category: "DYNAMIC_IMPORT",
        severity: "MEDIUM",
        impact: 7,
        message:
          "__import__() with dynamic strings can load arbitrary modules.",
      },
      {
        pattern: /\bgetattr\s*\(\s*\w+\s*,\s*(?:request|input|argv|environ)/,
        category: "DYNAMIC_ATTRIBUTE",
        severity: "HIGH",
        impact: 8,
        message:
          "Dynamic attribute access from user input can lead to property injection.",
        // G3c guard (2026-05-19): suppress when the second argument is
        // `request.method` / `request.method.lower()` — these are
        // constrained by Flask/Django to HTTP verb names (GET|POST|PUT|...)
        // and the resulting attribute lookup is framework dispatch (e.g.
        // class-based views calling `getattr(self, request.method.lower())`).
        // Closes Codex FP at flask/views.py:183.
        // Source: docs/plans/2026-05-19-lang-canary-baseline.md Recommended Step 2.
        guard: (line) => {
          return /\bgetattr\s*\([^,]+,\s*request\.method\b/.test(line);
        },
      },
    ];

    context.lines.forEach((line, index) => {
      const normalized = line.trim();
      if (!normalized || /^\s*#/.test(normalized)) return; // skip comments

      for (const rule of pyRules) {
        const match = rule.pattern.exec(line);
        if (!match) continue;
        if (hasSuppressionDirective(context.lines, index, rule.category))
          continue;
        // G3 guards (2026-05-19): per-rule context check returning `true`
        // suppresses a confirmed-FP shape. Rules without a `guard` always
        // emit on match.
        if (
          typeof rule.guard === "function" &&
          rule.guard(line, index, context.lines)
        )
          continue;
        const col = match.index;
        issues.push(
          formatIssue({
            line: index + 1,
            column: col,
            endLine: index + 1,
            endColumn: col + match[0].length,
            severity: rule.severity,
            category: rule.category,
            message: rule.message,
            impact: rule.impact,
            snippet: normalized,
            context: getContextLines(context.lines, index, 2),
          }),
        );
        break; // one finding per line
      }
    });
  }

  // ── Go-specific security rules ────────────────────────────────────────────
  if (context.language === "go" && !isTestFile && !isDocFile) {
    const goRules = [
      {
        pattern:
          /\bexec\.Command\s*\(\s*(?:cmd|command|input|args|userInput|req)/,
        category: "COMMAND_EXEC",
        severity: "HIGH",
        impact: 9,
        message:
          "exec.Command with user-controlled input is vulnerable to command injection.",
      },
      {
        pattern:
          /\bfmt\.Sprintf\s*\(.*(?:query|sql|SELECT|INSERT|UPDATE|DELETE)/,
        category: "SQL_INJECTION",
        severity: "HIGH",
        impact: 10,
        message:
          "fmt.Sprintf used to build SQL query; use parameterized queries (?, $1) instead.",
      },
      {
        // Reading a secret from an env var is the RECOMMENDED 12-factor
        // practice — the literal opposite of a hardcoded secret. Categorizing
        // it HARDCODED_SECRET (2026-05-30 partner scan: 12 FPs in deep-chat
        // example-servers) reads as an obvious false alarm to any Go dev. This
        // is an informational advisory about secrets-manager adoption, not a
        // credential-in-source finding.
        pattern: /os\.Getenv\s*\(\s*["']\w*(?:SECRET|KEY|PASSWORD|TOKEN|API)/,
        category: "SECRET_FROM_ENV",
        severity: "LOW",
        impact: 3,
        message:
          "Secret read from an environment variable (good practice). For higher assurance, consider a managed secrets store with rotation.",
      },
    ];

    context.lines.forEach((line, index) => {
      const normalized = line.trim();
      if (!normalized || /^\s*\/\//.test(normalized)) return;

      for (const rule of goRules) {
        const match = rule.pattern.exec(line);
        if (!match) continue;
        if (hasSuppressionDirective(context.lines, index, rule.category))
          continue;
        const col = match.index;
        issues.push(
          formatIssue({
            line: index + 1,
            column: col,
            endLine: index + 1,
            endColumn: col + match[0].length,
            severity: rule.severity,
            category: rule.category,
            message: rule.message,
            impact: rule.impact,
            snippet: normalized,
            context: getContextLines(context.lines, index, 2),
          }),
        );
        break;
      }
    });
  }

  // ── Rust-specific security rules ─────────────────────────────────────────
  if (context.language === "rust" && !isTestFile && !isDocFile) {
    try {
      const rustIssues = analyzeRust(context.content, context.filePath);
      for (const r of rustIssues) {
        // Adapter-time suppression: filter on the surfaced finding line +
        // emitted category. Source-level suppression would hide downstream
        // sinks the sibling analyzer didn't surface.
        if (hasSuppressionDirective(context.lines, r.line - 1, r.category))
          continue;
        issues.push(
          formatIssue({
            line: r.line,
            column: r.column || 0,
            endLine: r.endLine || r.line,
            endColumn: r.endColumn || 0,
            severity: r.severity,
            category: r.category,
            message: r.message,
            impact: r.impact,
            snippet: r.snippet,
            context: getContextLines(context.lines, r.line - 1, 2),
          }),
        );
      }
    } catch (_) {}
  }

  // ── Java / PHP / C# security rules ───────────────────────────────────────
  if (!isTestFile && !isDocFile) {
    const langAnalyzers = [
      { lang: "java", fn: analyzeJavaSecurity },
      { lang: "php", fn: analyzePhpSecurity },
      { lang: "csharp", fn: analyzeCSharpSecurity },
    ];
    for (const { lang, fn } of langAnalyzers) {
      if (context.language !== lang) continue;
      try {
        const langIssues = fn(context.content, context.filePath);
        for (const r of langIssues) {
          // Adapter-time suppression by surfaced category (Java/PHP/C#
          // analyzers emit category=rule.id so this matches user intent).
          if (hasSuppressionDirective(context.lines, r.line - 1, r.category))
            continue;
          // B1 (2026-05-19): strip language prefix so emitted category matches
          // the canonical names in `classifyFinding`'s allowlist in
          // `packages/cli/src/lib/mvp.ts`. Pre-fix, every `JAVA_*` (and
          // structurally `PHP_*`/`CSHARP_*`) finding was silently filtered out
          // of the default CLI surface because the allowlist requires exact
          // canonical names (e.g. `COMMAND_INJECTION`, not `JAVA_COMMAND_INJECTION`).
          // Opus-2 §4.5 + Opus-1 confirmed empirically that every
          // JAVA_*-stripped name exists in the allowlist — blanket
          // prefix-strip is safe; no per-rule mapping needed.
          // See docs/plans/2026-05-19-lang-canary-engine-internals-opus.md §4.5.
          const canonicalCategory = r.category.replace(
            /^(?:JAVA_|PHP_|CSHARP_)/,
            "",
          );
          issues.push(
            formatIssue({
              line: r.line,
              column: r.column || 0,
              endLine: r.endLine || r.line,
              endColumn: r.endColumn || 0,
              severity: r.severity,
              category: canonicalCategory,
              message: r.message,
              impact: r.impact,
              snippet: r.snippet,
              context: getContextLines(context.lines, r.line - 1, 2),
            }),
          );
        }
      } catch (_) {}
    }
  }

  // ── AI-generated code risk rules ─────────────────────────────────────────
  // Targets patterns that LLMs produce frequently but that are insecure or broken.
  if (!isTestFile && !isDocFile && !isInfraExecFile && !isMinifiedFile) {
    const aiRules = [
      {
        id: "AI_CODE_RISK_EMPTY_CATCH",
        // LOW + impact 3: a bare empty catch is a code smell, not a security
        // vuln. At MEDIUM these dominated reports (126 in one repo, 2026-05-30
        // partner scan). At LOW/impact-3 it is DEFERRED from the default CLI
        // MVP contract (MIN_IMPACT_BY_SEVERITY.LOW=5) — i.e. it does NOT appear
        // on the default partner-facing CLI report. This is BY DESIGN (de-noise);
        // it still emits from the engine and surfaces via `--rawFindings` and on
        // the GitHub Action path (which has no impact gate), and is counted in
        // the report's deferredCategoryCounts (never silently dropped). It
        // remains a true positive; we just don't lead the default report with it.
        // (Clarified 2026-05-31 audit — prior "keep firing, ranked LOW" comment
        // was misleading about default-contract visibility.)
        severity: "LOW",
        // Match empty catch bodies — but exempt the `catch (_)` / `catch (_err)` convention
        // (ESLint no-unused-vars leading-underscore = intentional-ignore).
        // Matches: `catch {}`, `catch (err) {}`, `catch (err, ctx) {}`.
        // Skips:   `catch (_) {}`, `catch (_err) {}`, `catch (_: any) {}`.
        pattern: /catch\s*(?:\(\s*(?!_)[^)]*\))?\s*\{\s*\}/,
        message:
          "Empty catch block swallows errors — a common LLM pattern. Add error handling or logging.",
        impact: 3,
      },
      {
        id: "AI_CODE_RISK_PERMISSIVE_CORS",
        severity: "HIGH",
        pattern: /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['"`]\*['"`]/,
        message:
          "Wildcard CORS origin (*) allows any domain to access this resource. Restrict to trusted origins.",
        impact: 8,
      },
      {
        id: "AI_CODE_RISK_DEFAULT_CREDENTIALS",
        severity: "CRITICAL",
        // Only fire on password-shape keys (not `secret:` which is heavily
        // reused in test fixtures and config validation — e.g. playwright
        // `fillOtp({ page, secret: "123456" })`). A literal value of "admin"
        // or "123456" assigned to `password:` / `pwd:` / `passwd:` in
        // non-test code is a real risk; on `secret:` it's usually test OTP
        // or OAuth client-secret placeholder.
        //
        // Capture-group on the key name (match[1]) so the per-rule gate at
        // ~line 1378 can distinguish enum/constant identifiers (`PASSWORD =
        // "PASSWORD"` — all-caps SCREAMING_SNAKE_CASE) from real lowercase
        // credential assignments. Plane FP P1 from Week 2 baseline (2026-05-12).
        pattern:
          /(password|passwd|pwd)\s*[:=]\s*['"`](?:admin|password|123456|test|root|letmein|welcome|changeme|default)['"`]/i,
        message:
          "Default or example credential detected — frequently inserted by AI code generators.",
        impact: 10,
      },
      {
        id: "AI_CODE_RISK_CONSOLE_SENSITIVE",
        severity: "HIGH",
        pattern: /console\.(?:log|info|debug)\s*\(/,
        message:
          "Sensitive data logged to console — AI models often insert debug logging around credentials.",
        impact: 8,
      },
      {
        id: "AI_CODE_RISK_TODO_SECURITY",
        severity: "MEDIUM",
        // Match security-critical TODOs without over-matching benign keywords.
        // Bare `token` matches "design token" / "component token" (keystone v3
        // FP #2). Bare `auth` matches "author" / "authority". `validat` /
        // `sanitiz` are broad and rarely mark security-critical TODOs.
        // Replaced with qualified shapes:
        //   - `(?:jwt|api|access|...)[-_\s]*token` — anchors token to auth context
        //   - `bypass\s+(?:auth|security|check)` — explicit bypass markers
        //   - `disable[d]?\s+(?:auth|security|check)` — explicit disable markers
        //   - high-precision keywords kept: secret, password, credential,
        //     permission, encrypt, decrypt, signature, hmac, oauth, jwt, csrf,
        //     xss, sql injection, hardcod
        pattern:
          /\/\/\s*(?:TODO|FIXME|HACK)\s*[:\-]?\s*[^\n]*\b(?:secret|password|credential|permission|encrypt|decrypt|signature|hmac|oauth|jwt|csrf|xss|sql\s*injection|hardcod|bypass\s+(?:auth|security|check)|disable[d]?\s+(?:auth|security|check)|(?:jwt|api|access|refresh|bearer|csrf|session|auth)[-_\s]*token)\b/i,
        // Message text matches the rule's actual mechanism — flags TODOs
        // *containing* security keywords, not TODOs *located in* auth paths
        // (the rule has no path-based attribution).
        message:
          "Security-critical TODO/FIXME — placeholders for auth, encryption, or credentials should be resolved before merge.",
        impact: 7,
      },
      {
        id: "AI_CODE_RISK_HARDCODED_IV",
        severity: "HIGH",
        pattern:
          /(?:iv|nonce|salt)\s*[:=]\s*(?:Buffer\.from\s*\(\s*['"`][A-Fa-f0-9]{16,}['"`]|['"`][A-Fa-f0-9]{16,}['"`])/,
        message:
          "Hardcoded IV/nonce/salt for cryptographic operation. Always generate these randomly.",
        impact: 9,
      },
      {
        // Intentionally does NOT match `rejectUnauthorized: false` — that's
        // already flagged by CERT_VALIDATION_DISABLED (security-rules-extended)
        // at the same severity, so firing both creates duplicate noise on the
        // same line. This rule targets the other common spelling (`verify`)
        // used by requests-like HTTP clients and some SDK configs.
        id: "AI_CODE_RISK_SKIP_SSL_VERIFY",
        severity: "HIGH",
        pattern: /\bverify\s*[:=]\s*false\b/,
        message:
          'SSL/TLS verification disabled — dangerous in production, often added by AI for "quick testing".',
        impact: 9,
      },
    ];

    let inBlockComment = false;
    context.lines.forEach((line, index) => {
      const normalized = line.trim();
      if (!normalized) return;
      // Track multi-line block comment state (handles JSDoc /** ... */ blocks)
      if (inBlockComment) {
        if (normalized.includes("*/")) inBlockComment = false;
        return;
      }
      if (normalized.startsWith("/*")) {
        if (!normalized.includes("*/")) inBlockComment = true;
        return;
      }
      if (COMMENT_REGEX.test(normalized)) return;

      for (const rule of aiRules) {
        if (isTestFile) continue; // AI pattern rules fire heavily in test files — almost always FPs
        if (isMinifiedFile) continue; // dist/bundled files contain vendored code — not user-authored
        if (isLocaleFile) continue; // i18n/locale UI strings like "Password" / "Password forgot?" fire AI_CODE_RISK_DEFAULT_CREDENTIALS as FPs (Plane FP P2, 2026-05-12)
        if (isVendoredBundle) continue; // vendored PWA bundles — library code, not user-authored (2026-05-12)
        if (isSeedFixtureFile) continue; // seed/fixture/sample-data — credentials by design (2026-05-12)
        const match = rule.pattern.exec(line);
        if (!match) continue;
        if (
          rule.id === "AI_CODE_RISK_CONSOLE_SENSITIVE" &&
          !isSensitiveConsoleLog(line)
        )
          continue;
        // DEFAULT_CREDENTIALS: skip when the captured key name is all-caps —
        // SCREAMING_SNAKE_CASE convention marks enum members / env-var names,
        // NOT credential assignments (e.g. `PASSWORD = "PASSWORD"` in Plane's
        // EAuthSteps enum at apps/space/types/auth.ts:14 — the value happens
        // to match the allow-list literal but the all-caps key signals an
        // identifier marker, not a credential). Lowercase `password = "password"`
        // remains a real TP. Plane FP P1 from Week 2 baseline (2026-05-12).
        // Pre-flight grep across 5 corpus clones found zero MY_API_PASSWORD =
        // "default" instances, so SCREAMING_SNAKE_CASE env-var-shape false-
        // positives are theoretical — accept the trade-off.
        if (
          rule.id === "AI_CODE_RISK_DEFAULT_CREDENTIALS" &&
          match[1] === match[1].toUpperCase()
        )
          continue;
        // EMPTY_CATCH: suppress when the preceding try-block wraps a
        // well-known feature-detect API whose failure path is *supposed* to
        // be a silent fallback. These are not "LLM-pattern empty catches" —
        // they're the documented-correct way to use the browser/runtime API.
        if (rule.id === "AI_CODE_RISK_EMPTY_CATCH") {
          const tryBlock = context.lines
            .slice(Math.max(0, index - 8), index + 1)
            .join("\n");
          const isFeatureDetect =
            /\b(?:fs\.accessSync|structuredClone|matchMedia|atob|require\.resolve|localStorage\.(?:getItem|setItem|removeItem)|sessionStorage\.(?:getItem|setItem|removeItem)|navigator\.clipboard|document\.execCommand|performance\.mark|performance\.measure)\s*\(|\bawait\s+import\s*\(/.test(
              tryBlock,
            );
          if (isFeatureDetect) continue;
          // Allow explicit opt-out for cases the heuristic misses — use
          // sparingly and only when a throw would genuinely break the UX.
          // Marker must be on `//` line — same line as `catch`, the line
          // above, or the line below — preserving the existing 3-line window.
          if (
            hasSuppressionDirective(context.lines, index, "empty-catch", {
              sameLine: true,
              nextLine: true,
              requireLineCommentPrefix: true,
            })
          )
            continue;
          // Non-production code paths: CLI bootstrap probes, CI publish
          // scripts, package-manager version fetchers, codegen cache-signal
          // writers. These swallow by design — a thrown error means
          // "degraded UX," not "security incident."
          //
          // `/bootstrap/` and `/scripts/ci/` are generic path conventions.
          // `/fetch-engine/` and `/client-generator-js/` happen to be Prisma
          // package names; acceptable here because the names are descriptive
          // enough that false-suppression on an unrelated repo is low-risk
          // (the semantic match between name and code role carries the weight,
          // not the repo identity).
          const isNonProductionPath =
            /(?:^|\/)bootstrap\//.test(normalizedFilePath) ||
            /(?:^|\/)scripts\/ci\//.test(normalizedFilePath) ||
            /(?:^|\/)fetch-engine\//.test(normalizedFilePath) ||
            /(?:^|\/)client-generator-js\//.test(normalizedFilePath);
          if (isNonProductionPath) continue;
        }
        // PERMISSIVE_CORS: suppress when the finding sits inside the CORS
        // library's own default-options object literal (the library surface,
        // not a user deployment). File-path heuristic is strong: filename ends
        // in `cors/index.{js,ts}` and the surrounding lines contain
        // `const defaults` / `DEFAULT_OPTIONS` / `defaultConfig` near the match.
        if (rule.id === "AI_CODE_RISK_PERMISSIVE_CORS") {
          // CORS-library file shapes:
          //   - cors/index.{js,ts,mjs,cjs,jsx,tsx} (Hono H1: src/middleware/cors/index.ts)
          //   - <anywhere>/cors.{js,ts,mjs,cjs,jsx,tsx} (Documenso D2: apps/openpage-api/lib/cors.ts)
          //   - <anywhere>/cors/<name>.{ext} (sibling library shapes)
          // 2026-05-12: broadened from cors/index.[jt]sx only to also cover the
          // bare cors.[ext] filename pattern (Documenso D2) + extended .mjs/.cjs.
          const isCorsLibraryFile =
            /(?:^|[/\\])cors[/\\][^/\\]+\.[mc]?[jt]sx?$|(?:^|[/\\])cors\.[mc]?[jt]sx?$/i.test(
              normalizedFilePath,
            );
          if (isCorsLibraryFile) {
            const ctxBlock = context.lines
              .slice(Math.max(0, index - 5), index + 2)
              .join("\n");
            // Library-default surrounding-code shapes:
            //   - `const defaults` / `defaultOptions` / `defaultConfig` (existing, Documenso D2)
            //   - `const opts` / `let opts` / `var opts` (Hono H1: `const opts = { origin: '*', ..., ...options }`)
            // (Type annotations like `: CorsOptions` were considered but the
            // engine's context-line normalizer strips TS type annotations,
            // making them an unreliable signal here. const-defaults shape
            // alone covers both real Phase 1 Week 2 FPs.)
            if (
              /\b(?:const|let|var)\s+(?:default(?:s|Options|Config)?|opts)\b/i.test(
                ctxBlock,
              )
            )
              continue;
          }
        }
        if (hasSuppressionDirective(context.lines, index, rule.id)) continue;
        const col = match.index;
        issues.push(
          formatIssue({
            line: index + 1,
            column: col,
            endLine: index + 1,
            endColumn: col + match[0].length,
            severity: rule.severity,
            category: rule.id,
            message: rule.message,
            impact: rule.impact,
            snippet: normalized,
            context: getContextLines(context.lines, index, 2),
          }),
        );
        break; // one finding per line
      }
    });
  }

  // ── Taint analysis (source → sink data flow) ─────────────────────────────
  if (!isTestFile && !isDocFile && !isInfraExecFile) {
    try {
      const taintIssues = analyzeTaint(context.filePath, context.content);
      for (const t of taintIssues) {
        // Adapter-time suppression at the surfaced sink line. Per #226 plan:
        // do NOT suppress at taint-source discovery; that would hide multiple
        // downstream sinks with one suppression directive.
        if (hasSuppressionDirective(context.lines, t.line - 1, t.category))
          continue;
        issues.push(
          formatIssue({
            line: t.line,
            column: t.column || 0,
            endLine: t.line,
            endColumn: (t.column || 0) + (t.snippet?.length || 0),
            severity: t.severity,
            category: t.category,
            message: t.message,
            impact: t.impact,
            snippet: t.snippet,
            context: getContextLines(context.lines, t.line - 1, 2),
          }),
        );
      }
    } catch (_) {
      // Taint analysis is best-effort — never crash the main scan
    }
  }

  // ── Python taint analysis ──────────────────────────────────────────────────
  if (!isTestFile && !isDocFile && context.filePath.endsWith(".py")) {
    try {
      const pythonTaintIssues = analyzePythonTaint(
        context.content,
        context.filePath,
      );
      for (const t of pythonTaintIssues) {
        // Adapter-time suppression at the surfaced sink line.
        if (hasSuppressionDirective(context.lines, t.line - 1, t.category))
          continue;
        issues.push(
          formatIssue({
            line: t.line,
            column: t.column || 0,
            endLine: t.line,
            endColumn: (t.column || 0) + (t.snippet?.length || 0),
            severity: t.severity,
            category: t.category,
            message: t.message,
            impact: t.impact,
            snippet: t.snippet,
            context: getContextLines(context.lines, t.line - 1, 2),
          }),
        );
      }
    } catch (_) {
      // Best-effort
    }
  }

  // ── Supply chain / malicious pattern analysis ─────────────────────────────
  // Detects obfuscation, exfiltration channels, Trojan Source, dynamic require
  try {
    const scIssues = analyzeSupplyChain(context.filePath, context.content, {
      isTestFile,
    });
    for (const sc of scIssues) {
      // Adapter-time suppression at the surfaced finding line + exact emitted
      // category. Supply-chain categories include high-impact malware classes
      // — do NOT widen to allowAnyCodetitan here.
      if (hasSuppressionDirective(context.lines, sc.line - 1, sc.category))
        continue;
      issues.push(
        formatIssue({
          line: sc.line,
          column: sc.column || 0,
          endLine: sc.endLine || sc.line,
          endColumn:
            sc.endColumn || (sc.column || 0) + (sc.snippet?.length || 0),
          severity: sc.severity,
          category: sc.category,
          message: sc.message,
          impact: sc.impact,
          snippet: sc.snippet,
          context: getContextLines(context.lines, sc.line - 1, 2),
        }),
      );
    }
  } catch (_) {
    // Supply chain analysis is best-effort — never crash the main scan
  }

  // ── Extended security rules (120 additional patterns) ────────────────────
  let extInBlockComment = false;
  context.lines.forEach((line, index) => {
    const normalized = line.trim();
    if (!normalized) return;
    // Track multi-line block comments (handles JSDoc /** ... */ blocks with
    // markdown code fences inside, common in TS libraries like got/axios).
    if (extInBlockComment) {
      if (normalized.includes("*/")) extInBlockComment = false;
      return;
    }
    if (normalized.startsWith("/*")) {
      if (!normalized.includes("*/")) extInBlockComment = true;
      return;
    }
    if (COMMENT_REGEX.test(normalized)) return;

    EXTENDED_SECURITY_RULES.forEach((rule) => {
      if (rule.skipTest && isTestFile) return;
      if (rule.skipDoc && isDocFile) return;
      if (isLocaleFile) return; // i18n/locale text data — all extended pattern rules are structural FPs here (2026-05-12)
      if (isVendoredBundle) return; // vendored PWA bundles — library code (2026-05-12)
      if (isSeedFixtureFile) return; // seed/fixture/sample-data files (2026-05-12)
      if (isInfraExecFile) return; // engine infra files intentionally contain dangerous patterns
      if (rule.filePathPattern && !rule.filePathPattern.test(context.filePath))
        return;
      if (isRuleMetadataLine(normalized)) return;

      // fileRequires: a regex that MUST match the whole file for the rule to
      // be eligible. Use for rules whose pattern is ambiguous without context
      // (e.g. `credentials: true` is CORS-risky ONLY when a CORS signal is
      // present in the file — otherwise it's a Prisma include or fetch option).
      if (rule.fileRequires && !rule.fileRequires.test(context.content)) return;

      // fileGuard: a regex that, if it matches the whole file, suppresses the rule.
      // Use this to avoid false positives when a mitigation exists elsewhere in the file.
      if (rule.fileGuard && rule.fileGuard.test(context.content)) return;

      // lineGuard: a regex that, if it matches the current line, suppresses the rule.
      // Use this for inline mitigations (e.g. a SQL escaper wrapping the interpolation).
      if (rule.lineGuard && rule.lineGuard.test(line)) return;

      // SQL_INJECTION per-interpolation refinement (NOT a wider lineGuard — a
      // regex .test() would suppress the WHOLE line on its first safe match,
      // hiding `SELECT ${req.query.t} FROM ${SAFE_CONST}`, a real injection).
      // Suppress ONLY when EVERY ${...} interpolation is provably safe:
      //   - an UPPER_SNAKE constant / const-map access (${MAX_ROWS}, ${TABLE_NAMES[t]})
      // A bare lowercase local (${tableName}) or req./user-input interpolation
      // keeps the finding firing. Closes MikroORM/oh-my-pi const-identifier FPs
      // (2026-05-30 partner scan); intentionally NARROW per the audit — does
      // NOT attempt a backward-provenance taint trace (that is its own change).
      if (
        rule.id === "SQL_INJECTION_STRING_FORMAT" &&
        allSqlInterpolationsAreConstantIdentifiers(line)
      ) {
        return;
      }

      // Maintainer-acknowledged suppression comments on the previous line.
      // If the line above carries a biome-ignore / eslint-disable / codetitan-
      // suppress directive, the maintainer has already reviewed the pattern;
      // re-flagging it is noise. Look only one line back to avoid distance-
      // based false suppression. Accepts any non-space token after
      // codetitan-suppress: (preserves custom markers like
      // `codetitan-suppress: my-custom-marker`) plus recognized biome /
      // eslint security-rule disables.
      if (
        hasSuppressionDirective(context.lines, index, [], {
          allowAnyCodetitan: true,
          includeToolSuppressions: true,
        })
      )
        return;

      // SENSITIVE_DATA_CONSOLE_LOG: the rule's pattern matches any keyword
      // inside a console.log, including informational string-literal text like
      // `console.log('Checking for hardcoded secrets...')`. Suppress when the
      // sensitive keyword only appears inside quoted strings — real leaks are
      // variable refs that survive `stripQuotedStrings`.
      if (rule.id === "BEARER_TOKEN_LOGGED") {
        // Require the credential keyword to appear OUTSIDE any quoted strings
        // — that is, as a variable reference or property access, not as
        // message text. The pre-fix rule fired on lines like
        //   log.debug("Attempting to authorize using JWT auth")
        // where "JWT" is purely a description of what the code is about to do,
        // no token being logged.
        const codeOnly = stripQuotedStrings(line);
        if (
          !/\bauthorization\b|\bbearer\b|\bjwt\b|\b(?:access|id|refresh|session|api|bearer|auth)Token\b/i.test(
            codeOnly,
          )
        )
          return;
        // Also exempt boolean-coercion patterns: `!!accessToken`, `Boolean(accessToken)`,
        // `hasToken: !!accessToken`. These log truthiness, not the token value.
        // Detect by checking each token ref is adjacent to `!!` or inside `Boolean(`.
        const tokenMatches =
          codeOnly.match(
            /\b(?:access|id|refresh|session|api|bearer|auth)Token\b/gi,
          ) || [];
        if (tokenMatches.length > 0) {
          const everyTokenCoerced = tokenMatches.every((tok) => {
            const idx = codeOnly.indexOf(tok);
            const prefix = codeOnly.slice(Math.max(0, idx - 16), idx);
            return /!!\s*$|Boolean\s*\(\s*$/.test(prefix);
          });
          if (everyTokenCoerced) return;
        }
      }
      if (rule.id === "SENSITIVE_DATA_CONSOLE_LOG") {
        // Same redaction-helper exemption as AI_CODE_RISK_CONSOLE_SENSITIVE
        // (see REDACTED_LOG_CALL_REGEX). If the call wraps a redactor with a
        // redaction-flag literal, the secret is masked before output.
        if (REDACTED_LOG_CALL_REGEX.test(line)) return;
        const codeOnly = stripQuotedStrings(line);
        if (
          !/password|passwd|ssn|creditCard|cvv|privateKey|secret|authToken/i.test(
            codeOnly,
          )
        )
          return;
        // Narrow suppression: only skip when the ONLY sensitive-keyword tokens
        // are AGGREGATION containers (counts, totals, stats). A variable or
        // property named `apiSecret` / `myAuthToken` may hold the actual secret
        // value, so we deliberately DO NOT suppress on compound-tail alone.
        // Suppress only when every match is preceded by an aggregation hint
        // (`stats.`, `counts.`, `total`, `num`, `count`, `found`, `detected`)
        // or has the canonical count-container tail (`...Secrets`, `...Passwords`).
        const allMatches =
          codeOnly.match(
            /\b\w*(?:password|passwd|ssn|creditCard|cvv|privateKey|secret|authToken)\w*\b/gi,
          ) || [];
        if (allMatches.length > 0) {
          const everyMatchLooksAggregate = allMatches.every((m) => {
            // Pluralized forms are almost always count containers: `hardcodedSecrets`, `apiPasswords`
            if (/(?:Secrets|Passwords)$/.test(m)) return true;
            // Otherwise require an aggregation prefix in the compound name
            return /^(?:total|num|count|found|detected|stats?|counts?|has|is|n)\w*(?:Password|Passwd|Ssn|SSN|CreditCard|Cvv|CVV|PrivateKey|Secret|AuthToken)$/.test(
              m,
            );
          });
          if (everyMatchLooksAggregate) return;
        }
      }

      const match = rule.pattern.exec(line);
      if (!match) return;

      const column = match.index;
      const matchLength = match[0].length;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: rule.severity,
          category: rule.id,
          message: rule.message,
          impact: rule.impact,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
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
    // A0 (2026-05-19): Django uses UPPERCASE on request attributes
    // (`request.GET/POST/COOKIES/META/FILES`). Without this, every Django
    // app produced zero taint findings regardless of vulnerability density.
    // Opus-2 §3.2 documented; Opus-1 fixtures #py-django-* validate.
    /\brequest\.(GET|POST|COOKIES|META|FILES)\b/,
    /\brequest\.get\s*\(/,
    /os\.environ\.get\s*\(/,
    /os\.getenv\s*\(/,
    /\binput\s*\(/,
    /sys\.argv\b/,
  ];

  const PY_SINKS = [
    {
      pattern: /\bexecute\s*\(/,
      category: "TAINT_SQL_INJECTION",
      severity: "HIGH",
      impact: 9,
      message:
        "Python: tainted user input in SQL execute() — use parameterized queries.",
    },
    {
      pattern: /\bexecutemany\s*\(/,
      category: "TAINT_SQL_INJECTION",
      severity: "HIGH",
      impact: 9,
      message:
        "Python: tainted user input in SQL executemany() — use parameterized queries.",
    },
    {
      pattern:
        /\bos\.system\s*\(|\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(/,
      category: "TAINT_COMMAND_INJECTION",
      severity: "HIGH",
      impact: 10,
      message:
        "Python: tainted user input in subprocess/os.system — command injection risk.",
    },
    {
      pattern: /\beval\s*\(/,
      category: "TAINT_EVAL",
      severity: "HIGH",
      impact: 10,
      message: "Python: tainted user input in eval().",
    },
    {
      pattern: /\bexec\s*\(/,
      category: "TAINT_EVAL",
      severity: "HIGH",
      impact: 9,
      message: "Python: tainted user input in exec().",
    },
    {
      pattern: /\bopen\s*\(/,
      category: "TAINT_PATH_TRAVERSAL",
      severity: "HIGH",
      impact: 9,
      message: "Python: tainted user input in open() — path traversal risk.",
    },
    {
      pattern: /\brender_template_string\s*\(/,
      category: "TAINT_TEMPLATE_INJECTION",
      severity: "CRITICAL",
      impact: 10,
      message:
        "Python: tainted user input in render_template_string — SSTI vulnerability.",
    },
    {
      pattern: /\bpickle\.loads?\s*\(/,
      category: "TAINT_INSECURE_DESERIALIZATION",
      severity: "CRITICAL",
      impact: 10,
      message:
        "Python: tainted user input in pickle.load — arbitrary code execution.",
    },
    // R3 (2026-05-19): Python TAINT_SSRF sinks. Only fires when a tainted
    // variable (alias-propagated from PY_SOURCES like request.args.get)
    // reaches one of these HTTP-client sinks. The taint-pass infrastructure
    // already enforces "source must reach sink via tainted variable" — that
    // FP discipline carries over for free; we don't fire on hardcoded URLs
    // like `requests.get("https://api.example.com")`.
    // CVE class: SSRF (CWE-918) — Capital One 2019, plus any application
    // doing internal-network requests with user-controllable URLs.
    // Source: docs/plans/2026-05-19-lang-canary-adversarial-fn-opus.md §7 Tier-1 #1.
    {
      pattern:
        /\b(?:requests|httpx|aiohttp|urllib3|http)\.(?:get|post|put|patch|delete|head|options|request)\s*\(/,
      category: "TAINT_SSRF",
      severity: "HIGH",
      impact: 8,
      message:
        "Python: tainted user input in HTTP client (SSRF risk) — validate URL against an allowlist or restrict to expected hosts.",
    },
    {
      pattern: /\burllib\.request\.urlopen\s*\(/,
      category: "TAINT_SSRF",
      severity: "HIGH",
      impact: 8,
      message:
        "Python: tainted user input in urllib.request.urlopen (SSRF risk) — validate URL against an allowlist.",
    },
  ];

  const PY_SANITIZERS = [
    /\bint\s*\(/,
    /\bfloat\s*\(/,
    /\bstr\s*\(/,
    /\babs\s*\(/,
    /\.strip\s*\(/,
    /\bescape\s*\(/,
    /\bquote\s*\(/,
    /\bmarkup\s*\(/i,
    /\bvalidat/i,
    /\bsanit/i,
    /\bwhitelist\b/i,
    /\ballowlist\b/i,
    /,\s*\(.*\)\s*$/, // tuple param style: cursor.execute("... %s", (val,))
    /\bsafe_load\b/,
  ];

  const taintedVars = new Set();
  const taintedLineMap = new Map();

  // Pass 1: find tainted sources
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    // G3a guard (2026-05-19): PYTHONSTARTUP is a local-developer env
    // variable read by Flask's `flask shell` lifecycle, not request-derived
    // attacker input. Don't tag aliases of it as tainted. Closes the
    // TAINT_EVAL / TAINT_PATH_TRAVERSAL FPs Codex measured on flask/cli.py.
    // Source: docs/plans/2026-05-19-lang-canary-baseline.md Recommended Step 1.
    if (/\bPYTHONSTARTUP\b/.test(line)) return;
    for (const src of PY_SOURCES) {
      if (!src.test(line)) continue;
      const m = line.match(/\b(\w+)\s*=\s*.+/);
      if (m && m[1] !== "if" && m[1] !== "while") {
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
    if (!trimmed || trimmed.startsWith("#") || seen.has(idx)) return;
    for (const sink of PY_SINKS) {
      if (!sink.pattern.test(line)) continue;
      const foundVar = [...taintedVars].find((v) =>
        new RegExp(`\\b${v}\\b`).test(line),
      );
      if (!foundVar) continue;
      if (PY_SANITIZERS.some((s) => s.test(line))) continue;
      const ctx = lines.slice(Math.max(0, idx - 3), idx).join("\n");
      if (
        PY_SANITIZERS.some((s) => s.test(ctx)) &&
        new RegExp(`\\b${foundVar}\\b`).test(ctx)
      )
        continue;
      issues.push({
        line: idx + 1,
        column: 0,
        severity: sink.severity,
        category: sink.category,
        message: `${sink.message} Variable \`${foundVar}\` from user input (line ${taintedLineMap.get(foundVar) || "?"}).`,
        impact: sink.impact,
        snippet: trimmed,
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

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: "MEDIUM",
          category: "SYNC_IO",
          message:
            "Synchronous fs operation blocks the event loop. Consider async alternatives.",
          impact: 4,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // Sync file parse detection
    const syncFileParsePattern = /JSON\.parse\s*\(\s*fs\.readFileSync/;
    const syncFileParseMatch = syncFileParsePattern.exec(line);
    if (syncFileParseMatch) {
      const column = syncFileParseMatch.index;
      const matchLength = syncFileParseMatch[0].length;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: "MEDIUM",
          category: "SYNC_FILE_PARSE",
          message:
            "Parsing large files synchronously can block the event loop.",
          impact: 7,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // Await in loop detection
    const awaitInLoopPattern1 = /await\s+.*for\s*\(/;
    const awaitInLoopPattern2 = /for\s*\(.*\)\s*{[^}]*await/;
    const awaitInLoopMatch =
      awaitInLoopPattern1.exec(line) || awaitInLoopPattern2.exec(line);
    if (awaitInLoopMatch) {
      const column = awaitInLoopMatch.index;
      const matchLength = awaitInLoopMatch[0].length;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: "MEDIUM",
          category: "AWAIT_IN_LOOP",
          message:
            "Await inside loops runs sequentially; batch with Promise.all if possible.",
          impact: 5,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // Async timeout detection
    const asyncTimeoutPattern = /setTimeout\s*\(\s*async\s/;
    const asyncTimeoutMatch = asyncTimeoutPattern.exec(line);
    if (asyncTimeoutMatch && /await/.test(line)) {
      const column = asyncTimeoutMatch.index;
      const matchLength = asyncTimeoutMatch[0].length;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: "LOW",
          category: "ASYNC_TIMEOUT",
          message:
            "Async logic inside setTimeout can hide rejections; ensure errors surface.",
          impact: 2,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }
  });

  const content = context.content;
  const nestedLoopMatch =
    nestedLoopRegex.exec(content) || nestedWhileRegex.exec(content);
  if (nestedLoopMatch) {
    const firstLine = getLineNumber(context.content, nestedLoopMatch.index);
    const lineContent = context.lines[firstLine - 1] || "";
    const column = lineContent.indexOf(nestedLoopMatch[0].substring(0, 10)); // Find approximate column

    issues.push(
      formatIssue({
        line: firstLine,
        column: column >= 0 ? column : 0,
        endLine: firstLine,
        endColumn: column >= 0 ? column + 10 : 10,
        severity: "MEDIUM",
        category: "NESTED_LOOPS",
        message:
          "Nested loops detected; confirm complexity is acceptable for expected data size.",
        impact: 6,
        snippet: context.lines[firstLine - 1]?.trim() || "",
        context: getContextLines(context.lines, firstLine - 1, 2),
      }),
    );
  }

  return issues;
}

function detectTestingGaps(context) {
  const issues = [];
  const isTestFile = TEST_FILE_REGEX.test(context.filePath);

  // Suppress FOCUSED_TEST entirely when the file is testing a test-framework's
  // own `.only`/`.skip`/`.todo` API (Remix FP #5 from 2026-05-10 re-baseline:
  // `packages/test/src/test/framework.test.ts:88, 161` — describe('describe.only',
  // ...) blocks where `.only()` is the system-under-test). Detection is content-
  // based (file mentions `describe('describe.only'...)` or similar) so it
  // generalizes across any test framework's self-tests, not just Remix's.
  const isTestFrameworkSelfTest =
    /\b(?:describe|it|test|context|suite|each)\s*\(\s*['"`](?:describe|it|test|context|suite|each)\.(?:only|skip|todo|each|concurrent)\b/.test(
      context.content,
    );

  // Require a test-framework identifier before `.only(`. Bare `.only(` matches
  // React's `Children.only(...)` API (Hono FP #2 from 2026-05-10 re-baseline)
  // and any other library that exposes a method named `only`. Test runners
  // gate `.only()` on `describe|it|test|context|suite|each`-shaped callers.
  const focusedTestPattern =
    /\b(?:describe|it|test|context|suite|each)\s*\.\s*only\s*\(/;

  // Track JSDoc / block-comment state. Test-framework docs frequently embed
  // `describe.only(...)` examples inside `/** ... */` (Remix FP #4). Mirrors
  // the same state machine used by the AI-rules loop above.
  let inBlockComment = false;

  context.lines.forEach((line, index) => {
    const normalized = line.trim();

    // Block-comment state machine. FOCUSED_TEST and TODO_TESTS must NOT fire
    // on lines inside JSDoc `/** ... */` blocks — test-framework docs embed
    // `describe.only(...)` examples there (Remix FP #4 from 2026-05-10).
    let isCommentLine = false;
    if (inBlockComment) {
      if (normalized.includes("*/")) inBlockComment = false;
      isCommentLine = true;
    } else if (normalized.startsWith("/*")) {
      if (!normalized.includes("*/")) inBlockComment = true;
      isCommentLine = true;
    } else if (normalized.startsWith("*")) {
      // JSDoc continuation line (` * something`)
      isCommentLine = true;
    }
    // NOTE: `//` line-comments are NOT treated as `isCommentLine` here —
    // TODO_TESTS deliberately matches `// TODO: add tests for X`. The
    // FOCUSED_TEST check below has its own line-comment guard.

    // Focused test detection (.only) — anchored to test-framework callers.
    // Skip block-comment lines AND `//` line-comments (FOCUSED_TEST fires on
    // executable code, not comments). Skip entirely when the file is a
    // test-framework self-test (`.only` is the system-under-test).
    const focusedTestMatch =
      !isCommentLine && !normalized.startsWith("//") && !isTestFrameworkSelfTest
        ? focusedTestPattern.exec(line)
        : null;
    if (isTestFile && focusedTestMatch) {
      const column = focusedTestMatch.index;
      const matchLength = focusedTestMatch[0].length;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: "HIGH",
          category: "FOCUSED_TEST",
          message: "Remove .only() to avoid skipping other tests.",
          impact: 7,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }

    // TODO test detection
    const todoTestPattern = /TODO:?[\s-]*add tests/i;
    const todoTestMatch = todoTestPattern.exec(line);
    if (!isTestFile && todoTestMatch) {
      const column = todoTestMatch.index;
      const matchLength = todoTestMatch[0].length;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: column + matchLength,
          severity: "MEDIUM",
          category: "TODO_TESTS",
          message: "TODO indicates missing test coverage.",
          impact: 4,
          snippet: normalized,
          context: getContextLines(context.lines, index, 2),
        }),
      );
    }
  });

  if (
    !isTestFile &&
    context.exportedSymbols.length > 0 &&
    context.lines.length > 40 &&
    !context.hasCompanionTest
  ) {
    issues.push(
      formatIssue({
        line: 1,
        column: 0,
        endLine: 1,
        endColumn: 0,
        severity: "MEDIUM",
        category: "MISSING_TESTS",
        message: `No companion test file found for exported module "${context.exportedSymbols[0]}".`,
        impact: 5,
        snippet: path.basename(context.filePath),
        context: getContextLines(context.lines, 0, 2),
      }),
    );
  }

  return issues;
}

function detectRefactoringHotspots(context) {
  const issues = [];
  const { lines } = context;

  if (lines.length > 400) {
    issues.push(
      formatIssue({
        line: 1,
        column: 0,
        endLine: 1,
        endColumn: 0,
        severity: "MEDIUM",
        category: "FILE_TOO_LONG",
        message: `File is ${lines.length} lines. Consider splitting responsibilities.`,
        impact: 6,
        snippet: path.basename(context.filePath),
        context: getContextLines(lines, 0, 2),
      }),
    );
  }

  let longLineCount = 0;
  lines.forEach((line, index) => {
    if (line.length > 140 && longLineCount < 3) {
      // Find where the line exceeds 140 chars
      const column = 140;
      longLineCount++;

      issues.push(
        formatIssue({
          line: index + 1,
          column,
          endLine: index + 1,
          endColumn: line.length,
          severity: "LOW",
          category: "LONG_LINE",
          message:
            "Line exceeds 140 characters; break into smaller pieces for readability.",
          impact: 2,
          snippet: line.trim(),
          context: getContextLines(lines, index, 2),
        }),
      );
    }
  });

  detectLongFunctions(lines).forEach((fnIssue) => issues.push(fnIssue));

  return issues;
}

function detectDocumentationGaps(context) {
  const issues = [];
  const { commentLines, nonEmptyLines, exportedSymbols } = context;
  const commentRatio = nonEmptyLines === 0 ? 0 : commentLines / nonEmptyLines;

  if (exportedSymbols.length > 0 && commentRatio < 0.04 && nonEmptyLines > 50) {
    issues.push(
      formatIssue({
        line: 1,
        column: 0,
        endLine: 1,
        endColumn: 0,
        severity: "MEDIUM",
        category: "POOR_DOCUMENTATION",
        message:
          "Exported module lacks inline documentation. Add JSDoc or doc comments for maintainability.",
        impact: 4,
        snippet: exportedSymbols[0],
        context: getContextLines(context.lines, 0, 2),
      }),
    );
  }

  if (/README|docs|\.md$/i.test(context.filePath)) {
    return issues;
  }

  const firstCodeLine = context.trimmedLines.findIndex(
    (line) => line && !COMMENT_REGEX.test(line),
  );
  if (
    firstCodeLine > 0 &&
    !COMMENT_REGEX.test(context.trimmedLines[firstCodeLine - 1] || "")
  ) {
    const actualLine = context.lines[firstCodeLine] || "";

    issues.push(
      formatIssue({
        line: firstCodeLine + 1,
        column: 0,
        endLine: firstCodeLine + 1,
        endColumn: actualLine.length,
        severity: "LOW",
        category: "MISSING_HEADER",
        message:
          "Consider adding a module header comment to describe purpose and usage.",
        impact: 2,
        snippet: context.trimmedLines[firstCodeLine] || "",
        context: getContextLines(context.lines, firstCodeLine, 2),
      }),
    );
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
        matchLength: functionMatch[0].length,
      };
    }

    depth += openBraces - closeBraces;

    if (tracking && depth <= tracking.depthAtStart) {
      const length = index + 1 - tracking.startLine;
      if (length > 80) {
        issues.push(
          formatIssue({
            line: tracking.startLine,
            column: tracking.column,
            endLine: tracking.startLine,
            endColumn: tracking.column + tracking.matchLength,
            severity: "MEDIUM",
            category: "LONG_FUNCTION",
            message: `Function spans ${length} lines. Break it into focused helpers.`,
            impact: 4,
            snippet: lines[tracking.startLine - 1]?.trim() || "",
            context: getContextLines(lines, tracking.startLine - 1, 2),
          }),
        );
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
      `${name}.test${ext.replace(".", "")}`,
      `${name}.spec${ext.replace(".", "")}`,
    ];

    for (const candidate of candidateNames) {
      const sameDir = path.join(dir, candidate);
      if (fs.existsSync(sameDir)) {
        return true;
      }

      const testsDir = path.join(dir, "__tests__", candidate);
      if (fs.existsSync(testsDir)) {
        return true;
      }
    }
  } catch (_) {
    return false;
  }

  return false;
}

function formatIssue({
  line,
  column,
  endLine,
  endColumn,
  severity,
  category,
  message,
  impact,
  snippet,
  context,
}) {
  return {
    line,
    column: column !== undefined ? column : 0,
    endLine: endLine || line,
    endColumn:
      endColumn !== undefined
        ? endColumn
        : column !== undefined
          ? column + (snippet?.length || 0)
          : 0,
    severity,
    category,
    message,
    impact,
    snippet,
    context: context || [],
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
  // Helpers exported for testing + future detectors that need to honor the
  // same suppression / file-classification contracts (#226).
  hasSuppressionDirective,
  getSecurityFileFlags,
};
