/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ 755:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.exec = exports.github = exports.core = void 0;
const fs = __importStar(__nccwpck_require__(896));
const path = __importStar(__nccwpck_require__(928));
const child_process_1 = __nccwpck_require__(317);
function toInputEnvName(name) {
    return `INPUT_${String(name || '')
        .trim()
        .replace(/ /g, '_')
        .toUpperCase()}`;
}
function toInputEnvNameLegacy(name) {
    return `INPUT_${String(name || '')
        .trim()
        .replace(/ /g, '_')
        .replace(/-/g, '_')
        .toUpperCase()}`;
}
function escapeCommandValue(value) {
    return value
        .replace(/%/g, '%25')
        .replace(/\r/g, '%0D')
        .replace(/\n/g, '%0A');
}
function emitAnnotation(kind, message) {
    const text = String(message || '');
    if (process.env.GITHUB_ACTIONS === 'true') {
        process.stdout.write(`::${kind}::${escapeCommandValue(text)}\n`);
        return;
    }
    const target = kind === 'error' ? process.stderr : process.stdout;
    target.write(`${text}\n`);
}
function appendOutput(name, value) {
    const outputPath = process.env.GITHUB_OUTPUT;
    if (!outputPath) {
        return;
    }
    const text = String(value ?? '');
    if (text.includes('\n')) {
        const marker = `EOF_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        fs.appendFileSync(outputPath, `${name}<<${marker}\n${text}\n${marker}\n`, 'utf8');
        return;
    }
    fs.appendFileSync(outputPath, `${name}=${text}\n`, 'utf8');
}
function loadGitHubPayload() {
    const eventPath = process.env.GITHUB_EVENT_PATH;
    if (!eventPath || !fs.existsSync(eventPath)) {
        return {};
    }
    try {
        return JSON.parse(fs.readFileSync(eventPath, 'utf8'));
    }
    catch {
        return {};
    }
}
function getRepoFromPayload(payload) {
    if (payload?.repository?.owner?.login && payload?.repository?.name) {
        return {
            owner: payload.repository.owner.login,
            repo: payload.repository.name,
        };
    }
    const repository = String(process.env.GITHUB_REPOSITORY || '');
    const [owner = '', repo = ''] = repository.split('/');
    return { owner, repo };
}
function encodeGitHubPath(filePath) {
    return String(filePath || '')
        .replace(/\\/g, '/')
        .split('/')
        .filter(Boolean)
        .map((segment) => encodeURIComponent(segment))
        .join('/');
}
async function requestGitHub(token, method, pathname, body, query) {
    const url = new URL(pathname, process.env.GITHUB_API_URL || 'https://api.github.com');
    for (const [key, value] of Object.entries(query || {})) {
        if (value === undefined || value === null || value === '') {
            continue;
        }
        url.searchParams.set(key, String(value));
    }
    const response = await fetch(url, {
        method,
        headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
            'User-Agent': 'codetitan-github-action',
            'X-GitHub-Api-Version': '2022-11-28',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const responseText = await response.text();
    const parsed = responseText ? JSON.parse(responseText) : {};
    if (!response.ok) {
        const message = parsed?.message || responseText || `GitHub API request failed with status ${response.status}`;
        throw new Error(message);
    }
    return parsed;
}
function resolveCommand(commandLine) {
    if (process.platform === 'win32' && !path.extname(commandLine)) {
        return `${commandLine}.cmd`;
    }
    return commandLine;
}
function sanitizeEnv(env) {
    const source = env || process.env;
    const sanitized = {};
    for (const [key, value] of Object.entries(source)) {
        if (value === undefined || value === null) {
            continue;
        }
        sanitized[key] = String(value);
    }
    return sanitized;
}
exports.core = {
    getInput(name) {
        return (process.env[toInputEnvName(name)] ||
            process.env[toInputEnvNameLegacy(name)] ||
            '');
    },
    info(message) {
        process.stdout.write(`${String(message || '')}\n`);
    },
    warning(message) {
        emitAnnotation('warning', String(message || ''));
    },
    error(message) {
        emitAnnotation('error', String(message || ''));
    },
    setOutput(name, value) {
        appendOutput(name, value);
    },
    setFailed(message) {
        process.exitCode = 1;
        emitAnnotation('error', String(message || ''));
    },
};
exports.github = {
    get context() {
        const payload = loadGitHubPayload();
        return {
            payload,
            repo: getRepoFromPayload(payload),
        };
    },
    getOctokit(token) {
        return {
            rest: {
                issues: {
                    listComments: async ({ owner, repo, issue_number }) => ({
                        data: await requestGitHub(token, 'GET', `/repos/${owner}/${repo}/issues/${issue_number}/comments`),
                    }),
                    createComment: async ({ owner, repo, issue_number, body }) => ({
                        data: await requestGitHub(token, 'POST', `/repos/${owner}/${repo}/issues/${issue_number}/comments`, { body }),
                    }),
                    updateComment: async ({ owner, repo, comment_id, body }) => ({
                        data: await requestGitHub(token, 'PATCH', `/repos/${owner}/${repo}/issues/comments/${comment_id}`, { body }),
                    }),
                    addLabels: async ({ owner, repo, issue_number, labels }) => ({
                        data: await requestGitHub(token, 'POST', `/repos/${owner}/${repo}/issues/${issue_number}/labels`, { labels }),
                    }),
                },
                pulls: {
                    listFiles: async ({ owner, repo, pull_number, per_page, page }) => ({
                        data: await requestGitHub(token, 'GET', `/repos/${owner}/${repo}/pulls/${pull_number}/files`, undefined, {
                            per_page,
                            page,
                        }),
                    }),
                    create: async ({ owner, repo, title, body, head, base }) => ({
                        data: await requestGitHub(token, 'POST', `/repos/${owner}/${repo}/pulls`, {
                            title,
                            body,
                            head,
                            base,
                        }),
                    }),
                },
                git: {
                    getRef: async ({ owner, repo, ref }) => ({
                        data: await requestGitHub(token, 'GET', `/repos/${owner}/${repo}/git/ref/${ref}`),
                    }),
                    createRef: async ({ owner, repo, ref, sha }) => ({
                        data: await requestGitHub(token, 'POST', `/repos/${owner}/${repo}/git/refs`, { ref, sha }),
                    }),
                },
                repos: {
                    getContent: async ({ owner, repo, path: filePath, ref }) => ({
                        data: await requestGitHub(token, 'GET', `/repos/${owner}/${repo}/contents/${encodeGitHubPath(filePath)}`, undefined, { ref }),
                    }),
                    createOrUpdateFileContents: async ({ owner, repo, path: filePath, ...body }) => ({
                        data: await requestGitHub(token, 'PUT', `/repos/${owner}/${repo}/contents/${encodeGitHubPath(filePath)}`, body),
                    }),
                },
            },
        };
    },
};
exports.exec = {
    exec(commandLine, args = [], options = {}) {
        return new Promise((resolve, reject) => {
            const resolvedCommand = resolveCommand(commandLine);
            const useShell = process.platform === 'win32';
            const child = (0, child_process_1.spawn)(useShell ? commandLine : resolvedCommand, args, {
                cwd: options.cwd,
                env: sanitizeEnv(options.env),
                shell: useShell,
                stdio: ['ignore', 'pipe', 'pipe'],
                windowsHide: true,
            });
            child.stdout.on('data', (chunk) => {
                options.listeners?.stdout?.(chunk);
                if (!options.silent) {
                    process.stdout.write(chunk);
                }
            });
            child.stderr.on('data', (chunk) => {
                options.listeners?.stderr?.(chunk);
                if (!options.silent) {
                    process.stderr.write(chunk);
                }
            });
            child.on('error', reject);
            child.on('close', (code) => {
                if (code === 0) {
                    resolve(0);
                    return;
                }
                reject(new Error(`${commandLine} ${args.join(' ')} exited with code ${code}`.trim()));
            });
        });
    },
};


/***/ }),

/***/ 395:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.runCoreAnalysisWith = runCoreAnalysisWith;
exports.findBundledRepoRoot = findBundledRepoRoot;
exports.hasBundledCoreWorkspace = hasBundledCoreWorkspace;
exports.runActionAnalysis = runActionAnalysis;
const fs = __importStar(__nccwpck_require__(896));
const os = __importStar(__nccwpck_require__(857));
const path = __importStar(__nccwpck_require__(928));
const module_1 = __nccwpck_require__(339);
const action_kit_1 = __nccwpck_require__(755);
const SUPPORTED_EXTENSIONS = new Set([
    '.js',
    '.jsx',
    '.ts',
    '.tsx',
    '.cjs',
    '.mjs',
]);
const SKIP_DIRECTORIES = new Set([
    '.git',
    '.codetitan',
    '.codetitan-cache',
    '.next',
    '.turbo',
    '.vercel',
    'coverage',
    'dist',
    'build',
    'node_modules',
    'reports',
    'test-results',
]);
const FINDING_CLASSES = [
    'dangerous command execution',
    'unsafe SQL usage',
    'unsafe DOM / XSS patterns',
    'secret exposure',
    'auth / route protection gaps',
    'AI-generated-code risk checks',
    // Note: the classifier maps many additional security categories to the above
    // classes so they are surfaced rather than silently dropped.
];
const PUBLIC_CORE_PACKAGE = '@noalia/codetitan-core';
function sanitizeCacheKey(value) {
    const sanitized = String(value || 'default')
        .replace(/[^a-z0-9._-]+/gi, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 96);
    return sanitized || 'default';
}
function readJsonFile(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}
function getActionPackageRoot(startDir = __dirname) {
    let current = path.resolve(startDir);
    while (true) {
        const actionYaml = path.join(current, 'action.yml');
        const packageJson = path.join(current, 'package.json');
        if (fs.existsSync(actionYaml) && fs.existsSync(packageJson)) {
            return current;
        }
        const parent = path.dirname(current);
        if (parent === current) {
            return null;
        }
        current = parent;
    }
}
function getRuntimeRoot(runtimeKey) {
    if (process.env.CODETITAN_ACTION_RUNTIME_ROOT) {
        return path.resolve(process.env.CODETITAN_ACTION_RUNTIME_ROOT);
    }
    const actionRef = process.env.GITHUB_ACTION_REF ||
        process.env.GITHUB_SHA ||
        process.env.RUNNER_OS ||
        'local';
    return path.join(os.tmpdir(), 'codetitan-action-runtime', `${sanitizeCacheKey(runtimeKey)}-${sanitizeCacheKey(actionRef)}`);
}
function ensureRuntimeManifest(runtimeRoot) {
    fs.mkdirSync(runtimeRoot, { recursive: true });
    const packageJsonPath = path.join(runtimeRoot, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
        fs.writeFileSync(packageJsonPath, JSON.stringify({
            name: 'codetitan-action-runtime',
            private: true,
        }, null, 2), 'utf8');
    }
}
function extractPackedTarballName(packStdout) {
    const tarballName = packStdout
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .pop();
    if (!tarballName || !tarballName.endsWith('.tgz')) {
        throw new Error('npm pack did not return a package tarball name.');
    }
    return tarballName;
}
async function npmInstall(runtimeRoot, specifier) {
    ensureRuntimeManifest(runtimeRoot);
    await action_kit_1.exec.exec('npm', ['install', '--no-save', '--no-audit', '--no-fund', specifier], {
        cwd: runtimeRoot,
        silent: true,
        env: {
            ...process.env,
            npm_config_loglevel: 'error',
        },
    });
}
async function ensureBundledCoreRuntime(repoRoot) {
    const startedAt = Date.now();
    const corePackagePath = path.join(repoRoot, 'packages', 'core', 'package.json');
    const corePackage = readJsonFile(corePackagePath);
    const runtimeRoot = getRuntimeRoot(`${corePackage.name}-${corePackage.version}`);
    const installMarker = path.join(runtimeRoot, 'node_modules', '@noalia', 'codetitan-core', 'package.json');
    if (fs.existsSync(installMarker) && process.env.CODETITAN_ACTION_FORCE_CORE_REFRESH !== '1') {
        action_kit_1.core.info(`Using cached bundled CodeTitan core runtime at ${runtimeRoot}.`);
        return {
            runtimeRoot,
            cacheHit: true,
            bootstrapDurationMs: Date.now() - startedAt,
        };
    }
    action_kit_1.core.info(`Preparing bundled CodeTitan core runtime from ${path.join(repoRoot, 'packages', 'core')}.`);
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
    ensureRuntimeManifest(runtimeRoot);
    let packStdout = '';
    await action_kit_1.exec.exec('npm', ['pack', path.join(repoRoot, 'packages', 'core'), '--pack-destination', runtimeRoot], {
        cwd: repoRoot,
        silent: true,
        listeners: {
            stdout: (data) => {
                packStdout += data.toString();
            },
        },
        env: {
            ...process.env,
            npm_config_loglevel: 'error',
        },
    });
    const tarballName = extractPackedTarballName(packStdout);
    await npmInstall(runtimeRoot, path.join(runtimeRoot, tarballName));
    return {
        runtimeRoot,
        cacheHit: false,
        bootstrapDurationMs: Date.now() - startedAt,
    };
}
async function ensurePublishedCoreRuntime() {
    const startedAt = Date.now();
    const actionPackageRoot = getActionPackageRoot(__dirname);
    const actionPackageJsonPath = actionPackageRoot
        ? path.join(actionPackageRoot, 'package.json')
        : null;
    const actionPackage = actionPackageJsonPath && fs.existsSync(actionPackageJsonPath)
        ? readJsonFile(actionPackageJsonPath)
        : null;
    const declaredSpecifier = actionPackage?.dependencies?.[PUBLIC_CORE_PACKAGE];
    const runtimeRoot = getRuntimeRoot('published-core');
    const installMarker = path.join(runtimeRoot, 'node_modules', '@noalia', 'codetitan-core', 'package.json');
    if (fs.existsSync(installMarker) && process.env.CODETITAN_ACTION_FORCE_CORE_REFRESH !== '1') {
        action_kit_1.core.info(`Using cached published CodeTitan core runtime at ${runtimeRoot}.`);
        return {
            runtimeRoot,
            cacheHit: true,
            bootstrapDurationMs: Date.now() - startedAt,
        };
    }
    const installSpecifier = declaredSpecifier
        ? `${PUBLIC_CORE_PACKAGE}@${declaredSpecifier}`
        : PUBLIC_CORE_PACKAGE;
    action_kit_1.core.info(`Installing published CodeTitan core runtime from npm (${installSpecifier}).`);
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
    await npmInstall(runtimeRoot, installSpecifier);
    return {
        runtimeRoot,
        cacheHit: false,
        bootstrapDurationMs: Date.now() - startedAt,
    };
}
function loadWorkspaceCoreApi(repoRoot) {
    const coreEntry = path.join(repoRoot, 'packages', 'core', 'index.js');
    // Dynamic runtime load keeps the action dist decoupled from the monorepo build graph.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require(coreEntry);
}
function loadInstalledCoreApi(runtimeRoot) {
    const requireFromRuntime = (0, module_1.createRequire)(path.join(runtimeRoot, 'package.json'));
    return requireFromRuntime(PUBLIC_CORE_PACKAGE);
}
function getCodeTitanOrchestrationCtor(coreApi) {
    const ctor = coreApi?.CodeTitanOrchestration || coreApi?.default || coreApi;
    if (typeof ctor !== 'function') {
        throw new Error('Unable to resolve CodeTitanOrchestration from the core runtime.');
    }
    return ctor;
}
function normalizePath(filePath) {
    const resolved = path.resolve(filePath);
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}
function ensureTrailingSeparator(dirPath) {
    return dirPath.endsWith(path.sep) ? dirPath : `${dirPath}${path.sep}`;
}
function getGitDiffUtils(coreApi) {
    const utils = coreApi?.GitDiffUtils;
    if (!utils || typeof utils.listChangedFiles !== 'function' || typeof utils.createChangedFilesWorkspace !== 'function') {
        throw new Error('Unable to resolve GitDiffUtils from the core runtime.');
    }
    return utils;
}
function filterProvidedChangedFiles(coreApi, rootPath, changedFiles) {
    const gitDiffUtils = getGitDiffUtils(coreApi);
    const normalizedRoot = normalizePath(rootPath);
    const normalizedRootWithSep = ensureTrailingSeparator(normalizedRoot);
    const seen = new Set();
    return (changedFiles || [])
        .map((filePath) => (path.isAbsolute(filePath) ? filePath : path.resolve(rootPath, filePath)))
        .filter((filePath) => {
        const normalizedFile = normalizePath(filePath);
        if (normalizedFile !== normalizedRoot && !normalizedFile.startsWith(normalizedRootWithSep)) {
            return false;
        }
        if (typeof gitDiffUtils.isSupportedSourceFile === 'function') {
            return gitDiffUtils.isSupportedSourceFile(filePath);
        }
        return SUPPORTED_EXTENSIONS.has(path.extname(filePath).toLowerCase());
    })
        .filter((filePath) => {
        const normalizedFile = normalizePath(filePath);
        if (seen.has(normalizedFile)) {
            return false;
        }
        seen.add(normalizedFile);
        return true;
    });
}
function createEmptyActionReport(projectPath, projectRoot, durationMs, changedScope) {
    return {
        status: 'completed',
        files_analyzed: 0,
        files_skipped: 0,
        findings_count: 0,
        findings: [],
        summary: {
            totalFindings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            totalFiles: 0,
            changedOnly: Boolean(changedScope?.enabled),
            changedFiles: changedScope?.changedFiles.length || 0,
            diffBase: changedScope?.diffBase || null,
            diffSpec: changedScope?.diffSpec || null,
            diffSource: changedScope?.diffSource || null,
        },
        metrics: {},
        duration_ms: durationMs,
        projectPath: projectRoot,
        projectName: path.basename(path.resolve(projectPath)),
        learnedProfile: null,
        prRiskScore: null,
    };
}
function classifyFinding(category) {
    if (!category) {
        return null;
    }
    const normalized = category.toUpperCase();
    // ── Dangerous command execution ──────────────────────────────────────────
    if (normalized === 'COMMAND_EXEC' ||
        normalized === 'COMMAND_INJECTION' ||
        normalized === 'TAINTED_COMMAND_INJECTION' ||
        normalized === 'TAINT_COMMAND_INJECTION' ||
        normalized === 'EVAL_USAGE' ||
        normalized === 'TAINT_EVAL' ||
        normalized === 'EVAL_IN_TIMEOUT' ||
        normalized === 'EVAL_DECODE_EXEC' ||
        normalized === 'DESERIALIZATION_JSON_PARSE_EVAL' ||
        normalized === 'GITHUB_ACTIONS_SCRIPT_INJECTION') {
        return 'dangerous command execution';
    }
    // ── Unsafe SQL / NoSQL / graph query usage ───────────────────────────────
    if (normalized === 'SQL_INJECTION' ||
        normalized === 'TAINTED_SQL_INJECTION' ||
        normalized === 'TAINT_SQL_INJECTION' ||
        normalized === 'SQL_INJECTION_KNEX_RAW' ||
        normalized === 'SQL_INJECTION_STRING_FORMAT' ||
        normalized === 'NOSQL_INJECTION_OPERATOR' ||
        normalized === 'NOSQL_INJECTION_WHERE' ||
        normalized === 'NOSQL_INJECTION_MAPREDUCE' ||
        normalized === 'TAINT_NOSQL_INJECTION' ||
        normalized === 'GRAPHQL_INJECTION' ||
        normalized === 'LDAP_INJECTION' ||
        normalized === 'XPATH_INJECTION' ||
        normalized === 'XML_INJECTION_CONCAT') {
        return 'unsafe SQL usage';
    }
    // ── Unsafe DOM / XSS patterns ────────────────────────────────────────────
    if (normalized === 'XSS' ||
        normalized === 'TAINTED_XSS' ||
        normalized === 'TAINT_XSS' ||
        normalized === 'DANGEROUSLY_SET_INNER_HTML' ||
        normalized === 'HTML_INJECTION_INNERHTML' ||
        normalized === 'DOCUMENT_WRITE_XSS' ||
        normalized === 'REACT_REF_INNER_HTML' ||
        normalized === 'REACT_HREF_JAVASCRIPT' ||
        normalized === 'SCRIPT_INJECTION_SRC' ||
        normalized === 'SRCDOC_XSS' ||
        normalized === 'DOM_CLOBBERING' ||
        normalized === 'DOCUMENT_DOMAIN_MANIPULATION' ||
        normalized === 'STORAGE_EVENT_INJECTION' ||
        normalized === 'POSTMESSAGE_NO_ORIGIN_CHECK' ||
        normalized === 'CSS_INJECTION' ||
        normalized === 'JSONP_CALLBACK' ||
        normalized === 'WEBWORKER_IMPORTSCRIPTS_DYNAMIC' ||
        normalized === 'TEMPLATE_INJECTION_HANDLEBARS' ||
        normalized === 'TEMPLATE_INJECTION_LODASH' ||
        normalized === 'TAINT_TEMPLATE_INJECTION') {
        return 'unsafe DOM / XSS patterns';
    }
    // ── Secret exposure ──────────────────────────────────────────────────────
    if (normalized !== 'UNSAFE_OBJECT_KEYS_AUTH' &&
        (normalized === 'HARDCODED_SECRET' ||
            normalized === 'BASIC_AUTH_URL' ||
            normalized === 'GCP_SERVICE_ACCOUNT' ||
            normalized === 'CI_SECRET_IN_PLAINTEXT' ||
            normalized === 'ENV_FILE_COMMITTED' ||
            normalized === 'TERRAFORM_PLAINTEXT_SECRET' ||
            normalized === 'DOCKER_SECRETS_IN_ENV' ||
            normalized === 'BEARER_TOKEN_LOGGED' ||
            normalized === 'LOCALSTORAGE_SENSITIVE_DATA' ||
            normalized === 'TOKEN_IN_LOCALSTORAGE' ||
            normalized === 'SENSITIVE_DATA_CONSOLE_LOG' ||
            normalized === 'CLEARTEXT_PASSWORD_STORAGE' ||
            normalized === 'PASSWORD_IN_URL' ||
            normalized === 'HARDCODED_ENCRYPTION_KEY' ||
            normalized === 'JWT_SECRET_HARDCODED' ||
            normalized === 'STATIC_SALT_BCRYPT' ||
            normalized.includes('PRIVATE_KEY') ||
            normalized.includes('ACCESS_KEY') ||
            normalized.includes('API_KEY') ||
            normalized.includes('SERVICE_ACCOUNT') ||
            normalized.includes('CREDENTIAL') ||
            normalized.includes('SECRET') ||
            normalized.includes('PASSWORD') ||
            normalized.endsWith('_TOKEN') ||
            normalized.endsWith('_KEY'))) {
        return 'secret exposure';
    }
    // ── Auth / route protection gaps ─────────────────────────────────────────
    if (normalized === 'MISSING_AUTH_MIDDLEWARE' ||
        normalized === 'BROKEN_AUTH' ||
        normalized === 'SESSION_FIXATION' ||
        normalized === 'OAUTH_STATE_MISSING' ||
        normalized === 'CSRF_PROTECTION_MISSING' ||
        normalized === 'JWT_NO_EXPIRY' ||
        normalized === 'JWT_NONE_ALGORITHM' ||
        normalized === 'JWT_WEAK_ALGORITHM' ||
        normalized === 'WEAK_JWT_SECRET' ||
        normalized === 'HARDCODED_ADMIN_ROLE' ||
        normalized === 'INSECURE_DIRECT_OBJECT_REF' ||
        normalized === 'MASS_ASSIGNMENT' ||
        normalized === 'TRUST_PROXY_WILDCARD' ||
        normalized === 'UNSAFE_OBJECT_KEYS_AUTH') {
        return 'auth / route protection gaps';
    }
    // ── Supply chain / AI-generated code risk ────────────────────────────────
    if (normalized.startsWith('AI_CODE_RISK_')) {
        return 'AI-generated-code risk checks';
    }
    if (normalized === 'INSTALL_TIME_EXEC' ||
        normalized === 'POSTINSTALL_EXEC' ||
        normalized === 'NPM_PREINSTALL_SCRIPT' ||
        normalized === 'NPM_INSTALL_UNSAFE' ||
        normalized === 'GITHUB_ACTIONS_UNPINNED_ACTION' ||
        normalized === 'SEMVER_WILDCARD' ||
        normalized === 'TROJAN_SOURCE' ||
        normalized === 'OBFUSCATED_HEX' ||
        normalized === 'CHARCODE_OBFUSCATION' ||
        normalized === 'EVAL_DECODE_EXEC' ||
        normalized === 'DNS_EXFILTRATION' ||
        normalized === 'ENV_HARVEST' ||
        normalized === 'NGROK_EXFIL' ||
        normalized === 'OAST_EXFIL' ||
        normalized === 'REQUESTBIN_EXFIL' ||
        normalized === 'BURP_COLLABORATOR' ||
        normalized === 'RAW_IP_REQUEST' ||
        normalized === 'DYNAMIC_REQUIRE' ||
        normalized === 'DYNAMIC_IMPORT') {
        return 'AI-generated-code risk checks';
    }
    // ── Other security findings — pass through to surface as security risks ──
    // These are HIGH/CRITICAL severity security issues that don't fit the above
    // classes but should not be silently dropped.
    if (normalized === 'PROTOTYPE_POLLUTION' ||
        normalized === 'PROTOTYPE_POLLUTION_MERGE' ||
        normalized === 'REGEX_INJECTION' ||
        normalized === 'TAINT_OPEN_REDIRECT' ||
        normalized === 'OPEN_REDIRECT' ||
        normalized === 'OPEN_REDIRECT_WINDOW_LOCATION' ||
        normalized === 'UNVALIDATED_REDIRECT' ||
        normalized === 'SERVER_SIDE_REDIRECT_INJECTION' ||
        normalized === 'TAINT_PATH_TRAVERSAL' ||
        normalized === 'PATH_TRAVERSAL' ||
        normalized === 'PATH_TRAVERSAL_READFILE' ||
        normalized === 'PATH_TRAVERSAL_WRITEFILE' ||
        normalized === 'TAINT_SSRF' ||
        normalized === 'SSRF' ||
        normalized === 'SSRF_USER_CONTROLLED_URL' ||
        normalized === 'SSRF_INTERNAL_RANGE' ||
        normalized === 'POTENTIAL_XXE' ||
        normalized === 'XXE' ||
        normalized === 'INSECURE_DESERIALIZATION' ||
        normalized === 'TAINT_INSECURE_DESERIALIZATION' ||
        normalized === 'TIMING_ATTACK' ||
        normalized === 'WEAK_HASH' ||
        normalized === 'WEAK_CIPHER_DES' ||
        normalized === 'WEAK_HMAC' ||
        normalized === 'ECB_MODE_CIPHER' ||
        normalized === 'RANDOM_IV_REUSE' ||
        normalized === 'WEAK_CRYPTO' ||
        normalized === 'INSECURE_RANDOM' ||
        normalized === 'INSECURE_RANDOM_SEED' ||
        normalized === 'PREDICTABLE_RANDOM_TOKEN' ||
        normalized === 'BCRYPT_LOW_ROUNDS' ||
        normalized === 'INSUFFICIENT_KEY_DERIVATION_ROUNDS' ||
        normalized === 'WEAK_KEY_LENGTH_RSA' ||
        normalized === 'WEAK_PASSWORD_POLICY' ||
        normalized === 'INSECURE_COOKIE_NO_HTTPONLY' ||
        normalized === 'INSECURE_COOKIE_NO_SECURE' ||
        normalized === 'INSECURE_COOKIE_NO_SAMESITE' ||
        normalized === 'INSECURE_TLS' ||
        normalized === 'OBSOLETE_TLS_VERSION' ||
        normalized === 'CERT_VALIDATION_DISABLED' ||
        normalized === 'CORS_ALL_METHODS' ||
        normalized === 'CORS_ALL_HEADERS' ||
        normalized === 'PERMISSIVE_CORS_WITH_CREDENTIALS' ||
        normalized === 'CLICKJACKING_NO_HEADER' ||
        normalized === 'HELMET_MISSING' ||
        normalized === 'HSTS_MISSING' ||
        normalized === 'CONTENT_TYPE_SNIFFING' ||
        normalized === 'RATE_LIMIT_MISSING' ||
        normalized === 'GRAPHQL_DEPTH_LIMIT_MISSING' ||
        normalized === 'GRAPHQL_INTROSPECTION_ENABLED' ||
        normalized === 'DEBUG_MODE_ENABLED' ||
        normalized === 'DEBUG_MODE' ||
        normalized === 'EXPOSE_STACK_TRACE_MIDDLEWARE' ||
        normalized === 'VERBOSE_ERROR_EXPOSURE' ||
        normalized === 'SWAGGER_UI_EXPOSED_PRODUCTION' ||
        normalized === 'DIRECTORY_LISTING_ENABLED' ||
        normalized === 'SENSITIVE_DATA_IN_GET' ||
        normalized === 'HTTP_RESPONSE_SPLITTING' ||
        normalized === 'HTTP_HEADER_INJECTION' ||
        normalized === 'CLIPBOARD_WRITE_SENSITIVE' ||
        normalized === 'UPLOADED_FILE_NO_VALIDATION' ||
        normalized === 'UNSAFE_FILE_UPLOAD' ||
        normalized === 'EMAIL_INJECTION' ||
        normalized === 'LOG_INJECTION' ||
        normalized === 'MORGAN_IN_PRODUCTION' ||
        normalized === 'RACE_CONDITION' ||
        normalized === 'UNSAFE_CODE' ||
        normalized === 'UNSAFE_TARGET_BLANK' ||
        normalized === 'WINDOW_OPEN_NOOPENER' ||
        normalized === 'INSECURE_IFRAME_SANDBOX' ||
        normalized === 'MISSING_VALIDATION' ||
        normalized === 'SECURITY_MISCONFIGURATION' ||
        normalized === 'SENSITIVE_DATA_EXPOSURE' ||
        normalized === 'DATA_EXPOSURE' ||
        normalized === 'KUBERNETES_NO_RESOURCE_LIMITS' ||
        normalized === 'KUBERNETES_PRIVILEGED_CONTAINER' ||
        normalized === 'DOCKER_ADD_REMOTE_URL' ||
        normalized === 'DOCKER_PRIVILEGED_FLAG' ||
        normalized === 'DOCKERFILE_ROOT_USER') {
        return 'dangerous command execution'; // Broadest class — surfaces as a security finding
    }
    return null;
}
function countBySeverity(findings) {
    const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
    };
    for (const finding of findings) {
        const severity = (finding.severity || 'LOW').toUpperCase();
        if (severity in counts) {
            counts[severity] += 1;
        }
    }
    return counts;
}
// Paths that intentionally contain fake/demo secrets or test fixtures — suppress HARDCODED_SECRET findings from these.
const DEMO_FIXTURE_PATHS = [
    'app/demo/',
    'app/playground/',
    'benchmark-runner.js',
    '__tests__/',
    '__fixtures__/',
    'test-',
    '.test.',
    '.spec.',
];
function isDemoOrFixturePath(filePath) {
    if (!filePath)
        return false;
    const normalized = filePath.replace(/\\/g, '/');
    return DEMO_FIXTURE_PATHS.some((p) => normalized.includes(p));
}
function isSuppressedFinding(finding) {
    // Suppress HARDCODED_SECRET findings in known demo/fixture paths
    if (finding.category === 'HARDCODED_SECRET' &&
        isDemoOrFixturePath(finding.file_path)) {
        return true;
    }
    return false;
}
function isSupportedFindingCategory(category) {
    return classifyFinding(category) !== null;
}
function applyMvpContract(report) {
    const rawFindings = report.findings || [];
    const findings = rawFindings
        .filter((finding) => isSupportedFindingCategory(finding.category))
        .filter((finding) => !isSuppressedFinding(finding));
    const deferredFindingsFiltered = rawFindings.length - findings.length;
    const severityCounts = countBySeverity(findings);
    return {
        ...report,
        findings,
        findings_count: findings.length,
        summary: {
            ...report.summary,
            totalFindings: findings.length,
            critical: severityCounts.CRITICAL,
            high: severityCounts.HIGH,
            medium: severityCounts.MEDIUM,
            low: severityCounts.LOW,
        },
        contract: {
            id: 'phase1-mvp',
            supportedScope: 'GitHub-hosted JS/TS repos',
            findingClasses: FINDING_CLASSES,
            deferredFindingsFiltered,
            rawFindings: rawFindings.length,
            surfacedFindings: findings.length,
        },
    };
}
function checkSupportedJsTsPath(targetPath) {
    if (!fs.existsSync(targetPath)) {
        return {
            supported: false,
            reason: `Path does not exist: ${targetPath}`,
            detectedFiles: 0,
        };
    }
    const stat = fs.statSync(targetPath);
    if (stat.isFile()) {
        const supported = SUPPORTED_EXTENSIONS.has(path.extname(targetPath).toLowerCase());
        return {
            supported,
            reason: supported
                ? `File target ${path.basename(targetPath)} is within the JS/TS MVP scope.`
                : `File target ${path.basename(targetPath)} is outside the JS/TS MVP scope.`,
            detectedFiles: supported ? 1 : 0,
        };
    }
    let detectedJsTsFiles = 0;
    let packageJsonFound = false;
    const queue = [targetPath];
    while (queue.length > 0 && detectedJsTsFiles < 250) {
        const current = queue.shift();
        let entries = [];
        try {
            entries = fs.readdirSync(current, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const entry of entries) {
            const nextPath = path.join(current, entry.name);
            if (entry.isDirectory()) {
                if (SKIP_DIRECTORIES.has(entry.name)) {
                    continue;
                }
                queue.push(nextPath);
                continue;
            }
            if (entry.name === 'package.json') {
                packageJsonFound = true;
            }
            if (SUPPORTED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
                detectedJsTsFiles += 1;
            }
            if (detectedJsTsFiles >= 250) {
                break;
            }
        }
    }
    if (detectedJsTsFiles > 0) {
        return {
            supported: true,
            reason: packageJsonFound
                ? `Detected ${detectedJsTsFiles} JS/TS source files in a Node-style project.`
                : `Detected ${detectedJsTsFiles} JS/TS source files.`,
            detectedFiles: detectedJsTsFiles,
        };
    }
    return {
        supported: false,
        reason: 'No JS/TS source files were detected. Phase 1 only supports JS/TS repositories.',
        detectedFiles: 0,
    };
}
async function runCoreAnalysisWith(coreApi, projectPath, level, options = {}) {
    const startTime = Date.now();
    const stat = fs.statSync(projectPath);
    const isFileTarget = stat.isFile();
    const rootPath = isFileTarget ? path.dirname(projectPath) : projectPath;
    const targetFile = isFileTarget ? normalizePath(projectPath) : null;
    const changedOnly = options.changedOnly === true;
    let analysisRoot = rootPath;
    let tempDir = null;
    let changedScope;
    if (changedOnly) {
        const gitDiffUtils = getGitDiffUtils(coreApi);
        const providedChangedFiles = Array.isArray(options.changedFiles)
            ? filterProvidedChangedFiles(coreApi, rootPath, options.changedFiles)
            : null;
        const diff = providedChangedFiles
            ? {
                changedFiles: providedChangedFiles,
                diffSpec: options.diffBase || 'github-api'
            }
            : gitDiffUtils.listChangedFiles(projectPath, {
                baseRef: options.diffBase
            });
        const changedFiles = diff.changedFiles.map((filePath) => normalizePath(filePath));
        changedScope = {
            enabled: true,
            diffBase: options.diffBase,
            diffSpec: diff.diffSpec,
            changedFiles: diff.changedFiles.map((filePath) => path.relative(rootPath, filePath).replace(/\\/g, '/')),
            diffSource: providedChangedFiles ? (options.diffSource || 'github-api') : 'git-diff'
        };
        if (isFileTarget) {
            if (!changedFiles.includes(targetFile || '')) {
                return createEmptyActionReport(projectPath, rootPath, Date.now() - startTime, changedScope);
            }
        }
        else {
            if (diff.changedFiles.length === 0) {
                return createEmptyActionReport(projectPath, rootPath, Date.now() - startTime, changedScope);
            }
            tempDir = gitDiffUtils.createChangedFilesWorkspace(rootPath, diff.changedFiles);
            analysisRoot = tempDir;
        }
    }
    if (isFileTarget && !changedOnly) {
        tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codetitan-action-file-'));
        const tempFilePath = path.join(tempDir, path.basename(projectPath));
        fs.copyFileSync(projectPath, tempFilePath);
        analysisRoot = tempDir;
    }
    const CodeTitanOrchestration = getCodeTitanOrchestrationCtor(coreApi);
    const orchestrator = new CodeTitanOrchestration({
        outputFormat: 'json',
        verbose: false,
        level,
        noAi: true,
        aiGenerated: true,
        fpFilter: false,
    });
    let coreReport;
    try {
        coreReport = await orchestrator.analyzeCodebase(analysisRoot, {
            profileProjectRoot: rootPath
        });
    }
    finally {
        if (tempDir) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    }
    const findings = (coreReport.findings || []).map((issue) => {
        const rawPath = issue.file || issue.file_path || '';
        const absoluteFile = rawPath
            ? (path.isAbsolute(rawPath) ? rawPath : path.resolve(analysisRoot, rawPath))
            : '';
        const displayFile = isFileTarget && absoluteFile ? projectPath : absoluteFile;
        // When changed-only mode copies files into a temp workspace, remap the
        // temp path back to the original rootPath so findings show clean repo-relative paths.
        const resolvedDisplay = tempDir && displayFile && displayFile.startsWith(tempDir)
            ? path.join(rootPath, displayFile.slice(tempDir.length))
            : displayFile;
        const relativePath = resolvedDisplay
            ? path.relative(rootPath, resolvedDisplay).replace(/\\/g, '/')
            : 'unknown';
        return {
            file_path: relativePath,
            line_number: issue.line || issue.line_number || 1,
            severity: issue.severity || 'MEDIUM',
            category: issue.category || 'UNKNOWN',
            message: issue.message || 'Issue detected',
            suggestion: issue.suggestion,
            domain: issue.domain,
            impact_score: issue.impact || issue.impact_score,
            code_snippet: issue.snippet || issue.code_snippet,
            ai_provider: issue.ai_provider,
            confidence: issue.confidence,
        };
    });
    const filteredFindings = targetFile
        ? findings.filter((finding) => {
            if (!finding.file_path || finding.file_path === 'unknown') {
                return false;
            }
            return normalizePath(path.resolve(rootPath, finding.file_path)) === targetFile;
        })
        : findings;
    const duration_ms = Date.now() - startTime;
    const report = {
        status: 'completed',
        files_analyzed: targetFile
            ? 1
            : (coreReport.summary?.totalFiles || new Set(filteredFindings.map((finding) => finding.file_path)).size),
        files_skipped: 0,
        findings_count: filteredFindings.length,
        findings: filteredFindings,
        summary: coreReport.summary || {},
        metrics: coreReport.metrics || {},
        duration_ms,
        projectPath: rootPath,
        projectName: isFileTarget ? path.basename(projectPath) : path.basename(path.resolve(projectPath)),
        learnedProfile: coreReport.learnedProfile || null,
        prRiskScore: coreReport.prRiskScore || coreReport.metrics?.prRiskScore || coreReport.summary?.prRiskScore || null,
    };
    report.summary = {
        ...(report.summary || {}),
        changedOnly,
        changedFiles: changedScope?.changedFiles.length || 0,
        diffBase: changedScope?.diffBase || null,
        diffSpec: changedScope?.diffSpec || null,
        diffSource: changedScope?.diffSource || null
    };
    if (changedOnly) {
        report.files_analyzed = isFileTarget ? 1 : (changedScope?.changedFiles.length || 0);
    }
    return report;
}
function findBundledRepoRoot(startDir = __dirname) {
    let current = path.resolve(startDir);
    while (true) {
        const rootPackageJson = path.join(current, 'package.json');
        const corePackageJson = path.join(current, 'packages', 'core', 'package.json');
        const actionPackageJson = path.join(current, 'packages', 'github-action', 'package.json');
        if (fs.existsSync(rootPackageJson) &&
            fs.existsSync(corePackageJson) &&
            fs.existsSync(actionPackageJson)) {
            return current;
        }
        const parent = path.dirname(current);
        if (parent === current) {
            return null;
        }
        current = parent;
    }
}
function hasBundledCoreWorkspace(repoRoot) {
    return (fs.existsSync(path.join(repoRoot, 'packages', 'core', 'index.js')) &&
        fs.existsSync(path.join(repoRoot, 'node_modules')));
}
function hasBundledCoreSource(repoRoot) {
    return (fs.existsSync(path.join(repoRoot, 'packages', 'core', 'package.json')) &&
        fs.existsSync(path.join(repoRoot, 'packages', 'core', 'index.js')));
}
async function runActionAnalysis(projectPath, level, options = {}) {
    const startedAt = Date.now();
    const supportedPath = checkSupportedJsTsPath(projectPath);
    if (!supportedPath.supported) {
        throw new Error(supportedPath.reason);
    }
    const bundledRepoRoot = findBundledRepoRoot(__dirname);
    const forcePackRuntime = process.env.CODETITAN_ACTION_FORCE_PACK_RUNTIME === '1';
    if (bundledRepoRoot && !forcePackRuntime && hasBundledCoreWorkspace(bundledRepoRoot)) {
        action_kit_1.core.info(`Using bundled CodeTitan core runtime from ${bundledRepoRoot}.`);
        const report = applyMvpContract(await runCoreAnalysisWith(loadWorkspaceCoreApi(bundledRepoRoot), projectPath, level, options));
        return {
            report,
            metrics: {
                runtimeLabel: 'workspace',
                runtimeRoot: process.env.CODETITAN_ACTION_RUNTIME_ROOT || '',
                cacheHit: true,
                bootstrapDurationMs: 0,
                analysisDurationMs: report.duration_ms,
                totalDurationMs: Date.now() - startedAt,
            },
        };
    }
    if (bundledRepoRoot && hasBundledCoreSource(bundledRepoRoot)) {
        const runtime = await ensureBundledCoreRuntime(bundledRepoRoot);
        const report = applyMvpContract(await runCoreAnalysisWith(loadInstalledCoreApi(runtime.runtimeRoot), projectPath, level, options));
        return {
            report,
            metrics: {
                runtimeLabel: 'bundled-pack',
                runtimeRoot: runtime.runtimeRoot,
                cacheHit: runtime.cacheHit,
                bootstrapDurationMs: runtime.bootstrapDurationMs,
                analysisDurationMs: report.duration_ms,
                totalDurationMs: Date.now() - startedAt,
            },
        };
    }
    const runtime = await ensurePublishedCoreRuntime();
    const report = applyMvpContract(await runCoreAnalysisWith(loadInstalledCoreApi(runtime.runtimeRoot), projectPath, level, options));
    return {
        report,
        metrics: {
            runtimeLabel: 'published',
            runtimeRoot: runtime.runtimeRoot,
            cacheHit: runtime.cacheHit,
            bootstrapDurationMs: runtime.bootstrapDurationMs,
            analysisDurationMs: report.duration_ms,
            totalDurationMs: Date.now() - startedAt,
        },
    };
}


/***/ }),

/***/ 194:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.findBundledRepoRoot = void 0;
exports.buildSarifReport = buildSarifReport;
exports.buildMarkdownSummary = buildMarkdownSummary;
exports.upsertPullRequestComment = upsertPullRequestComment;
exports.fetchPullRequestChangedFiles = fetchPullRequestChangedFiles;
exports.run = run;
const fs = __importStar(__nccwpck_require__(896));
const https = __importStar(__nccwpck_require__(692));
const path = __importStar(__nccwpck_require__(928));
const action_kit_1 = __nccwpck_require__(755);
const analysis_runtime_1 = __nccwpck_require__(395);
var analysis_runtime_2 = __nccwpck_require__(395);
Object.defineProperty(exports, "findBundledRepoRoot", ({ enumerable: true, get: function () { return analysis_runtime_2.findBundledRepoRoot; } }));
const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const COMMENT_MARKER = '<!-- codetitan-phase1-summary -->';
function formatDuration(ms) {
    if (!Number.isFinite(ms) || ms < 1000) {
        return `${Math.max(0, Math.round(ms || 0))}ms`;
    }
    return `${(ms / 1000).toFixed(2)}s`;
}
function countBySeverity(findings) {
    return findings.reduce((counts, finding) => {
        const severity = (finding.severity || 'LOW').toUpperCase();
        if (severity in counts) {
            counts[severity] += 1;
        }
        return counts;
    }, {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
    });
}
function buildSarifReport(findings) {
    return {
        version: '2.1.0',
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'CodeTitan',
                        version: '1.0.0',
                        informationUri: 'https://codetitan.dev',
                        rules: [...new Set(findings.map((finding) => finding.category || 'unknown'))].map((id) => ({
                            id,
                            shortDescription: { text: String(id) },
                        })),
                    },
                },
                results: findings.map((finding) => ({
                    ruleId: finding.category || 'unknown',
                    level: finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                        ? 'error'
                        : finding.severity === 'MEDIUM'
                            ? 'warning'
                            : 'note',
                    message: { text: finding.message },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: finding.file_path.replace(/\\/g, '/'),
                                    uriBaseId: '%SRCROOT%',
                                },
                                region: { startLine: Math.max(1, finding.line_number || 1) },
                            },
                        },
                    ],
                })),
            },
        ],
    };
}
function summarizeTopFindings(findings, limit = 5) {
    if (findings.length === 0) {
        return 'No MVP-scope findings surfaced.';
    }
    return findings
        .slice(0, limit)
        .map((finding) => `- [${finding.severity}] ${finding.file_path}:${finding.line_number} ${finding.category}: ${finding.message}`)
        .join('\n');
}
async function shareReport(report, apiKey, apiBase) {
    return new Promise((resolve) => {
        try {
            const body = JSON.stringify(report);
            const url = new URL('/api/v1/share', apiBase);
            const req = https.request({
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                    Authorization: `Bearer ${apiKey}`,
                },
            }, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk.toString(); });
                res.on('end', () => {
                    try {
                        const parsed = JSON.parse(data);
                        resolve(parsed.url || null);
                    }
                    catch {
                        resolve(null);
                    }
                });
            });
            req.on('error', () => resolve(null));
            req.setTimeout(10000, () => { req.destroy(); resolve(null); });
            req.write(body);
            req.end();
        }
        catch {
            resolve(null);
        }
    });
}
// Low-signal categories that fire on nearly every repo — exclude from "top pattern" signal
const NOISY_CATEGORIES = new Set(['MISSING_TESTS', 'LONG_LINE', 'FILE_TOO_LONG', 'MISSING_DOCS']);
function buildRepoSignalsSection(report) {
    const profile = report.learnedProfile;
    if (!profile || !profile.runCount || profile.runCount < 1) {
        return [];
    }
    const lines = ['', '## Repo Signals', ''];
    // Profile maturity (merged from former "## Repo Learning" section)
    if (profile.personalizationScore !== undefined) {
        lines.push(`- Profile maturity: ${profile.personalizationScore}/100 (${profile.runCount} scan${profile.runCount === 1 ? '' : 's'})`);
    }
    // Top hot directory — leaf name only avoids GitHub's doubled checkout path layout
    const hotDirs = profile.hotDirectories || {};
    const topDir = Object.entries(hotDirs)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 1)[0];
    if (topDir) {
        const [absPath, stats] = topDir;
        const leafDir = absPath.replace(/\\/g, '/').split('/').filter(Boolean).pop() || absPath;
        lines.push(`- Hottest directory: \`${leafDir}/\` (${stats.count} finding${stats.count === 1 ? '' : 's'} seen here)`);
    }
    // Top meaningful category — skip structural noise that fires on every repo
    const catStats = profile.categoryStats || {};
    const topCat = Object.entries(catStats)
        .filter(([cat]) => !NOISY_CATEGORIES.has(cat.toUpperCase()))
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 1)[0];
    if (topCat) {
        const [cat, stats] = topCat;
        const label = cat.toLowerCase().replace(/_/g, ' ');
        lines.push(`- Top finding pattern: ${label} (avg confidence ${Math.round(stats.averageConfidence * 100)}%)`);
    }
    // Suppression learning — the moat signal: a fresh scanner can never say this
    const suppressionCount = Object.keys(profile.suppressionRules || {}).length;
    if (suppressionCount > 0) {
        lines.push(`- Learned ${suppressionCount} suppression rule${suppressionCount === 1 ? '' : 's'} from your dismissals`);
    }
    // AI code density — wired when report.aiAttribution is populated (Phase 4 Tier 2 / §4.7)
    // Contract: expect aiAttribution.coverage (number 0–100) and aiAttribution.aiHigherFindingRate (delta %)
    const aiAttrib = report.aiAttribution;
    if (aiAttrib && typeof aiAttrib.coverage === 'number' && aiAttrib.coverage > 0) {
        const densityPct = aiAttrib.coverage;
        const findingRate = aiAttrib.aiHigherFindingRate;
        if (findingRate !== undefined) {
            lines.push(`- AI Code Density: ${densityPct}% of commits attributed to AI tools — AI code has a ${findingRate > 0 ? '+' : ''}${findingRate}% finding rate vs human-written code`);
        }
        else {
            lines.push(`- AI Code Density: ${densityPct}% of commits attributed to AI tools`);
        }
    }
    return lines.length > 3 ? lines : [];
}
function buildMarkdownSummary(report, findings, failOnSeverity, riskThreshold, runtimeMetrics, reportUrl) {
    const counts = countBySeverity(findings);
    const thresholdIndex = SEVERITY_ORDER.indexOf(failOnSeverity);
    const blockingSeverities = thresholdIndex >= 0 ? SEVERITY_ORDER.slice(thresholdIndex) : [];
    const blockingFindings = findings.filter((finding) => blockingSeverities.includes(finding.severity));
    const riskBlocked = Number(report.prRiskScore?.score || 0) >= riskThreshold;
    const lines = [
        '# CodeTitan PR Verification',
        '',
        `- Scope: ${report.contract?.supportedScope || 'GitHub-hosted JS/TS repos'}`,
        `- Files analyzed: ${report.files_analyzed || 0}`,
        `- Timing: analyzed ${report.files_analyzed || 0} file(s) in ${formatDuration(report.duration_ms || runtimeMetrics?.analysisDurationMs || 0)}${report.summary?.changedOnly ? ` (${report.summary.changedFiles || 0} changed, ${report.files_skipped || 0} skipped)` : ` (${report.files_skipped || 0} skipped)`}`,
        `- Surfaced findings: ${findings.length}`,
        `- Deferred findings filtered: ${report.contract?.deferredFindingsFiltered || 0}`,
        `- Quality gate: ${failOnSeverity}+`,
        `- Risk threshold: ${riskThreshold}`,
        `- Gate result: ${blockingFindings.length > 0 || riskBlocked ? 'FAIL' : 'PASS'}`,
    ];
    if (report.summary?.changedOnly) {
        lines.push(`- Diff scope: ${report.summary.changedFiles || 0} changed file(s)${report.summary.diffSpec ? ` (${report.summary.diffSpec})` : ''}`);
    }
    if (runtimeMetrics) {
        lines.push(`- Runtime mode: ${runtimeMetrics.runtimeLabel}`, `- Runtime cache: ${runtimeMetrics.cacheHit ? 'HIT' : 'MISS'}`, `- Runtime bootstrap: ${formatDuration(runtimeMetrics.bootstrapDurationMs)}`, `- Analysis time: ${formatDuration(runtimeMetrics.analysisDurationMs)}`, `- Total action time: ${formatDuration(runtimeMetrics.totalDurationMs)}`);
    }
    if (report.prRiskScore?.score !== undefined) {
        lines.push('', '## PR Risk', '', `- Score: ${report.prRiskScore.score}`, `- Level: ${report.prRiskScore.level || 'low'}`, `- Grade: ${report.prRiskScore.grade || 'A'}`, `- Summary: ${report.prRiskScore.reason || 'Risk is driven by current findings.'}`);
    }
    const repoSignals = buildRepoSignalsSection(report);
    if (repoSignals.length > 0) {
        lines.push(...repoSignals);
    }
    lines.push('', '## Severity', '', '| Severity | Count |', '| --- | ---: |', `| CRITICAL | ${counts.CRITICAL} |`, `| HIGH | ${counts.HIGH} |`, `| MEDIUM | ${counts.MEDIUM} |`, `| LOW | ${counts.LOW} |`, '', '## Top Findings', '', summarizeTopFindings(findings, 10), '', '_Generated by CodeTitan Phase 1 verification workflow._');
    if (reportUrl) {
        lines.push('', `**[View full report](${reportUrl})**`);
    }
    return lines.join('\n');
}
function hasBlockingFindings(findings, failOnSeverity) {
    const thresholdIndex = SEVERITY_ORDER.indexOf(failOnSeverity);
    if (thresholdIndex < 0) {
        return false;
    }
    const blockingSeverities = SEVERITY_ORDER.slice(thresholdIndex);
    return findings.some((finding) => blockingSeverities.includes((finding.severity || '').toUpperCase()));
}
async function writeStepSummary(markdown) {
    if (!process.env.GITHUB_STEP_SUMMARY) {
        return;
    }
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`, 'utf8');
}
async function upsertPullRequestComment(token, markdown) {
    const context = action_kit_1.github.context;
    if (!context.payload.pull_request) {
        return;
    }
    const octokit = action_kit_1.github.getOctokit(token);
    const { owner, repo } = context.repo;
    const issueNumber = context.payload.pull_request.number;
    const body = `${COMMENT_MARKER}\n${markdown}`;
    const comments = await octokit.rest.issues.listComments({
        owner,
        repo,
        issue_number: issueNumber,
    });
    const existing = comments.data.find((comment) => comment.body?.includes(COMMENT_MARKER));
    if (existing) {
        await octokit.rest.issues.updateComment({
            owner,
            repo,
            comment_id: existing.id,
            body,
        });
        return;
    }
    await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: issueNumber,
        body,
    });
}
async function fetchPullRequestChangedFiles(token) {
    const context = action_kit_1.github.context;
    if (!context.payload.pull_request || !token) {
        return [];
    }
    const octokit = action_kit_1.github.getOctokit(token);
    const { owner, repo } = context.repo;
    const pullNumber = context.payload.pull_request.number;
    const files = [];
    let page = 1;
    while (true) {
        const response = await octokit.rest.pulls.listFiles({
            owner,
            repo,
            pull_number: pullNumber,
            per_page: 100,
            page,
        });
        const pageFiles = response.data
            .map((file) => file?.filename)
            .filter((filePath) => Boolean(filePath));
        files.push(...pageFiles);
        if (response.data.length < 100) {
            break;
        }
        page += 1;
    }
    return files;
}
async function run() {
    try {
        const apiKey = action_kit_1.core.getInput('api-key');
        const githubToken = action_kit_1.core.getInput('github-token') || process.env.GITHUB_TOKEN || '';
        const analysisPath = action_kit_1.core.getInput('path') || '.';
        const level = action_kit_1.core.getInput('level') || '4';
        const failOnSeverity = (action_kit_1.core.getInput('fail-on-severity') || 'HIGH').toUpperCase();
        const riskThreshold = Number.parseInt(action_kit_1.core.getInput('risk-threshold') || '80', 10) || 80;
        const changedOnlyInput = (action_kit_1.core.getInput('changed-only') || '').trim().toLowerCase();
        const isPullRequestEvent = Boolean(action_kit_1.github.context.payload.pull_request);
        const changedOnly = changedOnlyInput === 'true' || (changedOnlyInput === '' && isPullRequestEvent);
        const diffBase = action_kit_1.core.getInput('diff-base') || action_kit_1.github.context.payload.pull_request?.base?.sha || '';
        const format = (action_kit_1.core.getInput('format') || 'json').toLowerCase();
        const configPathInput = action_kit_1.core.getInput('config-path');
        const runtimeRootInput = action_kit_1.core.getInput('runtime-root');
        const commentOnPR = action_kit_1.core.getInput('comment-on-pr') !== 'false';
        const debugEnabled = action_kit_1.core.getInput('debug') === 'true';
        const workspaceRoot = process.env.GITHUB_WORKSPACE || process.cwd();
        if (debugEnabled) {
            process.env.CODETITAN_ACTION_DEBUG = '1';
            action_kit_1.core.info(`Debug logging enabled (workspace=${workspaceRoot}, changedOnly=${changedOnly}, diffBase=${diffBase || 'HEAD'}).`);
        }
        if (!['json', 'sarif', 'both'].includes(format)) {
            throw new Error(`Unsupported format "${format}". Use json, sarif, or both.`);
        }
        if (configPathInput) {
            const resolvedConfigPath = path.resolve(workspaceRoot, configPathInput);
            if (!fs.existsSync(resolvedConfigPath)) {
                throw new Error(`config-path does not exist: ${resolvedConfigPath}`);
            }
            action_kit_1.core.info(`Using project config hint at ${resolvedConfigPath}`);
        }
        if (runtimeRootInput) {
            process.env.CODETITAN_ACTION_RUNTIME_ROOT = path.resolve(workspaceRoot, runtimeRootInput);
            action_kit_1.core.info(`Using persisted CodeTitan runtime root at ${process.env.CODETITAN_ACTION_RUNTIME_ROOT}.`);
        }
        const reportPath = path.join(workspaceRoot, 'codetitan-report.json');
        const summaryPath = path.join(workspaceRoot, 'codetitan-summary.md');
        const sarifPath = path.join(workspaceRoot, 'codetitan-report.sarif');
        const resolvedAnalysisPath = path.resolve(workspaceRoot, analysisPath);
        const bundledRepoRoot = (0, analysis_runtime_1.findBundledRepoRoot)(__dirname);
        if (bundledRepoRoot) {
            action_kit_1.core.info(`Detected bundled CodeTitan checkout at ${bundledRepoRoot}.`);
        }
        action_kit_1.core.info(`Running CodeTitan against ${analysisPath}`);
        let changedFiles;
        if (changedOnly && isPullRequestEvent && githubToken) {
            const prFiles = await fetchPullRequestChangedFiles(githubToken);
            changedFiles = prFiles.map((filePath) => path.resolve(workspaceRoot, filePath));
            action_kit_1.core.info(`Using GitHub PR diff scope with ${changedFiles.length} changed file(s).`);
        }
        else if (changedOnly && isPullRequestEvent) {
            action_kit_1.core.info('pull_request event detected but no GitHub token is available; falling back to local git diff for changed-only analysis.');
        }
        if (debugEnabled && changedFiles) {
            action_kit_1.core.info(`Debug diff files: ${changedFiles.join(', ')}`);
        }
        const { report, metrics } = await (0, analysis_runtime_1.runActionAnalysis)(resolvedAnalysisPath, Number.parseInt(level, 10) || 4, {
            changedOnly,
            diffBase,
            changedFiles,
            diffSource: changedFiles ? 'github-api' : 'git-diff'
        });
        action_kit_1.core.info(`CodeTitan analysis completed via ${metrics.runtimeLabel} runtime in ${formatDuration(metrics.totalDurationMs)} ` +
            `(bootstrap ${formatDuration(metrics.bootstrapDurationMs)}, analysis ${formatDuration(metrics.analysisDurationMs)}, cache ${metrics.cacheHit ? 'HIT' : 'MISS'}).`);
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
        const findings = report.findings || [];
        // Share report when api-key is provided and append the URL to the PR comment
        let sharedReportUrl = null;
        if (apiKey) {
            const apiBase = process.env.CODETITAN_API_URL || 'https://api.codetitan.dev';
            sharedReportUrl = await shareReport(report, apiKey, apiBase);
            if (sharedReportUrl) {
                action_kit_1.core.info(`Report shared: ${sharedReportUrl}`);
                action_kit_1.core.setOutput('report-url', sharedReportUrl);
            }
            else {
                action_kit_1.core.warning('Report share failed or is unavailable — PR comment will not include a report URL.');
                action_kit_1.core.setOutput('report-url', '');
            }
        }
        else {
            action_kit_1.core.setOutput('report-url', '');
        }
        const markdownSummary = buildMarkdownSummary(report, findings, failOnSeverity, riskThreshold, metrics, sharedReportUrl);
        const passed = !hasBlockingFindings(findings, failOnSeverity) && (report.prRiskScore?.score || 0) < riskThreshold;
        fs.writeFileSync(summaryPath, `${markdownSummary}\n`, 'utf8');
        await writeStepSummary(markdownSummary);
        action_kit_1.core.setOutput('passed', String(passed));
        action_kit_1.core.setOutput('findings', String(findings.length));
        action_kit_1.core.setOutput('runtime-mode', metrics.runtimeLabel);
        action_kit_1.core.setOutput('runtime-cache-hit', String(metrics.cacheHit));
        action_kit_1.core.setOutput('runtime-root', metrics.runtimeRoot || process.env.CODETITAN_ACTION_RUNTIME_ROOT || '');
        action_kit_1.core.setOutput('runtime-bootstrap-ms', String(metrics.bootstrapDurationMs));
        action_kit_1.core.setOutput('analysis-ms', String(metrics.analysisDurationMs));
        action_kit_1.core.setOutput('total-ms', String(metrics.totalDurationMs));
        action_kit_1.core.setOutput('personalization-score', String(report.summary?.personalizationScore || 0));
        action_kit_1.core.setOutput('risk-score', String(report.prRiskScore?.score || 0));
        action_kit_1.core.setOutput('report-path', reportPath);
        action_kit_1.core.setOutput('summary-path', summaryPath);
        action_kit_1.core.setOutput('top-findings-summary', summarizeTopFindings(findings));
        action_kit_1.core.setOutput('failure-kind', 'none');
        if (format === 'sarif' || format === 'both') {
            fs.writeFileSync(sarifPath, JSON.stringify(buildSarifReport(findings), null, 2), 'utf8');
            action_kit_1.core.setOutput('sarif-path', sarifPath);
        }
        else {
            action_kit_1.core.setOutput('sarif-path', '');
        }
        if (commentOnPR && githubToken) {
            await upsertPullRequestComment(githubToken, markdownSummary);
        }
        else if (commentOnPR && isPullRequestEvent) {
            action_kit_1.core.info('Skipping PR comment because no GitHub token is available.');
        }
        if ((report.prRiskScore?.score || 0) >= riskThreshold) {
            action_kit_1.core.setOutput('failure-kind', 'risk_gate');
            action_kit_1.core.setFailed(`CodeTitan PR risk score ${report.prRiskScore.score} meets or exceeds threshold ${riskThreshold}.`);
            return;
        }
        if (hasBlockingFindings(findings, failOnSeverity)) {
            action_kit_1.core.setOutput('failure-kind', 'quality_gate');
            action_kit_1.core.setFailed(`CodeTitan found ${findings.length} MVP-scope findings, including items at ${failOnSeverity} severity or above.`);
            return;
        }
        action_kit_1.core.info('CodeTitan verification completed without blocking findings.');
    }
    catch (error) {
        action_kit_1.core.setOutput('failure-kind', 'action_error');
        action_kit_1.core.setFailed(`Action failed with error: ${error.message}`);
    }
}
if (require.main === require.cache[eval('__filename')]) {
    run();
}


/***/ }),

/***/ 317:
/***/ ((module) => {

module.exports = require("child_process");

/***/ }),

/***/ 896:
/***/ ((module) => {

module.exports = require("fs");

/***/ }),

/***/ 692:
/***/ ((module) => {

module.exports = require("https");

/***/ }),

/***/ 339:
/***/ ((module) => {

module.exports = require("module");

/***/ }),

/***/ 857:
/***/ ((module) => {

module.exports = require("os");

/***/ }),

/***/ 928:
/***/ ((module) => {

module.exports = require("path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId].call(module.exports, module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __nccwpck_require__(194);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;