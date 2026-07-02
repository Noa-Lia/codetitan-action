/**
 * Hierarchical Orchestrator
 *
 * Coordinates 50+ agents across 5 Domain Titans for comprehensive codebase analysis.
 * Distributes tasks, manages waves, and collects results from all agents.
 *
 * Phase 3 Component 1
 */

const fs = require("fs").promises;
const path = require("path");
const { AIProviderManager } = require("./ai-providers");
const { analyzeDomain: heuristicAnalyze } = require("./domain-analyzers");
const CacheManager = require("./cache-manager");

class HierarchicalOrchestrator {
  constructor() {
    // 5 Domain Titans
    this.domainGods = [
      "security-god",
      "performance-god",
      "test-god",
      "refactoring-god",
      "documentation-god",
    ];
    this.selectedDomains = [...this.domainGods];

    // Agent management
    this.activeAgents = new Map();
    this.taskQueue = [];
    this.results = [];

    // Configuration
    this.maxConcurrent = 50; // Maximum agents running in parallel
    this.agentsPerDomain = 10; // Workers per Domain God
    this.projectRoot = null;
    this.aiManager = null;
    this.taskOptions = {};
    this.noAi = false; // Set to true to skip Claude and use heuristics only

    // Cache manager (keyed per file content hash — avoids re-analyzing unchanged files)
    this.cacheManager = new CacheManager({
      cacheDir: path.join(process.cwd(), ".codetitan-cache"),
      ttl: 24 * 60 * 60 * 1000, // 24h
    });

    // Cost tracking for this run
    this.costTracker = {
      totalUSD: 0,
      budgetLimitUSD: 1.0, // default $1 cap per run
      apiCallCount: 0,
      cacheHits: 0,
    };

    // Metrics
    this.metrics = {
      totalFiles: 0,
      totalTasks: 0,
      completedTasks: 0,
      failedTasks: 0,
      startTime: null,
      endTime: null,
    };
  }

  /**
   * Main orchestration method: analyze entire codebase
   */
  async orchestrateFullAnalysis(projectPath, options = {}) {
    this.metrics.startTime = Date.now();
    this.projectRoot = projectPath;
    this.verbose = options.verbose !== false;
    // `quiet` is a stricter form of `!verbose`: it also suppresses unconditional
    // status lines (wave headers, synthesis trace) that the CLI's --format json
    // / --format sarif / --format sbom / --stream modes need eliminated for
    // machine-parseable stdout. Wired in from codetitan-orchestration.js which
    // receives it from packages/cli/src/lib/analyzer.ts via the runLocalAnalysis
    // option chain.
    this.quiet = options.quiet === true;
    this.taskOptions = options;
    this.noAi = options.noAi === true || options["no-ai"] === true;
    if (options.budget)
      this.costTracker.budgetLimitUSD = parseFloat(options.budget);

    if (this.verbose) {
      console.log(`\n[START] Starting full analysis of: ${projectPath}`);
      if (this.noAi) console.log("[INFO] --no-ai: heuristic-only mode");
    }

    // Initialize cache
    await this.cacheManager.initialize();

    try {
      // Step 1: Discover all files in project
      // Use profileProjectRoot (the real repo root) for ignore patterns when available.
      // This matters in diff-aware mode where projectPath is a temp workspace dir.
      const ignoreRoot = options.profileProjectRoot || projectPath;
      const files = await this.discoverFiles(projectPath, ignoreRoot);
      this.metrics.totalFiles = files.length;
      // skippedSourceFiles is set inside discoverFiles() on this.metrics.
      if (this.verbose) {
        console.log(`[FILES] Discovered ${files.length} files`);
      }

      // Step 2: Resolve which domains to run (based on level or explicit domains)
      const domains = this.resolveDomains(options.level, options.domains);
      this.selectedDomains = domains;

      // Initialize AI provider manager (heuristics fallback if no keys)
      this.aiManager =
        options.aiManager || new AIProviderManager(options.aiConfig || {});

      // Step 3: Distribute files to ALL selected Domain Gods
      const taskDistribution = this.createTaskDistribution(files, domains);
      if (this.verbose) {
        console.log(
          `[CHART] Distributed tasks across ${domains.length} Domain Titans`,
        );
      }

      // Step 4: Execute in waves (max 50 agents at a time)
      const results = await this.executeWaves(taskDistribution);
      if (this.verbose) {
        console.log(`[OK] Completed analysis: ${results.length} results`);
      }

      // Step 5: Cross-file JS/TS taint pass (project-wide, after per-file waves).
      //
      // 2026-05-18 js-wire-in: close the 6th-instance dead-code gap surfaced
      // by `docs/plans/2026-05-18-js-cross-file-integration-audit.md`.
      // `analyzeCrossFileTaint` (`packages/core/lib/cross-file-taint.js`)
      // has lived dormant since the monorepo workspace sync — its only call
      // site was `incremental-analyzer.js`, which has zero production
      // consumers and is not on the public API surface
      // (`packages/core/index.js`). This block is the first production wire
      // for the JS cross-file taint analyzer.
      //
      // Shape mirrors the Python cross-file wire pattern (project-wide pass
      // after `executeWaves`, gated on `>= 2` files of the relevant
      // language, best-effort try/catch with stderr warn, results pushed in
      // the `{god, file, findings:{issues:[...]}, metrics}` shape that
      // `result-synthesis-engine.js:73-96` `collectFindings` consumes).
      //
      // A SEPARATE kill-switch is used (`disableCrossFileJs` / env
      // `CODETITAN_DISABLE_CROSS_FILE_JS=1`) — distinct from the Python
      // `disableCrossFile` flag — so operators can toggle Python and JS
      // cross-file passes independently (mirrors the `disableGoTaint`
      // precedent established by the Go wire-in arc).
      try {
        const disableCrossFileJs =
          (this.taskOptions && this.taskOptions.disableCrossFileJs === true) ||
          process.env.CODETITAN_DISABLE_CROSS_FILE_JS === "1";
        // Match the analyzer's own `isJsTs` filter (`cross-file-taint.js:87-89`):
        // .js, .ts, .jsx, .tsx, .mjs, .cjs. Re-declared here to avoid
        // requiring the analyzer module when we're going to skip anyway.
        const jsFiles = files.filter((f) =>
          /\.(?:js|ts|jsx|tsx|mjs|cjs)$/i.test(f),
        );
        if (disableCrossFileJs && jsFiles.length >= 2) {
          // Only log when a pass would otherwise have run — avoids a
          // confusing "skipped" line on pure-Python/pure-Go repos with the
          // env var set.
          console.warn(
            "[codetitan] js cross-file taint analysis skipped (disabled via " +
              (process.env.CODETITAN_DISABLE_CROSS_FILE_JS === "1"
                ? "CODETITAN_DISABLE_CROSS_FILE_JS=1 env"
                : "disableCrossFileJs option") +
              ")",
          );
        }
        if (!disableCrossFileJs && jsFiles.length >= 2) {
          // Lazy require: matches the Python wire pattern and keeps the
          // analyzer module out of the load-path on pure-Python/pure-Go
          // scans. Re-requiring is cheap once Node's module cache hits.
          const { analyzeCrossFileTaint } = require("./cross-file-taint");
          const crossFileFindings = await analyzeCrossFileTaint(
            this.projectRoot,
            files,
            this.taskOptions || {},
          );
          for (const finding of crossFileFindings || []) {
            results.push({
              god: "security-god",
              file: finding.file,
              findings: {
                issues: [
                  {
                    line: finding.line,
                    column: finding.column || 0,
                    severity: finding.severity,
                    category: finding.category,
                    message: finding.message,
                    impact: finding.impact || 8,
                    snippet: finding.snippet,
                    taintPath: finding.taintPath,
                  },
                ],
                linesAnalyzed: 0,
                executionTime: 0,
              },
              metrics: {
                linesAnalyzed: 0,
                issuesFound: 1,
                executionTime: 0,
              },
            });
          }
          if (this.verbose && crossFileFindings && crossFileFindings.length) {
            console.log(
              `[CROSS-FILE] JS/TS cross-file taint: ${crossFileFindings.length} findings across ${jsFiles.length} .js/.ts file(s)`,
            );
          }
        }
      } catch (err) {
        // Best-effort: cross-file taint never crashes the main orchestration.
        // Warn-log makes future regressions visible in stderr rather than
        // silently producing zero cross-file findings.
        console.warn(
          "[codetitan] js cross-file: orchestrator-dispatch error:",
          err && err.message ? err.message : err,
        );
      }

      this.metrics.endTime = Date.now();
      return results;
    } catch (error) {
      console.error(`[ERROR] Orchestration failed:`, error);
      this.metrics.endTime = Date.now();
      throw error;
    }
  }

  /**
   * Load ignore patterns from project root. Reads .codetitanignore first
   * (user-authored rule/path suppressions), then .gitignore (so the walker
   * doesn't scan tree state the user has already told git to ignore).
   *
   * `.gitignore` negation lines (`!pattern`) are dropped — the existing
   * matcher only has exclude semantics, and every dir we want to keep
   * analyzing (source trees) isn't inside a blanket ignore anyway.
   */
  async loadIgnorePatterns(projectPath) {
    const patterns = [];

    // .codetitanignore — user-authored, takes precedence
    try {
      const content = await fs.readFile(
        path.join(projectPath, ".codetitanignore"),
        "utf8",
      );
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        // Rule-specific suppressions like "path/to/file.js:RULE_ID" — extract the path part
        const colonIdx = line.indexOf(":");
        patterns.push(colonIdx > -1 ? line.slice(0, colonIdx) : line);
      }
    } catch (_) {
      // No .codetitanignore — that's fine
    }

    // .gitignore — respect the user's "not source" intent
    try {
      const content = await fs.readFile(
        path.join(projectPath, ".gitignore"),
        "utf8",
      );
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        // Skip negation — the matcher has no un-ignore path. Losing negation semantics is
        // safe here because SKIP_DIRS already covers the dirs where negation typically applies.
        if (line.startsWith("!")) continue;
        // Normalize gitignore anchoring markers so the matcher's prefix-regex lands:
        //   leading "/" — root-anchored marker; our matcher is already root-relative.
        //   trailing "/" — directory-only marker; the matcher uses "(/.*)?$" to
        //     cover subpaths, so a trailing "/" would force `publish-check/` to
        //     require a literal slash that `publish-check` (dir name alone) lacks.
        let stripped = line.startsWith("/") ? line.slice(1) : line;
        if (stripped.endsWith("/")) stripped = stripped.slice(0, -1);
        if (stripped) patterns.push(stripped);
      }
    } catch (_) {
      // No .gitignore — that's fine
    }

    return patterns;
  }

  /**
   * Tokenize a normalized ignore pattern into literal / `*` / `**` tokens.
   * Mirrors the old regex translation's scan order (`**` claimed greedily
   * left-to-right first, then `*`), so `***` → globstar + star. Every other
   * character — including regex metacharacters and `?` — is a LITERAL.
   * (`?` was never a working glob wildcard here: the old translation left it
   * unescaped in the regex where it acted as a stray quantifier; treating it
   * as a literal is the predictable behavior.)
   */
  tokenizeIgnorePattern(pattern) {
    const tokens = [];
    let literal = "";
    let i = 0;
    while (i < pattern.length) {
      if (pattern[i] === "*") {
        if (literal) {
          tokens.push({ type: "lit", value: literal });
          literal = "";
        }
        if (pattern[i + 1] === "*") {
          tokens.push({ type: "globstar" });
          i += 2;
        } else {
          tokens.push({ type: "star" });
          i += 1;
        }
      } else {
        literal += pattern[i];
        i += 1;
      }
    }
    if (literal) tokens.push({ type: "lit", value: literal });
    return tokens;
  }

  /**
   * Build a NON-BACKTRACKING matcher for one ignore pattern.
   *
   * Semantics (unchanged from the regex translation it replaces):
   *   `*`  — zero or more chars within ONE path segment (never crosses `/`)
   *   `**` — zero or more chars, `/` included
   *   plus the directory-prefix rule: the pattern matches the whole relative
   *   path, or a leading prefix of it that ends immediately before a `/`
   *   (the old trailing `(/.*)?$`), so `dist` matches both `dist` and
   *   `dist/bundle.js` but never `distx`.
   *
   * Implementation: forward reachability DP over token list × path positions.
   * `reachable[i]` = "the tokens consumed so far can end exactly at s[0..i)".
   * Each token is one linear sweep (literal: shift by the literal; `*`: flood
   * within the current segment; `**`: flood to end-of-string), so matching is
   * O(pattern length × path length) with NO backtracking — an adversarial
   * pattern (`*a*a*a…`) against a long path segment is polynomial, not
   * exponential. This closes the BUG-1 ReDoS residual that the previous
   * regex-based matcher documented as a follow-up.
   */
  buildIgnoreMatcher(pattern) {
    const tokens = this.tokenizeIgnorePattern(pattern);

    // Fast path: no wildcards — the vast majority of real .gitignore lines
    // (plain names like `node_modules`). Exact match or directory prefix.
    if (tokens.length === 1 && tokens[0].type === "lit") {
      const literal = tokens[0].value;
      const prefix = `${literal}/`;
      return (s) => s === literal || s.startsWith(prefix);
    }

    return (input) => {
      const s = String(input);
      const n = s.length;
      let reachable = new Array(n + 1).fill(false);
      reachable[0] = true;

      for (const token of tokens) {
        const next = new Array(n + 1).fill(false);
        if (token.type === "lit") {
          const literal = token.value;
          for (let i = 0; i + literal.length <= n; i++) {
            if (reachable[i] && s.startsWith(literal, i)) {
              next[i + literal.length] = true;
            }
          }
        } else if (token.type === "star") {
          // Flood forward within the current segment: once a position is
          // reachable, every later position up to the next `/` is too.
          let carry = false;
          for (let i = 0; i <= n; i++) {
            if (i > 0 && s[i - 1] === "/") carry = false; // `*` can't consume `/`
            carry = carry || reachable[i];
            next[i] = carry;
          }
        } else {
          // globstar: flood forward unconditionally.
          let carry = false;
          for (let i = 0; i <= n; i++) {
            carry = carry || reachable[i];
            next[i] = carry;
          }
        }
        reachable = next;
      }

      // Directory-prefix acceptance — the old `(/.*)?$`.
      for (let j = 0; j <= n; j++) {
        if (reachable[j] && (j === n || s[j] === "/")) return true;
      }
      return false;
    };
  }

  /**
   * Compile raw ignore patterns to reusable matchers ONCE.
   *
   * BUG-1 (Custos field report, 2026-06-04): `matchesIgnorePattern` used to
   * call `new RegExp(...)` for every pattern on every file/dir during the walk
   * — O(files × patterns) regex COMPILATIONS. At a real repo root with a large
   * .gitignore that pegs one CPU core for minutes with no output (observed:
   * 639s CPU, ~2 MB mem, zero progress). Compiling each pattern exactly once
   * here removes that storm.
   *
   * BUG-1 ReDoS residual (closed): the first fix still translated patterns to
   * backtracking regexes, so `*a*a*a…` against a long path segment could go
   * super-linear inside one `.test()`; a 12-wildcard cap dropped dense lines
   * as a crude backstop (over-scanning their files). Matching now runs through
   * `buildIgnoreMatcher` — a linear-sweep DP with no backtracking — so the cap
   * is gone: wildcard-dense patterns are HONORED (files correctly ignored)
   * and adversarial patterns from untrusted .gitignore lines (fork-PR Action,
   * external cold-audit) stay polynomial.
   *
   * @param {string[]} patterns - raw .gitignore/.codetitanignore path patterns
   * @returns {Array<{ raw: string, match: (relativePath: string) => boolean }>}
   */
  compileIgnoreMatchers(patterns) {
    const matchers = [];
    for (const pattern of patterns || []) {
      const p = String(pattern).replace(/\\/g, "/");
      if (!p) continue;
      matchers.push({ raw: p, match: this.buildIgnoreMatcher(p) });
    }
    return matchers;
  }

  /**
   * Returns true if the given absolute path matches any of the ignore patterns.
   * Supports ** glob wildcards and directory-prefix matching.
   *
   * `patterns` may be either raw strings or pre-compiled matchers
   * ({ raw, regex }). Pre-compiled matchers are the hot path (see
   * compileIgnoreMatchers / discoverFiles); raw strings are compiled on demand
   * for backward compatibility with any direct caller.
   */
  matchesIgnorePattern(absolutePath, projectPath, patterns) {
    const relative = path
      .relative(projectPath, absolutePath)
      .replace(/\\/g, "/");
    const matchers =
      patterns.length > 0 && typeof patterns[0] === "object"
        ? patterns
        : this.compileIgnoreMatchers(patterns);
    for (const matcher of matchers) {
      // Exact match (cheap, no matcher call)
      if (matcher.raw === relative) return true;
      // `match` is the current compiled shape; `regex` kept for any external
      // caller still holding pre-rewrite { raw, regex } objects.
      if (
        matcher.match ? matcher.match(relative) : matcher.regex.test(relative)
      )
        return true;
    }
    return false;
  }

  /**
   * Discover all relevant files in project.
   * @param {string} projectPath - Root directory to walk for source files.
   * @param {string} [ignoreRoot] - Directory containing .codetitanignore (defaults to projectPath).
   */
  async discoverFiles(projectPath, ignoreRoot) {
    const files = [];
    const resolvedIgnoreRoot = ignoreRoot || projectPath;
    const ignorePatterns = await this.loadIgnorePatterns(resolvedIgnoreRoot);
    // BUG-1: compile every ignore pattern to a RegExp ONCE here, then reuse the
    // compiled matchers across the whole walk. Previously each pattern was
    // recompiled per file/dir (O(files × patterns) `new RegExp`), which pegged
    // a CPU core for minutes at a real repo root with a large .gitignore.
    const ignoreMatchers = this.compileIgnoreMatchers(ignorePatterns);
    if (this.verbose && ignorePatterns.length > 0) {
      console.log(
        `[FILES] Loaded ${ignorePatterns.length} ignore pattern(s) from .codetitanignore + .gitignore`,
      );
    }

    // BUG-1 safety net — wall-clock deadline (configurable; default 120s) +
    // periodic heartbeat. The deadline is cooperative — checked between
    // directory reads and between entries. Ignore matching itself is now
    // linear-time per pattern (buildIgnoreMatcher, non-backtracking), so a
    // single match can no longer stall past the budget; the deadline's job is
    // bounding the tree TRAVERSAL on very large repos and surfacing a clear
    // error instead of silence.
    const discoveryTimeoutMs =
      Number(
        (this.taskOptions && this.taskOptions.discoveryTimeoutMs) ||
          process.env.CODETITAN_DISCOVERY_TIMEOUT_MS ||
          0,
      ) || 120000;
    const discoveryStart = Date.now();
    let visitedEntries = 0;
    let lastHeartbeat = discoveryStart;
    const HEARTBEAT_MS = 5000;
    const SKIP_DIRS = new Set([
      "node_modules",
      ".git",
      ".codetitan",
      ".codetitan-cache",
      "dist",
      "build",
      "coverage",
      ".next",
      ".turbo",
      "out",
      "vendor",
      "__pycache__",
      "venv",
      ".venv",
      ".pytest_cache",
      ".mypy_cache",
      ".tox",
      ".ruff_cache",
      ".cache",
      "site-packages",
    ]);
    const SKIP_DIR_PREFIXES = [".next"];

    // File extensions to analyze. .cjs/.mjs are JS/TS-family and MUST be
    // included — omitting them was a silent false negative (the file was
    // dropped here, never analyzed, yet reported "0 skipped" and "clean").
    // detectLanguage() maps them to "js" so the rule loops AND the taint engine
    // (taint-analyzer.js allowlist) engage.
    //
    // NOTE: .cts/.mts are deliberately EXCLUDED from analysis (2026-05-31 audit).
    // The taint engine's own extension allowlist (taint-analyzer.js) does not
    // include them, so analyzing .cts/.mts would run regex rules but SILENTLY
    // skip the flagship taint detectors while reporting the file "analyzed" —
    // the exact silent-FN this P0 fix exists to kill. Re-add .cts/.mts here ONLY
    // together with the taint-analyzer allowlist. Until then they are counted as
    // SKIPPED source files (see UNANALYZED_SOURCE_EXTS below) so the report never
    // claims "0 skipped / clean" over a .cts/.mts file it never taint-analyzed.
    const extensions = [
      ".js",
      ".ts",
      ".jsx",
      ".tsx",
      ".cjs",
      ".mjs",
      ".py",
      ".java",
      ".go",
      ".rb",
    ];

    // Source extensions that exist in the wild but are NOT yet fully analyzed,
    // counted as SKIPPED and surfaced — never silently dropped while the repo is
    // reported "clean". This is the honest-skip-counter: "0 skipped" must mean we
    // looked at everything in scope, not "we didn't count what we ignored."
    //   - .vue/.svelte/.astro: single-file-component formats need a real
    //     extractor, not just an allowlist entry.
    //   - .cts/.mts: excluded from `extensions` above because the taint engine
    //     can't analyze them yet (see NOTE there); count them as skipped so we
    //     stay honest until taint support lands.
    const UNANALYZED_SOURCE_EXTS = new Set([
      ".vue",
      ".svelte",
      ".astro",
      ".cts",
      ".mts",
    ]);
    let skippedSourceFiles = 0;

    const self = this;
    // BUG-1 deadline guard: abort discovery once it exceeds the wall-clock
    // budget instead of pegging a core indefinitely. Throws a typed error so the
    // orchestrator surfaces a clear message rather than a silent hang. Checked
    // at each walk(dir) AND per-entry, so a single directory returning a huge
    // entry list cannot run its whole loop past the budget. (Per-pattern
    // matching is linear-time — see buildIgnoreMatcher — so no single match
    // can outrun the checks.)
    const checkDeadline = () => {
      if (Date.now() - discoveryStart > discoveryTimeoutMs) {
        const err = new Error(
          `File discovery exceeded ${discoveryTimeoutMs}ms (visited ${visitedEntries} entries, found ${files.length} so far). ` +
            `Aborting to avoid a hang. If this is a very large repo, raise CODETITAN_DISCOVERY_TIMEOUT_MS or scope the scan to a subdirectory.`,
        );
        err.code = "DISCOVERY_TIMEOUT";
        throw err;
      }
    };
    async function walk(dir) {
      checkDeadline();
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          // BUG-1 heartbeat: periodically show the scan is alive. Emitted to
          // stderr-style console.warn so it never corrupts machine-parseable
          // stdout (--format json/sarif/sbom/markdown), and only when not in
          // quiet mode.
          visitedEntries += 1;
          // Per-entry deadline check (cheap): bounds a single huge directory.
          if ((visitedEntries & 0x3ff) === 0) checkDeadline();
          if (!self.quiet && Date.now() - lastHeartbeat > HEARTBEAT_MS) {
            lastHeartbeat = Date.now();
            console.warn(
              `[FILES] still scanning… ${visitedEntries} entries visited, ${files.length} source file(s) found`,
            );
          }

          // Skip node_modules, .git, build directories, etc.
          if (entry.isDirectory()) {
            if (
              SKIP_DIRS.has(entry.name) ||
              SKIP_DIR_PREFIXES.some((prefix) => entry.name.startsWith(prefix))
            )
              continue;
            if (
              ignoreMatchers.length > 0 &&
              self.matchesIgnorePattern(
                fullPath,
                resolvedIgnoreRoot,
                ignoreMatchers,
              )
            )
              continue;
            await walk(fullPath);
          } else if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();
            if (!extensions.includes(ext)) {
              // Count recognized-but-unanalyzed source files so the report
              // never claims "clean" over a file class it never examined.
              if (UNANALYZED_SOURCE_EXTS.has(ext)) skippedSourceFiles += 1;
              continue;
            }
            if (
              ignoreMatchers.length > 0 &&
              self.matchesIgnorePattern(
                fullPath,
                resolvedIgnoreRoot,
                ignoreMatchers,
              )
            )
              continue;
            files.push(fullPath);
          }
        }
      } catch (error) {
        // Re-throw the deadline abort; only swallow real I/O errors (a dir we
        // can't read should be skipped, not fatal).
        if (error && error.code === "DISCOVERY_TIMEOUT") throw error;
        // Skip directories we can't read
        console.warn(`[WARNING]  Skipping ${dir}: ${error.message}`);
      }
    }

    await walk(projectPath);
    // Record the skipped-source count on metrics (NOT on the returned array —
    // attaching enumerable props to the array breaks callers that deep-equal it).
    this.metrics.skippedSourceFiles = skippedSourceFiles;
    return files;
  }

  /**
   * Resolve domains to run based on analysis level or explicit override.
   */
  resolveDomains(level, domainsOverride) {
    if (Array.isArray(domainsOverride) && domainsOverride.length > 0) {
      return domainsOverride;
    }

    const parsedLevel = parseInt(level, 10);
    const domainsByLevel = {
      1: ["security-god"],
      2: ["security-god", "performance-god"],
      3: ["security-god", "performance-god", "test-god"],
      4: ["security-god", "performance-god", "test-god", "refactoring-god"],
      5: [...this.domainGods],
      6: [...this.domainGods],
      7: [...this.domainGods],
      8: [...this.domainGods],
    };

    return domainsByLevel[parsedLevel] || domainsByLevel[6];
  }

  /**
   * Distribute files across selected Domain Titans.
   * Each file is analyzed by every selected domain.
   */
  createTaskDistribution(files, domains = this.domainGods) {
    const distribution = {};
    domains.forEach((god) => {
      distribution[god] = files;
    });

    this.metrics.totalTasks = files.length * domains.length;
    return distribution;
  }

  /**
   * Execute tasks in waves of 50 agents max
   */
  async executeWaves(taskDistribution) {
    const allResults = [];

    // Convert distribution to flat array of tasks
    const allTasks = [];
    Object.entries(taskDistribution).forEach(([god, files]) => {
      files.forEach((file) => {
        allTasks.push({ god, file });
      });
    });

    if (this.verbose) {
      console.log(
        `\n[BOLT] Executing ${allTasks.length} tasks in waves of ${this.maxConcurrent}`,
      );
    }

    // Execute in waves
    const batchSize = this.maxConcurrent;
    const totalWaves = Math.ceil(allTasks.length / batchSize);

    for (let waveNum = 0; waveNum < totalWaves; waveNum++) {
      const start = waveNum * batchSize;
      const end = Math.min(start + batchSize, allTasks.length);
      const waveTasks = allTasks.slice(start, end);

      if (!this.quiet) {
        console.log(
          `\n🌊 Wave ${waveNum + 1}/${totalWaves}: Processing ${waveTasks.length} task${waveTasks.length === 1 ? "" : "s"}`,
        );
      }

      // Execute wave in parallel
      const waveResults = await Promise.allSettled(
        waveTasks.map((task) => this.executeTask(task)),
      );

      // Collect results and handle failures
      waveResults.forEach((result, index) => {
        if (result.status === "fulfilled") {
          allResults.push(result.value);
          this.metrics.completedTasks++;
        } else {
          console.error(`[ERROR] Task failed:`, result.reason);
          this.metrics.failedTasks++;
          // Add error result
          allResults.push({
            god: waveTasks[index].god,
            file: waveTasks[index].file,
            error: result.reason.message || "Unknown error",
            findings: [],
          });
        }
      });

      // Brief pause between waves
      if (waveNum < totalWaves - 1) {
        await this.pauseBetweenWaves();
      }
    }

    return allResults;
  }

  /**
   * Execute a single task (analyze one file with one Domain God)
   */
  async executeTask({ god, file }) {
    try {
      const findings = await this.analyzeFileWithGod(
        god,
        file,
        this.taskOptions,
      );

      return {
        god,
        file,
        findings,
        metrics: {
          linesAnalyzed: findings.linesAnalyzed || 0,
          issuesFound: findings.issues?.length || 0,
          executionTime: findings.executionTime || 0,
        },
      };
    } catch (error) {
      throw new Error(
        `Failed to analyze ${file} with ${god}: ${error.message}`,
      );
    }
  }

  /**
   * Analyze a file with a domain god.
   *
   * Strategy:
   *   1. Check cache — return immediately on hit (zero API calls)
   *   2. Run heuristic pre-filter — fast, always-free baseline
   *   3. If noAi OR budget exhausted OR no Claude available: return heuristic results
   *   4. If heuristic found ≥1 issue OR file is >80 lines: send to Claude for deeper analysis
   *   5. Merge Claude + heuristic findings (deduplicate by line ±2)
   *   6. Save merged results to cache
   */
  async analyzeFileWithGod(god, file, options = {}) {
    const start = Date.now();

    // ── 1. Cache check ────────────────────────────────────────────────────────
    // CacheManager keys off file path (content hash + mtime). We scope per-domain
    // by checking the domain in the stored result rather than the key itself.
    const rawCached = await this.cacheManager.get(file);
    if (rawCached && rawCached[god]) {
      this.costTracker.cacheHits++;
      return rawCached[god];
    }

    // ── 2. Read file ──────────────────────────────────────────────────────────
    const content = await fs.readFile(file, "utf-8");
    const lines = content.split(/\r?\n/);

    // ── 3. Heuristic pre-filter (always runs, always free) ────────────────────
    let heuristicResult;
    try {
      heuristicResult = heuristicAnalyze(god, file, content, this.projectRoot);
    } catch (err) {
      heuristicResult = {
        issues: [],
        linesAnalyzed: lines.length,
        executionTime: 0,
      };
    }
    const heuristicIssues = heuristicResult.issues || [];

    // ── 4. Decide whether to call Claude ─────────────────────────────────────
    const shouldCallClaude =
      !this.noAi &&
      this.aiManager &&
      this.costTracker.totalUSD < this.costTracker.budgetLimitUSD &&
      (heuristicIssues.length > 0 || lines.length > 80);

    let finalIssues = heuristicIssues;
    let providerMetadata = { provider: "heuristic", cacheHit: false };

    if (shouldCallClaude) {
      try {
        // Estimate cost before calling — skip if single file would bust budget
        const estimatedTokens = Math.ceil(content.length / 4);
        const provider = await this.aiManager.getProvider("claude");
        if (provider) {
          const estimatedCost = provider.estimateCost(estimatedTokens, 600);
          if (
            this.costTracker.totalUSD + estimatedCost <=
            this.costTracker.budgetLimitUSD
          ) {
            const aiResult = await this.aiManager.analyze(
              god,
              file,
              content,
              this.projectRoot,
              {
                preferredProvider: "claude",
                budget:
                  this.costTracker.budgetLimitUSD - this.costTracker.totalUSD,
              },
            );

            const aiIssues = aiResult.issues || [];
            const costUSD = aiResult.metadata?.costUSD || 0;
            this.costTracker.totalUSD += costUSD;
            this.costTracker.apiCallCount++;

            // Merge: Claude + heuristic, deduplicate by (category, line ±2)
            finalIssues = this.mergeIssues(aiIssues, heuristicIssues);
            providerMetadata = {
              provider: "claude",
              fallbackUsed: aiResult.metadata?.fallbackUsed || false,
              costUSD,
              runningTotalUSD: this.costTracker.totalUSD,
              cacheHit: false,
            };
          } else {
            if (this.verbose) {
              console.warn(
                `[Budget] Skipping Claude for ${path.basename(file)} — budget cap reached ($${this.costTracker.totalUSD.toFixed(3)})`,
              );
            }
          }
        }
      } catch (err) {
        // Claude failed — heuristic results already set as fallback
        if (this.verbose) {
          console.warn(
            `[Claude] Analysis failed for ${path.basename(file)}: ${err.message}`,
          );
        }
      }
    }

    const result = {
      issues: finalIssues,
      linesAnalyzed: lines.length,
      executionTime: Date.now() - start,
      metadata: providerMetadata,
    };

    // ── 5. Cache the result (domain-keyed within the file's cache entry) ────────
    // Merge with any existing cached domains for this file
    const existingEntry = (await this.cacheManager.get(file)) || {};
    existingEntry[god] = result;
    await this.cacheManager.set(file, existingEntry);

    return result;
  }

  /**
   * Merge Claude findings with heuristic findings.
   * Prefer Claude's finding when both flag the same location (line ±2, same category).
   * Append heuristic-only findings Claude missed.
   */
  mergeIssues(claudeIssues, heuristicIssues) {
    const merged = [...claudeIssues];
    const claimedLines = new Set(
      claudeIssues.map((i) => `${i.category}:${i.line}`),
    );

    for (const h of heuristicIssues) {
      // Check if Claude already flagged this location (±2 lines, same category)
      const isDuplicate = claudeIssues.some(
        (c) =>
          c.category === h.category &&
          Math.abs((c.line || 0) - (h.line || 0)) <= 2,
      );
      if (!isDuplicate) {
        merged.push(h);
      }
    }

    return merged;
  }

  /**
   * Pause between waves to avoid overwhelming the system
   */
  async pauseBetweenWaves() {
    const pauseMs = 500; // 500ms pause
    await new Promise((resolve) => setTimeout(resolve, pauseMs));
  }

  /**
   * Get orchestration metrics
   */
  getMetrics() {
    const duration = this.metrics.endTime
      ? this.metrics.endTime - this.metrics.startTime
      : Date.now() - this.metrics.startTime;

    return {
      ...this.metrics,
      duration,
      filesPerSecond:
        duration > 0 ? this.metrics.totalFiles / (duration / 1000) : 0,
      successRate:
        this.metrics.totalTasks > 0
          ? this.metrics.completedTasks / this.metrics.totalTasks
          : 0,
      failureRate:
        this.metrics.totalTasks > 0
          ? this.metrics.failedTasks / this.metrics.totalTasks
          : 0,
    };
  }
}

module.exports = HierarchicalOrchestrator;
