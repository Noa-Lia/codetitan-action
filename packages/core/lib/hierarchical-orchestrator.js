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
   * Returns true if the given absolute path matches any of the ignore patterns.
   * Supports ** glob wildcards and directory-prefix matching.
   */
  matchesIgnorePattern(absolutePath, projectPath, patterns) {
    const relative = path
      .relative(projectPath, absolutePath)
      .replace(/\\/g, "/");
    for (const pattern of patterns) {
      const p = pattern.replace(/\\/g, "/");
      // Exact match
      if (p === relative) return true;
      // glob **  handling: convert to regex
      // Build regex: replace ** and * separately to avoid collision
      const regexStr =
        "^" +
        p
          .replace(/\*\*/g, "\x00GLOBSTAR\x00") // stash ** before escaping
          .replace(/\*/g, "\x00STAR\x00") // stash * before escaping
          .replace(/[.+^${}()|[\]\\]/g, "\\$&") // escape regex special chars
          .replace(/\x00GLOBSTAR\x00/g, ".*") // ** → .* (any path segment)
          .replace(/\x00STAR\x00/g, "[^/]*") + // * → single-segment wildcard
        "(/.*)?$";
      if (new RegExp(regexStr).test(relative)) return true;
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
    if (this.verbose && ignorePatterns.length > 0) {
      console.log(
        `[FILES] Loaded ${ignorePatterns.length} ignore pattern(s) from .codetitanignore + .gitignore`,
      );
    }
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

    // File extensions to analyze
    const extensions = [
      ".js",
      ".ts",
      ".jsx",
      ".tsx",
      ".py",
      ".java",
      ".go",
      ".rb",
    ];

    const self = this;
    async function walk(dir) {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          // Skip node_modules, .git, build directories, etc.
          if (entry.isDirectory()) {
            if (
              SKIP_DIRS.has(entry.name) ||
              SKIP_DIR_PREFIXES.some((prefix) => entry.name.startsWith(prefix))
            )
              continue;
            if (
              ignorePatterns.length > 0 &&
              self.matchesIgnorePattern(
                fullPath,
                resolvedIgnoreRoot,
                ignorePatterns,
              )
            )
              continue;
            await walk(fullPath);
          } else if (entry.isFile()) {
            const ext = path.extname(entry.name);
            if (!extensions.includes(ext)) continue;
            if (
              ignorePatterns.length > 0 &&
              self.matchesIgnorePattern(
                fullPath,
                resolvedIgnoreRoot,
                ignorePatterns,
              )
            )
              continue;
            files.push(fullPath);
          }
        }
      } catch (error) {
        // Skip directories we can't read
        console.warn(`[WARNING]  Skipping ${dir}: ${error.message}`);
      }
    }

    await walk(projectPath);
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
          `\n🌊 Wave ${waveNum + 1}/${totalWaves}: Processing ${waveTasks.length} files`,
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
