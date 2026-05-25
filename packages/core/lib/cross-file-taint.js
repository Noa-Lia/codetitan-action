/**
 * Cross-File Taint Analysis
 *
 * Extends single-file taint tracking to follow user-controlled data
 * across module boundaries (one level deep — import/export tracking).
 *
 * Strategy:
 *   Phase 1 — Build export map: scan all JS/TS files, find functions that
 *              accept tainted parameters and return/pass them to sinks.
 *   Phase 2 — Resolve imports: find where exported tainted functions are called
 *              with user data as arguments.
 *   Phase 3 — Report inter-file taint paths.
 *
 * Limitations (honest):
 *   - 1 level deep (file A → file B, not A → B → C)
 *   - No type system (TS types ignored)
 *   - Named exports only (not default export detection)
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { hasSuppressionDirective } = require("./domain-analyzers");

// ── Re-use the same source / sink definitions as taint-analyzer.js ────────────
const SOURCE_PATTERNS = [
  /req\.(body|params|query|headers)\b/,
  /request\.(body|params|query|headers)\b/,
  /process\.argv\b/,
  /readline\b/,
  /event\.data\b/,
  /getenv\b/,
  /os\.environ\b/,
  /ctx\.(params|query|body|request)\b/,
  /c\.(param|query|body)\b/,
];

const SINKS = [
  { pattern: /\beval\s*\(/, category: "EVAL" },
  {
    pattern: /\b(exec|execSync|spawnSync|spawn|execFile|execFileSync)\s*\(/,
    category: "COMMAND_INJECTION",
  },
  {
    pattern:
      /\b(db|pool|client|conn|connection|knex|sequelize|pg|mysql|sqlite)\s*\.\s*(query|execute|run|all|get|raw)\s*\(/,
    category: "SQL_INJECTION",
  },
  // FN-3 Tier 1 (2026-05-18): Prisma standard API (findUnique/findMany/create/etc.)
  // with chain-prefix support (this.prisma, dbRead.prisma, tx.prisma).
  // Primary blocker for Prisma-heavy codebases (cal.com: 1912 such calls, 0 caught pre-fix).
  {
    pattern:
      /\b(?:\w+\.)*prisma\w*\s*\.\s*\w+\s*\.\s*(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany|create|createMany|update|updateMany|upsert|delete|deleteMany|count|aggregate|groupBy)\s*\(/,
    category: "SQL_INJECTION",
  },
  // FN-3 Tier 1: Prisma raw — supports tagged-template form, type generics,
  // and chain prefixes (this.prisma, tx.$queryRaw, this.prismaClient.$queryRaw).
  // Replaces the prior call-only pattern that missed cal.com's dominant tagged-template form.
  {
    pattern:
      /\b(?:\w+\.)*(?:prisma\w*|tx|client)\s*\.\s*\$(?:queryRaw|executeRaw|queryRawUnsafe|executeRawUnsafe)(?:<[^>]+>)?\s*[`(]/,
    category: "SQL_INJECTION",
  },
  // FN-3 Tier 1: Drizzle ORM — top-level query builder verbs with chain prefix.
  {
    pattern:
      /\b(?:\w+\.)*(?:db|drizzle)\s*\.\s*(?:select|insert|update|delete|with|transaction)\s*\(/,
    category: "SQL_INJECTION",
  },
  // better-sqlite3 prepared-statement SINK removed 2026-05-19 per Codex audit
  // (docs/plans/2026-05-19-cross-file-3commit-audit-codex.md, P1 finding):
  // bodyHasSink's line-only param check cannot distinguish safe bound
  // parameters (db.prepare("... ?").get(id)) from unsafe string concat
  // (db.prepare("... " + id).get()) — both match the same pattern with
  // `id` on the sink line. #319 (2026-05-24) added a bracket-bind heuristic
  // that closes the FP on db.query("?", [id]) shapes, but better-sqlite3
  // uses positional bare args (.get(id)) — the bracket heuristic doesn't
  // help. Restoration needs an arg-position gate; tracked separately.
  {
    pattern:
      /\b(?:Model|model|collection)\s*\.\s*(?:find|findOne|findById|update|updateOne|deleteOne|aggregate)\s*\(\s*\{/,
    category: "NOSQL_INJECTION",
  },
  { pattern: /\.innerHTML\s*=/, category: "XSS" },
  { pattern: /dangerouslySetInnerHTML\s*=/, category: "XSS" },
  { pattern: /document\.write\s*\(/, category: "XSS" },
  { pattern: /\.outerHTML\s*=/, category: "XSS" },
  {
    pattern:
      /\bfs\s*\.\s*(readFile|writeFile|appendFile|readFileSync|writeFileSync|unlink|unlinkSync|mkdir|mkdirSync)\s*\(/,
    category: "PATH_TRAVERSAL",
  },
  {
    pattern: /\bpath\s*\.\s*(join|resolve|normalize)\s*\(/,
    category: "PATH_TRAVERSAL",
  },
  { pattern: /\bres\s*\.\s*redirect\s*\(/, category: "OPEN_REDIRECT" },
  {
    pattern:
      /\b(?:fetch|axios|got|superagent|request|http\.get|https\.get)\s*\(/,
    category: "SSRF",
  },
  {
    pattern:
      /\b(?:ejs\.render|pug\.render|handlebars\.compile|nunjucks\.render|mustache\.render)\s*\(/,
    category: "TEMPLATE_INJECTION",
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function isJsTs(filePath) {
  return /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(filePath);
}

function readSync(filePath) {
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch (_) {
    return null;
  }
}

/**
 * Extract param names from a function signature string.
 * Handles:
 *   ("userInput, options")          → ["userInput", "options"]
 *   ("name: string")                → ["name"]
 *   ("{name, email}")               → ["name", "email"]     (FN-2 M7/M8 destructuring)
 *   ("{name: alias}")               → ["alias"]             (local rename)
 *   ("{...rest}")                   → ["rest"]
 *   ("req, {name, email}, opts")    → ["req", "name", "email", "opts"]
 */
function splitTopLevelCommas(str) {
  // Split on commas that are NOT inside {}, [], <>, or ().
  const out = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === "{" || c === "[" || c === "<" || c === "(") depth++;
    else if (c === "}" || c === "]" || c === ">" || c === ")") depth--;
    else if (c === "," && depth === 0) {
      out.push(str.slice(start, i));
      start = i + 1;
    }
  }
  out.push(str.slice(start));
  return out;
}

function extractParams(sigStr) {
  const m = sigStr.match(/\(([^)]*)\)/);
  if (!m) return [];
  const tokens = splitTopLevelCommas(m[1]);
  const results = [];
  for (const tok of tokens) {
    const trimmed = tok.trim();
    if (!trimmed) continue;
    // Destructured object pattern: {a, b: alias, ...rest}
    const destruct = trimmed.match(/^\{([^}]*)\}/);
    if (destruct) {
      const inner = splitTopLevelCommas(destruct[1]);
      for (const innerTok of inner) {
        const innerTrim = innerTok
          .trim()
          .replace(/^\.\.\./, "") // ...rest → rest
          .split(/[=]/)
          .shift()
          .trim();
        // Rename: "src: local" → take local name (RHS of colon)
        const renamed = innerTrim.match(/^(\w+)\s*:\s*(\w+)/);
        if (renamed) results.push(renamed[2]);
        else if (/^\w+$/.test(innerTrim)) results.push(innerTrim);
      }
      continue;
    }
    // Plain (or TS-annotated) param
    const name = trimmed
      .split(/[=:]/)
      .shift()
      .trim()
      .replace(/^\.\.\./, "");
    if (/^\w+$/.test(name)) results.push(name);
  }
  return results;
}

/**
 * #319 helper: returns true when *every* occurrence of any param name on
 * the given line is inside a `[...]` bracket group. Used to recognize the
 * `db.query("... ?", [id])` bound-parameter shape: the param is in the
 * bind-array argument, not interpolated into the SQL string itself.
 *
 * Limitation: assumes a single statement per line and brackets don't span
 * lines; misses nested array-of-arrays edge cases. Trade-off accepted for
 * a narrow FP fix; the full "real arg-aware gate" is deferred.
 */
function paramOnlyInBindBrackets(line, paramNames) {
  const bracketRegions = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "[") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "]") {
      depth--;
      if (depth === 0 && start >= 0) {
        bracketRegions.push([start, i]);
        start = -1;
      }
    }
  }
  if (bracketRegions.length === 0) return false;

  const inBracket = (idx) =>
    bracketRegions.some(([s, e]) => idx > s && idx < e);

  for (const p of paramNames) {
    const re = new RegExp(`\\b${p}\\b`, "g");
    let m;
    while ((m = re.exec(line)) !== null) {
      if (!inBracket(m.index)) return false;
    }
  }
  return true;
}

/**
 * Determine if a function body (string) contains a sink that involves
 * one of the listed param names.
 * Returns { hasSink, sinkCategory } or { hasSink: false }.
 */
function bodyHasSink(body, paramNames) {
  const lines = body.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*"))
      continue;

    // Strip single/double-quoted strings so sink + param-name patterns don't
    // match documentation prose inside an exported function body. Backticks
    // preserved so template-literal sinks still detect.
    const codeOnly = line.replace(/(['"])(?:\\.|(?!\1)[\s\S])*?\1/g, "''");

    for (const sink of SINKS) {
      if (!sink.pattern.test(codeOnly)) continue;
      // Check if any param name appears on the same line as the sink
      const paramOnLine = paramNames.some((p) =>
        new RegExp(`\\b${p}\\b`).test(codeOnly),
      );
      if (!paramOnLine) continue;

      // #319 bracket-bind gate (SQL_INJECTION only): if every occurrence of
      // a param is inside a `[...]` bracket group, treat as a bound parameter
      // (db.query("... ?", [id]) shape) rather than string-built SQL. This
      // closes the FP that #318 cited for better-sqlite3 and which equally
      // affects the live db.query SINK. The full "real arg-aware gate" (parse
      // the sink-call arglist, distinguish first-arg-string-concat from later
      // bind positions) is deferred. Other categories are unaffected.
      if (
        sink.category === "SQL_INJECTION" &&
        paramOnlyInBindBrackets(codeOnly, paramNames)
      )
        continue;

      return { hasSink: true, sinkCategory: sink.category };
    }
  }
  return { hasSink: false, sinkCategory: null };
}

// ── Phase 1: Build export map ─────────────────────────────────────────────────

/**
 * Scan a single file and return all exported functions that touch a sink
 * via their parameters.
 *
 * @returns {ExportedFn[]}
 *   ExportedFn = { name, paramNames, hasSink, sinkCategory }
 */
function scanExports(filePath) {
  const content = readSync(filePath);
  if (!content) return [];

  const results = [];

  // Pattern set — three export forms
  const exportPatterns = [
    // export function fnName(params) { body }
    /export\s+(?:async\s+)?function\s+(\w+)\s*(\([^)]*\))/g,
    // export const fnName = (params) => { body }  OR  bare-arrow `x =>`.
    // #320: `(\([^)]*\))` branch must capture so we can read it; the prior
    // alternation only captured the bare-arrow form, so `(name) =>` silently
    // landed as paramless and the export was dropped from the scan map.
    /export\s+const\s+(\w+)\s*=\s*(?:async\s+)?(?:(\([^)]*\))|(\w+))\s*=>/g,
    /export\s+const\s+(\w+)\s*=\s*(?:async\s+)?function\s*(\([^)]*\))/g,
    // module.exports.fnName = function(params) {
    /module\.exports\.(\w+)\s*=\s*(?:async\s+)?function\s*(\([^)]*\))/g,
    // exports.fnName = (params) => {  OR  = function(params) {
    /exports\.(\w+)\s*=\s*(?:async\s+)?(?:function\s*(\([^)]*\))|\(([^)]*)\)\s*=>)/g,
  ];

  for (const re of exportPatterns) {
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(content)) !== null) {
      const name = m[1];
      if (!name) continue;

      // Grab signature group — different capture positions per pattern.
      // m[2] is the `(params)` form (always wrapped); m[3] is the bare-arrow
      // form like `x =>`. extractParams needs parens, so wrap m[3] when it
      // is the only available capture.
      const sigGroup = m[2] || (m[3] ? `(${m[3]})` : "()");
      const paramNames = extractParams(sigGroup);

      // Crude body extraction: grab up to 60 lines after match position
      const afterMatch = content.slice(m.index);
      const bodyLines = afterMatch.split(/\r?\n/).slice(0, 60).join("\n");
      const { hasSink, sinkCategory } = bodyHasSink(bodyLines, paramNames);

      if (paramNames.length > 0) {
        results.push({ name, paramNames, hasSink, sinkCategory });
      }
    }
  }

  return results;
}

/**
 * Build export map for all JS/TS files.
 * @returns {Map<string, ExportedFn[]>} file path → exported functions
 */
function buildExportMap(files) {
  const map = new Map();
  for (const file of files) {
    if (!isJsTs(file)) continue;
    const exports = scanExports(file);
    if (exports.length > 0) map.set(file, exports);
  }
  return map;
}

// ── Phase 2: Resolve call sites ───────────────────────────────────────────────

/**
 * Given a relative import specifier and the file it appears in,
 * try to resolve it to an actual file in `files`.
 */
function resolveImport(specifier, fromFile, files) {
  if (!specifier.startsWith(".") && !specifier.startsWith("/")) return null;

  const dir = path.dirname(fromFile);
  // `path.resolve` returns backslashes on Windows. Canonicalize to forward-slash
  // so the candidate strings line up with the forward-slash `files` array we
  // get from `analyzeCrossFileTaint`'s entry-normalization. Without this,
  // consumer-side path divergence (CLI passes backslash, API consumers pass
  // forward-slash) caused 0 findings on the second shape — see task #314.
  const base = path.resolve(dir, specifier).replace(/\\/g, "/");

  // Exact match or with extension
  const candidates = [
    base,
    base + ".js",
    base + ".ts",
    base + ".jsx",
    base + ".tsx",
    base + "/index.js",
    base + "/index.ts",
  ];

  // Normalise the files set once for fast lookup
  for (const c of candidates) {
    if (files.includes(c)) return c;
    // Case-insensitive fallback on Windows
    const lc = c.toLowerCase();
    const found = files.find((f) => f.toLowerCase() === lc);
    if (found) return found;
  }
  return null;
}

/**
 * Check if a call-site line passes a tainted (source-derived) variable
 * to the named function.
 */
function callSitePassesTaint(line, fnLocalName) {
  // Does the line call fnLocalName(...)?
  const callRe = new RegExp(`\\b${fnLocalName}\\s*\\(([^)]*)\\)`);
  const callMatch = line.match(callRe);
  if (!callMatch) return false;

  const argString = callMatch[1];
  // Does any SOURCE pattern appear directly in the argument list?
  return SOURCE_PATTERNS.some((sp) => sp.test(argString));
}

// ── Phase 3: Scan all files for import + call-site taint ─────────────────────

function scanCallerFile(filePath, exportMap, files) {
  const content = readSync(filePath);
  if (!content) return [];

  const findings = [];
  const lines = content.split(/\r?\n/);

  // Collect all imports in this file: specifier → [{ localName, importedName }]
  const importedFns = []; // { localName, importedName, resolvedFile }

  // ES module imports: import { fnName } from './path'
  const esImportRe = /import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = esImportRe.exec(content)) !== null) {
    const specifier = m[2];
    const resolvedFile = resolveImport(specifier, filePath, files);
    if (!resolvedFile || !exportMap.has(resolvedFile)) continue;

    const parts = m[1].split(",");
    for (const part of parts) {
      const trimmed = part.trim();
      // Handle aliasing: `fnName as localName`
      const alias = trimmed.match(/(\w+)\s+as\s+(\w+)/);
      if (alias) {
        importedFns.push({
          localName: alias[2],
          importedName: alias[1],
          resolvedFile,
        });
      } else if (/^\w+$/.test(trimmed)) {
        importedFns.push({
          localName: trimmed,
          importedName: trimmed,
          resolvedFile,
        });
      }
    }
  }

  // CommonJS destructured require: const { fnName } = require('./path')
  const cjsDestructRe =
    /(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = cjsDestructRe.exec(content)) !== null) {
    const specifier = m[2];
    const resolvedFile = resolveImport(specifier, filePath, files);
    if (!resolvedFile || !exportMap.has(resolvedFile)) continue;

    const parts = m[1].split(",");
    for (const part of parts) {
      const trimmed = part.trim();
      const alias = trimmed.match(/(\w+)\s*:\s*(\w+)/);
      if (alias) {
        importedFns.push({
          localName: alias[2],
          importedName: alias[1],
          resolvedFile,
        });
      } else if (/^\w+$/.test(trimmed)) {
        importedFns.push({
          localName: trimmed,
          importedName: trimmed,
          resolvedFile,
        });
      }
    }
  }

  if (importedFns.length === 0) return findings;

  // Scan each line for call sites
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) return;

    for (const imp of importedFns) {
      const exportedFns = exportMap.get(imp.resolvedFile) || [];
      const exportedFn = exportedFns.find((ef) => ef.name === imp.importedName);
      if (!exportedFn || !exportedFn.hasSink) continue;

      if (callSitePassesTaint(line, imp.localName)) {
        // Adapter-time suppression: directive on the previous line, matching
        // the surfaced category exactly. Mirrors the JS-taint adapter contract
        // at domain-analyzers.js:2541. #226 wired the rule-loop and adapter
        // paths but not this cross-file path — #353 closes that gap.
        const category = `CROSS_FILE_TAINT_${exportedFn.sinkCategory}`;
        if (hasSuppressionDirective(lines, idx, category)) continue;

        const callerRel = path
          .relative(process.cwd(), filePath)
          .replace(/\\/g, "/");
        const importedRel = path
          .relative(process.cwd(), imp.resolvedFile)
          .replace(/\\/g, "/");

        findings.push({
          line: idx + 1,
          column: 0,
          severity: "HIGH",
          category,
          message: `Cross-file taint: user input flows from \`${callerRel}\` into \`${imp.importedName}\` in \`${importedRel}\` which reaches a ${exportedFn.sinkCategory} sink.`,
          impact: 8,
          snippet: trimmed,
          taintPath: [filePath, imp.resolvedFile],
          file: filePath,
        });
      }
    }
  });

  return findings;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Run cross-file taint analysis across the provided file list.
 *
 * @param {string}   projectPath  Root path of the project (used for resolution)
 * @param {string[]} files        Absolute paths to all files in scope
 * @param {object}   [options]    Optional flags (reserved for future use)
 * @returns {Promise<object[]>}   Array of taint findings
 */
async function analyzeCrossFileTaint(projectPath, files, options = {}) {
  try {
    // Canonicalize input paths to forward-slash. CLI's discoverFiles produces
    // backslash on Windows; external API consumers may pass forward-slash.
    // Internal lookups in resolveImport build candidate strings via
    // `path.resolve` (backslash on Windows) then normalize to forward-slash,
    // so the `files` array must also be forward-slash for `.includes()` to hit.
    // Without this canonical shape, consumer-side path divergence caused
    // 0 cross-file findings on forward-slash inputs even though backslash
    // worked — see task #314.
    const jsFiles = files.filter(isJsTs).map((f) => f.replace(/\\/g, "/"));
    if (jsFiles.length < 2) return [];

    // Phase 1
    const exportMap = buildExportMap(jsFiles);
    if (exportMap.size === 0) return [];

    // Phase 2 + 3
    const allFindings = [];
    for (const file of jsFiles) {
      const findings = scanCallerFile(file, exportMap, jsFiles);
      allFindings.push(...findings);
    }

    return allFindings;
  } catch (_) {
    return [];
  }
}

module.exports = { analyzeCrossFileTaint };
