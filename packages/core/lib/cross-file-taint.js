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

'use strict';

const fs = require('fs');
const path = require('path');

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
  { pattern: /\beval\s*\(/, category: 'EVAL' },
  { pattern: /\b(exec|execSync|spawnSync|spawn|execFile|execFileSync)\s*\(/, category: 'COMMAND_INJECTION' },
  { pattern: /\b(db|pool|client|conn|connection|knex|sequelize|pg|mysql|sqlite)\s*\.\s*(query|execute|run|all|get|raw)\s*\(/, category: 'SQL_INJECTION' },
  { pattern: /\bprisma\s*\.\s*\$(?:queryRaw|executeRaw|queryRawUnsafe|executeRawUnsafe)\s*\(/, category: 'SQL_INJECTION' },
  { pattern: /\b(?:Model|model|collection)\s*\.\s*(?:find|findOne|findById|update|updateOne|deleteOne|aggregate)\s*\(\s*\{/, category: 'NOSQL_INJECTION' },
  { pattern: /\.innerHTML\s*=/, category: 'XSS' },
  { pattern: /dangerouslySetInnerHTML\s*=/, category: 'XSS' },
  { pattern: /document\.write\s*\(/, category: 'XSS' },
  { pattern: /\.outerHTML\s*=/, category: 'XSS' },
  { pattern: /\bfs\s*\.\s*(readFile|writeFile|appendFile|readFileSync|writeFileSync|unlink|unlinkSync|mkdir|mkdirSync)\s*\(/, category: 'PATH_TRAVERSAL' },
  { pattern: /\bpath\s*\.\s*(join|resolve|normalize)\s*\(/, category: 'PATH_TRAVERSAL' },
  { pattern: /\bres\s*\.\s*redirect\s*\(/, category: 'OPEN_REDIRECT' },
  { pattern: /\b(?:fetch|axios|got|superagent|request|http\.get|https\.get)\s*\(/, category: 'SSRF' },
  { pattern: /\b(?:ejs\.render|pug\.render|handlebars\.compile|nunjucks\.render|mustache\.render)\s*\(/, category: 'TEMPLATE_INJECTION' },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function isJsTs(filePath) {
  return /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(filePath);
}

function readSync(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch (_) {
    return null;
  }
}

/**
 * Extract param names from a function signature string.
 * e.g. "(userInput, options)" → ["userInput", "options"]
 */
function extractParams(sigStr) {
  const m = sigStr.match(/\(([^)]*)\)/);
  if (!m) return [];
  return m[1]
    .split(',')
    .map(p => p.trim().split(/[=:]/).shift().trim().replace(/^\.\.\./, ''))
    .filter(p => /^\w+$/.test(p));
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
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    for (const sink of SINKS) {
      if (!sink.pattern.test(line)) continue;
      // Check if any param name appears on the same line as the sink
      const paramOnLine = paramNames.some(p => new RegExp(`\\b${p}\\b`).test(line));
      if (paramOnLine) return { hasSink: true, sinkCategory: sink.category };
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
    // export const fnName = (params) => { body }  OR  = function(params) {
    /export\s+const\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|(\w+))\s*=>/g,
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

      // Grab signature group — different capture positions per pattern
      const sigGroup = m[2] || m[3] || `(${m[3] || ''})`;
      const paramNames = extractParams(sigGroup);

      // Crude body extraction: grab up to 60 lines after match position
      const afterMatch = content.slice(m.index);
      const bodyLines = afterMatch.split(/\r?\n/).slice(0, 60).join('\n');
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
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) return null;

  const dir = path.dirname(fromFile);
  const base = path.resolve(dir, specifier);

  // Exact match or with extension
  const candidates = [
    base,
    base + '.js', base + '.ts', base + '.jsx', base + '.tsx',
    path.join(base, 'index.js'), path.join(base, 'index.ts'),
  ];

  // Normalise the files set once for fast lookup
  for (const c of candidates) {
    const norm = path.normalize(c);
    if (files.includes(norm) || files.includes(c)) return c;
    // Case-insensitive fallback on Windows
    const found = files.find(f => f.toLowerCase() === norm.toLowerCase());
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
  return SOURCE_PATTERNS.some(sp => sp.test(argString));
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

    const parts = m[1].split(',');
    for (const part of parts) {
      const trimmed = part.trim();
      // Handle aliasing: `fnName as localName`
      const alias = trimmed.match(/(\w+)\s+as\s+(\w+)/);
      if (alias) {
        importedFns.push({ localName: alias[2], importedName: alias[1], resolvedFile });
      } else if (/^\w+$/.test(trimmed)) {
        importedFns.push({ localName: trimmed, importedName: trimmed, resolvedFile });
      }
    }
  }

  // CommonJS destructured require: const { fnName } = require('./path')
  const cjsDestructRe = /(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = cjsDestructRe.exec(content)) !== null) {
    const specifier = m[2];
    const resolvedFile = resolveImport(specifier, filePath, files);
    if (!resolvedFile || !exportMap.has(resolvedFile)) continue;

    const parts = m[1].split(',');
    for (const part of parts) {
      const trimmed = part.trim();
      const alias = trimmed.match(/(\w+)\s*:\s*(\w+)/);
      if (alias) {
        importedFns.push({ localName: alias[2], importedName: alias[1], resolvedFile });
      } else if (/^\w+$/.test(trimmed)) {
        importedFns.push({ localName: trimmed, importedName: trimmed, resolvedFile });
      }
    }
  }

  if (importedFns.length === 0) return findings;

  // Scan each line for call sites
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) return;

    for (const imp of importedFns) {
      const exportedFns = exportMap.get(imp.resolvedFile) || [];
      const exportedFn = exportedFns.find(ef => ef.name === imp.importedName);
      if (!exportedFn || !exportedFn.hasSink) continue;

      if (callSitePassesTaint(line, imp.localName)) {
        const callerRel = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
        const importedRel = path.relative(process.cwd(), imp.resolvedFile).replace(/\\/g, '/');

        findings.push({
          line: idx + 1,
          column: 0,
          severity: 'HIGH',
          category: `CROSS_FILE_TAINT_${exportedFn.sinkCategory}`,
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
    const jsFiles = files.filter(isJsTs);
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
