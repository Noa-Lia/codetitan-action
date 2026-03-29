/**
 * Taint Analyzer — Lightweight source-to-sink data flow tracking
 *
 * Tracks user-controlled values from sources to dangerous sinks
 * without a full AST — uses regex-based variable tracking with
 * single-level alias following.
 *
 * Sources (user-controlled input):
 *   req.body, req.params, req.query, req.headers, process.argv,
 *   readline, event.data, getenv(), os.environ
 *
 * Sinks (dangerous operations):
 *   eval(), exec/execSync/spawnSync, db.query/db.execute/pool.query,
 *   innerHTML, dangerouslySetInnerHTML, fs.readFile/writeFile with user path,
 *   res.send/res.json with raw input, document.write
 *
 * Sanitizers (break the taint chain):
 *   parseInt/parseFloat, Number(), encodeURIComponent, escape,
 *   validator.escape, parameterized query (?, $1), prepared statements,
 *   Joi/Yup/Zod .validate(), sanitize-html
 */

'use strict';

// ── Source patterns ──────────────────────────────────────────────────────────
const SOURCE_PATTERNS = [
  /req\.(body|params|query|headers)\b/,
  /request\.(body|params|query|headers)\b/,
  /process\.argv\b/,
  /readline\b/,
  /event\.data\b/,
  /getenv\b/,
  /os\.environ\b/,
  /ctx\.(params|query|body|request)\b/,  // Koa
  /c\.(param|query|body)\b/,              // Gin (Go-style)
];

// ── Sink patterns ────────────────────────────────────────────────────────────
const SINKS = [
  { pattern: /\beval\s*\(/, category: 'TAINT_EVAL', message: 'Tainted user input reaches eval().' },
  { pattern: /\b(exec|execSync|spawnSync|spawn|execFile|execFileSync)\s*\(/, category: 'TAINT_COMMAND_INJECTION', message: 'Tainted user input reaches shell command.' },
  // SQL: classic drivers + ORMs
  { pattern: /\b(db|pool|client|conn|connection|knex|sequelize|pg|mysql|sqlite)\s*\.\s*(query|execute|run|all|get|raw)\s*\(/, category: 'TAINT_SQL_INJECTION', message: 'Tainted user input may reach a SQL query.' },
  // Prisma raw queries
  { pattern: /\bprisma\s*\.\s*\$(?:queryRaw|executeRaw|queryRawUnsafe|executeRawUnsafe)\s*\(/, category: 'TAINT_SQL_INJECTION', message: 'Tainted user input in Prisma raw query.' },
  // Mongoose / MongoDB
  { pattern: /\b(?:Model|model|collection)\s*\.\s*(?:find|findOne|findById|update|updateOne|deleteOne|aggregate)\s*\(\s*\{/, category: 'TAINT_NOSQL_INJECTION', message: 'Tainted user input in MongoDB/Mongoose query — NoSQL injection risk.' },
  // XSS sinks
  { pattern: /\.innerHTML\s*=/, category: 'TAINT_XSS', message: 'Tainted user input assigned to innerHTML.' },
  { pattern: /dangerouslySetInnerHTML\s*=/, category: 'TAINT_XSS', message: 'Tainted user input in dangerouslySetInnerHTML.' },
  { pattern: /document\.write\s*\(/, category: 'TAINT_XSS', message: 'Tainted user input passed to document.write().' },
  { pattern: /\.outerHTML\s*=/, category: 'TAINT_XSS', message: 'Tainted user input assigned to outerHTML.' },
  // Filesystem path traversal
  { pattern: /\bfs\s*\.\s*(readFile|writeFile|appendFile|readFileSync|writeFileSync|unlink|unlinkSync|mkdir|mkdirSync)\s*\(/, category: 'TAINT_PATH_TRAVERSAL', message: 'Tainted user input used as file path.' },
  { pattern: /\bpath\s*\.\s*(join|resolve|normalize)\s*\(/, category: 'TAINT_PATH_TRAVERSAL', message: 'Tainted user input in path.join/resolve — path traversal risk.' },
  // Open redirect
  { pattern: /\bres\s*\.\s*redirect\s*\(/, category: 'TAINT_OPEN_REDIRECT', message: 'Tainted user input in res.redirect() — open redirect vulnerability.' },
  { pattern: /\bc\s*\.\s*redirect\s*\(/, category: 'TAINT_OPEN_REDIRECT', message: 'Tainted user input in redirect() — open redirect vulnerability.' },
  // SSRF
  { pattern: /\b(?:fetch|axios|got|superagent|request|http\.get|https\.get)\s*\(/, category: 'TAINT_SSRF', message: 'Tainted user input in HTTP request URL — Server-Side Request Forgery risk.' },
  // Template injection
  { pattern: /\b(?:ejs\.render|pug\.render|handlebars\.compile|nunjucks\.render|mustache\.render)\s*\(/, category: 'TAINT_TEMPLATE_INJECTION', message: 'Tainted user input passed to template engine — template injection risk.' },
];

// ── Sanitizer patterns (break taint) ─────────────────────────────────────────
const SANITIZER_PATTERNS = [
  /\bparseInt\s*\(/,
  /\bparseFloat\s*\(/,
  /\bNumber\s*\(/,
  /\bencodeURIComponent\s*\(/,
  /\bescape\s*\(/,
  /\bvalidator\.escape\s*\(/,
  /\bsanitize\b/i,
  /\bescapeHtml\b/i,
  // Parameterized query placeholders — must be inside a string literal adjacent to the sink
  // Match '?' ONLY inside a quoted SQL string (e.g. "SELECT * WHERE id = ?")
  /['"]\s*[^'"]*\?\s*[^'"]*['"]/,  // ? inside a string literal
  /\$\d+/,        // $1, $2, etc. (PostgreSQL positional params)
  // Named params only in SQL context (after query/execute keyword)
  /(?:query|execute|run)\s*\(\s*['"]\s*[^'"]*:[a-zA-Z_]\w*/,
  /,\s*\[/,       // array param style: query('...', [id])
  /,\s*\{/,       // object param style: query('...', { id })
  // Joi/Yup/Zod validation
  /\.(validate|parseAsync|safeParse)\s*\(/,
  // Prepared statements
  /\bprepare\s*\(/,
  /\bpreparedStatement\b/i,
  // Type coercion that removes injection risk
  /\bString\s*\(/,
  /\bBoolean\s*\(/,
  // Allow-list / whitelist checks
  /\b(?:whitelist|allowlist|allowedValues|ALLOWED)\b/i,
  // HTML encoding libraries
  /\bhe\.encode\b|\bentities\.encode\b|\bxss\s*\(/,
];

/**
 * Run taint analysis on a single file's content.
 *
 * Performs multi-pass inter-procedural taint tracking:
 *   Pass 1 — Find direct taint sources
 *   Pass 2 — Multi-round alias propagation (follows chains: a=src → b=a → c=b)
 *   Pass 3 — Function parameter taint inference (functions receiving tainted args)
 *   Pass 4 — Return value taint propagation (functions returning tainted values)
 *   Pass 5 — Sink scan with context-aware sanitizer detection
 *
 * @param {string} filePath - Path to the file (for language detection)
 * @param {string} content - File content
 * @returns {Array<Object>} Array of taint findings
 */
function analyzeTaint(filePath, content) {
  const lines = content.split(/\r?\n/);
  const issues = [];

  // Only analyze JS/TS/JSX/TSX files for now
  const ext = filePath.split('.').pop().toLowerCase();
  if (!['js', 'ts', 'jsx', 'tsx', 'mjs', 'cjs'].includes(ext)) {
    return issues;
  }

  const taintedVars = new Set();
  const taintedLineMap = new Map(); // varName → line number where first tainted

  // ── Pass 1: Find direct tainted variable assignments ──────────────────────
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) return;

    for (const sourcePattern of SOURCE_PATTERNS) {
      if (!sourcePattern.test(line)) continue;

      // const/let/var varName = <source>
      const assignMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*.+/);
      if (assignMatch) {
        taintedVars.add(assignMatch[1]);
        taintedLineMap.set(assignMatch[1], idx + 1);
      }

      // const { a, b } = <source>
      const destructureMatch = line.match(/(?:const|let|var)\s*\{([^}]+)\}\s*=\s*.+/);
      if (destructureMatch) {
        const vars = destructureMatch[1].split(',').map(v => v.trim().split(/\s+as\s+/).pop().trim());
        for (const v of vars) {
          if (/^\w+$/.test(v)) {
            taintedVars.add(v);
            taintedLineMap.set(v, idx + 1);
          }
        }
      }

      // const [a, b] = <source>  (array destructuring)
      const arrDestructureMatch = line.match(/(?:const|let|var)\s*\[([^\]]+)\]\s*=\s*.+/);
      if (arrDestructureMatch) {
        const vars = arrDestructureMatch[1].split(',').map(v => v.trim());
        for (const v of vars) {
          if (/^\w+$/.test(v)) {
            taintedVars.add(v);
            taintedLineMap.set(v, idx + 1);
          }
        }
      }

      // varName = <source> (reassignment without declaration)
      const reassignMatch = line.match(/\b(\w+)\s*=\s*(?:req|request|process\.argv|event\.data|readline|ctx)\s*\./);
      if (reassignMatch) {
        taintedVars.add(reassignMatch[1]);
        taintedLineMap.set(reassignMatch[1], idx + 1);
      }
    }
  });

  if (taintedVars.size === 0) return issues; // No sources — skip

  // ── Pass 2: Multi-round alias propagation ────────────────────────────────
  // Repeat until stable (handles chains: a=req.body, b=a, c=b → all tainted)
  let changed = true;
  for (let round = 0; round < 5 && changed; round++) {
    changed = false;
    lines.forEach((line, idx) => {
      // Simple alias: const x = y
      const simpleAlias = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*[;,\n)]/);
      if (simpleAlias && taintedVars.has(simpleAlias[2]) && !taintedVars.has(simpleAlias[1])) {
        taintedVars.add(simpleAlias[1]);
        taintedLineMap.set(simpleAlias[1], idx + 1);
        changed = true;
      }

      // Property access: const x = tainted.prop
      const propAccess = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\.[\w.]+/);
      if (propAccess && taintedVars.has(propAccess[2]) && !taintedVars.has(propAccess[1])) {
        taintedVars.add(propAccess[1]);
        taintedLineMap.set(propAccess[1], idx + 1);
        changed = true;
      }

      // Template literal: const x = `...${tainted}...`
      const templateLit = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{(\w+)\}`/);
      if (templateLit && taintedVars.has(templateLit[2]) && !taintedVars.has(templateLit[1])) {
        taintedVars.add(templateLit[1]);
        taintedLineMap.set(templateLit[1], idx + 1);
        changed = true;
      }

      // String concat: const x = tainted + "..." or "..." + tainted
      const concat = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:(\w+)\s*\+|.*\+\s*(\w+))/);
      if (concat) {
        const lhs = concat[1];
        const rhs1 = concat[2], rhs2 = concat[3];
        if (!taintedVars.has(lhs) && ((rhs1 && taintedVars.has(rhs1)) || (rhs2 && taintedVars.has(rhs2)))) {
          taintedVars.add(lhs);
          taintedLineMap.set(lhs, idx + 1);
          changed = true;
        }
      }
    });
  }

  // ── Pass 3: Function parameter taint (intra-file inter-procedural) ────────
  // If a tainted var is passed to a locally-defined function, mark that
  // function's return value as tainted too.
  // Strategy: find function definitions, check if tainted var appears as call arg,
  // then mark the function's return vars as tainted.
  const taintedFunctions = new Set(); // function names whose params receive tainted data

  lines.forEach((line, idx) => {
    // Detect calls: helper(taintedVar) or helper(a, taintedVar, b)
    const callMatch = line.match(/\b(\w+)\s*\(([^)]*)\)/g);
    if (callMatch) {
      for (const call of callMatch) {
        const m = call.match(/^(\w+)\s*\(([^)]*)\)/);
        if (!m) continue;
        const fnName = m[1];
        const args = m[2].split(',').map(a => a.trim());
        const hasTaintedArg = args.some(arg => taintedVars.has(arg));
        if (hasTaintedArg) {
          taintedFunctions.add(fnName);
        }
      }
    }
  });

  // Pass 3b: Find return values of tainted functions and mark as tainted
  if (taintedFunctions.size > 0) {
    let inTaintedFn = null;
    let braceDepth = 0;

    lines.forEach((line, idx) => {
      // Detect function definition entry
      const fnDefMatch = line.match(/(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))/);
      if (fnDefMatch) {
        const fnName = fnDefMatch[1] || fnDefMatch[2];
        if (fnName && taintedFunctions.has(fnName)) {
          inTaintedFn = fnName;
          braceDepth = 0;
        }
      }

      if (inTaintedFn) {
        braceDepth += (line.match(/\{/g) || []).length;
        braceDepth -= (line.match(/\}/g) || []).length;

        // Detect return statement
        const returnMatch = line.match(/\breturn\s+(\w+)/);
        if (returnMatch && !taintedVars.has(returnMatch[1])) {
          taintedVars.add(returnMatch[1]);
          taintedLineMap.set(returnMatch[1], idx + 1);
        }

        if (braceDepth <= 0) inTaintedFn = null;
      }
    });

    // Mark call-site assignments: const result = taintedFn(...)
    lines.forEach((line, idx) => {
      const callAssign = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(\w+)\s*\(/);
      if (callAssign && taintedFunctions.has(callAssign[2]) && !taintedVars.has(callAssign[1])) {
        taintedVars.add(callAssign[1]);
        taintedLineMap.set(callAssign[1], idx + 1);
      }
    });
  }

  // ── Pass 4: Deduplicated sink scan ───────────────────────────────────────
  const reportedLines = new Set(); // avoid duplicate findings on same line

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) return;
    if (reportedLines.has(idx)) return;

    for (const sink of SINKS) {
      if (!sink.pattern.test(line)) continue;

      const foundTaintedVar = [...taintedVars].find(v =>
        new RegExp(`\\b${escapeRegex(v)}\\b`).test(line)
      );
      if (!foundTaintedVar) continue;

      // Inline sanitizer check
      const isSanitized = SANITIZER_PATTERNS.some(sp => sp.test(line));
      if (isSanitized) continue;

      // Context window: 5 lines before (expanded from 3)
      const contextBefore = lines.slice(Math.max(0, idx - 5), idx).join('\n');
      const isSanitizedBefore = SANITIZER_PATTERNS.some(sp => sp.test(contextBefore)) &&
        new RegExp(`\\b${escapeRegex(foundTaintedVar)}\\b`).test(contextBefore);
      if (isSanitizedBefore) continue;

      issues.push({
        line: idx + 1,
        column: line.indexOf(foundTaintedVar),
        severity: 'HIGH',
        category: sink.category,
        message: `${sink.message} Variable \`${foundTaintedVar}\` originates from user input (line ${taintedLineMap.get(foundTaintedVar) || '?'}).`,
        impact: 9,
        snippet: trimmed,
        suggestion: `Validate and sanitize \`${foundTaintedVar}\` before use. For SQL, use parameterized queries. For shell commands, use argument arrays (not string interpolation).`
      });

      reportedLines.add(idx);
      break; // one finding per line
    }
  });

  return issues;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = { analyzeTaint };
