/**
 * Supply Chain Analyzer
 *
 * Detects malicious patterns and supply chain attack indicators in code.
 * Inspired by @nodesecure/js-x-ray (MIT) — ported to pure regex for zero
 * binary dependency. Catches the patterns that npm package malware commonly uses.
 *
 * Categories detected:
 *   - Dynamic code execution (eval, Function constructor, obfuscation)
 *   - Suspicious network calls (data exfiltration, unusual endpoints)
 *   - Environment variable harvesting
 *   - Filesystem exfiltration
 *   - Dependency confusion / typosquatting indicators
 *   - Trojan Source (bidirectional Unicode control chars)
 *   - Process / shell injection via postinstall hooks
 *   - Obfuscation indicators (high hex density, base64 blobs, char-code arrays)
 *
 * @module supply-chain-analyzer
 */

'use strict';

const _dbg = (...args) => process.stderr.write('[SupplyChain] ' + args.join(' ') + '\n');

// ── Trojan Source: bidirectional Unicode control characters ──────────────────
// These are invisible in most editors but can reverse/reorder code meaning
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069\u200F\u061C]/;

// ── High hex/base64 density — classic obfuscation signal ─────────────────────
const HEX_BLOB_PATTERN = /(?:0x[0-9a-fA-F]{4}[,\s]+){6,}/;
const BASE64_BLOB_PATTERN = /['"`][A-Za-z0-9+/]{60,}={0,2}['"`]/;
const CHAR_CODE_ARRAY_PATTERN = /(?:\d{2,3}[,\s]+){10,}/;  // long arrays of char codes

// ── Dynamic require / import with concatenated string ─────────────────────────
const DYNAMIC_REQUIRE_PATTERN = /require\s*\(\s*(?:[^'"`)\s]+\s*\+|\[)/;
const DYNAMIC_IMPORT_PATTERN = /import\s*\(\s*(?:[^'"`)\s]+\s*\+|\[)/;

// ── Environment variable harvesting ──────────────────────────────────────────
// Bulk harvest: iterating over process.env keys and sending/writing them
const ENV_HARVEST_PATTERN = /(?:Object\.(?:keys|entries|values)\s*\(\s*process\.env|for\s*\([^)]*\s+(?:in|of)\s+process\.env)/;

// ── Suspicious exfil destinations ─────────────────────────────────────────────
// Requests to raw IP addresses or non-standard ports from a library
const RAW_IP_REQUEST = /(?:fetch|axios|http\.(?:get|post|request)|https\.(?:get|post|request))\s*\(\s*['"`]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
const NGROK_TUNNEL = /\.ngrok(?:\.io|\.app|free\.app)\b/;
const BURP_COLLABORATOR = /\.burpcollaborator\.net\b/;
const REQUESTBIN = /(?:requestbin|hookbin|beeceptor|webhook\.site)\b/;
const INTERACTSH = /\.oast\.(?:fun|me|online|site|pro|live)\b/;

// ── postinstall / lifecycle script exfil ─────────────────────────────────────
const POSTINSTALL_EXEC = /["'](?:postinstall|preinstall|install|prepare)["']\s*:\s*["'](?:node|sh|bash|python|curl|wget)/;

// ── DNS / encoded exfil ────────────────────────────────────────────────────────
const DNS_EXFIL = /dns\.(?:resolve|lookup)\s*\([^)]*(?:env|process|secret|key|token|password)/i;

// ── Suspicious combinations: fetch/axios sending env data ────────────────────
const SEND_ENV_DATA = /(?:fetch|axios|http\.request|https\.request)\s*[\s\S]{0,200}process\.env/;

// ── Shadow npm / install-time execution ───────────────────────────────────────
const INSTALL_TIME_EXEC = /require\s*\(['"`]child_process['"`]\)\s*\.(?:exec|spawn|execSync)/;

// ── Dangerous Buffer.from with base64 + eval ─────────────────────────────────
const BUFFER_EVAL = /eval\s*\(\s*(?:Buffer\.from|atob|decodeURIComponent)\s*\(/;
const BUFFER_BASE64_EXEC = /Buffer\.from\s*\(\s*['"`][A-Za-z0-9+/]{40,}={0,2}['"`]\s*,\s*['"`]base64['"`]\s*\)/;

/**
 * Analyze file content for supply chain attack indicators.
 *
 * @param {string} filePath - Path to the file being analyzed
 * @param {string} content  - Full file content
 * @param {object} [opts]   - Options
 * @param {boolean} [opts.isPackageFile] - True if this is inside node_modules
 * @returns {Array<object>} Array of findings in CodeTitan format
 */
const SUPPLY_CHAIN_INFRA_FILE_REGEX = /(?:fixers[\\/](?:command-exec-fixer|xss-fixer|fix-verifier)|tool-bridge|test-executor|benchmark-runner|supply-chain-analyzer)\.[jt]s$/i;

function analyzeSupplyChain(filePath, content, opts = {}) {
  // Skip engine infrastructure files that intentionally contain dangerous patterns as targets
  if (SUPPLY_CHAIN_INFRA_FILE_REGEX.test(filePath.replace(/\\/g, '/'))) return [];

  const findings = [];
  const lines = content.split(/\r?\n/);

  // ── Full-file checks (not line-by-line) ────────────────────────────────────

  // Trojan Source: scan the entire content for bidi chars
  if (BIDI_CHARS.test(content)) {
    const bidiLine = lines.findIndex(l => BIDI_CHARS.test(l));
    findings.push(makeFinding({
      line: bidiLine + 1,
      column: 0,
      severity: 'CRITICAL',
      category: 'TROJAN_SOURCE',
      message: 'Bidirectional Unicode control character detected. This can reverse code meaning invisibly (CVE-2021-42574).',
      impact: 10,
      snippet: lines[bidiLine] || ''
    }));
  }

  // Hex obfuscation blob
  if (HEX_BLOB_PATTERN.test(content)) {
    const hexLine = lines.findIndex(l => HEX_BLOB_PATTERN.test(l));
    if (hexLine >= 0) {
      findings.push(makeFinding({
        line: hexLine + 1,
        column: 0,
        severity: 'HIGH',
        category: 'OBFUSCATED_HEX',
        message: 'Dense hex literal array detected — common obfuscation technique in malicious packages.',
        impact: 8,
        snippet: lines[hexLine].slice(0, 120)
      }));
    }
  }

  // Char code array obfuscation
  if (CHAR_CODE_ARRAY_PATTERN.test(content)) {
    const charLine = lines.findIndex(l => CHAR_CODE_ARRAY_PATTERN.test(l));
    if (charLine >= 0) {
      findings.push(makeFinding({
        line: charLine + 1,
        column: 0,
        severity: 'MEDIUM',
        category: 'CHARCODE_OBFUSCATION',
        message: 'Long array of character codes detected — possible string obfuscation via fromCharCode().',
        impact: 7,
        snippet: lines[charLine].slice(0, 120)
      }));
    }
  }

  // Buffer + base64 blob (large base64 string decoded at runtime = classic packer)
  if (BUFFER_BASE64_EXEC.test(content)) {
    const bufLine = lines.findIndex(l => BUFFER_BASE64_EXEC.test(l));
    if (bufLine >= 0) {
      findings.push(makeFinding({
        line: bufLine + 1,
        column: 0,
        severity: 'HIGH',
        category: 'RUNTIME_BASE64_DECODE',
        message: 'Large base64 string decoded at runtime via Buffer.from — common payload packing technique.',
        impact: 8,
        snippet: lines[bufLine].slice(0, 120)
      }));
    }
  }

  // postinstall exfil
  if (POSTINSTALL_EXEC.test(content)) {
    const piLine = lines.findIndex(l => POSTINSTALL_EXEC.test(l));
    if (piLine >= 0) {
      findings.push(makeFinding({
        line: piLine + 1,
        column: 0,
        severity: 'CRITICAL',
        category: 'POSTINSTALL_EXEC',
        message: 'Lifecycle script (postinstall/preinstall) executes shell commands — review for install-time code execution.',
        impact: 10,
        snippet: lines[piLine]
      }));
    }
  }

  // ── Line-by-line checks ────────────────────────────────────────────────────
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || /^\s*(?:\/\/|#|\*)/.test(trimmed)) return;

    const lineNo = idx + 1;

    // eval(Buffer.from(...)) or eval(atob(...))
    if (BUFFER_EVAL.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: line.indexOf('eval'), severity: 'CRITICAL',
        category: 'EVAL_DECODE_EXEC',
        message: 'eval() executing decoded content (Buffer.from/atob) — active code execution of encoded payload.',
        impact: 10, snippet: trimmed
      }));
    }

    // Dynamic require with string concatenation
    if (DYNAMIC_REQUIRE_PATTERN.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: line.indexOf('require'), severity: 'HIGH',
        category: 'DYNAMIC_REQUIRE',
        message: 'Dynamic require() with runtime-computed module name — can load attacker-controlled modules.',
        impact: 8, snippet: trimmed
      }));
    }

    // Dynamic import with string concatenation
    if (DYNAMIC_IMPORT_PATTERN.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: line.indexOf('import'), severity: 'HIGH',
        category: 'DYNAMIC_IMPORT',
        message: 'Dynamic import() with runtime-computed path — can load attacker-controlled code.',
        impact: 8, snippet: trimmed
      }));
    }

    // Environment variable bulk harvest
    if (ENV_HARVEST_PATTERN.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'CRITICAL',
        category: 'ENV_HARVEST',
        message: 'Bulk iteration over process.env — pattern used in supply chain attacks to exfiltrate all environment variables.',
        impact: 10, snippet: trimmed
      }));
    }

    // Raw IP HTTP request
    if (RAW_IP_REQUEST.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'HIGH',
        category: 'RAW_IP_REQUEST',
        message: 'HTTP request to a raw IP address — legitimate libraries rarely use IPs directly; may indicate C2 communication.',
        impact: 9, snippet: trimmed
      }));
    }

    // Known exfil/C2 destinations
    if (NGROK_TUNNEL.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'CRITICAL',
        category: 'NGROK_EXFIL',
        message: 'Request to ngrok tunnel detected — commonly used in supply chain attacks for data exfiltration.',
        impact: 10, snippet: trimmed
      }));
    }

    if (BURP_COLLABORATOR.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'CRITICAL',
        category: 'BURP_COLLABORATOR',
        message: 'Burp Collaborator domain detected — used for out-of-band data exfiltration.',
        impact: 10, snippet: trimmed
      }));
    }

    if (REQUESTBIN.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'HIGH',
        category: 'REQUESTBIN_EXFIL',
        message: 'Request to a webhook inspection service (RequestBin/hookbin) — used for data exfiltration in supply chain attacks.',
        impact: 9, snippet: trimmed
      }));
    }

    if (INTERACTSH.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'CRITICAL',
        category: 'OAST_EXFIL',
        message: 'OAST (Out-of-band Application Security Testing) domain detected — used for covert data exfiltration.',
        impact: 10, snippet: trimmed
      }));
    }

    // DNS exfil
    if (DNS_EXFIL.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'HIGH',
        category: 'DNS_EXFILTRATION',
        message: 'DNS lookup with environment/secret data — possible DNS exfiltration channel.',
        impact: 9, snippet: trimmed
      }));
    }

    // Send env data over HTTP
    if (SEND_ENV_DATA.test(content.slice(Math.max(0, (idx - 3)) * 80, (idx + 3) * 80))) {
      // Only fire once per close proximity (check inline — crude but avoids full file re-scan)
    }

    // Install-time child_process exec in library code
    if (INSTALL_TIME_EXEC.test(line)) {
      findings.push(makeFinding({
        line: lineNo, column: 0, severity: 'HIGH',
        category: 'INSTALL_TIME_EXEC',
        message: 'child_process.exec/spawn inside library code — may execute at install time if called from lifecycle scripts.',
        impact: 9, snippet: trimmed
      }));
    }

    // Large base64 string (≥80 chars) not inside a comment
    const b64Match = BASE64_BLOB_PATTERN.exec(line);
    if (b64Match && b64Match[0].length > 80) {
      findings.push(makeFinding({
        line: lineNo, column: b64Match.index, severity: 'MEDIUM',
        category: 'LARGE_BASE64_BLOB',
        message: `Large base64-encoded blob (${b64Match[0].length - 2} chars) — may be an encoded payload. Verify this is expected (e.g., a legitimate asset).`,
        impact: 6, snippet: line.slice(b64Match.index, b64Match.index + 80) + '…'
      }));
    }
  });

  return findings;
}

/**
 * Format a finding into CodeTitan's standard issue shape.
 */
function makeFinding({ line, column, severity, category, message, impact, snippet }) {
  return {
    line,
    column: column || 0,
    endLine: line,
    endColumn: (column || 0) + (snippet?.length || 0),
    severity,
    category,
    message,
    impact,
    snippet: snippet ? snippet.slice(0, 200) : '',
    cwe: CWE_MAP[category] || 'CWE-506', // default: Embedded Malicious Code
    fixable: false
  };
}

const CWE_MAP = {
  TROJAN_SOURCE:       'CWE-116',  // Improper encoding/escaping
  OBFUSCATED_HEX:      'CWE-506',  // Embedded malicious code
  CHARCODE_OBFUSCATION:'CWE-506',
  RUNTIME_BASE64_DECODE:'CWE-506',
  POSTINSTALL_EXEC:    'CWE-78',   // Command injection
  EVAL_DECODE_EXEC:    'CWE-95',   // Improper neutralization of directives
  DYNAMIC_REQUIRE:     'CWE-427',  // Uncontrolled search path element
  DYNAMIC_IMPORT:      'CWE-427',
  ENV_HARVEST:         'CWE-200',  // Exposure of sensitive information
  RAW_IP_REQUEST:      'CWE-441',  // Unintended proxy/intermediary
  NGROK_EXFIL:         'CWE-200',
  BURP_COLLABORATOR:   'CWE-200',
  REQUESTBIN_EXFIL:    'CWE-200',
  OAST_EXFIL:          'CWE-200',
  DNS_EXFILTRATION:    'CWE-200',
  INSTALL_TIME_EXEC:   'CWE-78',
  LARGE_BASE64_BLOB:   'CWE-506',
};

module.exports = { analyzeSupplyChain };
