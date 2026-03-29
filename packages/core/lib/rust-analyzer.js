'use strict';

/**
 * Rust Security & Quality Analyzer
 *
 * Detects security and quality issues in Rust source files using
 * regex-based heuristics. Returns findings in CodeTitan format.
 *
 * @module rust-analyzer
 */

const RUST_RULES = [
  // Safety
  { id: 'UNSAFE_BLOCK',       severity: 'HIGH',     impact: 8,  pattern: /\bunsafe\s*\{/,                                                          message: 'Unsafe block detected. Ensure memory safety invariants are manually upheld.' },
  { id: 'UNWRAP_USAGE',       severity: 'MEDIUM',   impact: 5,  pattern: /\.(unwrap|expect)\s*\(/,                                                  message: '.unwrap()/.expect() can panic on None/Err; use ? operator or proper error handling.' },
  { id: 'PANIC_MACRO',        severity: 'MEDIUM',   impact: 5,  pattern: /\bpanic!\s*\(/,                                                           message: 'panic!() terminates the program; prefer returning Result or using recoverable errors.' },
  { id: 'TODO_UNIMPLEMENTED', severity: 'LOW',      impact: 3,  pattern: /\b(todo|unimplemented)!\s*\(/,                                            message: 'todo!()/unimplemented!() will panic at runtime if hit in production.' },
  // Memory
  { id: 'RAW_POINTER_DEREF',  severity: 'HIGH',     impact: 9,  pattern: /\*\s*(?:mut\s+)?(?:raw|ptr|p|pointer)\b|\bderef_unchecked\b/,            message: 'Raw pointer dereference detected; ensure bounds and lifetime validity.' },
  { id: 'TRANSMUTE_USAGE',    severity: 'CRITICAL', impact: 10, pattern: /std::mem::transmute\s*\(|mem::transmute\s*\(/,                           message: 'mem::transmute bypasses all type safety — highly dangerous, verify invariants.' },
  { id: 'FROM_RAW_PARTS',     severity: 'HIGH',     impact: 8,  pattern: /::from_raw_parts\s*\(/,                                                  message: 'from_raw_parts() requires valid pointer and length; incorrect use is UB.' },
  // Concurrency
  { id: 'MUTEX_POISON_IGNORED', severity: 'MEDIUM', impact: 6,  pattern: /\.lock\s*\(\s*\)\s*\.unwrap/,                                            message: 'Mutex::lock().unwrap() will panic if the mutex is poisoned; consider .lock().ok() or handle the PoisonError.' },
  { id: 'STATIC_MUT',         severity: 'HIGH',     impact: 8,  pattern: /static\s+mut\s+\w/,                                                      message: 'static mut is inherently unsafe and data-race-prone; prefer Mutex<T> or atomic types.' },
  // Cryptography
  { id: 'HARDCODED_KEY_RUST', severity: 'CRITICAL', impact: 10, pattern: /(?:key|secret|password|token)\s*:\s*(?:&\s*)?(?:str|[u8])\s*=\s*(?:b?["'])/, message: 'Hardcoded cryptographic key or secret in Rust code.' },
  // Command injection
  { id: 'COMMAND_FROM_STR',   severity: 'HIGH',     impact: 9,  pattern: /Command::new\s*\(\s*(?:&format!|&\w+(?:\s*\+|\s*format!))/,             message: 'Command::new() with dynamic string — shell injection risk. Use fixed command strings and pass args separately.' },
  // Format strings
  { id: 'FORMAT_MACRO_INJECTION', severity: 'MEDIUM', impact: 6, pattern: /format!\s*\(\s*\w+(?:\s*,|\s*\))/,                                     message: 'format!() with a variable as format string may panic or expose data if user-controlled.' },
];

/**
 * Analyze Rust source code for security and quality issues.
 *
 * @param {string} content  - Raw file contents.
 * @param {string} filePath - Absolute or relative path to the file.
 * @returns {Array<{line:number, column:number, endLine:number, endColumn:number,
 *                  severity:string, category:string, message:string,
 *                  impact:number, snippet:string}>}
 */
function analyzeRust(content, filePath) {
  // Only process .rs files
  if (!filePath || !filePath.endsWith('.rs')) return [];

  // Skip test files
  const normalizedPath = filePath.replace(/\\/g, '/');
  if (/_test\.rs$/.test(normalizedPath) || /\/tests\//.test(normalizedPath)) return [];

  const lines = content.split(/\r?\n/);
  const findings = [];

  lines.forEach((line, index) => {
    const trimmed = line.trim();

    // Skip pure comment lines (Rust line comments start with //)
    if (/^\s*\/\//.test(line)) return;

    for (const rule of RUST_RULES) {
      const match = rule.pattern.exec(line);
      if (!match) continue;

      const column = match.index;
      const matchLength = match[0].length;

      findings.push({
        line:       index + 1,
        column,
        endLine:    index + 1,
        endColumn:  column + matchLength,
        severity:   rule.severity,
        category:   rule.id,
        message:    rule.message,
        impact:     rule.impact,
        snippet:    trimmed.substring(0, 120),
      });

      // One finding per line — take the first matching rule and move on
      break;
    }
  });

  return findings;
}

module.exports = { analyzeRust, RUST_RULES };
