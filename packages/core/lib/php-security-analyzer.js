'use strict';
const PHP_RULES = [
  { id: 'PHP_SQL_INJECTION', severity: 'CRITICAL', impact: 10, pattern: /(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\$_(?:GET|POST|REQUEST)|(?:->(?:query|execute|prepare))\s*\([^)]*\$_(?:GET|POST|REQUEST)/, message: 'PHP SQL injection: user input interpolated directly into SQL query. Use PDO with prepared statements.' },
  { id: 'PHP_XSS', severity: 'HIGH', impact: 9, pattern: /echo\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[|print\s*\$_(?:GET|POST|REQUEST)/, message: 'PHP XSS: unescaped user input echoed to output. Use htmlspecialchars() or htmlentities().' },
  { id: 'PHP_COMMAND_INJECTION', severity: 'CRITICAL', impact: 10, pattern: /(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*[^"']*\$_(?:GET|POST|REQUEST)|`[^`]*\$_(?:GET|POST|REQUEST)/, message: 'PHP command injection: user input in shell execution. Validate strictly or use escapeshellarg().' },
  { id: 'PHP_FILE_INCLUSION', severity: 'CRITICAL', impact: 10, pattern: /(?:include|require|include_once|require_once)\s*[(\s]\s*\$_(?:GET|POST|REQUEST|COOKIE)/, message: 'PHP remote/local file inclusion: user input in include/require. Never use user input for file paths.' },
  { id: 'PHP_PATH_TRAVERSAL', severity: 'HIGH', impact: 9, pattern: /(?:file_get_contents|file_put_contents|fopen|readfile|unlink)\s*\(\s*[^"']*\$_(?:GET|POST|REQUEST)/, message: 'PHP path traversal: user-controlled file path. Use basename() and validate against an allowlist.' },
  { id: 'PHP_EVAL_INJECTION', severity: 'CRITICAL', impact: 10, pattern: /\beval\s*\(\s*\$/, message: 'PHP eval() with variable input — arbitrary code execution risk.' },
  { id: 'PHP_DESERIALIZATION', severity: 'CRITICAL', impact: 10, pattern: /unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|unserialize\s*\(\s*\$\w+/, message: 'PHP unsafe unserialize() — vulnerable to PHP object injection. Use json_decode() instead.' },
  { id: 'PHP_WEAK_CRYPTO', severity: 'HIGH', impact: 7, pattern: /\bmd5\s*\(|\bsha1\s*\(/, message: 'Weak hash (md5/sha1) for security purposes. Use password_hash() for passwords or hash("sha256", ...) for data integrity.' },
  { id: 'PHP_OPEN_REDIRECT', severity: 'HIGH', impact: 8, pattern: /header\s*\(\s*["']Location:\s*\$_(?:GET|POST|REQUEST)|header\s*\(\s*["']Location:\s*"\s*\.\s*\$/, message: 'PHP open redirect: user-controlled Location header. Validate against an allowlist of allowed destinations.' },
  { id: 'PHP_CSRF_NO_TOKEN', severity: 'MEDIUM', impact: 6, pattern: /\$_POST\[["'](?:action|submit|delete|update)["']\]/, message: 'PHP form action handler without visible CSRF token check. Ensure session-based CSRF tokens are validated.' },
  { id: 'PHP_HARDCODED_SECRET', severity: 'CRITICAL', impact: 10, pattern: /(?:password|passwd|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,}["']/i, message: 'PHP hardcoded credential. Move secrets to environment variables ($_ENV) or a secrets manager.' },
];

function analyzePhpSecurity(content, filePath) {
  if (!/\.php$/i.test(filePath)) return [];
  const findings = [];
  const lines = content.split(/\r?\n/);
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || /^\s*\/\/|^\s*#|^\s*\*/.test(trimmed)) return;
    for (const rule of PHP_RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      findings.push({ line: idx + 1, column: m.index, endLine: idx + 1, endColumn: m.index + m[0].length, severity: rule.severity, category: rule.id, message: rule.message, impact: rule.impact, snippet: trimmed.slice(0, 200) });
      break;
    }
  });
  return findings;
}
module.exports = { analyzePhpSecurity };
