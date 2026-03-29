'use strict';
// Java security rules — covers OWASP Top 10 patterns in Java/Spring/Servlet code
const JAVA_RULES = [
  // SQL injection
  { id: 'JAVA_SQL_INJECTION', severity: 'CRITICAL', impact: 10, pattern: /(?:Statement|PreparedStatement)\s+\w+\s*=.*\+\s*\w+|\.(?:execute|executeQuery|executeUpdate)\s*\(\s*["'][^"']*["']\s*\+|\.(?:execute|executeQuery|executeUpdate)\s*\([^"'][^)]*\+/, message: 'Java SQL injection: string-concatenated query. Use PreparedStatement with parameterized queries.' },
  // Command injection
  { id: 'JAVA_COMMAND_INJECTION', severity: 'CRITICAL', impact: 10, pattern: /Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(\s*(?!Arrays\.asList)/, message: 'Java command execution with dynamic input — command injection risk. Validate and sanitize all inputs.' },
  // Deserialization
  { id: 'JAVA_INSECURE_DESERIALIZATION', severity: 'CRITICAL', impact: 10, pattern: /ObjectInputStream\s*\(|\.readObject\s*\(\s*\)/, message: 'Java ObjectInputStream.readObject() is vulnerable to deserialization attacks. Use safe alternatives or validate class allowlists.' },
  // XXE
  { id: 'JAVA_XXE', severity: 'HIGH', impact: 9, pattern: /DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)/, message: 'Java XML factory without XXE protection. Disable external entity processing: factory.setFeature("http://xml.org/sax/features/external-general-entities", false).' },
  // Path traversal
  { id: 'JAVA_PATH_TRAVERSAL', severity: 'HIGH', impact: 9, pattern: /new\s+File\s*\(\s*(?:request\.getParameter|getParameter|req\.getParameter)/, message: 'Java File() with user input — path traversal vulnerability.' },
  // Weak crypto
  { id: 'JAVA_WEAK_CRYPTO', severity: 'HIGH', impact: 8, pattern: /Cipher\.getInstance\s*\(\s*["'](?:DES|RC4|RC2|Blowfish|AES\/ECB|DES\/ECB)/, message: 'Weak/insecure cipher algorithm. Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding.' },
  { id: 'JAVA_WEAK_HASH', severity: 'HIGH', impact: 7, pattern: /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/, message: 'Weak hash algorithm (MD5/SHA-1). Use SHA-256 or bcrypt/Argon2 for passwords.' },
  // XSS in JSP/Spring
  { id: 'JAVA_XSS', severity: 'HIGH', impact: 8, pattern: /response\.getWriter\(\)\.(?:print|write|println)\s*\(\s*request\.getParameter|out\.print\s*\(\s*request\.getParameter/, message: 'Java XSS: unescaped user input written to HTTP response. Use OWASP Java Encoder.' },
  // Spring Security misconfig
  { id: 'JAVA_CSRF_DISABLED', severity: 'HIGH', impact: 8, pattern: /\.csrf\(\)\.disable\(\)|http\.csrf\(\)\.disable/, message: 'Spring Security CSRF protection disabled — enables cross-site request forgery attacks.' },
  { id: 'JAVA_PERMISSIVE_CORS', severity: 'HIGH', impact: 8, pattern: /@CrossOrigin\s*\(\s*\*|allowedOrigins\s*=\s*"\\*"|\*.*Access-Control-Allow-Origin/, message: 'Wildcard CORS origin in Spring — allows any domain to make authenticated requests.' },
  // Hardcoded credentials
  { id: 'JAVA_HARDCODED_SECRET', severity: 'CRITICAL', impact: 10, pattern: /(?:password|passwd|secret|apiKey|api_key|token)\s*=\s*"[^"]{8,}"/, message: 'Hardcoded credential in Java source. Move to environment variables or a secrets manager.' },
  // Log injection
  { id: 'JAVA_LOG_INJECTION', severity: 'MEDIUM', impact: 6, pattern: /(?:log|logger)\.(?:info|debug|warn|error)\s*\(\s*[^"]*\+\s*(?:request\.getParameter|req\.getParameter|input|userInput)/, message: 'Java log injection: user input in log statements can forge log entries or enable Log4Shell-style attacks.' },
  // Insecure random
  { id: 'JAVA_INSECURE_RANDOM', severity: 'MEDIUM', impact: 6, pattern: /new\s+Random\s*\(\s*\)|Math\.random\s*\(\s*\)/, message: 'java.util.Random is not cryptographically secure. Use SecureRandom for security-sensitive values.' },
  // Open redirect
  { id: 'JAVA_OPEN_REDIRECT', severity: 'HIGH', impact: 8, pattern: /response\.sendRedirect\s*\(\s*request\.getParameter|sendRedirect\s*\(\s*[^"'][^)]*\)/, message: 'Java open redirect: user-controlled URL in sendRedirect(). Validate against an allowlist.' },
  // Trust boundary
  { id: 'JAVA_MASS_ASSIGNMENT', severity: 'HIGH', impact: 8, pattern: /BeanUtils\.copyProperties|@ModelAttribute|bindingResult.*\w+\.setAll/, message: 'Mass assignment / property binding from request — may allow setting unintended fields. Use DTOs with explicit field mapping.' },
];

function analyzeJavaSecurity(content, filePath) {
  if (!/\.(java)$/i.test(filePath)) return [];
  const isTest = /(?:Test|Spec)\.java$|src\/test\//.test(filePath);
  if (isTest) return [];
  const findings = [];
  const lines = content.split(/\r?\n/);
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || /^\s*\/\//.test(trimmed) || /^\s*\*/.test(trimmed)) return;
    for (const rule of JAVA_RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      findings.push({ line: idx + 1, column: m.index, endLine: idx + 1, endColumn: m.index + m[0].length, severity: rule.severity, category: rule.id, message: rule.message, impact: rule.impact, snippet: trimmed.slice(0, 200) });
      break;
    }
  });
  return findings;
}
module.exports = { analyzeJavaSecurity };
