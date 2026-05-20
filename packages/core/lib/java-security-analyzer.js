"use strict";
// Java security rules — covers OWASP Top 10 patterns in Java/Spring/Servlet code
const JAVA_RULES = [
  // SQL injection
  {
    id: "JAVA_SQL_INJECTION",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /(?:Statement|PreparedStatement)\s+\w+\s*=.*\+\s*\w+|\.(?:execute|executeQuery|executeUpdate)\s*\(\s*["'][^"']*["']\s*\+|\.(?:execute|executeQuery|executeUpdate)\s*\([^"'][^)]*\+/,
    message:
      "Java SQL injection: string-concatenated query. Use PreparedStatement with parameterized queries.",
  },
  // Command injection
  {
    id: "JAVA_COMMAND_INJECTION",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(\s*(?!Arrays\.asList)/,
    message:
      "Java command execution with dynamic input — command injection risk. Validate and sanitize all inputs.",
  },
  // Deserialization
  {
    id: "JAVA_INSECURE_DESERIALIZATION",
    severity: "CRITICAL",
    impact: 10,
    pattern: /ObjectInputStream\s*\(|\.readObject\s*\(\s*\)/,
    message:
      "Java ObjectInputStream.readObject() is vulnerable to deserialization attacks. Use safe alternatives or validate class allowlists.",
  },
  // R2 (2026-05-19): Jackson enableDefaultTyping — CVE-2017-7525 / CVE-2017-15095
  // class. Calling .enableDefaultTyping() (or .activateDefaultTyping() in
  // 2.10+ without a strict PolymorphicTypeValidator) allows attackers to
  // smuggle gadget chains via the @class type discriminator when the
  // ObjectMapper subsequently deserializes attacker-controlled JSON.
  // Single token, low FP risk: this method is documented-dangerous.
  // Source: docs/plans/2026-05-19-lang-canary-adversarial-fn-opus.md §7 Tier-2 #5.
  {
    id: "JAVA_INSECURE_DESERIALIZATION",
    severity: "CRITICAL",
    impact: 10,
    pattern:
      /\.(?:enableDefaultTyping|activateDefaultTyping)\s*\(|\.enableDefaultTypingAsProperty\s*\(/,
    message:
      "Jackson enableDefaultTyping / activateDefaultTyping enables polymorphic deserialization (CVE-2017-7525 class). Use a strict PolymorphicTypeValidator or @JsonTypeInfo per-class instead.",
  },
  // XXE
  {
    id: "JAVA_XXE",
    severity: "HIGH",
    impact: 9,
    pattern:
      /DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)/,
    message:
      'Java XML factory without XXE protection. Disable external entity processing: factory.setFeature("http://xml.org/sax/features/external-general-entities", false).',
    // G2 guard (2026-05-19): suppress when hardening calls follow within
    // a 10-line window of the factory instantiation. Closes the spring-boot
    // FP at AbstractPackagerMojo.java:234 where the factory is hardened
    // immediately after creation.
    // Source: docs/plans/2026-05-19-lang-canary-baseline.md Recommended Step 4.
    guard: (line, idx, lines) => {
      const HARDENING =
        /FEATURE_SECURE_PROCESSING|disallow-doctype-decl|setFeature\s*\([^)]*disallow|setExpandEntityReferences\s*\(\s*false\s*\)|setXIncludeAware\s*\(\s*false\s*\)/i;
      const end = Math.min(lines.length - 1, idx + 10);
      for (let i = idx; i <= end; i++) {
        if (HARDENING.test(lines[i])) return true; // suppress — hardened
      }
      return false; // not hardened — emit finding
    },
  },

  // Path traversal
  {
    id: "JAVA_PATH_TRAVERSAL",
    severity: "HIGH",
    impact: 9,
    pattern:
      /new\s+File\s*\(\s*(?:request\.getParameter|getParameter|req\.getParameter)/,
    message: "Java File() with user input — path traversal vulnerability.",
  },
  // R4 (2026-05-19): Java SSRF — user input flowing into HTTP client sinks.
  // Java has no equivalent of Python's analyzePythonTaint multi-pass aliasing,
  // so this rule (like JAVA_PATH_TRAVERSAL above) is single-line: the SSRF
  // pattern must directly contain the source on the same line.
  // This means multi-step aliases like `String url = req.getParameter("u"); new URL(url);`
  // won't fire — only `new URL(req.getParameter("u"))` will. That's
  // intentional FP discipline; multi-line aliases need a Java taint pass.
  // CVE class: CWE-918. Sinks chosen for direct + popular Spring/Java HTTP
  // libraries.
  // Source: docs/plans/2026-05-19-lang-canary-adversarial-fn-opus.md §7 Tier-1 #2.
  {
    id: "JAVA_SSRF",
    severity: "HIGH",
    impact: 8,
    pattern:
      /(?:new\s+URL\s*\(|URI\s*\.\s*create\s*\(|HttpClient\.\w+\.send\s*\(|RestTemplate\.\w*\s*\.\s*(?:getForObject|getForEntity|exchange|postForObject|postForEntity)\s*\(|OkHttpClient\s*\(\)\s*\.\s*newCall|WebClient\.\w*\.uri\s*\()\s*[^)]*\b(?:request\.getParameter|req\.getParameter|getParameter|getHeader|getQueryString|@RequestParam|@PathVariable|@RequestBody)/,
    message:
      "Java SSRF: user input flows into HTTP client URL — validate against an allowlist or restrict to expected hosts.",
  },
  // Weak crypto
  {
    id: "JAVA_WEAK_CRYPTO",
    severity: "HIGH",
    impact: 8,
    pattern:
      /Cipher\.getInstance\s*\(\s*["'](?:DES|RC4|RC2|Blowfish|AES\/ECB|DES\/ECB)/,
    message:
      "Weak/insecure cipher algorithm. Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding.",
  },
  {
    id: "JAVA_WEAK_HASH",
    severity: "HIGH",
    impact: 7,
    pattern: /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/,
    message:
      "Weak hash algorithm (MD5/SHA-1). Use SHA-256 or bcrypt/Argon2 for passwords.",
  },
  // XSS in JSP/Spring
  {
    id: "JAVA_XSS",
    severity: "HIGH",
    impact: 8,
    pattern:
      /response\.getWriter\(\)\.(?:print|write|println)\s*\(\s*request\.getParameter|out\.print\s*\(\s*request\.getParameter/,
    message:
      "Java XSS: unescaped user input written to HTTP response. Use OWASP Java Encoder.",
  },
  // Spring Security misconfig
  {
    id: "JAVA_CSRF_DISABLED",
    severity: "HIGH",
    impact: 8,
    pattern: /\.csrf\(\)\.disable\(\)|http\.csrf\(\)\.disable/,
    message:
      "Spring Security CSRF protection disabled — enables cross-site request forgery attacks.",
  },
  {
    id: "JAVA_PERMISSIVE_CORS",
    severity: "HIGH",
    impact: 8,
    pattern:
      /@CrossOrigin\s*\(\s*\*|allowedOrigins\s*=\s*"\\*"|\*.*Access-Control-Allow-Origin/,
    message:
      "Wildcard CORS origin in Spring — allows any domain to make authenticated requests.",
  },
  // Hardcoded credentials
  {
    id: "JAVA_HARDCODED_SECRET",
    severity: "CRITICAL",
    impact: 10,
    pattern: /(?:password|passwd|secret|apiKey|api_key|token)\s*=\s*"[^"]{8,}"/,
    message:
      "Hardcoded credential in Java source. Move to environment variables or a secrets manager.",
  },
  // Log injection
  {
    id: "JAVA_LOG_INJECTION",
    severity: "MEDIUM",
    impact: 6,
    pattern:
      /(?:log|logger)\.(?:info|debug|warn|error)\s*\(\s*[^"]*\+\s*(?:request\.getParameter|req\.getParameter|input|userInput)/,
    message:
      "Java log injection: user input in log statements can forge log entries or enable Log4Shell-style attacks.",
  },
  // Insecure random
  // G1 guard (2026-05-19): only emit when a security-sensitive keyword
  // appears in the same-line or 3-line context window. Closes the FPs
  // Codex measured on spring-boot Docker image-name / volume-name helpers
  // where `new Random()` is used for non-security identifiers.
  // Source: docs/plans/2026-05-19-lang-canary-baseline.md Recommended Step 3.
  {
    id: "JAVA_INSECURE_RANDOM",
    severity: "MEDIUM",
    impact: 6,
    pattern: /new\s+Random\s*\(\s*\)|Math\.random\s*\(\s*\)/,
    message:
      "java.util.Random is not cryptographically secure. Use SecureRandom for security-sensitive values.",
    guard: (line, idx, lines) => {
      const SECURITY_KEYWORDS =
        /\b(token|nonce|password|session|key|csrf|auth|crypto|secret|salt|iv|jwt|oauth|otp)\b/i;
      // Same-line + ±2 line window.
      const start = Math.max(0, idx - 2);
      const end = Math.min(lines.length - 1, idx + 2);
      for (let i = start; i <= end; i++) {
        if (SECURITY_KEYWORDS.test(lines[i])) return false; // do NOT suppress
      }
      return true; // suppress — no security context
    },
  },
  // Open redirect
  {
    id: "JAVA_OPEN_REDIRECT",
    severity: "HIGH",
    impact: 8,
    pattern:
      /response\.sendRedirect\s*\(\s*request\.getParameter|sendRedirect\s*\(\s*[^"'][^)]*\)/,
    message:
      "Java open redirect: user-controlled URL in sendRedirect(). Validate against an allowlist.",
  },
  // Trust boundary
  {
    id: "JAVA_MASS_ASSIGNMENT",
    severity: "HIGH",
    impact: 8,
    pattern:
      /BeanUtils\.copyProperties|@ModelAttribute|bindingResult.*\w+\.setAll/,
    message:
      "Mass assignment / property binding from request — may allow setting unintended fields. Use DTOs with explicit field mapping.",
  },
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
      // Per-rule context guard (G1/G2 — 2026-05-19). Receives the matched
      // line, its 0-indexed position, and the full lines array. Returns
      // `true` to suppress the finding (FP-shape detected) or falsy to
      // emit it. Rules without a `guard` always emit on match.
      if (typeof rule.guard === "function" && rule.guard(line, idx, lines)) {
        break;
      }
      findings.push({
        line: idx + 1,
        column: m.index,
        endLine: idx + 1,
        endColumn: m.index + m[0].length,
        severity: rule.severity,
        category: rule.id,
        message: rule.message,
        impact: rule.impact,
        snippet: trimmed.slice(0, 200),
      });
      break;
    }
  });
  return findings;
}
module.exports = { analyzeJavaSecurity };
