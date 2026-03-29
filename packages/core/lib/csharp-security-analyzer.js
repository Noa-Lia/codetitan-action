'use strict';
const CSHARP_RULES = [
  { id: 'CSHARP_SQL_INJECTION', severity: 'CRITICAL', impact: 10, pattern: /new\s+(?:SqlCommand|OleDbCommand|NpgsqlCommand|MySqlCommand|SqliteCommand)\s*\([^)]*\+|new\s+(?:SqlCommand|OleDbCommand|NpgsqlCommand|MySqlCommand|SqliteCommand)\s*\(\s*string\./, message: 'C# SQL injection: string-concatenated SqlCommand. Use parameterized queries (SqlParameter).' },
  { id: 'CSHARP_XSS', severity: 'HIGH', impact: 8, pattern: /Response\.Write\s*\(\s*Request(?:\[|\.)|\bHtml\.Raw\s*\(\s*(?!@Html\.)/, message: 'C# XSS: unencoded user input in HTML output. Use Html.Encode() or @Html.DisplayFor() in Razor.' },
  { id: 'CSHARP_COMMAND_INJECTION', severity: 'CRITICAL', impact: 10, pattern: /Process\.Start\s*\(\s*Request(?:\[|\.)|\bnew\s+ProcessStartInfo\s*\(\s*[^"']/, message: 'C# command injection: user input in Process.Start(). Validate and restrict allowed commands.' },
  { id: 'CSHARP_PATH_TRAVERSAL', severity: 'HIGH', impact: 9, pattern: /File\.(Read|Write|Open|Delete)\w*\s*\(\s*[^"']*Request\.|Path\.Combine\s*\(\s*[^"']*Request\./, message: 'C# path traversal: user input in file path operation. Use Path.GetFullPath() and validate against base directory.' },
  { id: 'CSHARP_DESERIALIZATION', severity: 'CRITICAL', impact: 10, pattern: /BinaryFormatter\s*\(\s*\)|JsonConvert\.DeserializeObject<object>|TypeNameHandling\.All/, message: 'C# insecure deserialization: BinaryFormatter or TypeNameHandling.All enables arbitrary code execution.' },
  { id: 'CSHARP_WEAK_CRYPTO', severity: 'HIGH', impact: 8, pattern: /new\s+(?:DESCryptoServiceProvider|RC2CryptoServiceProvider|MD5CryptoServiceProvider|SHA1CryptoServiceProvider|TripleDES)\s*\(/, message: 'C# weak cryptographic algorithm. Use AesGcm or RSA with OAEP padding.' },
  { id: 'CSHARP_HARDCODED_SECRET', severity: 'CRITICAL', impact: 10, pattern: /(?:password|secret|apiKey|token|connectionString)\s*=\s*@?"[^"]{8,}"/i, message: 'C# hardcoded credential. Use IConfiguration with environment variables or Azure Key Vault.' },
  { id: 'CSHARP_OPEN_REDIRECT', severity: 'HIGH', impact: 8, pattern: /Response\.Redirect\s*\(\s*Request\.|return\s+Redirect\s*\(\s*[^"']*Request\./, message: 'C# open redirect: user-controlled redirect URL. Validate against allowed origins with Url.IsLocalUrl().' },
  { id: 'CSHARP_LDAP_INJECTION', severity: 'HIGH', impact: 8, pattern: /DirectorySearcher.*Filter.*\+|DirectoryEntry.*Path.*\+\s*\w+/, message: 'C# LDAP injection: user input in LDAP filter/path. Encode with SecurityElement.Escape().' },
  { id: 'CSHARP_MASS_ASSIGNMENT', severity: 'MEDIUM', impact: 6, pattern: /\[Bind\s*\(\s*"\s*"\s*\)\]|\[Bind\s*\(\s*Include\s*=\s*""\s*\)\]|UpdateModel\s*\(/, message: 'C# mass assignment: [Bind("")] with empty string or UpdateModel() may bind unexpected properties. Use explicit ViewModels.' },
  { id: 'CSHARP_INSECURE_COOKIE', severity: 'MEDIUM', impact: 6, pattern: /new\s+HttpCookie.*\n?.*\.(?:HttpOnly|Secure)\s*=\s*false|\.HttpOnly\s*=\s*false|\.Secure\s*=\s*false/, message: 'C# insecure cookie: HttpOnly or Secure flag disabled. Both should be true for session cookies.' },
];

function analyzeCSharpSecurity(content, filePath) {
  if (!/\.cs$/i.test(filePath)) return [];
  const isTest = /Tests?\.cs$|Spec\.cs$/.test(filePath);
  if (isTest) return [];
  const findings = [];
  const lines = content.split(/\r?\n/);
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || /^\s*\/\//.test(trimmed)) return;
    for (const rule of CSHARP_RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      findings.push({ line: idx + 1, column: m.index, endLine: idx + 1, endColumn: m.index + m[0].length, severity: rule.severity, category: rule.id, message: rule.message, impact: rule.impact, snippet: trimmed.slice(0, 200) });
      break;
    }
  });
  return findings;
}
module.exports = { analyzeCSharpSecurity };
