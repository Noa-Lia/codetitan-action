/**
 * SQL Injection Fixer
 * Converts string concatenation to parameterized queries
 */

const fs = require('fs').promises;

class SQLInjectionFixer {
  async fix(finding, config) {
    try {
      const code = await fs.readFile(finding.filePath, 'utf8');
      const lines = code.split('\n');

      const lineIndex = (finding.line || finding.lineNumber) - 1;
      const originalLine = lines[lineIndex];

      // Detect SQL injection patterns
      const patterns = [
        // query(`SELECT * FROM users WHERE id = ${id}`)
        {
          regex: /(query|execute)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`\s*\)/,
          replacement: (match, method, query) => {
            // Extract variables from template literals
            const vars = query.match(/\$\{([^}]+)\}/g) || [];
            const paramNames = vars.map((v, i) => `$${i + 1}`);

            // Replace ${var} with $1, $2, etc.
            let fixedQuery = query;
            vars.forEach((v, i) => {
              fixedQuery = fixedQuery.replace(v, paramNames[i]);
            });

            // Extract variable names
            const varNames = vars.map(v => v.replace(/\$\{|\}/g, ''));

            return `${method}(\`${fixedQuery}\`, [${varNames.join(', ')}])`;
          }
        },
        // query("SELECT * FROM users WHERE id = " + id)
        {
          regex: /(query|execute)\s*\(\s*["']([^"']+)["']\s*\+\s*(\w+)/,
          replacement: (match, method, query, variable) => {
            return `${method}("${query}$1", [${variable}])`;
          }
        },
        // db.query(`SELECT * FROM ${table}`)
        {
          regex: /db\.(query|execute)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`/,
          replacement: (match, method, query) => {
            // Add comment to use parameterized query
            return match + ' // TODO: Use parameterized query';
          }
        }
      ];

      let fixedLine = originalLine;
      let matched = false;
      let confidence = 0.70;

      for (const pattern of patterns) {
        if (pattern.regex.test(originalLine)) {
          fixedLine = originalLine.replace(pattern.regex, pattern.replacement);
          matched = true;
          confidence = 0.85;
          break;
        }
      }

      if (!matched) {
        // Generic fix: add warning comment
        if (originalLine.includes('query') || originalLine.includes('execute')) {
          fixedLine = originalLine + ' // WARNING: Potential SQL injection - use parameterized queries';
          confidence = 0.60;
        }
      }

      // Apply fix
      if (!config.dryRun && fixedLine !== originalLine) {
        lines[lineIndex] = fixedLine;
        await fs.writeFile(finding.filePath, lines.join('\n'), 'utf8');

        return {
          success: true,
          originalLine,
          fixedLine,
          confidence,
          message: matched
            ? 'Converted to parameterized query'
            : 'Added SQL injection warning comment'
        };
      }

      return {
        success: config.dryRun,
        originalLine,
        fixedLine,
        confidence,
        dryRun: config.dryRun
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new SQLInjectionFixer();
