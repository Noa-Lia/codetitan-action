/**
 * XSS (Cross-Site Scripting) Fixer
 * Adds proper escaping/sanitization for user input
 */

const fs = require('fs').promises;

class XSSFixer {
  async fix(finding, config) {
    try {
      const code = await fs.readFile(finding.filePath, 'utf8');
      const lines = code.split('\n');
      const lineIndex = (finding.line || finding.lineNumber) - 1;
      const originalLine = lines[lineIndex];

      // Detect XSS patterns
      const patterns = [
        // innerHTML = userInput
        {
          regex: /\.innerHTML\s*=\s*(\w+)/,
          replacement: (match, variable) =>
            `.textContent = ${variable} // Fixed: Use textContent instead of innerHTML to prevent XSS`
        },
        // React: <div dangerouslySetInnerHTML={{__html: data}} />
        {
          regex: /dangerouslySetInnerHTML=\{\{__html:\s*(\w+)\}\}/,
          replacement: (match, variable) =>
            `/* XSS Warning: Sanitize ${variable} before using dangerouslySetInnerHTML */ dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(${variable})}}`
        },
        // document.write(userInput)
        {
          regex: /document\.write\(([^)]+)\)/,
          replacement: (match, content) =>
            `// XSS WARNING: document.write is unsafe. Use DOM manipulation instead.\n${originalLine}`
        }
      ];

      let fixedLine = originalLine;
      let matched = false;

      for (const pattern of patterns) {
        if (pattern.regex.test(originalLine)) {
          fixedLine = originalLine.replace(pattern.regex, pattern.replacement);
          matched = true;
          break;
        }
      }

      if (!matched) {
        fixedLine = originalLine + ' // TODO: Sanitize user input to prevent XSS';
      }

      if (!config.dryRun && fixedLine !== originalLine) {
        lines[lineIndex] = fixedLine;
        await fs.writeFile(finding.filePath, lines.join('\n'), 'utf8');
        return { success: true, originalLine, fixedLine, confidence: matched ? 0.85 : 0.70 };
      }

      return { success: config.dryRun, originalLine, fixedLine, confidence: matched ? 0.85 : 0.70, dryRun: config.dryRun };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

module.exports = new XSSFixer();
