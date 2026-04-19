/**
 * Hardcoded Secret Fixer
 * Replaces hardcoded credentials with environment variables
 */

const fs = require('fs').promises;

function toEnvVarName(varName) {
  const normalized = String(varName || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();

  return normalized || 'SECRET_VALUE';
}

class HardcodedSecretFixer {
  async fix(finding, config) {
    try {
      const code = await fs.readFile(finding.filePath, 'utf8');
      const lines = code.split('\n');

      // Get the offending line
      const lineIndex = (finding.line || finding.lineNumber) - 1;
      const originalLine = lines[lineIndex];

      // Detect common patterns
      const patterns = [
        // const password = 'secret123'
        {
          regex: /(const|let|var)\s+(\w*(?:password|secret|key|token|api[_-]?key)\w*)\s*=\s*['"]([^'"]+)['"]/i,
          replacement: (match, keyword, varName, value) => {
            const envVar = toEnvVarName(varName);
            return `${keyword} ${varName} = process.env.${envVar}; // TODO: Set ${envVar} in .env`;
          }
        },
        // password: 'secret123'
        {
          regex: /(\w*(?:password|secret|key|token|api[_-]?key)\w*)\s*:\s*['"]([^'"]+)['"]/i,
          replacement: (match, varName, value) => {
            const envVar = toEnvVarName(varName);
            return `${varName}: process.env.${envVar} // TODO: Set ${envVar} in .env`;
          }
        },
        // "Authorization": "Bearer hardcoded123"
        {
          regex: /(['"])Authorization\1\s*:\s*(['"])Bearer\s+([^'"]+)\2/i,
          replacement: (match) => {
            return `'Authorization': \`Bearer \${process.env.API_TOKEN}\` // TODO: Set API_TOKEN in .env`;
          }
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
        // Generic fix: add a TODO comment
        fixedLine = originalLine + ' // TODO: Move hardcoded credential to environment variable';
      }

      // Apply fix if not dry run
      if (!config.dryRun && fixedLine !== originalLine) {
        lines[lineIndex] = fixedLine;
        await fs.writeFile(finding.filePath, lines.join('\n'), 'utf8');

        return {
          success: true,
          originalLine,
          fixedLine,
          confidence: matched ? 0.90 : 0.70,
          message: matched
            ? 'Replaced hardcoded credential with environment variable'
            : 'Added TODO comment to move credential to environment variable'
        };
      }

      return {
        success: config.dryRun,
        originalLine,
        fixedLine,
        confidence: matched ? 0.90 : 0.70,
        dryRun: config.dryRun,
        message: 'Dry run - no changes made'
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new HardcodedSecretFixer();
module.exports.toEnvVarName = toEnvVarName;
