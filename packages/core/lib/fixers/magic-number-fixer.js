/**
 * Magic Number Fixer
 *
 * Extracts magic numbers to named constants for better readability.
 *
 * Identifies:
 * - Numeric literals in comparisons (if (x > 100))
 * - Timeouts/delays (setTimeout(..., 5000))
 * - Array indices beyond 0, 1
 * - Configuration values
 *
 * Generates:
 * - Meaningful constant names based on context
 * - UPPER_SNAKE_CASE naming convention
 * - Proper placement (top of file or function scope)
 *
 * Confidence: 70% (requires code review for naming)
 */

const fs = require('fs').promises;

class MagicNumberFixer {
  constructor() {
    // Numbers that are generally OK and don't need extraction
    this.commonNumbers = [0, 1, -1, 2, 10, 100, 1000];

    // Context-based naming patterns
    this.contextPatterns = [
      {
        pattern: /setTimeout.*,\s*(\d+)/,
        suffix: '_TIMEOUT_MS',
        confidence: 0.80
      },
      {
        pattern: /setInterval.*,\s*(\d+)/,
        suffix: '_INTERVAL_MS',
        confidence: 0.80
      },
      {
        pattern: /sleep.*\((\d+)\)/,
        suffix: '_DELAY_MS',
        confidence: 0.75
      },
      {
        pattern: /port.*=.*(\d{4,5})/,
        suffix: '_PORT',
        confidence: 0.85
      },
      {
        pattern: /maxRetries.*=.*(\d+)/,
        suffix: '_MAX_RETRIES',
        confidence: 0.90
      },
      {
        pattern: /limit.*=.*(\d+)/,
        suffix: '_LIMIT',
        confidence: 0.80
      },
      {
        pattern: /age.*[><=].*(\d+)/,
        suffix: '_AGE_THRESHOLD',
        confidence: 0.75
      },
      {
        pattern: /length.*[><=].*(\d+)/,
        suffix: '_LENGTH_THRESHOLD',
        confidence: 0.75
      },
      {
        pattern: /width.*=.*(\d+)/,
        suffix: '_WIDTH',
        confidence: 0.80
      },
      {
        pattern: /height.*=.*(\d+)/,
        suffix: '_HEIGHT',
        confidence: 0.80
      }
    ];
  }

  async fix(finding, config) {
    try {
      const code = await fs.readFile(finding.filePath, 'utf8');
      const lines = code.split('\n');
      const lineIndex = (finding.line || finding.lineNumber) - 1;

      if (lineIndex < 0 || lineIndex >= lines.length) {
        return { success: false, error: 'Invalid line number' };
      }

      const originalLine = lines[lineIndex];

      // Extract magic number from the line
      const magicNumber = this.extractMagicNumber(originalLine);

      if (!magicNumber || this.commonNumbers.includes(parseInt(magicNumber))) {
        // No fix needed for common numbers
        return {
          success: true,
          originalLine,
          fixedLine: originalLine,
          confidence: 0.50,
          dryRun: config.dryRun,
          transformation: 'Common number - no fix needed'
        };
      }

      // Generate constant name based on context
      const constantName = this.generateConstantName(originalLine, magicNumber);

      // Replace number with constant
      const fixedLine = originalLine.replace(
        new RegExp(`\\b${magicNumber}\\b`),
        constantName
      );

      // Find where to insert the constant declaration
      const insertionPoint = this.findConstantInsertionPoint(lines, lineIndex);

      // Create constant declaration
      const constantDecl = `const ${constantName} = ${magicNumber};`;

      // Check if constant already exists
      const constantExists = lines.some(line =>
        line.includes(`const ${constantName}`) || line.includes(`let ${constantName}`)
      );

      if (!constantExists) {
        lines.splice(insertionPoint, 0, constantDecl);
      }

      // Update the original line (accounting for insertion)
      const newLineIndex = constantExists ? lineIndex : lineIndex + 1;
      lines[newLineIndex] = fixedLine;

      const modifiedCode = lines.join('\n');

      if (!config.dryRun) {
        await fs.writeFile(finding.filePath, modifiedCode, 'utf8');
      }

      return {
        success: true,
        originalLine,
        fixedLine: `${constantDecl}\n${fixedLine}`,
        transformation: `Extracted ${magicNumber} to ${constantName}`,
        confidence: 0.70,
        dryRun: config.dryRun
      };

    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Extract magic number from line
   */
  extractMagicNumber(line) {
    // Match numbers that are likely magic numbers
    const patterns = [
      /\b(\d{2,})\b/,     // Numbers with 2+ digits
      /\b([2-9])\b/,      // Single digits except 0, 1
      /\b(\d+\.\d+)\b/    // Decimals
    ];

    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match) {
        return match[1];
      }
    }

    return null;
  }

  /**
   * Generate meaningful constant name based on context
   */
  generateConstantName(line, number) {
    // Try context-based patterns
    for (const pattern of this.contextPatterns) {
      if (pattern.pattern.test(line)) {
        // Extract variable name or use pattern suffix
        const varMatch = line.match(/(\w+)[\s=<>]/);
        const varName = varMatch ? varMatch[1] : 'VALUE';
        return `${this.toUpperSnakeCase(varName)}${pattern.suffix}`;
      }
    }

    // Fallback: Try to infer from nearby words
    const words = line.match(/\b[a-z]\w*\b/gi);
    if (words && words.length > 0) {
      const contextWord = words[0];
      return `${this.toUpperSnakeCase(contextWord)}_VALUE`;
    }

    // Ultimate fallback
    return `MAGIC_NUMBER_${number.replace('.', '_')}`;
  }

  /**
   * Convert string to UPPER_SNAKE_CASE
   */
  toUpperSnakeCase(str) {
    return str
      .replace(/([a-z])([A-Z])/g, '$1_$2')  // camelCase → camel_Case
      .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')  // XMLParser → XML_Parser
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')  // Remove non-alphanumeric
      .replace(/^_+|_+$/g, '');  // Trim underscores
  }

  /**
   * Find where to insert the constant declaration
   */
  findConstantInsertionPoint(lines, currentLine) {
    // Strategy: Insert at the top of the current function or file

    // Find function start
    for (let i = currentLine; i >= 0; i--) {
      const line = lines[i];

      // Function declaration
      if (
        line.match(/^\s*function\s+\w+/) ||
        line.match(/^\s*\w+\s*\([^)]*\)\s*{/) ||
        line.match(/^\s*const\s+\w+\s*=\s*\([^)]*\)\s*=>/)
      ) {
        // Insert after opening brace
        for (let j = i; j < lines.length; j++) {
          if (lines[j].includes('{')) {
            return j + 1;
          }
        }
        return i + 1;
      }
    }

    // No function found - insert after imports/requires
    let lastImport = -1;
    for (let i = 0; i < currentLine; i++) {
      if (lines[i].match(/^(const|let|var|import)\s+/) &&
          (lines[i].includes('require(') || lines[i].includes('from '))) {
        lastImport = i;
      }
    }

    if (lastImport !== -1) {
      return lastImport + 1;
    }

    // Ultimate fallback - top of file (after shebang if present)
    return lines[0].startsWith('#!') ? 2 : 0;
  }
}

module.exports = new MagicNumberFixer();
