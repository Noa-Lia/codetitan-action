/**
 * Enhanced Command Execution Fixer
 *
 * Secures shell command execution by:
 * - Converting exec() to execFile() (no shell interpretation)
 * - Adding input validation suggestions
 * - Recommending shell-escape libraries
 * - Converting string commands to array arguments
 * - Preventing command injection vulnerabilities
 *
 * Confidence: 85% for automatic transformations
 */

const fs = require('fs').promises;

class CommandExecFixer {
  constructor() {
    this.transformations = [
      {
        name: 'exec with template literal → execFile with validation',
        pattern: /exec\(`([^`]*)\$\{([^}]+)\}([^`]*)`\)/,
        fix: (match, before, variable, after) => {
          return `/* SECURITY: Validate ${variable} before using */\nexecFile('${before.trim()}', [${variable}, '${after.trim()}'])`;
        },
        confidence: 0.75
      },
      {
        name: 'exec with variable → execFile recommendation',
        pattern: /(const|let|var)\s+result\s*=\s*exec\(([^)]+)\)/,
        fix: (match, declType, args) => {
          return `${declType} result = execFile(/* command */, [/* args */]) // TODO: Split command into array arguments`;
        },
        confidence: 0.70
      },
      {
        name: 'exec with concatenation → validation warning',
        pattern: /exec\(.*\+.*\)/,
        fix: (match) => {
          return `${match} /* WARNING: Command injection risk! Use execFile with array args */`;
        },
        confidence: 0.85
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
      let fixedLine = originalLine;
      let transformation = null;
      let confidence = 0.70;

      // Try each transformation pattern
      for (const transform of this.transformations) {
        if (transform.pattern.test(originalLine)) {
          fixedLine = originalLine.replace(transform.pattern, transform.fix);
          transformation = transform.name;
          confidence = transform.confidence;
          break;
        }
      }

      // Fallback: Add safety comments for common patterns
      if (!transformation) {
        if (originalLine.includes('exec(') && originalLine.includes('${')) {
          fixedLine = originalLine + ' /* CRITICAL: Command injection vulnerability - use execFile */';
          transformation = 'Added critical security warning';
          confidence = 0.90;
        } else if (originalLine.includes('exec(')) {
          fixedLine = originalLine + ' // TODO: Consider execFile for safer execution';
          transformation = 'Added safety recommendation';
          confidence = 0.65;
        } else if (originalLine.includes('spawn(') && !originalLine.includes('[')) {
          fixedLine = originalLine + ' // TODO: Use array arguments to prevent shell injection';
          transformation = 'Added spawn safety note';
          confidence = 0.75;
        }
      }

      // Only proceed if line changed
      if (fixedLine === originalLine) {
        return {
          success: true,
          originalLine,
          fixedLine,
          confidence: 0.50,
          dryRun: config.dryRun
        };
      }

      // Apply fix
      lines[lineIndex] = fixedLine;
      const modifiedCode = lines.join('\n');

      // Check if we should add require for execFile
      const enhancedCode = this.ensureExecFileImport(modifiedCode, fixedLine);

      if (!config.dryRun) {
        await fs.writeFile(finding.filePath, enhancedCode, 'utf8');
      }

      return {
        success: true,
        originalLine,
        fixedLine,
        transformation,
        confidence,
        dryRun: config.dryRun
      };

    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Ensure execFile is imported if we recommend using it
   */
  ensureExecFileImport(code, fixedLine) {
    // Only add import if the fixed line actually uses execFile
    if (!fixedLine.includes('execFile')) {
      return code;
    }

    const lines = code.split('\n');

    // Check if already imported
    const hasExecFileImport = lines.some(line =>
      line.includes('execFile') && (line.includes('require(') || line.includes('import '))
    );

    if (hasExecFileImport) {
      return code;
    }

    // Check if child_process is already imported
    const childProcessImportIndex = lines.findIndex(line =>
      line.match(/const\s+{[^}]*}\s*=\s*require\(['"]child_process['"]\)/)
    );

    if (childProcessImportIndex !== -1) {
      // Add execFile to existing destructure
      const importLine = lines[childProcessImportIndex];
      if (!importLine.includes('execFile')) {
        lines[childProcessImportIndex] = importLine.replace(
          /{\s*([^}]*)\s*}/,
          '{ $1, execFile }'
        );
      }
    } else {
      // Find best place to add import (after other requires or at top)
      let insertIndex = 0;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('require(') || lines[i].includes('import ')) {
          insertIndex = i + 1;
        } else if (insertIndex > 0) {
          break;
        }
      }

      lines.splice(insertIndex, 0, "const { execFile } = require('child_process');");
    }

    return lines.join('\n');
  }
}

module.exports = new CommandExecFixer();
