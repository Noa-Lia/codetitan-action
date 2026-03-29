/**
 * Missing Documentation Fixer
 * Adds JSDoc comments to functions
 */

const fs = require('fs').promises;

class MissingDocsFixer {
  async fix(finding, config) {
    try {
      const code = await fs.readFile(finding.filePath, 'utf8');
      const lines = code.split('\n');
      const lineIndex = (finding.line || finding.lineNumber) - 1;

      // Add JSDoc comment above the function
      const funcLine = lines[lineIndex];
      const match = funcLine.match(/(async\s+)?function\s+(\w+)|(\w+)\s*[:=]\s*(async\s+)?\(/);

      if (match) {
        const funcName = match[2] || match[3];
        const indent = funcLine.match(/^\s*/)[0];
        const jsdoc = [
          `${indent}/**`,
          `${indent} * TODO: Add description for ${funcName}`,
          `${indent} * @param {*} params - Add parameter descriptions`,
          `${indent} * @returns {*} Add return description`,
          `${indent} */`
        ];

        if (!config.dryRun) {
          lines.splice(lineIndex, 0, ...jsdoc);
          await fs.writeFile(finding.filePath, lines.join('\n'), 'utf8');
          return { success: true, addedLines: jsdoc.length, confidence: 0.75 };
        }

        return { success: config.dryRun, addedLines: jsdoc.length, confidence: 0.75, dryRun: config.dryRun };
      }

      return { success: false, error: 'Could not detect function signature' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

module.exports = new MissingDocsFixer();
