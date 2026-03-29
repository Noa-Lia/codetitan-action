const path = require('path');
const { analyzeDomain } = require('../domain-analyzers');

class CodeIntelligenceAgent {
  async inspectFile(projectRoot, filePath) {
    const absolute = path.isAbsolute(filePath) ? filePath : path.join(projectRoot, filePath);
    const fs = require('fs');
    const content = await fs.promises.readFile(absolute, 'utf8');
    const security = analyzeDomain('security-god', absolute, content, projectRoot);
    const performance = analyzeDomain('performance-god', absolute, content, projectRoot);
    return {
      file: absolute,
      issues: [...security.issues, ...performance.issues]
    };
  }
}

module.exports = CodeIntelligenceAgent;
