const fs = require('fs');
const path = require('path');

class ArchitectureAgent {
  async summarize(projectPath) {
    const entries = await fs.promises.readdir(projectPath, { withFileTypes: true });
    const modules = entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .sort();

    return {
      modules,
      recommendation: modules.length > 10
        ? 'Consider grouping top-level modules into domains.'
        : 'Module count is manageable.'
    };
  }
}

module.exports = ArchitectureAgent;
