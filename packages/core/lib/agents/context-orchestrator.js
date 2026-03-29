const fs = require('fs');
const path = require('path');

class ContextOrchestratorAgent {
  async mapProject(projectPath, depth = 1) {
    const entries = await fs.promises.readdir(projectPath, { withFileTypes: true });
    return entries.map(entry => ({
      name: entry.name,
      type: entry.isDirectory() ? 'directory' : 'file'
    }));
  }
}

module.exports = ContextOrchestratorAgent;
