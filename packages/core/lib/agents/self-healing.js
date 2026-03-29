const FixerRunner = require('../fixer-runner');

class SelfHealingAgent {
  constructor({ projectRoot }) {
    this.projectRoot = projectRoot;
  }

  async proposeFixes(report) {
    const runner = new FixerRunner({ projectRoot: this.projectRoot, enableWrites: false });
    return runner.applyFixes(report, { dryRun: true });
  }
}

module.exports = SelfHealingAgent;
