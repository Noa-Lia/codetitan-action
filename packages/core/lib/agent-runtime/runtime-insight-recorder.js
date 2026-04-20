const path = require('path');
const InsightSync = require('../insight-sync');

function resolveSqlitePath(projectRoot = process.cwd()) {
  return path.join(projectRoot, 'data', 'collective-insight.db');
}

async function persistRuntimeInsight({
  result = {},
  projectRoot = process.cwd(),
  metadata = {}
} = {}) {
  const insight = new InsightSync({
    sqlitePath: resolveSqlitePath(projectRoot)
  });

  try {
    await insight.init();
    return await insight.ingestAgentRuntime(result, {
      ...metadata,
      projectPath: metadata.projectPath || projectRoot
    });
  } finally {
    await insight.close().catch(() => {});
  }
}

module.exports = {
  persistRuntimeInsight,
  resolveSqlitePath
};
