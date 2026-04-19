const fs = require('fs');
const path = require('path');

let cache = null;
let cachePath = null;

function resolveConfigPath() {
  const override = process.env.CLAUDE_CONFIG_PATH;
  if (override) {
    return path.resolve(override);
  }
  return path.join(__dirname, '..', 'config', 'defaults.json');
}

function buildFallbackConfig() {
  return {
    version: '1.0.0',
    settings: {},
    environment: process.env.NODE_ENV || 'development'
  };
}

function loadConfig() {
  const targetPath = resolveConfigPath();
  if (!cache || cachePath !== targetPath) {
// TODO: Fix SYNC_IO - Synchronous fs operation blocks the event loop. Consider async alternatives.
    if (fs.existsSync(targetPath)) {
      cache = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
    } else if (process.env.CLAUDE_CONFIG_PATH) {
      throw new Error(`Config file does not exist: ${targetPath}`);
    } else {
      cache = buildFallbackConfig();
    }
    cachePath = targetPath;
  }
  return cache;
}

function resetConfig() {
  cache = null;
  cachePath = null;
}

module.exports = {
  loadConfig,
  resetConfig
};
