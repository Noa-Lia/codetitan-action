const path = require('path');

class Guardrails {
  constructor(options = {}) {
    this.options = {
      workingDirectory: options.workingDirectory || process.cwd(),
      maxSteps: options.maxSteps || 6,
      allowMutatingTools: options.allowMutatingTools ?? false,
      ...options
    };
  }

  assertTask(task) {
    if (!task || typeof task !== 'object') {
      throw new Error('Task payload must be an object');
    }
  }

  assertStepBudget(context) {
    if (context.stepsTaken >= this.options.maxSteps) {
      throw new Error(`Agent runtime step budget exceeded (${this.options.maxSteps})`);
    }

    if (context.promptBudget && typeof context.promptBudget.toolCap === 'number' && context.stepsTaken >= context.promptBudget.toolCap) {
      throw new Error(`Agent runtime tool budget exceeded (${context.promptBudget.toolCap})`);
    }
  }

  assertTool(definition, input = {}, context = null) {
    if (!definition) {
      throw new Error('Tool definition is required');
    }

    const roleProfile = context && context.roleProfile ? context.roleProfile : null;

    if (roleProfile && Array.isArray(roleProfile.allowedTools) && !roleProfile.allowedTools.includes(definition.name)) {
      throw new Error(`Role ${roleProfile.name} cannot use tool ${definition.name}`);
    }

    if (definition.mutating && !this.options.allowMutatingTools && !(roleProfile && roleProfile.allowMutatingTools === true)) {
      throw new Error(`Mutating tool blocked by guardrails: ${definition.name}`);
    }

    if (definition.mutating && roleProfile && roleProfile.allowMutatingTools === false) {
      throw new Error(`Role ${roleProfile.name} cannot mutate files with tool ${definition.name}`);
    }

    ['file', 'path', 'directory', 'referenceFile', 'targetPath', 'cwd', 'baseDir', 'projectPath'].forEach(key => {
      if (typeof input[key] === 'string' && input[key].trim()) {
        this.ensurePathInsideRoot(input[key], key);
      }
    });

    if (Array.isArray(input.paths)) {
      input.paths.forEach(targetPath => {
        if (typeof targetPath === 'string' && targetPath.trim()) {
          this.ensurePathInsideRoot(targetPath, 'paths');
        }
      });
    }

    if (definition.mutating && roleProfile && roleProfile.requiresWorktreeForMutations) {
      if (definition.name === 'promote_worktree') {
        this.assertPromotionTargetsInRepo(input, context);
        return;
      }

      this.assertMutationTargetsInWorkspace(input, context);
    }
  }

  ensurePathInsideRoot(targetPath, label = 'path') {
    if (!targetPath || /^[a-z]+:\/\//i.test(targetPath)) {
      return targetPath;
    }

    const root = path.resolve(this.options.workingDirectory);
    const absolutePath = path.resolve(root, targetPath);
    const relativePath = path.relative(root, absolutePath);

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      throw new Error(`${label} escapes working directory: ${targetPath}`);
    }

    return absolutePath;
  }

  assertMutationTargetsInWorkspace(input = {}, context = null) {
    const workspace = context && typeof context.getPrimaryWorkspace === 'function'
      ? context.getPrimaryWorkspace()
      : null;

    if (!workspace || !workspace.path) {
      throw new Error('Mutating fixer tools require an active isolated worktree');
    }

    ['file', 'path', 'directory', 'targetPath', 'cwd'].forEach(key => {
      if (typeof input[key] === 'string' && input[key].trim()) {
        this.ensurePathInsideWorkspace(input[key], workspace.path, key);
      }
    });

    if (Array.isArray(input.paths)) {
      input.paths.forEach(targetPath => {
        if (typeof targetPath === 'string' && targetPath.trim()) {
          this.ensurePathInsideWorkspace(targetPath, workspace.path, 'paths');
        }
      });
    }
  }

  assertPromotionTargetsInRepo(input = {}, context = null) {
    const workspace = context && typeof context.getPrimaryWorkspace === 'function'
      ? context.getPrimaryWorkspace()
      : null;

    if (!workspace || !workspace.path) {
      throw new Error('Promotion requires an active isolated worktree');
    }

    const files = Array.isArray(input.files) ? input.files : [];
    if (files.length === 0) {
      throw new Error('Promotion requires one or more files');
    }

    files.forEach(targetPath => {
      if (typeof targetPath === 'string' && targetPath.trim()) {
        this.ensurePathInsideRoot(targetPath, 'files');
      }
    });
  }

  ensurePathInsideWorkspace(targetPath, workspacePath, label = 'path') {
    if (!targetPath || /^[a-z]+:\/\//i.test(targetPath)) {
      return targetPath;
    }

    const root = path.resolve(workspacePath);
    const absolutePath = path.resolve(targetPath);
    const relativePath = path.relative(root, absolutePath);

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      throw new Error(`${label} escapes active worktree: ${targetPath}`);
    }

    return absolutePath;
  }

  assertProviderBudget(context, usage = {}) {
    if (!context || !context.promptBudget) {
      return;
    }

    const tokenCap = context.promptBudget.tokenCap || 0;
    const usdCap = context.promptBudget.usdCap || 0;
    const projectedTokens =
      (context.providerUsage?.tokensUsed?.input || 0) +
      (context.providerUsage?.tokensUsed?.output || 0) +
      (context.providerUsage?.tokensUsed?.cached || 0) +
      (usage.tokensUsed?.input || 0) +
      (usage.tokensUsed?.output || 0) +
      (usage.tokensUsed?.cached || 0);
    const projectedCost = (context.providerUsage?.totalCostUsd || 0) + (usage.costUSD || usage.costUsd || 0);

    if (tokenCap > 0 && projectedTokens > tokenCap) {
      throw new Error(`Agent runtime token budget exceeded (${projectedTokens} > ${tokenCap})`);
    }

    if (usdCap > 0 && projectedCost > usdCap) {
      throw new Error(`Agent runtime USD budget exceeded (${projectedCost} > ${usdCap})`);
    }
  }
}

module.exports = Guardrails;
