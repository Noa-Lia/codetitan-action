class ExecutionContext {
  constructor({
    agent,
    role = '',
    roleProfile = null,
    capabilities = [],
    task = {},
    interpretation = {},
    budget = {},
    reasoningMode = 'standard'
  } = {}) {
    this.agent = agent;
    this.role = role;
    this.roleProfile = roleProfile;
    this.capabilities = capabilities;
    this.task = task;
    this.interpretation = interpretation;
    this.startedAt = Date.now();
    this.reasoningMode = reasoningMode;

    this.maxSteps = budget.maxSteps || roleProfile?.toolBudget?.maxCalls || 6;
    this.stepsTaken = 0;
    this.scratchpad = new Map();
    this.evidence = [];
    this.artifacts = [];
    this.toolTrace = [];
    this.toolResults = [];
    this.workspaces = [];
    this.cleanupHandlers = [];
    this.cleanup = {
      attempted: 0,
      completed: 0,
      failed: 0,
      errors: []
    };
    this.verificationStatus = budget.verificationStatus || 'not_started';
    this.toolBudget = {
      limit: this.maxSteps,
      used: 0,
      remaining: this.maxSteps
    };
    this.promptBudget = {
      tokenCap: budget.tokenCap ?? roleProfile?.promptBudget?.tokenCap ?? 0,
      usdCap: budget.usdCap ?? roleProfile?.promptBudget?.usdCap ?? 0,
      toolCap: budget.toolCap ?? roleProfile?.promptBudget?.toolCap ?? this.maxSteps
    };
    this.providerUsage = {
      selectedProvider: null,
      selectedModel: null,
      totalCostUsd: 0,
      retries: 0,
      tokensUsed: {
        input: 0,
        output: 0,
        cached: 0
      },
      advisorValidation: {
        requested: false,
        performed: false,
        verdict: null,
        provider: null,
        model: null
      },
      providers: {}
    };
    this.toolMetrics = {};
  }

  recordToolInvocation(definition, toolResult) {
    this.stepsTaken += 1;
    this.toolBudget.used = this.stepsTaken;
    this.toolBudget.remaining = Math.max(0, this.toolBudget.limit - this.stepsTaken);
    this.toolResults.push({
      name: definition.name,
      result: toolResult
    });
    this.recordToolMetrics(definition.name, toolResult);

    this.toolTrace.push({
      tool: definition.name,
      success: toolResult.success,
      riskLevel: definition.riskLevel,
      mutating: definition.mutating,
      durationMs: toolResult.durationMs,
      usage: toolResult.usage || {},
      input: toolResult.input,
      summary: toolResult.outputSummary,
      error: toolResult.error || null
    });

    if (Array.isArray(toolResult.evidence) && toolResult.evidence.length > 0) {
      this.evidence.push(...toolResult.evidence);
    }
  }

  recordToolMetrics(toolName, toolResult = {}) {
    if (!toolName) {
      return;
    }

    const usage = toolResult.usage || {};
    const current = this.toolMetrics[toolName] || {
      calls: 0,
      failures: 0,
      durationMs: 0,
      bytesTouched: 0,
      tokensTouched: 0
    };

    current.calls += 1;
    current.durationMs += toolResult.durationMs || 0;
    current.bytesTouched += usage.bytesTouched || 0;
    current.tokensTouched += usage.tokensTouched || 0;

    if (toolResult.success === false) {
      current.failures += 1;
    }

    this.toolMetrics[toolName] = current;
  }

  addEvidence(item) {
    this.evidence.push(item);
  }

  addArtifact(artifact) {
    this.artifacts.push(artifact);
  }

  registerWorkspace(handle = {}) {
    if (!handle || !handle.path) {
      return null;
    }

    const workspace = {
      id: handle.id || null,
      name: handle.name || null,
      path: handle.path,
      mode: handle.mode || null,
      baseDir: handle.baseDir || null,
      createdAt: handle.createdAt || new Date().toISOString(),
      cleanedUp: false
    };

    this.workspaces.push(workspace);
    this.setScratch('primaryWorkspace', workspace);
    return workspace;
  }

  getPrimaryWorkspace() {
    return this.workspaces[0] || null;
  }

  markWorkspaceCleanedUp(handleOrPath) {
    const workspaceId = handleOrPath && typeof handleOrPath === 'object' ? handleOrPath.id || null : null;
    const workspacePath = handleOrPath && typeof handleOrPath === 'object'
      ? handleOrPath.path
      : handleOrPath;

    const match = this.workspaces.find(workspace => (
      (workspaceId && workspace.id === workspaceId) ||
      (workspacePath && workspace.path === workspacePath)
    ));

    if (match) {
      match.cleanedUp = true;
    }
  }

  registerCleanup(label, handler) {
    const resolvedLabel = typeof label === 'string' && label.trim()
      ? label
      : `cleanup-${this.cleanupHandlers.length + 1}`;
    const resolvedHandler = typeof label === 'function' ? label : handler;

    if (typeof resolvedHandler !== 'function') {
      return;
    }

    this.cleanupHandlers.push({
      label: resolvedLabel,
      handler: resolvedHandler
    });
  }

  async runCleanup() {
    for (let index = this.cleanupHandlers.length - 1; index >= 0; index -= 1) {
      const entry = this.cleanupHandlers[index];
      this.cleanup.attempted += 1;

      try {
        await entry.handler();
        this.cleanup.completed += 1;
      } catch (error) {
        this.cleanup.failed += 1;
        this.cleanup.errors.push({
          label: entry.label,
          error: error.message
        });
      }
    }

    this.cleanupHandlers = [];

    return {
      ...this.cleanup,
      errors: [...this.cleanup.errors]
    };
  }

  setVerificationStatus(status) {
    if (status) {
      this.verificationStatus = status;
    }
  }

  setScratch(key, value) {
    this.scratchpad.set(key, value);
  }

  getScratch(key) {
    return this.scratchpad.get(key);
  }

  getLatestToolResult(toolName) {
    for (let index = this.toolResults.length - 1; index >= 0; index -= 1) {
      const entry = this.toolResults[index];
      if (entry.name === toolName) {
        return entry.result;
      }
    }

    return null;
  }

  getToolResultsByName(toolName) {
    return this.toolResults
      .filter(entry => entry.name === toolName)
      .map(entry => entry.result);
  }

  getLatestToolData(toolName) {
    const result = this.getLatestToolResult(toolName);
    return result ? result.data : null;
  }

  recordProviderUsage(usage = {}) {
    const providerName = usage.provider || usage.selectedProvider || null;
    const model = usage.model || null;
    const costUsd = usage.costUSD || usage.costUsd || 0;
    const retries = usage.retries || 0;
    const tokensUsed = usage.tokensUsed || {};

    this.providerUsage.selectedProvider = providerName || this.providerUsage.selectedProvider;
    this.providerUsage.selectedModel = model || this.providerUsage.selectedModel;
    this.providerUsage.totalCostUsd += costUsd;
    this.providerUsage.retries += retries;
    this.providerUsage.tokensUsed.input += tokensUsed.input || 0;
    this.providerUsage.tokensUsed.output += tokensUsed.output || 0;
    this.providerUsage.tokensUsed.cached += tokensUsed.cached || 0;

    if (providerName) {
      if (!this.providerUsage.providers[providerName]) {
        this.providerUsage.providers[providerName] = {
          model: model || null,
          calls: 0,
          costUsd: 0,
          retries: 0,
          tokensUsed: {
            input: 0,
            output: 0,
            cached: 0
          }
        };
      }

      const providerStats = this.providerUsage.providers[providerName];
      providerStats.model = model || providerStats.model;
      providerStats.calls += 1;
      providerStats.costUsd += costUsd;
      providerStats.retries += retries;
      providerStats.tokensUsed.input += tokensUsed.input || 0;
      providerStats.tokensUsed.output += tokensUsed.output || 0;
      providerStats.tokensUsed.cached += tokensUsed.cached || 0;
    }
  }

  markAdvisorValidation(validation = {}) {
    this.providerUsage.advisorValidation = {
      requested: validation.requested === true,
      performed: validation.performed === true,
      verdict: validation.verdict || null,
      provider: validation.provider || null,
      model: validation.model || null
    };
  }

  getRuntimeTelemetry() {
    const reviewArtifactPath = this.task?.metadata?.reviewArtifactPath || null;
    const fixSessionId = this.task?.metadata?.fixSessionId || null;
    const fixSessionPath = this.task?.metadata?.fixSessionPath || null;

    return {
      role: this.roleProfile?.name || null,
      reasoningMode: this.reasoningMode,
      allowedTools: this.roleProfile?.allowedTools || [],
      toolBudget: {
        ...this.toolBudget
      },
      promptBudget: {
        ...this.promptBudget
      },
      workspaceCount: this.workspaces.length,
      workspaces: this.workspaces.map(workspace => ({
        id: workspace.id,
        name: workspace.name,
        path: workspace.path,
        mode: workspace.mode,
        cleanedUp: workspace.cleanedUp
      })),
      cleanup: {
        ...this.cleanup,
        errors: [...this.cleanup.errors]
      },
      promotion: {
        requested: Boolean(this.getScratch('promotionRequested')),
        diffReviewed: Boolean(this.getScratch('diffReviewed')),
        promoted: Boolean(this.getScratch('promotionCompleted')),
        files: this.getScratch('promotedFiles') || []
      },
      workspaceValidation: {
        diffCaptured: Boolean(this.getScratch('diffCaptured')),
        validationPassed: Boolean(this.getScratch('lastValidationPassed'))
      },
      toolMetrics: { ...this.toolMetrics },
      providerUsage: {
        ...this.providerUsage,
        tokensUsed: {
          ...this.providerUsage.tokensUsed
        },
        advisorValidation: {
          ...this.providerUsage.advisorValidation
        }
      },
      reviewArtifact: {
        path: reviewArtifactPath,
        attached: Boolean(reviewArtifactPath)
      },
      fixSession: {
        id: fixSessionId,
        path: fixSessionPath,
        attached: Boolean(fixSessionId || fixSessionPath)
      },
      evidenceCount: this.evidence.length,
      verificationStatus: this.verificationStatus
    };
  }
}

module.exports = ExecutionContext;
