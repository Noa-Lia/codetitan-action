/**
 * Agent Registry Manager
 *
 * Manages the GOD LEVEL Agent Registry:
 * - Agent registration and discovery
 * - Capability-based search
 * - Performance tracking
 * - Status management
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const REGISTRY_PATH = path.join(__dirname, '..', 'data', 'agent-registry.json');
const DEFAULT_OPTIONS = {
  watch: true,
  debounceMs: 300,
  suppressMs: 500,
  executionHistoryLimit: 20
};

class AgentRegistryManager {
  constructor(options = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.registryPath = this.options.registryPath || REGISTRY_PATH;
    this.registry = this.createEmptyRegistry();
    this.ensureRegistryDirectory();
    this.loadRegistryFromDisk();
    this.rebuildDerivedIndexes();

    this._watchers = [];
    this._watchFileHandler = null;
    this._reloadTimer = null;
    this._lastWriteTime = 0;
    this._pendingSave = Promise.resolve();

    if (this.options.watch) {
      this.setupWatchers();
    }
  }

  static getDefaultRegistryPath() {
    return REGISTRY_PATH;
  }

  formatCliArg(value) {
    return /\s/.test(value) ? `"${value}"` : value;
  }

  getAgentDisplayIdentifier(agent) {
    return agent?.name || agent?.id || 'unknown';
  }

  getLatestReviewArtifactPath(agent) {
    const history = Array.isArray(agent?.execution_history) ? agent.execution_history : [];
    const latest = history[0] || null;
    return (
      latest?.review_artifact_path ||
      agent?.last_execution?.review_artifact_path ||
      agent?.runtime_state?.review_artifact_path ||
      null
    );
  }

  getLatestFixSession(agent) {
    const history = Array.isArray(agent?.execution_history) ? agent.execution_history : [];
    const latest = history[0] || null;
    const id =
      latest?.fix_session_id ||
      agent?.last_execution?.fix_session_id ||
      agent?.runtime_state?.fix_session_id ||
      null;
    const sessionPath =
      latest?.fix_session_path ||
      agent?.last_execution?.fix_session_path ||
      agent?.runtime_state?.fix_session_path ||
      null;

    if (!id && !sessionPath) {
      return null;
    }

    return { id, path: sessionPath };
  }

  buildReviewLinkedSessionCommand(agent) {
    return `codetitan agents show ${this.formatCliArg(this.getAgentDisplayIdentifier(agent))} --review-linked-session`;
  }

  buildApplyLinkedSessionCommand(agent, reviewArtifactPath) {
    const baseCommand =
      `codetitan agents show ${this.formatCliArg(this.getAgentDisplayIdentifier(agent))} ` +
      '--apply-linked-session --promote --diff-reviewed --validate-command "<cmd>"';

    if (reviewArtifactPath) {
      return `${baseCommand} --review-artifact ${this.formatCliArg(reviewArtifactPath)}`;
    }

    return `${baseCommand} --review-output "<file>.md"`;
  }

  buildLinkedSessionCommands(agent) {
    if (!this.getLatestFixSession(agent)) {
      return null;
    }

    const latestArtifact = this.getLatestReviewArtifactPath(agent);
    return {
      review: this.buildReviewLinkedSessionCommand(agent),
      replay: this.buildApplyLinkedSessionCommand(agent, latestArtifact)
    };
  }

  getReplayReadiness(agent) {
    const normalizedRole = String(agent?.runtime_state?.role || agent?.role || '').toLowerCase();
    const latestFixSession = this.getLatestFixSession(agent);
    const latestArtifact = this.getLatestReviewArtifactPath(agent);

    if (normalizedRole !== 'fixer') {
      return {
        replayable: false,
        state: 'not_fixer_role',
        reason: 'Only fixer agents expose replayable linked fix sessions.',
        has_fix_session: Boolean(latestFixSession),
        has_review_artifact: Boolean(latestArtifact)
      };
    }

    if (!latestFixSession) {
      return {
        replayable: false,
        state: 'missing_fix_session',
        reason: 'No linked fix session is recorded for this fixer.',
        has_fix_session: false,
        has_review_artifact: Boolean(latestArtifact)
      };
    }

    if (!latestArtifact) {
      return {
        replayable: true,
        state: 'needs_review_artifact',
        reason: 'Replay is available, but a fresh review artifact must be generated before promotion.',
        has_fix_session: true,
        has_review_artifact: false
      };
    }

    return {
      replayable: true,
      state: 'ready',
      reason: 'Replay is ready with a linked fix session and stored review artifact.',
      has_fix_session: true,
      has_review_artifact: true
    };
  }

  summarizeReplayReadiness(agents = []) {
    const summary = {
      total_matched: agents.length,
      replayable: 0,
      blocked: 0,
      by_state: {
        ready: 0,
        needs_review_artifact: 0,
        missing_fix_session: 0,
        not_fixer_role: 0
      }
    };

    agents.forEach(agent => {
      const readiness = agent?.replay_readiness || this.getReplayReadiness(agent);
      const state = readiness?.state || 'not_fixer_role';

      if (readiness?.replayable === true) {
        summary.replayable += 1;
      } else {
        summary.blocked += 1;
      }

      if (typeof summary.by_state[state] !== 'number') {
        summary.by_state[state] = 0;
      }
      summary.by_state[state] += 1;
    });

    return summary;
  }

  refreshDerivedAgentMetadata(agent) {
    if (!agent) {
      return null;
    }

    agent.linked_session_commands = this.buildLinkedSessionCommands(agent);
    agent.replay_readiness = this.getReplayReadiness(agent);
    return agent;
  }

  ensureRegistryDirectory() {
    fsp.mkdir(path.dirname(this.registryPath), { recursive: true }).catch(() => {});
  }

  /**
   * Load registry from file
   */
  loadRegistryFromDisk() {
    fsp.readFile(this.registryPath, 'utf8')
      .then(raw => JSON.parse(raw))
      .then(parsed => {
        this.registry = parsed;
        this.rebuildDerivedIndexes();
      })
      .catch(error => {
        if (error?.code !== 'ENOENT') {
          console.warn('[AgentRegistryManager] Failed to load registry (using in-memory default):', error.message);
        }
        this.registry = this.registry || this.createEmptyRegistry();
      });
  }

  /**
   * Save registry to file
   */
  saveRegistry() {
    try {
      this.rebuildDerivedIndexes();
      const data = JSON.stringify(this.registry, null, 2);
      this._lastWriteTime = Date.now();
      this._pendingSave = this._pendingSave
        .catch(() => {})
        .then(() => fsp.mkdir(path.dirname(this.registryPath), { recursive: true }))
        .then(() => fsp.writeFile(this.registryPath, data, 'utf8'))
        .catch(err => {
          console.error('Failed to save registry:', err.message);
        });
      return true;
    } catch (error) {
      console.error('Failed to save registry:', error.message);
      return false;
    }
  }

  /**
   * Create empty registry structure
   */
  createEmptyRegistry() {
    return {
      version: '1.0.0',
      last_updated: new Date().toISOString(),
      agent_count: 0,
      tiers: {
        meta_gods: 0,
        domain_gods: 0,
        specialists: 0,
        workers: 0
      },
      agents: [],
      domains: [],
      capabilities_index: {},
      specializations_index: {}
    };
  }

  createDefaultRuntimeState(agentSpec = {}) {
    const budgetLimit = agentSpec.toolBudget?.limit ?? agentSpec.toolBudget?.maxCalls ?? null;
    const used = agentSpec.toolBudget?.used ?? 0;
    const remaining = agentSpec.toolBudget?.remaining ?? (budgetLimit === null ? null : Math.max(0, budgetLimit - used));
    const reviewArtifactPath =
      agentSpec.reviewArtifactPath ??
      agentSpec.review_artifact_path ??
      agentSpec.reviewArtifact?.path ??
      null;
    const fixSessionId =
      agentSpec.fixSessionId ??
      agentSpec.fix_session_id ??
      agentSpec.fixSession?.id ??
      null;
    const fixSessionPath =
      agentSpec.fixSessionPath ??
      agentSpec.fix_session_path ??
      agentSpec.fixSession?.path ??
      null;
    const providerUsage = agentSpec.providerUsage || agentSpec.provider_usage || {};
    const providerTokens = providerUsage.tokensUsed || providerUsage.tokens_used || {};
    const toolMetrics = agentSpec.toolMetrics || agentSpec.tool_metrics || {};

    return {
      role: agentSpec.role || null,
      reasoning_mode: agentSpec.reasoningMode || agentSpec.reasoning_mode || 'standard',
      tool_budget: {
        limit: budgetLimit,
        used,
        remaining
      },
      evidence_count: agentSpec.evidenceCount ?? 0,
      verification_status: agentSpec.verificationStatus || 'not_started',
      tool_calls_used: agentSpec.toolCallsUsed ?? used,
      review_artifact_path: reviewArtifactPath,
      fix_session_id: fixSessionId,
      fix_session_path: fixSessionPath,
      provider_usage: {
        selected_provider: providerUsage.selectedProvider || providerUsage.selected_provider || null,
        selected_model: providerUsage.selectedModel || providerUsage.selected_model || null,
        total_cost_usd: providerUsage.totalCostUsd || providerUsage.total_cost_usd || 0,
        retries: providerUsage.retries || 0,
        tokens_used: {
          input: providerTokens.input || 0,
          output: providerTokens.output || 0,
          cached: providerTokens.cached || 0
        }
      },
      tool_metrics: toolMetrics
    };
  }

  ensureRuntimeState(agent) {
    if (!agent) {
      return null;
    }

    this.ensureExecutionHistory(agent);

    if (!agent.runtime_state) {
      agent.runtime_state = this.createDefaultRuntimeState(agent);
    } else {
      const defaultState = this.createDefaultRuntimeState(agent);
      agent.runtime_state = {
        ...defaultState,
        ...agent.runtime_state,
        tool_budget: {
          ...defaultState.tool_budget,
          ...(agent.runtime_state.tool_budget || {})
        }
      };
    }

    this.refreshDerivedAgentMetadata(agent);
    return agent.runtime_state;
  }

  ensureExecutionHistory(agent) {
    if (!agent) {
      return [];
    }

    if (!Array.isArray(agent.execution_history)) {
      agent.execution_history = [];
    }

    return agent.execution_history;
  }

  normalizeRuntimeState(runtimeState = {}) {
    const existingBudget = runtimeState.toolBudget || runtimeState.tool_budget || {};
    const budgetLimit = existingBudget.limit ?? existingBudget.maxCalls ?? null;
    const used = existingBudget.used ?? runtimeState.toolCallsUsed ?? runtimeState.tool_calls_used ?? 0;
    const remaining = existingBudget.remaining ?? (budgetLimit === null ? null : Math.max(0, budgetLimit - used));
    const reviewArtifactPath =
      runtimeState.reviewArtifactPath ??
      runtimeState.review_artifact_path ??
      runtimeState.reviewArtifact?.path ??
      null;
    const fixSessionId =
      runtimeState.fixSessionId ??
      runtimeState.fix_session_id ??
      runtimeState.fixSession?.id ??
      null;
    const fixSessionPath =
      runtimeState.fixSessionPath ??
      runtimeState.fix_session_path ??
      runtimeState.fixSession?.path ??
      null;
    const providerUsage = runtimeState.providerUsage || runtimeState.provider_usage || {};
    const providerTokens = providerUsage.tokensUsed || providerUsage.tokens_used || {};

    return {
      role: runtimeState.role ?? null,
      reasoning_mode: runtimeState.reasoningMode ?? runtimeState.reasoning_mode ?? 'standard',
      tool_budget: {
        limit: budgetLimit,
        used,
        remaining
      },
      evidence_count: runtimeState.evidenceCount ?? runtimeState.evidence_count ?? 0,
      verification_status: runtimeState.verificationStatus ?? runtimeState.verification_status ?? 'not_started',
      tool_calls_used: runtimeState.toolCallsUsed ?? runtimeState.tool_calls_used ?? used,
      review_artifact_path: reviewArtifactPath,
      fix_session_id: fixSessionId,
      fix_session_path: fixSessionPath,
      provider_usage: {
        selected_provider: providerUsage.selectedProvider || providerUsage.selected_provider || null,
        selected_model: providerUsage.selectedModel || providerUsage.selected_model || null,
        total_cost_usd: providerUsage.totalCostUsd || providerUsage.total_cost_usd || 0,
        retries: providerUsage.retries || 0,
        tokens_used: {
          input: providerTokens.input || 0,
          output: providerTokens.output || 0,
          cached: providerTokens.cached || 0
        }
      },
      tool_metrics: runtimeState.toolMetrics ?? runtimeState.tool_metrics ?? {}
    };
  }

  /**
   * Rebuild derived indexes (domains, tiers, capability maps)
   */
  rebuildDerivedIndexes() {
    const agents = Array.isArray(this.registry.agents) ? this.registry.agents : [];
    const existingDomainInfo = new Map(
      Array.isArray(this.registry.domains)
        ? this.registry.domains.map(domain => [domain.name, domain])
        : []
    );

    const domains = new Map();
    const capabilitiesIndex = {};
    const specializationsIndex = {};

    agents.forEach(agent => {
      this.ensureRuntimeState(agent);
      const domainName = agent.domain || 'unknown';
      if (!domains.has(domainName)) {
        const previous = existingDomainInfo.get(domainName) || {};
        domains.set(domainName, {
          name: domainName,
          description: previous.description || '',
          agent_count: 0,
          tier_distribution: {
            meta: 0,
            domain: 0,
            specialist: 0,
            worker: 0
          }
        });
      }

      const domainEntry = domains.get(domainName);
      domainEntry.agent_count += 1;
      switch (agent.tier) {
        case 1:
          domainEntry.tier_distribution.meta += 1;
          break;
        case 2:
          domainEntry.tier_distribution.domain += 1;
          break;
        case 3:
          domainEntry.tier_distribution.specialist += 1;
          break;
        case 4:
          domainEntry.tier_distribution.worker += 1;
          break;
        default:
          break;
      }

      (agent.capabilities || []).forEach(capability => {
        if (!capabilitiesIndex[capability]) {
          capabilitiesIndex[capability] = [];
        }
        if (!capabilitiesIndex[capability].includes(agent.name)) {
          capabilitiesIndex[capability].push(agent.name);
        }
      });

      (agent.specializations || []).forEach(specialization => {
        if (!specializationsIndex[specialization]) {
          specializationsIndex[specialization] = [];
        }
        if (!specializationsIndex[specialization].includes(agent.name)) {
          specializationsIndex[specialization].push(agent.name);
        }
      });

      this.refreshDerivedAgentMetadata(agent);
    });

    this.registry.agents = agents;
    this.registry.agent_count = agents.length;
    this.registry.domains = Array.from(domains.values());
    this.registry.capabilities_index = capabilitiesIndex;
    this.registry.specializations_index = specializationsIndex;
    this.registry.readiness_summary = this.summarizeReplayReadiness(agents);
    this.updateTierCounts();
  }

  /**
   * Register a new agent
   */
  registerAgent(agentSpec) {
    const agent = {
      id: agentSpec.id || this.generateAgentId(agentSpec.name),
      name: agentSpec.name,
      tier: agentSpec.tier,
      tier_name: this.getTierName(agentSpec.tier),
      domain: agentSpec.domain,
      file: agentSpec.file,
      capabilities: agentSpec.capabilities || [],
      specializations: agentSpec.specializations || [],
      status: 'active',
      current_task: null,
      performance_metrics: {
        tasks_completed: 0,
        success_rate: 1.0,
        avg_completion_time: '0s',
        quality_score: 1.0
      },
      resource_usage: {
        cpu: '0%',
        memory: '0MB',
        active_threads: 0
      },
      execution_history: [],
      runtime_state: this.createDefaultRuntimeState(agentSpec),
      created_at: new Date().toISOString(),
      last_active: null
    };

    // Add to agents array
    this.registry.agents.push(agent);

    // Update agent count
    this.registry.agent_count++;

    // Update tier counts
    this.updateTierCounts();

    // Update domain
    this.updateDomain(agent.domain);

    // Update capabilities index
    this.updateCapabilitiesIndex(agent);

    // Update specializations index
    this.updateSpecializationsIndex(agent);

    // Update timestamp
    this.registry.last_updated = new Date().toISOString();

    // Save registry
    this.saveRegistry();

    return agent;
  }

  /**
   * Generate unique agent ID
   */
  generateAgentId(name) {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `${name}-${timestamp}-${random}`;
  }

  /**
   * Get tier name from tier number
   */
  getTierName(tier) {
    const tierNames = {
      1: 'meta_god',
      2: 'domain_god',
      3: 'specialist',
      4: 'worker'
    };
    return tierNames[tier] || 'unknown';
  }

  /**
   * Update tier counts
   */
  updateTierCounts() {
    this.registry.tiers = {
      meta_gods: this.registry.agents.filter(a => a.tier === 1).length,
      domain_gods: this.registry.agents.filter(a => a.tier === 2).length,
      specialists: this.registry.agents.filter(a => a.tier === 3).length,
      workers: this.registry.agents.filter(a => a.tier === 4).length
    };
  }

  /**
   * Update domain information
   */
  updateDomain(domainName) {
    let domain = this.registry.domains.find(d => d.name === domainName);

    if (!domain) {
      domain = {
        name: domainName,
        description: '',
        agent_count: 0,
        tier_distribution: {
          meta: 0,
          domain: 0,
          specialist: 0,
          worker: 0
        }
      };
      this.registry.domains.push(domain);
    }

    const domainAgents = this.registry.agents.filter(a => a.domain === domainName);
    domain.agent_count = domainAgents.length;
    domain.tier_distribution = {
      meta: domainAgents.filter(a => a.tier === 1).length,
      domain: domainAgents.filter(a => a.tier === 2).length,
      specialist: domainAgents.filter(a => a.tier === 3).length,
      worker: domainAgents.filter(a => a.tier === 4).length
    };
  }

  /**
   * Update capabilities index
   */
  updateCapabilitiesIndex(agent) {
    agent.capabilities.forEach(capability => {
      if (!this.registry.capabilities_index[capability]) {
        this.registry.capabilities_index[capability] = [];
      }
      if (!this.registry.capabilities_index[capability].includes(agent.name)) {
        this.registry.capabilities_index[capability].push(agent.name);
      }
    });
  }

  /**
   * Update specializations index
   */
  updateSpecializationsIndex(agent) {
    agent.specializations.forEach(specialization => {
      if (!this.registry.specializations_index[specialization]) {
        this.registry.specializations_index[specialization] = [];
      }
      if (!this.registry.specializations_index[specialization].includes(agent.name)) {
        this.registry.specializations_index[specialization].push(agent.name);
      }
    });
  }

  /**
   * Discover agents by capability
   */
  discoverByCapability(capability) {
    const agentNames = this.registry.capabilities_index[capability] || [];
    return this.registry.agents.filter(a => agentNames.includes(a.name));
  }

  /**
   * Discover agents by specialization
   */
  discoverBySpecialization(specialization) {
    const agentNames = this.registry.specializations_index[specialization] || [];
    return this.registry.agents.filter(a => agentNames.includes(a.name));
  }

  /**
   * Discover agents by domain
   */
  discoverByDomain(domain) {
    return this.registry.agents.filter(a => a.domain === domain);
  }

  /**
   * Discover agents by tier
   */
  discoverByTier(tier) {
    return this.registry.agents.filter(a => a.tier === tier);
  }

  /**
   * Get agent by ID
   */
  getAgentById(id) {
    return this.registry.agents.find(a => a.id === id);
  }

  /**
   * Get agent by name
   */
  getAgentByName(name) {
    return this.registry.agents.find(a => a.name === name);
  }

  /**
   * Resolve agent by ID or name.
   */
  resolveAgent(identifier) {
    if (!identifier) return null;
    return this.getAgentById(identifier) || this.getAgentByName(identifier);
  }

  /**
   * Update agent status
   */
  updateAgentStatus(agentIdentifier, status) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return false;
    }
    this.ensureRuntimeState(agent);
    if (status) {
      agent.status = status;
    }
    agent.last_active = new Date().toISOString();
    this.registry.last_updated = agent.last_active;
    this.saveRegistry();
    return true;
  }

  /**
   * Update last_active timestamp without changing current task.
   */
  touchAgent(agentIdentifier, status, runtimeState = null) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return false;
    }
    this.ensureRuntimeState(agent);
    if (status) {
      agent.status = status;
    }
    if (runtimeState) {
      agent.runtime_state = {
        ...agent.runtime_state,
        ...this.normalizeRuntimeState(runtimeState),
        tool_budget: {
          ...agent.runtime_state.tool_budget,
          ...this.normalizeRuntimeState(runtimeState).tool_budget
        }
      };
    }
    agent.last_active = new Date().toISOString();
    this.registry.last_updated = agent.last_active;
    this.saveRegistry();
    return true;
  }

  updateAgentRuntimeState(agentIdentifier, runtimeState = {}) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return false;
    }

    const currentRuntimeState = this.ensureRuntimeState(agent);
    const normalizedState = this.normalizeRuntimeState(runtimeState);

    agent.runtime_state = {
      ...currentRuntimeState,
      ...normalizedState,
      tool_budget: {
        ...currentRuntimeState.tool_budget,
        ...normalizedState.tool_budget
      }
    };
    this.refreshDerivedAgentMetadata(agent);

    agent.last_active = new Date().toISOString();
    this.registry.last_updated = agent.last_active;
    this.saveRegistry();
    return true;
  }

  /**
   * Assign task to agent
   */
  assignTask(agentIdentifier, taskId) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return false;
    }
    this.ensureRuntimeState(agent);
    agent.current_task = taskId;
    agent.status = 'busy';
    agent.last_active = new Date().toISOString();
    this.registry.last_updated = agent.last_active;
    this.saveRegistry();
    return true;
  }

  /**
   * Complete task
   */
  completeTask(agentIdentifier, taskId, success, completionTime, qualityScore, telemetry = {}) {
    const agent = this.resolveAgent(agentIdentifier);
    if (agent && (!agent.current_task || agent.current_task === taskId)) {
      this.ensureRuntimeState(agent);
      agent.current_task = null;
      agent.status = 'idle';
      agent.last_active = new Date().toISOString();

      // Update performance metrics
      agent.performance_metrics.tasks_completed++;

      const totalTasks = agent.performance_metrics.tasks_completed;
      const currentSuccessRate = agent.performance_metrics.success_rate;
      const newSuccessRate = ((currentSuccessRate * (totalTasks - 1)) + (success ? 1 : 0)) / totalTasks;
      agent.performance_metrics.success_rate = newSuccessRate;

      // Update average completion time (simplified)
      agent.performance_metrics.avg_completion_time = completionTime;

      // Update quality score (moving average)
      const currentQuality = agent.performance_metrics.quality_score;
      const alpha = 0.2; // Smoothing factor
      agent.performance_metrics.quality_score = alpha * qualityScore + (1 - alpha) * currentQuality;

      agent.last_execution = {
        success,
        action: telemetry.action ?? null,
        result_summary: telemetry.resultSummary ?? null,
        error: success ? null : telemetry.error ?? null,
        execution_time_ms: telemetry.executionTime ?? null,
        reasoning_mode: telemetry.reasoningMode ?? telemetry.reasoning_mode ?? 'standard',
        provider_usage: telemetry.providerUsage ?? telemetry.provider_usage ?? {
          selected_provider: null,
          selected_model: null,
          total_cost_usd: 0,
          retries: 0,
          tokens_used: { input: 0, output: 0, cached: 0 }
        },
        tool_metrics: telemetry.toolMetrics ?? telemetry.tool_metrics ?? {},
        review_artifact_path: telemetry.reviewArtifactPath ?? null,
        fix_session_id: telemetry.fixSessionId ?? null,
        fix_session_path: telemetry.fixSessionPath ?? null
      };
      const normalizedState = this.normalizeRuntimeState(telemetry);
      agent.runtime_state = {
        ...agent.runtime_state,
        ...normalizedState,
        tool_budget: {
          ...agent.runtime_state.tool_budget,
          ...normalizedState.tool_budget
        }
      };
      this.appendExecutionHistory(agent, {
        timestamp: agent.last_active,
        success,
        action: telemetry.action ?? null,
        resultSummary: telemetry.resultSummary ?? null,
        error: success ? null : telemetry.error ?? null,
        executionTime: telemetry.executionTime ?? null,
        role: telemetry.role ?? null,
        reasoningMode: telemetry.reasoningMode ?? telemetry.reasoning_mode ?? 'standard',
        providerUsage: telemetry.providerUsage ?? telemetry.provider_usage ?? {},
        toolMetrics: telemetry.toolMetrics ?? telemetry.tool_metrics ?? {},
        verificationStatus: telemetry.verificationStatus ?? 'not_started',
        toolCallsUsed: telemetry.toolCallsUsed ?? 0,
        evidenceCount: telemetry.evidenceCount ?? 0,
        reviewArtifactPath: telemetry.reviewArtifactPath ?? null,
        fixSessionId: telemetry.fixSessionId ?? null,
        fixSessionPath: telemetry.fixSessionPath ?? null
      });
      this.refreshDerivedAgentMetadata(agent);

      this.registry.last_updated = agent.last_active;
      this.saveRegistry();
      return true;
    }
    return false;
  }

  /**
   * Update resource usage
   */
  updateResourceUsage(agentIdentifier, cpu, memory, threads) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return false;
    }
    agent.resource_usage = {
      cpu: `${cpu}%`,
      memory: `${memory}MB`,
      active_threads: threads
    };
    this.registry.last_updated = new Date().toISOString();
    this.saveRegistry();
    return true;
  }

  /**
   * Get performance metrics
   */
  getPerformanceMetrics(agentIdentifier) {
    const agent = this.resolveAgent(agentIdentifier);
    return agent ? agent.performance_metrics : null;
  }

  getAgents(filter = {}) {
    const { domain, tier, status, name } = filter;
    return this.registry.agents.filter(agent => {
      if (domain && agent.domain !== domain) return false;
      if (tier && String(agent.tier) !== String(tier)) return false;
      if (status && agent.status !== status) return false;
      if (name && !agent.name.toLowerCase().includes(String(name).toLowerCase())) return false;
      return true;
    });
  }

  appendExecutionHistory(agent, telemetry = {}) {
    if (!agent) {
      return null;
    }

    const history = this.ensureExecutionHistory(agent);
    const entry = {
      timestamp: telemetry.timestamp || new Date().toISOString(),
      success: telemetry.success === true,
      action: telemetry.action ?? null,
      result_summary: telemetry.resultSummary ?? telemetry.result_summary ?? null,
      error: telemetry.error ?? null,
      execution_time_ms: telemetry.executionTime ?? telemetry.execution_time_ms ?? null,
      role: telemetry.role ?? null,
      reasoning_mode: telemetry.reasoningMode ?? telemetry.reasoning_mode ?? 'standard',
      provider_usage: telemetry.providerUsage ?? telemetry.provider_usage ?? {
        selected_provider: null,
        selected_model: null,
        total_cost_usd: 0,
        retries: 0,
        tokens_used: { input: 0, output: 0, cached: 0 }
      },
      tool_metrics: telemetry.toolMetrics ?? telemetry.tool_metrics ?? {},
      verification_status: telemetry.verificationStatus ?? telemetry.verification_status ?? 'not_started',
      tool_calls_used: telemetry.toolCallsUsed ?? telemetry.tool_calls_used ?? 0,
      evidence_count: telemetry.evidenceCount ?? telemetry.evidence_count ?? 0,
      review_artifact_path: telemetry.reviewArtifactPath ?? telemetry.review_artifact_path ?? null,
      fix_session_id: telemetry.fixSessionId ?? telemetry.fix_session_id ?? null,
      fix_session_path: telemetry.fixSessionPath ?? telemetry.fix_session_path ?? null
    };

    history.unshift(entry);
    if (history.length > this.options.executionHistoryLimit) {
      history.length = this.options.executionHistoryLimit;
    }

    return entry;
  }

  getAgentExecutionHistory(agentIdentifier, limit = this.options.executionHistoryLimit) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return [];
    }

    return this.ensureExecutionHistory(agent).slice(0, Math.max(0, limit));
  }

  getAgentSnapshot(agentIdentifier) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return null;
    }

    this.refreshDerivedAgentMetadata(agent);
    return JSON.parse(JSON.stringify(agent));
  }

  getRegistrySnapshot() {
    this.rebuildDerivedIndexes();
    const snapshot = JSON.parse(JSON.stringify(this.registry));
    snapshot.readiness_summary = this.summarizeReplayReadiness(snapshot.agents || []);
    return snapshot;
  }

  recordExecution(agentIdentifier, {
    success,
    executionTime = null,
    taskAction = null,
    resultSummary = null,
    error = null,
    role = null,
    toolBudget = null,
    reasoningMode = 'standard',
    providerUsage = null,
    toolMetrics = null,
    evidenceCount = 0,
    verificationStatus = 'not_started',
    toolCallsUsed = 0,
    reviewArtifactPath = null,
    fixSessionId = null,
    fixSessionPath = null
  } = {}) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return;
    }

    this.ensureRuntimeState(agent);
    agent.performance_metrics = agent.performance_metrics || {};
    const metrics = agent.performance_metrics;
    metrics.tasks_completed = metrics.tasks_completed || 0;
    metrics.tasks_failed = metrics.tasks_failed || 0;
    metrics._total_time = metrics._total_time || 0;

    if (success) {
      metrics.tasks_completed += 1;
    } else {
      metrics.tasks_failed += 1;
    }

    const totalRuns = (metrics.tasks_completed || 0) + (metrics.tasks_failed || 0);
    metrics.success_rate = totalRuns === 0 ? 1 : (metrics.tasks_completed || 0) / totalRuns;

    if (executionTime !== null) {
      metrics._total_time += executionTime;
      metrics.avg_completion_time = `${Math.round(metrics._total_time / Math.max(totalRuns, 1))}ms`;
    }

    agent.last_active = new Date().toISOString();
    agent.last_execution = {
      success,
      action: taskAction,
      result_summary: resultSummary,
      error: success ? null : error,
      execution_time_ms: executionTime,
      reasoning_mode: reasoningMode,
      provider_usage: providerUsage || {
        selected_provider: null,
        selected_model: null,
        total_cost_usd: 0,
        retries: 0,
        tokens_used: { input: 0, output: 0, cached: 0 }
      },
      tool_metrics: toolMetrics || {},
      review_artifact_path: reviewArtifactPath,
      fix_session_id: fixSessionId,
      fix_session_path: fixSessionPath
    };
    const normalizedState = this.normalizeRuntimeState({
      role,
      toolBudget,
      reasoningMode,
      providerUsage,
      toolMetrics,
      evidenceCount,
      verificationStatus,
      toolCallsUsed,
      reviewArtifactPath,
      fixSessionId,
      fixSessionPath
    });
    agent.runtime_state = {
      ...agent.runtime_state,
      ...normalizedState,
      tool_budget: {
        ...agent.runtime_state.tool_budget,
        ...normalizedState.tool_budget
      }
    };
    this.appendExecutionHistory(agent, {
      timestamp: agent.last_active,
      success,
      action: taskAction,
      resultSummary,
      error: success ? null : error,
      executionTime,
      role,
      reasoningMode,
      providerUsage,
      toolMetrics,
      verificationStatus,
      toolCallsUsed,
      evidenceCount,
      reviewArtifactPath,
      fixSessionId,
      fixSessionPath
    });
    this.refreshDerivedAgentMetadata(agent);

    this.registry.last_updated = agent.last_active;
    this.saveRegistry();
  }

  /**
   * Respond to on-disk changes by reloading the registry.
   */
  reloadRegistry() {
    fsp.readFile(this.registryPath, 'utf8')
      .then(raw => JSON.parse(raw))
      .then(parsed => {
        this.registry = parsed;
        this.rebuildDerivedIndexes();
      })
      .catch(error => {
        console.warn('[AgentRegistryManager] Skipped reload:', error.message);
      });
  }

  /**
   * Schedule a debounced reload, ignoring our own writes.
   */
  scheduleReload() {
    if (Date.now() - this._lastWriteTime < this.options.suppressMs) {
      return;
    }

    if (this._reloadTimer) {
      clearTimeout(this._reloadTimer);
    }

    this._reloadTimer = setTimeout(() => {
      this._reloadTimer = null;
      this.reloadRegistry();
    }, this.options.debounceMs);
  }

  /**
   * Initialize filesystem watchers for hot reloading.
   */
  setupWatchers() {
    if (!this.options.watch) {
      return;
    }

    if (this._watchers.length > 0 || this._watchFileHandler) {
      return;
    }

    const startFsWatch = () => {
      try {
        const watcher = fs.watch(this.registryPath, eventType => {
          this.scheduleReload();
          if (eventType === 'rename') {
            this.restartWatchers();
          }
        });

        watcher.on('error', () => {
          this.restartWatchers(true);
        });

        this._watchers.push(watcher);
      } catch (error) {
        this.startWatchFileFallback();
      }
    };

    startFsWatch();

    if (this._watchers.length === 0) {
      this.startWatchFileFallback();
    }
  }

  /**
   * Fallback watcher using polling when fs.watch is unavailable.
   */
  startWatchFileFallback() {
    if (this._watchFileHandler) {
      return;
    }

    try {
      const handler = () => this.scheduleReload();
      fs.watchFile(
        this.registryPath,
        { interval: Math.max(this.options.debounceMs, 200) },
        handler
      );
      this._watchFileHandler = handler;
    } catch (error) {
      console.warn('[AgentRegistryManager] Unable to establish watchFile fallback:', error.message);
    }
  }

  /**
   * Tear down filesystem watchers.
   */
  teardownWatchers() {
    this._watchers.forEach(watcher => {
      try {
        watcher.close();
      } catch (error) {
        // no-op
      }
    });
    this._watchers = [];

    if (this._watchFileHandler) {
      fs.unwatchFile(this.registryPath, this._watchFileHandler);
      this._watchFileHandler = null;
    }
  }

  /**
   * Restart watchers, optionally forcing the polling fallback.
   */
  restartWatchers(forceFallback = false) {
    this.teardownWatchers();
    if (!this.options.watch) {
      return;
    }

    if (forceFallback) {
      this.startWatchFileFallback();
    } else {
      this.setupWatchers();
    }
  }

  /**
   * Dispose watchers and timers.
   */
  async flush() {
    await this._pendingSave.catch(() => {});
  }

  async close() {
    if (this._reloadTimer) {
      clearTimeout(this._reloadTimer);
      this._reloadTimer = null;
    }

    this.teardownWatchers();
    await this.flush();
  }

  /**
   * Health check
   */
  healthCheck(agentId) {
    const agent = this.getAgentById(agentId);
    if (!agent) return { healthy: false, reason: 'Agent not found' };

    const health = {
      healthy: true,
      agent_id: agent.id,
      agent_name: agent.name,
      status: agent.status,
      last_active: agent.last_active,
      performance: agent.performance_metrics,
      resources: agent.resource_usage
    };

    // Check if agent has been active recently
    if (agent.last_active) {
      const lastActive = new Date(agent.last_active);
      const now = new Date();
      const hoursSinceActive = (now - lastActive) / (1000 * 60 * 60);

      if (hoursSinceActive > 24) {
        health.healthy = false;
        health.reason = `Agent inactive for ${hoursSinceActive.toFixed(1)} hours`;
      }
    }

    // Check success rate
    if (agent.performance_metrics.success_rate < 0.8) {
      health.healthy = false;
      health.reason = `Low success rate: ${(agent.performance_metrics.success_rate * 100).toFixed(1)}%`;
    }

    // Check quality score
    if (agent.performance_metrics.quality_score < 0.7) {
      health.healthy = false;
      health.reason = `Low quality score: ${(agent.performance_metrics.quality_score * 100).toFixed(1)}%`;
    }

    return health;
  }

  /**
   * Get registry statistics
   */
  getStatistics() {
    return {
      total_agents: this.registry.agent_count,
      tiers: this.registry.tiers,
      domains: this.registry.domains.length,
      capabilities: Object.keys(this.registry.capabilities_index).length,
      specializations: Object.keys(this.registry.specializations_index).length,
      last_updated: this.registry.last_updated,
      active_agents: this.registry.agents.filter(a => a.status === 'active').length,
      idle_agents: this.registry.agents.filter(a => a.status === 'idle').length,
      busy_agents: this.registry.agents.filter(a => a.status === 'busy').length
    };
  }

  /**
   * Print registry summary
   */
  printSummary() {
    const stats = this.getStatistics();
    console.log('\n+- AGENT REGISTRY SUMMARY --------------------------------------+');
    console.log(`| Total Agents: ${stats.total_agents.toString().padEnd(50)} |`);
    console.log(`| Active: ${stats.active_agents.toString().padEnd(56)} |`);
    console.log(`| Idle: ${stats.idle_agents.toString().padEnd(58)} |`);
    console.log(`| Busy: ${stats.busy_agents.toString().padEnd(58)} |`);
    console.log('|                                                                |');
    console.log('| Tier Distribution:                                             |');
    console.log(`| +- Meta Gods: ${stats.tiers.meta_gods.toString().padEnd(49)} |`);
    console.log(`| +- Domain Titans: ${stats.tiers.domain_gods.toString().padEnd(45)} |`);
    console.log(`| +- Specialists: ${stats.tiers.specialists.toString().padEnd(47)} |`);
    console.log(`| +- Workers: ${stats.tiers.workers.toString().padEnd(51)} |`);
    console.log('|                                                                |');
    console.log(`| Domains: ${stats.domains.toString().padEnd(56)} |`);
    console.log(`| Capabilities: ${stats.capabilities.toString().padEnd(51)} |`);
    console.log(`| Specializations: ${stats.specializations.toString().padEnd(48)} |`);
    console.log('+----------------------------------------------------------------+\n');
  }
}

module.exports = AgentRegistryManager;
module.exports.DEFAULT_REGISTRY_PATH = REGISTRY_PATH;

// Example usage
if (require.main === module) {
  const manager = new AgentRegistryManager();
  manager.printSummary();

  console.log('\nDiscovering agents by capability "semantic_analysis":');
  const semanticAgents = manager.discoverByCapability('semantic_analysis');
  semanticAgents.forEach(agent => {
    console.log(`  - ${agent.name} (Tier ${agent.tier}: ${agent.tier_name})`);
  });
}
