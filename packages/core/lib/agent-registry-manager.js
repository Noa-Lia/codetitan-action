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

const REGISTRY_PATH = path.join(__dirname, '..', 'agents', 'agent-registry.json');
const DEFAULT_OPTIONS = {
  watch: true,
  debounceMs: 300,
  suppressMs: 500
};

class AgentRegistryManager {
  constructor(options = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.registryPath = this.options.registryPath || REGISTRY_PATH;
    this.registry = this.createEmptyRegistry();
    this.loadRegistryFromDisk();
    this.rebuildDerivedIndexes();

    this._watchers = [];
    this._watchFileHandler = null;
    this._reloadTimer = null;
    this._lastWriteTime = 0;

    if (this.options.watch) {
      this.setupWatchers();
    }
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
        console.warn('[AgentRegistryManager] Failed to load registry (using in-memory default):', error.message);
        this.registry = this.registry || this.createEmptyRegistry();
      });
  }

  /**
   * Save registry to file
   */
  saveRegistry() {
    try {
      const data = JSON.stringify(this.registry, null, 2);
      this._lastWriteTime = Date.now();
      fsp.writeFile(this.registryPath, data, 'utf8').catch(err => {
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
    });

    this.registry.agents = agents;
    this.registry.agent_count = agents.length;
    this.registry.domains = Array.from(domains.values());
    this.registry.capabilities_index = capabilitiesIndex;
    this.registry.specializations_index = specializationsIndex;
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
  touchAgent(agentIdentifier, status) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return false;
    }
    if (status) {
      agent.status = status;
    }
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
        execution_time_ms: telemetry.executionTime ?? null
      };

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

  recordExecution(agentIdentifier, { success, executionTime = null, taskAction = null, resultSummary = null, error = null } = {}) {
    const agent = this.resolveAgent(agentIdentifier);
    if (!agent) {
      return;
    }

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
      execution_time_ms: executionTime
    };

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
  close() {
    if (this._reloadTimer) {
      clearTimeout(this._reloadTimer);
      this._reloadTimer = null;
    }

    this.teardownWatchers();
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
