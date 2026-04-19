/**
 * Agent Spawner & Lifecycle Manager
 *
 * Manages the complete lifecycle of agents:
 * - Spawning new agent instances
 * - Monitoring agent health
 * - Tracking agent status
 * - Auto-recovery for failed agents
 * - Resource management
 * - Performance tracking
 */

const EventEmitter = require('events');
const { Worker } = require('worker_threads');
const path = require('path');
const fs = require('fs');
const AgentExecutionEngine = require('./agent-execution-engine');
const AgentSDK = require('./agent-sdk');
const { resolveRoleProfile } = require('./agent-runtime/role-profiles');

class AgentSpawner extends EventEmitter {
  constructor(messageBus, registry, options = {}) {
    super();

    this.messageBus = messageBus;
    this.registry = registry;
    this.executionEngine = new AgentExecutionEngine();

    this.options = {
      maxConcurrentAgents: options.maxConcurrentAgents ?? 250,
      healthCheckInterval: options.healthCheckInterval ?? 30000, // 30 seconds
      autoRecovery: options.autoRecovery ?? true,
      maxRecoveryAttempts: options.maxRecoveryAttempts ?? 3,
      agentTimeout: options.agentTimeout ?? 300000, // 5 minutes
      resourceLimits: {
        maxCpu: options.resourceLimits?.maxCpu ?? 80, // percent
        maxMemory: options.resourceLimits?.maxMemory ?? 1024 * 1024 * 1024, // 1GB per agent
        ...options.resourceLimits
      },
      ...options
    };

    // Active agent instances
    this.agents = new Map(); // agent_instance_id -> AgentInstance

    // Agent templates (definitions from registry)
    this.agentTemplates = new Map(); // agent_name -> template

    // Metrics
    this.metrics = {
      agentsSpawned: 0,
      agentsTerminated: 0,
      agentsFailed: 0,
      agentsRecovered: 0,
      totalUptime: 0,
      averageLifetime: 0
    };

    // Load agent templates
    this.loadAgentTemplates();

    // Start health monitoring
    this.startHealthMonitoring();

    console.log('[AgentSpawner] Initialized with max concurrent agents:', this.options.maxConcurrentAgents);
  }

  /**
   * Load agent templates from registry
   */
  loadAgentTemplates() {
    const agentsDir = path.join(__dirname, '..', 'agents');

    // Load from registry
    if (this.registry && this.registry.registry.agents) {
      this.registry.registry.agents.forEach(agent => {
        const agentFile = agent.file;

        // Security check: Prevent path traversal in agent file paths
        if (agentFile.includes('..') || path.isAbsolute(agentFile)) {
          console.warn(`[WARNING] Skipped potentially unsafe agent file path: ${agentFile}`);
          return;
        }

        this.agentTemplates.set(agent.name, {
          name: agent.name,
          tier: agent.tier,
          domain: agent.domain,
          file: path.join(agentsDir, agentFile),
          role: resolveRoleProfile({ role: agent.role || agent.name }, { action: 'analyze' }).name,
          capabilities: agent.capabilities,
          specializations: agent.specializations
        });
      });
    }

    console.log(`[AgentSpawner] Loaded ${this.agentTemplates.size} agent templates`);
  }

  /**
   * Spawn a new agent instance
   */
  async spawn(agentName, config = {}) {
    // Check if we've hit the limit
    if (this.agents.size >= this.options.maxConcurrentAgents) {
      throw new Error(`Maximum concurrent agents reached (${this.options.maxConcurrentAgents})`);
    }

    // Get agent template
    const template = this.agentTemplates.get(agentName);
    if (!template) {
      throw new Error(`Unknown agent: ${agentName}`);
    }

    // Create agent instance
    const instance = this.createAgentInstance(template, config);

    if (this.registry) {
      const resolve = typeof this.registry.resolveAgent === 'function'
        ? this.registry.resolveAgent.bind(this.registry)
        : (identifier) => this.registry.getAgentByName(identifier);

      const initialRecord = resolve(template.name);
      if (initialRecord?.id) {
        instance.registryId = initialRecord.id;
      }

      instance.sdk = new AgentSDK({
        agentId: instance.registryId,
        agentName: template.name,
        role: instance.role,
        toolBudget: {
          limit: instance.runtimePolicy.toolBudget.maxCalls,
          used: 0,
          remaining: instance.runtimePolicy.toolBudget.maxCalls
        },
        registryManager: this.registry,
        messageBus: this.messageBus,
        logger: console,
        heartbeatInterval: this.options.healthCheckInterval
      });
      instance.sdk.startSession({ status: 'active' });

      const refreshedRecord = resolve(instance.sdk.getRegistryIdentifier());
      if (refreshedRecord?.id) {
        instance.registryId = refreshedRecord.id;
      }
    }

    // Store instance
    this.agents.set(instance.id, instance);

    // Update metrics
    this.metrics.agentsSpawned++;

    // Emit event
    this.emit('agent:spawned', instance);

    // Register with message bus
    if (this.messageBus) {
      this.messageBus.registerAgent(
        instance.id,
        async (message) => {
          await this.handleAgentMessage(instance, message);
        },
        { sdk: instance.sdk }
      );
    }

    console.log(`[AgentSpawner] Spawned agent: ${instance.id} (${agentName})`);

    return instance;
  }

  /**
   * Create agent instance object
   */
  createAgentInstance(template, config) {
    const instanceId = `${template.name}-${Date.now()}-${Math.random().toString(36).substring(7)}`;

    const instance = {
      id: instanceId,
      name: template.name,
      tier: template.tier,
      domain: template.domain,
      file: template.file,
      role: template.role,
      capabilities: template.capabilities,
      specializations: template.specializations,
      registryId: null, // Will be set if registered in registry
      status: 'active',
      state: {
        currentTask: null,
        tasksCompleted: 0,
        tasksSucceeded: 0,
        tasksFailed: 0,
        lastActive: new Date().toISOString(),
        lastError: null,
        recoveryAttempts: 0
      },
      resources: {
        cpu: 0,
        memory: 0,
        threads: 0
      },
      runtimePolicy: resolveRoleProfile(template, { action: 'analyze', metadata: { role: template.role } }),
      performance: {
        averageResponseTime: 0,
        totalResponseTime: 0,
        requestsProcessed: 0
      },
      config,
      createdAt: new Date().toISOString(),
      terminatedAt: null,
      healthCheckFailures: 0,
      worker: null, // For future worker thread implementation
      sdk: null
    };

    return instance;
  }

  /**
   * Handle message sent to an agent
   */
  async handleAgentMessage(instance, message) {
    const startTime = Date.now();

    if (instance.sdk) {
      instance.sdk.heartbeat('active');
    }

    try {
      // Update last active
      instance.state.lastActive = new Date().toISOString();

      // Process message based on content
      const response = await this.processAgentTask(instance, message);

      // Send response if needed
      if (message.type === 'request' && this.messageBus) {
        if (typeof this.messageBus.respondToDelegatedTask === 'function') {
          await this.messageBus.respondToDelegatedTask(message, instance.id, response);
        } else {
          await this.messageBus.respond(message, instance.id, response);
        }
      }

      // Update performance metrics
      const responseTime = Date.now() - startTime;
      instance.performance.requestsProcessed++;
      instance.performance.totalResponseTime += responseTime;
      instance.performance.averageResponseTime =
        instance.performance.totalResponseTime / instance.performance.requestsProcessed;

      // Update state
      instance.state.tasksSucceeded++;

    } catch (error) {
      console.error(`[AgentSpawner] Agent ${instance.id} error:`, error.message);
      instance.state.tasksFailed++;
      instance.state.lastError = error.message;

      // Send error response
      if (message.type === 'request' && this.messageBus) {
        const failureResponse = this.createDelegationFailureResponse(instance, message, error);
        if (typeof this.messageBus.respondToDelegatedTask === 'function') {
          await this.messageBus.respondToDelegatedTask(message, instance.id, failureResponse);
        } else {
          await this.messageBus.respond(message, instance.id, {
            error: error.message,
            success: false
          });
        }
      }

      // Check if we need to recover
      if (this.options.autoRecovery) {
        this.attemptRecovery(instance);
      }
    }
  }

  /**
   * Process a task for an agent using REAL execution
   */
  async processAgentTask(instance, message) {
    const delegatedTaskRequest = message?.content?.delegation?.taskRequest || null;
    const taskId = delegatedTaskRequest?.taskId || message?.content?.task_id || message?.message_id || `${instance.id}-${Date.now()}`;
    const action = delegatedTaskRequest?.action || message?.content?.action || message?.type || 'unknown';
    const effectiveRole =
      delegatedTaskRequest?.requestedRole ||
      message?.content?.metadata?.role ||
      instance.role;

    // Mark agent as busy
    instance.status = 'busy';
    instance.state.currentTask = taskId;

    const lease = instance.sdk
      ? instance.sdk.leaseTask(taskId, {
        action,
        metadata: {
          ...(message?.content?.metadata || {}),
          role: effectiveRole
        },
        delegation: delegatedTaskRequest
      })
      : null;
    const leasedAt = lease?.startedAt || Date.now();

    try {
      // REAL EXECUTION: Use the execution engine to actually execute the task
      const executionResult = await this.executionEngine.executeTask(
        instance.name,
        {
          action: message?.content?.action,
          content: message?.content?.task || message?.content,
          metadata: {
            ...(message?.content?.metadata || {}),
            role: effectiveRole
          }
        }
      );

      // Mark as idle
      instance.status = 'idle';
      instance.state.currentTask = null;
      instance.state.tasksCompleted++;

      if (instance.sdk) {
        const duration = Date.now() - leasedAt;
        const success = executionResult?.success !== false;
        const quality = typeof executionResult?.quality === 'number'
          ? executionResult.quality
          : (success ? 1 : 0);
        const runtimeState = executionResult?.result?.runtime_state || {};
        instance.sdk.completeTask({
          taskId,
          success,
          executionTime: duration,
          resultSummary: executionResult?.result?.message || executionResult?.message || null,
          qualityScore: quality,
          error: success ? null : (executionResult?.error || executionResult?.result?.error || executionResult?.result?.message || null),
          role: runtimeState.role || instance.role,
          reasoningMode: runtimeState.reasoningMode || 'standard',
          toolBudget: runtimeState.toolBudget || {
            limit: instance.runtimePolicy.toolBudget.maxCalls,
            used: runtimeState.toolCallsUsed || 0,
            remaining: instance.runtimePolicy.toolBudget.maxCalls
          },
          providerUsage: runtimeState.providerUsage || null,
          toolMetrics: runtimeState.toolMetrics || null,
          evidenceCount: runtimeState.evidenceCount || 0,
          verificationStatus: runtimeState.verificationStatus || (success ? 'verified' : 'failed'),
          toolCallsUsed: runtimeState.toolCallsUsed || 0,
          statusOnComplete: 'idle'
        });
      }

      return executionResult;

    } catch (error) {
      // Mark as idle even on error
      instance.status = 'idle';
      instance.state.currentTask = null;
      instance.state.tasksCompleted++;

      if (instance.sdk) {
        const duration = Date.now() - leasedAt;
        instance.sdk.completeTask({
          taskId,
          success: false,
          executionTime: duration,
          error: error.message,
          qualityScore: 0,
          statusOnComplete: 'idle'
        });
      }

      throw error;
    }
  }

  createDelegationFailureResponse(instance, message, error) {
    const taskId = message?.content?.task_id || message?.message_id || `${instance.id}-${Date.now()}`;
    const action = message?.content?.action || message?.type || 'task';
    const budgetLimit = instance.runtimePolicy?.toolBudget?.maxCalls || 0;

    return {
      success: false,
      error: error.message,
      quality: 0,
      result: {
        type: action,
        status: 'failed',
        success: false,
        summary: error.message,
        message: error.message,
        quality: 0,
        evidence: [],
        evidenceSummary: 'No evidence recorded.',
        toolTrace: [],
        artifacts: [],
        runtime_state: {
          role: instance.role,
          reasoningMode: 'standard',
          toolBudget: {
            limit: budgetLimit,
            used: 0,
            remaining: budgetLimit
          },
          providerUsage: {
            selectedProvider: null,
            selectedModel: null,
            totalCostUsd: 0,
            retries: 0,
            tokensUsed: { input: 0, output: 0, cached: 0 }
          },
          toolMetrics: {},
          evidenceCount: 0,
          verificationStatus: 'failed',
          toolCallsUsed: 0
        },
        error: error.message,
        taskId
      }
    };
  }

  /**
   * Attempt to recover a failed agent
   */
  async attemptRecovery(instance) {
    if (instance.state.recoveryAttempts >= this.options.maxRecoveryAttempts) {
      console.error(`[AgentSpawner] Agent ${instance.id} exceeded max recovery attempts, terminating`);
      await this.terminate(instance.id, 'max_recovery_attempts');
      return;
    }

    instance.state.recoveryAttempts++;
    console.log(`[AgentSpawner] Attempting recovery for ${instance.id} (attempt ${instance.state.recoveryAttempts})`);

    // Reset agent state
    instance.status = 'idle';
    instance.state.currentTask = null;
    instance.state.lastError = null;
    instance.healthCheckFailures = 0;
    if (instance.sdk) {
      instance.sdk.heartbeat('idle');
    }

    this.metrics.agentsRecovered++;
    this.emit('agent:recovered', instance);
  }

  /**
   * Terminate an agent instance
   */
  async terminate(instanceId, reason = 'manual') {
    const instance = this.agents.get(instanceId);
    if (!instance) {
      throw new Error(`Agent instance not found: ${instanceId}`);
    }

    // Mark as terminated
    instance.status = 'terminated';
    instance.terminatedAt = new Date().toISOString();

    // Calculate lifetime
    const lifetime = new Date(instance.terminatedAt) - new Date(instance.createdAt);

    if (instance.sdk) {
      instance.sdk.stop({ status: 'terminated', reason });
      instance.sdk.close();
    }

    // Unregister from message bus
    if (this.messageBus) {
      this.messageBus.unregisterAgent(instance.id);
    }

    // Update registry
    if (this.registry) {
      this.registry.updateAgentStatus(instance.registryId, 'terminated');
    }

    // Remove from active agents
    this.agents.delete(instanceId);

    // Update metrics
    this.metrics.agentsTerminated++;
    this.metrics.totalUptime += lifetime;
    this.metrics.averageLifetime = this.metrics.totalUptime / this.metrics.agentsTerminated;

    // Emit event
    this.emit('agent:terminated', { instance, reason });

    console.log(`[AgentSpawner] Terminated agent: ${instanceId} (reason: ${reason}, lifetime: ${(lifetime / 1000).toFixed(1)}s)`);
  }

  /**
   * Get agent instance
   */
  getInstance(instanceId) {
    return this.agents.get(instanceId);
  }

  /**
   * Get all instances of a specific agent type
   */
  getInstancesByName(agentName) {
    return Array.from(this.agents.values()).filter(instance => instance.name === agentName);
  }

  /**
   * Get agents by status
   */
  getAgentsByStatus(status) {
    return Array.from(this.agents.values()).filter(instance => instance.status === status);
  }

  /**
   * Get agents by capability
   */
  getAgentsByCapability(capability) {
    return Array.from(this.agents.values()).filter(instance =>
      instance.capabilities.includes(capability)
    );
  }

  /**
   * Health check for an agent
   */
  async healthCheck(instance) {
    try {
      // Check if agent has been idle too long
      const lastActive = new Date(instance.state.lastActive);
      const now = new Date();
      const idleTime = now - lastActive;

      if (idleTime > this.options.agentTimeout && instance.status === 'busy') {
        throw new Error(`Agent timeout (idle for ${(idleTime / 1000).toFixed(1)}s)`);
      }

      // Check resource usage
      if (instance.resources.cpu > this.options.resourceLimits.maxCpu) {
        console.warn(`[AgentSpawner] Agent ${instance.id} high CPU usage: ${instance.resources.cpu}%`);
      }

      if (instance.resources.memory > this.options.resourceLimits.maxMemory) {
        console.warn(`[AgentSpawner] Agent ${instance.id} high memory usage: ${(instance.resources.memory / 1024 / 1024).toFixed(1)}MB`);
      }

      // Check error rate
      const errorRate = instance.state.tasksFailed / Math.max(instance.state.tasksCompleted, 1);
      if (errorRate > 0.5 && instance.state.tasksCompleted > 10) {
        throw new Error(`High error rate: ${(errorRate * 100).toFixed(1)}%`);
      }

      // Reset failure counter on successful check
      instance.healthCheckFailures = 0;

      return { healthy: true, instance };

    } catch (error) {
      instance.healthCheckFailures++;
      console.error(`[AgentSpawner] Health check failed for ${instance.id}:`, error.message);

      // Terminate if too many failures
      if (instance.healthCheckFailures >= 3) {
        await this.terminate(instance.id, 'health_check_failure');
        this.metrics.agentsFailed++;
      }

      return { healthy: false, error: error.message, instance };
    }
  }

  /**
   * Start health monitoring
   */
  startHealthMonitoring() {
    this.healthMonitorInterval = setInterval(async () => {
      const instances = Array.from(this.agents.values());

      for (const instance of instances) {
        await this.healthCheck(instance);
      }
    }, this.options.healthCheckInterval);

    console.log('[AgentSpawner] Health monitoring started');
  }

  /**
   * Stop health monitoring
   */
  stopHealthMonitoring() {
    if (this.healthMonitorInterval) {
      clearInterval(this.healthMonitorInterval);
      this.healthMonitorInterval = null;
      console.log('[AgentSpawner] Health monitoring stopped');
    }
  }

  /**
   * Get metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      activeAgents: this.agents.size,
      maxConcurrentAgents: this.options.maxConcurrentAgents,
      utilizationPercent: (this.agents.size / this.options.maxConcurrentAgents) * 100,
      agentsByStatus: {
        active: this.getAgentsByStatus('active').length,
        idle: this.getAgentsByStatus('idle').length,
        busy: this.getAgentsByStatus('busy').length
      }
    };
  }

  /**
   * Print metrics dashboard
   */
  printMetrics() {
    const metrics = this.getMetrics();
    console.log('\n+- AGENT SPAWNER METRICS ------------------------------------+');
    console.log(`| Active Agents: ${metrics.activeAgents}/${metrics.maxConcurrentAgents} (${metrics.utilizationPercent.toFixed(1)}%)${' '.repeat(30 - (metrics.activeAgents + '/' + metrics.maxConcurrentAgents).length)} |`);
    console.log(`| +- Active: ${metrics.agentsByStatus.active.toString().padEnd(51)} |`);
    console.log(`| +- Idle: ${metrics.agentsByStatus.idle.toString().padEnd(53)} |`);
    console.log(`| +- Busy: ${metrics.agentsByStatus.busy.toString().padEnd(53)} |`);
    console.log('|                                                            |');
    console.log(`| Lifecycle:                                                 |`);
    console.log(`| +- Agents Spawned: ${metrics.agentsSpawned.toString().padEnd(42)} |`);
    console.log(`| +- Agents Terminated: ${metrics.agentsTerminated.toString().padEnd(39)} |`);
    console.log(`| +- Agents Failed: ${metrics.agentsFailed.toString().padEnd(45)} |`);
    console.log(`| +- Agents Recovered: ${metrics.agentsRecovered.toString().padEnd(41)} |`);
    console.log('|                                                            |');
    console.log(`| Average Agent Lifetime: ${(metrics.averageLifetime / 1000).toFixed(1)}s${' '.repeat(30 - (metrics.averageLifetime / 1000).toFixed(1).length)} |`);
    console.log('+------------------------------------------------------------+\n');
  }

  /**
   * List all active agents
   */
  listAgents() {
    const instances = Array.from(this.agents.values());
    console.log('\n+- ACTIVE AGENTS --------------------------------------------+');
    instances.forEach(instance => {
      const uptime = ((Date.now() - new Date(instance.createdAt)) / 1000).toFixed(0);
      const taskStatus = `${instance.state.tasksSucceeded}/${instance.state.tasksCompleted} tasks`;
      console.log(`| ${instance.id.substring(0, 35).padEnd(35)} | ${instance.status.padEnd(6)} | ${uptime}s |`);
    });
    if (instances.length === 0) {
      console.log(`| No active agents${' '.repeat(44)} |`);
    }
    console.log('+------------------------------------------------------------+\n');
  }

  /**
   * Shutdown spawner
   */
  async shutdown() {
    console.log('[AgentSpawner] Shutting down...');

    // Stop health monitoring
    this.stopHealthMonitoring();

    // Terminate all agents
    const instances = Array.from(this.agents.keys());
    for (const instanceId of instances) {
      await this.terminate(instanceId, 'shutdown');
    }

    // Clear event listeners
    this.removeAllListeners();

    console.log('[AgentSpawner] Shutdown complete');
  }
}

module.exports = AgentSpawner;

// Example usage
if (require.main === module) {
  const AgentMessageBus = require('./agent-message-bus');
  const AgentRegistryManager = require('./agent-registry-manager');

  const messageBus = new AgentMessageBus();
  const registry = new AgentRegistryManager();
  const spawner = new AgentSpawner(messageBus, registry);

  async function test() {
    console.log('\n=== Testing Agent Spawner ===\n');

    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    // Spawn some agents
    const agent1 = await spawner.spawn('code-intelligence-agent');
    const agent2 = await spawner.spawn('architecture-agent');
    const agent3 = await spawner.spawn('self-healing-agent');

    // List agents
    spawner.listAgents();

    // Send a task to an agent
    await messageBus.request('test-client', agent1.id, {
      action: 'analyze',
      file: 'user-service.js'
    }, {}, 5000);

    // Wait a bit
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Print metrics
    spawner.printMetrics();
    messageBus.printMetrics();

    // Shutdown
    await spawner.shutdown();
    messageBus.shutdown();
  }

  test().catch(console.error);
}
