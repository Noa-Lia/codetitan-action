/**
 * Task Distribution System
 *
 * Intelligent task routing and distribution to optimal agents.
 *
 * Features:
 * - Capability-based agent selection
 * - Load balancing across agents
 * - Performance-aware routing
 * - Task decomposition
 * - Dependency management
 * - Retry and failover
 * - Task tracking and monitoring
 */

const EventEmitter = require('events');

class TaskDistributor extends EventEmitter {
  constructor(messageBus, spawner, registry, options = {}) {
    super();

    this.messageBus = messageBus;
    this.spawner = spawner;
    this.registry = registry;

    this.options = {
      selectionStrategy: options.selectionStrategy ?? 'weighted', // weighted, round-robin, least-loaded, performance-based
      maxRetries: options.maxRetries ?? 3,
      taskTimeout: options.taskTimeout ?? 300000, // 5 minutes
      autoSpawnAgents: options.autoSpawnAgents ?? true,
      loadBalancing: options.loadBalancing ?? true,
      ...options
    };

    // Active tasks
    this.tasks = new Map(); // task_id -> Task
    this.taskQueue = []; // Pending tasks

    // Agent selection weights
    this.selectionWeights = {
      capabilityMatch: 0.40,     // How well capabilities match
      specializationMatch: 0.30,  // Exact specialization match
      performance: 0.15,          // Agent's historical performance
      load: 0.10,                 // Current agent load
      availability: 0.05          // Agent availability
    };

    // Metrics
    this.metrics = {
      tasksReceived: 0,
      tasksAssigned: 0,
      tasksCompleted: 0,
      tasksFailed: 0,
      tasksRetried: 0,
      averageAssignmentTime: 0,
      totalAssignmentTime: 0,
      averageExecutionTime: 0,
      totalExecutionTime: 0
    };

    console.log('[TaskDistributor] Initialized with strategy:', this.options.selectionStrategy);
  }

  /**
   * Submit a task for distribution
   */
  async submitTask(task) {
    if (!task) throw new Error('Task is required');
    if (!task.type && !task.description) throw new Error('Task type required');

    const taskId = this.generateTaskId();

    const taskObj = {
      id: taskId,
      type: task.type,
      description: task.description || 'Unnamed task',
      requiredCapabilities: task.requiredCapabilities || [],
      preferredSpecializations: task.preferredSpecializations || [],
      priority: task.priority || 'medium',
      dependencies: task.dependencies || [],
      content: task.content || {},
      metadata: task.metadata || {},
      submittedAt: new Date().toISOString(),
      assignedAt: null,
      startedAt: null,
      completedAt: null,
      status: 'pending',
      assignedAgent: null,
      result: null,
      error: null,
      retryCount: 0,
      executionTime: null
    };

    // Store task
    this.tasks.set(taskId, taskObj);
    this.metrics.tasksReceived++;

    // Emit event
    this.emit('task:submitted', taskObj);

    console.log(`[TaskDistributor] Task submitted: ${taskId} - ${taskObj.description}`);

    // Assign task
    try {
      await this.assignTask(taskObj);
    } catch (error) {
      console.error(`[TaskDistributor] Failed to assign task ${taskId}:`, error.message);
      taskObj.status = 'failed';
      taskObj.error = error.message;
      this.metrics.tasksFailed++;
    }

    return taskObj;
  }

  /**
   * Assign a task to an agent
   */
  async assignTask(task) {
    const assignmentStartTime = Date.now();

    // Find optimal agent
    const agent = await this.selectOptimalAgent(task);

    if (!agent) {
      // No suitable agent found
      if (this.options.autoSpawnAgents) {
        // Try to spawn a suitable agent
        const spawnedAgent = await this.spawnSuitableAgent(task);
        if (spawnedAgent) {
          return this.assignTaskToAgent(task, spawnedAgent, assignmentStartTime);
        }
      }

      throw new Error('No suitable agent available');
    }

    return this.assignTaskToAgent(task, agent, assignmentStartTime);
  }

  getAgentIdentifier(agent) {
    return agent.registryId || agent.id || agent.name;
  }

  getRegistryRecord(agent) {
    if (!this.registry) return null;
    if (typeof this.registry.resolveAgent === 'function') {
      return this.registry.resolveAgent(this.getAgentIdentifier(agent));
    }
    if (agent.registryId && typeof this.registry.getAgentById === 'function') {
      return this.registry.getAgentById(agent.registryId);
    }
    if (agent.name && typeof this.registry.getAgentByName === 'function') {
      return this.registry.getAgentByName(agent.name);
    }
    if (agent.id && typeof this.registry.getAgentById === 'function') {
      return this.registry.getAgentById(agent.id);
    }
    return null;
  }

  /**
   * Assign task to specific agent
   */
  async assignTaskToAgent(task, agent, assignmentStartTime) {
    task.assignedAgent = agent.id;
    task.assignedAt = new Date().toISOString();
    task.status = 'assigned';

    // Update metrics
    const assignmentTime = Date.now() - assignmentStartTime;
    this.metrics.totalAssignmentTime += assignmentTime;
    this.metrics.averageAssignmentTime = this.metrics.totalAssignmentTime / ++this.metrics.tasksAssigned;

    const registryIdentifier = this.getAgentIdentifier(agent);
    if (this.registry && registryIdentifier) {
      this.registry.assignTask(registryIdentifier, task.id);
    }
    if (agent.sdk) {
      agent.sdk.heartbeat('busy');
    }

    // Send task to agent via message bus
    const taskStartTime = Date.now();

    try {
      task.startedAt = new Date().toISOString();
      task.status = 'in_progress';

      const response = await this.messageBus.request(
        'task-distributor',
        agent.id,
        {
          action: 'execute_task',
          task_id: task.id,
          task: task.content,
          metadata: task.metadata
        },
        {},
        this.options.taskTimeout
      );

      // Task completed successfully
      task.completedAt = new Date().toISOString();
      task.status = 'completed';
      task.result = response.content;
      task.executionTime = Date.now() - taskStartTime;

      // Update metrics
      this.metrics.tasksCompleted++;
      this.metrics.totalExecutionTime += task.executionTime;
      this.metrics.averageExecutionTime = this.metrics.totalExecutionTime / this.metrics.tasksCompleted;

      // Emit event
      this.emit('task:completed', task);

      console.log(`[TaskDistributor] Task completed: ${task.id} by ${agent.id} (${task.executionTime}ms)`);

      return task;

    } catch (error) {
      // Task failed
      task.error = error.message;
      task.status = 'failed';

      console.error(`[TaskDistributor] Task failed: ${task.id}`, error.message);

      // Retry if configured
      if (task.retryCount < this.options.maxRetries) {
        task.retryCount++;
        this.metrics.tasksRetried++;

        console.log(`[TaskDistributor] Retrying task ${task.id} (attempt ${task.retryCount}/${this.options.maxRetries})`);

        // Reset task state
        task.status = 'pending';
        task.assignedAgent = null;
        task.error = null;

        // Wait a bit before retrying
        await new Promise(resolve => setTimeout(resolve, 1000 * task.retryCount));

        // Try again with a different agent
        return this.assignTask(task);
      }

      // Max retries exceeded
      this.metrics.tasksFailed++;
      this.emit('task:failed', task);

      throw error;
    }
  }

  /**
   * Select optimal agent for a task
   */
  async selectOptimalAgent(task) {
    // Get all active agents
    const allAgents = Array.from(this.spawner.agents.values())
      .filter(agent => agent.status === 'active' || agent.status === 'idle');

    if (allAgents.length === 0) {
      return null;
    }

    // Filter agents by required capabilities
    const capableAgents = allAgents.filter(agent =>
      task.requiredCapabilities.every(cap => agent.capabilities.includes(cap))
    );

    if (capableAgents.length === 0) {
      return null;
    }

    // Select based on strategy
    switch (this.options.selectionStrategy) {
      case 'weighted':
        return this.selectByWeightedScore(capableAgents, task);

      case 'round-robin':
        return this.selectByRoundRobin(capableAgents);

      case 'least-loaded':
        return this.selectByLeastLoaded(capableAgents);

      case 'performance-based':
        return this.selectByPerformance(capableAgents);

      default:
        return this.selectByWeightedScore(capableAgents, task);
    }
  }

  /**
   * Select agent by weighted score
   */
  selectByWeightedScore(agents, task) {
    const scoredAgents = agents.map(agent => {
      const scores = {
        capabilityMatch: this.scoreCapabilityMatch(agent, task),
        specializationMatch: this.scoreSpecializationMatch(agent, task),
        performance: this.scorePerformance(agent),
        load: this.scoreLoad(agent),
        availability: this.scoreAvailability(agent)
      };

      const weightedScore =
        scores.capabilityMatch * this.selectionWeights.capabilityMatch +
        scores.specializationMatch * this.selectionWeights.specializationMatch +
        scores.performance * this.selectionWeights.performance +
        scores.load * this.selectionWeights.load +
        scores.availability * this.selectionWeights.availability;

      return {
        agent,
        score: weightedScore,
        breakdown: scores
      };
    });

    // Sort by score (highest first)
    scoredAgents.sort((a, b) => b.score - a.score);

    // Return highest scoring agent
    return scoredAgents[0].agent;
  }

  /**
   * Score capability match (0-1)
   */
  scoreCapabilityMatch(agent, task) {
    if (task.requiredCapabilities.length === 0) return 1.0;

    const matchCount = task.requiredCapabilities.filter(cap =>
      agent.capabilities.includes(cap)
    ).length;

    return matchCount / task.requiredCapabilities.length;
  }

  /**
   * Score specialization match (0-1)
   */
  scoreSpecializationMatch(agent, task) {
    if (!task.preferredSpecializations || task.preferredSpecializations.length === 0) {
      return 0.5; // Neutral score if no preferences
    }

    const matchCount = task.preferredSpecializations.filter(spec =>
      agent.specializations.includes(spec)
    ).length;

    return matchCount / task.preferredSpecializations.length;
  }

  /**
   * Score agent performance (0-1)
   */
  scorePerformance(agent) {
    const record = this.getRegistryRecord(agent);
    if (record?.performance_metrics) {
      const metrics = record.performance_metrics;
      if ((metrics.tasks_completed || 0) + (metrics.tasks_failed || 0) === 0) {
        return 0.5;
      }
      return metrics.success_rate ?? 0.5;
    }

    if (agent.state.tasksCompleted === 0) return 0.5;
    const successRate = agent.state.tasksSucceeded / agent.state.tasksCompleted;
    return successRate || 0.5;
  }

  /**
   * Score agent load (0-1, higher is better = less loaded)
   */
  scoreLoad(agent) {
    const record = this.getRegistryRecord(agent);
    const status = record?.status || agent.status;
    if (status === 'busy') return 0.1;
    if (status === 'idle') return 1.0;
    if (status === 'active') return 0.6;
    return 0.5;
  }

  /**
   * Score agent availability (0-1)
   */
  scoreAvailability(agent) {
    const record = this.getRegistryRecord(agent);
    const last = record?.last_active || agent.state.lastActive;
    if (!last) return 0.5;

    const lastActive = new Date(last);
    const now = new Date();
    const minutesSinceActive = (now - lastActive) / 1000 / 60;

    if (minutesSinceActive < 1) return 1.0;  // Very recent
    if (minutesSinceActive < 5) return 0.8;  // Recent
    if (minutesSinceActive < 15) return 0.5; // Somewhat recent
    return 0.2; // Old
  }

  /**
   * Select by round-robin
   */
  selectByRoundRobin(agents) {
    // Simple round-robin (pick least recently assigned)
    return agents.reduce((least, agent) => {
      if (!least) return agent;
      const currentLast = this.getRegistryRecord(agent)?.last_active || agent.state.lastActive;
      const leastLast = this.getRegistryRecord(least)?.last_active || least.state.lastActive;
      return new Date(currentLast) < new Date(leastLast) ? agent : least;
    }, null);
  }

  /**
   * Select least loaded agent
   */
  selectByLeastLoaded(agents) {
    return agents.reduce((least, agent) => {
      if (!least) return agent;
      return agent.state.tasksCompleted < least.state.tasksCompleted ? agent : least;
    }, null);
  }

  /**
   * Select by performance
   */
  selectByPerformance(agents) {
    return agents.reduce((best, agent) => {
      if (!best) return agent;

      const agentSuccessRate = agent.state.tasksCompleted > 0 ?
        agent.state.tasksSucceeded / agent.state.tasksCompleted : 0.5;

      const bestSuccessRate = best.state.tasksCompleted > 0 ?
        best.state.tasksSucceeded / best.state.tasksCompleted : 0.5;

      return agentSuccessRate > bestSuccessRate ? agent : best;
    }, null);
  }

  /**
   * Spawn a suitable agent for a task
   */
  async spawnSuitableAgent(task) {
    // Find agent type from registry that matches requirements
    const registryAgents = this.registry.registry.agents || [];

    const suitableAgentTypes = registryAgents.filter(agentDef =>
      task.requiredCapabilities.every(cap => agentDef.capabilities.includes(cap))
    );

    if (suitableAgentTypes.length === 0) {
      console.warn('[TaskDistributor] No suitable agent types found in registry');
      return null;
    }

    // Spawn the first matching agent
    const agentType = suitableAgentTypes[0];
    console.log(`[TaskDistributor] Spawning new agent: ${agentType.name} for task requirements`);

    try {
      // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
      const spawnedAgent = await this.spawner.spawn(agentType.name);
      return spawnedAgent;
    } catch (error) {
      console.error(`[TaskDistributor] Failed to spawn agent:`, error.message);
      return null;
    }
  }

  /**
   * Generate unique task ID
   */
  generateTaskId() {
    return `task-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Get task by ID
   */
  getTask(taskId) {
    return this.tasks.get(taskId);
  }

  /**
   * Get tasks by status
   */
  getTasksByStatus(status) {
    return Array.from(this.tasks.values()).filter(task => task.status === status);
  }

  /**
   * Get metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      pendingTasks: this.getTasksByStatus('pending').length,
      assignedTasks: this.getTasksByStatus('assigned').length,
      inProgressTasks: this.getTasksByStatus('in_progress').length,
      completedTasks: this.getTasksByStatus('completed').length,
      failedTasks: this.getTasksByStatus('failed').length,
      successRate: this.metrics.tasksCompleted > 0 ?
        (this.metrics.tasksCompleted / (this.metrics.tasksCompleted + this.metrics.tasksFailed)) : 1.0
    };
  }

  /**
   * Print metrics dashboard
   */
  printMetrics() {
    const metrics = this.getMetrics();
    console.log('\n+- TASK DISTRIBUTOR METRICS ---------------------------------+');
    console.log(`| Tasks Received: ${metrics.tasksReceived.toString().padEnd(47)} |`);
    console.log(`| Tasks Assigned: ${metrics.tasksAssigned.toString().padEnd(47)} |`);
    console.log(`| Tasks Completed: ${metrics.tasksCompleted.toString().padEnd(46)} |`);
    console.log(`| Tasks Failed: ${metrics.tasksFailed.toString().padEnd(49)} |`);
    console.log(`| Tasks Retried: ${metrics.tasksRetried.toString().padEnd(48)} |`);
    console.log('|                                                            |');
    console.log(`| Success Rate: ${(metrics.successRate * 100).toFixed(1)}%${' '.repeat(45 - (metrics.successRate * 100).toFixed(1).length)} |`);
    console.log(`| Avg Assignment Time: ${metrics.averageAssignmentTime.toFixed(2)}ms${' '.repeat(35 - metrics.averageAssignmentTime.toFixed(2).length)} |`);
    console.log(`| Avg Execution Time: ${metrics.averageExecutionTime.toFixed(2)}ms${' '.repeat(36 - metrics.averageExecutionTime.toFixed(2).length)} |`);
    console.log('|                                                            |');
    console.log(`| Current Status:                                            |`);
    console.log(`| +- Pending: ${metrics.pendingTasks.toString().padEnd(49)} |`);
    console.log(`| +- Assigned: ${metrics.assignedTasks.toString().padEnd(48)} |`);
    console.log(`| +- In Progress: ${metrics.inProgressTasks.toString().padEnd(45)} |`);
    console.log(`| +- Completed: ${metrics.completedTasks.toString().padEnd(47)} |`);
    console.log(`| +- Failed: ${metrics.failedTasks.toString().padEnd(50)} |`);
    console.log('+------------------------------------------------------------+\n');
  }

  /**
   * Shutdown distributor
   */
  shutdown() {
    console.log('[TaskDistributor] Shutting down...');
    this.tasks.clear();
    this.taskQueue = [];
    this.removeAllListeners();
    console.log('[TaskDistributor] Shutdown complete');
  }
}

module.exports = TaskDistributor;

// Example usage
if (require.main === module) {
  const AgentMessageBus = require('./agent-message-bus');
  const AgentRegistryManager = require('./agent-registry-manager');
  const AgentSpawner = require('./agent-spawner');

  const messageBus = new AgentMessageBus();
  const registry = new AgentRegistryManager();
  const spawner = new AgentSpawner(messageBus, registry);
  const distributor = new TaskDistributor(messageBus, spawner, registry);

  async function test() {
    console.log('\n=== Testing Task Distributor ===\n');

    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    // Spawn some agents
    await spawner.spawn('code-intelligence-agent');
    await spawner.spawn('architecture-agent');
    await spawner.spawn('self-healing-agent');

    // Submit tasks
    const task1 = await distributor.submitTask({
      description: 'Analyze code quality',
      requiredCapabilities: ['semantic_analysis'],
      content: {
        file: 'user-service.js'
      }
    });

    const task2 = await distributor.submitTask({
      description: 'Design architecture',
      requiredCapabilities: ['analysis', 'design'],
      content: {
        system: 'e-commerce'
      }
    });

    const task3 = await distributor.submitTask({
      description: 'Auto-fix errors',
      requiredCapabilities: ['error_detection', 'auto_fix'],
      content: {
        errors: ['null-pointer', 'type-error']
      }
    });

    // Wait for tasks to complete
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Print metrics
    distributor.printMetrics();
    spawner.printMetrics();
    messageBus.printMetrics();

    // Shutdown
    distributor.shutdown();
    await spawner.shutdown();
    messageBus.shutdown();
  }

  test().catch(console.error);
}
