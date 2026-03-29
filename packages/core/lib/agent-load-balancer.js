/**
 * Agent Load Balancer
 *
 * Manages agent load, detects failures, and handles retries.
 * Ensures system stability when running 50+ agents in parallel.
 *
 * Phase 3 Component 3
 */

class AgentLoadBalancer {
  constructor(options = {}) {
    // Configuration
    this.maxAgentsPerDomain = options.maxAgentsPerDomain || 10;
    this.maxConcurrent = options.maxConcurrent || 50;
    this.retryLimit = options.retryLimit || 3;
    this.timeoutMs = options.timeoutMs || 120000; // 2 minutes default

    // State tracking
    this.agentLoad = new Map();
    this.domainLoad = new Map();
    this.activeAgents = new Set();
    this.failedAgents = new Map();
    this.completedAgents = new Set();

    // Metrics
    this.metrics = {
      totalTasks: 0,
      successfulTasks: 0,
      failedTasks: 0,
      retriedTasks: 0,
      totalRetries: 0,
      timeouts: 0,
      averageExecutionTime: 0
    };

    // Execution times for averaging
    this.executionTimes = [];
  }

  /**
   * Balance load across domains
   * Ensures no domain gets overloaded
   */
  async balanceLoad(tasks) {
    console.log(`\n⚖️  Balancing ${tasks.length} tasks across domains...`);

    const balanced = [];
    const domainCounts = new Map();

    for (const task of tasks) {
      const domain = task.god;
      const currentCount = domainCounts.get(domain) || 0;

      // Track which wave this task should be in
      const wave = Math.floor(currentCount / this.maxAgentsPerDomain);

      balanced.push({
        ...task,
        wave,
        assignedDomain: domain,
        agentId: this.generateAgentId(domain, currentCount)
      });

      domainCounts.set(domain, currentCount + 1);
      this.domainLoad.set(domain, currentCount + 1);
    }

    this.metrics.totalTasks = tasks.length;

    console.log(`   Distributed across ${domainCounts.size} domains`);
    domainCounts.forEach((count, domain) => {
      console.log(`   - ${domain}: ${count} tasks`);
    });

    return balanced;
  }

  /**
   * Monitor agent execution with timeout and retry
   */
  async monitorAgent(agentId, taskPromise) {
    const startTime = Date.now();
    this.activeAgents.add(agentId);
    this.agentLoad.set(agentId, { startTime, retries: 0, status: 'running' });
    const timeoutPromise = this.createTimeout(this.timeoutMs, agentId);

    try {
      // Race between task completion and timeout
      const result = await Promise.race([
        taskPromise,
        timeoutPromise
      ]);
      timeoutPromise.cancel?.();

      // Success
      const duration = Date.now() - startTime;
      this.recordSuccess(agentId, duration);

      return result;

    } catch (error) {
      timeoutPromise.cancel?.();
      // Failure
      const duration = Date.now() - startTime;
      return await this.handleFailure(agentId, error, duration);
    }
  }

  /**
   * Create timeout promise
   */
  createTimeout(ms, agentId) {
    let timeoutHandle;
    const promise = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        this.metrics.timeouts++;
        reject(new Error(`Agent ${agentId} timed out after ${ms}ms`));
      }, ms);
      timeoutHandle.unref?.();
    });
    promise.cancel = () => clearTimeout(timeoutHandle);
    return promise;
  }

  /**
   * Record successful execution
   */
  recordSuccess(agentId, duration) {
    this.activeAgents.delete(agentId);
    this.completedAgents.add(agentId);

    const agentData = this.agentLoad.get(agentId);
    if (agentData) {
      agentData.status = 'completed';
      agentData.duration = duration;
    }

    this.executionTimes.push(duration);
    this.metrics.successfulTasks++;

    // Update average execution time
    this.metrics.averageExecutionTime =
      this.executionTimes.reduce((sum, t) => sum + t, 0) / this.executionTimes.length;
  }

  /**
   * Handle agent failure with retry logic
   */
  async handleFailure(agentId, error, duration) {
    console.error(`[ERROR] Agent ${agentId} failed after ${duration}ms: ${error.message}`);

    this.activeAgents.delete(agentId);

    const agentData = this.agentLoad.get(agentId) || { retries: 0 };
    const currentRetries = agentData.retries || 0;

    // Check if we should retry
    if (currentRetries < this.retryLimit) {
      // Retry with exponential backoff
      const backoffMs = 1000 * Math.pow(2, currentRetries); // 1s, 2s, 4s, 8s...
      console.log(`🔄 Retrying agent ${agentId} in ${backoffMs}ms (attempt ${currentRetries + 1}/${this.retryLimit})`);

      await this.delay(backoffMs);

      // Update retry count
      agentData.retries = currentRetries + 1;
      agentData.status = 'retrying';
      this.agentLoad.set(agentId, agentData);

      this.metrics.retriedTasks++;
      this.metrics.totalRetries++;

      return { retry: true, agentId, error: error.message };

    } else {
      // Max retries exceeded - mark as failed
      console.error(`💀 Agent ${agentId} failed permanently after ${this.retryLimit} retries`);

      agentData.status = 'failed';
      agentData.error = error.message;
      this.agentLoad.set(agentId, agentData);

      this.failedAgents.set(agentId, {
        error: error.message,
        retries: currentRetries,
        duration
      });

      this.metrics.failedTasks++;

      return {
        failed: true,
        agentId,
        error: error.message,
        retries: currentRetries
      };
    }
  }

  /**
   * Delay helper for exponential backoff
   */
  delay(ms) {
    return new Promise(resolve => {
      const timeoutHandle = setTimeout(resolve, ms);
      timeoutHandle.unref?.();
    });
  }

  /**
   * Generate unique agent ID
   */
  generateAgentId(domain, index) {
    return `${domain}-agent-${index}-${Date.now()}`;
  }

  /**
   * Get current load for a domain
   */
  getDomainLoad(domain) {
    return this.domainLoad.get(domain) || 0;
  }

  /**
   * Get active agent count
   */
  getActiveAgentCount() {
    return this.activeAgents.size;
  }

  /**
   * Check if system is at capacity
   */
  isAtCapacity() {
    return this.activeAgents.size >= this.maxConcurrent;
  }

  /**
   * Get load balancer metrics
   */
  getMetrics() {
    const totalProcessed = this.metrics.successfulTasks + this.metrics.failedTasks;
    const successRate = totalProcessed > 0
      ? (this.metrics.successfulTasks / totalProcessed * 100).toFixed(1)
      : 0;

    return {
      ...this.metrics,
      activeAgents: this.activeAgents.size,
      completedAgents: this.completedAgents.size,
      failedAgentsCount: this.failedAgents.size,
      successRate: `${successRate}%`,
      averageExecutionTimeMs: Math.round(this.metrics.averageExecutionTime),
      totalProcessed
    };
  }

  /**
   * Get detailed status report
   */
  getStatusReport() {
    const metrics = this.getMetrics();

    return {
      summary: {
        total: metrics.totalTasks,
        active: metrics.activeAgents,
        completed: metrics.completedAgents,
        failed: metrics.failedAgentsCount,
        successRate: metrics.successRate
      },
      performance: {
        averageExecutionTime: `${metrics.averageExecutionTimeMs}ms`,
        timeouts: metrics.timeouts,
        retries: metrics.totalRetries
      },
      capacity: {
        current: metrics.activeAgents,
        max: this.maxConcurrent,
        utilization: `${((metrics.activeAgents / this.maxConcurrent) * 100).toFixed(1)}%`,
        atCapacity: this.isAtCapacity()
      },
      domainLoad: Object.fromEntries(this.domainLoad)
    };
  }

  /**
   * Reset metrics (for testing)
   */
  reset() {
    this.agentLoad.clear();
    this.domainLoad.clear();
    this.activeAgents.clear();
    this.failedAgents.clear();
    this.completedAgents.clear();
    this.executionTimes = [];

    this.metrics = {
      totalTasks: 0,
      successfulTasks: 0,
      failedTasks: 0,
      retriedTasks: 0,
      totalRetries: 0,
      timeouts: 0,
      averageExecutionTime: 0
    };
  }

  /**
   * Get failed agents for debugging
   */
  getFailedAgents() {
    return Array.from(this.failedAgents.entries()).map(([agentId, data]) => ({
      agentId,
      ...data
    }));
  }

  /**
   * Display load balancer status (for console output)
   */
  displayStatus() {
    const status = this.getStatusReport();

    console.log('\n+===========================================================+');
    console.log('|              LOAD BALANCER STATUS                        |');
    console.log('+===========================================================+\n');

    console.log('[CHART] Summary:');
    console.log(`   Total Tasks: ${status.summary.total}`);
    console.log(`   Active: ${status.summary.active}`);
    console.log(`   Completed: ${status.summary.completed}`);
    console.log(`   Failed: ${status.summary.failed}`);
    console.log(`   Success Rate: ${status.summary.successRate}\n`);

    console.log('[BOLT] Performance:');
    console.log(`   Avg Execution Time: ${status.performance.averageExecutionTime}`);
    console.log(`   Timeouts: ${status.performance.timeouts}`);
    console.log(`   Total Retries: ${status.performance.retries}\n`);

    console.log('[TARGET] Capacity:');
    console.log(`   Current: ${status.capacity.current}/${status.capacity.max}`);
    console.log(`   Utilization: ${status.capacity.utilization}`);
    console.log(`   At Capacity: ${status.capacity.atCapacity ? 'Yes [WARNING]' : 'No [OK]'}\n`);

    if (Object.keys(status.domainLoad).length > 0) {
      console.log('[TRENDING] Domain Load:');
      Object.entries(status.domainLoad).forEach(([domain, load]) => {
        console.log(`   ${domain}: ${load} tasks`);
      });
      console.log();
    }
  }
}

module.exports = AgentLoadBalancer;
