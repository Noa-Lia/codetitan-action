const EventEmitter = require('events');

function callLogger(logger, level, message) {
  if (!logger) return;
  if (typeof logger[level] === 'function') {
    logger[level](message);
  } else if (typeof logger.log === 'function') {
    logger.log(message);
  }
}

class AgentSDK extends EventEmitter {
  constructor({
    agentId = null,
    agentName,
    registryManager,
    messageBus = null,
    logger = console,
    heartbeatInterval = 30000
  } = {}) {
    super();

    if (!registryManager) {
      throw new Error('AgentSDK requires a registryManager instance');
    }

    this.agentId = agentId;
    this.agentName = agentName;
    this.registry = registryManager;
    this.messageBus = messageBus;
    this.logger = logger;
    this.heartbeatInterval = heartbeatInterval;

    this.metrics = {
      tasksAttempted: 0,
      tasksSucceeded: 0,
      tasksFailed: 0,
      totalExecutionTime: 0,
      heartbeatsSent: 0
    };

    this.sessionStartedAt = null;
    this.currentTask = null;
    this._heartbeatTimer = null;
    this._sessionActive = false;
  }

  getRegistryIdentifier() {
    return this.agentId || this.agentName || null;
  }

  ensureAgentIdentifier() {
    if (this.agentId) {
      return this.agentId;
    }

    if (this.agentName) {
      const record = this.registry.getAgentByName(this.agentName);
      if (record) {
        this.agentId = record.id;
        return this.agentId;
      }
    }

    return this.agentName || null;
  }

  updateMessageBusReport() {
    if (!this.messageBus || typeof this.messageBus.updateAgentSdkReport !== 'function') {
      return;
    }
    const identifier = this.getRegistryIdentifier();
    if (!identifier) {
      return;
    }
    try {
      this.messageBus.updateAgentSdkReport(identifier, this.report());
    } catch (error) {
      callLogger(this.logger, 'warn', `[AgentSDK] Failed to push telemetry report: ${error.message}`);
    }
  }

  startSession({ status = 'active' } = {}) {
    const identifier = this.ensureAgentIdentifier();
    if (identifier) {
      this.registry.updateAgentStatus(identifier, status);
    } else {
      callLogger(this.logger, 'warn', '[AgentSDK] Unable to resolve agent identifier during startSession');
    }

    this.sessionStartedAt = Date.now();
    this._sessionActive = true;
    this.emit('session:start', { identifier, status, timestamp: this.sessionStartedAt });
    this.setupHeartbeat();
    this.updateMessageBusReport();
    return identifier;
  }

  setupHeartbeat() {
    if (!this.heartbeatInterval || this.heartbeatInterval <= 0) {
      return;
    }

    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
    }

    this._heartbeatTimer = setInterval(() => {
      try {
        this.heartbeat();
      } catch (error) {
        callLogger(this.logger, 'warn', `[AgentSDK] Heartbeat error: ${error.message}`);
      }
    }, this.heartbeatInterval);

    if (typeof this._heartbeatTimer.unref === 'function') {
      this._heartbeatTimer.unref();
    }
  }

  heartbeat(status) {
    const identifier = this.ensureAgentIdentifier();
    if (!identifier) {
      return;
    }

    this.registry.touchAgent(identifier, status);
    this.metrics.heartbeatsSent += 1;
    this.emit('heartbeat', { identifier, status, timestamp: Date.now() });
  }

  leaseTask(taskId, metadata = {}) {
    const identifier = this.ensureAgentIdentifier();
    const effectiveTaskId = taskId || `${identifier || 'agent'}-${Date.now()}`;

    if (identifier) {
      const assigned = this.registry.assignTask(identifier, effectiveTaskId);
      if (!assigned) {
        callLogger(this.logger, 'warn', `[AgentSDK] Failed to assign task ${effectiveTaskId} for ${identifier}`);
      }
    }

    this.currentTask = {
      id: effectiveTaskId,
      metadata,
      startedAt: Date.now()
    };

    this.metrics.tasksAttempted += 1;
    this.emit('task:start', { taskId: effectiveTaskId, metadata });
    this.heartbeat('busy');
    return this.currentTask;
  }

  completeTask({
    taskId,
    success = true,
    executionTime,
    resultSummary = null,
    qualityScore = success ? 1 : 0,
    error = null,
    statusOnComplete = success ? 'idle' : 'active'
  } = {}) {
    const activeTask = this.currentTask;
    const resolvedTaskId = taskId || (activeTask ? activeTask.id : null);
    const startedAt = activeTask ? activeTask.startedAt : Date.now();
    const duration = executionTime != null ? executionTime : Math.max(0, Date.now() - startedAt);
    const identifier = this.ensureAgentIdentifier();

    if (identifier && resolvedTaskId) {
      const completed = this.registry.completeTask(
        identifier,
        resolvedTaskId,
        success,
        `${Math.max(0, Math.round(duration))}ms`,
        qualityScore,
        {
          action: activeTask?.metadata?.action,
          resultSummary,
          error,
          executionTime: duration
        }
      );

      if (!completed) {
        this.registry.recordExecution(identifier, {
          success,
          executionTime: duration,
          taskAction: activeTask?.metadata?.action,
          resultSummary,
          error
        });
      }
    } else if (!identifier) {
      callLogger(this.logger, 'warn', '[AgentSDK] Unable to resolve agent identifier during completeTask');
    }

    if (success) {
      this.metrics.tasksSucceeded += 1;
    } else {
      this.metrics.tasksFailed += 1;
    }
    this.metrics.totalExecutionTime += duration;

    this.currentTask = null;
    this.emit('task:complete', {
      taskId: resolvedTaskId,
      success,
      duration,
      resultSummary,
      error
    });
    this.heartbeat(statusOnComplete);
    this.updateMessageBusReport();

    return duration;
  }

  stop({ status = 'idle', reason } = {}) {
    const identifier = this.ensureAgentIdentifier();
    if (identifier) {
      this.registry.updateAgentStatus(identifier, status);
    }
    this._sessionActive = false;
    this.emit('session:stop', { identifier, status, reason, timestamp: Date.now() });
    this.clearHeartbeat();
    this.updateMessageBusReport();
  }

  clearHeartbeat() {
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
  }

  close() {
    this.clearHeartbeat();
    this.updateMessageBusReport();
  }

  report() {
    const { tasksAttempted, tasksSucceeded, tasksFailed, totalExecutionTime, heartbeatsSent } = this.metrics;
    const successRate = tasksAttempted === 0 ? 1 : tasksSucceeded / tasksAttempted;
    const averageExecutionTime = tasksSucceeded === 0 ? 0 : totalExecutionTime / Math.max(tasksSucceeded, 1);

    return {
      identifier: this.getRegistryIdentifier(),
      tasksAttempted,
      tasksSucceeded,
      tasksFailed,
      successRate,
      averageExecutionTime,
      heartbeatsSent,
      sessionStartedAt: this.sessionStartedAt
    };
  }
}

module.exports = AgentSDK;
