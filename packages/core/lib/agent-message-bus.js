/**
 * Agent Message Bus - Event-Driven Communication System
 *
 * The nervous system of the GOD LEVEL Agent System.
 * Enables all agents to communicate via:
 * - Request-Response (1-to-1)
 * - Pub-Sub (1-to-many)
 * - Broadcast (1-to-all)
 * - Direct messaging
 *
 * Features:
 * - Message persistence
 * - Message routing
 * - Dead letter queue
 * - Message replay
 * - Performance metrics
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DELEGATION_CONTRACT = 'codetitan.agent-runtime.delegation';
const DELEGATION_VERSION = '1.0';
const DELEGATION_SECTION_KEYS = {
  taskRequest: 'task_request',
  evidencePackage: 'evidence_package',
  resultSummary: 'result_summary',
  followUpRequest: 'follow_up_request'
};

function ensureArray(value) {
  if (!value) {
    return [];
  }

  return Array.isArray(value) ? value.filter(Boolean) : [value].filter(Boolean);
}

function cloneObject(value, fallback = {}) {
  if (!value || typeof value !== 'object') {
    return { ...fallback };
  }

  return { ...value };
}

function resolveReviewArtifactPath(payload = {}, runtimeState = {}) {
  return payload?.review_artifact?.path ||
    runtimeState?.reviewArtifact?.path ||
    runtimeState?.review_artifact_path ||
    null;
}

function resolveFixSession(payload = {}, runtimeState = {}) {
  const fixSession = payload?.fix_session || runtimeState?.fixSession || {};

  const id = fixSession?.id || runtimeState?.fix_session_id || null;
  const sessionPath = fixSession?.path || runtimeState?.fix_session_path || null;

  if (!id && !sessionPath) {
    return null;
  }

  return {
    id,
    path: sessionPath
  };
}

class AgentMessageBus extends EventEmitter {
  constructor(options = {}) {
    super();
    this.setMaxListeners(0);

    this.options = {
      persistMessages: options.persistMessages ?? true,
      messageRetention: options.messageRetention ?? 7 * 24 * 60 * 60 * 1000, // 7 days
      maxQueueSize: options.maxQueueSize ?? 10000,
      deadLetterQueueEnabled: options.deadLetterQueueEnabled ?? true,
      metricsEnabled: options.metricsEnabled ?? true,
      ...options
    };

    // Message storage
    this.messages = new Map(); // message_id -> message
    this.messageLog = []; // Ordered list of all messages
    this.deadLetterQueue = []; // Failed messages

    // Subscriptions
    this.subscriptions = new Map(); // topic -> Set of agent_ids
    this.agentCallbacks = new Map(); // agent_id -> Map(topic -> callback)
    this.agentIntegrations = new Map(); // agent_id -> integration metadata
    this.agentSdkReports = new Map();
    this.retryTimers = new Set();
    this.persistencePath = path.join(__dirname, '..', 'data', 'message-bus');
    this.metricsPath = path.join(this.persistencePath, 'agent-metrics.json');

    // Request-Response tracking
    this.pendingRequests = new Map(); // correlation_id -> {resolve, reject, timeout}

    // Metrics
    this.metrics = {
      messagesSent: 0,
      messagesReceived: 0,
      messagesProcessed: 0,
      messagesFailed: 0,
      averageLatency: 0,
      totalLatency: 0,
      requestsInFlight: 0
    };

    // Persistence
    this.ensurePersistencePath();
    this.loadPersistedSdkReports();
    if (this.options.persistMessages) {
      this.loadPersistedMessages();
    }

    // Cleanup old messages periodically
    this.cleanupInterval = setInterval(() => this.cleanup(), 60 * 60 * 1000); // Every hour
    this.cleanupInterval.unref?.();
  }

  /**
   * Ensure persistence directory exists
   */
  ensurePersistencePath() {
    fs.promises.mkdir(this.persistencePath, { recursive: true }).catch(() => {});
  }

  /**
   * Load persisted messages from disk
   */
  loadPersistedMessages() {
    const messagesFile = path.join(this.persistencePath, 'messages.jsonl');
    fs.promises.stat(messagesFile)
      .then(stat => stat.isFile())
      .then(async exists => {
        if (!exists) return;
        const raw = await fs.promises.readFile(messagesFile, 'utf8');
        const lines = raw.split('\n').filter(Boolean);
        lines.forEach(line => {
          try {
            const message = JSON.parse(line);
            this.messages.set(message.message_id, message);
            this.messageLog.push(message);
          } catch (err) {
            console.error('Failed to parse message:', err.message);
          }
        });
        console.log(`[MessageBus] Loaded ${this.messages.size} persisted messages`);
      })
      .catch(() => {});
  }

  loadPersistedSdkReports() {
    fs.promises.readFile(this.metricsPath, 'utf8')
      .then(raw => JSON.parse(raw))
      .then(data => {
        Object.entries(data || {}).forEach(([agentId, report]) => {
          this.agentSdkReports.set(agentId, report);
        });
      })
      .catch(() => {});
  }

  persistSdkReports() {
    try {
      this.ensurePersistencePath();
      const serialized = {};
      for (const [agentId, report] of this.agentSdkReports.entries()) {
        serialized[agentId] = report;
      }
      fs.promises.writeFile(this.metricsPath, JSON.stringify(serialized, null, 2), 'utf8').catch(() => {});
    } catch (error) {
      console.error('[MessageBus] Failed to persist SDK reports:', error.message);
    }
  }

  /**
   * Persist message to disk
   */
  persistMessage(message) {
    if (!this.options.persistMessages) return;

    try {
      const messagesFile = path.join(this.persistencePath, 'messages.jsonl');
      fs.promises.appendFile(messagesFile, JSON.stringify(message) + '\n', 'utf8').catch(() => {});
    } catch (error) {
      console.error('[MessageBus] Failed to persist message:', error.message);
    }
  }

  /**
   * Generate unique message ID
   */
  generateMessageId() {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Create a message object
   */
  createMessage(from, to, type, content, metadata = {}) {
    const messageId = this.generateMessageId();
    const message = {
      message_id: messageId,
      id: messageId,
      timestamp: new Date().toISOString(),
      from,
      to,
      type,
      content,
      metadata: {
        correlation_id: metadata.correlation_id || this.generateMessageId(),
        session_id: metadata.session_id || null,
        parent_message_id: metadata.parent_message_id || null,
        priority: metadata.priority || 'medium',
        ttl: metadata.ttl || 300000, // 5 minutes default
        retry_count: metadata.retry_count || 0,
        max_retries: metadata.max_retries || 3,
        ...metadata
      },
      status: 'pending',
      sent_at: null,
      received_at: null,
      processed_at: null,
      error: null
    };

    return message;
  }

  /**
   * Send a message
   */
  async send(from, to, type, content, metadata = {}) {
    const message = this.createMessage(from, to, type, content, metadata);

    // Store message
    this.messages.set(message.message_id, message);
    this.messageLog.push(message);

    // Check queue size
    if (this.messageLog.length > this.options.maxQueueSize) {
      this.messageLog.shift(); // Remove oldest message
    }

    // Persist message
    this.persistMessage(message);

    // Update metrics
    this.metrics.messagesSent++;

    // Mark as sent
    message.sent_at = new Date().toISOString();
    message.status = 'sent';

    // Route message
    try {
      await this.routeMessage(message);
      message.status = 'delivered';
      this.metrics.messagesProcessed++;
    } catch (error) {
      message.status = 'failed';
      message.error = error.message;
      this.metrics.messagesFailed++;

      // Add to dead letter queue
      if (this.options.deadLetterQueueEnabled) {
        this.deadLetterQueue.push(message);
      }

      // Retry if configured
      if (message.metadata.retry_count < message.metadata.max_retries) {
        message.metadata.retry_count++;
        const retryHandle = setTimeout(() => {
          this.retryTimers.delete(retryHandle);
          this.send(from, to, type, content, metadata).catch(() => {});
        }, 1000 * message.metadata.retry_count);
        retryHandle.unref?.();
        this.retryTimers.add(retryHandle);
      }

      throw error;
    }

    return message;
  }

  /**
   * Route message to recipient(s)
   */
  async routeMessage(message) {
    const startTime = Date.now();

    switch (message.type) {
      case 'request':
        await this.handleRequest(message);
        break;

      case 'response':
        await this.handleResponse(message);
        break;

      case 'notification':
        await this.handleNotification(message);
        break;

      case 'broadcast':
        await this.handleBroadcast(message);
        break;

      default:
        throw new Error(`Unknown message type: ${message.type}`);
    }

    // Update latency metrics
    const latency = Date.now() - startTime;
    this.metrics.totalLatency += latency;
    this.metrics.averageLatency = this.metrics.totalLatency / this.metrics.messagesProcessed;
  }

  /**
   * Handle request message (1-to-1 with expected response)
   */
  async handleRequest(message) {
    message.received_at = new Date().toISOString();
    this.metrics.messagesReceived++;

    const integration = this.getAgentIntegration(message.to);
    if (integration?.sdk && typeof integration.sdk.heartbeat === 'function') {
      integration.sdk.heartbeat('active');
    }

    // Emit event for the recipient agent
    this.emit(`message:${message.to}`, message);

    // Also emit general message event
    this.emit('message', message);
  }

  /**
   * Handle response message
   */
  async handleResponse(message) {
    message.received_at = new Date().toISOString();
    this.metrics.messagesReceived++;

    const correlationId = message.metadata.correlation_id;
    const pendingRequest = this.pendingRequests.get(correlationId);

    if (pendingRequest) {
      // Clear timeout
      clearTimeout(pendingRequest.timeout);

      // Resolve promise
      pendingRequest.resolve(message);

      // Clean up
      this.pendingRequests.delete(correlationId);
      this.metrics.requestsInFlight--;
    } else {
      console.warn(`[MessageBus] Received response for unknown request: ${correlationId}`);
    }
  }

  /**
   * Handle notification message (1-to-many via pub-sub)
   */
  async handleNotification(message) {
    message.received_at = new Date().toISOString();
    this.metrics.messagesReceived++;

    const topic = message.to; // 'to' field is the topic for notifications
    const subscribers = this.subscriptions.get(topic);

    if (subscribers && subscribers.size > 0) {
      // Emit to all subscribers
      for (const agentId of subscribers) {
        const integration = this.getAgentIntegration(agentId);
        if (integration?.sdk && typeof integration.sdk.heartbeat === 'function') {
          integration.sdk.heartbeat('active');
        }
        this.emit(`message:${agentId}`, message);

        // Also call registered callback if exists
        const agentCallbacks = this.agentCallbacks.get(agentId);
        if (agentCallbacks) {
          const callback = agentCallbacks.get(topic);
          if (callback) {
            try {
              await callback(message);
            } catch (error) {
              console.error(`[MessageBus] Callback error for ${agentId}:`, error.message);
            }
          }
        }
      }
    }

    // Also emit general notification event
    this.emit(`notification:${topic}`, message);
  }

  /**
   * Handle broadcast message (1-to-all)
   */
  async handleBroadcast(message) {
    message.received_at = new Date().toISOString();
    this.metrics.messagesReceived++;

    // Emit to all registered agents
    for (const agentId of this.agentCallbacks.keys()) {
      const integration = this.getAgentIntegration(agentId);
      if (integration?.sdk && typeof integration.sdk.heartbeat === 'function') {
        integration.sdk.heartbeat('active');
      }
      this.emit(`message:${agentId}`, message);
    }

    // Also emit general broadcast event
    this.emit('broadcast', message);
  }

  createTaskRequestContract({
    from = null,
    to = null,
    taskId = null,
    action = 'execute_task',
    task = {},
    metadata = {},
    summary = null,
    requestedRole = null,
    priority = 'medium'
  } = {}) {
    const target = task?.file || task?.path || task?.directory || task?.basePath || null;

    return {
      kind: DELEGATION_SECTION_KEYS.taskRequest,
      taskId,
      action,
      summary: summary || task?.description || metadata?.description || `Delegated ${action}`,
      requestedRole: requestedRole || metadata?.role || null,
      requestedBy: from,
      assignedTo: to,
      priority,
      target,
      requestedAt: new Date().toISOString()
    };
  }

  createEvidencePackage({
    taskId = null,
    result = {}
  } = {}) {
    const payload = result?.result || result || {};
    const runtimeState = cloneObject(payload.runtime_state);
    const reviewArtifactPath = resolveReviewArtifactPath(payload, runtimeState);
    const fixSession = resolveFixSession(payload, runtimeState);
    const evidence = Array.isArray(payload.evidence) ? payload.evidence : [];
    const toolTrace = Array.isArray(payload.toolTrace) ? payload.toolTrace : [];
    const artifacts = Array.isArray(payload.artifacts) ? payload.artifacts : [];

    return {
      kind: DELEGATION_SECTION_KEYS.evidencePackage,
      taskId,
      evidenceCount: evidence.length,
      evidenceSummary: payload.evidenceSummary || 'No evidence recorded.',
      evidence,
      toolTrace,
      artifacts,
      runtimeState,
      providerUsage: runtimeState?.providerUsage || null,
      reviewArtifact: reviewArtifactPath ? { path: reviewArtifactPath } : null,
      fixSession
    };
  }

  createResultSummaryContract({
    taskId = null,
    result = {},
    completedBy = null
  } = {}) {
    const payload = result?.result || result || {};
    const runtimeState = cloneObject(payload.runtime_state);
    const reviewArtifactPath = resolveReviewArtifactPath(payload, runtimeState);
    const fixSession = resolveFixSession(payload, runtimeState);
    const success = result?.success !== false && payload?.success !== false;
    const status = payload.status || (success ? 'completed' : 'failed');
    const summary = payload.summary || payload.message || result?.message || result?.error || 'Delegated task completed';

    return {
      kind: DELEGATION_SECTION_KEYS.resultSummary,
      taskId,
      success,
      status,
      summary,
      message: payload.message || result?.message || summary,
      quality: typeof result?.quality === 'number'
        ? result.quality
        : (typeof payload?.quality === 'number' ? payload.quality : (success ? 1 : 0)),
      completedBy,
      reasoningMode: runtimeState.reasoningMode || 'standard',
      providerUsage: runtimeState.providerUsage || null,
      verificationStatus: runtimeState.verificationStatus || (success ? 'verified' : 'failed'),
      reviewArtifactPath,
      fixSessionId: fixSession?.id || null,
      fixSessionPath: fixSession?.path || null
    };
  }

  createFollowUpRequestContract({
    taskId = null,
    reason = 'additional_context_required',
    requestedInputs = [],
    action = 'provide_context',
    required = true,
    summary = null
  } = {}) {
    return {
      kind: DELEGATION_SECTION_KEYS.followUpRequest,
      taskId,
      action,
      reason,
      required,
      requestedInputs: ensureArray(requestedInputs),
      summary: summary || 'Provide additional context so the delegated task can continue.'
    };
  }

  createDelegationEnvelope({
    taskRequest = null,
    evidencePackage = null,
    resultSummary = null,
    followUpRequest = null
  } = {}) {
    const envelope = {
      contract: DELEGATION_CONTRACT,
      version: DELEGATION_VERSION
    };
    const sections = [];

    if (taskRequest) {
      envelope.taskRequest = taskRequest;
      sections.push(DELEGATION_SECTION_KEYS.taskRequest);
    }

    if (evidencePackage) {
      envelope.evidencePackage = evidencePackage;
      sections.push(DELEGATION_SECTION_KEYS.evidencePackage);
    }

    if (resultSummary) {
      envelope.resultSummary = resultSummary;
      sections.push(DELEGATION_SECTION_KEYS.resultSummary);
    }

    if (followUpRequest) {
      envelope.followUpRequest = followUpRequest;
      sections.push(DELEGATION_SECTION_KEYS.followUpRequest);
    }

    envelope.sections = sections;
    return envelope;
  }

  createDelegationMetadata(envelope = {}, metadata = {}) {
    const taskId =
      envelope?.taskRequest?.taskId ||
      envelope?.resultSummary?.taskId ||
      envelope?.evidencePackage?.taskId ||
      envelope?.followUpRequest?.taskId ||
      null;

    return {
      ...metadata,
      delegation_contract: DELEGATION_CONTRACT,
      delegation_version: DELEGATION_VERSION,
      delegation_sections: Array.isArray(envelope.sections) ? envelope.sections : [],
      delegated_task_id: taskId,
      delegation_status: envelope?.resultSummary?.status || null,
      follow_up_required: Boolean(envelope?.followUpRequest),
      review_artifact_path:
        envelope?.resultSummary?.reviewArtifactPath ||
        envelope?.evidencePackage?.reviewArtifact?.path ||
        null,
      fix_session_id:
        envelope?.resultSummary?.fixSessionId ||
        envelope?.evidencePackage?.fixSession?.id ||
        null,
      fix_session_path:
        envelope?.resultSummary?.fixSessionPath ||
        envelope?.evidencePackage?.fixSession?.path ||
        null
    };
  }

  getDelegationEnvelope(messageOrContent) {
    const content = messageOrContent?.content && typeof messageOrContent.content === 'object'
      ? messageOrContent.content
      : messageOrContent;
    const delegation = content?.delegation;

    if (!delegation || delegation.contract !== DELEGATION_CONTRACT) {
      return null;
    }

    return delegation;
  }

  buildFollowUpRequest(originalMessage, result) {
    const delegation = this.getDelegationEnvelope(originalMessage);
    const taskId = delegation?.taskRequest?.taskId || originalMessage?.content?.task_id || originalMessage?.message_id || null;
    const content = originalMessage?.content || {};
    const target = content?.task?.file || content?.task?.path || content?.task?.directory || content?.task?.basePath || content?.file || content?.path || null;

    if (target) {
      return null;
    }

    const failureMessage =
      result?.error ||
      result?.result?.error ||
      result?.result?.message ||
      result?.message ||
      '';
    const normalizedFailure = failureMessage.toLowerCase();

    if (!normalizedFailure) {
      return null;
    }

    const needsContext =
      normalizedFailure.includes('target') ||
      normalizedFailure.includes('file') ||
      normalizedFailure.includes('directory') ||
      normalizedFailure.includes('evidence');

    if (!needsContext) {
      return null;
    }

    return this.createFollowUpRequestContract({
      taskId,
      reason: 'additional_context_required',
      requestedInputs: ['file', 'directory', 'errors'],
      summary: 'Provide a concrete file or directory target so the delegated task can gather evidence.'
    });
  }

  /**
   * Send request and wait for response
   */
  async request(from, to, content, metadata = {}, timeout = 30000) {
    const correlationId = this.generateMessageId();

    // Create promise for response
    const responsePromise = new Promise((resolve, reject) => {
      // Set timeout
      const timeoutHandle = setTimeout(() => {
        const pendingRequest = this.pendingRequests.get(correlationId);
        if (!pendingRequest) {
          return;
        }
        this.pendingRequests.delete(correlationId);
        this.metrics.requestsInFlight = Math.max(0, this.metrics.requestsInFlight - 1);
        pendingRequest.reject(new Error(`Request timeout after ${timeout}ms`));
      }, timeout);
      timeoutHandle.unref?.();

      // Store pending request
      this.pendingRequests.set(correlationId, {
        resolve,
        reject,
        timeout: timeoutHandle
      });
    });

    this.metrics.requestsInFlight++;

    // Send request
    await this.send(from, to, 'request', content, {
      ...metadata,
      correlation_id: correlationId
    });

    // Wait for response
    return responsePromise;
  }

  async delegateTask(from, to, payload = {}, metadata = {}, timeout = 30000) {
    const taskId = payload.taskId || payload.task_id || this.generateMessageId();
    const action = payload.action || 'execute_task';
    const task = payload.task || payload.content || {};
    const taskMetadata = cloneObject(payload.metadata);
    const taskRequest = this.createTaskRequestContract({
      from,
      to,
      taskId,
      action,
      task,
      metadata: taskMetadata,
      summary: payload.summary,
      requestedRole: payload.requestedRole,
      priority: metadata.priority || payload.priority || taskMetadata.priority || 'medium'
    });
    const delegation = this.createDelegationEnvelope({ taskRequest });

    return this.request(
      from,
      to,
      {
        action,
        task_id: taskId,
        task,
        metadata: taskMetadata,
        delegation
      },
      this.createDelegationMetadata(delegation, metadata),
      timeout
    );
  }

  async sendFollowUpRequest(from, to, payload = {}, metadata = {}, timeout = 30000) {
    const taskId = payload.taskId || payload.task_id || null;
    const followUpRequest = this.createFollowUpRequestContract({
      taskId,
      reason: payload.reason,
      requestedInputs: payload.requestedInputs,
      action: payload.action,
      required: payload.required,
      summary: payload.summary
    });
    const delegation = this.createDelegationEnvelope({ followUpRequest });

    return this.request(
      from,
      to,
      {
        action: payload.action || 'provide_context',
        task_id: taskId,
        task: payload.task || {},
        metadata: cloneObject(payload.metadata),
        delegation
      },
      this.createDelegationMetadata(delegation, metadata),
      timeout
    );
  }

  /**
   * Send response to a request
   */
  async respond(originalMessage, from, content, metadata = {}) {
    return this.send(from, originalMessage.from, 'response', content, {
      ...metadata,
      correlation_id: originalMessage.metadata.correlation_id,
      parent_message_id: originalMessage.message_id,
      inReplyTo: originalMessage.message_id || originalMessage.id || null
    });
  }

  async respondToDelegatedTask(originalMessage, from, result = {}, metadata = {}) {
    const originalDelegation = this.getDelegationEnvelope(originalMessage);
    const taskId = originalDelegation?.taskRequest?.taskId || originalMessage?.content?.task_id || originalMessage?.message_id || null;
    const explicitFollowUp = Object.prototype.hasOwnProperty.call(metadata, 'followUpRequest')
      ? metadata.followUpRequest
      : undefined;
    const followUpRequest = explicitFollowUp === undefined
      ? this.buildFollowUpRequest(originalMessage, result)
      : explicitFollowUp;
    const delegation = this.createDelegationEnvelope({
      resultSummary: this.createResultSummaryContract({
        taskId,
        result,
        completedBy: from
      }),
      evidencePackage: this.createEvidencePackage({
        taskId,
        result
      }),
      followUpRequest: followUpRequest || null
    });
    const responseContent = {
      ...(result && typeof result === 'object' ? result : { value: result }),
      delegation
    };
    const {
      followUpRequest: _ignoredFollowUpRequest,
      ...responseMetadata
    } = metadata || {};

    return this.respond(
      originalMessage,
      from,
      responseContent,
      this.createDelegationMetadata(delegation, responseMetadata)
    );
  }

  /**
   * Subscribe to a topic
   */
  subscribe(agentId, topic, callback = null) {
    // Add to subscriptions
    if (!this.subscriptions.has(topic)) {
      this.subscriptions.set(topic, new Set());
    }
    this.subscriptions.get(topic).add(agentId);

    // Store callback if provided
    if (callback) {
      if (!this.agentCallbacks.has(agentId)) {
        this.agentCallbacks.set(agentId, new Map());
      }
      this.agentCallbacks.get(agentId).set(topic, callback);
    }

    console.log(`[MessageBus] ${agentId} subscribed to topic: ${topic}`);
  }

  /**
   * Unsubscribe from a topic
   */
  unsubscribe(agentId, topic) {
    const subscribers = this.subscriptions.get(topic);
    if (subscribers) {
      subscribers.delete(agentId);
      if (subscribers.size === 0) {
        this.subscriptions.delete(topic);
      }
    }

    // Remove callback
    const agentCallbacks = this.agentCallbacks.get(agentId);
    if (agentCallbacks) {
      agentCallbacks.delete(topic);
      if (agentCallbacks.size === 0) {
        this.agentCallbacks.delete(agentId);
      }
    }

    console.log(`[MessageBus] ${agentId} unsubscribed from topic: ${topic}`);
  }

  /**
   * Publish to a topic
   */
  async publish(from, topic, content, metadata = {}) {
    return this.send(from, topic, 'notification', content, metadata);
  }

  /**
   * Broadcast to all agents
   */
  async broadcast(from, content, metadata = {}) {
    return this.send(from, '*', 'broadcast', content, metadata);
  }

  /**
   * Register agent to receive messages
   */
  registerAgent(agentId, messageHandler, options = {}) {
    this.on(`message:${agentId}`, messageHandler);

    if (!this.agentCallbacks.has(agentId)) {
      this.agentCallbacks.set(agentId, new Map());
    }

    this.agentIntegrations.set(agentId, { sdk: options.sdk || null });

    if (options.sdk) {
      this.updateAgentSdkReport(agentId, options.sdk.report());
    }

    console.log(`[MessageBus] Agent registered: ${agentId}`);
  }

  /**
   * Unregister agent
   */
  unregisterAgent(agentId) {
    this.removeAllListeners(`message:${agentId}`);
    this.agentCallbacks.delete(agentId);
    this.agentIntegrations.delete(agentId);

    // Remove from all subscriptions
    for (const [topic, subscribers] of this.subscriptions.entries()) {
      subscribers.delete(agentId);
      if (subscribers.size === 0) {
        this.subscriptions.delete(topic);
      }
    }

    console.log(`[MessageBus] Agent unregistered: ${agentId}`);
  }

  /**
   * Get message by ID
   */
  getMessage(messageId) {
    return this.messages.get(messageId);
  }

  /**
   * Get messages for an agent
   */
  getMessagesForAgent(agentId, limit = 100) {
    return this.messageLog
      .filter(msg => msg.to === agentId || msg.from === agentId)
      .slice(-limit);
  }

  /**
   * Get integration metadata for an agent.
   */
  getAgentIntegration(agentId) {
    return this.agentIntegrations.get(agentId) || null;
  }

  /**
   * Update stored AgentSDK report and persist to disk.
   */
  updateAgentSdkReport(agentId, report) {
    if (!agentId || !report) {
      return;
    }
    this.agentSdkReports.set(agentId, report);
    this.persistSdkReports();
  }

  /**
   * Get an AgentSDK telemetry report if registered.
   */
  getAgentSdkReport(agentId) {
    const integration = this.getAgentIntegration(agentId);
    if (integration?.sdk && typeof integration.sdk.report === 'function') {
      const report = integration.sdk.report();
      this.updateAgentSdkReport(agentId, report);
      return report;
    }
    return this.agentSdkReports.get(agentId) || null;
  }

  /**
   * Get message thread (conversation)
   */
  getMessageThread(correlationId) {
    return this.messageLog
      .filter(msg => msg.metadata.correlation_id === correlationId)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }

  /**
   * Get metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      totalMessages: this.messages.size,
      messageLogSize: this.messageLog.length,
      deadLetterQueueSize: this.deadLetterQueue.length,
      activeSubscriptions: this.subscriptions.size,
      registeredAgents: this.agentCallbacks.size,
      pendingRequests: this.pendingRequests.size
    };
  }

  /**
   * Print metrics dashboard
   */
  printMetrics() {
    const metrics = this.getMetrics();
    console.log('\n+- MESSAGE BUS METRICS --------------------------------------+');
    console.log(`| Messages Sent: ${metrics.messagesSent.toString().padEnd(48)} |`);
    console.log(`| Messages Received: ${metrics.messagesReceived.toString().padEnd(44)} |`);
    console.log(`| Messages Processed: ${metrics.messagesProcessed.toString().padEnd(43)} |`);
    console.log(`| Messages Failed: ${metrics.messagesFailed.toString().padEnd(46)} |`);
    console.log(`| Average Latency: ${metrics.averageLatency.toFixed(2)}ms${' '.repeat(40 - metrics.averageLatency.toFixed(2).length)} |`);
    console.log('|                                                            |');
    console.log(`| Total Messages in Memory: ${metrics.totalMessages.toString().padEnd(35)} |`);
    console.log(`| Message Log Size: ${metrics.messageLogSize.toString().padEnd(45)} |`);
    console.log(`| Dead Letter Queue: ${metrics.deadLetterQueueSize.toString().padEnd(44)} |`);
    console.log('|                                                            |');
    console.log(`| Active Subscriptions: ${metrics.activeSubscriptions.toString().padEnd(41)} |`);
    console.log(`| Registered Agents: ${metrics.registeredAgents.toString().padEnd(44)} |`);
    console.log(`| Pending Requests: ${metrics.pendingRequests.toString().padEnd(45)} |`);
    console.log(`| Requests In Flight: ${metrics.requestsInFlight.toString().padEnd(43)} |`);
    console.log('+------------------------------------------------------------+\n');
  }

  /**
   * Cleanup old messages
   */
  cleanup() {
    const now = Date.now();
    const cutoff = now - this.options.messageRetention;

    // Remove old messages
    let removed = 0;
    for (const [messageId, message] of this.messages.entries()) {
      const messageTime = new Date(message.timestamp).getTime();
      if (messageTime < cutoff) {
        this.messages.delete(messageId);
        removed++;
      }
    }

    // Clean message log
    this.messageLog = this.messageLog.filter(msg => {
      const messageTime = new Date(msg.timestamp).getTime();
      return messageTime >= cutoff;
    });

    if (removed > 0) {
      console.log(`[MessageBus] Cleaned up ${removed} old messages`);
    }
  }

  /**
   * Shutdown message bus
   */
  shutdown() {
    this.persistSdkReports();
    clearInterval(this.cleanupInterval);
    for (const retryHandle of this.retryTimers) {
      clearTimeout(retryHandle);
    }
    this.retryTimers.clear();
    for (const pendingRequest of this.pendingRequests.values()) {
      clearTimeout(pendingRequest.timeout);
    }
    this.removeAllListeners();
    this.messages.clear();
    this.messageLog = [];
    this.subscriptions.clear();
    this.agentCallbacks.clear();
    this.pendingRequests.clear();
    console.log('[MessageBus] Shutdown complete');
  }
}

module.exports = AgentMessageBus;

// Example usage and testing
if (require.main === module) {
  const messageBus = new AgentMessageBus();

  // Simulate two agents
  const agent1 = 'code-intelligence-agent';
  const agent2 = 'architecture-agent';

  // Register agents
  messageBus.registerAgent(agent1, (message) => {
    console.log(`[${agent1}] Received message:`, message.content);

    // If it's a request, send response
    if (message.type === 'request') {
      messageBus.respond(message, agent1, {
        analysis: 'Code looks good',
        quality_score: 0.95
      });
    }
  });

  messageBus.registerAgent(agent2, (message) => {
    console.log(`[${agent2}] Received message:`, message.content);
  });

  // Test 1: Direct request-response
  console.log('\n=== Test 1: Request-Response ===');
  messageBus.request(agent2, agent1, {
    action: 'analyze',
    file: 'user-service.js'
  }).then(response => {
    console.log('[agent2] Received response:', response.content);
  }).catch(error => {
    console.error('[agent2] Request failed:', error.message);
  });

  // Test 2: Pub-Sub
  console.log('\n=== Test 2: Pub-Sub ===');
  messageBus.subscribe(agent1, 'code-quality');
  messageBus.subscribe(agent2, 'code-quality');

  messageBus.publish('self-healing-agent', 'code-quality', {
    file: 'user-service.js',
    issues_fixed: 5
  });

  // Test 3: Broadcast
  setTimeout(() => {
    console.log('\n=== Test 3: Broadcast ===');
    messageBus.broadcast('supreme-coordinator', {
      announcement: 'System health check complete',
      status: 'all systems operational'
    });
  }, 1000);

  // Print metrics after 2 seconds
  setTimeout(() => {
    messageBus.printMetrics();
  }, 2000);

  // Shutdown after 3 seconds
  setTimeout(() => {
    messageBus.shutdown();
  }, 3000);
}
