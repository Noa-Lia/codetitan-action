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
    const message = {
      message_id: this.generateMessageId(),
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

  /**
   * Send response to a request
   */
  async respond(originalMessage, from, content, metadata = {}) {
    return this.send(from, originalMessage.from, 'response', content, {
      ...metadata,
      correlation_id: originalMessage.metadata.correlation_id,
      parent_message_id: originalMessage.message_id
    });
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

    if (options.sdk) {
      this.agentIntegrations.set(agentId, { sdk: options.sdk });
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
