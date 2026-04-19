/**
 * Agent Execution Engine
 *
 * THE CRITICAL MISSING PIECE
 *
 * This is what makes agents actually DO work instead of being
 * just data structures. It:
 *
 * 1. Loads agent SKILL.md files
 * 2. Parses agent capabilities and instructions
 * 3. Interprets tasks
 * 4. Executes using Claude's tools (via function calling)
 * 5. Returns REAL results
 *
 * This is the bridge between infrastructure and actual work.
 */

const fs = require('fs');
const path = require('path');
const ToolBridge = require('./tool-bridge');
const AgentMessageBus = require('./agent-message-bus');
const AgentRegistryManager = require('./agent-registry-manager');
const Guardrails = require('./agent-runtime/guardrails');
const Planner = require('./agent-runtime/planner');
const { persistRuntimeInsight } = require('./agent-runtime/runtime-insight-recorder');
const ToolRouter = require('./agent-runtime/tool-router');
const { createDefaultToolRegistry } = require('./agent-runtime/tool-registry');
const { AIProviderManager } = require('./ai-providers');
const { loadConfig } = require('./config');

function resolveReviewArtifactPath(result, task = {}) {
  const payload = result?.result || result || {};
  const runtimeState = payload.runtime_state || {};

  return payload?.review_artifact?.path ||
    result?.review_artifact?.path ||
    runtimeState?.reviewArtifact?.path ||
    runtimeState?.review_artifact_path ||
    task?.metadata?.reviewArtifactPath ||
    null;
}

function resolveFixSessionMetadata(result, task = {}) {
  const payload = result?.result || result || {};
  const runtimeState = payload.runtime_state || {};
  const fixSession = payload?.fix_session || runtimeState?.fixSession || {};

  return {
    id:
      fixSession?.id ||
      runtimeState?.fix_session_id ||
      task?.metadata?.fixSessionId ||
      null,
    path:
      fixSession?.path ||
      runtimeState?.fix_session_path ||
      task?.metadata?.fixSessionPath ||
      null
  };
}

class AgentExecutionEngine {
  constructor(options = {}) {
    this.options = {
      agentsDir: options.agentsDir || path.join(__dirname, '..', 'agents'),
      enableToolExecution: options.enableToolExecution ?? true,
      maxExecutionTime: options.maxExecutionTime || 300000, // 5 minutes
      maxRuntimeSteps: options.maxRuntimeSteps || 8,
      ...options
    };

    // Loaded agent skills
    this.agentSkills = new Map(); // agent_name -> parsed skill

    // Tool Bridge - provides access to real file operations
    this.toolBridge = new ToolBridge({
      workingDirectory: options.workingDirectory || path.join(__dirname, '..'),
      enableFileOperations: options.enableFileOperations ?? true,
      enableBashOperations: options.enableBashOperations ?? false
    });
    this.providerManager = options.providerManager || new AIProviderManager(options.aiConfig || {});
    this.toolRegistry = options.toolRegistry || createDefaultToolRegistry();
    this.guardrails = options.guardrails || new Guardrails({
      workingDirectory: options.workingDirectory || path.join(__dirname, '..'),
      maxSteps: this.options.maxRuntimeSteps
    });
    this.toolRouter = options.toolRouter || new ToolRouter({
      toolBridge: this.toolBridge
    });
    this.runtimePlanner = options.runtimePlanner || new Planner({
      toolRegistry: this.toolRegistry,
      toolRouter: this.toolRouter,
      guardrails: this.guardrails,
      providerManager: this.providerManager,
      maxSteps: this.options.maxRuntimeSteps
    });

    this.config = loadConfig();
    this._ownsMessageBus = !options.messageBus;
    this._ownsRegistryManager = !options.registryManager;
    this._shutdown = false;
    this.messageBus = options.messageBus || new AgentMessageBus({
      persistMessages: false,
      metricsEnabled: false
    });
    this.registryManager = options.registryManager || new AgentRegistryManager({
      watch: options.registryWatch ?? false
    });

    // Execution context (tools available to agents) - DEPRECATED, using toolBridge now
    this.toolContext = null;

    // Metrics
    this.metrics = {
      skillsLoaded: 0,
      tasksExecuted: 0,
      tasksSucceeded: 0,
      tasksFailed: 0,
      averageExecutionTime: 0,
      totalExecutionTime: 0
    };

    console.log('[ExecutionEngine] Initialized');
  }

  /**
   * Set tool context (provides access to Claude's tools)
   * This would be injected by the Claude Code runtime
   */
  setToolContext(toolContext) {
    this.toolContext = toolContext;
    console.log('[ExecutionEngine] Tool context set');
  }

  /**
   * Load agent skill from SKILL.md file
   */
  async loadAgentSkill(agentName) {
    try {
      // Check if already loaded
      if (this.agentSkills.has(agentName)) {
        return this.agentSkills.get(agentName);
      }

      // Find the skill file
      const skillFile = path.join(this.options.agentsDir, `${agentName}.md`);

      // Read the file (with existence check)
      const content = await fs.promises.readFile(skillFile, 'utf8').catch(err => {
        if (err.code === 'ENOENT') {
          throw new Error(`Skill file not found: ${skillFile}`);
        }
        throw err;
      });

      // Parse the skill
      const skill = this.parseSkillFile(content, agentName);

      // Store parsed skill
      this.agentSkills.set(agentName, skill);
      this.metrics.skillsLoaded++;

      console.log(`[ExecutionEngine] Loaded skill: ${agentName}`);
      return skill;

    } catch (error) {
      console.error(`[ExecutionEngine] Failed to load skill ${agentName}:`, error.message);
      throw error;
    }
  }

  /**
   * Parse SKILL.md file
   */
  parseSkillFile(content, agentName) {
    const skill = {
      name: agentName,
      role: '',
      tier: null,
      domain: '',
      capabilities: [],
      specializations: [],
      tools: [],
      workflows: [],
      examples: [],
      rawContent: content
    };

    // Extract role
    const roleMatch = content.match(/## Role\n(.+?)(?=\n##|\n---)/s);
    if (roleMatch) {
      skill.role = roleMatch[1].trim();
    }

    // Extract tier
    const tierMatch = content.match(/## Tier\n\*\*Tier (\d+):/);
    if (tierMatch) {
      skill.tier = parseInt(tierMatch[1]);
    }

    // Extract domain
    const domainMatch = content.match(/## Domain\n(.+?)(?=\n##|\n---)/s);
    if (domainMatch) {
      skill.domain = domainMatch[1].trim();
    }

    // Extract capabilities section
    const capabilitiesMatch = content.match(/## Capabilities\n([\s\S]+?)(?=\n## )/);
    if (capabilitiesMatch) {
      const capText = capabilitiesMatch[1];

      // Look for bullet points or numbered lists
      const capabilityLines = capText.match(/[-*]\s+\*\*(.+?)\*\*/g);
      if (capabilityLines) {
        skill.capabilities = capabilityLines.map(line => {
          const match = line.match(/\*\*(.+?)\*\*/);
          return match ? match[1] : '';
        }).filter(Boolean);
      }
    }

    // Extract tools section
    const toolsMatch = content.match(/## Tools\n([\s\S]+?)(?=\n## )/);
    if (toolsMatch) {
      const toolsText = toolsMatch[1];

      // Look for function definitions
      const toolFunctions = toolsText.match(/###\s+(.+?)\n/g);
      if (toolFunctions) {
        skill.tools = toolFunctions.map(line => {
          const match = line.match(/###\s+(.+?)\n/);
          return match ? match[1].trim() : '';
        }).filter(Boolean);
      }
    }

    return skill;
  }

  /**
   * Execute a task using an agent
   *
   * This is where the REAL WORK happens
   */
  async executeTask(agentName, task) {
    const startTime = Date.now();
    this.metrics.tasksExecuted++;

    try {
      // Load agent skill if not already loaded
      const skill = await this.loadAgentSkill(agentName);

      console.log(`[ExecutionEngine] Executing task with ${agentName}`);
      console.log(`[ExecutionEngine] Task action: ${task.action || 'unknown'}`);

      // Interpret the task based on agent's capabilities
      const interpretation = this.interpretTask(skill, task);

      // Execute based on interpretation
      const result = await this.performExecution(skill, interpretation, task);
      const executionTime = Date.now() - startTime;

      if (result && result.success === false) {
        const runtimeState = result.runtime_state || {};
        const reviewArtifactPath = resolveReviewArtifactPath(result, task);
        const fixSession = resolveFixSessionMetadata(result, task);
        this.metrics.tasksFailed++;
        this.metrics.totalExecutionTime += executionTime;
        this.metrics.averageExecutionTime =
          this.metrics.totalExecutionTime / this.metrics.tasksExecuted;

        this.messageBus.emit('agent:result', {
          agent: agentName,
          success: false,
          task,
          interpretation,
          result,
          error: result.error || result.message,
          executionTime
        });
        this.registryManager.recordExecution(agentName, {
          success: false,
          executionTime,
          taskAction: task.action || interpretation.action,
          resultSummary: result?.message || null,
          error: result?.error || result?.message,
          role: runtimeState.role || null,
          toolBudget: runtimeState.toolBudget || null,
          reasoningMode: runtimeState.reasoningMode || 'standard',
          providerUsage: runtimeState.providerUsage || null,
          toolMetrics: runtimeState.toolMetrics || null,
          evidenceCount: runtimeState.evidenceCount || 0,
          verificationStatus: runtimeState.verificationStatus || 'failed',
          toolCallsUsed: runtimeState.toolCallsUsed || 0,
          reviewArtifactPath,
          fixSessionId: fixSession.id,
          fixSessionPath: fixSession.path
        });
        await this.persistInsight(task, result);

        return {
          success: false,
          agent: agentName,
          result,
          interpretation,
          error: result.error || result.message,
          quality: result.quality || 0,
          executionTime,
          timestamp: new Date().toISOString()
        };
      }

      this.metrics.totalExecutionTime += executionTime;
      this.metrics.averageExecutionTime =
        this.metrics.totalExecutionTime / this.metrics.tasksExecuted;
      this.metrics.tasksSucceeded++;

      console.log(`[ExecutionEngine] Task completed in ${executionTime}ms`);
      const runtimeState = result.runtime_state || {};
      const reviewArtifactPath = resolveReviewArtifactPath(result, task);
      const fixSession = resolveFixSessionMetadata(result, task);

      this.messageBus.emit('agent:result', {
        agent: agentName,
        success: true,
        task,
        interpretation,
        result,
        executionTime
      });
      this.registryManager.recordExecution(agentName, {
        success: true,
        executionTime,
        taskAction: task.action || interpretation.action,
        resultSummary: result?.message || null,
        role: runtimeState.role || null,
        toolBudget: runtimeState.toolBudget || null,
        reasoningMode: runtimeState.reasoningMode || 'standard',
        providerUsage: runtimeState.providerUsage || null,
        toolMetrics: runtimeState.toolMetrics || null,
        evidenceCount: runtimeState.evidenceCount || 0,
        verificationStatus: runtimeState.verificationStatus || 'verified',
        toolCallsUsed: runtimeState.toolCallsUsed || 0,
        reviewArtifactPath,
        fixSessionId: fixSession.id,
        fixSessionPath: fixSession.path
      });
      await this.persistInsight(task, result);

      return {
        success: true,
        agent: agentName,
        result,
        interpretation,
        quality: result?.quality || 1,
        executionTime,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      this.metrics.tasksFailed++;

      console.error(`[ExecutionEngine] Task execution failed:`, error.message);

      const executionTime = Date.now() - startTime;

      this.messageBus.emit('agent:result', {
        agent: agentName,
        success: false,
        task,
        error: error.message,
        executionTime
      });
      this.registryManager.recordExecution(agentName, {
        success: false,
        executionTime,
        taskAction: task.action || 'unknown',
        error: error.message,
        reviewArtifactPath: task?.metadata?.reviewArtifactPath || null,
        fixSessionId: task?.metadata?.fixSessionId || null,
        fixSessionPath: task?.metadata?.fixSessionPath || null
      });
      await this.persistInsight(task, {
        success: false,
        type: task.action || 'unknown',
        status: 'failed',
        summary: error.message,
        message: error.message,
        error: error.message,
        evidence: [],
        toolTrace: [],
        runtime_state: {
          reasoningMode: 'standard',
          verificationStatus: 'failed',
          providerUsage: null,
          toolMetrics: {}
        }
      });

      return {
        success: false,
        agent: agentName,
        error: error.message,
        executionTime,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Interpret task based on agent's capabilities
   */
  interpretTask(skill, task) {
    const interpretation = {
      action: task.action || 'unknown',
      capability_match: false,
      matched_capabilities: [],
      execution_strategy: 'generic',
      parameters: task.content || {}
    };

    // Map common actions to capabilities
    const actionCapabilityMap = {
      'analyze': ['semantic_analysis', 'analysis', 'quality_analysis'],
      'refactor': ['refactoring'],
      'generate': ['generation', 'code_generation'],
      'optimize': ['optimization', 'performance'],
      'test': ['testing', 'test_generation'],
      'fix': ['auto_fix', 'error_detection'],
      'design': ['design', 'architecture'],
      'validate': ['validation', 'checking'],
      'review': ['review', 'analysis', 'quality_analysis'],
      'security-review': ['security', 'review', 'analysis'],
      'replay': ['analysis', 'history'],
      'compare': ['analysis', 'history', 'review']
    };

    // Check if agent has capabilities for this action
    const requiredCapabilities = actionCapabilityMap[task.action] || [];
    const matchedCapabilities = skill.capabilities.filter(cap =>
      requiredCapabilities.some(req =>
        cap.toLowerCase().includes(req.toLowerCase())
      )
    );

    if (matchedCapabilities.length > 0) {
      interpretation.capability_match = true;
      interpretation.matched_capabilities = matchedCapabilities;
      interpretation.execution_strategy = task.action;
    }

    return interpretation;
  }

  async performExecution(skill, interpretation, task) {
    return this.runtimePlanner.execute({
      skill,
      interpretation,
      task
    });
  }

  buildRuntimeContext(action, context) {
    return {
      skill: {
        name: context.agent,
        role: context.role,
        capabilities: context.capabilities || []
      },
      interpretation: {
        execution_strategy: action,
        matched_capabilities: context.interpretation?.matched_capabilities || []
      },
      task: {
        action,
        content: context.task?.content || {},
        metadata: context.task?.metadata
      }
    };
  }

  ensureRuntimeAgentRegistration(runtimeContext = {}) {
    const agentName = runtimeContext?.skill?.name || 'runtime-agent';

    if (
      typeof this.registryManager?.resolveAgent !== 'function' ||
      typeof this.registryManager?.registerAgent !== 'function'
    ) {
      return agentName;
    }

    const existingAgent = this.registryManager.resolveAgent(agentName);
    if (existingAgent) {
      return agentName;
    }

    const normalizedRole = String(
      runtimeContext?.task?.metadata?.role ||
      runtimeContext?.skill?.role ||
      'researcher'
    ).toLowerCase();

    this.registryManager.registerAgent({
      name: agentName,
      tier: normalizedRole === 'orchestrator' ? 4 : 2,
      domain: 'runtime',
      capabilities: runtimeContext?.skill?.capabilities || [],
      role: normalizedRole
    });

    return agentName;
  }

  async executeRuntimeAction(action, context) {
    const startTime = Date.now();
    const runtimeContext = this.buildRuntimeContext(action, context);
    const agentName = this.ensureRuntimeAgentRegistration(runtimeContext);

    this.metrics.tasksExecuted++;

    try {
      const result = await this.runtimePlanner.execute(runtimeContext);
      const executionTime = Date.now() - startTime;
      const runtimeState = result?.runtime_state || {};
      const reviewArtifactPath = resolveReviewArtifactPath(result, runtimeContext.task);
      const fixSession = resolveFixSessionMetadata(result, runtimeContext.task);

      this.metrics.totalExecutionTime += executionTime;
      this.metrics.averageExecutionTime =
        this.metrics.totalExecutionTime / this.metrics.tasksExecuted;

      if (result?.success === false) {
        this.metrics.tasksFailed++;
        this.messageBus.emit('agent:result', {
          agent: agentName,
          success: false,
          task: runtimeContext.task,
          interpretation: runtimeContext.interpretation,
          result,
          error: result.error || result.message,
          executionTime
        });
        this.registryManager.recordExecution(agentName, {
          success: false,
          executionTime,
          taskAction: action,
          resultSummary: result?.message || null,
          error: result?.error || result?.message,
          role: runtimeState.role || runtimeContext.task?.metadata?.role || runtimeContext.skill?.role || null,
          toolBudget: runtimeState.toolBudget || null,
          reasoningMode: runtimeState.reasoningMode || runtimeContext.task?.metadata?.reasoningMode || 'standard',
          providerUsage: runtimeState.providerUsage || null,
          toolMetrics: runtimeState.toolMetrics || null,
          evidenceCount: runtimeState.evidenceCount || 0,
          verificationStatus: runtimeState.verificationStatus || 'failed',
          toolCallsUsed: runtimeState.toolCallsUsed || 0,
          reviewArtifactPath,
          fixSessionId: fixSession.id,
          fixSessionPath: fixSession.path
        });
        await this.persistInsight(runtimeContext.task, result);
        return result;
      }

      this.metrics.tasksSucceeded++;
      this.messageBus.emit('agent:result', {
        agent: agentName,
        success: true,
        task: runtimeContext.task,
        interpretation: runtimeContext.interpretation,
        result,
        executionTime
      });
      this.registryManager.recordExecution(agentName, {
        success: true,
        executionTime,
        taskAction: action,
        resultSummary: result?.message || null,
        role: runtimeState.role || runtimeContext.task?.metadata?.role || runtimeContext.skill?.role || null,
        toolBudget: runtimeState.toolBudget || null,
        reasoningMode: runtimeState.reasoningMode || runtimeContext.task?.metadata?.reasoningMode || 'standard',
        providerUsage: runtimeState.providerUsage || null,
        toolMetrics: runtimeState.toolMetrics || null,
        evidenceCount: runtimeState.evidenceCount || 0,
        verificationStatus: runtimeState.verificationStatus || 'verified',
        toolCallsUsed: runtimeState.toolCallsUsed || 0,
        reviewArtifactPath,
        fixSessionId: fixSession.id,
        fixSessionPath: fixSession.path
      });
      await this.persistInsight(runtimeContext.task, result);
      return result;
    } catch (error) {
      const executionTime = Date.now() - startTime;

      this.metrics.tasksFailed++;
      this.metrics.totalExecutionTime += executionTime;
      this.metrics.averageExecutionTime =
        this.metrics.totalExecutionTime / this.metrics.tasksExecuted;

      this.messageBus.emit('agent:result', {
        agent: agentName,
        success: false,
        task: runtimeContext.task,
        interpretation: runtimeContext.interpretation,
        error: error.message,
        executionTime
      });
      this.registryManager.recordExecution(agentName, {
        success: false,
        executionTime,
        taskAction: action,
        error: error.message,
        role: runtimeContext.task?.metadata?.role || runtimeContext.skill?.role || null,
        reasoningMode: runtimeContext.task?.metadata?.reasoningMode || 'standard',
        reviewArtifactPath: runtimeContext.task?.metadata?.reviewArtifactPath || null,
        fixSessionId: runtimeContext.task?.metadata?.fixSessionId || null,
        fixSessionPath: runtimeContext.task?.metadata?.fixSessionPath || null
      });
      await this.persistInsight(runtimeContext.task, {
        success: false,
        type: action,
        status: 'failed',
        summary: error.message,
        message: error.message,
        error: error.message,
        evidence: [],
        toolTrace: [],
        runtime_state: {
          role: runtimeContext.task?.metadata?.role || runtimeContext.skill?.role || null,
          reasoningMode: runtimeContext.task?.metadata?.reasoningMode || 'standard',
          verificationStatus: 'failed',
          providerUsage: null,
          toolMetrics: {}
        }
      });
      throw error;
    }
  }

  async persistInsight(task = {}, payload = {}) {
    if (process.env.NODE_ENV === 'test' && process.env.CODETITAN_PERSIST_RUNTIME_INSIGHTS !== '1') {
      return;
    }

    try {
      await persistRuntimeInsight({
        result: payload,
        projectRoot: this.options.workingDirectory || path.join(__dirname, '..'),
        metadata: {
          action: task.action || payload.type || 'runtime',
          targetPath: task?.content?.file || task?.content?.directory || task?.content?.projectPath || '.',
          reasoningMode: payload?.runtime_state?.reasoningMode || 'standard'
        }
      });
    } catch (error) {
      console.warn('[ExecutionEngine] Failed to persist runtime insight:', error.message);
    }
  }

  async executeAnalysis(context) {
    return this.executeRuntimeAction('analyze', context);
  }

  calculateQualityScore(analysis) {
    return Planner.calculateQualityScore(analysis);
  }

  generateRecommendations(analysis) {
    return Planner.generateRecommendations(analysis);
  }

  async executeRefactoring(context) {
    return this.executeRuntimeAction('refactor', context);
  }

  async executeGeneration(context) {
    return this.executeRuntimeAction('generate', context);
  }

  async executeOptimization(context) {
    return this.executeRuntimeAction('optimize', context);
  }

  async executeDesign(context) {
    return this.executeRuntimeAction('design', context);
  }

  async executeFix(context) {
    return this.executeRuntimeAction('fix', context);
  }

  async executeGeneric(context) {
    return this.executeRuntimeAction('generic', context);
  }

  async shutdown() {
    if (this._shutdown) {
      return;
    }

    this._shutdown = true;

    if (this._ownsMessageBus && typeof this.messageBus?.shutdown === 'function') {
      try {
        this.messageBus.shutdown();
      } catch (error) {
        console.warn('[ExecutionEngine] Failed to shutdown message bus:', error.message);
      }
    }

    if (this._ownsRegistryManager && typeof this.registryManager?.close === 'function') {
      try {
        this.registryManager.close();
      } catch (error) {
        console.warn('[ExecutionEngine] Failed to close registry manager:', error.message);
      }
    }
  }

  async close() {
    await this.shutdown();
  }

  /**
   * Get metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      successRate: this.metrics.tasksExecuted > 0 ?
        (this.metrics.tasksSucceeded / this.metrics.tasksExecuted) : 1.0
    };
  }

  /**
   * Print metrics
   */
  printMetrics() {
    const metrics = this.getMetrics();
    console.log('\n+- EXECUTION ENGINE METRICS ---------------------------------+');
    console.log(`| Skills Loaded: ${metrics.skillsLoaded.toString().padEnd(48)} |`);
    console.log(`| Tasks Executed: ${metrics.tasksExecuted.toString().padEnd(47)} |`);
    console.log(`| Tasks Succeeded: ${metrics.tasksSucceeded.toString().padEnd(46)} |`);
    console.log(`| Tasks Failed: ${metrics.tasksFailed.toString().padEnd(49)} |`);
    console.log(`| Success Rate: ${(metrics.successRate * 100).toFixed(1)}%${' '.repeat(45 - (metrics.successRate * 100).toFixed(1).length)} |`);
    console.log(`| Avg Execution Time: ${metrics.averageExecutionTime.toFixed(2)}ms${' '.repeat(36 - metrics.averageExecutionTime.toFixed(2).length)} |`);
    console.log('+------------------------------------------------------------+\n');
  }
}

module.exports = AgentExecutionEngine;

// Example usage
if (require.main === module) {
  async function test() {
    const engine = new AgentExecutionEngine();

    // Test 1: Load agent skill
    console.log('\n=== Test 1: Loading Agent Skill ===\n');
    const skill = await engine.loadAgentSkill('code-intelligence-agent');
    console.log('Loaded skill:', skill.name);
    console.log('Role:', skill.role.substring(0, 80) + '...');
    console.log('Capabilities:', skill.capabilities.slice(0, 5));

    // Test 2: Execute analysis task
    console.log('\n=== Test 2: Execute Analysis Task ===\n');
    const analysisResult = await engine.executeTask('code-intelligence-agent', {
      action: 'analyze',
      content: {
        file: 'user-service.js'
      }
    });
    console.log('Result:', JSON.stringify(analysisResult, null, 2));

    // Test 3: Execute design task
    console.log('\n=== Test 3: Execute Design Task ===\n');
    const designResult = await engine.executeTask('architecture-agent', {
      action: 'design',
      content: {
        system: 'e-commerce platform'
      }
    });
    console.log('Result:', JSON.stringify(designResult, null, 2));

    // Print metrics
    engine.printMetrics();
  }

  test().catch(console.error);
}
