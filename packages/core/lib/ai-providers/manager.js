/**
 * AIProviderManager - Smart routing, fallback, and provider orchestration
 * Handles provider selection, health checks, cost optimization, and failover
 *
 * @module ai-providers/manager
 */

function isDebugEnabled(value) {
  return value === '1' || value === 'true';
}

const SHOULD_DEBUG =
  isDebugEnabled(process.env.CODETITAN_DEBUG) ||
  isDebugEnabled(process.env.CODETITAN_DEBUG_AI);

// Internal diagnostic logger - opt-in only so normal CLI output stays clean.
const _dbg = (...args) => {
  if (!SHOULD_DEBUG) {
    return;
  }

  process.stderr.write(args.join(' ') + '\n');
};

const HeuristicProvider = require('./heuristic');
const ClaudeProvider = require('./claude');
const GPT5CodexProvider = require('./gpt5-codex');
const GeminiProvider = require('./gemini');

class AIProviderManager {
  constructor(config = {}) {
    this.config = {
      // Default domain routing (can be overridden in .codetitan.yml)
      domainRouting: {
        'security-god': 'claude',
        'performance-god': 'claude',
        'test-god': 'claude',
        'refactoring-god': 'claude',
        'documentation-god': 'claude'
      },
      fallbackChain: ['claude', 'gemini', 'heuristic'],
      budget: {
        monthlyLimit: 50.00,  // USD
        perAnalysis: 2.00     // USD
      },
      ...config
    };

    // Initialize all providers
    this.providers = new Map();
    this.initializeProviders();

    // Track usage and costs
    this.usage = {
      totalCost: 0,
      analysesByProvider: {},
      errors: []
    };
  }

  /**
   * Initialize all available providers
   */
  initializeProviders() {
    // Always add heuristic provider (no API key needed)
    this.providers.set('heuristic', new HeuristicProvider());

    // Add AI providers if API keys are configured
    try {
      const claude = new ClaudeProvider();
      if (claude.enabled) {
        this.providers.set('claude', claude);
      }
    } catch (error) {
      _dbg('[AIProviderManager] Claude initialization failed:', error.message);
    }

    try {
      const gptCodex = new GPT5CodexProvider();
      if (gptCodex.enabled) {
        this.providers.set('gpt-5-codex', gptCodex);
      }
    } catch (error) {
      _dbg('[AIProviderManager] GPT-5-Codex initialization failed:', error.message);
    }

    try {
      const gemini = new GeminiProvider();
      if (gemini.enabled) {
        this.providers.set('gemini', gemini);
      }
    } catch (error) {
      _dbg('[AIProviderManager] Gemini initialization failed:', error.message);
    }

    _dbg(`[AIProviderManager] Initialized ${this.providers.size} providers:`, Array.from(this.providers.keys()));
  }

  /**
   * Analyze code using smart provider selection
   *
   * @param {string} domain - Analysis domain
   * @param {string} filePath - File path
   * @param {string} content - File content
   * @param {string} projectRoot - Project root
   * @param {Object} options - Additional options
   * @param {string} [options.preferredProvider] - Override provider selection
   * @param {number} [options.budget] - Budget limit for this analysis
   * @returns {Promise<Object>} Analysis result
   */
  async analyze(domain, filePath, content, projectRoot, options = {}) {
    const start = Date.now();

    // Select provider based on options, domain routing, or smart selection
    let selectedProvider;
    if (options.preferredProvider) {
      selectedProvider = await this.getProvider(options.preferredProvider);
    } else {
      selectedProvider = await this.selectProvider(domain, content, options);
    }

    if (!selectedProvider) {
      _dbg(`[AIProviderManager] No provider available for ${domain}, using heuristic fallback`);
      selectedProvider = this.providers.get('heuristic');
    }

    // Attempt analysis with selected provider
    try {
      _dbg(`[AIProviderManager] Analyzing ${filePath} (${domain}) with ${selectedProvider.name}`);
      const result = await selectedProvider.analyze(domain, filePath, content, projectRoot, options);

      // Track usage
      this.trackUsage(selectedProvider.name, result.metadata.costUSD);

      return {
        ...result,
        metadata: {
          ...result.metadata,
          selectedProvider: selectedProvider.name,
          fallbackUsed: false,
          totalDuration: Date.now() - start
        }
      };
    } catch (error) {
      _dbg(`[AIProviderManager] Provider ${selectedProvider.name} failed:`, error.message);
      this.usage.errors.push({
        provider: selectedProvider.name,
        domain,
        error: error.message,
        timestamp: new Date().toISOString()
      });

      // Attempt fallback
      return await this.fallbackAnalysis(domain, filePath, content, projectRoot, selectedProvider.name, start, options);
    }
  }

  /**
   * Select best provider for domain based on quality, cost, and availability
   *
   * @param {string} domain - Analysis domain
   * @param {string} content - File content (for token estimation)
   * @param {Object} options - Options including budget
   * @returns {Promise<AIProvider>} Selected provider
   */
  async selectProvider(domain, content, options = {}) {
    // 1. Check domain routing preference
    const preferredProviderName = this.config.domainRouting[domain];
    if (preferredProviderName) {
      const provider = await this.getProvider(preferredProviderName);
      if (provider && await provider.isAvailable()) {
        // Check if within budget
        const estimatedCost = this.estimateAnalysisCost(provider, content);
        const budgetLimit = options.budget || this.config.budget.perAnalysis;

        if (estimatedCost <= budgetLimit) {
          return provider;
        } else {
          _dbg(`[AIProviderManager] ${preferredProviderName} exceeds budget ($${estimatedCost} > $${budgetLimit}), finding alternative`);
        }
      }
    }

    // 2. Find best available provider within budget
    const availableProviders = [];
    for (const [name, provider] of this.providers.entries()) {
      if (name === 'heuristic') continue; // Save heuristic as last resort

      const isAvailable = await provider.isAvailable();
      if (isAvailable) {
        const estimatedCost = this.estimateAnalysisCost(provider, content);
        const qualityScore = provider.getQualityScore(domain);

        availableProviders.push({
          name,
          provider,
          estimatedCost,
          qualityScore,
          score: qualityScore / (estimatedCost + 0.01) // Quality per dollar
        });
      }
    }

    // Sort by score (quality per dollar)
    availableProviders.sort((a, b) => b.score - a.score);

    // Return best provider within budget
    const budgetLimit = options.budget || this.config.budget.perAnalysis;
    const bestProvider = availableProviders.find(p => p.estimatedCost <= budgetLimit);

    if (bestProvider) {
      return bestProvider.provider;
    }

    // If no AI provider within budget, return cheapest AI or heuristic
    if (availableProviders.length > 0) {
      const cheapest = availableProviders.sort((a, b) => a.estimatedCost - b.estimatedCost)[0];
      _dbg(`[AIProviderManager] All providers exceed budget, using cheapest: ${cheapest.name} ($${cheapest.estimatedCost})`);
      return cheapest.provider;
    }

    // Last resort: heuristic
    return this.providers.get('heuristic');
  }

  /**
   * Estimate cost for analyzing content with a provider
   */
  estimateAnalysisCost(provider, content) {
    // Rough token estimation: ~4 chars per token
    const inputTokens = Math.ceil(content.length / 4);
    const estimatedOutputTokens = 500; // Typical findings output
    return provider.estimateCost(inputTokens, estimatedOutputTokens);
  }

  /**
   * Fallback to next available provider
   */
  async fallbackAnalysis(domain, filePath, content, projectRoot, failedProvider, startTime, options = {}) {
    _dbg(`[AIProviderManager] Attempting fallback after ${failedProvider} failed`);

    // Get fallback chain excluding failed provider
    const fallbackChain = this.config.fallbackChain.filter(name => name !== failedProvider);

    for (const providerName of fallbackChain) {
      const provider = this.providers.get(providerName);
      if (!provider) continue;

      const isAvailable = await provider.isAvailable();
      if (!isAvailable) continue;

      try {
        _dbg(`[AIProviderManager] Trying fallback provider: ${providerName}`);
        const result = await provider.analyze(domain, filePath, content, projectRoot, options);

        // Track usage
        this.trackUsage(providerName, result.metadata.costUSD);

        return {
          ...result,
          metadata: {
            ...result.metadata,
            selectedProvider: failedProvider,
            fallbackUsed: true,
            fallbackProvider: providerName,
            totalDuration: Date.now() - startTime
          }
        };
      } catch (error) {
        _dbg(`[AIProviderManager] Fallback ${providerName} also failed:`, error.message);
        this.usage.errors.push({
          provider: providerName,
          domain,
          error: error.message,
          timestamp: new Date().toISOString()
        });
        continue;
      }
    }

    // All providers failed, return empty result
    _dbg(`[AIProviderManager] All providers failed for ${domain} analysis`);
    return {
      issues: [],
      metadata: {
        provider: 'none',
        model: 'none',
        tokensUsed: { input: 0, output: 0, cached: 0 },
        costUSD: 0,
        duration: Date.now() - startTime,
        confidence: 0,
        error: 'All providers failed',
        selectedProvider: failedProvider,
        fallbackUsed: true,
        totalDuration: Date.now() - startTime
      }
    };
  }

  /**
   * Get provider by name
   */
  async getProvider(name) {
    return this.providers.get(name);
  }

  /**
   * Get all available providers
   */
  async getAvailableProviders() {
    const available = [];
    for (const [name, provider] of this.providers.entries()) {
      const isAvailable = await provider.isAvailable();
      if (isAvailable) {
        available.push({
          name,
          model: provider.model,
          costPerInputToken: provider.costPerInputToken,
          costPerOutputToken: provider.costPerOutputToken
        });
      }
    }
    return available;
  }

  /**
   * Track usage for cost monitoring
   */
  trackUsage(providerName, cost) {
    this.usage.totalCost += cost;

    if (!this.usage.analysesByProvider[providerName]) {
      this.usage.analysesByProvider[providerName] = {
        count: 0,
        totalCost: 0
      };
    }

    this.usage.analysesByProvider[providerName].count++;
    this.usage.analysesByProvider[providerName].totalCost += cost;
  }

  /**
   * Get usage statistics
   */
  getUsageStats() {
    return {
      ...this.usage,
      remainingBudget: this.config.budget.monthlyLimit - this.usage.totalCost,
      providers: Array.from(this.providers.keys())
    };
  }

  /**
   * Reset usage tracking (e.g., monthly)
   */
  resetUsage() {
    this.usage = {
      totalCost: 0,
      analysesByProvider: {},
      errors: []
    };
  }

  normalizeReasoningMode(reasoningMode) {
    return reasoningMode === 'deep' ? 'deep' : 'standard';
  }

  getBudgetPolicy(roleProfile = {}, reasoningMode = 'standard', overrides = {}) {
    const normalizedMode = this.normalizeReasoningMode(reasoningMode);
    const baseToolBudget = { ...(roleProfile.toolBudget || {}) };
    const basePromptBudget = { ...(roleProfile.promptBudget || {}) };

    if (normalizedMode === 'deep') {
      if (typeof baseToolBudget.maxCalls === 'number') {
        baseToolBudget.maxCalls += 2;
      }

      if (typeof basePromptBudget.tokenCap === 'number') {
        basePromptBudget.tokenCap *= 2;
      }

      if (typeof basePromptBudget.usdCap === 'number') {
        basePromptBudget.usdCap = Number((basePromptBudget.usdCap * 2).toFixed(2));
      }
    }

    return {
      reasoningMode: normalizedMode,
      toolBudget: {
        ...baseToolBudget,
        ...(overrides.toolBudget || {})
      },
      promptBudget: {
        ...basePromptBudget,
        ...(overrides.promptBudget || {})
      }
    };
  }

  mapActionToDomain(action = 'review') {
    switch (String(action || '').toLowerCase()) {
      case 'security-review':
        return 'security-god';
      case 'optimize':
      case 'performance-review':
        return 'performance-god';
      case 'test':
      case 'validate':
        return 'test-god';
      case 'fix':
      case 'refactor':
        return 'refactoring-god';
      case 'review':
      case 'compare':
      case 'replay':
      case 'analyze':
      default:
        return 'documentation-god';
    }
  }

  buildAdvisorPrompt(payload = {}) {
    return JSON.stringify({
      action: payload.action || 'review',
      summary: payload.summary || '',
      evidenceSummary: payload.evidenceSummary || '',
      evidenceCount: Array.isArray(payload.evidence) ? payload.evidence.length : 0,
      toolTraceCount: Array.isArray(payload.toolTrace) ? payload.toolTrace.length : 0
    });
  }

  async validateAdvisorDecision(payload = {}) {
    const requested = payload.enabled === true;
    const reasoningMode = this.normalizeReasoningMode(payload.reasoningMode);

    if (!requested) {
      return {
        requested: false,
        performed: false,
        verdict: 'skipped',
        provider: null,
        model: null,
        retries: 0,
        tokensUsed: { input: 0, output: 0, cached: 0 },
        costUSD: 0
      };
    }

    const content = this.buildAdvisorPrompt(payload);
    const domain = this.mapActionToDomain(payload.action);
    let retries = 0;
    const provider = payload.preferredProvider
      ? await this.getProvider(payload.preferredProvider)
      : await this.selectProvider(domain, content, { budget: payload.budgetUsd });
    const selected = provider || this.providers.get('heuristic');

    if (!selected) {
      return {
        requested: true,
        performed: false,
        verdict: 'unavailable',
        provider: null,
        model: null,
        retries: 0,
        tokensUsed: { input: 0, output: 0, cached: 0 },
        costUSD: 0
      };
    }

    try {
      const result = await selected.analyze(domain, payload.filePath || 'runtime-advisor.json', content, payload.projectRoot || process.cwd(), {
        budget: payload.budgetUsd,
        reasoningMode
      });
      const issues = Array.isArray(result.issues) ? result.issues : [];
      const verdict = issues.length > 0 ? 'questioned' : 'confirmed';

      return {
        requested: true,
        performed: true,
        verdict,
        provider: result.metadata?.selectedProvider || result.metadata?.provider || selected.name,
        model: result.metadata?.model || selected.model,
        retries,
        tokensUsed: result.metadata?.tokensUsed || { input: 0, output: 0, cached: 0 },
        costUSD: result.metadata?.costUSD || 0,
        confidence: result.metadata?.confidence ?? null,
        issues
      };
    } catch (error) {
      retries += 1;
      return {
        requested: true,
        performed: false,
        verdict: 'failed',
        provider: selected.name,
        model: selected.model,
        retries,
        tokensUsed: { input: 0, output: 0, cached: 0 },
        costUSD: 0,
        error: error.message
      };
    }
  }
}

module.exports = AIProviderManager;
