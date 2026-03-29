/**
 * ClaudeProvider - Anthropic Claude Sonnet 4.6 integration
 * Best for: Security analysis, complex reasoning, nuanced code understanding
 * 1M token context window with advanced coding and agentic capabilities
 *
 * @module ai-providers/claude
 */

const AIProvider = require('./base');

/**
 * Retry an async fn with exponential backoff on 429 rate limit errors.
 * @param {Function} fn - Async function to retry
 * @param {number} maxRetries - Max retry attempts (default 4)
 * @param {number} baseDelayMs - Initial delay in ms (default 1000)
 */
async function withRateLimitRetry(fn, maxRetries = 4, baseDelayMs = 1000) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const isRateLimit = err?.status === 429 || err?.error?.type === 'rate_limit_error' ||
        (err?.message || '').toLowerCase().includes('rate limit');
      const isOverload = err?.status === 529 || (err?.message || '').toLowerCase().includes('overloaded');

      if ((isRateLimit || isOverload) && attempt < maxRetries) {
        // Use Retry-After header if present, else exponential backoff
        const retryAfter = parseInt(err?.headers?.['retry-after'] || '0', 10);
        const backoff = retryAfter > 0
          ? retryAfter * 1000
          : baseDelayMs * Math.pow(2, attempt) + Math.random() * 500;
        await new Promise(resolve => setTimeout(resolve, backoff));
        continue;
      }
      throw err;
    }
  }
  throw lastError;
}

class ClaudeProvider extends AIProvider {
  constructor(config = {}) {
    const defaultModel = config.model || 'claude-sonnet-4-6-20260217';

    // Model-specific pricing (as of March 2026)
    const modelPricing = {
      'claude-opus-4-6-20260205': {
        input: 0.000005,    // $5 per M tokens
        output: 0.000025,   // $25 per M tokens
        cached: 0.0000005,
        contextWindow: 1000000
      },
      'claude-sonnet-4-6-20260217': {
        input: 0.000003,    // $3 per M tokens
        output: 0.000015,   // $15 per M tokens
        cached: 0.0000003,
        contextWindow: 1000000
      },
      'claude-haiku-4-5-20251015': {
        input: 0.000001,    // $1 per M tokens
        output: 0.000005,   // $5 per M tokens
        cached: 0.0000001,
        contextWindow: 200000
      },
      'claude-3-5-sonnet-20241022': {
        input: 0.000003,
        output: 0.000015,
        cached: 0.0000003,
        contextWindow: 200000
      }
    };

    const pricing = modelPricing[defaultModel] || modelPricing['claude-sonnet-4-6-20260217'];

    super({
      name: 'claude',
      model: defaultModel,
      apiKey: config.apiKey || process.env.ANTHROPIC_API_KEY,
      costPerInputToken: pricing.input,
      costPerOutputToken: pricing.output,
      costPerCachedToken: pricing.cached,
      maxTokens: config.maxTokens || 4000,
      timeout: config.timeout || 60000,
      contextWindow: pricing.contextWindow,
      ...config
    });

    // Initialize Anthropic client if available
    this.client = null;
    if (this.enabled) {
      try {
        const Anthropic = require('@anthropic-ai/sdk');
        this.client = new Anthropic({
          apiKey: this.apiKey
        });
      } catch (error) {
        console.warn('[ClaudeProvider] @anthropic-ai/sdk not installed. Run: npm install @anthropic-ai/sdk');
        this.enabled = false;
      }
    }
  }

  /**
   * Analyze code using Claude Sonnet 4.6
   * Best-in-class model for security analysis and complex reasoning
   * @override
   */
  async analyze(domain, filePath, content, projectRoot, options = {}) {
    if (!this.enabled || !this.client) {
      throw new Error('ClaudeProvider is not available. Check API key and dependencies.');
    }

    const start = Date.now();

    try {
      const systemPrompt = this.getDomainSystemPrompt(domain);
      const userPrompt = this.buildPrompt(domain, filePath, content);

      const response = await withRateLimitRetry(() => this.client.messages.create({
        model: this.model,
        max_tokens: this.maxTokens,
        system: [
          {
            type: 'text',
            text: systemPrompt,
            cache_control: { type: 'ephemeral' } // Cache system prompt
          }
        ],
        messages: [
          {
            role: 'user',
            content: userPrompt
          }
        ],
        temperature: 0.3 // Lower temperature for more consistent analysis
      }));

      // Extract the text content from response
      const rawResponse = response.content[0]?.text || '{}';
      const issues = this.parseResponse(rawResponse);

      // Filter and validate issues
      const validIssues = issues.filter(issue => this.validateIssue(issue));

      return {
        issues: validIssues,
        metadata: {
          provider: this.name,
          model: this.model,
          tokensUsed: {
            input: response.usage.input_tokens || 0,
            output: response.usage.output_tokens || 0,
            cached: response.usage.cache_read_input_tokens || 0
          },
          costUSD: this.calculateActualCost(response.usage),
          duration: Date.now() - start,
          confidence: 0.95, // Claude has very high confidence
          stopReason: response.stop_reason
        }
      };
    } catch (error) {
      console.error(`[ClaudeProvider] Analysis failed:`, error);

      // Return empty result with error metadata
      return {
        issues: [],
        metadata: {
          provider: this.name,
          model: this.model,
          tokensUsed: { input: 0, output: 0, cached: 0 },
          costUSD: 0,
          duration: Date.now() - start,
          confidence: 0,
          error: error.message
        }
      };
    }
  }

  /**
   * Calculate actual cost from usage object
   */
  calculateActualCost(usage) {
    const inputTokens = usage.input_tokens || 0;
    const outputTokens = usage.output_tokens || 0;
    const cachedTokens = usage.cache_read_input_tokens || 0;
    const writeCacheTokens = usage.cache_creation_input_tokens || 0;

    const inputCost = ((inputTokens - cachedTokens - writeCacheTokens) * this.costPerInputToken);
    const cachedCost = (cachedTokens * this.costPerCachedToken);
    const writeCacheCost = (writeCacheTokens * this.costPerInputToken * 1.25); // Write cache costs 25% more
    const outputCost = (outputTokens * this.costPerOutputToken);

    return inputCost + cachedCost + writeCacheCost + outputCost;
  }

  /**
   * Check if Claude API is available
   * @override
   */
  async isAvailable() {
    if (!this.enabled || !this.client) return false;

    try {
      // Simple health check using a minimal request
      await withRateLimitRetry(() => this.client.messages.create({
        model: this.model,
        max_tokens: 10,
        messages: [
          {
            role: 'user',
            content: 'ping'
          }
        ]
      }));
      return true;
    } catch (error) {
      console.warn('[ClaudeProvider] Health check failed:', error.message);
      return false;
    }
  }

  /**
   * Claude's domain expertise scores
   * @override
   */
  getQualityScore(domain) {
    const scores = {
      'security-god': 10,      // Best-in-class security analysis
      'performance-god': 8,    // Very good at performance reasoning
      'test-god': 9,           // Excellent test generation
      'refactoring-god': 9,    // Strong refactoring suggestions
      'documentation-god': 8   // Good documentation generation
    };
    return scores[domain] || 8;
  }

  /**
   * Enhanced system prompts for Claude (more detailed than base)
   * @override
   */
  getDomainSystemPrompt(domain) {
    const basePrompt = super.getDomainSystemPrompt(domain);

    // Add Claude-specific instructions
    const claudeEnhancements = `

IMPORTANT INSTRUCTIONS:
- Analyze the code deeply, understanding context and intent
- Only report genuine issues, not stylistic preferences
- Provide actionable suggestions with code examples when helpful
- Consider the broader architectural context
- Severity levels: HIGH (security/data loss risks), MEDIUM (bugs/performance issues), LOW (code quality/maintainability)
- Return ONLY valid JSON, no additional text`;

    return basePrompt + claudeEnhancements;
  }
}

module.exports = ClaudeProvider;
