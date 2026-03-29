/**
 * GPT5CodexProvider - OpenAI GPT-5.4 integration
 * Best for: Code analysis, refactoring, test generation, documentation
 * 1.05M token context window with advanced coding and agentic capabilities
 * Specialized for software engineering tasks with superior code understanding
 *
 * @module ai-providers/gpt5-codex
 */

const AIProvider = require('./base');

class GPT5CodexProvider extends AIProvider {
  constructor(config = {}) {
    const defaultModel = config.model || 'gpt-5.4';

    // Model-specific pricing (as of March 2026)
    const modelPricing = {
      'gpt-5.4': {
        input: 0.0000025,   // $2.50 per M tokens
        output: 0.000010,   // $10.00 per M tokens
        cached: 0.00000125,
        contextWindow: 1050000
      },
      'gpt-5.4-mini': {
        input: 0.00000015,  // $0.15 per M tokens
        output: 0.0000006,  // $0.60 per M tokens
        cached: 0.000000075,
        contextWindow: 400000
      },
      'gpt-5.3-codex': {
        input: 0.000002,    // $2.00 per M tokens
        output: 0.000008,   // $8.00 per M tokens
        cached: 0.000001,
        contextWindow: 128000
      },
      'gpt-4o': {
        input: 0.0000025,
        output: 0.000010,
        cached: 0.00000125,
        contextWindow: 128000
      }
    };

    const pricing = modelPricing[defaultModel] || modelPricing['gpt-5.4'];

    super({
      name: 'codex',
      model: defaultModel,
      apiKey: config.apiKey || process.env.OPENAI_API_KEY,
      costPerInputToken: pricing.input,
      costPerOutputToken: pricing.output,
      costPerCachedToken: pricing.cached,
      maxTokens: config.maxTokens || 4000,
      timeout: config.timeout || 60000,
      contextWindow: pricing.contextWindow,
      ...config
    });

    // Initialize OpenAI client if available
    this.client = null;
    if (this.enabled) {
      try {
        const OpenAI = require('openai');
        this.client = new OpenAI({
          apiKey: this.apiKey
        });
      } catch (error) {
        console.warn('[GPT5CodexProvider] openai package not installed. Run: npm install openai');
        this.enabled = false;
      }
    }
  }

  /**
   * Analyze code using GPT-5.4 with Structured Outputs
   * Most capable OpenAI model for software engineering tasks
   * @override
   */
  async analyze(domain, filePath, content, projectRoot, options = {}) {
    if (!this.enabled || !this.client) {
      throw new Error('GPT5CodexProvider is not available. Check API key and dependencies.');
    }

    const start = Date.now();

    try {
      const systemPrompt = this.getDomainSystemPrompt(domain);
      const userPrompt = this.buildPrompt(domain, filePath, content);

      const response = await this.client.chat.completions.create({
        model: this.model,
        messages: [
          {
            role: 'system',
            content: systemPrompt
          },
          {
            role: 'user',
            content: userPrompt
          }
        ],
        max_tokens: this.maxTokens,
        temperature: 0.2, // Low temperature for consistent analysis
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'code_analysis',
            strict: true,
            schema: {
              type: 'object',
              properties: {
                issues: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      category: { type: 'string' },
                      severity: {
                        type: 'string',
                        enum: ['HIGH', 'MEDIUM', 'LOW']
                      },
                      line: { type: 'number' },
                      message: { type: 'string' },
                      suggestion: { type: 'string' }
                    },
                    required: ['category', 'severity', 'line', 'message', 'suggestion'],
                    additionalProperties: false
                  }
                }
              },
              required: ['issues'],
              additionalProperties: false
            }
          }
        }
      });

      // Parse response (already JSON with structured outputs)
      const rawResponse = response.choices[0]?.message?.content || '{"issues": []}';
      const parsed = JSON.parse(rawResponse);
      const issues = parsed.issues || [];

      // Filter and validate issues
      const validIssues = issues.filter(issue => this.validateIssue(issue));

      return {
        issues: validIssues,
        metadata: {
          provider: this.name,
          model: this.model,
          tokensUsed: {
            input: response.usage.prompt_tokens || 0,
            output: response.usage.completion_tokens || 0,
            cached: response.usage.prompt_tokens_details?.cached_tokens || 0
          },
          costUSD: this.calculateActualCost(response.usage),
          duration: Date.now() - start,
          confidence: 0.94, // GPT-5.4 is highly accurate for code
          finishReason: response.choices[0]?.finish_reason
        }
      };
    } catch (error) {
      console.error(`[GPT5CodexProvider] Analysis failed:`, error);

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
    const inputTokens = usage.prompt_tokens || 0;
    const outputTokens = usage.completion_tokens || 0;
    const cachedTokens = usage.prompt_tokens_details?.cached_tokens || 0;

    const inputCost = ((inputTokens - cachedTokens) * this.costPerInputToken);
    const cachedCost = (cachedTokens * this.costPerCachedToken);
    const outputCost = (outputTokens * this.costPerOutputToken);

    return inputCost + cachedCost + outputCost;
  }

  /**
   * Check if OpenAI API is available
   * @override
   */
  async isAvailable() {
    if (!this.enabled || !this.client) return false;

    try {
      // Simple health check using models endpoint
      await this.client.models.retrieve(this.model);
      return true;
    } catch (error) {
      console.warn('[GPT5CodexProvider] Health check failed:', error.message);
      return false;
    }
  }

  /**
   * GPT-5.4 domain expertise scores
   * @override
   */
  getQualityScore(domain) {
    const scores = {
      'security-god': 8,       // Good security analysis
      'performance-god': 9,    // Excellent performance optimization
      'test-god': 10,          // Best test generation (76.3% SWE-bench)
      'refactoring-god': 10,   // Best refactoring (51.3% benchmark)
      'documentation-god': 10  // Excellent documentation generation
    };
    return scores[domain] || 9;
  }

  /**
   * Enhanced system prompts for GPT-5.4
   * @override
   */
  getDomainSystemPrompt(domain) {
    const basePrompt = super.getDomainSystemPrompt(domain);

    // Add GPT-5-Codex specific instructions
    const codexEnhancements = `

IMPORTANT INSTRUCTIONS:
- You are GPT-5.4, optimized for long-running, agentic coding tasks
- Analyze code with deep understanding of patterns, anti-patterns, and best practices
- Focus on actionable, specific findings with line numbers
- Provide concrete code suggestions in your "suggestion" field
- Only report genuine issues that would improve code quality/security/performance
- Severity: HIGH = security/data loss, MEDIUM = bugs/performance, LOW = quality/maintainability
- Return ONLY valid JSON matching the schema, no additional commentary`;

    return basePrompt + codexEnhancements;
  }
}

module.exports = GPT5CodexProvider;
