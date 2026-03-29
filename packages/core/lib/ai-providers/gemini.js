/**
 * GeminiProvider - Google Gemini 2.5 Pro / 3.1 Pro integration
 * Best for: Performance optimization, large codebase analysis, multi-modal understanding
 * Gemini 2.5 Pro: 2M token context window, stable, cost-effective
 * Gemini 3.1 Pro: 2M token context, preview, advanced reasoning
 *
 * @module ai-providers/gemini
 */

const AIProvider = require('./base');

class GeminiProvider extends AIProvider {
  constructor(config = {}) {
    // Model selection: Default to stable Gemini 2.5 Pro
    const defaultModel = config.model || 'gemini-2.5-pro';

    // Model-specific pricing (as of March 2026)
    const modelPricing = {
      // Gemini 3.1 Pro Preview (latest, Feb 2026)
      'gemini-3.1-pro-preview': {
        input: 0.000002,     // $2.00 per M tokens
        output: 0.000012,    // $12.00 per M tokens
        cached: 0.0000005,
        contextWindow: 2000000
      },
      // Gemini 2.5 Pro (Stable, default)
      'gemini-2.5-pro': {
        input: 0.00000125,   // $1.25 per M tokens
        output: 0.00001,     // $10.00 per M tokens
        cached: 0.0000003125,
        contextWindow: 2000000
      },
      // Gemini 2.5 Flash (fast, cost-effective)
      'gemini-2.5-flash': {
        input: 0.0000003,    // $0.30 per M tokens
        output: 0.0000025,   // $2.50 per M tokens
        cached: 0.0000000375,
        contextWindow: 1000000
      },
      // Gemini 2.5 Flash-Lite (fastest, cheapest)
      'gemini-2.5-flash-lite': {
        input: 0.0000001,    // $0.10 per M tokens
        output: 0.0000004,   // $0.40 per M tokens
        cached: 0.000000025,
        contextWindow: 1000000
      },
      // Gemini 1.5 Pro (legacy)
      'gemini-1.5-pro': {
        input: 0.00000125,
        output: 0.000005,
        cached: 0.0000003125,
        contextWindow: 2000000
      }
    };

    const pricing = modelPricing[defaultModel] || modelPricing['gemini-2.5-pro'];

    super({
      name: 'gemini',
      model: defaultModel,
      apiKey: config.apiKey || process.env.GOOGLE_AI_API_KEY,
      costPerInputToken: pricing.input,
      costPerOutputToken: pricing.output,
      costPerCachedToken: pricing.cached,
      maxTokens: config.maxTokens || 8000,
      timeout: config.timeout || 60000,
      contextWindow: pricing.contextWindow,
      ...config
    });

    this.fallbackModel = config.fallbackModel || 'gemini-2.5-flash';

    // Initialize Gemini client if available
    this.client = null;
    if (this.enabled) {
      try {
        const { GoogleGenerativeAI } = require('@google/generative-ai');
        this.genAI = new GoogleGenerativeAI(this.apiKey);
        this.client = this.genAI.getGenerativeModel({
          model: this.model,
          generationConfig: {
            responseMimeType: 'application/json',
            temperature: 0.2,
            maxOutputTokens: this.maxTokens
          }
        });
      } catch (error) {
        console.warn('[GeminiProvider] @google/generative-ai not installed. Run: npm install @google/generative-ai');
        this.enabled = false;
      }
    }
  }

  /**
   * Analyze code using Gemini 2.5 Pro
   * @override
   */
  async analyze(domain, filePath, content, projectRoot, options = {}) {
    if (!this.enabled || !this.client) {
      throw new Error('GeminiProvider is not available. Check API key and dependencies.');
    }

    const start = Date.now();

    try {
      const systemPrompt = this.getDomainSystemPrompt(domain);
      const userPrompt = this.buildPrompt(domain, filePath, content);

      // Combine system and user prompts for Gemini
      const fullPrompt = `${systemPrompt}\n\n${userPrompt}`;

      let result;
      let activeModel = this.model;

      try {
        result = await this.client.generateContent(fullPrompt);
      } catch (error) {
        if (this.fallbackModel && this.fallbackModel !== this.model) {
          console.warn(`[GeminiProvider] Primary model ${this.model} failed: ${error.message}. Retrying with fallback: ${this.fallbackModel}`);
          try {
            activeModel = this.fallbackModel;
            const fallbackClient = this.genAI.getGenerativeModel({
              model: this.fallbackModel,
              generationConfig: {
                responseMimeType: 'application/json',
                temperature: 0.2,
                maxOutputTokens: this.maxTokens
              }
            });
            result = await fallbackClient.generateContent(fullPrompt);
          } catch (fallbackError) {
            console.error(`[GeminiProvider] Fallback model ${this.fallbackModel} also failed:`, fallbackError);
            throw error; // Throw original error
          }
        } else {
          throw error;
        }
      }

      const response = result.response;

      // Extract text and parse JSON
      const rawResponse = response.text() || '{"issues": []}';
      const parsed = JSON.parse(rawResponse);
      const issues = parsed.issues || [];

      // Filter and validate issues
      const validIssues = issues.filter(issue => this.validateIssue(issue));

      // Extract usage metadata
      const usageMetadata = response.usageMetadata || {};

      return {
        issues: validIssues,
        metadata: {
          provider: this.name,
          model: activeModel,
          tokensUsed: {
            input: usageMetadata.promptTokenCount || 0,
            output: usageMetadata.candidatesTokenCount || 0,
            cached: usageMetadata.cachedContentTokenCount || 0
          },
          costUSD: this.calculateActualCost(usageMetadata),
          duration: Date.now() - start,
          confidence: 0.90, // Gemini 2.5 Pro is fast and accurate
          finishReason: response.candidates?.[0]?.finishReason
        }
      };
    } catch (error) {
      console.error(`[GeminiProvider] Analysis failed:`, error);

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
   * Calculate actual cost from usage metadata
   */
  calculateActualCost(usageMetadata) {
    const inputTokens = usageMetadata.promptTokenCount || 0;
    const outputTokens = usageMetadata.candidatesTokenCount || 0;
    const cachedTokens = usageMetadata.cachedContentTokenCount || 0;

    const inputCost = ((inputTokens - cachedTokens) * this.costPerInputToken);
    const cachedCost = (cachedTokens * this.costPerCachedToken);
    const outputCost = (outputTokens * this.costPerOutputToken);

    return inputCost + cachedCost + outputCost;
  }

  /**
   * Check if Gemini API is available
   * @override
   */
  async isAvailable() {
    if (!this.enabled || !this.client) return false;

    try {
      // Simple health check with minimal prompt
      const result = await this.client.generateContent('ping');
      return !!result.response;
    } catch (error) {
      console.warn('[GeminiProvider] Health check failed:', error.message);
      return false;
    }
  }

  /**
   * Gemini's domain expertise scores
   * @override
   */
  getQualityScore(domain) {
    const scores = {
      'security-god': 7,       // Decent security analysis
      'performance-god': 10,   // Excellent performance optimization (fastest model)
      'test-god': 8,           // Good test generation
      'refactoring-god': 8,    // Good refactoring suggestions
      'documentation-god': 7   // Decent documentation generation
    };
    return scores[domain] || 8;
  }

  /**
   * Enhanced system prompts for Gemini
   * @override
   */
  getDomainSystemPrompt(domain) {
    const basePrompt = super.getDomainSystemPrompt(domain);

    // Add Gemini-specific instructions
    const geminiEnhancements = `

IMPORTANT INSTRUCTIONS:
- You are Gemini 2.5 Pro, optimized for fast, cost-effective code analysis
- Analyze code efficiently, focusing on high-impact findings
- Provide actionable suggestions with specific line numbers
- Only report genuine issues, avoid false positives
- Severity: HIGH = critical security/data loss, MEDIUM = bugs/performance, LOW = code quality
- Return ONLY valid JSON matching the required structure
- No additional commentary outside the JSON response`;

    return basePrompt + geminiEnhancements;
  }
}

module.exports = GeminiProvider;
