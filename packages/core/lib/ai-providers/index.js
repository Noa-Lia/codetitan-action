/**
 * AI Providers - Multi-AI code analysis architecture
 * Exports all providers and the manager for easy integration
 *
 * @module ai-providers
 */

const AIProvider = require('./base');
const HeuristicProvider = require('./heuristic');
const ClaudeProvider = require('./claude');
const GPT5CodexProvider = require('./gpt5-codex');
const GeminiProvider = require('./gemini');
const AIProviderManager = require('./manager');

// Phase 6 Advanced Features
const EnsembleAnalyzer = require('./ensemble');
const ConfidenceScorer = require('./confidence');

module.exports = {
  // Base class
  AIProvider,

  // Concrete providers
  HeuristicProvider,
  ClaudeProvider,
  GPT5CodexProvider,
  GeminiProvider,

  // Manager (primary interface)
  AIProviderManager,

  // Phase 6 Advanced Features
  EnsembleAnalyzer,
  ConfidenceScorer,

  /**
   * Create and configure AI provider manager
   * @param {Object} config - Configuration options
   * @returns {AIProviderManager}
   */
  createManager(config = {}) {
    return new AIProviderManager(config);
  }
};
