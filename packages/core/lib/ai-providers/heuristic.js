/**
 * HeuristicProvider - Wraps existing regex-based analysis
 * This provider is always available (no API key needed) and serves as fallback
 *
 * @module ai-providers/heuristic
 */

const AIProvider = require('./base');
const { analyzeDomain: analyzeWithHeuristics } = require('../domain-analyzers');

class HeuristicProvider extends AIProvider {
  constructor(config = {}) {
    super({
      name: 'heuristic',
      model: 'regex-v1',
      apiKey: 'local', // Always available
      costPerInputToken: 0,
      costPerOutputToken: 0,
      ...config
    });
    this.enabled = true; // Always enabled
  }

  /**
   * Analyze code using deterministic regex patterns
   * @override
   */
  async analyze(domain, filePath, content, projectRoot, options = {}) {
    const start = Date.now();

    try {
      // Call existing heuristic analyzer
      const result = analyzeWithHeuristics(domain, filePath, content, projectRoot);

      // Transform to standardized format
      return {
        issues: result.issues.map(issue => ({
          category: issue.category,
          severity: issue.severity,
          line: issue.line,
          message: issue.message,
          suggestion: this.generateSuggestion(issue),
          impact: issue.impact,
          snippet: issue.snippet
        })),
        metadata: {
          provider: this.name,
          model: this.model,
          tokensUsed: {
            input: 0,
            output: 0,
            cached: 0
          },
          costUSD: 0,
          duration: Date.now() - start,
          confidence: 0.7, // Heuristics have moderate confidence
          linesAnalyzed: result.linesAnalyzed,
          ...result.metadata
        }
      };
    } catch (error) {
      console.error(`[HeuristicProvider] Analysis failed:`, error);
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
   * Always available (no API needed)
   * @override
   */
  async isAvailable() {
    return true;
  }

  /**
   * Heuristics have domain-specific quality scores
   * @override
   */
  getQualityScore(domain) {
    // Heuristics are decent but not as comprehensive as AI
    const scores = {
      'security-god': 6,      // Good at detecting obvious patterns
      'performance-god': 5,   // Can catch common anti-patterns
      'test-god': 4,          // Limited to obvious gaps
      'refactoring-god': 6,   // Good at metrics-based detection
      'documentation-god': 3  // Limited understanding of context
    };
    return scores[domain] || 4;
  }

  /**
   * Generate actionable suggestion for a heuristic finding
   */
  generateSuggestion(issue) {
    const suggestions = {
      'EVAL_USAGE': 'Replace dynamic evaluation with JSON.parse() for data, or refactor to use explicit logic instead of runtime code execution.',
      'FUNCTION_CONSTRUCTOR': 'Avoid dynamic function construction. Use explicit function definitions or safe alternatives.',
      'COMMAND_EXEC': 'Validate all inputs before executing commands. Use libraries like shell-escape or safer alternatives like execa with shell: false.',
      'INSECURE_HTTP': 'Replace http:// with https:// in all external requests to encrypt data in transit.',
      'HARDCODED_SECRET': 'Move credentials to environment variables (process.env.API_KEY) and use a secrets manager in production.',
      'DISABLE_LINT_SECURITY': 'Review the security implications before disabling lint rules. Add a comment explaining why it\'s safe.',
      'WEAK_HASH': 'Replace MD5 with SHA-256 or bcrypt for cryptographic purposes.',
// TODO: Fix SYNC_IO - Synchronous fs operation blocks the event loop. Consider async alternatives.
      'SYNC_IO': 'Replace fs.readFileSync with fs.promises.readFile or the async fs methods to avoid blocking the event loop.',
      'SYNC_FILE_PARSE': 'Use fs.promises.readFile followed by JSON.parse, or stream large files instead of loading them entirely into memory.',
      'AWAIT_IN_LOOP': 'Batch async operations using Promise.all() to run them in parallel instead of sequentially.',
      'ASYNC_TIMEOUT': 'Wrap async setTimeout logic in try-catch and ensure errors are properly logged or handled.',
      'NESTED_LOOPS': 'Review algorithm complexity. Consider using Map/Set for O(1) lookups or optimizing with caching.',
      'FOCUSED_TEST': 'Remove .only() from test suites to ensure all tests run in CI.',
      'TODO_TESTS': 'Implement the missing tests indicated by the TODO comment.',
      'MISSING_TESTS': 'Create a companion test file (e.g., filename.test.js) covering exported functions.',
      'FILE_TOO_LONG': 'Split this file into multiple focused modules using Single Responsibility Principle.',
      'LONG_LINE': 'Break long lines into multiple lines for better readability. Consider extracting complex expressions into variables.',
      'LONG_FUNCTION': 'Extract parts of this function into smaller, focused helper functions.',
      'POOR_DOCUMENTATION': 'Add JSDoc comments explaining the module\'s purpose, parameters, and return values.',
      'MISSING_HEADER': 'Add a brief comment at the top explaining what this module does and how to use it.'
    };

    return suggestions[issue.category] || 'Review and address this issue based on best practices for your domain.';
  }

  /**
   * Cost estimation (always free)
   * @override
   */
  estimateCost(inputTokens, estimatedOutputTokens = 500, cachedTokens = 0) {
    return 0;
  }
}

module.exports = HeuristicProvider;
