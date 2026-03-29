/**
 * Base abstraction for all AI providers in CodeTitan
 * Implements the Strategy pattern for pluggable AI analysis
 *
 * @module ai-providers/base
 */

class AIProvider {
  /**
   * @param {Object} config - Provider configuration
   * @param {string} config.name - Provider name (e.g., 'claude', 'gpt-5-codex')
   * @param {string} config.model - Model identifier
   * @param {string} config.apiKey - API key for authentication
   * @param {number} config.costPerInputToken - Cost per million input tokens
   * @param {number} config.costPerOutputToken - Cost per million output tokens
   * @param {number} [config.costPerCachedToken] - Cost per million cached tokens
   * @param {number} [config.maxTokens=4000] - Max output tokens
   * @param {number} [config.timeout=60000] - Request timeout in ms
   */
  constructor(config) {
    this.name = config.name;
    this.model = config.model;
    this.apiKey = config.apiKey;
    this.costPerInputToken = config.costPerInputToken;
    this.costPerOutputToken = config.costPerOutputToken;
    this.costPerCachedToken = config.costPerCachedToken || config.costPerInputToken;
    this.maxTokens = config.maxTokens || 4000;
    this.timeout = config.timeout || 60000;
    this.enabled = !!config.apiKey;
  }

  /**
   * Analyze code using this AI provider
   *
   * @param {string} domain - Analysis domain (e.g., 'security-god', 'performance-god')
   * @param {string} filePath - Path to file being analyzed
   * @param {string} content - File content
   * @param {string} projectRoot - Project root directory
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Analysis result with findings
   *
   * Result format:
   * {
   *   issues: Array<{
   *     category: string,
   *     severity: string,
   *     line: number,
   *     message: string,
   *     suggestion: string
   *   }>,
   *   metadata: {
   *     provider: string,
   *     model: string,
   *     tokensUsed: { input: number, output: number, cached: number },
   *     costUSD: number,
   *     duration: number,
   *     confidence: number (0-1)
   *   }
   * }
   */
  async analyze(domain, filePath, content, projectRoot, options = {}) {
    throw new Error(`analyze() must be implemented by ${this.constructor.name}`);
  }

  /**
   * Check if provider is available and healthy
   * @returns {Promise<boolean>}
   */
  async isAvailable() {
    if (!this.enabled) return false;
    if (!this.apiKey) return false;

    try {
      // Subclasses can override with actual health check
      return true;
    } catch (error) {
      console.warn(`[${this.name}] Health check failed:`, error.message);
      return false;
    }
  }

  /**
   * Estimate cost for a given analysis
   *
   * @param {number} inputTokens - Estimated input tokens
   * @param {number} [estimatedOutputTokens=500] - Estimated output tokens
   * @param {number} [cachedTokens=0] - Number of cached tokens
   * @returns {number} Cost in USD
   */
  estimateCost(inputTokens, estimatedOutputTokens = 500, cachedTokens = 0) {
    const inputCost = ((inputTokens - cachedTokens) * this.costPerInputToken) / 1_000_000;
    const cachedCost = (cachedTokens * this.costPerCachedToken) / 1_000_000;
    const outputCost = (estimatedOutputTokens * this.costPerOutputToken) / 1_000_000;

    return inputCost + cachedCost + outputCost;
  }

  /**
   * Get quality score for a specific domain (0-10)
   * Override in subclasses to specify domain expertise
   *
   * @param {string} domain - Analysis domain
   * @returns {number} Quality score 0-10
   */
  getQualityScore(domain) {
    // Default: average quality across all domains
    return 5;
  }

  /**
   * Build system prompt for a given domain
   *
   * @param {string} domain - Analysis domain
   * @returns {string} System prompt
   */
  getDomainSystemPrompt(domain) {
    const prompts = {
      'security-god': `You are a world-class security expert analyzing code for vulnerabilities.
Focus on OWASP Top 10 vulnerabilities:
- SQL Injection
- XSS (Cross-Site Scripting)
- Authentication/Authorization flaws
- Sensitive data exposure
- Insecure deserialization
- Command injection
- Path traversal
- CSRF

Return findings as a JSON array with this exact structure:
{
  "issues": [
    {
      "category": "SQL_INJECTION",
      "severity": "HIGH",
      "line": 42,
      "message": "User input directly in SQL query without parameterization",
      "suggestion": "Use parameterized queries or ORM methods to prevent SQL injection"
    }
  ]
}`,

      'performance-god': `You are a performance optimization expert analyzing code for bottlenecks.
Focus on:
- N+1 query problems
- Synchronous I/O in async contexts
- Memory leaks (unclosed connections, event listeners)
- Inefficient algorithms (O(n²) where O(n) possible)
- Unnecessary computations in loops
- Missing indexes for database queries
- Large bundle sizes, missing lazy loading

Return findings as a JSON array with this exact structure:
{
  "issues": [
    {
      "category": "SYNC_IO",
      "severity": "MEDIUM",
      "line": 15,
      "message": "Synchronous file read blocks event loop",
// TODO: Fix SYNC_IO - Synchronous fs operation blocks the event loop. Consider async alternatives.
      "suggestion": "Replace fs.readFileSync with fs.promises.readFile"
    }
  ]
}`,

      'test-god': `You are a testing expert analyzing code coverage and test quality.
Focus on:
- Missing test coverage for critical paths
- Weak or meaningless assertions
- Missing edge case tests
- Untested error handling
- Integration test gaps
- Missing performance/load tests
- Test flakiness indicators

Return findings as a JSON array with this exact structure:
{
  "issues": [
    {
      "category": "MISSING_TESTS",
      "severity": "MEDIUM",
      "line": 50,
      "message": "Complex authentication logic has no test coverage",
      "suggestion": "Add unit tests covering success, failure, and edge cases"
    }
  ]
}`,

      'refactoring-god': `You are a code quality expert analyzing code for maintainability issues.
Focus on:
- SOLID principle violations
- Code duplication (DRY violations)
- Long methods/functions (>50 lines)
- High cyclomatic complexity
- God objects/classes
- Feature envy
- Inappropriate intimacy
- Dead code

Return findings as a JSON array with this exact structure:
{
  "issues": [
    {
      "category": "LONG_METHOD",
      "severity": "LOW",
      "line": 100,
      "message": "Method has 120 lines and handles 5 different responsibilities",
      "suggestion": "Extract to separate methods: validateInput(), processData(), saveResults()"
    }
  ]
}`,

      'documentation-god': `You are a documentation expert analyzing code clarity and documentation quality.
Focus on:
- Missing JSDoc/docstrings for public APIs
- Unclear variable/function names
- Missing README sections
- Outdated documentation
- Missing usage examples
- Undocumented complex logic
- Missing type definitions

Return findings as a JSON array with this exact structure:
{
  "issues": [
    {
      "category": "MISSING_DOCS",
      "severity": "LOW",
      "line": 25,
      "message": "Public API method lacks JSDoc documentation",
      "suggestion": "Add JSDoc with @param, @returns, and usage example"
    }
  ]
}`
    };

    return prompts[domain] || prompts['security-god'];
  }

  /**
   * Build analysis prompt for file
   *
   * @param {string} domain - Analysis domain
   * @param {string} filePath - File path
   * @param {string} content - File content
   * @returns {string} User prompt
   */
  buildPrompt(domain, filePath, content) {
    const language = this.detectLanguage(filePath);

    return `Analyze this ${language} file for ${domain} issues:

File: ${filePath}
\`\`\`${language}
${content}
\`\`\`

Return ONLY valid JSON with findings. If no issues found, return {"issues": []}.`;
  }

  /**
   * Detect programming language from file path
   * @param {string} filePath - File path
   * @returns {string} Language identifier
   */
  detectLanguage(filePath) {
    const ext = filePath.split('.').pop().toLowerCase();
    const langMap = {
      js: 'javascript',
      ts: 'typescript',
      jsx: 'javascript',
      tsx: 'typescript',
      py: 'python',
      rb: 'ruby',
      go: 'go',
      java: 'java',
      cpp: 'cpp',
      c: 'c',
      rs: 'rust',
      php: 'php',
      cs: 'csharp'
    };
    return langMap[ext] || 'code';
  }

  /**
   * Parse and validate AI response
   * @param {string} response - Raw AI response
   * @returns {Array} Issues array
   */
  parseResponse(response) {
    try {
      // Try to parse as JSON
      const parsed = JSON.parse(response);

      if (Array.isArray(parsed)) {
        return parsed;
      }

      if (parsed.issues && Array.isArray(parsed.issues)) {
        return parsed.issues;
      }

      if (parsed.findings && Array.isArray(parsed.findings)) {
        return parsed.findings;
      }

      console.warn(`[${this.name}] Unexpected response format, returning empty array`);
      return [];
    } catch (error) {
      console.error(`[${this.name}] Failed to parse response:`, error.message);
      console.error('Response:', response.substring(0, 200));
      return [];
    }
  }

  /**
   * Validate issue object has required fields
   * @param {Object} issue - Issue to validate
   * @returns {boolean}
   */
  validateIssue(issue) {
    return !!(
      issue &&
      issue.category &&
      issue.severity &&
      issue.line &&
      issue.message
    );
  }
}

module.exports = AIProvider;
