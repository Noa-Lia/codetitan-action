/**
 * Confidence Scoring System
 *
 * Advanced confidence calculation for automated fixes.
 * Considers multiple factors including complexity, context, and pattern matching.
 */

class ConfidenceScorer {
  constructor() {
    // Confidence weights for different factors
    this.weights = {
      patternMatch: 0.30,      // How well the pattern matches
      complexity: 0.25,        // Code complexity in the area
      context: 0.20,           // Surrounding code context
      codeQuality: 0.15,       // Overall code quality
      fixHistory: 0.10         // Success rate of similar fixes
    };

    // Thresholds
    this.thresholds = {
      high: 0.90,              // 90%+ = High confidence
      medium: 0.75,            // 75-90% = Medium confidence
      low: 0.60                // 60-75% = Low confidence
    };
  }

  /**
   * Calculate overall confidence score for a fix
   * @param {Object} fix - The proposed fix
   * @param {Object} context - Additional context
   * @returns {Object} Confidence score and breakdown
   */
  calculateConfidence(fix, context = {}) {
    const scores = {
      patternMatch: this.scorePatternMatch(fix),
      complexity: this.scoreComplexity(fix, context),
      context: this.scoreContext(fix, context),
      codeQuality: this.scoreCodeQuality(fix, context),
      fixHistory: this.scoreFixHistory(fix, context)
    };

    // Calculate weighted average
    const confidence = Object.entries(scores).reduce((total, [key, score]) => {
      return total + (score * this.weights[key]);
    }, 0);

    // Determine confidence level
    let level = 'low';
    if (confidence >= this.thresholds.high) {
      level = 'high';
    } else if (confidence >= this.thresholds.medium) {
      level = 'medium';
    }

    return {
      score: confidence,
      level,
      breakdown: scores,
      recommendation: this.getRecommendation(confidence, level)
    };
  }

  /**
   * Score pattern matching accuracy
   * @param {Object} fix - The proposed fix
   * @returns {number} Score 0-1
   */
  scorePatternMatch(fix) {
    let score = 0.5; // Base score

    // Check if we have an exact pattern match
    if (fix.patternMatch === 'exact') {
      score = 1.0;
    } else if (fix.patternMatch === 'partial') {
      score = 0.7;
    } else if (fix.patternMatch === 'fuzzy') {
      score = 0.5;
    }

    // Adjust based on number of matches
    if (fix.matchCount === 1) {
      score *= 1.0; // Perfect single match
    } else if (fix.matchCount > 1 && fix.matchCount <= 3) {
      score *= 0.9; // Few matches is good
    } else if (fix.matchCount > 3) {
      score *= 0.7; // Many matches may indicate pattern too broad
    }

    return Math.min(1.0, score);
  }

  /**
   * Score code complexity in the fix area
   * @param {Object} fix - The proposed fix
   * @param {Object} context - Additional context
   * @returns {number} Score 0-1
   */
  scoreComplexity(fix, context) {
    // Lower complexity = higher confidence
    const complexity = context.complexity || this.analyzeComplexity(fix);

    if (complexity <= 5) {
      return 1.0; // Very simple code
    } else if (complexity <= 10) {
      return 0.8; // Simple code
    } else if (complexity <= 15) {
      return 0.6; // Moderate complexity
    } else if (complexity <= 20) {
      return 0.4; // Complex code
    } else {
      return 0.2; // Very complex code
    }
  }

  /**
   * Analyze code complexity
   * @param {Object} fix - The proposed fix
   * @returns {number} Complexity score
   */
  analyzeComplexity(fix) {
    if (!fix.code) return 5;

    let complexity = 0;

    // Count control flow statements
    complexity += (fix.code.match(/if|else|while|for|switch|case/g) || []).length * 2;

    // Count function calls
    complexity += (fix.code.match(/\w+\(/g) || []).length;

    // Count logical operators
    complexity += (fix.code.match(/&&|\|\||!/g) || []).length;

    // Count nested blocks (estimate)
    const openBraces = (fix.code.match(/{/g) || []).length;
    complexity += openBraces;

    return complexity;
  }

  /**
   * Score surrounding code context
   * @param {Object} fix - The proposed fix
   * @param {Object} context - Additional context
   * @returns {number} Score 0-1
   */
  scoreContext(fix, context) {
    let score = 0.5; // Base score

    // Check if context is consistent
    if (context.fileType) {
      const expectedTypes = fix.expectedFileTypes || ['.js', '.ts', '.jsx', '.tsx'];
      if (expectedTypes.includes(context.fileType)) {
        score += 0.2;
      }
    }

    // Check if similar patterns exist nearby
    if (context.similarPatternsNearby > 0) {
      score += 0.2; // Consistent with nearby code
    }

    // Check if fix aligns with coding style
    if (context.styleConsistent !== false) {
      score += 0.1;
    }

    return Math.min(1.0, score);
  }

  /**
   * Score overall code quality
   * @param {Object} fix - The proposed fix
   * @param {Object} context - Additional context
   * @returns {number} Score 0-1
   */
  scoreCodeQuality(fix, context) {
    let score = 0.7; // Assume decent quality by default

    // Penalize if code has many other issues
    if (context.otherIssues) {
      const issueCount = context.otherIssues.length;
      if (issueCount > 10) {
        score -= 0.3;
      } else if (issueCount > 5) {
        score -= 0.2;
      } else if (issueCount > 2) {
        score -= 0.1;
      }
    }

    // Bonus for good practices
    if (context.hasTests) {
      score += 0.1;
    }
    if (context.hasDocumentation) {
      score += 0.1;
    }

    return Math.max(0, Math.min(1.0, score));
  }

  /**
   * Score based on historical fix success
   * @param {Object} fix - The proposed fix
   * @param {Object} context - Additional context
   * @returns {number} Score 0-1
   */
  scoreFixHistory(fix, context) {
    // If we have historical data, use it
    if (context.fixHistory) {
      const { successful, total } = context.fixHistory;
      return total > 0 ? successful / total : 0.7;
    }

    // Default scores based on fix type
    const defaultScores = {
      'SYNC_IO': 0.9,           // Usually safe
      'HARDCODED_SECRET': 0.85,  // Safe to flag
      'COMMAND_EXEC': 0.8,       // Usually straightforward
      'SQL_INJECTION': 0.75,     // Needs care
      'XSS': 0.75,              // Needs care
      'MISSING_DOCS': 0.95,      // Very safe
      'MAGIC_NUMBER': 0.7        // Context-dependent
    };

    return defaultScores[fix.category] || 0.7;
  }

  /**
   * Get recommendation based on confidence
   * @param {number} confidence - Confidence score
   * @param {string} level - Confidence level
   * @returns {string} Recommendation
   */
  getRecommendation(confidence, level) {
    if (level === 'high') {
      return 'AUTO_APPLY - High confidence, safe to apply automatically';
    } else if (level === 'medium') {
      return 'REVIEW - Medium confidence, review before applying';
    } else {
      return 'MANUAL - Low confidence, manual review required';
    }
  }

  /**
   * Should fix be auto-applied?
   * @param {number} confidence - Confidence score
   * @param {number} threshold - Minimum threshold (default 0.90)
   * @returns {boolean} Whether to auto-apply
   */
  shouldAutoApply(confidence, threshold = 0.90) {
    return confidence >= threshold;
  }

  /**
   * Adjust confidence based on runtime factors
   * @param {number} baseConfidence - Base confidence score
   * @param {Object} factors - Runtime factors
   * @returns {number} Adjusted confidence
   */
  adjustConfidence(baseConfidence, factors = {}) {
    let adjusted = baseConfidence;

    // Reduce confidence for edge cases
    if (factors.edgeCase) {
      adjusted *= 0.8;
    }

    // Reduce confidence if similar fixes failed recently
    if (factors.recentFailures > 2) {
      adjusted *= 0.7;
    }

    // Increase confidence if tests pass
    if (factors.testsPassed) {
      adjusted *= 1.1;
    }

    // Increase confidence if verified by AST
    if (factors.astVerified) {
      adjusted *= 1.05;
    }

    return Math.min(1.0, adjusted);
  }
}

module.exports = ConfidenceScorer;
