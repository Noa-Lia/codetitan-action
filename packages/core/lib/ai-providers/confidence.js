/**
 * ConfidenceScorer - Advanced confidence scoring for AI findings
 *
 * Multi-factor confidence scoring system that evaluates:
 * - Provider agreement (ensemble consensus)
 * - Severity consistency
 * - Pattern strength (for heuristic findings)
 * - Historical accuracy (for providers)
 * - Code context signals
 *
 * Score range: 0-100 (higher = more confident)
 *
 * @module ai-providers/confidence
 */

class ConfidenceScorer {
  constructor(config = {}) {
    this.config = {
      // Weight factors for confidence calculation
      weights: {
        providerAgreement: 0.40,   // 40% - Multiple AIs agree
        severityConsistency: 0.15, // 15% - Severity matches pattern
        patternStrength: 0.20,     // 20% - Strong code pattern match
        historicalAccuracy: 0.15,  // 15% - Provider's past accuracy
        contextSignals: 0.10,      // 10% - Code context indicators
        ...config.weights
      },

      // Thresholds for confidence levels
      thresholds: {
        veryHigh: 90,  // 90-100: Very confident
        high: 75,      // 75-89: High confidence
        medium: 50,    // 50-74: Medium confidence
        low: 25,       // 25-49: Low confidence
        veryLow: 0     // 0-24: Very low confidence
      },

      // Historical accuracy tracking
      providerAccuracy: {
        'claude': 0.92,
        'gpt-5-codex': 0.89,
        'gemini': 0.85,
        'heuristic': 0.70,
        ...config.providerAccuracy
      },

      // History tracking configuration
      enableHistoryTracking: config.enableHistoryTracking !== false,
      runId: config.runId || null,
      projectId: config.projectId || null,

      ...config
    };

    // Track confidence scoring accuracy over time
    this.history = {
      totalScored: 0,
      truePositives: 0,
      falsePositives: 0,
      calibrationData: []
    };

    // Initialize confidence history tracker if enabled
    if (this.config.enableHistoryTracking) {
      try {
        const ConfidenceHistoryTracker = require('../confidence-history-tracker');
        this.historyTracker = new ConfidenceHistoryTracker({
          enableTracking: true,
          batchSize: 50,
          flushInterval: 30000
        });
      } catch (error) {
        console.warn('[ConfidenceScorer] Could not initialize history tracker:', error.message);
        this.historyTracker = null;
      }
    }
  }

  /**
   * Calculate confidence score for a finding
   *
   * @param {Object} finding - The finding to score
   * @param {Object} context - Additional context for scoring
   * @returns {Object} Confidence score and breakdown
   */
  async score(finding, context = {}) {
    const scores = {
      providerAgreement: this.scoreProviderAgreement(finding, context),
      severityConsistency: this.scoreSeverityConsistency(finding, context),
      patternStrength: this.scorePatternStrength(finding, context),
      historicalAccuracy: this.scoreHistoricalAccuracy(finding, context),
      contextSignals: this.scoreContextSignals(finding, context)
    };

    // Calculate weighted total
    const totalScore = Object.keys(scores).reduce((sum, factor) => {
      return sum + (scores[factor] * this.config.weights[factor]);
    }, 0);

    // Round to integer 0-100
    const confidenceScore = Math.round(Math.max(0, Math.min(100, totalScore)));

    // Determine confidence level
    const confidenceLevel = this.getConfidenceLevel(confidenceScore);

    // Build explanation
    const explanation = this.buildExplanation(scores, confidenceScore, confidenceLevel);

    // Track for calibration
    this.history.totalScored++;

    const result = {
      score: confidenceScore,
      level: confidenceLevel,
      breakdown: scores,
      explanation,
      uncertainty: this.calculateUncertainty(scores, confidenceScore)
    };

    // Track in database if enabled
    if (this.historyTracker && this.config.runId && this.config.projectId) {
      await this.historyTracker.trackScore({
        finding,
        runId: this.config.runId,
        projectId: this.config.projectId,
        confidenceResult: result,
        sourceProvider: finding.sourceProvider || context.sourceProvider || 'heuristic',
        supportingProviders: finding.supportingProviders || context.supportingProviders || [],
        algorithmVersion: 'v1.0'
      }).catch(err => {
        // Silent fail - don't break scoring if tracking fails
        if (this.config.verbose) {
          console.warn('[ConfidenceScorer] Tracking failed:', err.message);
        }
      });
    }

    return result;
  }

  /**
   * Score provider agreement (ensemble consensus)
   * Score: 0-100
   */
  scoreProviderAgreement(finding, context) {
    if (!finding.supportingProviders || finding.supportingProviders.length === 0) {
      // Single provider - use base score
      const provider = finding.sourceProvider || 'unknown';
      const baseAccuracy = this.config.providerAccuracy[provider] || 0.5;
      return baseAccuracy * 100;
    }

    // Multiple providers - use agreement rate
    if (finding.confidence !== undefined) {
      // Ensemble already calculated confidence
      return finding.confidence * 100;
    }

    // Calculate agreement based on provider count
    const providerCount = finding.supportingProviders.length;
    const totalProviders = context.totalProviders || 3;
    const agreementRate = providerCount / totalProviders;

    // Weight by provider quality
    const providerWeights = finding.supportingProviders.map(p =>
      this.config.providerAccuracy[p] || 0.5
    );
    const avgQuality = providerWeights.reduce((sum, w) => sum + w, 0) / providerWeights.length;

    return (agreementRate * 0.7 + avgQuality * 0.3) * 100;
  }

  /**
   * Score severity consistency
   * Checks if severity matches the category expectations
   */
  scoreSeverityConsistency(finding, context) {
    // Expected severity ranges for categories
    const expectedSeverity = {
      // Security
      'SQL_INJECTION': 'HIGH',
      'XSS': 'HIGH',
      'COMMAND_EXEC': 'HIGH',
      'PATH_TRAVERSAL': 'HIGH',
      'HARDCODED_SECRET': 'HIGH',
      'UNSAFE_DESERIALIZE': 'HIGH',
      'WEAK_CRYPTO': 'MEDIUM',
      'INSECURE_RANDOM': 'MEDIUM',
      'MISSING_AUTH': 'HIGH',
      'RATE_LIMIT_MISSING': 'MEDIUM',

      // Performance
      'SYNC_IO': 'MEDIUM',
      'N_PLUS_ONE_QUERY': 'HIGH',
      'INEFFICIENT_LOOP': 'MEDIUM',
      'MEMORY_LEAK': 'HIGH',
      'BLOCKING_CALL': 'MEDIUM',

      // Code Quality
      'MAGIC_NUMBER': 'LOW',
      'LONG_METHOD': 'MEDIUM',
      'COMPLEX_CONDITION': 'MEDIUM',
      'DUPLICATE_CODE': 'MEDIUM',
      'UNUSED_VARIABLE': 'LOW'
    };

    const expected = expectedSeverity[finding.category];
    const actual = finding.severity;

    if (!expected) {
      // Unknown category - neutral score
      return 50;
    }

    if (expected === actual) {
      // Perfect match
      return 100;
    }

    // Partial match (one level off)
    const severityOrder = ['LOW', 'MEDIUM', 'HIGH'];
    const expectedIdx = severityOrder.indexOf(expected);
    const actualIdx = severityOrder.indexOf(actual);

    const diff = Math.abs(expectedIdx - actualIdx);

    if (diff === 1) {
      return 70; // One level off
    } else {
      return 30; // Two levels off (suspicious)
    }
  }

  /**
   * Score pattern strength
   * For heuristic findings, how strong is the regex match?
   * For AI findings, how specific is the code snippet?
   */
  scorePatternStrength(finding, context) {
    // If AI-generated, check code snippet specificity
    if (finding.sourceProvider && finding.sourceProvider !== 'heuristic') {
      if (finding.code_snippet && finding.code_snippet.length > 20) {
        return 80; // Good specificity
      } else if (finding.code_snippet && finding.code_snippet.length > 0) {
        return 60; // Some specificity
      } else {
        return 40; // Low specificity
      }
    }

    // Heuristic pattern strength
    if (finding.pattern_match_strength !== undefined) {
      return finding.pattern_match_strength * 100;
    }

    // Check category reliability
    const reliableCategories = [
      'SQL_INJECTION',
      'XSS',
      'COMMAND_EXEC',
      'HARDCODED_SECRET',
      'SYNC_IO'
    ];

    if (reliableCategories.includes(finding.category)) {
      return 75;
    } else {
      return 50;
    }
  }

  /**
   * Score historical accuracy
   * Based on provider's past performance
   */
  scoreHistoricalAccuracy(finding, context) {
    const provider = finding.sourceProvider || 'unknown';
    const accuracy = this.config.providerAccuracy[provider] || 0.5;

    // If we have historical data for this category
    if (context.categoryAccuracy && context.categoryAccuracy[finding.category]) {
      const categoryAccuracy = context.categoryAccuracy[finding.category];
      return (accuracy * 0.6 + categoryAccuracy * 0.4) * 100;
    }

    return accuracy * 100;
  }

  /**
   * Score context signals
   * Code context indicators that boost or reduce confidence
   */
  scoreContextSignals(finding, context) {
    let score = 50; // Neutral baseline

    // Positive signals
    const positiveSignals = [
      // Line number provided
      finding.line_number && finding.line_number > 0 ? 10 : 0,

      // Suggestion provided
      finding.suggestion && finding.suggestion.length > 10 ? 10 : 0,

      // Impact score provided and high
      finding.impact_score && finding.impact_score >= 8 ? 10 : 0,

      // File path is specific (not generic)
      finding.file_path && !finding.file_path.includes('node_modules') ? 5 : 0,

      // Multiple evidence signals
      finding.evidence && Array.isArray(finding.evidence) && finding.evidence.length > 0 ? 10 : 0
    ];

    // Negative signals
    const negativeSignals = [
      // Generic message
      finding.message && finding.message.length < 20 ? -10 : 0,

      // Test file (often false positives)
      finding.file_path && /\.(test|spec)\.(js|ts|py)$/.test(finding.file_path) ? -5 : 0,

      // No line number (vague finding)
      !finding.line_number || finding.line_number === 0 ? -10 : 0
    ];

    const totalAdjustment = [
      ...positiveSignals,
      ...negativeSignals
    ].reduce((sum, val) => sum + val, 0);

    return Math.max(0, Math.min(100, score + totalAdjustment));
  }

  /**
   * Get confidence level from score
   */
  getConfidenceLevel(score) {
    if (score >= this.config.thresholds.veryHigh) return 'VERY_HIGH';
    if (score >= this.config.thresholds.high) return 'HIGH';
    if (score >= this.config.thresholds.medium) return 'MEDIUM';
    if (score >= this.config.thresholds.low) return 'LOW';
    return 'VERY_LOW';
  }

  /**
   * Build human-readable explanation
   */
  buildExplanation(scores, totalScore, level) {
    const factors = [];

    if (scores.providerAgreement >= 80) {
      factors.push('multiple AI providers agree');
    } else if (scores.providerAgreement >= 60) {
      factors.push('some provider agreement');
    } else {
      factors.push('single provider detection');
    }

    if (scores.severityConsistency >= 80) {
      factors.push('severity matches pattern');
    }

    if (scores.patternStrength >= 80) {
      factors.push('strong code pattern');
    }

    if (scores.contextSignals >= 60) {
      factors.push('good code context');
    } else if (scores.contextSignals <= 40) {
      factors.push('weak code context');
    }

    const prefix = level === 'VERY_HIGH' || level === 'HIGH'
      ? 'High confidence because'
      : level === 'MEDIUM'
        ? 'Medium confidence because'
        : 'Low confidence because';

    return `${prefix}: ${factors.join(', ')}.`;
  }

  /**
   * Calculate uncertainty (inverse of confidence with variance consideration)
   */
  calculateUncertainty(scores, totalScore) {
    // Base uncertainty is inverse of confidence
    const baseUncertainty = 100 - totalScore;

    // Calculate variance across factors (high variance = more uncertainty)
    const values = Object.values(scores);
    const mean = values.reduce((sum, v) => sum + v, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;

    // Normalize variance to 0-20 range
    const variancePenalty = Math.min(20, variance / 5);

    return Math.min(100, baseUncertainty + variancePenalty);
  }

  /**
   * Batch score multiple findings
   */
  async batchScore(findings, context = {}) {
    const scored = [];
    for (const finding of findings) {
      const confidenceScore = await this.score(finding, context);
      scored.push({
        ...finding,
        confidenceScore
      });
    }
    return scored;
  }

  /**
   * Update provider accuracy based on validation results
   */
  updateProviderAccuracy(provider, wasCorrect) {
    if (!this.config.providerAccuracy[provider]) {
      this.config.providerAccuracy[provider] = 0.5;
    }

    // Update with exponential moving average (alpha = 0.1)
    const alpha = 0.1;
    const newAccuracy = wasCorrect ? 1.0 : 0.0;
    this.config.providerAccuracy[provider] =
      this.config.providerAccuracy[provider] * (1 - alpha) + newAccuracy * alpha;

    // Track calibration
    if (wasCorrect) {
      this.history.truePositives++;
    } else {
      this.history.falsePositives++;
    }
  }

  /**
   * Get calibration statistics
   */
  getCalibration() {
    const total = this.history.truePositives + this.history.falsePositives;
    const accuracy = total > 0 ? this.history.truePositives / total : 0;

    return {
      totalValidated: total,
      accuracy,
      providerAccuracy: { ...this.config.providerAccuracy }
    };
  }

  /**
   * Export confidence scorer for persistence
   */
  export() {
    return {
      config: this.config,
      history: this.history
    };
  }

  /**
   * Import previously exported confidence scorer
   */
  import(data) {
    if (data.config) {
      this.config = { ...this.config, ...data.config };
    }
    if (data.history) {
      this.history = { ...this.history, ...data.history };
    }
  }

  /**
   * Record an outcome for a finding (validation feedback)
   */
  async recordOutcome(params) {
    if (!this.historyTracker) {
      return { recorded: false, reason: 'tracker_not_initialized' };
    }

    return await this.historyTracker.recordOutcome(params);
  }

  /**
   * Flush pending tracked data
   */
  async flush() {
    if (this.historyTracker) {
      return await this.historyTracker.flush();
    }
    return { scores: { flushed: 0 }, outcomes: { flushed: 0 } };
  }

  /**
   * Get tracking statistics
   */
  getTrackingStats() {
    if (this.historyTracker) {
      return this.historyTracker.getStats();
    }
    return null;
  }

  /**
   * Cleanup and destroy scorer
   */
  async destroy() {
    if (this.historyTracker) {
      return await this.historyTracker.destroy();
    }
  }
}

module.exports = ConfidenceScorer;
