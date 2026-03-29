/**
 * Confidence History Tracker - Track and analyze confidence scoring over time
 *
 * This service provides comprehensive tracking of confidence scores, outcomes,
 * and calibration data to enable continuous improvement of the confidence algorithm.
 *
 * Features:
 * - Track every confidence score with full breakdown
 * - Record outcomes and validation results
 * - Calculate calibration metrics
 * - Support A/B testing experiments
 * - Provider performance tracking
 * - Real-time analytics
 *
 * @module confidence-history-tracker
 */

const { createClient } = require('@supabase/supabase-js');

class ConfidenceHistoryTracker {
  constructor(config = {}) {
    this.config = {
      supabaseUrl: config.supabaseUrl || process.env.SUPABASE_URL,
      supabaseKey: config.supabaseKey || process.env.SUPABASE_SERVICE_KEY,
      enableTracking: config.enableTracking !== false,
      batchSize: config.batchSize || 100,
      flushInterval: config.flushInterval || 30000, // 30 seconds
      ...config
    };

    // Initialize Supabase client
    if (this.config.supabaseUrl && this.config.supabaseKey) {
      this.supabase = createClient(
        this.config.supabaseUrl,
        this.config.supabaseKey
      );
    }

    // Batch queue for performance
    this.scoreQueue = [];
    this.outcomeQueue = [];

    // Start auto-flush interval
    if (this.config.enableTracking && this.supabase) {
      this.flushInterval = setInterval(
        () => this.flush(),
        this.config.flushInterval
      );
    }

    // Statistics
    this.stats = {
      scoresTracked: 0,
      outcomesRecorded: 0,
      batchesFlushed: 0,
      errors: 0
    };
  }

  /**
   * Track a confidence score
   *
   * @param {Object} params - Score tracking parameters
   * @returns {Promise<Object>} Tracking result with score ID
   */
  async trackScore(params) {
    const {
      finding,
      runId,
      projectId,
      confidenceResult,
      sourceProvider,
      supportingProviders = [],
      algorithmVersion = 'v1.0',
      experimentId = null,
      fixApplied = false,
      fixSucceeded = null
    } = params;

    if (!this.config.enableTracking || !this.supabase) {
      return { tracked: false };
    }

    const scoreRecord = {
      finding_id: finding.id || null,
      run_id: runId,
      project_id: projectId,

      // Finding context
      category: finding.category,
      severity: finding.severity,
      domain: finding.domain || 'unknown',
      file_path: finding.file_path || finding.filePath,
      line_number: finding.line_number || finding.lineNumber,

      // Provider info
      source_provider: sourceProvider,
      supporting_providers: supportingProviders,
      ensemble_consensus: supportingProviders.length > 1,

      // Confidence scores
      confidence_score: confidenceResult.score,
      confidence_level: confidenceResult.level,
      uncertainty_score: Math.round(confidenceResult.uncertainty || 0),

      // Score breakdown
      score_provider_agreement: Math.round(confidenceResult.breakdown.providerAgreement || 0),
      score_severity_consistency: Math.round(confidenceResult.breakdown.severityConsistency || 0),
      score_pattern_strength: Math.round(confidenceResult.breakdown.patternStrength || 0),
      score_historical_accuracy: Math.round(confidenceResult.breakdown.historicalAccuracy || 0),
      score_context_signals: Math.round(confidenceResult.breakdown.contextSignals || 0),

      // Weights (from confidence scorer config)
      weight_provider_agreement: 0.40,
      weight_severity_consistency: 0.15,
      weight_pattern_strength: 0.20,
      weight_historical_accuracy: 0.15,
      weight_context_signals: 0.10,

      // Explanation
      explanation: confidenceResult.explanation,
      recommendation: this.getRecommendation(confidenceResult.score),

      // Algorithm metadata
      algorithm_version: algorithmVersion,
      experiment_id: experimentId,

      // Fix status
      fix_applied: fixApplied,
      fix_attempted_at: fixApplied ? new Date().toISOString() : null,
      fix_succeeded: fixSucceeded,

      // Metadata
      metadata: {
        finding_message: finding.message?.substring(0, 500),
        code_snippet: finding.code_snippet?.substring(0, 200)
      }
    };

    try {
      if (this.config.batchSize > 1) {
        // Add to batch queue
        this.scoreQueue.push(scoreRecord);
        this.stats.scoresTracked++;

        // Flush if batch is full
        if (this.scoreQueue.length >= this.config.batchSize) {
          await this.flushScores();
        }

        return { tracked: true, queued: true };
      } else {
        // Immediate insert
        const { data, error } = await this.supabase
          .from('confidence_scores')
          .insert([scoreRecord])
          .select();

        if (error) {
          console.error('[ConfidenceTracker] Error tracking score:', error);
          this.stats.errors++;
          return { tracked: false, error };
        }

        this.stats.scoresTracked++;
        return { tracked: true, scoreId: data[0].id, data: data[0] };
      }
    } catch (error) {
      console.error('[ConfidenceTracker] Exception tracking score:', error);
      this.stats.errors++;
      return { tracked: false, error: error.message };
    }
  }

  /**
   * Record an outcome for a confidence score
   *
   * @param {Object} params - Outcome parameters
   * @returns {Promise<Object>} Outcome record
   */
  async recordOutcome(params) {
    const {
      confidenceScoreId,
      findingId = null,
      outcomeType,
      outcomeStatus = 'SUCCESS',
      wasCorrect = null,
      fixWorked = null,
      introducedBugs = false,
      syntaxValid = null,
      testsPassed = null,
      buildSucceeded = null,
      userRating = null,
      userComment = null,
      userId = null,
      timeToOutcomeMs = null,
      validationMethod = 'automated',
      impactAssessment = null
    } = params;

    if (!this.config.enableTracking || !this.supabase) {
      return { recorded: false };
    }

    const outcomeRecord = {
      confidence_score_id: confidenceScoreId,
      finding_id: findingId,

      outcome_type: outcomeType,
      outcome_status: outcomeStatus,

      was_correct: wasCorrect,
      fix_worked: fixWorked,
      introduced_bugs: introducedBugs,

      syntax_valid: syntaxValid,
      tests_passed: testsPassed,
      build_succeeded: buildSucceeded,

      user_rating: userRating,
      user_comment: userComment,
      user_id: userId,

      time_to_outcome_ms: timeToOutcomeMs,
      validation_method: validationMethod,

      impact_assessment: impactAssessment
    };

    try {
      if (this.config.batchSize > 1) {
        // Add to batch queue
        this.outcomeQueue.push(outcomeRecord);
        this.stats.outcomesRecorded++;

        // Flush if batch is full
        if (this.outcomeQueue.length >= this.config.batchSize) {
          await this.flushOutcomes();
        }

        return { recorded: true, queued: true };
      } else {
        // Immediate insert
        const { data, error } = await this.supabase
          .from('confidence_outcomes')
          .insert([outcomeRecord])
          .select();

        if (error) {
          console.error('[ConfidenceTracker] Error recording outcome:', error);
          this.stats.errors++;
          return { recorded: false, error };
        }

        this.stats.outcomesRecorded++;
        return { recorded: true, outcomeId: data[0].id, data: data[0] };
      }
    } catch (error) {
      console.error('[ConfidenceTracker] Exception recording outcome:', error);
      this.stats.errors++;
      return { recorded: false, error: error.message };
    }
  }

  /**
   * Flush queued scores to database
   */
  async flushScores() {
    if (this.scoreQueue.length === 0) return { flushed: 0 };

    const batch = this.scoreQueue.splice(0, this.config.batchSize);

    try {
      const { data, error } = await this.supabase
        .from('confidence_scores')
        .insert(batch)
        .select();

      if (error) {
        console.error('[ConfidenceTracker] Error flushing scores:', error);
        this.stats.errors++;
        // Re-queue on error
        this.scoreQueue.unshift(...batch);
        return { flushed: 0, error };
      }

      this.stats.batchesFlushed++;
      return { flushed: batch.length, data };
    } catch (error) {
      console.error('[ConfidenceTracker] Exception flushing scores:', error);
      this.stats.errors++;
      // Re-queue on error
      this.scoreQueue.unshift(...batch);
      return { flushed: 0, error: error.message };
    }
  }

  /**
   * Flush queued outcomes to database
   */
  async flushOutcomes() {
    if (this.outcomeQueue.length === 0) return { flushed: 0 };

    const batch = this.outcomeQueue.splice(0, this.config.batchSize);

    try {
      const { data, error } = await this.supabase
        .from('confidence_outcomes')
        .insert(batch)
        .select();

      if (error) {
        console.error('[ConfidenceTracker] Error flushing outcomes:', error);
        this.stats.errors++;
        // Re-queue on error
        this.outcomeQueue.unshift(...batch);
        return { flushed: 0, error };
      }

      this.stats.batchesFlushed++;
      return { flushed: batch.length, data };
    } catch (error) {
      console.error('[ConfidenceTracker] Exception flushing outcomes:', error);
      this.stats.errors++;
      // Re-queue on error
      this.outcomeQueue.unshift(...batch);
      return { flushed: 0, error: error.message };
    }
  }

  /**
   * Flush all queued data
   */
  async flush() {
    const results = await Promise.allSettled([
      this.flushScores(),
      this.flushOutcomes()
    ]);

    return {
      scores: results[0].status === 'fulfilled' ? results[0].value : { flushed: 0, error: results[0].reason },
      outcomes: results[1].status === 'fulfilled' ? results[1].value : { flushed: 0, error: results[1].reason }
    };
  }

  /**
   * Get confidence accuracy by level
   */
  async getAccuracyByLevel() {
    if (!this.supabase) return null;

    try {
      const { data, error } = await this.supabase
        .from('confidence_accuracy_by_level')
        .select('*')
        .order('confidence_level');

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('[ConfidenceTracker] Error getting accuracy by level:', error);
      return null;
    }
  }

  /**
   * Get provider comparison
   */
  async getProviderComparison() {
    if (!this.supabase) return null;

    try {
      const { data, error } = await this.supabase
        .from('provider_comparison')
        .select('*')
        .order('accuracy_pct', { ascending: false, nullsFirst: false });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('[ConfidenceTracker] Error getting provider comparison:', error);
      return null;
    }
  }

  /**
   * Get recent confidence trends
   */
  async getRecentTrends(days = 30) {
    if (!this.supabase) return null;

    try {
      const { data, error } = await this.supabase
        .from('recent_confidence_trends')
        .select('*')
        .order('date', { ascending: false })
        .limit(days);

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('[ConfidenceTracker] Error getting recent trends:', error);
      return null;
    }
  }

  /**
   * Get calibration data for a time period
   */
  async getCalibration(params = {}) {
    if (!this.supabase) return null;

    const {
      periodType = 'daily',
      projectId = null,
      category = null,
      domain = null,
      provider = null,
      limit = 30
    } = params;

    try {
      let query = this.supabase
        .from('confidence_calibration')
        .select('*')
        .eq('period_type', periodType);

      if (projectId) query = query.eq('project_id', projectId);
      if (category) query = query.eq('category', category);
      if (domain) query = query.eq('domain', domain);
      if (provider) query = query.eq('provider', provider);

      const { data, error } = await query
        .order('period_start', { ascending: false })
        .limit(limit);

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('[ConfidenceTracker] Error getting calibration:', error);
      return null;
    }
  }

  /**
   * Create a new experiment
   */
  async createExperiment(params) {
    if (!this.supabase) return null;

    const {
      name,
      description,
      algorithmVersion,
      weights,
      thresholds,
      providerAccuracy,
      trafficAllocation = 0.1,
      targetDomains = [],
      targetCategories = []
    } = params;

    try {
      const { data, error } = await this.supabase
        .from('confidence_experiments')
        .insert([{
          experiment_name: name,
          description,
          status: 'active',
          algorithm_version: algorithmVersion,
          weights,
          thresholds,
          provider_accuracy: providerAccuracy,
          traffic_allocation: trafficAllocation,
          target_domains: targetDomains,
          target_categories: targetCategories
        }])
        .select();

      if (error) throw error;
      return data[0];
    } catch (error) {
      console.error('[ConfidenceTracker] Error creating experiment:', error);
      return null;
    }
  }

  /**
   * Update experiment results
   */
  async updateExperimentResults(experimentId, results) {
    if (!this.supabase) return null;

    try {
      const { data, error } = await this.supabase
        .from('confidence_experiments')
        .update({
          scores_generated: results.scoresGenerated,
          fixes_applied: results.fixesApplied,
          outcomes_recorded: results.outcomesRecorded,
          accuracy: results.accuracy,
          improvement_over_baseline: results.improvementOverBaseline
        })
        .eq('id', experimentId)
        .select();

      if (error) throw error;
      return data[0];
    } catch (error) {
      console.error('[ConfidenceTracker] Error updating experiment:', error);
      return null;
    }
  }

  /**
   * Get recommendation based on confidence score
   */
  getRecommendation(score) {
    if (score >= 90) return 'AUTO_APPLY';
    if (score >= 75) return 'REVIEW_RECOMMENDED';
    if (score >= 50) return 'MANUAL_REVIEW';
    return 'SKIP';
  }

  /**
   * Get tracker statistics
   */
  getStats() {
    return {
      ...this.stats,
      queuedScores: this.scoreQueue.length,
      queuedOutcomes: this.outcomeQueue.length,
      enabled: this.config.enableTracking && !!this.supabase
    };
  }

  /**
   * Cleanup and stop tracker
   */
  async destroy() {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }

    // Final flush
    await this.flush();

    return this.getStats();
  }
}

module.exports = ConfidenceHistoryTracker;
