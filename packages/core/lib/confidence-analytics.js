/**
 * Confidence Analytics Service
 *
 * Provides analytics, insights, and calibration reports for confidence scoring.
 * Used for algorithm tuning and continuous improvement.
 *
 * @module confidence-analytics
 */

const { createClient } = require('@supabase/supabase-js');

class ConfidenceAnalytics {
  constructor(config = {}) {
    this.config = {
      supabaseUrl: config.supabaseUrl || process.env.SUPABASE_URL,
      supabaseKey: config.supabaseKey || process.env.SUPABASE_SERVICE_KEY,
      ...config
    };

    // Initialize Supabase client
    if (this.config.supabaseUrl && this.config.supabaseKey) {
      this.supabase = createClient(
        this.config.supabaseUrl,
        this.config.supabaseKey
      );
    }
  }

  /**
   * Get comprehensive confidence dashboard
   */
  async getDashboard(params = {}) {
    const {
      projectId = null,
      days = 30
    } = params;

    const [
      accuracyByLevel,
      providerComparison,
      recentTrends,
      calibration,
      topCategories
    ] = await Promise.all([
      this.getAccuracyByLevel(projectId),
      this.getProviderComparison(projectId),
      this.getRecentTrends(days),
      this.getCalibrationSummary(projectId),
      this.getTopCategories(projectId, 10)
    ]);

    return {
      timestamp: new Date().toISOString(),
      projectId,
      accuracyByLevel,
      providerComparison,
      recentTrends,
      calibration,
      topCategories,
      recommendations: this.generateRecommendations({
        accuracyByLevel,
        providerComparison,
        calibration
      })
    };
  }

  /**
   * Get accuracy breakdown by confidence level
   */
  async getAccuracyByLevel(projectId = null) {
    if (!this.supabase) return null;

    try {
      let query = this.supabase
        .from('confidence_accuracy_by_level')
        .select('*');

      if (projectId) {
        // Filter by project through confidence_scores join
        const { data: scores } = await this.supabase
          .from('confidence_scores')
          .select('confidence_level, id')
          .eq('project_id', projectId);

        if (!scores || scores.length === 0) return [];

        // Aggregate manually
        const levels = {};
        for (const score of scores) {
          if (!levels[score.confidence_level]) {
            levels[score.confidence_level] = {
              confidence_level: score.confidence_level,
              total_predictions: 0,
              correct_predictions: 0,
              accuracy_pct: 0
            };
          }
          levels[score.confidence_level].total_predictions++;
        }

        return Object.values(levels);
      }

      const { data, error } = await query.order('confidence_level');

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('[ConfidenceAnalytics] Error getting accuracy by level:', error);
      return [];
    }
  }

  /**
   * Get provider performance comparison
   */
  async getProviderComparison(projectId = null) {
    if (!this.supabase) return null;

    try {
      const { data, error } = await this.supabase
        .from('provider_comparison')
        .select('*')
        .order('accuracy_pct', { ascending: false, nullsFirst: false });

      if (error) throw error;

      // Filter by project if needed
      if (projectId && data) {
        // Get scores for this project
        const { data: projectScores } = await this.supabase
          .from('confidence_scores')
          .select('source_provider')
          .eq('project_id', projectId);

        if (projectScores) {
          const projectProviders = new Set(projectScores.map(s => s.source_provider));
          return data.filter(p => projectProviders.has(p.source_provider));
        }
      }

      return data || [];
    } catch (error) {
      console.error('[ConfidenceAnalytics] Error getting provider comparison:', error);
      return [];
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
      return data || [];
    } catch (error) {
      console.error('[ConfidenceAnalytics] Error getting recent trends:', error);
      return [];
    }
  }

  /**
   * Get calibration summary
   */
  async getCalibrationSummary(projectId = null) {
    if (!this.supabase) return null;

    try {
      let query = this.supabase
        .from('confidence_calibration')
        .select('*')
        .eq('period_type', 'daily')
        .order('period_start', { ascending: false })
        .limit(30);

      if (projectId) {
        query = query.eq('project_id', projectId);
      }

      const { data, error } = await query;

      if (error) throw error;

      if (!data || data.length === 0) {
        return {
          overall_accuracy: 0,
          expected_calibration_error: 0,
          total_predictions: 0,
          total_correct: 0
        };
      }

      // Aggregate calibration data
      const summary = {
        overall_accuracy: 0,
        expected_calibration_error: 0,
        total_predictions: data.reduce((sum, d) => sum + (d.total_predictions || 0), 0),
        total_correct: data.reduce((sum, d) => sum + (d.total_correct || 0), 0),
        avg_confidence: data.reduce((sum, d) => sum + (d.avg_confidence_score || 0), 0) / data.length,
        recent_period: data[0]?.period_start
      };

      summary.overall_accuracy = summary.total_predictions > 0
        ? summary.total_correct / summary.total_predictions
        : 0;

      summary.expected_calibration_error = data.reduce((sum, d) => sum + (d.expected_calibration_error || 0), 0) / data.length;

      return summary;
    } catch (error) {
      console.error('[ConfidenceAnalytics] Error getting calibration summary:', error);
      return null;
    }
  }

  /**
   * Get top categories by volume
   */
  async getTopCategories(projectId = null, limit = 10) {
    if (!this.supabase) return null;

    try {
      let query = this.supabase
        .from('confidence_scores')
        .select('category, confidence_score, confidence_level, fix_applied');

      if (projectId) {
        query = query.eq('project_id', projectId);
      }

      const { data, error } = await query;

      if (error) throw error;

      if (!data || data.length === 0) return [];

      // Aggregate by category
      const categoryMap = {};
      for (const score of data) {
        if (!categoryMap[score.category]) {
          categoryMap[score.category] = {
            category: score.category,
            count: 0,
            avg_confidence: 0,
            fixes_applied: 0,
            high_confidence: 0
          };
        }
        const cat = categoryMap[score.category];
        cat.count++;
        cat.avg_confidence += score.confidence_score;
        if (score.fix_applied) cat.fixes_applied++;
        if (['VERY_HIGH', 'HIGH'].includes(score.confidence_level)) cat.high_confidence++;
      }

      // Calculate averages and format
      const categories = Object.values(categoryMap).map(cat => ({
        ...cat,
        avg_confidence: Math.round(cat.avg_confidence / cat.count),
        high_confidence_pct: Math.round((cat.high_confidence / cat.count) * 100)
      }));

      // Sort by count and limit
      categories.sort((a, b) => b.count - a.count);
      return categories.slice(0, limit);
    } catch (error) {
      console.error('[ConfidenceAnalytics] Error getting top categories:', error);
      return [];
    }
  }

  /**
   * Generate recommendations based on analytics
   */
  generateRecommendations(analytics) {
    const recommendations = [];

    // Check accuracy by level
    if (analytics.accuracyByLevel) {
      for (const level of analytics.accuracyByLevel) {
        if (level.total_predictions > 10) {
          if (level.confidence_level === 'VERY_HIGH' && level.accuracy_pct < 90) {
            recommendations.push({
              type: 'threshold_adjustment',
              priority: 'HIGH',
              message: `VERY_HIGH confidence level only ${level.accuracy_pct}% accurate. Consider raising threshold from 90 to 95.`,
              action: 'Increase VERY_HIGH threshold',
              expected_impact: 'Reduce false positives in auto-applied fixes'
            });
          }

          if (level.confidence_level === 'HIGH' && level.accuracy_pct > 95) {
            recommendations.push({
              type: 'threshold_adjustment',
              priority: 'MEDIUM',
              message: `HIGH confidence level is ${level.accuracy_pct}% accurate. Consider lowering threshold to auto-apply more fixes.`,
              action: 'Lower HIGH threshold or auto-apply HIGH confidence',
              expected_impact: 'Increase fix automation while maintaining quality'
            });
          }
        }
      }
    }

    // Check provider performance
    if (analytics.providerComparison) {
      const sortedProviders = [...analytics.providerComparison]
        .sort((a, b) => (b.accuracy_pct || 0) - (a.accuracy_pct || 0));

      if (sortedProviders.length > 1) {
        const best = sortedProviders[0];
        const worst = sortedProviders[sortedProviders.length - 1];

        if (best && worst && (best.accuracy_pct - worst.accuracy_pct) > 20) {
          recommendations.push({
            type: 'provider_weighting',
            priority: 'HIGH',
            message: `Large accuracy gap between ${best.source_provider} (${best.accuracy_pct}%) and ${worst.source_provider} (${worst.accuracy_pct}%).`,
            action: `Increase weight for ${best.source_provider} in ensemble`,
            expected_impact: 'Improve overall confidence accuracy'
          });
        }
      }
    }

    // Check calibration
    if (analytics.calibration) {
      if (analytics.calibration.expected_calibration_error > 0.15) {
        recommendations.push({
          type: 'calibration',
          priority: 'HIGH',
          message: `Confidence scores are poorly calibrated (ECE: ${analytics.calibration.expected_calibration_error.toFixed(3)}).`,
          action: 'Review weight distribution and adjust based on historical accuracy',
          expected_impact: 'Better alignment between confidence scores and actual accuracy'
        });
      }
    }

    return recommendations;
  }

  /**
   * Get confidence score distribution
   */
  async getScoreDistribution(projectId = null, bins = 10) {
    if (!this.supabase) return null;

    try {
      let query = this.supabase
        .from('confidence_scores')
        .select('confidence_score');

      if (projectId) {
        query = query.eq('project_id', projectId);
      }

      const { data, error } = await query;

      if (error) throw error;

      if (!data || data.length === 0) return [];

      // Create bins
      const binSize = 100 / bins;
      const distribution = Array(bins).fill(0).map((_, i) => ({
        bin: `${i * binSize}-${(i + 1) * binSize}`,
        count: 0,
        min: i * binSize,
        max: (i + 1) * binSize
      }));

      // Fill bins
      for (const score of data) {
        const binIndex = Math.min(Math.floor(score.confidence_score / binSize), bins - 1);
        distribution[binIndex].count++;
      }

      return distribution;
    } catch (error) {
      console.error('[ConfidenceAnalytics] Error getting score distribution:', error);
      return [];
    }
  }

  /**
   * Get factor importance analysis
   */
  async getFactorImportance(projectId = null) {
    if (!this.supabase) return null;

    try {
      let query = this.supabase
        .from('confidence_scores')
        .select(`
          score_provider_agreement,
          score_severity_consistency,
          score_pattern_strength,
          score_historical_accuracy,
          score_context_signals,
          confidence_score
        `);

      if (projectId) {
        query = query.eq('project_id', projectId);
      }

      const { data, error } = await query.limit(1000);

      if (error) throw error;

      if (!data || data.length === 0) return null;

      // Calculate correlations with final score
      const factors = [
        'score_provider_agreement',
        'score_severity_consistency',
        'score_pattern_strength',
        'score_historical_accuracy',
        'score_context_signals'
      ];

      const importance = {};

      for (const factor of factors) {
        const correlation = this.calculateCorrelation(
          data.map(d => d[factor] || 0),
          data.map(d => d.confidence_score)
        );

        importance[factor] = {
          correlation,
          avg_value: data.reduce((sum, d) => sum + (d[factor] || 0), 0) / data.length,
          std_dev: this.calculateStdDev(data.map(d => d[factor] || 0))
        };
      }

      return importance;
    } catch (error) {
      console.error('[ConfidenceAnalytics] Error getting factor importance:', error);
      return null;
    }
  }

  /**
   * Calculate correlation between two arrays
   */
  calculateCorrelation(x, y) {
    const n = x.length;
    const sumX = x.reduce((a, b) => a + b, 0);
    const sumY = y.reduce((a, b) => a + b, 0);
    const sumXY = x.reduce((sum, xi, i) => sum + xi * y[i], 0);
    const sumX2 = x.reduce((sum, xi) => sum + xi * xi, 0);
    const sumY2 = y.reduce((sum, yi) => sum + yi * yi, 0);

    const numerator = (n * sumXY) - (sumX * sumY);
    const denominator = Math.sqrt(((n * sumX2) - (sumX * sumX)) * ((n * sumY2) - (sumY * sumY)));

    return denominator === 0 ? 0 : numerator / denominator;
  }

  /**
   * Calculate standard deviation
   */
  calculateStdDev(arr) {
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const variance = arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
    return Math.sqrt(variance);
  }

  /**
   * Export report as JSON
   */
  async exportReport(params = {}) {
    const dashboard = await this.getDashboard(params);
    const distribution = await this.getScoreDistribution(params.projectId);
    const factorImportance = await this.getFactorImportance(params.projectId);

    return {
      generated_at: new Date().toISOString(),
      project_id: params.projectId,
      dashboard,
      score_distribution: distribution,
      factor_importance: factorImportance
    };
  }
}

module.exports = ConfidenceAnalytics;
