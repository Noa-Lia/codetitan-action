/**
 * Pattern Learning Integration Layer
 *
 * Hooks the Pattern Learner into the CodeTitan analysis pipeline.
 * Automatically runs pattern detection, learning, and predictions after each analysis.
 *
 * Usage:
 *   const integration = new PatternIntegration(dbPath);
 *   await integration.init();
 *   await integration.processAnalysisResults(report, runId);
 */

const path = require('path');
const CollectiveInsight = require('./collective-insight');
const { PatternLearner } = require('./pattern-learner');

class PatternIntegration {
  constructor(dbPath) {
    this.dbPath = dbPath;
    this.insight = null;
    this.learner = null;
    this.modelPath = path.join(path.dirname(dbPath), 'pattern-model.json');
  }

  /**
   * Initialize database and learner
   */
  async init() {
    this.insight = new CollectiveInsight(this.dbPath);
    await this.insight.init();

    this.learner = new PatternLearner();

    // Load existing model if available
    const existingModel = this.learner.loadModel(this.modelPath);
    if (existingModel) {
      console.log(`   Loaded pattern model from ${new Date(existingModel.timestamp).toLocaleString()}`);
    }
  }

  /**
   * Process analysis results through pattern learning pipeline
   * @param {object} report - Analysis report from ResultSynthesisEngine
   * @param {number} runId - Database run ID
   */
  async processAnalysisResults(report, runId) {
    console.log(`\n========================================================`);
    console.log(`🎓 CodeTitan Level 6: Pattern Learning Pipeline`);
    console.log(`========================================================`);

    try {
      // Step 1: Detect patterns in historical findings
      const patterns = await this.detectHistoricalPatterns();

      // Step 2: Learn from fix history
      const learningResults = await this.learnFromHistory();

      // Step 3: Generate predictions for next analysis
      const predictions = await this.generatePredictions(report, runId);

      // Step 4: Rank current findings with confidence scores
      const rankedFindings = await this.rankCurrentFindings(report, patterns);

      // Step 5: Store patterns and predictions
      await this.storeLearningResults(patterns, predictions, runId);

      // Step 6: Save updated model
      this.learner.saveModel(this.modelPath);

      // Return enhanced report
      return {
        patterns,
        learningResults,
        predictions,
        rankedFindings,
        modelPath: this.modelPath
      };

    } catch (error) {
      console.error(`\n[ERROR] Pattern learning pipeline error:`, error.message);
      throw error;
    }
  }

  /**
   * Detect patterns in historical findings
   */
  async detectHistoricalPatterns() {
    const allFindings = await this.insight.getAllFindings(1000);

    if (allFindings.length === 0) {
      console.log(`\n[WARNING]  No historical findings available for pattern detection`);
      return {
        clusters: [],
        totalPatterns: 0,
        uniqueIssues: 0,
        summary: {}
      };
    }

    const patterns = this.learner.detectPatterns(allFindings);

    // Analyze root causes
    const rootCauses = this.learner.analyzeRootCauses(allFindings);

    console.log(`\n[CHART] Pattern Detection Summary:`);
    console.log(`   Total clusters found: ${patterns.totalPatterns}`);
    console.log(`   Unique issues: ${patterns.uniqueIssues}`);
    console.log(`   Most common category: ${patterns.summary.mostCommonCategory || 'N/A'}`);
    console.log(`   Average cluster size: ${patterns.summary.avgClusterSize.toFixed(1)}`);

    if (rootCauses.pathPatterns.length > 0) {
      console.log(`\n📂 Top Path Patterns:`);
      rootCauses.pathPatterns.slice(0, 3).forEach((p, i) => {
        console.log(`   ${i + 1}. ${p.pattern} (${p.count} issues)`);
      });
    }

    return {
      ...patterns,
      rootCauses
    };
  }

  /**
   * Learn from fix history
   */
  async learnFromHistory() {
    const fixHistory = await this.insight.getFixHistory();

    if (fixHistory.length === 0) {
      console.log(`\n[WARNING]  No fix history available for learning`);
      return {
        model: { categories: [] },
        topSuccessRates: [],
        lowSuccessRates: []
      };
    }

    const learningResults = this.learner.learnFromFixes(fixHistory);

    console.log(`\n[TRENDING] Learning Results:`);
    if (learningResults.topSuccessRates.length > 0) {
      console.log(`   Top success rates:`);
      learningResults.topSuccessRates.slice(0, 3).forEach(cat => {
        console.log(`     ${cat.category}: ${(cat.successRate * 100).toFixed(1)}%`);
      });
    }

    if (learningResults.lowSuccessRates.length > 0) {
      console.log(`   Need improvement:`);
      learningResults.lowSuccessRates.slice(0, 3).forEach(cat => {
        console.log(`     ${cat.category}: ${(cat.successRate * 100).toFixed(1)}%`);
      });
    }

    return learningResults;
  }

  /**
   * Generate predictions for next analysis
   */
  async generatePredictions(currentReport, runId) {
    const historicalRuns = await this.insight.getHistoricalRuns(20);

    if (historicalRuns.length < 2) {
      console.log(`\n[WARNING]  Insufficient historical data for predictions (need at least 2 runs)`);
      return {
        predictions: [],
        confidence: 0,
        message: 'Insufficient historical data'
      };
    }

    const predictions = this.learner.predictIssues(currentReport, historicalRuns);

    console.log(`\n🔮 Predictions:`);
    if (predictions.predictions.length > 0) {
      console.log(`   Likely issues in next analysis:`);
      predictions.predictions.slice(0, 5).forEach((pred, i) => {
        console.log(`     ${i + 1}. ${pred.category} (${(pred.probability * 100).toFixed(1)}% probability)`);
      });
    } else {
      console.log(`   No predictions generated`);
    }

    if (predictions.temporalPatterns?.cascades?.length > 0) {
      console.log(`\n[BOLT] Cascade Patterns:`);
      predictions.temporalPatterns.cascades.slice(0, 3).forEach(cascade => {
        console.log(`     ${cascade.chain} (seen ${cascade.count}x)`);
      });
    }

    return predictions;
  }

  /**
   * Rank current findings with ML confidence
   */
  async rankCurrentFindings(report, patterns) {
    if (!report.findings || report.findings.length === 0) {
      return [];
    }

    const ranked = this.learner.rankRecommendations(report.findings, patterns);

    console.log(`\n[STAR] Prioritization:`);
    if (ranked.length > 0) {
      console.log(`   Top 5 recommendations:`);
      ranked.slice(0, 5).forEach((rec, i) => {
        console.log(`     ${i + 1}. [${rec.priority}] ${rec.finding.category} in ${path.basename(rec.finding.file || 'unknown')}`);
        console.log(`        Score: ${rec.score.toFixed(1)} | Confidence: ${(rec.confidence * 100).toFixed(0)}%`);
      });
    }

    return ranked;
  }

  /**
   * Store learning results in database
   */
  async storeLearningResults(patterns, predictions, runId) {
    // Store pattern clusters
    if (patterns.clusters) {
      for (const cluster of patterns.clusters) {
        await this.insight.storePatternCluster(cluster);
      }
      console.log(`\n💾 Stored ${patterns.clusters.length} pattern clusters`);
    }

    // Store predictions for future validation
    if (predictions.predictions && predictions.predictions.length > 0) {
      await this.insight.storePredictions(runId, predictions.predictions);
      console.log(`💾 Stored ${predictions.predictions.length} predictions for validation`);
    }
  }

  /**
   * Record a fix attempt (call this when applying fixes)
   */
  async recordFix(category, success, metadata = {}) {
    await this.insight.recordFixAttempt(category, success, metadata);

    // Update the learner's model
    this.learner.learnFromFixes([{
      category,
      success,
      timestamp: new Date().toISOString()
    }]);

    // Save updated model
    this.learner.saveModel(this.modelPath);
  }

  /**
   * Get ML-enhanced dashboard
   */
  async getDashboard(limit = 5) {
    const dashboard = await this.insight.getMLDashboard(limit);

    return {
      ...dashboard,
      modelInfo: {
        path: this.modelPath,
        lastUpdated: this.learner.fixerModel.toJSON().categories.length > 0
          ? 'Active'
          : 'Needs training data'
      }
    };
  }

  /**
   * Validate previous predictions
   */
  async validatePredictions(runId) {
    const validation = await this.insight.validatePredictions(runId);

    console.log(`\n[OK] Prediction Validation:`);
    console.log(`   Accuracy: ${(validation.accuracy * 100).toFixed(1)}%`);
    console.log(`   Hits: ${validation.hits}/${validation.total}`);

    return validation;
  }

  /**
   * Generate insights report
   */
  async generateInsightsReport() {
    const dashboard = await this.getDashboard(10);

    const report = {
      timestamp: new Date().toISOString(),
      summary: dashboard.summary,
      qualityTrend: dashboard.qualityTrend,
      topCategories: dashboard.topCategories,
      ml: dashboard.ml,
      insights: []
    };

    // Generate actionable insights
    const insights = [];

    // Insight 1: Quality trend
    if (dashboard.qualityTrend.delta !== null) {
      if (dashboard.qualityTrend.delta > 0) {
        insights.push({
          type: 'POSITIVE',
          message: `Code quality improved by ${dashboard.qualityTrend.delta.toFixed(1)} points`,
          action: 'Continue current practices'
        });
      } else if (dashboard.qualityTrend.delta < -5) {
        insights.push({
          type: 'WARNING',
          message: `Code quality declined by ${Math.abs(dashboard.qualityTrend.delta).toFixed(1)} points`,
          action: 'Review recent changes and refocus on quality'
        });
      }
    }

    // Insight 2: Pattern clusters
    if (dashboard.ml.clusters.length > 0) {
      const largestCluster = dashboard.ml.clusters[0];
      insights.push({
        type: 'PATTERN',
        message: `Recurring pattern: ${largestCluster.category} (${largestCluster.size} occurrences)`,
        action: largestCluster.rootCause || 'Consider systematic refactoring',
        priority: 'HIGH'
      });
    }

    // Insight 3: Fix success rates
    if (dashboard.ml.fixSuccessRates.length > 0) {
      const bestFix = dashboard.ml.fixSuccessRates[0];
      if (bestFix.successRate > 0.8) {
        insights.push({
          type: 'SUCCESS',
          message: `Auto-fix for ${bestFix.category} is highly reliable (${(bestFix.successRate * 100).toFixed(0)}%)`,
          action: 'Enable automatic fixes for this category',
          priority: 'MEDIUM'
        });
      }

      const worstFix = dashboard.ml.fixSuccessRates[dashboard.ml.fixSuccessRates.length - 1];
      if (worstFix.successRate < 0.5) {
        insights.push({
          type: 'WARNING',
          message: `Auto-fix for ${worstFix.category} needs improvement (${(worstFix.successRate * 100).toFixed(0)}%)`,
          action: 'Review fixer logic or switch to manual fixes',
          priority: 'MEDIUM'
        });
      }
    }

    // Insight 4: Prediction accuracy
    if (dashboard.ml.predictionAccuracy !== null) {
      if (dashboard.ml.predictionAccuracy > 0.7) {
        insights.push({
          type: 'SUCCESS',
          message: `Prediction model is performing well (${(dashboard.ml.predictionAccuracy * 100).toFixed(0)}% accuracy)`,
          action: 'Trust proactive recommendations',
          priority: 'LOW'
        });
      } else if (dashboard.ml.totalPredictions > 10) {
        insights.push({
          type: 'INFO',
          message: `Prediction accuracy is ${(dashboard.ml.predictionAccuracy * 100).toFixed(0)}% (improving with more data)`,
          action: 'Continue gathering data to improve predictions',
          priority: 'LOW'
        });
      }
    }

    report.insights = insights;

    return report;
  }

  /**
   * Close database connection
   */
  async close() {
    if (this.insight) {
      await this.insight.close();
    }
  }
}

module.exports = PatternIntegration;
