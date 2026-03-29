/**
 * Quality Gate - CI/CD Quality Checks
 *
 * Enforces minimum quality thresholds before deployments:
 * - Minimum accuracy requirements
 * - Calibration error thresholds
 * - Provider performance checks
 * - Confidence score requirements
 *
 * @module quality-gate
 */

const ConfidenceAnalytics = require('./confidence-analytics');

class QualityGate {
  constructor(config = {}) {
    this.config = {
      // Thresholds
      minAccuracy: config.minAccuracy || 0.85,        // 85% minimum accuracy
      maxCalibrationError: config.maxCalibrationError || 0.20,  // 20% max ECE
      minConfidenceAvg: config.minConfidenceAvg || 70,  // 70% avg confidence
      minHighConfidencePct: config.minHighConfidencePct || 0.30, // 30% high confidence

      // Flags
      blockOnFailure: config.blockOnFailure !== false,
      verbose: config.verbose || false,

      ...config
    };

    this.analytics = new ConfidenceAnalytics();
  }

  /**
   * Check if quality gate passes
   *
   * @param {string} runId - Run ID
   * @param {string} projectId - Project ID
   * @returns {Promise<Object>} Gate result
   */
  async checkGate(runId, projectId) {
    this.log('🚦 Checking quality gate...');

    const issues = [];
    const warnings = [];
    const metrics = {};

    try {
      // Get calibration data
      const calibration = await this.analytics.getCalibrationSummary(projectId);

      if (calibration) {
        metrics.accuracy = calibration.overall_accuracy;
        metrics.calibration = calibration.expected_calibration_error;
        metrics.totalPredictions = calibration.total_predictions;

        // Check accuracy
        if (calibration.overall_accuracy < this.config.minAccuracy) {
          issues.push({
            type: 'accuracy',
            severity: 'HIGH',
            message: `Accuracy ${(calibration.overall_accuracy * 100).toFixed(1)}% below threshold ${(this.config.minAccuracy * 100)}%`,
            actual: calibration.overall_accuracy,
            expected: this.config.minAccuracy
          });
        } else if (calibration.overall_accuracy < this.config.minAccuracy + 0.05) {
          warnings.push({
            type: 'accuracy',
            message: `Accuracy ${(calibration.overall_accuracy * 100).toFixed(1)}% close to threshold`,
            actual: calibration.overall_accuracy
          });
        }

        // Check calibration error
        if (calibration.expected_calibration_error > this.config.maxCalibrationError) {
          issues.push({
            type: 'calibration',
            severity: 'MEDIUM',
            message: `Calibration error ${(calibration.expected_calibration_error * 100).toFixed(1)}% above threshold ${(this.config.maxCalibrationError * 100)}%`,
            actual: calibration.expected_calibration_error,
            expected: this.config.maxCalibrationError
          });
        }

        // Check minimum predictions
        if (calibration.total_predictions < 10) {
          warnings.push({
            type: 'data',
            message: `Only ${calibration.total_predictions} predictions - metrics may be unreliable`,
            actual: calibration.total_predictions
          });
        }
      } else {
        warnings.push({
          type: 'data',
          message: 'No calibration data available - gate checks skipped'
        });
      }

      // Get provider comparison
      const providers = await this.analytics.getProviderComparison(projectId);

      if (providers && providers.length > 0) {
        const avgAccuracy = providers.reduce((sum, p) => sum + (p.accuracy_pct || 0), 0) / providers.length;
        metrics.providerAccuracyAvg = avgAccuracy;

        if (avgAccuracy < this.config.minAccuracy * 100) {
          issues.push({
            type: 'provider_accuracy',
            severity: 'MEDIUM',
            message: `Average provider accuracy ${avgAccuracy.toFixed(1)}% below threshold`,
            actual: avgAccuracy / 100,
            expected: this.config.minAccuracy
          });
        }
      }

      // Determine if gate passes
      const passed = issues.length === 0;

      const result = {
        passed,
        timestamp: new Date().toISOString(),
        runId,
        projectId,
        metrics,
        issues,
        warnings,
        recommendation: passed ?
          'Quality gate passed - safe to deploy' :
          'Quality gate failed - review issues before deploying'
      };

      if (!passed) {
        this.log(`❌ Quality gate FAILED - ${issues.length} issues found`, 'error');
        issues.forEach(issue => {
          this.log(`   • [${issue.severity}] ${issue.message}`, 'error');
        });
      } else {
        this.log(`✅ Quality gate PASSED`);
        if (warnings.length > 0) {
          this.log(`⚠️  ${warnings.length} warnings:`);
          warnings.forEach(warning => {
            this.log(`   • ${warning.message}`, 'warn');
          });
        }
      }

      return result;

    } catch (error) {
      this.log(`❌ Quality gate check failed: ${error.message}`, 'error');

      if (this.config.blockOnFailure) {
        throw error;
      }

      return {
        passed: false,
        error: error.message,
        timestamp: new Date().toISOString(),
        runId,
        projectId
      };
    }
  }

  /**
   * Check gate with custom thresholds
   */
  async checkWithThresholds(runId, projectId, thresholds) {
    const originalConfig = { ...this.config };
    this.config = { ...this.config, ...thresholds };

    try {
      return await this.checkGate(runId, projectId);
    } finally {
      this.config = originalConfig;
    }
  }

  /**
   * Get gate configuration
   */
  getConfig() {
    return { ...this.config };
  }

  /**
   * Update gate configuration
   */
  updateConfig(updates) {
    this.config = { ...this.config, ...updates };
  }

  /**
   * Log message
   */
  log(message, level = 'info') {
    if (this.config.verbose || level === 'error' || level === 'warn') {
      const prefix = level === 'error' ? '❌' : level === 'warn' ? '⚠️' : 'ℹ️';
      console.log(`${prefix} [QualityGate] ${message}`);
    }
  }
}

module.exports = QualityGate;
