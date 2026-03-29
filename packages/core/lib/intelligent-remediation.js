/**
 * Intelligent Remediation Integration
 *
 * Integrates the Embeddings Engine with CodeTitan's existing analysis pipeline.
 * Automatically suggests fixes based on historical patterns.
 */

const EmbeddingsEngine = require('./embeddings-engine');
const CollectiveInsight = require('./collective-insight');
const path = require('path');

class IntelligentRemediation {
  constructor(options = {}) {
    this.dbPath = options.dbPath || path.join(__dirname, '..', 'data', 'collective-insight.db');
    this.embeddingsEngine = null;
    this.collectiveInsight = null;
    this.enabled = options.enabled !== false;
    this.confidenceThreshold = options.confidenceThreshold || 0.6;
  }

  /**
   * Initialize the intelligent remediation system
   */
  async init() {
    if (!this.enabled) {
      console.log('Intelligent Remediation disabled');
      return;
    }

    console.log('Initializing Intelligent Remediation...');

    // Initialize embeddings engine
    this.embeddingsEngine = new EmbeddingsEngine(this.dbPath);
    await this.embeddingsEngine.init();

    // Initialize collective insight
    this.collectiveInsight = new CollectiveInsight(this.dbPath);
    await this.collectiveInsight.init();

    console.log('✓ Intelligent Remediation ready');
  }

  /**
   * Process findings from analysis and enrich with recommendations
   * @param {Array} findings - Array of findings from domain analyzers
   * @returns {Array} - Enriched findings with recommendations
   */
  async enrichFindings(findings) {
    if (!this.enabled || !this.embeddingsEngine) {
      return findings;
    }

    console.log(`\n[BRAIN] Enriching ${findings.length} findings with AI recommendations...`);

    const enriched = [];
    let recommendationsAdded = 0;

    for (const finding of findings) {
      try {
        // Get remediation recommendation
        const recommendation = await this.embeddingsEngine.recommendRemediation(finding, 5);

        const enrichedFinding = {
          ...finding,
          recommendation: {
            status: recommendation.status,
            confidence: recommendation.confidence,
            suggestedFixes: recommendation.recommendations.map(rec => ({
              name: rec.fix,
              confidence: rec.confidence,
              description: this.getFixDescription(rec.fix),
              examples: rec.examples
            })),
            similarIssues: recommendation.similarIssues.length,
            autoFixable: recommendation.confidence >= this.confidenceThreshold
          }
        };

        if (recommendation.recommendations.length > 0) {
          recommendationsAdded++;
        }

        enriched.push(enrichedFinding);
      } catch (error) {
        console.warn(`Failed to enrich finding: ${error.message}`);
        enriched.push(finding);
      }
    }

    console.log(`✓ Added recommendations to ${recommendationsAdded}/${findings.length} findings`);

    return enriched;
  }

  /**
   * Learn from fix application results
   * @param {Object} finding - Original finding
   * @param {String} fixApplied - Name of fix that was applied
   * @param {Boolean} success - Whether the fix was successful
   */
  async recordFixResult(finding, fixApplied, success) {
    if (!this.enabled || !this.embeddingsEngine) {
      return;
    }

    try {
      await this.embeddingsEngine.learnFromFix(finding, fixApplied, success);
      console.log(`✓ Learned from fix: ${fixApplied} (${success ? 'success' : 'failed'})`);
    } catch (error) {
      console.warn(`Failed to record fix result: ${error.message}`);
    }
  }

  /**
   * Generate automated fix report
   * @param {Array} enrichedFindings - Findings with recommendations
   * @returns {Object} - Fix report with statistics
   */
  generateFixReport(enrichedFindings) {
    const report = {
      totalFindings: enrichedFindings.length,
      findingsWithRecommendations: 0,
      autoFixableCandidates: 0,
      fixesByCategory: {},
      highConfidenceFixes: [],
      summary: {}
    };

    for (const finding of enrichedFindings) {
      if (!finding.recommendation) continue;

      const rec = finding.recommendation;

      if (rec.suggestedFixes && rec.suggestedFixes.length > 0) {
        report.findingsWithRecommendations++;

        // Track by category
        if (!report.fixesByCategory[finding.category]) {
          report.fixesByCategory[finding.category] = {
            count: 0,
            fixes: new Set()
          };
        }
        report.fixesByCategory[finding.category].count++;
        rec.suggestedFixes.forEach(fix => {
          report.fixesByCategory[finding.category].fixes.add(fix.name);
        });
      }

      if (rec.autoFixable) {
        report.autoFixableCandidates++;

        report.highConfidenceFixes.push({
          file: finding.file,
          line: finding.line,
          category: finding.category,
          severity: finding.severity,
          message: finding.message,
          suggestedFix: rec.suggestedFixes[0].name,
          confidence: rec.confidence
        });
      }
    }

    // Convert Sets to Arrays for JSON serialization
    Object.keys(report.fixesByCategory).forEach(category => {
      report.fixesByCategory[category].fixes = Array.from(
        report.fixesByCategory[category].fixes
      );
    });

    // Generate summary
    report.summary = {
      recommendationCoverage: (report.findingsWithRecommendations / report.totalFindings * 100).toFixed(1) + '%',
      autoFixPotential: (report.autoFixableCandidates / report.totalFindings * 100).toFixed(1) + '%',
      topCategories: Object.entries(report.fixesByCategory)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 5)
        .map(([category, data]) => ({
          category,
          count: data.count,
          uniqueFixes: data.fixes.length
        }))
    };

    return report;
  }

  /**
   * Get fix description from fix name
   * This would ideally be loaded from a fix registry
   */
  getFixDescription(fixName) {
    const descriptions = {
      'sanitize-shell-input': 'Sanitize shell command inputs to prevent injection attacks',
      'async-fs-operations': 'Convert synchronous file operations to async/await',
      'add-jsdoc-comments': 'Add JSDoc documentation comments to exported functions',
      'generate-test-scaffold': 'Generate test file scaffold with basic test cases',
      'add-error-handling': 'Wrap code in try-catch block with proper error handling',
      'extract-function': 'Extract complex logic into separate well-named function',
      'add-input-validation': 'Add input validation and type checking',
      'use-https': 'Replace HTTP URLs with HTTPS for secure communication',
      'remove-todo-comment': 'Address TODO comment by implementing or removing it'
    };

    return descriptions[fixName] || `Apply ${fixName} fix`;
  }

  /**
   * Get performance metrics
   */
  getMetrics() {
    if (!this.embeddingsEngine) {
      return { enabled: false };
    }

    return {
      enabled: true,
      ...this.embeddingsEngine.getMetrics()
    };
  }

  /**
   * Close and cleanup
   */
  async close() {
    if (this.embeddingsEngine) {
      await this.embeddingsEngine.close();
    }
    if (this.collectiveInsight) {
      await this.collectiveInsight.close();
    }
  }
}

module.exports = IntelligentRemediation;
