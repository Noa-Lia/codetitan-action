/**
 * Pattern Learner - CodeTitan Level 6 ML Enhancement
 *
 * Implements machine learning pattern recognition for historical issue analysis
 * and proactive recommendations.
 *
 * Core Capabilities:
 * - Pattern detection via clustering and temporal analysis
 * - Learning pipeline tracking fixer success rates
 * - Proactive issue prediction based on code patterns
 * - Confidence-scored recommendations
 *
 * ML Algorithms Used:
 * - DBSCAN clustering for similar finding detection
 * - Bayesian inference for fixer success probability
 * - TF-IDF for code pattern matching
 * - Temporal correlation analysis for cascade failures
 * - Markov chains for issue prediction
 */

const fs = require('fs');
const path = require('path');

/**
 * Cosine similarity for vector comparison
 */
function cosineSimilarity(vecA, vecB) {
  const dotProduct = vecA.reduce((sum, val, i) => sum + val * vecB[i], 0);
  const magnitudeA = Math.sqrt(vecA.reduce((sum, val) => sum + val * val, 0));
  const magnitudeB = Math.sqrt(vecB.reduce((sum, val) => sum + val * val, 0));
  return magnitudeA && magnitudeB ? dotProduct / (magnitudeA * magnitudeB) : 0;
}

/**
 * Euclidean distance for clustering
 */
function euclideanDistance(vecA, vecB) {
  return Math.sqrt(vecA.reduce((sum, val, i) => sum + Math.pow(val - vecB[i], 2), 0));
}

/**
 * DBSCAN Clustering Implementation
 * Groups similar findings based on feature vectors
 */
class DBSCANClustering {
  constructor(eps = 0.3, minPts = 2) {
    this.eps = eps;
    this.minPts = minPts;
  }

  /**
   * Cluster findings into groups of similar issues
   * @param {Array} points - Array of {id, features: []} objects
   * @returns {Array} Array of clusters, each containing point IDs
   */
  cluster(points) {
    const visited = new Set();
    const clusters = [];
    let noise = [];

    for (let i = 0; i < points.length; i++) {
      if (visited.has(i)) continue;

      visited.add(i);
      const neighbors = this.regionQuery(points, i);

      if (neighbors.length < this.minPts) {
        noise.push(points[i].id);
      } else {
        const cluster = [];
        this.expandCluster(points, i, neighbors, cluster, visited);
        clusters.push(cluster);
      }
    }

    return { clusters, noise };
  }

  regionQuery(points, pointIdx) {
    const neighbors = [];
    const point = points[pointIdx];

    for (let i = 0; i < points.length; i++) {
      if (i === pointIdx) continue;
      const dist = euclideanDistance(point.features, points[i].features);
      if (dist <= this.eps) {
        neighbors.push(i);
      }
    }

    return neighbors;
  }

  expandCluster(points, pointIdx, neighbors, cluster, visited) {
    cluster.push(points[pointIdx].id);

    for (let i = 0; i < neighbors.length; i++) {
      const neighborIdx = neighbors[i];

      if (!visited.has(neighborIdx)) {
        visited.add(neighborIdx);
        const newNeighbors = this.regionQuery(points, neighborIdx);

        if (newNeighbors.length >= this.minPts) {
          neighbors.push(...newNeighbors);
        }
      }

      // Add to cluster if not already in any cluster
      if (!cluster.includes(points[neighborIdx].id)) {
        cluster.push(points[neighborIdx].id);
      }
    }
  }
}

/**
 * Bayesian Success Probability Model
 * Tracks and learns from fixer success rates
 */
class BayesianFixerModel {
  constructor() {
    // Prior: initially assume 50% success rate
    this.prior = { alpha: 2, beta: 2 };
    // Category-specific models
    this.categoryModels = new Map();
  }

  /**
   * Update model with fix attempt result
   * @param {string} category - Issue category
   * @param {boolean} success - Whether fix succeeded
   */
  updateModel(category, success) {
    if (!this.categoryModels.has(category)) {
      this.categoryModels.set(category, { ...this.prior });
    }

    const model = this.categoryModels.get(category);
    if (success) {
      model.alpha += 1;
    } else {
      model.beta += 1;
    }
  }

  /**
   * Get success probability for a category
   * @param {string} category - Issue category
   * @returns {number} Probability between 0 and 1
   */
  getSuccessProbability(category) {
    const model = this.categoryModels.get(category) || this.prior;
    // Mean of Beta distribution: alpha / (alpha + beta)
    return model.alpha / (model.alpha + model.beta);
  }

  /**
   * Get confidence interval for success rate
   * @param {string} category - Issue category
   * @returns {object} {lower, upper, confidence}
   */
  getConfidenceInterval(category, confidence = 0.95) {
    const model = this.categoryModels.get(category) || this.prior;
    const mean = this.getSuccessProbability(category);

    // Simplified confidence calculation using normal approximation
    const n = model.alpha + model.beta;
    const variance = (model.alpha * model.beta) / (n * n * (n + 1));
    const stdDev = Math.sqrt(variance);

    // Z-score for 95% confidence ~ 1.96
    const z = confidence === 0.95 ? 1.96 : 1.645;

    return {
      mean,
      lower: Math.max(0, mean - z * stdDev),
      upper: Math.min(1, mean + z * stdDev),
      confidence,
      sampleSize: n - 4 // Subtract prior
    };
  }

  /**
   * Serialize model for storage
   */
  toJSON() {
    return {
      prior: this.prior,
      categories: Array.from(this.categoryModels.entries()).map(([cat, model]) => ({
        category: cat,
        alpha: model.alpha,
        beta: model.beta,
        successRate: this.getSuccessProbability(cat)
      }))
    };
  }

  /**
   * Restore model from JSON
   */
  static fromJSON(data) {
    const model = new BayesianFixerModel();
    model.prior = data.prior;
    data.categories.forEach(({ category, alpha, beta }) => {
      model.categoryModels.set(category, { alpha, beta });
    });
    return model;
  }
}

/**
 * TF-IDF Code Pattern Analyzer
 * Extracts and matches code patterns across findings
 */
class CodePatternAnalyzer {
  constructor() {
    this.vocabulary = new Map();
    this.documentFrequency = new Map();
    this.totalDocuments = 0;
  }

  /**
   * Tokenize code snippet into features
   */
  tokenize(code) {
    // Extract meaningful tokens: identifiers, keywords, operators
    const tokens = [];

    // Keywords
    const keywords = code.match(/\b(function|const|let|var|if|for|while|return|await|async|class|import|export|require)\b/g) || [];
    tokens.push(...keywords);

    // API calls and method names
    const apiCalls = code.match(/\w+\.\w+/g) || [];
    tokens.push(...apiCalls);

    // Function/constructor calls
    const calls = code.match(/\w+\s*\(/g) || [];
    tokens.push(...calls.map(c => c.trim()));

    return tokens;
  }

  /**
   * Build TF-IDF vectors for code snippets
   * @param {Array} documents - Array of {id, code} objects
   */
  buildVectors(documents) {
    this.totalDocuments = documents.length;

    // Build vocabulary and document frequency
    documents.forEach(doc => {
      const tokens = this.tokenize(doc.code);
      const uniqueTokens = new Set(tokens);

      uniqueTokens.forEach(token => {
        this.documentFrequency.set(
          token,
          (this.documentFrequency.get(token) || 0) + 1
        );
      });
    });

    // Calculate TF-IDF vectors
    return documents.map(doc => {
      const tokens = this.tokenize(doc.code);
      const termFreq = new Map();

      tokens.forEach(token => {
        termFreq.set(token, (termFreq.get(token) || 0) + 1);
      });

      const vector = [];
      const features = [];

      this.documentFrequency.forEach((df, term) => {
        const tf = termFreq.get(term) || 0;
        const idf = Math.log(this.totalDocuments / df);
        const tfidf = tf * idf;

        vector.push(tfidf);
        features.push(term);
      });

      return {
        id: doc.id,
        vector,
        features,
        originalTokens: tokens
      };
    });
  }

  /**
   * Find similar code patterns
   * @param {string} targetCode - Code to find patterns for
   * @param {Array} vectors - Pre-computed TF-IDF vectors
   * @param {number} threshold - Similarity threshold (0-1)
   */
  findSimilarPatterns(targetCode, vectors, threshold = 0.3) {
    const targetTokens = this.tokenize(targetCode);
    const targetVector = [];

    this.documentFrequency.forEach((df, term) => {
      const tf = targetTokens.filter(t => t === term).length;
      const idf = Math.log(this.totalDocuments / df);
      targetVector.push(tf * idf);
    });

    const similarities = vectors.map(vec => ({
      id: vec.id,
      similarity: cosineSimilarity(targetVector, vec.vector)
    }));

    return similarities
      .filter(s => s.similarity >= threshold)
      .sort((a, b) => b.similarity - a.similarity);
  }
}

/**
 * Temporal Pattern Detector
 * Analyzes time-series relationships between findings
 */
class TemporalPatternDetector {
  constructor() {
    this.cooccurrenceMatrix = new Map();
    this.cascadeChains = [];
  }

  /**
   * Analyze temporal relationships in findings
   * @param {Array} historicalRuns - Array of runs with findings
   */
  analyzeTemporalPatterns(historicalRuns) {
    // Sort runs by timestamp
    const sortedRuns = historicalRuns.sort((a, b) =>
      new Date(a.timestamp) - new Date(b.timestamp)
    );

    // Build co-occurrence matrix
    sortedRuns.forEach(run => {
      const categories = run.findings.map(f => f.category);

      for (let i = 0; i < categories.length; i++) {
        for (let j = i + 1; j < categories.length; j++) {
          const pair = [categories[i], categories[j]].sort().join('|');
          this.cooccurrenceMatrix.set(
            pair,
            (this.cooccurrenceMatrix.get(pair) || 0) + 1
          );
        }
      }
    });

    // Detect cascade patterns (A appears, then B appears in next run)
    for (let i = 0; i < sortedRuns.length - 1; i++) {
      const currentCategories = new Set(sortedRuns[i].findings.map(f => f.category));
      const nextCategories = new Set(sortedRuns[i + 1].findings.map(f => f.category));

      currentCategories.forEach(current => {
        nextCategories.forEach(next => {
          if (current !== next) {
            const chain = `${current} -> ${next}`;
            const existing = this.cascadeChains.find(c => c.chain === chain);
            if (existing) {
              existing.count++;
            } else {
              this.cascadeChains.push({ chain, from: current, to: next, count: 1 });
            }
          }
        });
      });
    }

    return {
      cooccurring: this.getTopCooccurrences(5),
      cascades: this.cascadeChains
        .sort((a, b) => b.count - a.count)
        .slice(0, 5)
    };
  }

  /**
   * Get categories that frequently appear together
   */
  getTopCooccurrences(limit = 5) {
    return Array.from(this.cooccurrenceMatrix.entries())
      .map(([pair, count]) => ({
        categories: pair.split('|'),
        count
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  /**
   * Predict likely next issues based on current findings
   * @param {Array} currentCategories - Categories in current analysis
   * @returns {Array} Predicted categories with probabilities
   */
  predictNextIssues(currentCategories) {
    const predictions = new Map();

    currentCategories.forEach(category => {
      const relevantCascades = this.cascadeChains.filter(c => c.from === category);
      const total = relevantCascades.reduce((sum, c) => sum + c.count, 0);

      relevantCascades.forEach(cascade => {
        const probability = cascade.count / total;
        predictions.set(cascade.to, (predictions.get(cascade.to) || 0) + probability);
      });
    });

    return Array.from(predictions.entries())
      .map(([category, probability]) => ({ category, probability }))
      .sort((a, b) => b.probability - a.probability);
  }
}

/**
 * Root Cause Correlation Analyzer
 * Identifies common root causes across findings
 */
class RootCauseAnalyzer {
  constructor() {
    this.filePathPatterns = new Map();
    this.categoryCorrelations = new Map();
  }

  /**
   * Analyze correlations between findings
   * @param {Array} findings - All findings from database
   */
  analyzeCorrelations(findings) {
    // Group by file path patterns
    findings.forEach(finding => {
      if (!finding.file) return;

      // Extract path patterns (e.g., lib/*, scripts/*, etc.)
      const pathPattern = this.extractPathPattern(finding.file);

      if (!this.filePathPatterns.has(pathPattern)) {
        this.filePathPatterns.set(pathPattern, {
          pattern: pathPattern,
          categories: new Map(),
          count: 0
        });
      }

      const pattern = this.filePathPatterns.get(pathPattern);
      pattern.count++;
      pattern.categories.set(
        finding.category,
        (pattern.categories.get(finding.category) || 0) + 1
      );
    });

    // Find categories that correlate (appear together frequently)
    const categoryPairs = new Map();

    this.filePathPatterns.forEach(pattern => {
      const categories = Array.from(pattern.categories.keys());
      for (let i = 0; i < categories.length; i++) {
        for (let j = i + 1; j < categories.length; j++) {
          const pair = [categories[i], categories[j]].sort().join('|');
          categoryPairs.set(pair, (categoryPairs.get(pair) || 0) + 1);
        }
      }
    });

    this.categoryCorrelations = categoryPairs;

    return {
      pathPatterns: Array.from(this.filePathPatterns.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      correlatedCategories: Array.from(categoryPairs.entries())
        .map(([pair, count]) => ({
          categories: pair.split('|'),
          count
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
    };
  }

  /**
   * Extract generalized path pattern
   */
  extractPathPattern(filePath) {
    const parts = filePath.split(/[/\\]/);

    if (parts.length <= 2) {
      return parts.join('/');
    }

    // Return first two levels: lib/*, scripts/*, etc.
    return parts.slice(0, 2).join('/') + '/*';
  }

  /**
   * Identify root cause based on finding cluster
   */
  identifyRootCause(findingCluster) {
    const categories = findingCluster.map(f => f.category);
    const files = findingCluster.map(f => f.file);

    // Check if all in same path pattern
    const pathPatterns = files.map(f => this.extractPathPattern(f));
    const uniquePatterns = new Set(pathPatterns);

    let rootCause = {
      type: 'distributed',
      confidence: 0.3
    };

    if (uniquePatterns.size === 1) {
      rootCause = {
        type: 'localized',
        location: Array.from(uniquePatterns)[0],
        confidence: 0.8,
        suggestion: `Issues concentrated in ${Array.from(uniquePatterns)[0]}. Consider refactoring this module.`
      };
    } else if (categories.length > 0 && new Set(categories).size === 1) {
      rootCause = {
        type: 'systemic',
        category: categories[0],
        confidence: 0.7,
        suggestion: `Pattern of ${categories[0]} across multiple files suggests systemic issue. Review coding standards.`
      };
    }

    return rootCause;
  }
}

/**
 * Main Pattern Learner Class
 * Orchestrates all ML components
 */
class PatternLearner {
  constructor() {
    this.clustering = new DBSCANClustering(0.3, 2);
    this.fixerModel = new BayesianFixerModel();
    this.codeAnalyzer = new CodePatternAnalyzer();
    this.temporalDetector = new TemporalPatternDetector();
    this.rootCauseAnalyzer = new RootCauseAnalyzer();
  }

  /**
   * Detect patterns in historical findings
   * @param {Array} findingsHistory - Array of finding objects from database
   * @returns {object} Detected patterns and clusters
   */
  detectPatterns(findingsHistory) {
    console.log(`\n[BRAIN] Pattern Detection: Analyzing ${findingsHistory.length} historical findings...`);

    // Convert findings to feature vectors
    const features = this.extractFeatures(findingsHistory);

    // Cluster similar findings
    const clusterResult = this.clustering.cluster(features);
    console.log(`   Found ${clusterResult.clusters.length} clusters and ${clusterResult.noise.length} unique issues`);

    // Build TF-IDF vectors for code patterns
    const codeDocuments = findingsHistory
      .filter(f => f.snippet)
      .map(f => ({ id: f.id, code: f.snippet }));

    const codeVectors = codeDocuments.length > 0
      ? this.codeAnalyzer.buildVectors(codeDocuments)
      : [];

    console.log(`   Analyzed ${codeVectors.length} code patterns`);

    // Map clusters back to findings
    const patternClusters = clusterResult.clusters.map((cluster, idx) => {
      const clusterFindings = cluster.map(id =>
        findingsHistory.find(f => f.id === id)
      ).filter(Boolean);

      return {
        id: `cluster_${idx}`,
        size: cluster.length,
        categories: [...new Set(clusterFindings.map(f => f.category))],
        severities: [...new Set(clusterFindings.map(f => f.severity))],
        dominantCategory: this.getDominantValue(clusterFindings, 'category'),
        dominantSeverity: this.getDominantValue(clusterFindings, 'severity'),
        rootCause: this.rootCauseAnalyzer.identifyRootCause(clusterFindings),
        findings: clusterFindings
      };
    });

    return {
      clusters: patternClusters,
      totalPatterns: clusterResult.clusters.length,
      uniqueIssues: clusterResult.noise.length,
      codePatterns: codeVectors,
      summary: {
        mostCommonCategory: this.getDominantValue(findingsHistory, 'category'),
        mostCommonSeverity: this.getDominantValue(findingsHistory, 'severity'),
        avgClusterSize: clusterResult.clusters.length > 0
          ? clusterResult.clusters.reduce((sum, c) => sum + c.length, 0) / clusterResult.clusters.length
          : 0
      }
    };
  }

  /**
   * Extract feature vectors from findings
   */
  extractFeatures(findings) {
    return findings.map(finding => {
      // Categorical encoding
      const severityMap = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const domainMap = { Security: 4, Performance: 3, Testing: 2, 'Code Quality': 1, Documentation: 0 };

      const features = [
        severityMap[finding.severity] || 0,
        domainMap[finding.domain] || 0,
        // Category hash (simple numeric encoding)
        this.hashString(finding.category || '') % 100 / 100,
        // File depth indicator
        (finding.file || '').split(/[/\\]/).length / 10,
        // Line position (normalized)
        (finding.line || 0) / 1000
      ];

      return {
        id: finding.id,
        features
      };
    });
  }

  /**
   * Learn from fix history
   * @param {Array} fixHistory - Array of {category, success, timestamp} objects
   */
  learnFromFixes(fixHistory) {
    console.log(`\n[BOOKS] Learning Pipeline: Processing ${fixHistory.length} fix attempts...`);

    fixHistory.forEach(fix => {
      this.fixerModel.updateModel(fix.category, fix.success);
    });

    const modelSummary = this.fixerModel.toJSON();
    console.log(`   Learned success rates for ${modelSummary.categories.length} categories`);

    return {
      model: modelSummary,
      topSuccessRates: modelSummary.categories
        .sort((a, b) => b.successRate - a.successRate)
        .slice(0, 5),
      lowSuccessRates: modelSummary.categories
        .sort((a, b) => a.successRate - b.successRate)
        .slice(0, 5)
    };
  }

  /**
   * Predict issues in current codebase
   * @param {object} currentAnalysis - Current analysis results
   * @param {Array} historicalRuns - Historical run data
   * @returns {object} Predicted issues with confidence
   */
  predictIssues(currentAnalysis, historicalRuns = []) {
    console.log(`\n🔮 Predictive Analysis: Forecasting potential issues...`);

    if (historicalRuns.length === 0) {
      return {
        predictions: [],
        confidence: 0,
        message: 'Insufficient historical data for predictions'
      };
    }

    // Analyze temporal patterns
    const temporalPatterns = this.temporalDetector.analyzeTemporalPatterns(historicalRuns);

    // Get current categories
    const currentCategories = currentAnalysis.findings
      ? currentAnalysis.findings.map(f => f.category)
      : [];

    // Predict next likely issues
    const predictions = this.temporalDetector.predictNextIssues(currentCategories);

    console.log(`   Generated ${predictions.length} predictions`);

    return {
      predictions: predictions.slice(0, 10),
      temporalPatterns,
      currentCategories: [...new Set(currentCategories)],
      confidence: predictions.length > 0 ? 0.7 : 0.3
    };
  }

  /**
   * Rank recommendations by impact and confidence
   * @param {Array} findings - Current findings
   * @param {object} patterns - Detected patterns
   * @returns {Array} Ranked recommendations
   */
  rankRecommendations(findings, patterns = {}) {
    console.log(`\n[STAR] Recommendation Engine: Ranking ${findings.length} findings...`);

    const recommendations = findings.map(finding => {
      // Base score: severity x impact
      const severityWeight = { CRITICAL: 100, HIGH: 50, MEDIUM: 20, LOW: 5 };
      const baseScore = (severityWeight[finding.severity] || 10) * (finding.impact || 1);

      // Confidence from fixer model
      const fixerConfidence = this.fixerModel.getConfidenceInterval(finding.category);

      // Pattern frequency bonus (recurring issues get higher priority)
      let frequencyBonus = 0;
      if (patterns.clusters) {
        const inCluster = patterns.clusters.find(c =>
          c.categories.includes(finding.category)
        );
        if (inCluster && inCluster.size > 2) {
          frequencyBonus = Math.log(inCluster.size) * 10;
        }
      }

      const totalScore = baseScore + frequencyBonus;
      const confidence = fixerConfidence.sampleSize > 0
        ? fixerConfidence.mean
        : 0.5;

      return {
        finding,
        score: totalScore,
        confidence,
        fixSuccessRate: fixerConfidence.mean,
        fixerConfidenceInterval: fixerConfidence,
        priority: this.calculatePriority(totalScore, confidence),
        recommendation: this.generateRecommendation(finding, fixerConfidence, patterns)
      };
    });

    const ranked = recommendations.sort((a, b) => b.score - a.score);

    console.log(`   Top priority: ${ranked[0]?.finding.category || 'none'} (score: ${ranked[0]?.score.toFixed(1) || 0})`);

    return ranked;
  }

  /**
   * Calculate priority level
   */
  calculatePriority(score, confidence) {
    const combined = score * confidence;
    if (combined > 100) return 'CRITICAL';
    if (combined > 50) return 'HIGH';
    if (combined > 20) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Generate actionable recommendation
   */
  generateRecommendation(finding, fixerConfidence, patterns) {
    const recommendations = [];

    // Fix recommendation based on success rate
    if (fixerConfidence.mean > 0.7) {
      recommendations.push({
        action: 'AUTO_FIX',
        description: `Automatic fix available with ${(fixerConfidence.mean * 100).toFixed(0)}% success rate`,
        confidence: fixerConfidence.mean
      });
    } else if (fixerConfidence.mean > 0.4) {
      recommendations.push({
        action: 'MANUAL_REVIEW',
        description: `Review automated fix suggestion (${(fixerConfidence.mean * 100).toFixed(0)}% success rate)`,
        confidence: fixerConfidence.mean
      });
    } else {
      recommendations.push({
        action: 'MANUAL_FIX',
        description: 'Manual intervention recommended',
        confidence: 0.8
      });
    }

    // Pattern-based recommendations
    if (patterns.clusters) {
      const relatedCluster = patterns.clusters.find(c =>
        c.categories.includes(finding.category)
      );
      if (relatedCluster && relatedCluster.rootCause.suggestion) {
        recommendations.push({
          action: 'ROOT_CAUSE',
          description: relatedCluster.rootCause.suggestion,
          confidence: relatedCluster.rootCause.confidence
        });
      }
    }

    return recommendations;
  }

  /**
   * Helper: Get most common value in array of objects
   */
  getDominantValue(items, key) {
    const counts = new Map();
    items.forEach(item => {
      const value = item[key];
      counts.set(value, (counts.get(value) || 0) + 1);
    });

    let maxCount = 0;
    let dominant = null;
    counts.forEach((count, value) => {
      if (count > maxCount) {
        maxCount = count;
        dominant = value;
      }
    });

    return dominant;
  }

  /**
   * Simple string hash function
   */
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }

  /**
   * Analyze root causes across findings
   * @param {Array} findings - Findings to analyze
   */
  analyzeRootCauses(findings) {
    return this.rootCauseAnalyzer.analyzeCorrelations(findings);
  }

  /**
   * Save model state
   */
  saveModel(filePath) {
    const state = {
      fixerModel: this.fixerModel.toJSON(),
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    };

    // TODO: Fix SYNC_IO - Synchronous fs operation blocks the event loop. Consider async alternatives.
    fs.writeFileSync(filePath, JSON.stringify(state, null, 2));
    return state;
  }

  /**
   * Load model state
   */
  loadModel(filePath) {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    // TODO: Fix SYNC_IO - Synchronous fs operation blocks the event loop. Consider async alternatives.

    const state = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    this.fixerModel = BayesianFixerModel.fromJSON(state.fixerModel);
    return state;
  }
}

module.exports = {
  PatternLearner,
  DBSCANClustering,
  BayesianFixerModel,
  CodePatternAnalyzer,
  TemporalPatternDetector,
  RootCauseAnalyzer
};
