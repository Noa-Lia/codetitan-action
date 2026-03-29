/**
 * ML-Enhanced Confidence Scoring Engine
 * 
 * Provides machine learning-based confidence scoring that learns from:
 * - Historical accept/reject decisions
 * - Project-specific patterns
 * - Context-aware adjustments
 * - False positive feedback loops
 * 
 * @module ml-confidence-scorer
 */

const { createClient } = require('@supabase/supabase-js');

/**
 * Feature weights learned from historical data
 */
const DEFAULT_WEIGHTS = {
    // Code characteristics
    patternMatch: 0.25,
    codeComplexity: 0.15,
    contextSimilarity: 0.15,

    // Historical signals
    categoryAcceptRate: 0.15,
    projectAcceptRate: 0.10,
    userAcceptRate: 0.05,

    // Verification signals
    aiConsensus: 0.10,
    testCoverage: 0.05,
};

/**
 * Context-aware threshold configurations
 */
const CONTEXT_THRESHOLDS = {
    // File type contexts
    'test-file': { autoApply: 0.95, suggest: 0.80, ignore: 0.30 },
    'production-code': { autoApply: 0.98, suggest: 0.85, ignore: 0.40 },
    'config-file': { autoApply: 0.99, suggest: 0.90, ignore: 0.50 },

    // Severity contexts
    'security-critical': { autoApply: 0.99, suggest: 0.90, ignore: 0.50 },
    'performance': { autoApply: 0.90, suggest: 0.75, ignore: 0.35 },
    'style': { autoApply: 0.85, suggest: 0.60, ignore: 0.25 },

    // Risk contexts
    'breaking-change': { autoApply: 0.99, suggest: 0.95, ignore: 0.60 },
    'non-breaking': { autoApply: 0.90, suggest: 0.75, ignore: 0.30 },

    // Default
    'default': { autoApply: 0.92, suggest: 0.75, ignore: 0.35 },
};

/**
 * ML-Enhanced Confidence Scorer
 */
class MLConfidenceScorer {
    constructor(config = {}) {
        this.config = {
            supabaseUrl: config.supabaseUrl || process.env.SUPABASE_URL,
            supabaseKey: config.supabaseKey || process.env.SUPABASE_SERVICE_KEY,
            learningRate: config.learningRate || 0.01,
            minSamples: config.minSamples || 10,
            cacheExpiry: config.cacheExpiry || 3600000, // 1 hour
            ...config,
        };

        // Learned weights (start with defaults, update from DB)
        this.weights = { ...DEFAULT_WEIGHTS };

        // Project-specific weight overrides
        this.projectWeights = new Map();

        // Category-specific adjustment factors
        this.categoryFactors = new Map();

        // False positive tracking
        this.falsePositiveCache = new Map();

        // Pattern memory for similar fixes
        this.patternMemory = new Map();

        // Initialize Supabase client if credentials available
        if (this.config.supabaseUrl && this.config.supabaseKey) {
            this.supabase = createClient(
                this.config.supabaseUrl,
                this.config.supabaseKey
            );
        }

        // Load learned weights from DB
        this.initializeWeights();
    }

    /**
     * Initialize weights from historical data
     */
    async initializeWeights() {
        if (!this.supabase) return;

        try {
            // Load global learned weights
            const { data: globalWeights } = await this.supabase
                .from('ml_confidence_weights')
                .select('*')
                .eq('scope', 'global')
                .single();

            if (globalWeights?.weights) {
                this.weights = { ...this.weights, ...globalWeights.weights };
            }

            // Load category factors
            const { data: categoryData } = await this.supabase
                .from('ml_category_factors')
                .select('*');

            if (categoryData) {
                for (const row of categoryData) {
                    this.categoryFactors.set(row.category, row.factor);
                }
            }

            console.log('[MLConfidence] Loaded weights from database');
        } catch (error) {
            // Silently use defaults if DB not available
        }
    }

    /**
     * Calculate ML-enhanced confidence score
     */
    async calculateConfidence(finding, context = {}) {
        const features = await this.extractFeatures(finding, context);

        // Base weighted score
        let score = this.calculateWeightedScore(features);

        // Apply context-aware adjustments
        score = this.applyContextAdjustments(score, context);

        // Apply false positive penalty
        score = this.applyFalsePositivePenalty(score, finding);

        // Apply category-specific factors
        score = this.applyCategoryFactor(score, finding.category);

        // Apply project-specific learned adjustments
        score = await this.applyProjectLearning(score, finding, context);

        // Clamp to valid range
        score = Math.max(0, Math.min(1, score));

        // Determine action thresholds based on context
        const thresholds = this.getContextThresholds(context);
        const action = this.determineAction(score, thresholds);

        return {
            score: Math.round(score * 100) / 100,
            confidence: Math.round(score * 100),
            level: this.getConfidenceLevel(score),
            action,
            thresholds,
            features,
            explanation: this.generateExplanation(score, features, action),
            adjustments: {
                contextFactor: context.contextFactor || 1,
                falsePositivePenalty: this.getFalsePositivePenalty(finding),
                categoryFactor: this.categoryFactors.get(finding.category) || 1,
            },
        };
    }

    /**
     * Extract ML features from finding and context
     */
    async extractFeatures(finding, context) {
        const features = {};

        // Pattern match quality (0-1)
        features.patternMatch = this.assessPatternMatch(finding);

        // Code complexity score (0-1, lower is better)
        features.codeComplexity = 1 - (Math.min(context.complexity || 5, 10) / 10);

        // Context similarity to successful fixes (0-1)
        features.contextSimilarity = await this.calculateContextSimilarity(finding, context);

        // Historical accept rate for this category (0-1)
        features.categoryAcceptRate = await this.getCategoryAcceptRate(finding.category);

        // Project-specific accept rate (0-1)
        features.projectAcceptRate = await this.getProjectAcceptRate(context.projectId);

        // User accept rate (0-1)
        features.userAcceptRate = await this.getUserAcceptRate(context.userId);

        // AI consensus (did multiple AI models agree?) (0-1)
        features.aiConsensus = context.aiConsensus || 0.5;

        // Test coverage indicator (0-1)
        features.testCoverage = context.hasTests ? 0.8 : 0.5;

        return features;
    }

    /**
     * Calculate weighted score from features
     */
    calculateWeightedScore(features) {
        let score = 0;
        let totalWeight = 0;

        for (const [feature, value] of Object.entries(features)) {
            const weight = this.weights[feature] || 0;
            score += value * weight;
            totalWeight += weight;
        }

        return totalWeight > 0 ? score / totalWeight * totalWeight : 0.5;
    }

    /**
     * Assess pattern match quality
     */
    assessPatternMatch(finding) {
        let score = 0.5;

        // Higher confidence if rule exists
        if (finding.ruleId) score += 0.2;

        // Higher confidence if CWE mapped
        if (finding.cwe) score += 0.1;

        // Higher confidence if exact line found
        if (finding.line && finding.column) score += 0.1;

        // Higher confidence if fix is suggested
        if (finding.fix) score += 0.1;

        return Math.min(1, score);
    }

    /**
     * Calculate similarity to past successful fixes
     */
    async calculateContextSimilarity(finding, context) {
        // Check pattern memory for similar patterns
        const key = `${finding.category}:${finding.ruleId || 'unknown'}`;
        const cached = this.patternMemory.get(key);

        if (cached && Date.now() - cached.timestamp < this.config.cacheExpiry) {
            return cached.similarity;
        }

        if (!this.supabase || !context.projectId) return 0.5;

        try {
            // Find similar fixes in history
            const { data: similar } = await this.supabase
                .from('fix_outcomes')
                .select('confidence_score, was_accepted, file_type')
                .eq('category', finding.category)
                .eq('project_id', context.projectId)
                .order('created_at', { ascending: false })
                .limit(20);

            if (!similar || similar.length < 3) return 0.5;

            // Calculate similarity based on accept rate and average confidence
            const acceptedCount = similar.filter(s => s.was_accepted).length;
            const similarity = acceptedCount / similar.length;

            this.patternMemory.set(key, { similarity, timestamp: Date.now() });

            return similarity;
        } catch {
            return 0.5;
        }
    }

    /**
     * Get historical accept rate for category
     */
    async getCategoryAcceptRate(category) {
        if (!this.supabase) return 0.5;

        const cached = this.categoryFactors.get(`rate:${category}`);
        if (cached !== undefined) return cached;

        try {
            const { data } = await this.supabase
                .from('fix_outcomes')
                .select('was_accepted')
                .eq('category', category)
                .limit(100);

            if (!data || data.length < 5) return 0.5;

            const rate = data.filter(d => d.was_accepted).length / data.length;
            this.categoryFactors.set(`rate:${category}`, rate);

            return rate;
        } catch {
            return 0.5;
        }
    }

    /**
     * Get project-specific accept rate
     */
    async getProjectAcceptRate(projectId) {
        if (!this.supabase || !projectId) return 0.5;

        try {
            const { data } = await this.supabase
                .from('fix_outcomes')
                .select('was_accepted')
                .eq('project_id', projectId)
                .limit(50);

            if (!data || data.length < 5) return 0.5;

            return data.filter(d => d.was_accepted).length / data.length;
        } catch {
            return 0.5;
        }
    }

    /**
     * Get user-specific accept rate
     */
    async getUserAcceptRate(userId) {
        if (!this.supabase || !userId) return 0.5;

        try {
            const { data } = await this.supabase
                .from('fix_outcomes')
                .select('was_accepted')
                .eq('user_id', userId)
                .limit(50);

            if (!data || data.length < 5) return 0.5;

            return data.filter(d => d.was_accepted).length / data.length;
        } catch {
            return 0.5;
        }
    }

    /**
     * Apply context-aware adjustments
     */
    applyContextAdjustments(score, context) {
        let adjusted = score;

        // Boost for test files (safer to modify)
        if (context.isTestFile) {
            adjusted *= 1.05;
        }

        // Reduce for config files (more sensitive)
        if (context.isConfigFile) {
            adjusted *= 0.95;
        }

        // Reduce for breaking changes
        if (context.isBreakingChange) {
            adjusted *= 0.90;
        }

        // Boost if has test coverage
        if (context.hasTests) {
            adjusted *= 1.05;
        }

        // Adjust based on file age (older files = more conservative)
        if (context.fileAge) {
            const ageYears = context.fileAge / (365 * 24 * 60 * 60 * 1000);
            if (ageYears > 2) {
                adjusted *= 0.95;
            }
        }

        // Adjust based on recent changes to file
        if (context.recentChanges && context.recentChanges > 10) {
            adjusted *= 0.95; // More active files = more careful
        }

        return adjusted;
    }

    /**
     * Apply false positive penalty
     */
    applyFalsePositivePenalty(score, finding) {
        const key = `${finding.category}:${finding.ruleId || 'unknown'}`;
        const penalty = this.falsePositiveCache.get(key) || 0;

        return score * (1 - penalty);
    }

    /**
     * Get false positive penalty for a finding type
     */
    getFalsePositivePenalty(finding) {
        const key = `${finding.category}:${finding.ruleId || 'unknown'}`;
        return this.falsePositiveCache.get(key) || 0;
    }

    /**
     * Apply category-specific factor
     */
    applyCategoryFactor(score, category) {
        const factor = this.categoryFactors.get(category) || 1;
        return score * factor;
    }

    /**
     * Apply project-specific learning
     */
    async applyProjectLearning(score, finding, context) {
        if (!context.projectId) return score;

        // Check for project-specific weight overrides
        const projectWeights = this.projectWeights.get(context.projectId);
        if (projectWeights && projectWeights[finding.category]) {
            return score * projectWeights[finding.category];
        }

        return score;
    }

    /**
     * Get context-aware thresholds
     */
    getContextThresholds(context) {
        let contextKey = 'default';

        if (context.isTestFile) contextKey = 'test-file';
        else if (context.isConfigFile) contextKey = 'config-file';
        else if (context.isBreakingChange) contextKey = 'breaking-change';
        else if (context.isSecurity) contextKey = 'security-critical';
        else if (context.isPerformance) contextKey = 'performance';
        else if (context.isStyle) contextKey = 'style';
        else if (context.isProduction) contextKey = 'production-code';

        return CONTEXT_THRESHOLDS[contextKey] || CONTEXT_THRESHOLDS.default;
    }

    /**
     * Determine action based on score and thresholds
     */
    determineAction(score, thresholds) {
        if (score >= thresholds.autoApply) return 'AUTO_APPLY';
        if (score >= thresholds.suggest) return 'SUGGEST';
        if (score >= thresholds.ignore) return 'REVIEW';
        return 'IGNORE';
    }

    /**
     * Get confidence level label
     */
    getConfidenceLevel(score) {
        if (score >= 0.95) return 'VERY_HIGH';
        if (score >= 0.85) return 'HIGH';
        if (score >= 0.70) return 'MEDIUM';
        if (score >= 0.50) return 'LOW';
        return 'VERY_LOW';
    }

    /**
     * Generate human-readable explanation
     */
    generateExplanation(score, features, action) {
        const reasons = [];

        // Highlight top contributing factors
        const sortedFeatures = Object.entries(features)
            .sort((a, b) => (b[1] * (this.weights[b[0]] || 0)) - (a[1] * (this.weights[a[0]] || 0)));

        for (const [feature, value] of sortedFeatures.slice(0, 3)) {
            const weight = this.weights[feature] || 0;
            const contribution = value * weight;

            if (contribution > 0.1) {
                reasons.push(this.featureToReason(feature, value));
            }
        }

        const actionText = {
            AUTO_APPLY: 'Safe to auto-apply',
            SUGGEST: 'Recommended with review',
            REVIEW: 'Requires manual review',
            IGNORE: 'Not recommended',
        }[action];

        return {
            summary: `${actionText} (${Math.round(score * 100)}% confidence)`,
            reasons,
        };
    }

    /**
     * Convert feature to human-readable reason
     */
    featureToReason(feature, value) {
        const templates = {
            patternMatch: value > 0.8 ? 'Strong pattern match' : 'Moderate pattern match',
            codeComplexity: value > 0.7 ? 'Low code complexity' : 'Higher code complexity',
            contextSimilarity: value > 0.7 ? 'Similar to past successful fixes' : 'Limited historical data',
            categoryAcceptRate: value > 0.7 ? 'High accept rate for this category' : 'Mixed history for this category',
            projectAcceptRate: value > 0.7 ? 'Good track record in this project' : 'Limited project history',
            aiConsensus: value > 0.7 ? 'Multiple AI models agree' : 'Single model recommendation',
            testCoverage: value > 0.7 ? 'Test coverage available' : 'No test coverage',
        };

        return templates[feature] || `${feature}: ${Math.round(value * 100)}%`;
    }

    /**
     * Record feedback for learning (accept/reject)
     */
    async recordFeedback(findingId, finding, wasAccepted, context = {}) {
        // Update false positive cache
        const key = `${finding.category}:${finding.ruleId || 'unknown'}`;

        if (!wasAccepted) {
            const current = this.falsePositiveCache.get(key) || 0;
            const newPenalty = Math.min(0.5, current + 0.05);
            this.falsePositiveCache.set(key, newPenalty);
        } else {
            // Reduce penalty on accept
            const current = this.falsePositiveCache.get(key) || 0;
            const newPenalty = Math.max(0, current - 0.02);
            this.falsePositiveCache.set(key, newPenalty);
        }

        if (!this.supabase) return;

        try {
            // Store outcome for learning
            await this.supabase.from('fix_outcomes').insert({
                finding_id: findingId,
                category: finding.category,
                rule_id: finding.ruleId,
                was_accepted: wasAccepted,
                confidence_score: finding.confidence || 0,
                project_id: context.projectId,
                user_id: context.userId,
                file_type: context.fileType,
                created_at: new Date().toISOString(),
            });

            // Trigger weight update if enough samples
            await this.maybeUpdateWeights();
        } catch (error) {
            console.error('[MLConfidence] Failed to record feedback:', error);
        }
    }

    /**
     * Update weights if enough new data
     */
    async maybeUpdateWeights() {
        if (!this.supabase) return;

        try {
            // Count recent outcomes
            const { count } = await this.supabase
                .from('fix_outcomes')
                .select('id', { count: 'exact', head: true })
                .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

            if (count >= this.config.minSamples) {
                await this.trainWeights();
            }
        } catch {
            // Silently fail
        }
    }

    /**
     * Train weights using gradient descent on recent data
     */
    async trainWeights() {
        if (!this.supabase) return;

        try {
            // Get recent outcomes with features
            const { data: outcomes } = await this.supabase
                .from('fix_outcomes')
                .select('*')
                .order('created_at', { ascending: false })
                .limit(500);

            if (!outcomes || outcomes.length < this.config.minSamples) return;

            // Simple online learning update
            for (const outcome of outcomes) {
                const prediction = outcome.confidence_score || 0.5;
                const actual = outcome.was_accepted ? 1 : 0;
                const error = actual - prediction;

                // Update category factor
                const category = outcome.category;
                const currentFactor = this.categoryFactors.get(category) || 1;
                const newFactor = currentFactor + (this.config.learningRate * error);
                this.categoryFactors.set(category, Math.max(0.5, Math.min(1.5, newFactor)));
            }

            // Persist updated weights
            await this.persistWeights();

        } catch (error) {
            console.error('[MLConfidence] Training failed:', error);
        }
    }

    /**
     * Persist learned weights to database
     */
    async persistWeights() {
        if (!this.supabase) return;

        try {
            await this.supabase
                .from('ml_confidence_weights')
                .upsert({
                    scope: 'global',
                    weights: this.weights,
                    updated_at: new Date().toISOString(),
                });

            // Persist category factors
            const categoryRows = Array.from(this.categoryFactors.entries())
                .filter(([key]) => !key.startsWith('rate:'))
                .map(([category, factor]) => ({
                    category,
                    factor,
                    updated_at: new Date().toISOString(),
                }));

            if (categoryRows.length > 0) {
                await this.supabase
                    .from('ml_category_factors')
                    .upsert(categoryRows);
            }
        } catch (error) {
            console.error('[MLConfidence] Failed to persist weights:', error);
        }
    }

    /**
     * Adjust category weights based on production incident correlations.
     * Categories that correlate to production incidents get a severity boost
     * (capped at 2× the baseline factor).
     *
     * @param {Array<{ category: string }>} incidentCorrelations
     */
    async incorporateProductionData(incidentCorrelations) {
        if (!incidentCorrelations || incidentCorrelations.length === 0) return;

        for (const corr of incidentCorrelations) {
            if (!corr.category) continue;
            const current = this.categoryFactors.get(corr.category) || 1.0;
            // Boost by 15% per correlated incident, capped at 2.0×
            const updated = Math.min(current * 1.15, 2.0);
            this.categoryFactors.set(corr.category, updated);
        }

        await this.persistWeights();
    }

    /**
     * Get learning statistics
     */
    getStats() {
        return {
            weights: { ...this.weights },
            categoryFactors: Object.fromEntries(this.categoryFactors),
            falsePositivePenalties: Object.fromEntries(this.falsePositiveCache),
            patternMemorySize: this.patternMemory.size,
        };
    }

    /**
     * Reset learned state (for testing)
     */
    reset() {
        this.weights = { ...DEFAULT_WEIGHTS };
        this.categoryFactors.clear();
        this.falsePositiveCache.clear();
        this.patternMemory.clear();
        this.projectWeights.clear();
    }
}

// Database migration SQL for ML confidence tables
const MIGRATION_SQL = `
-- ML Confidence Weights
CREATE TABLE IF NOT EXISTS ml_confidence_weights (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scope TEXT NOT NULL DEFAULT 'global',
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    weights JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(scope, project_id)
);

-- ML Category Factors
CREATE TABLE IF NOT EXISTS ml_category_factors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    category TEXT NOT NULL UNIQUE,
    factor FLOAT NOT NULL DEFAULT 1.0,
    sample_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Fix Outcomes for learning
CREATE TABLE IF NOT EXISTS fix_outcomes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id TEXT,
    category TEXT NOT NULL,
    rule_id TEXT,
    was_accepted BOOLEAN NOT NULL,
    confidence_score FLOAT,
    project_id UUID,
    user_id UUID,
    file_type TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_fix_outcomes_category ON fix_outcomes(category);
CREATE INDEX IF NOT EXISTS idx_fix_outcomes_project ON fix_outcomes(project_id);
CREATE INDEX IF NOT EXISTS idx_fix_outcomes_created ON fix_outcomes(created_at);
`;

module.exports = {
    MLConfidenceScorer,
    DEFAULT_WEIGHTS,
    CONTEXT_THRESHOLDS,
    MIGRATION_SQL,
};
