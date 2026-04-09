/**
 * @noalia/codetitan-core - Public API
 * 
 * Clean, stable exports for the CodeTitan core engine.
 * All internal modules are accessible through this single entry point.
 */

// Main Orchestration
const CodeTitanOrchestration = require('./lib/codetitan-orchestration');
const HierarchicalOrchestrator = require('./lib/hierarchical-orchestrator');
const ResultSynthesisEngine = require('./lib/result-synthesis-engine');

// AI Providers
const { AIProviderManager } = require('./lib/ai-providers');

// Domain Analyzers
const { analyzeDomain } = require('./lib/domain-analyzers');

// Titan Modes (L4-L8) - formerly "godmode"
const godmode = {
    // Level 4: AI-Powered Adaptive Fixers
    Level4AIFixers: safeRequire('./lib/godmode/titan-fix'),
    TitanFix: safeRequire('./lib/godmode/titan-fix'),

    // Level 5: Self-Healing CI/CD
    Level5SelfHealingCI: safeRequire('./lib/godmode/titan-heal'),
    TitanHeal: safeRequire('./lib/godmode/titan-heal'),

    // Level 6: Collective Intelligence
    Level6CollectiveInsight: safeRequire('./lib/godmode/titan-insight'),
    TitanInsight: safeRequire('./lib/godmode/titan-insight'),

    // Level 7: Autonomous Optimizer
    Level7AutonomousOptimizer: safeRequire('./lib/godmode/titan-optimize'),
    TitanOptimize: safeRequire('./lib/godmode/titan-optimize'),

    // Level 8: Sentinel Mode (Always-On Guardian)
    Level8Sentinel: safeRequire('./lib/godmode/titan-sentinel'),
    TitanSentinel: safeRequire('./lib/godmode/titan-sentinel'),

    // Additional Titan utilities
    TitanDetect: safeRequire('./lib/godmode/titan-detect'),
    TitanReport: safeRequire('./lib/godmode/titan-report'),
    TitanScan: safeRequire('./lib/godmode/titan-scan'),
    TitanSupreme: safeRequire('./lib/godmode/titan-supreme'),
};

// Scanners
const ContainerScanner = require('./lib/container-scanner');
const IaCScanner = require('./lib/iac-scanner');
const DependencyScanner = require('./lib/dependency-scanner');

// Generators & Exporters
const SBOMGenerator = require('./lib/sbom-generator');
const SarifExporter = require('./lib/sarif-exporter');

// Analysis Tools
const TechnicalDebtCalculator = require('./lib/technical-debt-calculator');
const DuplicationDetector = require('./lib/duplication-detector');
const CoverageParser = require('./lib/coverage-parser');
const LearnedProfileManager = require('./lib/learned-profile');
const PRRiskScorer = require('./lib/pr-risk-scorer');
const { MLConfidenceScorer } = require('./lib/ml-confidence-scorer');
const GitDiffUtils = require('./lib/git-diff-utils');

// Utilities
const CacheManager = require('./lib/cache-manager');
const QualityGates = require('./lib/quality-gates');

/**
 * Safe require helper - returns null if module doesn't exist
 */
function safeRequire(modulePath) {
    try {
        return require(modulePath);
    } catch (e) {
        return null;
    }
}

// Export everything
module.exports = {
    // Main entry points
    CodeTitanOrchestration,
    HierarchicalOrchestrator,
    ResultSynthesisEngine,

    // AI
    AIProviderManager,

    // Analyzers
    analyzeDomain,

    // Titan Modes (godmode) - L4-L8
    godmode,

    // Scanners
    ContainerScanner,
    IaCScanner,
    DependencyScanner,

    // Generators
    SBOMGenerator,
    SarifExporter,

    // Analysis Tools
    TechnicalDebtCalculator,
    DuplicationDetector,
    CoverageParser,
    LearnedProfileManager,
    PRRiskScorer,
    MLConfidenceScorer,
    GitDiffUtils,

    // Utilities
    CacheManager,
    QualityGates,

    // Convenience function for quick analysis
    async analyze(projectPath, options = {}) {
        const orchestration = new CodeTitanOrchestration(options);
        return orchestration.analyzeCodebase(projectPath);
    }
};
