/**
 * @noalia/codetitan-core - TypeScript Definitions
 * 
 * Type definitions for the CodeTitan core analysis engine.
 */

// ============================================
// Main Orchestration
// ============================================

export interface AnalysisOptions {
    level?: number;
    domains?: string[];
    outputFormat?: 'console' | 'json' | 'markdown';
    saveReport?: boolean;
    reportPath?: string;
    verbose?: boolean;
    applyFixes?: boolean;
    cache?: boolean;
    aiConfig?: AIConfig;
}

export interface AIConfig {
    provider?: 'claude' | 'gpt' | 'gemini' | 'ensemble';
    apiKey?: string;
    maxTokens?: number;
    temperature?: number;
}

export interface AnalysisReport {
    sessionId: string;
    timestamp: string;
    duration: number;
    durationFormatted: string;
    summary: AnalysisSummary;
    domainSummary: Record<string, number>;
    findings: Finding[];
    topIssues: Finding[];
    recommendations: Recommendation[];
    metrics: QualityMetrics;
    performance: PerformanceMetrics;
    bySeverity: Record<string, Finding[]>;
    byDomain: Record<string, Finding[]>;
    byFile: Record<string, Finding[]>;
}

export interface AnalysisSummary {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    totalFiles: number;
    filesWithIssues: number;
    totalLinesAnalyzed: number;
}

export interface Finding {
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    message: string;
    impact: number;
    snippet: string;
    context: string[];
    domain?: string;
    domainName?: string;
    file?: string;
}

export interface Recommendation {
    priority: 'URGENT' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    action: string;
    impact: string;
    effort: string;
    topIssue?: string;
}

export interface QualityMetrics {
    totalLines: number;
    issuesPerKLOC: string;
    qualityScore: string;
    criticalDensity: string;
    healthGrade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface PerformanceMetrics {
    orchestrator: OrchestratorMetrics;
    loadBalancer: LoadBalancerMetrics;
}

export interface OrchestratorMetrics {
    totalFiles: number;
    totalTasks: number;
    completedTasks: number;
    failedTasks: number;
    filesPerSecond: string;
    successRate: string;
}

export interface LoadBalancerMetrics {
    activeAgents: number;
    completedAgents: number;
    failedAgents: number;
    totalRetries: number;
    timeouts: number;
    successRate: string;
    averageExecutionTime: string;
}

// ============================================
// Classes
// ============================================

export class CodeTitanOrchestration {
    constructor(options?: AnalysisOptions);
    analyzeCodebase(projectPath: string): Promise<AnalysisReport>;
    exportJSON(report: AnalysisReport, filePath: string): Promise<string>;
    exportMarkdown(report: AnalysisReport, filePath: string): Promise<string>;
    quickAnalysis(projectPath: string, maxFiles?: number): Promise<AnalysisReport>;
}

export class HierarchicalOrchestrator {
    domainTitans: string[];
    selectedDomains: string[];
    maxConcurrent: number;

    constructor();
    orchestrateFullAnalysis(projectPath: string, options?: AnalysisOptions): Promise<any[]>;
    discoverFiles(projectPath: string): Promise<string[]>;
    resolveDomains(level?: string | number, domains?: string[]): string[];
    getMetrics(): OrchestratorMetrics;
}

export class ResultSynthesisEngine {
    synthesize(rawResults: any[]): Promise<AnalysisReport>;
    toJSON(report: AnalysisReport): string;
    toMarkdown(report: AnalysisReport): string;
}

export class AIProviderManager {
    constructor(config?: AIConfig);
    analyze(domain: string, file: string, content: string, projectRoot: string, options?: any): Promise<any>;
}

// ============================================
// Titan Modes (L4-L8)
// ============================================

export interface TitanModeConfig {
    minConfidence?: number;
    provider?: string;
    autoFix?: boolean;
    dryRun?: boolean;
    verbose?: boolean;
}

export class Level4AIFixers {
    constructor(config?: TitanModeConfig);
    runLevel4Fixes(findings: Finding[], options?: any): Promise<any>;
    filterFixableFindings(findings: Finding[]): Finding[];
    processFixForFinding(finding: Finding, options?: any): Promise<any>;
    getStats(): any;
}

export class Level5SelfHealingCI {
    constructor(config?: any);
    run(options?: any): Promise<any>;
    validateBuild(context: any): Promise<any>;
    attemptAutoHealing(failures: any[], context: any): Promise<any>;
    runTests(context: any): Promise<any>;
    checkCoverage(context: any): Promise<any>;
    getStats(): any;
}

export class Level6CollectiveInsight {
    constructor(config?: any);
    activate(projectPath: string): Promise<any>;
    loadHistoricalData(): Promise<any>;
    extractPatterns(history: any): any;
    buildRecommendations(patterns: any, projectPath: string): any;
    generateInsights(history: any, patterns: any): any;
    close(): void;
}

export class Level7AutonomousOptimizer {
    constructor(config?: any);
    runOptimizationSprint(projectPath: string, options?: any): Promise<any>;
    performMultiDomainAnalysis(projectPath: string): Promise<any>;
    prioritizeImprovements(findings: Finding[]): any[];
    applyImprovements(improvements: any[], projectPath: string): Promise<any>;
    rollbackSprint(sprintResults: any): Promise<any>;
    getSprintHistory(): any;
}

export class Level8Sentinel {
    constructor(config?: any);
    start(projectPath: string): Promise<void>;
    stop(): Promise<void>;
    analyzeCommit(commit: any, projectPath: string): Promise<any>;
    handleIncident(incident: any): Promise<any>;
    autoRemediate(incident: any): Promise<any>;
    escalateIncident(incident: any): Promise<void>;
    getStatus(): any;
}

// ============================================
// Godmode Export Object
// ============================================

export interface Godmode {
    Level4AIFixers: typeof Level4AIFixers;
    TitanFix: typeof Level4AIFixers;
    Level5SelfHealingCI: typeof Level5SelfHealingCI;
    TitanHeal: typeof Level5SelfHealingCI;
    Level6CollectiveInsight: typeof Level6CollectiveInsight;
    TitanInsight: typeof Level6CollectiveInsight;
    Level7AutonomousOptimizer: typeof Level7AutonomousOptimizer;
    TitanOptimize: typeof Level7AutonomousOptimizer;
    Level8Sentinel: typeof Level8Sentinel;
    TitanSentinel: typeof Level8Sentinel;
    TitanDetect: any;
    TitanReport: any;
    TitanScan: any;
    TitanSupreme: any;
}

export const godmode: Godmode;

// ============================================
// Scanners
// ============================================

export class ContainerScanner {
    constructor(options?: any);
    scan(imagePath: string): Promise<any>;
    analyzeDockerfile(filePath: string): Promise<any>;
}

export class IaCScanner {
    constructor(options?: any);
    scan(filePath: string): Promise<any>;
    scanTerraform(filePath: string): Promise<any>;
    scanCloudFormation(filePath: string): Promise<any>;
}

export class DependencyScanner {
    constructor(options?: any);
    scan(projectPath: string): Promise<any>;
    checkVulnerabilities(dependencies: any[]): Promise<any>;
}

// ============================================
// Generators & Exporters
// ============================================

export class SBOMGenerator {
    constructor(options?: any);
    generate(projectPath: string): Promise<any>;
    exportCycloneDX(sbom: any, outputPath: string): Promise<void>;
    exportSPDX(sbom: any, outputPath: string): Promise<void>;
}

export class SarifExporter {
    constructor(options?: any);
    export(findings: Finding[], outputPath: string): Promise<void>;
    toSarif(findings: Finding[]): any;
}

// ============================================
// Analysis Tools
// ============================================

export class TechnicalDebtCalculator {
    constructor(options?: any);
    calculate(findings: Finding[]): any;
}

export class DuplicationDetector {
    constructor(options?: any);
    detect(files: string[]): Promise<any>;
}

export class CoverageParser {
    constructor(options?: any);
    parse(coveragePath: string): Promise<any>;
}

// ============================================
// Utilities
// ============================================

export class CacheManager {
    constructor(options?: any);
    get(key: string): any;
    set(key: string, value: any, ttl?: number): void;
    invalidate(pattern?: string): void;
    clear(): void;
}

export class QualityGates {
    constructor(config?: any);
    evaluate(report: AnalysisReport): { passed: boolean; failures: string[] };
}

// ============================================
// Helper Functions
// ============================================

export function analyzeDomain(
    domain: string,
    filePath: string,
    content: string,
    projectRoot: string
): {
    issues: Finding[];
    linesAnalyzed: number;
    metadata: any;
    executionTime: number;
};

export function analyze(
    projectPath: string,
    options?: AnalysisOptions
): Promise<AnalysisReport>;
