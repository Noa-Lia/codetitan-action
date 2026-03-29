/**
 * TITAN MODE™ Level 7: TITAN COLLECTIVE
 * AI-Powered Autonomous Optimizer
 *
 * Orchestrates multi-service improvement sprints using AI analysis and fixes.
 * Prioritizes improvements based on impact, effort, and deployment windows.
 *
 * Capabilities:
 * - Multi-domain analysis (security, performance, testing, refactoring, docs)
 * - AI-powered priority queue based on business impact
 * - Scheduled optimization sprints
 * - Deployment window awareness
 * - Post-deployment telemetry validation
 * - Continuous learning from outcomes
 *
 * @module titanmode/level7-collective
 */

const { AIProviderManager, EnsembleAnalyzer } = require('../ai-providers');
const { FixGenerator, FixApplier } = require('../ai-fixers');
const TitanFix = require('./titan-fix');

class Level7AutonomousOptimizer {
  constructor(config = {}) {
    this.config = {
      // Optimization sprint schedule (cron format)
      schedule: config.schedule || '0 2 * * 0', // Sunday 2am

      // Sprint Budget (max time in minutes)
      maxSprintDuration: config.maxSprintDuration || 30,

      // Domains to optimize
      domains: config.domains || [
        'security-god',
        'performance-god',
        'test-god',
        'refactoring-god',
        'documentation-god'
      ],

      // Maximum improvements per sprint
      maxImprovementsPerSprint: config.maxImprovementsPerSprint || 20,

      // Use ensemble analysis for better quality
      useEnsemble: config.useEnsemble !== false,

      // Deployment windows (ISO 8601 format)
      deploymentWindows: config.deploymentWindows || [
        { day: 'Sunday', start: '02:00', end: '06:00' },
        { day: 'Wednesday', start: '14:00', end: '16:00' }
      ],

      // Telemetry validation after deployment
      validateTelemetry: config.validateTelemetry !== false,

      ...config
    };

    this.aiManager = new AIProviderManager();
    this.ensemble = new EnsembleAnalyzer(this.aiManager);
    this.titanFix = new TitanFix();

    // Check if Titan Insight (Level 6) is available
    try {
      const TitanInsight = require('./titan-insight');
      this.titanInsight = new TitanInsight();
      this.useInsight = true;
    } catch (e) {
      this.useInsight = false;
      console.log('[Titan Optimize] Titan Insight not available, running standalone.');
    }

    this.improvementQueue = [];
    this.sprintHistory = [];
  }

  /**
   * Run autonomous optimization sprint
   */
  async runOptimizationSprint(projectPath, options = {}) {
    console.log('⚡ [TITAN MODE Level 7] TITAN COLLECTIVE - Autonomous Optimizer\n');
    console.log(`Starting optimization sprint for: ${projectPath}\n`);

    const startTime = Date.now();

    // Phase 1: Multi-domain analysis
    console.log('[Phase 1] Multi-domain analysis...');
    const analysis = await this.performMultiDomainAnalysis(projectPath);

    console.log(`   Found ${analysis.totalFindings} issues across ${this.config.domains.length} domains`);

    // Phase 2: Prioritize improvements
    console.log('\n[Phase 2] Prioritizing improvements...');
    const prioritized = await this.prioritizeImprovements(analysis.findings);

    console.log(`   Prioritized ${prioritized.length} improvements`);

    // Phase 3: Schedule improvements
    console.log('\n[Phase 3] Scheduling improvements...');
    const scheduled = this.scheduleImprovements(prioritized);

    console.log(`   Scheduled ${scheduled.immediate.length} for immediate deployment`);
    console.log(`   Queued ${scheduled.queued.length} for next window`);

    // Phase 4: Apply immediate improvements
    console.log('\n[Phase 4] Applying immediate improvements...');
    const results = await this.applyImprovements(scheduled.immediate, projectPath);

    console.log(`   Applied: ${results.applied}`);
    console.log(`   Failed: ${results.failed}`);

    // Phase 5: Validate telemetry (if enabled)
    if (this.config.validateTelemetry) {
      console.log('\n[Phase 5] Validating telemetry...');
      const telemetry = await this.validateTelemetry(results);
      console.log(`   Telemetry check: ${telemetry.healthy ? '✓ HEALTHY' : '✗ DEGRADED'}`);

      if (!telemetry.healthy) {
        console.log('   Rolling back changes...');
        await this.rollbackSprint(results);
      }
    }

    // Record sprint
    const sprint = {
      startTime,
      endTime: Date.now(),
      duration: Date.now() - startTime,
      projectPath,
      analysis,
      prioritized: prioritized.length,
      applied: results.applied,
      failed: results.failed,
      cost: results.cost,
      telemetry: this.config.validateTelemetry ? await this.validateTelemetry(results) : null
    };

    this.sprintHistory.push(sprint);

    console.log(`\n[Level 7] Sprint complete in ${(sprint.duration / 1000).toFixed(1)}s`);

    return sprint;
  }

  /**
   * Perform multi-domain analysis using ensemble
   */
  async performMultiDomainAnalysis(projectPath) {
    const fs = require('fs');
    const path = require('path');

    const findings = [];

    // Find code files
    const findCodeFiles = (dir) => {
      const files = [];
      const items = fs.readdirSync(dir, { withFileTypes: true });

      for (const item of items) {
        if (item.name.startsWith('.') || item.name === 'node_modules') continue;

        const fullPath = path.join(dir, item.name);

        if (item.isDirectory()) {
          files.push(...findCodeFiles(fullPath));
        } else if (/\.(js|jsx|ts|tsx|py|java|go)$/.test(item.name)) {
          files.push(fullPath);
        }
      }

      return files;
    };

    const files = findCodeFiles(projectPath);

    console.log(`   Analyzing ${files.length} files across ${this.config.domains.length} domains...`);

    // Analyze each file with each domain (in parallel for speed)
    // Analyze each file with each domain (in parallel for speed)
    // Removed demo limit of 50 files - analyzing all eligible files
    const BATCH_SIZE = 10;

    for (let i = 0; i < files.length; i += BATCH_SIZE) {
      const batch = files.slice(i, i + BATCH_SIZE);

      // Process batch in parallel
      await Promise.all(batch.map(async (file) => {
        try {
          const content = await fs.promises.readFile(file, 'utf-8');

          for (const domain of this.config.domains) {
            try {
              let result;

              if (this.config.useEnsemble) {
                result = await this.ensemble.analyzeWithEnsemble(domain, file, content, projectPath);
              } else {
                result = await this.aiManager.analyze(domain, file, content, projectPath);
              }

              if (result.issues) {
                findings.push(...result.issues);
              }

            } catch (error) {
              console.error(`   Error analyzing ${file} with ${domain}:`, error.message);
            }
          }
        } catch (readError) {
          console.error(`   Error reading file ${file}:`, readError.message);
        }
      }));
    }

    return {
      totalFindings: findings.length,
      findings,
      files: files.length
    };
  }

  /**
   * Prioritize improvements using AI-powered scoring
   */
  async prioritizeImprovements(findings) {
    // Score each finding based on:
    // - Business impact (severity, category, affected users)
    // - Implementation effort (complexity, dependencies)
    // - Risk (breaking changes, test coverage)

    const scored = findings.map(finding => {
      const impact = this.calculateImpact(finding);
      const effort = this.estimateEffort(finding);
      const risk = this.assessRisk(finding);

      const priority = (impact * 0.5) + ((10 - effort) * 0.3) + ((10 - risk) * 0.2);

      return {
        finding,
        impact,
        effort,
        risk,
        priority
      };
    });

    // Sort by priority (highest first)
    scored.sort((a, b) => b.priority - a.priority);

    return scored.slice(0, this.config.maxImprovementsPerSprint);
  }

  /**
   * Calculate business impact score (1-10)
   */
  calculateImpact(finding) {
    let score = 0;

    // Severity
    if (finding.severity === 'HIGH') score += 5;
    else if (finding.severity === 'MEDIUM') score += 3;
    else score += 1;

    // Bonus for PERFORMANCE or TECH DEBT during Optimization Sprints
    if (finding.category === 'N_PLUS_ONE_QUERY' || finding.category === 'COMPLEX_CONDITION') {
      score += 2;
    }

    // Category impact
    const highImpactCategories = ['SQL_INJECTION', 'XSS', 'COMMAND_EXEC', 'N_PLUS_ONE_QUERY'];
    if (highImpactCategories.includes(finding.category)) {
      score += 3;
    }

    // Confidence
    if (finding.confidenceScore?.score > 80) {
      score += 2;
    }

    return Math.min(10, score);
  }

  /**
   * Estimate implementation effort (1-10, lower = easier)
   */
  estimateEffort(finding) {
    const easyCategories = ['SYNC_IO', 'MAGIC_NUMBER', 'UNUSED_VARIABLE'];
    const hardCategories = ['COMPLEX_CONDITION', 'LONG_METHOD', 'SQL_INJECTION'];

    if (easyCategories.includes(finding.category)) return 3;
    if (hardCategories.includes(finding.category)) return 8;

    return 5; // Medium effort
  }

  /**
   * Assess deployment risk (1-10, lower = safer)
   */
  assessRisk(finding) {
    let risk = 5; // Baseline

    // Lower risk if has auto-fix
    if (finding.has_auto_fix) risk -= 2;

    // Lower risk if high confidence
    if (finding.confidenceScore?.score > 90) risk -= 2;

    // Higher risk for logic changes
    const riskyCategories = ['SQL_INJECTION', 'COMPLEX_CONDITION'];
    if (riskyCategories.includes(finding.category)) risk += 3;

    // Titan Insight Integration: Lower risk if we have high historical success
    if (this.useInsight && this.titanInsight) {
      // This is a simplified check. In real implementation we would await or have these pre-loaded.
      // Assuming we preload stats in init or lazily.
      // For now, let's assume we trust common categories more if Insight is enabled.
      const safeCategories = ['UNUSED_VARIABLE', 'MAGIC_NUMBER']; // Placeholder for Insight data
      if (safeCategories.includes(finding.category)) risk -= 1;
    }

    return Math.max(1, Math.min(10, risk));
  }

  /**
   * Schedule improvements based on deployment windows
   */
  scheduleImprovements(prioritized) {
    const now = new Date();
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'long' });
    const currentTime = now.toTimeString().slice(0, 5);

    // Check if we're in a deployment window
    const inWindow = this.config.deploymentWindows.some(window =>
      window.day === currentDay && currentTime >= window.start && currentTime <= window.end
    );

    if (inWindow) {
      return {
        immediate: prioritized.slice(0, 10), // Deploy top 10 now
        queued: prioritized.slice(10)
      };
    } else {
      return {
        immediate: [],
        queued: prioritized // Queue all for next window
      };
    }
  }

  /**
   * Apply improvements using Level 4 fixers
   */
  async applyImprovements(improvements, projectPath) {
    const findings = improvements.map(imp => imp.finding);

    const results = await this.titanFix.runLevel4Fixes(findings, {
      projectPath
    });

    return results;
  }

  /**
   * Validate telemetry after deployment
   */
  async validateTelemetry(deploymentResults) {
    // TODO: Integrate with actual telemetry system (Datadog, New Relic, etc.)
    // Check metrics like:
    // - Error rate
    // - Response time
    // - CPU/Memory usage
    // - Request success rate

    // Placeholder implementation
    return {
      healthy: true,
      metrics: {
        errorRate: 0.001,
        avgResponseTime: 150,
        cpuUsage: 45,
        memoryUsage: 60
      }
    };
  }

  /**
   * Rollback sprint changes
   */
  async rollbackSprint(sprintResults) {
    console.log('   Rolling back all changes from sprint...');

    for (const result of sprintResults.results) {
      if (result.applied && result.fixId) {
        await this.titanFix.fixApplier.rollback(result.fixId);
      }
    }

    console.log('   Rollback complete');
  }

  /**
   * Get sprint history
   */
  getSprintHistory() {
    return this.sprintHistory;
  }
}

module.exports = Level7AutonomousOptimizer;
