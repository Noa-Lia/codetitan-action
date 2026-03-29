/**
 * CodeTitan Orchestration
 *
 * Ultimate integration of all 5 Domain Titans with 50+ agent orchestration.
 * Main entry point for comprehensive codebase analysis.
 *
 * Phase 3 Integration Component
 */

const HierarchicalOrchestrator = require('./hierarchical-orchestrator');
const ResultSynthesisEngine = require('./result-synthesis-engine');
const AgentLoadBalancer = require('./agent-load-balancer');
const FPFilter = require('./fp-filter');
// FixerRunner is required lazily inside analyzeCodebase to avoid circular dep issues
const fs = require('fs').promises;
const path = require('path');

class CodeTitanOrchestration {
  constructor(options = {}) {
    // Initialize all components
    this.orchestrator = new HierarchicalOrchestrator();
    this.synthesizer = new ResultSynthesisEngine();
    this.loadBalancer = new AgentLoadBalancer({
      maxAgentsPerDomain: options.maxAgentsPerDomain || 10,
      maxConcurrent: options.maxConcurrent || 50,
      retryLimit: options.retryLimit || 3,
      timeoutMs: options.timeoutMs || 120000
    });

    // Configuration
    this.options = {
      outputFormat: options.outputFormat || 'console', // 'console', 'json', 'markdown'
      saveReport: options.saveReport || false,
      reportPath: options.reportPath || './codetitan-report.md',
      verbose: options.verbose !== false, // Default to verbose
      applyFixes: options.applyFixes || false,
      fpFilter: options.fpFilter !== false, // Default: enable FP filtering if API key present
      ...options
    };

    // FP filter (uses Claude to suppress false positives in HIGH/CRITICAL findings)
    this.fpFilter = new FPFilter({
      enabled: this.options.fpFilter !== false,
    });

    // Session tracking
    this.sessionId = this.generateSessionId();
    this.startTime = null;
    this.endTime = null;
  }

  /**
   * Main method: Analyze entire codebase with ULTIMATE CodeTitan
   * @param {string} projectPath - Path to the project to analyze
   * @param {Object} [runOptions={}] - Optional per-call options
   * @param {Function} [runOptions.onProgress] - Optional progress callback.
   *   Called with events:
   *   - { type: 'progress', pct: 0-100, message: string, filesProcessed: number, totalFiles: number }
   *   - { type: 'finding', finding: { severity, category, message, file, line } }
   *   - { type: 'done', summary: { critical, high, medium, low, total } }
   */
  async analyzeCodebase(projectPath, runOptions = {}) {
    this.startTime = Date.now();

    // Merge per-call options with constructor options (per-call takes precedence)
    const effectiveOptions = { ...this.options, ...runOptions };

    // Helper: safely invoke onProgress callback without crashing the analysis
    const emit = (event) => {
      if (typeof effectiveOptions.onProgress === 'function') {
        try {
          effectiveOptions.onProgress(event);
        } catch (_) {
          // onProgress errors must never affect analysis
        }
      }
    };

    try {
      // Display header
      if (effectiveOptions.verbose) {
        this.displayHeader();
      }

      // Validate project path
      await this.validateProjectPath(projectPath);

      // Step 1: Orchestrate full analysis across all Domain Gods
      if (effectiveOptions.verbose) {
        console.log('\n[START] STEP 1: Orchestrating analysis across all Domain Titans...');
      }

      emit({ type: 'progress', pct: 10, message: 'Starting analysis across all Domain Titans...', filesProcessed: 0, totalFiles: 0 });

      const rawResults = await this.orchestrator.orchestrateFullAnalysis(projectPath, effectiveOptions);

      emit({ type: 'progress', pct: 40, message: 'Synthesizing results from all domains...', filesProcessed: 0, totalFiles: 0 });

      // Step 2: Synthesize results into unified report
      if (effectiveOptions.verbose) {
        console.log('\n[LINK] STEP 2: Synthesizing results from all domains...');
      }
      const report = await this.synthesizer.synthesize(rawResults);

      // Emit individual findings as they are available after synthesis
      if (report.findings && report.findings.length > 0) {
        for (const finding of report.findings) {
          emit({
            type: 'finding',
            finding: {
              severity: finding.severity,
              category: finding.category,
              message: finding.message,
              file: finding.file || finding.file_path || '',
              line: finding.line || finding.line_number || 1
            }
          });
        }
      }

      emit({ type: 'progress', pct: 70, message: 'Filtering false positives...', filesProcessed: 0, totalFiles: 0 });

      // Step 3: LLM false-positive filtering on synthesized issues
      if (this.fpFilter.enabled && report.issues && report.issues.length > 0) {
        if (effectiveOptions.verbose) {
          console.log(`\n[FILTER] STEP 2b: Filtering false positives (${report.issues.length} findings)...`);
        }
        try {
          // Group issues by file and filter each file's findings
          const byFile = new Map();
          for (const issue of report.issues) {
            const fp = issue.file_path || issue.filePath || '';
            if (!byFile.has(fp)) byFile.set(fp, []);
            byFile.get(fp).push(issue);
          }

          const filteredIssues = [];
          for (const [fp, fileIssues] of byFile) {
            let fileContent = '';
            try { fileContent = require('fs').readFileSync(fp, 'utf8'); } catch (_) {}
            const filtered = await this.fpFilter.filterFindings(fileIssues, fileContent, fp);
            filteredIssues.push(...filtered);
          }

          const fpStats = this.fpFilter.getStats();
          if (effectiveOptions.verbose && fpStats.filtered > 0) {
            console.log(`[FILTER] Suppressed ${fpStats.filtered} false positives (${fpStats.filterRate * 100}% FP rate)`);
          }
          report.issues = filteredIssues;
        } catch (_fpErr) {
          // FP filtering is best-effort — never crash the main scan
        }
      }

      emit({ type: 'progress', pct: 85, message: 'Compiling final report...', filesProcessed: 0, totalFiles: 0 });

      // Step 4: Get load balancer metrics
      const lbMetrics = this.loadBalancer.getMetrics();

      // Step 5: Get orchestrator metrics
      const orchMetrics = this.orchestrator.getMetrics();

      // Step 6: Compile final report
      this.endTime = Date.now();
      const finalReport = this.compileReport(report, lbMetrics, orchMetrics);

      // Step: Apply adaptive fixes if requested
      if (effectiveOptions.applyFixes && finalReport.topIssues && finalReport.topIssues.length > 0) {
        if (effectiveOptions.verbose) {
          console.log('\n[FIX] Applying adaptive fixes...');
        }
        try {
          const FixerRunner = require('./fixer-runner');
          const fixerRunner = new FixerRunner({
            projectRoot: projectPath,
            enableWrites: true,
          });
          const fixResult = await fixerRunner.applyFixes(finalReport);
          if (effectiveOptions.verbose) {
            console.log(`[FIX] Applied ${fixResult.applied} fixes, skipped ${fixResult.skipped}, errors: ${fixResult.errors.length}`);
            if (fixResult.filesTouched.length > 0) {
              console.log(`[FIX] Files modified: ${fixResult.filesTouched.join(', ')}`);
            }
          }
          finalReport.fixes = fixResult;
        } catch (fixErr) {
          if (effectiveOptions.verbose) {
            console.warn(`[FIX] Fix runner error: ${fixErr.message}`);
          }
        }
      }

      // Step 6: Display results
      if (effectiveOptions.verbose) {
        console.log('\n[CHART] STEP 3: Generating final report...');
        this.displayReport(finalReport);
      }

      // Step 7: Save report if requested
      if (effectiveOptions.saveReport) {
        await this.saveReport(finalReport);
      }

      // Emit done event with summary
      const summary = finalReport.summary || {};
      emit({
        type: 'done',
        summary: {
          critical: summary.critical || 0,
          high: summary.high || 0,
          medium: summary.medium || 0,
          low: summary.low || 0,
          total: summary.totalFindings || 0
        }
      });

      return finalReport;

    } catch (error) {
      this.endTime = Date.now();
      console.error('\n[ERROR] CodeTitan ANALYSIS FAILED:');
      console.error(error);
      throw error;
    }
  }

  /**
   * Validate project path exists
   */
  async validateProjectPath(projectPath) {
    try {
      const stats = await fs.stat(projectPath);
      if (!stats.isDirectory()) {
        throw new Error(`Path is not a directory: ${projectPath}`);
      }
    } catch (error) {
      throw new Error(`Invalid project path: ${projectPath} - ${error.message}`);
    }
  }

  /**
   * Compile final report with all metrics
   */
  compileReport(synthesisReport, lbMetrics, orchMetrics) {
    const duration = this.endTime - this.startTime;

    return {
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      duration: duration,
      durationFormatted: this.formatDuration(duration),

      // Synthesis results
      summary: synthesisReport.summary,
      domainSummary: synthesisReport.domainSummary,
      findings: synthesisReport.findings,
      topIssues: synthesisReport.topIssues,
      recommendations: synthesisReport.recommendations,
      metrics: synthesisReport.metrics,

      // Performance metrics
      performance: {
        orchestrator: {
          totalFiles: orchMetrics.totalFiles,
          totalTasks: orchMetrics.totalTasks,
          completedTasks: orchMetrics.completedTasks,
          failedTasks: orchMetrics.failedTasks,
          filesPerSecond: orchMetrics.filesPerSecond?.toFixed(2),
          successRate: (orchMetrics.successRate * 100).toFixed(1) + '%'
        },
        loadBalancer: {
          activeAgents: lbMetrics.activeAgents,
          completedAgents: lbMetrics.completedAgents,
          failedAgents: lbMetrics.failedAgentsCount,
          totalRetries: lbMetrics.totalRetries,
          timeouts: lbMetrics.timeouts,
          successRate: lbMetrics.successRate,
          averageExecutionTime: lbMetrics.averageExecutionTimeMs + 'ms'
        }
      },

      // Grouped findings for easy access
      bySeverity: synthesisReport.bySeverity,
      byDomain: synthesisReport.byDomain,
      byFile: synthesisReport.byFile
    };
  }

  /**
   * Display beautiful header
   */
  displayHeader() {
    console.log('\n+===========================================================+');
    console.log('|                                                           |');
    console.log('|          [FIRE] ULTIMATE CodeTitan ANALYSIS [FIRE]                |');
    console.log('|                                                           |');
    console.log('|      Multi-Agent Orchestration Across 5 Domains          |');
    console.log('|                                                           |');
    console.log('+===========================================================+');
    console.log(`\n[CLIPBOARD] Session ID: ${this.sessionId}`);
    console.log(`⏰ Started: ${new Date().toLocaleString()}\n`);
  }

  /**
   * Display comprehensive report
   */
  displayReport(report) {
    console.log('\n+===========================================================+');
    console.log('|                                                           |');
    console.log('|                  ANALYSIS COMPLETE [OK]                     |');
    console.log('|                                                           |');
    console.log('+===========================================================+\n');

    // Summary
    this.displaySummary(report);

    // Quality metrics
    this.displayQualityMetrics(report);

    // Domain breakdown
    this.displayDomainBreakdown(report);

    // Top issues
    this.displayTopIssues(report);

    // Recommendations
    this.displayRecommendations(report);

    // Performance metrics
    this.displayPerformanceMetrics(report);

    // Footer
    console.log('\n+===========================================================+');
    console.log('|            CodeTitan ANALYSIS COMPLETE                     |');
    console.log('+===========================================================+\n');
  }

  /**
   * Display summary statistics
   */
  displaySummary(report) {
    console.log('[CHART] SUMMARY\n');
    console.log(`   Total Findings: ${report.summary.totalFindings}`);
    console.log(`   🔴 Critical: ${report.summary.critical}`);
    console.log(`   🟠 High: ${report.summary.high}`);
    console.log(`   🟡 Medium: ${report.summary.medium}`);
    console.log(`   🟢 Low: ${report.summary.low}`);
    console.log(`   Files Analyzed: ${report.summary.totalFiles}`);
    console.log(`   Files with Issues: ${report.summary.filesWithIssues}\n`);
  }

  /**
   * Display quality metrics
   */
  displayQualityMetrics(report) {
    console.log('💎 QUALITY METRICS\n');
    console.log(`   Quality Score: ${report.metrics.qualityScore}/100`);
    console.log(`   Health Grade: ${report.metrics.healthGrade}`);
    console.log(`   Issues per KLOC: ${report.metrics.issuesPerKLOC}`);
    console.log(`   Critical Density: ${report.metrics.criticalDensity} per KLOC`);
    console.log(`   Total Lines: ${report.metrics.totalLines.toLocaleString()}\n`);
  }

  /**
   * Display domain breakdown
   */
  displayDomainBreakdown(report) {
    console.log('[CLIPBOARD] FINDINGS BY DOMAIN\n');

    const domainNames = {
      'security-god': 'Security',
      'performance-god': 'Performance',
      'test-god': 'Testing',
      'refactoring-god': 'Code Quality',
      'documentation-god': 'Documentation'
    };

    Object.entries(report.domainSummary).forEach(([god, count]) => {
      const name = domainNames[god] || god;
      const bar = this.createProgressBar(count, report.summary.totalFindings);
      console.log(`   ${name.padEnd(15)} ${bar} ${count}`);
    });
    console.log();
  }

  /**
   * Display top issues
   */
  displayTopIssues(report) {
    if (report.topIssues.length === 0) {
      console.log('[CELEBRATE] NO CRITICAL ISSUES FOUND!\n');
      return;
    }

    console.log('[WARNING]  TOP 10 ISSUES\n');

    report.topIssues.slice(0, 10).forEach((issue, index) => {
      const severityIcon = this.getSeverityIcon(issue.severity);
      console.log(`   ${index + 1}. ${severityIcon} ${issue.message}`);
      console.log(`      File: ${path.basename(issue.file)}:${issue.line}`);
      console.log(`      Domain: ${issue.domainName} | Category: ${issue.category}\n`);
    });
  }

  /**
   * Display recommendations
   */
  displayRecommendations(report) {
    console.log('[TIP] RECOMMENDATIONS\n');

    if (report.recommendations.length === 0) {
      console.log('   [OK] No recommendations - excellent code quality!\n');
      return;
    }

    report.recommendations.forEach((rec, index) => {
      const priorityIcon = this.getPriorityIcon(rec.priority);
      console.log(`   ${index + 1}. ${priorityIcon} ${rec.action}`);
      console.log(`      Priority: ${rec.priority} | Impact: ${rec.impact}`);
      console.log(`      Effort: ${rec.effort}`);
      if (rec.topIssue) {
        console.log(`      Focus: ${rec.topIssue}`);
      }
      console.log();
    });
  }

  /**
   * Display performance metrics
   */
  displayPerformanceMetrics(report) {
    console.log('[BOLT] PERFORMANCE METRICS\n');

    console.log('   Orchestration:');
    console.log(`     Files Processed: ${report.performance.orchestrator.totalFiles}`);
    console.log(`     Tasks Completed: ${report.performance.orchestrator.completedTasks}`);
    console.log(`     Success Rate: ${report.performance.orchestrator.successRate}`);
    console.log(`     Throughput: ${report.performance.orchestrator.filesPerSecond} files/sec\n`);

    console.log('   Load Balancer:');
    console.log(`     Agents Used: ${report.performance.loadBalancer.completedAgents}`);
    console.log(`     Failed Agents: ${report.performance.loadBalancer.failedAgents}`);
    console.log(`     Retries: ${report.performance.loadBalancer.totalRetries}`);
    console.log(`     Success Rate: ${report.performance.loadBalancer.successRate}`);
    console.log(`     Avg Execution: ${report.performance.loadBalancer.averageExecutionTime}\n`);

    console.log(`   Total Duration: ${report.durationFormatted}\n`);
  }

  /**
   * Save report to file
   */
  async saveReport(report) {
    try {
      const markdown = this.synthesizer.toMarkdown(report);
      await fs.writeFile(this.options.reportPath, markdown);
      console.log(`[NOTE] Report saved to: ${this.options.reportPath}\n`);
    } catch (error) {
      console.error(`[WARNING]  Failed to save report: ${error.message}`);
    }
  }

  /**
   * Helper: Create progress bar
   */
  createProgressBar(value, total, width = 20) {
    if (total === 0) return '░'.repeat(width) + ' 0%';
    const percentage = value / total;
    const filled = Math.round(percentage * width);
    const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
    return `${bar} ${(percentage * 100).toFixed(0)}%`;
  }

  /**
   * Helper: Get severity icon
   */
  getSeverityIcon(severity) {
    const icons = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🟢'
    };
    return icons[severity] || '⚪';
  }

  /**
   * Helper: Get priority icon
   */
  getPriorityIcon(priority) {
    const icons = {
      URGENT: '🚨',
      HIGH: '[WARNING]',
      MEDIUM: 'ℹ️',
      LOW: '[TIP]',
      INFO: '[OK]'
    };
    return icons[priority] || '*';
  }

  /**
   * Helper: Format duration
   */
  formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Helper: Generate session ID
   */
  generateSessionId() {
    return `godmode-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Export report as JSON
   */
  async exportJSON(report, filePath) {
    const json = JSON.stringify(report, null, 2);
    await fs.writeFile(filePath, json);
    return filePath;
  }

  /**
   * Export report as Markdown
   */
  async exportMarkdown(report, filePath) {
    const markdown = this.synthesizer.toMarkdown(report);
    await fs.writeFile(filePath, markdown);
    return filePath;
  }

  /**
   * Quick analysis (limited scope for testing)
   */
  async quickAnalysis(projectPath, maxFiles = 20) {
    console.log(`\n[BOLT] QUICK ANALYSIS MODE (max ${maxFiles} files)\n`);

    // Temporarily limit file discovery
    const originalMaxConcurrent = this.orchestrator.maxConcurrent;
    this.orchestrator.maxConcurrent = Math.min(maxFiles, 20);

    try {
      const report = await this.analyzeCodebase(projectPath);
      return report;
    } finally {
      this.orchestrator.maxConcurrent = originalMaxConcurrent;
    }
  }
}

module.exports = CodeTitanOrchestration;

/*
 * SMOKE TEST — onProgress callback usage:
 *
 *   const CodeTitanOrchestration = require('./codetitan-orchestration');
 *   const engine = new CodeTitanOrchestration({ verbose: false });
 *   await engine.analyzeCodebase('/path/to/project', {
 *     onProgress(event) {
 *       if (event.type === 'progress') {
 *         console.log(`[${event.pct}%] ${event.message}`);
 *       } else if (event.type === 'finding') {
 *         console.log(`FINDING [${event.finding.severity}] ${event.finding.message}`);
 *       } else if (event.type === 'done') {
 *         console.log('Done!', event.summary);
 *       }
 *     }
 *   });
 *
 *   // Backward-compatible: omitting onProgress works exactly as before.
 *   const report = await engine.analyzeCodebase('/path/to/project');
 */
