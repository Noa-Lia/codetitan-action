/**
 * CodeTitan LEVEL 6: SUPABASE COLLECTIVE INSIGHT CONNECTOR
 *
 * This module provides a high-level interface for storing and querying
 * CodeTitan analysis data in Supabase PostgreSQL database.
 *
 * Features:
 * - Multi-project tracking with RLS security
 * - Run history and quality metrics
 * - Finding categorization and trending
 * - Cross-project analytics
 * - Fix success tracking
 */

const { createClient } = require('@supabase/supabase-js');

class SupabaseCollectiveInsight {
  constructor(options = {}) {
    this.supabaseUrl = options.supabaseUrl || process.env.SUPABASE_URL;
    this.supabaseKey = options.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!this.supabaseUrl || !this.supabaseKey) {
      throw new Error(
        'Supabase credentials required. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables.'
      );
    }

    // Initialize Supabase client with service role key (bypasses RLS for admin operations)
    this.supabase = createClient(this.supabaseUrl, this.supabaseKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });

    this.userId = options.userId || null;
    this.teamId = options.teamId || null;
  }

  /**
   * Initialize or get a project
   */
  async ensureProject(projectInfo) {
    const {
      projectName,
      projectPath,
      repositoryUrl = null,
      languages = null,
      framework = null,
      tags = []
    } = projectInfo;

    // Try to find existing project
    const { data: existing, error: findError } = await this.supabase
      .from('godmode_projects')
      .select('*')
      .eq('project_path', projectPath)
      .eq('team_id', this.teamId)
      .single();

    if (existing && !findError) {
      return existing;
    }

    // Create new project
    const { data: project, error: createError } = await this.supabase
      .from('godmode_projects')
      .insert({
        project_name: projectName,
        project_path: projectPath,
        repository_url: repositoryUrl,
        team_id: this.teamId,
        owner_id: this.userId,
        languages,
        framework,
        tags
      })
      .select()
      .single();

    if (createError) {
      throw new Error(`Failed to create project: ${createError.message}`);
    }

    return project;
  }

  /**
   * Ingest a complete analysis report
   */
  async ingestReport(report, metadata = {}) {
    const {
      projectPath,
      projectName = 'Unknown Project',
      repositoryUrl = null,
      applyFixes = false
    } = metadata;

    // Ensure project exists
    const project = await this.ensureProject({
      projectName,
      projectPath,
      repositoryUrl
    });

    const runInfo = report.summary || {};
    const metrics = report.metrics || {};

    // Start transaction
    const runData = {
      project_id: project.id,
      session_id: report.sessionId || null,
      completed_at: new Date().toISOString(),
      duration_ms: report.duration || null,
      files_analyzed: runInfo.totalFiles || 0,
      total_findings: runInfo.totalFindings || 0,
      quality_score: metrics.qualityScore ? Number(metrics.qualityScore) : null,
      health_grade: metrics.healthGrade || null,
      security_score: metrics.securityScore || null,
      performance_score: metrics.performanceScore || null,
      maintainability_score: metrics.maintainabilityScore || null,
      documentation_score: metrics.documentationScore || null,
      test_coverage_score: metrics.testCoverageScore || null,
      godmode_level: metadata.godmodeLevel || null,
      quick_mode: metadata.quickMode || false,
      raw_report: report
    };

    // Calculate findings by severity
    const findings = report.topIssues || [];
    runData.critical_findings = findings.filter(f => f.severity === 'critical').length;
    runData.high_findings = findings.filter(f => f.severity === 'high').length;
    runData.medium_findings = findings.filter(f => f.severity === 'medium').length;
    runData.low_findings = findings.filter(f => f.severity === 'low').length;

    // Insert run
    const { data: run, error: runError } = await this.supabase
      .from('godmode_runs')
      .insert(runData)
      .select()
      .single();

    if (runError) {
      throw new Error(`Failed to insert run: ${runError.message}`);
    }

    // Insert findings
    const findingInserts = findings.map(issue => ({
      run_id: run.id,
      project_id: project.id,
      domain: issue.domainName || issue.domain || 'unknown',
      category: issue.category || 'UNCATEGORIZED',
      severity: issue.severity || 'info',
      message: issue.message || '',
      description: issue.description || null,
      recommendation: issue.recommendation || null,
      file_path: issue.file || null,
      line_number: issue.line || null,
      code_snippet: issue.snippet || null,
      has_auto_fix: issue.hasAutoFix || false
    }));

    if (findingInserts.length > 0) {
      const { error: findingsError } = await this.supabase
        .from('godmode_findings')
        .insert(findingInserts);

      if (findingsError) {
        console.error('Failed to insert findings:', findingsError.message);
      }
    }

    // Insert fix summary if fixes were applied
    if (applyFixes && report.fixSummary) {
      const fixSummary = report.fixSummary;
      const { error: fixError } = await this.supabase
        .from('godmode_fix_summaries')
        .insert({
          run_id: run.id,
          project_id: project.id,
          attempted: fixSummary.attempted || 0,
          applied: fixSummary.applied || 0,
          skipped: fixSummary.skipped || 0,
          failed: fixSummary.failed || 0,
          files_touched: fixSummary.filesTouched || [],
          files_touched_count: (fixSummary.filesTouched || []).length,
          fixes_by_category: fixSummary.byCategory || null,
          fixes_by_severity: fixSummary.bySeverity || null,
          success_rate: fixSummary.applied > 0
            ? (fixSummary.applied / fixSummary.attempted * 100)
            : 0
        });

      if (fixError) {
        console.error('Failed to insert fix summary:', fixError.message);
      }
    }

    // Create quality snapshot
    await this.createQualitySnapshot(project.id, run.id, runData);

    return {
      runId: run.id,
      projectId: project.id,
      findingsCount: findingInserts.length,
      applyFixes
    };
  }

  /**
   * Create a quality snapshot for trend tracking
   */
  async createQualitySnapshot(projectId, runId, runData) {
    const today = new Date().toISOString().split('T')[0];

    const { error } = await this.supabase
      .from('godmode_quality_snapshots')
      .insert({
        project_id: projectId,
        run_id: runId,
        snapshot_date: today,
        quality_score: runData.quality_score,
        health_grade: runData.health_grade,
        security_score: runData.security_score,
        performance_score: runData.performance_score,
        maintainability_score: runData.maintainability_score,
        documentation_score: runData.documentation_score,
        test_coverage_score: runData.test_coverage_score,
        total_findings: runData.total_findings,
        critical_findings: runData.critical_findings,
        high_findings: runData.high_findings,
        medium_findings: runData.medium_findings,
        low_findings: runData.low_findings
      })
      .onConflict('project_id,snapshot_date')
      .ignoreDuplicates();

    if (error) {
      console.error('Failed to create quality snapshot:', error.message);
    }
  }

  /**
   * Get project summary statistics
   */
  async getProjectSummary(projectPath) {
    const { data: project } = await this.supabase
      .from('godmode_projects')
      .select('id, project_name, current_health_grade, current_quality_score, last_analyzed_at')
      .eq('project_path', projectPath)
      .eq('team_id', this.teamId)
      .single();

    if (!project) {
      return null;
    }

    const { data: runs } = await this.supabase
      .from('godmode_runs')
      .select('quality_score, total_findings, started_at')
      .eq('project_id', project.id)
      .order('started_at', { ascending: false });

    const { data: findingsCount } = await this.supabase
      .from('godmode_findings')
      .select('id', { count: 'exact', head: true })
      .eq('project_id', project.id);

    return {
      project: project.project_name,
      healthGrade: project.current_health_grade,
      qualityScore: project.current_quality_score,
      lastAnalyzed: project.last_analyzed_at,
      totalRuns: runs?.length || 0,
      totalFindings: findingsCount?.count || 0,
      recentRuns: runs?.slice(0, 10) || []
    };
  }

  /**
   * Get top finding categories across all projects or a specific project
   */
  async getTopCategories(limit = 10, projectPath = null) {
    let query = this.supabase
      .from('godmode_findings')
      .select(`
        category,
        domain,
        severity,
        project_id
      `);

    if (projectPath) {
      const { data: project } = await this.supabase
        .from('godmode_projects')
        .select('id')
        .eq('project_path', projectPath)
        .eq('team_id', this.teamId)
        .single();

      if (project) {
        query = query.eq('project_id', project.id);
      }
    }

    const { data: findings } = await query;

    if (!findings) {
      return [];
    }

    // Aggregate by category
    const categoryMap = new Map();
    findings.forEach(finding => {
      const key = finding.category;
      if (!categoryMap.has(key)) {
        categoryMap.set(key, {
          category: finding.category,
          domain: finding.domain,
          count: 0,
          projects: new Set()
        });
      }
      const cat = categoryMap.get(key);
      cat.count++;
      cat.projects.add(finding.project_id);
    });

    // Convert to array and sort
    const categories = Array.from(categoryMap.values())
      .map(cat => ({
        category: cat.category,
        domain: cat.domain,
        count: cat.count,
        projectCount: cat.projects.size
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);

    return categories;
  }

  /**
   * Get quality trend for a project
   */
  async getQualityTrend(projectPath, days = 30) {
    const { data: project } = await this.supabase
      .from('godmode_projects')
      .select('id')
      .eq('project_path', projectPath)
      .eq('team_id', this.teamId)
      .single();

    if (!project) {
      return null;
    }

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    const { data: snapshots } = await this.supabase
      .from('godmode_quality_snapshots')
      .select('*')
      .eq('project_id', project.id)
      .gte('snapshot_date', cutoffDate.toISOString().split('T')[0])
      .order('snapshot_date', { ascending: true });

    if (!snapshots || snapshots.length === 0) {
      return { trend: [], latest: null, delta: null };
    }

    const latest = snapshots[snapshots.length - 1];
    const previous = snapshots.length > 1 ? snapshots[snapshots.length - 2] : null;
    const delta = previous ? latest.quality_score - previous.quality_score : null;

    return {
      trend: snapshots,
      latest,
      previous,
      delta
    };
  }

  /**
   * Get comprehensive dashboard data
   */
  async getDashboard(options = {}) {
    const { projectPath = null, topCategoriesLimit = 10 } = options;

    const summary = projectPath
      ? await this.getProjectSummary(projectPath)
      : await this.getAllProjectsSummary();

    const topCategories = await this.getTopCategories(topCategoriesLimit, projectPath);

    const qualityTrend = projectPath
      ? await this.getQualityTrend(projectPath)
      : null;

    return {
      summary,
      topCategories,
      qualityTrend
    };
  }

  /**
   * Get summary across all projects
   */
  async getAllProjectsSummary() {
    const { data: projects, count: projectCount } = await this.supabase
      .from('godmode_projects')
      .select('*', { count: 'exact' })
      .eq('team_id', this.teamId);

    const { data: runs, count: runCount } = await this.supabase
      .from('godmode_runs')
      .select('quality_score, total_findings', { count: 'exact' });

    const { count: findingsCount } = await this.supabase
      .from('godmode_findings')
      .select('id', { count: 'exact', head: true });

    const avgQuality = runs?.length > 0
      ? runs.reduce((sum, r) => sum + (r.quality_score || 0), 0) / runs.length
      : null;

    const totalFindings = runs?.reduce((sum, r) => sum + (r.total_findings || 0), 0) || 0;

    return {
      totalProjects: projectCount || 0,
      totalRuns: runCount || 0,
      totalFindings: findingsCount || 0,
      avgQualityScore: avgQuality ? avgQuality.toFixed(2) : null,
      projects: projects || []
    };
  }

  /**
   * Get cross-project insights
   */
  async getCrossProjectInsights(limit = 10) {
    const { data: insights } = await this.supabase
      .from('godmode_cross_project_insights')
      .select('*')
      .order('project_count', { ascending: false })
      .limit(limit);

    return insights || [];
  }

  /**
   * Refresh materialized views (call periodically for updated analytics)
   */
  async refreshAnalytics() {
    await this.supabase.rpc('refresh_materialized_view', {
      view_name: 'godmode_top_categories'
    });

    await this.supabase.rpc('refresh_materialized_view', {
      view_name: 'godmode_project_health_summary'
    });
  }

  /**
   * Search findings by text
   */
  async searchFindings(searchText, options = {}) {
    const { projectPath = null, limit = 50 } = options;

    let query = this.supabase
      .from('godmode_findings')
      .select(`
        *,
        godmode_runs!inner(project_id),
        godmode_projects!inner(project_name, project_path)
      `)
      .textSearch('message', searchText)
      .limit(limit);

    if (projectPath) {
      query = query.eq('godmode_projects.project_path', projectPath);
    }

    const { data: findings } = await query;

    return findings || [];
  }

  /**
   * Get fix success metrics
   */
  async getFixSuccessMetrics(projectPath = null) {
    let query = this.supabase
      .from('godmode_fix_summaries')
      .select('*');

    if (projectPath) {
      const { data: project } = await this.supabase
        .from('godmode_projects')
        .select('id')
        .eq('project_path', projectPath)
        .eq('team_id', this.teamId)
        .single();

      if (project) {
        query = query.eq('project_id', project.id);
      }
    }

    const { data: summaries } = await query;

    if (!summaries || summaries.length === 0) {
      return {
        totalAttempted: 0,
        totalApplied: 0,
        totalSkipped: 0,
        totalFailed: 0,
        avgSuccessRate: 0,
        fixesByCategory: {}
      };
    }

    const metrics = summaries.reduce((acc, s) => {
      acc.totalAttempted += s.attempted || 0;
      acc.totalApplied += s.applied || 0;
      acc.totalSkipped += s.skipped || 0;
      acc.totalFailed += s.failed || 0;
      return acc;
    }, {
      totalAttempted: 0,
      totalApplied: 0,
      totalSkipped: 0,
      totalFailed: 0
    });

    metrics.avgSuccessRate = metrics.totalAttempted > 0
      ? (metrics.totalApplied / metrics.totalAttempted * 100).toFixed(2)
      : 0;

    // Aggregate fixes by category
    const fixesByCategory = {};
    summaries.forEach(s => {
      if (s.fixes_by_category) {
        Object.entries(s.fixes_by_category).forEach(([cat, count]) => {
          fixesByCategory[cat] = (fixesByCategory[cat] || 0) + count;
        });
      }
    });

    metrics.fixesByCategory = fixesByCategory;

    return metrics;
  }

  /**
   * Close connection (Supabase client doesn't require explicit closing)
   */
  async close() {
    // No-op for Supabase client
    return;
  }
}

module.exports = SupabaseCollectiveInsight;
