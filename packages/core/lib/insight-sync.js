const CollectiveInsight = require('./collective-insight');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const fs = require('fs');

/**
 * InsightSync - Dual-write integration layer for SQLite + Supabase
 *
 * Supports three modes:
 * - sqlite-only: Traditional SQLite-only mode (default fallback)
 * - supabase-only: Cloud-only mode (requires Supabase credentials)
 * - dual-write: Write to both stores with conflict resolution
 *
 * Features:
 * - Automatic failover to SQLite if Supabase is unavailable
 * - Migration utilities for backfilling historical data
 * - Sync validation and consistency checking
 * - Progress reporting for long-running migrations
 */
class InsightSync {
  constructor(options = {}) {
    this.mode = options.mode || process.env.CODETITAN_SYNC_MODE || 'sqlite-only';
    this.sqlitePath = options.sqlitePath || path.join(process.cwd(), 'data', 'collective-insight.db');
    this.runtimeInsightPath = options.runtimeInsightPath || path.join(path.dirname(this.sqlitePath), 'agent-runtime-insights.json');

    // Credentials
    this.supabaseUrl = options.supabaseUrl || process.env.SUPABASE_URL;
    this.supabaseKey = options.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

    // Security: Validate URL to prevent SSRF
    if (this.supabaseUrl && !this._isValidUrl(this.supabaseUrl)) {
      console.warn(`[WARNING] Invalid Supabase URL provided: ${this.supabaseUrl}`);
      this.supabaseUrl = null; // Disable cloud connection on invalid URL
    }

    // Initialize SQLite (always available as fallback)
    this.sqlite = new CollectiveInsight(this.sqlitePath);
    this.supabase = null;
    this.supabaseReady = false;

    // Track sync stats
    this.stats = {
      sqliteWrites: 0,
      supabaseWrites: 0,
      runtimeInsightWrites: 0,
      failovers: 0,
      conflicts: 0,
      errors: []
    };
  }

  /**
   * Validate URL structure and protocol
   */
  _isValidUrl(string) {
    try {
      const url = new URL(string);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }

  /**
   * Initialize both stores
   */
  async init() {

    // Always initialize SQLite
    await this.sqlite.init();


    // Try to initialize Supabase if credentials are available
    if (this.mode !== 'sqlite-only') {
      try {
        await this.initSupabase();
      } catch (error) {
        console.warn('[WARNING]  Supabase initialization failed, falling back to SQLite-only mode');
        console.warn(`   Reason: ${error.message}`);
        this.mode = 'sqlite-only';
        this.stats.errors.push({
          timestamp: new Date().toISOString(),
          operation: 'init',
          error: error.message
        });
      }
    }
  }

  /**
   * Initialize Supabase connection
   */
  async initSupabase() {
    if (!this.supabaseUrl || !this.supabaseKey) {
      throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
    }

    this.supabase = createClient(this.supabaseUrl, this.supabaseKey);

    // Test connection by checking if tables exist

    const { data, error } = await this.supabase
      .from('godmode_runs')
      .select('id')
      .limit(1);


    if (error && error.code === '42P01') {
      // Table doesn't exist - create schema
      await this.createSupabaseSchema();
    } else if (error) {
      throw new Error(`Supabase connection failed: ${error.message}`);
    }

    this.supabaseReady = true;
    console.log(`[OK] Supabase connected (mode: ${this.mode})`);
  }

  /**
   * Create Supabase schema matching SQLite structure
   */
  async createSupabaseSchema() {
    console.log('[CHART] Creating Supabase schema for CodeTitan insights...');

    const schema = `
      -- CodeTitan Collective Insight Tables
      CREATE TABLE IF NOT EXISTS godmode_runs (
        id BIGSERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        project_path TEXT NOT NULL,
        session_id TEXT,
        duration_ms INTEGER,
        files_analyzed INTEGER,
        total_findings INTEGER,
        quality_score DECIMAL(5,2),
        health_grade TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS godmode_findings (
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES godmode_runs(id) ON DELETE CASCADE,
        domain TEXT,
        category TEXT,
        severity TEXT,
        message TEXT,
        file TEXT,
        line INTEGER,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(run_id, file, line, category)
      );

      CREATE TABLE IF NOT EXISTS godmode_fix_summaries (
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES godmode_runs(id) ON DELETE CASCADE,
        attempted INTEGER,
        applied INTEGER,
        skipped INTEGER,
        files_touched INTEGER,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- Indexes for performance
      CREATE INDEX IF NOT EXISTS idx_godmode_runs_project_path ON godmode_runs(project_path);
      CREATE INDEX IF NOT EXISTS idx_godmode_runs_timestamp ON godmode_runs(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_godmode_findings_run_id ON godmode_findings(run_id);
      CREATE INDEX IF NOT EXISTS idx_godmode_findings_category ON godmode_findings(category);
      CREATE INDEX IF NOT EXISTS idx_godmode_findings_severity ON godmode_findings(severity);
    `;

    // Execute schema using RPC or direct SQL
    const { error } = await this.supabase.rpc('exec_sql', { sql: schema });

    if (error) {
      // Fallback: try using execute_sql from mcp-supabase
      console.log('   Note: Schema creation requires database admin privileges');
      console.log('   Please run the following SQL in Supabase SQL Editor:');
      console.log(schema);
      throw new Error('Schema creation failed - please create tables manually');
    }

    console.log('[OK] Supabase schema created');
  }

  /**
   * Ingest a report with dual-write support
   */
  async ingestReport(report, metadata = {}) {
    const results = {
      sqlite: null,
      supabase: null,
      mode: this.mode
    };

    try {
      // ALWAYS write to SQLite (guaranteed reliable)
      results.sqlite = await this.sqlite.ingestReport(report, metadata);
      this.stats.sqliteWrites++;

      // Write to Supabase based on mode
      if (this.mode === 'dual-write' || this.mode === 'supabase-only') {
        if (this.supabaseReady) {
          try {
            results.supabase = await this.ingestToSupabase(report, metadata);
            this.stats.supabaseWrites++;
          } catch (error) {
            console.warn('[WARNING]  Supabase write failed, data preserved in SQLite');
            console.warn(`   Error: ${error.message}`);
            this.stats.failovers++;
            this.stats.errors.push({
              timestamp: new Date().toISOString(),
              operation: 'ingest',
              error: error.message
            });

            // Don't throw - SQLite write succeeded
            results.supabase = { error: error.message };
          }
        } else {
          console.warn('[WARNING]  Supabase not ready, using SQLite only');
          this.stats.failovers++;
        }
      }

      return results;

    } catch (error) {
      // Critical failure - even SQLite failed
      console.error('[ERROR] Critical: Failed to ingest report');
      throw error;
    }
  }

  /**
   * Ingest report to Supabase
   */
  async ingestToSupabase(report, metadata) {
    const timestamp = new Date().toISOString();
    const { projectPath, applyFixes = false } = metadata;
    const runInfo = report.summary || {};
    const metrics = report.metrics || {};

    // Insert run
    const { data: runData, error: runError } = await this.supabase
      .from('godmode_runs')
      .insert({
        timestamp,
        project_path: projectPath || 'unknown',
        session_id: report.sessionId || null,
        duration_ms: report.duration || null,
        files_analyzed: runInfo.totalFiles || null,
        total_findings: runInfo.totalFindings || null,
        quality_score: metrics.qualityScore ? Number(metrics.qualityScore) : null,
        health_grade: metrics.healthGrade || null
      })
      .select()
      .single();

    if (runError) {
      throw new Error(`Failed to insert run: ${runError.message}`);
    }

    const runId = runData.id;

    // Insert findings
    const findings = report.topIssues || [];
    if (findings.length > 0) {
      const findingsToInsert = findings.map(issue => ({
        run_id: runId,
        domain: issue.domainName || issue.domain || null,
        category: issue.category || null,
        severity: issue.severity || null,
        message: issue.message || null,
        file: issue.file || null,
        line: issue.line || null
      }));

      const { error: findingsError } = await this.supabase
        .from('godmode_findings')
        .insert(findingsToInsert);

      if (findingsError) {
        console.warn(`[WARNING]  Some findings failed to insert: ${findingsError.message}`);
      }
    }

    // Insert fix summary if applicable
    if (applyFixes && report.fixSummary) {
      const { error: fixError } = await this.supabase
        .from('godmode_fix_summaries')
        .insert({
          run_id: runId,
          attempted: report.fixSummary.attempted || 0,
          applied: report.fixSummary.applied || 0,
          skipped: report.fixSummary.skipped || 0,
          files_touched: (report.fixSummary.filesTouched || []).length
        });

      if (fixError) {
        console.warn(`[WARNING]  Fix summary failed to insert: ${fixError.message}`);
      }
    }

    return { runId, timestamp, findings: findings.length, applyFixes };
  }

  /**
   * Get summary from both stores
   */
  async getSummary() {
    const summary = {
      sqlite: await this.sqlite.getSummary(),
      supabase: null,
      syncStats: this.stats
    };

    if (this.supabaseReady && this.mode !== 'sqlite-only') {
      try {
        summary.supabase = await this.getSupabaseSummary();
      } catch (error) {
        console.warn('[WARNING]  Failed to fetch Supabase summary');
        summary.supabase = { error: error.message };
      }
    }

    return summary;
  }

  /**
   * Get summary from Supabase
   */
  async getSupabaseSummary() {
    const { data, error } = await this.supabase
      .from('godmode_runs')
      .select('id, total_findings, quality_score, timestamp')
      .order('timestamp', { ascending: false });

    if (error) {
      throw new Error(`Failed to fetch summary: ${error.message}`);
    }

    const runCount = data.length;
    const findingsLogged = data.reduce((sum, run) => sum + (run.total_findings || 0), 0);
    const avgQuality = data.length > 0
      ? data.reduce((sum, run) => sum + (run.quality_score || 0), 0) / data.length
      : null;
    const lastRun = data.length > 0 ? data[0].timestamp : null;

    return {
      runCount,
      findingsLogged,
      avgQuality,
      lastRun
    };
  }

  /**
   * Get dashboard from both stores
   */
  async getDashboard(limit = 5) {
    return {
      sqlite: await this.sqlite.getDashboard(limit),
      supabase: this.supabaseReady ? await this.getSupabaseDashboard(limit) : null,
      mode: this.mode,
      syncStats: this.stats
    };
  }

  /**
   * Get Supabase dashboard
   */
  async getSupabaseDashboard(limit = 5) {
    const summary = await this.getSupabaseSummary();

    // Get top categories
    const { data: categoryData } = await this.supabase
      .from('godmode_findings')
      .select('category')
      .not('category', 'is', null);

    const categoryCounts = {};
    categoryData?.forEach(row => {
      categoryCounts[row.category] = (categoryCounts[row.category] || 0) + 1;
    });

    const topCategories = Object.entries(categoryCounts)
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);

    // Get quality trend
    const { data: trendData } = await this.supabase
      .from('godmode_runs')
      .select('quality_score, timestamp')
      .not('quality_score', 'is', null)
      .order('timestamp', { ascending: false })
      .limit(2);

    const qualityTrend = {
      latest: trendData?.[0] || null,
      previous: trendData?.[1] || null,
      delta: trendData?.length === 2
        ? Number(trendData[0].quality_score) - Number(trendData[1].quality_score)
        : null
    };

    return { summary, topCategories, qualityTrend };
  }

  sanitizeProviderUsage(providerUsage = {}) {
    const tokensUsed = providerUsage.tokensUsed || providerUsage.tokens_used || {};
    return {
      selectedProvider: providerUsage.selectedProvider || providerUsage.selected_provider || null,
      selectedModel: providerUsage.selectedModel || providerUsage.selected_model || null,
      totalCostUsd: providerUsage.totalCostUsd || providerUsage.total_cost_usd || 0,
      retries: providerUsage.retries || 0,
      tokensUsed: {
        input: tokensUsed.input || 0,
        output: tokensUsed.output || 0,
        cached: tokensUsed.cached || 0
      }
    };
  }

  extractConventionCandidates(record = {}) {
    const sources = Array.isArray(record.evidence)
      ? record.evidence.map(item => item?.source).filter(Boolean)
      : [];
    const directoryCounts = {};

    sources.forEach(source => {
      if (typeof source !== 'string' || /^[a-z]+:\/\//i.test(source)) {
        return;
      }

      const normalized = source.replace(/\\/g, '/');
      const directory = normalized.includes('/') ? normalized.split('/').slice(0, -1).join('/') : '.';
      directoryCounts[directory] = (directoryCounts[directory] || 0) + 1;
    });

    return Object.entries(directoryCounts)
      .sort((left, right) => right[1] - left[1])
      .slice(0, 5)
      .map(([directory, count]) => ({ directory, count }));
  }

  extractFalsePositiveSignatures(record = {}, metadata = {}) {
    const dismissedActions = Array.isArray(metadata.dismissedActions) ? metadata.dismissedActions : [];
    return dismissedActions.slice(0, 20).map(action => ({
      action: action.action || action.type || 'dismissed',
      target: action.target || action.file || null,
      reason: action.reason || null
    }));
  }

  extractRiskClues(record = {}) {
    const toolTrace = Array.isArray(record.toolTrace) ? record.toolTrace : [];
    return toolTrace
      .filter(entry => entry && (entry.success === false || entry.riskLevel === 'high'))
      .slice(0, 10)
      .map(entry => ({
        tool: entry.tool,
        riskLevel: entry.riskLevel || 'unknown',
        mutating: entry.mutating === true,
        success: entry.success === true,
        summary: entry.summary || null
      }));
  }

  sanitizeRuntimeRecord(record = {}, metadata = {}) {
    const runtimeState = record.runtime_state || record.runtimeState || {};
    const evidence = Array.isArray(record.evidence) ? record.evidence : [];
    const toolTrace = Array.isArray(record.toolTrace) ? record.toolTrace : [];
    const reviewArtifact = record.review_artifact || record.reviewArtifact || runtimeState.reviewArtifact || null;
    const fixSession = record.fix_session || record.fixSession || runtimeState.fixSession || null;
    const promoted = record.promoted === true || record.repository_modified === true;
    const acceptedActions = [];
    const dismissedActions = [];

    if (promoted || record.status === 'applied_in_workspace' || record.status === 'validated_in_workspace') {
      acceptedActions.push({
        action: metadata.action || record.type || 'runtime',
        status: record.status || null,
        target: record.file || record.target || metadata.targetPath || null
      });
    } else if (record.success === false || record.status === 'planned' || record.status === 'insufficient_evidence') {
      dismissedActions.push({
        action: metadata.action || record.type || 'runtime',
        status: record.status || null,
        target: record.file || record.target || metadata.targetPath || null,
        reason: record.error || record.summary || null
      });
    }

    return {
      timestamp: new Date().toISOString(),
      projectPath: metadata.projectPath || process.cwd(),
      action: metadata.action || record.type || null,
      agent: metadata.agent || null,
      target: metadata.targetPath || record.target || record.file || null,
      reasoningMode: runtimeState.reasoningMode || metadata.reasoningMode || 'standard',
      verificationStatus: runtimeState.verificationStatus || null,
      evidenceSummary: record.evidenceSummary || 'No evidence recorded.',
      evidenceCount: evidence.length,
      evidence: evidence.slice(0, 25).map(item => ({
        kind: item.kind || 'observation',
        source: item.source || null,
        summary: item.summary || null
      })),
      toolTrace: toolTrace.slice(0, 25).map(entry => ({
        tool: entry.tool || null,
        success: entry.success === true,
        riskLevel: entry.riskLevel || null,
        mutating: entry.mutating === true,
        durationMs: entry.durationMs || 0,
        summary: entry.summary || null,
        error: entry.error || null
      })),
      providerUsage: this.sanitizeProviderUsage(runtimeState.providerUsage || {}),
      acceptedActions,
      dismissedActions: [
        ...dismissedActions,
        ...this.extractFalsePositiveSignatures(record, metadata)
      ],
      verificationOutcome: {
        status: runtimeState.verificationStatus || null,
        promoted,
        repositoryModified: record.repository_modified === true
      },
      conventions: this.extractConventionCandidates(record),
      falsePositiveSignatures: this.extractFalsePositiveSignatures(record, metadata),
      riskClues: this.extractRiskClues(record),
      reviewArtifactPath: reviewArtifact?.path || runtimeState.reviewArtifact?.path || runtimeState.review_artifact_path || null,
      fixSession: {
        id: fixSession?.id || runtimeState.fixSession?.id || runtimeState.fix_session_id || null,
        path: fixSession?.path || runtimeState.fixSession?.path || runtimeState.fix_session_path || null
      }
    };
  }

  async readRuntimeInsightStore() {
    try {
      const raw = await fs.promises.readFile(this.runtimeInsightPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && Array.isArray(parsed.entries)) {
        return parsed;
      }
    } catch (_) {
      // Ignore missing files and malformed content; callers overwrite with fresh state.
    }

    return {
      version: 1,
      entries: []
    };
  }

  async ingestAgentRuntime(record = {}, metadata = {}) {
    const sanitized = this.sanitizeRuntimeRecord(record, metadata);
    const store = await this.readRuntimeInsightStore();
    const entryLimit = Math.max(1, Math.min(Number(metadata.limit) || 200, 1000));

    store.entries.unshift(sanitized);
    store.entries = store.entries.slice(0, entryLimit);

    await fs.promises.mkdir(path.dirname(this.runtimeInsightPath), { recursive: true });
    await fs.promises.writeFile(`${this.runtimeInsightPath}`, `${JSON.stringify(store, null, 2)}\n`, 'utf8');
    this.stats.runtimeInsightWrites += 1;

    return {
      path: this.runtimeInsightPath,
      entry: sanitized,
      count: store.entries.length
    };
  }

  /**
   * MIGRATION UTILITY: Backfill all SQLite data to Supabase
   */
  async syncHistoricalData(options = {}) {
    if (!this.supabaseReady) {
      throw new Error('Supabase is not ready. Check credentials and connection.');
    }

    const { dryRun = false, batchSize = 50, progressCallback } = options;

    console.log('🔄 Starting historical data migration...');
    console.log(`   Mode: ${dryRun ? 'DRY RUN' : 'LIVE MIGRATION'}`);
    console.log(`   Batch size: ${batchSize}`);

    const migrationStats = {
      totalRuns: 0,
      totalFindings: 0,
      totalFixSummaries: 0,
      migratedRuns: 0,
      migratedFindings: 0,
      migratedFixSummaries: 0,
      errors: [],
      startTime: Date.now()
    };

    try {
      // Get all runs from SQLite
      const runs = await this.sqlite.all('SELECT * FROM runs ORDER BY timestamp ASC');
      migrationStats.totalRuns = runs.length;

      console.log(`[CHART] Found ${runs.length} runs in SQLite`);

      // Process runs in batches
      for (let i = 0; i < runs.length; i += batchSize) {
        const batch = runs.slice(i, i + batchSize);

        if (progressCallback) {
          progressCallback({
            current: i + batch.length,
            total: runs.length,
            phase: 'runs'
          });
        }

        for (const run of batch) {
          try {
            if (!dryRun) {
              // Insert run into Supabase
              const { data: supabaseRun, error: runError } = await this.supabase
                .from('godmode_runs')
                .insert({
                  timestamp: run.timestamp,
                  project_path: run.project_path,
                  session_id: run.session_id,
                  duration_ms: run.duration_ms,
                  files_analyzed: run.files_analyzed,
                  total_findings: run.total_findings,
                  quality_score: run.quality_score,
                  health_grade: run.health_grade
                })
                .select()
                .single();

              if (runError) {
                throw new Error(`Run ${run.id}: ${runError.message}`);
              }

              const newRunId = supabaseRun.id;
              migrationStats.migratedRuns++;

              // Migrate findings for this run
              const findings = await this.sqlite.all(
                'SELECT * FROM findings WHERE run_id = ?',
                [run.id]
              );

              migrationStats.totalFindings += findings.length;

              if (findings.length > 0) {
                const findingsToInsert = findings.map(f => ({
                  run_id: newRunId,
                  domain: f.domain,
                  category: f.category,
                  severity: f.severity,
                  message: f.message,
                  file: f.file,
                  line: f.line
                }));

                const { error: findingsError } = await this.supabase
                  .from('godmode_findings')
                  .insert(findingsToInsert);

                if (findingsError) {
                  throw new Error(`Findings for run ${run.id}: ${findingsError.message}`);
                }

                migrationStats.migratedFindings += findings.length;
              }

              // Migrate fix summaries
              const fixSummaries = await this.sqlite.all(
                'SELECT * FROM fix_summaries WHERE run_id = ?',
                [run.id]
              );

              migrationStats.totalFixSummaries += fixSummaries.length;

              if (fixSummaries.length > 0) {
                const fixSummariesToInsert = fixSummaries.map(f => ({
                  run_id: newRunId,
                  attempted: f.attempted,
                  applied: f.applied,
                  skipped: f.skipped,
                  files_touched: f.files_touched
                }));

                const { error: fixError } = await this.supabase
                  .from('godmode_fix_summaries')
                  .insert(fixSummariesToInsert);

                if (fixError) {
                  throw new Error(`Fix summaries for run ${run.id}: ${fixError.message}`);
                }

                migrationStats.migratedFixSummaries += fixSummaries.length;
              }
            } else {
              // Dry run - just count
              migrationStats.migratedRuns++;
              const findings = await this.sqlite.all(
                'SELECT COUNT(*) as count FROM findings WHERE run_id = ?',
                [run.id]
              );
              migrationStats.migratedFindings += findings[0].count;

              const fixSummaries = await this.sqlite.all(
                'SELECT COUNT(*) as count FROM fix_summaries WHERE run_id = ?',
                [run.id]
              );
              migrationStats.migratedFixSummaries += fixSummaries[0].count;
            }
          } catch (error) {
            migrationStats.errors.push({
              runId: run.id,
              timestamp: run.timestamp,
              error: error.message
            });
          }
        }
      }

      migrationStats.duration = Date.now() - migrationStats.startTime;

      console.log('\n[OK] Migration complete!');
      console.log(`   Runs: ${migrationStats.migratedRuns}/${migrationStats.totalRuns}`);
      console.log(`   Findings: ${migrationStats.migratedFindings}/${migrationStats.totalFindings}`);
      console.log(`   Fix Summaries: ${migrationStats.migratedFixSummaries}/${migrationStats.totalFixSummaries}`);
      console.log(`   Errors: ${migrationStats.errors.length}`);
      console.log(`   Duration: ${(migrationStats.duration / 1000).toFixed(2)}s`);

      return migrationStats;

    } catch (error) {
      console.error('[ERROR] Migration failed:', error.message);
      throw error;
    }
  }

  /**
   * VALIDATION UTILITY: Verify data consistency between stores
   */
  async validateSync(options = {}) {
    if (!this.supabaseReady) {
      throw new Error('Supabase is not ready. Check credentials and connection.');
    }

    console.log('[SEARCH] Validating sync consistency...');

    const validation = {
      sqliteCount: 0,
      supabaseCount: 0,
      consistent: false,
      discrepancies: [],
      sampleChecks: []
    };

    // Count runs in both stores
    const sqliteRuns = await this.sqlite.all('SELECT COUNT(*) as count FROM runs');
    validation.sqliteCount = sqliteRuns[0].count;

    const { count: supabaseCount } = await this.supabase
      .from('godmode_runs')
      .select('*', { count: 'exact', head: true });

    validation.supabaseCount = supabaseCount;

    // Check if counts match
    if (validation.sqliteCount !== validation.supabaseCount) {
      validation.discrepancies.push({
        type: 'count_mismatch',
        message: `SQLite has ${validation.sqliteCount} runs, Supabase has ${validation.supabaseCount} runs`
      });
    }

    // Sample recent runs for detailed comparison
    const recentSqliteRuns = await this.sqlite.all(
      'SELECT * FROM runs ORDER BY timestamp DESC LIMIT 10'
    );

    for (const sqliteRun of recentSqliteRuns) {
      const { data: supabaseRuns } = await this.supabase
        .from('godmode_runs')
        .select('*')
        .eq('project_path', sqliteRun.project_path)
        .eq('timestamp', sqliteRun.timestamp)
        .limit(1);

      if (!supabaseRuns || supabaseRuns.length === 0) {
        validation.sampleChecks.push({
          sqliteId: sqliteRun.id,
          timestamp: sqliteRun.timestamp,
          status: 'missing_in_supabase'
        });
      } else {
        const supabaseRun = supabaseRuns[0];
        const fieldsMatch =
          sqliteRun.project_path === supabaseRun.project_path &&
          sqliteRun.total_findings === supabaseRun.total_findings &&
          Math.abs((sqliteRun.quality_score || 0) - (supabaseRun.quality_score || 0)) < 0.01;

        validation.sampleChecks.push({
          sqliteId: sqliteRun.id,
          supabaseId: supabaseRun.id,
          timestamp: sqliteRun.timestamp,
          status: fieldsMatch ? 'consistent' : 'field_mismatch'
        });
      }
    }

    validation.consistent =
      validation.discrepancies.length === 0 &&
      validation.sampleChecks.every(check => check.status === 'consistent');

    console.log(`\n${validation.consistent ? '[OK]' : '[WARNING]'} Validation complete`);
    console.log(`   SQLite runs: ${validation.sqliteCount}`);
    console.log(`   Supabase runs: ${validation.supabaseCount}`);
    console.log(`   Discrepancies: ${validation.discrepancies.length}`);
    console.log(`   Sample checks: ${validation.sampleChecks.filter(c => c.status === 'consistent').length}/${validation.sampleChecks.length} consistent`);

    return validation;
  }

  /**
   * Close both connections
   */
  async close() {
    await this.sqlite.close();
    // Supabase client doesn't need explicit closing
    this.supabaseReady = false;
  }

  /**
   * Get sync statistics
   */
  getStats() {
    return {
      ...this.stats,
      mode: this.mode,
      supabaseReady: this.supabaseReady,
      uptime: process.uptime()
    };
  }
}

module.exports = InsightSync;
