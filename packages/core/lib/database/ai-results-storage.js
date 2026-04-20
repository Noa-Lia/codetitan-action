/**
 * AI Results Storage - Database persistence for multi-AI analysis results
 *
 * Stores:
 * - Analysis runs with AI metadata
 * - Findings with confidence scores
 * - Provider performance metrics
 * - Fix applications and outcomes
 * - Ensemble consensus data
 *
 * Supports both PostgreSQL (Supabase) and SQLite (local)
 *
 * @module database/ai-results-storage
 */

const fs = require('fs').promises;
const path = require('path');

function shouldUseTls(connectionString) {
  if (!connectionString) {
    return false;
  }

  return !/(?:localhost|127\.0\.0\.1)/i.test(connectionString);
}

class AIResultsStorage {
  constructor(config = {}) {
    this.config = {
      // Database type: 'postgres' or 'sqlite'
      type: config.type || process.env.DATABASE_TYPE || 'sqlite',

      // PostgreSQL connection
      postgresUrl: config.postgresUrl || process.env.DATABASE_URL || process.env.POSTGRES_CONNECTION_STRING,

      // SQLite file path
      sqlitePath: config.sqlitePath || process.env.CODETITAN_SQLITE_PATH || './data/codetitan.db',

      // Auto-create tables
      autoMigrate: config.autoMigrate !== false,

      ...config
    };

    this.db = null;
    this.isPostgres = this.config.type === 'postgres';
  }

  /**
   * Initialize database connection
   */
  async initialize() {
    if (this.isPostgres) {
      await this.initializePostgres();
    } else {
      await this.initializeSQLite();
    }

    if (this.config.autoMigrate) {
      await this.runMigrations();
    }

    return this;
  }

  /**
   * Initialize PostgreSQL connection
   */
  async initializePostgres() {
    try {
      const { Pool } = require('pg');
      this.db = new Pool({
        connectionString: this.config.postgresUrl,
        ssl: shouldUseTls(this.config.postgresUrl) ? {} : false
      });

      // Test connection
      await this.db.query('SELECT NOW()');
      console.log('[AIResultsStorage] Connected to PostgreSQL');

    } catch (error) {
      console.error('[AIResultsStorage] PostgreSQL initialization failed:', error.message);
      console.log('[AIResultsStorage] Falling back to SQLite');
      this.isPostgres = false;
      await this.initializeSQLite();
    }
  }

  /**
   * Initialize SQLite connection
   */
  async initializeSQLite() {
    try {
      const sqlite3 = require('better-sqlite3');

      // Ensure directory exists
      const dir = path.dirname(this.config.sqlitePath);
      await fs.mkdir(dir, { recursive: true });

      this.db = sqlite3(this.config.sqlitePath);
      console.log(`[AIResultsStorage] Connected to SQLite: ${this.config.sqlitePath}`);

    } catch (error) {
      console.error('[AIResultsStorage] SQLite initialization failed:', error.message);
      throw new Error('Failed to initialize database');
    }
  }

  /**
   * Run database migrations
   */
  async runMigrations() {
    console.log('[AIResultsStorage] Running migrations...');

    if (this.isPostgres) {
      await this.runPostgresMigrations();
    } else {
      await this.runSQLiteMigrations();
    }

    console.log('[AIResultsStorage] Migrations complete');
  }

  /**
   * Run PostgreSQL migrations
   */
  async runPostgresMigrations() {
    const migrations = [
      // AI Analysis Runs
      `CREATE TABLE IF NOT EXISTS ai_analysis_runs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_path TEXT NOT NULL,
        level INTEGER NOT NULL,
        started_at TIMESTAMP NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMP,
        status TEXT NOT NULL DEFAULT 'running',
        files_analyzed INTEGER DEFAULT 0,
        findings_count INTEGER DEFAULT 0,
        total_cost_usd DECIMAL(10, 6) DEFAULT 0,
        duration_ms INTEGER,
        ensemble_enabled BOOLEAN DEFAULT false,
        metadata JSONB
      )`,

      // AI Findings (enhanced godmode_findings)
      `CREATE TABLE IF NOT EXISTS ai_findings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        run_id UUID REFERENCES ai_analysis_runs(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        line_number INTEGER,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        message TEXT NOT NULL,
        domain TEXT NOT NULL,
        code_snippet TEXT,
        suggestion TEXT,
        impact_score INTEGER,

        -- AI-specific fields
        provider TEXT NOT NULL,
        model TEXT,
        confidence_score INTEGER,
        confidence_level TEXT,
        confidence_explanation TEXT,

        -- Ensemble fields
        supporting_providers TEXT[],
        agreement_rate DECIMAL(3, 2),
        dispute_level DECIMAL(3, 2),

        -- Fix tracking
        has_auto_fix BOOLEAN DEFAULT false,
        fix_applied BOOLEAN DEFAULT false,
        fix_id UUID,

        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        metadata JSONB
      )`,

      // AI Provider Performance
      `CREATE TABLE IF NOT EXISTS ai_provider_performance (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        domain TEXT NOT NULL,
        date DATE NOT NULL DEFAULT CURRENT_DATE,

        -- Performance metrics
        total_analyses INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0,
        total_cost_usd DECIMAL(10, 6) DEFAULT 0,
        total_tokens_input BIGINT DEFAULT 0,
        total_tokens_output BIGINT DEFAULT 0,
        total_tokens_cached BIGINT DEFAULT 0,
        avg_duration_ms INTEGER,

        -- Quality metrics
        accuracy_rate DECIMAL(3, 2),
        false_positive_rate DECIMAL(3, 2),

        updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
        UNIQUE(provider, model, domain, date)
      )`,

      // AI Fix Applications
      `CREATE TABLE IF NOT EXISTS ai_fix_applications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        finding_id UUID REFERENCES ai_findings(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        fix_type TEXT NOT NULL,
        start_line INTEGER,
        end_line INTEGER,
        original_code TEXT,
        fixed_code TEXT,
        explanation TEXT,

        -- Fix metadata
        provider TEXT NOT NULL,
        model TEXT,
        cost_usd DECIMAL(10, 6),
        verified BOOLEAN DEFAULT false,
        breaking_changes BOOLEAN DEFAULT false,

        -- Application tracking
        applied_at TIMESTAMP,
        backup_path TEXT,
        rolled_back BOOLEAN DEFAULT false,
        rollback_at TIMESTAMP,

        -- Outcome tracking
        tests_passed BOOLEAN,
        manual_review_required BOOLEAN DEFAULT false,

        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        metadata JSONB
      )`,

      // Ensemble Results
      `CREATE TABLE IF NOT EXISTS ai_ensemble_results (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        run_id UUID REFERENCES ai_analysis_runs(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        domain TEXT NOT NULL,

        -- Ensemble metrics
        providers_used TEXT[] NOT NULL,
        agreement_rate DECIMAL(3, 2) NOT NULL,
        high_confidence_count INTEGER DEFAULT 0,
        disputed_count INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0,

        -- Cost breakdown
        total_cost_usd DECIMAL(10, 6) DEFAULT 0,
        cost_by_provider JSONB,

        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        metadata JSONB
      )`,

      // Indexes for performance
      `CREATE INDEX IF NOT EXISTS idx_ai_findings_run_id ON ai_findings(run_id)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_findings_confidence ON ai_findings(confidence_level, confidence_score DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_findings_provider ON ai_findings(provider, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_provider_perf_lookup ON ai_provider_performance(provider, domain, date DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_fix_apps_finding ON ai_fix_applications(finding_id)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_ensemble_run ON ai_ensemble_results(run_id)`
    ];

    for (const migration of migrations) {
      await this.db.query(migration);
    }
  }

  /**
   * Run SQLite migrations
   */
  runSQLiteMigrations() {
    const migrations = [
      // AI Analysis Runs
      `CREATE TABLE IF NOT EXISTS ai_analysis_runs (
        id TEXT PRIMARY KEY,
        project_path TEXT NOT NULL,
        level INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        files_analyzed INTEGER DEFAULT 0,
        findings_count INTEGER DEFAULT 0,
        total_cost_usd REAL DEFAULT 0,
        duration_ms INTEGER,
        ensemble_enabled INTEGER DEFAULT 0,
        metadata TEXT
      )`,

      // AI Findings
      `CREATE TABLE IF NOT EXISTS ai_findings (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_number INTEGER,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        message TEXT NOT NULL,
        domain TEXT NOT NULL,
        code_snippet TEXT,
        suggestion TEXT,
        impact_score INTEGER,

        provider TEXT NOT NULL,
        model TEXT,
        confidence_score INTEGER,
        confidence_level TEXT,
        confidence_explanation TEXT,

        supporting_providers TEXT,
        agreement_rate REAL,
        dispute_level REAL,

        has_auto_fix INTEGER DEFAULT 0,
        fix_applied INTEGER DEFAULT 0,
        fix_id TEXT,

        created_at TEXT NOT NULL,
        metadata TEXT,

        FOREIGN KEY (run_id) REFERENCES ai_analysis_runs(id) ON DELETE CASCADE
      )`,

      // AI Provider Performance
      `CREATE TABLE IF NOT EXISTS ai_provider_performance (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        domain TEXT NOT NULL,
        date TEXT NOT NULL,

        total_analyses INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0,
        total_cost_usd REAL DEFAULT 0,
        total_tokens_input INTEGER DEFAULT 0,
        total_tokens_output INTEGER DEFAULT 0,
        total_tokens_cached INTEGER DEFAULT 0,
        avg_duration_ms INTEGER,

        accuracy_rate REAL,
        false_positive_rate REAL,

        updated_at TEXT NOT NULL,
        UNIQUE(provider, model, domain, date)
      )`,

      // AI Fix Applications
      `CREATE TABLE IF NOT EXISTS ai_fix_applications (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        fix_type TEXT NOT NULL,
        start_line INTEGER,
        end_line INTEGER,
        original_code TEXT,
        fixed_code TEXT,
        explanation TEXT,

        provider TEXT NOT NULL,
        model TEXT,
        cost_usd REAL,
        verified INTEGER DEFAULT 0,
        breaking_changes INTEGER DEFAULT 0,

        applied_at TEXT,
        backup_path TEXT,
        rolled_back INTEGER DEFAULT 0,
        rollback_at TEXT,

        tests_passed INTEGER,
        manual_review_required INTEGER DEFAULT 0,

        created_at TEXT NOT NULL,
        metadata TEXT,

        FOREIGN KEY (finding_id) REFERENCES ai_findings(id) ON DELETE CASCADE
      )`,

      // Ensemble Results
      `CREATE TABLE IF NOT EXISTS ai_ensemble_results (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        domain TEXT NOT NULL,

        providers_used TEXT NOT NULL,
        agreement_rate REAL NOT NULL,
        high_confidence_count INTEGER DEFAULT 0,
        disputed_count INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0,

        total_cost_usd REAL DEFAULT 0,
        cost_by_provider TEXT,

        created_at TEXT NOT NULL,
        metadata TEXT,

        FOREIGN KEY (run_id) REFERENCES ai_analysis_runs(id) ON DELETE CASCADE
      )`,

      // Indexes
      `CREATE INDEX IF NOT EXISTS idx_ai_findings_run_id ON ai_findings(run_id)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_findings_confidence ON ai_findings(confidence_level, confidence_score DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_findings_provider ON ai_findings(provider, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_provider_perf_lookup ON ai_provider_performance(provider, domain, date DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_fix_apps_finding ON ai_fix_applications(finding_id)`,
      `CREATE INDEX IF NOT EXISTS idx_ai_ensemble_run ON ai_ensemble_results(run_id)`
    ];

    for (const migration of migrations) {
// TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
      this.db.exec(migration);
    }
  }

  /**
   * Create a new analysis run
   */
  async createAnalysisRun(data) {
    const id = this.generateId();
    const now = new Date().toISOString();

    const run = {
      id,
      project_path: data.projectPath,
      level: data.level,
      started_at: now,
      status: 'running',
      ensemble_enabled: data.ensembleEnabled || false,
      metadata: JSON.stringify(data.metadata || {})
    };

    if (this.isPostgres) {
      await this.db.query(
        `INSERT INTO ai_analysis_runs (id, project_path, level, started_at, status, ensemble_enabled, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [run.id, run.project_path, run.level, run.started_at, run.status, run.ensemble_enabled, run.metadata]
      );
    } else {
      const stmt = this.db.prepare(
        `INSERT INTO ai_analysis_runs (id, project_path, level, started_at, status, ensemble_enabled, metadata)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      );
      stmt.run(run.id, run.project_path, run.level, run.started_at, run.status, run.ensemble_enabled ? 1 : 0, run.metadata);
    }

    return run;
  }

  /**
   * Complete an analysis run
   */
  async completeAnalysisRun(runId, data) {
    const now = new Date().toISOString();

    if (this.isPostgres) {
      await this.db.query(
        `UPDATE ai_analysis_runs
         SET completed_at = $1, status = $2, files_analyzed = $3, findings_count = $4,
             total_cost_usd = $5, duration_ms = $6
         WHERE id = $7`,
        [now, 'completed', data.filesAnalyzed, data.findingsCount, data.totalCost, data.duration, runId]
      );
    } else {
      const stmt = this.db.prepare(
        `UPDATE ai_analysis_runs
         SET completed_at = ?, status = ?, files_analyzed = ?, findings_count = ?,
             total_cost_usd = ?, duration_ms = ?
         WHERE id = ?`
      );
      stmt.run(now, 'completed', data.filesAnalyzed, data.findingsCount, data.totalCost, data.duration, runId);
    }
  }

  /**
   * Store a finding
   */
  async storeFinding(runId, finding) {
    const id = this.generateId();
    const now = new Date().toISOString();

    const data = {
      id,
      run_id: runId,
      file_path: finding.file_path,
      line_number: finding.line_number || null,
      severity: finding.severity,
      category: finding.category,
      message: finding.message,
      domain: finding.domain,
      code_snippet: finding.code_snippet || null,
      suggestion: finding.suggestion || null,
      impact_score: finding.impact_score || null,
      provider: finding.sourceProvider || finding.provider || 'unknown',
      model: finding.model || null,
      confidence_score: finding.confidenceScore?.score || finding.confidence_score || null,
      confidence_level: finding.confidenceScore?.level || finding.confidence_level || null,
      confidence_explanation: finding.confidenceScore?.explanation || finding.confidence_explanation || null,
      supporting_providers: finding.supportingProviders ? JSON.stringify(finding.supportingProviders) : null,
      agreement_rate: finding.agreement_rate || null,
      dispute_level: finding.dispute_level || null,
      has_auto_fix: finding.has_auto_fix || false,
      fix_applied: finding.fix_applied || false,
      fix_id: finding.fix_id || null,
      created_at: now,
      metadata: JSON.stringify(finding.metadata || {})
    };

    if (this.isPostgres) {
      await this.db.query(
        `INSERT INTO ai_findings (
          id, run_id, file_path, line_number, severity, category, message, domain,
          code_snippet, suggestion, impact_score, provider, model, confidence_score,
          confidence_level, confidence_explanation, supporting_providers, agreement_rate,
          dispute_level, has_auto_fix, fix_applied, fix_id, created_at, metadata
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)`,
        Object.values(data)
      );
    } else {
      const stmt = this.db.prepare(
        `INSERT INTO ai_findings (
          id, run_id, file_path, line_number, severity, category, message, domain,
          code_snippet, suggestion, impact_score, provider, model, confidence_score,
          confidence_level, confidence_explanation, supporting_providers, agreement_rate,
          dispute_level, has_auto_fix, fix_applied, fix_id, created_at, metadata
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      stmt.run(...Object.values(data).map(v => typeof v === 'boolean' ? (v ? 1 : 0) : v));
    }

    return data;
  }

  /**
   * Generate UUID (compatible with both Postgres and SQLite)
   */
  generateId() {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Close database connection
   */
  async close() {
    if (this.isPostgres) {
      await this.db.end();
    } else if (this.db) {
      this.db.close();
    }
  }
}

module.exports = AIResultsStorage;
