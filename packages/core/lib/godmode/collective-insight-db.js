/**
 * Collective Insight Database
 * SQLite-backed knowledge base for cross-project learning
 *
 * Stores:
 * - Analysis runs (when, what, where)
 * - Findings (issues discovered)
 * - Fixes (what worked, what didn't)
 * - Provider performance (costs, quality, speed)
 * - Team knowledge (patterns, best practices)
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

class CollectiveInsightDB {
  constructor(dbPath = null) {
    // Default to project root /data directory
    this.dbPath = dbPath || path.join(process.cwd(), 'data', 'collective-insight.db');

    // Ensure data directory exists
    const dataDir = path.dirname(this.dbPath);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL'); // Better concurrency

    this.initializeTables();
  }

  /**
   * Initialize database schema
   */
  initializeTables() {
    // Table 1: Analysis Runs
// TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS analysis_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_path TEXT NOT NULL,
        project_name TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        level INTEGER,
        files_analyzed INTEGER DEFAULT 0,
        duration_ms INTEGER,
        success BOOLEAN DEFAULT 1,
        error TEXT,
        metadata TEXT -- JSON blob
      )
    `);

// TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.
    // Table 2: Findings
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        file_path TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        line_number INTEGER,
        message TEXT,
        suggestion TEXT,
        provider TEXT, -- which AI found it
        confidence REAL, -- 0-1
        created_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
      )
    `);
// TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.

    // Table 3: Fixes
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS fixes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER,
        run_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        applied_at TEXT NOT NULL,
        provider TEXT, -- which AI generated the fix
        fix_code TEXT,
        success BOOLEAN,
        confidence REAL,
        rollback_reason TEXT,
        metadata TEXT, -- JSON blob
        FOREIGN KEY (finding_id) REFERENCES findings(id),
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
      )
    `);
    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.

    // Table 4: Provider Performance
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS provider_performance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        provider TEXT NOT NULL,
        domain TEXT,
        files_analyzed INTEGER DEFAULT 0,
        findings_count INTEGER DEFAULT 0,
        duration_ms INTEGER,
        cost_usd REAL DEFAULT 0,
        tokens_used INTEGER DEFAULT 0,
        confidence_avg REAL,
        success BOOLEAN DEFAULT 1,
        error TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
      )
    `);
    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.

    // Table 5: Team Knowledge
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS team_knowledge (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_type TEXT NOT NULL, -- 'common_issue', 'fix_success', 'provider_excellence'
        category TEXT,
        provider TEXT,
        occurrences INTEGER DEFAULT 1,
        success_rate REAL,
        avg_confidence REAL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        metadata TEXT -- JSON blob
      )
    `);
    // TODO: Fix COMMAND_EXEC - Command execution opens the door to injection attacks. Validate or sandbox inputs.

    // Create indexes for performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
      CREATE INDEX IF NOT EXISTS idx_fixes_category ON fixes(category);
      CREATE INDEX IF NOT EXISTS idx_fixes_success ON fixes(success);
      CREATE INDEX IF NOT EXISTS idx_provider_perf_provider ON provider_performance(provider);
      CREATE INDEX IF NOT EXISTS idx_provider_perf_domain ON provider_performance(domain);
      CREATE INDEX IF NOT EXISTS idx_knowledge_pattern ON team_knowledge(pattern_type, category);
    `);

    console.log('✓ Collective Insight database initialized');
  }

  /**
   * Record a new analysis run
   */
  recordRun({ projectPath, projectName, level, metadata = {} }) {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_runs (project_path, project_name, started_at, level, metadata)
      VALUES (?, ?, datetime('now'), ?, ?)
    `);

    const result = stmt.run(
      projectPath,
      projectName || path.basename(projectPath),
      level,
      JSON.stringify(metadata)
    );

    return result.lastInsertRowid;
  }

  /**
   * Complete an analysis run
   */
  completeRun(runId, { filesAnalyzed, durationMs, success = true, error = null }) {
    const stmt = this.db.prepare(`
      UPDATE analysis_runs
      SET completed_at = datetime('now'),
          files_analyzed = ?,
          duration_ms = ?,
          success = ?,
          error = ?
      WHERE id = ?
    `);

    stmt.run(filesAnalyzed, durationMs, success ? 1 : 0, error, runId);
  }

  /**
   * Record a finding
   */
  recordFinding(runId, finding) {
    const stmt = this.db.prepare(`
      INSERT INTO findings (
        run_id, file_path, category, severity, line_number,
        message, suggestion, provider, confidence, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `);

    return stmt.run(
      runId,
      finding.filePath || finding.file,
      finding.category,
      finding.severity,
      finding.line || finding.lineNumber,
      finding.message,
      finding.suggestion || finding.fix,
      finding.provider || 'heuristic',
      finding.confidence || 0.7
    ).lastInsertRowid;
  }

  /**
   * Record a fix attempt
   */
  recordFix(runId, fix) {
    const stmt = this.db.prepare(`
      INSERT INTO fixes (
        finding_id, run_id, category, applied_at, provider,
        fix_code, success, confidence, rollback_reason, metadata
      ) VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      fix.findingId || null,
      runId,
      fix.category,
      fix.provider || 'heuristic',
      fix.code || fix.fixCode,
      fix.success ? 1 : 0,
      fix.confidence || 0.7,
      fix.rollbackReason || null,
      JSON.stringify(fix.metadata || {})
    ).lastInsertRowid;
  }

  /**
   * Record provider performance
   */
  recordProviderPerformance(runId, perf) {
    const stmt = this.db.prepare(`
      INSERT INTO provider_performance (
        run_id, provider, domain, files_analyzed, findings_count,
        duration_ms, cost_usd, tokens_used, confidence_avg, success, error, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `);

    stmt.run(
      runId,
      perf.provider,
      perf.domain || null,
      perf.filesAnalyzed || 0,
      perf.findingsCount || 0,
      perf.durationMs || 0,
      perf.costUsd || 0,
      perf.tokensUsed || 0,
      perf.confidenceAvg || 0,
      perf.success ? 1 : 0,
      perf.error || null
    );
  }

  /**
   * Update team knowledge (patterns)
   */
  updateKnowledge(pattern) {
    // Check if pattern exists
    const existing = this.db.prepare(`
      SELECT id, occurrences FROM team_knowledge
      WHERE pattern_type = ? AND category = ? AND provider = ?
    `).get(pattern.type, pattern.category || '', pattern.provider || '');

    if (existing) {
      // Update existing
      this.db.prepare(`
        UPDATE team_knowledge
        SET occurrences = occurrences + 1,
            success_rate = ?,
            avg_confidence = ?,
            last_seen = datetime('now'),
            metadata = ?
        WHERE id = ?
      `).run(
        pattern.successRate || null,
        pattern.avgConfidence || null,
        JSON.stringify(pattern.metadata || {}),
        existing.id
      );
    } else {
      // Insert new
      this.db.prepare(`
        INSERT INTO team_knowledge (
          pattern_type, category, provider, occurrences,
          success_rate, avg_confidence, first_seen, last_seen, metadata
        ) VALUES (?, ?, ?, 1, ?, ?, datetime('now'), datetime('now'), ?)
      `).run(
        pattern.type,
        pattern.category || null,
        pattern.provider || null,
        pattern.successRate || null,
        pattern.avgConfidence || null,
        JSON.stringify(pattern.metadata || {})
      );
    }
  }

  /**
   * Get historical data for Level 6 analysis
   */
  getHistoricalData(lookbackDays = 90) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - lookbackDays);
    const cutoffStr = cutoff.toISOString();

    return {
      runs: this.db.prepare(`
        SELECT * FROM analysis_runs
        WHERE started_at >= ?
        ORDER BY started_at DESC
      `).all(cutoffStr),

      findingsByCategory: this.db.prepare(`
        SELECT category, severity, COUNT(*) as count
        FROM findings f
        JOIN analysis_runs r ON f.run_id = r.id
        WHERE r.started_at >= ?
        GROUP BY category, severity
        ORDER BY count DESC
      `).all(cutoffStr),

      fixSuccessRate: this.db.prepare(`
        SELECT f.category,
               COUNT(*) as total,
               SUM(CASE WHEN f.success = 1 THEN 1 ELSE 0 END) as successful,
               AVG(f.confidence) as avg_confidence
        FROM fixes f
        JOIN analysis_runs r ON f.run_id = r.id
        WHERE r.started_at >= ?
        GROUP BY f.category
        ORDER BY successful DESC
      `).all(cutoffStr),

      providerStats: this.db.prepare(`
        SELECT p.provider,
               COUNT(*) as analyses,
               AVG(p.duration_ms) as avg_duration,
               SUM(p.cost_usd) as total_cost,
               AVG(p.confidence_avg) as avg_confidence,
               SUM(CASE WHEN p.success = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as success_rate
        FROM provider_performance p
        WHERE p.created_at >= ?
        GROUP BY p.provider
      `).all(cutoffStr),

      patterns: this.db.prepare(`
        SELECT * FROM team_knowledge
        WHERE last_seen >= ?
        ORDER BY occurrences DESC
      `).all(cutoffStr)
    };
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      totalRuns: this.db.prepare('SELECT COUNT(*) as count FROM analysis_runs').get().count,
      totalFindings: this.db.prepare('SELECT COUNT(*) as count FROM findings').get().count,
      totalFixes: this.db.prepare('SELECT COUNT(*) as count FROM fixes').get().count,
      fixSuccessRate: this.db.prepare(`
        SELECT
          SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as rate
        FROM fixes
      `).get().rate || 0,
      uniquePatterns: this.db.prepare('SELECT COUNT(*) as count FROM team_knowledge').get().count
    };
  }

  /**
   * Close database connection
   */
  close() {
    this.db.close();
  }
}

module.exports = CollectiveInsightDB;
