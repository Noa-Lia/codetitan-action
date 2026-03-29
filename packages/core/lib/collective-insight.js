const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

class CollectiveInsight {
  constructor(dbPath) {
    this.dbPath = dbPath;
    this.db = null;
  }

  async init() {
    await fs.promises.mkdir(path.dirname(this.dbPath), { recursive: true });
    await new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, err => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });

    await this.run(`
      CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        project_path TEXT NOT NULL,
        session_id TEXT,
        duration_ms INTEGER,
        files_analyzed INTEGER,
        total_findings INTEGER,
        quality_score REAL,
        health_grade TEXT
      )
    `);

    await this.run(`
      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        domain TEXT,
        category TEXT,
        severity TEXT,
        message TEXT,
        file TEXT,
        line INTEGER,
        UNIQUE(run_id, file, line, category),
        FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
      )
    `);

    await this.run(`
      CREATE TABLE IF NOT EXISTS fix_summaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        attempted INTEGER,
        applied INTEGER,
        skipped INTEGER,
        files_touched INTEGER,
        FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
      )
    `);

    // Pattern Learning Tables (Level 6 ML Enhancement)
    await this.run(`
      CREATE TABLE IF NOT EXISTS pattern_clusters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cluster_id TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        size INTEGER,
        dominant_category TEXT,
        dominant_severity TEXT,
        root_cause_type TEXT,
        root_cause_confidence REAL,
        root_cause_suggestion TEXT
      )
    `);

    await this.run(`
      CREATE TABLE IF NOT EXISTS fix_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT,
        success INTEGER NOT NULL,
        run_id INTEGER,
        file TEXT,
        FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE SET NULL
      )
    `);

    await this.run(`
      CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        predicted_category TEXT NOT NULL,
        probability REAL NOT NULL,
        confidence REAL,
        occurred INTEGER DEFAULT 0,
        FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
      )
    `);

    await this.run(`
      CREATE TABLE IF NOT EXISTS code_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_hash TEXT UNIQUE NOT NULL,
        category TEXT,
        frequency INTEGER DEFAULT 1,
        last_seen TEXT,
        tfidf_vector TEXT
      )
    `);
  }

  run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function (err) {
        if (err) {
          reject(err);
        } else {
          resolve({ lastID: this.lastID, changes: this.changes });
        }
      });
    });
  }

  all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });
  }

  async ingestReport(report, metadata = {}) {
    const timestamp = new Date().toISOString();
    const {
      projectPath,
      applyFixes = false
    } = metadata;

    const runInfo = report.summary || {};
    const metrics = report.metrics || {};

    await this.run('BEGIN TRANSACTION');
    try {
      const runInsert = await this.run(
        `INSERT INTO runs (timestamp, project_path, session_id, duration_ms, files_analyzed, total_findings, quality_score, health_grade)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          timestamp,
          projectPath || 'unknown',
          report.sessionId || null,
          report.duration || null,
          runInfo.totalFiles || null,
          runInfo.totalFindings || null,
          metrics.qualityScore ? Number(metrics.qualityScore) : null,
          metrics.healthGrade || null
        ]
      );

      const runId = runInsert.lastID;

      const findings = report.topIssues || [];
      for (const issue of findings) {
        await this.run(
          `INSERT OR IGNORE INTO findings (run_id, domain, category, severity, message, file, line)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            runId,
            issue.domainName || issue.domain || null,
            issue.category || null,
            issue.severity || null,
            issue.message || null,
            issue.file || null,
            issue.line || null
          ]
        );
      }

      if (applyFixes && report.fixSummary) {
        await this.run(
          `INSERT INTO fix_summaries (run_id, attempted, applied, skipped, files_touched)
           VALUES (?, ?, ?, ?, ?)`,
          [
            runId,
            report.fixSummary.attempted || 0,
            report.fixSummary.applied || 0,
            report.fixSummary.skipped || 0,
            (report.fixSummary.filesTouched || []).length
          ]
        );
      }

      await this.run('COMMIT');
      return { runId, timestamp, findings: findings.length, applyFixes };
    } catch (error) {
      await this.run('ROLLBACK');
      throw error;
    }
  }

  async getSummary() {
    const rows = await this.all(`
      SELECT
        COUNT(*) AS runCount,
        SUM(total_findings) AS findingsLogged,
        AVG(quality_score) AS avgQuality,
        MAX(timestamp) AS lastRun
      FROM runs
    `);

    return rows[0] || {
      runCount: 0,
      findingsLogged: 0,
      avgQuality: null,
      lastRun: null
    };
  }

  async getTopCategories(limit = 5) {
    const rows = await this.all(
      `SELECT category, COUNT(*) AS count
       FROM findings
       WHERE category IS NOT NULL
       GROUP BY category
       ORDER BY count DESC
       LIMIT ?`,
      [limit]
    );
    return rows;
  }

  async getQualityTrend() {
    const rows = await this.all(
      `SELECT quality_score AS quality, timestamp
       FROM runs
       WHERE quality_score IS NOT NULL
       ORDER BY timestamp DESC
       LIMIT 2`
    );

    if (rows.length === 0) {
      return { latest: null, previous: null, delta: null };
    }

    const latest = rows[0];
    const previous = rows[1] || null;
    let delta = null;
    if (latest && previous) {
      delta = Number(latest.quality) - Number(previous.quality);
    }

    return {
      latest,
      previous,
      delta
    };
  }

  async getDashboard(limit = 5) {
    const summary = await this.getSummary();
    const topCategories = await this.getTopCategories(limit);
    const qualityTrend = await this.getQualityTrend();
    return {
      summary,
      topCategories,
      qualityTrend
    };
  }

  async close() {
    if (!this.db) return;
    await new Promise((resolve, reject) => {
      this.db.close(err => (err ? reject(err) : resolve()));
    });
    this.db = null;
  }

  // ============================================================================
  // Pattern Learning Methods (Level 6 ML Enhancement)
  // ============================================================================

  /**
   * Record a fix attempt for learning
   */
  async recordFixAttempt(category, success, metadata = {}) {
    await this.run(
      `INSERT INTO fix_attempts (timestamp, category, severity, success, run_id, file)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        new Date().toISOString(),
        category,
        metadata.severity || null,
        success ? 1 : 0,
        metadata.runId || null,
        metadata.file || null
      ]
    );
  }

  /**
   * Get fix history for learning
   */
  async getFixHistory(categoryFilter = null) {
    let sql = `SELECT timestamp, category, severity, success, file FROM fix_attempts`;
    const params = [];

    if (categoryFilter) {
      sql += ` WHERE category = ?`;
      params.push(categoryFilter);
    }

    sql += ` ORDER BY timestamp DESC`;

    const rows = await this.all(sql, params);
    return rows.map(r => ({
      timestamp: r.timestamp,
      category: r.category,
      severity: r.severity,
      success: Boolean(r.success),
      file: r.file
    }));
  }

  /**
   * Store pattern cluster
   */
  async storePatternCluster(cluster) {
    await this.run(
      `INSERT OR REPLACE INTO pattern_clusters
       (cluster_id, created_at, size, dominant_category, dominant_severity,
        root_cause_type, root_cause_confidence, root_cause_suggestion)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        cluster.id,
        new Date().toISOString(),
        cluster.size,
        cluster.dominantCategory || null,
        cluster.dominantSeverity || null,
        cluster.rootCause?.type || null,
        cluster.rootCause?.confidence || null,
        cluster.rootCause?.suggestion || null
      ]
    );
  }

  /**
   * Get all pattern clusters
   */
  async getPatternClusters(limit = 10) {
    return await this.all(
      `SELECT * FROM pattern_clusters ORDER BY size DESC LIMIT ?`,
      [limit]
    );
  }

  /**
   * Store predictions for validation
   */
  async storePredictions(runId, predictions) {
    for (const pred of predictions) {
      await this.run(
        `INSERT INTO predictions (run_id, predicted_category, probability, confidence)
         VALUES (?, ?, ?, ?)`,
        [runId, pred.category, pred.probability, pred.confidence || 0.5]
      );
    }
  }

  /**
   * Validate predictions against actual findings
   */
  async validatePredictions(runId) {
    // Get predictions for this run
    const predictions = await this.all(
      `SELECT id, predicted_category FROM predictions WHERE run_id = ?`,
      [runId]
    );

    // Get actual findings
    const actualCategories = await this.all(
      `SELECT DISTINCT category FROM findings WHERE run_id = ?`,
      [runId]
    );

    const actualSet = new Set(actualCategories.map(r => r.category));

    // Mark predictions as occurred or not
    for (const pred of predictions) {
      const occurred = actualSet.has(pred.predicted_category);
      await this.run(
        `UPDATE predictions SET occurred = ? WHERE id = ?`,
        [occurred ? 1 : 0, pred.id]
      );
    }

    // Calculate accuracy
    const results = await this.all(
      `SELECT
        COUNT(*) as total,
        SUM(occurred) as hits
       FROM predictions
       WHERE run_id = ?`,
      [runId]
    );

    const accuracy = results[0].total > 0
      ? results[0].hits / results[0].total
      : 0;

    return {
      total: results[0].total,
      hits: results[0].hits,
      accuracy
    };
  }

  /**
   * Get historical runs with findings for pattern analysis
   */
  async getHistoricalRuns(limit = 20) {
    const runs = await this.all(
      `SELECT * FROM runs ORDER BY timestamp DESC LIMIT ?`,
      [limit]
    );

    // Enrich with findings
    for (const run of runs) {
      run.findings = await this.all(
        `SELECT * FROM findings WHERE run_id = ?`,
        [run.id]
      );
    }

    return runs;
  }

  /**
   * Get all findings for pattern detection
   */
  async getAllFindings(limit = 1000) {
    return await this.all(
      `SELECT f.*, r.timestamp, r.project_path
       FROM findings f
       JOIN runs r ON f.run_id = r.id
       ORDER BY r.timestamp DESC
       LIMIT ?`,
      [limit]
    );
  }

  /**
   * Get enhanced dashboard with ML insights
   */
  async getMLDashboard(limit = 5) {
    const basicDashboard = await this.getDashboard(limit);

    // Add pattern clusters
    const clusters = await this.getPatternClusters(limit);

    // Add fix success rates
    const fixStats = await this.all(`
      SELECT
        category,
        COUNT(*) as attempts,
        SUM(success) as successes,
        CAST(SUM(success) AS REAL) / COUNT(*) as success_rate
      FROM fix_attempts
      GROUP BY category
      HAVING COUNT(*) >= 2
      ORDER BY success_rate DESC
      LIMIT ?
    `, [limit]);

    // Add prediction accuracy
    const predictionStats = await this.all(`
      SELECT
        AVG(occurred) as avg_accuracy,
        COUNT(*) as total_predictions
      FROM predictions
    `);

    return {
      ...basicDashboard,
      ml: {
        clusters: clusters.map(c => ({
          id: c.cluster_id,
          size: c.size,
          category: c.dominant_category,
          severity: c.dominant_severity,
          rootCause: c.root_cause_suggestion
        })),
        fixSuccessRates: fixStats.map(f => ({
          category: f.category,
          attempts: f.attempts,
          successes: f.successes,
          successRate: f.success_rate
        })),
        predictionAccuracy: predictionStats[0]?.avg_accuracy || null,
        totalPredictions: predictionStats[0]?.total_predictions || 0
      }
    };
  }
}

module.exports = CollectiveInsight;
