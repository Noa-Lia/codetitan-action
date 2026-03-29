'use strict';

const path = require('path');
const crypto = require('crypto');

/**
 * FeedbackLoop — production learning engine.
 *
 * Records fix outcomes, correlates production incidents to prior findings,
 * suggests new rules from recurring patterns, and adjusts ML confidence weights.
 *
 * Storage: Supabase when credentials are present; SQLite local fallback otherwise.
 */
class FeedbackLoop {
  constructor(config = {}) {
    this.config = {
      projectRoot: config.projectRoot || process.cwd(),
      supabaseUrl: config.supabaseUrl || process.env.SUPABASE_URL,
      supabaseKey: config.supabaseKey || process.env.SUPABASE_SERVICE_KEY,
      dbPath: config.dbPath || path.join(config.projectRoot || process.cwd(), '.codetitan', 'feedback.db'),
      incidentWindowMs: config.incidentWindowMs || 7 * 24 * 60 * 60 * 1000, // 7 days
      ruleThreshold: config.ruleThreshold || 3,   // incidents before suggesting a rule
      ...config
    };

    this._db = null;         // SQLite instance (lazy)
    this._supabase = null;   // Supabase client (lazy)
    this._ready = null;      // Promise<void> — resolved when storage is ready

    // Allow injecting a test store to bypass SQLite/Supabase entirely
    if (config._store) {
      this._store = config._store;
      this._ready = Promise.resolve();
    } else {
      this._store = null;
    }
  }

  // ─── Storage init ──────────────────────────────────────────────────────────

  async _ensureReady() {
    if (this._ready) return this._ready;
    this._ready = this._initStorage();
    return this._ready;
  }

  async _initStorage() {
    // Try Supabase first
    if (this.config.supabaseUrl && this.config.supabaseKey) {
      try {
        const { createClient } = require('@supabase/supabase-js');
        this._supabase = createClient(this.config.supabaseUrl, this.config.supabaseKey);
        // Quick connectivity test
        await this._supabase.from('production_incidents').select('id').limit(1);
        return; // Supabase works
      } catch {
        this._supabase = null;
      }
    }

    // Fallback: SQLite
    await this._initSQLite();
  }

  async _initSQLite() {
    const fs = require('fs').promises;
    await fs.mkdir(path.dirname(this.config.dbPath), { recursive: true });

    const { Database } = await this._openSQLite(this.config.dbPath);
    this._db = Database;

    // Create tables (exec returns a Promise here)
    await this._db.exec(`
      CREATE TABLE IF NOT EXISTS fix_outcomes (
        id TEXT PRIMARY KEY,
        fix_id TEXT NOT NULL,
        finding_id TEXT,
        category TEXT,
        success INTEGER NOT NULL,
        confidence_score REAL,
        incident_id TEXT,
        error_message TEXT,
        project_root TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS production_incidents (
        id TEXT PRIMARY KEY,
        file_path TEXT,
        line_number INTEGER,
        error_message TEXT,
        stack_trace TEXT,
        severity TEXT DEFAULT 'HIGH',
        source TEXT DEFAULT 'manual',
        correlated_finding_id TEXT,
        project_root TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS generated_rules (
        id TEXT PRIMARY KEY,
        rule_id TEXT UNIQUE NOT NULL,
        pattern TEXT NOT NULL,
        description TEXT,
        severity TEXT DEFAULT 'HIGH',
        incident_count INTEGER DEFAULT 0,
        confidence REAL DEFAULT 0,
        approved INTEGER DEFAULT 0,
        project_root TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_incidents_file ON production_incidents(file_path);
      CREATE INDEX IF NOT EXISTS idx_incidents_created ON production_incidents(created_at);
      CREATE INDEX IF NOT EXISTS idx_outcomes_fix ON fix_outcomes(fix_id);
    `);
  }

  async _openSQLite(dbPath) {
    return new Promise((resolve, reject) => {
      try {
        const sqlite3 = require('sqlite3').verbose();
        const db = new sqlite3.Database(dbPath, (err) => {
          if (err) return reject(err);

          const Database = {
            exec: (sql) => new Promise((res, rej) => db.exec(sql, e => e ? rej(e) : res())),
            run: (sql, params = []) => new Promise((res, rej) => db.run(sql, params, e => e ? rej(e) : res())),
            all: (sql, params = []) => new Promise((res, rej) => db.all(sql, params, (e, rows) => e ? rej(e) : res(rows || []))),
            get: (sql, params = []) => new Promise((res, rej) => db.get(sql, params, (e, row) => e ? rej(e) : res(row))),
          };

          resolve({ Database });
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * Record the outcome of an applied fix.
   * @param {string} fixId
   * @param {{ success: boolean, incidentId?: string, errorMessage?: string, category?: string, confidenceScore?: number }} outcome
   */
  async recordOutcome(fixId, outcome) {
    await this._ensureReady();

    const id = crypto.randomUUID();
    const row = {
      id,
      fix_id: fixId,
      finding_id: outcome.findingId || null,
      category: outcome.category || null,
      success: outcome.success ? 1 : 0,
      confidence_score: outcome.confidenceScore || null,
      incident_id: outcome.incidentId || null,
      error_message: outcome.errorMessage || null,
      project_root: this.config.projectRoot,
      created_at: new Date().toISOString()
    };

    if (this._store) {
      this._store.outcomes.push({ ...row, success: outcome.success ? 1 : 0 });
      return { id, recorded: true };
    }
    if (this._supabase) {
      await this._supabase.from('fix_outcomes').insert({ ...row, success: outcome.success });
    } else if (this._db) {
      await this._db.run(
        `INSERT INTO fix_outcomes (id,fix_id,finding_id,category,success,confidence_score,incident_id,error_message,project_root,created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?)`,
        [row.id, row.fix_id, row.finding_id, row.category, row.success,
         row.confidence_score, row.incident_id, row.error_message, row.project_root, row.created_at]
      );
    }

    // Feed back into ML scorer if category info is available
    if (outcome.category !== undefined) {
      try {
        const MLConfidenceScorer = require('./ml-confidence-scorer');
        const scorer = new MLConfidenceScorer({ supabaseUrl: this.config.supabaseUrl, supabaseKey: this.config.supabaseKey });
        await scorer.recordFeedback(
          fixId,
          { category: outcome.category, ruleId: outcome.findingId },
          outcome.success,
          { projectId: this.config.projectRoot }
        );
      } catch { /* scorer may not be available */ }
    }

    return { id, recorded: true };
  }

  /**
   * Correlate a production incident to known findings.
   * @param {{ file: string, line?: number, error: string, stackTrace?: string, severity?: string, source?: string }} incident
   * @returns {Promise<{ correlatedFindings: Object[], newRuleCandidate: Object|null, incidentId: string }>}
   */
  async correlateIncident(incident) {
    await this._ensureReady();

    const incidentId = crypto.randomUUID();
    const normalized = this._normalizeIncident(incident, incidentId);

    // Store the incident
    await this._storeIncident(normalized);

    // Find findings that match the same file/area
    const correlatedFindings = await this._findCorrelatedFindings(normalized);

    // Check if this error pattern has been seen enough times to warrant a rule
    const newRuleCandidate = await this._checkForRuleCandidate(normalized);

    return { correlatedFindings, newRuleCandidate, incidentId };
  }

  /**
   * Suggest a new rule based on an incident.
   * @param {{ file: string, error: string, stackTrace?: string, severity?: string }} incident
   * @returns {Promise<Object|null>} Rule suggestion or null if not enough pattern confidence
   */
  async suggestNewRule(incident) {
    await this._ensureReady();

    const pattern = this._extractPattern(incident);
    const ruleId = 'AUTO-' + crypto.createHash('sha256')
      .update(JSON.stringify(pattern)).digest('hex').slice(0, 8).toUpperCase();

    const count = await this._countSimilarIncidents(pattern);
    if (count < this.config.ruleThreshold) return null;

    const confidence = Math.min(0.5 + (count - this.config.ruleThreshold) * 0.1, 0.95);

    const rule = {
      ruleId,
      pattern,
      description: `Auto-detected: ${pattern.errorType} in ${pattern.filePattern}`,
      severity: incident.severity || 'HIGH',
      incidentCount: count,
      confidence,
      autoGenerated: true,
      lastSeen: new Date().toISOString()
    };

    // Persist proposal
    await this._persistRuleProposal(rule);

    return rule;
  }

  /**
   * Get insights for a project over a time range.
   * @param {string|null} projectId
   * @param {string} timeRange - e.g. '7d', '30d'
   * @returns {Promise<Object>}
   */
  async getInsights(projectId, timeRange = '7d') {
    await this._ensureReady();

    const sinceMs = this._parseTimeRange(timeRange);
    const since = new Date(Date.now() - sinceMs).toISOString();

    const [outcomes, incidents, rules] = await Promise.all([
      this._getOutcomes(since),
      this._getIncidents(since),
      this._getProposedRules()
    ]);

    const total = outcomes.length;
    const successful = outcomes.filter(o => o.success === 1 || o.success === true).length;
    const fixSuccessRate = total > 0 ? successful / total : null;

    // Top failing categories
    const catCounts = {};
    for (const o of outcomes) {
      if (!(o.success === 1 || o.success === true) && o.category) {
        catCounts[o.category] = (catCounts[o.category] || 0) + 1;
      }
    }
    const topFailingCategories = Object.entries(catCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([category, count]) => ({ category, count }));

    return {
      fixSuccessRate,
      totalFixes: total,
      successfulFixes: successful,
      topFailingCategories,
      rulesFromIncidents: rules,
      incidentCount: incidents.length,
      recommendedPriorities: topFailingCategories.map(c => c.category),
      timeRange
    };
  }

  /**
   * Adjust ML confidence weights based on production incident correlations.
   * @param {Array<{ category: string }>} incidentCorrelations
   */
  async updateConfidenceFromProduction(incidentCorrelations) {
    try {
      const MLConfidenceScorer = require('./ml-confidence-scorer');
      const scorer = new MLConfidenceScorer({
        supabaseUrl: this.config.supabaseUrl,
        supabaseKey: this.config.supabaseKey
      });
      await scorer.incorporateProductionData(incidentCorrelations);
    } catch { /* scorer may not be available */ }
  }

  // ─── Internal helpers ──────────────────────────────────────────────────────

  _normalizeIncident(incident, id) {
    return {
      id,
      file_path: incident.file || incident.filePath || null,
      line_number: incident.line || incident.lineNumber || null,
      error_message: incident.error || incident.message || '',
      stack_trace: incident.stackTrace || incident.stack || null,
      severity: (incident.severity || 'HIGH').toUpperCase(),
      source: incident.source || 'manual',
      correlated_finding_id: null,
      project_root: this.config.projectRoot,
      created_at: new Date().toISOString()
    };
  }

  async _storeIncident(normalized) {
    if (this._store) {
      this._store.incidents.push(normalized);
      return;
    }
    if (this._supabase) {
      await this._supabase.from('production_incidents').insert(normalized);
    } else if (this._db) {
      await this._db.run(
        `INSERT INTO production_incidents
         (id,file_path,line_number,error_message,stack_trace,severity,source,correlated_finding_id,project_root,created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?)`,
        [normalized.id, normalized.file_path, normalized.line_number,
         normalized.error_message, normalized.stack_trace, normalized.severity,
         normalized.source, normalized.correlated_finding_id,
         normalized.project_root, normalized.created_at]
      );
    }
  }

  async _findCorrelatedFindings(incident) {
    // Search local project's recent analysis cache (.codetitan-cache)
    const findings = [];
    if (!incident.file_path) return findings;

    try {
      const cacheDir = require('path').join(this.config.projectRoot, '.codetitan-cache');
      const fs = require('fs').promises;
      const files = await fs.readdir(cacheDir).catch(() => []);
      for (const f of files) {
        if (!f.endsWith('.json')) continue;
        try {
          const data = JSON.parse(await fs.readFile(require('path').join(cacheDir, f), 'utf-8'));
          const issues = data.issues || data.findings || [];
          for (const issue of issues) {
            if (issue.file_path === incident.file_path) {
              const lineDiff = Math.abs((issue.line_number || 0) - (incident.line_number || 0));
              if (lineDiff <= 10) {
                findings.push({ ...issue, correlationScore: 1 - lineDiff / 10 });
              }
            }
          }
        } catch { /* skip malformed cache */ }
      }
    } catch { /* cache not available */ }

    return findings.slice(0, 10);
  }

  async _checkForRuleCandidate(incident) {
    const pattern = this._extractPattern(incident);
    const count = await this._countSimilarIncidents(pattern);
    if (count >= this.config.ruleThreshold) {
      return this.suggestNewRule(incident);
    }
    return null;
  }

  _extractPattern(incident) {
    const errorMsg = incident.error_message || incident.error || '';
    // Extract error type (first word of error class)
    const errorTypeMatch = errorMsg.match(/^([A-Za-z]+Error|[A-Za-z]+Exception|[A-Za-z]+Fault)/);
    const errorType = errorTypeMatch ? errorTypeMatch[1] : 'UnknownError';

    // Extract file pattern (strip specific line numbers / hashes)
    const filePath = incident.file_path || '';
    const filePattern = filePath.replace(/\/[a-f0-9]{8,}/g, '/<hash>').split('/').slice(-2).join('/');

    return { errorType, filePattern, severity: incident.severity || 'HIGH' };
  }

  async _countSimilarIncidents(pattern) {
    const since = new Date(Date.now() - this.config.incidentWindowMs).toISOString();

    if (this._store) {
      return this._store.incidents.filter(i =>
        (i.error_message || '').includes(pattern.errorType) && i.created_at >= since
      ).length;
    }

    if (this._supabase) {
      const { count } = await this._supabase
        .from('production_incidents')
        .select('id', { count: 'exact', head: true })
        .ilike('error_message', `%${pattern.errorType}%`)
        .gte('created_at', since);
      return count || 0;
    }

    if (this._db) {
      const row = await this._db.get(
        `SELECT COUNT(*) as n FROM production_incidents WHERE error_message LIKE ? AND created_at >= ?`,
        [`%${pattern.errorType}%`, since]
      );
      return row?.n || 0;
    }

    return 0;
  }

  async _persistRuleProposal(rule) {
    if (this._store) {
      const existing = this._store.rules.findIndex(r => r.rule_id === rule.ruleId);
      const row = { rule_id: rule.ruleId, pattern: rule.pattern, description: rule.description,
                    severity: rule.severity, incident_count: rule.incidentCount,
                    confidence: rule.confidence, approved: false };
      if (existing >= 0) this._store.rules[existing] = row;
      else this._store.rules.push(row);
      return;
    }
    if (this._supabase) {
      await this._supabase.from('generated_rules').upsert({
        id: crypto.randomUUID(),
        rule_id: rule.ruleId,
        pattern: rule.pattern,
        description: rule.description,
        severity: rule.severity,
        incident_count: rule.incidentCount,
        confidence: rule.confidence,
        approved: false,
        project_root: this.config.projectRoot,
        created_at: new Date().toISOString()
      }, { onConflict: 'rule_id' });
    } else if (this._db) {
      await this._db.run(
        `INSERT OR REPLACE INTO generated_rules
         (id,rule_id,pattern,description,severity,incident_count,confidence,approved,project_root,created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?)`,
        [crypto.randomUUID(), rule.ruleId,
         JSON.stringify(rule.pattern), rule.description, rule.severity,
         rule.incidentCount, rule.confidence, 0, this.config.projectRoot,
         new Date().toISOString()]
      );
    }
  }

  async _getOutcomes(since) {
    if (this._store) {
      return this._store.outcomes.filter(o => o.created_at >= since);
    }
    if (this._supabase) {
      const { data } = await this._supabase
        .from('fix_outcomes').select('*').gte('created_at', since);
      return data || [];
    }
    if (this._db) {
      return this._db.all(`SELECT * FROM fix_outcomes WHERE created_at >= ?`, [since]);
    }
    return [];
  }

  async _getIncidents(since) {
    if (this._store) {
      return this._store.incidents.filter(i => i.created_at >= since);
    }
    if (this._supabase) {
      const { data } = await this._supabase
        .from('production_incidents').select('*').gte('created_at', since);
      return data || [];
    }
    if (this._db) {
      return this._db.all(`SELECT * FROM production_incidents WHERE created_at >= ?`, [since]);
    }
    return [];
  }

  async _getProposedRules() {
    if (this._store) {
      return this._store.rules.filter(r => !r.approved);
    }
    if (this._supabase) {
      const { data } = await this._supabase
        .from('generated_rules').select('*').eq('approved', false);
      return data || [];
    }
    if (this._db) {
      return this._db.all(`SELECT * FROM generated_rules WHERE approved = 0`);
    }
    return [];
  }

  _parseTimeRange(range) {
    const match = String(range).match(/^(\d+)([dhm])$/);
    if (!match) return 7 * 24 * 60 * 60 * 1000;
    const [, n, unit] = match;
    const ms = { d: 86400000, h: 3600000, m: 60000 };
    return parseInt(n) * (ms[unit] || 86400000);
  }
}

module.exports = FeedbackLoop;
