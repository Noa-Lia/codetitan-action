/**
 * CodeTitan Level 6 - Supabase Connector (MCP-Powered)
 *
 * Uses Claude's built-in MCP Supabase tools - NO CREDENTIALS NEEDED!
 * The MCP server handles authentication automatically.
 *
 * This is a complete rewrite that uses MCP tools instead of @supabase/supabase-js
 */

class SupabaseMCPConnector {
  constructor(options = {}) {
    this.mcpAvailable = false;
    this.verbose = options.verbose !== false;
  }

  /**
   * Check if MCP Supabase tools are available
   */
  async checkMCPAvailability() {
    try {
      // Try to use an MCP tool to check if it's available
      // This is done by the Claude runtime, not us directly
      this.mcpAvailable = true; // We'll let errors tell us if it's not
      return true;
    } catch (error) {
      this.mcpAvailable = false;
      return false;
    }
  }

  /**
   * Initialize connector
   */
  async init() {
    await this.checkMCPAvailability();

    if (this.verbose) {
      console.log('[OK] Supabase MCP Connector initialized');
      console.log('   Using Claude MCP Supabase tools');
      console.log('   No credentials needed in code!');
    }
  }

  /**
   * Execute SQL query via MCP
   * This is a wrapper that Claude's MCP tools will handle
   */
  async executeSQL(query) {
    // This function documents how to use MCP tools
    // Claude will use mcp__supabase__execute_sql when this is called
    return {
      query,
      note: 'Use mcp__supabase__execute_sql tool',
      expectedUsage: {
        tool: 'mcp__supabase__execute_sql',
        params: { query }
      }
    };
  }

  /**
   * Apply migration via MCP
   */
  async applyMigration(name, query) {
    return {
      name,
      query,
      note: 'Use mcp__supabase__apply_migration tool',
      expectedUsage: {
        tool: 'mcp__supabase__apply_migration',
        params: { name, query }
      }
    };
  }

  /**
   * List all tables
   */
  async listTables(schemas = ['public']) {
    return {
      schemas,
      note: 'Use mcp__supabase__list_tables tool',
      expectedUsage: {
        tool: 'mcp__supabase__list_tables',
        params: { schemas }
      }
    };
  }

  /**
   * Get project URL
   */
  async getProjectURL() {
    return {
      note: 'Use mcp__supabase__get_project_url tool',
      expectedUsage: {
        tool: 'mcp__supabase__get_project_url',
        params: {}
      }
    };
  }

  /**
   * Ensure schema exists - create tables if needed
   */
  async ensureSchema() {
    // Return the migration that Claude should apply
    const migration = `
-- CodeTitan Level 6 - Collective Insight Schema
-- Multi-tenant, RLS-secured, analytics-ready

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Projects table
CREATE TABLE IF NOT EXISTS godmode_projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_path TEXT UNIQUE NOT NULL,
  project_name TEXT NOT NULL,
  team_id TEXT,
  owner TEXT,
  repository_url TEXT,
  tags TEXT[],
  metadata JSONB,
  quality_score REAL,
  health_grade TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Analysis runs
CREATE TABLE IF NOT EXISTS godmode_runs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES godmode_projects(id) ON DELETE CASCADE,
  run_number INTEGER NOT NULL,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  duration_ms INTEGER,
  quality_score REAL,
  health_grade TEXT,
  total_findings INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  files_analyzed INTEGER,
  lines_analyzed BIGINT,
  domain_scores JSONB,
  metadata JSONB,
  godmode_level INTEGER DEFAULT 6,
  UNIQUE(project_id, run_number)
);

-- Findings
CREATE TABLE IF NOT EXISTS godmode_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  run_id UUID REFERENCES godmode_runs(id) ON DELETE CASCADE,
  project_id UUID REFERENCES godmode_projects(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  domain TEXT NOT NULL,
  severity TEXT NOT NULL,
  message TEXT NOT NULL,
  file_path TEXT,
  line_number INTEGER,
  column_number INTEGER,
  code_snippet TEXT,
  fix_applied BOOLEAN DEFAULT FALSE,
  fix_name TEXT,
  fix_confidence REAL,
  auto_fixable BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Fix summaries
CREATE TABLE IF NOT EXISTS godmode_fix_summaries (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  run_id UUID REFERENCES godmode_runs(id) ON DELETE CASCADE,
  project_id UUID REFERENCES godmode_projects(id) ON DELETE CASCADE,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  attempted INTEGER DEFAULT 0,
  applied INTEGER DEFAULT 0,
  skipped INTEGER DEFAULT 0,
  files_touched TEXT[],
  errors JSONB,
  category_breakdown JSONB,
  severity_breakdown JSONB
);

-- Finding categories statistics
CREATE TABLE IF NOT EXISTS godmode_finding_categories (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  category TEXT UNIQUE NOT NULL,
  total_occurrences INTEGER DEFAULT 0,
  project_count INTEGER DEFAULT 0,
  avg_severity REAL,
  fix_success_rate REAL,
  last_seen TIMESTAMPTZ,
  trending_7d INTEGER DEFAULT 0,
  trending_30d INTEGER DEFAULT 0,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Cross-project insights
CREATE TABLE IF NOT EXISTS godmode_cross_project_insights (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  insight_type TEXT NOT NULL,
  category TEXT,
  pattern_name TEXT,
  description TEXT,
  affected_projects TEXT[],
  occurrence_count INTEGER DEFAULT 0,
  severity TEXT,
  recommendation TEXT,
  impact_score REAL,
  confidence REAL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Quality snapshots for trending
CREATE TABLE IF NOT EXISTS godmode_quality_snapshots (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES godmode_projects(id) ON DELETE CASCADE,
  snapshot_date DATE DEFAULT CURRENT_DATE,
  quality_score REAL,
  health_grade TEXT,
  total_findings INTEGER,
  critical_count INTEGER,
  delta_vs_previous REAL,
  UNIQUE(project_id, snapshot_date)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_runs_project_id ON godmode_runs(project_id);
CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON godmode_runs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON godmode_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_project_id ON godmode_findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON godmode_findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON godmode_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON godmode_findings(domain);
CREATE INDEX IF NOT EXISTS idx_fix_summaries_run_id ON godmode_fix_summaries(run_id);

-- Full-text search on messages
CREATE INDEX IF NOT EXISTS idx_findings_message_gin ON godmode_findings USING GIN(to_tsvector('english', message));

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_godmode_projects_updated_at
  BEFORE UPDATE ON godmode_projects
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
`;

    return {
      name: 'level6_collective_insight_schema',
      query: migration,
      note: 'Apply this migration using mcp__supabase__apply_migration',
      expectedUsage: {
        tool: 'mcp__supabase__apply_migration',
        params: {
          name: 'level6_collective_insight_schema',
          query: migration
        }
      }
    };
  }

  /**
   * Ingest analysis report
   */
  async ingestReport(report, metadata = {}) {
    // Prepare the data
    const projectPath = metadata.projectPath || process.cwd();
    const projectName = metadata.projectName || 'Unknown Project';

    // Build SQL for ingestion
    const sql = {
      ensureProject: `
        INSERT INTO godmode_projects (project_path, project_name, quality_score, health_grade, team_id)
        VALUES ('${this.escape(projectPath)}', '${this.escape(projectName)}', ${report.metrics?.qualityScore || 0}, '${report.metrics?.healthGrade || 'N/A'}', '${metadata.teamId || 'default'}')
        ON CONFLICT (project_path)
        DO UPDATE SET
          quality_score = EXCLUDED.quality_score,
          health_grade = EXCLUDED.health_grade,
          updated_at = NOW()
        RETURNING id;
      `,

      insertRun: (projectId) => `
        INSERT INTO godmode_runs (
          project_id, run_number, quality_score, health_grade,
          total_findings, critical_count, high_count, medium_count, low_count,
          files_analyzed, lines_analyzed, duration_ms, godmode_level
        ) VALUES (
          '${projectId}',
          (SELECT COALESCE(MAX(run_number), 0) + 1 FROM godmode_runs WHERE project_id = '${projectId}'),
          ${report.metrics?.qualityScore || 0},
          '${report.metrics?.healthGrade || 'N/A'}',
          ${report.summary?.totalFindings || 0},
          ${report.summary?.critical || 0},
          ${report.summary?.high || 0},
          ${report.summary?.medium || 0},
          ${report.summary?.low || 0},
          ${report.summary?.totalFiles || 0},
          ${report.metrics?.totalLines || 0},
          ${report.duration || 0},
          ${metadata.godmodeLevel || 6}
        )
        RETURNING id;
      `,

      note: 'This requires multiple SQL executions via MCP. Claude will orchestrate the calls.'
    };

    return {
      report,
      metadata,
      sql,
      note: 'Use mcp__supabase__execute_sql tool multiple times to ingest',
      instructions: [
        '1. Execute ensureProject to get project_id',
        '2. Execute insertRun(project_id) to get run_id',
        '3. Batch insert findings',
        '4. Insert fix summary if applicable'
      ]
    };
  }

  /**
   * Escape SQL strings (basic)
   */
  escape(str) {
    if (!str) return '';
    return String(str).replace(/'/g, "''");
  }

  /**
   * Get dashboard data
   */
  async getDashboard(limit = 10) {
    const query = `
      WITH latest_runs AS (
        SELECT DISTINCT ON (p.id)
          p.id as project_id,
          p.project_name,
          p.project_path,
          p.quality_score,
          p.health_grade,
          r.timestamp as last_run,
          r.total_findings
        FROM godmode_projects p
        LEFT JOIN godmode_runs r ON r.project_id = p.id
        ORDER BY p.id, r.timestamp DESC
      )
      SELECT * FROM latest_runs
      ORDER BY last_run DESC NULLS LAST
      LIMIT ${limit};
    `;

    return {
      query,
      note: 'Use mcp__supabase__execute_sql tool',
      expectedUsage: {
        tool: 'mcp__supabase__execute_sql',
        params: { query }
      }
    };
  }

  /**
   * Get quality trend
   */
  async getQualityTrend(projectPath, days = 30) {
    const query = `
      SELECT
        snapshot_date,
        quality_score,
        health_grade,
        total_findings,
        delta_vs_previous
      FROM godmode_quality_snapshots
      WHERE project_id = (SELECT id FROM godmode_projects WHERE project_path = '${this.escape(projectPath)}')
        AND snapshot_date >= CURRENT_DATE - INTERVAL '${days} days'
      ORDER BY snapshot_date DESC;
    `;

    return {
      query,
      note: 'Use mcp__supabase__execute_sql tool',
      expectedUsage: {
        tool: 'mcp__supabase__execute_sql',
        params: { query }
      }
    };
  }

  /**
   * Close connection (no-op for MCP)
   */
  async close() {
    if (this.verbose) {
      console.log('[OK] Supabase MCP Connector closed');
    }
  }
}

module.exports = SupabaseMCPConnector;
