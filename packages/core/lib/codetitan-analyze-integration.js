/**
 * CodeTitan Level 6 - Analyze Command Integration Example
 *
 * This module shows how to integrate InsightSync into the analyze command.
 * Replace CollectiveInsight usage with InsightSync for dual-write support.
 *
 * BEFORE (lib/codetitan-orchestration.js or similar):
 * ```javascript
 * const CollectiveInsight = require('./collective-insight');
 * const insight = new CollectiveInsight(dbPath);
 * await insight.init();
 * await insight.ingestReport(report, metadata);
 * ```
 *
 * AFTER:
 * ```javascript
 * const InsightSync = require('./insight-sync');
 * const insight = new InsightSync({ sqlitePath: dbPath });
 * await insight.init();
 * await insight.ingestReport(report, metadata);
 * ```
 *
 * The API is backward compatible - existing code continues to work,
 * but gains dual-write capability when CODETITAN_SYNC_MODE is set.
 */

const InsightSync = require('./insight-sync');
const path = require('path');

/**
 * Create an insight store with automatic mode detection
 */
function createInsightStore(options = {}) {
  const sqlitePath = options.sqlitePath ||
    path.join(process.cwd(), 'data', 'collective-insight.db');

  return new InsightSync({ sqlitePath });
}

/**
 * Example: Ingest a CodeTitan analysis report
 */
async function ingestAnalysisReport(report, metadata = {}) {
  const insight = createInsightStore();

  try {
    await insight.init();

    // Ingest with dual-write support
    const result = await insight.ingestReport(report, metadata);

    // Log sync results
    if (result.mode === 'dual-write') {
      console.log('\n[CHART] Insight stored in both SQLite and Supabase');
      if (result.supabase?.error) {
        console.log(`   [WARNING]  Supabase write failed: ${result.supabase.error}`);
      } else {
        console.log(`   [OK] SQLite run ID: ${result.sqlite.runId}`);
        console.log(`   [OK] Supabase run ID: ${result.supabase.runId}`);
      }
    } else if (result.mode === 'supabase-only') {
      console.log('\n[CHART] Insight stored in Supabase');
      console.log(`   [OK] Run ID: ${result.supabase.runId}`);
    } else {
      console.log('\n[CHART] Insight stored in SQLite');
      console.log(`   [OK] Run ID: ${result.sqlite.runId}`);
    }

    return result;

  } finally {
    await insight.close();
  }
}

/**
 * Example: Get dashboard data
 */
async function getDashboard(limit = 5) {
  const insight = createInsightStore();

  try {
    await insight.init();
    const dashboard = await insight.getDashboard(limit);

    // Print dashboard
    console.log('\n+=======================================================+');
    console.log('|              CodeTitan Collective Insight              |');
    console.log('+=======================================================+\n');

    const data = dashboard.sqlite; // Use SQLite as source of truth

    console.log('[CHART] Summary');
    console.log(`   Total runs: ${data.summary.runCount}`);
    console.log(`   Findings logged: ${data.summary.findingsLogged}`);
    console.log(`   Avg quality: ${data.summary.avgQuality?.toFixed(1) || 'N/A'}`);
    console.log(`   Last run: ${data.summary.lastRun || 'Never'}`);

    console.log('\n🔝 Top Categories');
    data.topCategories.forEach((cat, i) => {
      console.log(`   ${i + 1}. ${cat.category}: ${cat.count} issues`);
    });

    console.log('\n[TRENDING] Quality Trend');
    if (data.qualityTrend.latest) {
      const delta = data.qualityTrend.delta;
      const arrow = delta > 0 ? '[TRENDING]' : delta < 0 ? '📉' : '➡️';
      console.log(`   Latest: ${data.qualityTrend.latest.quality}`);
      if (delta !== null) {
        console.log(`   Change: ${delta > 0 ? '+' : ''}${delta.toFixed(1)} ${arrow}`);
      }
    } else {
      console.log('   No data available');
    }

    // Show sync stats if in dual-write mode
    if (dashboard.mode === 'dual-write') {
      console.log('\n🔄 Sync Stats');
      console.log(`   SQLite writes: ${dashboard.syncStats.sqliteWrites}`);
      console.log(`   Supabase writes: ${dashboard.syncStats.supabaseWrites}`);
      console.log(`   Failovers: ${dashboard.syncStats.failovers}`);
    }

    return dashboard;

  } finally {
    await insight.close();
  }
}

/**
 * Example integration into god-mode-cli.cjs
 *
 * In the analyze command handler:
 */
async function analyzeCommandExample(targetPath, options) {
  // ... existing analysis logic ...

  // Generate report
  const report = {
    sessionId: 'some-session-id',
    duration: 5000,
    summary: {
      totalFiles: 100,
      totalFindings: 42
    },
    topIssues: [
      { category: 'COMMAND_EXEC', severity: 'HIGH', file: 'index.js', line: 15 },
      // ... more issues
    ],
    metrics: {
      qualityScore: 72.5,
      healthGrade: 'B'
    },
    fixSummary: options.applyFixes ? {
      attempted: 10,
      applied: 8,
      skipped: 2,
      filesTouched: ['file1.js', 'file2.js']
    } : null
  };

  // Ingest if --ingest flag is present
  if (options.ingest) {
    await ingestAnalysisReport(report, {
      projectPath: targetPath,
      applyFixes: options.applyFixes
    });
  }

  // ... rest of analyze command ...
}

/**
 * Migration command example
 */
async function migrateCommand() {
  console.log('🔄 Migrating SQLite data to Supabase...\n');

  const insight = createInsightStore();

  try {
    await insight.init();

    if (!insight.supabaseReady) {
      console.error('[ERROR] Supabase is not configured. Check environment variables.');
      process.exit(1);
    }

    // Run migration
    const stats = await insight.syncHistoricalData({
      dryRun: false,
      batchSize: 50,
      progressCallback: (progress) => {
        console.log(`   Progress: ${progress.current}/${progress.total} runs`);
      }
    });

    console.log('\n[OK] Migration complete!');
    console.log(`   Migrated ${stats.migratedRuns} runs`);
    console.log(`   Migrated ${stats.migratedFindings} findings`);

  } finally {
    await insight.close();
  }
}

/**
 * Validation command example
 */
async function validateCommand() {
  console.log('[SEARCH] Validating sync consistency...\n');

  const insight = createInsightStore();

  try {
    await insight.init();

    if (!insight.supabaseReady) {
      console.error('[ERROR] Supabase is not configured.');
      process.exit(1);
    }

    const validation = await insight.validateSync();

    if (validation.consistent) {
      console.log('[OK] Databases are in sync!');
    } else {
      console.log('[WARNING]  Databases are out of sync');
      console.log(`   SQLite: ${validation.sqliteCount} runs`);
      console.log(`   Supabase: ${validation.supabaseCount} runs`);
    }

  } finally {
    await insight.close();
  }
}

module.exports = {
  createInsightStore,
  ingestAnalysisReport,
  getDashboard,
  analyzeCommandExample,
  migrateCommand,
  validateCommand
};
