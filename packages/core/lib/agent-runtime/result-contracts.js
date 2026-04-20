function truncateText(value, maxLength = 180) {
  if (typeof value !== 'string') {
    return '';
  }

  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength - 3)}...`;
}

function createEvidenceItem({
  kind = 'observation',
  source = 'runtime',
  summary = '',
  data = null
} = {}) {
  return {
    kind,
    source,
    summary: truncateText(summary, 240),
    data
  };
}

function summarizeToolOutput(toolName, data, error) {
  if (error) {
    return truncateText(error, 180);
  }

  if (!data || typeof data !== 'object') {
    return `${toolName} completed`;
  }

  switch (toolName) {
    case 'read_file':
      return `Read ${data.filePath} (${data.lines || 0} lines)`;
    case 'list_files':
      return `Listed ${(data.entries || []).length} entries under ${data.basePath}`;
    case 'analyze_path':
      return `Analyzed ${data.filePath} (${data.lines || 0} lines, ${(data.complexity && data.complexity.level) || 'unknown'} complexity)`;
    case 'search_code':
      return `Found ${(data.matches || []).length} match(es) for "${data.query}" under ${data.basePath}`;
    case 'run_tests':
      return `Ran ${[data.command, ...(data.args || [])].filter(Boolean).join(' ')} (${data.passed ? 'passed' : 'failed'})`;
    case 'git_status':
      return `Git status on ${data.branch || 'working tree'} (${(data.files || []).length} changed file(s))`;
    case 'git_diff':
      return `Git diff captured ${data.filesChanged || 0} file(s) (+${data.additions || 0}/-${data.deletions || 0})`;
    case 'fetch_history':
      if (data.run) {
        return `Loaded history run ${data.run.runId} with ${data.run.total || 0} finding(s)`;
      }
      return `Loaded ${(data.runs || []).length} history run(s) for ${data.projectPath}`;
    case 'compare_runs':
      return `Compared ${data.baseline?.runId || 'runA'} to ${data.current?.runId || 'runB'} (+${(data.added || []).length}/-${(data.fixed || []).length})`;
    case 'create_worktree':
      return `Created ${data.mode || 'isolated'} workspace at ${data.path}`;
    case 'edit_file':
      return `Edited ${data.filePath} by replacing an explicit source string`;
    case 'promote_worktree':
      return `Promoted ${(data.files || []).length} file(s) from ${data.workspacePath} into the repository`;
    case 'browse_web':
      return `Browsed ${data.url} using ${data.action || 'read'} (${data.itemCount || 0} item(s))`;
    case 'post_github_review':
      return `Posted GitHub review to ${data.owner}/${data.repo}#${data.prNumber} (${data.commentCount || 0} comment(s))`;
    case 'submit_fix_candidate':
      return `Recorded ${(data.candidates || []).length} fix candidate(s)`;
    default:
      return `${toolName} completed`;
  }
}

function createToolResult({
  tool,
  success,
  input = {},
  data = null,
  error = null,
  evidence = [],
  metadata = {},
  startedAt,
  finishedAt
}) {
  const start = typeof startedAt === 'number' ? startedAt : Date.now();
  const end = typeof finishedAt === 'number' ? finishedAt : Date.now();

  return {
    tool,
    success,
    input,
    data,
    error,
    evidence,
    metadata,
    usage: metadata.usage || {},
    durationMs: Math.max(0, end - start),
    outputSummary: metadata.outputSummary || summarizeToolOutput(tool, data, error)
  };
}

function summarizeEvidence(evidence = []) {
  const summaries = evidence
    .map(item => item && item.summary)
    .filter(Boolean);

  if (summaries.length === 0) {
    return 'No evidence recorded.';
  }

  if (summaries.length === 1) {
    return summaries[0];
  }

  const preview = summaries.slice(0, 2).join(' ');
  const remainder = summaries.length - 2;

  if (remainder <= 0) {
    return preview;
  }

  return `${preview} +${remainder} more evidence item(s).`;
}

function createTaskResult({
  success,
  type,
  status = 'completed',
  summary = '',
  message = '',
  quality = 0,
  evidence = [],
  toolTrace = [],
  artifacts = [],
  runtime = {},
  data = {},
  error = null
}) {
  const taskMessage = message || summary || error || `${type} completed`;

  return {
    success,
    type,
    status,
    summary,
    message: taskMessage,
    quality,
    evidence,
    evidenceSummary: summarizeEvidence(evidence),
    toolTrace,
    artifacts,
    runtime,
    data,
    error
  };
}

function materializeLegacyResult(taskResult) {
  const base = {
    type: taskResult.type,
    status: taskResult.status,
    success: taskResult.success,
    message: taskResult.message,
    summary: taskResult.summary,
    quality: taskResult.quality,
    evidence: taskResult.evidence,
    evidenceSummary: taskResult.evidenceSummary,
    toolTrace: taskResult.toolTrace,
    artifacts: taskResult.artifacts,
    runtime_state: taskResult.runtime,
    real_execution: true,
    runtime_execution: true
  };

  if (taskResult.data && typeof taskResult.data === 'object') {
    Object.assign(base, taskResult.data);
  }

  if (taskResult.error) {
    base.error = taskResult.error;
  }

  return base;
}

module.exports = {
  createEvidenceItem,
  createToolResult,
  createTaskResult,
  materializeLegacyResult,
  summarizeEvidence,
  truncateText
};
