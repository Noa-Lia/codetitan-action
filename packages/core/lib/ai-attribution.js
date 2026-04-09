'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const SUPPORTED_AI_TOOLS = [
  {
    id: 'github_copilot',
    name: 'GitHub Copilot',
    signals: [
      { label: 'copilot', regex: /\bcopilot\b/i, weight: 6 },
      { label: 'github-copilot', regex: /\bgithub[\s_-]*copilot\b/i, weight: 7 },
      { label: 'copilot-author', regex: /copilot/i, weight: 5, fields: ['authorName', 'authorEmail'] }
    ]
  },
  {
    id: 'cursor',
    name: 'Cursor',
    signals: [
      { label: 'cursor', regex: /\bcursor\b/i, weight: 6 },
      { label: 'cursor-agent', regex: /\bcursor\s+(agent|composer)\b/i, weight: 7 }
    ]
  },
  {
    id: 'claude_code',
    name: 'Claude Code',
    signals: [
      { label: 'claude-code', regex: /\bclaude\s+code\b/i, weight: 8 },
      { label: 'anthropic-claude', regex: /\banthropic\b.*\bclaude\b|\bclaude\b.*\banthropic\b/i, weight: 5 },
      { label: 'claude-cli', regex: /\bclaude\b/i, weight: 3 }
    ]
  },
  {
    id: 'aider',
    name: 'Aider',
    signals: [
      { label: 'aider', regex: /\baider\b/i, weight: 8 },
      { label: 'aider-coauthor', regex: /co-authored-by:.*\baider\b/i, weight: 8 }
    ]
  },
  {
    id: 'chatgpt',
    name: 'ChatGPT',
    signals: [
      { label: 'chatgpt', regex: /\bchatgpt\b/i, weight: 8 },
      { label: 'openai-gpt', regex: /\bopenai\b|\bgpt-4(\.\d+)?\b|\bgpt-4o\b|\bgpt-5(\.\d+)?\b/i, weight: 5 }
    ]
  },
  {
    id: 'cline',
    name: 'Cline',
    signals: [
      { label: 'cline', regex: /\bcline\b/i, weight: 8 }
    ]
  },
  {
    id: 'windsurf',
    name: 'Windsurf',
    signals: [
      { label: 'windsurf', regex: /\bwindsurf\b/i, weight: 8 },
      { label: 'codeium', regex: /\bcodeium\b/i, weight: 5 }
    ]
  }
];

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function toPercent(value, digits = 1) {
  return Number((value * 100).toFixed(digits));
}

function severityWeight(severity) {
  switch (String(severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 8;
    case 'HIGH':
      return 5;
    case 'MEDIUM':
      return 3;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}

function classifyQuality(score) {
  if (score >= 85) return 'strong';
  if (score >= 70) return 'watch';
  return 'risky';
}

function buildEmptyCommitAttribution(timeRange, reason = null) {
  return {
    available: false,
    reason,
    timeRange,
    scannedCommits: 0,
    attributedCommits: 0,
    unattributedCommits: 0,
    detectedToolsCount: 0,
    coverage: 0,
    supportedTools: SUPPORTED_AI_TOOLS.map(tool => ({ id: tool.id, name: tool.name })),
    tools: []
  };
}

function buildEmptyFindingAttribution(runId = null, totalFindings = 0, reason = null) {
  return {
    available: false,
    reason,
    runId,
    totalFindings,
    attributedFindings: 0,
    unattributedFindings: totalFindings,
    coverage: 0,
    tools: []
  };
}

class AIAttribution {
  constructor(options = {}) {
    this.projectRoot = path.resolve(options.projectRoot || process.cwd());
    this.execFileSync = options.execFileSync || execFileSync;
    this.repoRoot = options.repoRoot || null;
    this.commitCache = new Map();
    this.blameCache = new Map();
  }

  runGit(args, { allowFailure = false } = {}) {
    try {
      const output = this.execFileSync('git', ['-C', this.projectRoot, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe']
      });
      return String(output || '').replace(/\r\n/g, '\n');
    } catch (error) {
      if (allowFailure) {
        return '';
      }
      const stderr = error && typeof error.stderr === 'string' ? error.stderr.trim() : '';
      throw new Error(stderr || error.message || 'git command failed');
    }
  }

  resolveRepoRoot() {
    if (this.repoRoot) {
      return this.repoRoot;
    }

    const resolved = this.runGit(['rev-parse', '--show-toplevel'], { allowFailure: true }).trim();
    this.repoRoot = resolved || null;
    return this.repoRoot;
  }

  projectHash(projectPath) {
    const normalized = path.resolve(projectPath).toLowerCase().replace(/\\/g, '/');
    return crypto.createHash('sha1').update(normalized).digest('hex').slice(0, 12);
  }

  historyRoot() {
    return path.join(os.homedir(), '.codetitan', 'history');
  }

  loadLatestHistoryRun() {
    const historyDir = path.join(this.historyRoot(), this.projectHash(this.projectRoot));
    if (!fs.existsSync(historyDir)) {
      return null;
    }

    const runFile = fs.readdirSync(historyDir)
      .filter(file => file.endsWith('.json') && file !== 'meta.json')
      .sort()
      .reverse()[0];

    if (!runFile) {
      return null;
    }

    try {
      const raw = fs.readFileSync(path.join(historyDir, runFile), 'utf8');
      return JSON.parse(raw);
    } catch (_) {
      return null;
    }
  }

  parseTimeRange(range = '30d') {
    const match = String(range).match(/^(\d+)([dhm])$/i);
    if (!match) {
      return 30 * 24 * 60 * 60 * 1000;
    }

    const amount = Number(match[1]);
    const unit = match[2].toLowerCase();
    const units = { d: 86400000, h: 3600000, m: 60000 };
    return amount * (units[unit] || units.d);
  }

  getSinceIso(timeRange = '30d') {
    const windowMs = this.parseTimeRange(timeRange);
    return new Date(Date.now() - windowMs).toISOString();
  }

  parseCommitLog(output) {
    return String(output || '')
      .split('\x1e')
      .map(entry => entry.trim())
      .filter(Boolean)
      .map(entry => {
        const [sha, authoredAt, authorName, authorEmail, subject, body] = entry.split('\x1f');
        return {
          sha: (sha || '').trim(),
          authoredAt: (authoredAt || '').trim(),
          authorName: (authorName || '').trim(),
          authorEmail: (authorEmail || '').trim(),
          subject: (subject || '').trim(),
          body: (body || '').trim()
        };
      })
      .filter(entry => entry.sha);
  }

  scoreTool(commit = {}) {
    let best = null;
    const fields = {
      all: [commit.subject, commit.body, commit.authorName, commit.authorEmail].filter(Boolean).join('\n'),
      authorName: commit.authorName || '',
      authorEmail: commit.authorEmail || '',
      subject: commit.subject || '',
      body: commit.body || ''
    };

    SUPPORTED_AI_TOOLS.forEach(tool => {
      let score = 0;
      const matchedSignals = [];

      tool.signals.forEach(signal => {
        const signalFields = Array.isArray(signal.fields) && signal.fields.length > 0
          ? signal.fields
          : ['all'];

        const matched = signalFields.some(field => signal.regex.test(fields[field] || ''));
        if (matched) {
          score += signal.weight;
          matchedSignals.push(signal.label);
        }
      });

      if (!best || score > best.score) {
        best = { tool, score, matchedSignals };
      }
    });

    if (!best || best.score <= 0) {
      return null;
    }

    return {
      toolId: best.tool.id,
      tool: best.tool.name,
      confidence: clamp(Number((best.score / 12).toFixed(2)), 0.34, 0.99),
      matchedSignals: best.matchedSignals
    };
  }

  readCommit(sha) {
    if (!sha) {
      return null;
    }

    if (this.commitCache.has(sha)) {
      return this.commitCache.get(sha);
    }

    const raw = this.runGit([
      'show',
      '-s',
      '--date=iso-strict',
      '--format=%H%x1f%aI%x1f%an%x1f%ae%x1f%s%x1f%b',
      sha
    ], { allowFailure: true }).trim();

    if (!raw) {
      this.commitCache.set(sha, null);
      return null;
    }

    const [commit] = this.parseCommitLog(`${raw}\x1e`);
    this.commitCache.set(sha, commit || null);
    return commit || null;
  }

  collectCommitAttribution(options = {}) {
    const timeRange = options.timeRange || '30d';
    const repoRoot = this.resolveRepoRoot();

    if (!repoRoot) {
      return buildEmptyCommitAttribution(timeRange, 'No git repository available for attribution.');
    }

    const raw = this.runGit([
      'log',
      `--since=${this.getSinceIso(timeRange)}`,
      `--max-count=${Math.max(1, Math.min(Number(options.limit) || 250, 1000))}`,
      '--date=iso-strict',
      '--format=%H%x1f%aI%x1f%an%x1f%ae%x1f%s%x1f%b%x1e'
    ], { allowFailure: true });

    const commits = this.parseCommitLog(raw);
    if (commits.length === 0) {
      return {
        ...buildEmptyCommitAttribution(timeRange, null),
        available: true,
        reason: null
      };
    }

    const byTool = new Map();
    let attributedCommits = 0;

    commits.forEach(commit => {
      const match = this.scoreTool(commit);
      if (!match) {
        return;
      }

      attributedCommits += 1;
      const current = byTool.get(match.toolId) || {
        toolId: match.toolId,
        tool: match.tool,
        commitCount: 0,
        averageConfidence: 0,
        sampleCommits: []
      };

      current.commitCount += 1;
      current.averageConfidence += match.confidence;
      if (current.sampleCommits.length < 5) {
        current.sampleCommits.push({
          sha: commit.sha,
          subject: commit.subject,
          authoredAt: commit.authoredAt,
          confidence: match.confidence
        });
      }

      byTool.set(match.toolId, current);
    });

    const tools = Array.from(byTool.values())
      .map(tool => ({
        ...tool,
        averageConfidence: Number((tool.averageConfidence / tool.commitCount).toFixed(2)),
        coverage: toPercent(tool.commitCount / commits.length),
        attributedCommits: tool.commitCount
      }))
      .sort((left, right) => right.commitCount - left.commitCount || right.averageConfidence - left.averageConfidence);

    return {
      available: true,
      reason: null,
      repoRoot,
      timeRange,
      scannedCommits: commits.length,
      attributedCommits,
      unattributedCommits: commits.length - attributedCommits,
      detectedToolsCount: tools.length,
      coverage: commits.length > 0 ? toPercent(attributedCommits / commits.length) : 0,
      supportedTools: SUPPORTED_AI_TOOLS.map(tool => ({ id: tool.id, name: tool.name })),
      tools
    };
  }

  normalizeFinding(finding = {}) {
    const filePath = finding.file_path || finding.filePath || finding.file || null;
    const lineNumber = Number(finding.line_number || finding.lineNumber || finding.line || 0);
    const severity = String(finding.severity || '').toUpperCase();

    if (!filePath || !lineNumber) {
      return null;
    }

    return {
      filePath,
      lineNumber,
      severity,
      category: finding.category || null
    };
  }

  resolveRepoRelativePath(filePath) {
    const repoRoot = this.resolveRepoRoot();
    if (!repoRoot || !filePath) {
      return null;
    }

    const absolute = path.isAbsolute(filePath)
      ? path.resolve(filePath)
      : path.resolve(this.projectRoot, filePath);
    const relative = path.relative(repoRoot, absolute);

    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
      return null;
    }

    return relative.replace(/\\/g, '/');
  }

  blameFindingLine(relativePath, lineNumber) {
    const cacheKey = `${relativePath}:${lineNumber}`;
    if (this.blameCache.has(cacheKey)) {
      return this.blameCache.get(cacheKey);
    }

    const raw = this.runGit([
      'blame',
      '--porcelain',
      '-L',
      `${lineNumber},${lineNumber}`,
      '--',
      relativePath
    ], { allowFailure: true });

    if (!raw) {
      this.blameCache.set(cacheKey, null);
      return null;
    }

    const lines = raw.split('\n');
    const header = lines[0] || '';
    const match = header.match(/^([0-9a-f]{8,40}|0{40})\s/);
    const sha = match ? match[1] : null;
    if (!sha || /^0+$/.test(sha)) {
      this.blameCache.set(cacheKey, null);
      return null;
    }

    const commit = this.readCommit(sha);
    this.blameCache.set(cacheKey, commit);
    return commit;
  }

  attributeFindings(findings = [], options = {}) {
    const repoRoot = this.resolveRepoRoot();
    const totalFindings = Array.isArray(findings) ? findings.length : 0;
    const runId = options.runId || null;

    if (!repoRoot) {
      return buildEmptyFindingAttribution(runId, totalFindings, 'No git repository available for blame attribution.');
    }

    const byTool = new Map();
    let attributedFindings = 0;

    for (const finding of Array.isArray(findings) ? findings : []) {
      const normalized = this.normalizeFinding(finding);
      if (!normalized) {
        continue;
      }

      const relativePath = this.resolveRepoRelativePath(normalized.filePath);
      if (!relativePath) {
        continue;
      }

      const commit = this.blameFindingLine(relativePath, normalized.lineNumber);
      if (!commit) {
        continue;
      }

      const match = this.scoreTool(commit);
      if (!match) {
        continue;
      }

      attributedFindings += 1;
      const current = byTool.get(match.toolId) || {
        toolId: match.toolId,
        tool: match.tool,
        findingCount: 0,
        weightedFindings: 0,
        severity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        },
        sampleFindings: []
      };

      current.findingCount += 1;
      current.weightedFindings += severityWeight(normalized.severity);
      const severityKey = normalized.severity.toLowerCase();
      if (Object.prototype.hasOwnProperty.call(current.severity, severityKey)) {
        current.severity[severityKey] += 1;
      }
      if (current.sampleFindings.length < 5) {
        current.sampleFindings.push({
          file: relativePath,
          line: normalized.lineNumber,
          severity: normalized.severity,
          category: normalized.category
        });
      }

      byTool.set(match.toolId, current);
    }

    const tools = Array.from(byTool.values())
      .map(tool => ({
        ...tool,
        coverage: totalFindings > 0 ? toPercent(tool.findingCount / totalFindings) : 0
      }))
      .sort((left, right) => right.weightedFindings - left.weightedFindings || right.findingCount - left.findingCount);

    return {
      available: true,
      reason: null,
      repoRoot,
      runId,
      totalFindings,
      attributedFindings,
      unattributedFindings: Math.max(0, totalFindings - attributedFindings),
      coverage: totalFindings > 0 ? toPercent(attributedFindings / totalFindings) : 0,
      tools
    };
  }

  computeToolQuality(commitAttribution = {}, findingAttribution = {}) {
    const tools = new Map();

    (Array.isArray(commitAttribution.tools) ? commitAttribution.tools : []).forEach(entry => {
      tools.set(entry.toolId, {
        toolId: entry.toolId,
        tool: entry.tool,
        commitCount: entry.commitCount || 0,
        findingCount: 0,
        weightedFindings: 0,
        severity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      });
    });

    (Array.isArray(findingAttribution.tools) ? findingAttribution.tools : []).forEach(entry => {
      const current = tools.get(entry.toolId) || {
        toolId: entry.toolId,
        tool: entry.tool,
        commitCount: 0,
        findingCount: 0,
        weightedFindings: 0,
        severity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      };

      current.findingCount = entry.findingCount || 0;
      current.weightedFindings = entry.weightedFindings || 0;
      current.severity = {
        critical: entry.severity?.critical || 0,
        high: entry.severity?.high || 0,
        medium: entry.severity?.medium || 0,
        low: entry.severity?.low || 0
      };

      tools.set(entry.toolId, current);
    });

    return Array.from(tools.values())
      .map(entry => {
        const defectRate = entry.commitCount > 0
          ? Number((entry.weightedFindings / entry.commitCount).toFixed(2))
          : null;
        const rawScore = entry.commitCount > 0
          ? clamp(100 - (entry.weightedFindings * 6) - Math.max(0, entry.commitCount < 3 ? 8 : 0), 0, 100)
          : 100;
        const qualityScore = Number(rawScore.toFixed(1));

        return {
          toolId: entry.toolId,
          tool: entry.tool,
          commitCount: entry.commitCount,
          findingCount: entry.findingCount,
          weightedFindings: entry.weightedFindings,
          severity: entry.severity,
          defectRate,
          qualityScore,
          qualityBand: classifyQuality(qualityScore),
          signalStrength: entry.commitCount >= 10 ? 'high' : entry.commitCount >= 3 ? 'medium' : 'low'
        };
      })
      .sort((left, right) => left.qualityScore - right.qualityScore || right.commitCount - left.commitCount);
  }

  buildTeamRecommendations(commitAttribution = {}, toolQualityScores = []) {
    const attributedCommits = Number(commitAttribution.attributedCommits || 0);
    if (attributedCommits < 50) {
      return [
        {
          type: 'sample_size',
          message: `Need at least 50 attributed commits for stable team-level recommendations. Current sample: ${attributedCommits}.`
        }
      ];
    }

    const sufficientlySampled = toolQualityScores.filter(tool => tool.commitCount >= 5);
    if (sufficientlySampled.length === 0) {
      return [
        {
          type: 'sample_size',
          message: 'Attributed commit volume exists, but no single tool has at least 5 commits of stable signal yet.'
        }
      ];
    }

    const ordered = [...sufficientlySampled].sort((left, right) => right.qualityScore - left.qualityScore);
    const best = ordered[0];
    const worst = ordered[ordered.length - 1];
    const recommendations = [];

    recommendations.push({
      type: 'prefer_tool',
      toolId: best.toolId,
      tool: best.tool,
      message: `${best.tool} currently has the strongest quality score (${best.qualityScore}) across ${best.commitCount} attributed commits.`
    });

    if (worst && worst.toolId !== best.toolId && worst.qualityScore <= 70) {
      recommendations.push({
        type: 'review_tool',
        toolId: worst.toolId,
        tool: worst.tool,
        message: `${worst.tool} is producing the weakest quality score (${worst.qualityScore}); require extra review on its diffs until defect density drops.`
      });
    }

    return recommendations;
  }
}

module.exports = {
  AIAttribution,
  SUPPORTED_AI_TOOLS,
  severityWeight,
  classifyQuality,
  buildEmptyCommitAttribution,
  buildEmptyFindingAttribution
};
