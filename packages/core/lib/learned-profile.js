'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function severityWeight(severity) {
  switch (String(severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 1.0;
    case 'HIGH':
      return 0.75;
    case 'MEDIUM':
      return 0.45;
    case 'LOW':
      return 0.2;
    default:
      return 0.1;
  }
}

function normalizeWhitespace(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function normalizeSnippet(value) {
  return normalizeWhitespace(value).slice(0, 160);
}

class LearnedProfileManager {
  constructor(options = {}) {
    this.projectRoot = path.resolve(options.projectRoot || process.cwd());
    this.profilePath = options.profilePath || path.join(this.projectRoot, '.codetitan', 'learned-profile.json');
    this.dismissedRulesPath = options.dismissedRulesPath || path.join(require('os').homedir(), '.codetitan', 'dismissed-rules.json');
    this.profileVersion = options.profileVersion || 1;
  }

  buildRepoFingerprint(projectRoot = this.projectRoot) {
    const normalized = path.resolve(projectRoot).toLowerCase().replace(/\\/g, '/');
    return crypto.createHash('sha1').update(normalized).digest('hex');
  }

  createDefaultProfile(projectRoot = this.projectRoot) {
    return {
      profileVersion: this.profileVersion,
      repoFingerprint: this.buildRepoFingerprint(projectRoot),
      projectRoot: path.resolve(projectRoot),
      runCount: 0,
      personalizationScore: 0,
      categoryStats: {},
      fileRiskScores: {},
      hotDirectories: {},
      suppressionRules: {},
      fixerAcceptance: {
        __project: {
          accepted: 0,
          rejected: 0
        },
        byCategory: {}
      },
      confidenceCalibration: {
        lastAverageConfidence: 0,
        averageConfidence: 0,
        totalScoredFindings: 0
      },
      lastRunAt: null
    };
  }

  normalizeFixerAcceptance(fixerAcceptance = {}) {
    const normalized = {
      __project: {
        accepted: Number(fixerAcceptance?.__project?.accepted || 0),
        rejected: Number(fixerAcceptance?.__project?.rejected || 0)
      },
      byCategory: {}
    };

    const categoryEntries = fixerAcceptance?.byCategory && typeof fixerAcceptance.byCategory === 'object'
      ? fixerAcceptance.byCategory
      : fixerAcceptance;

    for (const [category, value] of Object.entries(categoryEntries || {})) {
      if (category === '__project' || category === 'byCategory' || !value || typeof value !== 'object') {
        continue;
      }

      normalized.byCategory[String(category).toUpperCase()] = {
        accepted: Number(value.accepted || 0),
        rejected: Number(value.rejected || 0)
      };
    }

    return normalized;
  }

  recordFixerDecision(fixerAcceptance, category, accepted) {
    const normalizedCategory = String(category || 'UNKNOWN').toUpperCase();
    if (!fixerAcceptance.byCategory[normalizedCategory]) {
      fixerAcceptance.byCategory[normalizedCategory] = {
        accepted: 0,
        rejected: 0
      };
    }

    const bucket = accepted ? 'accepted' : 'rejected';
    fixerAcceptance.__project[bucket] += 1;
    fixerAcceptance.byCategory[normalizedCategory][bucket] += 1;
  }

  resolveProfilePath(projectRoot = this.projectRoot) {
    if (this.profilePath && path.isAbsolute(this.profilePath) && projectRoot === this.projectRoot) {
      return this.profilePath;
    }
    return path.join(path.resolve(projectRoot), '.codetitan', 'learned-profile.json');
  }

  loadProfile(projectRoot = this.projectRoot) {
    try {
      if (typeof fs.readFileSync !== 'function') {
        return this.createDefaultProfile(projectRoot);
      }

      const raw = fs.readFileSync(this.resolveProfilePath(projectRoot), 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') {
        return this.createDefaultProfile(projectRoot);
      }

      return {
        ...this.createDefaultProfile(projectRoot),
        ...parsed,
        categoryStats: parsed.categoryStats || {},
        fileRiskScores: parsed.fileRiskScores || {},
        hotDirectories: parsed.hotDirectories || {},
        suppressionRules: parsed.suppressionRules || {},
        fixerAcceptance: this.normalizeFixerAcceptance(parsed.fixerAcceptance || {}),
        confidenceCalibration: {
          ...this.createDefaultProfile(projectRoot).confidenceCalibration,
          ...(parsed.confidenceCalibration || {})
        }
      };
    } catch (_) {
      return this.createDefaultProfile(projectRoot);
    }
  }

  saveProfile(profile) {
    const resolvedPath = this.resolveProfilePath(profile?.projectRoot || this.projectRoot);
    const serialized = `${JSON.stringify(profile, null, 2)}\n`;

    try {
      if (typeof fs.mkdirSync === 'function' && typeof fs.writeFileSync === 'function') {
        fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
        fs.writeFileSync(resolvedPath, serialized, 'utf8');
      } else if (fs.promises && typeof fs.promises.writeFile === 'function') {
        const mkdirPromise = typeof fs.promises.mkdir === 'function'
          ? fs.promises.mkdir(path.dirname(resolvedPath), { recursive: true })
          : Promise.resolve();
        void mkdirPromise
          .then(() => fs.promises.writeFile(resolvedPath, serialized, 'utf8'))
          .catch(() => {});
      }
    } catch (_) {
      return resolvedPath;
    }

    return resolvedPath;
  }

  normalizeFindingPath(finding = {}) {
    const raw = finding.file_path || finding.filePath || finding.file || '';
    return String(raw || '').replace(/\\/g, '/');
  }

  getDirectoryForFinding(finding = {}) {
    const filePath = this.normalizeFindingPath(finding);
    if (!filePath || !filePath.includes('/')) {
      return '.';
    }
    return filePath.split('/').slice(0, -1).join('/') || '.';
  }

  getDismissalSnippet(finding = {}) {
    if (finding.code_snippet || finding.codeSnippet) {
      return normalizeSnippet(finding.code_snippet || finding.codeSnippet);
    }

    return normalizeSnippet([
      finding.file_path || finding.filePath || finding.file || '',
      finding.line_number || finding.lineNumber || finding.line || '',
      finding.message || ''
    ].filter(Boolean).join(':'));
  }

  createDismissalKey(category, snippet) {
    const normalizedCategory = normalizeWhitespace(category || 'UNKNOWN').toUpperCase();
    const normalizedSnippet = normalizeSnippet(snippet || '');
    return `${normalizedCategory}:${normalizedSnippet}`;
  }

  loadDismissalRules() {
    try {
      if (typeof fs.existsSync !== 'function' || typeof fs.readFileSync !== 'function') {
        return {};
      }

      if (!fs.existsSync(this.dismissedRulesPath)) {
        return {};
      }
      return JSON.parse(fs.readFileSync(this.dismissedRulesPath, 'utf8'));
    } catch (_) {
      return {};
    }
  }

  computePersonalizationScore(profile) {
    const runScore = Math.min(40, (profile.runCount || 0) * 4);
    const fileScore = Math.min(20, Object.keys(profile.fileRiskScores || {}).length * 2);
    const directoryScore = Math.min(15, Object.keys(profile.hotDirectories || {}).length * 3);
    const categoryScore = Math.min(15, Object.keys(profile.categoryStats || {}).length * 3);
    const suppressionScore = Math.min(10, Object.keys(profile.suppressionRules || {}).length);
    return clamp(Math.round(runScore + fileScore + directoryScore + categoryScore + suppressionScore), 0, 100);
  }

  buildFindingSignals(profile, finding = {}) {
    const filePath = this.normalizeFindingPath(finding);
    const directory = this.getDirectoryForFinding(finding);
    const fileRiskScore = Number(profile.fileRiskScores?.[filePath]?.score || 0);
    const directoryFrequency = Number(profile.hotDirectories?.[directory]?.frequency || 0);
    const categoryStats = profile.categoryStats?.[String(finding.category || 'UNKNOWN').toUpperCase()] || {};
    const categoryFrequency = Number(categoryStats.frequency || 0);
    const acceptanceLedger = this.normalizeFixerAcceptance(profile.fixerAcceptance || {});
    const categoryAcceptance = acceptanceLedger.byCategory[String(finding.category || 'UNKNOWN').toUpperCase()] || {
      accepted: 0,
      rejected: 0
    };
    const categoryDecisions = Number(categoryAcceptance.accepted || 0) + Number(categoryAcceptance.rejected || 0);
    const projectDecisions = Number(acceptanceLedger.__project.accepted || 0) + Number(acceptanceLedger.__project.rejected || 0);
    const snippet = this.getDismissalSnippet(finding);
    const dismissalCount = Number(profile.suppressionRules?.[this.createDismissalKey(finding.category, snippet)] || 0);
    const rejectionRate = categoryDecisions > 0
      ? Number(categoryAcceptance.rejected || 0) / categoryDecisions
      : 0;
    const dismissalPenalty = clamp((dismissalCount * 0.05) + (rejectionRate * 0.15), 0, 0.5);
    const contextSimilarity = clamp(0.5 + (fileRiskScore * 0.25) + (directoryFrequency * 0.15) + (categoryFrequency * 0.1), 0.1, 0.99);
    const categoryAcceptRate = categoryDecisions > 0
      ? clamp(Number(categoryAcceptance.accepted || 0) / categoryDecisions, 0.05, 0.99)
      : clamp(0.5 + (fileRiskScore * 0.2) + (categoryFrequency * 0.15) - dismissalPenalty, 0.05, 0.99);
    const projectAcceptRate = projectDecisions > 0
      ? clamp(Number(acceptanceLedger.__project.accepted || 0) / projectDecisions, 0.05, 0.99)
      : clamp(0.5 + (profile.personalizationScore / 200) + (directoryFrequency * 0.05) - dismissalPenalty, 0.05, 0.99);
    const profileFactor = clamp(
      1 + (fileRiskScore * 0.15) + (directoryFrequency * 0.05) + ((categoryAcceptRate - 0.5) * 0.1) + ((projectAcceptRate - 0.5) * 0.05) - dismissalPenalty,
      0.7,
      1.25
    );

    return {
      fileRiskScore,
      directoryFrequency,
      categoryFrequency,
      dismissalCount,
      falsePositivePenalty: dismissalPenalty,
      contextSimilarity,
      categoryAcceptRate,
      projectAcceptRate,
      profileFactor
    };
  }

  buildScoringContext(profile, findings = []) {
    const contexts = {};
    for (const finding of findings) {
      const key = this.createFindingIdentity(finding);
      contexts[key] = this.buildFindingSignals(profile, finding);
    }

    return {
      projectId: this.projectRoot,
      personalizationScore: profile.personalizationScore || 0,
      findingContexts: contexts
    };
  }

  createFindingIdentity(finding = {}) {
    return `${finding.category || 'UNKNOWN'}:${this.normalizeFindingPath(finding)}:${finding.line_number || finding.lineNumber || finding.line || 0}`;
  }

  updateProfile(profile, findings = [], metadata = {}) {
    const projectRoot = profile?.projectRoot || this.projectRoot;
    const next = {
      ...this.createDefaultProfile(projectRoot),
      ...profile,
      categoryStats: { ...(profile.categoryStats || {}) },
      fileRiskScores: { ...(profile.fileRiskScores || {}) },
      hotDirectories: { ...(profile.hotDirectories || {}) },
      suppressionRules: { ...(profile.suppressionRules || {}) },
      fixerAcceptance: this.normalizeFixerAcceptance(profile.fixerAcceptance || {}),
      confidenceCalibration: {
        ...this.createDefaultProfile(projectRoot).confidenceCalibration,
        ...(profile.confidenceCalibration || {})
      }
    };

    next.runCount = Number(next.runCount || 0) + 1;
    next.lastRunAt = new Date().toISOString();

    const maxDirectoryCount = Math.max(1, findings.length);
    findings.forEach(finding => {
      const filePath = this.normalizeFindingPath(finding);
      const directory = this.getDirectoryForFinding(finding);
      const category = String(finding.category || 'UNKNOWN').toUpperCase();
      const risk = severityWeight(finding.severity);
      const confidence = Number((finding.confidence || 0) / 100) || 0;

      const fileEntry = next.fileRiskScores[filePath] || { hits: 0, score: 0, lastSeverity: 'LOW' };
      fileEntry.hits += 1;
      fileEntry.score = Number(((fileEntry.score * 0.7) + (risk * 0.3)).toFixed(3));
      fileEntry.lastSeverity = String(finding.severity || 'LOW').toUpperCase();
      next.fileRiskScores[filePath] = fileEntry;

      const dirEntry = next.hotDirectories[directory] || { count: 0, frequency: 0 };
      dirEntry.count += 1;
      dirEntry.frequency = Number((dirEntry.count / (next.runCount * maxDirectoryCount)).toFixed(3));
      next.hotDirectories[directory] = dirEntry;

      const categoryEntry = next.categoryStats[category] || { count: 0, frequency: 0, averageConfidence: 0 };
      categoryEntry.count += 1;
      categoryEntry.frequency = Number((categoryEntry.count / Math.max(1, next.runCount)).toFixed(3));
      categoryEntry.averageConfidence = Number((((categoryEntry.averageConfidence || 0) * 0.7) + (confidence * 0.3)).toFixed(3));
      next.categoryStats[category] = categoryEntry;
    });

    const dismissals = this.loadDismissalRules();
    next.suppressionRules = dismissals;

    const acceptedFindings = Array.isArray(metadata.acceptedFindings) ? metadata.acceptedFindings : [];
    acceptedFindings.forEach((finding) => {
      this.recordFixerDecision(next.fixerAcceptance, finding.category, true);
    });

    const fpFilteredFindings = Array.isArray(metadata.fpFilteredFindings) ? metadata.fpFilteredFindings : [];
    fpFilteredFindings.forEach((finding) => {
      this.recordFixerDecision(next.fixerAcceptance, finding.category, false);
    });

    const confidences = findings
      .map(finding => Number(finding.confidence || 0))
      .filter(value => Number.isFinite(value) && value > 0);
    const averageConfidence = confidences.length > 0
      ? confidences.reduce((sum, value) => sum + value, 0) / confidences.length
      : 0;

    next.confidenceCalibration.lastAverageConfidence = Number(averageConfidence.toFixed(2));
    next.confidenceCalibration.totalScoredFindings = Number(next.confidenceCalibration.totalScoredFindings || 0) + findings.length;
    next.confidenceCalibration.averageConfidence = Number((
      ((Number(next.confidenceCalibration.averageConfidence || 0) * Math.max(0, next.runCount - 1)) + averageConfidence) /
      Math.max(1, next.runCount)
    ).toFixed(2));

    next.personalizationScore = this.computePersonalizationScore(next);
    return next;
  }
}

module.exports = LearnedProfileManager;
