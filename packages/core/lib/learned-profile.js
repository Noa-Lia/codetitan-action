"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function severityWeight(severity) {
  switch (String(severity || "").toUpperCase()) {
    case "CRITICAL":
      return 1.0;
    case "HIGH":
      return 0.75;
    case "MEDIUM":
      return 0.45;
    case "LOW":
      return 0.2;
    default:
      return 0.1;
  }
}

function normalizeWhitespace(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeSnippet(value) {
  return normalizeWhitespace(value).slice(0, 160);
}

class LearnedProfileManager {
  constructor(options = {}) {
    this.projectRoot = path.resolve(options.projectRoot || process.cwd());
    this.profilePath =
      options.profilePath ||
      path.join(this.projectRoot, ".codetitan", "learned-profile.json");
    this.dismissedRulesPath =
      options.dismissedRulesPath ||
      path.join(require("os").homedir(), ".codetitan", "dismissed-rules.json");
    // v2 (2026-06-04): profiles persisted by pre-v2 code may carry
    // suppressionRules copied from the OLD flat, repo-agnostic dismissed-rules
    // store — a cross-repo / fixture false-negative if read back. loadProfile
    // drops suppressionRules from any profile with profileVersion < 2 so a
    // poisoned pre-fix profile can't re-suppress a real finding on the first
    // post-upgrade scan. (Agent-2 review finding.)
    this.profileVersion = options.profileVersion || 2;
  }

  buildRepoFingerprint(projectRoot = this.projectRoot) {
    const normalized = path
      .resolve(projectRoot)
      .toLowerCase()
      .replace(/\\/g, "/");
    return crypto.createHash("sha1").update(normalized).digest("hex");
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
          rejected: 0,
        },
        byCategory: {},
      },
      confidenceCalibration: {
        lastAverageConfidence: 0,
        averageConfidence: 0,
        totalScoredFindings: 0,
      },
      lastRunAt: null,
    };
  }

  normalizeFixerAcceptance(fixerAcceptance = {}) {
    const normalized = {
      __project: {
        accepted: Number(fixerAcceptance?.__project?.accepted || 0),
        rejected: Number(fixerAcceptance?.__project?.rejected || 0),
      },
      byCategory: {},
    };

    const categoryEntries =
      fixerAcceptance?.byCategory &&
      typeof fixerAcceptance.byCategory === "object"
        ? fixerAcceptance.byCategory
        : fixerAcceptance;

    for (const [category, value] of Object.entries(categoryEntries || {})) {
      if (
        category === "__project" ||
        category === "byCategory" ||
        !value ||
        typeof value !== "object"
      ) {
        continue;
      }

      normalized.byCategory[String(category).toUpperCase()] = {
        accepted: Number(value.accepted || 0),
        rejected: Number(value.rejected || 0),
      };
    }

    return normalized;
  }

  recordFixerDecision(fixerAcceptance, category, accepted) {
    const normalizedCategory = String(category || "UNKNOWN").toUpperCase();
    if (!fixerAcceptance.byCategory[normalizedCategory]) {
      fixerAcceptance.byCategory[normalizedCategory] = {
        accepted: 0,
        rejected: 0,
      };
    }

    const bucket = accepted ? "accepted" : "rejected";
    fixerAcceptance.__project[bucket] += 1;
    fixerAcceptance.byCategory[normalizedCategory][bucket] += 1;
  }

  resolveProfilePath(projectRoot = this.projectRoot) {
    if (
      this.profilePath &&
      path.isAbsolute(this.profilePath) &&
      projectRoot === this.projectRoot
    ) {
      return this.profilePath;
    }
    return path.join(
      path.resolve(projectRoot),
      ".codetitan",
      "learned-profile.json",
    );
  }

  loadProfile(projectRoot = this.projectRoot) {
    try {
      if (typeof fs.readFileSync !== "function") {
        return this.createDefaultProfile(projectRoot);
      }

      const raw = fs.readFileSync(this.resolveProfilePath(projectRoot), "utf8");
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") {
        return this.createDefaultProfile(projectRoot);
      }

      // Migration gate (v2): a profile persisted by pre-v2 code may have had the
      // OLD flat, repo-agnostic dismissed-rules store copied wholesale into its
      // suppressionRules. Reading that back would re-suppress a real finding in
      // an unrelated repo (the exact cross-repo / fixture false-negative the v2
      // store-scoping fixes) on the FIRST post-upgrade scan, BEFORE updateProfile
      // rebuilds suppressionRules from the scoped store. Drop suppressionRules
      // from any sub-v2 profile so they can never be applied. Safe: updateProfile
      // repopulates suppressionRules from the per-repo bucket every run.
      // Fail CLOSED: keep suppressionRules ONLY when the persisted version is a
      // real number >= 2. Require typeof number (not just numeric-coercible) so
      // a forged "2.0.0"/"v2"/{}/[2] — all of which coerce oddly — DROPS rather
      // than survives the gate. (`NaN < 2` is false, so a naive `< 2` check
      // would have kept the poison; an array like [2] coerces to 2 under
      // Number(), so a typeof guard is needed too.)
      const pv = parsed.profileVersion;
      const suppressionRules =
        typeof pv === "number" && pv >= 2 ? parsed.suppressionRules || {} : {};

      return {
        ...this.createDefaultProfile(projectRoot),
        ...parsed,
        categoryStats: parsed.categoryStats || {},
        fileRiskScores: parsed.fileRiskScores || {},
        hotDirectories: parsed.hotDirectories || {},
        suppressionRules,
        fixerAcceptance: this.normalizeFixerAcceptance(
          parsed.fixerAcceptance || {},
        ),
        confidenceCalibration: {
          ...this.createDefaultProfile(projectRoot).confidenceCalibration,
          ...(parsed.confidenceCalibration || {}),
        },
      };
    } catch (_) {
      return this.createDefaultProfile(projectRoot);
    }
  }

  saveProfile(profile) {
    const resolvedPath = this.resolveProfilePath(
      profile?.projectRoot || this.projectRoot,
    );
    const serialized = `${JSON.stringify(profile, null, 2)}\n`;

    try {
      if (
        typeof fs.mkdirSync === "function" &&
        typeof fs.writeFileSync === "function"
      ) {
        fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
        if (typeof fs.renameSync === "function") {
          // Temp-file + rename so a crash or concurrent reader never sees a
          // torn profile. A torn read makes loadProfile fall back to the
          // default profile, and the next saveProfile then persists that
          // default — silently discarding the accumulated learning history.
          // Concurrent read-modify-write stays last-writer-wins (no lockfile):
          // fail-open, a lost update only under-counts, never suppresses.
          const tempPath = `${resolvedPath}.${process.pid}.${crypto
            .randomBytes(6)
            .toString("hex")}.tmp`;
          try {
            fs.writeFileSync(tempPath, serialized, "utf8");
            fs.renameSync(tempPath, resolvedPath);
          } catch (_) {
            // Windows can refuse the rename while AV/indexers hold the
            // destination — fall back to the direct write, clean the temp.
            fs.writeFileSync(resolvedPath, serialized, "utf8");
            if (typeof fs.rmSync === "function") {
              try {
                fs.rmSync(tempPath, { force: true });
              } catch (_) {
                // best-effort cleanup
              }
            }
          }
        } else {
          fs.writeFileSync(resolvedPath, serialized, "utf8");
        }
      } else if (fs.promises && typeof fs.promises.writeFile === "function") {
        const mkdirPromise =
          typeof fs.promises.mkdir === "function"
            ? fs.promises.mkdir(path.dirname(resolvedPath), { recursive: true })
            : Promise.resolve();
        void mkdirPromise
          .then(() => fs.promises.writeFile(resolvedPath, serialized, "utf8"))
          .catch(() => {});
      }
    } catch (_) {
      return resolvedPath;
    }

    return resolvedPath;
  }

  normalizeFindingPath(finding = {}) {
    const raw = finding.file_path || finding.filePath || finding.file || "";
    return String(raw || "").replace(/\\/g, "/");
  }

  getDirectoryForFinding(finding = {}) {
    const filePath = this.normalizeFindingPath(finding);
    if (!filePath || !filePath.includes("/")) {
      return ".";
    }
    return filePath.split("/").slice(0, -1).join("/") || ".";
  }

  getDismissalSnippet(finding = {}) {
    if (finding.code_snippet || finding.codeSnippet) {
      return normalizeSnippet(finding.code_snippet || finding.codeSnippet);
    }

    return normalizeSnippet(
      [
        finding.file_path || finding.filePath || finding.file || "",
        finding.line_number || finding.lineNumber || finding.line || "",
        finding.message || "",
      ]
        .filter(Boolean)
        .join(":"),
    );
  }

  createDismissalKey(category, snippet) {
    const normalizedCategory = normalizeWhitespace(
      category || "UNKNOWN",
    ).toUpperCase();
    const normalizedSnippet = normalizeSnippet(snippet || "");
    return `${normalizedCategory}:${normalizedSnippet}`;
  }

  /**
   * Load the dismissal-rule counts that apply to THIS repo only.
   *
   * BUG-3 (Custos field report, 2026-06-04): the dismissed-rules store at
   * ~/.codetitan/dismissed-rules.json was a flat, repo-agnostic
   * `{ "CATEGORY:snippet": count }` map, and updateProfile copied the WHOLE
   * file into every repo's `suppressionRules`. Fixture dismissals recorded
   * while developing CodeTitan (e.g. `HARDCODED_SECRET:const API_KEY =
   * "sk_test_1234567890";`) therefore bled into unrelated repos and, at the
   * auto-suppress threshold, could silently drop a REAL secret finding in a
   * partner's code — a trust-destroying false negative.
   *
   * The store is now namespaced by repoFingerprint:
   *   { "version": 2, "repos": { "<fingerprint>": { "CAT:snip": n } } }
   * Only the current repo's bucket is returned. A LEGACY flat file (no
   * `version`/`repos`, bare `CAT:snip` keys at the top level) is treated as
   * un-attributable and returns {} — it is never applied to any repo, which
   * closes the leak for stores written before this change.
   *
   * @param {string} [projectRoot] - Repo root whose dismissals to load.
   *   Defaults to this.projectRoot. The fingerprint is derived from it.
   */
  loadDismissalRules(projectRoot = this.projectRoot) {
    try {
      if (
        typeof fs.existsSync !== "function" ||
        typeof fs.readFileSync !== "function"
      ) {
        return {};
      }

      if (!fs.existsSync(this.dismissedRulesPath)) {
        return {};
      }
      const parsed = JSON.parse(
        fs.readFileSync(this.dismissedRulesPath, "utf8"),
      );
      return this.selectRepoDismissals(parsed, projectRoot);
    } catch (_) {
      return {};
    }
  }

  /**
   * Extract the current repo's dismissal bucket from a parsed store.
   * Shared shape contract with the CLI writer (packages/cli/src/lib/dismissals.ts):
   *   v2 → { version: 2, repos: { "<fp>": { "CAT:snip": n } } }
   *   legacy → bare { "CAT:snip": n } (returns {} — never applied; see above)
   */
  selectRepoDismissals(parsed, projectRoot = this.projectRoot) {
    if (!parsed || typeof parsed !== "object") {
      return {};
    }
    if (parsed.repos && typeof parsed.repos === "object") {
      const fingerprint = this.buildRepoFingerprint(projectRoot);
      const bucket = parsed.repos[fingerprint];
      return bucket && typeof bucket === "object" ? bucket : {};
    }
    // Legacy flat store — un-attributable to a repo. Do NOT apply it (closes
    // the cross-repo leak). Returning {} means pre-existing global dismissals
    // simply stop being honored until re-recorded against a specific repo.
    return {};
  }

  computePersonalizationScore(profile) {
    const runScore = Math.min(40, (profile.runCount || 0) * 4);
    const fileScore = Math.min(
      20,
      Object.keys(profile.fileRiskScores || {}).length * 2,
    );
    const directoryScore = Math.min(
      15,
      Object.keys(profile.hotDirectories || {}).length * 3,
    );
    const categoryScore = Math.min(
      15,
      Object.keys(profile.categoryStats || {}).length * 3,
    );
    const suppressionScore = Math.min(
      10,
      Object.keys(profile.suppressionRules || {}).length,
    );
    return clamp(
      Math.round(
        runScore +
          fileScore +
          directoryScore +
          categoryScore +
          suppressionScore,
      ),
      0,
      100,
    );
  }

  buildFindingSignals(profile, finding = {}) {
    const filePath = this.normalizeFindingPath(finding);
    const directory = this.getDirectoryForFinding(finding);
    const fileRiskScore = Number(
      profile.fileRiskScores?.[filePath]?.score || 0,
    );
    const directoryFrequency = Number(
      profile.hotDirectories?.[directory]?.frequency || 0,
    );
    const categoryStats =
      profile.categoryStats?.[
        String(finding.category || "UNKNOWN").toUpperCase()
      ] || {};
    const categoryFrequency = Number(categoryStats.frequency || 0);
    const acceptanceLedger = this.normalizeFixerAcceptance(
      profile.fixerAcceptance || {},
    );
    const categoryAcceptance = acceptanceLedger.byCategory[
      String(finding.category || "UNKNOWN").toUpperCase()
    ] || {
      accepted: 0,
      rejected: 0,
    };
    const categoryDecisions =
      Number(categoryAcceptance.accepted || 0) +
      Number(categoryAcceptance.rejected || 0);
    const projectDecisions =
      Number(acceptanceLedger.__project.accepted || 0) +
      Number(acceptanceLedger.__project.rejected || 0);
    const snippet = this.getDismissalSnippet(finding);
    const dismissalCount = Number(
      profile.suppressionRules?.[
        this.createDismissalKey(finding.category, snippet)
      ] || 0,
    );
    const rejectionRate =
      categoryDecisions > 0
        ? Number(categoryAcceptance.rejected || 0) / categoryDecisions
        : 0;
    const dismissalPenalty = clamp(
      dismissalCount * 0.05 + rejectionRate * 0.15,
      0,
      0.5,
    );
    const contextSimilarity = clamp(
      0.5 +
        fileRiskScore * 0.25 +
        directoryFrequency * 0.15 +
        categoryFrequency * 0.1,
      0.1,
      0.99,
    );
    const categoryAcceptRate =
      categoryDecisions > 0
        ? clamp(
            Number(categoryAcceptance.accepted || 0) / categoryDecisions,
            0.05,
            0.99,
          )
        : clamp(
            0.5 +
              fileRiskScore * 0.2 +
              categoryFrequency * 0.15 -
              dismissalPenalty,
            0.05,
            0.99,
          );
    const projectAcceptRate =
      projectDecisions > 0
        ? clamp(
            Number(acceptanceLedger.__project.accepted || 0) / projectDecisions,
            0.05,
            0.99,
          )
        : clamp(
            0.5 +
              profile.personalizationScore / 200 +
              directoryFrequency * 0.05 -
              dismissalPenalty,
            0.05,
            0.99,
          );
    const profileFactor = clamp(
      1 +
        fileRiskScore * 0.15 +
        directoryFrequency * 0.05 +
        (categoryAcceptRate - 0.5) * 0.1 +
        (projectAcceptRate - 0.5) * 0.05 -
        dismissalPenalty,
      0.7,
      1.25,
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
      profileFactor,
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
      findingContexts: contexts,
    };
  }

  createFindingIdentity(finding = {}) {
    return `${finding.category || "UNKNOWN"}:${this.normalizeFindingPath(finding)}:${finding.line_number || finding.lineNumber || finding.line || 0}`;
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
      fixerAcceptance: this.normalizeFixerAcceptance(
        profile.fixerAcceptance || {},
      ),
      confidenceCalibration: {
        ...this.createDefaultProfile(projectRoot).confidenceCalibration,
        ...(profile.confidenceCalibration || {}),
      },
    };

    // Stamp the current schema version. The `...profile` spread above carries
    // the loaded profile's OLD profileVersion; without this override a migrated
    // (sub-v2) profile would be re-saved as sub-v2 and loadProfile would keep
    // dropping its suppressionRules every run. suppressionRules are rebuilt from
    // the scoped store just below, so promoting to v2 here is safe.
    next.profileVersion = this.profileVersion;

    next.runCount = Number(next.runCount || 0) + 1;
    next.lastRunAt = new Date().toISOString();

    const maxDirectoryCount = Math.max(1, findings.length);
    findings.forEach((finding) => {
      const filePath = this.normalizeFindingPath(finding);
      const directory = this.getDirectoryForFinding(finding);
      const category = String(finding.category || "UNKNOWN").toUpperCase();
      const risk = severityWeight(finding.severity);
      const confidence = Number((finding.confidence || 0) / 100) || 0;

      const fileEntry = next.fileRiskScores[filePath] || {
        hits: 0,
        score: 0,
        lastSeverity: "LOW",
      };
      fileEntry.hits += 1;
      fileEntry.score = Number((fileEntry.score * 0.7 + risk * 0.3).toFixed(3));
      fileEntry.lastSeverity = String(finding.severity || "LOW").toUpperCase();
      next.fileRiskScores[filePath] = fileEntry;

      const dirEntry = next.hotDirectories[directory] || {
        count: 0,
        frequency: 0,
      };
      dirEntry.count += 1;
      dirEntry.frequency = Number(
        (dirEntry.count / (next.runCount * maxDirectoryCount)).toFixed(3),
      );
      next.hotDirectories[directory] = dirEntry;

      const categoryEntry = next.categoryStats[category] || {
        count: 0,
        frequency: 0,
        averageConfidence: 0,
      };
      categoryEntry.count += 1;
      categoryEntry.frequency = Number(
        (categoryEntry.count / Math.max(1, next.runCount)).toFixed(3),
      );
      categoryEntry.averageConfidence = Number(
        (
          (categoryEntry.averageConfidence || 0) * 0.7 +
          confidence * 0.3
        ).toFixed(3),
      );
      next.categoryStats[category] = categoryEntry;
    });

    // Per-repo dismissals only (BUG-3): scope by the profile's own repo root so
    // one repo's suppressions never leak into another's profile.
    const dismissals = this.loadDismissalRules(projectRoot);
    next.suppressionRules = dismissals;

    const acceptedFindings = Array.isArray(metadata.acceptedFindings)
      ? metadata.acceptedFindings
      : [];
    acceptedFindings.forEach((finding) => {
      this.recordFixerDecision(next.fixerAcceptance, finding.category, true);
    });

    const fpFilteredFindings = Array.isArray(metadata.fpFilteredFindings)
      ? metadata.fpFilteredFindings
      : [];
    fpFilteredFindings.forEach((finding) => {
      this.recordFixerDecision(next.fixerAcceptance, finding.category, false);
    });

    const confidences = findings
      .map((finding) => Number(finding.confidence || 0))
      .filter((value) => Number.isFinite(value) && value > 0);
    const averageConfidence =
      confidences.length > 0
        ? confidences.reduce((sum, value) => sum + value, 0) /
          confidences.length
        : 0;

    next.confidenceCalibration.lastAverageConfidence = Number(
      averageConfidence.toFixed(2),
    );
    next.confidenceCalibration.totalScoredFindings =
      Number(next.confidenceCalibration.totalScoredFindings || 0) +
      findings.length;
    next.confidenceCalibration.averageConfidence = Number(
      (
        (Number(next.confidenceCalibration.averageConfidence || 0) *
          Math.max(0, next.runCount - 1) +
          averageConfidence) /
        Math.max(1, next.runCount)
      ).toFixed(2),
    );

    next.personalizationScore = this.computePersonalizationScore(next);
    return next;
  }
}

module.exports = LearnedProfileManager;
