'use strict';

const { severityWeight } = require('./ai-attribution');

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function classifyRisk(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

function gradeRisk(score) {
  if (score >= 90) return 'F';
  if (score >= 75) return 'D';
  if (score >= 60) return 'C';
  if (score >= 40) return 'B';
  return 'A';
}

class PRRiskScorer {
  score(input = {}) {
    const findingAttribution = input.findingAttribution || {};
    const toolQualityScores = Array.isArray(input.toolQualityScores) ? input.toolQualityScores : [];
    const latestFindings = Array.isArray(input.latestFindings) ? input.latestFindings : [];

    const totalWeightedFindings = latestFindings.reduce((sum, finding) => sum + severityWeight(finding.severity), 0);
    const severityComponent = clamp(totalWeightedFindings * 4, 0, 70);

    const toolQualityMap = new Map(toolQualityScores.map(tool => [tool.toolId, tool]));
    const byTool = (Array.isArray(findingAttribution.tools) ? findingAttribution.tools : []).map(tool => {
      const quality = toolQualityMap.get(tool.toolId);
      const qualityScore = quality ? quality.qualityScore : 100;
      const contribution = Number((tool.weightedFindings * ((100 - qualityScore) / 100)).toFixed(2));
      return {
        toolId: tool.toolId,
        tool: tool.tool,
        weightedFindings: tool.weightedFindings,
        qualityScore,
        scoreContribution: contribution
      };
    }).sort((left, right) => right.scoreContribution - left.scoreContribution);

    const aiQualityComponent = clamp(byTool.reduce((sum, tool) => sum + (tool.scoreContribution * 3), 0), 0, 25);
    const attributionCoverage = Number(findingAttribution.coverage || 0);
    const coverageComponent = attributionCoverage >= 60 ? 5 : attributionCoverage >= 30 ? 3 : 0;
    const score = Number(clamp(severityComponent + aiQualityComponent + coverageComponent, 0, 100).toFixed(1));
    const level = classifyRisk(score);
    const highestRiskTool = byTool[0] || null;

    let reason = 'Risk is driven primarily by current finding severity.';
    if (highestRiskTool && highestRiskTool.scoreContribution > 0) {
      reason = `${highestRiskTool.tool} contributes the largest AI-quality penalty in the current finding set.`;
    } else if (attributionCoverage === 0) {
      reason = 'No findings could be attributed back to AI-authored commits, so only severity contributes to PR risk.';
    }

    return {
      score,
      level,
      grade: gradeRisk(score),
      reason,
      components: {
        severity: Number(severityComponent.toFixed(1)),
        aiQuality: Number(aiQualityComponent.toFixed(1)),
        attributionCoverage: coverageComponent
      },
      byTool
    };
  }

  scoreRepositoryRisk(input = {}) {
    const findings = Array.isArray(input.findings) ? input.findings : [];
    const learnedProfile = input.learnedProfile || {};
    const findingAttribution = input.findingAttribution || {};

    const files = new Set();
    const directories = new Set();
    let weightedSeverity = 0;
    let knownFileRisk = 0;
    let hotDirectoryHits = 0;
    let novelPaths = 0;

    for (const finding of findings) {
      const filePath = String(finding.file_path || finding.file || '').replace(/\\/g, '/');
      const directory = filePath.includes('/') ? filePath.split('/').slice(0, -1).join('/') : '.';
      const fileRisk = Number(learnedProfile.fileRiskScores?.[filePath]?.score || 0);
      const hotDirectory = Number(learnedProfile.hotDirectories?.[directory]?.frequency || 0);

      files.add(filePath);
      directories.add(directory);
      weightedSeverity += severityWeight(finding.severity);
      knownFileRisk += fileRisk;
      hotDirectoryHits += hotDirectory;
      if (!learnedProfile.fileRiskScores?.[filePath]) {
        novelPaths += 1;
      }
    }

    const findingsCount = Math.max(1, findings.length);
    const fileCount = Math.max(1, files.size);
    const severityComponent = clamp(weightedSeverity * 2.5, 0, 30);
    const fileRiskComponent = clamp((knownFileRisk / fileCount) * 20, 0, 20);
    const historicalDirs = Object.keys(learnedProfile.hotDirectories || {}).length;
    const patternDeviationRatio = historicalDirs > 0
      ? clamp(1 - (hotDirectoryHits / Math.max(1, directories.size)), 0, 1)
      : 0.5;
    const patternDeviationComponent = Number((patternDeviationRatio * 20).toFixed(1));
    const concentrationRatio = files.size > 0 ? clamp(findings.length / fileCount / 3, 0, 1) : 0;
    const changeConcentrationComponent = Number((concentrationRatio * 10).toFixed(1));
    const aiCoverage = Number(findingAttribution.coverage || 0) / 100;
    const aiCodeDensityComponent = Number((clamp(aiCoverage, 0, 1) * 10).toFixed(1));
    const noveltyRatio = clamp(novelPaths / findingsCount, 0, 1);
    const noveltyComponent = Number((noveltyRatio * 10).toFixed(1));
    const score = Number(clamp(
      severityComponent +
      fileRiskComponent +
      patternDeviationComponent +
      changeConcentrationComponent +
      aiCodeDensityComponent +
      noveltyComponent,
      0,
      100
    ).toFixed(1));

    const elevatedFiles = Array.from(files).filter(filePath => Number(learnedProfile.fileRiskScores?.[filePath]?.score || 0) >= 0.6);
    let reason = 'Risk is driven by current finding severity and repo history.';
    if (elevatedFiles.length > 0) {
      reason = `${elevatedFiles.length} touched file(s) already carry elevated risk in this repo's history.`;
    } else if (novelPaths > 0) {
      reason = `${novelPaths} finding(s) land in files the repo history has not seen before, which raises novelty risk.`;
    } else if (aiCoverage > 0) {
      reason = `A portion of the current finding set is attributed to AI-authored code, which increases review risk in this repo.`;
    }

    return {
      score,
      level: classifyRisk(score),
      grade: gradeRisk(score),
      reason,
      components: {
        severity: Number(severityComponent.toFixed(1)),
        fileRiskHistory: Number(fileRiskComponent.toFixed(1)),
        patternDeviation: patternDeviationComponent,
        changeConcentration: changeConcentrationComponent,
        aiCodeDensity: aiCodeDensityComponent,
        novelty: noveltyComponent
      },
      repoContext: {
        personalizationScore: Number(learnedProfile.personalizationScore || 0),
        runCount: Number(learnedProfile.runCount || 0),
        touchedFiles: files.size,
        novelPaths,
        elevatedRiskFiles: elevatedFiles.slice(0, 10)
      }
    };
  }
}

module.exports = PRRiskScorer;
