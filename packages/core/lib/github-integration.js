/**
 * GitHub Actions Integration
 *
 * Provides PR inline review comments, commit status checks, fix PR creation,
 * and legacy workflow-output helpers.
 *
 * @module github-integration
 */

const https = require('https');

// ---------------------------------------------------------------------------
// Low-level GitHub REST helper
// ---------------------------------------------------------------------------

/**
 * Make an authenticated request to the GitHub REST API.
 *
 * @param {string} method  HTTP verb (GET, POST, PUT, PATCH, …)
 * @param {string} apiPath URL path, e.g. '/repos/owner/repo/pulls/1/reviews'
 * @param {object|null} body  Request body (will be JSON-serialised)
 * @param {string} token GitHub personal-access token or GITHUB_TOKEN
 * @returns {Promise<object>} Parsed JSON response
 */
async function githubRequest(method, apiPath, body, token) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const reqOptions = {
            hostname: 'api.github.com',
            path: apiPath,
            method,
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'CodeTitan/1.0',
                'Content-Type': 'application/json',
                ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
            },
        };

        const req = https.request(reqOptions, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch {
                    resolve(data);
                }
            });
        });

        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

// ---------------------------------------------------------------------------
// Finding → comment body formatter
// ---------------------------------------------------------------------------

/**
 * Build the body text for a single inline PR review comment.
 *
 * @param {object} finding
 * @returns {string}
 */
function formatFindingComment(finding) {
    const severityEmoji = {
        CRITICAL: '🔴',
        HIGH: '🟠',
        MEDIUM: '🟡',
        LOW: '🟢',
    }[finding.severity] || '⚪';

    const category = finding.category || finding.rule_id || 'ISSUE';
    let body = `**${severityEmoji} [${finding.severity}] ${category}**\n\n${finding.message}`;

    if (finding.suggestion) {
        body += `\n\n\`\`\`suggestion\n${finding.suggestion}\n\`\`\``;
    }

    if (finding.cwe) {
        body += `\n\n> CWE: ${finding.cwe}`;
    }

    body += '\n\n---\n*[CodeTitan](https://codetitan.dev)*';
    return body;
}

// Note: quality-gates module is used for reference but not directly imported

/**
 * GitHub Check Run statuses
 */
const CHECK_STATUSES = {
    QUEUED: 'queued',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
};

/**
 * GitHub Check Run conclusions
 */
const CHECK_CONCLUSIONS = {
    SUCCESS: 'success',
    FAILURE: 'failure',
    NEUTRAL: 'neutral',
    CANCELLED: 'cancelled',
    TIMED_OUT: 'timed_out',
    ACTION_REQUIRED: 'action_required',
};

/**
 * Format analysis results for GitHub PR comment
 */
function formatPRComment(analysisResult, options = {}) {
    const { showDetails = true, maxIssues = 10 } = options;

    const { issues, metrics, qualityGate } = analysisResult;

    let comment = `## 🔍 CodeTitan Analysis Results\n\n`;

    // Quality Gate Status
    if (qualityGate) {
        const icon = qualityGate.passed ? '✅' : '❌';
        comment += `### ${icon} Quality Gate: ${qualityGate.passed ? 'PASSED' : 'FAILED'}\n\n`;

        if (!qualityGate.passed) {
            comment += `| Condition | Expected | Actual | Status |\n`;
            comment += `|-----------|----------|--------|--------|\n`;
            qualityGate.conditions.filter(c => !c.passed).forEach(condition => {
                comment += `| ${condition.name} | ${condition.operator} ${condition.threshold} | ${condition.value} | ❌ |\n`;
            });
            comment += `\n`;
        }
    }

    // Summary Stats
    const critical = issues.filter(i => i.severity === 'CRITICAL').length;
    const high = issues.filter(i => i.severity === 'HIGH').length;
    const medium = issues.filter(i => i.severity === 'MEDIUM').length;
    const low = issues.filter(i => i.severity === 'LOW').length;

    comment += `### 📊 Summary\n\n`;
    comment += `| Severity | Count |\n`;
    comment += `|----------|-------|\n`;
    comment += `| 🔴 Critical | ${critical} |\n`;
    comment += `| 🟠 High | ${high} |\n`;
    comment += `| 🟡 Medium | ${medium} |\n`;
    comment += `| 🟢 Low | ${low} |\n`;
    comment += `| **Total** | **${issues.length}** |\n\n`;

    // Issue Details
    if (showDetails && issues.length > 0) {
        comment += `### 🐛 Issues Found\n\n`;

        const displayIssues = issues.slice(0, maxIssues);
        displayIssues.forEach((issue, idx) => {
            const severityIcon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
            }[issue.severity] || '⚪';

            comment += `<details>\n`;
            comment += `<summary>${severityIcon} <strong>${issue.category}</strong> in <code>${issue.file}:${issue.line}</code></summary>\n\n`;
            comment += `**Message:** ${issue.message}\n\n`;
            if (issue.snippet) {
                comment += `**Code:**\n\`\`\`\n${issue.snippet}\n\`\`\`\n\n`;
            }
            if (issue.cwe) {
                comment += `**CWE:** ${issue.cwe}\n`;
            }
            comment += `</details>\n\n`;
        });

        if (issues.length > maxIssues) {
            comment += `> **Note:** Showing ${maxIssues} of ${issues.length} issues. View full report in the dashboard.\n\n`;
        }
    }

    // Footer
    comment += `---\n`;
    comment += `*Analyzed by [CodeTitan](https://codetitan.dev) 🚀*\n`;

    return comment;
}

/**
 * Format check run output for GitHub API
 */
function formatCheckRun(analysisResult, options = {}) {
    const { issues, metrics, qualityGate } = analysisResult;

    const conclusion = qualityGate?.passed ? CHECK_CONCLUSIONS.SUCCESS : CHECK_CONCLUSIONS.FAILURE;

    const annotations = issues.slice(0, 50).map(issue => ({
        path: issue.file,
        start_line: issue.line,
        end_line: issue.endLine || issue.line,
        annotation_level: mapSeverityToLevel(issue.severity),
        message: issue.message,
        title: `${issue.category} (${issue.severity})`,
        raw_details: issue.snippet || '',
    }));

    return {
        name: 'CodeTitan Security Analysis',
        status: CHECK_STATUSES.COMPLETED,
        conclusion,
        output: {
            title: qualityGate?.passed
                ? `✅ Analysis Passed - ${issues.length} issues found`
                : `❌ Analysis Failed - ${issues.length} issues found`,
            summary: generateSummary(issues, qualityGate),
            annotations,
        },
    };
}

/**
 * Map severity to GitHub annotation level
 */
function mapSeverityToLevel(severity) {
    switch (severity) {
        case 'CRITICAL':
        case 'HIGH':
            return 'failure';
        case 'MEDIUM':
            return 'warning';
        case 'LOW':
            return 'notice';
        default:
            return 'notice';
    }
}

/**
 * Generate summary for check run
 */
function generateSummary(issues, qualityGate) {
    const critical = issues.filter(i => i.severity === 'CRITICAL').length;
    const high = issues.filter(i => i.severity === 'HIGH').length;
    const medium = issues.filter(i => i.severity === 'MEDIUM').length;
    const low = issues.filter(i => i.severity === 'LOW').length;

    let summary = `## CodeTitan Analysis\n\n`;
    summary += `| Metric | Value |\n`;
    summary += `|--------|-------|\n`;
    summary += `| Critical Issues | ${critical} |\n`;
    summary += `| High Issues | ${high} |\n`;
    summary += `| Medium Issues | ${medium} |\n`;
    summary += `| Low Issues | ${low} |\n`;
    summary += `| Total Issues | ${issues.length} |\n\n`;

    if (qualityGate) {
        summary += `### Quality Gate\n\n`;
        summary += qualityGate.passed
            ? `✅ **PASSED** - All conditions met\n`
            : `❌ **FAILED** - ${qualityGate.conditions.filter(c => !c.passed).length} condition(s) not met\n`;
    }

    return summary;
}

/**
 * GitHub Actions workflow output
 */
function formatWorkflowOutput(analysisResult) {
    const { issues, qualityGate } = analysisResult;

    const outputs = {
        total_issues: issues.length,
        critical_issues: issues.filter(i => i.severity === 'CRITICAL').length,
        high_issues: issues.filter(i => i.severity === 'HIGH').length,
        medium_issues: issues.filter(i => i.severity === 'MEDIUM').length,
        low_issues: issues.filter(i => i.severity === 'LOW').length,
        quality_gate_passed: qualityGate?.passed ?? true,
        quality_gate_status: qualityGate?.passed ? 'passed' : 'failed',
    };

    // Output in GitHub Actions format
    let output = '';
    Object.entries(outputs).forEach(([key, value]) => {
        output += `::set-output name=${key}::${value}\n`;
    });

    // Also add summary to step summary
    output += `\n## CodeTitan Analysis Summary\n`;
    output += `| Metric | Value |\n`;
    output += `|--------|-------|\n`;
    Object.entries(outputs).forEach(([key, value]) => {
        const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        output += `| ${formattedKey} | ${value} |\n`;
    });

    return output;
}

/**
 * Create GitHub Actions annotation command
 */
function createAnnotation(issue) {
    const level = mapSeverityToLevel(issue.severity);
    const file = issue.file;
    const line = issue.line;
    const endLine = issue.endLine || line;
    const col = issue.column || 1;
    const endCol = issue.endColumn || col;

    // GitHub Actions annotation format
    return `::${level === 'failure' ? 'error' : level} file=${file},line=${line},endLine=${endLine},col=${col},endColumn=${endCol}::${issue.message}`;
}

/**
 * Output all annotations for GitHub Actions
 */
function outputAnnotations(issues) {
    return issues.map(createAnnotation).join('\n');
}

// ---------------------------------------------------------------------------
// postPRAnnotations
// ---------------------------------------------------------------------------

/**
 * Post all findings as a single GitHub PR review with inline comments.
 *
 * Uses POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews so that every
 * comment is grouped in one review rather than flooding the PR with individual
 * timeline events.
 *
 * @param {object[]} findings  Array of finding objects from the JSON report
 * @param {object}   options
 * @param {string}   options.owner     Repository owner (user or org)
 * @param {string}   options.repo      Repository name
 * @param {string|number} options.prNumber  Pull-request number
 * @param {string}   options.commitSha Full commit SHA being reviewed
 * @param {string}   options.token     GitHub token with pull-requests:write scope
 * @returns {Promise<object>} GitHub API response
 */
async function postPRAnnotations(findings, options) {
    const { owner, repo, prNumber, commitSha, token } = options;

    if (!token) throw new Error('postPRAnnotations: GitHub token is required');
    if (!owner || !repo || !prNumber || !commitSha) {
        throw new Error('postPRAnnotations: owner, repo, prNumber, and commitSha are required');
    }

    // Cap at 50 — GitHub's hard limit for review comments per request
    const capped = findings.slice(0, 50);

    const comments = capped
        .filter((f) => f.file_path || f.file)
        .map((f) => ({
            path: (f.file_path || f.file).replace(/\\/g, '/'),
            line: f.line_number || f.line || 1,
            side: 'RIGHT',
            body: formatFindingComment(f),
        }));

    const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = findings.filter((f) => f.severity === 'HIGH').length;

    const overallBody =
        `## CodeTitan Security Analysis\n\n` +
        `Found **${findings.length}** issue(s): ` +
        `${criticalCount} critical, ${highCount} high.\n\n` +
        (findings.length > 50
            ? `> Showing 50 of ${findings.length} findings. View the full report in the workflow artifacts.\n\n`
            : '') +
        `_Powered by [CodeTitan](https://codetitan.dev)_`;

    const reviewBody = {
        commit_id: commitSha,
        body: overallBody,
        event: 'COMMENT',
        comments,
    };

    return githubRequest(
        'POST',
        `/repos/${owner}/${repo}/pulls/${prNumber}/reviews`,
        reviewBody,
        token,
    );
}

// ---------------------------------------------------------------------------
// postStatusCheck
// ---------------------------------------------------------------------------

/**
 * Post a commit status check (the coloured dot next to a SHA).
 *
 * @param {object} summary   Summary object, e.g. { critical: 2, high: 5 }
 * @param {object} options
 * @param {string} options.owner
 * @param {string} options.repo
 * @param {string} options.commitSha
 * @param {string} options.token
 * @returns {Promise<object>} GitHub API response
 */
async function postStatusCheck(summary, options) {
    const { owner, repo, commitSha, token } = options;

    if (!token) throw new Error('postStatusCheck: GitHub token is required');
    if (!owner || !repo || !commitSha) {
        throw new Error('postStatusCheck: owner, repo, and commitSha are required');
    }

    const critical = summary.critical ?? summary.criticalCount ?? 0;
    const high = summary.high ?? summary.highCount ?? 0;

    const passed = critical === 0 && high === 0;

    const statusBody = {
        state: passed ? 'success' : 'failure',
        target_url: 'https://codetitan.dev',
        description: passed
            ? 'All checks passed'
            : `${critical} critical, ${high} high findings`,
        context: 'CodeTitan / security',
    };

    return githubRequest(
        'POST',
        `/repos/${owner}/${repo}/statuses/${commitSha}`,
        statusBody,
        token,
    );
}

// ---------------------------------------------------------------------------
// createFixPR
// ---------------------------------------------------------------------------

/**
 * Create a new branch, commit auto-fix file updates, then open a PR.
 *
 * @param {object[]} fixes   Array of { file, original, fixed, message }
 * @param {object}   options
 * @param {string}   options.owner
 * @param {string}   options.repo
 * @param {string}   options.baseBranch  Base branch to branch from (e.g. 'main')
 * @param {string}   options.token
 * @returns {Promise<string>} URL of the created pull request
 */
async function createFixPR(fixes, options) {
    const { owner, repo, baseBranch = 'main', token } = options;

    if (!token) throw new Error('createFixPR: GitHub token is required');
    if (!owner || !repo) throw new Error('createFixPR: owner and repo are required');
    if (!fixes || fixes.length === 0) throw new Error('createFixPR: no fixes provided');

    const timestamp = Date.now();
    const newBranch = `codetitan-fixes-${timestamp}`;

    // 1. Resolve the SHA of the tip of baseBranch
    const baseRef = await githubRequest(
        'GET',
        `/repos/${owner}/${repo}/git/ref/heads/${baseBranch}`,
        null,
        token,
    );

    if (!baseRef.object || !baseRef.object.sha) {
        throw new Error(`createFixPR: could not resolve SHA for branch '${baseBranch}': ${JSON.stringify(baseRef)}`);
    }

    const baseSha = baseRef.object.sha;

    // 2. Create the new branch from that SHA
    await githubRequest(
        'POST',
        `/repos/${owner}/${repo}/git/refs`,
        { ref: `refs/heads/${newBranch}`, sha: baseSha },
        token,
    );

    // 3. Commit each file change onto the new branch
    const appliedFiles = [];

    for (const fix of fixes) {
        const filePath = (fix.file || '').replace(/\\/g, '/');
        if (!filePath || !fix.fixed) continue;

        // Fetch current file metadata to get its blob SHA
        const fileInfo = await githubRequest(
            'GET',
            `/repos/${owner}/${repo}/contents/${filePath}?ref=${newBranch}`,
            null,
            token,
        );

        if (!fileInfo.sha) {
            console.warn(`createFixPR: could not get SHA for ${filePath}, skipping`);
            continue;
        }

        const contentEncoded = Buffer.from(fix.fixed, 'utf8').toString('base64');

        await githubRequest(
            'PUT',
            `/repos/${owner}/${repo}/contents/${filePath}`,
            {
                message: `fix: ${fix.message || `auto-fix in ${filePath}`}`,
                content: contentEncoded,
                sha: fileInfo.sha,
                branch: newBranch,
            },
            token,
        );

        appliedFiles.push(filePath);
    }

    if (appliedFiles.length === 0) {
        throw new Error('createFixPR: no files were successfully updated');
    }

    // 4. Build PR description table
    const tableRows = fixes
        .filter((f) => appliedFiles.includes((f.file || '').replace(/\\/g, '/')))
        .map((f) => `| \`${(f.file || '').replace(/\\/g, '/')}\` | ${f.message || '—'} |`)
        .join('\n');

    const prBody =
        `## CodeTitan Auto-Fix PR\n\n` +
        `This pull request was automatically created by CodeTitan to resolve **${appliedFiles.length}** detected issue(s).\n\n` +
        `| File | Issue |\n` +
        `|------|-------|\n` +
        `${tableRows}\n\n` +
        `> Review each change carefully before merging.\n\n` +
        `_Generated by [CodeTitan](https://codetitan.dev)_`;

    // 5. Open the PR
    const pr = await githubRequest(
        'POST',
        `/repos/${owner}/${repo}/pulls`,
        {
            title: `fix: CodeTitan auto-fixes (${appliedFiles.length} issue${appliedFiles.length === 1 ? '' : 's'})`,
            body: prBody,
            head: newBranch,
            base: baseBranch,
        },
        token,
    );

    if (!pr.html_url) {
        throw new Error(`createFixPR: PR creation failed: ${JSON.stringify(pr)}`);
    }

    return pr.html_url;
}

module.exports = {
    githubRequest,
    postPRAnnotations,
    postStatusCheck,
    createFixPR,
    formatPRComment,
    formatCheckRun,
    formatWorkflowOutput,
    createAnnotation,
    outputAnnotations,
    CHECK_STATUSES,
    CHECK_CONCLUSIONS,
};
