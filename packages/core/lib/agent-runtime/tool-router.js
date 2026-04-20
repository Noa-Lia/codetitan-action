const {
  createEvidenceItem,
  createToolResult,
  truncateText
} = require('./result-contracts');

class ToolRouter {
  constructor({ toolBridge, logger = console } = {}) {
    if (!toolBridge) {
      throw new Error('ToolRouter requires a toolBridge instance');
    }

    this.toolBridge = toolBridge;
    this.logger = logger;
  }

  async execute(definition, input = {}, context = null) {
    switch (definition.name) {
      case 'read_file':
        return this.readFile(input);
      case 'list_files':
        return this.listFiles(input);
      case 'analyze_path':
        return this.analyzePath(input);
      case 'search_code':
        return this.searchCode(input);
      case 'run_tests':
        return this.runTests(input);
      case 'git_status':
        return this.gitStatus(input);
      case 'git_diff':
        return this.gitDiff(input);
      case 'fetch_history':
        return this.fetchHistory(input);
      case 'compare_runs':
        return this.compareRuns(input);
      case 'create_worktree':
        return this.createWorktree(input, context);
      case 'edit_file':
        return this.editFile(input);
      case 'promote_worktree':
        return this.promoteWorktree(input, context);
      case 'browse_web':
        return this.browseWeb(input);
      case 'post_github_review':
        return this.postGitHubReview(input);
      case 'submit_fix_candidate':
        return this.submitFixCandidate(input);
      default:
        return createToolResult({
          tool: definition.name,
          success: false,
          input,
          error: `Tool not implemented: ${definition.name}`
        });
    }
  }

  async readFile(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.read(input.file);

    if (!raw.success) {
      return createToolResult({
        tool: 'read_file',
        success: false,
        input,
        error: raw.error,
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'read_file',
      success: true,
      input,
      data: {
        filePath: raw.filePath,
        content: raw.content,
        size: raw.size,
        lines: raw.lines
      },
      evidence: [
        createEvidenceItem({
          kind: 'file_read',
          source: raw.filePath,
          summary: `Read ${raw.filePath} (${raw.lines} lines).`,
          data: {
            filePath: raw.filePath,
            size: raw.size,
            lines: raw.lines
          }
        })
      ],
      metadata: {
        outputSummary: `Read ${raw.filePath} (${raw.lines} lines).`,
        usage: {
          bytesTouched: raw.size || 0,
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async listFiles(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.listFiles(input.path, input.options || {});

    if (!Array.isArray(raw)) {
      return createToolResult({
        tool: 'list_files',
        success: false,
        input,
        error: raw && raw.error ? raw.error : 'Unable to list files',
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'list_files',
      success: true,
      input,
      data: {
        basePath: input.path,
        entries: raw
      },
      evidence: [
        createEvidenceItem({
          kind: 'directory_listing',
          source: input.path,
          summary: `Listed ${raw.length} entries under ${input.path}.`,
          data: {
            basePath: input.path,
            entryCount: raw.length
          }
        })
      ],
      metadata: {
        outputSummary: `Listed ${raw.length} entries under ${input.path}.`,
        usage: {
          bytesTouched: Buffer.byteLength(JSON.stringify(raw), 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async analyzePath(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.analyzeFile(input.path);

    if (!raw.success) {
      return createToolResult({
        tool: 'analyze_path',
        success: false,
        input,
        error: raw.error,
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'analyze_path',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'analysis',
          source: raw.filePath,
          summary: `Analyzed ${raw.filePath}: ${raw.lines} lines, complexity ${raw.complexity.level}.`,
          data: {
            filePath: raw.filePath,
            lines: raw.lines,
            complexity: raw.complexity
          }
        })
      ],
      metadata: {
        outputSummary: `Analyzed ${raw.filePath} (${raw.lines} lines, ${raw.complexity.level} complexity).`,
        usage: {
          bytesTouched: raw.size || 0,
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async searchCode(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.searchCode(input.query, {
      path: input.path || '.',
      caseSensitive: input.caseSensitive,
      maxResults: input.maxResults,
      extension: input.extension,
      extensions: input.extensions
    });

    if (!raw.success) {
      return createToolResult({
        tool: 'search_code',
        success: false,
        input,
        error: raw.error,
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'search_code',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'search',
          source: raw.basePath,
          summary: `Found ${raw.matches.length} match(es) for "${raw.query}" under ${raw.basePath}.`,
          data: {
            query: raw.query,
            matches: raw.matches.length,
            filesScanned: raw.filesScanned
          }
        })
      ],
      metadata: {
        outputSummary: `Found ${raw.matches.length} match(es) for "${raw.query}" under ${raw.basePath}.`,
        usage: {
          bytesTouched: Buffer.byteLength(JSON.stringify(raw.matches || []), 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async runTests(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.runTests(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'run_tests',
        success: false,
        input,
        error: raw.error || raw.stderr || `Command exited with status ${raw.exitCode}`,
        data: {
          command: raw.command,
          args: raw.args || [],
          cwd: raw.cwd,
          exitCode: raw.exitCode,
          stdout: truncateText(raw.stdout || '', 1200),
          stderr: truncateText(raw.stderr || '', 1200),
          passed: false
        },
        evidence: [
          createEvidenceItem({
            kind: 'test_run',
            source: raw.cwd || input.cwd || '.',
            summary: `Test command ${[raw.command, ...(raw.args || [])].filter(Boolean).join(' ')} failed with exit code ${raw.exitCode}.`,
            data: {
              command: raw.command,
              exitCode: raw.exitCode
            }
          })
        ],
        metadata: {
          outputSummary: `Test command ${[raw.command, ...(raw.args || [])].filter(Boolean).join(' ')} failed.`,
          usage: {
            bytesTouched: Buffer.byteLength(`${raw.stdout || ''}${raw.stderr || ''}`, 'utf8'),
            tokensTouched: 0
          }
        },
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'run_tests',
      success: true,
      input,
      data: {
        command: raw.command,
        args: raw.args || [],
        cwd: raw.cwd,
        exitCode: raw.exitCode,
        stdout: truncateText(raw.stdout || '', 1200),
        stderr: truncateText(raw.stderr || '', 1200),
        passed: true
      },
      evidence: [
        createEvidenceItem({
          kind: 'test_run',
          source: raw.cwd || input.cwd || '.',
          summary: `Test command ${[raw.command, ...(raw.args || [])].filter(Boolean).join(' ')} passed.`,
          data: {
            command: raw.command,
            exitCode: raw.exitCode
          }
        })
      ],
      metadata: {
        outputSummary: `Test command ${[raw.command, ...(raw.args || [])].filter(Boolean).join(' ')} passed.`,
        usage: {
          bytesTouched: Buffer.byteLength(`${raw.stdout || ''}${raw.stderr || ''}`, 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async gitStatus(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.gitStatus(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'git_status',
        success: false,
        input,
        error: raw.error || raw.stderr || 'Unable to inspect git status',
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'git_status',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'git_status',
          source: raw.cwd || input.cwd || '.',
          summary: `Git status on ${raw.branch || 'working tree'} shows ${raw.files.length} changed file(s).`,
          data: {
            branch: raw.branch,
            changedFiles: raw.files.length,
            clean: raw.clean
          }
        })
      ],
      metadata: {
        outputSummary: `Git status on ${raw.branch || 'working tree'} (${raw.files.length} changed file(s)).`,
        usage: {
          bytesTouched: Buffer.byteLength(`${raw.stdout || ''}${raw.stderr || ''}`, 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async gitDiff(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.gitDiff(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'git_diff',
        success: false,
        input,
        error: raw.error || raw.stderr || 'Unable to capture git diff',
        startedAt,
        finishedAt: Date.now()
      });
    }

    const additions = (raw.diff.match(/^\+(?!\+\+)/gm) || []).length;
    const deletions = (raw.diff.match(/^-(?!---)/gm) || []).length;

    return createToolResult({
      tool: 'git_diff',
      success: true,
      input,
      data: {
        ...raw,
        additions,
        deletions,
        diff: truncateText(raw.diff || '', 4000)
      },
      evidence: [
        createEvidenceItem({
          kind: 'git_diff',
          source: raw.cwd || input.cwd || '.',
          summary: `Captured git diff for ${raw.filesChanged} file(s) (+${additions}/-${deletions}).`,
          data: {
            filesChanged: raw.filesChanged,
            additions,
            deletions
          }
        })
      ],
      metadata: {
        outputSummary: `Captured git diff for ${raw.filesChanged} file(s) (+${additions}/-${deletions}).`,
        usage: {
          bytesTouched: Buffer.byteLength(raw.diff || '', 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async fetchHistory(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.fetchHistory(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'fetch_history',
        success: false,
        input,
        error: raw.error || 'Unable to load history',
        startedAt,
        finishedAt: Date.now()
      });
    }

    const summary = raw.run
      ? `Loaded run ${raw.run.runId} (${raw.run.total || 0} finding(s)).`
      : `Loaded ${(raw.runs || []).length} run(s) for ${raw.projectPath}.`;

    return createToolResult({
      tool: 'fetch_history',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'history',
          source: raw.projectPath,
          summary,
          data: {
            runId: raw.run ? raw.run.runId : null,
            runCount: raw.runCount || (raw.runs || []).length
          }
        })
      ],
      metadata: {
        outputSummary: summary,
        usage: {
          bytesTouched: Buffer.byteLength(JSON.stringify(raw), 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async compareRuns(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.compareRuns(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'compare_runs',
        success: false,
        input,
        error: raw.error || 'Unable to compare runs',
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'compare_runs',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'history_compare',
          source: raw.projectPath,
          summary: `Compared ${raw.baseline.runId} to ${raw.current.runId}: +${raw.added.length} added, -${raw.fixed.length} fixed.`,
          data: {
            baselineRunId: raw.baseline.runId,
            currentRunId: raw.current.runId,
            added: raw.added.length,
            fixed: raw.fixed.length,
            unchanged: raw.unchanged.length
          }
        })
      ],
      metadata: {
        outputSummary: `Compared ${raw.baseline.runId} to ${raw.current.runId} (+${raw.added.length}/-${raw.fixed.length}).`,
        usage: {
          bytesTouched: Buffer.byteLength(JSON.stringify(raw), 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async createWorktree(input, context = null) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.createWorktree(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'create_worktree',
        success: false,
        input,
        error: raw.error || 'Unable to create isolated workspace',
        startedAt,
        finishedAt: Date.now()
      });
    }

    if (context && typeof context.registerWorkspace === 'function') {
      context.registerWorkspace(raw);

      if (typeof context.addArtifact === 'function') {
        context.addArtifact({
          kind: 'workspace',
          id: raw.id || null,
          name: raw.name || null,
          path: raw.path,
          mode: raw.mode || null
        });
      }

      if (typeof context.registerCleanup === 'function' && typeof this.toolBridge.removeWorktree === 'function') {
        context.registerCleanup(`remove_worktree:${raw.id || raw.path}`, async () => {
          const removal = await this.toolBridge.removeWorktree({
            handleId: raw.id || null,
            path: raw.path
          });

          if (!removal.success) {
            throw new Error(removal.error || `Unable to remove workspace ${raw.path}`);
          }

          if (typeof context.markWorkspaceCleanedUp === 'function') {
            context.markWorkspaceCleanedUp(raw);
          }
        });
      }
    }

    return createToolResult({
      tool: 'create_worktree',
      success: true,
      input,
      data: {
        id: raw.id || null,
        name: raw.name || input.name || null,
        path: raw.path,
        mode: raw.mode || null,
        baseDir: raw.baseDir || input.baseDir || null,
        ref: raw.ref || input.ref || null,
        fallbackReason: raw.fallbackReason || null
      },
      evidence: [
        createEvidenceItem({
          kind: 'workspace',
          source: raw.path,
          summary: `Created ${raw.mode || 'isolated'} workspace at ${raw.path}.`,
          data: {
            id: raw.id || null,
            mode: raw.mode || null,
            baseDir: raw.baseDir || input.baseDir || null
          }
        })
      ],
      metadata: {
        outputSummary: `Created ${raw.mode || 'isolated'} workspace at ${raw.path}.`,
        usage: {
          bytesTouched: 0,
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async editFile(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.edit(input.file, input.oldString, input.newString);

    if (!raw.success) {
      return createToolResult({
        tool: 'edit_file',
        success: false,
        input,
        error: raw.error || 'Unable to edit file',
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'edit_file',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'workspace_edit',
          source: raw.filePath,
          summary: `Edited ${raw.filePath} in isolated workspace using an explicit replacement.`,
          data: {
            filePath: raw.filePath,
            absolutePath: raw.absolutePath,
            difference: raw.difference
          }
        })
      ],
      metadata: {
        outputSummary: `Edited ${raw.filePath} in isolated workspace.`,
        usage: {
          bytesTouched: Math.max(raw.oldLength || 0, raw.newLength || 0),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async promoteWorktree(input, context = null) {
    const startedAt = Date.now();
    const workspace = context && typeof context.getPrimaryWorkspace === 'function'
      ? context.getPrimaryWorkspace()
      : null;
    const raw = await this.toolBridge.promoteWorktree({
      handleId: input.handleId || (workspace ? workspace.id : null),
      path: input.path || (workspace ? workspace.path : null),
      files: input.files || []
    });

    if (!raw.success) {
      return createToolResult({
        tool: 'promote_worktree',
        success: false,
        input,
        error: raw.error || 'Unable to promote files from isolated workspace',
        startedAt,
        finishedAt: Date.now()
      });
    }

    if (context && typeof context.addArtifact === 'function') {
      context.addArtifact({
        kind: 'promotion',
        files: raw.files || [],
        workspace: workspace ? workspace.path : raw.path
      });
    }

    return createToolResult({
      tool: 'promote_worktree',
      success: true,
      input,
      data: {
        files: raw.files || [],
        workspacePath: workspace ? workspace.path : raw.path,
        promotedPath: raw.path
      },
      evidence: [
        createEvidenceItem({
          kind: 'workspace_promotion',
          source: workspace ? workspace.path : raw.path,
          summary: `Promoted ${(raw.files || []).length} file(s) from the isolated workspace into the repository.`,
          data: {
            files: raw.files || []
          }
        })
      ],
      metadata: {
        outputSummary: `Promoted ${(raw.files || []).length} file(s) from the isolated workspace into the repository.`,
        usage: {
          bytesTouched: 0,
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async submitFixCandidate(input) {
    const startedAt = Date.now();
    const candidates = Array.isArray(input.candidates) ? input.candidates : [];

    if (candidates.length === 0) {
      return createToolResult({
        tool: 'submit_fix_candidate',
        success: false,
        input,
        error: 'No fix candidates were supplied',
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'submit_fix_candidate',
      success: true,
      input,
      data: {
        candidates
      },
      evidence: [
        createEvidenceItem({
          kind: 'fix_candidate',
          source: input.file || 'runtime',
          summary: `Recorded ${candidates.length} fix candidate(s).`,
          data: {
            candidateCount: candidates.length
          }
        })
      ],
      metadata: {
        outputSummary: `Recorded ${candidates.length} fix candidate(s).`,
        usage: {
          bytesTouched: Buffer.byteLength(JSON.stringify(candidates), 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async browseWeb(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.browseWeb(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'browse_web',
        success: false,
        input,
        error: raw.error || 'Unable to browse web content',
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'browse_web',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'web_observation',
          source: raw.url,
          summary: `Browsed ${raw.url} using ${raw.action || 'read'} and captured ${raw.itemCount || 0} item(s).`,
          data: {
            url: raw.url,
            action: raw.action || 'read',
            itemCount: raw.itemCount || 0
          }
        })
      ],
      metadata: {
        outputSummary: `Browsed ${raw.url} using ${raw.action || 'read'}.`,
        usage: {
          bytesTouched: raw.bytesTouched || Buffer.byteLength(raw.text || '', 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }

  async postGitHubReview(input) {
    const startedAt = Date.now();
    const raw = await this.toolBridge.postGitHubReview(input);

    if (!raw.success) {
      return createToolResult({
        tool: 'post_github_review',
        success: false,
        input,
        error: raw.error || 'Unable to post GitHub review',
        startedAt,
        finishedAt: Date.now()
      });
    }

    return createToolResult({
      tool: 'post_github_review',
      success: true,
      input,
      data: raw,
      evidence: [
        createEvidenceItem({
          kind: 'github_review',
          source: `${raw.owner}/${raw.repo}#${raw.prNumber}`,
          summary: `Posted ${raw.commentCount || 0} GitHub review comment(s) to ${raw.owner}/${raw.repo}#${raw.prNumber}.`,
          data: {
            reviewId: raw.reviewId,
            commentCount: raw.commentCount || 0
          }
        })
      ],
      metadata: {
        outputSummary: `Posted GitHub review to ${raw.owner}/${raw.repo}#${raw.prNumber}.`,
        usage: {
          bytesTouched: Buffer.byteLength(JSON.stringify(input.findings || []), 'utf8'),
          tokensTouched: 0
        }
      },
      startedAt,
      finishedAt: Date.now()
    });
  }
}

module.exports = ToolRouter;
