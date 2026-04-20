const path = require('path');

const ExecutionContext = require('./execution-context');
const { resolveBudgetPolicy, resolveReasoningMode, resolveRoleProfile } = require('./role-profiles');
const {
  createEvidenceItem,
  createTaskResult,
  materializeLegacyResult,
  summarizeEvidence,
  truncateText
} = require('./result-contracts');

class Planner {
  constructor({
    toolRegistry,
    toolRouter,
    guardrails,
    maxSteps = 6,
    providerManager = null
  } = {}) {
    if (!toolRegistry || !toolRouter || !guardrails) {
      throw new Error('Planner requires toolRegistry, toolRouter, and guardrails');
    }

    this.toolRegistry = toolRegistry;
    this.toolRouter = toolRouter;
    this.guardrails = guardrails;
    this.maxSteps = maxSteps;
    this.providerManager = providerManager;
  }

  async execute({ skill = {}, interpretation = {}, task = {} } = {}) {
    const taskType = (interpretation.execution_strategy && interpretation.execution_strategy !== 'generic')
      ? interpretation.execution_strategy
      : (task.action || interpretation.execution_strategy || 'generic');
    const resultType = this.getResultType(taskType);
    const roleProfile = resolveRoleProfile(skill, task);
    const reasoningMode = resolveReasoningMode(
      task?.metadata?.reasoningMode ||
      task?.reasoningMode ||
      task?.content?.reasoningMode
    );
    const budgetPolicy = this.providerManager && typeof this.providerManager.getBudgetPolicy === 'function'
      ? this.providerManager.getBudgetPolicy(roleProfile, reasoningMode, {
        toolBudget: {
          maxCalls: Math.min(this.maxSteps, roleProfile.toolBudget.maxCalls || this.maxSteps)
        }
      })
      : resolveBudgetPolicy(roleProfile, reasoningMode);
    const context = new ExecutionContext({
      agent: skill.name || 'unknown-agent',
      role: skill.role || '',
      roleProfile,
      capabilities: skill.capabilities || [],
      task,
      interpretation,
      reasoningMode,
      budget: {
        maxSteps: Math.min(this.maxSteps, budgetPolicy.toolBudget.maxCalls || this.maxSteps),
        tokenCap: budgetPolicy.promptBudget.tokenCap,
        usdCap: budgetPolicy.promptBudget.usdCap,
        toolCap: budgetPolicy.promptBudget.toolCap || budgetPolicy.toolBudget.maxCalls || this.maxSteps
      }
    });
    let taskResult = null;

    try {
      this.guardrails.assertTask(task);
      this.assertSafeMode(taskType, task);

      const steps = this.buildToolSequence(taskType, task);
      if (steps.length === 0) {
        taskResult = this.buildInsufficientResult(
          context,
          resultType,
          'No file or directory target was provided for runtime-backed execution.'
        );
      } else {
        for (const step of steps) {
          const toolResult = await this.executeStep(context, step);
          if (!toolResult.success && step.required !== false) {
            context.setVerificationStatus('failed');
            taskResult = this.buildFailureResult(context, resultType, toolResult.error || `${step.tool} failed`);
            break;
          }
        }

        if (!taskResult) {
          if (taskType === 'fix') {
            await this.recordFixCandidates(context);
          }

          this.setCompletionVerificationStatus(context, taskType);
          taskResult = this.buildTaskResult(context, taskType);
          await this.applyAdvisorValidation(context, taskResult, taskType);
        }
      }
    } catch (error) {
      context.setVerificationStatus('failed');
      taskResult = this.buildFailureResult(context, resultType, error.message);
    } finally {
      await context.runCleanup();
      if (taskResult && taskResult.runtime) {
        taskResult.runtime = {
          ...taskResult.runtime,
          ...context.getRuntimeTelemetry()
        };
      }
      if (taskResult && taskResult.data && taskResult.data.workspace) {
        const workspace = context.getPrimaryWorkspace();
        taskResult.data.workspace = workspace ? {
          path: workspace.path,
          mode: workspace.mode,
          cleaned_up: workspace.cleanedUp
        } : null;
      }
    }

    return materializeLegacyResult(taskResult);
  }

  buildToolSequence(taskType, task = {}) {
    const content = task.content || {};
    const fileTarget = this.resolveFileTarget(task);
    const referenceFile = content.referenceFile || null;
    const directoryTarget = this.resolveDirectoryTarget(task, fileTarget || referenceFile);
    const editRequest = this.resolveEditRequest(task);
    const steps = [];

    switch (taskType) {
      case 'analyze':
        if (fileTarget) {
          steps.push({ tool: 'analyze_path', input: { path: fileTarget }, required: true });
        } else if (content.query) {
          steps.push({
            tool: 'search_code',
            input: {
              query: content.query,
              path: directoryTarget || content.searchPath || '.',
              maxResults: content.maxResults,
              caseSensitive: content.caseSensitive,
              extension: content.extension,
              extensions: this.resolveSearchExtensions(task, taskType)
            },
            required: true
          });
        } else if (directoryTarget) {
          steps.push({ tool: 'list_files', input: { path: directoryTarget }, required: true });
        }
        break;
      case 'review':
        if (fileTarget) {
          steps.push({ tool: 'analyze_path', input: { path: fileTarget }, required: true });
          steps.push({ tool: 'read_file', input: { file: fileTarget }, required: false });
        } else if (directoryTarget) {
          steps.push({ tool: 'list_files', input: { path: directoryTarget }, required: true });
        }
        if (content.url || content.webUrl) {
          steps.push({
            tool: 'browse_web',
            input: {
              url: content.url || content.webUrl,
              action: content.webAction || 'read'
            },
            required: false
          });
        }
        if (content.query) {
          steps.push({
            tool: 'search_code',
            input: {
              query: content.query,
              path: directoryTarget || content.searchPath || '.',
              maxResults: content.maxResults,
              caseSensitive: content.caseSensitive,
              extension: content.extension,
              extensions: this.resolveSearchExtensions(task, taskType)
            },
            required: false
          });
        }
        break;
      case 'security-review': {
        if (fileTarget) {
          steps.push({ tool: 'analyze_path', input: { path: fileTarget }, required: false });
          steps.push({ tool: 'read_file', input: { file: fileTarget }, required: false });
        } else if (directoryTarget) {
          steps.push({ tool: 'list_files', input: { path: directoryTarget }, required: false });
        }
        if (content.url || content.webUrl) {
          steps.push({
            tool: 'browse_web',
            input: {
              url: content.url || content.webUrl,
              action: content.webAction || 'read'
            },
            required: false
          });
        }

        const searchBasePath = directoryTarget || content.searchPath || '.';
        const queries = this.resolveSecurityQueries(task);
        queries.forEach(query => {
          steps.push({
            tool: 'search_code',
            input: {
              query,
              path: searchBasePath,
              maxResults: content.maxResults,
              caseSensitive: content.caseSensitive,
              extension: content.extension,
              extensions: this.resolveSearchExtensions(task, taskType)
            },
            required: false
          });
        });
        break;
      }
      case 'replay':
        steps.push({
          tool: 'fetch_history',
          input: {
            projectPath: content.projectPath || '.',
            runId: content.runId,
            limit: content.limit
          },
          required: true
        });
        break;
      case 'compare':
        steps.push({
          tool: 'compare_runs',
          input: {
            projectPath: content.projectPath || '.',
            runA: content.runA || content.baselineRunId,
            runB: content.runB || content.currentRunId
          },
          required: true
        });
        break;
      case 'refactor':
      case 'optimize':
        if (fileTarget) {
          steps.push({ tool: 'analyze_path', input: { path: fileTarget }, required: true });
          steps.push({ tool: 'read_file', input: { file: fileTarget }, required: true });
        }
        break;
      case 'fix':
        if (fileTarget) {
          steps.push({ tool: 'analyze_path', input: { path: fileTarget }, required: true });
          steps.push({ tool: 'read_file', input: { file: fileTarget }, required: true });
          steps.push({
            tool: 'create_worktree',
            input: this.buildWorktreeInput(task, fileTarget),
            required: true
          });
          if (editRequest) {
            steps.push({
              tool: 'edit_file',
              input: {
                file: fileTarget,
                oldString: editRequest.oldString,
                newString: editRequest.newString
              },
              scope: {
                file: 'workspace'
              },
              required: true
            });
            steps.push({
              tool: 'git_diff',
              input: {
                cwd: '.',
                file: fileTarget
              },
              scope: {
                cwd: 'workspace'
              },
              required: false
            });
            if (content.command) {
              steps.push({
                tool: 'run_tests',
                input: {
                  command: content.command,
                  args: content.args || [],
                  cwd: content.cwd || '.',
                  timeoutMs: content.timeoutMs
                },
                scope: {
                  cwd: 'workspace'
                },
                required: true
              });
            }
            if (content.promote === true) {
              steps.push({
                tool: 'promote_worktree',
                input: {
                  files: this.resolvePromotionFiles(task, fileTarget)
                },
                required: true
              });
            }
          }
        }
        break;
      case 'test':
      case 'validate':
        steps.push({
          tool: 'git_status',
          input: {
            cwd: directoryTarget || content.cwd || '.'
          },
          required: false
        });
        if (fileTarget || content.base || content.head || content.cached || Array.isArray(content.paths)) {
          steps.push({
            tool: 'git_diff',
            input: {
              cwd: directoryTarget || content.cwd || '.',
              file: fileTarget || null,
              paths: content.paths,
              base: content.base,
              head: content.head,
              cached: content.cached,
              unified: content.unified
            },
            required: false
          });
        }
        if (content.command) {
          steps.push({
            tool: 'run_tests',
            input: {
              command: content.command,
              args: content.args || [],
              cwd: content.cwd || directoryTarget || '.',
              timeoutMs: content.timeoutMs
            },
            required: true
          });
        } else if (!fileTarget && !directoryTarget) {
          return [];
        }
        break;
      case 'design':
        if (directoryTarget) {
          steps.push({ tool: 'list_files', input: { path: directoryTarget }, required: true });
        }
        if (fileTarget) {
          steps.push({ tool: 'analyze_path', input: { path: fileTarget }, required: false });
          steps.push({ tool: 'read_file', input: { file: fileTarget }, required: false });
        }
        break;
      case 'generate':
        if (directoryTarget) {
          steps.push({ tool: 'list_files', input: { path: directoryTarget }, required: false });
        }
        if (referenceFile) {
          steps.push({ tool: 'read_file', input: { file: referenceFile }, required: false });
        }
        break;
      default:
        if (fileTarget) {
          steps.push({ tool: 'analyze_path', input: { path: fileTarget }, required: false });
        } else if (directoryTarget) {
          steps.push({ tool: 'list_files', input: { path: directoryTarget }, required: false });
        }
        break;
    }

    return steps;
  }

  async executeStep(context, step) {
    const resolvedInput = this.resolveStepInput(context, step);
    const definition = this.toolRegistry.get(step.tool);
    const validation = this.toolRegistry.validate(step.tool, resolvedInput);

    if (!validation.valid) {
      throw new Error(`Invalid input for ${step.tool}: ${validation.errors.join(', ')}`);
    }

    this.guardrails.assertStepBudget(context);
    this.guardrails.assertTool(definition, resolvedInput, context);
    this.assertStepPolicy(context, step, resolvedInput);

    const toolResult = await this.toolRouter.execute(definition, resolvedInput, context);
    context.recordToolInvocation(definition, toolResult);
    this.recordStepState(context, step.tool, toolResult);

    return toolResult;
  }

  async recordFixCandidates(context) {
    if (context.getLatestToolData('edit_file')) {
      return;
    }

    const analysis = context.getLatestToolData('analyze_path');
    if (!analysis) {
      return;
    }

    const errors = Array.isArray(context.task.content && context.task.content.errors)
      ? context.task.content.errors
      : [];
    const candidates = Planner.deriveFixCandidates(analysis, errors);

    if (candidates.length === 0) {
      return;
    }

    const submitResult = await this.executeStep(context, {
      tool: 'submit_fix_candidate',
      input: {
        file: analysis.filePath,
        candidates
      },
      required: false
    });

    if (submitResult.success) {
      context.addArtifact({
        kind: 'fix_candidates',
        file: analysis.filePath,
        count: candidates.length
      });
    }
  }

  buildTaskResult(context, taskType) {
    switch (taskType) {
      case 'analyze':
        return this.buildAnalysisResult(context);
      case 'review':
        return this.buildReviewResult(context);
      case 'security-review':
        return this.buildSecurityReviewResult(context);
      case 'replay':
        return this.buildReplayResult(context);
      case 'compare':
        return this.buildCompareResult(context);
      case 'refactor':
        return this.buildRefactorResult(context);
      case 'generate':
        return this.buildGenerationResult(context);
      case 'optimize':
        return this.buildOptimizationResult(context);
      case 'design':
        return this.buildDesignResult(context);
      case 'fix':
        return this.buildFixResult(context);
      case 'test':
      case 'validate':
        return this.buildVerificationResult(context, taskType);
      default:
        return this.buildGenericResult(context);
    }
  }

  async applyAdvisorValidation(context, taskResult, taskType) {
    const validationRequested = context.task?.metadata?.advisorValidation === true ||
      context.task?.content?.advisorValidation === true;

    if (!this.providerManager || typeof this.providerManager.validateAdvisorDecision !== 'function') {
      context.markAdvisorValidation({ requested: validationRequested, performed: false, verdict: 'unavailable' });
      return;
    }

    if (!validationRequested) {
      context.markAdvisorValidation({ requested: false, performed: false, verdict: 'skipped' });
      return;
    }

    const validation = await this.providerManager.validateAdvisorDecision({
      enabled: true,
      action: taskType,
      filePath: context.task?.content?.file || null,
      projectRoot: context.task?.content?.directory || context.task?.content?.projectPath || process.cwd(),
      summary: taskResult.summary,
      evidenceSummary: taskResult.evidenceSummary,
      evidence: taskResult.evidence,
      toolTrace: taskResult.toolTrace,
      reasoningMode: context.reasoningMode,
      budgetUsd: context.promptBudget.usdCap
    });

    this.guardrails.assertProviderBudget(context, validation);
    context.recordProviderUsage(validation);
    context.markAdvisorValidation({
      requested: true,
      performed: validation.performed === true,
      verdict: validation.verdict,
      provider: validation.provider,
      model: validation.model
    });

    context.addEvidence(
      createEvidenceItem({
        kind: 'advisor_validation',
        source: validation.provider || 'advisor',
        summary: `Advisor validation ${validation.verdict || 'completed'} using ${validation.provider || 'unavailable'}${validation.model ? ` (${validation.model})` : ''}.`,
        data: {
          verdict: validation.verdict || null,
          provider: validation.provider || null,
          model: validation.model || null,
          costUSD: validation.costUSD || 0,
          retries: validation.retries || 0
        }
      })
    );

    taskResult.evidence = context.evidence;
    taskResult.evidenceSummary = summarizeEvidence(context.evidence);
    taskResult.runtime = {
      ...(taskResult.runtime || {}),
      providerUsage: context.providerUsage
    };
    taskResult.data = {
      ...(taskResult.data || {}),
      advisor_validation: {
        verdict: validation.verdict || null,
        provider: validation.provider || null,
        model: validation.model || null,
        performed: validation.performed === true,
        retries: validation.retries || 0,
        cost_usd: validation.costUSD || 0,
        issues: validation.issues || []
      }
    };
  }

  buildAnalysisResult(context) {
    const analysis = context.getLatestToolData('analyze_path');
    const inventory = context.getLatestToolData('list_files');
    const searchResults = context.getLatestToolData('search_code');

    if (!analysis && !inventory && !searchResults) {
      return this.buildInsufficientResult(context, 'analysis', 'No analyzable file or directory context was available.');
    }

    if (analysis) {
      const recommendations = Planner.generateRecommendations(analysis);
      const qualityScore = Planner.calculateQualityScore(analysis);
      context.addEvidence(
        createEvidenceItem({
          kind: 'assessment',
          source: analysis.filePath,
          summary: `Derived ${recommendations.length} recommendation(s) from measured complexity and size signals.`,
          data: {
            recommendationCount: recommendations.length,
            qualityScore
          }
        })
      );

      return createTaskResult({
        success: true,
        type: 'analysis',
        status: 'completed',
        summary: `Analyzed ${analysis.filePath} and produced ${recommendations.length} recommendation(s).`,
        message: `${context.agent} analyzed ${analysis.filePath} using runtime-backed tools.`,
        quality: qualityScore,
        evidence: context.evidence,
        toolTrace: context.toolTrace,
        artifacts: context.artifacts,
        runtime: {
          ...context.getRuntimeTelemetry(),
          verificationStatus: 'verified'
        },
        data: {
          file: analysis.filePath,
          agent_capability: context.capabilities.join(', '),
          findings: {
            quality_score: qualityScore,
            size: analysis.size,
            lines: analysis.lines,
            non_empty_lines: analysis.nonEmptyLines,
            functions: analysis.functions,
            classes: analysis.classes,
            comments: analysis.comments,
            todos: analysis.todos,
            complexity: analysis.complexity,
            issues_found: recommendations.length,
            recommendations
          },
          analyzed_by: context.agent
        }
      });
    }

    if (searchResults) {
      return createTaskResult({
        success: true,
        type: 'analysis',
        status: 'completed',
        summary: `Found ${searchResults.matches.length} code match(es) for "${searchResults.query}".`,
        message: `${context.agent} searched code evidence for "${searchResults.query}".`,
        quality: searchResults.matches.length > 0 ? 0.7 : 0.4,
        evidence: context.evidence,
        toolTrace: context.toolTrace,
        artifacts: context.artifacts,
        runtime: {
          ...context.getRuntimeTelemetry(),
          verificationStatus: 'verified'
        },
        data: {
          query: searchResults.query,
          base_path: searchResults.basePath,
          files_scanned: searchResults.filesScanned,
          matches: searchResults.matches,
          truncated: searchResults.truncated
        }
      });
    }

    return createTaskResult({
      success: true,
      type: 'analysis',
      status: 'inventory',
      summary: `Inspected ${inventory.basePath} and found ${inventory.entries.length} entries.`,
      message: `${context.agent} inspected ${inventory.basePath} using runtime-backed tools.`,
      quality: 0.5,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        directory: inventory.basePath,
        findings: {
          entries: inventory.entries.length,
          files: inventory.entries.filter(entry => entry.isFile).length,
          directories: inventory.entries.filter(entry => entry.isDirectory).length
        },
        analyzed_by: context.agent
      }
    });
  }

  buildReviewResult(context) {
    const analysis = context.getLatestToolData('analyze_path');
    const inventory = context.getLatestToolData('list_files');
    const readResult = context.getLatestToolData('read_file');
    const searchResults = context.getToolResultsByName('search_code')
      .filter(result => result && result.success && result.data)
      .map(result => result.data);

    if (!analysis && !inventory && !readResult && searchResults.length === 0) {
      return this.buildInsufficientResult(context, 'review', 'Review requires a target file, directory, or search query.');
    }

    const targetPath = analysis?.filePath || inventory?.basePath || context.task.content?.file || context.task.content?.directory || '.';
    const recommendations = analysis ? Planner.generateRecommendations(analysis) : [];
    const reviewQuality = analysis ? Planner.calculateQualityScore(analysis) : 0.65;
    const matchCount = searchResults.reduce((total, result) => total + result.matches.length, 0);

    if (recommendations.length > 0) {
      context.addEvidence(
        createEvidenceItem({
          kind: 'review_assessment',
          source: targetPath,
          summary: `Prepared ${recommendations.length} review recommendation(s) for ${targetPath}.`,
          data: {
            recommendationCount: recommendations.length,
            matchCount
          }
        })
      );
    }

    return createTaskResult({
      success: true,
      type: 'review',
      status: 'completed',
      summary: `Reviewed ${targetPath}${recommendations.length > 0 ? ` and prepared ${recommendations.length} recommendation(s)` : ''}${matchCount > 0 ? ` with ${matchCount} supporting code match(es)` : ''}.`,
      message: `${context.agent} completed a runtime-backed review for ${targetPath}.`,
      quality: reviewQuality,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        target: targetPath,
        review: {
          recommendations,
          source_excerpt: readResult ? Planner.createSourceExcerpt(readResult.content) : null,
          inventory: inventory ? {
            entries: inventory.entries.length,
            files: inventory.entries.filter(entry => entry.isFile).length,
            directories: inventory.entries.filter(entry => entry.isDirectory).length
          } : null,
          search_matches: searchResults.map(result => ({
            query: result.query,
            files_scanned: result.filesScanned,
            matches: result.matches
          }))
        }
      }
    });
  }

  buildSecurityReviewResult(context) {
    const analysis = context.getLatestToolData('analyze_path');
    const inventory = context.getLatestToolData('list_files');
    const searchResults = context.getToolResultsByName('search_code')
      .filter(result => result && result.success && result.data)
      .map(result => result.data);

    if (!analysis && !inventory && searchResults.length === 0) {
      return this.buildInsufficientResult(context, 'security_review', 'Security review requires a target path or security queries.');
    }

    const targetPath = analysis?.filePath || inventory?.basePath || context.task.content?.file || context.task.content?.directory || '.';
    const totalMatches = searchResults.reduce((total, result) => total + result.matches.length, 0);
    const filesScanned = searchResults.reduce((total, result) => total + (result.filesScanned || 0), 0);

    context.addEvidence(
      createEvidenceItem({
        kind: 'security_review',
        source: targetPath,
        summary: `Security review scanned ${filesScanned} file(s) and found ${totalMatches} suspicious match(es).`,
        data: {
          queries: searchResults.map(result => result.query),
          totalMatches
        }
      })
    );

    return createTaskResult({
      success: true,
      type: 'security_review',
      status: totalMatches > 0 ? 'matches_found' : 'completed',
      summary: `Security review scanned ${filesScanned} file(s) for ${searchResults.length} pattern(s) and found ${totalMatches} suspicious match(es).`,
      message: `${context.agent} completed a runtime-backed security review for ${targetPath}.`,
      quality: totalMatches > 0 ? 0.7 : 0.9,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        target: targetPath,
        patterns: searchResults.map(result => result.query),
        files_scanned: filesScanned,
        total_matches: totalMatches,
        matches: searchResults.flatMap(result => result.matches.map(match => ({
          ...match,
          query: result.query
        }))),
        complexity: analysis ? analysis.complexity : null
      }
    });
  }

  buildReplayResult(context) {
    const history = context.getLatestToolData('fetch_history');

    if (!history || !history.run) {
      return this.buildInsufficientResult(context, 'replay', 'Replay requires a persisted run id in local history.');
    }

    return createTaskResult({
      success: true,
      type: 'replay',
      status: 'completed',
      summary: `Loaded run ${history.run.runId} from ${history.projectPath} with ${history.run.total} finding(s).`,
      message: `${context.agent} replayed persisted history for run ${history.run.runId}.`,
      quality: 1,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        project_path: history.projectPath,
        run: history.run
      }
    });
  }

  buildCompareResult(context) {
    const comparison = context.getLatestToolData('compare_runs');

    if (!comparison) {
      return this.buildInsufficientResult(context, 'comparison', 'Compare requires two persisted run ids from local history.');
    }

    return createTaskResult({
      success: true,
      type: 'comparison',
      status: 'completed',
      summary: `Compared ${comparison.baseline.runId} to ${comparison.current.runId}: +${comparison.added.length} added, -${comparison.fixed.length} fixed.`,
      message: `${context.agent} compared persisted history for ${comparison.baseline.runId} and ${comparison.current.runId}.`,
      quality: 1,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        comparison
      }
    });
  }

  buildRefactorResult(context) {
    const analysis = context.getLatestToolData('analyze_path');
    const readResult = context.getLatestToolData('read_file');

    if (!analysis) {
      return this.buildInsufficientResult(context, 'refactoring', 'A target file is required for evidence-backed refactoring proposals.');
    }

    const candidates = Planner.deriveRefactorCandidates(analysis);
    const qualityScore = Planner.calculateQualityScore(analysis);

    return createTaskResult({
      success: true,
      type: 'refactoring',
      status: 'planned',
      summary: `Prepared ${candidates.length} refactoring proposal(s) for ${analysis.filePath}. No code was modified.`,
      message: `${context.agent} prepared evidence-backed refactoring proposals for ${analysis.filePath}.`,
      quality: qualityScore,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'pending'
      },
      data: {
        file: analysis.filePath,
        refactorings_applied: [],
        refactorings_proposed: candidates,
        changes_count: 0,
        source_excerpt: readResult ? Planner.createSourceExcerpt(readResult.content) : null
      }
    });
  }

  buildGenerationResult(context) {
    const inventory = context.getLatestToolData('list_files');
    const readResult = context.getLatestToolData('read_file');
    const content = context.task.content || {};
    const targetPath = content.targetPath || content.file || null;

    if (!inventory && !readResult && !targetPath) {
      return this.buildInsufficientResult(context, 'generation', 'Generation planning needs a target path, directory, or reference file.');
    }

    return createTaskResult({
      success: true,
      type: 'generation',
      status: 'planned',
      summary: `Prepared a generation plan${targetPath ? ` for ${targetPath}` : ''}. No files were created.`,
      message: `${context.agent} prepared a runtime-backed generation plan without mutating the repository.`,
      quality: 0.5,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'pending'
      },
      data: {
        generated: content.type || 'code',
        lines_generated: 0,
        files_created: 0,
        generated_artifacts: [],
        generation_plan: {
          target_path: targetPath,
          requested_type: content.type || null,
          sibling_files: inventory ? inventory.entries.slice(0, 10).map(entry => entry.path) : [],
          reference_excerpt: readResult ? Planner.createSourceExcerpt(readResult.content) : null
        }
      }
    });
  }

  buildOptimizationResult(context) {
    const analysis = context.getLatestToolData('analyze_path');

    if (!analysis) {
      return this.buildInsufficientResult(context, 'optimization', 'A target file is required for runtime-backed optimization proposals.');
    }

    const candidates = Planner.deriveOptimizationCandidates(analysis);
    const qualityScore = Planner.calculateQualityScore(analysis);

    return createTaskResult({
      success: true,
      type: 'optimization',
      status: 'planned',
      summary: `Prepared ${candidates.length} optimization proposal(s) for ${analysis.filePath}. No code was modified.`,
      message: `${context.agent} prepared evidence-backed optimization proposals for ${analysis.filePath}.`,
      quality: qualityScore,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'pending'
      },
      data: {
        target: analysis.filePath,
        improvements: {
          before: {
            lines: analysis.lines,
            complexity_score: analysis.complexity.score
          },
          after: null,
          improvement_percent: 0
        },
        optimizations_applied: [],
        optimization_candidates: candidates
      }
    });
  }

  buildDesignResult(context) {
    const inventory = context.getLatestToolData('list_files');
    const analysis = context.getLatestToolData('analyze_path');

    if (!inventory && !analysis) {
      return this.buildInsufficientResult(context, 'design', 'Design review needs a directory or file target.');
    }

    const architecture = Planner.inferArchitecture(inventory, analysis);

    return createTaskResult({
      success: true,
      type: 'design',
      status: 'completed',
      summary: `Reviewed architecture signals and inferred a ${architecture.type} shape.`,
      message: `${context.agent} summarized architecture signals from runtime-backed evidence.`,
      quality: 0.6,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        architecture_type: architecture.type,
        services_identified: architecture.serviceCount,
        patterns_recommended: architecture.patterns,
        architecture_signals: architecture.signals
      }
    });
  }

  buildFixResult(context) {
    const analysis = context.getLatestToolData('analyze_path');
    const editResult = context.getLatestToolData('edit_file');
    const gitDiff = context.getLatestToolData('git_diff');
    const testRun = context.getLatestToolData('run_tests');
    const promotionResult = context.getLatestToolData('promote_worktree');
    const workspace = context.getPrimaryWorkspace();
    const reviewArtifactPath = context.task?.metadata?.reviewArtifactPath || null;
    const reviewArtifact = reviewArtifactPath ? { path: reviewArtifactPath } : null;
    const fixSessionId = context.task?.metadata?.fixSessionId || null;
    const fixSessionPath = context.task?.metadata?.fixSessionPath || null;
    const fixSession = (fixSessionId || fixSessionPath)
      ? {
          id: fixSessionId,
          path: fixSessionPath
        }
      : null;

    if (!analysis) {
      return this.buildInsufficientResult(context, 'fix', 'A target file is required for evidence-backed fix proposals.');
    }

    const errors = Array.isArray(context.task.content && context.task.content.errors)
      ? context.task.content.errors
      : [];
    const candidates = Planner.deriveFixCandidates(analysis, errors);
    const qualityScore = Planner.calculateQualityScore(analysis);

    if (promotionResult) {
      return createTaskResult({
        success: true,
        type: 'fix',
        status: 'promoted_after_validation',
        summary: `Promoted ${promotionResult.files.length} validated file(s) from the isolated workspace back into the repository.`,
        message: `${context.agent} promoted a validated fix from an isolated workspace after review.`,
        quality: Math.max(qualityScore, 0.95),
        evidence: context.evidence,
        toolTrace: context.toolTrace,
        artifacts: context.artifacts,
        runtime: {
          ...context.getRuntimeTelemetry(),
          verificationStatus: 'verified'
        },
        data: {
          file: analysis.filePath,
          errors_fixed: 0,
          fixes_applied: [
            {
              file: editResult ? editResult.filePath : analysis.filePath,
              promoted_files: promotionResult.files
            }
          ],
          fixes_proposed: candidates,
          diff_excerpt: gitDiff ? gitDiff.diff : null,
          diff_files_changed: gitDiff ? gitDiff.filesChanged : 0,
          validation: testRun ? {
            command: testRun.command,
            args: testRun.args || [],
            exit_code: testRun.exitCode,
            passed: testRun.passed
          } : null,
          promoted: true,
          promoted_files: promotionResult.files,
          diff_reviewed: context.task.content && context.task.content.diffReviewed === true,
          repository_modified: true,
          review_artifact: reviewArtifact,
          fix_session: fixSession,
          workspace: workspace ? {
            path: workspace.path,
            mode: workspace.mode,
            cleaned_up: workspace.cleanedUp
          } : null
        }
      });
    }

    if (editResult) {
      const summaryParts = [`Applied an isolated edit to ${analysis.filePath}. No repository files were promoted.`];
      if (gitDiff) {
        summaryParts.push(`Workspace diff covers ${gitDiff.filesChanged} file(s).`);
      }
      if (testRun) {
        summaryParts.push(`Validation command exited with code ${testRun.exitCode}.`);
      }

      return createTaskResult({
        success: true,
        type: 'fix',
        status: testRun ? 'validated_in_workspace' : 'applied_in_workspace',
        summary: summaryParts.join(' '),
        message: `${context.agent} applied an explicit fix edit inside an isolated workspace.`,
        quality: testRun && testRun.passed ? Math.max(qualityScore, 0.9) : Math.max(qualityScore, 0.7),
        evidence: context.evidence,
        toolTrace: context.toolTrace,
        artifacts: context.artifacts,
        runtime: {
          ...context.getRuntimeTelemetry(),
          verificationStatus: 'pending'
        },
        data: {
          file: analysis.filePath,
          errors_fixed: 0,
          fixes_applied: [
            {
              file: editResult.filePath,
              workspace_path: editResult.absolutePath,
              old_length: editResult.oldLength,
              new_length: editResult.newLength,
              difference: editResult.difference
            }
          ],
          fixes_proposed: candidates,
          diff_excerpt: gitDiff ? gitDiff.diff : null,
          diff_files_changed: gitDiff ? gitDiff.filesChanged : 0,
          validation: testRun ? {
            command: testRun.command,
            args: testRun.args || [],
            exit_code: testRun.exitCode,
            passed: testRun.passed
          } : null,
          promoted: false,
          repository_modified: false,
          review_artifact: reviewArtifact,
          fix_session: fixSession,
          workspace: workspace ? {
            path: workspace.path,
            mode: workspace.mode,
            cleaned_up: workspace.cleanedUp
          } : null
        }
      });
    }

    return createTaskResult({
      success: true,
      type: 'fix',
      status: 'planned',
      summary: `Prepared ${candidates.length} fix candidate(s) for ${analysis.filePath}. No code was modified.`,
      message: `${context.agent} prepared evidence-backed fix candidates for ${analysis.filePath}.`,
      quality: qualityScore,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'pending'
      },
      data: {
        file: analysis.filePath,
        errors_fixed: 0,
        fixes_applied: [],
        fixes_proposed: candidates,
        review_artifact: reviewArtifact,
        fix_session: fixSession,
        workspace: workspace ? {
          path: workspace.path,
          mode: workspace.mode,
          cleaned_up: workspace.cleanedUp
        } : null
      }
    });
  }

  buildVerificationResult(context, taskType) {
    const testRun = context.getLatestToolData('run_tests');
    const gitStatus = context.getLatestToolData('git_status');
    const gitDiff = context.getLatestToolData('git_diff');

    if (!testRun && !gitStatus && !gitDiff) {
      return this.buildInsufficientResult(context, taskType === 'validate' ? 'validation' : 'test', 'Verification requires a test command, git context, or both.');
    }

    const summaries = [];
    if (testRun) {
      summaries.push(`Ran ${[testRun.command, ...(testRun.args || [])].filter(Boolean).join(' ')} with exit code ${testRun.exitCode}.`);
    }
    if (gitStatus) {
      summaries.push(`Git status reported ${gitStatus.files.length} changed file(s).`);
    }
    if (gitDiff) {
      summaries.push(`Git diff covered ${gitDiff.filesChanged} file(s).`);
    }

    return createTaskResult({
      success: true,
      type: taskType === 'validate' ? 'validation' : 'test',
      status: 'completed',
      summary: summaries.join(' '),
      message: `${context.agent} collected runtime-backed verification evidence.`,
      quality: testRun && testRun.passed ? 0.9 : 0.6,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        command: testRun ? testRun.command : null,
        args: testRun ? testRun.args || [] : [],
        exit_code: testRun ? testRun.exitCode : null,
        stdout_excerpt: testRun ? testRun.stdout : null,
        stderr_excerpt: testRun ? testRun.stderr : null,
        git_branch: gitStatus ? gitStatus.branch : null,
        changed_files: gitStatus ? gitStatus.files : [],
        diff_excerpt: gitDiff ? gitDiff.diff : null,
        diff_files_changed: gitDiff ? gitDiff.filesChanged : 0
      }
    });
  }

  buildGenericResult(context) {
    const analysis = context.getLatestToolData('analyze_path');
    const inventory = context.getLatestToolData('list_files');

    if (!analysis && !inventory) {
      return this.buildInsufficientResult(context, 'generic', 'No runtime-observable target was available for the requested task.');
    }

    const observations = [];
    if (analysis) {
      observations.push(`Analyzed ${analysis.filePath} (${analysis.lines} lines).`);
    }
    if (inventory) {
      observations.push(`Listed ${inventory.entries.length} entries under ${inventory.basePath}.`);
    }

    return createTaskResult({
      success: true,
      type: 'generic',
      status: 'completed',
      summary: observations.join(' '),
      message: `${context.agent} processed the task with runtime-backed evidence.`,
      quality: analysis ? Planner.calculateQualityScore(analysis) : 0.5,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'verified'
      },
      data: {
        action: context.task.action,
        agent: context.agent,
        agent_role: context.role,
        capabilities_available: context.capabilities,
        task_processed: true,
        observations
      }
    });
  }

  buildInsufficientResult(context, type, message) {
    return createTaskResult({
      success: false,
      type,
      status: 'insufficient_evidence',
      summary: message,
      message,
      quality: 0,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'failed'
      },
      error: message
    });
  }

  buildFailureResult(context, type, errorMessage) {
    return createTaskResult({
      success: false,
      type,
      status: 'failed',
      summary: errorMessage,
      message: errorMessage,
      quality: 0,
      evidence: context.evidence,
      toolTrace: context.toolTrace,
      artifacts: context.artifacts,
      runtime: {
        ...context.getRuntimeTelemetry(),
        verificationStatus: 'failed'
      },
      error: errorMessage
    });
  }

  resolveFileTarget(task = {}) {
    const content = task.content || {};
    return content.file || content.path || content.targetFile || null;
  }

  resolveDirectoryTarget(task = {}, fileTarget = null) {
    const content = task.content || {};
    if (content.directory || content.dir || content.targetDirectory) {
      return content.directory || content.dir || content.targetDirectory;
    }

    if (content.targetPath) {
      return path.dirname(content.targetPath);
    }

    if (fileTarget) {
      return path.dirname(fileTarget);
    }

    return null;
  }

  buildWorktreeInput(task = {}, fileTarget = null) {
    const content = task.content || {};
    const basename = fileTarget
      ? path.basename(fileTarget, path.extname(fileTarget))
      : 'fix';

    return {
      name: content.workspaceName || `fix-${basename}`,
      baseDir: content.worktreeBaseDir || '.codetitan/worktrees/runtime-fixer',
      ref: content.ref,
      fallbackToCopy: content.fallbackToCopy
    };
  }

  resolvePromotionFiles(task = {}, fileTarget = null) {
    const content = task.content || {};
    const files = Array.isArray(content.files) ? content.files.filter(Boolean) : [];

    if (files.length > 0) {
      return files;
    }

    return fileTarget ? [fileTarget] : [];
  }

  resolveEditRequest(task = {}) {
    const content = task.content || {};
    const nestedEdit = content.edit && typeof content.edit === 'object' ? content.edit : {};
    const oldString = nestedEdit.oldString || content.oldString || content.original || content.snippet || null;
    const newString = nestedEdit.newString !== undefined
      ? nestedEdit.newString
      : (content.newString !== undefined ? content.newString : content.replacement);

    if (typeof oldString !== 'string' || oldString.length === 0) {
      return null;
    }

    if (typeof newString !== 'string') {
      return null;
    }

    return {
      oldString,
      newString
    };
  }

  resolveSecurityQueries(task = {}) {
    const content = task.content || {};
    const rawQueries = Array.isArray(content.queries)
      ? content.queries
      : (content.query ? [content.query] : []);
    const queries = rawQueries
      .map(value => String(value || '').trim())
      .filter(Boolean);

    if (queries.length > 0) {
      return queries;
    }

    return [
      'dangerouslySetInnerHTML',
      'innerHTML',
      'eval(',
      'exec(',
      'child_process',
      'http://',
      'process.env'
    ];
  }

  resolveSearchExtensions(task = {}, taskType = 'generic') {
    const content = task.content || {};
    const explicitExtensions = Array.isArray(content.extensions)
      ? content.extensions
        .map(value => String(value || '').trim())
        .filter(Boolean)
      : [];

    if (explicitExtensions.length > 0) {
      return explicitExtensions;
    }

    if (content.extension) {
      return undefined;
    }

    switch (taskType) {
      case 'analyze':
      case 'review':
      case 'security-review':
        return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
      default:
        return undefined;
    }
  }

  resolveStepInput(context, step = {}) {
    const input = {
      ...(step.input || {})
    };
    const scope = step.scope || {};
    const workspace = context && typeof context.getPrimaryWorkspace === 'function'
      ? context.getPrimaryWorkspace()
      : null;

    if (!workspace || !workspace.path) {
      return input;
    }

    Object.entries(scope).forEach(([key, scopeType]) => {
      if (scopeType !== 'workspace') {
        return;
      }

      if (typeof input[key] === 'string' && input[key].trim()) {
        input[key] = this.resolveWorkspacePath(workspace.path, input[key], key === 'cwd');
      }

      if (Array.isArray(input[key])) {
        input[key] = input[key].map(value => (
          typeof value === 'string' && value.trim()
            ? this.resolveWorkspacePath(workspace.path, value, false)
            : value
        ));
      }
    });

    return input;
  }

  resolveWorkspacePath(workspacePath, targetPath, isCwd = false) {
    if (!targetPath || /^[a-z]+:\/\//i.test(targetPath)) {
      return targetPath;
    }

    if (path.isAbsolute(targetPath)) {
      return targetPath;
    }

    if (isCwd) {
      return path.resolve(workspacePath, targetPath);
    }

    return path.resolve(workspacePath, targetPath);
  }

  assertSafeMode(taskType, task = {}) {
    const content = task.content || {};
    if (taskType === 'fix' && (content.direct === true || content.mode === 'direct')) {
      throw new Error('Unsafe direct mode is not supported in the agent runtime. Use isolated worktree promotion instead.');
    }
  }

  assertStepPolicy(context, step = {}, resolvedInput = {}) {
    if (step.tool !== 'promote_worktree') {
      return;
    }

    const content = context.task.content || {};
    const workspace = context.getPrimaryWorkspace();
    const editResult = context.getLatestToolData('edit_file');
    const gitDiff = context.getLatestToolData('git_diff');
    const testRun = context.getLatestToolData('run_tests');

    context.setScratch('promotionRequested', true);
    context.setScratch('diffReviewed', content.diffReviewed === true);

    if (!workspace || !workspace.path) {
      throw new Error('Promotion requires an active isolated worktree');
    }

    if (!editResult) {
      throw new Error('Promotion requires an applied workspace edit');
    }

    if (!gitDiff) {
      throw new Error('Promotion requires captured diff evidence from the active worktree');
    }

    if (content.diffReviewed !== true) {
      throw new Error('Promotion requires diffReviewed=true');
    }

    if (!testRun || testRun.passed !== true) {
      throw new Error('Promotion requires a passing validation command from the active worktree');
    }

    if (!Array.isArray(resolvedInput.files) || resolvedInput.files.length === 0) {
      throw new Error('Promotion requires one or more files');
    }
  }

  recordStepState(context, toolName, toolResult) {
    if (!toolResult || !toolResult.success) {
      if (toolName === 'run_tests') {
        context.setScratch('lastValidationPassed', false);
      }
      return;
    }

    switch (toolName) {
      case 'git_diff':
        context.setScratch('diffCaptured', true);
        break;
      case 'run_tests':
        context.setScratch('lastValidationPassed', toolResult.data && toolResult.data.passed === true);
        if (toolResult.data && toolResult.data.passed === true) {
          context.setVerificationStatus('verified');
        }
        break;
      case 'promote_worktree':
        context.setScratch('promotionCompleted', true);
        context.setScratch('promotedFiles', toolResult.data && toolResult.data.files ? toolResult.data.files : []);
        context.setVerificationStatus('verified');
        break;
      default:
        break;
    }
  }

  getResultType(taskType) {
    switch (taskType) {
      case 'analyze':
        return 'analysis';
      case 'review':
        return 'review';
      case 'security-review':
        return 'security_review';
      case 'replay':
        return 'replay';
      case 'compare':
        return 'comparison';
      case 'refactor':
        return 'refactoring';
      case 'generate':
        return 'generation';
      case 'optimize':
        return 'optimization';
      case 'validate':
        return 'validation';
      default:
        return taskType;
    }
  }

  setCompletionVerificationStatus(context, taskType) {
    switch (taskType) {
      case 'analyze':
      case 'review':
      case 'security-review':
      case 'replay':
      case 'compare':
      case 'design':
      case 'test':
      case 'validate':
      case 'generic':
        context.setVerificationStatus('verified');
        break;
      case 'fix': {
        const editResult = context.getLatestToolData('edit_file');
        const testRun = context.getLatestToolData('run_tests');
        const promotionResult = context.getLatestToolData('promote_worktree');

        if (promotionResult || (editResult && testRun && testRun.passed)) {
          context.setVerificationStatus('verified');
        } else {
          context.setVerificationStatus('pending');
        }
        break;
      }
      default:
        context.setVerificationStatus('pending');
        break;
    }
  }

  static calculateQualityScore(analysis) {
    let score = 1.0;
    const lines = analysis.lines || 1;
    const comments = analysis.comments || 0;
    const todos = analysis.todos || 0;
    const complexityLevel = analysis.complexity && analysis.complexity.level;

    if (complexityLevel === 'high') {
      score -= 0.2;
    } else if (complexityLevel === 'medium') {
      score -= 0.1;
    }

    const commentRatio = comments / lines;
    if (commentRatio < 0.05) {
      score -= 0.1;
    } else if (commentRatio < 0.10) {
      score -= 0.05;
    }

    if (todos > 5) {
      score -= 0.1;
    } else if (todos > 0) {
      score -= 0.05;
    }

    if (typeof analysis.filePath === 'string' && analysis.filePath.includes('test')) {
      score += 0.1;
    }

    if (typeof analysis.filePath === 'string' && analysis.filePath.endsWith('.md')) {
      score += 0.05;
    }

    return Math.max(0, Math.min(1, score));
  }

  static generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.complexity && analysis.complexity.level === 'high') {
      recommendations.push('High complexity detected - consider refactoring into smaller functions');
    }

    if (analysis.complexity && analysis.complexity.conditionals > 10) {
      recommendations.push(`${analysis.complexity.conditionals} conditionals found - consider using polymorphism or strategy pattern`);
    }

    if (analysis.complexity && analysis.complexity.loops > 5) {
      recommendations.push('Multiple loops detected - consider using functional methods (map, filter, reduce)');
    }

    if ((analysis.comments || 0) / Math.max(analysis.lines || 1, 1) < 0.05) {
      recommendations.push('Low comment ratio - add documentation for complex logic');
    }

    if ((analysis.todos || 0) > 0) {
      recommendations.push(`${analysis.todos} TODO comments found - address pending tasks`);
    }

    if ((analysis.lines || 0) > 500) {
      recommendations.push('File exceeds 500 lines - consider splitting into multiple modules');
    }

    if ((analysis.functions || 0) > 20) {
      recommendations.push('High function count - consider grouping related functions into classes');
    }

    return recommendations;
  }

  static deriveRefactorCandidates(analysis) {
    const candidates = [];

    if ((analysis.lines || 0) > 300 || (analysis.complexity && analysis.complexity.level !== 'low')) {
      candidates.push({
        title: 'Extract smaller units',
        rationale: 'File size or complexity is high enough to justify smaller functions or modules.'
      });
    }

    if ((analysis.functions || 0) > 20) {
      candidates.push({
        title: 'Group related functions',
        rationale: 'A high function count suggests the file may be carrying multiple responsibilities.'
      });
    }

    if ((analysis.todos || 0) > 0) {
      candidates.push({
        title: 'Resolve TODO hotspots',
        rationale: 'Outstanding TODO comments often mark unstable areas that should be cleaned up before structural refactors.'
      });
    }

    if (candidates.length === 0) {
      candidates.push({
        title: 'No structural refactor required',
        rationale: 'Measured file signals did not indicate an obvious refactoring hotspot.'
      });
    }

    return candidates;
  }

  static deriveOptimizationCandidates(analysis) {
    const candidates = [];

    if (analysis.complexity && analysis.complexity.loops > 0) {
      candidates.push({
        title: 'Review loop-heavy sections',
        rationale: `${analysis.complexity.loops} loop construct(s) were detected and may hide repeated work or allocation churn.`
      });
    }

    if (analysis.complexity && analysis.complexity.conditionals > 10) {
      candidates.push({
        title: 'Flatten conditional branches',
        rationale: 'A large number of branches can block straightforward optimization and make hot paths harder to reason about.'
      });
    }

    if ((analysis.lines || 0) > 400) {
      candidates.push({
        title: 'Split hot and cold paths',
        rationale: 'Large files often mix critical and non-critical logic, which makes targeted optimization harder.'
      });
    }

    if (candidates.length === 0) {
      candidates.push({
        title: 'Baseline only',
        rationale: 'The current file metrics do not point to an obvious optimization hotspot.'
      });
    }

    return candidates;
  }

  static deriveFixCandidates(analysis, errors = []) {
    const sources = errors.length > 0
      ? errors
      : Planner.generateRecommendations(analysis);

    return sources.slice(0, 5).map(issue => ({
      issue,
      proposal: Planner.suggestFix(issue, analysis),
      confidence: Planner.scoreFixCandidate(issue, analysis),
      file: analysis.filePath
    }));
  }

  static suggestFix(issue, analysis) {
    const normalized = String(issue || '').toLowerCase();

    if (normalized.includes('todo')) {
      return 'Replace the TODO with an implemented branch or convert it into a tracked issue reference.';
    }

    if (normalized.includes('complex')) {
      return 'Split the complex branch into smaller helpers with focused tests before changing behavior.';
    }

    if (normalized.includes('comment') || normalized.includes('documentation')) {
      return 'Document the non-obvious control flow around the measured hotspot before making structural changes.';
    }

    if ((analysis.lines || 0) > 500) {
      return 'Reduce file scope first, then apply the minimal behavior-preserving fix inside the extracted unit.';
    }

    return 'Inspect the highlighted lines and apply the smallest behavior-preserving change that resolves the measured issue.';
  }

  static scoreFixCandidate(issue, analysis) {
    let score = 0.7;
    const normalized = String(issue || '').toLowerCase();

    if (normalized.includes('todo') || normalized.includes('comment')) {
      score += 0.1;
    }

    if (analysis.complexity && analysis.complexity.level === 'high') {
      score -= 0.1;
    }

    return Math.max(0.2, Math.min(0.95, score));
  }

  static inferArchitecture(inventory, analysis) {
    const entries = inventory ? inventory.entries : [];
    const names = entries.map(entry => entry.name.toLowerCase());
    const signals = [];

    if (names.some(name => name.includes('service')) || names.filter(name => ['api', 'worker', 'jobs'].includes(name)).length >= 2) {
      signals.push('Multiple service-like directories were detected.');
      return {
        type: 'service-oriented',
        serviceCount: entries.filter(entry => entry.isDirectory).length,
        patterns: ['API boundary review', 'Async workflow isolation', 'Shared contract tests'],
        signals
      };
    }

    if ((entries.filter(entry => entry.isDirectory).length >= 3) || analysis) {
      signals.push('Multiple modules are present, but evidence still clusters around one codebase root.');
      return {
        type: 'modular-monolith',
        serviceCount: 1,
        patterns: ['Module boundaries', 'Shared domain contracts', 'Clear ownership per directory'],
        signals
      };
    }

    signals.push('Only a small number of modules were visible in the runtime evidence.');
    return {
      type: 'single-module',
      serviceCount: 1,
      patterns: ['Keep cohesion high', 'Avoid premature service splits'],
      signals
    };
  }

  static createSourceExcerpt(content) {
    if (typeof content !== 'string' || content.trim().length === 0) {
      return null;
    }

    return truncateText(
      content
        .split('\n')
        .slice(0, 8)
        .join('\n'),
      500
    );
  }
}

module.exports = Planner;
