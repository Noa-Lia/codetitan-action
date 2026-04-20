const BUILTIN_ROLE_PROFILES = {
  researcher: {
    name: 'researcher',
    description: 'Read-only evidence gathering and code inspection.',
    allowedTools: ['read_file', 'list_files', 'analyze_path', 'search_code', 'git_status', 'git_diff', 'fetch_history', 'compare_runs', 'browse_web'],
    allowMutatingTools: false,
    toolBudget: {
      maxCalls: 5
    },
    promptBudget: {
      tokenCap: 4000,
      usdCap: 0.25,
      toolCap: 5
    }
  },
  reviewer: {
    name: 'reviewer',
    description: 'Read-only review and synthesis of code quality signals.',
    allowedTools: ['read_file', 'list_files', 'analyze_path', 'search_code', 'git_status', 'git_diff', 'fetch_history', 'compare_runs', 'browse_web', 'post_github_review'],
    allowMutatingTools: false,
    toolBudget: {
      maxCalls: 8
    },
    promptBudget: {
      tokenCap: 6000,
      usdCap: 0.4,
      toolCap: 8
    }
  },
  fixer: {
    name: 'fixer',
    description: 'Prepares fix candidates and applies bounded edits inside isolated worktrees.',
    allowedTools: ['create_worktree', 'edit_file', 'promote_worktree', 'read_file', 'list_files', 'analyze_path', 'search_code', 'git_status', 'git_diff', 'run_tests', 'submit_fix_candidate', 'fetch_history', 'compare_runs'],
    allowMutatingTools: true,
    requiresWorktreeForMutations: true,
    toolBudget: {
      maxCalls: 8
    },
    promptBudget: {
      tokenCap: 4500,
      usdCap: 0.75,
      toolCap: 8
    }
  },
  verifier: {
    name: 'verifier',
    description: 'Checks outputs and validation evidence without mutating files.',
    allowedTools: ['read_file', 'list_files', 'analyze_path', 'search_code', 'git_status', 'git_diff', 'run_tests', 'fetch_history', 'compare_runs'],
    allowMutatingTools: false,
    toolBudget: {
      maxCalls: 7
    },
    promptBudget: {
      tokenCap: 3500,
      usdCap: 0.3,
      toolCap: 7
    }
  },
  orchestrator: {
    name: 'orchestrator',
    description: 'Coordinates and synthesizes evidence without producing fix artifacts directly.',
    allowedTools: ['read_file', 'list_files', 'analyze_path', 'search_code', 'git_status', 'git_diff', 'fetch_history', 'compare_runs', 'browse_web'],
    allowMutatingTools: false,
    toolBudget: {
      maxCalls: 5
    },
    promptBudget: {
      tokenCap: 5000,
      usdCap: 0.35,
      toolCap: 5
    }
  }
};

function normalizeRoleName(value) {
  if (!value || typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  if (BUILTIN_ROLE_PROFILES[normalized]) {
    return normalized;
  }

  if (normalized.includes('fix')) {
    return 'fixer';
  }
  if (normalized.includes('verif') || normalized.includes('validat')) {
    return 'verifier';
  }
  if (normalized.includes('review')) {
    return 'reviewer';
  }
  if (normalized.includes('research') || normalized.includes('analysis') || normalized.includes('code intelligence')) {
    return 'researcher';
  }
  if (normalized.includes('architect') || normalized.includes('orchestrat') || normalized.includes('coordinat')) {
    return 'orchestrator';
  }

  return null;
}

function inferRoleFromTask(task = {}) {
  const action = (task.action || '').toLowerCase();
  switch (action) {
    case 'fix':
      return 'fixer';
    case 'validate':
    case 'test':
      return 'verifier';
    case 'design':
      return 'orchestrator';
    case 'review':
    case 'security-review':
    case 'compare':
      return 'reviewer';
    case 'replay':
      return 'researcher';
    case 'refactor':
    case 'optimize':
    case 'generate':
      return 'reviewer';
    case 'analyze':
      return 'researcher';
    default:
      return 'reviewer';
  }
}

function resolveRequestedRole(skill = {}, task = {}) {
  const metadata = task.metadata || {};
  return normalizeRoleName(
    metadata.agentRole ||
    metadata.role ||
    task.role ||
    skill.runtimeRole ||
    skill.roleProfile ||
    skill.role
  );
}

function getRoleProfile(roleName) {
  const resolvedRoleName = normalizeRoleName(roleName) || 'reviewer';
  const baseProfile = BUILTIN_ROLE_PROFILES[resolvedRoleName] || BUILTIN_ROLE_PROFILES.reviewer;

  return {
    ...baseProfile,
    allowedTools: [...baseProfile.allowedTools],
    toolBudget: {
      ...baseProfile.toolBudget
    },
    promptBudget: {
      ...baseProfile.promptBudget
    }
  };
}

function resolveReasoningMode(value) {
  return value === 'deep' ? 'deep' : 'standard';
}

function resolveBudgetPolicy(roleProfile = {}, reasoningMode = 'standard') {
  const normalizedMode = resolveReasoningMode(reasoningMode);
  const toolBudget = { ...(roleProfile.toolBudget || {}) };
  const promptBudget = { ...(roleProfile.promptBudget || {}) };

  if (normalizedMode === 'deep') {
    if (typeof toolBudget.maxCalls === 'number') {
      toolBudget.maxCalls += 2;
    }

    if (typeof promptBudget.tokenCap === 'number') {
      promptBudget.tokenCap *= 2;
    }

    if (typeof promptBudget.usdCap === 'number') {
      promptBudget.usdCap = Number((promptBudget.usdCap * 2).toFixed(2));
    }
  }

  return {
    reasoningMode: normalizedMode,
    toolBudget,
    promptBudget
  };
}

function resolveRoleProfile(skill = {}, task = {}) {
  const explicitRole = resolveRequestedRole(skill, task);
  const roleName = explicitRole || inferRoleFromTask(task);
  return getRoleProfile(roleName);
}

module.exports = {
  BUILTIN_ROLE_PROFILES,
  getRoleProfile,
  inferRoleFromTask,
  normalizeRoleName,
  resolveBudgetPolicy,
  resolveReasoningMode,
  resolveRoleProfile
};
