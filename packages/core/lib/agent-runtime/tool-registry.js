function validatePrimitive(type, value) {
  if (type === 'array') {
    return Array.isArray(value);
  }

  if (type === 'object') {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  return typeof value === type;
}

function validateSchema(schema = {}, input = {}) {
  const errors = [];
  const value = input || {};

  if (schema.type && !validatePrimitive(schema.type, value)) {
    errors.push(`Input must be a ${schema.type}`);
    return { valid: false, errors };
  }

  if (Array.isArray(schema.enum) && schema.enum.length > 0 && !schema.enum.includes(value)) {
    errors.push(`Value must be one of: ${schema.enum.join(', ')}`);
    return { valid: false, errors };
  }

  const required = schema.required || [];
  required.forEach(propertyName => {
    if (value[propertyName] === undefined || value[propertyName] === null || value[propertyName] === '') {
      errors.push(`Missing required field: ${propertyName}`);
    }
  });

  const properties = schema.properties || {};
  if (schema.additionalProperties === false && value && typeof value === 'object' && !Array.isArray(value)) {
    Object.keys(value).forEach(propertyName => {
      if (!Object.prototype.hasOwnProperty.call(properties, propertyName)) {
        errors.push(`Unexpected field: ${propertyName}`);
      }
    });
  }

  Object.entries(properties).forEach(([propertyName, propertySchema]) => {
    const propertyValue = value[propertyName];

    if (propertyValue === undefined || propertyValue === null) {
      return;
    }

    if (propertySchema.type && !validatePrimitive(propertySchema.type, propertyValue)) {
      errors.push(`Field ${propertyName} must be a ${propertySchema.type}`);
      return;
    }

    if (Array.isArray(propertySchema.enum) && propertySchema.enum.length > 0 && !propertySchema.enum.includes(propertyValue)) {
      errors.push(`Field ${propertyName} must be one of: ${propertySchema.enum.join(', ')}`);
      return;
    }

    if (propertySchema.minLength && typeof propertyValue === 'string' && propertyValue.length < propertySchema.minLength) {
      errors.push(`Field ${propertyName} must be at least ${propertySchema.minLength} characters`);
    }

    if (propertySchema.type === 'number') {
      if (typeof propertySchema.minimum === 'number' && propertyValue < propertySchema.minimum) {
        errors.push(`Field ${propertyName} must be at least ${propertySchema.minimum}`);
      }
      if (typeof propertySchema.maximum === 'number' && propertyValue > propertySchema.maximum) {
        errors.push(`Field ${propertyName} must be at most ${propertySchema.maximum}`);
      }
    }

    if (propertySchema.type === 'array') {
      if (typeof propertySchema.minItems === 'number' && propertyValue.length < propertySchema.minItems) {
        errors.push(`Field ${propertyName} must contain at least ${propertySchema.minItems} item(s)`);
      }
      if (typeof propertySchema.maxItems === 'number' && propertyValue.length > propertySchema.maxItems) {
        errors.push(`Field ${propertyName} must contain at most ${propertySchema.maxItems} item(s)`);
      }
      if (propertySchema.items && propertySchema.items.type) {
        propertyValue.forEach((item, index) => {
          if (!validatePrimitive(propertySchema.items.type, item)) {
            errors.push(`Field ${propertyName}[${index}] must be a ${propertySchema.items.type}`);
            return;
          }

          if (Array.isArray(propertySchema.items.enum) && !propertySchema.items.enum.includes(item)) {
            errors.push(`Field ${propertyName}[${index}] must be one of: ${propertySchema.items.enum.join(', ')}`);
          }
        });
      }
    }
  });

  return {
    valid: errors.length === 0,
    errors
  };
}

class ToolRegistry {
  constructor({ definitions = [] } = {}) {
    this.definitions = new Map();
    definitions.forEach(definition => this.register(definition));
  }

  register(definition) {
    if (!definition || !definition.name) {
      throw new Error('Tool definition requires a name');
    }

    this.definitions.set(definition.name, definition);
    return definition;
  }

  get(name) {
    return this.definitions.get(name) || null;
  }

  list() {
    return Array.from(this.definitions.values());
  }

  validate(name, input) {
    const definition = this.get(name);

    if (!definition) {
      return {
        valid: false,
        errors: [`Unknown tool: ${name}`]
      };
    }

    return validateSchema(definition.inputSchema, input);
  }
}

const DEFAULT_TOOL_DEFINITIONS = [
  {
    name: 'read_file',
    description: 'Read a source file from the current working directory.',
    inputSchema: {
      type: 'object',
      required: ['file'],
      additionalProperties: false,
      properties: {
        file: { type: 'string', minLength: 1 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'io', weight: 1 }
  },
  {
    name: 'list_files',
    description: 'List files or directories under a path.',
    inputSchema: {
      type: 'object',
      required: ['path'],
      additionalProperties: false,
      properties: {
        path: { type: 'string', minLength: 1 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'io', weight: 1 }
  },
  {
    name: 'analyze_path',
    description: 'Inspect a file and derive deterministic complexity metrics.',
    inputSchema: {
      type: 'object',
      required: ['path'],
      additionalProperties: false,
      properties: {
        path: { type: 'string', minLength: 1 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'analysis', weight: 2 }
  },
  {
    name: 'search_code',
    description: 'Search code for a query within the working directory.',
    inputSchema: {
      type: 'object',
      required: ['query'],
      additionalProperties: false,
      properties: {
        query: { type: 'string', minLength: 1 },
        path: { type: 'string', minLength: 1 },
        caseSensitive: { type: 'boolean' },
        maxResults: { type: 'number', minimum: 1, maximum: 200 },
        extension: { type: 'string', minLength: 1 },
        extensions: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 12 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'search', weight: 2 }
  },
  {
    name: 'run_tests',
    description: 'Run an allowlisted test command using structured arguments.',
    inputSchema: {
      type: 'object',
      required: ['command'],
      additionalProperties: false,
      properties: {
        command: { type: 'string', minLength: 1 },
        cwd: { type: 'string', minLength: 1 },
        args: { type: 'array', items: { type: 'string' }, maxItems: 50 },
        timeoutMs: { type: 'number', minimum: 1, maximum: 300000 }
      }
    },
    riskLevel: 'medium',
    mutating: false,
    cost: { unit: 'verification', weight: 3 }
  },
  {
    name: 'git_status',
    description: 'Inspect repository status from the current working tree.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        cwd: { type: 'string', minLength: 1 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'git', weight: 1 }
  },
  {
    name: 'git_diff',
    description: 'Capture a git diff for the working tree, staged changes, or a revision range.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        cwd: { type: 'string', minLength: 1 },
        file: { type: 'string', minLength: 1 },
        paths: { type: 'array', items: { type: 'string' }, maxItems: 100 },
        base: { type: 'string', minLength: 1 },
        head: { type: 'string', minLength: 1 },
        cached: { type: 'boolean' },
        unified: { type: 'number', minimum: 0, maximum: 20 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'git', weight: 2 }
  },
  {
    name: 'fetch_history',
    description: 'Read persisted local analysis history for the active project or a specific run.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        projectPath: { type: 'string', minLength: 1 },
        runId: { type: 'string', minLength: 1 },
        limit: { type: 'number', minimum: 1, maximum: 100 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'history', weight: 1 }
  },
  {
    name: 'compare_runs',
    description: 'Compare two persisted analysis runs for the active project.',
    inputSchema: {
      type: 'object',
      required: ['runA', 'runB'],
      additionalProperties: false,
      properties: {
        projectPath: { type: 'string', minLength: 1 },
        runA: { type: 'string', minLength: 1 },
        runB: { type: 'string', minLength: 1 }
      }
    },
    riskLevel: 'low',
    mutating: false,
    cost: { unit: 'history', weight: 2 }
  },
  {
    name: 'create_worktree',
    description: 'Create an isolated worktree or copy-based workspace for fixer-style execution.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        name: { type: 'string', minLength: 1 },
        baseDir: { type: 'string', minLength: 1 },
        ref: { type: 'string', minLength: 1 },
        fallbackToCopy: { type: 'boolean' }
      }
    },
    riskLevel: 'medium',
    mutating: false,
    cost: { unit: 'workspace', weight: 2 }
  },
  {
    name: 'edit_file',
    description: 'Edit a file by replacing an explicit source string with a replacement string.',
    inputSchema: {
      type: 'object',
      required: ['file', 'oldString', 'newString'],
      additionalProperties: false,
      properties: {
        file: { type: 'string', minLength: 1 },
        oldString: { type: 'string', minLength: 1 },
        newString: { type: 'string' }
      }
    },
    riskLevel: 'high',
    mutating: true,
    cost: { unit: 'mutation', weight: 3 }
  },
  {
    name: 'promote_worktree',
    description: 'Promote validated files from the active isolated worktree back into the repository.',
    inputSchema: {
      type: 'object',
      required: ['files'],
      additionalProperties: false,
      properties: {
        files: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 100 },
        handleId: { type: 'string', minLength: 1 },
        path: { type: 'string', minLength: 1 }
      }
    },
    riskLevel: 'high',
    mutating: true,
    cost: { unit: 'promotion', weight: 3 }
  },
  {
    name: 'browse_web',
    description: 'Use the managed browser MCP bridge to inspect a web page without raw shell access.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      additionalProperties: false,
      properties: {
        url: { type: 'string', minLength: 1 },
        action: { type: 'string', enum: ['read', 'screenshot', 'click', 'type'] },
        selector: { type: 'string', minLength: 1 },
        text: { type: 'string' }
      }
    },
    riskLevel: 'medium',
    mutating: false,
    cost: { unit: 'browser', weight: 3 }
  },
  {
    name: 'post_github_review',
    description: 'Post inline review comments for findings to a GitHub pull request using structured arguments.',
    inputSchema: {
      type: 'object',
      required: ['owner', 'repo', 'prNumber', 'commitSha', 'findings'],
      additionalProperties: false,
      properties: {
        owner: { type: 'string', minLength: 1 },
        repo: { type: 'string', minLength: 1 },
        prNumber: { type: 'number', minimum: 1 },
        commitSha: { type: 'string', minLength: 7 },
        token: { type: 'string', minLength: 1 },
        findings: { type: 'array', minItems: 1, maxItems: 50, items: { type: 'object' } }
      }
    },
    riskLevel: 'medium',
    mutating: false,
    cost: { unit: 'github', weight: 3 }
  },
  {
    name: 'submit_fix_candidate',
    description: 'Record a proposed fix candidate without mutating source files.',
    inputSchema: {
      type: 'object',
      required: ['candidates'],
      additionalProperties: false,
      properties: {
        candidates: { type: 'array', minItems: 1, maxItems: 100, items: { type: 'object' } },
        file: { type: 'string', minLength: 1 }
      }
    },
    riskLevel: 'medium',
    mutating: false,
    cost: { unit: 'artifact', weight: 1 }
  }
];

function createDefaultToolRegistry() {
  return new ToolRegistry({
    definitions: DEFAULT_TOOL_DEFINITIONS
  });
}

module.exports = {
  DEFAULT_TOOL_DEFINITIONS,
  ToolRegistry,
  createDefaultToolRegistry,
  validateSchema
};
