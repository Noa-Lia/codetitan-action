/**
 * FixGenerator - AI-powered automated code fix generation
 *
 * Generates code fixes for findings using AI providers.
 * Uses multi-pass approach: generate → validate → refine
 *
 * @module ai-fixers/fix-generator
 */

function isDebugEnabled(value) {
  return value === '1' || value === 'true';
}

const SHOULD_DEBUG =
  isDebugEnabled(process.env.CODETITAN_DEBUG) ||
  isDebugEnabled(process.env.CODETITAN_DEBUG_FIX);

// Internal diagnostic logger - opt-in only so normal CLI output stays clean.
const _dbg = (...args) => {
  if (!SHOULD_DEBUG) {
    return;
  }

  process.stderr.write(args.join(' ') + '\n');
};

class FixGenerator {
  constructor(aiManager, config = {}) {
    this.aiManager = aiManager;
    this.config = {
      // Preferred provider for fix generation (best at code understanding)
      preferredProvider: config.preferredProvider || 'gpt-5-codex',

      // Fallback providers if preferred unavailable
      fallbackProviders: config.fallbackProviders || ['claude', 'gpt-5-codex', 'gemini'],

      // Maximum fix attempts before giving up
      maxAttempts: config.maxAttempts || 3,

      // Generate test cases for fixes
      generateTests: config.generateTests !== false,

      // Verify fixes don't break existing code
      verifyFix: config.verifyFix !== false,

      // Maximum cost per fix
      maxCostPerFix: config.maxCostPerFix || 0.05,

      ...config
    };

    // Track fix generation stats
    this.stats = {
      totalGenerated: 0,
      successful: 0,
      failed: 0,
      totalCost: 0
    };
  }

  /**
   * Generate a fix for a finding
   *
   * @param {Object} finding - The finding to fix
   * @param {string} fileContent - Current file content
   * @param {Object} options - Generation options
   * @returns {Promise<Object>} Fix generation result
   */
  async generateFix(finding, fileContent, options = {}) {
    const start = Date.now();

    try {
      // Select best provider for fix generation
      const provider = await this.selectFixProvider();

      _dbg(`[FixGenerator] Generating fix for ${finding.category} using ${provider}`);

      // Build fix generation prompt
      const prompt = this.buildFixPrompt(finding, fileContent);

      // Generate fix using AI
      const fixResponse = await this.requestFixFromAI(provider, prompt, finding);

      // Parse and validate fix
      const fix = this.parseFix(fixResponse, finding);

      // Verify fix doesn't break code (if enabled)
      if (this.config.verifyFix) {
        const verification = await this.verifyFix(fix, fileContent, finding);
        fix.verified = verification.passed;
        fix.verificationDetails = verification;

        if (!verification.passed) {
          // Attempt refinement
          if (options.allowRefinement !== false) {
            return this.refineFix(finding, fileContent, fix, verification);
          }
        }
      }

      // Generate tests (if enabled)
      if (this.config.generateTests && fix.verified) {
        fix.tests = await this.generateTests(fix, finding, fileContent);
      }

      // Track stats
      this.stats.totalGenerated++;
      if (fix.verified) {
        this.stats.successful++;
      } else {
        this.stats.failed++;
      }
      this.stats.totalCost += fix.cost || 0;

      return {
        success: fix.verified,
        fix,
        duration: Date.now() - start,
        provider
      };

    } catch (error) {
      _dbg(`[FixGenerator] Failed to generate fix:`, error);
      this.stats.failed++;
      return {
        success: false,
        error: error.message,
        duration: Date.now() - start
      };
    }
  }

  /**
   * Select best provider for fix generation
   */
  async selectFixProvider() {
    const available = await this.aiManager.getAvailableProviders();
    const availableNames = available.map(p => p.name);

    // Try preferred provider first
    if (availableNames.includes(this.config.preferredProvider)) {
      return this.config.preferredProvider;
    }

    // Try fallback providers
    for (const provider of this.config.fallbackProviders) {
      if (availableNames.includes(provider)) {
        return provider;
      }
    }

    throw new Error('No AI providers available for fix generation');
  }

  /**
   * Build fix generation prompt
   */
  buildFixPrompt(finding, fileContent) {
    const { category, severity, message, line_number, code_snippet, suggestion } = finding;

    return `You are an expert code fixer. Generate a precise code fix for this issue.

**Issue Details:**
- Category: ${category}
- Severity: ${severity}
- Line: ${line_number}
- Message: ${message}
${suggestion ? `- Suggested Fix: ${suggestion}` : ''}

**Problematic Code:**
\`\`\`
${code_snippet || 'N/A'}
\`\`\`

**Full File Context:**
\`\`\`
${this.truncateContext(fileContent, line_number, 20)}
\`\`\`

**Your Task:**
Generate a fix that:
1. Resolves the ${category} issue completely
2. Maintains existing functionality
3. Follows language best practices
4. Includes inline comments explaining the fix

**Response Format (JSON):**
{
  "fixType": "replace|insert|delete",
  "startLine": <number>,
  "endLine": <number>,
  "originalCode": "<code to replace>",
  "fixedCode": "<replacement code>",
  "explanation": "<why this fixes the issue>",
  "breakingChanges": <true|false>,
  "testable": <true|false>
}

Generate the fix now:`;
  }

  /**
   * Truncate file content to context window around line number
   */
  truncateContext(content, lineNumber, contextLines = 20) {
    if (!content) return '';

    const lines = content.split('\n');
    const start = Math.max(0, (lineNumber || 0) - contextLines);
    const end = Math.min(lines.length, (lineNumber || 0) + contextLines);

    const contextBlock = lines.slice(start, end);

    // Add line numbers
    return contextBlock
      .map((line, idx) => `${start + idx + 1}: ${line}`)
      .join('\n');
  }

  /**
   * Request fix from AI provider
   */
  async requestFixFromAI(provider, prompt, finding) {
    // Use the AI manager to make the request
    // We'll create a temporary "file" with the prompt as content
    const result = await this.aiManager.analyze(
      'refactoring-god', // Use refactoring domain for fix generation
      finding.file_path || 'temp.js',
      prompt,
      process.cwd(),
      {
        preferredProvider: provider,
        budget: this.config.maxCostPerFix
      }
    );

    return result;
  }

  /**
   * Parse fix response from AI
   */
  parseFix(aiResponse, finding) {
    try {
      // AI should return JSON in the response
      const responseText = aiResponse.issues?.[0]?.message || aiResponse.rawResponse || '';

      // Try to extract JSON from response
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('No JSON found in AI response');
      }

      const fixData = JSON.parse(jsonMatch[0]);

      return {
        type: fixData.fixType || 'replace',
        startLine: fixData.startLine || finding.line_number,
        endLine: fixData.endLine || finding.line_number,
        originalCode: fixData.originalCode || '',
        fixedCode: fixData.fixedCode || '',
        explanation: fixData.explanation || '',
        breakingChanges: fixData.breakingChanges || false,
        testable: fixData.testable !== false,
        verified: false,
        cost: aiResponse.metadata?.costUSD || 0,
        provider: aiResponse.metadata?.provider || 'unknown'
      };

    } catch (error) {
      _dbg('[FixGenerator] Failed to parse fix:', error);

      // Fallback: create a manual fix based on suggestion
      return {
        type: 'comment',
        startLine: finding.line_number,
        endLine: finding.line_number,
        originalCode: '',
        fixedCode: `// TODO: Fix ${finding.category} - ${finding.message}`,
        explanation: finding.suggestion || 'Manual fix required',
        breakingChanges: false,
        testable: false,
        verified: false,
        cost: 0,
        provider: 'fallback'
      };
    }
  }

  /**
   * Verify fix doesn't break code
   */
  async verifyFix(fix, originalContent, finding) {
    try {
      // Apply fix to content
      const fixedContent = this.applyFixToContent(fix, originalContent);

      // Basic validation checks
      const checks = {
        syntaxValid: this.checkSyntax(fixedContent, finding.file_path),
        lengthReasonable: Math.abs(fixedContent.length - originalContent.length) < originalContent.length * 0.5,
        noDeletedCode: !this.deletedSignificantCode(originalContent, fixedContent),
        fixApplied: fixedContent !== originalContent
      };

      const passed = Object.values(checks).every(Boolean);

      return {
        passed,
        checks,
        fixedContent
      };

    } catch (error) {
      return {
        passed: false,
        error: error.message,
        checks: {}
      };
    }
  }

  /**
   * Apply fix to file content
   */
  applyFixToContent(fix, content) {
    const lines = content.split('\n');

    if (fix.type === 'replace') {
      // Replace lines startLine to endLine
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.endLine);
      const replacement = fix.fixedCode.split('\n');

      return [...before, ...replacement, ...after].join('\n');

    } else if (fix.type === 'insert') {
      // Insert at line
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.startLine - 1);
      const insertion = fix.fixedCode.split('\n');

      return [...before, ...insertion, ...after].join('\n');

    } else if (fix.type === 'delete') {
      // Delete lines
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.endLine);

      return [...before, ...after].join('\n');

    } else if (fix.type === 'comment') {
      // Add comment
      const before = lines.slice(0, fix.startLine - 1);
      const after = lines.slice(fix.startLine - 1);

      return [...before, fix.fixedCode, ...after].join('\n');
    }

    return content;
  }

  /**
   * Basic syntax check (language-specific)
   */
  checkSyntax(content, filePath) {
    // For now, just check for balanced braces
    const openBraces = (content.match(/\{/g) || []).length;
    const closeBraces = (content.match(/\}/g) || []).length;

    // Allow some tolerance
    return Math.abs(openBraces - closeBraces) <= 1;
  }

  /**
   * Check if fix deleted significant code
   */
  deletedSignificantCode(original, fixed) {
    const originalLines = original.split('\n').filter(l => l.trim().length > 0).length;
    const fixedLines = fixed.split('\n').filter(l => l.trim().length > 0).length;

    // Flag if more than 30% of code deleted
    return fixedLines < originalLines * 0.7;
  }

  /**
   * Refine fix based on verification failures
   */
  async refineFix(finding, fileContent, failedFix, verification) {
    _dbg('[FixGenerator] Refining failed fix...');

    // Build refinement prompt
    const refinementPrompt = `The previous fix failed verification. Refine it.

**Original Fix:**
\`\`\`
${failedFix.fixedCode}
\`\`\`

**Verification Failures:**
${JSON.stringify(verification.checks, null, 2)}

**Please provide a corrected fix that passes all checks.`;

    // Try to generate refined fix
    const provider = failedFix.provider || this.config.preferredProvider;

    try {
      const refinedResponse = await this.requestFixFromAI(provider, refinementPrompt, finding);
      const refinedFix = this.parseFix(refinedResponse, finding);
      const refinedVerification = await this.verifyFix(refinedFix, fileContent, finding);

      refinedFix.verified = refinedVerification.passed;
      refinedFix.verificationDetails = refinedVerification;

      return {
        success: refinedFix.verified,
        fix: refinedFix,
        refined: true,
        provider
      };

    } catch (error) {
      _dbg('[FixGenerator] Refinement failed:', error);
      return {
        success: false,
        fix: failedFix,
        refined: false,
        error: error.message
      };
    }
  }

  /**
   * Generate test cases for fix
   */
  async generateTests(fix, finding, fileContent) {
    _dbg('[FixGenerator] Generating tests for fix...');

    const testPrompt = `Generate test cases for this code fix.

**Fix Applied:**
\`\`\`
${fix.fixedCode}
\`\`\`

**What Was Fixed:**
${finding.category} - ${finding.message}

**Generate:**
1. Test case that proves the bug is fixed
2. Test case that proves functionality is maintained
3. Edge cases

Respond with Jest/Mocha test code.`;

    try {
      const provider = fix.provider || this.config.preferredProvider;
      const testResponse = await this.requestFixFromAI(provider, testPrompt, finding);

      return {
        generated: true,
        code: testResponse.issues?.[0]?.suggestion || '// Tests could not be generated',
        provider: testResponse.metadata?.provider
      };

    } catch (error) {
      _dbg('[FixGenerator] Test generation failed:', error);
      return {
        generated: false,
        error: error.message
      };
    }
  }

  /**
   * Batch generate fixes for multiple findings
   */
  async batchGenerateFixes(findings, fileContents, options = {}) {
    const results = [];

    for (let i = 0; i < findings.length; i++) {
      const finding = findings[i];
      const content = fileContents[finding.file_path];

      if (!content) {
        results.push({
          finding,
          success: false,
          error: 'File content not provided'
        });
        continue;
      }

      // Generate fix
      const fixResult = await this.generateFix(finding, content, options);

      results.push({
        finding,
        ...fixResult
      });

      // Respect rate limits
      if (options.delayBetweenFixes) {
        await new Promise(resolve => setTimeout(resolve, options.delayBetweenFixes));
      }
    }

    return results;
  }

  /**
   * Get fix generation statistics
   */
  getStats() {
    return {
      ...this.stats,
      successRate: this.stats.totalGenerated > 0
        ? this.stats.successful / this.stats.totalGenerated
        : 0,
      averageCost: this.stats.totalGenerated > 0
        ? this.stats.totalCost / this.stats.totalGenerated
        : 0
    };
  }

  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      totalGenerated: 0,
      successful: 0,
      failed: 0,
      totalCost: 0
    };
  }
}

module.exports = FixGenerator;
