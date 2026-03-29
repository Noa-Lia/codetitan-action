/**
 * Auto-Refactoring Engine
 *
 * This engine can ACTUALLY MODIFY code, not just suggest changes.
 * It uses the Tool Bridge to safely apply refactorings with
 * automatic backup and rollback.
 *
 * KEY DIFFERENCE FROM BEFORE:
 * - Before: Agents suggested "consider refactoring"
 * - Now: Engine ACTUALLY refactors the code
 *
 * SAFETY MECHANISMS:
 * - Automatic backup before changes
 * - Validation after changes
 * - Automatic rollback on failure
 * - Change tracking
 */

const ToolBridge = require('./tool-bridge');

class AutoRefactoringEngine {
  constructor(options = {}) {
    this.toolBridge = options.toolBridge || new ToolBridge({
      workingDirectory: options.workingDirectory || process.cwd(),
      enableFileOperations: true,
      enableBackups: true,
      enableValidation: options.enableValidation ?? false
    });

    this.metrics = {
      refactoringsAttempted: 0,
      refactoringsSucceeded: 0,
      refactoringsFailed: 0,
      filesModified: 0,
      linesChanged: 0
    };

    console.log('[AutoRefactoring] Initialized');
  }

  /**
   * Apply a refactoring to a file
   */
  async applyRefactoring(filePath, refactoringType, params = {}) {
    this.metrics.refactoringsAttempted++;

    console.log(`[AutoRefactoring] Applying ${refactoringType} to ${filePath}`);

    try {
      // Read current file
      const readResult = await this.toolBridge.read(filePath);
      if (!readResult.success) {
        throw new Error(`Cannot read file: ${readResult.error}`);
      }

      const originalContent = readResult.content;

      // Apply the refactoring
      const refactoredContent = await this.performRefactoring(
        originalContent,
        refactoringType,
        params
      );

      if (!refactoredContent || refactoredContent === originalContent) {
        console.log(`[AutoRefactoring] No changes needed for ${refactoringType}`);
        return {
          success: true,
          changed: false,
          refactoringType: refactoringType
        };
      }

      // Write the refactored content (with automatic backup)
      const writeResult = await this.toolBridge.write(filePath, refactoredContent, {
        validate: params.validate,
        validationCommand: params.validationCommand
      });

      if (writeResult.success) {
        this.metrics.refactoringsSucceeded++;
        this.metrics.filesModified++;
        this.metrics.linesChanged += this.countLineChanges(originalContent, refactoredContent);

        console.log(`[AutoRefactoring] Successfully applied ${refactoringType}`);

        return {
          success: true,
          changed: true,
          changeId: writeResult.changeId,
          refactoringType: refactoringType,
          linesChanged: this.countLineChanges(originalContent, refactoredContent),
          backedUp: writeResult.backedUp
        };
      } else {
        throw new Error(`Write failed: ${writeResult.error}`);
      }

    } catch (error) {
      this.metrics.refactoringsFailed++;
      console.error(`[AutoRefactoring] Failed to apply ${refactoringType}:`, error.message);

      return {
        success: false,
        refactoringType: refactoringType,
        error: error.message
      };
    }
  }

  /**
   * Perform the actual refactoring logic
   */
  async performRefactoring(content, refactoringType, params) {
    switch (refactoringType) {
      case 'remove-console-logs':
        return this.removeConsoleLogs(content);

      case 'add-strict-mode':
        return this.addStrictMode(content);

      case 'modernize-var-to-const':
        return this.modernizeVarToConst(content);

      case 'add-jsdoc-comments':
        return this.addJSDocComments(content, params);

      case 'extract-magic-numbers':
        return this.extractMagicNumbers(content, params);

      case 'simplify-conditionals':
        return this.simplifyConditionals(content);

      case 'remove-dead-code':
        return this.removeDeadCode(content);

      case 'optimize-imports':
        return this.optimizeImports(content);

      // SECURITY REFACTORINGS (Security God)
      case 'fix-sql-injection':
        return this.fixSQLInjection(content, params);

      case 'remove-hardcoded-secrets':
        return this.removeHardcodedSecrets(content, params);

      case 'fix-xss-vulnerability':
        return this.fixXSSVulnerability(content, params);

      case 'add-input-validation':
        return this.addInputValidation(content, params);

      case 'upgrade-weak-crypto':
        return this.upgradeWeakCrypto(content, params);

      // PERFORMANCE REFACTORINGS (Performance God)
      case 'fix-n-plus-one-query':
        return this.fixNPlusOneQuery(content, params);

      case 'add-caching-layer':
        return this.addCachingLayer(content, params);

      case 'optimize-nested-loops':
        return this.optimizeNestedLoops(content, params);

      // TEST REFACTORINGS (Test God)
      case 'generate-unit-test':
        return this.generateUnitTest(content, params);

      case 'add-edge-case-tests':
        return this.addEdgeCaseTests(content, params);

      case 'improve-test-assertions':
        return this.improveTestAssertions(content, params);

      case 'add-test-mocks':
        return this.addTestMocks(content, params);

      // REFACTORING OPERATIONS (Refactoring God)
      case 'extract-constant':
        return this.extractConstant(content, params);

      case 'simplify-conditional':
        return this.simplifyConditional(content, params);

      case 'remove-duplication':
        return this.removeDuplication(content, params);

      case 'extract-method':
        return this.extractMethod(content, params);

      // DOCUMENTATION OPERATIONS (Documentation God)
      case 'add-jsdoc':
        return this.addJSDoc(content, params);

      case 'add-param-docs':
        return this.addParamDocs(content, params);

      case 'add-return-docs':
        return this.addReturnDocs(content, params);

      case 'add-usage-examples':
        return this.addUsageExamples(content, params);

      default:
        console.warn(`[AutoRefactoring] Unknown refactoring type: ${refactoringType}`);
        return content;
    }
  }

  /**
   * Remove console.log statements
   */
  removeConsoleLogs(content) {
    const lines = content.split('\n');
    const filtered = lines.filter(line => {
      const trimmed = line.trim();
      return !trimmed.startsWith('console.log(') &&
        !trimmed.startsWith('console.debug(') &&
        !trimmed.startsWith('console.info(') &&
        !trimmed.match(/^\s*\/\/\s*console\./);
    });
    return filtered.join('\n');
  }

  /**
   * Add 'use strict' directive
   */
  addStrictMode(content) {
    if (content.includes("'use strict'") || content.includes('"use strict"')) {
      return content; // Already has strict mode
    }

    const lines = content.split('\n');

    // Find first non-comment, non-empty line
    let insertIndex = 0;
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (trimmed && !trimmed.startsWith('//') && !trimmed.startsWith('/*') && !trimmed.startsWith('*')) {
        insertIndex = i;
        break;
      }
    }

    lines.splice(insertIndex, 0, "'use strict';", '');
    return lines.join('\n');
  }

  /**
   * Modernize var declarations to const/let
   */
  modernizeVarToConst(content) {
    const lines = content.split('\n');
    const refactored = lines.map(line => {
      // Only match var at start of line (avoids comments/strings mostly)
      const match = line.match(/^(\s*)var\s+(\w+)(.*)$/);

      if (match) {
        const [fullLine, indent, name, rest] = match;

        // 1. Is it initialized? check if rest starts with =
        const isInitialized = /^\s*=/.test(rest);

        if (!isInitialized) {
          // Uninitialized var MUST be let
          return `${indent}let ${name}${rest}`;
        }

        // 2. If initialized, check for reassignments in the whole file
        // We count how many times "name =" appears
        const reassignRegex = new RegExp(`\\b${name}\\s*=[^=]`, 'g');
        const assignMatches = content.match(reassignRegex) || [];
        const assignCount = assignMatches.length;

        // Check for mutation operators (++, +=, etc)
        const mutationRegex = new RegExp(`\\b${name}\\s*(\\+\\+|--|\\+=|-=|\\*=|\\/=|%=)`, 'g');
        const mutationMatches = content.match(mutationRegex) || [];

        // If assigned more than once (declaration + reassignment), or mutated -> let
        if (assignCount > 1 || mutationMatches.length > 0) {
          return `${indent}let ${name}${rest}`;
        } else {
          // Otherwise safely const
          return `${indent}const ${name}${rest}`;
        }
      }
      return line;
    });

    return refactored.join('\n');
  }

  /**
   * Add JSDoc comments to functions
   */
  addJSDocComments(content, params) {
    const lines = content.split('\n');
    const result = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check if this is a function declaration
      const functionMatch = line.match(/^\s*(async\s+)?function\s+(\w+)\s*\((.*?)\)/);
      const arrowMatch = line.match(/^\s*const\s+(\w+)\s*=\s*(\(.*?\)|[\w]+)\s*=>/);

      if (functionMatch || arrowMatch) {
        // Check if previous line is already a comment
        const prevLine = i > 0 ? lines[i - 1].trim() : '';
        if (!prevLine.startsWith('*') && !prevLine.startsWith('//')) {
          // Add JSDoc comment
          const indent = line.match(/^\s*/)[0];
          result.push(`${indent}/**`);
          result.push(`${indent} * ${functionMatch ? functionMatch[2] : arrowMatch[1]}`);
          result.push(`${indent} */`);
        }
      }

      result.push(line);
    }

    return result.join('\n');
  }

  /**
   * Extract magic numbers to named constants
   */
  extractMagicNumbers(content, params) {
    // Find magic numbers and suggest constant names
    const numbers = new Set();
    const lines = content.split('\n');

    // Find numbers that appear multiple times
    lines.forEach(line => {
      const matches = line.match(/\b\d+\.?\d*\b/g);
      if (matches) {
        matches.forEach(num => {
          if (num !== '0' && num !== '1') { // Ignore 0 and 1
            numbers.add(num);
          }
        });
      }
    });

    // For now, just add a comment suggesting extraction
    // A full implementation would create const declarations
    const comment = `// TODO: Consider extracting magic numbers to constants: ${Array.from(numbers).join(', ')}`;

    return comment + '\n' + content;
  }

  /**
   * Simplify conditional expressions
   */
  simplifyConditionals(content) {
    let result = content;

    // Simplify === true to just the expression
    result = result.replace(/(\w+)\s*===\s*true/g, '$1');
    result = result.replace(/(\w+)\s*===\s*false/g, '!$1');

    // Simplify !== false to just the expression
    result = result.replace(/(\w+)\s*!==\s*false/g, '$1');
    result = result.replace(/(\w+)\s*!==\s*true/g, '!$1');

    // Simplify double negation
    result = result.replace(/!!(\w+)/g, '$1');

    return result;
  }

  /**
   * Remove commented-out code
   */
  removeDeadCode(content) {
    const lines = content.split('\n');
    const filtered = lines.filter(line => {
      const trimmed = line.trim();
      // Remove lines that are commented out code (heuristic)
      if (trimmed.startsWith('// ') && /[;{}()]/.test(trimmed)) {
        return false;
      }
      return true;
    });
    return filtered.join('\n');
  }

  /**
   * Optimize import statements
   */
  optimizeImports(content) {
    const lines = content.split('\n');
    const imports = [];
    const other = [];

    lines.forEach(line => {
      if (line.trim().startsWith('const') && line.includes('require(')) {
        imports.push(line);
      } else if (line.trim().startsWith('import')) {
        imports.push(line);
      } else {
        other.push(line);
      }
    });

    // Sort imports alphabetically
    imports.sort();

    // Combine: imports + blank line + rest
    return imports.length > 0
      ? imports.join('\n') + '\n\n' + other.join('\n')
      : content;
  }

  // ========================
  // SECURITY REFACTORINGS
  // ========================

  /**
   * Fix SQL injection vulnerabilities
   * Converts string concatenation to parameterized queries
   */
  fixSQLInjection(content, params) {
    let result = content;

    // Pattern 1: db.query("SELECT * FROM table WHERE id = " + variable)
    // Replace with: db.query("SELECT * FROM table WHERE id = ?", [variable])
    result = result.replace(
      /(\.query\s*\(\s*["'`])([^"'`]*)(["'`]\s*\+\s*)(\w+)(\s*\))/g,
      (match, prefix, query, concat, variable, suffix) => {
        // Replace the string with placeholder
        const updatedQuery = query.replace(/\s+$/, ' ') + '?';
        return `${prefix}${updatedQuery}${query.endsWith("'") ? "'" : '"'}, [${variable}]${suffix}`;
      }
    );

    // Pattern 2: Template literals with variables
    // db.query(`SELECT * FROM users WHERE id = '${userId}'`)
    // Replace with: db.query("SELECT * FROM users WHERE id = ?", [userId])
    result = result.replace(
      /\.query\s*\(\s*`([^`]*)\$\{(\w+)\}([^`]*)`\s*\)/g,
      (match, before, variable, after) => {
        const query = before + '?' + after;
        return `.query("${query}", [${variable}])`;
      }
    );

    return result;
  }

  /**
   * Remove hardcoded secrets and replace with environment variables
   */
  removeHardcodedSecrets(content, params) {
    let result = content;
    const secretsFound = [];

    // Pattern 1: API keys
    result = result.replace(
      /(const|let|var)\s+(API_KEY|APIKEY|api_key)\s*=\s*["']([^"']{16,})["']/gi,
      (match, declType, varName, value) => {
        const envVarName = varName.toUpperCase();
        secretsFound.push({ name: envVarName, value });
        return `${declType} ${varName} = process.env.${envVarName}`;
      }
    );

    // Pattern 2: Passwords
    result = result.replace(
      /(const|let|var)\s+(PASSWORD|PASSWD|PWD|DB_PASSWORD)\s*=\s*["']([^"']+)["']/gi,
      (match, declType, varName, value) => {
        const envVarName = varName.toUpperCase();
        secretsFound.push({ name: envVarName, value });
        return `${declType} ${varName} = process.env.${envVarName}`;
      }
    );

    // Pattern 3: Tokens
    result = result.replace(
      /(const|let|var)\s+(TOKEN|SECRET|AUTH_TOKEN)\s*=\s*["']([^"']{20,})["']/gi,
      (match, declType, varName, value) => {
        const envVarName = varName.toUpperCase();
        secretsFound.push({ name: envVarName, value });
        return `${declType} ${varName} = process.env.${envVarName}`;
      }
    );

    // Pattern 4: AWS keys
    result = result.replace(
      /(const|let|var)\s+(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*["']([^"']+)["']/gi,
      (match, declType, varName, value) => {
        secretsFound.push({ name: varName, value });
        return `${declType} ${varName} = process.env.${varName}`;
      }
    );

    // If secrets were found, add a comment at the top
    if (secretsFound.length > 0) {
      const secretsList = secretsFound.map(s => s.name).join(', ');
      const comment = `// SECURITY: Moved secrets to environment variables: ${secretsList}\n// Add these to your .env file:\n${secretsFound.map(s => `// ${s.name}=${s.value}`).join('\n')}\n\n`;
      result = comment + result;
    }

    return result;
  }

  /**
   * Fix XSS vulnerabilities
   * Replace innerHTML with textContent
   */
  fixXSSVulnerability(content, params) {
    let result = content;

    // Pattern 1: element.innerHTML = userVariable
    // Check if variable name suggests user input
    result = result.replace(
      /(\w+)\.innerHTML\s*=\s*([^;]*(?:user|input|param|req\.|data\.|props\.)[^;]*)/gi,
      (match, element, value) => {
        // If it's just a variable (not HTML structure), use textContent
        if (!value.includes('<')) {
          return `${element}.textContent = ${value}`;
        }
        // If it includes HTML tags, warn but still replace
        return `${element}.textContent = ${value}; // WARNING: Original used innerHTML with user data`;
      }
    );

    // Pattern 2: dangerouslySetInnerHTML in React
    result = result.replace(
      /dangerouslySetInnerHTML=\{\{__html:\s*([^}]+)\}\}/g,
      (match, value) => {
        return `// WARNING: Removed dangerouslySetInnerHTML. Use safe rendering instead.\n// Consider using a sanitization library like DOMPurify`;
      }
    );

    // Pattern 3: document.write
    result = result.replace(
      /document\.write\s*\([^)]*\)/g,
      '// WARNING: document.write removed (security risk). Use DOM manipulation instead.'
    );

    return result;
  }

  /**
   * Add input validation to functions
   */
  addInputValidation(content, params) {
    const lines = content.split('\n');
    const result = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Find function declarations
      const functionMatch = line.match(/^\s*function\s+(\w+)\s*\(([^)]+)\)\s*\{/);
      const arrowMatch = line.match(/^\s*const\s+(\w+)\s*=\s*\(([^)]+)\)\s*=>\s*\{/);

      if (functionMatch || arrowMatch) {
        const funcName = functionMatch ? functionMatch[1] : arrowMatch[1];
        const paramsStr = functionMatch ? functionMatch[2] : arrowMatch[2];
        const paramsList = paramsStr.split(',').map(p => p.trim());

        result.push(line);

        // Add validation for each parameter
        const indent = line.match(/^\s*/)[0] + '  ';
        for (const param of paramsList) {
          const paramName = param.split('=')[0].trim(); // Handle default params

          // Add type-based validation based on parameter name heuristics
          if (paramName.match(/id$/i)) {
            result.push(`${indent}if (typeof ${paramName} !== 'number' && typeof ${paramName} !== 'string') {`);
            result.push(`${indent}  throw new Error('Invalid ${paramName}: must be number or string');`);
            result.push(`${indent}}`);
          } else if (paramName.match(/email/i)) {
            result.push(`${indent}if (typeof ${paramName} !== 'string' || !${paramName}.includes('@')) {`);
            result.push(`${indent}  throw new Error('Invalid ${paramName}: must be valid email');`);
            result.push(`${indent}}`);
          } else if (paramName.match(/age|count|index|size/i)) {
            result.push(`${indent}if (typeof ${paramName} !== 'number' || ${paramName} < 0) {`);
            result.push(`${indent}  throw new Error('Invalid ${paramName}: must be non-negative number');`);
            result.push(`${indent}}`);
          } else if (paramName.match(/name|title|text/i)) {
            result.push(`${indent}if (typeof ${paramName} !== 'string' || ${paramName}.length === 0) {`);
            result.push(`${indent}  throw new Error('Invalid ${paramName}: must be non-empty string');`);
            result.push(`${indent}}`);
          }
        }

        continue;
      }

      result.push(line);
    }

    return result.join('\n');
  }

  /**
   * Upgrade weak cryptography to stronger alternatives
   */
  upgradeWeakCrypto(content, params) {
    let result = content;

    // Pattern 1: MD5 -> SHA256
    result = result.replace(
      /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/gi,
      "crypto.createHash('sha256')"
    );

    // Pattern 2: SHA1 -> SHA256
    result = result.replace(
      /crypto\.createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
      "crypto.createHash('sha256')"
    );

    // Pattern 3: Math.random() for security -> crypto.randomBytes()
    // Only in specific contexts (token generation, etc.)
    result = result.replace(
      /(token|secret|key|id)\s*=\s*Math\.random\(\)\.toString\((\d+)\)/gi,
      (match, varName, radix) => {
        return `${varName} = crypto.randomBytes(16).toString('hex')`;
      }
    );

    // Pattern 4: Deprecated createCipher -> createCipheriv
    result = result.replace(
      /crypto\.createCipher\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^)]+)\)/g,
      (match, algorithm, password) => {
        return `// WARNING: crypto.createCipher is deprecated. Use crypto.createCipheriv instead.\n// Example: crypto.createCipheriv('aes-256-gcm', key, iv)`;
      }
    );

    return result;
  }

  // ========================
  // PERFORMANCE REFACTORINGS
  // ========================

  /**
   * Fix N+1 query problems
   * Convert loops with queries to batch queries
   */
  fixNPlusOneQuery(content, params) {
    let result = content;

    // Pattern 1: for...of loop with await query inside
    // for (const id of ids) { const result = await query(..., id) }
    result = result.replace(
      /for\s*\(\s*const\s+(\w+)\s+of\s+(\w+)\s*\)\s*\{([^}]*await\s+\w+\.query\([^,]+,\s*\[?\1\]?\))/gs,
      (match, itemVar, arrayVar, body) => {
        return `// PERFORMANCE: Converted N+1 to batch query
const results = await db.query(
  'SELECT * FROM table WHERE id IN (?)',
  [${arrayVar}]
);

// Group results by ID
const resultsMap = results.reduce((acc, item) => {
  acc[item.id] = item;
  return acc;
}, {});

// Map to maintain original order
const data = ${arrayVar}.map(${itemVar} => resultsMap[${itemVar}]);`;
      }
    );

    return result;
  }

  /**
   * Add caching layer to expensive operations
   */
  addCachingLayer(content, params) {
    const lines = content.split('\n');
    const result = [];
    let inFunction = false;
    let functionName = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Detect async function that does queries/fetches
      const funcMatch = line.match(/async\s+function\s+(\w+)\s*\(([^)]*)\)/);
      if (funcMatch && (content.includes('.query(') || content.includes('fetch(') || content.includes('await'))) {
        functionName = funcMatch[1];
        const params = funcMatch[2];

        // Add cache before function
        result.push(`// PERFORMANCE: Added caching layer`);
        result.push(`const ${functionName}Cache = new Map();`);
        result.push('');
        result.push(line);

        // Add cache check at start of function
        if (params) {
          const paramName = params.split(',')[0].trim();
          result.push(`  const cacheKey = ${paramName};`);
          result.push(`  if (${functionName}Cache.has(cacheKey)) {`);
          result.push(`    return ${functionName}Cache.get(cacheKey);`);
          result.push(`  }`);
        }

        inFunction = true;
        continue;
      }

      // If in cached function and we hit return, cache the result
      if (inFunction && line.trim().startsWith('return ')) {
        result.push(`  const result = ${line.trim().substring(7)}`);
        result.push(`  ${functionName}Cache.set(cacheKey, result);`);
        result.push(`  return result;`);
        inFunction = false;
        continue;
      }

      result.push(line);
    }

    return result.join('\n');
  }

  /**
   * Optimize nested loops with Set-based lookups
   */
  optimizeNestedLoops(content, params) {
    let result = content;

    // Pattern: Nested loops checking equality
    // for (item1 of arr1) { for (item2 of arr2) { if (item1 === item2) ... } }
    result = result.replace(
      /for\s*\(\s*(?:const|let)\s+(\w+)\s+of\s+(\w+)\s*\)\s*\{[^}]*for\s*\(\s*(?:const|let)\s+(\w+)\s+of\s+(\w+)\s*\)\s*\{[^}]*if\s*\(\s*\1\s*===\s*\3\s*\)/gs,
      (match, var1, arr1, var2, arr2) => {
        return `// PERFORMANCE: Optimized O(n²) to O(n) using Set
const ${arr2}Set = new Set(${arr2});
for (const ${var1} of ${arr1}) {
  if (${arr2}Set.has(${var1}))`;
      }
    );

    // Pattern: array.includes in loop (O(n²))
    result = result.replace(
      /for\s*\(\s*(?:const|let)\s+(\w+)\s+of\s+(\w+)\s*\)\s*\{([^}]*if\s*\([^}]*?(\w+)\.includes\(\1\))/gs,
      (match, itemVar, arrayVar, body, targetArray) => {
        return `// PERFORMANCE: Optimized includes() in loop using Set
const ${targetArray}Set = new Set(${targetArray});
for (const ${itemVar} of ${arrayVar}) {
  if (${targetArray}Set.has(${itemVar}))`;
      }
    );

    return result;
  }

  // ========================
  // TEST REFACTORINGS
  // ========================

  /**
   * Generate unit test for an untested function
   * Creates a basic test file with happy path and edge cases
   */
  generateUnitTest(content, params) {
    const lines = content.split('\n');
    let testContent = '';

    // Find exported functions
    const functionMatches = content.matchAll(/export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/g);

    for (const match of functionMatches) {
      const funcName = match[1];
      const funcParams = match[2];

      // Generate test file content
      testContent += `// TEST: Auto-generated unit test for ${funcName}\n`;
      testContent += `describe('${funcName}', () => {\n`;
      testContent += `  it('should ${funcName.replace(/([A-Z])/g, ' $1').toLowerCase()}', () => {\n`;
      testContent += `    // TODO: Add test implementation\n`;
      testContent += `    const result = ${funcName}(/* TODO: Add params */);\n`;
      testContent += `    expect(result).toBeDefined();\n`;
      testContent += `  });\n\n`;

      testContent += `  it('should handle null inputs', () => {\n`;
      testContent += `    expect(() => ${funcName}(null)).toThrow();\n`;
      testContent += `  });\n\n`;

      testContent += `  it('should handle empty inputs', () => {\n`;
      testContent += `    const result = ${funcName}();\n`;
      testContent += `    expect(result).toBeDefined();\n`;
      testContent += `  });\n`;
      testContent += `});\n\n`;
    }

    return testContent || '// No exported functions found to test\n' + content;
  }

  /**
   * Add edge case tests to existing test suite
   */
  addEdgeCaseTests(content, params) {
    let result = content;

    // Find test blocks without edge cases
    const testPattern = /describe\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*\(\)\s*=>\s*\{([\s\S]*?)\n\}\);/g;

    result = result.replace(testPattern, (match, testName, testBody) => {
      // Check if already has edge case tests
      if (testBody.includes('null') && testBody.includes('undefined') && testBody.includes('empty')) {
        return match; // Already has edge cases
      }

      // Add edge case tests
      let edgeCases = '';

      if (!testBody.includes('null')) {
        edgeCases += `\n  // AUTO-GENERATED: Edge case tests\n`;
        edgeCases += `  it('should handle null inputs', () => {\n`;
        edgeCases += `    expect(() => ${testName}(null)).toThrow();\n`;
        edgeCases += `  });\n`;
      }

      if (!testBody.includes('undefined')) {
        edgeCases += `\n  it('should handle undefined inputs', () => {\n`;
        edgeCases += `    expect(() => ${testName}(undefined)).toThrow();\n`;
        edgeCases += `  });\n`;
      }

      if (!testBody.includes('empty')) {
        edgeCases += `\n  it('should handle empty inputs', () => {\n`;
        edgeCases += `    const result = ${testName}([]);\n`;
        edgeCases += `    expect(result).toBeDefined();\n`;
        edgeCases += `  });\n`;
      }

      if (!testBody.includes('negative')) {
        edgeCases += `\n  it('should handle negative values', () => {\n`;
        edgeCases += `    const result = ${testName}(-1);\n`;
        edgeCases += `    expect(result).toBeDefined();\n`;
        edgeCases += `  });\n`;
      }

      return `describe('${testName}', () => {${testBody}${edgeCases}\n});`;
    });

    return result;
  }

  /**
   * Improve weak test assertions
   * Replace generic matchers with specific ones
   */
  improveTestAssertions(content, params) {
    let result = content;

    // Pattern 1: toBe(true) -> toBeTruthy() or more specific
    result = result.replace(
      /expect\(Array\.isArray\(([^)]+)\)\)\.toBe\(true\)/g,
      'expect($1).toBeInstanceOf(Array)'
    );

    result = result.replace(
      /expect\(([^)]+)\)\.toBe\(true\)/g,
      'expect($1).toBeTruthy()'
    );

    result = result.replace(
      /expect\(([^)]+)\)\.toBe\(false\)/g,
      'expect($1).toBeFalsy()'
    );

    // Pattern 2: Truthy checks -> specific property checks
    result = result.replace(
      /expect\(([^.]+)\.(\w+)\)\.toBeTruthy\(\)/g,
      'expect($1).toHaveProperty(\'$2\')'
    );

    // Pattern 3: Generic toBe -> specific matchers
    result = result.replace(
      /expect\(typeof\s+([^)]+)\)\.toBe\(['"]string['"]\)/g,
      'expect($1).toEqual(expect.any(String))'
    );

    result = result.replace(
      /expect\(typeof\s+([^)]+)\)\.toBe\(['"]number['"]\)/g,
      'expect($1).toEqual(expect.any(Number))'
    );

    result = result.replace(
      /expect\(typeof\s+([^)]+)\)\.toBe\(['"]object['"]\)/g,
      'expect($1).toEqual(expect.any(Object))'
    );

    return result;
  }

  /**
   * Add mocks for external dependencies
   */
  addTestMocks(content, params) {
    let result = content;
    let mocksAdded = false;

    // Check for fetch/API calls
    if (content.includes('fetch(') || content.includes('axios.')) {
      const mockSetup = `
  // AUTO-GENERATED: Mock setup for API calls
  beforeEach(() => {
    global.fetch = jest.fn().mockResolvedValue({
      json: () => Promise.resolve({ data: 'mock data' }),
      ok: true,
      status: 200
    });
  });

  afterEach(() => {
    global.fetch.mockClear();
  });
`;
      // Insert after first describe(
      result = result.replace(
        /(describe\s*\([^{]+\{)/,
        `$1${mockSetup}`
      );
      mocksAdded = true;
    }

    // Check for database calls
    if (content.includes('db.') || content.includes('database.')) {
      const dbMock = `
  // AUTO-GENERATED: Mock setup for database calls
  const mockDb = {
    query: jest.fn().mockResolvedValue([]),
    insert: jest.fn().mockResolvedValue({ id: 1 }),
    update: jest.fn().mockResolvedValue({ affected: 1 }),
    delete: jest.fn().mockResolvedValue({ deleted: 1 })
  };
`;
      // Insert at top of file
      result = dbMock + '\n' + result;
      mocksAdded = true;
    }

    // Check for filesystem operations
    if (content.includes('fs.') || content.includes('readFile') || content.includes('writeFile')) {
      const fsMock = `
  // AUTO-GENERATED: Mock setup for filesystem operations
  jest.mock('fs', () => ({
    readFile: jest.fn().mockResolvedValue('mock file content'),
    writeFile: jest.fn().mockResolvedValue(undefined),
    readFileSync: jest.fn().mockReturnValue('mock file content'),
    writeFileSync: jest.fn()
  }));
`;
      // Insert at top of file
      result = fsMock + '\n' + result;
      mocksAdded = true;
    }

    if (mocksAdded) {
      result = '// TEST: Auto-generated mocks added\n' + result;
    }

    return result;
  }

  // ========================
  // REFACTORING OPERATIONS
  // ========================

  /**
   * Extract magic numbers to named constants
   */
  extractConstant(content, params) {
    const lines = content.split('\n');
    const constants = [];
    const seenNumbers = new Set();

    // Find magic numbers (excluding 0, 1)
    const magicNumberPattern = /\b(\d{2,}|0\.\d+)\b/g;

    lines.forEach((line, index) => {
      const matches = line.matchAll(magicNumberPattern);
      for (const match of matches) {
        const num = match[1];
        if (num !== '0' && num !== '1' && !seenNumbers.has(num)) {
          seenNumbers.add(num);
          // Generate constant name based on context
          const contextMatch = line.match(new RegExp(`(\\w+)\\s*[=<>]+\\s*${num}`));
          const varName = contextMatch ? contextMatch[1].toUpperCase() : 'VALUE';
          constants.push({
            name: `${varName}_THRESHOLD_${num.replace('.', '_')}`,
            value: num,
            line: index
          });
        }
      }
    });

    if (constants.length === 0) {
      return content; // No magic numbers found
    }

    // Add constants at top
    const constDeclarations = constants.map(c =>
      `const ${c.name} = ${c.value};`
    ).join('\n');

    // Replace numbers with constants in code
    let result = content;
    constants.forEach(c => {
      const regex = new RegExp(`\\b${c.value}\\b`, 'g');
      result = result.replace(regex, c.name);
    });

    return `// REFACTORING: Extracted magic numbers to constants\n${constDeclarations}\n\n${result}`;
  }

  /**
   * Simplify complex conditionals
   */
  simplifyConditional(content, params) {
    let result = content;

    // Pattern 1: if (x.y === true) or if (x === true) -> if (x.y) or if (x)
    // Updated to match property access (obj.prop) and simple variables
    result = result.replace(
      /if\s*\(\s*([\w.]+)\s*===\s*true\s*\)/g,
      'if ($1)'
    );

    result = result.replace(
      /if\s*\(\s*([\w.]+)\s*===\s*false\s*\)/g,
      'if (!$1)'
    );

    // Pattern 2: if (x == true) -> if (x)
    result = result.replace(
      /if\s*\(\s*([\w.]+)\s*==\s*true\s*\)/g,
      'if ($1)'
    );

    result = result.replace(
      /if\s*\(\s*([\w.]+)\s*==\s*false\s*\)/g,
      'if (!$1)'
    );

    // Pattern 3: if (!x.y === false) -> if (x.y)
    result = result.replace(
      /if\s*\(\s*!\s*([\w.]+)\s*===\s*false\s*\)/g,
      'if ($1)'
    );

    // Pattern 4: Simplify double negatives !!(!x) -> x
    result = result.replace(
      /if\s*\(\s*!\s*!\s*\(\s*!\s*([\w.]+)\s*\)\s*\)/g,
      'if ($1)'
    );

    return result;
  }

  /**
   * Remove duplicated code by extracting common patterns
   */
  removeDuplication(content, params) {
    let result = content;

    // Find repeated function patterns (simplified detection)
    // Pattern: async function getXById(id) { const x = await db.query(...) }

    const functionPattern = /async function get(\w+)ById\(id\)\s*\{[\s\S]*?const \1 = await db\.query\([^;]+;[\s\S]*?if \(!(\1)\) throw new Error\([^)]+\);[\s\S]*?return \1;[\s\S]*?\}/g;

    const matches = [...content.matchAll(functionPattern)];

    if (matches.length >= 2) {
      // Extract common pattern
      const comment = '// REFACTORING: Extracted common query pattern\n';
      const genericFunction = `async function getEntityById(table, id, entityName = 'Entity') {
  const entity = await db.query(\`SELECT * FROM \${table} WHERE id = ?\`, [id]);
  if (!entity) throw new Error(\`\${entityName} not found\`);
  return entity;
}

`;

      // Replace specific functions with calls to generic
      matches.forEach(match => {
        const entityName = match[1];
        const replacement = `const get${entityName}ById = (id) => getEntityById('${entityName.toLowerCase()}s', id, '${entityName}');`;
        result = result.replace(match[0], replacement);
      });

      result = comment + genericFunction + result;
    }

    return result;
  }

  /**
   * Extract long method into smaller methods
   */
  extractMethod(content, params) {
    let result = content;

    // Simplified extraction: Look for functions with validation + logic blocks
    // Pattern: function with multiple distinct sections (validation, calculation, etc.)

    const longFunctionPattern = /function (\w+)\([^)]*\)\s*\{([\s\S]{300,}?)\}/g;

    result = result.replace(longFunctionPattern, (match, funcName, body) => {
      // Check if function has distinct sections
      if (body.includes('// Validate') || body.includes('// Calculate') || body.includes('// Save')) {
        // Add comment suggesting extraction
        return `// REFACTORING: Consider extracting methods from ${funcName}\n// Suggested: validate${funcName}, calculate${funcName}, save${funcName}\n${match}`;
      }
      return match;
    });

    return result;
  }

  // ========================
  // DOCUMENTATION OPERATIONS
  // ========================

  /**
   * Add JSDoc to undocumented functions
   */
  addJSDoc(content, params) {
    const lines = content.split('\n');
    const result = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for export function without JSDoc
      const funcMatch = line.match(/export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/);

      if (funcMatch) {
        // Check if previous lines have JSDoc
        const prevLine = i > 0 ? lines[i - 1].trim() : '';
        const twoPrevLine = i > 1 ? lines[i - 2].trim() : '';

        if (!prevLine.includes('*/') && !twoPrevLine.includes('*/')) {
          // Add JSDoc
          const funcName = funcMatch[1];
          const params = funcMatch[2];
          const indent = line.match(/^\s*/)[0];

          result.push(`${indent}/**`);
          result.push(`${indent} * ${funcName.replace(/([A-Z])/g, ' $1').trim()}`);

          // Add @param for each parameter
          if (params.trim()) {
            const paramList = params.split(',').map(p => p.trim().split(/\s+/)[0]);
            paramList.forEach(param => {
              if (param && param !== '...') {
                result.push(`${indent} * @param {*} ${param} - Parameter description`);
              }
            });
          }

          result.push(`${indent} * @returns {*} Return value description`);
          result.push(`${indent} */`);
        }
      }

      result.push(line);
    }

    return result.join('\n');
  }

  /**
   * Add @param documentation to existing JSDoc
   */
  addParamDocs(content, params) {
    let result = content;

    // Find functions with params but missing @param in JSDoc
    const funcPattern = /\/\*\*([\s\S]*?)\*\/\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]+)\)/g;

    result = result.replace(funcPattern, (match, jsdoc, funcName, funcParams) => {
      const paramList = funcParams.split(',').map(p => p.trim().split(/\s+/)[0]);
      let updatedJSDoc = jsdoc;

      // Check which params are missing
      paramList.forEach(param => {
        if (param && !jsdoc.includes(`@param`) || !jsdoc.includes(param)) {
          // Add missing @param before @returns or at end
          const indent = match.match(/^\s*/)[0];
          const paramDoc = `\n${indent} * @param {*} ${param} - Parameter description`;

          if (updatedJSDoc.includes('@returns')) {
            updatedJSDoc = updatedJSDoc.replace(/(@returns)/, `${paramDoc}\n${indent} * $1`);
          } else {
            updatedJSDoc += paramDoc;
          }
        }
      });

      return `/**${updatedJSDoc}*/\nexport function ${funcName}(${funcParams})`;
    });

    return result;
  }

  /**
   * Add @returns documentation to functions that return values
   */
  addReturnDocs(content, params) {
    let result = content;

    // Find functions with return statements but no @returns
    const funcPattern = /\/\*\*([\s\S]*?)\*\/\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{([\s\S]*?)return\s+([^;]+);/g;

    result = result.replace(funcPattern, (match, jsdoc, funcName, body, returnValue) => {
      if (!jsdoc.includes('@returns') && !jsdoc.includes('@return')) {
        const indent = match.match(/^\s*/)[0];
        const isAsync = match.includes('async');
        const returnType = isAsync ? 'Promise<*>' : '*';

        const updatedJSDoc = jsdoc + `\n${indent} * @returns {${returnType}} Return value description`;
        return match.replace(jsdoc, updatedJSDoc);
      }
      return match;
    });

    return result;
  }

  /**
   * Add @example sections to JSDoc
   */
  addUsageExamples(content, params) {
    let result = content;

    // Find JSDoc without @example
    const jsdocPattern = /\/\*\*([\s\S]*?)\*\/\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/g;

    result = result.replace(jsdocPattern, (match, jsdoc, funcName, funcParams) => {
      if (!jsdoc.includes('@example')) {
        const indent = match.match(/^\s*/)[0];

        // Generate simple example
        const paramList = funcParams ? funcParams.split(',').map((p, i) => `param${i + 1}`).join(', ') : '';
        const example = `\n${indent} * @example\n${indent} * ${funcName}(${paramList})\n${indent} * // Returns: result`;

        const updatedJSDoc = jsdoc + example;
        return match.replace(jsdoc, updatedJSDoc);
      }
      return match;
    });

    return result;
  }

  /**
   * Count line changes between two versions
   */
  countLineChanges(original, modified) {
    const originalLines = original.split('\n');
    const modifiedLines = modified.split('\n');

    // Simple diff: count lines that are different
    const maxLength = Math.max(originalLines.length, modifiedLines.length);
    let changes = 0;

    for (let i = 0; i < maxLength; i++) {
      const orig = originalLines[i] || '';
      const mod = modifiedLines[i] || '';
      if (orig !== mod) {
        changes++;
      }
    }

    return changes;
  }

  /**
   * Get metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      successRate: this.metrics.refactoringsAttempted > 0
        ? this.metrics.refactoringsSucceeded / this.metrics.refactoringsAttempted
        : 0
    };
  }

  /**
   * Print metrics
   */
  printMetrics() {
    const metrics = this.getMetrics();
    console.log('\n+- AUTO-REFACTORING METRICS ---------------------------------+');
    console.log(`| Refactorings Attempted: ${metrics.refactoringsAttempted.toString().padEnd(41)} |`);
    console.log(`| Refactorings Succeeded: ${metrics.refactoringsSucceeded.toString().padEnd(41)} |`);
    console.log(`| Refactorings Failed: ${metrics.refactoringsFailed.toString().padEnd(44)} |`);
    console.log(`| Success Rate: ${(metrics.successRate * 100).toFixed(1)}%${' '.repeat(47 - (metrics.successRate * 100).toFixed(1).length)} |`);
    console.log(`|                                                            |`);
    console.log(`| Files Modified: ${metrics.filesModified.toString().padEnd(49)} |`);
    console.log(`| Lines Changed: ${metrics.linesChanged.toString().padEnd(50)} |`);
    console.log('+------------------------------------------------------------+\n');
  }
}

module.exports = AutoRefactoringEngine;

// Example usage
if (require.main === module) {
  async function test() {
    const engine = new AutoRefactoringEngine();

    console.log('\n=== Auto-Refactoring Engine Demo ===\n');

    // Create a test file
    const testContent = `
var x = 10;
var y = 20;
console.log('Debug:', x);
if (someCondition === true) {
  console.debug('test');
  var z = x + y;
}
// var oldCode = 'removed';
    `.trim();

    console.log('Original content:');
    console.log(testContent);
    console.log('\n---\n');

    // Test modernize var to const
    console.log('After modernize-var-to-const:');
    console.log(engine.performRefactoring(testContent, 'modernize-var-to-const'));
    console.log('\n---\n');

    // Test remove console logs
    console.log('After remove-console-logs:');
    console.log(engine.performRefactoring(testContent, 'remove-console-logs'));
    console.log('\n---\n');

    engine.printMetrics();
  }

  test().catch(console.error);
}
