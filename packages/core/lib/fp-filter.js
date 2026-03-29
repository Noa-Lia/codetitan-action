'use strict';

/**
 * fp-filter.js — False-positive filter for CodeTitan SAST findings.
 *
 * Uses the Claude AI API to review HIGH/CRITICAL findings and determine
 * whether each one is a genuine issue or a false positive. Falls back
 * gracefully when @anthropic-ai/sdk is not installed or no API key is set.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

function isDebugEnabled(value) {
  return value === '1' || value === 'true';
}

const SHOULD_DEBUG =
  isDebugEnabled(process.env.CODETITAN_DEBUG) ||
  isDebugEnabled(process.env.CODETITAN_DEBUG_FP_FILTER);

const _dbg = (...args) => {
  if (!SHOULD_DEBUG) {
    return;
  }

  process.stderr.write(args.join(' ') + '\n');
};

// Optional SDK — module still loads when the package is absent.
let Anthropic = null;
try {
  Anthropic = require('@anthropic-ai/sdk');
} catch (_e) {
  _dbg('[fp-filter] @anthropic-ai/sdk not installed — FPFilter will be disabled.');
}

/** Severity levels that are worth the API cost of FP-filtering. */
const FILTER_SEVERITIES = new Set(['HIGH', 'CRITICAL']);

/**
 * Build a deterministic cache key for a finding without any crypto dep.
 *
 * @param {string} filePath
 * @param {object} finding
 * @returns {string}
 */
function cacheKey(filePath, finding) {
  const snippet = (finding.snippet || '').slice(0, 50);
  return `${filePath}|${finding.category}:${finding.line}:${snippet}`;
}

/**
 * Extract `linesAbove` lines before and `linesBelow` lines after a 1-based
 * line number from a file's raw text content.
 *
 * @param {string} content   Raw file text.
 * @param {number} lineNo    1-based target line.
 * @param {number} linesAbove
 * @param {number} linesBelow
 * @returns {string}
 */
function extractContext(content, lineNo, linesAbove = 5, linesBelow = 5) {
  if (!content) return '';
  const lines = content.split('\n');
  const start = Math.max(0, lineNo - 1 - linesAbove);
  const end   = Math.min(lines.length, lineNo + linesBelow);
  return lines
    .slice(start, end)
    .map((text, idx) => {
      const no = start + idx + 1;
      const marker = no === lineNo ? '>>>' : '   ';
      return `${marker} ${String(no).padStart(4, ' ')} | ${text}`;
    })
    .join('\n');
}

/**
 * Build the prompt that is sent to Claude for a batch of findings.
 *
 * @param {string} filePath
 * @param {string} codeContext
 * @param {object[]} findings
 * @returns {string}
 */
function buildPrompt(filePath, codeContext, findings) {
  const findingsList = findings
    .map((f, i) => `${i + 1}. ${JSON.stringify(f)}`)
    .join('\n');

  return `You are a security code reviewer. For each finding below, classify it as TRUE_POSITIVE (real issue), FALSE_POSITIVE (not a real issue in this context), or UNCERTAIN.

File: ${filePath}

Code context (around the finding):
\`\`\`
${codeContext}
\`\`\`

Findings to classify:
${findingsList}

Respond with ONLY a JSON array in this exact format:
[{"id": 1, "verdict": "TRUE_POSITIVE", "reason": "brief reason"},...]

Rules:
- FALSE_POSITIVE only if you are >90% confident it's not exploitable given the code context
- UNCERTAIN = keep the finding (conservative)
- Consider sanitization, input validation, and actual data flow visible in the context`;
}

/**
 * Parse Claude's response text into a map of { id -> verdict }.
 * Returns an empty map on any parse failure (caller will keep findings).
 *
 * @param {string} text
 * @returns {Map<number, string>}
 */
function parseVerdicts(text) {
  const verdicts = new Map();
  try {
    // Strip markdown fences if present.
    const cleaned = text.replace(/```(?:json)?/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(cleaned);
    if (!Array.isArray(parsed)) return verdicts;
    for (const item of parsed) {
      if (typeof item.id === 'number' && typeof item.verdict === 'string') {
        verdicts.set(item.id, item.verdict.toUpperCase());
      }
    }
  } catch (e) {
    _dbg('[fp-filter] Failed to parse Claude response:', e.message);
  }
  return verdicts;
}

// ---------------------------------------------------------------------------
// VerdictStore — persistent false-positive verdict cache backed by JSONL file
// ---------------------------------------------------------------------------

const VERDICT_STORE_PATH   = path.join(os.homedir(), '.codetitan', 'fp-verdicts.json');
const VERDICT_STORE_MAX    = 10_000;
const VERDICT_STORE_PRUNE  = Math.floor(VERDICT_STORE_MAX * 0.2); // oldest 20 %

/**
 * Persists FP verdicts to `~/.codetitan/fp-verdicts.json` in JSONL format so
 * they survive across analysis sessions.
 *
 * Design decisions:
 *  - Synchronous read on init (once per process startup — acceptable cost).
 *  - Async append-only writes (non-blocking hot path).
 *  - In-memory Map mirrors the file; all lookups are O(1).
 *  - When the store reaches VERDICT_STORE_MAX entries the oldest 20 % are
 *    pruned from both the Map and the backing file (full rewrite of what
 *    remains).
 */
class VerdictStore {
  constructor() {
    /** @type {Map<string, { isFP: boolean, reason?: string, ts: number }>} */
    this._map    = new Map();
    this._path   = VERDICT_STORE_PATH;
    this._writing = false; // simple mutex to avoid concurrent full-rewrites
    this._load();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** Synchronously load existing verdicts from disk into memory. */
  _load() {
    if (typeof fs.readFileSync !== 'function') {
      return;
    }

    try {
      const raw = fs.readFileSync(this._path, 'utf8');
      let loaded = 0;
      for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const entry = JSON.parse(trimmed);
          if (entry && typeof entry.key === 'string') {
            this._map.set(entry.key, {
              isFP:   Boolean(entry.isFP),
              reason: entry.reason,
              ts:     entry.ts || 0,
            });
            loaded++;
          }
        } catch (_) {
          // Skip malformed lines silently.
        }
      }
      _dbg(`[VerdictStore] Loaded ${loaded} persisted verdicts from ${this._path}`);
    } catch (err) {
      if (err.code !== 'ENOENT') {
        _dbg('[VerdictStore] Could not read verdicts file:', err.message);
      }
      // File absent — start fresh (normal on first run).
    }
  }

  /**
   * Ensure the parent directory exists, then append a single JSONL line.
   * Non-blocking — errors are logged but never thrown.
   *
   * @param {string}   key
   * @param {boolean}  isFP
   * @param {string}  [reason]
   */
  _append(key, isFP, reason) {
    const line = JSON.stringify({ key, isFP, reason, ts: Date.now() }) + '\n';
    // Ensure directory exists (async — ignore errors if already present).
    fs.mkdir(path.dirname(this._path), { recursive: true }, (mkdirErr) => {
      if (mkdirErr && mkdirErr.code !== 'EEXIST') {
        _dbg('[VerdictStore] mkdir failed:', mkdirErr.message);
        return;
      }
      fs.appendFile(this._path, line, 'utf8', (appendErr) => {
        if (appendErr) {
          _dbg('[VerdictStore] appendFile failed:', appendErr.message);
        }
      });
    });
  }

  /**
   * Rewrite the backing file from the current in-memory Map contents.
   * Used only after a prune — keeps the file consistent with memory.
   */
  _rewrite() {
    if (this._writing) return; // avoid overlapping rewrites
    this._writing = true;

    const lines = [];
    for (const [key, val] of this._map) {
      lines.push(JSON.stringify({ key, isFP: val.isFP, reason: val.reason, ts: val.ts }));
    }
    const content = lines.join('\n') + '\n';

    fs.mkdir(path.dirname(this._path), { recursive: true }, (mkdirErr) => {
      if (mkdirErr && mkdirErr.code !== 'EEXIST') {
        _dbg('[VerdictStore] mkdir failed during rewrite:', mkdirErr.message);
        this._writing = false;
        return;
      }
      fs.writeFile(this._path, content, 'utf8', (writeErr) => {
        if (writeErr) {
          _dbg('[VerdictStore] rewrite failed:', writeErr.message);
        } else {
          _dbg(`[VerdictStore] Rewrote ${this._map.size} entries after prune.`);
        }
        this._writing = false;
      });
    });
  }

  /**
   * Remove the oldest VERDICT_STORE_PRUNE entries when the cap is exceeded.
   * Entries are sorted by ascending timestamp.
   */
  _prune() {
    if (this._map.size <= VERDICT_STORE_MAX) return;

    // Collect all entries sorted oldest-first.
    const sorted = [...this._map.entries()].sort((a, b) => a[1].ts - b[1].ts);
    const toDelete = sorted.slice(0, VERDICT_STORE_PRUNE);

    for (const [key] of toDelete) {
      this._map.delete(key);
    }

    _dbg(`[VerdictStore] Pruned ${toDelete.length} oldest entries (cap=${VERDICT_STORE_MAX}).`);
    this._rewrite();
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Persist a verdict for `key` to disk and cache it in memory.
   *
   * @param {string}  key    Cache key (from `cacheKey()`).
   * @param {boolean} isFP   Whether the finding is a false positive.
   * @param {string} [reason] Optional human-readable reason.
   */
  save(key, isFP, reason) {
    this._map.set(key, { isFP, reason, ts: Date.now() });
    this._append(key, isFP, reason);
    this._prune();
  }

  /**
   * Retrieve a previously stored verdict.
   *
   * @param {string} key
   * @returns {{ isFP: boolean, reason?: string, ts: number } | undefined}
   */
  get(key) {
    return this._map.get(key);
  }

  /**
   * Total number of verdicts held in memory (mirrors disk after load).
   *
   * @returns {number}
   */
  size() {
    return this._map.size;
  }
}

// ---------------------------------------------------------------------------

class FPFilter {
  /**
   * @param {object}  options
   * @param {boolean} [options.enabled=true]
   * @param {string}  [options.model='claude-haiku-4-5-20251001']
   * @param {number}  [options.maxFindingsPerCall=5]
   * @param {boolean} [options.cacheEnabled=true]
   */
  constructor(options = {}) {
    const {
      enabled           = true,
      model             = 'claude-haiku-4-5-20251001',
      maxFindingsPerCall = 5,
      cacheEnabled      = true,
    } = options;

    this.model              = model;
    this.maxFindingsPerCall = maxFindingsPerCall;
    this.cacheEnabled       = cacheEnabled;

    // Disable if SDK missing or no API key is configured.
    if (!Anthropic) {
      this.enabled = false;
      _dbg('[fp-filter] Disabled — @anthropic-ai/sdk not available.');
    } else if (!process.env.ANTHROPIC_API_KEY) {
      this.enabled = false;
      _dbg('[fp-filter] Disabled — ANTHROPIC_API_KEY not set.');
    } else {
      this.enabled = enabled;
      this._client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    }

    /** @type {Map<string, boolean>} in-memory result cache */
    this._cache = new Map();

    /** @type {VerdictStore | null} persistent verdict store */
    this._verdictStore = this.cacheEnabled ? new VerdictStore() : null;

    // Stats counters.
    this._stats = {
      total:            0,
      filtered:         0,
      passedThrough:    0,
      cacheHits:        0,
      apiCallsMade:     0,
      persistedVerdicts: 0,
    };

    // Initialise persistedVerdicts count from what the store loaded.
    if (this._verdictStore) {
      this._stats.persistedVerdicts = this._verdictStore.size();
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Filter an array of findings for a single file, removing false positives.
   *
   * Only HIGH/CRITICAL findings are sent to the API. All other severities pass
   * through untouched. If the API call fails the original findings are returned
   * unmodified — we never drop findings on error.
   *
   * @param {object[]} findings    Array of finding objects.
   * @param {string}   fileContent Raw text content of the analysed file.
   * @param {string}   filePath    Relative or absolute path used for context.
   * @returns {Promise<object[]>}  Findings with false positives removed.
   */
  async filterFindings(findings, fileContent, filePath) {
    if (!findings || findings.length === 0) return findings;

    this._stats.total += findings.length;

    // Short-circuit when disabled.
    if (!this.enabled) {
      this._stats.passedThrough += findings.length;
      return findings;
    }

    // Split findings by whether they should be reviewed.
    const toReview  = [];
    const passThrough = [];

    for (const f of findings) {
      const severity = (f.severity || '').toUpperCase();
      if (FILTER_SEVERITIES.has(severity)) {
        toReview.push(f);
      } else {
        passThrough.push(f);
        this._stats.passedThrough++;
      }
    }

    if (toReview.length === 0) {
      return findings;
    }

    // --- Cache pass ---
    const stillNeedReview = [];
    const cacheResults    = new Map(); // finding index -> isFP

    for (let i = 0; i < toReview.length; i++) {
      const f   = toReview[i];
      const key = cacheKey(filePath, f);

      if (this.cacheEnabled && this._cache.has(key)) {
        // Hot in-memory cache hit.
        this._stats.cacheHits++;
        cacheResults.set(i, this._cache.get(key));
      } else if (this._verdictStore) {
        // Check persisted store (populated from a previous session).
        const stored = this._verdictStore.get(key);
        if (stored !== undefined) {
          this._stats.cacheHits++;
          // Warm the in-memory cache so subsequent calls in the same session are fast.
          this._cache.set(key, stored.isFP);
          cacheResults.set(i, stored.isFP);
        } else {
          stillNeedReview.push({ originalIdx: i, finding: f });
        }
      } else {
        stillNeedReview.push({ originalIdx: i, finding: f });
      }
    }

    // --- API pass: process in batches ---
    const apiResults = new Map(); // originalIdx -> isFP

    if (stillNeedReview.length > 0) {
      const batches = [];
      for (let i = 0; i < stillNeedReview.length; i += this.maxFindingsPerCall) {
        batches.push(stillNeedReview.slice(i, i + this.maxFindingsPerCall));
      }

      for (const batch of batches) {
        // Build a merged code context spanning all findings in the batch.
        const contexts = batch.map(({ finding }) =>
          extractContext(fileContent, finding.line || 1)
        );
        const mergedContext = contexts.join('\n---\n');

        const batchFindings = batch.map(({ finding }) => finding);
        const prompt        = buildPrompt(filePath, mergedContext, batchFindings);

        let verdicts = new Map();
        try {
          this._stats.apiCallsMade++;
          const message = await this._client.messages.create({
            model:      this.model,
            max_tokens: 1024,
            messages:   [{ role: 'user', content: prompt }],
          });

          const responseText = message.content
            .filter(b => b.type === 'text')
            .map(b => b.text)
            .join('');

          verdicts = parseVerdicts(responseText);
          _dbg(`[fp-filter] Batch of ${batch.length} findings processed. Verdicts: ${verdicts.size}`);
        } catch (err) {
          _dbg('[fp-filter] API call failed:', err.message, '— keeping original findings.');
          // On error: treat everything in this batch as non-FP (keep them).
          for (const { originalIdx } of batch) {
            apiResults.set(originalIdx, false);
          }
          continue;
        }

        // Map 1-based prompt IDs back to originalIdx.
        batch.forEach(({ originalIdx, finding }, batchPos) => {
          const promptId = batchPos + 1;
          const verdict  = verdicts.get(promptId);
          const isFP     = verdict === 'FALSE_POSITIVE';

          apiResults.set(originalIdx, isFP);

          // Populate in-memory cache and persist to disk.
          if (this.cacheEnabled) {
            const key = cacheKey(filePath, finding);
            this._cache.set(key, isFP);
            if (this._verdictStore) {
              this._verdictStore.save(key, isFP);
              this._stats.persistedVerdicts = this._verdictStore.size();
            }
          }
        });
      }
    }

    // --- Assemble final reviewed set ---
    const reviewed = [];
    for (let i = 0; i < toReview.length; i++) {
      const isFP = cacheResults.has(i)
        ? cacheResults.get(i)
        : (apiResults.get(i) || false);

      if (isFP) {
        this._stats.filtered++;
        _dbg(`[fp-filter] Dropped FP: ${toReview[i].category} at line ${toReview[i].line}`);
      } else {
        reviewed.push(toReview[i]);
        this._stats.passedThrough++;
      }
    }

    return [...passThrough, ...reviewed];
  }

  /**
   * Check whether a single finding is a false positive.
   *
   * Extracts code context from `codeContext` (raw file text) or uses it
   * directly as a pre-extracted snippet string.
   *
   * @param {object} finding      The finding object.
   * @param {string} codeContext  Either raw file content or a pre-built snippet.
   * @returns {Promise<boolean>}  `true` if the finding is a false positive.
   */
  async isFalsePositive(finding, codeContext) {
    if (!this.enabled) return false;

    const key = cacheKey('__single__', finding);
    if (this.cacheEnabled && this._cache.has(key)) {
      this._stats.cacheHits++;
      return this._cache.get(key);
    }
    if (this._verdictStore) {
      const stored = this._verdictStore.get(key);
      if (stored !== undefined) {
        this._stats.cacheHits++;
        this._cache.set(key, stored.isFP);
        return stored.isFP;
      }
    }

    // Treat codeContext as raw file content if it contains newlines and a line
    // number is available, otherwise use it verbatim.
    let snippet = codeContext;
    if (finding.line && codeContext && codeContext.includes('\n')) {
      snippet = extractContext(codeContext, finding.line);
    }

    const prompt   = buildPrompt('(single-finding check)', snippet, [finding]);
    let   isFP     = false;

    try {
      this._stats.apiCallsMade++;
      const message = await this._client.messages.create({
        model:      this.model,
        max_tokens: 256,
        messages:   [{ role: 'user', content: prompt }],
      });

      const responseText = message.content
        .filter(b => b.type === 'text')
        .map(b => b.text)
        .join('');

      const verdicts = parseVerdicts(responseText);
      isFP = verdicts.get(1) === 'FALSE_POSITIVE';
    } catch (err) {
      _dbg('[fp-filter] isFalsePositive API call failed:', err.message);
      isFP = false; // Conservative: keep the finding on error.
    }

    if (this.cacheEnabled) {
      this._cache.set(key, isFP);
      if (this._verdictStore) {
        this._verdictStore.save(key, isFP);
        this._stats.persistedVerdicts = this._verdictStore.size();
      }
    }

    return isFP;
  }

  /**
   * Returns lifetime statistics for this filter instance.
   *
   * @returns {{ total: number, filtered: number, passedThrough: number, cacheHits: number, apiCallsMade: number, persistedVerdicts: number }}
   */
  getStats() {
    // Refresh persistedVerdicts from the live store in case it changed.
    if (this._verdictStore) {
      this._stats.persistedVerdicts = this._verdictStore.size();
    }
    return { ...this._stats };
  }
}

module.exports = FPFilter;
