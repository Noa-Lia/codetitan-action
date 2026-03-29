/**
 * Embeddings Engine for CodeTitan Level 6
 *
 * Provides semantic understanding of code issues and automated remediation recommendations.
 * Uses embeddings to find similar historical issues and suggest proven fixes.
 *
 * NOW UPGRADED: Supports Semantic Code Search (RAG) for the specific codebase.
 *
 * Architecture:
 * - Input: Finding (category, message, context, applied fix) OR Code Chunk
 * - Process: Generate semantic embeddings using local Xenova model
 * - Storage: SQLite with vector extension (pgvector for production)
 * - Output: Similar issues + recommended remediations OR relevant code chunks
 */

const { pipeline } = require('@xenova/transformers');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

class EmbeddingsEngine {
  constructor(dbPath) {
    this.dbPath = dbPath || path.join(__dirname, '..', 'data', 'collective-insight.db');
    this.db = null;
    this.embedder = null;
    this.embeddingDimension = 384; // all-MiniLM-L6-v2 dimension

    // Cache for frequently accessed embeddings
    this.cache = new Map();
    this.maxCacheSize = 1000;

    // Performance metrics
    this.metrics = {
      embeddingsGenerated: 0,
      similaritySearches: 0,
      cacheHits: 0,
      averageEmbeddingTime: 0,
      averageSearchTime: 0,
      codeChunksIndexed: 0
    };
  }

  /**
   * Initialize the embeddings engine
   */
  async init() {
    console.log('Initializing Embeddings Engine...');

    // Initialize database
    await this.initDatabase();

    // Initialize embedding model
    await this.initEmbedder();

    console.log('✓ Embeddings Engine ready!');
  }

  /**
   * Initialize SQLite database with vector storage
   */
  async initDatabase() {
    await fs.mkdir(path.dirname(this.dbPath), { recursive: true });

    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) reject(err);
        else resolve();
      });
    }).then(() => this.createVectorTables());
  }

  /**
   * Create vector storage tables
   */
  async createVectorTables() {
    // Issue embeddings table
    await this.run(`
      CREATE TABLE IF NOT EXISTS issue_embeddings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        context TEXT,
        file_pattern TEXT,
        embedding BLOB NOT NULL,
        applied_fix TEXT,
        fix_success BOOLEAN DEFAULT 0,
        confidence_score REAL DEFAULT 0.0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
      )
    `);

    // NEW: Code Chunk embeddings table for Semantic Code Search
    await this.run(`
      CREATE TABLE IF NOT EXISTS code_embeddings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        start_line INTEGER NOT NULL,
        end_line INTEGER NOT NULL,
        content TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        embedding BLOB NOT NULL,
        last_indexed_at TEXT NOT NULL,
        UNIQUE(file_path, start_line)
      )
    `);

    // Index on category and severity for fast filtering
    await this.run(`
      CREATE INDEX IF NOT EXISTS idx_issue_category
      ON issue_embeddings(category, severity)
    `);

    // Index on file path for faster chunk lookups
    await this.run(`
      CREATE INDEX IF NOT EXISTS idx_code_file_path
      ON code_embeddings(file_path)
    `);

    // Remediation patterns table (learned fixes)
    await this.run(`
      CREATE TABLE IF NOT EXISTS remediation_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        pattern_name TEXT NOT NULL,
        description TEXT,
        fix_template TEXT NOT NULL,
        success_count INTEGER DEFAULT 0,
        application_count INTEGER DEFAULT 0,
        avg_confidence REAL DEFAULT 0.0,
        embedding BLOB NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    // Similarity search results cache
    await this.run(`
      CREATE TABLE IF NOT EXISTS similarity_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query_hash TEXT UNIQUE NOT NULL,
        results BLOB NOT NULL,
        created_at TEXT NOT NULL,
        ttl_seconds INTEGER DEFAULT 3600
      )
    `);
  }

  /**
   * Initialize local embedding model (no API key required)
   */
  async initEmbedder() {
    if (!this.embedder) {
      console.log('Loading local embedding model (Xenova/all-MiniLM-L6-v2)...');
      this.embedder = await pipeline(
        'feature-extraction',
        'Xenova/all-MiniLM-L6-v2'
      );
      console.log('✓ Embedding model loaded');
    }
    return this.embedder;
  }

  /**
   * Generate semantic embedding from text
   */
  async generateTextEmbedding(text) {
    const startTime = Date.now();

    // Check cache
    const cacheKey = this.hashText(text);
    if (this.cache.has(cacheKey)) {
      this.metrics.cacheHits++;
      return this.cache.get(cacheKey);
    }

    // Generate embedding
    const model = await this.initEmbedder();
    const output = await model(text, {
      pooling: 'mean',
      normalize: true
    });

    const embedding = Array.from(output.data);

    // Update cache
    this.updateCache(cacheKey, embedding);

    // Update metrics
    this.metrics.embeddingsGenerated++;
    const duration = Date.now() - startTime;
    this.metrics.averageEmbeddingTime =
      (this.metrics.averageEmbeddingTime * (this.metrics.embeddingsGenerated - 1) + duration) /
      this.metrics.embeddingsGenerated;

    return embedding;
  }

  /**
   * Generate semantic embedding from finding data
   */
  async generateEmbedding(finding) {
    const text = this.findingToText(finding);
    return this.generateTextEmbedding(text);
  }

  /**
   * Convert finding object to text for embedding
   */
  findingToText(finding) {
    const parts = [
      `Category: ${finding.category || 'unknown'}`,
      `Severity: ${finding.severity || 'medium'}`,
      `Message: ${finding.message || ''}`,
      finding.context ? `Context: ${finding.context}` : '',
      finding.file ? `File pattern: ${this.extractFilePattern(finding.file)}` : '',
      finding.snippet ? `Code: ${finding.snippet}` : ''
    ];

    return parts.filter(Boolean).join('\n');
  }

  /**
   * Extract file pattern (e.g., *.js, lib/*.js) from file path
   */
  extractFilePattern(filePath) {
    const parts = filePath.split(/[/\\]/);
    if (parts.length <= 1) return path.extname(filePath);

    const ext = path.extname(filePath);
    const dir = parts[parts.length - 2];
    return `${dir}/*${ext}`;
  }

  /**
   * Store embedding in vector database
   */
  async storeEmbedding(embedding, metadata) {
    const {
      findingId = null,
      category,
      severity,
      message,
      context = null,
      filePattern = null,
      appliedFix = null,
      fixSuccess = false,
      confidenceScore = 0.0
    } = metadata;

    const embeddingBlob = Buffer.from(new Float32Array(embedding).buffer);
    const timestamp = new Date().toISOString();

    const result = await this.run(
      `INSERT INTO issue_embeddings
       (finding_id, category, severity, message, context, file_pattern,
        embedding, applied_fix, fix_success, confidence_score, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        findingId,
        category,
        severity,
        message,
        context,
        filePattern,
        embeddingBlob,
        appliedFix,
        fixSuccess ? 1 : 0,
        confidenceScore,
        timestamp
      ]
    );

    return result.lastID;
  }

  /**
   * Index a codebase by chunking and embedding files
   * @param {string} rootDir - Root directory to index
   * @param {string[]} extensions - File extensions to index
   */
  async indexCodebase(rootDir, extensions = ['.js', '.ts', '.py', '.jsx', '.tsx', '.go', '.rs']) {
    console.log(`Indexing codebase in: ${rootDir}`);

    const files = await this.walkDir(rootDir, extensions);
    console.log(`Found ${files.length} files to index.`);

    let chunkCount = 0;

    for (const file of files) {
      try {
        const content = await fs.readFile(file, 'utf8');
        const chunks = this.chunkFile(content);

        for (const chunk of chunks) {
          const chunkHash = this.hashText(chunk.content);

          // Check if chunk already exists and hasn't changed (naively by hash and path/line)
          const existing = await this.get('SELECT id FROM code_embeddings WHERE file_path = ? AND start_line = ? AND content_hash = ?', [file, chunk.startLine, chunkHash]);

          if (!existing) {
            const embedding = await this.generateTextEmbedding(chunk.content);
            const embeddingBlob = Buffer.from(new Float32Array(embedding).buffer);

            // Upsert logic (delete if exists at path/line but different hash, then insert)
            await this.run('DELETE FROM code_embeddings WHERE file_path = ? AND start_line = ?', [file, chunk.startLine]);

            await this.run(`
                       INSERT INTO code_embeddings (file_path, start_line, end_line, content, content_hash, embedding, last_indexed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                   `, [file, chunk.startLine, chunk.endLine, chunk.content, chunkHash, embeddingBlob, new Date().toISOString()]);

            chunkCount++;
          }
        }
      } catch (err) {
        console.error(`Failed to index file ${file}:`, err.message);
      }
    }

    this.metrics.codeChunksIndexed += chunkCount;
    console.log(`Indexed ${chunkCount} new code chunks.`);
    return chunkCount;
  }

  /**
   * Recursively find files
   */
  async walkDir(dir, extensions) {
    const files = [];
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        files.push(...await this.walkDir(fullPath, extensions));
      } else if (entry.isFile() && extensions.includes(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
    return files;
  }

  /**
   * Split file content into semantic chunks
   */
  chunkFile(content, maxLines = 50, overlap = 5) {
    const lines = content.split('\n');
    const chunks = [];

    for (let i = 0; i < lines.length; i += (maxLines - overlap)) {
      const chunkLines = lines.slice(i, i + maxLines);
      if (chunkLines.length < 5) continue; // Skip tiny chunks

      chunks.push({
        startLine: i + 1,
        endLine: i + chunkLines.length,
        content: chunkLines.join('\n')
      });
    }
    return chunks;
  }

  /**
   * Semantic Code Search
   * @param {string} query - Natural language query
   * @param {number} topK - Number of results
   */
  async searchCode(query, topK = 5, threshold = 0.6) {
    const queryEmbedding = await this.generateTextEmbedding(query);

    const rows = await this.all('SELECT id, file_path, start_line, end_line, content, embedding FROM code_embeddings');

    const results = [];
    for (const row of rows) {
      const storedEmbedding = new Float32Array(row.embedding);
      const similarity = this.cosineSimilarity(queryEmbedding, Array.from(storedEmbedding));

      if (similarity >= threshold) {
        results.push({
          file: row.file_path,
          startLine: row.start_line,
          endLine: row.end_line,
          content: row.content,
          similarity
        });
      }
    }

    return results.sort((a, b) => b.similarity - a.similarity).slice(0, topK);
  }

  /**
   * Find similar historical issues using cosine similarity
   */
  async findSimilarIssues(currentFinding, topK = 5, threshold = 0.7) {
    const startTime = Date.now();

    // Generate embedding for current finding
    const queryEmbedding = await this.generateEmbedding(currentFinding);

    // Get all stored embeddings (with optional category filter)
    const categoryFilter = currentFinding.category
      ? `WHERE category = '${currentFinding.category}'`
      : '';

    const rows = await this.all(`
      SELECT id, category, severity, message, context, file_pattern,
             embedding, applied_fix, fix_success, confidence_score
      FROM issue_embeddings
      ${categoryFilter}
    `);

    // Calculate similarities
    const similarities = [];
    for (const row of rows) {
      const storedEmbedding = new Float32Array(row.embedding);
      const similarity = this.cosineSimilarity(
        queryEmbedding,
        Array.from(storedEmbedding)
      );

      if (similarity >= threshold) {
        similarities.push({
          id: row.id,
          category: row.category,
          severity: row.severity,
          message: row.message,
          context: row.context,
          filePattern: row.file_pattern,
          appliedFix: row.applied_fix,
          fixSuccess: row.fix_success === 1,
          confidenceScore: row.confidence_score,
          similarity: parseFloat(similarity.toFixed(4))
        });
      }
    }

    // Sort by similarity descending
    similarities.sort((a, b) => b.similarity - a.similarity);

    // Update metrics
    this.metrics.similaritySearches++;
    const duration = Date.now() - startTime;
    this.metrics.averageSearchTime =
      (this.metrics.averageSearchTime * (this.metrics.similaritySearches - 1) + duration) /
      this.metrics.similaritySearches;

    return similarities.slice(0, topK);
  }

  /**
   * Recommend remediation based on similar issues
   */
  async recommendRemediation(currentFinding, topK = 5) {
    // Find similar historical issues
    const similarIssues = await this.findSimilarIssues(currentFinding, topK);

    if (similarIssues.length === 0) {
      return {
        status: 'no_similar_issues',
        confidence: 0.0,
        recommendations: [],
        similarIssues: []
      };
    }

    // Aggregate successful fixes
    const fixPatterns = new Map();
    let totalWeight = 0;

    for (const issue of similarIssues) {
      if (issue.appliedFix && issue.fixSuccess) {
        const weight = issue.similarity * (issue.confidenceScore || 0.5);
        totalWeight += weight;

        if (!fixPatterns.has(issue.appliedFix)) {
          fixPatterns.set(issue.appliedFix, {
            fix: issue.appliedFix,
            occurrences: 0,
            totalWeight: 0,
            avgSimilarity: 0,
            examples: []
          });
        }

        const pattern = fixPatterns.get(issue.appliedFix);
        pattern.occurrences++;
        pattern.totalWeight += weight;
        pattern.avgSimilarity =
          (pattern.avgSimilarity * (pattern.occurrences - 1) + issue.similarity) /
          pattern.occurrences;
        pattern.examples.push({
          message: issue.message,
          similarity: issue.similarity
        });
      }
    }

    // Convert to recommendations array
    const recommendations = Array.from(fixPatterns.values())
      .map(pattern => ({
        fix: pattern.fix,
        confidence: totalWeight > 0 ? pattern.totalWeight / totalWeight : 0,
        occurrences: pattern.occurrences,
        avgSimilarity: pattern.avgSimilarity,
        examples: pattern.examples.slice(0, 3) // Top 3 examples
      }))
      .sort((a, b) => b.confidence - a.confidence);

    // Calculate overall confidence
    const overallConfidence = recommendations.length > 0
      ? recommendations[0].confidence
      : 0.0;

    return {
      status: 'success',
      confidence: parseFloat(overallConfidence.toFixed(4)),
      recommendations: recommendations,
      similarIssues: similarIssues.map(issue => ({
        message: issue.message,
        similarity: issue.similarity,
        fix: issue.appliedFix,
        success: issue.fixSuccess
      })),
      metrics: {
        totalSimilarIssues: similarIssues.length,
        successfulFixes: Array.from(fixPatterns.values())
          .reduce((sum, p) => sum + p.occurrences, 0),
        uniqueFixPatterns: fixPatterns.size
      }
    };
  }

  /**
   * Learn from a new fix application
   */
  async learnFromFix(finding, fixApplied, success) {
    // Generate embedding
    const embedding = await this.generateEmbedding(finding);

    // Store with fix metadata
    await this.storeEmbedding(embedding, {
      category: finding.category,
      severity: finding.severity,
      message: finding.message,
      context: finding.context,
      filePattern: finding.file ? this.extractFilePattern(finding.file) : null,
      appliedFix: fixApplied,
      fixSuccess: success,
      confidenceScore: success ? 0.8 : 0.2
    });

    // Update remediation pattern if exists
    await this.updateRemediationPattern(finding.category, fixApplied, success);
  }

  /**
   * Update remediation pattern statistics
   */
  async updateRemediationPattern(category, fixName, success) {
    const timestamp = new Date().toISOString();

    // Try to find existing pattern
    const existing = await this.all(
      `SELECT * FROM remediation_patterns
       WHERE category = ? AND pattern_name = ?`,
      [category, fixName]
    );

    if (existing.length > 0) {
      // Update existing pattern
      const pattern = existing[0];
      const newApplicationCount = pattern.application_count + 1;
      const newSuccessCount = pattern.success_count + (success ? 1 : 0);
      const newAvgConfidence = newSuccessCount / newApplicationCount;

      await this.run(
        `UPDATE remediation_patterns
         SET application_count = ?,
             success_count = ?,
             avg_confidence = ?,
             updated_at = ?
         WHERE id = ?`,
        [newApplicationCount, newSuccessCount, newAvgConfidence, timestamp, pattern.id]
      );
    } else {
      // Create new pattern (requires embedding and template)
      // This would be populated by the fixer registry
      console.log(`New remediation pattern discovered: ${category} -> ${fixName}`);
    }
  }

  /**
   * Cosine similarity between two vectors
   */
  cosineSimilarity(a, b) {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    if (normA === 0 || normB === 0) return 0;
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  /**
   * Simple hash function for caching
   */
  hashText(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }

  /**
   * Update embedding cache (LRU)
   */
  updateCache(key, value) {
    if (this.cache.size >= this.maxCacheSize) {
      // Remove oldest entry
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  /**
   * Get performance metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      cacheSize: this.cache.size,
      cacheHitRate: this.metrics.embeddingsGenerated > 0
        ? (this.metrics.cacheHits / this.metrics.embeddingsGenerated).toFixed(4)
        : 0
    };
  }

  /**
   * Database helpers
   */
  run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  }

  get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  /**
   * Close database connection
   */
  async close() {
    if (!this.db) return;
    await new Promise((resolve, reject) => {
      this.db.close(err => (err ? reject(err) : resolve()));
    });
    this.db = null;
  }
}

module.exports = EmbeddingsEngine;
