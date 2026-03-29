/**
 * Agent Memory System
 * 
 * Learns and remembers from:
 * - Accept/reject decisions on fixes
 * - Project-specific coding patterns
 * - Team coding style preferences
 * - Historical context for similar issues
 * 
 * Uses embeddings for semantic similarity matching.
 * 
 * @module agent-memory
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

/**
 * Memory categories for organization
 */
const MEMORY_TYPES = {
    FIX_DECISION: 'fix_decision',        // Accept/reject on a fix
    PATTERN_PREFERENCE: 'pattern',        // Preferred code patterns
    STYLE_RULE: 'style',                  // Team style preferences
    ERROR_CONTEXT: 'error_context',       // Context around errors
    SUCCESSFUL_FIX: 'successful_fix',     // Fixes that worked
    REJECTED_FIX: 'rejected_fix',         // Fixes that were rejected
    CODE_SNIPPET: 'code_snippet',         // Important code samples
};

/**
 * Memory importance levels
 */
const IMPORTANCE = {
    CRITICAL: 1.0,    // Always remember
    HIGH: 0.8,        // Remember unless space constrained
    MEDIUM: 0.5,      // Remember if relevant
    LOW: 0.3,         // May forget
    TRANSIENT: 0.1,   // Forget quickly
};

/**
 * Simple embedding generator (for local use without external API)
 */
class LocalEmbeddings {
    constructor() {
        // Vocabulary for simple TF-IDF style embeddings
        this.vocab = new Map();
        this.idf = new Map();
        this.docCount = 0;
    }

    /**
     * Generate a simple embedding vector
     */
    embed(text) {
        const tokens = this.tokenize(text);
        const vector = new Array(256).fill(0);

        for (const token of tokens) {
            // Use hash for dimension mapping
            const hash = this.hashString(token);
            const dim = hash % 256;
            vector[dim] += 1;
        }

        // Normalize
        const magnitude = Math.sqrt(vector.reduce((sum, v) => sum + v * v, 0));
        if (magnitude > 0) {
            for (let i = 0; i < vector.length; i++) {
                vector[i] /= magnitude;
            }
        }

        return vector;
    }

    /**
     * Calculate cosine similarity between two vectors
     */
    similarity(vec1, vec2) {
        if (!vec1 || !vec2 || vec1.length !== vec2.length) return 0;

        let dot = 0;
        for (let i = 0; i < vec1.length; i++) {
            dot += vec1[i] * vec2[i];
        }
        return dot;
    }

    /**
     * Tokenize text
     */
    tokenize(text) {
        return text
            .toLowerCase()
            .replace(/[^a-z0-9_]/g, ' ')
            .split(/\s+/)
            .filter(t => t.length > 2);
    }

    /**
     * Hash a string to a number
     */
    hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash);
    }
}

/**
 * Memory item structure
 */
class MemoryItem {
    constructor(data) {
        this.id = data.id || crypto.randomUUID();
        this.type = data.type || MEMORY_TYPES.CODE_SNIPPET;
        this.content = data.content;
        this.embedding = data.embedding || null;
        this.metadata = data.metadata || {};
        this.importance = data.importance || IMPORTANCE.MEDIUM;
        this.accessCount = data.accessCount || 0;
        this.lastAccessed = data.lastAccessed || new Date();
        this.createdAt = data.createdAt || new Date();
        this.projectId = data.projectId;
        this.userId = data.userId;
        this.category = data.category;
        this.tags = data.tags || [];
    }

    /**
     * Update access statistics
     */
    access() {
        this.accessCount++;
        this.lastAccessed = new Date();
    }

    /**
     * Calculate decay based on age and importance
     */
    getDecay() {
        const ageHours = (Date.now() - new Date(this.createdAt).getTime()) / (1000 * 60 * 60);
        const accessBoost = Math.log(this.accessCount + 1) * 0.1;
        const decay = Math.exp(-ageHours / (24 * 7)) * this.importance + accessBoost;
        return Math.min(1, Math.max(0, decay));
    }

    toJSON() {
        return {
            id: this.id,
            type: this.type,
            content: this.content,
            embedding: this.embedding,
            metadata: this.metadata,
            importance: this.importance,
            accessCount: this.accessCount,
            lastAccessed: this.lastAccessed,
            createdAt: this.createdAt,
            projectId: this.projectId,
            userId: this.userId,
            category: this.category,
            tags: this.tags,
        };
    }
}

/**
 * Agent Memory System
 */
class AgentMemory {
    constructor(config = {}) {
        this.config = {
            supabaseUrl: config.supabaseUrl || process.env.SUPABASE_URL,
            supabaseKey: config.supabaseKey || process.env.SUPABASE_SERVICE_KEY,
            maxMemories: config.maxMemories || 10000,
            similarityThreshold: config.similarityThreshold || 0.7,
            decayInterval: config.decayInterval || 3600000, // 1 hour
            ...config,
        };

        // In-memory store (hot cache)
        this.memories = new Map();

        // Embedding generator
        this.embeddings = config.embeddings || new LocalEmbeddings();

        // Project-specific pattern counts
        this.patternCounts = new Map();

        // Team style preferences
        this.stylePreferences = new Map();

        // Initialize Supabase
        if (this.config.supabaseUrl && this.config.supabaseKey) {
            this.supabase = createClient(
                this.config.supabaseUrl,
                this.config.supabaseKey
            );
        }

        // Start decay timer
        this.startDecayTimer();
    }

    /**
     * Remember a new piece of information
     */
    async remember(data) {
        const content = typeof data.content === 'string'
            ? data.content
            : JSON.stringify(data.content);

        const embedding = this.embeddings.embed(content);

        const memory = new MemoryItem({
            ...data,
            content,
            embedding,
        });

        // Store in memory
        this.memories.set(memory.id, memory);

        // Persist to database
        await this.persist(memory);

        // Enforce memory limit
        await this.enforceLimit();

        return memory;
    }

    /**
     * Remember a fix decision (accept/reject)
     */
    async rememberFixDecision(fix, wasAccepted, context = {}) {
        const content = {
            ruleId: fix.ruleId,
            category: fix.category,
            message: fix.message,
            snippet: fix.snippet,
            fixApplied: fix.fix,
            wasAccepted,
        };

        return this.remember({
            type: wasAccepted ? MEMORY_TYPES.SUCCESSFUL_FIX : MEMORY_TYPES.REJECTED_FIX,
            content: JSON.stringify(content),
            metadata: {
                ruleId: fix.ruleId,
                category: fix.category,
                severity: fix.severity,
                confidence: fix.confidence,
                fileName: context.fileName,
            },
            importance: wasAccepted ? IMPORTANCE.HIGH : IMPORTANCE.MEDIUM,
            projectId: context.projectId,
            userId: context.userId,
            category: fix.category,
            tags: [fix.ruleId, fix.category, wasAccepted ? 'accepted' : 'rejected'],
        });
    }

    /**
     * Remember a coding pattern preference
     */
    async rememberPattern(pattern, context = {}) {
        // Track pattern frequency
        const key = `${context.projectId}:${pattern.category}:${pattern.name}`;
        const count = this.patternCounts.get(key) || 0;
        this.patternCounts.set(key, count + 1);

        return this.remember({
            type: MEMORY_TYPES.PATTERN_PREFERENCE,
            content: JSON.stringify(pattern),
            metadata: {
                category: pattern.category,
                name: pattern.name,
                frequency: count + 1,
            },
            importance: count > 5 ? IMPORTANCE.HIGH : IMPORTANCE.MEDIUM,
            projectId: context.projectId,
            category: pattern.category,
            tags: [pattern.category, pattern.name, 'pattern'],
        });
    }

    /**
     * Remember a team style rule
     */
    async rememberStyle(rule, context = {}) {
        const key = `${context.projectId}:${rule.name}`;
        this.stylePreferences.set(key, rule);

        return this.remember({
            type: MEMORY_TYPES.STYLE_RULE,
            content: JSON.stringify(rule),
            metadata: {
                name: rule.name,
                enforcement: rule.enforcement || 'suggest',
            },
            importance: IMPORTANCE.HIGH,
            projectId: context.projectId,
            tags: ['style', rule.name],
        });
    }

    /**
     * Recall relevant memories for a given context
     */
    async recall(query, options = {}) {
        const {
            type,
            projectId,
            limit = 10,
            minSimilarity = this.config.similarityThreshold,
        } = options;

        const queryEmbedding = this.embeddings.embed(query);
        const results = [];

        for (const memory of this.memories.values()) {
            // Filter by type if specified
            if (type && memory.type !== type) continue;

            // Filter by project if specified
            if (projectId && memory.projectId !== projectId) continue;

            // Calculate similarity
            const similarity = this.embeddings.similarity(queryEmbedding, memory.embedding);

            if (similarity >= minSimilarity) {
                memory.access();
                results.push({
                    memory,
                    similarity,
                    relevance: similarity * memory.getDecay(),
                });
            }
        }

        // Sort by relevance
        results.sort((a, b) => b.relevance - a.relevance);

        return results.slice(0, limit);
    }

    /**
     * Recall fix decisions for a similar issue
     */
    async recallFixDecisions(finding, context = {}) {
        const query = `${finding.category} ${finding.ruleId} ${finding.message || ''} ${finding.snippet || ''}`;

        const memories = await this.recall(query, {
            type: null, // Include both accepted and rejected
            projectId: context.projectId,
            limit: 20,
        });

        // Separate accepted and rejected
        const accepted = memories.filter(m =>
            m.memory.type === MEMORY_TYPES.SUCCESSFUL_FIX
        );
        const rejected = memories.filter(m =>
            m.memory.type === MEMORY_TYPES.REJECTED_FIX
        );

        // Calculate preference score
        const acceptedScore = accepted.reduce((sum, m) => sum + m.relevance, 0);
        const rejectedScore = rejected.reduce((sum, m) => sum + m.relevance, 0);
        const totalScore = acceptedScore + rejectedScore;

        return {
            acceptedMemories: accepted,
            rejectedMemories: rejected,
            preferenceScore: totalScore > 0 ? acceptedScore / totalScore : 0.5,
            recommendation: acceptedScore > rejectedScore ? 'LIKELY_ACCEPT' :
                rejectedScore > acceptedScore ? 'LIKELY_REJECT' : 'NEUTRAL',
        };
    }

    /**
     * Recall style preferences for a project
     */
    async recallStyles(projectId) {
        const styles = [];

        for (const [key, rule] of this.stylePreferences) {
            if (key.startsWith(`${projectId}:`)) {
                styles.push(rule);
            }
        }

        return styles;
    }

    /**
     * Learn from a batch of historical decisions
     */
    async learnFromHistory(decisions) {
        for (const decision of decisions) {
            await this.rememberFixDecision(
                decision.fix,
                decision.wasAccepted,
                {
                    projectId: decision.projectId,
                    userId: decision.userId,
                    fileName: decision.fileName,
                }
            );
        }
    }

    /**
     * Get most common patterns for a project
     */
    getTopPatterns(projectId, limit = 10) {
        const patterns = [];

        for (const [key, count] of this.patternCounts) {
            if (key.startsWith(`${projectId}:`)) {
                const [, category, name] = key.split(':');
                patterns.push({ category, name, count });
            }
        }

        return patterns
            .sort((a, b) => b.count - a.count)
            .slice(0, limit);
    }

    /**
     * Persist memory to database
     */
    async persist(memory) {
        if (!this.supabase) return;

        try {
            await this.supabase.from('agent_memories').upsert({
                id: memory.id,
                type: memory.type,
                content: memory.content,
                embedding: memory.embedding,
                metadata: memory.metadata,
                importance: memory.importance,
                access_count: memory.accessCount,
                last_accessed: memory.lastAccessed,
                created_at: memory.createdAt,
                project_id: memory.projectId,
                user_id: memory.userId,
                category: memory.category,
                tags: memory.tags,
            });
        } catch (error) {
            console.error('[AgentMemory] Persist failed:', error.message);
        }
    }

    /**
     * Load memories from database
     */
    async load(options = {}) {
        if (!this.supabase) return;

        try {
            let query = this.supabase
                .from('agent_memories')
                .select('*')
                .order('last_accessed', { ascending: false })
                .limit(options.limit || 1000);

            if (options.projectId) {
                query = query.eq('project_id', options.projectId);
            }

            const { data, error } = await query;

            if (error) throw error;

            for (const row of data || []) {
                const memory = new MemoryItem({
                    id: row.id,
                    type: row.type,
                    content: row.content,
                    embedding: row.embedding,
                    metadata: row.metadata,
                    importance: row.importance,
                    accessCount: row.access_count,
                    lastAccessed: row.last_accessed,
                    createdAt: row.created_at,
                    projectId: row.project_id,
                    userId: row.user_id,
                    category: row.category,
                    tags: row.tags,
                });
                this.memories.set(memory.id, memory);
            }

            console.log(`[AgentMemory] Loaded ${this.memories.size} memories`);
        } catch (error) {
            console.error('[AgentMemory] Load failed:', error.message);
        }
    }

    /**
     * Enforce memory limit through decay
     */
    async enforceLimit() {
        if (this.memories.size <= this.config.maxMemories) return;

        // Calculate decay for all memories
        const decayed = Array.from(this.memories.values())
            .map(m => ({ memory: m, decay: m.getDecay() }))
            .sort((a, b) => a.decay - b.decay);

        // Remove lowest decay memories
        const toRemove = decayed.slice(0, this.memories.size - this.config.maxMemories);

        for (const { memory } of toRemove) {
            this.memories.delete(memory.id);

            // Also remove from database
            if (this.supabase) {
                await this.supabase
                    .from('agent_memories')
                    .delete()
                    .eq('id', memory.id);
            }
        }
    }

    /**
     * Start decay timer for periodic cleanup
     */
    startDecayTimer() {
        this.decayTimer = setInterval(() => {
            this.enforceLimit().catch(() => { });
        }, this.config.decayInterval);
    }

    /**
     * Get memory statistics
     */
    getStats() {
        const byType = {};
        const byImportance = {};
        let totalAccess = 0;

        for (const memory of this.memories.values()) {
            byType[memory.type] = (byType[memory.type] || 0) + 1;

            const impLevel = memory.importance >= 0.8 ? 'high' :
                memory.importance >= 0.5 ? 'medium' : 'low';
            byImportance[impLevel] = (byImportance[impLevel] || 0) + 1;

            totalAccess += memory.accessCount;
        }

        return {
            totalMemories: this.memories.size,
            byType,
            byImportance,
            averageAccess: this.memories.size > 0 ? totalAccess / this.memories.size : 0,
            patternCount: this.patternCounts.size,
            styleRules: this.stylePreferences.size,
        };
    }

    /**
     * Clear all memories (for testing)
     */
    clear() {
        this.memories.clear();
        this.patternCounts.clear();
        this.stylePreferences.clear();
    }

    /**
     * Stop the decay timer
     */
    destroy() {
        if (this.decayTimer) {
            clearInterval(this.decayTimer);
        }
    }
}

// Database migration SQL
const MIGRATION_SQL = `
-- Agent Memories Table
CREATE TABLE IF NOT EXISTS agent_memories (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding FLOAT8[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    importance FLOAT DEFAULT 0.5,
    access_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    project_id UUID,
    user_id UUID,
    category TEXT,
    tags TEXT[] DEFAULT '{}'
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_agent_memories_type ON agent_memories(type);
CREATE INDEX IF NOT EXISTS idx_agent_memories_project ON agent_memories(project_id);
CREATE INDEX IF NOT EXISTS idx_agent_memories_category ON agent_memories(category);
CREATE INDEX IF NOT EXISTS idx_agent_memories_importance ON agent_memories(importance);
CREATE INDEX IF NOT EXISTS idx_agent_memories_last_accessed ON agent_memories(last_accessed);

-- GIN index for tags
CREATE INDEX IF NOT EXISTS idx_agent_memories_tags ON agent_memories USING GIN(tags);
`;

module.exports = {
    AgentMemory,
    MemoryItem,
    LocalEmbeddings,
    MEMORY_TYPES,
    IMPORTANCE,
    MIGRATION_SQL,
};
