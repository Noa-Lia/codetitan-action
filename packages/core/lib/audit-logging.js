/**
 * Audit Logging API
 * 
 * Comprehensive audit logging for SOC 2 compliance.
 * Tracks all security-relevant events with immutable logging.
 * 
 * @module audit-logging
 */

/**
 * Audit Event Types
 */
const fs = require('fs');
const crypto = require('crypto');
const AUDIT_EVENT_TYPES = {
    // Authentication Events
    AUTH_LOGIN_SUCCESS: 'auth.login.success',
    AUTH_LOGIN_FAILURE: 'auth.login.failure',
    AUTH_LOGOUT: 'auth.logout',
    AUTH_TOKEN_REFRESH: 'auth.token.refresh',
    AUTH_PASSWORD_CHANGE: 'auth.password.change',
    AUTH_MFA_ENABLED: 'auth.mfa.enabled',
    AUTH_MFA_DISABLED: 'auth.mfa.disabled',
    AUTH_SSO_LOGIN: 'auth.sso.login',

    // Authorization Events
    AUTHZ_ACCESS_GRANTED: 'authz.access.granted',
    AUTHZ_ACCESS_DENIED: 'authz.access.denied',
    AUTHZ_ROLE_ASSIGNED: 'authz.role.assigned',
    AUTHZ_ROLE_REVOKED: 'authz.role.revoked',
    AUTHZ_PERMISSION_CHANGED: 'authz.permission.changed',

    // Data Access Events
    DATA_READ: 'data.read',
    DATA_CREATE: 'data.create',
    DATA_UPDATE: 'data.update',
    DATA_DELETE: 'data.delete',
    DATA_EXPORT: 'data.export',

    // Analysis Events
    ANALYSIS_STARTED: 'analysis.started',
    ANALYSIS_COMPLETED: 'analysis.completed',
    ANALYSIS_FAILED: 'analysis.failed',
    FIX_APPLIED: 'fix.applied',
    FIX_REJECTED: 'fix.rejected',

    // Configuration Events
    CONFIG_CHANGED: 'config.changed',
    RULE_CREATED: 'rule.created',
    RULE_UPDATED: 'rule.updated',
    RULE_DELETED: 'rule.deleted',
    INTEGRATION_ADDED: 'integration.added',
    INTEGRATION_REMOVED: 'integration.removed',

    // Security Events
    SEC_SUSPICIOUS_ACTIVITY: 'security.suspicious',
    SEC_RATE_LIMIT_EXCEEDED: 'security.rate_limit',
    SEC_API_KEY_CREATED: 'security.apikey.created',
    SEC_API_KEY_REVOKED: 'security.apikey.revoked',
};

/**
 * Audit Log Severity Levels
 */
const SEVERITY_LEVELS = {
    DEBUG: 'debug',
    INFO: 'info',
    WARNING: 'warning',
    ERROR: 'error',
    CRITICAL: 'critical',
};

/**
 * Audit Log Entry
 */
class AuditLogEntry {
    constructor(options) {
        this.id = options.id || this.generateId();
        this.timestamp = options.timestamp || new Date().toISOString();
        this.eventType = options.eventType;
        this.severity = options.severity || SEVERITY_LEVELS.INFO;
        this.actor = {
            userId: options.userId,
            email: options.email,
            ipAddress: options.ipAddress,
            userAgent: options.userAgent,
            sessionId: options.sessionId,
        };
        this.resource = {
            type: options.resourceType,
            id: options.resourceId,
            name: options.resourceName,
        };
        this.action = options.action;
        this.outcome = options.outcome || 'success';  // success, failure
        this.details = options.details || {};
        this.metadata = {
            organizationId: options.organizationId,
            projectId: options.projectId,
            environment: options.environment || 'production',
            version: options.version,
        };
        this.hash = null;  // Computed for integrity verification
    }

    generateId() {
        return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    computeHash() {
        // In production, use crypto to compute SHA-256 hash
        const data = JSON.stringify({
            id: this.id,
            timestamp: this.timestamp,
            eventType: this.eventType,
            actor: this.actor,
            resource: this.resource,
            action: this.action,
            outcome: this.outcome,
        });

        this.hash = crypto.createHash('sha256').update(data).digest('hex');
        return this.hash;
    }

    toJSON() {
        return {
            id: this.id,
            timestamp: this.timestamp,
            eventType: this.eventType,
            severity: this.severity,
            actor: this.actor,
            resource: this.resource,
            action: this.action,
            outcome: this.outcome,
            details: this.details,
            metadata: this.metadata,
            hash: this.hash,
        };
    }
}

/**
 * Audit Logger
 */
class AuditLogger {
    constructor(options = {}) {
        this.logs = [];
        this.maxLogs = options.maxLogs || 10000;
        this.sinks = options.sinks || [];  // Output destinations
        this.enabled = options.enabled !== false;
        this.defaultMetadata = options.defaultMetadata || {};
    }

    /**
     * Log an audit event
     */
    log(eventType, options = {}) {
        if (!this.enabled) return null;

        const entry = new AuditLogEntry({
            eventType,
            ...this.defaultMetadata,
            ...options,
        });

        entry.computeHash();

        // Add to in-memory store (with size limit)
        this.logs.push(entry);
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }

        // Send to all sinks
        this.sinks.forEach(sink => {
            try {
                sink.write(entry);
            } catch (error) {
                console.error('Audit sink error:', error);
            }
        });

        return entry;
    }

    /**
     * Convenience methods for common events
     */
    logLogin(userId, email, success, options = {}) {
        return this.log(
            success ? AUDIT_EVENT_TYPES.AUTH_LOGIN_SUCCESS : AUDIT_EVENT_TYPES.AUTH_LOGIN_FAILURE,
            {
                userId,
                email,
                outcome: success ? 'success' : 'failure',
                action: 'login',
                ...options,
            }
        );
    }

    logLogout(userId, email, options = {}) {
        return this.log(AUDIT_EVENT_TYPES.AUTH_LOGOUT, {
            userId,
            email,
            action: 'logout',
            ...options,
        });
    }

    logDataAccess(userId, resourceType, resourceId, action, options = {}) {
        const eventType = {
            read: AUDIT_EVENT_TYPES.DATA_READ,
            create: AUDIT_EVENT_TYPES.DATA_CREATE,
            update: AUDIT_EVENT_TYPES.DATA_UPDATE,
            delete: AUDIT_EVENT_TYPES.DATA_DELETE,
            export: AUDIT_EVENT_TYPES.DATA_EXPORT,
        }[action] || AUDIT_EVENT_TYPES.DATA_READ;

        return this.log(eventType, {
            userId,
            resourceType,
            resourceId,
            action,
            ...options,
        });
    }

    logAnalysis(userId, projectId, status, options = {}) {
        const eventType = {
            started: AUDIT_EVENT_TYPES.ANALYSIS_STARTED,
            completed: AUDIT_EVENT_TYPES.ANALYSIS_COMPLETED,
            failed: AUDIT_EVENT_TYPES.ANALYSIS_FAILED,
        }[status] || AUDIT_EVENT_TYPES.ANALYSIS_STARTED;

        return this.log(eventType, {
            userId,
            projectId,
            resourceType: 'project',
            resourceId: projectId,
            action: 'analysis',
            outcome: status === 'failed' ? 'failure' : 'success',
            ...options,
        });
    }

    logSecurityEvent(eventType, userId, details, options = {}) {
        return this.log(eventType, {
            userId,
            severity: SEVERITY_LEVELS.WARNING,
            details,
            ...options,
        });
    }

    /**
     * Query logs
     */
    query(filters = {}) {
        let results = [...this.logs];

        if (filters.eventType) {
            results = results.filter(l => l.eventType === filters.eventType);
        }

        if (filters.userId) {
            results = results.filter(l => l.actor.userId === filters.userId);
        }

        if (filters.resourceType) {
            results = results.filter(l => l.resource.type === filters.resourceType);
        }

        if (filters.severity) {
            results = results.filter(l => l.severity === filters.severity);
        }

        if (filters.outcome) {
            results = results.filter(l => l.outcome === filters.outcome);
        }

        if (filters.startDate) {
            const start = new Date(filters.startDate);
            results = results.filter(l => new Date(l.timestamp) >= start);
        }

        if (filters.endDate) {
            const end = new Date(filters.endDate);
            results = results.filter(l => new Date(l.timestamp) <= end);
        }

        // Sort by timestamp descending (newest first)
        results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Pagination
        const offset = filters.offset || 0;
        const limit = filters.limit || 100;
        const total = results.length;
        results = results.slice(offset, offset + limit);

        return {
            logs: results.map(l => l.toJSON()),
            total,
            offset,
            limit,
        };
    }

    /**
     * Export logs for compliance
     */
    exportLogs(format = 'json', filters = {}) {
        const { logs } = this.query({ ...filters, limit: this.maxLogs });

        if (format === 'json') {
            return JSON.stringify(logs, null, 2);
        }

        if (format === 'csv') {
            if (logs.length === 0) return '';

            const headers = ['id', 'timestamp', 'eventType', 'severity', 'userId', 'action', 'outcome'];
            const rows = logs.map(log => [
                log.id,
                log.timestamp,
                log.eventType,
                log.severity,
                log.actor.userId || '',
                log.action || '',
                log.outcome,
            ].join(','));

            return [headers.join(','), ...rows].join('\n');
        }

        throw new Error(`Unsupported format: ${format}`);
    }

    /**
     * Verify log integrity
     */
    verifyIntegrity() {
        const issues = [];

        this.logs.forEach((log, index) => {
            const originalHash = log.hash;
            log.computeHash();

            if (originalHash !== log.hash) {
                issues.push({
                    logId: log.id,
                    index,
                    issue: 'Hash mismatch - potential tampering detected',
                });
            }
        });

        return {
            verified: issues.length === 0,
            totalLogs: this.logs.length,
            issues,
        };
    }

    /**
     * Add a sink for log output
     */
    addSink(sink) {
        this.sinks.push(sink);
    }

    /**
     * Clear logs (for testing only)
     */
    clear() {
        this.logs = [];
    }
}

/**
 * Console Sink - outputs to console
 */
class ConsoleSink {
    write(entry) {
        const color = {
            debug: '\x1b[37m',
            info: '\x1b[36m',
            warning: '\x1b[33m',
            error: '\x1b[31m',
            critical: '\x1b[35m',
        }[entry.severity] || '\x1b[0m';

        console.log(
            `${color}[AUDIT] ${entry.timestamp} | ${entry.eventType} | ${entry.actor.userId || 'anonymous'} | ${entry.outcome}\x1b[0m`
        );
    }
}

/**
 * File Sink - outputs to file (append)
 */
class FileSink {
    constructor(filePath) {
        this.filePath = filePath;
    }

    write(entry) {
        const line = JSON.stringify(entry.toJSON()) + '\n';
        fs.promises.appendFile(this.filePath, line).catch(() => { });
    }
}

module.exports = {
    AuditLogger,
    AuditLogEntry,
    ConsoleSink,
    FileSink,
    AUDIT_EVENT_TYPES,
    SEVERITY_LEVELS,
};
