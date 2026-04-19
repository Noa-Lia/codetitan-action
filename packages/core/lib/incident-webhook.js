'use strict';

const crypto = require('crypto');

/**
 * IncidentWebhook — Express router that receives production incidents
 * from Sentry, PagerDuty, DataDog, or generic sources and feeds them
 * into the FeedbackLoop.
 */
class IncidentWebhook {
  constructor(feedbackLoop, options = {}) {
    this.feedbackLoop = feedbackLoop;
    this.options = {
      secret: options.secret || process.env.CODETITAN_WEBHOOK_SECRET || '',
      replayWindowMs: options.replayWindowMs || 5 * 60 * 1000,
      sharedSecretHeader: options.sharedSecretHeader || 'x-codetitan-webhook-secret',
      signatureHeader: options.signatureHeader || 'x-codetitan-signature',
      timestampHeader: options.timestampHeader || 'x-codetitan-timestamp',
      verifyProjectBinding: options.verifyProjectBinding || null,
    };
    this.seenSignatures = new Map();
  }

  /**
   * Returns an Express router with all webhook endpoints mounted.
   * @returns {import('express').Router}
   */
  createExpressRouter() {
    const { Router } = require('express');
    const router = Router();

    router.post('/webhook/incident', async (req, res) => {
      const authorization = await this._authorizeWebhookRequest(req);
      if (!authorization.ok) {
        return res.status(authorization.status).json({ error: authorization.error });
      }

      try {
        const source = req.headers['x-webhook-source'] ||
                       req.body?.source ||
                       this._detectSource(req.body);

        const incident = {
          ...this.parseIncident(req.body, source),
          projectId: authorization.context.projectId,
          tenantId: authorization.context.tenantId,
        };

        if (!incident.error) {
          return res.status(400).json({ error: 'Cannot parse incident: missing error/message field' });
        }

        const result = await this.feedbackLoop.correlateIncident(incident);
        res.json({
          ok: true,
          incidentId: result.incidentId,
          correlatedFindings: result.correlatedFindings.length,
          newRuleCandidate: result.newRuleCandidate ? result.newRuleCandidate.ruleId : null
        });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    router.post('/webhook/deployment', async (req, res) => {
      const authorization = await this._authorizeWebhookRequest(req);
      if (!authorization.ok) {
        return res.status(authorization.status).json({ error: authorization.error });
      }

      try {
        const { environment, version, status } = req.body || {};
        await this.feedbackLoop.recordOutcome(`deploy-${version || 'unknown'}`, {
          success: status !== 'failed',
          category: 'DEPLOYMENT',
          projectId: authorization.context.projectId,
          errorMessage: status === 'failed' ? `Deployment ${version} failed in ${environment}` : null
        });
        res.json({ ok: true });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    router.post('/webhook/rollback', async (req, res) => {
      const authorization = await this._authorizeWebhookRequest(req);
      if (!authorization.ok) {
        return res.status(authorization.status).json({ error: authorization.error });
      }

      try {
        const { fixId, reason, version } = req.body || {};
        if (fixId) {
          await this.feedbackLoop.recordOutcome(fixId, {
            success: false,
            projectId: authorization.context.projectId,
            errorMessage: reason || `Rollback triggered for version ${version}`
          });
        }
        res.json({ ok: true });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    router.get('/webhook/status', (_req, res) => {
      res.json({
        ok: true,
        service: 'codetitan-feedback-webhook',
        timestamp: new Date().toISOString()
      });
    });

    return router;
  }

  /**
   * Normalise incident payloads from different sources into a common shape.
   * @param {Object} body
   * @param {string} source - 'sentry' | 'pagerduty' | 'datadog' | 'generic'
   * @returns {{ file, line, error, stackTrace, severity, source, raw }}
   */
  parseIncident(body, source = 'generic') {
    const raw = body;
    let file = null, line = null, error = null, stackTrace = null, severity = 'HIGH';

    switch (source) {
      case 'sentry': {
        const event = body.event || body;
        error = event.message || event.title || event.culprit || '';
        stackTrace = this._extractSentryStack(event);
        const culprit = event.culprit || '';
        const fileMatch = culprit.match(/^([^\s]+\.[a-z]+)/i);
        if (fileMatch) file = fileMatch[1];
        severity = this._mapSentrySeverity(event.level);
        break;
      }

      case 'pagerduty': {
        const incident = body.incident || body.messages?.[0]?.incident || body;
        error = incident.title || incident.summary || '';
        const body2 = incident.body?.details || incident.body || {};
        file = body2.file || null;
        severity = this._mapPagerDutySeverity(incident.urgency || incident.priority?.name);
        break;
      }

      case 'datadog': {
        error = body.title || body.text || '';
        stackTrace = body.text || null;
        severity = this._mapDataDogSeverity(body.alert_type || body.priority);
        const tags = body.tags || [];
        for (const tag of tags) {
          const match = tag.match(/^file:(.+)$/);
          if (match) { file = match[1]; break; }
        }
        break;
      }

      default: {
        error = body.error || body.message || body.title || '';
        file = body.file || body.filePath || body.file_path || null;
        line = body.line || body.lineNumber || body.line_number || null;
        stackTrace = body.stackTrace || body.stack_trace || body.stack || null;
        severity = (body.severity || 'HIGH').toUpperCase();
        break;
      }
    }

    return { file, line, error, stackTrace, severity, source, raw };
  }

  async _authorizeWebhookRequest(req) {
    const secret = this.options.secret;
    if (!secret) {
      return { ok: false, status: 503, error: 'Webhook authentication is not configured' };
    }

    const body = req.body || {};
    const payload = JSON.stringify(body);
    const sharedSecret = req.headers[this.options.sharedSecretHeader];
    const signature = req.headers[this.options.signatureHeader];
    const timestamp = req.headers[this.options.timestampHeader];

    const sharedSecretValid = typeof sharedSecret === 'string' && sharedSecret === secret;
    const signatureValid = this._verifySignature(payload, signature, timestamp);

    if (!sharedSecretValid && !signatureValid) {
      return { ok: false, status: 401, error: 'Invalid or missing webhook authentication' };
    }

    if (signatureValid) {
      const replayKey = `${timestamp}:${signature}`;
      const previousSeenAt = this.seenSignatures.get(replayKey);
      const now = Date.now();
      this._cleanupSeenSignatures(now);

      if (previousSeenAt && now - previousSeenAt < this.options.replayWindowMs) {
        return { ok: false, status: 403, error: 'Webhook replay detected' };
      }

      this.seenSignatures.set(replayKey, now);
    }

    const context = this._extractProjectContext(body);
    if (!context.projectId || !context.tenantId) {
      return { ok: false, status: 400, error: 'project_id and tenant_id are required' };
    }

    if (typeof this.options.verifyProjectBinding === 'function') {
      const isValidBinding = await this.options.verifyProjectBinding(context);
      if (!isValidBinding) {
        return { ok: false, status: 403, error: 'Project binding is invalid for this tenant' };
      }
    }

    return { ok: true, context };
  }

  _verifySignature(payload, signature, timestamp) {
    if (typeof signature !== 'string' || typeof timestamp !== 'string') {
      return false;
    }

    const numericTimestamp = Number(timestamp);
    if (!Number.isFinite(numericTimestamp)) {
      return false;
    }

    if (Math.abs(Date.now() - numericTimestamp) > this.options.replayWindowMs) {
      return false;
    }

    const normalizedSignature = signature.startsWith('v1=') ? signature.slice(3) : signature;
    const expected = crypto.createHmac('sha256', this.options.secret)
      .update(`${timestamp}.${payload}`)
      .digest('hex');

    try {
      const provided = Buffer.from(normalizedSignature, 'utf8');
      const wanted = Buffer.from(expected, 'utf8');

      if (provided.length !== wanted.length) {
        return false;
      }

      return crypto.timingSafeEqual(provided, wanted);
    } catch {
      return false;
    }
  }

  _extractProjectContext(body) {
    return {
      projectId: body?.project_id || body?.projectId || null,
      tenantId: body?.tenant_id || body?.tenantId || body?.owner_id || body?.ownerId || body?.user_id || body?.userId || null,
    };
  }

  _cleanupSeenSignatures(now = Date.now()) {
    for (const [key, seenAt] of this.seenSignatures.entries()) {
      if (now - seenAt > this.options.replayWindowMs) {
        this.seenSignatures.delete(key);
      }
    }
  }

  _detectSource(body) {
    if (!body) return 'generic';
    if (body.event?.event_id || body.project_slug) return 'sentry';
    if (body.incident?.html_url?.includes('pagerduty')) return 'pagerduty';
    if (body.alert_type || body.aggreg_key) return 'datadog';
    return 'generic';
  }

  _extractSentryStack(event) {
    try {
      const exc = event.exception?.values?.[0];
      if (!exc) return null;
      const frames = exc.stacktrace?.frames || [];
      return frames.map(f => `  at ${f.function || '?'} (${f.filename}:${f.lineno})`).join('\n');
    } catch {
      return null;
    }
  }

  _mapSentrySeverity(level) {
    const map = { fatal: 'CRITICAL', error: 'HIGH', warning: 'MEDIUM', info: 'LOW', debug: 'LOW' };
    return map[level] || 'HIGH';
  }

  _mapPagerDutySeverity(urgencyOrPriority) {
    const val = (urgencyOrPriority || '').toLowerCase();
    if (val === 'high' || val === 'p1' || val === 'critical') return 'CRITICAL';
    if (val === 'low' || val === 'p3' || val === 'p4') return 'LOW';
    return 'HIGH';
  }

  _mapDataDogSeverity(alertType) {
    const val = (alertType || '').toLowerCase();
    if (val === 'error' || val === 'p1') return 'HIGH';
    if (val === 'warning' || val === 'p2') return 'MEDIUM';
    if (val === 'info' || val === 'success') return 'LOW';
    return 'HIGH';
  }
}

module.exports = IncidentWebhook;
