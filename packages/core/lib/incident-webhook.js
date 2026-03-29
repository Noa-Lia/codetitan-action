'use strict';

/**
 * IncidentWebhook — Express router that receives production incidents
 * from Sentry, PagerDuty, DataDog, or generic sources and feeds them
 * into the FeedbackLoop.
 */
class IncidentWebhook {
  constructor(feedbackLoop) {
    this.feedbackLoop = feedbackLoop;
  }

  /**
   * Returns an Express router with all webhook endpoints mounted.
   * @returns {import('express').Router}
   */
  createExpressRouter() {
    const { Router } = require('express');
    const router = Router();

    // POST /webhook/incident
    router.post('/webhook/incident', async (req, res) => {
      try {
        const source = req.headers['x-webhook-source'] ||
                       req.body?.source ||
                       this._detectSource(req.body);

        const incident = this.parseIncident(req.body, source);

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

    // POST /webhook/deployment
    router.post('/webhook/deployment', async (req, res) => {
      try {
        const { environment, version, status, timestamp } = req.body || {};
        // Record deployment as a neutral outcome marker
        await this.feedbackLoop.recordOutcome(`deploy-${version || 'unknown'}`, {
          success: status !== 'failed',
          category: 'DEPLOYMENT',
          errorMessage: status === 'failed' ? `Deployment ${version} failed in ${environment}` : null
        });
        res.json({ ok: true });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // POST /webhook/rollback
    router.post('/webhook/rollback', async (req, res) => {
      try {
        const { fixId, reason, version } = req.body || {};
        if (fixId) {
          await this.feedbackLoop.recordOutcome(fixId, {
            success: false,
            errorMessage: reason || `Rollback triggered for version ${version}`
          });
        }
        res.json({ ok: true });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // GET /webhook/status
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
        // Sentry alert webhook
        const event = body.event || body;
        error = event.message || event.title || event.culprit || '';
        stackTrace = this._extractSentryStack(event);
        const culprit = event.culprit || '';
        // "src/auth.js in handleLogin" → extract file
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
        // Extract file from tags if present
        const tags = body.tags || [];
        for (const tag of tags) {
          const m = tag.match(/^file:(.+)$/);
          if (m) { file = m[1]; break; }
        }
        break;
      }

      default: {
        // Generic / manual payload
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

  // ─── Private helpers ───────────────────────────────────────────────────────

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
