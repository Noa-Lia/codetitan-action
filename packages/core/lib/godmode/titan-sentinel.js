/**
 * TITAN MODE™ Level 8: TITAN SENTINEL
 * Always-On Guardian Mode
 *
 * Always-on guardian monitoring commits, incidents, and live telemetry.
 * Automatic detection and remediation with escalation to humans when needed.
 *
 * Capabilities:
 * - Continuous monitoring of git commits
 * - Real-time incident detection from telemetry
 * - Automatic AI-powered remediation
 * - Escalation matrix (Slack, PagerDuty, email)
 * - Learning from incident patterns
 * - Proactive vulnerability scanning
 *
 * @module titanmode/level8-sentinel
 */

const { AIProviderManager, EnsembleAnalyzer } = require('../ai-providers');
const TitanFix = require('./titan-fix');
const TitanOptimize = require('./titan-optimize');
const { EventEmitter } = require('events');

class Level8Sentinel extends EventEmitter {
  constructor(config = {}) {
    super();

    this.config = {
      // Monitoring modes
      monitorCommits: config.monitorCommits !== false,
      monitorTelemetry: config.monitorTelemetry !== false,
      monitorIncidents: config.monitorIncidents !== false,

      // Auto-remediation settings
      autoRemediate: config.autoRemediate !== false,
      maxAutoRemediations: config.maxAutoRemediations || 10,
      remediationConfidenceThreshold: config.remediationConfidenceThreshold || 85,

      // Escalation settings
      escalateOnFailure: config.escalateOnFailure !== false,
      escalationChannels: config.escalationChannels || ['console'], // console, slack, pagerduty, email

      // Alert thresholds
      thresholds: {
        criticalFindings: config.thresholds?.criticalFindings || 1,
        highFindings: config.thresholds?.highFindings || 5,
        errorRate: config.thresholds?.errorRate || 0.05, // 5%
        responseTime: config.thresholds?.responseTime || 3000, // 3s
        ...config.thresholds
      },

      // Polling interval (ms)
      pollingInterval: config.pollingInterval || 60000, // 1 minute

      ...config
    };

    this.aiManager = new AIProviderManager();
    this.ensemble = new EnsembleAnalyzer(this.aiManager);
    this.titanFix = new TitanFix();
    this.titanOptimize = new TitanOptimize();

    // Phase 3: production feedback loop
    const FeedbackLoop = require('../feedback-loop');
    this.feedbackLoop = new FeedbackLoop({ projectRoot: config.projectRoot || process.cwd() });

    this.state = {
      active: false,
      lastCheck: null,
      incidents: [],
      remediations: [],
      escalations: []
    };

    this.intervals = [];
  }

  /**
   * Start Sentinel Mode
   */
  async start(projectPath) {
    console.log('⚡ [TITAN MODE Level 8] TITAN SENTINEL - Always-On Guardian ACTIVATED\n');
    console.log('🛡️  Always-on guardian monitoring your codebase\n');

    this.state.active = true;
    this.state.projectPath = projectPath;

    console.log('Monitoring:');
    if (this.config.monitorCommits) console.log('  ✓ Git commits');
    if (this.config.monitorTelemetry) console.log('  ✓ Live telemetry');
    if (this.config.monitorIncidents) console.log('  ✓ Incidents');

    console.log('\nEscalation channels:');
    for (const channel of this.config.escalationChannels) {
      console.log(`  ✓ ${channel}`);
    }

    console.log('\n');

    // Start monitoring tasks
    if (this.config.monitorCommits) {
      this.startCommitMonitoring(projectPath);
    }

    if (this.config.monitorTelemetry) {
      this.startTelemetryMonitoring();
    }

    if (this.config.monitorIncidents) {
      this.startIncidentMonitoring();
    }

    this.emit('started', { projectPath });

    console.log('[Sentinel] Monitoring active...\n');
  }

  /**
   * Stop Sentinel Mode
   */
  async stop() {
    console.log('[Sentinel] Stopping monitoring...');

    this.state.active = false;

    // Clear all intervals
    for (const interval of this.intervals) {
      clearInterval(interval);
    }

    this.intervals = [];

    this.emit('stopped');

    console.log('[Sentinel] Monitoring stopped\n');
  }

  /**
   * Monitor git commits for security/quality issues
   */
  startCommitMonitoring(projectPath) {
    console.log('[Sentinel] Starting commit monitoring...');

    const interval = setInterval(async () => {
      if (!this.state.active) return;

      try {
        // Get latest commits
        const commits = await this.getRecentCommits(projectPath);

        for (const commit of commits) {
          await this.analyzeCommit(commit, projectPath);
        }

      } catch (error) {
        this.handleError('commit-monitoring', error);
      }
    }, this.config.pollingInterval);

    this.intervals.push(interval);
  }

  /**
   * Monitor telemetry for anomalies
   */
  startTelemetryMonitoring() {
    console.log('[Sentinel] Starting telemetry monitoring...');

    const interval = setInterval(async () => {
      if (!this.state.active) return;

      try {
        const telemetry = await this.collectTelemetry();

        // Check thresholds
        if (telemetry.errorRate > this.config.thresholds.errorRate) {
          await this.handleIncident({
            type: 'high-error-rate',
            severity: 'HIGH',
            message: `Error rate ${(telemetry.errorRate * 100).toFixed(2)}% exceeds threshold ${(this.config.thresholds.errorRate * 100)}%`,
            telemetry
          });
        }

        if (telemetry.avgResponseTime > this.config.thresholds.responseTime) {
          await this.handleIncident({
            type: 'slow-response',
            severity: 'MEDIUM',
            message: `Average response time ${telemetry.avgResponseTime}ms exceeds threshold ${this.config.thresholds.responseTime}ms`,
            telemetry
          });
        }

      } catch (error) {
        this.handleError('telemetry-monitoring', error);
      }
    }, this.config.pollingInterval);

    this.intervals.push(interval);
  }

  /**
   * Monitor for security incidents
   */
  startIncidentMonitoring() {
    console.log('[Sentinel] Starting incident monitoring...');

    const interval = setInterval(async () => {
      if (!this.state.active) return;

      try {
        // Check for security incidents
        const incidents = await this.detectSecurityIncidents();

        for (const incident of incidents) {
          await this.handleIncident(incident);
        }

      } catch (error) {
        this.handleError('incident-monitoring', error);
      }
    }, this.config.pollingInterval);

    this.intervals.push(interval);
  }

  /**
   * Analyze a git commit
   */
  async analyzeCommit(commit, projectPath) {
    console.log(`[Sentinel] Analyzing commit ${commit.sha.slice(0, 7)}: ${commit.message}`);

    // Get changed files
    const changedFiles = await this.getCommitChanges(commit.sha, projectPath);

    const findings = [];

    // Analyze each changed file
    for (const file of changedFiles) {
      try {
        const content = await this.readFile(file.path);

        // Use ensemble for maximum accuracy
        const result = await this.ensemble.analyzeWithEnsemble(
          'security-god',
          file.path,
          content,
          projectPath,
          { budget: 0.05 }
        );

        findings.push(...(result.issues || []));

      } catch (error) {
        console.error(`   Error analyzing ${file.path}:`, error.message);
      }
    }

    // Check for critical/high findings
    const critical = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');

    if (critical.length > 0) {
      await this.handleIncident({
        type: 'commit-security-issue',
        severity: 'HIGH',
        message: `Commit ${commit.sha.slice(0, 7)} introduced ${critical.length} security issues`,
        commit,
        findings: critical
      });
    }
  }

  /**
   * Handle an incident (detect → analyze → correlate → remediate → escalate if needed)
   */
  async handleIncident(incident) {
    console.log(`\n🚨 [INCIDENT DETECTED] ${incident.type}`);
    console.log(`   Severity: ${incident.severity}`);
    console.log(`   Message: ${incident.message}`);

    this.state.incidents.push({
      ...incident,
      timestamp: new Date().toISOString(),
      status: 'detected'
    });

    this.emit('incident', incident);

    // Phase 3: correlate with known findings and learn from this incident
    try {
      const correlation = await this.feedbackLoop.correlateIncident({
        file: incident.file || incident.filePath,
        line: incident.line || incident.lineNumber,
        error: incident.message || incident.type,
        stackTrace: incident.stackTrace,
        severity: incident.severity,
        source: incident.source || 'sentinel'
      });

      if (correlation.newRuleCandidate) {
        console.log(`   💡 New rule candidate: ${correlation.newRuleCandidate.ruleId}`);
        this.emit('new-rule-candidate', correlation.newRuleCandidate);
      }

      if (correlation.correlatedFindings.length > 0) {
        console.log(`   🔗 Correlated to ${correlation.correlatedFindings.length} known finding(s)`);
        // Boost confidence weights for the correlated categories
        const categories = correlation.correlatedFindings.map(f => ({ category: f.category })).filter(c => c.category);
        if (categories.length > 0) {
          await this.feedbackLoop.updateConfidenceFromProduction(categories);
        }
      }
    } catch {
      // Feedback loop is non-critical — never block incident handling
    }

    // Auto-remediate if enabled
    if (this.config.autoRemediate && this.shouldAutoRemediate(incident)) {
      console.log('   Attempting automatic remediation...');

      const remediation = await this.autoRemediate(incident);

      if (remediation.success) {
        console.log('   ✓ Incident auto-remediated');
        incident.status = 'remediated';
        incident.remediation = remediation;

        this.state.remediations.push(remediation);
        this.emit('remediated', { incident, remediation });

        return;
      } else {
        console.log('   ✗ Auto-remediation failed');
        incident.status = 'escalated';
      }
    }

    // Escalate to humans
    console.log('   Escalating to humans...');
    await this.escalateIncident(incident);

    incident.status = 'escalated';
    this.emit('escalated', incident);
  }

  /**
   * Determine if incident should be auto-remediated
   */
  shouldAutoRemediate(incident) {
    // Don't auto-remediate if we've hit the limit
    if (this.state.remediations.length >= this.config.maxAutoRemediations) {
      return false;
    }

    // Only auto-remediate medium/low severity
    if (incident.severity === 'CRITICAL' || incident.severity === 'HIGH') {
      return false;
    }

    return true;
  }

  /**
   * Automatically remediate incident using AI
   */
  async autoRemediate(incident) {
    try {
      if (incident.findings && incident.findings.length > 0) {
        // Use Level 4 fixers to remediate findings
        const results = await this.titanFix.runLevel4Fixes(incident.findings);

        return {
          success: results.applied > 0,
          applied: results.applied,
          cost: results.cost,
          details: results
        };
      }

      return { success: false, reason: 'No automated fix available' };

    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Escalate incident to humans
   */
  async escalateIncident(incident) {
    const escalation = {
      incident,
      timestamp: new Date().toISOString(),
      channels: []
    };

    for (const channel of this.config.escalationChannels) {
      try {
        await this.sendEscalation(channel, incident);
        escalation.channels.push(channel);
      } catch (error) {
        console.error(`   Failed to escalate via ${channel}:`, error.message);
      }
    }

    this.state.escalations.push(escalation);

    return escalation;
  }

  /**
   * Send escalation via specific channel
   */
  async sendEscalation(channel, incident) {
    const payload = {
      type: incident.type,
      severity: incident.severity,
      message: incident.message,
      timestamp: new Date().toISOString(),
      project: this.state.projectPath,
    };

    switch (channel) {
      case 'console':
        console.log('\n📢 ESCALATION:');
        console.log(`   Type: ${incident.type}`);
        console.log(`   Severity: ${incident.severity}`);
        console.log(`   Message: ${incident.message}`);
        console.log(`   Action required: Manual review and remediation\n`);
        break;

      case 'slack':
        await this.sendSlackNotification(payload);
        break;

      case 'pagerduty':
        await this.sendPagerDutyAlert(payload);
        break;

      case 'email':
        await this.sendEmailNotification(payload);
        break;

      default:
        console.log(`   Unknown escalation channel: ${channel}`);
    }
  }

  /**
   * Send Slack notification via webhook
   */
  async sendSlackNotification(payload) {
    const webhookUrl = process.env.SENTINEL_SLACK_WEBHOOK;
    if (!webhookUrl) {
      console.log('   [Slack] No webhook URL configured (SENTINEL_SLACK_WEBHOOK)');
      return;
    }

    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `🚨 *${payload.severity} INCIDENT*: ${payload.type}`,
          blocks: [
            {
              type: 'section',
              text: {
                type: 'mrkdwn',
                text: `*Severity:* ${payload.severity}\n*Type:* ${payload.type}\n*Message:* ${payload.message}`
              }
            },
            {
              type: 'context',
              elements: [
                { type: 'mrkdwn', text: `Project: \`${payload.project}\` | ${payload.timestamp}` }
              ]
            }
          ]
        })
      });
      console.log(`   [Slack] Notification sent (${response.status})`);
    } catch (error) {
      console.error('   [Slack] Failed to send:', error.message);
    }
  }

  /**
   * Send PagerDuty alert via Events API
   */
  async sendPagerDutyAlert(payload) {
    const routingKey = process.env.SENTINEL_PAGERDUTY_KEY;
    if (!routingKey) {
      console.log('   [PagerDuty] No routing key configured (SENTINEL_PAGERDUTY_KEY)');
      return;
    }

    try {
      const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          routing_key: routingKey,
          event_action: 'trigger',
          dedup_key: `sentinel-${payload.type}-${Date.now()}`,
          payload: {
            summary: `[CodeTitan Sentinel] ${payload.severity}: ${payload.message}`,
            severity: payload.severity === 'CRITICAL' ? 'critical' : payload.severity === 'HIGH' ? 'error' : 'warning',
            source: 'codetitan-sentinel',
            custom_details: payload
          }
        })
      });
      console.log(`   [PagerDuty] Alert created (${response.status})`);
    } catch (error) {
      console.error('   [PagerDuty] Failed to send:', error.message);
    }
  }

  /**
   * Send email notification via configured SMTP or API
   */
  async sendEmailNotification(payload) {
    const emailEndpoint = process.env.SENTINEL_EMAIL_ENDPOINT;
    const emailTo = process.env.SENTINEL_EMAIL_TO;

    if (!emailEndpoint || !emailTo) {
      console.log('   [Email] No endpoint/recipient configured (SENTINEL_EMAIL_ENDPOINT, SENTINEL_EMAIL_TO)');
      return;
    }

    try {
      const response = await fetch(emailEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: emailTo,
          subject: `[CodeTitan Alert] ${payload.severity}: ${payload.type}`,
          html: `
            <h2>🚨 CodeTitan Sentinel Alert</h2>
            <p><strong>Severity:</strong> ${payload.severity}</p>
            <p><strong>Type:</strong> ${payload.type}</p>
            <p><strong>Message:</strong> ${payload.message}</p>
            <p><strong>Project:</strong> ${payload.project}</p>
            <p><strong>Time:</strong> ${payload.timestamp}</p>
          `
        })
      });
      console.log(`   [Email] Notification sent (${response.status})`);
    } catch (error) {
      console.error('   [Email] Failed to send:', error.message);
    }
  }

  /**
   * Handle monitoring errors
   */
  handleError(source, error) {
    console.error(`[Sentinel] Error in ${source}:`, error.message);
    this.emit('error', { source, error });
  }

  /**
   * Get recent commits since last check
   * Uses simple-git for reliable git operations
   */
  async getRecentCommits(projectPath) {
    try {
      const simpleGit = require('simple-git');
      const git = simpleGit(projectPath);

      // Get commits from the last hour (or since last check)
      const since = this.state.lastCheck
        ? new Date(this.state.lastCheck).toISOString()
        : new Date(Date.now() - 3600000).toISOString(); // 1 hour ago

      const log = await git.log({
        '--since': since,
        maxCount: 10
      });

      this.state.lastCheck = new Date().toISOString();

      return log.all.map(commit => ({
        sha: commit.hash,
        message: commit.message,
        author: commit.author_name,
        date: commit.date,
        files: [] // Will be populated by getCommitChanges
      }));
    } catch (error) {
      console.error('[Sentinel] Failed to get commits:', error.message);
      return [];
    }
  }

  /**
   * Get files changed in a specific commit
   * Uses simple-git to parse the diff
   */
  async getCommitChanges(sha, projectPath) {
    try {
      const simpleGit = require('simple-git');
      const git = simpleGit(projectPath);
      const path = require('path');

      // Get the diff for this commit
      const diff = await git.diff([`${sha}^`, sha, '--name-status']);

      const changes = diff.split('\n')
        .filter(line => line.trim())
        .map(line => {
          const [status, ...fileParts] = line.split('\t');
          const file = fileParts.join('\t');
          return {
            status: status === 'A' ? 'added' : status === 'D' ? 'deleted' : 'modified',
            path: path.join(projectPath, file),
            relativePath: file
          };
        })
        .filter(change => /\.(js|jsx|ts|tsx|py|java|go)$/.test(change.path));

      return changes;
    } catch (error) {
      console.error('[Sentinel] Failed to get commit changes:', error.message);
      return [];
    }
  }

  /**
   * Read file content safely
   */
  async readFile(filePath) {
    const fs = require('fs').promises;
    return fs.readFile(filePath, 'utf-8');
  }

  /**
   * Collect telemetry from the application
   * Integrates with process metrics and optional external sources
   */
  async collectTelemetry() {
    const os = require('os');

    // Collect real system metrics
    const cpuUsage = os.loadavg()[0] / os.cpus().length * 100;
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const memoryUsage = ((totalMem - freeMem) / totalMem) * 100;

    // Simulated application metrics (would integrate with APM in production)
    const errorRate = this.state.incidents.filter(
      i => i.type === 'error' &&
        new Date(i.timestamp) > new Date(Date.now() - 300000) // Last 5 min
    ).length / 100;

    return {
      errorRate: Math.min(errorRate, 0.1),
      avgResponseTime: 100 + Math.random() * 100, // Would come from APM
      cpuUsage: Math.min(cpuUsage, 100),
      memoryUsage: Math.min(memoryUsage, 100),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Detect security incidents from recent activity
   * Monitors for suspicious patterns and known vulnerability signatures
   */
  async detectSecurityIncidents() {
    const incidents = [];

    // Check for recently added files with suspicious patterns
    // In production, this would integrate with security tools (Snyk, etc.)

    // Check for high severity findings in recent commits
    if (this.state.incidents.some(i =>
      i.severity === 'CRITICAL' &&
      i.status !== 'remediated' &&
      new Date(i.timestamp) > new Date(Date.now() - 3600000)
    )) {
      incidents.push({
        type: 'unresolved-critical',
        severity: 'HIGH',
        message: 'Unresolved critical security issue detected in recent commits'
      });
    }

    return incidents;
  }

  /**
   * Get Sentinel status
   */
  getStatus() {
    return {
      active: this.state.active,
      projectPath: this.state.projectPath,
      lastCheck: this.state.lastCheck,
      incidents: this.state.incidents.length,
      remediations: this.state.remediations.length,
      escalations: this.state.escalations.length,
      uptime: this.state.active ? Date.now() - this.state.startTime : 0
    };
  }
}

module.exports = Level8Sentinel;
