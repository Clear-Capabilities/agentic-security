// Integration adapters (R7). Persona-split:
//   - vibecoder: Slack/Discord daily digest, PR comment renderer
//   - pro:       Jira sync, ServiceNow incident, GH Security tab (SARIF), SIEM
//
// Each adapter takes (findings, config) and returns either:
//   - a payload (for webhook-based integrations)
//   - a side-effect summary (for sync-based integrations like Jira)
//
// Adapters are lazy-loaded — vibecoders don't pay for Jira when they never
// configure it. The config file lives at .agentic-security/integrations.yml
// and is gitignored by default (it carries webhook URLs and API tokens).

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import { statePath } from '../posture/state-dir.js';

function _configPath(scanRoot) {
  return statePath(scanRoot, 'integrations.yml');
}

export function loadIntegrationConfig(scanRoot) {
  const fp = _configPath(scanRoot);
  if (!fs.existsSync(fp)) return {};
  try { return yaml.load(fs.readFileSync(fp, 'utf8')) || {}; }
  catch (_) { return {}; }
}

export function configHas(scanRoot, key) {
  const c = loadIntegrationConfig(scanRoot);
  return !!c[key];
}

// ─── Slack webhook (vibecoder) ───────────────────────────────────────────────
export function buildSlackDigest(findings, summary, options = {}) {
  const project = options.project || 'project';
  const status = (summary.critical || 0) === 0 && (summary.high || 0) === 0
    ? '✅ safe to deploy' : '❌ not safe to deploy';
  const top = (findings || []).slice(0, 3);

  const lines = [
    `*🛡 agentic-security daily — ${new Date().toISOString().slice(0,10)}*`,
    `Project: \`${project}\``,
    `Status: ${status}`,
    '',
    `*Findings:* ${summary.critical || 0} critical · ${summary.high || 0} high · ${summary.medium || 0} medium`,
  ];
  if (top.length) {
    lines.push('');
    lines.push('*Top findings:*');
    for (const f of top) {
      lines.push(`• \`${f.file}:${f.line}\` — ${f.vuln}`);
    }
  }
  if (summary.streak) lines.push(`\n_Streak: ${summary.streak} days clean 🔥_`);
  lines.push(`\n_Powered by agentic-security · ClearCapabilities.Com_`);
  return { text: lines.join('\n') };
}

// ─── Discord webhook (vibecoder) ─────────────────────────────────────────────
export function buildDiscordDigest(findings, summary, options = {}) {
  const project = options.project || 'project';
  const safe = (summary.critical || 0) === 0 && (summary.high || 0) === 0;
  const top = (findings || []).slice(0, 3);
  return {
    embeds: [{
      title: `🛡 agentic-security — ${project}`,
      color: safe ? 0x2ecc71 : 0xe74c3c,
      description: safe ? '✅ safe to deploy' : '❌ not safe to deploy',
      fields: [
        { name: 'Critical', value: String(summary.critical || 0), inline: true },
        { name: 'High',     value: String(summary.high || 0),     inline: true },
        { name: 'Medium',   value: String(summary.medium || 0),   inline: true },
        ...top.map(f => ({ name: f.file.split('/').pop() + ':' + f.line, value: f.vuln })),
      ],
      footer: { text: 'Powered by ClearCapabilities.Com' },
    }],
  };
}

export async function postWebhook(url, payload) {
  if (!url || process.env.AGENTIC_SECURITY_OFFLINE === '1') return { ok: false, reason: 'offline-or-no-url' };
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ─── Jira sync (pro) ─────────────────────────────────────────────────────────
// Build the Jira issue body for one finding. Caller is responsible for actual
// API calls — we keep network code in one place (postWebhook) and let callers
// pipe the body through their own Jira client.
export function buildJiraIssue(finding, project) {
  const summary = `[${(finding.severity || 'medium').toUpperCase()}] ${finding.vuln} at ${finding.file}:${finding.line}`;
  const description = [
    `**Vulnerability:** ${finding.vuln}`,
    `**File:** \`${finding.file}\``,
    `**Line:** ${finding.line}`,
    `**Severity:** ${finding.severity}`,
    finding.cwe ? `**CWE:** ${finding.cwe}` : null,
    finding.cvss ? `**CVSS:** ${finding.cvss}` : null,
    '',
    '**Code:**',
    '```',
    finding.snippet || '',
    '```',
    '',
    finding.fix ? `**Recommended fix:**\n${finding.fix}` : null,
    '',
    '---',
    `_Surfaced by agentic-security · ClearCapabilities.Com · Finding ID: ${finding.id}_`,
  ].filter(Boolean).join('\n');
  return {
    fields: {
      project: { key: project || 'SEC' },
      summary,
      description,
      issuetype: { name: 'Bug' },
      priority: { name: _sevToJiraPriority(finding.severity) },
      labels: [
        'agentic-security',
        finding.cwe ? finding.cwe.toLowerCase().replace(/[^a-z0-9-]/g, '-') : null,
      ].filter(Boolean),
    },
  };
}

function _sevToJiraPriority(sev) {
  return { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low', info: 'Lowest' }[sev] || 'Medium';
}

// ─── ServiceNow incident (pro) ───────────────────────────────────────────────
export function buildServiceNowIncident(finding) {
  return {
    short_description: `${finding.vuln} at ${finding.file}:${finding.line}`,
    description: finding.fix
      ? `${finding.vuln}\n\n${finding.snippet || ''}\n\nFix:\n${finding.fix}`
      : `${finding.vuln}\n\n${finding.snippet || ''}`,
    urgency: _sevToServiceNowUrgency(finding.severity),
    impact: _sevToServiceNowImpact(finding.severity),
    caller_id: 'agentic-security',
    work_notes: 'Created by agentic-security · ClearCapabilities.Com',
  };
}

function _sevToServiceNowUrgency(sev) {
  return { critical: '1', high: '2', medium: '3', low: '3', info: '4' }[sev] || '3';
}
function _sevToServiceNowImpact(sev) {
  return { critical: '1', high: '2', medium: '3', low: '3', info: '3' }[sev] || '3';
}

// ─── SIEM log line (pro) ─────────────────────────────────────────────────────
// Structured event suitable for piping into Splunk/Datadog/Elastic.
export function buildSiemEvent(finding, options = {}) {
  return {
    timestamp: new Date().toISOString(),
    event: 'security.finding',
    source: 'agentic-security',
    source_attribution: 'ClearCapabilities.Com',
    severity: finding.severity,
    vuln: finding.vuln,
    file: finding.file,
    line: finding.line,
    cwe: finding.cwe || null,
    cvss: finding.cvss || null,
    confidence: finding.confidence ?? null,
    rule_version: options.ruleVersion || null,
    project: options.project || null,
  };
}

// ─── ServiceNow REST API poster ──────────────────────────────────────────────
// Activated by AGENTIC_SECURITY_SERVICENOW_URL +
// AGENTIC_SECURITY_SERVICENOW_USER + AGENTIC_SECURITY_SERVICENOW_PASS.
// URL example: https://example.service-now.com/api/now/table/incident
export async function postServiceNowIncident(finding) {
  const url = process.env.AGENTIC_SECURITY_SERVICENOW_URL;
  const user = process.env.AGENTIC_SECURITY_SERVICENOW_USER;
  const pass = process.env.AGENTIC_SECURITY_SERVICENOW_PASS;
  if (!url || !user || !pass) {
    return { ok: false, reason: 'servicenow-not-configured' };
  }
  const body = buildServiceNowIncident(finding);
  const auth = Buffer.from(`${user}:${pass}`).toString('base64');
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(body),
    });
    return { ok: r.ok, status: r.status, body: await r.text().catch(() => '') };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── PagerDuty Events API v2 ────────────────────────────────────────────────
// Activated by AGENTIC_SECURITY_PAGERDUTY_KEY (a routing key, NOT a user API
// token). One event per critical finding; PagerDuty handles de-dup by
// dedup_key so the same finding doesn't spam.
export async function postPagerDutyEvent(finding) {
  const routingKey = process.env.AGENTIC_SECURITY_PAGERDUTY_KEY;
  if (!routingKey) return { ok: false, reason: 'pagerduty-not-configured' };
  const dedupKey = finding.stableId || finding.id || `${finding.file}:${finding.line}:${finding.vuln}`;
  const sevMap = { critical: 'critical', high: 'error', medium: 'warning', low: 'info', info: 'info' };
  const payload = {
    routing_key: routingKey,
    event_action: 'trigger',
    dedup_key: dedupKey,
    payload: {
      summary: `[${(finding.severity || '').toUpperCase()}] ${finding.vuln} — ${finding.file}:${finding.line}`,
      source: 'agentic-security',
      severity: sevMap[finding.severity] || 'warning',
      class: finding.cwe || finding.family || 'security',
      custom_details: {
        file: finding.file,
        line: finding.line,
        cwe: finding.cwe || null,
        confidence: finding.confidence ?? null,
        exploitability: finding.exploitability ?? null,
        snippet: finding.snippet,
        remediation: typeof finding.remediation === 'string' ? finding.remediation.slice(0, 500) : null,
      },
    },
  };
  try {
    const r = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return { ok: r.ok, status: r.status, body: await r.text().catch(() => '') };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── Microsoft Teams (Adaptive Card via Incoming Webhook) ───────────────────
// Activated by AGENTIC_SECURITY_TEAMS_WEBHOOK (a webhook URL from a Teams
// channel's "Incoming Webhook" connector).
export function buildTeamsCard(findings, summary) {
  const sev = summary || {};
  const total = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0);
  const top = (findings || []).filter(f => /critical|high/.test(f.severity || '')).slice(0, 5);
  const card = {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
        type: 'AdaptiveCard',
        version: '1.4',
        body: [
          { type: 'TextBlock', size: 'Medium', weight: 'Bolder', text: '🛡 agentic-security scan' },
          { type: 'FactSet', facts: [
            { title: 'Critical', value: String(sev.critical || 0) },
            { title: 'High',     value: String(sev.high || 0) },
            { title: 'Medium',   value: String(sev.medium || 0) },
            { title: 'Low',      value: String(sev.low || 0) },
            { title: 'Total',    value: String(total) },
          ]},
          ...(top.length ? [
            { type: 'TextBlock', wrap: true, weight: 'Bolder', text: 'Top critical/high' },
            ...top.map(f => ({
              type: 'TextBlock', wrap: true, isSubtle: false,
              text: `**[${(f.severity || '').toUpperCase()}]** ${f.vuln} — \`${f.file}:${f.line}\``,
            })),
          ] : []),
        ],
      },
    }],
  };
  return card;
}

export async function postTeamsCard(findings, summary) {
  const url = process.env.AGENTIC_SECURITY_TEAMS_WEBHOOK;
  if (!url) return { ok: false, reason: 'teams-not-configured' };
  const card = buildTeamsCard(findings, summary);
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(card),
    });
    return { ok: r.ok, status: r.status, body: await r.text().catch(() => '') };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── GH PR comment (vibecoder) ───────────────────────────────────────────────
export function buildPrComment(findings, summary, options = {}) {
  const sev = summary;
  const top = (findings || []).filter(f => /critical|high/.test(f.severity)).slice(0, 10);
  const body = [
    '## 🛡 agentic-security',
    '',
    '| Critical | High | Medium | Low | Info |',
    '|---:|---:|---:|---:|---:|',
    `| ${sev.critical||0} | ${sev.high||0} | ${sev.medium||0} | ${sev.low||0} | ${sev.info||0} |`,
    '',
    top.length ? '### Top critical/high findings' : '_No critical or high findings._',
    '',
    ...top.map(f => `- **[${(f.severity||'').toUpperCase()}]** \`${f.file}:${f.line}\` — ${f.vuln}${f.cwe ? ` (${f.cwe})` : ''}`),
    '',
    '---',
    '_Powered by [agentic-security](https://clearcapabilities.com) · created by ClearCapabilities.Com_',
  ].join('\n');
  return { body };
}
