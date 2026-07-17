// Two-way ticket sync — GitHub Issues / Linear / Jira.
//
// State file: .agentic-security/tickets.json
//   { findingId → { provider, externalId, externalUrl, state, syncedAt } }
//
// Sync algorithm:
//   - For every open critical/high finding without a ticket → create one.
//   - For every existing ticket whose finding is no longer in last-scan → close it.
//   - The state file is idempotent: re-running sync is a no-op once everything matches.
//
// Auth via environment variables:
//   GitHub  — `gh` CLI (uses existing auth)
//   Linear  — LINEAR_API_KEY
//   Jira    — JIRA_BASE_URL, JIRA_EMAIL, JIRA_TOKEN, JIRA_PROJECT_KEY

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { buildJiraIssue } from './index.js';
import { escapeMarkdown } from '../util/untrusted.js';

function statePath(scanRoot) {
  return path.join(scanRoot, '.agentic-security', 'tickets.json');
}
export function readState(scanRoot) {
  const fp = statePath(scanRoot);
  if (!fs.existsSync(fp)) return {};
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return {}; }
}
function writeState(scanRoot, state) {
  fs.mkdirSync(path.dirname(statePath(scanRoot)), { recursive: true });
  fs.writeFileSync(statePath(scanRoot), JSON.stringify(state, null, 2));
}

function findingTitle(f) {
  // vuln/title are lifted from the (untrusted) scanned code — escape before
  // they land in an issue title. See docs/AGENT_THREAT_MODEL.md path #1.
  const label = escapeMarkdown(f.vuln) || escapeMarkdown(f.title) || 'security finding';
  return `[${(f.severity || 'medium').toUpperCase()}] ${label} at ${f.file}:${f.line}`;
}
function findingBody(f) {
  const br = f.blastRadius;
  const exploited = f.exploitedNow ? `\n> ⚠️ **EPSS percentile ${(f.epssPercentile * 100).toFixed(1)}%** — actively exploited.\n` : '';
  return [
    `**File:** \`${f.file}:${f.line}\``,
    `**Severity:** ${f.severity}`,
    f.cwe ? `**CWE:** ${f.cwe}` : null,
    f.epss != null ? `**EPSS:** ${f.epss.toFixed(4)} (percentile ${(f.epssPercentile * 100).toFixed(1)}%)` : null,
    exploited,
    f.description ? `\n${escapeMarkdown(f.description)}` : null,
    br?.narrative ? `\n**Blast radius:** ${br.narrative}` : null,
    // snippet is attacker-authored code; escape so a crafted ``` fence or
    // <img>/[x](url) inside it cannot break out of the code block.
    f.snippet ? `\n\`\`\`\n${escapeMarkdown(f.snippet)}\n\`\`\`` : null,
    f.remediation ? `\n**Remediation:** ${f.remediation}` : null,
    `\n---\n_Surfaced by agentic-security · finding id: ${f.id}_`,
  ].filter(Boolean).join('\n');
}

// ─── GitHub Issues (via gh CLI) ──────────────────────────────────────────────
function ghCreate(repo, title, body, labels) {
  const args = ['issue', 'create', '--title', title, '--body', body];
  if (repo) args.unshift('--repo', repo);
  for (const l of labels) args.push('--label', l);
  try {
    const out = cp.execFileSync('gh', args, { encoding: 'utf8' });
    return { ok: true, url: out.trim() };
  } catch (e) { return { ok: false, error: e.message }; }
}
function ghClose(repo, url, comment) {
  const args = ['issue', 'close', url, '--comment', comment];
  if (repo) args.unshift('--repo', repo);
  try { cp.execFileSync('gh', args, { encoding: 'utf8' }); return { ok: true }; }
  catch (e) { return { ok: false, error: e.message }; }
}

// ─── Linear (REST GraphQL) ───────────────────────────────────────────────────
async function linearGraphQL(query, variables) {
  const key = process.env.LINEAR_API_KEY;
  if (!key) return { ok: false, error: 'LINEAR_API_KEY not set' };
  try {
    const res = await fetch('https://api.linear.app/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': key },
      body: JSON.stringify({ query, variables }),
    });
    const body = await res.json();
    if (body.errors) return { ok: false, error: JSON.stringify(body.errors) };
    return { ok: true, data: body.data };
  } catch (e) { return { ok: false, error: e.message }; }
}
async function linearCreate(teamId, title, description) {
  const m = `mutation($input: IssueCreateInput!) { issueCreate(input: $input) { issue { id url } } }`;
  const r = await linearGraphQL(m, { input: { teamId, title, description } });
  if (!r.ok) return r;
  const issue = r.data?.issueCreate?.issue;
  return issue ? { ok: true, externalId: issue.id, url: issue.url } : { ok: false, error: 'no issue returned' };
}
async function linearClose(issueId, stateName) {
  const sm = `query($id: String!) { issue(id: $id) { team { states { nodes { id name } } } } }`;
  const sr = await linearGraphQL(sm, { id: issueId });
  if (!sr.ok) return sr;
  const states = sr.data?.issue?.team?.states?.nodes || [];
  const target = states.find(s => s.name.toLowerCase() === (stateName || 'done').toLowerCase()) || states[states.length - 1];
  if (!target) return { ok: false, error: 'no target state' };
  const m = `mutation($id: String!, $stateId: String!) { issueUpdate(id: $id, input: {stateId: $stateId}) { success } }`;
  return linearGraphQL(m, { id: issueId, stateId: target.id });
}

// ─── Jira (REST) ─────────────────────────────────────────────────────────────
async function jiraRequest(method, urlPath, body) {
  const base = process.env.JIRA_BASE_URL;
  const email = process.env.JIRA_EMAIL;
  const token = process.env.JIRA_TOKEN;
  if (!base || !email || !token) return { ok: false, error: 'JIRA_BASE_URL, JIRA_EMAIL, JIRA_TOKEN required' };
  const auth = Buffer.from(`${email}:${token}`).toString('base64');
  try {
    const res = await fetch(`${base.replace(/\/$/, '')}${urlPath}`, {
      method,
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    return res.ok ? { ok: true, data } : { ok: false, error: `HTTP ${res.status}: ${text.slice(0, 200)}` };
  } catch (e) { return { ok: false, error: e.message }; }
}
async function jiraCreate(finding) {
  const project = process.env.JIRA_PROJECT_KEY || 'SEC';
  const issue = buildJiraIssue(finding, project);
  const r = await jiraRequest('POST', '/rest/api/2/issue', issue);
  if (!r.ok) return r;
  const key = r.data?.key;
  const base = process.env.JIRA_BASE_URL.replace(/\/$/, '');
  return { ok: true, externalId: key, url: `${base}/browse/${key}` };
}
async function jiraClose(externalId) {
  const t = await jiraRequest('GET', `/rest/api/2/issue/${externalId}/transitions`);
  if (!t.ok) return t;
  const transitions = t.data?.transitions || [];
  const done = transitions.find(x => /done|closed|resolved/i.test(x.name)) || transitions[transitions.length - 1];
  if (!done) return { ok: false, error: 'no transition available' };
  return jiraRequest('POST', `/rest/api/2/issue/${externalId}/transitions`, { transition: { id: done.id } });
}

// ─── orchestrator ────────────────────────────────────────────────────────────
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export async function syncTickets({ scanRoot, provider, severity = 'high', repo, teamId, dryRun = false }) {
  const minRank = SEV_RANK[severity] ?? 3;
  const lastScanPath = path.join(scanRoot, '.agentic-security', 'last-scan.json');
  if (!fs.existsSync(lastScanPath)) return { ok: false, error: 'no last-scan.json — run a scan first' };
  const last = JSON.parse(fs.readFileSync(lastScanPath, 'utf8'));
  const allFindings = [...(last.findings || []), ...(last.secrets || []), ...(last.supplyChain || [])];
  const eligible = allFindings.filter(f => (SEV_RANK[f.severity] ?? 0) >= minRank);
  const stillOpen = new Set(eligible.map(f => f.id));
  const state = readState(scanRoot);
  const created = [], closed = [], failed = [];

  // Create tickets for new findings.
  for (const f of eligible) {
    if (state[f.id] && !state[f.id].closedAt) continue; // already tracked + open
    const title = findingTitle(f);
    const body = findingBody(f);
    if (dryRun) { created.push({ id: f.id, title, dryRun: true }); continue; }
    let r;
    if (provider === 'github') {
      const labels = ['security', `severity:${f.severity}`];
      if (f.cwe) labels.push(f.cwe.toLowerCase());
      r = ghCreate(repo, title, body, labels);
      if (r.ok) state[f.id] = { provider, externalUrl: r.url, externalId: r.url, state: 'open', syncedAt: new Date().toISOString() };
    } else if (provider === 'linear') {
      if (!teamId) { failed.push({ id: f.id, error: 'linear: --team-id required' }); continue; }
      r = await linearCreate(teamId, title, body);
      if (r.ok) state[f.id] = { provider, externalId: r.externalId, externalUrl: r.url, state: 'open', syncedAt: new Date().toISOString() };
    } else if (provider === 'jira') {
      r = await jiraCreate(f);
      if (r.ok) state[f.id] = { provider, externalId: r.externalId, externalUrl: r.url, state: 'open', syncedAt: new Date().toISOString() };
    } else {
      return { ok: false, error: `unknown provider: ${provider}` };
    }
    if (r.ok) created.push({ id: f.id, externalId: r.externalId || r.url });
    else failed.push({ id: f.id, error: r.error });
  }

  // Close tickets for findings no longer present.
  for (const [findingId, entry] of Object.entries(state)) {
    if (entry.closedAt || stillOpen.has(findingId)) continue;
    if (entry.provider !== provider) continue;
    if (dryRun) { closed.push({ id: findingId, dryRun: true }); continue; }
    let r;
    if (provider === 'github') r = ghClose(repo, entry.externalUrl, 'Auto-closed by agentic-security: finding no longer present.');
    else if (provider === 'linear') r = await linearClose(entry.externalId);
    else if (provider === 'jira') r = await jiraClose(entry.externalId);
    if (r?.ok) {
      entry.closedAt = new Date().toISOString();
      entry.state = 'closed';
      closed.push({ id: findingId, externalId: entry.externalId });
    } else {
      failed.push({ id: findingId, error: r?.error || 'close failed' });
    }
  }

  if (!dryRun) writeState(scanRoot, state);
  return { ok: true, created, closed, failed, totalTracked: Object.keys(state).length };
}
