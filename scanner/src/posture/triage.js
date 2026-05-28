// Pro-only triage layer (R6). JSON-backed store at .agentic-security/triage.json.
// Tracks state, assignees, comments, and transitions per finding. Computes
// MTTR and trend stats from the transition log.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath, safeWriteState } from './state-dir.js';
import { appendAcceptRiskFromTriage } from './sca-policy.js';

export const STATES = ['open', 'in-progress', 'fixed', 'wont-fix', 'false-positive'];

function _storePath(scanRoot) {
  return statePath(scanRoot, 'triage.json');
}

export function loadTriage(scanRoot) {
  const fp = _storePath(scanRoot);
  if (!fs.existsSync(fp)) return { findings: {}, transitions: [] };
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch (_) { return { findings: {}, transitions: [] }; }
}

function _save(scanRoot, data) {
  const fp = _storePath(scanRoot);
  safeWriteState(fp, JSON.stringify(data, null, 2));
}

// Sync the triage store with the latest scan: new findings become 'open',
// findings no longer surfaced become 'fixed' (with a transition entry).
export function syncWithScan(scanRoot, findings) {
  const data = loadTriage(scanRoot);
  const now = new Date().toISOString();
  const seen = new Set();
  for (const f of findings) {
    const id = f.id || `${f.file}:${f.line}:${f.vuln}`;
    seen.add(id);
    if (!data.findings[id]) {
      data.findings[id] = {
        id,
        file: f.file,
        line: f.line,
        vuln: f.vuln,
        severity: f.severity,
        state: 'open',
        assignee: null,
        opened_at: now,
        comments: [],
        // Phase 4 / Item 7: capture SCA-relevant fields so the
        // triage → sca-policy bridge has enough data to materialize an
        // accept-risk entry on wont-fix. No-ops for SAST findings.
        type: f.type || null,
        name: f.name || null,
        version: f.version || null,
        ecosystem: f.ecosystem || null,
        osvId: f.osvId || null,
        cveAliases: Array.isArray(f.cveAliases) ? f.cveAliases : [],
      };
      data.transitions.push({ id, from: null, to: 'open', at: now });
    }
  }
  // Auto-close findings that scanner no longer sees.
  for (const id of Object.keys(data.findings)) {
    const cur = data.findings[id];
    if (seen.has(id)) continue;
    if (cur.state === 'fixed' || cur.state === 'wont-fix' || cur.state === 'false-positive') continue;
    cur.state = 'fixed';
    cur.fixed_at = now;
    data.transitions.push({ id, from: 'open', to: 'fixed', at: now, automatic: true });
  }
  _save(scanRoot, data);
  return data;
}

export function assign(scanRoot, id, assignee) {
  const data = loadTriage(scanRoot);
  if (!data.findings[id]) return { ok: false, error: 'unknown finding id' };
  data.findings[id].assignee = assignee;
  data.findings[id].assigned_at = new Date().toISOString();
  _save(scanRoot, data);
  return { ok: true };
}

export function transition(scanRoot, id, toState, comment) {
  const data = loadTriage(scanRoot);
  if (!data.findings[id]) return { ok: false, error: 'unknown finding id' };
  if (!STATES.includes(toState)) return { ok: false, error: `invalid state: ${toState}` };
  const cur = data.findings[id];
  const from = cur.state;
  cur.state = toState;
  if (toState === 'fixed') cur.fixed_at = new Date().toISOString();
  data.transitions.push({ id, from, to: toState, at: new Date().toISOString(), comment });
  _save(scanRoot, data);

  // Phase 4 / Item 7 of the SCA improvement plan — bridge wont-fix
  // transitions on SCA findings into sca-policy.yml accept-risk entries
  // so the suppression is durable across rescans. The finding object on
  // the triage store has a `type` field when it was synced from a scan
  // via syncWithScan; we only bridge type === 'vulnerable_dep'.
  let policyBridge = null;
  if (toState === 'wont-fix' && cur.type === 'vulnerable_dep') {
    try {
      const reason = comment || `Marked wont-fix in triage on ${new Date().toISOString().slice(0,10)}`;
      policyBridge = appendAcceptRiskFromTriage(scanRoot, cur, reason);
    } catch (e) {
      policyBridge = { ok: false, reason: String(e && e.message || e) };
    }
  }
  return { ok: true, policyBridge };
}

export function comment(scanRoot, id, author, body) {
  const data = loadTriage(scanRoot);
  if (!data.findings[id]) return { ok: false, error: 'unknown finding id' };
  data.findings[id].comments.push({ author, body, at: new Date().toISOString() });
  _save(scanRoot, data);
  return { ok: true };
}

export function list(scanRoot, filter = {}) {
  const data = loadTriage(scanRoot);
  let out = Object.values(data.findings);
  if (filter.state) out = out.filter(f => f.state === filter.state);
  if (filter.severity) out = out.filter(f => f.severity === filter.severity);
  if (filter.assignee) out = out.filter(f => f.assignee === filter.assignee);
  if (filter.unassigned) out = out.filter(f => !f.assignee);
  return out;
}

// Trends across the last N days. Returns counts by severity, opened/closed
// pairs, and median MTTR.
export function trend(scanRoot, sinceDays = 30) {
  const data = loadTriage(scanRoot);
  const cutoff = Date.now() - sinceDays * 86400000;
  const findings = Object.values(data.findings);
  const recent = data.transitions.filter(t => new Date(t.at).getTime() >= cutoff);

  const opened = recent.filter(t => t.to === 'open').length;
  const closed = recent.filter(t => t.to === 'fixed').length;

  const openBySev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.state === 'open' || f.state === 'in-progress') {
      openBySev[f.severity] = (openBySev[f.severity] || 0) + 1;
    }
  }

  // MTTR: for each finding fixed in window, (fixed_at - opened_at).
  const mttrMs = [];
  for (const f of findings) {
    if (!f.fixed_at) continue;
    if (new Date(f.fixed_at).getTime() < cutoff) continue;
    const dur = new Date(f.fixed_at).getTime() - new Date(f.opened_at).getTime();
    if (dur > 0) mttrMs.push(dur);
  }
  mttrMs.sort((a, b) => a - b);
  const medianMttr = mttrMs.length
    ? mttrMs[Math.floor(mttrMs.length / 2)] / 86400000
    : null;

  return {
    sinceDays,
    opened,
    closed,
    net: closed - opened,
    openBySev,
    medianMttrDays: medianMttr,
    totalOpen: findings.filter(f => f.state === 'open' || f.state === 'in-progress').length,
  };
}

export function exportTriageMetrics(scanRoot) {
  const triage = loadTriage(scanRoot);
  const findings = Object.values(triage.findings || {});
  const families = {};
  for (const f of findings) {
    const fam = f.family || 'unknown';
    if (!families[fam]) families[fam] = { tp: 0, fp: 0 };
    if (f.state === 'fixed' || f.state === 'open' || f.state === 'in-progress') families[fam].tp++;
    else if (f.state === 'false-positive') families[fam].fp++;
  }
  return { families };
}
