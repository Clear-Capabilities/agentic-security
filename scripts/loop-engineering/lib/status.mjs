// status.mjs: one function used by `status --json`, the dashboard API and the
// static fallback. Liveness is judged by the READER from lease + process
// identity, because a dead controller cannot update its own state.
import { join } from 'node:path';
import { platform } from 'node:os';
import { layout, currentRunId, judgeLease, readEvents, STALE_AFTER_MS } from './state.mjs';
import { readJson, redactDeep, nowIso } from './util.mjs';
import { loadManifest, checkPrdFresh } from './manifest.mjs';
import { TreeIndex } from './tree.mjs';
import { assessAll, computeProgress } from './progress.mjs';
import { evidenceKey } from './state.mjs';
import { activeOpLeases } from './oplease.mjs';
import { identityMatches } from './procscan.mjs';

const TERMINAL = new Set(['completed', 'crashed', 'stopped', 'failed', 'paused-budget', 'blocked']);
export const isTerminal = (s) => TERMINAL.has(s);

export function buildStatus(repoRoot, runId = null, { tree = null, events = 40 } = {}) {
  const id = runId || currentRunId(repoRoot);
  const out = { generatedAt: nowIso(), platform: platform(), repoRoot, runId: id, ok: true };
  const m = loadManifest(repoRoot);
  if (!m.ok) return { ...out, ok: false, error: m.error, status: 'invalid-manifest', verifiedPercent: 0 };
  const manifest = m.manifest;
  out.manifest = { version: m.version, acceptanceHash: manifest.acceptanceHash, prdSha256: manifest.prd.sha256, totals: manifest.totals, supersedes: manifest.supersedes, changes: manifest.changes ? { added: manifest.changes.added, denominator: manifest.changes.denominator } : null };
  const prdFresh = checkPrdFresh(repoRoot, manifest);
  if (!id) return { ...out, status: 'not-started', verifiedPercent: 0, prdFresh };
  const L = layout(repoRoot, id);
  const state = readJson(L.stateFile, null);
  if (!state) return { ...out, ok: false, status: 'unknown-run', error: `run ${id} has no state`, verifiedPercent: 0 };
  const ti = tree || new TreeIndex(repoRoot, join(layout(repoRoot).cacheDir, 'tree-cache.json')).build();
  const assess = assessAll({ L, manifest, tree: ti, key: evidenceKey(repoRoot) });
  const progress = computeProgress(manifest, assess, state.requirements || {});
  const ctl = judgeLease(L.leaseFile);
  const grd = judgeLease(L.guardianLeaseFile);
  // Effective status: a run that CLAIMS to be running but whose controller is
  // dead or stale is reported as such, never as running.
  let status = state.status;
  let statusReason = state.statusReason || null;
  if (!isTerminal(status) && status !== 'paused') {
    if (ctl.state === 'dead' || ctl.state === 'absent') { status = 'crashed'; statusReason = 'controller process is not alive (detected by reader)'; }
    else if (ctl.state === 'stale') { status = 'stale'; statusReason = `controller heartbeat is ${Math.round(ctl.ageMs / 1000)}s old (>${STALE_AFTER_MS / 1000}s)`; }
  }
  const leases = activeOpLeases(L.leasesDir);
  const cur = state.current ? { ...state.current } : null;
  if (cur?.pid) cur.workerAlive = identityMatches(cur.pid, cur.start);
  return redactDeep({
    ...out, status, statusReason, recordedStatus: state.status,
    runStartedAt: state.startedAt, updatedAt: state.updatedAt,
    verifiedPercent: progress.verifiedPercent, verifiedWeight: progress.verifiedWeight, totalWeight: progress.totalWeight,
    verifiedRequirements: progress.verifiedRequirements, totalRequirements: progress.totalRequirements,
    passedCriteria: progress.passedCriteria, totalCriteria: progress.totalCriteria,
    counts: progress.counts, categories: progress.categories,
    controller: { liveness: ctl.state, pid: state.controller?.pid || null, heartbeatAgeMs: ctl.ageMs ?? null, lastHeartbeatAt: ctl.lease?.at || null },
    guardian: { liveness: grd.state, pid: state.guardian?.pid || null },
    serve: grd.lease?.serve || null,
    current: cur, activeOperations: leases.map((l) => ({ label: l.label, pid: l.pid, deadlineAt: l.deadlineAt, startedAt: l.startedAt })),
    lastSubstantiveProgressAt: state.lastProgressAt || null,
    budgets: state.budgets || null, limits: manifest.profile?.limits || null,
    blockers: state.runBlockers || [],
    prdFresh,
    nextReady: progress.requirements.filter((r) => r.state === 'ready' && r.dependenciesVerified).slice(0, 5).map((r) => r.id),
    requirements: progress.requirements,
    recentEvents: readEvents(L, events),
    finalVerdict: state.finalVerdict || null,
    commands: commandsFor(id),
  });
}

export function commandsFor(runId) {
  const base = 'node scripts/loop-engineering/run.mjs';
  return {
    status: `${base} status --json`, pause: `${base} pause`, resume: `${base} resume`,
    stop: `${base} stop --run ${runId}`, verifyAll: `${base} verify --all --final`, plan: `${base} plan --next`,
  };
}

export function renderStaticHtml(status) {
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const rows = (status.requirements || []).map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.state)}</td><td>${r.criteria.passed}/${r.criteria.total}</td><td>${esc(r.title)}</td></tr>`).join('');
  return `<!doctype html><meta charset="utf-8"><title>Loop status (static)</title><body style="font:14px system-ui;margin:2rem"><h1>Loop status (static snapshot)</h1>
<p>Run <code>${esc(status.runId)}</code>: <b>${esc(status.status)}</b> ${esc(status.statusReason || '')}</p>
<p>Verified completion: <b>${esc(status.verifiedPercent)}%</b> (${esc(status.verifiedWeight)}/${esc(status.totalWeight)} weight, ${esc(status.verifiedRequirements)}/${esc(status.totalRequirements)} requirements, ${esc(status.passedCriteria)}/${esc(status.totalCriteria)} criteria). Generated ${esc(status.generatedAt)}.</p>
<table border="1" cellpadding="4" cellspacing="0"><tr><th>ID</th><th>State</th><th>Criteria</th><th>Title</th></tr>${rows}</table></body>`;
}
