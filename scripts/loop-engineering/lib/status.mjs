// status.mjs: one function used by `status --json`, the dashboard API and the
// static fallback. Liveness is judged by the READER from lease + process
// identity, because a dead controller cannot update its own state.
import { join } from 'node:path';
import { platform } from 'node:os';
import { layout, currentRunId, judgeLease, readEvents, readStateFile, STALE_AFTER_MS } from './state.mjs';
import { readJson, redactDeep, nowIso } from './util.mjs';
import { loadManifest, checkPrdFresh } from './manifest.mjs';
import { TreeIndex } from './tree.mjs';
import { assessAll, computeProgress } from './progress.mjs';
import { evidenceKey } from './state.mjs';
import { activeOpLeases } from './oplease.mjs';
import { identityMatches } from './procscan.mjs';
import { assessFinal } from './final.mjs';
import { detectDrift } from './drift.mjs';
import { loadProfile } from './profile.mjs';
import { resolve } from 'node:path';

const TERMINAL = new Set(['completed', 'crashed', 'stopped', 'failed', 'paused-budget', 'blocked']);
export const isTerminal = (s) => TERMINAL.has(s);

export function buildStatus(repoRoot, runId = null, { tree = null, events = 40 } = {}) {
  const id = runId || currentRunId(repoRoot);
  const out = { generatedAt: nowIso(), platform: platform(), repoRoot, runId: id, ok: true };
  const m = loadManifest(repoRoot);
  if (!m.ok) return { ...out, ok: false, error: m.error, status: 'invalid-manifest', verifiedPercent: 0 };
  const manifest = m.manifest;
  out.manifest = { version: m.version, prdPath: manifest.prd.path, acceptanceHash: manifest.acceptanceHash, prdSha256: manifest.prd.sha256, totals: manifest.totals, supersedes: manifest.supersedes, changes: manifest.changes ? { added: manifest.changes.added, denominator: manifest.changes.denominator } : null };
  const prdFresh = checkPrdFresh(repoRoot, manifest);
  if (!id) return { ...out, status: 'not-started', verifiedPercent: 0, prdFresh };
  const L = layout(repoRoot, id);
  const state = readStateFile(L).state;
  if (!state) return { ...out, ok: false, status: 'unknown-run', error: `run ${id} has no state`, verifiedPercent: 0 };
  const ti = tree || new TreeIndex(repoRoot, join(layout(repoRoot).cacheDir, 'tree-cache.json')).build();
  const assess = assessAll({ L, manifest, tree: ti, key: evidenceKey(repoRoot) });
  const key = evidenceKey(repoRoot);
  const final = assessFinal({ file: L.finalEvidence, manifest, tree: ti, key });
  const progress = computeProgress(manifest, assess, state.requirements || {}, { final });
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
  // A run recorded as completed whose final record no longer describes this tree is not complete.
  if (status === 'completed' && ((final.required && !final.ok) || progress.verifiedPercent < 100)) {
    status = 'final-stale';
    statusReason = `completion no longer holds: ${final.required && !final.ok ? final.reasons.join('; ') : 'a requirement no longer has fresh passing evidence'}`;
  }
  // Drift is judged by the reader from the frozen record, so it is visible even when no controller is alive.
  let drift = null;
  if (state.frozen && status !== 'completed') {
    let prof; try { prof = loadProfile(resolve(repoRoot, state.profilePath)).profile; } catch { prof = null; }
    const d = detectDrift({ repoRoot, frozen: state.frozen, profile: prof });
    if (d.drifted) drift = d;
  }
  const leases = activeOpLeases(L.leasesDir);
  const cur = state.current ? { ...state.current } : null;
  if (cur?.pid) cur.workerAlive = identityMatches(cur.pid, cur.start);
  const result = {
    ...out, status, statusReason, recordedStatus: state.status,
    runStartedAt: state.startedAt, updatedAt: state.updatedAt,
    verifiedPercent: progress.verifiedPercent, verifiedWeight: progress.verifiedWeight, totalWeight: progress.totalWeight,
    verifiedRequirements: progress.verifiedRequirements, totalRequirements: progress.totalRequirements,
    passedCriteria: progress.passedCriteria, totalCriteria: progress.totalCriteria,
    counts: progress.counts, categories: progress.categories, ...(progress.workstreams ? { workstreams: progress.workstreams } : {}),
    final: { required: final.required, ok: final.ok, reasons: final.reasons, recordedAt: final.recordedAt || null }, drift,
    controller: { liveness: ctl.state, pid: state.controller?.pid || null, heartbeatAgeMs: ctl.ageMs ?? null, lastHeartbeatAt: ctl.lease?.at || null, mainLoopAgeMs: ctl.lease?.mainTickAt ? Date.now() - ctl.lease.mainTickAt : null },
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
    evidencePaths: evidencePaths(L, progress, state),
  };
  result.continuation = continuationFor(result, state);
  result.summary = summarize(result);
  return redactDeep(result);
}

function evidencePaths(L, progress, state) {
  return {
    finalReport: state.finalVerdict ? L.finalReport : null,
    finalEvidence: L.finalEvidence,
    completionReport: L.completionReport,
    requirementEvidence: Object.fromEntries(progress.requirements.filter((r) => r.evidence?.file).map((r) => [r.id, r.evidence.file])),
  };
}

// The exact command that moves this run forward, chosen from the state the reader judged, never from what the controller claims.
export function continuationFor(st, state) {
  const base = 'node scripts/loop-engineering/run.mjs';
  const prd = st.manifest?.prdPath || state?.frozen?.prdPath || '<prd>';
  const init = `${base} init --prd ${prd} --profile ${state?.profilePath || '<profile>'}`;
  if (st.drift) return { command: init, why: 'frozen inputs changed; review the change, then re-initialise explicitly (this invalidates the evidence that depended on it)' };
  switch (st.status) {
    case 'running': case 'verifying': case 'starting': return { command: `${base} status --json`, why: 'the controller is live; nothing to continue' };
    case 'paused': case 'stopped': case 'crashed': case 'stale': case 'failed': return { command: `${base} resume`, why: `run is ${st.status}; resume restarts a controller from the checkpoint` };
    case 'paused-budget': return { command: init, why: 'a finite budget is exhausted; raising it is a reviewed profile edit followed by a new init, then resume' };
    case 'blocked': return { command: `${base} resume`, why: 'resolve the listed blockers (caps are never reset), then resume' };
    case 'final-stale': return { command: init, why: 'the tree changed after the final verification; re-initialise to start a new run' };
    case 'completed': return { command: null, why: 'complete: every criterion and the final gate passed on a stable digest' };
    case 'initialized': return { command: `${base} start --background`, why: 'initialised, not started' };
    default: return { command: `${base} status --json`, why: 'inspect' };
  }
}

// ONE normalised view used by the CLI, the JSON and the dashboard, so they cannot disagree (LOOP-003.AC01).
export function summarize(st) {
  const rows = st.requirements || [];
  const ids = (state) => rows.filter((r) => r.state === state).map((r) => r.id);
  const cur = st.current;
  const row = cur?.requirement ? rows.find((r) => r.id === cur.requirement) : null;
  const unmet = cur?.unmetCriteria?.length ? cur.unmetCriteria : (row?.unmetCriteria || []);
  const activeCriterion = cur?.requirement ? { requirement: cur.requirement, criterion: unmet[0] || null, phase: cur.phase || null } : null;
  const b = st.budgets || {}, l = st.limits || {};
  const ws = st.workstreams ? Object.entries(st.workstreams).map(([key, w]) => ({ key, label: w.label, kind: w.kind, verified: w.verifiedRequirements, total: w.totalRequirements, verifiedWeight: w.verifiedWeight, totalWeight: w.totalWeight, stale: w.stale, blocked: w.blocked, failed: w.failed })) : [];
  const spent = { usd: Number((b.usdUsed || 0).toFixed(2)), attempts: b.attemptsUsed || 0, wallSeconds: Math.round((b.wallUsedMs || 0) / 1000), limits: { usd: l.claudeBudgetUsd ?? null, attempts: l.runMaxAttempts ?? null, wallSeconds: l.runWallSeconds ?? null } };
  const s = {
    percent: st.verifiedPercent, verifiedWeight: st.verifiedWeight, totalWeight: st.totalWeight, verifiedRequirements: st.verifiedRequirements, totalRequirements: st.totalRequirements,
    workstreams: ws, stale: ids('stale'), blocked: ids('blocked'), failed: [...ids('failed'), ...ids('timed-out')],
    activeCriterion, spent, lastHeartbeatAt: st.controller?.lastHeartbeatAt || null, liveness: st.controller?.liveness || null,
    continuation: st.continuation?.command || null,
  };
  s.lines = summaryLines(s);
  return s;
}

export function summaryLines(s) {
  const lines = [];
  lines.push(`weighted verified progress: ${s.percent}% (${s.verifiedWeight}/${s.totalWeight} weight, ${s.verifiedRequirements}/${s.totalRequirements} requirements)`);
  for (const w of s.workstreams) lines.push(`workstream ${w.key}: ${w.verified}/${w.total} verified (${w.verifiedWeight}/${w.totalWeight} weight)${w.stale || w.blocked || w.failed ? `, stale ${w.stale}, blocked ${w.blocked}, failed ${w.failed}` : ''}`);
  lines.push(`stale: ${s.stale.join(' ') || 'none'}`);
  lines.push(`blocked: ${s.blocked.join(' ') || 'none'}`);
  lines.push(`failed: ${s.failed.join(' ') || 'none'}`);
  lines.push(`active criterion: ${s.activeCriterion ? `${s.activeCriterion.criterion || s.activeCriterion.requirement} (${s.activeCriterion.requirement}${s.activeCriterion.phase ? `, ${s.activeCriterion.phase}` : ''})` : 'none'}`);
  lines.push(`spent: ${s.spent.attempts}/${s.spent.limits.attempts ?? '?'} attempts, $${s.spent.usd.toFixed(2)} of $${s.spent.limits.usd ?? '?'}, ${s.spent.wallSeconds}s of ${s.spent.limits.wallSeconds ?? '?'}s`);
  lines.push(`last heartbeat: ${s.lastHeartbeatAt || 'never'} (${s.liveness || 'unknown'})`);
  lines.push(`continue: ${s.continuation || 'nothing to continue'}`);
  return lines;
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
