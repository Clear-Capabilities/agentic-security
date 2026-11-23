// Imported runtime observations fed back into the contract (contract-driven verification, Epic G).
//
// Observations come only through the existing sanitizing importer (`lineage/deployment/trace-correlation.js` `importTraceLines`): closed
// key allowlists, paths normalized to route shapes, credential- and payload-shaped fields removed and counted. No live collector, no
// raw user input: a route-level trace says a route was reached, never what was sent.
//
// The workflow, each step a record with its evidence:
//   1. `discrepancies`  compare the observation set with the context build's entry points. An observed route the build never modeled
//                       is an `unmodeled-path` discrepancy naming the missing assumption. Each discrepancy carries the environment,
//                       the window, the sampling, and whether the observation can be tied to the contract's build at all
//                       (`buildBinding`: matched, mismatched, unknown); a mismatched, unknown or stale binding is a LIMITATION
//                       on the record, never corroboration that the current code runs that path. A statically modeled route with no
//                       observation is `not-observed-in-window`, never "unreachable" or "safe" (G-AC02).
//   2. `propose`        a PROPOSED contract revision whose invariant scope covers the path, and a proposed scenario request; neither
//                       is approved here (G-AC06). A model may draft; only the ledger approves.
//   3. `regressionRecord` once a reviewer approved the proposal and the scenario was replayed in the trust boundary, the confirmed case
//                       becomes development regression coverage with its provenance; it is tagged so it can never enter a sealed
//                       evaluation population.
import { importTraceLines } from '../lineage/deployment/trace-correlation.js';
import { digestOf } from '../posture/assurance/identity.js';
import { contractRef, validateContract } from './schema.js';

export const DISCREPANCY_KINDS = Object.freeze(['unmodeled-path', 'not-observed-in-window', 'environment-mismatch']);
export const BUILD_BINDINGS = Object.freeze(['matched', 'mismatched', 'unknown']);
const routeLabel = (r) => (r && r.path ? `${r.method || 'ANY'} ${r.path}` : null);
const normLabel = (l) => String(l || '').replace(/:[A-Za-z_][\w]*/g, ':id');

/**
 * @param {object} o
 * @param {string} o.traceText          JSONL trace lines (sanitized on import)
 * @param {string} o.environment        the environment the contract speaks about
 * @param {object} o.contract           a validated contract
 * @param {string[]} o.modeledRoutes    entry-point labels from the context build ("PUT /invoices/:id/memo")
 * @param {object} [o.build]            { revision } the operator says the traced deployment ran; compared with the contract's pin
 * @param {string} o.now                ISO time supplied by the caller (staleness is judged against it)
 * @param {number} [o.staleAfterDays]
 */
export function discrepancies({ traceText, environment, contract, modeledRoutes = [], build = null, now, staleAfterDays = 7 }) {
  const imp = importTraceLines(traceText, { environment });
  if (imp.status !== 'ok') return { status: imp.status, reason: imp.reason, records: [] };
  const set = imp.set;
  const pinned = new Set((contract?.scope?.repositories || []).map((r) => r.revision));
  const buildBinding = !build || !build.revision ? 'unknown' : pinned.has(build.revision) ? 'matched' : 'mismatched';
  const obs = set.observations || [];
  const modeled = new Map(modeledRoutes.map((l) => [normLabel(l), l]));
  const records = [];
  const seenModeled = new Set();
  for (const o of obs) {
    const label = routeLabel(o.route);
    if (!label) continue;
    const key = normLabel(label);
    const stale = typeof now === 'string' && (Date.parse(now) - Date.parse(o.lastObservedAt)) > staleAfterDays * 86400000;
    const limitations = [];
    if (buildBinding !== 'matched') limitations.push(buildBinding === 'mismatched' ? 'the traced build is not the contract\'s pinned revision: this is not evidence about the current code' : 'no build identity was supplied for the trace: it cannot be tied to the contract\'s revision');
    if (stale) limitations.push(`last observed ${o.lastObservedAt}, older than ${staleAfterDays} days`);
    if (o.sampled) limitations.push('sampled traffic: absence elsewhere means nothing');
    if (modeled.has(key)) { seenModeled.add(key); continue; }
    records.push({
      id: `disc:${digestOf({ environment, label: key, contract: contractRef(contract) }).slice(7, 23)}`, kind: 'unmodeled-path', route: label, environment, observationId: o.id,
      window: { first: o.firstObservedAt, last: o.lastObservedAt }, eventCount: o.eventCount, outcome: o.outcome, sampled: o.sampled, buildBinding, stale, limitations,
      missingAssumption: `the context build modeled no entry point for ${label}; the contract's invariants say nothing about it`,
      evidence: { source: 'imported-trace', sanitization: set.sanitization ?? null },
    });
  }
  for (const [key, label] of modeled) {
    if (seenModeled.has(key)) continue;
    records.push({ id: `disc:${digestOf({ environment, label: key, absent: true }).slice(7, 23)}`, kind: 'not-observed-in-window', route: label, environment, buildBinding, limitations: ['no observation in this window is not evidence that the path is unreachable, blocked or safe'], evidence: { source: 'imported-trace' } });
  }
  return { status: 'ok', reason: null, buildBinding, imported: { accepted: set.stats?.accepted ?? null, rejected: set.stats?.rejected ?? null }, records };
}

/**
 * A PROPOSED contract revision covering an unmodeled path, and the scenario request that would exercise it. The version is bumped,
 * the review is `proposed`, and nothing about it is authority until a reviewer approves the new content in the ledger.
 */
export function propose(contract, discrepancy, { invariantId = null } = {}) {
  if (discrepancy?.kind !== 'unmodeled-path') return { ok: false, reason: 'only an unmodeled path produces a proposal' };
  const next = JSON.parse(JSON.stringify(contract));
  const [maj, min, pat] = next.version.split('.').map(Number);
  next.version = `${maj}.${min + 1}.${pat}`;
  next.review = { state: 'proposed', origin: 'inferred', note: `runtime discrepancy ${discrepancy.id}: ${discrepancy.route} was observed and not modeled` };
  const target = invariantId ? next.invariants.find((i) => i.id === invariantId) : null;
  if (target) {
    target.scope = { ...(target.scope || {}), routes: [...new Set([...(target.scope?.routes || []), discrepancy.route])].slice(0, 64) };
    target.attacker = { ...target.attacker, entryPoints: [...new Set([...(target.attacker.entryPoints || []), discrepancy.route])].slice(0, 64) };
  }
  delete next.threatPack; // the readable pack no longer matches; a reviewer writes the new one
  const v = validateContract(next);
  return { ok: v.ok, errors: v.errors, contract: next, contractRef: v.ok ? contractRef(next) : null, scenarioRequest: { route: discrepancy.route, environment: discrepancy.environment, inputs: 'synthetic reconstruction required: the trace carries the route shape only, never the request', incomplete: true }, approval: 'not-recorded' };
}

/** The regression record of a confirmed, approved, replayed case. `replay` is a classified scenario result from the trust boundary. */
export function regressionRecord({ discrepancy, proposalRef, approval, replay }) {
  const replayed = replay && replay.status === 'completed';
  const status = approval?.state !== 'approved' ? 'awaiting-approval' : !replayed ? 'awaiting-replay' : replay.outcome === 'confirmed' ? 'regression-case' : 'not-reproduced';
  return { schema: 'agentic-security/runtime-regression-record', discrepancyId: discrepancy.id, route: discrepancy.route, proposalRef, approval: approval ? { state: approval.state, transitionId: approval.transitionId ?? null } : null, replay: replay ? { status: replay.status, outcome: replay.outcome ?? null, recordId: replay.recordId ?? null } : null, status, population: 'development-regression', sealedEligible: false, limitations: discrepancy.limitations || [] };
}

// ---- isolated shadow comparison (G-03) ------------------------------------------------------------------------------------------
//
// The same declared workload is replayed against the baseline and the patched application, each through the business-state oracle in
// its own trust-boundary run with its own in-memory store (separate processes, no shared mutable state by construction). The comparison
// reads both reports: the expected denials, the allowed (control) behaviour with its durable effect, the errors, and the forbidden
// outcomes. Thresholds are versioned and fixed before the comparison. A patch that breaks the authorized workflow fails, with both
// reports kept as evidence.
export const SHADOW_THRESHOLDS = Object.freeze({ version: 'shadow-thresholds/1', allowControlRegression: false, allowNewForbidden: false });

export function shadowCompare({ baseline, patched, thresholds = SHADOW_THRESHOLDS }) {
  const view = (r) => {
    const run = (r?.results || []).find((x) => x.status === 'completed') || null;
    const pre = run?.report?.preconditions || null;
    return { completed: !!run, outcome: run?.outcome ?? null, controlRan: pre ? pre.controlRan : null, controlDurableEffect: pre ? pre.controlDurableEffect : null, forbidden: (run?.report?.assertions || []).filter((a) => a.violated).map((a) => `${a.phase}:${a.id}`), reason: run?.reason ?? r?.reason ?? null };
  };
  const b = view(baseline); const p = view(patched);
  const findings = [];
  if (!b.completed || !p.completed) return { status: 'incomplete', thresholds: thresholds.version, baseline: b, patched: p, findings: ['one side did not complete; nothing is compared'] };
  if (b.controlRan && b.controlDurableEffect && !(p.controlRan && p.controlDurableEffect)) findings.push('authorized-workflow-regression: the control flow worked on the baseline and does not on the patch');
  const newForbidden = p.forbidden.filter((x) => !b.forbidden.includes(x));
  if (newForbidden.length) findings.push(`new-forbidden-outcome: ${newForbidden.join(', ')}`);
  const fixed = b.forbidden.filter((x) => !p.forbidden.includes(x));
  const fail = (findings.some((f) => f.startsWith('authorized')) && !thresholds.allowControlRegression) || (newForbidden.length > 0 && !thresholds.allowNewForbidden);
  return { status: fail ? 'fail' : 'pass', thresholds: thresholds.version, baseline: b, patched: p, fixedForbidden: fixed, findings, scope: 'the declared control and attack sequences only; empirical agreement on this workload is a bounded observation, not proof' };
}
