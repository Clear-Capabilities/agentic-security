// Coverage-aware portfolio progress and review views (X-707).
//
// ONE projection for every surface, in the pattern of lineage/deployment/projection.js: the CLI (`agentic-security portfolio progress`),
// the MCP tool (`portfolio_progress`) and the fleet summary all call `buildProgressView`, so none formats its own progress text and the
// surfaces cannot disagree. It is a VIEW: it reads a verified store and ledger and invents nothing.
//
// What it keeps apart (X-707.AC01), because adding them together is how a portfolio looks finished when it is not:
//   verified    units whose result is current and complete. The only count that is progress.
//   problems    blocked, failed, canceled and stale units, each listed with its reason. A stale unit is one whose earlier result was
//               invalidated by a changed input; it is pending again and its old result does not count.
//   coverage    per repository, how many of its units are verified, and whether the repository is fully verified, partial or not started.
//   budget      per limit: the limit (or `null` when none is enforced), what is used, what in-flight attempts hold, what remains.
//   review      what a human still has to look at: blocked units, contracts awaiting approval, boundaries that could not be resolved.
//
// Aggregate findings (X-707.AC02) deduplicate by STABLE IDENTITY only. Two findings with the same `stableId` are one aggregate finding
// with every occurrence kept (repository, environment, release, commit, file, line, severity). The affected releases are listed
// separately, per finding and per release. A finding with no stable id is never merged by guesswork: it stays its own row, listed apart.
//
// Liveness (X-707.AC03). A worker's last sign of life is the newest of its heartbeat and its lease events. Beyond the declared
// `HEARTBEAT.staleAfterMs` it is `stale` and stays in the view with its age: a stale worker is never dropped from the report to make it
// look healthier, and its output is irrelevant (nothing here reads stdout). A controller that has finished is reported as FINISHED, which
// is not the same as every unit verified, which is not the same as every repository passing; the view says each separately and never
// states that the portfolio passed.
//
// Strings from the store (failure reasons) are checked for secret shapes before they are shown. Pure given its inputs: no clock (`now`
// is an argument), no randomness, fixed key order.

import { featureStatus } from '../assurance/config.js';
import { findSecret } from './bundle.js';
import { NOT_A_GUARANTEE, FEATURE_ID } from './wording.js';
import { DIMENSIONS, HEARTBEAT } from './scheduler.js';
import { UNIT_STATES } from './work-units.js';

export const PROGRESS_SCHEMA = 'agentic-security/portfolio-progress';
export const PROGRESS_VERSION = '1.0.0';
export const FINDINGS_SCHEMA = 'agentic-security/portfolio-findings';
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const MAX_STRING = 300;
const MAX_LIST = 200;

const safe = (s) => {
  const t = String(s ?? '').slice(0, MAX_STRING);
  return findSecret(t) ? '[withheld: secret-shaped text]' : t;
};
const byKey = (k) => (a, b) => (a[k] < b[k] ? -1 : a[k] > b[k] ? 1 : 0);
const cap = (list) => ({ items: list.slice(0, MAX_LIST), truncated: list.length > MAX_LIST, total: list.length });

// ---------------------------------------------------------------- aggregate findings (X-707.AC02)

/**
 * @param {Array<{ repository: string, environment?: string, release?: string, commit?: string, evidenceRef?: string, finding: object }>} entries
 *   each occurrence of a finding in one repository/environment/release
 */
export function aggregateFindings(entries, { blockingSeverity = 'high' } = {}) {
  const rank = (s) => SEVERITY_RANK[s] ?? -1;
  const groups = new Map();
  const unidentified = [];
  let occurrences = 0;
  for (const e of Array.isArray(entries) ? entries : []) {
    const f = e?.finding;
    if (!e || typeof e.repository !== 'string' || !f || typeof f !== 'object') continue;
    occurrences += 1;
    const occ = {
      repository: e.repository, environment: e.environment ?? null, release: e.release ?? null, commit: e.commit ?? null,
      file: typeof f.file === 'string' ? f.file : null, line: Number.isInteger(f.line) ? f.line : null, severity: f.severity ?? null, evidenceRef: e.evidenceRef ?? null,
    };
    if (typeof f.stableId !== 'string' || !f.stableId) { unidentified.push({ ...occ, vuln: safe(f.vuln), cwe: f.cwe ?? null, note: 'no stable id: not merged with any other finding' }); continue; }
    if (!groups.has(f.stableId)) groups.set(f.stableId, { identity: f.stableId, vuln: safe(f.vuln), cwe: f.cwe ?? null, family: f.family ?? null, occurrences: [] });
    groups.get(f.stableId).occurrences.push(occ);
  }
  const items = [...groups.values()].sort(byKey('identity')).map((g) => {
    g.occurrences.sort((a, b) => `${a.repository}|${a.environment}|${a.release}|${a.file}|${a.line}`.localeCompare(`${b.repository}|${b.environment}|${b.release}|${b.file}|${b.line}`));
    const sev = g.occurrences.reduce((m, o) => (rank(o.severity) > rank(m) ? o.severity : m), null);
    const uniq = (k) => [...new Set(g.occurrences.map((o) => o[k]).filter((v) => v !== null))].sort();
    return { ...g, severity: sev, severities: uniq('severity'), repositories: uniq('repository'), environments: uniq('environment'), affectedReleases: uniq('release'), occurrenceCount: g.occurrences.length };
  });
  const byRelease = {};
  for (const it of items) for (const r of it.affectedReleases) (byRelease[r] ??= []).push(it.identity);
  const bySeverity = {};
  for (const it of items) bySeverity[it.severity ?? 'unknown'] = (bySeverity[it.severity ?? 'unknown'] ?? 0) + 1;
  const blockingRepos = new Set();
  for (const it of items) for (const o of it.occurrences) if (rank(o.severity) >= rank(blockingSeverity)) blockingRepos.add(o.repository);
  for (const o of unidentified) if (rank(o.severity) >= rank(blockingSeverity)) blockingRepos.add(o.repository);
  return {
    schema: FINDINGS_SCHEMA, schemaVersion: PROGRESS_VERSION, occurrences, unique: items.length, blockingSeverity,
    items, unidentified: unidentified.sort((a, b) => `${a.repository}|${a.file}|${a.line}`.localeCompare(`${b.repository}|${b.file}|${b.line}`)),
    byRelease: Object.fromEntries(Object.keys(byRelease).sort().map((k) => [k, byRelease[k].sort()])),
    bySeverity: Object.fromEntries(Object.keys(bySeverity).sort().map((k) => [k, bySeverity[k]])),
    repositoriesWithBlockingFindings: [...blockingRepos].sort(),
  };
}

// ---------------------------------------------------------------- review queue sources

/** Review items from a business coverage report (posture/invariants/coverage.js): contracts that are not approved. */
export function reviewItemsFromInvariantCoverage(coverage) {
  const out = [];
  for (const i of coverage?.invariants ?? []) {
    if (i.state !== 'approved') out.push({ kind: 'contract-approval', id: i.id ?? i.key, repository: null, reason: `contract '${safe(i.key)}' is ${safe(i.state)}: a violation of it is advisory until a reviewer approves it`, source: 'invariant-coverage' });
  }
  return out;
}

/** Review items from boundary contexts (lineage/deployment/projection.js): findings whose deployment exposure is unresolved or unbound. */
export function reviewItemsFromBoundaryContexts(contexts) {
  const out = [];
  for (const c of Array.isArray(contexts) ? contexts : []) {
    if (!c || typeof c !== 'object') continue;
    const unresolved = c.exposure?.state === 'unresolved';
    const unbound = c.binding && c.binding.status !== 'bound';
    if (unresolved || unbound) out.push({ kind: 'boundary-resolution', id: c.id ?? null, repository: c.finding?.repository ?? null, reason: unresolved ? 'deployment reachability is unresolved: a person must decide whether the path is real' : 'the finding is not bound to a deployed service', source: 'deployment-boundaries' });
  }
  return out;
}

// ---------------------------------------------------------------- the view

const lastSignal = (u, ledger) => {
  const attemptId = u.lease?.attemptId;
  let at = 0;
  for (const e of u.events) if (e.attemptId === attemptId && typeof e.at === 'number' && e.at > at) at = e.at;
  const hb = attemptId ? ledger.heartbeats?.[attemptId]?.at : null;
  return Math.max(at, typeof hb === 'number' ? hb : 0);
};

/**
 * @param {object} p
 * @param {object} p.store      a verified portfolio store
 * @param {object} [p.ledger]   the scheduler ledger (usage, reservations, heartbeats, cancellations)
 * @param {object} [p.budgets]  the budgets the scheduler runs under
 * @param {number} p.now        milliseconds
 * @param {Array}  [p.reviewItems]
 * @param {Array}  [p.findings] occurrences for `aggregateFindings`
 * @param {string} [p.blockingSeverity]
 * @param {{ intervalMs: number, staleAfterMs: number }} [p.heartbeat]
 */
export function buildProgressView({ store, ledger = null, budgets = null, now, reviewItems = [], findings = null, blockingSeverity = 'high', heartbeat = HEARTBEAT } = {}) {
  if (!store || typeof store.units !== 'object') return { ok: false, errors: [{ code: 'NO_STORE', message: 'a verified portfolio store is required' }] };
  if (!Number.isFinite(now)) return { ok: false, errors: [{ code: 'NO_NOW', message: 'now (milliseconds) is required; the view reads no clock' }] };
  const led = ledger ?? { usage: { portfolio: {}, repositories: {} }, reservations: {}, heartbeats: {}, cancellations: [], overruns: [] };
  const units = Object.values(store.units).sort(byKey('id'));
  const ref = (u) => ({ unitId: u.id, repository: u.repository, taskType: u.taskType });

  const count = Object.fromEntries(UNIT_STATES.map((s) => [s, 0]));
  for (const u of units) count[u.state] += 1;
  const lastEvent = (u, type) => [...u.events].reverse().find((e) => e.type === type);
  const blocked = units.filter((u) => u.state === 'blocked').map((u) => ({ ...ref(u), reason: safe(u.blockedReason) }));
  const failed = units.filter((u) => u.state === 'failed').map((u) => ({ ...ref(u), retryCount: u.retryCount, reason: safe(lastEvent(u, 'failed')?.reason ?? (lastEvent(u, 'expired') ? 'lease expired' : 'failed')) }));
  const canceled = units.filter((u) => u.state === 'canceled').map((u) => ({ ...ref(u), reason: safe(lastEvent(u, 'canceled')?.reason) }));
  const stale = units.filter((u) => u.stale.length && u.state !== 'verified').map((u) => ({ ...ref(u), state: u.state, staleResults: u.stale.length, reason: 'an earlier result was invalidated by a changed input and does not count', changedDimensions: u.stale.at(-1)?.changedDimensions ?? null }));

  // workers: every lease holder, live or stale
  const workers = units.filter((u) => u.state === 'leased' || u.state === 'running').map((u) => {
    const last = lastSignal(u, led);
    const age = Math.max(0, now - last);
    return { ...ref(u), holder: u.lease.holder, attemptId: u.lease.attemptId, state: u.state, lastSignalAt: last || null, ageMs: age, status: !last ? 'no-heartbeat' : age > heartbeat.staleAfterMs ? 'stale' : 'live', leaseExpiresAt: u.lease.expiresAt };
  }).sort(byKey('attemptId'));

  // coverage by repository
  const repos = new Map();
  for (const u of units) {
    if (!repos.has(u.repository)) repos.set(u.repository, { repository: u.repository, commit: u.commit, units: 0, verified: 0, problems: 0, inFlight: 0, pending: 0 });
    const r = repos.get(u.repository);
    r.units += 1;
    if (u.state === 'verified') r.verified += 1;
    else if (u.state === 'blocked' || u.state === 'failed' || u.state === 'canceled') r.problems += 1;
    else if (u.state === 'leased' || u.state === 'running') r.inFlight += 1;
    else r.pending += 1;
  }
  const coverageRepos = [...repos.values()].sort(byKey('repository')).map((r) => ({ ...r, status: r.verified === r.units ? 'fully-verified' : r.verified > 0 ? 'partial' : r.problems > 0 ? 'incomplete' : 'not-started' }));
  const fully = coverageRepos.filter((r) => r.status === 'fully-verified').length;

  // budget
  const reserved = { portfolio: {}, repositories: {} };
  for (const r of Object.values(led.reservations ?? {})) {
    reserved.portfolio.count = (reserved.portfolio.count ?? 0) + 1;
    for (const d of DIMENSIONS) reserved.portfolio[d] = (reserved.portfolio[d] ?? 0) + r[d];
    reserved.repositories[r.repository] ??= { count: 0 };
    reserved.repositories[r.repository].count += 1;
    for (const d of DIMENSIONS) reserved.repositories[r.repository][d] = (reserved.repositories[r.repository][d] ?? 0) + r[d];
  }
  const dimView = (limits, used, held) => {
    const o = {};
    for (const d of [...DIMENSIONS, 'concurrency']) {
      const limit = Number.isFinite(limits?.[d]) ? limits[d] : null;
      const u = d === 'concurrency' ? (held?.count ?? 0) : (used?.[d] ?? 0);
      const h = d === 'concurrency' ? 0 : (held?.[d] ?? 0);
      o[d] = { limit, used: u, reserved: h, remaining: limit === null ? null : Math.max(0, limit - u - h), enforced: limit !== null };
    }
    return o;
  };
  const repoLimits = (name) => ({ ...(budgets?.repositories?.default ?? {}), ...(budgets?.repositories?.[name] ?? {}) });
  const budget = {
    declared: !!budgets,
    portfolio: dimView(budgets?.portfolio, led.usage?.portfolio, reserved.portfolio),
    repositories: Object.fromEntries(coverageRepos.map((r) => [r.repository, dimView(repoLimits(r.repository), led.usage?.repositories?.[r.repository], reserved.repositories[r.repository])])),
    overruns: (led.overruns ?? []).length,
  };

  // review queue
  const review = [
    ...blocked.map((b) => ({ kind: 'blocked-unit', id: b.unitId, repository: b.repository, reason: b.reason, source: 'portfolio' })),
    ...(Array.isArray(reviewItems) ? reviewItems : []).map((i) => ({ kind: String(i.kind ?? 'review'), id: i.id ?? null, repository: i.repository ?? null, reason: safe(i.reason), source: String(i.source ?? 'supplied') })),
  ];
  const reviewByKind = {};
  for (const r of review) reviewByKind[r.kind] = (reviewByKind[r.kind] ?? 0) + 1;

  const aggregate = Array.isArray(findings) ? aggregateFindings(findings, { blockingSeverity }) : null;
  const inFlight = count.leased + count.running;
  const total = units.length;
  const controllerFinished = inFlight === 0 && count.pending === 0;
  const allVerified = total > 0 && count.verified === total;
  const nonVerified = total - count.verified;
  const completion = {
    controllerFinished,
    allUnitsVerified: allVerified,
    repositoriesFullyVerified: { n: fully, of: coverageRepos.length },
    findingsSupplied: aggregate !== null,
    repositoriesWithBlockingFindings: aggregate ? aggregate.repositoriesWithBlockingFindings : null,
    passAssessment: 'not-implied',
    statement: controllerFinished && !allVerified
      ? `The controller has finished, but ${nonVerified} of ${total} unit(s) are not verified (${count.blocked} blocked, ${count.failed} failed, ${count.canceled} canceled${count.pending ? `, ${count.pending} pending` : ''}). Finished does not mean every repository was checked, and it does not mean any repository passed.`
      : controllerFinished && allVerified
        ? `Every planned unit is verified (${total} of ${total}) in ${fully} of ${coverageRepos.length} repositories. That means the planned checks completed; it does not mean every repository passed${aggregate ? `: ${aggregate.repositoriesWithBlockingFindings.length} repositor${aggregate.repositoriesWithBlockingFindings.length === 1 ? 'y has' : 'ies have'} ${blockingSeverity}-or-worse findings in the supplied results` : ' (findings were not supplied to this view)'}.`
        : `The controller has not finished: ${count.verified} of ${total} unit(s) verified, ${inFlight} in flight, ${count.pending} pending.`,
  };

  const staleWorkers = workers.filter((w) => w.status !== 'live');
  const lines = [
    `Portfolio progress (${store.synthetic ? 'SYNTHETIC; ' : ''}as of ${now}): ${count.verified}/${total} unit(s) verified; ${fully}/${coverageRepos.length} repositor${coverageRepos.length === 1 ? 'y' : 'ies'} fully verified`,
    `  Not verified: ${count.blocked} blocked, ${count.failed} failed, ${count.canceled} canceled, ${stale.length} stale, ${count.pending} pending, ${inFlight} in flight`,
    `  Workers: ${workers.length - staleWorkers.length} live, ${staleWorkers.length} stale or silent (stale after ${heartbeat.staleAfterMs} ms without a heartbeat)`,
    `  Budget: ${budgets ? DIMENSIONS.filter((d) => budget.portfolio[d].enforced).map((d) => `${d} ${budget.portfolio[d].remaining} left`).join(', ') || 'no portfolio limit enforced' : 'not declared to this view'}`,
    `  Pending human review: ${review.length}${review.length ? ` (${Object.keys(reviewByKind).sort().map((k) => `${k}: ${reviewByKind[k]}`).join(', ')})` : ''}`,
    `  ${completion.statement}`,
    `  ${NOT_A_GUARANTEE}`,
  ];
  return {
    ok: true,
    view: {
      schema: PROGRESS_SCHEMA, schemaVersion: PROGRESS_VERSION, ...(store.synthetic ? { synthetic: true } : {}), planId: store.planId, asOf: now,
      heartbeat: { intervalMs: heartbeat.intervalMs, staleAfterMs: heartbeat.staleAfterMs },
      units: { total, verified: count.verified, pending: count.pending, inFlight, blocked: cap(blocked), failed: cap(failed), canceled: cap(canceled), stale: cap(stale), counts: count },
      workers: { items: workers, stale: staleWorkers.length, live: workers.length - staleWorkers.length },
      coverage: { repositories: coverageRepos, fullyVerified: fully, total: coverageRepos.length },
      budget,
      review: { pending: review.length, byKind: Object.fromEntries(Object.keys(reviewByKind).sort().map((k) => [k, reviewByKind[k]])), ...cap(review) },
      cancellations: (led.cancellations ?? []).map((c) => ({ scope: c.scope, reason: safe(c.reason), at: c.at })),
      findings: aggregate,
      completion,
      lines,
    },
  };
}

/** The additive field a surface asks for: `{ portfolioProgress }`, or `{}` when the feature is off, so flag-off output is unchanged. */
export function portfolioProgressFields({ config, ...input } = {}) {
  if (!config || featureStatus(config, FEATURE_ID).status !== 'ok') return {};
  const r = buildProgressView(input);
  return r.ok ? { portfolioProgress: r.view } : { portfolioProgressErrors: r.errors };
}

/** Attach the view to a fleet rollup. Flag off: the SAME object comes back untouched. */
export function attachPortfolioProgress(rollup, input) {
  const extra = portfolioProgressFields(input);
  return Object.keys(extra).length ? { ...rollup, ...extra } : rollup;
}
