// Bounded portfolio scheduler: budgets, fairness and scoped cancellation (X-706).
//
// work-units.js gives durable, leased units but hands out the next pending unit in id order, with no notion of cost and no notion of
// who is waiting. This module decides WHICH unit is leased next, and whether ANY unit may be leased at all, from five limits declared
// at two levels (the whole portfolio, and each repository): wall time, provider spend, concurrency, request count and storage.
//
// ADMISSION (X-706.AC01). The check happens BEFORE the lease, inside the same locked store transaction that creates the lease, so two
// processes cannot both squeeze under a limit. A unit must carry an ESTIMATE of what it can cost (an unknown cost is never zero: a unit
// with no estimate is not leased, and is reported `no-estimate`). Admission counts what has been used, plus what in-flight attempts have
// RESERVED, plus this unit's estimate. A refusal is one of two kinds, and they are reported separately:
//   at-capacity  would fit once an in-flight attempt settles (a wait)
//   exhausted    would not fit even with nothing in flight (will not recover without a larger budget)
// An attempt that ends without a usage report (expired, failed, canceled) is charged its whole reservation, because what it spent is
// unknown. A reported overrun of the estimate is recorded and shrinks what remains; it is detected, not rolled back. Wall time is also
// enforced while the unit runs: the executor's signal aborts at the unit's wall estimate (capped by what the portfolio has left).
//
// FAIRNESS (X-706.AC02). Priority is a WEIGHT, not an order. Among repositories that currently have an admissible unit, the next lease
// goes to the one with the lowest `leasesGranted / weight` (weights are integers 1..8, default 1; ties break on repository name, and
// within a repository on unit id). Consequences, each tested:
//   - no starvation: a repository that is admissible is served within a bounded number of leases whatever the others hold, so a
//     repository with 300 units cannot hold back one with 1;
//   - priority shifts the SHARE, it never removes it: weight 8 against weight 1 is served about eight times as often, and the
//     weight-1 repository is still served;
//   - a repository that was blocked for a long time is owed service and is served first when it is admissible again (a bounded burst);
//   - a blocked repository (declared blocked, over its own budget, or with every unit blocked) is SKIPPED, never waited on. The skip
//     reason is returned per repository, so a stall is visible instead of silent.
// A unit whose estimate cannot fit the remaining budget is never leased and never blocks a smaller sibling.
//
// CANCELLATION (X-706.AC03). A cancellation names a scope (one unit, one repository, or everything) and is recorded in the ledger, so a
// process that did not receive the call still honours it. For attempts running in THIS process the scope's AbortController is aborted;
// work started through `ctx.spawn` runs under sandbox/supervise.js, which terminates the whole process tree and reports survivors. A
// lease is RELEASED only when the attempt has settled and nothing survived; otherwise it is left to EXPIRE (so no other worker can start
// the same unit while a descendant may still be running) and the report says so. Verified units and their receipts are never touched.
// The report is always `incomplete` with a reason when anything in scope was not verified.
//
// SPEND (routing). `routingBudgetFor` gives the routing policy the remaining dollars (portfolio and repository, less reservations), and
// `chargeModelSpend` refuses a routing decision that is blocked, has no upper cost bound, or would exceed the unit's reservation.
// No provider is called here; the executor does that through an injected transport.
//
// Heartbeats are recorded with the lease renewal. Nothing here reads a clock except where a function takes `clock`/`now`.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { superviseSpawn } from '../../sandbox/supervise.js';
import {
  leaseUnit, startUnit, completeUnit, failUnit, cancelUnits, recoverExpired, renewLease, mutateStore, readStore, progressOf, typedError,
} from './work-units.js';

export const LEDGER_SCHEMA = 'agentic-security/portfolio-ledger';
const LEDGER_VERSION = 1;
export const DIMENSIONS = Object.freeze(['wallMs', 'spendUsd', 'requests', 'storageBytes']);
export const WEIGHT_RANGE = Object.freeze({ min: 1, max: 8, default: 1 });
export const HEARTBEAT = Object.freeze({ intervalMs: 5000, staleAfterMs: 15000 });
export const SKIP_CODES = Object.freeze(['repository-blocked', 'no-estimate', 'at-capacity', 'exhausted', 'canceled']);
const MAX_LEDGER_BYTES = 16 * 1024 * 1024;

const zero = () => ({ wallMs: 0, spendUsd: 0, requests: 0, storageBytes: 0 });
const isNum = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;

// ---------------------------------------------------------------- budgets

/**
 * Budgets: `{ portfolio: { concurrency, wallMs, spendUsd, requests, storageBytes }, repositories?: { default?, [name]: partial limits },
 * priorities?: { [name]: weight } }`. Every portfolio limit is REQUIRED (an unlimited portfolio is a decision to make out loud, not a
 * default); a repository limit that is absent is not enforced for that repository and the view says so.
 */
export function validateBudgets(b) {
  const errors = [];
  const bad = (p, message) => errors.push({ code: 'BAD_BUDGETS', path: p, message });
  if (!b || typeof b !== 'object') return { ok: false, errors: [{ code: 'BAD_BUDGETS', path: '', message: 'not an object' }] };
  const lim = (o, p, required) => {
    if (!o || typeof o !== 'object') { if (required) bad(p, 'required'); return; }
    if (o.concurrency !== undefined && !(Number.isInteger(o.concurrency) && o.concurrency >= 1 && o.concurrency <= 64)) bad(`${p}.concurrency`, 'an integer in 1..64');
    else if (required && o.concurrency === undefined) bad(`${p}.concurrency`, 'required');
    for (const d of DIMENSIONS) {
      if (o[d] === undefined) { if (required) bad(`${p}.${d}`, 'required'); } else if (!isNum(o[d])) bad(`${p}.${d}`, 'a finite non-negative number');
    }
  };
  lim(b.portfolio, 'portfolio', true);
  for (const [name, o] of Object.entries(b.repositories ?? {})) lim(o, `repositories.${name}`, false);
  for (const [name, w] of Object.entries(b.priorities ?? {})) {
    if (!(Number.isInteger(w) && w >= WEIGHT_RANGE.min && w <= WEIGHT_RANGE.max)) bad(`priorities.${name}`, `an integer weight in ${WEIGHT_RANGE.min}..${WEIGHT_RANGE.max}`);
  }
  return { ok: errors.length === 0, errors };
}

const limitsFor = (budgets, repo) => ({ ...(budgets.repositories?.default ?? {}), ...(budgets.repositories?.[repo] ?? {}) });
const weightOf = (budgets, repo) => budgets.priorities?.[repo] ?? WEIGHT_RANGE.default;

// ---------------------------------------------------------------- ledger

export const ledgerPathFor = (storeFile) => `${storeFile}.ledger.json`;

export function newLedger() {
  return { schema: LEDGER_SCHEMA, version: LEDGER_VERSION, usage: { portfolio: zero(), repositories: {} }, reservations: {}, grants: {}, heartbeats: {}, cancellations: [], overruns: [], settled: {} };
}

export function readLedger(storeFile) {
  const file = ledgerPathFor(storeFile);
  let raw;
  try {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_LEDGER_BYTES) throw typedError('LEDGER_CORRUPT', 'ledger is not a regular file within the size limit');
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) { if (e.code === 'ENOENT') return newLedger(); throw e; }
  let l;
  try { l = JSON.parse(raw); } catch { throw typedError('LEDGER_CORRUPT', 'ledger is not valid JSON'); }
  if (!l || l.schema !== LEDGER_SCHEMA || l.version !== LEDGER_VERSION || typeof l.reservations !== 'object' || typeof l.usage !== 'object') throw typedError('LEDGER_CORRUPT', 'not a portfolio ledger of a supported version');
  return l;
}

function writeLedger(storeFile, ledger) {
  const file = ledgerPathFor(storeFile);
  const tmp = `${file}.tmp-${process.pid}`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(ledger), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

const repoUsage = (ledger, repo) => (ledger.usage.repositories[repo] ??= zero());
const add = (a, b) => { for (const d of DIMENSIONS) a[d] += b[d] ?? 0; };

/** Charge an attempt's reservation to usage and release it. `usage` null charges the whole reservation (what it spent is unknown). Idempotent. */
function settle(ledger, attemptId, usage, how) {
  const r = ledger.reservations[attemptId];
  if (!r) return null;
  const charge = {};
  const over = [];
  for (const d of DIMENSIONS) {
    charge[d] = usage && isNum(usage[d]) ? usage[d] : r[d];
    if (usage && isNum(usage[d]) && usage[d] > r[d]) over.push(d);
  }
  add(ledger.usage.portfolio, charge); add(repoUsage(ledger, r.repository), charge);
  if (over.length) ledger.overruns.push({ attemptId, unitId: r.unitId, repository: r.repository, dimensions: over });
  delete ledger.reservations[attemptId];
  delete ledger.heartbeats[attemptId];
  ledger.settled[attemptId] = how;
  return { charge, over };
}

const inScope = (unit, scope) => !!scope && (scope.all === true || (scope.unitId && scope.unitId === unit.id) || (scope.repository && scope.repository === unit.repository));

/** Settle reservations whose lease ended and cancel pending units inside a recorded cancellation scope. Returns what changed. */
function reconcile(store, ledger, now) {
  const recovered = recoverExpired(store, now);
  const settledNow = [];
  for (const [attemptId, r] of Object.entries(ledger.reservations)) {
    const u = store.units[r.unitId];
    if (!u || !u.lease || u.lease.attemptId !== attemptId) { settle(ledger, attemptId, null, 'lease-ended'); settledNow.push(attemptId); }
  }
  const canceled = [];
  for (const c of ledger.cancellations) {
    for (const u of Object.values(store.units)) {
      if ((u.state === 'pending' || u.state === 'blocked') && inScope(u, c.scope)) { cancelUnits(store, { unitId: u.id, reason: c.reason, now }); canceled.push(u.id); }
    }
  }
  return { recovered, settled: settledNow, canceled };
}

// ---------------------------------------------------------------- admission and selection

function checkLimits(limits, used, flight, flightCount, est, scope) {
  const out = [];
  if (Number.isInteger(limits.concurrency) && flightCount >= limits.concurrency) out.push({ code: 'at-capacity', scope, dimension: 'concurrency', limit: limits.concurrency, inFlight: flightCount });
  for (const d of DIMENSIONS) {
    if (!isNum(limits[d])) continue;
    if (used[d] + est[d] > limits[d]) out.push({ code: 'exhausted', scope, dimension: d, limit: limits[d], used: used[d], needed: est[d] });
    else if (used[d] + flight[d] + est[d] > limits[d]) out.push({ code: 'at-capacity', scope, dimension: d, limit: limits[d], used: used[d], reserved: flight[d], needed: est[d] });
  }
  return out;
}

function normalizeEstimate(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const e = {};
  for (const d of DIMENSIONS) { if (!isNum(raw[d])) return null; e[d] = raw[d]; }
  return e.wallMs > 0 ? e : null;
}

/** What each repository and the portfolio currently have reserved by in-flight attempts. */
function flightOf(ledger) {
  const portfolio = { ...zero(), count: 0 };
  const repos = {};
  for (const r of Object.values(ledger.reservations)) {
    const rr = (repos[r.repository] ??= { ...zero(), count: 0 });
    for (const d of DIMENSIONS) { portfolio[d] += r[d]; rr[d] += r[d]; }
    portfolio.count += 1; rr.count += 1;
  }
  return { portfolio, repos };
}

/**
 * Pure selection over a reconciled store and ledger: the unit that would be leased next, or why none can be.
 * @returns {{ unit: object|null, estimate: object|null, skipped: Array, idle: boolean, waiting: boolean }}
 */
export function selectUnit({ store, ledger, budgets, estimateOf, blockedRepositories = [] }) {
  const flight = flightOf(ledger);
  const pendingByRepo = new Map();
  for (const u of Object.values(store.units).sort((a, b) => (a.id < b.id ? -1 : 1))) {
    if (u.state === 'pending') { if (!pendingByRepo.has(u.repository)) pendingByRepo.set(u.repository, []); pendingByRepo.get(u.repository).push(u); }
  }
  const skipped = [];
  const blocked = new Set(blockedRepositories);
  const candidates = [];
  for (const [repo, units] of [...pendingByRepo].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (blocked.has(repo)) { skipped.push({ repository: repo, code: 'repository-blocked', detail: 'declared blocked; its units are skipped and independent repositories continue' }); continue; }
    const repoFlight = flight.repos[repo] ?? { ...zero(), count: 0 };
    const repoLimits = limitsFor(budgets, repo);
    let pick = null; const unitSkips = [];
    for (const u of units) {
      const est = normalizeEstimate(estimateOf(u));
      if (!est) { unitSkips.push({ repository: repo, unitId: u.id, code: 'no-estimate', detail: 'no cost estimate, and an unknown cost is never treated as zero' }); continue; }
      const refusals = [
        ...checkLimits(budgets.portfolio, ledger.usage.portfolio, flight.portfolio, flight.portfolio.count, est, 'portfolio'),
        ...checkLimits(repoLimits, repoUsage(ledger, repo), repoFlight, repoFlight.count, est, 'repository'),
      ];
      if (refusals.length) {
        const code = refusals.some((r) => r.code === 'exhausted') ? 'exhausted' : 'at-capacity';
        unitSkips.push({ repository: repo, unitId: u.id, code, detail: refusals.map((r) => `${r.scope} ${r.dimension}`).join(', '), refusals });
        continue;
      }
      pick = { unit: u, estimate: est };
      break;
    }
    skipped.push(...unitSkips.filter((s) => !pick || s.unitId !== pick.unit.id));
    if (pick) candidates.push({ repo, ...pick });
  }
  let chosen = null;
  for (const c of candidates) {
    const score = (ledger.grants[c.repo] ?? 0) / weightOf(budgets, c.repo);
    if (!chosen || score < chosen.score) chosen = { ...c, score };
  }
  const idle = pendingByRepo.size === 0;
  return { unit: chosen ? chosen.unit : null, estimate: chosen ? chosen.estimate : null, skipped, idle, waiting: !chosen && skipped.some((s) => s.code === 'at-capacity') };
}

/**
 * Admit and lease the next unit in ONE locked transaction. Returns `{ lease, ... }` or `{ lease: null, idle, waiting, skipped }`.
 * A repeat `requestId` from the same holder returns the existing lease and reserves nothing more.
 */
export function scheduleNext(file, { budgets, estimateOf, holder, now, ttlMs, requestId = null, blockedRepositories = [] }) {
  const bv = validateBudgets(budgets);
  if (!bv.ok) throw typedError('BAD_BUDGETS', `invalid budgets: ${bv.errors[0].path} ${bv.errors[0].message}`, { errors: bv.errors });
  return mutateStore(file, (store) => {
    const ledger = readLedger(file);
    const changed = reconcile(store, ledger, now);
    const finish = (out) => { writeLedger(file, ledger); return { ...out, reconciled: changed }; };
    if (requestId) {
      for (const u of Object.values(store.units)) {
        if (u.lease && u.lease.requestId === requestId && u.lease.holder === holder) {
          return finish({ lease: { unitId: u.id, attemptId: u.lease.attemptId, expiresAt: u.lease.expiresAt, repository: u.repository, duplicate: true }, idle: false, waiting: false, skipped: [] });
        }
      }
    }
    const sel = selectUnit({ store, ledger, budgets, estimateOf, blockedRepositories });
    if (!sel.unit) return finish({ lease: null, idle: sel.idle, waiting: sel.waiting, skipped: sel.skipped });
    const l = leaseUnit(store, { holder, now, ttlMs, unitId: sel.unit.id, requestId });
    ledger.reservations[l.attemptId] = { unitId: sel.unit.id, repository: sel.unit.repository, holder, at: now, ...sel.estimate, used: { spendUsd: 0, requests: 0 } };
    ledger.grants[sel.unit.repository] = (ledger.grants[sel.unit.repository] ?? 0) + 1;
    return finish({ lease: { ...l, repository: sel.unit.repository, reservation: sel.estimate }, idle: false, waiting: false, skipped: sel.skipped });
  });
}

/** Settle an attempt's reservation (idempotent). `usage` null charges the whole reservation. */
export function settleAttempt(file, { attemptId, usage = null, how = 'reported' }) {
  return mutateStore(file, () => {
    const ledger = readLedger(file);
    const r = settle(ledger, attemptId, usage, how);
    writeLedger(file, ledger);
    return r;
  });
}

/** Renew the lease and record a heartbeat in one transaction. */
export function heartbeat(file, { unitId, attemptId, now, ttlMs }) {
  return mutateStore(file, (store) => {
    const ledger = readLedger(file);
    const r = renewLease(store, { unitId, attemptId, now, ttlMs });
    if (r.ok) {
      const u = store.units[unitId];
      ledger.heartbeats[attemptId] = { holder: u.lease.holder, unitId, repository: u.repository, at: now };
      writeLedger(file, ledger);
    }
    return r;
  });
}

// ---------------------------------------------------------------- routing and spend

/** What the routing policy may spend for a task in `repository` right now: the smaller of the portfolio and repository remainders, less reservations. */
export function routingBudgetFor({ budgets, ledger, repository }) {
  const flight = flightOf(ledger);
  const left = (limit, used, reserved) => (isNum(limit) ? Math.max(0, limit - used - reserved) : Infinity);
  const p = left(budgets.portfolio.spendUsd, ledger.usage.portfolio.spendUsd, flight.portfolio.spendUsd);
  const r = left(limitsFor(budgets, repository).spendUsd, repoUsage(ledger, repository).spendUsd, (flight.repos[repository] ?? zero()).spendUsd);
  const remainingUsd = Math.min(p, r);
  return { remainingUsd: Number.isFinite(remainingUsd) ? remainingUsd : 0 };
}

/** The dollar upper bound of a routing decision, or null when the decision selects nothing or carries no bound. Unknown is never free. */
export function spendBoundOf(decision) {
  if (!decision || (decision.status !== 'routed' && decision.status !== 'fallback') || !decision.selected) return null;
  const c = decision.expectedBounds?.costUsd;
  const bound = Math.max(isNum(c?.upperBound) ? c.upperBound : 0, isNum(c?.measuredMedian) ? c.measuredMedian : 0);
  return bound > 0 ? bound : null;
}

/** Charge one model request (a routing decision) against the attempt's reservation. Refuses when blocked, unbounded or over the reservation. */
export function chargeModelSpend(file, { attemptId, decision }) {
  return mutateStore(file, () => {
    const ledger = readLedger(file);
    const r = ledger.reservations[attemptId];
    if (!r) return { ok: false, code: 'no-reservation', reason: 'this attempt holds no reservation (it ended, or was never admitted)' };
    const bound = spendBoundOf(decision);
    if (bound === null) return { ok: false, code: 'no-spend-bound', reason: 'the routing decision selects nothing or carries no cost bound; an unknown cost is not charged as zero and the request is not made' };
    if (r.used.requests + 1 > r.requests) return { ok: false, code: 'request-limit', reason: `the unit reserved ${r.requests} request(s)` };
    if (r.used.spendUsd + bound > r.spendUsd) return { ok: false, code: 'unit-spend-exceeded', reason: `needs up to ${bound} against ${r.spendUsd - r.used.spendUsd} remaining in the unit's reservation` };
    r.used.spendUsd += bound; r.used.requests += 1;
    writeLedger(file, ledger);
    return { ok: true, charged: bound };
  });
}

// ---------------------------------------------------------------- cancellation

/** Tracks the attempts running in this process so a scope can be cancelled. */
export function createCancelScope() {
  const running = new Map();
  return {
    running,
    register(attemptId, entry) { running.set(attemptId, entry); },
    unregister(attemptId) { running.delete(attemptId); },
    /**
     * Cancel everything in `scope` ({ unitId } | { repository } | { all: true }).
     * @returns {Promise<object>} an `incomplete` report with the reason, what was released and what is left to expire
     */
    async cancel({ file, scope, reason, now, waitMs = 5000 }) {
      if (!scope || !(scope.all === true || scope.unitId || scope.repository)) throw typedError('BAD_SCOPE', 'a cancellation needs a scope: unitId, repository or all');
      const why = String(reason ?? 'canceled').slice(0, 300);
      mutateStore(file, (store) => {
        const ledger = readLedger(file);
        ledger.cancellations.push({ scope: { ...scope }, reason: why, at: now });
        reconcile(store, ledger, now);
        writeLedger(file, ledger);
      });
      const mine = [...running.entries()].filter(([, e]) => inScope({ id: e.unitId, repository: e.repository }, scope));
      for (const [, e] of mine) e.controller.abort(Object.assign(new Error(why), { code: 'CANCELED' }));
      await Promise.race([Promise.all(mine.map(([, e]) => e.settled)), new Promise((r) => setTimeout(r, waitMs))]);
      return mutateStore(file, (store) => {
        const ledger = readLedger(file);
        const report = { status: 'nothing-to-cancel', incomplete: false, reason: why, scope: { ...scope }, canceled: [], leasesReleased: [], leasesLeftToExpire: [], verifiedPreserved: [], survivors: [] };
        for (const id of Object.keys(store.units).sort()) {
          const u = store.units[id];
          if (!inScope(u, scope)) continue;
          if (u.state === 'verified') { report.verifiedPreserved.push(id); continue; }
          if (u.state === 'leased' || u.state === 'running') {
            const attemptId = u.lease.attemptId;
            const e = running.get(attemptId) ?? mine.find(([a]) => a === attemptId)?.[1];
            if (e && e.finished === true && e.survivors.length === 0) {
              cancelUnits(store, { unitId: id, reason: why, now });
              settle(ledger, attemptId, null, 'canceled');
              report.leasesReleased.push(id); report.canceled.push(id);
            } else {
              report.leasesLeftToExpire.push({ unitId: id, attemptId, expiresAt: u.lease.expiresAt, why: e ? (e.survivors.length ? 'a descendant survived termination' : 'the attempt did not settle in time') : 'the attempt runs in another process' });
              if (e?.survivors.length) report.survivors.push({ unitId: id, pids: e.survivors });
            }
          } else if (u.state === 'canceled') report.canceled.push(id);
        }
        if (report.canceled.length || report.leasesLeftToExpire.length) { report.status = 'incomplete'; report.incomplete = true; }
        writeLedger(file, ledger);
        return report;
      });
    },
  };
}

// ---------------------------------------------------------------- the driver

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Drive a store with budgets. `executor(unit, ctx)` returns `{ resultDigest, dependencies, usage? }` where `usage` may report
 * `{ spendUsd, requests, storageBytes }` (wall time is measured). `ctx` carries `attemptId`, `signal`, `heartbeat()`, `reservation`,
 * `spawn(bin, args, opts)` (supervised: the process tree ends with the attempt) and `requestModel(decision)` (charges the routing decision).
 *
 * With `backend`, the backend is probed before every lease; an unavailable one stops the run with `stopped: 'blocked'` and the typed probe
 * result in `blocked`. @returns {Promise<{ progress: object|null, stopped: string, order: string[], skipped: Array, blocked?: object }>}
 */
export async function runScheduled({
  file, budgets, estimateOf, executor, holder = 'worker', clock = () => Date.now(), ttlMs, maxLeases = Infinity, cancelScope = null,
  blockedRepositories = [], heartbeatMs = HEARTBEAT.intervalMs, pollMs = 25, maxWaitMs = 2000, workers = null, backend = null,
}) {
  const bv = validateBudgets(budgets);
  if (!bv.ok) throw typedError('BAD_BUDGETS', `invalid budgets: ${bv.errors[0].path} ${bv.errors[0].message}`, { errors: bv.errors });
  const order = [];
  let leased = 0; let stopped = 'drained'; let lastSkipped = []; let blocked = null;
  const limit = Math.max(1, Math.min(workers ?? budgets.portfolio.concurrency, 16));
  let inFlight = 0;

  async function worker(n) {
    let waited = 0;
    for (;;) {
      if (leased >= maxLeases) { stopped = 'max-leases'; return; }
      // a shared backend that went away stops the run: nothing is written anywhere else instead (X-708.AC03)
      if (backend) { const p = backend.probe(); if (!p.ok) { stopped = 'blocked'; blocked = p; return; } }
      let r;
      try { r = scheduleNext(file, { budgets, estimateOf, holder: `${holder}-${n}`, now: clock(), ttlMs, blockedRepositories }); } catch (e) {
        if (backend && !backend.probe().ok) { stopped = 'blocked'; blocked = backend.probe(); return; }
        throw e;
      }
      lastSkipped = r.skipped;
      if (!r.lease) {
        if (r.idle) return;
        if (r.waiting) {
          if (inFlight === 0 && waited >= maxWaitMs) { stopped = 'waiting-timeout'; return; }
          await sleep(pollMs); waited += pollMs; continue;
        }
        stopped = 'nothing-schedulable'; return;
      }
      waited = 0;
      leased += 1; inFlight += 1;
      order.push(r.lease.unitId);
      try { await runOne(r.lease); } catch (e) {
        // the attempt could not record its outcome because the backend is gone: its lease is left to expire, never re-homed
        if (backend && !backend.probe().ok) { stopped = 'blocked'; blocked = backend.probe(); return; }
        throw e;
      } finally { inFlight -= 1; }
    }
  }

  async function runOne(lease) {
    const { unitId, attemptId } = lease;
    const controller = new AbortController();
    const entry = { unitId, repository: lease.repository, controller, finished: false, survivors: [], terminations: [], settled: null };
    let resolveSettled; entry.settled = new Promise((r) => { resolveSettled = r; });
    cancelScope?.register(attemptId, entry);
    const startedAt = clock();
    let timer = null; let beat = null;
    try {
      mutateStore(file, (s) => startUnit(s, { unitId, attemptId, now: clock() }));
      const unit = readStore(file).units[unitId];
      const wallCap = lease.reservation.wallMs;
      timer = setTimeout(() => controller.abort(Object.assign(new Error('wall-time budget for the unit was reached'), { code: 'WALL_TIMEOUT' })), wallCap);
      const doBeat = () => { try { heartbeat(file, { unitId, attemptId, now: clock(), ttlMs }); } catch { /* the lease is gone; the result will be refused */ } };
      beat = setInterval(doBeat, heartbeatMs); doBeat();
      const ctx = {
        attemptId, signal: controller.signal, reservation: lease.reservation, heartbeat: doBeat,
        async spawn(bin, args, opts = {}) {
          const r = await superviseSpawn(bin, args, { ...opts, signal: controller.signal });
          entry.terminations.push(r.termination);
          if (r.termination?.survivors?.length) entry.survivors.push(...r.termination.survivors);
          return r;
        },
        requestModel: (decision) => chargeModelSpend(file, { attemptId, decision }),
      };
      let res = null; let err = null;
      try { res = await executor(unit, ctx); } catch (e) { err = e; }
      clearTimeout(timer); clearInterval(beat);
      const canceled = controller.signal.aborted && controller.signal.reason?.code === 'CANCELED';
      if (canceled) return; // cancel() performs the store transition once this attempt has settled
      const timedOut = controller.signal.aborted && controller.signal.reason?.code === 'WALL_TIMEOUT';
      const spent = mutateStore(file, (s) => {
        const ledger = readLedger(file);
        const tracked = ledger.reservations[attemptId]?.used ?? { spendUsd: 0, requests: 0 };
        const failed = err || !res || timedOut;
        // a failed attempt spent an unknown amount: it is charged its reservation; a reported success is charged what it reported
        const usage = failed ? null : { wallMs: Math.max(1, clock() - startedAt), spendUsd: tracked.spendUsd, requests: tracked.requests, ...(res.usage ?? {}) };
        settle(ledger, attemptId, usage, failed ? 'failed' : 'reported');
        writeLedger(file, ledger);
        if (failed) failUnit(s, { unitId, attemptId, reason: timedOut ? 'wall-time budget reached' : err ? err.message : 'executor returned nothing', now: clock() });
        else completeUnit(s, { unitId, attemptId, resultDigest: res.resultDigest, dependencies: res.dependencies, now: clock() });
        return true;
      });
      void spent;
    } finally {
      clearTimeout(timer); clearInterval(beat);
      entry.finished = true;
      resolveSettled();
      cancelScope?.unregister(attemptId);
    }
  }

  await Promise.all(Array.from({ length: limit }, (_, i) => worker(i)));
  let progress = null;
  try { progress = progressOf(readStore(file)); } catch (e) { if (!blocked) throw e; }
  return { progress, stopped, order, skipped: lastSkipped, ...(blocked ? { blocked } : {}) };
}

