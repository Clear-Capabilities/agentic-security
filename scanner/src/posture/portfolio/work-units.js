// Durable, leased portfolio work units (X-704).
//
// fleet.js already gives a many-repository run isolation, bounded concurrency and a per-repository completed marker. What it cannot do
// is say WHICH unit of work was in flight when a process died, hand that unit to another worker without doing it twice, or refuse to
// count a half-finished attempt as progress. This module adds that, in the same local-first shape: one JSON file, written atomically,
// no server, no network.
//
//   PLAN      `planPortfolio` decomposes the AUTHORIZED repositories into units, one per (repository, exact commit, task type). A unit id
//             is a hash of those three and its required inputs, so the same plan always yields the same ids (X-704.AC01); a repository
//             that is not on the authorization list is excluded and disclosed, never silently planned.
//   STATES    pending, leased, running, verified, blocked, failed, canceled. A lease has an expiry; an expired lease is recovered into
//             pending (or failed once retries are spent). Every transition appends an event to the unit's attempt chain; the chain is
//             hash-linked, so an attempt record can be read and verified but not rewritten (X-704.AC02).
//   PROGRESS  only a unit in `verified` with a recorded result counts. A leased or running unit, a failed attempt, an expired lease and a
//             duplicate delivery of a completion all leave the count where it was (X-704.AC03).
//
// Operations are idempotent by attempt id: delivering the same `complete` twice records one verification; delivering a completion for a
// stale attempt (the lease expired and the unit moved on) is refused, because a zombie worker's result must not displace its successor's.
//
// The clock is an argument everywhere (`now`, milliseconds), so recovery is testable without sleeping and nothing here reads a clock.
// Persistence is `mutateStore`: an exclusive lock file, read, verify, change, write to a temporary file, rename. A store that fails
// verification is an error, never silently reset to empty.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { canonicalJson } from '../evidence-bundle.js';
import { digestOf } from '../assurance/identity.js';
import { isCommit } from '../assurance/schema-kit.js';

const STORE_SCHEMA = 'agentic-security/portfolio-store';
const PLAN_SCHEMA = 'agentic-security/portfolio-plan';
const STORE_VERSION = 1;
export const UNIT_STATES = Object.freeze(['pending', 'leased', 'running', 'verified', 'blocked', 'failed', 'canceled']);
const TASK_TYPES = Object.freeze(['sast-scan', 'sca-reachability', 'boundary-graph', 'invariant-scenarios', 'verification-replay', 'attestation']);
export const DEPENDENCY_DIMENSIONS = Object.freeze(['code', 'policy', 'graph', 'invariant', 'oracle', 'toolchain']);

export const PORTFOLIO_LIMITS = Object.freeze({
  maxUnits: 5000, maxEventsPerUnit: 400, maxStoreBytes: 32 * 1024 * 1024, defaultLeaseMs: 5 * 60_000, maxLeaseMs: 6 * 60 * 60_000, defaultMaxRetries: 2, maxRetries: 10,
  lockStaleMs: 30_000, lockWaitMs: 2000,
});

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

// ---------------------------------------------------------------- plan

const unitIdOf = (u) => `wu:${crypto.createHash('sha256').update(canonicalJson({ repository: u.repository, commit: u.commit, taskType: u.taskType, requiredInputs: u.requiredInputs })).digest('hex').slice(0, 16)}`;

/**
 * Decompose authorized repositories into stable work units.
 *
 * @param {object} a
 * @param {Array<{name:string, commit:string}>} a.repositories   candidates, each pinned to an exact commit
 * @param {string[]} a.authorized       the repository names the operator has authorized; anything else is excluded and disclosed
 * @param {string[]} a.taskTypes        task types to run per repository (from TASK_TYPES)
 * @param {Object<string,string[]>} [a.requiredInputs]  per task type, the named inputs the unit needs (e.g. ['source','policy'])
 */
export function planPortfolio({ repositories = [], authorized = [], taskTypes = [], requiredInputs = {}, synthetic = false } = {}) {
  const errors = [];
  const rejected = [];
  const allow = new Set(authorized);
  for (const t of taskTypes) if (!TASK_TYPES.includes(t)) errors.push({ code: 'UNKNOWN_TASK_TYPE', message: `'${t}' is not a task type` });
  if (taskTypes.length === 0) errors.push({ code: 'NO_TASKS', message: 'a plan needs at least one task type' });
  const seen = new Set();
  const units = [];
  for (const r of repositories) {
    if (!r || typeof r.name !== 'string' || !r.name) { errors.push({ code: 'BAD_REPOSITORY', message: 'repository needs a name' }); continue; }
    if (!allow.has(r.name)) { rejected.push({ repository: r.name, reason: 'not-authorized' }); continue; }
    if (!isCommit(r.commit)) { errors.push({ code: 'UNBOUND_REVISION', message: `repository '${r.name}' is not pinned to an exact commit` }); continue; }
    if (seen.has(r.name)) { errors.push({ code: 'DUPLICATE_REPOSITORY', message: `repository '${r.name}' is listed twice` }); continue; }
    seen.add(r.name);
    for (const taskType of taskTypes) {
      const inputs = [...new Set(requiredInputs[taskType] ?? [])].sort();
      const u = { repository: r.name, commit: r.commit, taskType, requiredInputs: inputs };
      units.push({ id: unitIdOf(u), ...u });
    }
  }
  if (units.length > PORTFOLIO_LIMITS.maxUnits) errors.push({ code: 'TOO_MANY_UNITS', message: `plan has ${units.length} units; the limit is ${PORTFOLIO_LIMITS.maxUnits}` });
  units.sort((a, b) => (a.id < b.id ? -1 : 1));
  const body = { schema: PLAN_SCHEMA, schemaVersion: '1.0.0', ...(synthetic ? { synthetic: true } : {}), units, rejected: rejected.sort((a, b) => (a.repository < b.repository ? -1 : 1)) };
  return { ok: errors.length === 0, errors, plan: errors.length === 0 ? { ...body, id: `pplan:${digestOf(units).slice(7, 23)}` } : null };
}

// ---------------------------------------------------------------- state

const eventDigest = (e) => digestOf(e);

export function appendEvent(unit, ev) {
  if (unit.events.length >= PORTFOLIO_LIMITS.maxEventsPerUnit) throw typedError('EVENT_LIMIT', `unit ${unit.id} reached ${PORTFOLIO_LIMITS.maxEventsPerUnit} recorded events`);
  const prev = unit.events.length ? unit.events[unit.events.length - 1].digest : null;
  const body = { seq: unit.events.length + 1, prev, ...ev };
  unit.events.push({ ...body, digest: eventDigest(body) });
}

export function typedError(code, message, extra = {}) { return Object.assign(new Error(message), { code, ...extra }); }

/** A new, empty store for a plan. */
export function newStore(plan) {
  if (!plan || plan.schema !== PLAN_SCHEMA) throw typedError('BAD_PLAN', 'not a portfolio plan');
  const units = {};
  for (const u of plan.units) {
    units[u.id] = { ...u, state: 'pending', retryCount: 0, maxRetries: PORTFOLIO_LIMITS.defaultMaxRetries, generation: 0, attemptSeq: 0, lease: null, result: null, stale: [], blockedReason: null, events: [] };
  }
  return { schema: STORE_SCHEMA, version: STORE_VERSION, planId: plan.id, ...(plan.synthetic ? { synthetic: true } : {}), units };
}

/** Verify the store's internal consistency: event chains, state/lease/result agreement. Returns `{ ok, errors }`. */
export function verifyStore(store) {
  const errors = [];
  if (!store || store.schema !== STORE_SCHEMA || store.version !== STORE_VERSION || typeof store.units !== 'object' || !store.units) return { ok: false, errors: [{ code: 'BAD_STORE', message: 'not a portfolio store of a supported version' }] };
  for (const [id, u] of Object.entries(store.units)) {
    if (u.id !== id || unitIdOf(u) !== id) errors.push({ code: 'ID_MISMATCH', unit: id, message: 'unit identity does not match its repository, commit, task type and inputs' });
    if (!UNIT_STATES.includes(u.state)) errors.push({ code: 'BAD_STATE', unit: id, message: `unknown state '${u.state}'` });
    let prev = null;
    (u.events ?? []).forEach((e, i) => {
      const { digest, ...body } = e;
      if (e.seq !== i + 1 || e.prev !== prev || eventDigest(body) !== digest) errors.push({ code: 'EVENT_CHAIN_BROKEN', unit: id, message: `event ${i + 1} was altered or removed` });
      prev = digest;
    });
    if ((u.state === 'leased' || u.state === 'running') !== !!u.lease) errors.push({ code: 'LEASE_STATE_MISMATCH', unit: id, message: 'a lease exists exactly when the unit is leased or running' });
    if (u.state === 'verified' && !(u.result && DIGEST_RE.test(u.result.resultDigest ?? ''))) errors.push({ code: 'VERIFIED_WITHOUT_RESULT', unit: id, message: 'a verified unit must carry a result digest' });
    if (u.state !== 'verified' && u.result) errors.push({ code: 'RESULT_WITHOUT_VERIFIED', unit: id, message: 'only a verified unit may carry a current result' });
  }
  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------- transitions (pure on a store object)

const unitOf = (store, id) => {
  const u = store.units[id];
  if (!u) throw typedError('UNKNOWN_UNIT', `no such unit '${id}'`);
  return u;
};

function clampLease(ttlMs) {
  const t = ttlMs ?? PORTFOLIO_LIMITS.defaultLeaseMs;
  if (!Number.isFinite(t) || t < 1) throw typedError('BAD_LEASE', 'lease duration must be a positive number of milliseconds');
  return Math.min(t, PORTFOLIO_LIMITS.maxLeaseMs);
}

function spendAttempt(u, ev, now) {
  // an attempt ended without a verified result: it costs a retry. Out of retries is a terminal failure.
  u.lease = null;
  u.retryCount += 1;
  appendEvent(u, { ...ev, at: now });
  u.state = u.retryCount > u.maxRetries ? 'failed' : 'pending';
}

/** Recover every unit whose lease has expired. Returns the ids recovered. */
export function recoverExpired(store, now) {
  const out = [];
  for (const id of Object.keys(store.units).sort()) {
    const u = store.units[id];
    if ((u.state === 'leased' || u.state === 'running') && u.lease && u.lease.expiresAt <= now) {
      const attemptId = u.lease.attemptId;
      spendAttempt(u, { type: 'expired', attemptId, holder: u.lease.holder }, now);
      out.push(id);
    }
  }
  return out;
}

/**
 * Lease the next pending unit (or a named one) to `holder`. A repeat of the same `requestId` from the same holder returns the same lease
 * instead of leasing a second unit (duplicate delivery of the request). Returns `null` when nothing is leasable.
 */
export function leaseUnit(store, { holder, now, ttlMs, unitId = null, requestId = null, skip = () => false }) {
  if (typeof holder !== 'string' || !holder) throw typedError('BAD_HOLDER', 'a lease needs a holder');
  recoverExpired(store, now);
  if (requestId) {
    for (const u of Object.values(store.units)) {
      if (u.lease && u.lease.requestId === requestId && u.lease.holder === holder) return { unitId: u.id, attemptId: u.lease.attemptId, expiresAt: u.lease.expiresAt, duplicate: true };
    }
  }
  const candidates = unitId ? [unitOf(store, unitId)] : Object.values(store.units).sort((a, b) => (a.id < b.id ? -1 : 1));
  const u = candidates.find((c) => c.state === 'pending' && !skip(c));
  if (!u) return null;
  u.attemptSeq += 1;
  const attemptId = `${u.id}#${u.generation}.${u.attemptSeq}`;
  const expiresAt = now + clampLease(ttlMs);
  u.lease = { holder, attemptId, expiresAt, requestId };
  u.state = 'leased';
  appendEvent(u, { type: 'leased', attemptId, holder, at: now, expiresAt });
  return { unitId: u.id, attemptId, expiresAt, duplicate: false };
}

function liveAttempt(store, unitId, attemptId, now) {
  recoverExpired(store, now);
  const u = unitOf(store, unitId);
  if (!u.lease || u.lease.attemptId !== attemptId) return { u, ok: false };
  return { u, ok: true };
}

/** leased -> running. Idempotent for the same attempt. */
export function startUnit(store, { unitId, attemptId, now }) {
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'this attempt does not hold the lease (it expired, or the unit moved on)' };
  if (u.state === 'running') return { ok: true, duplicate: true };
  u.state = 'running';
  appendEvent(u, { type: 'started', attemptId, at: now });
  return { ok: true, duplicate: false };
}

/** Extend a live lease. */
export function renewLease(store, { unitId, attemptId, now, ttlMs }) {
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'the lease is no longer held' };
  u.lease.expiresAt = now + clampLease(ttlMs);
  appendEvent(u, { type: 'renewed', attemptId, at: now, expiresAt: u.lease.expiresAt });
  return { ok: true, expiresAt: u.lease.expiresAt };
}

/** A recorded result's dependency digests, one per dimension. All six are required: a result without them cannot be reused. */
export function checkDependencies(deps) {
  const missing = DEPENDENCY_DIMENSIONS.filter((d) => !DIGEST_RE.test(deps?.[d] ?? ''));
  return missing;
}

/**
 * Record a verified result. Accepted only from the live attempt, with all six dependency digests. A second delivery of the same
 * completion is acknowledged and changes nothing; a completion from a stale attempt is refused.
 */
export function completeUnit(store, { unitId, attemptId, resultDigest, dependencies, now }) {
  const u0 = unitOf(store, unitId);
  if (u0.state === 'verified' && u0.result?.attemptId === attemptId) return { ok: true, duplicate: true, counted: false };
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'this attempt does not hold the lease (it expired, or the unit moved on); the result is discarded' };
  if (!DIGEST_RE.test(resultDigest ?? '')) return { ok: false, code: 'bad-result', reason: 'a result needs a sha256 digest' };
  const missing = checkDependencies(dependencies);
  if (missing.length) return { ok: false, code: 'unbound-dependencies', reason: `result is missing dependency digests: ${missing.join(', ')}` };
  const deps = Object.fromEntries(DEPENDENCY_DIMENSIONS.map((d) => [d, dependencies[d]]));
  u.lease = null;
  u.result = { attemptId, resultDigest, dependencies: deps, dependencyDigest: digestOf(deps), generation: u.generation };
  u.state = 'verified';
  appendEvent(u, { type: 'verified', attemptId, at: now, resultDigest, dependencyDigest: u.result.dependencyDigest });
  return { ok: true, duplicate: false, counted: true };
}

/** The live attempt ended in failure. Costs a retry; out of retries the unit is terminally `failed`. */
export function failUnit(store, { unitId, attemptId, reason, now }) {
  const u0 = unitOf(store, unitId);
  const dup = u0.events.some((e) => e.type === 'failed' && e.attemptId === attemptId);
  if (dup) return { ok: true, duplicate: true };
  const { u, ok } = liveAttempt(store, unitId, attemptId, now);
  if (!ok) return { ok: false, code: 'stale-attempt', reason: 'this attempt does not hold the lease' };
  spendAttempt(u, { type: 'failed', attemptId, holder: u.lease?.holder ?? null, reason: String(reason ?? 'failed').slice(0, 300) }, now);
  return { ok: true, duplicate: false, state: u.state };
}

/** Park a unit that cannot proceed (a missing input). Not counted; independent units still run. */
export function blockUnit(store, { unitId, reason, now }) {
  const u = unitOf(store, unitId);
  if (!['pending', 'leased', 'running'].includes(u.state)) return { ok: false, code: 'bad-state', reason: `cannot block a ${u.state} unit` };
  u.lease = null; u.state = 'blocked'; u.blockedReason = String(reason ?? 'blocked').slice(0, 300);
  appendEvent(u, { type: 'blocked', reason: u.blockedReason, at: now });
  return { ok: true };
}

export function unblockUnit(store, { unitId, now }) {
  const u = unitOf(store, unitId);
  if (u.state !== 'blocked') return { ok: false, code: 'bad-state', reason: `unit is ${u.state}, not blocked` };
  u.state = 'pending'; u.blockedReason = null;
  appendEvent(u, { type: 'unblocked', at: now });
  return { ok: true };
}

/** Cancel every unit that is not verified or terminally failed (or one named unit). Leases are released; verified receipts and failure records are kept. */
export function cancelUnits(store, { unitId = null, reason, now }) {
  const canceled = [];
  for (const id of Object.keys(store.units).sort()) {
    if (unitId && id !== unitId) continue;
    const u = store.units[id];
    if (u.state === 'verified' || u.state === 'canceled' || u.state === 'failed') continue; // receipts and terminal failures keep their own status
    u.lease = null; u.state = 'canceled';
    appendEvent(u, { type: 'canceled', reason: String(reason ?? 'canceled').slice(0, 300), at: now });
    canceled.push(id);
  }
  return { ok: true, canceled };
}

// ---------------------------------------------------------------- progress

/** Counts by state. `verified` is the only count that is progress. */
export function progressOf(store) {
  const by = Object.fromEntries(UNIT_STATES.map((s) => [s, 0]));
  let staleResults = 0;
  for (const u of Object.values(store.units)) { by[u.state] += 1; staleResults += u.stale.length; }
  const total = Object.keys(store.units).length;
  return { total, ...by, completed: by.verified, remaining: total - by.verified - by.canceled, staleResults, done: total > 0 && by.verified === total };
}

/** The current scoped results: verified units only, keyed by unit id. Two runs converged exactly when these are equal. */
export function scopedResults(store) {
  return Object.fromEntries(Object.values(store.units).filter((u) => u.state === 'verified').sort((a, b) => (a.id < b.id ? -1 : 1)).map((u) => [u.id, u.result.resultDigest]));
}

/** Repositories whose every unit is verified and current: what `runFleet({ portfolioVerified })` may skip. */
export function fullyVerifiedRepositories(store) {
  const by = new Map();
  for (const u of Object.values(store.units)) by.set(u.repository, (by.get(u.repository) ?? true) && u.state === 'verified');
  return [...by].filter(([, ok]) => ok).map(([r]) => r).sort();
}

// ---------------------------------------------------------------- persistence

function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function withLock(file, fn) {
  const lock = `${file}.lock`;
  const start = Date.now();
  for (;;) {
    try { fs.writeFileSync(lock, String(process.pid), { flag: 'wx' }); break; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > PORTFOLIO_LIMITS.lockStaleMs) { fs.unlinkSync(lock); continue; } } catch { continue; }
      if (Date.now() - start > PORTFOLIO_LIMITS.lockWaitMs) throw typedError('LOCK_TIMEOUT', 'could not take the portfolio store lock');
      sleepSync(5);
    }
  }
  try { return fn(); } finally { try { fs.unlinkSync(lock); } catch { /* already gone */ } }
}

/** Read and verify a store. Throws `STORE_CORRUPT` rather than returning a guess. */
export function readStore(file) {
  let raw;
  try {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile() || st.size > PORTFOLIO_LIMITS.maxStoreBytes) throw typedError('STORE_CORRUPT', 'store is not a regular file within the size limit');
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  let store;
  try { store = JSON.parse(raw); } catch { throw typedError('STORE_CORRUPT', 'store is not valid JSON'); }
  const v = verifyStore(store);
  if (!v.ok) throw typedError('STORE_CORRUPT', `store failed verification: ${v.errors[0].code} ${v.errors[0].unit ?? ''}`, { errors: v.errors });
  return store;
}

function writeStore(file, store) {
  const text = JSON.stringify(store);
  if (text.length > PORTFOLIO_LIMITS.maxStoreBytes) throw typedError('STORE_TOO_LARGE', 'store would exceed the size limit');
  const tmp = `${file}.tmp-${process.pid}`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/**
 * Open (or create) the durable store for a plan. An existing store for a DIFFERENT plan is an error: resuming the wrong portfolio would
 * silently mix two sets of results.
 */
export function openStore(file, plan) {
  return withLock(file, () => {
    const existing = readStore(file);
    if (existing) {
      if (existing.planId !== plan.id) throw typedError('PLAN_MISMATCH', `the store at this path belongs to plan ${existing.planId}, not ${plan.id}`);
      return existing;
    }
    const fresh = newStore(plan);
    writeStore(file, fresh);
    return fresh;
  });
}

/** Locked read-modify-write. `fn(store)` mutates and returns a value; the store is verified before it is written back. */
export function mutateStore(file, fn) {
  return withLock(file, () => {
    const store = readStore(file);
    if (!store) throw typedError('NO_STORE', 'no portfolio store at this path');
    const out = fn(store);
    const v = verifyStore(store);
    if (!v.ok) throw typedError('STORE_CORRUPT', `refusing to write a store that fails verification: ${v.errors[0].code}`, { errors: v.errors });
    writeStore(file, store);
    return out;
  });
}

// ---------------------------------------------------------------- runner

/**
 * Drive a store to completion with bounded concurrency. Mirrors runFleet's isolation: an executor that throws FAILS its unit (and costs
 * a retry), it never takes the run down. `executor(unit, ctx)` returns `{ resultDigest, dependencies }`.
 *
 * `maxUnits` stops after that many units have been leased, for interruption tests and for time-boxed runs. Returns the progress.
 */
export async function runPortfolio({ file, executor, holder = 'worker', clock = () => Date.now(), ttlMs, concurrency = 2, maxUnits = Infinity, skip = () => false }) {
  let leased = 0;
  const limit = Math.max(1, Math.min(concurrency, 16));
  async function worker(n) {
    for (;;) {
      if (leased >= maxUnits) return;
      const lease = mutateStore(file, (s) => leaseUnit(s, { holder: `${holder}-${n}`, now: clock(), ttlMs, skip }));
      if (!lease) return;
      leased += 1;
      mutateStore(file, (s) => startUnit(s, { unitId: lease.unitId, attemptId: lease.attemptId, now: clock() }));
      const unit = readStore(file).units[lease.unitId];
      let res = null; let err = null;
      try { res = await executor(unit, { attemptId: lease.attemptId }); } catch (e) { err = e; }
      mutateStore(file, (s) => {
        if (err || !res) failUnit(s, { unitId: lease.unitId, attemptId: lease.attemptId, reason: err ? err.message : 'executor returned nothing', now: clock() });
        else completeUnit(s, { unitId: lease.unitId, attemptId: lease.attemptId, resultDigest: res.resultDigest, dependencies: res.dependencies, now: clock() });
      });
    }
  }
  await Promise.all(Array.from({ length: limit }, (_, i) => worker(i)));
  return progressOf(readStore(file));
}
