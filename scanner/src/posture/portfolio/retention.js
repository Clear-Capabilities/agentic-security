// Evidence retention for portfolio artifacts (X-708.AC01).
//
// `posture/retention-policy.js` ages the scanner's own registered state files. A portfolio keeps a different population: replay
// evidence that lets someone re-run a check, metadata that describes a release, traces of model calls, and secrets that must not
// outlive their use. They differ in how long they should live, so a record here has a CLASS, and the policy sets a retention per class:
//
//   replay-evidence  replay manifests and verification receipts. Kept longest: they are what makes a claim re-checkable.
//   metadata         manifests, findings, provenance, toolchain identities.
//   model-trace      records of model calls (prompts, responses, routing decisions). Short: they hold the most sensitive content.
//   secret           anything credential-like captured in the course of a run. Default 0 days (delete at the next sweep) and a hard
//                    ceiling of 7 days. A secret is never exported.
//
// `RETENTION_DEFAULTS` are engineering defaults, not a regulatory claim; an operator sets their own per class, and a configured value
// above the class's `maxDays` is clamped down and the clamp is disclosed (a TTL that can be configured to "never" is not a TTL), the
// same rule retention-policy.js applies.
//
// THE ORDER OF PROTECTION, each tested in both directions:
//   1. a REQUIRED CURRENT receipt is never deleted, whatever its age and whether or not a hold exists. A record is required when it
//      is named in `currentReceiptIds`, or when a unit listed in its `requiredBy` is `verified` in the store right now. When it is also
//      past its retention the plan says so (`expiredButRequired`): the deletion is blocked loudly, never skipped silently. Once the unit
//      goes stale, is cancelled or is re-planned, the record is no longer required and ages out normally.
//   2. a LEGAL HOLD (identity-bound, reasoned, optionally expiring: the shape and the check of posture/legal-hold.js, which this reuses)
//      on the record, its class or its repository keeps it. A hold on a `secret` is honoured and flagged, because a hold is a legal act.
//   3. otherwise a record past its class's retention is deleted; a record in a class the policy does not know is KEPT and reported.
//
// DELETION IS LOGGED, AND LOGGED FIRST. Each deletion appends an intent entry to a hash-chained log (record id, class, path, size, content
// digest, reason, age, policy version, actor) and only then removes the file; an outcome entry follows. If the log cannot be written
// nothing is deleted. The log records that a deletion happened and what it was, never the content. Paths are confined to the root,
// symlinks are refused, and a directory record is refused (not recursed into).
//
// `planRetention` is pure. `applyRetention` re-plans at the moment of deletion with the live store, so a plan made earlier cannot delete
// a record that has become required since.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { isUnderHold } from '../legal-hold.js';
import { digestOf } from '../assurance/identity.js';

export const RETENTION_CLASSES = Object.freeze(['replay-evidence', 'metadata', 'model-trace', 'secret']);
export const RETENTION_DEFAULTS = Object.freeze({
  'replay-evidence': Object.freeze({ defaultDays: 365, maxDays: 1095 }),
  metadata: Object.freeze({ defaultDays: 730, maxDays: 1825 }),
  'model-trace': Object.freeze({ defaultDays: 30, maxDays: 90 }),
  secret: Object.freeze({ defaultDays: 0, maxDays: 7 }),
});
export const RETENTION_LOG_SCHEMA = 'agentic-security/retention-log';
const DAY = 86_400_000;
const BUNDLE_ROLE_CLASS = Object.freeze({ 'replay-manifest': 'replay-evidence', receipt: 'replay-evidence', manifest: 'metadata', findings: 'metadata', provenance: 'metadata', toolchain: 'metadata' });

/** The retention class of a portfolio bundle role (bundle.js ROLES). An unknown role has no class and is never deleted by this module. */
export const classOfBundleRole = (role) => BUNDLE_ROLE_CLASS[role] ?? null;

/** Validate a policy `{ version, classes: { <class>: { retainDays } } }` and return the effective days per class, with any clamp disclosed. */
export function resolveRetentionPolicy(policy) {
  const errors = [];
  if (policy !== undefined && policy !== null && (typeof policy !== 'object' || Array.isArray(policy))) return { ok: false, errors: [{ code: 'BAD_POLICY', message: 'a policy is an object' }] };
  const version = policy?.version ?? 'defaults';
  if (typeof version !== 'string' || !version) errors.push({ code: 'BAD_POLICY', message: 'version must be a non-empty string' });
  const effective = {};
  for (const cls of Object.keys(policy?.classes ?? {})) if (!RETENTION_CLASSES.includes(cls)) errors.push({ code: 'UNKNOWN_CLASS', message: `'${cls}' is not a retention class` });
  for (const cls of RETENTION_CLASSES) {
    const b = RETENTION_DEFAULTS[cls];
    const set = policy?.classes?.[cls]?.retainDays;
    if (set !== undefined && !(typeof set === 'number' && Number.isFinite(set) && set >= 0)) { errors.push({ code: 'BAD_DAYS', message: `${cls}.retainDays must be a non-negative number` }); continue; }
    const days = set === undefined ? b.defaultDays : Math.min(set, b.maxDays);
    effective[cls] = { days, source: set === undefined ? 'default' : 'policy', clamped: set !== undefined && set > b.maxDays, maxDays: b.maxDays };
  }
  return errors.length ? { ok: false, errors } : { ok: true, version, effective };
}

/**
 * Validate legal holds. A hold is `{ target, owner, reason, expires_at? }` with `target` one of `{ id }`, `{ class }`, `{ repository }`.
 * Identity-bound (owner), reasoned (reason), and an expiry, when present, must parse. Returns the holds in the shape legal-hold.js reads.
 */
export function normalizeHolds(holds) {
  const errors = []; const out = [];
  for (const [i, h] of (Array.isArray(holds) ? holds : []).entries()) {
    const t = h?.target;
    const key = t && typeof t === 'object' ? (t.id ? `id:${t.id}` : t.class ? `class:${t.class}` : t.repository ? `repository:${t.repository}` : null) : null;
    if (!key) { errors.push({ code: 'BAD_HOLD', index: i, message: 'a hold targets an id, a class or a repository' }); continue; }
    if (t.class && !RETENTION_CLASSES.includes(t.class)) { errors.push({ code: 'BAD_HOLD', index: i, message: `'${t.class}' is not a retention class` }); continue; }
    if (typeof h.owner !== 'string' || !h.owner) { errors.push({ code: 'BAD_HOLD', index: i, message: 'a hold needs an owner (identity-bound)' }); continue; }
    if (typeof h.reason !== 'string' || !h.reason) { errors.push({ code: 'BAD_HOLD', index: i, message: 'a hold needs a reason' }); continue; }
    if (h.expires_at && !Number.isFinite(Date.parse(h.expires_at))) { errors.push({ code: 'BAD_HOLD', index: i, message: 'expires_at must be a parseable date' }); continue; }
    out.push({ artifact: key, owner: h.owner, reason: h.reason, expires_at: h.expires_at ?? null });
  }
  return { ok: errors.length === 0, errors, holds: out };
}

const createdMs = (r) => (typeof r.createdAt === 'number' ? r.createdAt : Date.parse(r.createdAt));

/**
 * @param {object} p
 * @param {Array<{id:string, class:string, path:string, createdAt:number|string, repository?:string, requiredBy?:string[]}>} p.records
 * @param {object} [p.policy]
 * @param {Array} [p.holds]
 * @param {number} p.now  milliseconds
 * @param {object} [p.store]  a portfolio store: a record whose `requiredBy` names a verified unit is a required current receipt
 * @param {Iterable<string>} [p.currentReceiptIds]
 */
export function planRetention({ records, policy, holds = [], now, store = null, currentReceiptIds = [] } = {}) {
  const pol = resolveRetentionPolicy(policy);
  if (!pol.ok) return { ok: false, errors: pol.errors };
  const h = normalizeHolds(holds);
  if (!h.ok) return { ok: false, errors: h.errors };
  if (!Number.isFinite(now)) return { ok: false, errors: [{ code: 'NO_NOW', message: 'now (milliseconds) is required' }] };
  const required = new Set(currentReceiptIds);
  const decisions = [];
  for (const r of Array.isArray(records) ? records : []) {
    const base = { id: r?.id ?? null, class: r?.class ?? null, path: r?.path ?? null };
    if (!r || typeof r.id !== 'string' || !r.id || typeof r.path !== 'string' || !Number.isFinite(createdMs(r))) { decisions.push({ ...base, action: 'keep', reason: 'malformed-record', detail: 'a record needs an id, a path and a creation time; it is not deleted' }); continue; }
    if (!RETENTION_CLASSES.includes(r.class)) { decisions.push({ ...base, action: 'keep', reason: 'unclassified', detail: `'${r.class}' is not a retention class; unclassified records are never deleted` }); continue; }
    const ageDays = (now - createdMs(r)) / DAY;
    const ttl = pol.effective[r.class].days;
    const expired = ageDays > ttl;
    const requiredNow = required.has(r.id) || (Array.isArray(r.requiredBy) && r.requiredBy.some((uid) => store?.units?.[uid]?.state === 'verified'));
    const d = { ...base, ageDays: Math.round(ageDays * 100) / 100, ttlDays: ttl, expired };
    if (requiredNow) { decisions.push({ ...d, action: 'protect', reason: 'required-current-receipt', expiredButRequired: expired, detail: expired ? 'past its retention, but a current verified result depends on it: deletion is blocked' : 'a current verified result depends on it' }); continue; }
    const names = [`id:${r.id}`, `class:${r.class}`, ...(r.repository ? [`repository:${r.repository}`] : [])];
    const hold = names.map((n) => isUnderHold(n, h.holds, now)).find(Boolean);
    if (hold) { decisions.push({ ...d, action: 'keep', reason: 'legal-hold', hold: { target: hold.artifact, owner: hold.owner, reason: hold.reason, expires_at: hold.expires_at }, ...(r.class === 'secret' ? { warning: 'a secret is being retained under a legal hold' } : {}) }); continue; }
    decisions.push(expired ? { ...d, action: 'delete', reason: r.class === 'secret' ? 'secret-expired' : 'expired' } : { ...d, action: 'keep', reason: 'within-retention' });
  }
  const count = (a) => decisions.filter((x) => x.action === a).length;
  return {
    ok: true, policyVersion: pol.version, effective: pol.effective, now, decisions,
    summary: { records: decisions.length, delete: count('delete'), keep: count('keep'), protect: count('protect'), expiredButRequired: decisions.filter((x) => x.expiredButRequired).length, heldByLegalHold: decisions.filter((x) => x.reason === 'legal-hold').length },
  };
}

// ---------------------------------------------------------------- the deletion log

const entryDigest = (e) => digestOf(e);

function readLog(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  return raw.split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

/** Verify the hash chain of a deletion log. Returns `{ ok, entries, errors }`. */
export function verifyRetentionLog(file) {
  let entries;
  try { entries = readLog(file); } catch { return { ok: false, entries: [], errors: [{ code: 'LOG_UNREADABLE', message: 'the deletion log is unreadable' }] }; }
  const errors = []; let prev = null;
  entries.forEach((e, i) => {
    const { digest, ...body } = e;
    if (e.seq !== i + 1 || e.prev !== prev || entryDigest(body) !== digest) errors.push({ code: 'LOG_BROKEN', seq: i + 1, message: `entry ${i + 1} was altered, removed or reordered` });
    prev = digest;
  });
  return { ok: errors.length === 0, entries, errors };
}

function appendLog(file, entry) {
  const v = verifyRetentionLog(file);
  if (!v.ok) throw Object.assign(new Error('the deletion log fails verification; nothing will be deleted'), { code: 'LOG_BROKEN' });
  const last = v.entries.at(-1);
  const body = { schema: RETENTION_LOG_SCHEMA, seq: v.entries.length + 1, prev: last ? last.digest : null, ...entry };
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const fd = fs.openSync(file, 'a', 0o600);
  try { fs.writeSync(fd, `${JSON.stringify({ ...body, digest: entryDigest(body) })}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function confined(root, rel) {
  if (path.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) return null;
  const abs = path.resolve(root, rel);
  const rootReal = fs.realpathSync(root);
  if (abs !== rootReal && !abs.startsWith(rootReal + path.sep) && !abs.startsWith(path.resolve(root) + path.sep)) return null;
  // a directory inside the root that is a link out of it must not carry a deletion out of the root either
  const parentReal = fs.realpathSync(path.dirname(abs));
  if (parentReal !== rootReal && !parentReal.startsWith(rootReal + path.sep)) return null;
  return abs;
}

/**
 * Plan and apply, logging every deletion first. `dryRun` plans only. Returns the plan plus what happened.
 * @returns {{ ok: boolean, plan?: object, deleted: object[], failed: object[], blocked: object[], errors?: object[] }}
 */
export function applyRetention({ root, logFile, actor, dryRun = false, ...planInput } = {}) {
  const plan = planRetention(planInput);
  if (!plan.ok) return { ok: false, errors: plan.errors, deleted: [], failed: [], blocked: [] };
  const blocked = plan.decisions.filter((d) => d.expiredButRequired).map((d) => ({ id: d.id, reason: d.reason, detail: d.detail }));
  if (dryRun) return { ok: true, plan, dryRun: true, deleted: [], failed: [], blocked };
  if (typeof actor !== 'string' || !actor) return { ok: false, errors: [{ code: 'NO_ACTOR', message: 'a deletion is attributed to an actor' }], plan, deleted: [], failed: [], blocked };
  const deleted = []; const failed = [];
  for (const d of plan.decisions.filter((x) => x.action === 'delete')) {
    const fail = (code, message) => failed.push({ id: d.id, code, message });
    let abs;
    try { abs = confined(root, d.path); } catch { abs = null; }
    if (!abs) { fail('PATH_ESCAPES_ROOT', 'the record path is not inside the retention root'); continue; }
    let st;
    try { st = fs.lstatSync(abs); } catch (e) { fail(e.code === 'ENOENT' ? 'ALREADY_GONE' : 'STAT_FAILED', 'the file is not there to delete'); continue; }
    if (st.isSymbolicLink()) { fail('SYMLINK_REFUSED', 'a symbolic link is not followed or removed'); continue; }
    if (!st.isFile()) { fail('NOT_A_FILE', 'only files are deleted, never directories'); continue; }
    const digest = `sha256:${crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex')}`;
    const entry = { recordId: d.id, class: d.class, path: d.path, bytes: st.size, contentDigest: digest, reason: d.reason, ageDays: d.ageDays, ttlDays: d.ttlDays, policyVersion: plan.policyVersion, actor, at: new Date(plan.now).toISOString() };
    try { appendLog(logFile, { type: 'delete-intent', ...entry }); } catch (e) { fail(e.code ?? 'LOG_FAILED', 'the deletion could not be logged, so the file was not deleted'); continue; }
    try { fs.unlinkSync(abs); } catch (e) {
      try { appendLog(logFile, { type: 'delete-failed', recordId: d.id, code: e.code ?? 'UNLINK_FAILED', at: entry.at }); } catch { /* the intent entry stands */ }
      fail(e.code ?? 'UNLINK_FAILED', 'the file could not be removed'); continue;
    }
    try { appendLog(logFile, { type: 'deleted', recordId: d.id, contentDigest: digest, at: entry.at }); } catch { /* the intent entry already recorded it */ }
    deleted.push({ id: d.id, class: d.class, path: d.path, contentDigest: digest });
  }
  return { ok: true, plan, deleted, failed, blocked };
}
