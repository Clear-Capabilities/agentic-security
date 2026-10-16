// Opt-in, privacy-preserving ingestion of runtime observations (E5-03).
//
// A runtime collector can see far more than this scanner needs: request bodies, headers, tokens, user identifiers. The scanner needs only WHICH
// route, function or file was exercised, and in which build. This module is the one door between a collector's output and the trace file that
// runtime-correlation.js reads, and it lets through only that.
//
// RULES (each is a test)
//   1. Off by default. Nothing is ingested unless the project's runtime policy says `collect: true` (or the caller passes that policy in).
//   2. An allowlist, not a blocklist. A record is rebuilt field by field from the fields below; every other field is dropped, counted by NAME and
//      never persisted, whatever it holds. A new field a collector invents is dropped until this list names it.
//   3. Values must look like what the field is: a route is a path, a symbol is a dotted identifier, a file is a relative path. A value that does not
//      fit rejects the whole record.
//   4. A canary scan runs over every value that IS allowed through (a route like /users/jane@example.com/orders, a symbol that is really a token):
//      an email, bearer token, JWT, cloud key, private key, card number (Luhn), SSN, or long opaque string rejects the whole record.
//      Query strings and fragments never survive: the route is the path only, and id-like segments (numbers, UUIDs, long hex) become `:id`.
//   5. Retention: records older than `retentionDays` are removed from the file when it is next written, and by `applyRetention`.
//   6. Disclosure: a sidecar `runtime-trace.meta.json` records the policy, the declared sampling rate, what was dropped and rejected (counts by
//      reason, never contents), and when. A trace with sampling below 1, or no declared sampling, can never support "not observed": see
//      runtime-correlation.js. Everything works offline from local files.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath } from './state-dir.js';
import { safeWriteState } from './state-dir.js';

export const POLICY_FILE = 'runtime-policy.json';
const TRACE_FILE = 'runtime-trace.jsonl';
const META_FILE = 'runtime-trace.meta.json';
const DEFAULT_RETENTION_DAYS = 30;
const ALLOWED_KINDS = Object.freeze(['function-call', 'route-hit', 'syscall', 'file-touch', 'service-call']);
export const ALLOWED_FIELDS = Object.freeze(['ts', 'kind', 'qid', 'route', 'fileRel', 'line', 'count', 'name', 'caller', 'service', 'peer', 'commit', 'buildHash', 'imageDigest', 'sbomRef', 'environment']);

const SYMBOL = /^[A-Za-z_$][\w$]*(?:[.:#/][A-Za-z_$][\w$]*)*(?:\(\))?$/;
const TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;
const REL_PATH = /^(?!.*\.\.)(?!\/)[\w@.+/-]{1,300}$/;
const SYSCALL = /^[a-z_][a-z0-9_]{0,40}$/;

// Canary patterns: what a secret or personal datum looks like. A hit rejects the record. Deliberately broad: a falsely rejected record costs one
// observation; a falsely accepted one persists a secret.
const CANARIES = [
  ['email', /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/],
  ['bearer-token', /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/i],
  ['jwt', /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/],
  ['cloud-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bAIza[0-9A-Za-z_-]{30,}\b|\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ['private-key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['ssn', /\b\d{3}-\d{2}-\d{4}\b/],
  ['secret-assignment', /\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S{3,}/i],
];

function luhn(digits) {
  let sum = 0; let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) { let d = digits.charCodeAt(i) - 48; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; }
  return sum % 10 === 0;
}

/** Name of the first canary the string trips, or null. */
export function canaryHit(s) {
  if (typeof s !== 'string') return null;
  for (const [name, re] of CANARIES) if (re.test(s)) return name;
  for (const m of s.matchAll(/\b\d(?:[ -]?\d){12,18}\b/g)) { const d = m[0].replace(/[ -]/g, ''); if (d.length >= 13 && d.length <= 19 && luhn(d)) return 'payment-card'; }
  if (/[A-Za-z0-9+/_-]{40,}={0,2}/.test(s)) return 'opaque-string';
  return null;
}

const SECRET_CANARY_NAMES = new Set(['bearer-token', 'jwt', 'cloud-key', 'private-key', 'secret-assignment']);
/** Name of the first SECRET-shaped pattern in a text (keys, tokens, passwords, card numbers), or null. Narrower than canaryHit: personal data and opaque strings are not matched. */
export function secretCanaryHit(s) {
  if (typeof s !== 'string') return null;
  for (const [name, re] of CANARIES) if (SECRET_CANARY_NAMES.has(name) && re.test(s)) return name;
  for (const m of s.matchAll(/\b\d(?:[ -]?\d){12,18}\b/g)) { const d = m[0].replace(/[ -]/g, ''); if (d.length >= 13 && d.length <= 19 && luhn(d)) return 'payment-card'; }
  return null;
}

/** The path of a route with the query and fragment removed and id-like segments generalised. Null when it is not a path. */
export function normalizeRoute(raw) {
  if (typeof raw !== 'string' || raw.length > 300) return null;
  let p = raw.trim();
  const cut = p.search(/[?#]/); if (cut >= 0) p = p.slice(0, cut);
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^/]+(\/.*)?$/i.exec(p); if (m) p = m[1] || '/';
  if (!p.startsWith('/') || /[\s<>"'\\]/.test(p)) return null;
  return p.split('/').map((seg) => (/^\d+$/.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) || /^[0-9a-f]{16,}$/i.test(seg) ? ':id' : seg)).join('/');
}

/**
 * Rebuild one record from the allowlist.
 * @returns {{record:object}|{rejected:string, dropped:string[]}}  `dropped` lists the NAMES of fields not persisted (never their values)
 */
export function normalizeRecord(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { rejected: 'not-an-object', dropped: [] };
  const dropped = Object.keys(raw).filter((k) => !ALLOWED_FIELDS.includes(k));
  if (!ALLOWED_KINDS.includes(raw.kind)) return { rejected: 'unknown-kind', dropped };
  const out = { kind: raw.kind };
  const reject = (reason) => ({ rejected: reason, dropped });
  if (raw.ts !== undefined) { if (typeof raw.ts !== 'string' || !Number.isFinite(Date.parse(raw.ts))) return reject('bad-timestamp'); out.ts = new Date(raw.ts).toISOString(); }
  if (raw.qid !== undefined) { if (typeof raw.qid !== 'string' || raw.qid.length > 300 || !SYMBOL.test(raw.qid)) return reject('bad-symbol'); out.qid = raw.qid; }
  if (raw.caller !== undefined) { if (typeof raw.caller !== 'string' || raw.caller.length > 300 || !SYMBOL.test(raw.caller)) return reject('bad-caller'); out.caller = raw.caller; }
  for (const k of ['service', 'peer']) if (raw[k] !== undefined) { if (typeof raw[k] !== 'string' || !TOKEN.test(raw[k])) return reject(`bad-${k}`); out[k] = raw[k]; }
  if (raw.route !== undefined) { const r = normalizeRoute(raw.route); if (!r) return reject('bad-route'); out.route = r; }
  if (raw.fileRel !== undefined) { if (typeof raw.fileRel !== 'string' || !REL_PATH.test(raw.fileRel)) return reject('bad-file'); out.fileRel = raw.fileRel; }
  if (raw.name !== undefined) { if (typeof raw.name !== 'string' || !SYSCALL.test(raw.name)) return reject('bad-name'); out.name = raw.name; }
  for (const k of ['line', 'count']) if (raw[k] !== undefined) { if (!Number.isInteger(raw[k]) || raw[k] < 0 || raw[k] > 1e9) return reject(`bad-${k}`); out[k] = raw[k]; }
  for (const k of ['commit', 'buildHash', 'imageDigest', 'sbomRef', 'environment']) if (raw[k] !== undefined) { if (typeof raw[k] !== 'string' || !TOKEN.test(raw[k])) return reject(`bad-${k}`); out[k] = raw[k]; }
  // canary scan over everything that is about to be persisted, except the identity fields whose shape (hex, digest) is itself long and opaque
  for (const [k, v] of Object.entries(out)) {
    if (typeof v !== 'string' || ['kind', 'ts', 'commit', 'buildHash', 'imageDigest', 'sbomRef'].includes(k)) continue;
    const hit = canaryHit(v);
    if (hit) return reject(`canary:${hit}`);
  }
  if (raw.kind === 'service-call' && (!out.service || !out.peer)) return reject('service-call-without-endpoints');
  if (raw.kind === 'route-hit' && !out.route) return reject('route-hit-without-route');
  if (raw.kind === 'function-call' && !out.qid && !out.fileRel) return reject('function-call-without-symbol');
  return { record: out, dropped };
}

/** Read the project's runtime policy; null when absent or unreadable. */
function loadRuntimePolicy(scanRoot) {
  try {
    const p = JSON.parse(fs.readFileSync(statePath(scanRoot, POLICY_FILE), 'utf8'));
    return p && typeof p === 'object' ? p : null;
  } catch { return null; }
}

const bump = (o, k) => { o[k] = (o[k] || 0) + 1; };

/** Remove records older than the retention window from the trace file. Returns how many were removed. */
export function applyRetention(scanRoot, { retentionDays = DEFAULT_RETENTION_DAYS, now = Date.now() } = {}) {
  const file = statePath(scanRoot, TRACE_FILE);
  let text; try { text = fs.readFileSync(file, 'utf8'); } catch { return { removed: 0, kept: 0 }; }
  const keep = []; let removed = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let r; try { r = JSON.parse(line); } catch { removed++; continue; }
    const t = r && r.ts ? Date.parse(r.ts) : NaN;
    if (Number.isFinite(t) && now - t > retentionDays * 86400_000) { removed++; continue; }
    keep.push(line);
  }
  if (removed > 0 && !safeWriteState(file, keep.length ? keep.join('\n') + '\n' : '')) return { removed: 0, kept: keep.length + removed, error: 'could not rewrite the trace file' };
  return { removed, kept: keep.length };
}

/**
 * Ingest collector records.
 * @param {string} scanRoot
 * @param {object[]} records
 * @param {object} opts policy (overrides the policy file), sampleRate (declared by the collector, 0..1), now
 * @returns {{ok:boolean, reason?:string, accepted:number, rejected:Object<string,number>, droppedFields:Object<string,number>, meta?:object}}
 */
export function ingestRuntimeRecords(scanRoot, records, opts = {}) {
  const policy = opts.policy || loadRuntimePolicy(scanRoot);
  if (!policy || policy.collect !== true) return { ok: false, reason: 'runtime collection is not enabled: set {"collect": true} in .agentic-security/runtime-policy.json', accepted: 0, rejected: {}, droppedFields: {} };
  if (!Array.isArray(records)) return { ok: false, reason: 'records must be an array', accepted: 0, rejected: {}, droppedFields: {} };
  const allowedKinds = Array.isArray(policy.kinds) ? policy.kinds.filter((k) => ALLOWED_KINDS.includes(k)) : ALLOWED_KINDS;
  const retentionDays = Number.isInteger(policy.retentionDays) && policy.retentionDays > 0 ? policy.retentionDays : DEFAULT_RETENTION_DAYS;
  const declared = opts.sampleRate !== undefined ? opts.sampleRate : policy.sampleRate;
  const sampleRate = typeof declared === 'number' && declared > 0 && declared <= 1 ? declared : null;
  const now = opts.now ?? Date.now();
  const rejected = {}; const droppedFields = {}; const lines = [];
  for (const raw of records) {
    const n = normalizeRecord(raw);
    for (const d of n.dropped || []) bump(droppedFields, d);
    if (n.rejected) { bump(rejected, n.rejected.startsWith('canary:') ? n.rejected : n.rejected); continue; }
    if (!allowedKinds.includes(n.record.kind)) { bump(rejected, 'kind-not-allowed-by-policy'); continue; }
    if (!n.record.ts) n.record.ts = new Date(now).toISOString();
    lines.push(JSON.stringify(n.record));
  }
  const file = statePath(scanRoot, TRACE_FILE);
  const ret = applyRetention(scanRoot, { retentionDays, now });
  let existing = ''; try { existing = fs.readFileSync(file, 'utf8'); } catch { /* none yet */ }
  if (lines.length && !safeWriteState(file, existing + lines.join('\n') + '\n')) return { ok: false, reason: 'could not write the trace file (no project marker or state writes disabled)', accepted: 0, rejected, droppedFields };
  const prior = (() => { try { return JSON.parse(fs.readFileSync(statePath(scanRoot, META_FILE), 'utf8')); } catch { return null; } })();
  const meta = {
    schema: 'agentic-security/runtime-trace-meta@1',
    updatedAt: new Date(now).toISOString(),
    retentionDays,
    // null means the collector did not say. Both null and < 1 mean "absence of an observation proves nothing"
    sampleRate,
    samplingDisclosed: sampleRate !== null,
    totals: {
      accepted: ((prior && prior.totals && prior.totals.accepted) || 0) + lines.length,
      rejected: sumInto((prior && prior.totals && prior.totals.rejected) || {}, rejected),
      droppedFields: sumInto((prior && prior.totals && prior.totals.droppedFields) || {}, droppedFields),
      expiredByRetention: ((prior && prior.totals && prior.totals.expiredByRetention) || 0) + ret.removed,
    },
    note: 'Counts only. No dropped or rejected value is stored.',
  };
  safeWriteState(statePath(scanRoot, META_FILE), JSON.stringify(meta, null, 2) + '\n');
  return { ok: true, accepted: lines.length, rejected, droppedFields, expired: ret.removed, meta };
}

function sumInto(base, add) { const o = { ...base }; for (const [k, v] of Object.entries(add)) o[k] = (o[k] || 0) + v; return o; }

/** The sidecar next to a trace file, or null. */
export function loadTraceMeta(traceFile) {
  try { return JSON.parse(fs.readFileSync(path.join(path.dirname(traceFile), META_FILE), 'utf8')); } catch { return null; }
}
