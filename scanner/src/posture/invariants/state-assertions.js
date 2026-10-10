// Verifier-side evaluation of invariant expressions over durable state (X-404).
//
// The business-state oracle's harness only DRIVES a scenario and records what the application wrote: per operation, the net
// durable writes (key, before, after), the side-effect events it emitted, and the response it returned. It never decides
// anything. This module reads that log, after the whole process tree is dead, and decides whether each forbidden outcome of the
// invariant happened. The decision looks at durable state and permitted side effects. The response status is recorded in the
// event sequence for the reader, but it is never an input to a verdict: a handler that answers 403 while it wrote another
// tenant's record has violated the contract, and a handler that answers 200 and wrote nothing forbidden has not.
//
// Pure functions: no fs, no clock, no randomness.
import { digestOf, semanticId } from '../assurance/identity.js';

const EVIDENCE_ID_PREFIX = 'ievd';
const EVIDENCE_ID_FIELDS = ['invariantId', 'forbiddenId', 'op', 'logDigest', 'ops'];
const SECRET_KEY = /secret|token|passw|api[_-]?key|authorization|cookie|credential|ssn|private/i;
const MAX_SNAPSHOT_KEYS = 24;
const MAX_TEXT = 80;

/** A snapshot safe to store in a record: secret-looking fields redacted, long strings cut, size bounded. Never throws. */
export function sanitizeSnapshot(snapshot) {
  const clean = (v, depth) => {
    if (v === null || typeof v === 'number' || typeof v === 'boolean') return v;
    if (typeof v === 'string') return v.length > MAX_TEXT ? `${v.slice(0, MAX_TEXT)}...` : v;
    if (depth > 3 || v === undefined) return null;
    if (Array.isArray(v)) return v.slice(0, 8).map((x) => clean(x, depth + 1));
    if (typeof v === 'object') {
      const out = {};
      for (const k of Object.keys(v).slice(0, 16)) out[k] = SECRET_KEY.test(k) ? '[redacted]' : clean(v[k], depth + 1);
      return out;
    }
    return null;
  };
  const out = {};
  const src = snapshot && typeof snapshot === 'object' ? snapshot : {};
  for (const k of Object.keys(src).slice(0, MAX_SNAPSHOT_KEYS)) out[k] = SECRET_KEY.test(k) ? '[redacted]' : clean(src[k], 0);
  return out;
}

const tenantOf = (rec) => (rec && typeof rec === 'object' && typeof rec.tenant === 'string' ? rec.tenant : null);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

function opsOf(phaseLog) { return Array.isArray(phaseLog?.steps) ? phaseLog.steps : []; }

/** Replay the write log over the initial snapshot, item by item (an item is one step or one parallel group). */
function itemStates(phaseLog) {
  const state = new Map(Object.entries(phaseLog?.initial || {}));
  const items = new Map();
  for (const op of opsOf(phaseLog)) {
    if (!items.has(op.item)) items.set(op.item, { item: op.item, ops: [], before: new Map(state) });
    items.get(op.item).ops.push(op);
    for (const w of op.writes || []) { if (w.after === null || w.after === undefined) state.delete(w.key); else state.set(w.key, w.after); }
    items.get(op.item).after = new Map(state);
  }
  return [...items.values()];
}

const sumOf = (m, prefix, field) => { let s = 0; for (const [k, v] of m) if (k.startsWith(prefix)) s += num(v?.[field]); return s; };

/**
 * Evaluate one forbidden expression over one phase log.
 * @returns {{ violated: boolean, ops: number[], detail: string }} `ops` are the operation indices that carry the violation.
 */
function evaluateOne(expr, phaseLog, ctx) {
  const actors = ctx.actors;
  const ops = opsOf(phaseLog);
  const hit = [];
  let detail = '';
  switch (expr.op) {
    case 'cross-tenant-write':
      for (const op of ops) {
        const a = actors[op.actor];
        if (!a) continue;
        for (const w of op.writes || []) {
          if (expr.prefix && !w.key.startsWith(expr.prefix)) continue;
          const owner = tenantOf(w.before) ?? tenantOf(w.after);
          if (owner !== null && owner !== a.tenant) { hit.push(op.op); detail = `${op.actor} (tenant ${a.tenant}) changed '${w.key}' owned by tenant ${owner}`; break; }
        }
      }
      break;
    case 'cross-tenant-read':
      for (const op of ops) {
        const a = actors[op.actor];
        if (!a || typeof op.response !== 'string') continue;
        const leaked = (ctx.markers || []).find((m) => m.tenant !== a.tenant && op.response.includes(m.marker));
        if (leaked) { hit.push(op.op); detail = `the response to ${op.actor} (tenant ${a.tenant}) carried a marker owned by tenant ${leaked.tenant}`; }
      }
      break;
    case 'unauthorized-role-change':
      for (const op of ops) {
        const a = actors[op.actor];
        if (!a || !expr.actions.includes(op.action) || expr.allowedRoles.includes(a.role)) continue;
        if ((op.writes || []).length > 0) { hit.push(op.op); detail = `${op.actor} (role ${a.role}) changed durable state through '${op.action}'`; }
      }
      break;
    case 'sum-not-conserved':
      for (const it of itemStates(phaseLog)) {
        if (it.ops.some((op) => (expr.allowedActions || []).includes(op.action))) continue;
        const b = sumOf(it.before, expr.prefix, expr.field);
        const af = sumOf(it.after, expr.prefix, expr.field);
        if (b !== af) { hit.push(...it.ops.map((o) => o.op)); detail = `the total of '${expr.field}' under '${expr.prefix}' moved from ${b} to ${af}`; }
      }
      break;
    case 'transition-outside': {
      const allowed = new Set(expr.allowed.map((t) => `${t.from}>${t.to}`));
      for (const op of ops) {
        for (const w of op.writes || []) {
          if (!w.key.startsWith(expr.prefix) || !w.before || !w.after) continue;
          const from = w.before[expr.field]; const to = w.after[expr.field];
          if (from === to || typeof from !== 'string' || typeof to !== 'string') continue;
          if (!allowed.has(`${from}>${to}`)) { hit.push(op.op); detail = `'${w.key}' moved ${from} to ${to}, which is not an allowed transition`; }
        }
      }
      break;
    }
    case 'duplicate-effect': {
      const counts = new Map();
      for (const op of ops) for (const ev of op.events || []) {
        if (ev.name !== expr.event) continue;
        const k = ev.key ?? '';
        const c = counts.get(k) || { n: 0, ops: [] };
        c.n++; c.ops.push(op.op); counts.set(k, c);
      }
      const max = expr.max ?? 1;
      for (const [k, c] of counts) if (c.n > max) { hit.push(...c.ops); detail = `effect '${expr.event}'${k ? ` for key '${k}'` : ''} happened ${c.n} times (at most ${max} allowed)`; }
      break;
    }
    default:
      return { violated: false, ops: [], detail: `unsupported expression '${String(expr.op).slice(0, 40)}'`, unsupported: true };
  }
  return { violated: hit.length > 0, ops: [...new Set(hit)].sort((a, b) => a - b), detail };
}

/**
 * Evaluate every forbidden outcome of an invariant over one phase log.
 * @param {object} args
 * @param {string} args.invariantId
 * @param {Array}  args.forbidden   the invariant's expressions
 * @param {object} args.actors      actor id -> { tenant, role }
 * @param {Array}  [args.markers]   [{ tenant, marker }] strings owned by a tenant
 * @param {object} args.phaseLog    the harness log for one phase
 * @returns {Array<{ id, op, violated, ops, detail, evidenceId }>}
 */
export function evaluateAssertions({ invariantId, forbidden, actors, markers = [], phaseLog }) {
  const logDigest = digestOf({ initial: phaseLog?.initial ?? null, steps: opsOf(phaseLog), final: phaseLog?.final ?? null });
  return forbidden.map((expr) => {
    const r = evaluateOne(expr, phaseLog, { actors, markers });
    return {
      id: expr.id, op: expr.op, violated: r.violated, ops: r.ops, detail: r.detail, unsupported: r.unsupported === true,
      evidenceId: semanticId(EVIDENCE_ID_PREFIX, { invariantId, forbiddenId: expr.id, op: expr.op, logDigest, ops: r.ops }, EVIDENCE_ID_FIELDS),
    };
  });
}

/** The ordered event sequence of a phase: what ran, who ran it, the durable keys it changed and the effects it emitted. */
export function eventSequence(phaseLog) {
  return opsOf(phaseLog).map((op) => ({
    item: op.item, op: op.op, actor: op.actor, action: op.action, status: op.status ?? null, ok: op.ok === true,
    wrote: (op.writes || []).map((w) => w.key), emitted: (op.events || []).map((e) => e.name),
  }));
}

/** True if at least one operation changed durable state or emitted a permitted effect (the control produced a durable effect). */
export function hasDurableEffect(phaseLog) {
  return opsOf(phaseLog).some((op) => (op.writes || []).length > 0 || (op.events || []).length > 0);
}
