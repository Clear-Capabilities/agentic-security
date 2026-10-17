// Cross-route consistency (E4-03): does every route that touches a resource enforce what its sibling routes enforce?
//
// The classic authorization bug is not a missing check on the only route; it is a check on `GET /orders/:id` and none on `PUT /orders/:id` or
// `DELETE /orders/:id`. A per-route review sees each handler as fine. This compares, per resource, the controls the routes carry, using the facts
// DCI already extracted along route -> middleware -> handler -> service -> persistence, so a check made in a service layer counts for the route that
// reaches it.
//
// WHAT IT CLAIMS. For a resource touched by two or more routes, a control (authentication, authorization-role, ownership, tenant-scope) that at
// least one route enforces before its sensitive operation and another does not is an INCONSISTENCY. It is evidence that the missing route is
// weaker than its sibling, not proof of a vulnerability: that needs a counterexample (E4-04).
//
// WHAT IT REFUSES TO CLAIM.
//   - A route whose control could hide behind an unresolved call or a traversal limit is `unknown`, never "missing": absence of evidence in an
//     incomplete context is not absence of the control, and dynamic dispatch is not proof of safety either.
//   - A route that an invariant declares public-by-design for that control is SUPPRESSED, with the policy id and reason kept.
//   - A resource touched by a single route has nothing to compare and produces nothing.
//   - The resource name comes from the text of the data operation (collection, table or model); an operation whose target cannot be named is
//     left out and counted, not guessed.
import { evaluateInvariants } from './invariants.js';

export const CONSISTENCY_DIMENSIONS = Object.freeze(['authentication', 'authorization-role', 'ownership', 'tenant-scope']);

const SQL_TARGET = /\b(?:FROM|INTO|UPDATE)\s+[`"']?([A-Za-z_][\w.]*)/i;
const COLLECTION = /\bcollection\s*\(\s*['"`]([\w.-]+)['"`]\s*\)/;
const DB_MEMBER = /\b(?:db|database|mongo|prisma|knex|models?)\s*\.\s*([A-Za-z_]\w*)\s*\.\s*(?:find|findOne|findMany|findById|findAll|findUnique|findFirst|insert|insertOne|insertMany|create|update|updateOne|updateMany|delete|deleteOne|deleteMany|remove|save|upsert|count|aggregate|get)\b/;
const MODEL = /\b([A-Z][A-Za-z0-9]+)\s*\.\s*(?:find|findOne|findAll|findByPk|findById|findUnique|create|update|destroy|delete|remove|save|where|objects)\b/;
const REPO_CALL = /\b([a-z][A-Za-z0-9]*?)(?:Repo|Repository|Dao|Store)\s*\.\s*\w+\s*\(/;

/** Resource key: lowercase, singular-ish (`Orders`, `order`, `orders` all become `order`). */
export function resourceKey(text) {
  const t = String(text || '');
  const m = COLLECTION.exec(t) || DB_MEMBER.exec(t) || SQL_TARGET.exec(t) || MODEL.exec(t) || REPO_CALL.exec(t);
  if (!m) return null;
  const raw = m[1].split('.').pop().toLowerCase();
  if (!raw || ['db', 'models', 'model', 'table', 'tables', 'users_table_placeholder'].includes(raw)) return null;
  return raw.replace(/ies$/, 'y').replace(/(?<!s)s$/, '');
}

function operationOf(fact) {
  const t = String(fact.text || '');
  if (/\b(?:delete|remove|destroy|drop)\w*/i.test(t)) return 'delete';
  if (/\b(?:update|set|patch|save|upsert|replace)\w*/i.test(t)) return 'update';
  if (/\b(?:insert|create|add)\w*/i.test(t)) return 'create';
  return fact.subkind === 'write' ? 'update' : 'read';
}

function stateOf(bundle, dim) {
  const facts = bundle.reach?.facts || [];
  const sens = facts.filter((f) => f.category === 'sensitive');
  const first = sens.length ? Math.min(...sens.map((f) => f.effLine)) : null;
  const kinds = dim === 'ownership' ? ['ownership'] : [dim];
  const ctl = facts.filter((f) => f.category === 'control' && kinds.includes(f.kind) && (first === null || f.effLine < first || (f.basis === 'query-filter' && f.effLine <= first)));
  if (ctl.length) return { state: 'enforced', evidence: ctl.slice(0, 3).map((f) => ({ file: f.file, line: f.line, basis: f.basis, evidence: f.evidence })) };
  const prot = bundle.manifest?.protection?.[dim === 'tenant-scope' ? 'ownership' : dim];
  if (prot && prot.state === 'present' && dim !== 'tenant-scope' && dim !== 'ownership') return { state: 'enforced', evidence: prot.evidence || [] };
  const unresolved = (bundle.manifest?.unknowns || []).some((u) => u.material) || bundle.reach?.capped || prot?.state === 'not_resolved' || prot?.state === 'omitted_due_to_budget';
  return unresolved ? { state: 'unknown' } : { state: 'absent' };
}

/**
 * @param {{entrypoint:object, manifest:object, reach:object}[]} bundles
 * @param {{invariants?:object, now?:Date}} [opts] an invariants document: its public-by-design waivers suppress findings
 */
export function findCrossRouteInconsistencies(bundles, opts = {}) {
  const now = opts.now || new Date();
  const built = bundles.filter((b) => b.manifest && b.reach);
  const byResource = new Map();
  let unnamed = 0;
  for (const b of built) {
    const sens = (b.reach.facts || []).filter((f) => f.category === 'sensitive' && String(f.kind).startsWith('data-'));
    const touched = new Map();
    for (const f of sens) {
      const key = resourceKey(f.text);
      if (!key) { unnamed++; continue; }
      if (!touched.has(key)) touched.set(key, new Set());
      touched.get(key).add(operationOf(f));
    }
    for (const [key, ops] of touched) {
      if (!byResource.has(key)) byResource.set(key, []);
      byResource.get(key).push({ bundle: b, ops: [...ops].sort() });
    }
  }
  const findings = []; const suppressed = []; const unknown = [];
  const waiver = (b, dim) => {
    if (!opts.invariants) return null;
    const r = evaluateInvariants({ ...opts.invariants, invariants: [...opts.invariants.invariants, { id: 'PROBE-DIM', title: 'probe', rule: 'requires', appliesTo: { routes: ['**'] }, requires: [dim] }] }, [b], { now });
    const probe = r.results.find((x) => x.invariantId === 'PROBE-DIM');
    return probe && probe.verdict === 'public_by_policy' ? probe.waivedBy : null;
  };
  for (const [resource, entries] of [...byResource].sort(([a], [c]) => (a < c ? -1 : 1))) {
    const routes = [...new Map(entries.map((e) => [e.bundle.entrypoint.id, e])).values()];
    if (routes.length < 2) continue;
    for (const dim of CONSISTENCY_DIMENSIONS) {
      const states = routes.map((r) => ({ r, ...stateOf(r.bundle, dim) }));
      const enforced = states.filter((s) => s.state === 'enforced');
      if (!enforced.length) continue;
      for (const s of states) {
        if (s.state === 'enforced') continue;
        const ep = s.r.bundle.entrypoint;
        const base = { resource, dimension: dim, route: ep.label, file: ep.rootSpan?.file || ep.registrationSite?.file || '', operations: s.r.ops, enforcedAt: enforced.map((e) => ({ route: e.r.bundle.entrypoint.label, operations: e.r.ops, evidence: e.evidence })) };
        if (s.state === 'unknown') { unknown.push({ ...base, reason: 'an unresolved call or a traversal limit could hide the control; dynamic dispatch is not proof of absence' }); continue; }
        const w = waiver(s.r.bundle, dim);
        if (w) { suppressed.push({ ...base, waivedBy: w, reason: 'declared public-by-design for this control' }); continue; }
        const klass = dim === 'tenant-scope' ? 'cross-tenant' : dim === 'ownership' ? 'idor' : 'missing-control';
        findings.push({ id: `xroute:${resource}:${dim}:${ep.id}`, class: klass, ...base, confidence: 'inconsistency', explanation: `${enforced.map((e) => e.r.bundle.entrypoint.label).join(', ')} enforce ${dim} on ${resource}; ${ep.label} (${s.r.ops.join('/')}) does not` });
      }
    }
  }
  findings.sort((a, b) => (a.id < b.id ? -1 : 1));
  return { findings, suppressed, unknown, resourcesCompared: [...byResource].filter(([, e]) => new Set(e.map((x) => x.bundle.entrypoint.id)).size >= 2).map(([k]) => k).sort(), operationsWithoutResource: unnamed };
}
