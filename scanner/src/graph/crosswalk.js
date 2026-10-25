//
// crosswalk.js: evidence-bearing identity mappings between graph layers
// (DAG-06 R06.2, R06.5).
//
// A crosswalk never merges entities. It records "this entity in graph A
// corresponds to these entities in graph B, by this method, with this
// evidence". Every mapping is:
//   - versioned (CROSSWALK_VERSION);
//   - explicit about cardinality (`one-to-one`, `one-to-many`, or `none` with a
//     stated reason), so a projection that coarsens many underlying sites into
//     one projected node says so instead of pretending to be one-to-one;
//   - evidence-bearing: method, grade and basis are required;
//   - checked against the registry when one is supplied: a reference to a graph
//     or entity that is not registered is rejected as DANGLING_REF.
//
// Mapping types and the graph layers each connects:
//   finding-to-callsite   findings        -> semantic     (location join)
//   callsite-to-witness   semantic        -> provenance   (scope + line join)
//   witness-to-flow       provenance      -> dataflow     (data element join)
//   node-to-sites         dataflow node   -> semantic     (a projected node's underlying call sites)
//   identity              same layer      -> same layer   (the same entity under another reference)
//
// `identity` mappings are only legal inside ONE repository. Declaring two
// entities in different repositories "the same" because their local ids match
// is exactly the collision this module exists to prevent, and is rejected as
// CROSS_REPO_ID_COLLISION.

import { createHash } from 'node:crypto';
import { GraphViewError, validateRef, refKey, canonicalJson } from './refs.js';

export const CROSSWALK_VERSION = '1.0.0';

export const MAPPING_TYPES = Object.freeze({
  'finding-to-callsite': { from: { graphKind: 'findings', entityKind: 'finding' }, to: { graphKind: 'semantic', entityKind: 'callSite' } },
  'callsite-to-witness': { from: { graphKind: 'semantic', entityKind: 'callSite' }, to: { graphKind: 'provenance', entityKind: 'pedge' } },
  'witness-to-flow': { from: { graphKind: 'provenance', entityKind: 'pedge' }, to: { graphKind: 'dataflow', entityKind: 'flow' } },
  'node-to-sites': { from: { graphKind: 'dataflow', entityKind: 'node' }, to: { graphKind: 'semantic', entityKind: 'callSite' } },
  identity: { from: null, to: null },
});

const CARDINALITY = (n) => (n === 0 ? 'none' : n === 1 ? 'one-to-one' : 'one-to-many');

function checkEnd(ref, want, label, type) {
  const bad = validateRef(ref);
  if (bad) throw new GraphViewError('BAD_REF', `${type} ${label}: ${bad}`, { ref });
  if (want && (ref.graphKind !== want.graphKind || ref.entityKind !== want.entityKind)) {
    throw new GraphViewError('BAD_MAPPING', `${type} ${label} must be a ${want.graphKind} ${want.entityKind}, got ${ref.graphKind} ${ref.entityKind}`, { ref });
  }
}

export function createCrosswalk({ registry = null } = {}) {
  const mappings = new Map();   // id -> record
  const forward = new Map();    // refKey -> record[]
  const reverse = new Map();    // refKey -> record[]
  const push = (m, k, r) => { const a = m.get(k); if (a) a.push(r); else m.set(k, [r]); };

  function add(spec) {
    const type = spec?.type;
    const desc = MAPPING_TYPES[type];
    if (!desc) throw new GraphViewError('BAD_MAPPING', `unknown mapping type ${JSON.stringify(type)}`);
    checkEnd(spec.from, desc.from, 'from', type);
    if (!Array.isArray(spec.to)) throw new GraphViewError('BAD_MAPPING', `${type}: "to" is a list (empty with an unmapped reason when nothing matched)`);
    for (const t of spec.to) checkEnd(t, desc.to, 'to', type);

    const ev = spec.evidence;
    if (!ev || typeof ev.method !== 'string' || !ev.method || typeof ev.grade !== 'string' || !ev.grade || typeof ev.basis !== 'string' || !ev.basis) {
      throw new GraphViewError('BAD_MAPPING', `${type}: evidence needs { method, grade, basis }`);
    }
    const keys = spec.to.map(refKey);
    if (new Set(keys).size !== keys.length) throw new GraphViewError('BAD_MAPPING', `${type}: duplicate targets in one mapping`);
    if (spec.to.length === 0 && !spec.unmapped) throw new GraphViewError('BAD_MAPPING', `${type}: an empty mapping must say why in "unmapped"`);

    if (type === 'identity') {
      for (const t of spec.to) {
        if (t.repository !== spec.from.repository) {
          throw new GraphViewError('CROSS_REPO_ID_COLLISION', `identity mapping between repositories ${spec.from.repository} and ${t.repository} refused: matching local ids do not make two entities the same`, { from: spec.from, to: t });
        }
        if (t.entityKind !== spec.from.entityKind || t.graphKind !== spec.from.graphKind) {
          throw new GraphViewError('BAD_MAPPING', 'identity maps an entity to the same kind of entity');
        }
      }
    }
    if (registry) {
      for (const r of [spec.from, ...spec.to]) {
        if (!registry.has(r)) throw new GraphViewError('DANGLING_REF', `${type}: ${r.graphKind} ${r.entityKind} ${r.localId} (repository ${r.repository}) is not in a registered graph`, { ref: r });
      }
    }

    const id = `xwalk:${createHash('sha256').update(canonicalJson([type, refKey(spec.from), [...keys].sort(), ev.method])).digest('hex').slice(0, 16)}`;
    if (mappings.has(id)) return mappings.get(id);
    const record = Object.freeze({
      id, version: CROSSWALK_VERSION, type, from: spec.from, to: Object.freeze([...spec.to]),
      cardinality: CARDINALITY(spec.to.length),
      coarsens: !!spec.coarsens,
      evidence: Object.freeze({ ...ev }),
      unknowns: Object.freeze([...(spec.unknowns ?? [])]),
      unmapped: spec.unmapped ?? null,
    });
    mappings.set(id, record);
    push(forward, refKey(record.from), record);
    for (const k of keys) push(reverse, k, record);
    return record;
  }

  const ofType = (list, type) => (type ? list.filter((m) => m.type === type) : list);

  return {
    version: CROSSWALK_VERSION,
    add,
    all: () => [...mappings.values()],
    /** Mappings that start at `ref`. */
    from: (ref, type) => ofType(forward.get(refKey(ref)) ?? [], type),
    /** Mappings that end at `ref` (the reverse direction; many sources may share a target). */
    to: (ref, type) => ofType(reverse.get(refKey(ref)) ?? [], type),

    /**
     * Follow a chain of mapping types from `start`. Returns every chain found
     * and, for each step, which references had NO mapping (a gap is reported,
     * never skipped). `evidence` lists every mapping used, so the join is
     * traceable end to end.
     */
    trace(start, types, { maxChains = 1000 } = {}) {
      let chains = [{ refs: [start], mappings: [] }];
      const gaps = [];
      let truncated = false;
      for (const type of types) {
        const next = [];
        for (const c of chains) {
          const last = c.refs[c.refs.length - 1];
          const ms = this.from(last, type);
          if (ms.length === 0) { gaps.push({ type, ref: last }); continue; }
          for (const m of ms) {
            if (m.to.length === 0) { gaps.push({ type, ref: last, unmapped: m.unmapped, mapping: m.id }); continue; }
            for (const t of m.to) {
              if (next.length >= maxChains) { truncated = true; break; }
              next.push({ refs: [...c.refs, t], mappings: [...c.mappings, m.id] });
            }
          }
        }
        chains = next;
      }
      const used = new Set(chains.flatMap((c) => c.mappings));
      return { start, types: [...types], chains, gaps, truncated, evidence: [...used].map((id) => mappings.get(id)) };
    },
  };
}
