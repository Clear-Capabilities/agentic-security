//
// crosswalk-builders.js: build the standard crosswalk mappings from registered
// views. Every builder joins on facts the two graphs both carry and records
// the join as evidence; none invents an identity.
//
//   finding -> semantic call site       file + line (location-exact)
//   call site -> provenance witnesses   enclosing function (qid) + line
//   witness -> projected flow           data element id
//   projected node -> underlying sites  decision kind/category/coverage/externality
//
// Where a join cannot pin one target, the mapping lists ALL candidates
// (one-to-many) and carries an `unknowns` entry. It never picks one silently.

import { canonicalJson } from './refs.js';

const stripLine = (qid) => String(qid).replace(/@\d+$/, '');
const normFile = (f) => String(f ?? '').replace(/^\.\//, '').replace(/\\/g, '/');

/**
 * Join findings to semantic call sites by exact file and line.
 * @returns {object[]} the mappings added
 */
export function mapFindingsToCallSites(crosswalk, findings, semantic) {
  const byLoc = new Map();
  for (const cs of semantic.entities('callSite')) {
    const k = `${normFile(cs.native.file)}:${cs.native.line}`;
    if (!byLoc.has(k)) byLoc.set(k, []);
    byLoc.get(k).push(cs);
  }
  const added = [];
  for (const f of findings.entities('finding')) {
    const { file, line } = f.native;
    if (!Number.isInteger(line) || !file) {
      added.push(crosswalk.add({
        type: 'finding-to-callsite', from: f.ref, to: [], unmapped: 'finding-has-no-file-and-line',
        evidence: { method: 'file-line', grade: 'none', basis: 'the finding carries no integer line, so it cannot be located' },
      }));
      continue;
    }
    const hits = byLoc.get(`${normFile(file)}:${line}`) ?? [];
    if (hits.length === 0) continue; // not a call-site finding; absence is visible as a trace gap
    added.push(crosswalk.add({
      type: 'finding-to-callsite', from: f.ref, to: hits.map((h) => h.ref), coarsens: hits.length > 1,
      evidence: { method: 'file-line', grade: hits.length === 1 ? 'location-exact' : 'location-ambiguous', basis: `${normFile(file)}:${line}` },
      unknowns: hits.length > 1 ? [{ kind: 'ambiguous-location', count: hits.length, reason: 'several call sites share this line; the finding names a line, not a call' }] : [],
    }));
  }
  return added;
}

/**
 * Join semantic call sites to provenance witnesses (pedges): same enclosing
 * function and same line. The provenance scope is `<qid>@<line>`; the semantic
 * symbol carries the qid without the line suffix.
 */
export function mapCallSitesToWitnesses(crosswalk, semantic, provenance) {
  const witnessByKey = new Map();
  for (const w of provenance.entities('pedge')) {
    const k = `${stripLine(w.native.scope)}\u0000${w.native.line}`;
    if (!witnessByKey.has(k)) witnessByKey.set(k, []);
    witnessByKey.get(k).push(w);
  }
  const symQid = new Map(semantic.entities('symbol').map((s) => [s.localId, s.native.qid]));
  const sitesPerKey = new Map();
  const keyOf = (cs) => `${symQid.get(cs.native.caller)}\u0000${cs.native.line}`;
  const sites = semantic.entities('callSite');
  for (const cs of sites) sitesPerKey.set(keyOf(cs), (sitesPerKey.get(keyOf(cs)) ?? 0) + 1);
  const added = [];
  for (const cs of sites) {
    const hits = witnessByKey.get(keyOf(cs)) ?? [];
    if (hits.length === 0) continue;
    const shared = sitesPerKey.get(keyOf(cs));
    added.push(crosswalk.add({
      type: 'callsite-to-witness', from: cs.ref, to: hits.map((h) => h.ref), coarsens: hits.length > 1 || shared > 1,
      evidence: { method: 'scope-line', grade: shared > 1 ? 'location-ambiguous' : 'location-exact', basis: `${symQid.get(cs.native.caller)} line ${cs.native.line}` },
      unknowns: shared > 1 ? [{ kind: 'shared-line', callSites: shared, reason: 'provenance records a line, not a call; these witnesses cannot be pinned to one of the call sites on that line' }] : [],
    }));
  }
  return added;
}

/**
 * Join provenance witnesses to the projected flows that carry their data
 * element. A flow aggregates many witnesses (and many sites), so every mapping
 * is flagged `coarsens`.
 */
export function mapWitnessesToFlows(crosswalk, provenance, dataflow) {
  const flowsByDe = new Map();
  for (const fl of dataflow.entities('flow')) {
    for (const de of fl.native.dataElementIds || []) {
      if (!flowsByDe.has(de)) flowsByDe.set(de, []);
      flowsByDe.get(de).push(fl);
    }
  }
  const added = [];
  for (const w of provenance.entities('pedge')) {
    const hits = flowsByDe.get(w.native.dataElementId) ?? [];
    if (hits.length === 0) continue;
    added.push(crosswalk.add({
      type: 'witness-to-flow', from: w.ref, to: hits.map((h) => h.ref), coarsens: true,
      evidence: { method: 'data-element', grade: 'identity-shared', basis: w.native.dataElementId },
      unknowns: [{ kind: 'flow-granularity', reason: 'a projected flow aggregates every witness of its data element; the flow does not say which site this witness belongs to' }],
    }));
  }
  return added;
}

const calleeText = (e) => {
  if (!e || typeof e !== 'object') return null;
  if (e.kind === 'ident') return e.name;
  if (e.kind === 'member') { const o = calleeText(e.object); return o ? `${o}.${e.prop ?? '[]'}` : null; }
  return null;
};

/**
 * Map each projected (category-granular) dataflow node to the underlying call
 * sites it stands for. `sites` is the sink-site list `buildDataFlowGraph`
 * returns. A node with several sites maps one-to-many and is flagged `coarsens`;
 * a site that no semantic call site matches is listed under `unknowns`.
 */
export function mapProjectedNodesToSites(crosswalk, dataflow, semantic, sites) {
  const callSites = semantic.entities('callSite');
  const added = [];
  for (const n of dataflow.entities('node')) {
    const node = n.native;
    const matching = (sites || []).filter((s) => s.decision
      && s.decision.kind === node.kind
      && (s.decision.category ?? null) === (node.subtype ?? null)
      && s.decision.coverageStatus === node.coverageStatus
      && s.decision.externality === node.externality?.value
      && canonicalJson(s.destination ?? null) === canonicalJson(node.destination ?? null));
    if (matching.length === 0) continue;
    const targets = new Map();
    const unmapped = [];
    for (const s of matching) {
      const atLine = callSites.filter((c) => normFile(c.native.file) === normFile(s.file) && c.native.line === s.line);
      const want = calleeText(s.calleeExpr);
      const exact = want ? atLine.filter((c) => c.native.calleeText === want) : [];
      const picked = exact.length ? exact : atLine;
      if (picked.length === 0) unmapped.push({ file: s.file, line: s.line, reason: 'no semantic call site at this location' });
      for (const c of picked) targets.set(c.localId, c);
    }
    const to = [...targets.values()].map((c) => c.ref);
    const unknowns = unmapped.map((u) => ({ kind: 'unmapped-site', ...u }));
    if (to.length === 0) continue;
    added.push(crosswalk.add({
      type: 'node-to-sites', from: n.ref, to, coarsens: to.length > 1, unknowns,
      evidence: { method: 'decision-match', grade: to.length === 1 ? 'projection-exact' : 'projection-coarse', basis: `${node.kind}/${node.subtype ?? 'none'}: ${matching.length} sink site(s)` },
    }));
  }
  return added;
}
