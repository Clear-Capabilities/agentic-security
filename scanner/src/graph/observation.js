//
// observation.js: attributing a runtime observation to the underlying sites of
// a projected node (DAG-06 acceptance: "a projected node with several
// underlying sites cannot falsely assign one runtime observation to every
// site").
//
// A runtime observation is matched to a PROJECTED node (a destination, store or
// queue). When that node stands for several call sites (a `node-to-sites`
// mapping with more than one target), the observation says nothing about which
// site produced it unless it carries its own discriminator. The result is:
//
//   attributed  exactly one site is justified: the node has a single site, or
//               the observation names a site (`file` + `line`, or a call-site
//               id) that matches exactly one candidate.
//   ambiguous   several candidates remain. `attributedTo` is EMPTY, every
//               candidate is listed, and no site receives the observation.
//   unmatched   the observation names a site that is not one of the candidates.
//
// "Observed" is therefore a property of the projected node unless a site is
// positively identified. An observation is never copied onto each site.

import { refKey } from './refs.js';

/**
 * @param {object} crosswalk
 * @param {object} registry
 * @param {object} nodeRef  ref to the projected dataflow node the observation matched
 * @param {{file?:string, line?:number, callSiteId?:string}} [observation]
 */
export function attributeObservation(crosswalk, registry, nodeRef, observation = {}) {
  const mappings = crosswalk.from(nodeRef, 'node-to-sites');
  const candidates = [];
  const seen = new Set();
  for (const m of mappings) for (const t of m.to) if (!seen.has(refKey(t))) { seen.add(refKey(t)); candidates.push(t); }
  const base = { node: nodeRef, candidates, mappings: mappings.map((m) => m.id) };

  if (candidates.length === 0) {
    return { ...base, status: 'unmatched', attributedTo: [], reason: 'the projected node has no recorded underlying sites' };
  }
  const normFile = (f) => String(f ?? '').replace(/^\.\//, '');
  const hasDiscriminator = observation.callSiteId || (observation.file && Number.isInteger(observation.line));
  if (hasDiscriminator) {
    const hit = candidates.filter((c) => {
      if (observation.callSiteId) return c.localId === observation.callSiteId;
      const n = registry.node(c).native;
      return normFile(n.file) === normFile(observation.file) && n.line === observation.line;
    });
    if (hit.length === 1) return { ...base, status: 'attributed', attributedTo: hit, basis: 'observation-names-site' };
    if (hit.length === 0) return { ...base, status: 'unmatched', attributedTo: [], reason: 'the observation names a site that is not one of the node\'s underlying sites' };
    return { ...base, status: 'ambiguous', attributedTo: [], candidates: hit, reason: 'several call sites share the named location' };
  }
  if (candidates.length === 1) return { ...base, status: 'attributed', attributedTo: candidates, basis: 'sole-underlying-site' };
  return {
    ...base, status: 'ambiguous', attributedTo: [],
    reason: `the projected node stands for ${candidates.length} sites and the observation does not say which one produced it`,
  };
}
