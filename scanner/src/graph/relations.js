//
// relations.js: relation kinds and the traversal filter (DAG-06 R06.3, R06.4).
//
// Two independent axes, never collapsed into one:
//   - RELATION: what the edge means (data flow, calls, ...).
//   - ORIGIN: how the edge came to exist (derived from code, declared by an
//     operator, observed at runtime, ...).
//
// A query chooses the relations it may traverse AND the origins it trusts.
// The default filter traverses code-derived and derived edges only, so an
// operator declaration or a runtime observation is never silently walked as
// if it were a code-derived data flow (R06.4).

import { GraphViewError } from './refs.js';

export const RELATION_KINDS = Object.freeze([
  'data_flow',            // a value moves from one place to another
  'control_dependence',   // execution of B depends on a decision at A
  'calls',                // a call site invokes a callee
  'returns',              // a callee result comes back to a caller
  'dependency',           // A needs B (package, module, component)
  'declaration',          // A declares/contains B (symbol -> call site, origin)
  'observation',          // a runtime observation attached to an entity
  'artifact_derivation',  // A was built into / produced B
]);

export const EDGE_ORIGINS = Object.freeze([
  'code',      // read directly from analyzed source
  'derived',   // computed from code-derived facts by a projection or index
  'declared',  // asserted by an operator (cross-repo links, deployments)
  'observed',  // seen at runtime (telemetry)
  'schema',    // taken from a schema or manifest
]);

/** Origins a default query trusts as "the program's own structure". */
export const DEFAULT_TRUSTED_ORIGINS = Object.freeze(['code', 'derived', 'schema']);

/**
 * Normalize a relation filter. Accepted forms:
 *   undefined / null          -> every relation, trusted origins only
 *   'calls' | ['calls', ...]  -> those relations, trusted origins only
 *   { relations, origins }    -> explicit on both axes
 * Unknown relation or origin names throw, so a typo never silently widens
 * or empties a query.
 */
export function normalizeFilter(filter) {
  let relations = null;
  let origins = DEFAULT_TRUSTED_ORIGINS;
  if (filter === undefined || filter === null) {
    // defaults
  } else if (typeof filter === 'string') {
    relations = [filter];
  } else if (Array.isArray(filter)) {
    relations = filter;
  } else if (typeof filter === 'object') {
    if (filter.relations !== undefined && filter.relations !== null) {
      relations = typeof filter.relations === 'string' ? [filter.relations] : filter.relations;
    }
    if (filter.origins !== undefined && filter.origins !== null) {
      origins = typeof filter.origins === 'string' ? [filter.origins] : filter.origins;
    }
  } else {
    throw new GraphViewError('BAD_FILTER', 'a relation filter is a name, a list of names or { relations, origins }');
  }
  if (relations !== null) {
    if (!Array.isArray(relations)) throw new GraphViewError('BAD_FILTER', 'relations must be a list');
    for (const r of relations) {
      if (!RELATION_KINDS.includes(r)) throw new GraphViewError('BAD_FILTER', `unknown relation kind ${JSON.stringify(r)}`);
    }
  }
  if (!Array.isArray(origins)) throw new GraphViewError('BAD_FILTER', 'origins must be a list');
  for (const o of origins) {
    if (!EDGE_ORIGINS.includes(o)) throw new GraphViewError('BAD_FILTER', `unknown edge origin ${JSON.stringify(o)}`);
  }
  return { relations: relations ? new Set(relations) : null, origins: new Set(origins) };
}

export function edgeMatches(edge, nf) {
  if (nf.relations && !nf.relations.has(edge.relation)) return false;
  return nf.origins.has(edge.origin);
}
