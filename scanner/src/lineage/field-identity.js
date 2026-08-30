import { pathIsCoveredByPrefix } from '../dataflow/access-paths.js';

// State: Map<accessPath: string, Set<dataElementId: string>>. See
// scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md for the full design
// rationale (why this shape instead of dataflow/access-paths.js's
// Set<accessPath>, ancestor/descendant asymmetry, why redundant
// ancestor+descendant entries are an accepted, deferred optimization).

export function emptyState() {
  return new Map();
}

export function identitiesAt(state, path) {
  const result = new Set();
  const exact = state.get(path);
  if (exact) for (const id of exact) result.add(id);
  for (const [candidatePath, ids] of state) {
    if (candidatePath === path) continue;
    // Ancestor coverage (pre-existing): a coarser recorded fact about a
    // container implies the same fact about anything under it, when nothing
    // more specific overrides it.
    // Descendant coverage (NEW, fixing FR-301's real violation — see the
    // "Corrected design" note in DESIGN_INTRAPROCEDURAL.md §3 for the full
    // story): asking about a container AS A WHOLE (e.g. `return rec` after
    // `rec = {email: X, ssn: Y}`) must aggregate everything recorded under
    // it — the object legitimately carries every field's identity. This does
    // NOT reintroduce cross-field leakage: querying `rec.email` never picks
    // up a SIBLING path like `rec.ssn` (neither is a prefix of the other),
    // it only aggregates when you ask about an actual ancestor of both.
    if (pathIsCoveredByPrefix(path, candidatePath) || pathIsCoveredByPrefix(candidatePath, path)) {
      for (const id of ids) result.add(id);
    }
  }
  return result;
}

export function addIdentity(state, path, dataElementId) {
  const current = state.get(path);
  if (current && current.has(dataElementId)) return state;
  const next = new Map(state);
  next.set(path, new Set([...(current ?? []), dataElementId]));
  return next;
}

export function removeIdentitiesAt(state, path) {
  const next = new Map();
  for (const [p, ids] of state) {
    if (p === path || pathIsCoveredByPrefix(p, path)) continue;
    next.set(p, ids);
  }
  return next;
}

export function joinStates(a, b) {
  const next = new Map(a);
  for (const [path, ids] of b) {
    const current = next.get(path);
    next.set(path, current ? new Set([...current, ...ids]) : new Set(ids));
  }
  return next;
}

export function statesEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const [path, ids] of a) {
    const other = b.get(path);
    if (!other || other.size !== ids.size) return false;
    for (const id of ids) if (!other.has(id)) return false;
  }
  return true;
}

export function hashState(state) {
  return [...state.entries()]
    .map(([path, ids]) => `${path}=${[...ids].sort().join(',')}`)
    .sort()
    .join('|');
}
