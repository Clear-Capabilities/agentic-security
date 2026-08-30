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
    if (candidatePath !== path && pathIsCoveredByPrefix(path, candidatePath)) {
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
