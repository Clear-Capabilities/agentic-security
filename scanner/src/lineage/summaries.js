import { hashState, emptyState, addIdentity } from './field-identity.js';
import { resolveExprIdentities, residualFlat } from './engine.js';
import { accessPathOf } from '../dataflow/access-paths.js';

export function emptyFieldSummary() {
  return { returnFlat: new Set(), returnByPath: new Map(), mutatedParams: new Map(), widenings: [] };
}

const DEFAULT_MAX_CONTEXTS = 16; // matches dataflow/summaries.js's own default, chosen independently for this
                                  // package (a lineage-specific cap, not shared config, per the isolation
                                  // principle — see the constructor param below for how a caller can override it)

export class FieldIdentitySummaryCache {
  constructor(maxContextsPerFn = DEFAULT_MAX_CONTEXTS) {
    this._cache = new Map();
    this._stack = new Set();
    this._contextsByQid = new Map();
    this._maxContextsPerFn = maxContextsPerFn;
  }

  _key(qid, entryState) {
    return `${qid}::${hashState(entryState)}`;
  }

  has(qid, entryState) {
    return this._cache.has(this._key(qid, entryState));
  }

  get(qid, entryState) {
    return this._cache.get(this._key(qid, entryState));
  }

  set(qid, entryState, summary) {
    this._cache.set(this._key(qid, entryState), summary);
    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    seen.add(hash);
    this._contextsByQid.set(qid, seen);
  }

  compute(qid, entryState, analyzeFn) {
    if (this.has(qid, entryState)) return this.get(qid, entryState);

    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    if (!seen.has(hash) && seen.size >= this._maxContextsPerFn) {
      // Past this function's distinct-context cap: degrade to the
      // empty-entry summary (if one exists) rather than computing an
      // unbounded number of contexts. Mirrors
      // dataflow/summaries.js's own graceful degradation past its own cap.
      const fallback = this._cache.get(this._key(qid, emptyState())) ?? emptyFieldSummary();
      this.set(qid, entryState, fallback);
      return fallback;
    }

    if (this._stack.has(qid)) {
      // Recursion guard, THIS INCREMENT'S SCOPE: return a bottom stub
      // immediately, never recurse further, and do NOT attempt any
      // fixed-point refinement here — that precision improvement is
      // increment B5's job. This guard's only job in B1 is safety (never
      // infinite-loop on a hand-built recursive call graph), not
      // precision. A caller receiving `_recursive: true` knows this
      // summary may under-approximate the function's real behavior.
      return { ...emptyFieldSummary(), _recursive: true };
    }

    this._stack.add(qid);
    const summary = analyzeFn(entryState);
    this.set(qid, entryState, summary);
    this._stack.delete(qid);
    return summary;
  }

  size() {
    return this._cache.size;
  }

  clear() {
    this._cache.clear();
    this._stack.clear();
    this._contextsByQid.clear();
  }
}

// Maps a call site's argument expressions onto a fresh entry state for the
// callee, keyed by the callee's own parameter names — the interprocedural
// analog of `engine.js`'s `assign` transfer function: each argument is
// resolved against the CALLER's current state via `resolveExprIdentities`,
// and its residual (root-level) identities plus its byPath (field-level)
// structure are both written into the callee's entry state at the
// corresponding parameter name, using the exact same residual+byPath split
// `assign` already uses — this is a direct, deliberate reuse of Sub-project
// A's already-hardened write pattern, not a new mechanism.
export function entryStateFromCall(paramNames, callArgs, callerState) {
  let entryState = emptyState();
  const n = Math.min(paramNames.length, callArgs.length);
  for (let i = 0; i < n; i++) {
    const paramName = paramNames[i];
    const resolved = resolveExprIdentities(callerState, callArgs[i]);
    const residual = residualFlat(resolved.flat, resolved.byPath);
    for (const id of residual) entryState = addIdentity(entryState, paramName, id);
    for (const [subPath, ids] of resolved.byPath) {
      for (const id of ids) entryState = addIdentity(entryState, `${paramName}.${subPath}`, id);
    }
  }
  return entryState;
}

// Maps a callee's summary back onto the CALLER's own state at the call
// site — the interprocedural analog of reading a function's return value
// and observing its side effects. Unlike dataflow/summaries.js's
// applyAtCallSite (which only propagates a mutation back for a bare
// `ident` argument, silently dropping a `member`-expression argument like
// `f(obj.field)`), this version also resolves a member-expression argument
// via `accessPathOf` — a deliberate, scoped improvement: field mutations
// plausibly target `obj.field`-shaped arguments often enough that
// dropping them silently would be a real, avoidable under-approximation.
export function applyAtCallSite(summary, paramNames, callArgs) {
  const mutations = [];
  for (const [paramPath, ids] of summary.mutatedParams) {
    const [rootParamName, ...rest] = paramPath.split('.');
    const idx = paramNames.indexOf(rootParamName);
    if (idx === -1) continue;
    const arg = callArgs[idx];
    const argPath = accessPathOf(arg);
    if (!argPath) continue;
    const fullPath = rest.length > 0 ? `${argPath}.${rest.join('.')}` : argPath;
    mutations.push({ path: fullPath, dataElementIds: [...ids] });
  }
  return { returnFlat: summary.returnFlat, returnByPath: summary.returnByPath, mutations };
}
