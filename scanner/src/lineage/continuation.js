// continuation.js: resumable path queries (DAG-07 R07.9).
//
// A path query that stopped at a budget leaves a frontier. This module keeps
// that frontier in memory under an opaque token so the next page can pick up
// where the previous one stopped, instead of repeating the work.
//
// Resume is a convenience and never a source of soundness:
//   - a token is bound to the EXACT graph digest and to the digest of the
//     query configuration it was issued under; a different graph or a
//     different configuration is rejected, never silently re-based;
//   - tokens expire (TTL) and the store is bounded in entries and bytes, so a
//     client cannot make it grow without limit; the oldest token is evicted
//     first and an evicted token reports `evicted`, never a wrong answer;
//   - a resumed page is always marked `resumed` and can never license a
//     negative claim (path-query.js enforces that), so partial results stay
//     partial however many times they are resumed.

import { createHash, randomBytes } from 'node:crypto';
import { reconstructPaths, DEFAULTS } from './path-query.js';

export const CONTINUATION_DEFAULTS = Object.freeze({
  maxEntries: 64,
  maxBytes: 64 * 1024 * 1024,
  ttlMs: 10 * 60 * 1000,
});

function stableJson(v) {
  if (Array.isArray(v)) return `[${v.map(stableJson).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableJson(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

/** Digest of the query configuration that affects results (budgets and start). */
export function configDigest(startNodeId, opts = {}) {
  const budget = {};
  for (const k of Object.keys(DEFAULTS)) budget[k] = opts[k] ?? DEFAULTS[k];
  return createHash('sha256').update(stableJson({ startNodeId, budget })).digest('hex');
}

function approxBytes(state) {
  // Frames and edges are small objects; a coarse, deliberately generous estimate.
  return 256 + (state.stack?.length ?? 0) * 160 + (state.edgesRev?.length ?? 0) * 320 + (state.nodesRev?.length ?? 0) * 96;
}

export class ContinuationStore {
  constructor(limits = {}) {
    const pick = (k) => (Number.isInteger(limits[k]) && limits[k] > 0 ? limits[k] : CONTINUATION_DEFAULTS[k]);
    this.limits = { maxEntries: pick('maxEntries'), maxBytes: pick('maxBytes'), ttlMs: pick('ttlMs') };
    this._now = typeof limits.now === 'function' ? limits.now : Date.now;
    this._entries = new Map(); // token -> {graphDigest, configDigest, state, bytes, expiresAt}
    this._evicted = new Set();
    this._bytes = 0;
  }

  size() { return this._entries.size; }
  bytes() { return this._bytes; }

  _drop(token, evicted) {
    const e = this._entries.get(token);
    if (!e) return;
    this._bytes -= e.bytes;
    this._entries.delete(token);
    if (evicted) {
      this._evicted.add(token);
      if (this._evicted.size > 1024) this._evicted.delete(this._evicted.values().next().value);
    }
  }

  _sweep() {
    const now = this._now();
    for (const [t, e] of this._entries) if (e.expiresAt <= now) this._drop(t, false);
  }

  /** Store a frontier. Returns {ok, token} or {ok:false, reason:'too-large'}. */
  issue({ graphDigest, configDigest: cfg, state }) {
    this._sweep();
    const bytes = approxBytes(state);
    if (bytes > this.limits.maxBytes) return { ok: false, reason: 'too-large' };
    while (this._entries.size >= this.limits.maxEntries || this._bytes + bytes > this.limits.maxBytes) {
      const oldest = this._entries.keys().next().value;
      if (oldest === undefined) break;
      this._drop(oldest, true);
    }
    const token = `cont:${randomBytes(12).toString('hex')}`;
    this._entries.set(token, { graphDigest, configDigest: cfg, state, bytes, expiresAt: this._now() + this.limits.ttlMs });
    this._bytes += bytes;
    return { ok: true, token };
  }

  /**
   * Redeem a token against the CURRENT graph and configuration digests.
   * One-shot: a successful redeem removes the entry (the next page issues a
   * new token), so a token cannot be replayed to fork the frontier.
   */
  redeem(token, { graphDigest, configDigest: cfg }) {
    this._sweep();
    const e = this._entries.get(token);
    if (!e) return { ok: false, reason: this._evicted.has(token) ? 'evicted' : 'unknown-or-expired' };
    if (e.graphDigest !== graphDigest) return { ok: false, reason: 'graph-changed' };
    if (e.configDigest !== cfg) return { ok: false, reason: 'config-changed' };
    this._drop(token, false);
    return { ok: true, state: e.state };
  }
}

/**
 * Run (or resume) a path query. `continuationToken` in `opts` resumes.
 * Returns the reconstructPaths result plus `continuation`:
 * { token|null, rejected: reason|null }. A token is issued only when the
 * query stopped with work left.
 */
export function queryWithContinuation(store, continuations, startNodeId, opts = {}) {
  const { continuationToken, ...queryOpts } = opts;
  const graphDigest = store.digest();
  const cfg = configDigest(startNodeId, queryOpts);
  let resumeState;
  if (continuationToken !== undefined) {
    const r = continuations.redeem(continuationToken, { graphDigest, configDigest: cfg });
    if (!r.ok) {
      // Rejected: report invalid, never fall back to a fresh query that
      // would look like the continuation worked.
      return {
        status: 'invalid', paths: [], truncated: true, truncationReasons: [], negativeClaimAllowed: false,
        budgetErrors: [`continuation rejected: ${r.reason}`],
        continuation: { token: null, rejected: r.reason },
      };
    }
    resumeState = r.state;
  }
  const result = reconstructPaths(store, startNodeId, { ...queryOpts, ...(resumeState ? { resumeState } : {}) });
  let token = null;
  let note = null;
  if (result.resumeState) {
    const issued = continuations.issue({ graphDigest, configDigest: cfg, state: result.resumeState });
    if (issued.ok) token = issued.token; else note = issued.reason;
    delete result.resumeState;
  }
  result.continuation = { token, rejected: null, ...(note ? { notIssued: note } : {}) };
  return result;
}
