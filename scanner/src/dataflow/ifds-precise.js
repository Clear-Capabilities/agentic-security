// IFDS-precise extensions — Recommendation #2 of the world-class roadmap.
//
// The existing scanner/src/dataflow/ifds.js implements the core IFDS
// worklist algorithm with k=1 summarized return-taint. This module adds
// the three world-class pieces still missing:
//
//   1. Per-call-site summary REFINEMENT — instead of "this function
//      returns tainted unconditionally," cache "returns tainted under
//      entry state X" so the same callee at different sites uses
//      different summaries.
//   2. On-demand BACKWARD SLICING for high-confidence findings —
//      starting from a critical sink, walk backwards through the
//      use-def chain and emit a minimal trace that explains exactly
//      which lines contribute taint.
//   3. PERSISTENT cross-scan summary cache — write the summary table
//      to .agentic-security/ifds-summaries.json after each scan and
//      reload on the next scan. Skip re-analysis of unchanged
//      functions (incremental analysis).
//
// Opt-in via AGENTIC_SECURITY_IFDS_PRECISE=1 alongside the existing
// AGENTIC_SECURITY_DEEP=1.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import { statePath, safeWriteState, stateWritesEnabled } from '../posture/state-dir.js';
// ── Per-call-site refined summaries ────────────────────────────────────────

/**
 * RefinedSummaryCache — extends the base summary cache with per-entry-state
 * refinement. Whereas the base cache stores ONE summary per function under
 * empty entry state, this layer caches a MAP of (entryStateHash → summary)
 * per function.
 *
 * The intent: at call site A→B(x), the entry state captures which of B's
 * formal parameters are tainted by A's actual argument expressions. If x
 * is tainted at site 1 but not at site 2, we cache TWO summaries for B,
 * and the caller's worklist consults the right one.
 *
 * Capped at MAX_REFINEMENTS_PER_FN to keep cache size bounded.
 */
const MAX_REFINEMENTS_PER_FN = 4;

export class RefinedSummaryCache {
  constructor(baseCache, opts = {}) {
    this._base = baseCache;
    this._refinements = new Map();              // qid → Map<stateHash, summary>
    this._lru = new Map();                      // qid → array (recency)
    this.maxPerFn = opts.maxPerFn || MAX_REFINEMENTS_PER_FN;
    this.metrics = { refinementHits: 0, refinementMisses: 0, refinementEvictions: 0 };
  }

  _hash(entryState) {
    if (!entryState) return '∅';
    if (entryState instanceof Set) {
      if (entryState.size === 0) return '∅';
      return [...entryState].sort().join('|');
    }
    if (Array.isArray(entryState)) {
      if (entryState.length === 0) return '∅';
      return entryState.slice().sort().join('|');
    }
    if (typeof entryState === 'object') {
      // Object keyed by parameter index → tainted bool.
      const keys = Object.keys(entryState).sort();
      return keys.map(k => `${k}=${entryState[k] ? 1 : 0}`).join(',') || '∅';
    }
    return String(entryState);
  }

  get(qid, entryState) {
    const h = this._hash(entryState);
    const m = this._refinements.get(qid);
    if (m && m.has(h)) {
      this._touch(qid, h);
      this.metrics.refinementHits++;
      return m.get(h);
    }
    // Fallback to base for empty entry state (matches k=1 behavior).
    if (this._base && typeof this._base.get === 'function') {
      const v = this._base.get(qid, entryState);
      if (v) return v;
    }
    this.metrics.refinementMisses++;
    return undefined;
  }

  store(qid, entryState, summary) {
    const h = this._hash(entryState);
    let m = this._refinements.get(qid);
    let order = this._lru.get(qid);
    if (!m) { m = new Map(); this._refinements.set(qid, m); }
    if (!order) { order = []; this._lru.set(qid, order); }
    if (!m.has(h)) {
      while (order.length >= this.maxPerFn) {
        const evict = order.shift();
        m.delete(evict);
        this.metrics.refinementEvictions++;
      }
      order.push(h);
    }
    m.set(h, summary);
    // Also seed base for the empty-entry path.
    if ((entryState instanceof Set && entryState.size === 0) && this._base && typeof this._base.set === 'function') {
      try { this._base.set(qid, new Set(), summary); } catch {}
    }
  }

  _touch(qid, h) {
    const order = this._lru.get(qid);
    if (!order) return;
    const idx = order.indexOf(h);
    if (idx >= 0) { order.splice(idx, 1); order.push(h); }
  }

  size() {
    let n = 0;
    for (const m of this._refinements.values()) n += m.size;
    return n;
  }
}

// ── On-demand backward slicing ─────────────────────────────────────────────

/**
 * backwardSlice(callGraph, finding) — given a finding at a sink, walk
 * backwards through use-def edges to produce a minimal trace explaining
 * each step from source to sink. Returns an array of { line, file,
 * snippet, reason } entries ordered source-first.
 *
 * The traversal is intentionally bounded (depth ≤ MAX_SLICE_DEPTH) and
 * cycle-aware. For very deep flows we emit a `...` elision rather than
 * unbounded growth.
 */
const MAX_SLICE_DEPTH = 16;

export function backwardSlice(callGraph, finding, opts = {}) {
  const seen = new Set();
  const out = [];
  if (!finding) return out;
  let cur = finding.sink || finding;
  let depth = 0;
  while (cur && depth < MAX_SLICE_DEPTH) {
    const key = `${cur.file || finding.file}:${cur.line}`;
    if (seen.has(key)) { out.push({ ...cur, reason: 'cycle-detected' }); break; }
    seen.add(key);
    out.push({
      file: cur.file || finding.file,
      line: cur.line,
      snippet: cur.snippet || cur.expr || null,
      reason: cur.reason || 'use-def-pred',
    });
    cur = cur.predecessor || (callGraph && callGraph.getPred && callGraph.getPred(cur)) || null;
    depth++;
  }
  if (depth >= MAX_SLICE_DEPTH) out.push({ reason: 'slice-depth-cap' });
  return out.reverse(); // source-first
}

// ── Persistent cross-scan summary cache ────────────────────────────────────

function _cachePath(scanRoot) {
  return statePath(scanRoot, 'ifds-summaries.json');
}

function _fileHash(content) {
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

/**
 * Load a previously-persisted IFDS summary cache. Returns:
 *   { summaries: Map<qid, summary>, fileHashes: Map<filePath, sha>, scanTs }
 * or null if no persisted cache exists / is unreadable.
 */
export function loadPersistedCache(scanRoot) {
  const fp = _cachePath(scanRoot);
  if (!fs.existsSync(fp)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return {
      summaries: new Map(Object.entries(raw.summaries || {})),
      fileHashes: new Map(Object.entries(raw.fileHashes || {})),
      scanTs: raw.scanTs || null,
    };
  } catch { return null; }
}

/**
 * Persist the current scan's summaries to disk. Subsequent scans can
 * skip re-analysis of functions whose file hash hasn't changed.
 */
export function persistCache(scanRoot, cache, perFileIR) {
  // A read-only scan still ANALYSES; it just may not persist the cache. The
  // next scan simply recomputes, which is slower and identical. (PRD M1)
  if (!stateWritesEnabled()) return;
  const fileHashes = {};
  for (const [filePath, ir] of (perFileIR || new Map())) {
    if (ir && typeof ir._content === 'string') fileHashes[filePath] = _fileHash(ir._content);
  }
  const summaries = {};
  for (const [qid, sum] of (cache._refinements || new Map())) {
    // Serialize only the empty-entry-state summary — the refinements are
    // ephemeral per scan; the empty-entry summary is the stable contract.
    if (sum.has('∅')) summaries[qid] = sum.get('∅');
  }
  const out = { scanTs: new Date().toISOString(), summaries, fileHashes };
  try { safeWriteState(_cachePath(scanRoot), JSON.stringify(out, null, 2)); }
  catch { /* best-effort */ }
}

/**
 * Skip analysis of an unchanged function — when the file containing the
 * function hasn't changed since the last persisted cache, reuse the prior
 * summary.
 */
export function shouldSkipReanalysis(prevCache, filePath, currentContent) {
  if (!prevCache || !prevCache.fileHashes) return false;
  const prevHash = prevCache.fileHashes.get(filePath);
  if (!prevHash) return false;
  return prevHash === _fileHash(currentContent);
}

export const _internals = { _cachePath, _fileHash, MAX_REFINEMENTS_PER_FN, MAX_SLICE_DEPTH };
