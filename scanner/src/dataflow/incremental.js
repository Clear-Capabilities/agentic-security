// Differential / incremental taint (P4.3).
//
// Today every scan re-analyzes every file. On a 100k-LoC monorepo the
// deep-engine pass takes 4-8 minutes. PR-scoped re-analysis should be
// 10-50× faster.
//
// Strategy:
//   1. Persist a SHA-256 of each file's POST-COMMENT-STRIP source under
//      `.agentic-security/incremental/files.json`.
//   2. Persist each function's SUMMARY (returnTainted / mutatedParams /
//      taintedGlobals) keyed by `qid` under
//      `.agentic-security/incremental/summaries.json`.
//   3. On the next scan, diff the file-hash map. For unchanged files,
//      seed the SummaryCache with the persisted summaries.
//   4. For CHANGED files, invalidate their qids' summaries AND the
//      summaries of any function that previously called into them
//      (back-pointer set persisted alongside summaries).
//
// Safety:
//   - The cache invalidates on rule-pack version change (any change to
//     `catalog.js` bumps the rules.lock.json digest).
//   - The cache invalidates on scanner version change.
//   - On any inconsistency (truncated file, JSON parse error), the cache
//     is dropped and we fall back to a full scan.
//
// This module is purely the persistence + invalidation layer. The engine
// is responsible for calling `seedSummaryCache` / `recordSummary` /
// `commitIncrementalState`.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import { statePath, stateWritesEnabled } from '../posture/state-dir.js';

const FILES_PATH = 'files.json';
const SUMMARIES_PATH = 'summaries.json';
const VERSION_PATH = 'version.json';
const MAX_PERSISTED_SUMMARIES = 50000;

/** Compute the content hash used for file-equality detection. */
export function hashFileContent(stripped) {
  return crypto.createHash('sha256').update(stripped || '').digest('hex');
}

/** Read the persisted state. Returns a fresh empty state on any error. */
export function readIncrementalState(projectRoot) {
  const dir = statePath(projectRoot, 'incremental');
  try {
    const versionFp = path.join(dir, VERSION_PATH);
    if (!fs.existsSync(versionFp)) return _emptyState();
    const v = JSON.parse(fs.readFileSync(versionFp, 'utf8'));
    return {
      version: v,
      files: _readJsonOrEmpty(path.join(dir, FILES_PATH), {}),
      summaries: _readJsonOrEmpty(path.join(dir, SUMMARIES_PATH), {}),
    };
  } catch (_e) {
    return _emptyState();
  }
}

function _emptyState() {
  return { version: null, files: {}, summaries: {} };
}

function _readJsonOrEmpty(fp, fallback) {
  try {
    if (!fs.existsSync(fp)) return fallback;
    return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch (_e) {
    return fallback;
  }
}

/**
 * Validate persisted state against the current rule-pack + scanner version.
 * Returns `{ valid: boolean, reason?: string }`.
 */
export function validateIncrementalState(state, currentVersion) {
  if (!state || !state.version) return { valid: false, reason: 'no prior state' };
  if (!currentVersion) return { valid: false, reason: 'no current version' };
  if (state.version.scanner !== currentVersion.scanner) return { valid: false, reason: 'scanner version changed' };
  if (state.version.rules  !== currentVersion.rules)   return { valid: false, reason: 'rule-pack changed' };
  return { valid: true };
}

/**
 * Diff the previous file-hash map against the current scan's hashes.
 * Returns:
 *   { unchanged: [filePath, ...], changed: [filePath, ...], added: [...], removed: [...] }
 */
export function diffFileHashes(prevFiles, currentHashes) {
  const unchanged = [];
  const changed = [];
  const added = [];
  const removed = [];
  for (const [fp, h] of Object.entries(currentHashes)) {
    if (!(fp in prevFiles)) added.push(fp);
    else if (prevFiles[fp] === h) unchanged.push(fp);
    else changed.push(fp);
  }
  for (const fp of Object.keys(prevFiles)) {
    if (!(fp in currentHashes)) removed.push(fp);
  }
  return { unchanged, changed, added, removed };
}

/**
 * Decide which previously-persisted summaries are still safe to reuse.
 *
 *   summaries: persisted summary map { qid: summary }
 *   callerOfQid: persisted reverse-call-graph { qid: [callerQid, ...] }
 *   changedQids: Set of qids whose source files changed
 *
 * Returns: { reusable: Set<qid>, invalidated: Set<qid> }
 */
export function pickReusableSummaries(summaries, callerOfQid, changedQids) {
  const invalidated = new Set();
  // Seed with directly-changed qids.
  for (const q of changedQids) invalidated.add(q);
  // BFS via reverse call graph — invalidate every transitive caller.
  const stack = [...changedQids];
  while (stack.length) {
    const q = stack.pop();
    const callers = callerOfQid?.[q] || [];
    for (const c of callers) {
      if (!invalidated.has(c)) {
        invalidated.add(c);
        stack.push(c);
      }
    }
  }
  const reusable = new Set();
  for (const q of Object.keys(summaries || {})) {
    if (!invalidated.has(q)) reusable.add(q);
  }
  return { reusable, invalidated };
}

/** Seed a SummaryCache instance from persisted summaries. */
export function seedSummaryCache(summaryCache, persisted, reusableQids) {
  if (!summaryCache || !persisted) return 0;
  let n = 0;
  for (const qid of reusableQids) {
    const s = persisted[qid];
    if (!s) continue;
    // Reconstitute Set fields (JSON dropped them).
    const summary = {
      returnTainted: !!s.returnTainted,
      mutatedParams: new Set(s.mutatedParams || []),
      // W5.53: mutatedThisFields is a THIRD Set-valued summary field
      // (object-instance field taint via method calls), added after this
      // module's own serialize/reseed pair was written — omitting it here
      // wouldn't crash (every consumer already null-guards with `&&`), but
      // would silently drop the capability on any incremental/warm-cache
      // scan, exactly the class of gap `_summaryEq`'s own header comment in
      // summaries.js warns about for a different (but structurally
      // identical) reason: a summary field that exists on some code paths
      // and not others must be threaded through EVERY path that copies the
      // summary shape, not just the ones exercised by this session's own
      // tests.
      mutatedThisFields: new Set(s.mutatedThisFields || []),
      taintedGlobals: new Set(s.taintedGlobals || []),
      findings: Array.isArray(s.findings) ? s.findings : [],
      // DAG-07 R07.3: provenance of a restored summary. Never serialized
      // (serializeSummaries copies named fields only), so it cannot leak back
      // into the persisted state; SummaryCache reads it to tell a restored
      // empty-entry summary standing in for a tainted context from a computed one.
      _incrementalSeed: true,
    };
    if (Number.isInteger(s.findingsTruncated) && s.findingsTruncated > 0) {
      // Findings beyond the persist cap were dropped when this was saved, so
      // reuse is a partial replay of what the function reported.
      summary._findingsTruncated = s.findingsTruncated;
      if (summaryCache._incrementalFindingsTruncated === undefined) summaryCache._incrementalFindingsTruncated = 0;
      summaryCache._incrementalFindingsTruncated += 1;
    }
    // Use the bottom taint-state key — these are summaries that DON'T depend
    // on entry taint state (e.g., pure functions). Higher-fidelity reuse
    // would require persisting the entry-state hash too; deferred.
    summaryCache.set(qid, new Set(), summary, null);
    n++;
  }
  return n;
}

/**
 * Serialize a SummaryCache for persistence.
 *
 * ACTUAL current filter: excludes `_budgetExceeded` and `_recursive`
 * summaries, and caps at MAX_PERSISTED_SUMMARIES. There is no
 * context-independence filter — nothing in this codebase ever sets a
 * `_persistable` flag (this comment previously claimed one existed and gated
 * on it; grep confirms no such flag is set anywhere). Every non-recursive,
 * non-budget-exceeded summary is persisted regardless of whether it depends
 * on the entry taint-state it was computed under.
 *
 * OPEN QUESTION, not resolved by this comment fix: whether the reseeding
 * side (`pickReusableSummaries`/`seedSummaryCache`) re-validates a persisted
 * summary against the CALLER's actual entry taint-state before reuse, or
 * trusts it as-is. If it trusts it as-is, a summary computed under one
 * tainted-arg shape could be replayed for a call site with a different shape
 * next scan — a real correctness question for the k-CFA context-sensitivity
 * this cache exists to provide, worth a dedicated investigation rather than
 * a guess made while reconciling documentation.
 *
 * Returns a plain object `{ qid: summary }` safe for JSON.stringify.
 */
export function serializeSummaries(summaryCache) {
  const out = {};
  if (!summaryCache || !summaryCache._cache) return out;
  // DAG-07 R07.3. The cache key is `<qid>::<entryHash>[@caller][::receiver]`
  // and a qid itself contains `::`, so the old `key.split('::')[0]` reduced
  // every key to its FILE and let whichever entry context was written last
  // stand for the whole file. Only the EMPTY-entry summary is a statement
  // about what a function does when nothing tainted flows in; a summary
  // computed under a tainted entry must never be restored as that. Parse the
  // key from the right, persist the empty-entry summary under the real qid,
  // and count what was not persisted so reuse can be reported honestly.
  const EMPTY_SUFFIX = '::empty';
  let count = 0;
  const skippedContexts = new Map();
  for (const [key, summary] of summaryCache._cache) {
    if (!summary || summary._budgetExceeded || summary._recursive) continue;
    if (!key.endsWith(EMPTY_SUFFIX)) {
      const m = /^(.*?::[^:]*@\d+)::/.exec(key);
      const q = m ? m[1] : key;
      skippedContexts.set(q, (skippedContexts.get(q) || 0) + 1);
      continue;
    }
    const qid = key.slice(0, -EMPTY_SUFFIX.length);
    if (!qid) continue;
    if (count >= MAX_PERSISTED_SUMMARIES) break;
    const findings = Array.isArray(summary.findings) ? summary.findings : [];
    out[qid] = {
      returnTainted: !!summary.returnTainted,
      mutatedParams: [...(summary.mutatedParams || [])],
      mutatedThisFields: [...(summary.mutatedThisFields || [])],
      taintedGlobals: [...(summary.taintedGlobals || [])],
      findings: findings.slice(0, 50),
      entryContext: 'empty',
      ...(findings.length > 50 ? { findingsTruncated: findings.length - 50 } : {}),
    };
    count++;
  }
  for (const [q, n] of skippedContexts) if (out[q]) out[q].contextsNotPersisted = n;
  return out;
}

/**
 * Commit incremental state to disk. Idempotent — safe to call from anywhere.
 *
 *   state.files       { filepath: sha256 }
 *   state.summaries   { qid: summary }      (output of serializeSummaries)
 *   state.callers     { qid: [callerQid] }  (reverse call-graph)
 *   currentVersion    { scanner, rules }
 */
export function commitIncrementalState(projectRoot, state, currentVersion) {
  if (!projectRoot) return false;
  const dir = statePath(projectRoot, 'incremental');
  try {
    if (!stateWritesEnabled()) return;
  fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, VERSION_PATH), JSON.stringify(currentVersion, null, 2));
    fs.writeFileSync(path.join(dir, FILES_PATH), JSON.stringify(state.files || {}, null, 2));
    const payload = {
      summaries: state.summaries || {},
      callers: state.callers || {},
    };
    fs.writeFileSync(path.join(dir, SUMMARIES_PATH), JSON.stringify(payload));
    return true;
  } catch (_e) {
    return false;
  }
}

/** Drop persisted state — used when a version mismatch is detected. */
export function dropIncrementalState(projectRoot) {
  const dir = statePath(projectRoot, 'incremental');
  try {
    if (!fs.existsSync(dir)) return true;
    for (const fn of [VERSION_PATH, FILES_PATH, SUMMARIES_PATH]) {
      const fp = path.join(dir, fn);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    return true;
  } catch (_e) {
    return false;
  }
}
