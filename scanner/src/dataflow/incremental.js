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
const VERSION_PATH = 'version.json';   // the MANIFEST: written last, names and digests every data file
const DEPS_PATH = 'deps.json';         // DAG-05: dependency model + global components
const REPLAY_PATH = 'replay.json';     // DAG-05: typed contexts, exit states, per-function findings
const DATA_FILES = [FILES_PATH, SUMMARIES_PATH, DEPS_PATH, REPLAY_PATH];
const MAX_PERSISTED_SUMMARIES = 50000;
// DAG-05 R05.6: bump when the on-disk shape changes; an older or newer record is rejected, never guessed at.
export const INCREMENTAL_FORMAT = 'incremental-state/2';

/** Compute the content hash used for file-equality detection. */
export function hashFileContent(stripped) {
  return crypto.createHash('sha256').update(stripped || '').digest('hex');
}

/**
 * Read the persisted state. Returns a fresh empty state on any error.
 *
 * DAG-05 R05.6: the version file is a manifest that names every data file with
 * its SHA-256. A state is accepted only when the format is the current one, every
 * named file exists and matches its digest and parses, so a crash between the
 * temp write and the rename, a truncated file or a hand edit is rejected as a
 * whole. A rejection is carried as `state.rejected` (the reason) so the caller
 * can say why it fell back to cold analysis.
 */
export function readIncrementalState(projectRoot) {
  const dir = statePath(projectRoot, 'incremental');
  const versionFp = path.join(dir, VERSION_PATH);
  let manifest;
  try {
    if (!fs.existsSync(versionFp)) return _emptyState();
    manifest = JSON.parse(fs.readFileSync(versionFp, 'utf8'));
  } catch (_e) {
    return _rejected('cache manifest is corrupt (does not parse)');
  }
  if (!manifest || typeof manifest !== 'object' || manifest.format !== INCREMENTAL_FORMAT) {
    return _rejected(`cache format is not ${INCREMENTAL_FORMAT} (found ${manifest && manifest.format ? manifest.format : 'legacy'})`);
  }
  const listed = manifest.files && typeof manifest.files === 'object' ? manifest.files : null;
  if (!listed || !manifest.version || typeof manifest.version !== 'object') return _rejected('cache manifest is incomplete');
  const parsed = {};
  for (const name of DATA_FILES) {
    const entry = listed[name];
    if (!entry || typeof entry.sha256 !== 'string') return _rejected(`cache manifest does not list ${name}`);
    let text;
    try { text = fs.readFileSync(path.join(dir, name), 'utf8'); }
    catch { return _rejected(`incomplete cache: ${name} is missing`); }
    const got = crypto.createHash('sha256').update(text).digest('hex');
    if (got !== entry.sha256) return _rejected(`cache record ${name} failed its integrity digest (interrupted write or corruption)`);
    try { parsed[name] = JSON.parse(text); }
    catch { return _rejected(`cache record ${name} does not parse`); }
  }
  if (!parsed[FILES_PATH] || typeof parsed[FILES_PATH] !== 'object' || Array.isArray(parsed[FILES_PATH])) return _rejected('cache record files.json has the wrong shape');
  if (!parsed[SUMMARIES_PATH] || typeof parsed[SUMMARIES_PATH] !== 'object') return _rejected('cache record summaries.json has the wrong shape');
  if (parsed[DEPS_PATH] !== null && (typeof parsed[DEPS_PATH] !== 'object' || (parsed[DEPS_PATH] && parsed[DEPS_PATH].schema !== 'dep-graph/1'))) {
    return _rejected('cache dependency graph has an incompatible schema');
  }
  return {
    version: manifest.version,
    generation: manifest.generation || null,
    files: parsed[FILES_PATH],
    summaries: parsed[SUMMARIES_PATH],
    deps: parsed[DEPS_PATH],
    replay: parsed[REPLAY_PATH],
  };
}

function _emptyState() {
  return { version: null, files: {}, summaries: {}, deps: null, replay: null };
}

function _rejected(reason) {
  return { ..._emptyState(), rejected: reason };
}

/**
 * Validate persisted state against the current rule-pack + scanner version.
 * Returns `{ valid: boolean, reason?: string }`.
 */
export function validateIncrementalState(state, currentVersion) {
  if (state && state.rejected) return { valid: false, reason: state.rejected };
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

// ── DAG-05 R05.3: typed, context-keyed persistence ──────────────────────────

/**
 * A copy of a finding that survives JSON. An expression-object `callee` is kept as a structural copy:
 * it is plain data, equal by value to the original, and only the backward slicer compares it by
 * reference (replay is refused under that option). Returns null when the value cannot be serialised
 * at all (a cycle), which makes the owner non-replayable rather than lossy.
 */
export function jsonSafeFinding(f) {
  try { return JSON.parse(JSON.stringify(f)); } catch { return null; }
}

export const CONTEXT_SCHEMA = 'summary-context/1';
const MAX_FINDINGS_PER_CONTEXT = 200;

/**
 * Every computed context of every function, each under its COMPLETE key: qid,
 * the canonical entry-taint list, the state hash derived from it and the
 * receiver hash. A context is either persisted whole or counted in `skipped`
 * with the reason; it is never reduced to the empty-entry slot.
 *
 *   { schema, contexts: { qid: [ { entry:[...], stateHash, recv, summary } ] }, skipped: { reason: n } }
 */
export function serializeContexts(summaryCache) {
  const contexts = {};
  const skipped = {};
  const note = (r) => { skipped[r] = (skipped[r] || 0) + 1; };
  if (!summaryCache || !summaryCache._cache) return { schema: CONTEXT_SCHEMA, contexts, skipped };
  const meta = summaryCache._meta;
  let count = 0;
  for (const [key, summary] of summaryCache._cache) {
    if (!summary) continue;
    if (summary._budgetExceeded) { note('budget-exceeded'); continue; }
    if (summary._recursive) { note('recursion-stub'); continue; }
    const m = meta && meta.get(key);
    if (!m) { note('no-key-metadata'); continue; }
    const findings = Array.isArray(summary.findings) ? summary.findings : [];
    if (findings.length > MAX_FINDINGS_PER_CONTEXT) { note('findings-over-cap'); continue; }
    const safe = [];
    let ok = true;
    for (const f of findings) { const c = jsonSafeFinding(f); if (c === null) { ok = false; break; } safe.push(c); }
    if (!ok) { note('findings-not-serialisable'); continue; }
    if (count >= MAX_PERSISTED_SUMMARIES) { note('persist-cap'); continue; }
    (contexts[m.qid] ||= []).push({
      entry: m.entry, stateHash: m.stateHash, recv: m.recv || null,
      summary: {
        returnTainted: !!summary.returnTainted,
        mutatedParams: [...(summary.mutatedParams || [])].sort(),
        mutatedThisFields: [...(summary.mutatedThisFields || [])].sort(),
        taintedGlobals: [...(summary.taintedGlobals || [])].sort(),
        findings: safe,
      },
    });
    count++;
  }
  for (const q of Object.keys(contexts)) contexts[q].sort((a, b) => (a.stateHash + (a.recv || '') < b.stateHash + (b.recv || '') ? -1 : 1));
  return { schema: CONTEXT_SCHEMA, contexts, skipped };
}

/**
 * Restore persisted contexts for the given function ids. Each record is checked
 * (shape, entry list reproduces its state hash) before it is stored under its
 * real key; a record that fails is counted and ignored, so the function simply
 * recomputes that context. Returns { restored, rejected }.
 */
export function restoreContexts(summaryCache, persisted, qids) {
  let restored = 0; let rejected = 0;
  if (!summaryCache || !persisted || persisted.schema !== CONTEXT_SCHEMA || !persisted.contexts) return { restored, rejected };
  for (const qid of qids) {
    for (const rec of persisted.contexts[qid] || []) {
      const s = rec && rec.summary;
      if (!s || !Array.isArray(rec.entry) || typeof rec.stateHash !== 'string' || !Array.isArray(s.findings)) { rejected++; continue; }
      const summary = {
        returnTainted: !!s.returnTainted,
        mutatedParams: new Set(s.mutatedParams || []),
        mutatedThisFields: new Set(s.mutatedThisFields || []),
        taintedGlobals: new Set(s.taintedGlobals || []),
        findings: s.findings,
      };
      if (summaryCache.restoreContext(qid, rec.entry, rec.recv || null, rec.stateHash, summary)) restored++; else rejected++;
    }
  }
  return { restored, rejected };
}

/**
 * Commit incremental state to disk. Idempotent: safe to call from anywhere.
 *
 *   state.files       { filepath: sha256 }
 *   state.summaries   { qid: summary }      (output of serializeSummaries)
 *   state.callers     { qid: [callerQid] }  (reverse call-graph)
 *   state.deps        DAG-05 dependency model + global components (or null)
 *   state.replay      DAG-05 typed contexts / exit states / findings (or null)
 *   currentVersion    { scanner, rules }
 *
 * DAG-05 R05.6: atomic. Every data file is written to a uniquely named temp file
 * and fsynced, then renamed over its final name, and the manifest (version.json,
 * which holds each file's SHA-256) is renamed LAST. A crash anywhere in that
 * sequence leaves either the previous manifest with data it no longer matches, or
 * a half-renamed set; `readIncrementalState` rejects both whole, so the next scan
 * is cold, never a mixture of two generations. `io` is a seam for tests that
 * simulate the crash (`io.renameSync`).
 */
export function commitIncrementalState(projectRoot, state, currentVersion, io = {}) {
  if (!projectRoot) return false;
  const dir = statePath(projectRoot, 'incremental');
  const rename = io.renameSync || fs.renameSync;
  const gen = crypto.randomBytes(6).toString('hex');
  const temps = [];
  try {
    if (!stateWritesEnabled()) return false;
    fs.mkdirSync(dir, { recursive: true });
    const payloads = {
      [FILES_PATH]: state.files || {},
      [SUMMARIES_PATH]: { summaries: state.summaries || {}, callers: state.callers || {} },
      [DEPS_PATH]: state.deps || null,
      [REPLAY_PATH]: state.replay || null,
    };
    const listed = {};
    for (const name of DATA_FILES) {
      const text = JSON.stringify(payloads[name]);
      listed[name] = { sha256: crypto.createHash('sha256').update(text).digest('hex'), bytes: Buffer.byteLength(text) };
      const tmp = path.join(dir, `${name}.tmp-${gen}`);
      temps.push(tmp);
      _writeFileTemp(tmp, text);
    }
    const manifest = { format: INCREMENTAL_FORMAT, generation: gen, version: currentVersion, files: listed };
    const manifestTmp = path.join(dir, `${VERSION_PATH}.tmp-${gen}`);
    temps.push(manifestTmp);
    _writeFileTemp(manifestTmp, JSON.stringify(manifest, null, 2));
    for (const name of DATA_FILES) rename(path.join(dir, `${name}.tmp-${gen}`), path.join(dir, name));
    rename(manifestTmp, path.join(dir, VERSION_PATH));
    _sweepTemps(dir, gen);
    return true;
  } catch (_e) {
    // Leave whatever the crash left: the reader rejects an inconsistent set. Only
    // our own temp files are removed, and only the ones not yet renamed.
    for (const t of temps) { try { if (fs.existsSync(t)) fs.unlinkSync(t); } catch { /* best effort */ } }
    return false;
  }
}

// No fsync, on purpose: the reader checks the SHA-256 of every file the manifest names, so a write
// that did not reach the disk (power loss) is detected and rejected whole and the next scan is cold.
// Durability is not what protects the cache; the digest check is. An fsync per file cost more than
// the analysis it saved on a small edit.
function _writeFileTemp(fp, text) {
  fs.writeFileSync(fp, text, { mode: 0o600 });
}

/** Remove temp files left by an earlier interrupted commit (never the current one's). */
function _sweepTemps(dir, keepGen) {
  try {
    for (const n of fs.readdirSync(dir)) {
      if (/\.tmp-[0-9a-f]+$/.test(n) && !n.endsWith(`.tmp-${keepGen}`)) { try { fs.unlinkSync(path.join(dir, n)); } catch { /* best effort */ } }
    }
  } catch { /* best effort */ }
}

/** Drop persisted state, used when a version mismatch is detected. */
export function dropIncrementalState(projectRoot) {
  const dir = statePath(projectRoot, 'incremental');
  try {
    if (!fs.existsSync(dir)) return true;
    for (const fn of fs.readdirSync(dir)) {
      if (DATA_FILES.includes(fn) || fn === VERSION_PATH || /\.tmp-[0-9a-f]+$/.test(fn)) {
        const fp = path.join(dir, fn);
        if (fs.existsSync(fp)) fs.unlinkSync(fp);
      }
    }
    return true;
  } catch (_e) {
    return false;
  }
}
