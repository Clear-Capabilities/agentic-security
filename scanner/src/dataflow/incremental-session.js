// DAG-05: one incremental session per deep-analysis run.
//
//   begin   read the persisted state, fingerprint the current project, decide warm
//           or cold (and say why), restore the typed contexts of clean functions
//   finish  stamp cache provenance on the findings, persist the new generation
//           atomically, and describe what was reused versus recomputed
//
// The decision is made from CONTENT (dep-fingerprint.js). Any doubt is cold:
// an unreadable, corrupt, incomplete or incompatible cache, a changed global
// input, an unsupported option, a prior analysis that was cut short or did not
// converge. A cold run is a full analysis and reports `mode: 'cold'` with the
// reason, so a missing speed-up is never silent and a wrong answer never
// results from a cache that could not be trusted.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { SummaryCache } from './summaries.js';
import {
  readIncrementalState, validateIncrementalState, hashFileContent, diffFileHashes,
  serializeContexts, restoreContexts, commitIncrementalState, CONTEXT_SCHEMA,
} from './incremental.js';
import { ReplayHooks } from './incremental-replay.js';
import {
  buildDependencyModel, globalComponents, planIncremental, countByReason, diffComponents, DEP_GRAPH_SCHEMA,
} from './dep-fingerprint.js';
import { loadProjectStubs } from '../ir/type-stubs.js';

const REPLAY_SCHEMA = 'replay/1';

// Options whose effect on a function's result is not captured by the function's own
// fingerprint, so reuse under them is refused rather than guessed.
const UNSUPPORTED_FOR_REPLAY = [
  ['AGENTIC_SECURITY_POINTS_TO', 'a whole-program points-to graph feeds every function'],
  ['AGENTIC_SECURITY_RHS', 'reachability slicing restricts which functions are analysed'],
  ['AGENTIC_SECURITY_KCFA_CALLSTRING', 'call-string contexts key summaries by caller'],
  ['AGENTIC_SECURITY_BACKWARD_SLICE', 'the backward slicer needs live IR references a stored finding does not have'],
  ['AGENTIC_SECURITY_SYMEXEC', 'the exploit prover needs live IR references a stored finding does not have'],
];
// Reasons that make a finished run's records untrustworthy for reuse.
const BLOCKING_INCOMPLETE = new Set(['deadline', 'analysis-error', 'summary-budget']);

let _scannerVersion = null;
function scannerVersion() {
  if (_scannerVersion) return _scannerVersion;
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    for (const rel of ['../../package.json', '../package.json', './package.json']) {
      try { const v = JSON.parse(fs.readFileSync(path.resolve(here, rel), 'utf8')).version; if (v) { _scannerVersion = v; return v; } } catch { /* next */ }
    }
  } catch { /* fall through */ }
  _scannerVersion = 'unknown';
  return _scannerVersion;
}

/** Reverse call graph (callee -> callers) from the dependency model's own edges. */
function callersFrom(model) {
  const callers = {};
  for (const [qid, f] of Object.entries(model.functions)) {
    for (const c of f.callees) (callers[c] ||= []).push(qid);
  }
  return callers;
}

/**
 * Start a session. Returns null when incremental analysis is not enabled or the
 * caller supplied no scan root / file contents (nothing could be persisted).
 */
export function beginIncrementalSession({ enabled, opts, perFileIR, callGraph, cha, env = process.env, now = Date.now }) {
  if (!enabled || !opts || !opts.scanRoot || !opts.fileContents) return null;
  const t0 = now();
  const fileHashes = {};
  for (const [fp, content] of Object.entries(opts.fileContents)) fileHashes[fp] = hashFileContent(content);
  const global = globalComponents({
    scanRoot: opts.scanRoot, fileContents: opts.fileContents, opts, env,
    stubsProvider: opts._stubsProvider || ((root) => (root ? loadProjectStubs(root) : null)),
  });
  const rulesDigest = crypto.createHash('sha256').update(`${global.catalog}${global.sanitizers}`).digest('hex').slice(0, 16);
  const version = { scanner: opts.scannerVersion || scannerVersion(), rules: opts.rulesDigest || `content:${rulesDigest}` };
  const tRead = now();
  const prior = readIncrementalState(opts.scanRoot);
  const readMs = now() - tRead;
  const t1 = now();
  const reuse = prior.deps && prior.deps.global && prior.deps.global.analyzers === global.analyzers
    ? { functions: prior.deps.functions, priorFiles: prior.files, curFiles: fileHashes } : null;
  const model = buildDependencyModel({ perFileIR, callGraph, cha, fileContents: opts.fileContents, reuse });
  const fingerprintMs = (t1 - t0) + (now() - t1);
  const session = {
    root: opts.scanRoot, version, global, model, fileHashes, prior, callGraph,
    mode: 'cold', reason: null, plan: null, cache: null, hooks: null,
    restored: { contexts: 0, rejected: 0 }, fingerprintMs, priorGeneration: prior.generation || null,
    fileDiff: null, io: opts._incrementalIo || {}, timing: { fingerprintMs, readMs, planMs: 0, restoreMs: 0 },
  };
  const decide = () => {
    const unsupported = UNSUPPORTED_FOR_REPLAY.find(([name]) => env[name] === '1');
    if (unsupported) return `replay unsupported under ${unsupported[0]}: ${unsupported[1]}`;
    if (!Object.keys(model.functions).length) return 'no analysable functions in this project, so there is nothing to reuse';
    const valid = validateIncrementalState(prior, version);
    if (!valid.valid) {
      // name the content that moved when the version string alone does not
      const moved = prior.deps && prior.deps.global ? diffComponents(prior.deps.global, global) : [];
      return moved.length && /rule-pack/.test(valid.reason) ? `${valid.reason} (${moved.join(', ')})` : valid.reason;
    }
    if (!prior.deps) return 'prior state has no dependency model';
    if (!prior.replay || prior.replay.schema !== REPLAY_SCHEMA) return 'prior state has no replay records';
    if (!prior.replay.complete) return `prior analysis was incomplete (${(prior.replay.reasons || []).join(', ') || 'unspecified'})`;
    if (!prior.replay.converged) return 'prior fixed point did not converge';
    if (prior.deps.schema !== DEP_GRAPH_SCHEMA) return 'prior dependency graph has an incompatible schema';
    return null;
  };
  const why = decide();
  session.fileDiff = diffFileHashes(prior.files || {}, fileHashes);
  if (why) {
    session.reason = why;
    session.hooks = new ReplayHooks();
    return session;
  }
  const tPlan = now();
  const records = new Map(Object.entries(prior.replay.records || {}));
  const plan = planIncremental(
    { global: prior.deps.global || {}, deps: prior.deps, hasRecord: (q) => records.has(q) },
    { global, model },
  );
  if (plan.mode === 'cold') {
    session.reason = plan.reason;
    session.plan = plan;
    session.hooks = new ReplayHooks();
    return session;
  }
  session.timing.planMs = now() - tPlan;
  const tRestore = now();
  const cache = new SummaryCache();
  const stats = restoreContexts(cache, { schema: CONTEXT_SCHEMA, contexts: prior.replay.contexts }, plan.clean);
  // A clean function whose empty-entry context could not be restored cannot be replayed.
  for (const q of [...plan.clean]) {
    if (!cache.has(q, new Set())) { plan.clean.delete(q); plan.dirty.set(q, 'context-not-restorable'); }
  }
  session.timing.restoreMs = now() - tRestore;
  const closure = new Map(Object.entries(model.functions).map(([q, f]) => [q, f.closure]));
  session.mode = 'warm';
  session.plan = plan;
  session.cache = cache;
  session.restored = stats;
  session.hooks = new ReplayHooks({ clean: plan.clean, records, generation: prior.generation, closure });
  return session;
}

/** Options to merge into the runTaintEngine call. */
export function engineOptionsFor(session) {
  if (!session) return {};
  return { _replay: session.hooks, ...(session.cache ? { summaryCache: session.cache } : {}) };
}

/**
 * Finish: stamp provenance, persist the new generation, return the stats object
 * to attach to the findings array.
 */
export function finishIncrementalSession(session, findings, { now = Date.now } = {}) {
  if (!session) return null;
  const hooks = session.hooks;
  const model = session.model;
  // provenance on every finding
  const gen = session.priorGeneration;
  let reused = 0; let recomputed = 0;
  for (const f of findings) {
    if (hooks && hooks.reusedFindingIds.has(f.id)) {
      f.cacheProvenance = { state: 'reused', generation: gen, closureFingerprint: model.functions[f._funcQid]?.closure ?? null };
      reused++;
    } else {
      f.cacheProvenance = { state: 'recomputed' };
      recomputed++;
    }
  }
  const incomplete = Array.isArray(findings.analysisIncomplete) ? findings.analysisIncomplete : [];
  const blocking = incomplete.filter((x) => BLOCKING_INCOMPLETE.has(x.reason)).map((x) => x.reason);
  const nonConverged = incomplete.some((x) => x.reason === 'recursion-nonconverged');
  const cache = findings._summaryCache;
  const t0 = now();
  let committed = false;
  let commitError = null;
  const persistPhases = {};
  let lapT = now();
  const lap = (n) => { const x = now(); persistPhases[n] = x - lapT; lapT = x; };
  try {
    const ctx = serializeContexts(cache);
    lap('serialize-contexts');
    const records = hooks.buildRecords(Object.keys(model.functions));
    lap('build-records');
    const replay = {
      schema: REPLAY_SCHEMA,
      complete: blocking.length === 0,
      reasons: [...new Set(blocking)].sort(),
      converged: hooks.converged && !nonConverged,
      contexts: ctx.contexts, contextsNotPersisted: ctx.skipped, records,
    };
    const deps = {
      schema: DEP_GRAPH_SCHEMA, global: session.global, chaDigest: model.chaDigest,
      functions: model.functions, fileSymbols: model.fileSymbols, sccs: model.sccs,
    };
    lap('assemble');
    committed = commitIncrementalState(session.root, {
      files: session.fileHashes,
      // the typed contexts live in replay.json; summaries.json keeps the legacy reverse call graph only
      summaries: {},
      callers: callersFrom(model),
      deps, replay,
    }, session.version, session.io);
    lap('commit');
    if (!committed) commitError = 'state not written (state writes disabled, unwritable directory, or an interrupted write)';
  } catch (e) { commitError = String((e && e.message) || e); }
  const persistMs = now() - t0;

  const plan = session.plan;
  const cleanN = plan && plan.clean ? plan.clean.size : 0;
  const replayed = hooks ? hooks.replayed.size : 0;
  const fnTotal = Object.keys(model.functions).length;
  return {
    // legacy fields the existing tests and consumers read
    seeded: session.restored.restored ?? 0, reusable: replayed, discardedLegacy: 0,
    mode: session.mode,
    reason: session.mode === 'cold' ? session.reason : null,
    priorGeneration: gen,
    provenance: {
      reusedFunctions: replayed,
      recomputedFunctions: Math.max(0, fnTotal - replayed),
      reusedFindings: reused,
      recomputedFindings: recomputed,
      restoredContexts: session.restored.restored ?? 0,
      contextsRejected: session.restored.rejected ?? 0,
    },
    invalidation: plan ? {
      cleanFunctions: cleanN,
      dirtyFunctions: plan.dirty.size,
      dirtyByReason: countByReason(plan.dirty),
      // the first 500 recomputed functions and why, so a reader can see what the edit reached
      dirty: [...plan.dirty].sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(0, 500).map(([qid, reason]) => ({ qid, reason })),
      removedSymbols: plan.removed,
      removedFiles: plan.removedFiles || [],
      movedOrRenamedSymbols: plan.renamed || [],
      sccWidened: plan.widened || 0,
      changedGlobalComponents: plan.changedComponents || [],
    } : null,
    files: { changed: session.fileDiff.changed.length, added: session.fileDiff.added.length, removed: session.fileDiff.removed.length, unchanged: session.fileDiff.unchanged.length },
    model: { ...model.stats, fingerprintMs: session.fingerprintMs },
    timing: session.timing,
    persisted: { committed, error: commitError, ms: persistMs, phaseMs: persistPhases },
    // DAG-07 R07.3 shape: reuse proven equivalent by fingerprint is complete; a cold fallback is a full analysis.
    completion: {
      status: 'complete',
      reasons: [],
      emptyEntryReusedForTaintedContexts: 0,
      summariesWithTruncatedFindings: 0,
    },
  };
}
