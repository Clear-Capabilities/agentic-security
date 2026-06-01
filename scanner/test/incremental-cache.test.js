// v0.69 #5 — cross-scan incremental summary cache tests.
//
// Verifies the read → seed → commit lifecycle:
//   (a) commitIncrementalState writes a state directory that
//       readIncrementalState can round-trip
//   (b) validateIncrementalState rejects state across scanner-version mismatch
//   (c) diffFileHashes classifies changed/added/removed correctly
//   (d) pickReusableSummaries invalidates transitive callers of changed qids
//   (e) seedSummaryCache populates a SummaryCache instance from prior state
//   (f) integration: two consecutive runDeepAnalysis calls share state

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  readIncrementalState, validateIncrementalState, diffFileHashes,
  hashFileContent, pickReusableSummaries, seedSummaryCache,
  serializeSummaries, commitIncrementalState, dropIncrementalState,
} from '../src/dataflow/incremental.js';
import { SummaryCache } from '../src/dataflow/summaries.js';

function mkRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'inc-'));
}

test('commit + read state round-trips', () => {
  const root = mkRoot();
  const state = {
    files: { 'a.js': hashFileContent('content-a') },
    summaries: { 'a.js::f@1': { returnTainted: true, mutatedParams: ['x'], taintedGlobals: [], findings: [] } },
    callers: { 'a.js::f@1': ['b.js::g@1'] },
  };
  const ok = commitIncrementalState(root, state, { scanner: '0.69.0', rules: 'cat:42' });
  assert.equal(ok, true);
  const r = readIncrementalState(root);
  assert.deepEqual(r.version, { scanner: '0.69.0', rules: 'cat:42' });
  assert.deepEqual(r.files, state.files);
  // summaries are wrapped in { summaries, callers } payload
  assert.ok(r.summaries.summaries || r.summaries);
  fs.rmSync(root, { recursive: true, force: true });
});

test('validateIncrementalState rejects scanner-version mismatch', () => {
  const ok = validateIncrementalState({ version: { scanner: '0.68.0', rules: 'r1' } }, { scanner: '0.69.0', rules: 'r1' });
  assert.equal(ok.valid, false);
  assert.match(ok.reason, /scanner/i);
});

test('validateIncrementalState accepts matching versions', () => {
  const ok = validateIncrementalState({ version: { scanner: '0.69.0', rules: 'r1' } }, { scanner: '0.69.0', rules: 'r1' });
  assert.equal(ok.valid, true);
});

test('diffFileHashes classifies unchanged / changed / added / removed', () => {
  const prev = { 'a.js': 'h1', 'b.js': 'h2', 'c.js': 'h3' };
  const cur = { 'a.js': 'h1', 'b.js': 'h2X', 'd.js': 'h4' };
  const d = diffFileHashes(prev, cur);
  assert.deepEqual(d.unchanged.sort(), ['a.js']);
  assert.deepEqual(d.changed.sort(), ['b.js']);
  assert.deepEqual(d.added.sort(), ['d.js']);
  assert.deepEqual(d.removed.sort(), ['c.js']);
});

test('pickReusableSummaries invalidates direct + transitive callers of changed qids', () => {
  const summaries = {
    'A': { returnTainted: false },
    'B': { returnTainted: false },
    'C': { returnTainted: false },
    'D': { returnTainted: false },
  };
  // Call graph: A calls B, B calls C, D is unrelated.
  const callerOfQid = {
    'B': ['A'],
    'C': ['B'],
  };
  // C's file changed.
  const { reusable, invalidated } = pickReusableSummaries(summaries, callerOfQid, new Set(['C']));
  // C is changed; B (caller of C) and A (caller of B) are transitively invalid.
  assert.ok(invalidated.has('C'));
  assert.ok(invalidated.has('B'));
  assert.ok(invalidated.has('A'));
  assert.ok(reusable.has('D'));
  assert.ok(!reusable.has('A'));
});

test('seedSummaryCache populates a SummaryCache from a persisted payload', () => {
  const cache = new SummaryCache();
  const persisted = {
    'Q1': { returnTainted: true, mutatedParams: ['x'], taintedGlobals: ['g'], findings: [] },
    'Q2': { returnTainted: false, mutatedParams: [], taintedGlobals: [], findings: [] },
  };
  const n = seedSummaryCache(cache, persisted, new Set(['Q1', 'Q2']));
  assert.equal(n, 2);
  assert.ok(cache.size() >= 2);
});

test('serializeSummaries round-trips through JSON without dropping Set fields', () => {
  const cache = new SummaryCache();
  cache.set('Q', new Set(), {
    returnTainted: true,
    mutatedParams: new Set(['p1', 'p2']),
    taintedGlobals: new Set(['g']),
    findings: [],
  });
  const serialized = serializeSummaries(cache);
  const json = JSON.parse(JSON.stringify(serialized));
  assert.equal(json.Q.returnTainted, true);
  assert.deepEqual(json.Q.mutatedParams.sort(), ['p1', 'p2']);
  assert.deepEqual(json.Q.taintedGlobals, ['g']);
});

test('dropIncrementalState removes the state directory', () => {
  const root = mkRoot();
  commitIncrementalState(root, { files: {}, summaries: {}, callers: {} }, { scanner: '0.69.0', rules: 'r' });
  assert.ok(fs.existsSync(path.join(root, '.agentic-security', 'incremental', 'version.json')));
  dropIncrementalState(root);
  assert.equal(fs.existsSync(path.join(root, '.agentic-security', 'incremental', 'version.json')), false);
  fs.rmSync(root, { recursive: true, force: true });
});

test('hashFileContent is stable for identical input', () => {
  const a = hashFileContent('hello world');
  const b = hashFileContent('hello world');
  assert.equal(a, b);
  const c = hashFileContent('hello worlD');
  assert.notEqual(a, c);
});

// Regression (R23): end-to-end cold-commit → warm-reuse through runDeepAnalysis.
// The unit tests above exercise the persistence PRIMITIVES directly, so they
// stayed green while the orchestration in dataflow/index.js was a no-op: the
// commit guard keyed on `currentFileHashes`, which was only computed inside the
// valid-prior-state branch — so a COLD scan never persisted, and therefore no
// later scan ever had state to reuse. This test drives the actual entry point
// twice and fails if the first (cold) scan does not persist a baseline.
test('incremental e2e: first runDeepAnalysis persists a baseline, second reuses it', async () => {
  const { buildProjectIR } = await import('../src/ir/index.js');
  const { runDeepAnalysis } = await import('../src/dataflow/index.js');
  const root = mkRoot();
  const files = {
    'h.js':
      'function getName(req){ return req.query.name; }\n' +
      'function handler(req, res){ const n = getName(req); db.query("SELECT * FROM u WHERE n = " + n); }\n',
  };
  const { perFile, callGraph } = buildProjectIR(files);
  const prev = process.env.AGENTIC_SECURITY_INCREMENTAL;
  process.env.AGENTIC_SECURITY_INCREMENTAL = '1';
  try {
    // Run 1 — COLD. Must persist version.json + files.json (the exact files the
    // pre-fix code never wrote on a cold cache).
    runDeepAnalysis(perFile, callGraph, { scanRoot: root, fileContents: files });
    const incDir = path.join(root, '.agentic-security', 'incremental');
    assert.ok(fs.existsSync(path.join(incDir, 'version.json')), 'cold scan must persist version.json');
    assert.ok(fs.existsSync(path.join(incDir, 'files.json')), 'cold scan must persist files.json');
    const persistedFiles = JSON.parse(fs.readFileSync(path.join(incDir, 'files.json'), 'utf8'));
    assert.ok(Object.keys(persistedFiles).length >= 1, 'files baseline must be non-empty');

    // Run 2 — WARM. Prior state validates (same scanner/rules), so the engine
    // seeds the SummaryCache and attaches _incrementalStats. Its presence proves
    // run 1 committed AND run 2 read it back (the loop the bug broke end-to-end).
    const findings2 = runDeepAnalysis(perFile, callGraph, { scanRoot: root, fileContents: files });
    assert.ok(findings2._incrementalStats,
      'warm run must attach _incrementalStats (prior state must have validated + seeded)');
    assert.ok(findings2._incrementalStats.reusable >= 1,
      `warm run should mark ≥1 persisted summary reusable, got ${findings2._incrementalStats.reusable}`);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_INCREMENTAL;
    else process.env.AGENTIC_SECURITY_INCREMENTAL = prev;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
