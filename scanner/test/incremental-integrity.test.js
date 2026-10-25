// DAG-05 acceptance: what a cached result may and may not be trusted for.
//
//   * global inputs (options, build configuration, catalog and SANITIZER content, stubs, policies,
//     boundary contracts, scanner and rule-pack versions) invalidate the whole cache, and the run
//     says which one moved;
//   * a context (an entry-taint state) is persisted under its complete key and comes back as that
//     context, never as the empty-entry slot, so a tainted and a clean call do not contaminate each
//     other after serialize and reload;
//   * a corrupt, truncated, incompatible, incomplete or interrupted cache is rejected whole and the
//     scan is cold, with the reason stated, and the next scan heals it;
//   * every finding says whether it was replayed or analysed afresh;
//   * a language with no incremental hook says so and is analysed in full.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { tempRoot, cleanup, deep, normalized, stateDirOf, storedState } from './helpers/incremental-harness.js';
import { SummaryCache } from '../src/dataflow/summaries.js';
import {
  serializeContexts, restoreContexts, readIncrementalState, commitIncrementalState, validateIncrementalState, CONTEXT_SCHEMA, INCREMENTAL_FORMAT,
} from '../src/dataflow/incremental.js';
import { CATALOG, _catalogSize } from '../src/dataflow/catalog.js';
import { globalComponents, diffComponents } from '../src/dataflow/dep-fingerprint.js';

const PROJECT = Object.freeze({
  'lib.js': 'function clean(x){ return escapeSql(x); }\nfunction raw(x){ return x; }\nmodule.exports = { clean, raw };\n',
  'a.js': "const { raw } = require('./lib');\nfunction ha(req){ db.query('SELECT ' + raw(req.query.a)); }\nmodule.exports = { ha };\n",
  'b.js': "const { clean } = require('./lib');\nfunction hb(req){ db.query('SELECT ' + clean(req.query.b)); }\nmodule.exports = { hb };\n",
  'c.js': 'function hc(req){ exec(req.query.c); }\nmodule.exports = { hc };\n',
});

/** Generation 1, then `after()` may disturb something, then a second scan, compared with a cold scan. */
function secondScan({ files = PROJECT, between = () => {}, opts = {}, env = {}, coldOpts = opts, coldEnv = env, edited = files } = {}) {
  const root = tempRoot('int'); const coldRoot = tempRoot('int-cold');
  try {
    deep({ ...files }, root, { opts, env });
    between(root);
    const second = deep({ ...edited }, root, { opts, env });
    const cold = deep({ ...edited }, coldRoot, { incremental: false, opts: coldOpts, env: coldEnv });
    return { second, cold, stats: second._incrementalStats, root };
  } catch (e) { cleanup(root); throw e; } finally { cleanup(coldRoot); }
}

const rewriteManifestDigest = (root, name, text) => {
  const dir = stateDirOf(root);
  const m = JSON.parse(fs.readFileSync(path.join(dir, 'version.json'), 'utf8'));
  fs.writeFileSync(path.join(dir, name), text);
  m.files[name] = { sha256: crypto.createHash('sha256').update(text).digest('hex'), bytes: Buffer.byteLength(text) };
  fs.writeFileSync(path.join(dir, 'version.json'), JSON.stringify(m));
};

// ── global components ───────────────────────────────────────────────────────

test('a changed sanitizer model invalidates the cache even though the catalog SIZE is unchanged', () => {
  const sizeBefore = _catalogSize();
  const entry = CATALOG.find((e) => e && e.kind === 'sanitizer');
  assert.ok(entry, 'the catalog has sanitizer entries');
  const saved = JSON.stringify(entry);
  const root = tempRoot('san'); const coldRoot = tempRoot('san-cold');
  try {
    deep({ ...PROJECT }, root);
    entry.match = { ...entry.match, __behaviourChange: true };          // same number of entries, different sanitizer
    assert.equal(_catalogSize(), sizeBefore);
    const out = deep({ ...PROJECT }, root);
    assert.equal(out._incrementalStats.mode, 'cold');
    assert.match(out._incrementalStats.reason, /rule-pack changed \(.*sanitizers.*\)|global input changed: .*sanitizers/);
    assert.deepEqual(normalized(out), normalized(deep({ ...PROJECT }, coldRoot, { incremental: false })));
  } finally {
    Object.keys(entry).forEach((k) => delete entry[k]); Object.assign(entry, JSON.parse(saved));
    cleanup(root, coldRoot);
  }
  assert.equal(JSON.stringify(entry), saved, 'the catalog was restored');
});

test('a changed source/sink catalog entry invalidates the cache (content, not count)', () => {
  const entry = CATALOG.find((e) => e && e.kind === 'sink');
  const saved = JSON.stringify(entry);
  const root = tempRoot('cat');
  try {
    deep({ ...PROJECT }, root);
    entry.label = `${entry.label} (edited)`;
    const out = deep({ ...PROJECT }, root);
    assert.equal(out._incrementalStats.mode, 'cold');
    assert.match(out._incrementalStats.reason, /rule-pack changed \(.*catalog.*\)|global input changed: .*catalog/);
  } finally { Object.keys(entry).forEach((k) => delete entry[k]); Object.assign(entry, JSON.parse(saved)); cleanup(root); }
});

const GLOBAL_CASES = [
  ['analysis options', 'options', { env: { AGENTIC_SECURITY_KCFA_MAX_CONTEXTS: '3' }, phase: 'second' }],
  ['build configuration', 'build', { between: (root) => fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture","version":"2.0.0","dependencies":{"x":"1"}}') }],
  ['policies', 'policies', { between: (root) => { fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true }); fs.writeFileSync(path.join(root, '.agentic-security', 'rules.yml'), 'ignorePaths: [vendor]\n'); } }],
  ['boundary contracts', 'boundary', { between: (root) => { fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true }); fs.writeFileSync(path.join(root, '.agentic-security', 'boundary-contracts.yml'), 'boundaries: []\n'); } }],
];

for (const [label, component, c] of GLOBAL_CASES) {
  test(`a changed ${label} is a global invalidation and the run says so`, () => {
    const root = tempRoot('glob'); const coldRoot = tempRoot('glob-cold');
    try {
      deep({ ...PROJECT }, root);
      if (c.between) c.between(root);
      if (c.between) c.between(coldRoot);
      const out = deep({ ...PROJECT }, root, { env: c.env || {} });
      assert.equal(out._incrementalStats.mode, 'cold');
      assert.match(out._incrementalStats.reason, new RegExp(`global input changed: .*${component}`));
      assert.deepEqual(out._incrementalStats.invalidation.changedGlobalComponents.includes(component), true);
      assert.deepEqual(normalized(out), normalized(deep({ ...PROJECT }, coldRoot, { incremental: false, env: c.env || {} })));
    } finally { cleanup(root, coldRoot); }
  });
}

test('altered type stubs invalidate the cache when stub filtering is on, and are ignored when it is off', () => {
  const root = tempRoot('stubs');
  const on = { AGENTIC_SECURITY_TYPE_STUBS: '1' };
  try {
    deep({ ...PROJECT }, root, { env: on, opts: { _stubsProvider: () => ({ signatures: new Map([['f', { paramTypes: ['string'] }]]) }) } });
    const same = deep({ ...PROJECT }, root, { env: on, opts: { _stubsProvider: () => ({ signatures: new Map([['f', { paramTypes: ['string'] }]]) }) } });
    assert.equal(same._incrementalStats.mode, 'warm', same._incrementalStats.reason);
    const changed = deep({ ...PROJECT }, root, { env: on, opts: { _stubsProvider: () => ({ signatures: new Map([['f', { paramTypes: ['number'] }]]) }) } });
    assert.equal(changed._incrementalStats.mode, 'cold');
    assert.match(changed._incrementalStats.reason, /global input changed: .*stubs/);
  } finally { cleanup(root); }
  // flag off: stubs are not an input at all
  const a = globalComponents({ scanRoot: null, fileContents: {}, env: {}, stubsProvider: () => 1 });
  const b = globalComponents({ scanRoot: null, fileContents: {}, env: {}, stubsProvider: () => 2 });
  assert.deepEqual(diffComponents(a, b), []);
});

test('a different scanner version or rule-pack digest is rejected with its own reason', () => {
  const v = secondScan({ opts: { scannerVersion: '1.0.0' }, coldOpts: {}, edited: PROJECT });
  cleanup(v.root);
  const root = tempRoot('ver');
  try {
    deep({ ...PROJECT }, root, { opts: { scannerVersion: '1.0.0', rulesDigest: 'r1' } });
    assert.match(deep({ ...PROJECT }, root, { opts: { scannerVersion: '1.0.1', rulesDigest: 'r1' } })._incrementalStats.reason, /scanner version changed/);
    assert.match(deep({ ...PROJECT }, root, { opts: { scannerVersion: '1.0.1', rulesDigest: 'r2' } })._incrementalStats.reason, /rule-pack changed/);
  } finally { cleanup(root); }
});

test('options the cache cannot honour fall back to cold, and say which', () => {
  for (const flag of ['AGENTIC_SECURITY_POINTS_TO', 'AGENTIC_SECURITY_KCFA_CALLSTRING']) {
    const { second, cold, stats, root } = secondScan({ env: { [flag]: '1' }, edited: PROJECT });
    try {
      assert.equal(stats.mode, 'cold');
      assert.match(stats.reason, new RegExp(`replay unsupported under ${flag}`));
      assert.deepEqual(normalized(second), normalized(cold));
    } finally { cleanup(root); }
  }
});

// ── contexts ────────────────────────────────────────────────────────────────

const summaryOf = (returnTainted, findings = []) => ({ returnTainted, mutatedParams: new Set(), mutatedThisFields: new Set(), taintedGlobals: new Set(), findings });

test('a tainted and a clean context do not contaminate each other after serialize and reload', () => {
  const cache = new SummaryCache();
  cache.set('f.js::helper@1', new Set(), summaryOf(false));
  cache.set('f.js::helper@1', new Set(['x']), summaryOf(true, [{ kind: 'taint', sinkId: 's', file: 'f.js', line: 3, trace: [] }]));
  cache.set('f.js::helper@1', new Set(['x', 'y']), summaryOf(true));
  const wire = JSON.parse(JSON.stringify(serializeContexts(cache)));
  assert.equal(wire.schema, CONTEXT_SCHEMA);
  assert.equal(wire.contexts['f.js::helper@1'].length, 3, 'every context is persisted under its own key');
  const fresh = new SummaryCache();
  const r = restoreContexts(fresh, wire, ['f.js::helper@1']);
  assert.deepEqual(r, { restored: 3, rejected: 0 });
  assert.equal(fresh.get('f.js::helper@1', new Set()).returnTainted, false, 'the empty-entry slot still answers CLEAN');
  assert.equal(fresh.get('f.js::helper@1', new Set(['x'])).returnTainted, true);
  assert.equal(fresh.get('f.js::helper@1', new Set(['x'])).findings.length, 1);
  assert.equal(fresh.get('f.js::helper@1', new Set(['x', 'y'])).findings.length, 0);
  assert.equal(fresh.has('f.js::helper@1', new Set(['y'])), false, 'a context that was never computed is not invented');
  assert.ok(!fresh.get('f.js::helper@1', new Set())._incrementalSeed, 'a verified context is not marked as a stand-in');
});

test('a context whose entry list does not reproduce its hash is rejected and the empty slot is untouched', () => {
  const cache = new SummaryCache();
  cache.set('q', new Set(), summaryOf(false));
  cache.set('q', new Set(['x']), summaryOf(true));
  const wire = JSON.parse(JSON.stringify(serializeContexts(cache)));
  const tainted = wire.contexts.q.find((c) => c.entry.length);
  tainted.entry = ['y'];                       // the key no longer matches the context it claims to be
  const fresh = new SummaryCache();
  const r = restoreContexts(fresh, wire, ['q']);
  assert.equal(r.rejected, 1);
  assert.equal(fresh.get('q', new Set()).returnTainted, false);
  assert.equal(fresh.has('q', new Set(['y'])), false);
  assert.equal(fresh.has('q', new Set(['x'])), false);
});

test('a budget-exceeded or recursion-stub summary is never persisted as a context', () => {
  const cache = new SummaryCache();
  cache.set('a', new Set(), { ...summaryOf(false), _budgetExceeded: true });
  cache.set('b', new Set(), { ...summaryOf(false), _recursive: true });
  cache.set('c', new Set(), summaryOf(true));
  const wire = serializeContexts(cache);
  assert.deepEqual(Object.keys(wire.contexts), ['c']);
  assert.deepEqual(wire.skipped, { 'budget-exceeded': 1, 'recursion-stub': 1 });
});

test('end to end: one helper called with clean and tainted arguments keeps both answers after reload', () => {
  const files = {
    'h.js': 'function helper(v){ db.query("SELECT " + v); }\nmodule.exports = { helper };\n',
    'clean.js': "const { helper } = require('./h');\nfunction callClean(req){ helper('constant'); }\nmodule.exports = { callClean };\n",
    'dirty.js': "const { helper } = require('./h');\nfunction callDirty(req){ helper(req.query.q); }\nmodule.exports = { callDirty };\n",
  };
  const root = tempRoot('ctx'); const coldRoot = tempRoot('ctx-cold');
  try {
    deep({ ...files }, root);
    const again = deep({ ...files }, root);
    assert.equal(again._incrementalStats.mode, 'warm');
    assert.deepEqual(normalized(again), normalized(deep({ ...files }, coldRoot, { incremental: false })));
    // sanitise the tainted caller only: its finding goes, and the clean caller is not blamed in its place
    const edited = { ...files, 'dirty.js': "const { helper } = require('./h');\nfunction callDirty(req){ helper(escapeSql(req.query.q)); }\nmodule.exports = { callDirty };\n" };
    const warm = deep({ ...edited }, root);
    assert.equal(warm._incrementalStats.mode, 'warm');
    assert.deepEqual(normalized(warm), normalized(deep({ ...edited }, tempRoot('ctx-cold2'), { incremental: false })));
    // and the other direction: the clean caller starts passing request data
    const edited2 = { ...files, 'clean.js': "const { helper } = require('./h');\nfunction callClean(req){ helper(req.body.z); }\nmodule.exports = { callClean };\n" };
    const warm2 = deep({ ...edited2 }, root);
    assert.deepEqual(normalized(warm2), normalized(deep({ ...edited2 }, tempRoot('ctx-cold3'), { incremental: false })));
  } finally { cleanup(root, coldRoot); }
});

// ── corruption and interruption ─────────────────────────────────────────────

function coldWithReason(mutateState, reasonRe, label) {
  test(`${label}: rejected whole, the scan is cold and says why, and the next scan heals it`, () => {
    const { second, cold, stats, root } = secondScan({ between: mutateState });
    try {
      assert.equal(stats.mode, 'cold');
      assert.match(stats.reason, reasonRe);
      assert.deepEqual(normalized(second), normalized(cold));
      assert.equal(stats.persisted.committed, true, 'the cold run wrote a fresh, valid cache');
      const healed = deep({ ...PROJECT }, root);
      assert.equal(healed._incrementalStats.mode, 'warm');
      assert.deepEqual(normalized(healed), normalized(cold));
    } finally { cleanup(root); }
  });
}

coldWithReason((root) => { const f = path.join(stateDirOf(root), 'replay.json'); const t = fs.readFileSync(f, 'utf8'); fs.writeFileSync(f, t.slice(0, Math.floor(t.length / 2))); }, /replay\.json failed its integrity digest/, 'a truncated record');
coldWithReason((root) => { const f = path.join(stateDirOf(root), 'deps.json'); fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace('"own"', '"0wn"')); }, /deps\.json failed its integrity digest/, 'a hand-edited record');
coldWithReason((root) => fs.writeFileSync(path.join(stateDirOf(root), 'version.json'), '{ this is not json'), /manifest is corrupt/, 'a corrupt manifest');
coldWithReason((root) => fs.writeFileSync(path.join(stateDirOf(root), 'version.json'), JSON.stringify({ scanner: '0.1', rules: 'x' })), /cache format is not incremental-state\/2 \(found legacy\)/, 'a legacy-format cache');
coldWithReason((root) => fs.rmSync(path.join(stateDirOf(root), 'deps.json')), /incomplete cache: deps\.json is missing/, 'an incomplete cache (a record is missing)');
coldWithReason((root) => rewriteManifestDigest(root, 'deps.json', JSON.stringify({ ...storedState(root).deps, schema: 'dep-graph/999' })), /incompatible schema/, 'an incompatible dependency-graph schema');
coldWithReason((root) => { const r = storedState(root).replay; rewriteManifestDigest(root, 'replay.json', JSON.stringify({ ...r, complete: false, reasons: ['deadline'] })); }, /prior analysis was incomplete \(deadline\)/, 'a cache from a cut-short analysis');
coldWithReason((root) => { const r = storedState(root).replay; rewriteManifestDigest(root, 'replay.json', JSON.stringify({ ...r, converged: false })); }, /fixed point did not converge/, 'a cache whose fixed point did not converge');

test('a crash after the temp files are written but before any rename leaves the previous generation intact', () => {
  const root = tempRoot('crash1'); const cold = tempRoot('crash1-cold');
  try {
    deep({ ...PROJECT }, root);
    const before = readIncrementalState(root);
    assert.ok(!before.rejected);
    const edited = { ...PROJECT, 'c.js': 'function hc(req){ exec(escape(req.query.c)); }\nmodule.exports = { hc };\n' };
    const crashed = deep({ ...edited }, root, { opts: { _incrementalIo: { renameSync() { throw new Error('simulated crash before rename'); } } } });
    assert.equal(crashed._incrementalStats.persisted.committed, false);
    assert.deepEqual(normalized(crashed), normalized(deep({ ...edited }, cold, { incremental: false })));
    const after = readIncrementalState(root);
    assert.ok(!after.rejected, `the previous generation must still verify: ${after.rejected}`);
    assert.equal(after.generation, before.generation);
    assert.deepEqual(fs.readdirSync(stateDirOf(root)).filter((n) => /\.tmp-/.test(n)), [], 'our own temp files are cleaned up');
    const next = deep({ ...edited }, root);
    assert.equal(next._incrementalStats.mode, 'warm');
    assert.notEqual(readIncrementalState(root).generation, before.generation);
  } finally { cleanup(root, cold); }
});

test('a crash between the data renames and the manifest rename is detected, never half-trusted', () => {
  const root = tempRoot('crash2'); const cold = tempRoot('crash2-cold');
  try {
    deep({ ...PROJECT }, root);
    const edited = { ...PROJECT, 'c.js': 'function hc(req){ exec(escape(req.query.c)); }\nmodule.exports = { hc };\n' };
    let calls = 0;
    const io = { renameSync(a, b) { calls += 1; if (/version\.json$/.test(b)) throw new Error('simulated crash at the manifest rename'); fs.renameSync(a, b); } };
    deep({ ...edited }, root, { opts: { _incrementalIo: io } });
    assert.ok(calls >= 5, 'the data files were renamed before the crash');
    const state = readIncrementalState(root);
    assert.match(state.rejected, /failed its integrity digest/, 'a new data file under the old manifest is a mismatch');
    const out = deep({ ...edited }, root);
    assert.equal(out._incrementalStats.mode, 'cold');
    assert.match(out._incrementalStats.reason, /integrity digest/);
    assert.deepEqual(normalized(out), normalized(deep({ ...edited }, cold, { incremental: false })));
    assert.equal(deep({ ...edited }, root)._incrementalStats.mode, 'warm', 'the cold run left a valid cache');
  } finally { cleanup(root, cold); }
});

test('commit is atomic at the unit level: a torn pair is rejected, a clean pair verifies', () => {
  const root = tempRoot('unit');
  try {
    const ok = commitIncrementalState(root, { files: { 'a.js': 'h' }, summaries: {}, callers: {}, deps: null, replay: null }, { scanner: '1', rules: 'r' });
    assert.equal(ok, true);
    const st = readIncrementalState(root);
    assert.equal(st.rejected, undefined);
    assert.deepEqual(st.version, { scanner: '1', rules: 'r' });
    assert.equal(validateIncrementalState(st, { scanner: '1', rules: 'r' }).valid, true);
    let n = 0;
    const torn = commitIncrementalState(root, { files: { 'b.js': 'h2' }, summaries: {}, callers: {}, deps: null, replay: null }, { scanner: '1', rules: 'r' }, { renameSync(a, b) { n += 1; if (n === 2) throw new Error('crash'); fs.renameSync(a, b); } });
    assert.equal(torn, false);
    assert.match(readIncrementalState(root).rejected, /integrity digest/);
    assert.equal(INCREMENTAL_FORMAT, 'incremental-state/2');
  } finally { cleanup(root); }
});

// ── provenance in the output ────────────────────────────────────────────────

test('findings and the scan summary say what was reused and what was recomputed', () => {
  const root = tempRoot('prov');
  try {
    const first = deep({ ...PROJECT }, root);
    assert.ok(first.length > 0 && first.every((f) => f.cacheProvenance && f.cacheProvenance.state === 'recomputed'), 'a cold run recomputes every finding');
    const edited = { ...PROJECT, 'c.js': 'function hc(req){ exec(req.query.c + "x"); }\nmodule.exports = { hc };\n' };
    const warm = deep({ ...edited }, root);
    const states = Object.fromEntries(warm.filter((f) => /^ir-taint:/.test(f.id)).map((f) => [f.file, f.cacheProvenance.state]));
    assert.equal(states['c.js'], 'recomputed', 'the edited function was analysed in this scan');
    assert.equal(states['a.js'] ?? states['lib.js'], 'reused', 'an untouched function was replayed');
    const reused = warm.find((f) => f.cacheProvenance.state === 'reused');
    assert.match(reused.cacheProvenance.generation, /^[0-9a-f]{12}$/, 'a reused fact names the generation it came from');
    assert.match(reused.cacheProvenance.closureFingerprint, /^[0-9a-f]{64}$/, 'and the dependency fingerprint it was validated against');
    const st = warm._incrementalStats;
    assert.equal(st.provenance.reusedFindings + st.provenance.recomputedFindings, warm.length);
    assert.ok(st.provenance.reusedFunctions > 0 && st.provenance.recomputedFunctions > 0);
  } finally { cleanup(root); }
});

// ── languages ───────────────────────────────────────────────────────────────

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const copyExample = (rel) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'dag05-ex-')); fs.cpSync(path.join(REPO, 'examples', rel), d, { recursive: true }); return d; };
const keys = (scan) => (scan.findings || []).map((f) => `${f.file}:${f.line}:${f.vuln}:${f.cwe}`).sort();

async function scanWith(root, incremental) {
  const prev = process.env.AGENTIC_SECURITY_INCREMENTAL;
  if (incremental) process.env.AGENTIC_SECURITY_INCREMENTAL = '1'; else delete process.env.AGENTIC_SECURITY_INCREMENTAL;
  try {
    const { runScan } = await import('../src/runScan.js');
    return (await runScan(root, { deep: true, deepInCi: true })).scan;
  } finally { if (prev === undefined) delete process.env.AGENTIC_SECURITY_INCREMENTAL; else process.env.AGENTIC_SECURITY_INCREMENTAL = prev; }
}

test('Haskell: warm equals cold, an edit recomputes, and a cabal plan export or manifest change is a build-configuration invalidation', async () => {
  const root = copyExample('haskell-app/vulnerable'); const coldRoot = copyExample('haskell-app/vulnerable');
  try {
    const first = await scanWith(root, true);
    assert.equal(first.scanHealth.deepAnalysis.incremental.mode, 'cold');
    const second = await scanWith(root, true);
    const inc2 = second.scanHealth.deepAnalysis.incremental;
    assert.equal(inc2.mode, 'warm', inc2.reason);
    assert.ok(inc2.provenance.reusedFunctions > 0);
    assert.deepEqual(keys(second), keys(await scanWith(coldRoot, false)));

    // an edit to the Haskell source recomputes and still equals a cold scan of the same edit
    const mainHs = path.join(root, 'src', 'Main.hs');
    fs.appendFileSync(mainHs, '\n\nextraHelper :: String -> String\nextraHelper s = s\n');
    fs.appendFileSync(path.join(coldRoot, 'src', 'Main.hs'), '\n\nextraHelper :: String -> String\nextraHelper s = s\n');
    const third = await scanWith(root, true);
    assert.equal(third.scanHealth.deepAnalysis.incremental.mode, 'warm');
    assert.deepEqual(keys(third), keys(await scanWith(coldRoot, false)));

    // a cabal plan export appearing (build plan) invalidates everything and says it was the build configuration
    fs.mkdirSync(path.join(root, 'dist-newstyle', 'cache'), { recursive: true });
    fs.writeFileSync(path.join(root, 'dist-newstyle', 'cache', 'plan.json'), JSON.stringify({ 'cabal-version': '3.10', 'compiler-id': 'ghc-9.6.4', 'install-plan': [] }));
    const fourth = await scanWith(root, true);
    assert.equal(fourth.scanHealth.deepAnalysis.incremental.mode, 'cold');
    assert.match(fourth.scanHealth.deepAnalysis.incremental.reason, /global input changed: build/);
    assert.equal((await scanWith(root, true)).scanHealth.deepAnalysis.incremental.mode, 'warm', 'the plan-change run left a valid cache');
    // and a manifest edit is the same kind of invalidation
    fs.appendFileSync(path.join(root, 'app.cabal'), '\n-- bumped\n');
    const sixth = await scanWith(root, true);
    assert.equal(sixth.scanHealth.deepAnalysis.incremental.mode, 'cold');
    assert.match(sixth.scanHealth.deepAnalysis.incremental.reason, /global input changed: build/);
  } finally { cleanup(root, coldRoot); }
});

test('Nix/NixOS: there is no incremental hook, the scan is cold every time and says so, and the findings equal a plain scan', async () => {
  const root = copyExample('nixos-host/vulnerable'); const coldRoot = copyExample('nixos-host/vulnerable');
  try {
    const one = await scanWith(root, true);
    const two = await scanWith(root, true);
    for (const s of [one, two]) {
      const inc = s.scanHealth.deepAnalysis.incremental;
      assert.equal(inc.mode, 'cold', JSON.stringify(inc));
      assert.match(inc.reason, /nothing to reuse|did not run/);
      assert.deepEqual(inc.languagesWithoutIncrementalHook, ['nix']);
      assert.equal(inc.languages.nix.incremental, false);
      assert.match(inc.note, /keep no cross-scan state and run in full/);
    }
    assert.deepEqual(keys(two), keys(await scanWith(coldRoot, false)));
    // a changed configuration is picked up on the very next scan (nothing is cached to go stale)
    fs.appendFileSync(path.join(root, 'configuration.nix'), '\n# edited\n');
    fs.appendFileSync(path.join(coldRoot, 'configuration.nix'), '\n# edited\n');
    assert.deepEqual(keys(await scanWith(root, true)), keys(await scanWith(coldRoot, false)));
  } finally { cleanup(root, coldRoot); }
});
