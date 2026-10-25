// DAG-05 acceptance: dependency-complete incremental analysis.
//
// The property under test is the one that matters for a cache: a WARM scan (reusing what a previous
// scan stored) must give the same answer as a COLD scan of the same tree, over a matrix of edits that
// each break a different dependency (a body, a callee that was deleted, an import, a renamed function,
// a removed file, a new file, a recursive cycle, a class whose methods share state). Speed is not
// asserted here; bench/dag-incremental measures it.
//
// Each case also checks the INVALIDATION itself, not just the final answer: the functions that must
// be recomputed are recomputed, and an unrelated function is not.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { tempRoot, cleanup, deep, normalized, incompleteReasons, storedState } from './helpers/incremental-harness.js';
import { buildProjectIR } from '../src/ir/index.js';
import { buildClassHierarchy, annotateRTA } from '../src/ir/class-hierarchy.js';
import {
  buildDependencyModel, canonicalFunctionText, planIncremental, stableSerialize, countByReason,
} from '../src/dataflow/dep-fingerprint.js';

const BASE = Object.freeze({
  'lib/util.js': 'function pass(x){ return x; }\nfunction wrap(x){ return pass(x); }\nmodule.exports = { pass, wrap };\n',
  'lib/db.js': 'function runQuery(q){ db.query("SELECT * FROM t WHERE a = " + q); }\nmodule.exports = { runQuery };\n',
  'lib/clean.js': 'function clean(x){ return escapeSql(x); }\nmodule.exports = { clean };\n',
  'routes/a.js': "const { wrap } = require('../lib/util');\nconst { runQuery } = require('../lib/db');\nfunction handlerA(req, res){ const v = wrap(req.query.id); runQuery(v); }\nmodule.exports = { handlerA };\n",
  'routes/b.js': "const { clean } = require('../lib/clean');\nconst { runQuery } = require('../lib/db');\nfunction handlerB(req, res){ const v = clean(req.query.id); runQuery(v); }\nmodule.exports = { handlerB };\n",
  'routes/c.js': "function handlerC(req, res){ exec('ls ' + req.query.dir); }\nmodule.exports = { handlerC };\n",
  'lib/rec.js': 'function ping(n){ if (n) { return pong(n); } return 1; }\nfunction pong(n){ return ping(n); }\nmodule.exports = { ping };\n',
});

/**
 * Warm scan after `mutate` versus a cold scan of the mutated tree. Returns both plus the stats.
 * The cold scan uses its own root so nothing it writes can reach the warm one.
 */
function warmVersusCold(mutate, { base = BASE, opts, env } = {}) {
  const warmRoot = tempRoot('warm'); const coldRoot = tempRoot('cold');
  try {
    deep({ ...base }, warmRoot, { opts, env });                      // generation 1 (cold, writes the cache)
    const edited = { ...base }; mutate(edited);
    const warm = deep(edited, warmRoot, { opts, env });              // generation 2 (warm)
    const cold = deep(edited, coldRoot, { incremental: false, opts, env });
    return { warm, cold, stats: warm._incrementalStats, warmRoot, edited };
  } catch (e) { cleanup(warmRoot, coldRoot); throw e; } finally { cleanup(coldRoot); }
}

const MATRIX = {
  'edit a leaf body (sanitise it)': { mutate: (f) => { f['lib/util.js'] = 'function pass(x){ return escapeSql(x); }\nfunction wrap(x){ return pass(x); }\nmodule.exports = { pass, wrap };\n'; }, mustRecompute: ['wrap'], mustReuse: ['handlerC', 'clean'] },
  'delete a callee a caller still names': { mutate: (f) => { f['lib/util.js'] = 'function wrap(x){ return pass(x); }\nmodule.exports = { wrap };\n'; }, mustRecompute: ['wrap'], mustReuse: ['handlerC'] },
  'rename a function': { mutate: (f) => { f['lib/util.js'] = 'function forward(x){ return x; }\nfunction wrap(x){ return pass(x); }\nmodule.exports = { forward, wrap };\n'; }, mustRecompute: ['wrap', 'forward'], mustReuse: ['handlerC'] },
  'change an import': { mutate: (f) => { f['routes/b.js'] = "const { pass } = require('../lib/util');\nconst { runQuery } = require('../lib/db');\nfunction handlerB(req, res){ const v = pass(req.query.id); runQuery(v); }\nmodule.exports = { handlerB };\n"; }, mustRecompute: ['handlerB'], mustReuse: ['handlerC', 'clean'] },
  'add a file with a new vulnerability': { mutate: (f) => { f['routes/d.js'] = 'function handlerD(req, res){ eval(req.body.code); }\nmodule.exports = { handlerD };\n'; }, mustRecompute: ['handlerD'], mustReuse: ['handlerA', 'handlerC'] },
  'remove a file': { mutate: (f) => { delete f['routes/c.js']; }, mustRecompute: [], mustReuse: ['handlerA', 'handlerB'] },
  'unrelated edit in another file': { mutate: (f) => { f['routes/c.js'] = `${f['routes/c.js']}\n// note\nfunction other(){ return 1; }\n`; }, mustRecompute: ['other'], mustReuse: ['handlerA', 'handlerB', 'wrap'] },
  'edit one member of a recursive cycle': { mutate: (f) => { f['lib/rec.js'] = 'function ping(n){ if (n) { return pong(n); } return req.query.z; }\nfunction pong(n){ return ping(n); }\nmodule.exports = { ping };\n'; }, mustRecompute: ['ping', 'pong'], mustReuse: ['handlerA'] },
};

const nameOf = (qid) => (/::([^:@]+)@\d+/.exec(qid) || [])[1] || qid;

for (const [label, c] of Object.entries(MATRIX)) {
  test(`cold and warm agree, and exactly the dependents recompute: ${label}`, () => {
    const { warm, cold, stats, warmRoot } = warmVersusCold(c.mutate);
    try {
      assert.equal(stats.mode, 'warm', `expected a warm run, got cold: ${stats.reason}`);
      assert.deepEqual(normalized(warm), normalized(cold), 'warm findings differ from a cold scan of the same tree');
      assert.deepEqual(incompleteReasons(warm), incompleteReasons(cold), 'completion differs between warm and cold');
      const dirtyNames = new Set(stats.invalidation.dirty.map((d) => nameOf(d.qid)));
      for (const n of c.mustRecompute) assert.ok(dirtyNames.has(n), `${n} depends on the edit and must be recomputed (dirty: ${[...dirtyNames].join(', ')})`);
      for (const n of c.mustReuse) assert.ok(!dirtyNames.has(n), `${n} does not depend on the edit and must be reused (dirty: ${[...dirtyNames].join(', ')})`);
      assert.ok(stats.provenance.reusedFunctions > 0, 'a one-file edit must not recompute everything');
      assert.equal(Object.values(stats.invalidation.dirtyByReason).reduce((a, b) => a + b, 0), stats.invalidation.dirtyFunctions);
    } finally { cleanup(warmRoot); }
  });
}

test('the dirty set names the dependents and spares the unrelated (edit a leaf)', () => {
  const root = tempRoot('dirty');
  try {
    deep({ ...BASE }, root);
    const edited = { ...BASE, 'lib/util.js': 'function pass(x){ return escapeSql(x); }\nfunction wrap(x){ return pass(x); }\nmodule.exports = { pass, wrap };\n' };
    const out = deep(edited, root);
    const st = out._incrementalStats;
    assert.equal(st.mode, 'warm');
    const afterDeps = storedState(root).deps.functions;
    // wrap calls pass, handlerA calls wrap: both are dependents of the edit and recomputed; the rest are reused
    const reused = Object.keys(afterDeps).filter((q) => !/pass@|wrap@|handlerA@/.test(q));
    assert.ok(reused.length >= 5);
    assert.ok(st.invalidation.dirtyFunctions >= 3 && st.invalidation.dirtyFunctions <= 4, `dirty=${st.invalidation.dirtyFunctions}`);
    assert.ok(st.provenance.reusedFunctions >= reused.length - 1);
  } finally { cleanup(root); }
});

test('a deleted callee invalidates its caller through the PRIOR graph even when the current IR has no trace of it', () => {
  // The caller's own fingerprint is held identical on purpose: the only evidence left that something
  // moved is the prior graph, which still has the edge caller -> callee and the callee's file symbols.
  const prior = {
    global: { options: 'o' },
    deps: { functions: { 'f.js::A@1': { file: 'f.js', own: 'a', closure: 'ca', callees: ['g.js::B@1'] }, 'g.js::B@1': { file: 'g.js', own: 'b', closure: 'cb', callees: [] }, 'h.js::C@1': { file: 'h.js', own: 'c', closure: 'cc', callees: [] } }, sccs: {}, fileSymbols: { 'f.js': ['f.js::A@1'], 'g.js': ['g.js::B@1'], 'h.js': ['h.js::C@1'] } },
    hasRecord: () => true,
  };
  const current = {
    global: { options: 'o' },
    model: { functions: { 'f.js::A@1': { file: 'f.js', own: 'a', closure: 'ca', callees: [] }, 'h.js::C@1': { file: 'h.js', own: 'c', closure: 'cc', callees: [] } }, sccs: {}, fileSymbols: { 'f.js': ['f.js::A@1'], 'h.js': ['h.js::C@1'] } },
  };
  const plan = planIncremental(prior, current);
  assert.equal(plan.mode, 'warm');
  assert.deepEqual(plan.removed, ['g.js::B@1']);
  assert.equal(plan.dirty.get('f.js::A@1'), 'callee-removed-or-renamed');
  assert.ok(plan.clean.has('h.js::C@1') && !plan.clean.has('f.js::A@1'));
});

test('a renamed function (same file, new qid) is reported as moved and its callers are dirty', () => {
  const mk = (names) => Object.fromEntries(names.map((n) => [`u.js::${n}@1`, { file: 'u.js', name: n, own: n, closure: n, callees: [] }]));
  const prior = { global: {}, deps: { functions: { ...mk(['pass']), 'a.js::caller@1': { file: 'a.js', own: 'x', closure: 'x', callees: ['u.js::pass@1'] } }, sccs: {} }, hasRecord: () => true };
  const current = { global: {}, model: { functions: { ...mk(['forward']), 'a.js::caller@1': { file: 'a.js', own: 'x', closure: 'x', callees: [] } }, sccs: {}, fileSymbols: { 'u.js': ['u.js::forward@1'], 'a.js': ['a.js::caller@1'] } } };
  const plan = planIncremental(prior, current);
  assert.deepEqual(plan.removed, ['u.js::pass@1']);
  assert.deepEqual(plan.renamed.map((r) => r.name), ['pass']);
  assert.equal(plan.dirty.get('a.js::caller@1'), 'callee-removed-or-renamed');
  assert.equal(plan.dirty.get('u.js::forward@1'), 'new');
});

test('a function with no cached record is never replayed', () => {
  const prior = { global: {}, deps: { functions: { 'a.js::f@1': { file: 'a.js', own: 'x', closure: 'x', callees: [] } }, sccs: {} }, hasRecord: () => false };
  const current = { global: {}, model: { functions: { 'a.js::f@1': { file: 'a.js', own: 'x', closure: 'x', callees: [] } }, sccs: {}, fileSymbols: {} } };
  const plan = planIncremental(prior, current);
  assert.equal(plan.clean.size, 0);
  assert.equal(plan.dirty.get('a.js::f@1'), 'no-cached-record');
});

test('a whole cycle is recomputed when one member changes (SCC widening)', () => {
  const root = tempRoot('scc');
  try {
    deep({ ...BASE }, root);
    // pong is edited only by a comment-free semantic change; ping is untouched in text and calls pong
    const edited = { ...BASE, 'lib/rec.js': 'function ping(n){ if (n) { return pong(n); } return 1; }\nfunction pong(n){ return ping(n) + req.query.q; }\nmodule.exports = { ping };\n' };
    const out = deep(edited, root);
    const st = out._incrementalStats;
    assert.equal(st.mode, 'warm');
    assert.ok(st.invalidation.dirtyByReason['scc-member'] >= 1 || st.invalidation.dirtyByReason['depends-on-changed'] >= 1, JSON.stringify(st.invalidation.dirtyByReason));
    const cold = deep(edited, tempRoot('cold-scc'), { incremental: false });
    assert.deepEqual(normalized(out), normalized(cold));
    const dep = storedState(root).deps;
    const members = Object.values(dep.sccs)[0];
    assert.ok(members && members.length === 2, 'ping and pong form one component');
  } finally { cleanup(root); }
});

test('a JavaScript class declares no fields, so its methods are independent and the warm answer still matches a cold scan', () => {
  const cls = (setBody) => ({
    'svc.js': `class Svc {\n  setQ(req) { ${setBody} }\n  run() { db.query("SELECT " + this.q); }\n  other() { return 1; }\n}\nmodule.exports = { Svc };\n`,
    'free.js': 'function free(req) { exec(req.query.c); }\nmodule.exports = { free };\n',
  });
  const root = tempRoot('cls'); const cold = tempRoot('cls-cold');
  try {
    deep(cls('this.q = 1;'), root);
    const edited = cls('this.q = req.query.q;');
    const warm = deep(edited, root);
    assert.equal(warm._incrementalStats.mode, 'warm');
    assert.deepEqual(normalized(warm), normalized(deep(edited, cold, { incremental: false })));
    assert.ok(warm._incrementalStats.provenance.reusedFunctions >= 1, 'the unrelated file is reused');
  } finally { cleanup(root, cold); }
});

test('methods of a class with DECLARED fields share state: they form one component and an unrelated function stays out', () => {
  const src = {
    'svc.js': 'class Svc {\n  setQ(req) { this.q = req.query.q; }\n  run() { db.query("SELECT " + this.q); }\n  other() { return 1; }\n}\nfunction use(s) { return s.run(); }\nmodule.exports = { Svc, use };\n',
    'free.js': 'function free(req) { exec(req.query.c); }\nmodule.exports = { free };\n',
  };
  const model = (fields) => {
    const { perFile, callGraph } = buildProjectIR(src);
    perFile['svc.js'].classes = [{ name: 'Svc', line: 1, bases: [], fields }];
    const cha = buildClassHierarchy(perFile, callGraph); annotateRTA(cha, perFile);
    return buildDependencyModel({ perFileIR: perFile, callGraph, cha, fileContents: src });
  };
  const withoutFields = model([]);
  assert.equal(Object.keys(withoutFields.sccs).length, 0, 'a class with no declared fields couples nothing');
  const withFields = model(['q']);
  const groups = Object.values(withFields.sccs);
  assert.equal(groups.length, 1);
  const names = groups[0].map(nameOf).sort();
  assert.deepEqual(names, ['other', 'run', 'setQ']);
  const freeQ = Object.keys(withFields.functions).find((k) => /::free@/.test(k));
  assert.equal(withFields.functions[freeQ].scc, null, 'an unrelated function stays out');
});

test('cold and warm agree under a small function limit (records know whether the main loop covered a function)', () => {
  const opts = { fnLimit: 4 };
  const { warm, cold, stats, warmRoot } = warmVersusCold(MATRIX['edit a leaf body (sanitise it)'].mutate, { opts });
  try {
    assert.equal(stats.mode, 'warm', stats.reason);
    assert.deepEqual(normalized(warm), normalized(cold));
    assert.deepEqual(incompleteReasons(warm), incompleteReasons(cold));
  } finally { cleanup(warmRoot); }
});

test('the body fingerprint ignores node ids (a process-global counter) and sees real edits', () => {
  const src = { 'a.js': 'function f(x){ const y = x + 1; return y; }\nmodule.exports = { f };\n' };
  const one = buildProjectIR(src);
  const two = buildProjectIR({ 'pre.js': 'function p(a){ return a; }\nfunction q(b){ return p(b); }\n', ...src });
  const qid = [...one.callGraph.functions.keys()].find((k) => /::f@/.test(k));
  const a = canonicalFunctionText(one.callGraph.functions.get(qid));
  const b = canonicalFunctionText(two.callGraph.functions.get(qid));
  assert.equal(a, b, 'identical source must fingerprint identically across builds');
  const three = buildProjectIR({ 'a.js': 'function f(x){ const y = x + 2; return y; }\nmodule.exports = { f };\n' });
  assert.notEqual(a, canonicalFunctionText(three.callGraph.functions.get(qid)));
});

test('a callee that appears for a name a caller already used changes the caller (resolution is part of the fingerprint)', () => {
  const model = (files) => { const { perFile, callGraph } = buildProjectIR(files); const cha = buildClassHierarchy(perFile, callGraph); annotateRTA(cha, perFile); return buildDependencyModel({ perFileIR: perFile, callGraph, cha, fileContents: files }); };
  const caller = 'function go(x){ return helper(x); }\nmodule.exports = { go };\n';
  const before = model({ 'a.js': caller });
  const after = model({ 'a.js': caller, 'b.js': 'function helper(x){ return x; }\nmodule.exports = { helper };\n' });
  const q = Object.keys(before.functions).find((k) => /::go@/.test(k));
  assert.equal(before.functions[q].callees.length, 0);
  assert.notEqual(before.functions[q].own, after.functions[q].own, 'go() did not change, but what helper() means for it did');
});

test('countByReason and stableSerialize are deterministic', () => {
  assert.deepEqual(countByReason(new Map([['a', 'x'], ['b', 'y'], ['c', 'x']])), { x: 2, y: 1 });
  assert.equal(stableSerialize({ b: 1, a: [new Set([2, 1]), new Map([['k', 1]])] }), stableSerialize({ a: [new Set([1, 2]), new Map([['k', 1]])], b: 1 }));
});

test('a removed file is reported with its symbols, from the prior file-to-symbol mapping', () => {
  const { stats, warmRoot } = warmVersusCold(MATRIX['remove a file'].mutate);
  try {
    assert.deepEqual(stats.invalidation.removedFiles, ['routes/c.js']);
    assert.ok(stats.invalidation.removedSymbols.some((q) => /handlerC/.test(q)), `removed symbols: ${stats.invalidation.removedSymbols.join(', ')}`);
  } finally { cleanup(warmRoot); }
});

test('Python: a warm scan after an edit agrees with a cold scan', () => {
  const base = {
    'util.py': 'def passthrough(x):\n    return x\n\ndef wrap(x):\n    return passthrough(x)\n',
    'views.py': 'from util import wrap\nimport os\n\ndef run(req):\n    cmd = wrap(req.args.get("c"))\n    os.system(cmd)\n\ndef other(req):\n    return 1\n',
    'safe.py': 'def noop():\n    return 0\n',
  };
  const root = tempRoot('py'); const coldRoot = tempRoot('py-cold');
  try {
    deep({ ...base }, root);
    for (const edit of [
      { 'util.py': 'import shlex\n\ndef passthrough(x):\n    return shlex.quote(x)\n\ndef wrap(x):\n    return passthrough(x)\n' },
      { 'views.py': `${base['views.py']}\ndef extra(req):\n    os.system(req.args.get("z"))\n` },
    ]) {
      const edited = { ...base, ...edit };
      const warm = deep({ ...edited }, root);
      assert.equal(warm._incrementalStats.mode, 'warm', warm._incrementalStats.reason);
      assert.deepEqual(normalized(warm), normalized(deep({ ...edited }, coldRoot, { incremental: false })));
    }
  } finally { cleanup(root, coldRoot); }
});

// A seeded random walk over edits: wrap a return, add a vulnerable function, rename a function, drop a
// file, restore a file. After EVERY step the warm result must equal a cold scan of the same tree.
test('seeded random edit walk: warm equals cold after every step', () => {
  const FILES = 8;
  const proj = {};
  for (let i = 0; i < FILES; i++) {
    proj[`m${i}.js`] = [
      i > 0 ? `const { leaf_${i - 1} } = require('./m${i - 1}');` : '',
      `function leaf_${i}(v) { const t = String(v); return t.trim(); }`,
      `function mid_${i}(v) { const a = v + 1; return leaf_${i}(a); }`,
      `function top_${i}(v) { const b = mid_${i}(v); ${i > 0 ? `return b + leaf_${i - 1}(v);` : 'return b;'} }`,
      i % 3 === 0 ? `function handler_${i}(req, res) { const q = top_${i}(req.query.id); db.query("SELECT " + q); }` : `function util_${i}(v) { return top_${i}(v); }`,
      `module.exports = { leaf_${i}, top_${i} };`,
    ].filter(Boolean).join('\n') + '\n';
  }
  let seed = 424242;
  const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
  const root = tempRoot('walk');
  const original = { ...proj };
  let cur = { ...proj };
  let ran = 0; let warmRuns = 0; let sawFindings = false;
  try {
    deep({ ...cur }, root);
    for (let step = 0; step < 14; step++) {
      const names = Object.keys(cur);
      const f = names[Math.floor(rnd() * names.length)];
      const next = { ...cur };
      const kind = Math.floor(rnd() * 5);
      if (kind === 0) next[f] = next[f].replace(/return ([^;]+);/, 'return String($1);');
      else if (kind === 1) next[f] = `${next[f]}function added_${step}(req) { exec(req.query.q); }\n`;
      else if (kind === 2) next[f] = next[f].replace(/function (mid_\d+)\(/, 'function $1Renamed(');
      else if (kind === 3 && names.length > 4) delete next[f];
      else if (original[f] === undefined) continue; else next[f] = original[f];
      if (!Object.keys(next).length) continue;
      const warm = deep({ ...next }, root);
      ran += 1; if (warm._incrementalStats.mode === 'warm') warmRuns += 1; if (warm.some((f) => /^ir-taint:/.test(f.id))) sawFindings = true;
      const coldRoot = tempRoot('walk-cold');
      try {
        const cold = deep({ ...next }, coldRoot, { incremental: false });
        assert.deepEqual(normalized(warm), normalized(cold), `step ${step} (kind ${kind}, ${f}): warm differs from cold`);
        assert.deepEqual(incompleteReasons(warm), incompleteReasons(cold), `step ${step}: completion differs`);
      } finally { cleanup(coldRoot); }
      cur = next;
    }
    assert.ok(ran >= 10, `the walk must exercise at least 10 steps, ran ${ran}`);
    assert.equal(warmRuns, ran, 'every step after the first reuses the cache');
    assert.ok(sawFindings, 'the walk must involve real findings or the comparison is vacuous');
  } finally { cleanup(root); }
});

test('a this.method() call is a dependency of its caller (the Babel frontend spells this as _this_)', () => {
  const svc = (bBody) => ({
    'svc.js': `class Svc {\n  a(req) { return this.b(req.query.x); }\n  b(v) { ${bBody} }\n  c() { return 1; }\n}\nmodule.exports = { Svc };\n`,
    'free.js': 'function free(req) { exec(req.query.c); }\nmodule.exports = { free };\n',
  });
  const root = tempRoot('this'); const cold = tempRoot('this-cold');
  try {
    deep(svc('db.query("SELECT " + v); return v;'), root);
    const edited = svc('db.query("SELECT " + escapeSql(v)); return v;');
    const warm = deep(edited, root);
    assert.equal(warm._incrementalStats.mode, 'warm');
    assert.deepEqual(normalized(warm), normalized(deep(edited, cold, { incremental: false })));
    const dirty = new Set(warm._incrementalStats.invalidation.dirty.map((d) => nameOf(d.qid)));
    assert.ok(dirty.has('b') && dirty.has('a'), `b changed and a calls it through this: dirty = ${[...dirty].join(', ')}`);
    assert.ok(!dirty.has('free'), 'an unrelated file is not recomputed');
  } finally { cleanup(root, cold); }
});
