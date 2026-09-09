// Progress reporting for the deep taint engine's main analysis loop. Before
// this, `runTaintEngine`'s dominant per-function loop (the one already
// bounded by `fnLimit`) ran silently for its whole duration — on a large
// project this is the single longest-running phase of a scan and gave the
// operator no sign anything was happening. `opts.onProgress`, when supplied,
// fires once per function actually analyzed by that loop, additive and
// opt-in (an omitted callback changes nothing — every existing caller stays
// byte-identical).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR } from '../src/ir/index.js';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

test('runTaintEngine: reports progress once per analyzed function via opts.onProgress', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function f1(x){ return x; }\nfunction f2(x){ return x; }\nfunction f3(x){ return x; }\n',
  });
  const calls = [];
  runTaintEngine(perFile, callGraph, {
    fnLimit: 5000,
    deadlineMs: Date.now() + 30000,
    onProgress: (p) => calls.push({ ...p }),
  });
  // buildProjectIR also synthesizes a module-level function for top-level
  // statements, so the real function count can exceed the 3 declared here —
  // derive the expectation from the call graph itself rather than assume it.
  const total = callGraph.functions.size;
  assert.equal(calls.length, total, `expected one progress call per function, got ${calls.length} for ${total} functions`);
  assert.deepEqual(calls.map(c => c.current), Array.from({ length: total }, (_, i) => i + 1));
  assert.ok(calls.every(c => c.total === total), `expected total=${total} on every call, got ${JSON.stringify(calls)}`);
});

test('runTaintEngine: omitting opts.onProgress does not throw and changes nothing else', () => {
  const { perFile, callGraph } = buildProjectIR({ 'a.js': 'function f(x){ return x; }\n' });
  assert.doesNotThrow(() => runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 }));
});

test('runTaintEngine: opts.onProgress total respects fnLimit, not the full function count', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function f1(x){ return x; }\nfunction f2(x){ return x; }\nfunction f3(x){ return x; }\n',
  });
  const calls = [];
  runTaintEngine(perFile, callGraph, {
    fnLimit: 2,
    deadlineMs: Date.now() + 30000,
    onProgress: (p) => calls.push({ ...p }),
  });
  assert.equal(calls.length, 2, `expected the loop to stop at fnLimit=2, got ${calls.length} progress calls`);
  assert.ok(calls.every(c => c.total === 2), `expected total=2 on every call, got ${JSON.stringify(calls)}`);
});

test('runDeepAnalysis: threads opts.onProgress through to the taint engine\'s main loop', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function f1(x){ return x; }\nfunction f2(x){ return x; }\n',
  });
  const calls = [];
  runDeepAnalysis(perFile, callGraph, {
    fnLimit: 5000,
    deadlineMs: Date.now() + 30000,
    onProgress: (p) => calls.push({ ...p }),
  });
  assert.ok(calls.length >= 2, `expected onProgress to fire for both functions, got ${calls.length} calls`);
});
