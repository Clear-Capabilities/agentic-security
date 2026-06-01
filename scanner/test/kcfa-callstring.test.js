// R2 — bounded k=1 call-string context sensitivity (opt-in) tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SummaryCache } from '../src/dataflow/summaries.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { buildProjectIR } from '../src/ir/index.js';

function withCallString(val, fn) {
  const prev = process.env.AGENTIC_SECURITY_KCFA_CALLSTRING;
  if (val) process.env.AGENTIC_SECURITY_KCFA_CALLSTRING = val;
  else delete process.env.AGENTIC_SECURITY_KCFA_CALLSTRING;
  try { return fn(); }
  finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_KCFA_CALLSTRING;
    else process.env.AGENTIC_SECURITY_KCFA_CALLSTRING = prev;
  }
}

test('OFF (default): caller context does not change the cache key', () => {
  withCallString(undefined, () => {
    const c = new SummaryCache();
    const k1 = c._key('H::1', new Set());
    c.setCallerContext('A::1');
    assert.equal(c._key('H::1', new Set()), k1, 'key must be byte-identical when call-string is off');
  });
});

test('ON: distinct callers produce distinct keys; setCallerContext returns previous', () => {
  withCallString('1', () => {
    const c = new SummaryCache();
    c.setCallerContext('A::1');
    const kA = c._key('H::1', new Set());
    const prev = c.setCallerContext('B::1');
    const kB = c._key('H::1', new Set());
    assert.notEqual(kA, kB, 'same callee+entry under different callers must key differently');
    assert.equal(prev, 'A::1');
  });
});

test('ON: a helper keeps a distinct summary per caller (no over-merge)', () => {
  withCallString('1', () => {
    const c = new SummaryCache();
    c.setCallerContext('A::1'); c.set('H::1', new Set(), { returnTainted: true });
    c.setCallerContext('B::1'); c.set('H::1', new Set(), { returnTainted: false });
    c.setCallerContext('A::1'); assert.equal(c.get('H::1', new Set()).returnTainted, true);
    c.setCallerContext('B::1'); assert.equal(c.get('H::1', new Set()).returnTainted, false);
  });
});

test('OFF: the same helper summary is SHARED across callers (the monovariant baseline)', () => {
  withCallString(undefined, () => {
    const c = new SummaryCache();
    c.setCallerContext('A::1'); c.set('H::1', new Set(), { returnTainted: true });
    c.setCallerContext('B::1');
    assert.equal(c.get('H::1', new Set()).returnTainted, true, 'off → callers share one summary');
  });
});

test('integration: enabling call-string does not break the engine (flow still fires)', () => {
  // A baseline-caught flow: enabling call-string keying must not regress it.
  const code = 'function h(req){ eval(req.query.id); }';
  const run = () => { const { perFile, callGraph } = buildProjectIR({ 'h.js': code }); return runDeepAnalysis(perFile, callGraph, {}).length; };
  const off = withCallString(undefined, run);
  const on = withCallString('1', run);
  assert.ok(off >= 1, 'baseline flow should fire');
  assert.equal(on, off, 'call-string on must not change findings on a single-caller flow');
});
