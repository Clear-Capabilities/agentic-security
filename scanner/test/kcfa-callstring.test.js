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

// NON-empty entry state throughout — the EMPTY-entry-state baseline is
// deliberately EXEMPT from caller-string splitting (see `_key`'s own header
// comment): `engine.js`'s outer fixed-point pre-pass loop shares and
// progressively refines ONE empty-entry summary per function across both
// multiple passes and every zero-argument call path that reaches it, and
// splitting that shared summary by caller silently breaks multi-hop
// mutation propagation (confirmed directly — see
// summary-cache-convergence.test.js's own 3-hop propagation case, which
// this exact splitting behavior used to fail before the guard was added).
test('ON: distinct callers produce distinct keys for a NON-empty entry state', () => {
  withCallString('1', () => {
    const c = new SummaryCache();
    c.setCallerContext('A::1');
    const kA = c._key('H::1', new Set(['x']));
    const prev = c.setCallerContext('B::1');
    const kB = c._key('H::1', new Set(['x']));
    assert.notEqual(kA, kB, 'same callee+non-empty-entry under different callers must key differently');
    assert.equal(prev, 'A::1');
  });
});

test('ON: an EMPTY entry state is NEVER caller-suffixed, even with call-string enabled', () => {
  withCallString('1', () => {
    const c = new SummaryCache();
    c.setCallerContext('A::1');
    const kA = c._key('H::1', new Set());
    c.setCallerContext('B::1');
    const kB = c._key('H::1', new Set());
    assert.equal(kA, kB, 'the empty-entry key must stay caller-independent — it is the shared baseline the pre-pass fixed-point loop relies on');
  });
});

test('ON: a helper keeps a distinct summary per caller for a NON-empty entry (no over-merge)', () => {
  withCallString('1', () => {
    const c = new SummaryCache();
    const entry = new Set(['x']);
    c.setCallerContext('A::1'); c.set('H::1', entry, { returnTainted: true });
    c.setCallerContext('B::1'); c.set('H::1', entry, { returnTainted: false });
    c.setCallerContext('A::1'); assert.equal(c.get('H::1', entry).returnTainted, true);
    c.setCallerContext('B::1'); assert.equal(c.get('H::1', entry).returnTainted, false);
  });
});

test('ON: a helper called with EMPTY entry still shares one summary across callers (the pre-pass baseline)', () => {
  withCallString('1', () => {
    const c = new SummaryCache();
    c.setCallerContext('A::1'); c.set('H::1', new Set(), { returnTainted: true });
    c.setCallerContext('B::1');
    assert.equal(c.get('H::1', new Set()).returnTainted, true, 'empty-entry summary must stay shared even with call-string ON');
  });
});

test('OFF: the same helper summary is SHARED across callers (the monovariant baseline)', () => {
  withCallString(undefined, () => {
    const c = new SummaryCache();
    c.setCallerContext('A::1'); c.set('H::1', new Set(['x']), { returnTainted: true });
    c.setCallerContext('B::1');
    assert.equal(c.get('H::1', new Set(['x'])).returnTainted, true, 'off → callers share one summary');
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
