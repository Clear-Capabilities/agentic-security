// R4 — collection-element taint (deep engine). Verifies array-element taint and
// the Object.assign mutated-param path (which const→let in engine.js repaired).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { buildProjectIR } from '../src/ir/index.js';

function deepFindings(code) {
  const { perFile, callGraph } = buildProjectIR({ 'h.js': code });
  return runDeepAnalysis(perFile, callGraph, {});
}

test('array push → index read is tainted (R4)', () => {
  const f = deepFindings('function h(req){ const a = []; a.push(req.query.id); eval(a[0]); }');
  assert.ok(f.length >= 1, `expected a finding via the array element, got ${f.length}`);
});

test('array unshift → later index read is tainted', () => {
  const f = deepFindings('function h(req){ const a = []; a.unshift(req.body.cmd); eval(a[3]); }');
  assert.ok(f.length >= 1);
});

test('precision: a clean push (no tainted element) does not fire', () => {
  assert.equal(deepFindings('function h(req){ const a = []; a.push("safe"); eval(a[0]); }').length, 0);
});

test('regression: object-property taint still works', () => {
  assert.ok(deepFindings('function h(req){ const o = {}; o.cmd = req.query.id; eval(o.cmd); }').length >= 1);
});
