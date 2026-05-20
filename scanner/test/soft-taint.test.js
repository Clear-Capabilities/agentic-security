// v0.70 #6 — probabilistic / soft taint tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { effectivenessFor, computeSoftTaintProbability, annotateSoftTaint, _internal } from '../src/dataflow/soft-taint.js';

test('effectivenessFor: known strong sanitizers return high values', () => {
  assert.equal(effectivenessFor('DOMPurify.sanitize'), 0.98);
  assert.equal(effectivenessFor('encodeURIComponent'), 0.99);
  assert.equal(effectivenessFor('parameterize'), 1.0);
});

test('effectivenessFor: tail-of-dotted callee falls back', () => {
  // `obj.setString` → tail is `setString` → 1.0
  assert.equal(effectivenessFor('cmd.setString'), 1.0);
  // `_.escape` → tail is `escape` → 0.85
  assert.equal(effectivenessFor('_.escape'), 0.85);
});

test('effectivenessFor: unknown callee returns null', () => {
  assert.equal(effectivenessFor('mysteryFn'), null);
  assert.equal(effectivenessFor(null), null);
  assert.equal(effectivenessFor(''), null);
});

test('computeSoftTaintProbability: no sanitizers in path keeps p = 1.0', () => {
  const f = { trace: [{ sourceLabel: 'req.body' }], chain: [] };
  const r = computeSoftTaintProbability(f);
  assert.equal(r.p, 1.0);
  assert.equal(r.why.length, 0);
});

test('computeSoftTaintProbability: strong sanitizer brings p near zero', () => {
  const f = {
    trace: [{ sourceLabel: 'req.body' }],
    chain: [{ callee: 'DOMPurify.sanitize' }],
    pathSteps: [],
  };
  const r = computeSoftTaintProbability(f);
  assert.ok(r.p < 0.05, `expected p < 0.05 after DOMPurify; got ${r.p}`);
  assert.ok(r.why.find(w => w.callee === 'DOMPurify.sanitize'));
});

test('computeSoftTaintProbability: weak sanitizer barely reduces p', () => {
  const f = {
    trace: [{ sourceLabel: 'req.body' }],
    chain: [{ callee: 'trim' }],
    pathSteps: [],
  };
  const r = computeSoftTaintProbability(f);
  assert.ok(r.p > 0.9, `trim should be weak; expected p > 0.9, got ${r.p}`);
});

test('computeSoftTaintProbability: stacked sanitizers compound multiplicatively', () => {
  const f = {
    trace: [{ sourceLabel: 'req.body' }],
    chain: [{ callee: 'escape' }, { callee: 'encodeURIComponent' }],
    pathSteps: [],
  };
  const r = computeSoftTaintProbability(f);
  // escape × encodeURIComponent → (1-0.85) × (1-0.99) = 0.15 × 0.01 = 0.0015
  assert.ok(r.p < 0.01, `stacked should compound; got ${r.p}`);
  assert.equal(r.why.length, 2);
});

test('annotateSoftTaint: below-threshold demotion lowers severity but keeps finding', () => {
  const findings = [
    {
      parser: 'IR-TAINT', severity: 'critical', vuln: 'sqli',
      trace: [{ sourceLabel: 'req.body' }],
      chain: [{ callee: 'setString' }],
    },
  ];
  annotateSoftTaint(findings, { threshold: 0.5 });
  assert.equal(findings[0]._softTaintDemoted, true);
  assert.equal(findings[0].severity, 'high');                  // critical → high
  assert.equal(findings[0]._softTaintOriginalSeverity, 'critical');
  assert.ok(findings[0].taintProbability < 0.5);
});

test('annotateSoftTaint: above-threshold keeps original severity', () => {
  const findings = [
    {
      parser: 'IR-TAINT', severity: 'high', vuln: 'cmd',
      trace: [{ sourceLabel: 'req.body' }],
      chain: [{ callee: 'trim' }],     // weak sanitizer
    },
  ];
  annotateSoftTaint(findings, { threshold: 0.5 });
  assert.equal(findings[0]._softTaintDemoted, undefined);
  assert.equal(findings[0].severity, 'high');
});

test('annotateSoftTaint: non-IR-TAINT findings are skipped', () => {
  const findings = [
    { parser: 'REGEX', severity: 'high', vuln: 'xss', chain: [{ callee: 'DOMPurify.sanitize' }] },
  ];
  annotateSoftTaint(findings);
  assert.equal(findings[0].taintProbability, undefined,
    'non-IR-TAINT findings must not be annotated');
});

test('annotateSoftTaint: emits _softTaintStats with demoted count', () => {
  const findings = [
    { parser: 'IR-TAINT', severity: 'critical', chain: [{ callee: 'setString' }], trace: [] },
    { parser: 'IR-TAINT', severity: 'high', chain: [{ callee: 'trim' }], trace: [] },
  ];
  annotateSoftTaint(findings, { threshold: 0.5 });
  const stats = findings._softTaintStats;
  assert.ok(stats);
  assert.equal(stats.demoted, 1);
  assert.equal(stats.threshold, 0.5);
});

test('DEFAULT_EFFECTIVENESS table is non-empty + sane', () => {
  const t = _internal.DEFAULT_EFFECTIVENESS;
  assert.ok(Object.keys(t).length > 10);
  for (const [name, eff] of Object.entries(t)) {
    assert.ok(eff >= 0 && eff <= 1, `${name}: ${eff} out of [0,1]`);
  }
});
