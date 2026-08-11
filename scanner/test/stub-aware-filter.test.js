// v0.73 — type-stub-aware filter tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyStubAwareFilter, _internal } from '../src/dataflow/stub-aware-filter.js';

test('_normalizeType maps common synonyms', () => {
  assert.equal(_internal._normalizeType('number'), 'number');
  assert.equal(_internal._normalizeType('Number'), 'number');
  assert.equal(_internal._normalizeType('int32'), 'number');
  assert.equal(_internal._normalizeType('boolean'), 'boolean');
  assert.equal(_internal._normalizeType('Bool'), 'boolean');
  assert.equal(_internal._normalizeType('String'), 'string');
  assert.equal(_internal._normalizeType('Date'), 'Date');
  assert.equal(_internal._normalizeType('UserProfile'), 'userprofile');
});

// Recall-preserving convention (dataflow/CLAUDE.md, and every other
// precision annotator in this directory — proof-gate.js,
// verification-separation.js): an annotator may demote confidence/tier,
// never severity. This module used to mutate severity directly; it now
// demotes confidence + confidenceTier + exploitabilityTier, mirroring
// proof-gate.js's own demotion shape exactly, and severity is untouched.
test('applyStubAwareFilter: XSS with numeric source demotes confidence/tier, never severity', () => {
  const stubs = {
    signatures: new Map([['getUserId', { paramTypes: [], returnType: 'number' }]]),
    types: new Map(),
  };
  const findings = [{
    parser: 'IR-TAINT',
    cwe: 'CWE-79',
    severity: 'high',
    confidence: 0.9,
    confidenceTier: 'high',
    exploitabilityTier: 'high',
    trace: [{ sourceLabel: 'user.getUserId' }],
    chain: [],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, true);
  assert.equal(findings[0].severity, 'high', 'severity must never be mutated by this filter');
  assert.ok(findings[0].confidence < 0.9, 'confidence must be demoted');
  assert.equal(findings[0]._confidenceBeforeStubFilter, 0.9);
  assert.equal(findings[0].confidenceTier, 'medium', 'high -> medium, one tier down');
  assert.equal(findings[0].exploitabilityTier, 'medium', 'high -> medium, one tier down');
  assert.match(findings[0]._stubTypeReason, /number/);
});

test('applyStubAwareFilter: XSS with string source is NOT demoted', () => {
  const stubs = {
    signatures: new Map([['getUserName', { paramTypes: [], returnType: 'string' }]]),
    types: new Map(),
  };
  const findings = [{
    parser: 'IR-TAINT',
    cwe: 'CWE-79',
    severity: 'high',
    trace: [{ sourceLabel: 'user.getUserName' }],
    chain: [],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, undefined);
  assert.equal(findings[0].severity, 'high');
});

test('applyStubAwareFilter: SQL inj with Date source demotes confidence/tier, severity untouched', () => {
  const stubs = {
    signatures: new Map([['getCreated', { paramTypes: [], returnType: 'Date' }]]),
    types: new Map(),
  };
  const findings = [{
    parser: 'IR-TAINT',
    cwe: 'CWE-89',
    severity: 'critical',
    confidenceTier: 'medium',
    exploitabilityTier: 'critical',
    trace: [{ sourceLabel: 'row.getCreated' }],
    chain: [],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, true);
  assert.equal(findings[0].severity, 'critical', 'severity must never be mutated by this filter');
  assert.equal(findings[0].confidenceTier, 'low', 'medium -> low, one tier down');
  assert.equal(findings[0].exploitabilityTier, 'high', 'critical -> high, one tier down');
});

test('applyStubAwareFilter: unknown CWE families are left alone', () => {
  const stubs = {
    signatures: new Map([['fn', { paramTypes: [], returnType: 'number' }]]),
    types: new Map(),
  };
  const findings = [{
    parser: 'IR-TAINT',
    cwe: 'CWE-99999',
    severity: 'high',
    trace: [{ sourceLabel: 'a.fn' }],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, undefined);
});

test('applyStubAwareFilter: non-IR-TAINT findings are skipped', () => {
  const stubs = {
    signatures: new Map([['fn', { paramTypes: [], returnType: 'number' }]]),
    types: new Map(),
  };
  const findings = [{
    parser: 'REGEX',
    cwe: 'CWE-79',
    severity: 'high',
    trace: [{ sourceLabel: 'a.fn' }],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, undefined);
});

test('applyStubAwareFilter: missing source type leaves finding intact', () => {
  const stubs = { signatures: new Map(), types: new Map() };
  const findings = [{
    parser: 'IR-TAINT',
    cwe: 'CWE-79',
    severity: 'high',
    trace: [{ sourceLabel: 'unknown.thing' }],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, undefined);
  assert.equal(findings[0].severity, 'high');
});

test('applyStubAwareFilter: emits _stubFilterStats with demoted count', () => {
  const stubs = {
    signatures: new Map([['x', { paramTypes: [], returnType: 'number' }]]),
    types: new Map(),
  };
  const findings = [
    { parser: 'IR-TAINT', cwe: 'CWE-79', severity: 'high', trace: [{ sourceLabel: 'a.x' }] },
    { parser: 'IR-TAINT', cwe: 'CWE-79', severity: 'high', trace: [{ sourceLabel: 'b.unknown' }] },
  ];
  applyStubAwareFilter(findings, stubs);
  const stats = findings._stubFilterStats;
  assert.ok(stats);
  assert.equal(stats.demoted, 1);
  assert.equal(stats.totalConsidered, 2);
});
