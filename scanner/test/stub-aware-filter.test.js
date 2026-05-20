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

test('applyStubAwareFilter: XSS with numeric source is demoted', () => {
  const stubs = {
    signatures: new Map([['getUserId', { paramTypes: [], returnType: 'number' }]]),
    types: new Map(),
  };
  const findings = [{
    parser: 'IR-TAINT',
    cwe: 'CWE-79',
    severity: 'high',
    trace: [{ sourceLabel: 'user.getUserId' }],
    chain: [],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, true);
  assert.equal(findings[0].severity, 'medium');     // high → medium
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

test('applyStubAwareFilter: SQL inj with Date source is demoted', () => {
  const stubs = {
    signatures: new Map([['getCreated', { paramTypes: [], returnType: 'Date' }]]),
    types: new Map(),
  };
  const findings = [{
    parser: 'IR-TAINT',
    cwe: 'CWE-89',
    severity: 'critical',
    trace: [{ sourceLabel: 'row.getCreated' }],
    chain: [],
  }];
  applyStubAwareFilter(findings, stubs);
  assert.equal(findings[0]._stubTypeDemoted, true);
  assert.equal(findings[0].severity, 'high');       // critical → high
  assert.equal(findings[0]._stubTypeOriginalSeverity, 'critical');
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
