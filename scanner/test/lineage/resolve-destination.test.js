//
// resolve-destination.test.js — Milestone 2, Sub-project A, increment 1.
//
// Unit tests for `resolveDestination(site)` against hand-built `site`
// shapes, mirroring `coverage.test.js`'s own hand-built-site style for
// `detectUnresolvedDestination`. Real-parsed-code proofs (through
// `buildGraphWithCoverage`) live in `test/lineage/coverage.test.js`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveDestination } from '../../src/lineage/resolve-destination.js';

// ── 'literal' outcome ──

test('M2A1/1a: a literal arg0 on an eligible category (external-api) resolves to literal', () => {
  const site = {
    decision: { category: 'external-api' },
    calleeExpr: { kind: 'ident', name: 'fetch' },
    args: [{ kind: 'literal', value: 'https://payments.example/charge' }],
  };
  const r = resolveDestination(site);
  assert.equal(r.resolutionStatus, 'literal');
  assert.equal(r.literalValue, 'https://payments.example/charge');
  assert.equal(r.raw, '"https://payments.example/charge"');
  assert.equal(r.blockingExpression, null);
});

test('M2A1/1b: a literal arg0 on a NON-eligible category (database) does NOT resolve to literal — arg0 is a payload there', () => {
  const site = {
    decision: { category: 'database' },
    calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'cursor' }, prop: 'execute' },
    args: [{ kind: 'literal', value: 'SELECT * FROM t' }],
  };
  const r = resolveDestination(site);
  assert.notEqual(r.resolutionStatus, 'literal');
});

test('M2A1/1c: a literal receiver (member callee whose object is itself literal-kind) resolves to literal', () => {
  const site = {
    decision: { category: 'external-api' },
    calleeExpr: { kind: 'member', object: { kind: 'literal', value: 'https://payments.example' }, prop: 'post' },
    args: [{ kind: 'ident', name: 'body' }],
  };
  const r = resolveDestination(site);
  assert.equal(r.resolutionStatus, 'literal');
  assert.equal(r.literalValue, 'https://payments.example');
  assert.equal(r.blockingExpression, null);
});

test('M2A1/1d: a numeric literal arg0 coerces literalValue to a string', () => {
  const site = {
    decision: { category: 'file' },
    calleeExpr: { kind: 'ident', name: 'writeFile' },
    args: [{ kind: 'literal', value: 8080 }],
  };
  const r = resolveDestination(site);
  assert.equal(r.resolutionStatus, 'literal');
  assert.equal(r.literalValue, '8080');
  assert.equal(typeof r.literalValue, 'string');
});

// ── 'dynamic' outcome ──

test('M2A1/2a: a computed receiver (not a plain ident) resolves to dynamic, regardless of category', () => {
  const site = {
    decision: { category: 'database' },
    calleeExpr: { kind: 'member', object: { kind: 'call', callee: { kind: 'ident', name: 'getClient' }, args: [] }, prop: 'charge' },
    args: [{ kind: 'ident', name: 'x' }],
  };
  const r = resolveDestination(site);
  assert.equal(r.resolutionStatus, 'dynamic');
  assert.equal(r.literalValue, null);
  assert.match(r.blockingExpression, /computed expression/);
  assert.equal(r.raw, r.blockingExpression);
});

test('M2A1/2b: a non-literal arg0 on an eligible category (external-api) resolves to dynamic — the fetch(url) case', () => {
  const site = {
    decision: { category: 'external-api' },
    calleeExpr: { kind: 'ident', name: 'fetch' },
    args: [{ kind: 'ident', name: 'url' }],
  };
  const r = resolveDestination(site);
  assert.equal(r.resolutionStatus, 'dynamic');
  assert.equal(r.blockingExpression, 'url');
  assert.equal(r.raw, 'url');
  assert.equal(r.literalValue, null);
});

// ── 'unknown' outcome — the regression proof ──

test('M2A1/3a: a non-literal arg0 on a NON-eligible category (database) stays unknown — cursor.execute(sql), sql is the payload not the destination', () => {
  const site = {
    decision: { category: 'database' },
    calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'cursor' }, prop: 'execute' },
    args: [{ kind: 'ident', name: 'sql' }],
  };
  const r = resolveDestination(site);
  assert.equal(r.resolutionStatus, 'unknown');
  assert.equal(r.raw, null);
  assert.equal(r.literalValue, null);
  assert.equal(r.blockingExpression, null);
});

test('M2A1/3b: a plain-ident receiver with a plain-ident, non-eligible-category arg0 stays unknown — document.write(html)', () => {
  const site = {
    decision: { category: 'client-storage' },
    calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'document' }, prop: 'write' },
    args: [{ kind: 'ident', name: 'html' }],
  };
  const r = resolveDestination(site);
  assert.equal(r.resolutionStatus, 'unknown');
});

test('M2A1/3c: no site.decision at all still resolves — category defaults to null, arg0 never eligible', () => {
  const site = { calleeExpr: { kind: 'ident', name: 'fetch' }, args: [{ kind: 'literal', value: 'https://x' }] };
  const r = resolveDestination(site);
  // arg0 is a literal, but with no category info the arg0-eligibility gate
  // cannot pass — this must not crash and must not silently assume eligible.
  assert.equal(r.resolutionStatus, 'unknown');
});

// ── malformed-input safety — never throws ──

test('M2A1/4: resolveDestination never throws on malformed/missing input, always returns the full shape', () => {
  const badSites = [
    null, undefined, 42, 'x', [], {},
    { calleeExpr: null, args: null },
    { calleeExpr: {}, args: 'not-an-array' },
    { decision: null, calleeExpr: { kind: 'member', object: null, prop: 'x' }, args: [] },
    { decision: { category: 42 }, calleeExpr: { kind: 'member', object: { kind: 'unknown' }, prop: 'x' }, args: [{}] },
    { decision: {}, calleeExpr: 'a.b.c', args: [{ kind: 'literal' }] },
  ];
  for (const site of badSites) {
    const r = resolveDestination(site);
    assert.equal(typeof r, 'object');
    assert.ok(r !== null);
    assert.ok(['literal', 'resolved_from_constant', 'resolved_from_config', 'resolved_from_schema',
      'declared_service', 'runtime_corroborated', 'dynamic', 'unknown'].includes(r.resolutionStatus));
    assert.ok('raw' in r);
    assert.ok('literalValue' in r);
    assert.ok('blockingExpression' in r);
  }
});

test('M2A1/5: resolveDestination is deterministic — same input, same output, twice', () => {
  const site = {
    decision: { category: 'external-api' },
    calleeExpr: { kind: 'ident', name: 'fetch' },
    args: [{ kind: 'ident', name: 'url' }],
  };
  assert.deepEqual(resolveDestination(site), resolveDestination(site));
});
