// R13 — routing gated on a Wilson upper bound.
//
// The property under test is that flattering-but-thin evidence CANNOT buy a
// downgrade. Most of these tests are attempts to get one cheaply.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createTrustLedger, applyMeasuredTrust, renderTrustSummary,
  DEFAULT_MAX_MISS_RATE, MIN_SAMPLES,
} from '../src/posture/model-trust.js';

const feed = (ledger, key, n, misses) => {
  for (let i = 0; i < n; i++) ledger.record(key, i < misses);
};

test('no evidence is not permission', () => {
  const l = createTrustLedger();
  const v = l.verdict('cheap::CWE-79');
  assert.equal(v.allowed, false);
  assert.equal(v.n, 0);
  assert.match(v.reason, /No evidence is not permission/);
});

test('a perfect but tiny sample is refused — this is the whole point', () => {
  // 0 misses in 5 looks flawless. Its 95% upper bound is ~52%: the data is
  // equally consistent with a model that misses half the time.
  const l = createTrustLedger();
  feed(l, 'k', 5, 0);
  const v = l.verdict('k');
  assert.equal(v.allowed, false);
  assert.equal(v.missRate, 0, 'the point estimate really is perfect');
  assert.match(v.reason, /5 adjudicated sample/);
});

test('a clean run just under the sample floor still cannot clear the bar', () => {
  const l = createTrustLedger();
  feed(l, 'k', MIN_SAMPLES - 1, 0);
  assert.equal(l.verdict('k').allowed, false);
});

test('enough clean samples do clear it', () => {
  const l = createTrustLedger();
  feed(l, 'k', 200, 0);
  const v = l.verdict('k');
  assert.equal(v.allowed, true, v.reason);
  assert.ok(v.upperBound <= DEFAULT_MAX_MISS_RATE, `upper bound ${v.upperBound} must clear the bar`);
  assert.match(v.reason, /upper bound/);
});

test('the bound, not the point estimate, decides', () => {
  // A miss rate of 2% is under the 5% bar on the point estimate. At n=50 the
  // upper bound is still well above 5%, so it must be refused; at large n the
  // same rate clears.
  const small = createTrustLedger();
  feed(small, 'k', 50, 1);
  const vs = small.verdict('k');
  assert.ok(vs.missRate < DEFAULT_MAX_MISS_RATE, 'precondition: the point estimate looks fine');
  assert.equal(vs.allowed, false, 'a flattering point estimate must not be enough');
  assert.match(vs.reason, /point estimate is not the claim/);

  const large = createTrustLedger();
  feed(large, 'k', 2000, 40);
  assert.equal(large.verdict('k').allowed, true, 'the same rate with real evidence clears');
});

test('a model that genuinely misses is refused at any sample size', () => {
  const l = createTrustLedger();
  feed(l, 'k', 5000, 1000); // 20% miss rate
  const v = l.verdict('k');
  assert.equal(v.allowed, false);
  assert.ok(v.upperBound > DEFAULT_MAX_MISS_RATE);
});

test('extra false positives are not misses', () => {
  // Only disagreement where the cheap model MISSED counts. Noise costs triage
  // time; a miss costs a breach.
  const l = createTrustLedger();
  for (let i = 0; i < 200; i++) l.record('k', false);
  assert.equal(l.observations('k').misses, 0);
  assert.equal(l.verdict('k').allowed, true);
});

test('classes are independent — one clean class does not vouch for another', () => {
  const l = createTrustLedger();
  feed(l, 'cheap::CWE-79', 200, 0);
  feed(l, 'cheap::CWE-89', 200, 60);
  assert.equal(l.verdict('cheap::CWE-79').allowed, true);
  assert.equal(l.verdict('cheap::CWE-89').allowed, false);
  assert.equal(l.verdict('cheap::CWE-502').allowed, false, 'an unobserved class must not inherit trust');
});

test('a stricter bar is honoured', () => {
  const strict = createTrustLedger({ maxMissRate: 0.001 });
  feed(strict, 'k', 200, 0);
  assert.equal(strict.verdict('k').allowed, false, 'a tighter bar needs more evidence');
});

test('applyMeasuredTrust withholds the downgrade without evidence', () => {
  const l = createTrustLedger();
  const route = { model: 'strong', effort: 'high', reason: 'Critical severity.' };
  const out = applyMeasuredTrust(route, { model: 'cheap', effort: 'low' }, l, 'k');
  assert.equal(out.model, 'strong', 'the capability route is the floor');
  assert.equal(out.trust.applied, false);
  assert.match(out.reason, /Downgrade withheld/);
});

test('applyMeasuredTrust downgrades once evidence supports it', () => {
  const l = createTrustLedger();
  feed(l, 'k', 500, 2);
  const route = { model: 'strong', effort: 'high', reason: 'High severity.' };
  const out = applyMeasuredTrust(route, { model: 'cheap', effort: 'low' }, l, 'k');
  assert.equal(out.model, 'cheap');
  assert.equal(out.effort, 'low');
  assert.equal(out.trust.applied, true);
  assert.match(out.reason, /on measured evidence/);
});

test('measured trust can only downgrade, never promote', () => {
  // Evidence about a cheap model's miss rate says nothing about whether a hard
  // class deserves a stronger model, so the proposal is always the cheaper one
  // and the route is never raised above what policy chose.
  const l = createTrustLedger();
  feed(l, 'k', 500, 0);
  const route = { model: 'cheap', effort: 'low', reason: 'Low severity hardening.' };
  const out = applyMeasuredTrust(route, { model: 'cheap', effort: 'low' }, l, 'k');
  assert.equal(out.model, 'cheap');
});

test('the report and summary carry n, not just verdicts', () => {
  const l = createTrustLedger();
  feed(l, 'a', 200, 0);
  feed(l, 'b', 3, 0);
  const rep = l.report();
  assert.equal(rep.a.allowed, true);
  assert.equal(rep.b.allowed, false);
  assert.equal(rep.b.n, 3);
  const line = renderTrustSummary(rep);
  assert.match(line, /1\/2 class\(es\) cleared/);
  assert.match(line, /below the 30-sample minimum/);
  assert.equal(renderTrustSummary({}), null);
});

test('malformed keys are ignored rather than creating phantom classes', () => {
  const l = createTrustLedger();
  assert.equal(l.record('', true), false);
  assert.equal(l.record(null, true), false);
  assert.deepEqual(l.report(), {});
});

// ---------------------------------------------- wiring into the router

test('routeModelWithTrust is byte-identical to the capability route without a ledger', async () => {
  const { routeModelForFinding, routeModelWithTrust } = await import('../src/posture/model-routing.js');
  for (const f of [
    { severity: 'critical', cwe: 'CWE-89' },
    { severity: 'high', cwe: 'CWE-79' },
    { severity: 'low', cwe: 'CWE-1004' },
    { severity: 'high', multiFile: true, cwe: 'CWE-502' },
  ]) {
    const base = routeModelForFinding(f);
    const withTrust = routeModelWithTrust(f, null);
    assert.equal(withTrust.model, base.model);
    assert.equal(withTrust.effort, base.effort);
    assert.equal(withTrust.reason, base.reason);
    assert.equal(withTrust.trust, null);
  }
});

test('a critical finding is not downgraded without evidence, and is with it', async () => {
  const { routeModelForFinding, routeModelWithTrust, trustKeyFor } = await import('../src/posture/model-routing.js');
  const finding = { severity: 'critical', cwe: 'CWE-89' };
  const strong = routeModelForFinding(finding).model;

  const empty = createTrustLedger();
  const held = routeModelWithTrust(finding, empty);
  assert.equal(held.model, strong, 'no evidence must leave the strong model in place');
  assert.equal(held.trust.applied, false);

  const proven = createTrustLedger();
  feed(proven, trustKeyFor(finding), 500, 1);
  const moved = routeModelWithTrust(finding, proven);
  assert.notEqual(moved.model, strong, 'measured evidence should permit the downgrade');
  assert.equal(moved.trust.applied, true);
});

test('trust keys separate cwe and severity', async () => {
  const { trustKeyFor } = await import('../src/posture/model-routing.js');
  const a = trustKeyFor({ severity: 'critical', cwe: 'CWE-89' });
  assert.notEqual(a, trustKeyFor({ severity: 'high', cwe: 'CWE-89' }));
  assert.notEqual(a, trustKeyFor({ severity: 'critical', cwe: 'CWE-79' }));
  // Evidence gathered for one class must not leak into another.
  const l = createTrustLedger();
  feed(l, a, 500, 0);
  assert.equal(l.verdict(trustKeyFor({ severity: 'critical', cwe: 'CWE-79' })).allowed, false);
});
