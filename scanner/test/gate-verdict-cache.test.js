// Gate verdict cache — unit tests for the pure decision logic (PRD R1).
//
// The cache decides whether to SKIP verification. That makes its failure mode
// asymmetric and nasty: a bug does not fail loudly, it silently stops checking
// things. So every rejection path is pinned here, and the bias is always
// towards doing the work.
//
// The I/O path (a real cold run populating the cache, a warm run reusing it,
// tamper and corruption both discarding it) was proven by hand with captured
// timings — 255s cold, 3s warm — and recorded in the commit message.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  envFingerprint,
  computeVerdictKey,
  evaluateCachedVerdict,
  renderProvenance,
  cachingDisabled,
  DEFAULT_TTL_MS,
} from '../../scripts/gate-verdict-cache.mjs';

const PARTS = {
  commitSha: 'a'.repeat(40),
  treeSha: 'b'.repeat(40),
  bundleSha: 'c'.repeat(64),
  rulesetVersion: 'deadbeefdeadbeef',
  nodeVersion: 'v24.16.0',
  platform: 'darwin-arm64',
  envFingerprint: '',
};

// ---------------------------------------------------------------- the key
test('the key is stable across identical inputs', () => {
  assert.equal(computeVerdictKey(PARTS), computeVerdictKey({ ...PARTS }));
});

test('every key component changes the key', () => {
  // One assertion per component. Miss one and the cache starts reusing a
  // verdict across inputs that could have changed the outcome, which is the
  // only way this feature can be actively harmful.
  const base = computeVerdictKey(PARTS);
  for (const field of Object.keys(PARTS)) {
    const changed = computeVerdictKey({ ...PARTS, [field]: `${PARTS[field]}-changed` });
    assert.notEqual(changed, base, `changing ${field} must change the key`);
  }
});

test('an unreadable input yields a null key, which means "cannot cache"', () => {
  for (const field of ['commitSha', 'treeSha', 'bundleSha', 'rulesetVersion', 'nodeVersion', 'platform']) {
    assert.equal(computeVerdictKey({ ...PARTS, [field]: null }), null, `${field} null must void the key`);
    assert.equal(computeVerdictKey({ ...PARTS, [field]: '' }), null, `${field} empty must void the key`);
  }
});

test('an EMPTY env fingerprint is a real value, not a missing one', () => {
  // Regression. Treating '' as missing made the key null on every ordinary run
  // — no AGENTIC_SECURITY_* variable is set most of the time — so caching never
  // engaged at all. The feature looked implemented and did nothing.
  assert.notEqual(computeVerdictKey({ ...PARTS, envFingerprint: '' }), null);
});

test('envFingerprint captures values and is order-independent', () => {
  const a = envFingerprint({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_PROVE: '1', PATH: '/usr/bin' });
  const b = envFingerprint({ AGENTIC_SECURITY_PROVE: '1', AGENTIC_SECURITY_DEEP: '1', PATH: '/other' });
  assert.equal(a, b, 'enumeration order and unrelated variables must not matter');
  assert.notEqual(a, envFingerprint({ AGENTIC_SECURITY_DEEP: '0', AGENTIC_SECURITY_PROVE: '1' }),
    'a changed VALUE must change the fingerprint, not just a changed name');
});

// --------------------------------------------------------------- reuse rules
const KEY = computeVerdictKey(PARTS);
const rec = (over = {}) => ({
  checkId: 'test-suite', key: KEY, verdict: 'pass', by: 'pre-push',
  commitSha: PARTS.commitSha, durationMs: 1000, at: new Date().toISOString(), ...over,
});

test('a fresh matching pass is reusable', () => {
  assert.equal(evaluateCachedVerdict({ record: rec(), key: KEY, checkId: 'test-suite' }).usable, true);
});

test('no record means run it', () => {
  const r = evaluateCachedVerdict({ record: null, key: KEY, checkId: 'test-suite' });
  assert.equal(r.usable, false);
  assert.match(r.reason, /no cached verdict/);
});

test('a record for a different check is never reused', () => {
  const r = evaluateCachedVerdict({ record: rec(), key: KEY, checkId: 'corpus-gate' });
  assert.equal(r.usable, false);
});

test('a changed key is never reused', () => {
  const r = evaluateCachedVerdict({ record: rec(), key: 'different', checkId: 'test-suite' });
  assert.equal(r.usable, false);
  assert.match(r.reason, /inputs changed/);
});

test('ONLY a pass is reused — a failure is always re-run', () => {
  // Caching a failure would strand a developer who has fixed it: "still failing
  // after I fixed it" destroys trust in a gate faster than slowness does.
  for (const verdict of ['fail', 'error', 'skipped', undefined]) {
    const r = evaluateCachedVerdict({ record: rec({ verdict }), key: KEY, checkId: 'test-suite' });
    assert.equal(r.usable, false, `verdict ${verdict} must not be reused`);
  }
});

test('an expired record is re-run, not failed', () => {
  const old = rec({ at: new Date(Date.now() - DEFAULT_TTL_MS - 60000).toISOString() });
  const r = evaluateCachedVerdict({ record: old, key: KEY, checkId: 'test-suite' });
  assert.equal(r.usable, false);
  assert.match(r.reason, /older than/);
});

test('a record dated in the future is rejected', () => {
  // Clock skew or a doctored file. Either way, not evidence.
  const future = rec({ at: new Date(Date.now() + 3600000).toISOString() });
  assert.equal(evaluateCachedVerdict({ record: future, key: KEY, checkId: 'test-suite' }).usable, false);
});

test('a record with an unreadable timestamp is rejected', () => {
  assert.equal(evaluateCachedVerdict({ record: rec({ at: 'not-a-date' }), key: KEY, checkId: 'test-suite' }).usable, false);
});

// ------------------------------------------------------------- transparency
test('provenance names when, by which gate, and for which commit', () => {
  const line = renderProvenance(rec({ by: 'pre-push', durationMs: 172000 }));
  assert.match(line, /cached/);
  assert.match(line, /pre-push/);
  assert.match(line, new RegExp(PARTS.commitSha.slice(0, 7)));
  assert.match(line, /172s/);
});

// ------------------------------------------------------------- escape hatch
test('caching can be switched off by flag or environment', () => {
  assert.equal(cachingDisabled(['--no-cache'], {}), true);
  assert.equal(cachingDisabled([], { AGENTIC_SECURITY_GATE_NO_CACHE: '1' }), true);
  assert.equal(cachingDisabled([], {}), false);
});
