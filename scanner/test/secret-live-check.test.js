// Live-secret validation (#22). Only the pure surfaces + the no-provider path
// are tested — a recognized provider would make a real network call, so those
// are exercised via the request builder (no I/O), never a live fetch.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSecretLive, _internal } from '../src/posture/secret-live-check.js';

const { buildLiveCheckRequest, classifyStatus } = _internal;

test('buildLiveCheckRequest: GitHub PAT → GET /user with token auth', () => {
  const r = buildLiveCheckRequest({ match: 'ghp_' + 'a'.repeat(36) });
  assert.equal(r.provider, 'github');
  assert.equal(r.url, 'https://api.github.com/user');
  assert.match(r.headers.Authorization, /^token ghp_/);
});

test('buildLiveCheckRequest: Stripe live key → /v1/account bearer', () => {
  const r = buildLiveCheckRequest({ value: 'sk_live_' + 'A'.repeat(24) });
  assert.equal(r.provider, 'stripe');
  assert.match(r.headers.Authorization, /^Bearer sk_live_/);
});

test('buildLiveCheckRequest: OpenAI key → /v1/models bearer', () => {
  const r = buildLiveCheckRequest({ token: 'sk-' + 'a'.repeat(40) });
  assert.equal(r.provider, 'openai');
  assert.match(r.url, /openai\.com\/v1\/models/);
});

test('buildLiveCheckRequest: unknown / short secret → null (no check)', () => {
  assert.equal(buildLiveCheckRequest({ match: 'hunter2' }), null);
  assert.equal(buildLiveCheckRequest({}), null);
  assert.equal(buildLiveCheckRequest(null), null);
});

test('classifyStatus: 2xx=live, 401/403=dead, else unknown (never a false dead)', () => {
  assert.equal(classifyStatus(200), 'live');
  assert.equal(classifyStatus(204), 'live');
  assert.equal(classifyStatus(401), 'dead');
  assert.equal(classifyStatus(403), 'dead');
  assert.equal(classifyStatus(429), 'unknown'); // rate-limited ≠ dead
  assert.equal(classifyStatus(500), 'unknown');
});

test('checkSecretLive: unrecognized provider → unknown, makes no network call', async () => {
  const r = await checkSecretLive({ match: 'not-a-known-token-shape' });
  assert.deepEqual(r, { verdict: 'unknown', provider: null });
});

// ── PRD F4.2 — the two properties that make live-checking SAFE ──────────────
//
// Validating a secret is an OUTBOUND CALL CARRYING A LIVE CREDENTIAL. That is a
// materially different act from reading files, and it is only defensible under
// two conditions:
//
//   1. it never happens unless the operator explicitly asked for it, and
//   2. the credential only ever travels to the party that ISSUED it.
//
// The existing tests cover request shape and status classification — what the
// feature does when invoked. These cover whether it should have been invoked at
// all, and where the secret goes. A regression in either is a credential-
// exfiltration bug wearing the costume of a feature.

test('SAFETY: nothing is validated without explicit opt-in', async () => {
  // The default path must make no network call at all. A scan that quietly
  // validated would ship every detected secret to a third party on the
  // strength of the user running `scan`.
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (...a) => { calls += 1; return realFetch(...a); };
  const prev = process.env.AGENTIC_SECURITY_VALIDATE_SECRETS;
  delete process.env.AGENTIC_SECURITY_VALIDATE_SECRETS;
  try {
    const fs2 = await import('node:fs');
    const os2 = await import('node:os');
    const path2 = await import('node:path');
    const d = fs2.mkdtempSync(path2.join(os2.tmpdir(), 'novalidate-'));
    fs2.writeFileSync(path2.join(d, 'package.json'), '{"name":"x","version":"1.0.0"}');
    fs2.writeFileSync(path2.join(d, 'app.js'),
      'const t = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";\nmodule.exports = { t };\n');
    const { runScan } = await import('../src/runScan.js');
    const { scan } = await runScan(d);
    assert.ok((scan.secrets || []).length > 0, 'precondition: the secret must be detected');
    assert.equal(calls, 0, 'a default scan made a network call while holding a detected secret');
    fs2.rmSync(d, { recursive: true, force: true });
  } finally {
    globalThis.fetch = realFetch;
    if (prev !== undefined) process.env.AGENTIC_SECURITY_VALIDATE_SECRETS = prev;
  }
});

test('SAFETY: a secret is only ever sent to the provider that issued it', () => {
  // A request builder that pointed a GitHub PAT at any host other than GitHub
  // would be exfiltrating the credential, whatever the intent. Pin the
  // destination per provider rather than trusting the table to stay correct.
  const { buildLiveCheckRequest } = _internal;
  const cases = [
    ['ghp_' + 'aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890', /(^|\.)github\.com$/],
    ['sk_' + 'live_FAKEKEYFORTESTING000000000000', /(^|\.)stripe\.com$/],
  ];
  for (const [secret, hostRe] of cases) {
    const req = buildLiveCheckRequest({ match: secret, value: secret, type: 'token' });
    if (!req) continue;                       // provider not supported — fine
    const host = new URL(req.url).hostname;
    assert.match(host, hostRe, `a secret would have been sent to ${host}`);
    assert.match(new URL(req.url).protocol, /^https:$/, 'a credential must never travel over plain http');
  }
});

test('SAFETY: an unknown secret shape produces no request at all', () => {
  // The fallback must be "do nothing", not "try somewhere plausible". Guessing
  // a validation endpoint for an unrecognised token is how a secret reaches a
  // host nobody vetted.
  const { buildLiveCheckRequest } = _internal;
  for (const junk of ['hunter2', 'AAAA', '', 'not-a-token-at-all']) {
    assert.equal(buildLiveCheckRequest({ match: junk, value: junk, type: 'token' }), null,
      `an unrecognised secret produced a request: ${junk}`);
  }
});
