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
