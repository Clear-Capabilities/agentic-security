// Unit tests for frontend/src/lib/api-client.js — extractTokenFromFragment
// is pure string parsing (no DOM needed); fetchGraph is tested against a
// mocked global fetch here (the REAL live-HTTP proof against a REAL running
// explore server is test/live-fetch-parity.test.js, per the M3-Wire plan's
// own "single most important test" — AC-16).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractTokenFromFragment, fetchGraph } from '../src/lib/api-client.js';

const REAL_TOKEN = 'a'.repeat(64);

test('extractTokenFromFragment: a real #token=<hex> hash', () => {
  assert.equal(extractTokenFromFragment(`#token=${REAL_TOKEN}`), REAL_TOKEN);
});

test('extractTokenFromFragment: token can coexist with other hash params (view/selected/filters)', () => {
  assert.equal(extractTokenFromFragment(`#token=${REAL_TOKEN}&view=privacy`), REAL_TOKEN);
  assert.equal(extractTokenFromFragment(`#view=privacy&token=${REAL_TOKEN}`), REAL_TOKEN);
});

test('extractTokenFromFragment: a missing hash returns null', () => {
  assert.equal(extractTokenFromFragment(''), null);
  assert.equal(extractTokenFromFragment('#'), null);
  assert.equal(extractTokenFromFragment(undefined), null);
});

test('extractTokenFromFragment: a hash with no token param returns null', () => {
  assert.equal(extractTokenFromFragment('#view=architecture'), null);
});

test('extractTokenFromFragment: a malformed/short token is rejected (not a real 64-hex-char token)', () => {
  assert.equal(extractTokenFromFragment('#token=too-short'), null);
  assert.equal(extractTokenFromFragment('#token='), null);
  assert.equal(extractTokenFromFragment(`#token=${'g'.repeat(64)}`), null); // 'g' is not hex
});

test('fetchGraph: throws when no token is given', async () => {
  await assert.rejects(() => fetchGraph({}), /session token is required/);
});

test('fetchGraph: success path unwraps the .data envelope field', async () => {
  const originalFetch = globalThis.fetch;
  const graph = { nodes: [{ id: 'n1' }], edges: [], flows: [] };
  globalThis.fetch = async (url, opts) => {
    assert.equal(url, '/api/v1/graph');
    assert.equal(opts.headers['x-agentic-security-token'], REAL_TOKEN);
    return {
      ok: true,
      status: 200,
      json: async () => ({ digest: 'dfg:x', schemaVersion: '1.0.0', data: graph }),
    };
  };
  try {
    const result = await fetchGraph({ token: REAL_TOKEN });
    assert.deepEqual(result, graph);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchGraph: respects a baseUrl override (used only by the live-HTTP test)', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(url, 'http://127.0.0.1:1234/api/v1/graph');
    return { ok: true, status: 200, json: async () => ({ data: {} }) };
  };
  try {
    await fetchGraph({ token: REAL_TOKEN, baseUrl: 'http://127.0.0.1:1234' });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchGraph: a non-200 response throws a clear error, including the server\'s own error message when present', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    json: async () => ({ error: 'missing or invalid session token' }),
  });
  try {
    await assert.rejects(() => fetchGraph({ token: REAL_TOKEN }), /status 401.*missing or invalid session token/s);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchGraph: a non-200 response with a non-JSON body still throws a clear error (no crash)', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 500,
    json: async () => { throw new Error('not json'); },
  });
  try {
    await assert.rejects(() => fetchGraph({ token: REAL_TOKEN }), /status 500/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchGraph: a 200 response missing the expected .data envelope shape throws rather than returning garbage', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ notData: true }),
  });
  try {
    await assert.rejects(() => fetchGraph({ token: REAL_TOKEN }), /unexpected response shape/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
