// M3 §3.4: providers must make ZERO network calls when unconfigured. Spy on
// global.fetch, matching llm-validator-default-on.test.js's existing
// precedent (scanner/test/llm-validator-default-on.test.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { resolveProviderConfig } from '../../src/posture/provenance/providers/config.js';
import * as github from '../../src/posture/provenance/providers/github.js';
import * as gitlab from '../../src/posture/provenance/providers/gitlab.js';

function withEnv(vars, fn) {
  const prior = {};
  for (const k of Object.keys(vars)) prior[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  return Promise.resolve(fn()).finally(() => {
    for (const [k, v] of Object.entries(prior)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });
}

test('resolveProviderConfig: returns null with no env var and no config file present', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  try {
    assert.equal(resolveProviderConfig(tmp, 'github'), null);
    assert.equal(resolveProviderConfig(tmp, 'gitlab'), null);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('resolveProviderConfig: env var wins, no file needed', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: 'ghp_test123' }, () => {
      const cfg = resolveProviderConfig(tmp, 'github');
      assert.equal(cfg.token, 'ghp_test123');
    });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('github.fetchPRMetadata / fetchCodeowners: unconfigured means zero network calls', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  const priorFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: undefined }, async () => {
      const cfg = resolveProviderConfig(tmp, 'github');
      const pr = await github.fetchPRMetadata(tmp, 'abc123', 'https://github.com/owner/repo.git', cfg);
      const owners = await github.fetchCodeowners(tmp, 'https://github.com/owner/repo.git', cfg);
      assert.equal(pr, null);
      assert.equal(owners, null);
      assert.equal(fetchCalled, false, 'no fetch should be attempted without configuration');
    });
  } finally {
    global.fetch = priorFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('gitlab.fetchPRMetadata / fetchCodeowners: unconfigured means zero network calls', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  const priorFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
  try {
    await withEnv({ AGENTIC_SECURITY_GITLAB_TOKEN: undefined }, async () => {
      const cfg = resolveProviderConfig(tmp, 'gitlab');
      const pr = await gitlab.fetchPRMetadata(tmp, 'abc123', 'https://gitlab.com/owner/repo.git', cfg);
      const owners = await gitlab.fetchCodeowners(tmp, 'https://gitlab.com/owner/repo.git', cfg);
      assert.equal(pr, null);
      assert.equal(owners, null);
      assert.equal(fetchCalled, false, 'no fetch should be attempted without configuration');
    });
  } finally {
    global.fetch = priorFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('github.fetchPRMetadata: configured, makes exactly one fetch call and parses a real-shaped response', async () => {
  const priorFetch = global.fetch;
  let callCount = 0;
  global.fetch = async (url) => {
    callCount++;
    assert.match(url, /\/commits\/abc123\/pulls$/);
    return {
      ok: true,
      json: async () => ([{ number: 42, requested_reviewers: [{ login: 'alice' }], merged_at: '2026-01-01T00:00:00Z' }]),
    };
  };
  try {
    const pr = await github.fetchPRMetadata('/tmp', 'abc123', 'https://github.com/owner/repo.git', { token: 'x', baseUrl: null });
    assert.equal(pr.prNumber, 42);
    assert.deepEqual(pr.reviewers, ['alice']);
    assert.equal(callCount, 1);
  } finally { global.fetch = priorFetch; }
});
