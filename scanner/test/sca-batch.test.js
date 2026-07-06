// SCA batched EPSS lookups — verify that _enrichWithEPSS makes one HTTP
// request per 100 CVEs instead of one per CVE.
//
// The engine has its own disk-backed sessionStorage shim under
// ~/.claude/agentic-security/osv-cache/, with no TTL — a cache entry a prior
// test run wrote is still there, and stays there, on the next run. So every
// test uses a CVE-id range that is genuinely unique per invocation.
//
// A prior version of this file claimed to key off "process.pid + Date.now()"
// but only actually used the last 3 digits of process.pid (1,000 possible
// values). PIDs get reused by the OS across separate test invocations, so a
// re-used PID suffix collided with an id a previous run had already cached —
// _enrichWithEPSS correctly saw a cache hit and skipped the fetch, and the
// "exactly one request" assertions intermittently failed with 0. That was a
// test-isolation bug, not a bug in the EPSS/SCA code (cache-first is the
// intended production behavior).
//
// Fix: derive the namespace from Date.now() + process.pid (unique across
// repeated invocations — a collision would need two test runs to start in the
// same millisecond under the same OS-recycled pid), and delete every cache
// file this file writes once its tests finish, so it can never leave a
// residue for a *future* run to collide with either.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// Track every fetch call so we can assert on batching.
let fetchCalls = [];
globalThis.fetch = async (url) => {
  fetchCalls.push(url);
  const m = String(url).match(/[?&]cve=([^&]+)/);
  const cves = m ? decodeURIComponent(m[1]).split(',') : [];
  const data = cves.map((cve, i) => ({
    cve,
    epss: (0.001 * (i + 1)).toFixed(4),
    percentile: (0.5 + 0.001 * i).toFixed(4),
  }));
  return { ok: true, json: async () => ({ data }) };
};

delete process.env.AGENTIC_SECURITY_OFFLINE;

const { _enrichWithEPSS, _fetchEPSSBatch } = await import('../src/engine.js');

// Per-run-unique CVE namespace so we never collide with a prior run's cache.
// Format: CVE-9999-{run}{seq6}. Year 9999 never collides with a real CVE
// (years are always ≤ the current real year); {run} is the actual
// process.pid + Date.now() combination the old comment claimed to use.
const RUN_ID = `${Date.now()}${process.pid}`;
// Every CVE id this file ever mints, so the cleanup pass below can delete
// exactly the cache files this run created — never more, never less.
const _mintedCveIds = [];
function cveId(seq) {
  const id = `CVE-9999-${RUN_ID}${String(seq).padStart(6, '0')}`;
  _mintedCveIds.push(id);
  return id;
}
function makeFinding(cve, name) {
  return { type: 'vulnerable_dep', name: name || 'pkg', cveAliases: [cve] };
}

function _cacheFilePathFor(cve) {
  const cacheDir = path.join(os.homedir(), '.claude', 'agentic-security', 'osv-cache');
  const key = 'osv_epss:' + cve.toUpperCase();
  return path.join(cacheDir, crypto.createHash('sha256').update(key).digest('hex') + '.json');
}

test('EPSS: single CVE → one batched request', async () => {
  fetchCalls = [];
  const cve = cveId(100001);
  const out = await _enrichWithEPSS([makeFinding(cve, 'lodash')]);
  assert.equal(fetchCalls.length, 1, 'exactly one HTTP request');
  assert.match(fetchCalls[0], new RegExp(`cve=${cve}`));
  assert.ok(out[0].epssScore != null, 'epssScore populated');
});

test('EPSS: 50 CVEs → one batched request (under batch size)', async () => {
  fetchCalls = [];
  const findings = Array.from({ length: 50 }, (_, i) =>
    makeFinding(cveId(200000 + i + 1), `pkg${i}`));
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 1, 'one batched request for 50 CVEs');
  const cveCount = (fetchCalls[0].match(/CVE-/g) || []).length;
  assert.equal(cveCount, 50, 'all 50 CVEs in one request');
});

test('EPSS: 250 CVEs → 3 batched requests (100 + 100 + 50)', async () => {
  fetchCalls = [];
  const findings = Array.from({ length: 250 }, (_, i) =>
    makeFinding(cveId(300000 + i + 1), `pkg${i}`));
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 3, 'three batched requests at batch=100');
  const counts = fetchCalls.map(u => (u.match(/CVE-/g) || []).length);
  assert.deepEqual(counts.sort((a, b) => a - b), [50, 100, 100]);
});

test('EPSS: cached CVEs skip the network entirely on rerun', async () => {
  const cve = cveId(400000);
  // Warm the cache.
  fetchCalls = [];
  await _enrichWithEPSS([makeFinding(cve, 'pkg')]);
  assert.equal(fetchCalls.length, 1, 'warmup fetched');
  // Second call against the same CVE must use the cache and skip fetch.
  fetchCalls = [];
  await _enrichWithEPSS([makeFinding(cve, 'pkg')]);
  assert.equal(fetchCalls.length, 0, 'cached CVE issues no further requests');
});

test('EPSS: malformed CVE ids are filtered out before fetching', async () => {
  fetchCalls = [];
  const goodCve = cveId(500001);
  const findings = [
    makeFinding(goodCve, 'good'),
    { type: 'vulnerable_dep', name: 'noaliases', cveAliases: [] },
    { type: 'vulnerable_dep', name: 'malformed', cveAliases: ['NOT-A-CVE'] },
  ];
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 1, 'one fetch for the only valid CVE');
  assert.match(fetchCalls[0], new RegExp(goodCve));
});

test('EPSS: offline mode skips all fetching', async () => {
  process.env.AGENTIC_SECURITY_OFFLINE = '1';
  fetchCalls = [];
  const findings = Array.from({ length: 10 }, (_, i) =>
    makeFinding(cveId(600000 + i + 1), `pkg${i}`));
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 0, 'no fetches in offline mode');
  delete process.env.AGENTIC_SECURITY_OFFLINE;
});

test('_fetchEPSSBatch: empty input is a no-op', async () => {
  fetchCalls = [];
  const out = await _fetchEPSSBatch([]);
  assert.equal(fetchCalls.length, 0);
  assert.equal(out.size, 0);
});

// Cleanup — runs last (node:test runs tests in registration order within a
// file). Deletes every disk-cache entry this run wrote so it can never
// collide with a future run. Best-effort: a file that was never created
// (e.g. the offline-mode test's ids, which never hit the network) is simply
// absent, not an error.
test('cleanup: remove this run\'s disk-cache entries', () => {
  for (const cve of _mintedCveIds) {
    try { fs.unlinkSync(_cacheFilePathFor(cve)); } catch { /* never existed — fine */ }
  }
});
