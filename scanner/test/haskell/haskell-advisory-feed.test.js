// The live Hackage advisory feed: opt-in, coverage-recording, failure-degrading. No test here touches the network: a fake OSV
// serves the REAL pinned HSEC records (test/fixtures/hackage-advisories), so a wrong answer would be a wrong answer about real advisories.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { refreshHackageAdvisories, snapshotPath, getLastRefresh, _resetLastRefresh, FEED_ENV, PINNED_ENV } from '../../src/language/haskell-advisory-feed.js';
import { loadAdvisorySnapshot, evaluateComponents } from '../../src/language/haskell-sca.js';
import { configuredAdvisoryDb, analyzeHaskellSupply, prefetchHackageFeed } from '../../src/language/haskell-supply.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'hackage-advisories', 'records');
const REAL = readdirSync(DIR).filter((f) => f.endsWith('.json')).sort().map((f) => JSON.parse(readFileSync(join(DIR, f), 'utf8')));
const NOW = Date.parse('2026-10-07T12:00:00Z');
const HOUR = 3600000;

/** A fake OSV over the real records. `calls` records every request so a test can prove none was made. */
function fakeOsv({ failVulns = new Set(), failBatch = false, pageToken = new Set(), tamper = null } = {}) {
  const calls = [];
  const byPkg = (name) => REAL.filter((r) => (r.affected || []).some((a) => a.package && a.package.name === name));
  const impl = async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body || null });
    const json = (status, obj) => ({ status, text: async () => (typeof obj === 'string' ? obj : JSON.stringify(obj)) });
    if (failBatch) return json(503, {});
    if (url.endsWith('/v1/querybatch')) {
      const { queries } = JSON.parse(init.body);
      return json(200, { results: queries.map((q) => ({ vulns: byPkg(q.package.name).map((r) => ({ id: r.id, modified: r.modified })), ...(pageToken.has(q.package.name) ? { next_page_token: 'x' } : {}) })) });
    }
    const m = /\/v1\/vulns\/(.+)$/.exec(url);
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (failVulns.has(id)) return json(500, {});
      const rec = REAL.find((r) => r.id === id);
      if (!rec) return json(404, {});
      return json(200, tamper ? tamper(rec) : rec);
    }
    return json(404, {});
  };
  impl.calls = calls;
  return impl;
}

const liveEnv = (dir, extra = {}) => ({ XDG_CONFIG_HOME: dir, [FEED_ENV]: '1', ...extra });
const tmp = () => mkdtempSync(join(tmpdir(), 'agsec-hsfeed-'));
const loadDb = (dir) => { const r = loadAdvisorySnapshot(JSON.parse(readFileSync(snapshotPath({ XDG_CONFIG_HOME: dir }), 'utf8')), { now: NOW }); assert.ok(r.ok, r.reason); return r.db; };

test('[HS-009] disabled by default: no flag, no request, no file', async () => {
  const dir = tmp(); const f = fakeOsv();
  const r = await refreshHackageAdvisories(['aeson'], { env: { XDG_CONFIG_HOME: dir }, fetchImpl: f, now: NOW });
  assert.equal(r.status, 'disabled');
  assert.equal(f.calls.length, 0);
  assert.equal(existsSync(snapshotPath({ XDG_CONFIG_HOME: dir })), false);
});

test('[HS-009] AGENTIC_SECURITY_OFFLINE=1 beats the opt-in: still no request', async () => {
  const dir = tmp(); const f = fakeOsv();
  const r = await refreshHackageAdvisories(['aeson'], { env: liveEnv(dir, { AGENTIC_SECURITY_OFFLINE: '1' }), fetchImpl: f, now: NOW });
  assert.equal(r.status, 'offline');
  assert.equal(f.calls.length, 0);
});

test('[HS-009] an operator-pinned snapshot is used as given and never refreshed over', async () => {
  const dir = tmp(); const f = fakeOsv();
  const r = await refreshHackageAdvisories(['aeson'], { env: liveEnv(dir, { [PINNED_ENV]: '/some/pinned.json' }), fetchImpl: f, now: NOW });
  assert.equal(r.status, 'pinned-snapshot-in-use');
  assert.equal(f.calls.length, 0);
});

test('[HS-009] a refresh writes a verifiable, operator-only snapshot and the matcher finds the real advisory', async () => {
  const dir = tmp(); const f = fakeOsv();
  const r = await refreshHackageAdvisories(['aeson', 'text', 'lens-nonexistent-xyz'], { env: liveEnv(dir), fetchImpl: f, now: NOW });
  assert.equal(r.status, 'refreshed', JSON.stringify(r));
  const p = snapshotPath({ XDG_CONFIG_HOME: dir });
  assert.equal(statSync(p).mode & 0o777, 0o600, 'the snapshot is readable by the operator only');
  const db = loadDb(dir);
  assert.equal(db.coverage('aeson'), 'covered');
  assert.equal(db.coverage('never-asked-for'), 'uncovered');
  // aeson has real advisories; HSEC-2023-0001 is inside this version range
  const ev = evaluateComponents([{ name: 'aeson', version: '1.0.0.0' }, { name: 'text', version: '2.0' }, { name: 'never-asked-for', version: '1.0' }], db);
  assert.ok(ev.findings.some((x) => x.osvId === 'HSEC-2023-0001'), 'a real advisory is matched from the fetched record');
  assert.equal(ev.statuses.find((s) => s.name === 'text').status, 'no-advisories', 'a queried package with no advisory is legitimately clean');
  assert.equal(ev.statuses.find((s) => s.name === 'never-asked-for').status, 'feed-incomplete', 'a package the feed never covered is UNKNOWN, not clean');
});

test('[HS-009] a covered package is not queried again inside the TTL, and is after it', async () => {
  const dir = tmp(); const f = fakeOsv();
  const env = liveEnv(dir);
  await refreshHackageAdvisories(['aeson'], { env, fetchImpl: f, now: NOW });
  const n = f.calls.length;
  const again = await refreshHackageAdvisories(['aeson'], { env, fetchImpl: f, now: NOW + HOUR });
  assert.equal(again.status, 'current');
  assert.equal(f.calls.length, n, 'no request inside the TTL');
  const later = await refreshHackageAdvisories(['aeson'], { env, fetchImpl: f, now: NOW + 25 * HOUR });
  assert.equal(later.status, 'refreshed');
  assert.ok(f.calls.length > n, 'requested again after the TTL');
});

test('[HS-009] a record that cannot be fetched leaves its package UNCOVERED, never clean', async () => {
  const dir = tmp(); const f = fakeOsv({ failVulns: new Set(['HSEC-2023-0001']) });
  const r = await refreshHackageAdvisories(['aeson', 'xml-conduit'], { env: liveEnv(dir), fetchImpl: f, now: NOW });
  assert.equal(r.status, 'partial');
  assert.ok(r.uncovered.includes('aeson'));
  assert.ok(!r.uncovered.includes('xml-conduit'));
  const db = loadDb(dir);
  assert.equal(db.coverage('aeson'), 'uncovered');
  assert.equal(db.coverage('xml-conduit'), 'covered');
  const ev = evaluateComponents([{ name: 'aeson', version: '1.0.0.0' }], db);
  assert.equal(ev.statuses[0].status, 'feed-incomplete');
  assert.deepEqual(ev.findings, [], 'no finding is invented, and none is silently cleared: the status says unknown');
});

test('[HS-009] an unreachable feed with no previous snapshot is a stated failure, writes nothing, and the reason says why', async () => {
  _resetLastRefresh();
  const dir = tmp(); const f = fakeOsv({ failBatch: true });
  const env = liveEnv(dir);
  const r = await refreshHackageAdvisories(['aeson'], { env, fetchImpl: f, now: NOW });
  assert.equal(r.status, 'failed');
  assert.equal(existsSync(snapshotPath({ XDG_CONFIG_HOME: dir })), false);
  const c = configuredAdvisoryDb(null, env);
  assert.equal(c.db, null);
  assert.match(c.reason, /Live feed: failed/);
});

test('[HS-009] an unreachable feed keeps the previous snapshot and its coverage dates', async () => {
  const dir = tmp(); const env = liveEnv(dir);
  await refreshHackageAdvisories(['aeson'], { env, fetchImpl: fakeOsv(), now: NOW });
  const before = readFileSync(snapshotPath({ XDG_CONFIG_HOME: dir }), 'utf8');
  const r = await refreshHackageAdvisories(['aeson'], { env, fetchImpl: fakeOsv({ failBatch: true }), now: NOW + 48 * HOUR });
  assert.equal(r.status, 'failed');
  assert.equal(readFileSync(snapshotPath({ XDG_CONFIG_HOME: dir }), 'utf8'), before, 'the previous snapshot is untouched');
  assert.equal(loadDb(dir).coverage('aeson'), 'covered');
});

test('[HS-009] coverage older than the feed age limit reads feed-stale (unknown), not clean', async () => {
  const dir = tmp(); const env = liveEnv(dir);
  await refreshHackageAdvisories(['text'], { env, fetchImpl: fakeOsv(), now: NOW });
  const snap = JSON.parse(readFileSync(snapshotPath({ XDG_CONFIG_HOME: dir }), 'utf8'));
  const old = loadAdvisorySnapshot(snap, { now: NOW + 90 * 86400000 });
  assert.ok(old.ok);
  assert.equal(old.db.coverage('text'), 'stale');
  assert.equal(evaluateComponents([{ name: 'text', version: '2.0' }], old.db).statuses[0].status, 'feed-stale');
});

test('[HS-009] hostile wire data: bad names never reach a query, bad ids never reach a URL, a mismatched record is dropped', async () => {
  const dir = tmp(); const calls = [];
  const evil = async (url, init = {}) => {
    calls.push({ url, body: init.body });
    const json = (o) => ({ status: 200, text: async () => JSON.stringify(o) });
    if (url.endsWith('/v1/querybatch')) return json({ results: JSON.parse(init.body).queries.map(() => ({ vulns: [{ id: '../../etc/passwd' }, { id: 'HSEC-2023-0001', modified: '2025-11-14T00:00:00Z' }] })) });
    return json({ id: 'HSEC-9999-9999', summary: 'a different record than the one asked for' });
  };
  const r = await refreshHackageAdvisories(['aeson', '../evil', 'a b', 'x/y'], { env: liveEnv(dir), fetchImpl: evil, now: NOW });
  const batch = JSON.parse(calls.find((c) => c.url.endsWith('/v1/querybatch')).body);
  assert.deepEqual(batch.queries.map((q) => q.package.name), ['aeson'], 'only a valid Hackage name is ever queried');
  assert.ok(calls.every((c) => !c.url.includes('..')), 'no path-shaped id reached a URL');
  assert.ok(r.uncovered.includes('aeson'), 'the record that was not the one requested is not accepted, so the package is not covered');
});

test('[HS-009] a response over the size bound is refused', async () => {
  const dir = tmp();
  const huge = async (url) => ({ status: 200, text: async () => (url.endsWith('/v1/querybatch') ? JSON.stringify({ results: [{ vulns: [{ id: 'HSEC-2023-0001' }] }] }) : 'x'.repeat(2 << 20)) });
  const r = await refreshHackageAdvisories(['aeson'], { env: liveEnv(dir), fetchImpl: huge, now: NOW });
  assert.ok(r.uncovered.includes('aeson'));
});

test('[HS-009] a package with more advisories than one page is not claimed as covered', async () => {
  const dir = tmp();
  const r = await refreshHackageAdvisories(['aeson'], { env: liveEnv(dir), fetchImpl: fakeOsv({ pageToken: new Set(['aeson']) }), now: NOW });
  assert.ok(r.uncovered.includes('aeson'));
});

test('[HS-009] a tampered cache is discarded and rebuilt, not trusted', async () => {
  const dir = tmp(); const env = liveEnv(dir);
  await refreshHackageAdvisories(['aeson'], { env, fetchImpl: fakeOsv(), now: NOW });
  const p = snapshotPath({ XDG_CONFIG_HOME: dir });
  const snap = JSON.parse(readFileSync(p, 'utf8'));
  snap.records[0].affected = [];                    // someone empties an advisory in the cache
  writeFileSync(p, JSON.stringify(snap));
  const f = fakeOsv();
  const r = await refreshHackageAdvisories(['aeson'], { env, fetchImpl: f, now: NOW + HOUR });
  assert.equal(r.status, 'refreshed', 'the cache was not trusted, so the package was looked up again');
  assert.match(String(r.cacheProblem), /discarded/);
  assert.ok(f.calls.length > 0);
  const ev = evaluateComponents([{ name: 'aeson', version: '1.0.0.0' }], loadDb(dir));
  assert.ok(ev.findings.length > 0, 'the advisory is back');
});

test('[HS-009] a snapshot with no coverage field behaves exactly as before: every package counts as covered', () => {
  const r = loadAdvisorySnapshot({ schema: 1, generatedAt: '2026-10-01T00:00:00Z', records: [], recordHashes: {} }, { now: NOW });
  assert.ok(r.ok);
  assert.equal(r.db.coverage('anything'), 'covered');
  assert.equal(evaluateComponents([{ name: 'anything', version: '1.0' }], r.db).statuses[0].status, 'no-advisories');
});

test('[HS-009] end to end: the scan reports an advisory-feed-incomplete gap for a package the feed did not cover', async () => {
  const dir = tmp(); const env = liveEnv(dir);
  const files = { 'app.cabal': 'name: app\nversion: 0.1\nbuild-type: Simple\ncabal-version: >=1.10\nexecutable app\n  main-is: Main.hs\n  build-depends: base, aeson ==1.0.0.0, mystery-pkg ==1.0\n  default-language: Haskell2010\n', 'Main.hs': 'main :: IO ()\nmain = pure ()\n' };
  const pre = await prefetchHackageFeed(files, { env, fetchImpl: fakeOsv({ failVulns: new Set(['HSEC-2023-0001']) }), now: NOW });
  assert.ok(pre && (pre.status === 'partial' || pre.status === 'refreshed'));
  const out = analyzeHaskellSupply(files, { root: null, env, now: NOW });
  const kinds = out.gaps.map((g) => g.kind);
  assert.ok(kinds.includes('advisory-feed-incomplete'), `gaps: ${kinds.join(', ')}`);
  assert.ok(out.statuses.some((s) => s.name === 'aeson' && s.status === 'feed-incomplete'));
});

test('[HS-009] prefetch costs nothing and requests nothing unless the feed is enabled', async () => {
  const f = fakeOsv();
  assert.equal(await prefetchHackageFeed({ 'a.cabal': 'name: a\n' }, { env: {}, fetchImpl: f }), null);
  assert.equal(f.calls.length, 0);
});
