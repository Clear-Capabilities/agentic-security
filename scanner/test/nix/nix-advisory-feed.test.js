// The live NVD advisory feed for the upstream software in a Nix closure: opt-in, coverage-recording, failure-degrading, and keyed by
// CPE identity so a component with no CPE is unknown rather than clean. No test here touches the network: a fake NVD serves the
// TRIMMED REAL gnu:gzip sample (test/fixtures/nvd-cpe/gnu-gzip.sample.json, captured from the public API) plus clearly synthetic
// records where a real one does not exercise the case (marked SYNTHETIC).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, statSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { refreshNixAdvisories, snapshotPath, getLastRefresh, _resetLastRefresh, nvdToOsv, cpeKey, loadLiveSnapshot, FEED_ENV, PINNED_ENV, KEY_ENV, NVD_BASE } from '../../src/language/nix-advisory-feed.js';
import { matchNixVulnerabilities, NixAdvisoryData, closureIdentities, upstreamIdentity } from '../../src/language/nix-sca.js';
import { importNixClosure } from '../../src/language/nix-closure.js';
import { configuredNixAdvisories, configuredNixMeta, prefetchNixAdvisoryFeed, analyzeNixClosure } from '../../src/language/resolved-pass.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLE = JSON.parse(readFileSync(join(HERE, '..', 'fixtures', 'nvd-cpe', 'gnu-gzip.sample.json'), 'utf8'));
const GZIP = SAMPLE.response.vulnerabilities;            // real NVD CVE objects for gnu:gzip
const NOW = Date.parse('2026-10-07T12:00:00Z');
const HOUR = 3600000;
const GZ = 'gnu:gzip';

const synth = (id, matches, extra = {}) => ({ cve: { id, sourceIdentifier: 'synthetic', published: '2026-01-01T00:00:00.000', lastModified: '2026-01-02T00:00:00.000', vulnStatus: 'Analyzed', descriptions: [{ lang: 'en', value: `SYNTHETIC ${id}` }], configurations: [{ nodes: [{ operator: 'OR', negate: false, cpeMatch: matches }] }], references: [], ...extra } });
const cm = (criteria, bounds = {}, vulnerable = true) => ({ vulnerable, criteria: `cpe:2.3:a:${criteria}:*:*:*:*:*:*:*`, matchCriteriaId: 'SYN', ...bounds });

/** A fake NVD. `byProduct` maps 'vendor:product' to the CVE objects it returns. `calls` records every request. */
function fakeNvd(byProduct, { status = null, textOf = null, mutate = null } = {}) {
  const calls = [];
  const impl = async (url, init = {}) => {
    calls.push({ url, headers: init.headers || {} });
    const json = (st, obj) => ({ status: st, text: async () => (typeof obj === 'string' ? obj : JSON.stringify(obj)) });
    if (status) { const st = typeof status === 'function' ? status(calls.length, url) : status; if (st) return json(st, {}); }
    const u = new URL(url);
    const vms = u.searchParams.get('virtualMatchString') || '';
    const m = /^cpe:2\.3:\*:([^:]+:[^:]+)$/.exec(vms);
    if (!m) return json(404, {});
    const all = byProduct[m[1]] || [];
    const start = Number(u.searchParams.get('startIndex')); const size = Number(u.searchParams.get('resultsPerPage'));
    const page = { resultsPerPage: Math.min(size, all.length - start), startIndex: start, totalResults: all.length, format: 'NVD_CVE', version: '2.0', timestamp: '2026-10-07T12:00:00.000', vulnerabilities: all.slice(start, start + size) };
    return json(200, mutate ? mutate(page) : (textOf ? textOf(page) : page));
  };
  impl.calls = calls;
  return impl;
}
const sleeper = () => { const s = async (ms) => { s.waits.push(ms); }; s.waits = []; return s; };
const liveEnv = (dir, extra = {}) => ({ XDG_CONFIG_HOME: dir, [FEED_ENV]: '1', ...extra });
const tmp = () => mkdtempSync(join(tmpdir(), 'agsec-nixfeed-'));
const snapFile = (dir) => snapshotPath({ XDG_CONFIG_HOME: dir });
const readSnap = (dir) => JSON.parse(readFileSync(snapFile(dir), 'utf8'));
const refresh = (ids, dir, f, extra = {}, envExtra = {}) => refreshNixAdvisories(ids, { env: liveEnv(dir, envExtra), fetchImpl: f, now: NOW, sleep: sleeper(), ...extra });

// ── a closure for matching, built through the real importer ──────────────────────────────
const A = '0123456789abcdfghijklmnpqrsvwxyz';
const hh = (i) => { let s = ''; let x = i * 2654435761 % 4294967296; for (let j = 0; j < 32; j++) { s += A[x % 32]; x = (Math.floor(x / 32) + j * 11 + i) % 4294967296; } return s; };
const out = (i, n) => `/nix/store/${hh(i)}-${n}`;
const drv = (i, n) => `/nix/store/${hh(i + 500)}-${n}.drv`;
function closureOf(specs, lockSha = 'a'.repeat(64)) {
  const app = { path: out(1, 'app-1.0'), drv: drv(1, 'app-1.0') };
  const pathinfo = {}; const drvs = {};
  specs.forEach((s, k) => {
    const i = 10 + k;
    s.path = out(i, `${s.pname}-${s.version}`); s.drv = drv(i, `${s.pname}-${s.version}`);
    drvs[s.drv] = { outputs: { out: { path: s.path } }, inputSrcs: [], inputDrvs: {}, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: `${s.pname}-${s.version}`, pname: s.pname, version: s.version, out: s.path, outputs: 'out', ...(s.urls ? { urls: s.urls } : {}) } };
    pathinfo[s.path] = { narHash: 'sha256-x', narSize: 1, references: [], deriver: s.drv };
  });
  pathinfo[app.path] = { narHash: 'sha256-x', narSize: 1, references: [app.path, ...specs.map((s) => s.path)], deriver: app.drv };
  drvs[app.drv] = { outputs: { out: { path: app.path } }, inputSrcs: [], inputDrvs: Object.fromEntries(specs.map((s) => [s.drv, ['out']])), system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: 'app-1.0', pname: 'app', version: '1.0', out: app.path, buildInputs: specs.map((s) => s.path).join(' ') } };
  const prov = (cmd) => ({ tool: 'nix', command: cmd, target: { system: 'x86_64-linux', installable: '.#app' }, revision: {}, flakeLockSha256: lockSha, generatedAt: '2026-10-01T00:00:00Z' });
  const exports = [{ schema: 'nix-path-info-json', data: pathinfo, provenance: prov('nix path-info --json --recursive .#app') }, { schema: 'nix-derivation-show-json', data: drvs, provenance: prov('nix derivation show --recursive .#app') }];
  const closure = importNixClosure({ exports, expected: { system: 'x86_64-linux', installable: '.#app', flakeLockSha256: lockSha }, now: NOW });
  return { closure, drvEnv: Object.fromEntries(Object.entries(drvs).map(([k, v]) => [k, v.env])), exports };
}
const CPE_META = { gzip: { identifiers: { cpe: 'cpe:2.3:a:gnu:gzip:*:*:*:*:*:*:*:*' } } };
const liveData = (dir, extra = {}) => { const r = loadLiveSnapshot(readSnap(dir)); assert.ok(r.ok, r.reason); return new NixAdvisoryData({ records: r.records, source: 'nvd-live-feed', generatedAt: r.generatedAt, covered: r.covered, now: NOW, ...extra }); };
const match = (specs, data, meta = CPE_META) => { const { closure, drvEnv } = closureOf(specs); return matchNixVulnerabilities({ closure, drvEnv, data, meta }); };

// ── contract: off, offline, pinned, foreign ──────────────────────────────────────────────
test('[NIX-009 feed] disabled by default: no flag, no request, no file', async () => {
  const dir = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  const r = await refreshNixAdvisories([GZ], { env: { XDG_CONFIG_HOME: dir }, fetchImpl: f, now: NOW });
  assert.equal(r.status, 'disabled'); assert.equal(f.calls.length, 0); assert.equal(existsSync(snapFile(dir)), false);
});

test('[NIX-009 feed] AGENTIC_SECURITY_OFFLINE=1 beats the opt-in', async () => {
  const dir = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  const r = await refresh([GZ], dir, f, {}, { AGENTIC_SECURITY_OFFLINE: '1' });
  assert.equal(r.status, 'offline'); assert.equal(f.calls.length, 0);
});

test('[NIX-009 feed] an operator-pinned snapshot is used as given and never refreshed over', async () => {
  const dir = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  const r = await refresh([GZ], dir, f, {}, { [PINNED_ENV]: '/some/pinned.json' });
  assert.equal(r.status, 'pinned-snapshot-in-use'); assert.equal(f.calls.length, 0);
});

test('[NIX-009 feed] a hand-written operator snapshot in the configuration directory is never overwritten', async () => {
  const dir = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  mkdirSync(join(dir, 'agentic-security'), { recursive: true });
  const hand = JSON.stringify({ generatedAt: '2026-10-01T00:00:00Z', records: [] });
  writeFileSync(snapFile(dir), hand);
  const r = await refresh([GZ], dir, f);
  assert.equal(r.status, 'operator-snapshot-in-use'); assert.equal(f.calls.length, 0);
  assert.equal(readFileSync(snapFile(dir), 'utf8'), hand);
});

// ── a refresh ────────────────────────────────────────────────────────────────────────────
test('[NIX-009 feed] a refresh writes a hash-recorded 0600 snapshot to the operator directory only, and queries a validated CPE URL', async () => {
  const dir = tmp(); const project = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  const r = await refresh([GZ], dir, f);
  assert.equal(r.status, 'refreshed', JSON.stringify(r));
  assert.equal(statSync(snapFile(dir)).mode & 0o777, 0o600, 'readable by the operator only');
  assert.deepEqual(readdirSync(project), [], 'nothing is written into a scanned project');
  assert.equal(f.calls.length, 1);
  const u = new URL(f.calls[0].url);
  assert.equal(`${u.origin}${u.pathname}`, NVD_BASE);
  assert.equal(u.searchParams.get('virtualMatchString'), 'cpe:2.3:*:gnu:gzip');
  assert.equal(f.calls[0].headers.apiKey, undefined, 'no key header without a key');
  const snap = readSnap(dir);
  assert.equal(snap.schema, 'nix-advisories-live/1');
  assert.ok(snap.covered[GZ]); assert.equal(snap.records.length, GZIP.length);
  for (const rec of snap.records) assert.equal(snap.recordHashes[rec.id], createHash('sha256').update(JSON.stringify(rec)).digest('hex'));
  assert.ok(snap.records.map((x) => x.id).includes('CVE-2022-1271'));
});

test('[NIX-009 feed] rate limiting: keyless spacing is 6.5 s between requests; a key sends the header and uses 0.7 s; an invalid key is ignored', async () => {
  const many = Array.from({ length: 5 }, (_, i) => synth(`CVE-2099-000${i + 1}`, [cm('v:p', { versionEndExcluding: '2.0' })]));
  const d1 = tmp(); const f1 = fakeNvd({ 'v:p': many }); const s1 = sleeper();
  await refreshNixAdvisories(['v:p'], { env: liveEnv(d1), fetchImpl: f1, now: NOW, sleep: s1, pageSize: 2 });
  assert.equal(f1.calls.length, 3); assert.deepEqual(s1.waits, [6500, 6500], 'no wait before the first request, 6.5 s before each later one');
  const d2 = tmp(); const f2 = fakeNvd({ 'v:p': many }); const s2 = sleeper();
  const KEY = '12345678-1234-1234-1234-123456789abc';
  await refreshNixAdvisories(['v:p'], { env: liveEnv(d2, { [KEY_ENV]: KEY }), fetchImpl: f2, now: NOW, sleep: s2, pageSize: 2 });
  assert.deepEqual(s2.waits, [700, 700]); assert.equal(f2.calls[0].headers.apiKey, KEY);
  assert.ok(!f2.calls.some((c) => c.url.includes(KEY)), 'the key is never placed in a URL');
  const f3 = fakeNvd({ 'v:p': many });
  const r3 = await refreshNixAdvisories(['v:p'], { env: liveEnv(tmp(), { [KEY_ENV]: 'x\r\nInjected: 1' }), fetchImpl: f3, now: NOW, sleep: sleeper() });
  assert.equal(f3.calls[0].headers.apiKey, undefined); assert.match(r3.detail, /not a valid key/);
});

test('[NIX-009 feed] a throttling response stops the run (no retry, no hammering) and leaves the rest uncovered', async () => {
  const dir = tmp(); const f = fakeNvd({ 'a:one': [synth('CVE-2099-1001', [cm('a:one')])], 'b:two': [], 'c:three': [] }, { status: (n) => (n >= 2 ? 403 : null) });
  const r = await refresh(['a:one', 'b:two', 'c:three'], dir, f);
  assert.equal(r.status, 'partial'); assert.equal(r.throttled, true);
  assert.equal(f.calls.length, 2, 'one good request, one refused, then nothing');
  assert.deepEqual(r.uncovered, ['b:two', 'c:three']);
  const snap = readSnap(dir); assert.ok(snap.covered['a:one']); assert.equal(snap.covered['b:two'], undefined);
});

test('[NIX-009 feed] the per-scan request cap leaves later identities for a later scan and says so', async () => {
  const dir = tmp(); const f = fakeNvd({ 'a:one': [], 'b:two': [], 'c:three': [] });
  const r = await refresh(['a:one', 'b:two', 'c:three'], dir, f, { maxRequestsKeyless: 2 });
  assert.equal(f.calls.length, 2); assert.deepEqual(r.uncovered, ['c:three']); assert.match(r.failures[0], /request cap/);
});

test('[NIX-009 feed] a covered identity is not queried again inside the TTL, and is after it', async () => {
  const dir = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  await refresh([GZ], dir, f); const n = f.calls.length;
  const again = await refresh([GZ], dir, f, { now: NOW + HOUR });
  assert.equal(again.status, 'current'); assert.equal(f.calls.length, n);
  const later = await refresh([GZ], dir, f, { now: NOW + 25 * HOUR });
  assert.equal(later.status, 'refreshed'); assert.ok(f.calls.length > n);
});

// ── validation of what goes to the URL and what comes back ───────────────────────────────
test('[NIX-009 feed] identities that are not plain CPE names never reach a URL', async () => {
  const dir = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  const bad = ['gnu:gzip&apiKey=x', 'a:b:c', '../etc:passwd', 'v:p%0d%0a', { vendor: 'x y', product: 'z' }, 'cpe:2.3:a:ok', 'UPPER:CASE:extra', 42, null, `v:${'p'.repeat(80)}`];
  const r = await refresh([...bad, GZ], dir, f);
  assert.equal(r.status, 'refreshed');
  assert.equal(f.calls.length, 1); assert.equal(new URL(f.calls[0].url).searchParams.get('virtualMatchString'), 'cpe:2.3:*:gnu:gzip');
  const only = await refresh(bad, tmp(), f);
  assert.equal(only.status, 'nothing-to-do'); assert.ok(only.invalid >= 8); assert.equal(f.calls.length, 1, 'no request for invalid identities');
  assert.equal(cpeKey('cpe:2.3:a:GNU:gzip:1.12:*:*:*:*:*:*:*'), 'gnu:gzip');
  assert.equal(cpeKey({ vendor: 'gnu', product: 'gzip' }), 'gnu:gzip');
});

test('[NIX-009 feed] a record that does not name the requested product, or is rejected, is dropped', async () => {
  const dir = tmp();
  const other = synth('CVE-2099-2001', [cm('someone:else', { versionEndExcluding: '9' })]);                 // names a different product
  const rejected = synth('CVE-2099-2002', [cm('v:p', { versionEndExcluding: '9' })], { vulnStatus: 'Rejected' });
  const notVuln = synth('CVE-2099-2003', [cm('v:p', {}, false)]);                                            // vulnerable:false is a running-on condition
  const good = synth('CVE-2099-2004', [cm('v:p', { versionEndExcluding: '9' })]);
  const forged = { cve: { id: 'not-a-cve', configurations: good.cve.configurations } };
  const f = fakeNvd({ 'v:p': [other, rejected, notVuln, good, forged] });
  const r = await refresh(['v:p'], dir, f);
  assert.equal(r.status, 'refreshed'); assert.equal(r.dropped, 4);
  assert.deepEqual(readSnap(dir).records.map((x) => x.id), ['CVE-2099-2004']);
});

test('[NIX-009 feed] a malformed, oversized or incomplete answer leaves the identity UNCOVERED, never clean', async () => {
  const cases = [
    ['wrong page', fakeNvd({ 'v:p': [] }, { mutate: (p) => ({ ...p, startIndex: 7 }) }), {}],
    ['not a page', fakeNvd({ 'v:p': [] }, { mutate: () => ({ hello: 'world' }) }), {}],
    ['not json', fakeNvd({ 'v:p': [] }, { textOf: () => 'this is not json' }), {}],
    ['too large', fakeNvd({ 'v:p': [synth('CVE-2099-3001', [cm('v:p')])] }), { maxResponseBytes: 100 }],
    ['server error', fakeNvd({ 'v:p': [] }, { status: 500 }), {}],
  ];
  for (const [name, f, extra] of cases) {
    const dir = tmp();
    const r = await refresh(['v:p'], dir, f, extra);
    assert.equal(r.status, 'failed', name); assert.deepEqual(r.uncovered, ['v:p'], name);
    assert.equal(existsSync(snapFile(dir)), false, `${name}: nothing is written when nothing was read`);
  }
  // more CVEs than the feed will read: not covered, and no further pages are requested
  const many = Array.from({ length: 7 }, (_, i) => synth(`CVE-2099-400${i}`, [cm('v:p')]));
  const f = fakeNvd({ 'v:p': many });
  const r = await refresh(['v:p'], tmp(), f, { pageSize: 2, maxPages: 2 });
  assert.equal(r.status, 'failed'); assert.equal(f.calls.length, 1); assert.match(r.failures[0], /more than the 4/);
  // a result set that shrinks part-way through
  let n = 0; const shrink = fakeNvd({ 'v:p': many.slice(0, 4) }, { mutate: (p) => (++n === 2 ? { ...p, totalResults: 3 } : p) });
  const r2 = await refresh(['v:p'], tmp(), shrink, { pageSize: 2 });
  assert.equal(r2.status, 'failed'); assert.match(r2.failures[0], /changed while/);
});

test('[NIX-009 feed] pagination reads every page before an identity is called covered', async () => {
  const dir = tmp(); const many = Array.from({ length: 5 }, (_, i) => synth(`CVE-2099-500${i}`, [cm('v:p', { versionEndExcluding: '2.0' })]));
  const r = await refresh(['v:p'], dir, fakeNvd({ 'v:p': many }), { pageSize: 2 });
  assert.equal(r.status, 'refreshed'); assert.equal(readSnap(dir).records.length, 5);
  // a page that comes back empty before the total is reached is a short read, not coverage
  const short = fakeNvd({ 'v:p': many }, { mutate: (p) => (p.startIndex >= 2 ? { ...p, vulnerabilities: [] } : p) });
  const r2 = await refresh(['v:p'], tmp(), short, { pageSize: 2 });
  assert.equal(r2.status, 'failed'); assert.match(r2.failures[0], /not read to the end/);
});

// ── failure degrades; the cache is checked ───────────────────────────────────────────────
test('[NIX-009 feed] an unreachable feed keeps the previous snapshot and its coverage dates; with none it is a stated failure', async () => {
  _resetLastRefresh();
  const dir = tmp();
  const none = await refresh([GZ], dir, fakeNvd({}, { status: 503 }));
  assert.equal(none.status, 'failed'); assert.equal(existsSync(snapFile(dir)), false); assert.equal(getLastRefresh().status, 'failed');
  await refresh([GZ], dir, fakeNvd({ [GZ]: GZIP }));
  const before = readFileSync(snapFile(dir), 'utf8');
  const r = await refresh([GZ], dir, fakeNvd({}, { status: 503 }), { now: NOW + 48 * HOUR });
  assert.equal(r.status, 'failed'); assert.match(r.detail, /previous snapshot is used/);
  assert.equal(readFileSync(snapFile(dir), 'utf8'), before, 'untouched');
});

test('[NIX-009 feed] a cache whose records fail their hashes is discarded, never repaired or trusted', async () => {
  const dir = tmp();
  await refresh([GZ], dir, fakeNvd({ [GZ]: GZIP }));
  const snap = readSnap(dir);
  snap.records[0].summary = 'tampered after signing';
  writeFileSync(snapFile(dir), JSON.stringify(snap));
  // the loader refuses it: no advisory data, with the reason, so every component is unknown
  const c = configuredNixAdvisories(null, { XDG_CONFIG_HOME: dir });
  assert.equal(c.data, null); assert.match(c.reason, /refused: record CVE-\S+ does not match its recorded hash/);
  // the next refresh starts clean and says why
  const r = await refresh([GZ], dir, fakeNvd({ [GZ]: GZIP }));
  assert.equal(r.status, 'refreshed'); assert.match(r.cacheProblem, /discarded/);
  assert.ok(configuredNixAdvisories(null, { XDG_CONFIG_HOME: dir }).data);
});

test('[NIX-009 feed] identities sharing a CVE merge, and re-reading one replaces only its own entries', async () => {
  const dir = tmp();
  const shared = synth('CVE-2099-6001', [cm('v:one', { versionEndExcluding: '2' }), cm('v:two', { versionEndExcluding: '5' })]);
  const only1 = synth('CVE-2099-6002', [cm('v:one', { versionEndExcluding: '3' })]);
  await refresh(['v:one'], dir, fakeNvd({ 'v:one': [shared, only1], 'v:two': [shared] }));
  await refresh(['v:two'], dir, fakeNvd({ 'v:one': [shared, only1], 'v:two': [shared] }));
  let snap = readSnap(dir);
  const sh = snap.records.find((x) => x.id === 'CVE-2099-6001');
  assert.deepEqual(sh.affected.map((a) => a.package.cpe).sort(), ['v:one', 'v:two']);
  // v:one is re-read and its CVE-2099-6002 is gone upstream: only that record leaves; v:two's entry survives
  await refresh(['v:one'], dir, fakeNvd({ 'v:one': [shared] }), { now: NOW + 30 * HOUR });
  snap = readSnap(dir);
  assert.deepEqual(snap.records.map((x) => x.id), ['CVE-2099-6001']);
  assert.deepEqual(snap.records[0].affected.map((a) => a.package.cpe).sort(), ['v:one', 'v:two']);
  assert.deepEqual(Object.keys(snap.covered).sort(), ['v:one', 'v:two']);
});

// ── NVD -> record conversion ─────────────────────────────────────────────────────────────
test('[NIX-009 feed] the real NVD sample converts to ranges: end-exclusive, end-inclusive and exact versions', () => {
  const byId = Object.fromEntries(GZIP.map((v) => [v.cve.id, nvdToOsv(v.cve, GZ)]));
  assert.deepEqual(byId['CVE-2022-1271'].affected[0].ranges, [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.12' }] }]);
  assert.deepEqual(byId['CVE-2003-0367'].affected[0].ranges, [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { last_affected: '1.3.5' }] }]);
  assert.deepEqual(byId['CVE-2005-0988'].affected[0].versions, ['1.2.4', '1.2.4a', '1.3.3']);
  assert.equal(nvdToOsv(GZIP[0].cve, 'debian:debian_linux').affected[0].package.cpe, 'debian:debian_linux', 'the same record read for another product yields only that product');
  assert.equal(nvdToOsv(GZIP[0].cve, 'nobody:nothing'), null);
});

test('[NIX-009 feed] SYNTHETIC: an exclusive start bound excludes that exact version, an inclusive one does not', () => {
  const d = (m) => new NixAdvisoryData({ records: [nvdToOsv(synth('CVE-2099-7001', [m]).cve, 'v:p')], now: NOW, generatedAt: '2026-10-07T00:00:00Z' });
  const run = (data, version) => match([{ pname: 'p', version }], data, { p: { identifiers: { cpe: 'cpe:2.3:a:v:p:*:*:*:*:*:*:*:*' } } }).findings.map((f) => f.status).filter((x) => x !== 'fixed');   // 'fixed' is the informational answer for a version at or past the fix
  const excl = d(cm('v:p', { versionStartExcluding: '2.0', versionEndExcluding: '3.0' }));
  assert.deepEqual(run(excl, '2.0'), [], 'the start bound itself is not affected');
  assert.deepEqual(run(excl, '2.0.1'), ['affected']);
  assert.deepEqual(run(excl, '3.0'), [], 'the fix itself is not affected');
  const incl = d(cm('v:p', { versionStartIncluding: '2.0', versionEndExcluding: '3.0' }));
  assert.deepEqual(run(incl, '2.0'), ['affected']);
  assert.deepEqual(run(incl, '1.9'), []);
  const last = d(cm('v:p', { versionEndIncluding: '3.0' }));
  assert.deepEqual(run(last, '3.0'), ['affected']); assert.deepEqual(run(last, '3.0.1'), []);
});

// ── matching: identity gate and coverage ─────────────────────────────────────────────────
test('[NIX-009 feed] a live snapshot finds the real advisory by CPE identity and not outside the range', async () => {
  const dir = tmp(); await refresh([GZ], dir, fakeNvd({ [GZ]: GZIP }));
  const hit = match([{ pname: 'gzip', version: '1.11' }], liveData(dir));
  const f = hit.findings.find((x) => x.osvId === 'CVE-2022-1271');
  assert.ok(f, 'gzip 1.11 is inside CVE-2022-1271 (fixed in 1.12)');
  assert.equal(f.status, 'affected'); assert.equal(f.dataSource.identityAuthority, 'explicit'); assert.deepEqual(f.fixedIn, ['1.12']);
  const past = match([{ pname: 'gzip', version: '1.15' }], liveData(dir));
  assert.ok(past.findings.length > 0 && past.findings.every((x) => x.status === 'fixed'), 'at or past every fix: informational only');
  assert.equal(past.statuses.length, 0, 'and no unknown is raised for a covered identity');
});

test('[NIX-009 feed] a covered identity with no advisories at all is legitimately not-affected', async () => {
  const dir = tmp(); await refresh(['v:p'], dir, fakeNvd({ 'v:p': [] }));
  const r = match([{ pname: 'p', version: '1.0' }], liveData(dir), { p: { identifiers: { cpe: 'cpe:2.3:a:v:p:*:*:*:*:*:*:*:*' } } });
  assert.deepEqual(r.findings, []);
  assert.equal(r.statuses[0].status, 'not-affected'); assert.equal(r.statuses[0].feedCoverage, undefined);
});

test('[NIX-009 feed] an identity the feed did not cover is UNKNOWN, never not-affected', async () => {
  const dir = tmp(); await refresh([GZ], dir, fakeNvd({ [GZ]: GZIP }));
  const data = liveData(dir);
  // a different explicit CPE that was never read
  const unread = match([{ pname: 'mystery', version: '3.1' }], data, { mystery: { identifiers: { cpe: 'cpe:2.3:a:acme:mystery:*:*:*:*:*:*:*:*' } } });
  const s = unread.statuses.find((x) => x.name === 'mystery');
  assert.equal(s.status, 'unknown'); assert.equal(s.feedCoverage, 'incomplete'); assert.match(s.reason, /never read acme:mystery/);
  // a covered identity whose coverage has aged out
  const stale = liveData(dir, { now: NOW + 40 * 86400000 });
  const old = match([{ pname: 'gzip', version: '1.15' }], stale);
  const os = old.statuses.find((x) => x.name === 'gzip');
  assert.equal(os.status, 'unknown'); assert.match(os.reason, /longer ago than its age limit/); assert.equal(os.feedCoverage, 'incomplete');
  // and a covered identity with no advisories is unknown once its coverage is stale, not clean
  const d2 = tmp(); await refresh(['v:p'], d2, fakeNvd({ 'v:p': [] }));
  const e = match([{ pname: 'p', version: '1.0' }], liveData(d2, { now: NOW + 40 * 86400000 }), { p: { identifiers: { cpe: 'cpe:2.3:a:v:p:*:*:*:*:*:*:*:*' } } });
  assert.equal(e.statuses[0].status, 'unknown');
});

test('[NIX-009 feed] a component with no CPE (a source URL or purl alone, or only its name) is unknown: the feed is keyed by CPE', async () => {
  const dir = tmp(); await refresh([GZ], dir, fakeNvd({ [GZ]: GZIP }));
  const data = liveData(dir);
  const urlOnly = match([{ pname: 'gzip', version: '1.11', urls: 'https://github.com/example/gzip/releases/download/v1.11/gzip-1.11.tar.gz' }], data, {});
  const s = urlOnly.statuses.find((x) => x.name === 'gzip');
  assert.equal(s.status, 'unknown'); assert.equal(s.feedCoverage, 'incomplete'); assert.match(s.reason, /declares no CPE identity/);
  assert.deepEqual(urlOnly.findings, [], 'the attribute name gzip alone never matches a CPE advisory');
  // several possible CPEs: ambiguous, so a lead at most, never a verdict
  const amb = match([{ pname: 'gzip', version: '1.11' }], data, { gzip: { identifiers: { possibleCPEs: [{ vendor: 'gnu', product: 'gzip' }, { vendor: 'other', product: 'gzip' }] } } });
  assert.ok(amb.findings.some((f) => f.status === 'candidate'));
  assert.ok(amb.findings.every((f) => f.status === 'candidate' || f.status === 'unknown'), 'no firm verdict from an ambiguous identity');
  assert.ok(amb.statuses.every((x) => x.status !== 'not-affected'));
});

test('[NIX-009 feed] a pinned snapshot without a coverage table behaves exactly as before (no new unknowns)', () => {
  const rec = nvdToOsv(GZIP.find((v) => v.cve.id === 'CVE-2022-1271').cve, GZ);
  const data = new NixAdvisoryData({ records: [rec], now: NOW, generatedAt: '2026-10-07T00:00:00Z' });
  const r = match([{ pname: 'gzip', version: '1.15' }], data);
  assert.deepEqual(r.findings.map((f) => f.status), ['fixed']); assert.equal(r.statuses.length, 0);
  const none = match([{ pname: 'p', version: '1.0' }], new NixAdvisoryData({ records: [], now: NOW, generatedAt: '2026-10-07T00:00:00Z' }), { p: { identifiers: { cpe: 'cpe:2.3:a:v:p:*:*:*:*:*:*:*:*' } } });
  assert.equal(none.statuses[0].feedCoverage, undefined, 'no coverage claim, so no coverage gap');
  assert.equal(data.cpeCoverage('anything:at-all'), 'covered');
});

test('[NIX-009 feed] a withdrawn record never produces a finding', () => {
  const rec = nvdToOsv(GZIP.find((v) => v.cve.id === 'CVE-2022-1271').cve, GZ);
  const run = (r) => match([{ pname: 'gzip', version: '1.11' }], new NixAdvisoryData({ records: [r], now: NOW, generatedAt: '2026-10-07T00:00:00Z' })).findings.length;
  assert.equal(run(rec), 1);
  assert.equal(run({ ...rec, withdrawn: '2026-09-01T00:00:00Z' }), 0);
});

// ── identity collection and the scan integration ─────────────────────────────────────────
test('[NIX-009 feed] closureIdentities lists the CPEs the matcher will use, and the components that have none', () => {
  const { closure, drvEnv } = closureOf([{ pname: 'gzip', version: '1.11' }, { pname: 'zlib', version: '1.3', urls: 'https://github.com/madler/zlib/archive/v1.3.tar.gz' }, { pname: 'ssl', version: '1.5.0' }]);
  const r = closureIdentities({ closure, drvEnv, meta: { ...CPE_META, ssl: { identifiers: { possibleCPEs: ['cpe:2.3:a:vendora:ssl:*:*:*:*:*:*:*:*', { vendor: 'vendorb', product: 'ssl' }] } } } });
  assert.deepEqual(r.cpes, ['gnu:gzip', 'vendora:ssl', 'vendorb:ssl']);
  assert.deepEqual(r.withoutCpe, ['zlib']);
  assert.equal(upstreamIdentity({ pname: 'x', version: '1' }, null, { identifiers: { cpe: 'cpe:2.3:a:V:P:1:*:*:*:*:*:*:*' } }, null).candidates.find((c) => c.cpe).cpe, 'v:p');
});

function projectFiles(specs, lockText = '{"nodes":{},"root":"root","version":7}') {
  const sha = createHash('sha256').update(lockText).digest('hex');
  const { exports } = closureOf(specs, sha);
  return { 'flake.lock': lockText, 'nix-export.json': JSON.stringify({ exports }) };
}

test('[NIX-009 feed] prefetch: nothing happens unless enabled; when enabled it asks only for the closure\'s CPEs and the scan then uses them', async () => {
  const meta = join(tmp(), 'meta.json');
  writeFileSync(meta, JSON.stringify({ gzip: { meta: CPE_META.gzip }, 'pkgs.zlib': { pname: 'zlib', meta: { identifiers: { purl: 'pkg:github/madler/zlib' } } } }));
  const dir = tmp(); const f = fakeNvd({ [GZ]: GZIP });
  const files = projectFiles([{ pname: 'gzip', version: '1.11' }, { pname: 'zlib', version: '1.3' }]);
  const off = await prefetchNixAdvisoryFeed(files, { env: { XDG_CONFIG_HOME: dir, AGENTIC_SECURITY_NIX_META: meta }, fetchImpl: f, now: NOW });
  assert.equal(off, null); assert.equal(f.calls.length, 0);
  const env = liveEnv(dir, { AGENTIC_SECURITY_NIX_META: meta });
  const r = await prefetchNixAdvisoryFeed(files, { env, fetchImpl: f, now: NOW, sleep: sleeper() });
  assert.equal(r.status, 'refreshed', JSON.stringify(r)); assert.equal(f.calls.length, 1, 'only gzip has a CPE; the purl-only zlib is not queried');
  const a = analyzeNixClosure(files, { env, now: NOW });
  assert.ok(a.findings.some((x) => x.osvId === 'CVE-2022-1271' && x.status === 'affected'), JSON.stringify(a.gaps));
  const z = a.statuses.find((x) => x.name === 'zlib');
  assert.equal(z.status, 'unknown'); assert.equal(z.feedCoverage, 'incomplete');
  assert.ok(a.gaps.some((g) => g.kind === 'closure-advisory-feed-incomplete' && /zlib/.test(g.detail)), 'the gap is reported');
});

test('[NIX-009 feed] prefetch: a refused export (bound to another flake.lock) asks for nothing', async () => {
  const files = projectFiles([{ pname: 'gzip', version: '1.11' }]);
  files['flake.lock'] = '{"nodes":{"other":{}},"root":"other","version":7}';
  const meta = join(tmp(), 'meta.json'); writeFileSync(meta, JSON.stringify(CPE_META));
  const f = fakeNvd({ [GZ]: GZIP });
  const r = await prefetchNixAdvisoryFeed(files, { env: liveEnv(tmp(), { AGENTIC_SECURITY_NIX_META: meta }), fetchImpl: f, now: NOW, sleep: sleeper() });
  assert.equal(r, null); assert.equal(f.calls.length, 0);
});

test('[NIX-009 feed] the metadata file comes from the operator only', () => {
  assert.deepEqual(configuredNixMeta({}).meta, {});
  const p = join(tmp(), 'm.json');
  writeFileSync(p, '{"nixpkgs.gzip":{"pname":"gzip","meta":{"identifiers":{"cpe":"cpe:2.3:a:gnu:gzip:*:*:*:*:*:*:*:*"}}},"__proto__":{"meta":{}}}');
  const m = configuredNixMeta({ AGENTIC_SECURITY_NIX_META: p });
  assert.ok(m.meta.gzip.identifiers); assert.equal(Object.keys(m.meta).length, 1);
  assert.match(configuredNixMeta({ AGENTIC_SECURITY_NIX_META: '/nonexistent/x.json' }).reason, /unreadable/);
});

test('[NIX-009 feed] the engine runs the prefetch only when the flag is set', () => {
  const src = readFileSync(join(HERE, '..', '..', 'src', 'engine.js'), 'utf8');
  assert.match(src, /process\.env\.AGENTIC_SECURITY_NIX_ADVISORIES_LIVE==='1'[^\n]*prefetchNixAdvisoryFeed\(allFileContents\)/);
});
