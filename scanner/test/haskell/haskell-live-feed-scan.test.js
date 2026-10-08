// Found by running the live feed against real projects (bench/live-feed): two things the unit tests of the feed module cannot see, because
// they only appear in a whole scan's output. No network: a fake OSV serves the REAL pinned HSEC records.
//   1. scanHealth.languageCoverage.optionalModes['hackage-live'] was hard-coded `selected:false`, so a scan that DID query OSV reported the
//      live feed as "not selected".
//   2. The scan result's finding for a Hackage advisory dropped matchStatus / matchReason / declaredRange, so a `possibly-affected`
//      finding (only a declared range is known) was indistinguishable from an `affected` one (resolved version inside the range).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runScan } from '../../src/runScan.js';
import { normalizeFindings } from '../../src/report/index.js';
import { liveFeedOptionalState } from '../../src/language/haskell-advisory-feed.js';
import { AdvisoryDb, evaluateComponents } from '../../src/language/haskell-sca.js';
import { hackageComponents } from '../../src/language/haskell-supply.js';
import { queryRegistries } from '../../src/engine.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'hackage-advisories', 'records');
const REAL = readdirSync(DIR).filter((f) => f.endsWith('.json')).sort().map((f) => JSON.parse(readFileSync(join(DIR, f), 'utf8')));

function fakeFetch() {
  return async (url, init = {}) => {
    const json = (status, obj) => ({ status, text: async () => JSON.stringify(obj), json: async () => obj });
    const u = String(url);
    if (!/^https:\/\/api\.osv\.dev\//.test(u)) return json(404, {});
    if (u.endsWith('/v1/querybatch')) {
      const { queries } = JSON.parse(init.body);
      return json(200, { results: queries.map((q) => ({ vulns: REAL.filter((r) => (r.affected || []).some((a) => a.package && a.package.name === q.package.name)).map((r) => ({ id: r.id, modified: r.modified })) })) });
    }
    const m = /\/v1\/vulns\/(.+)$/.exec(u);
    const rec = m && REAL.find((r) => r.id === decodeURIComponent(m[1]));
    return rec ? json(200, rec) : json(404, {});
  };
}

async function liveScan(cabal, { live = true } = {}) {
  const proj = mkdtempSync(join(tmpdir(), 'agsec-livescan-proj-'));
  writeFileSync(join(proj, 'app.cabal'), cabal);
  writeFileSync(join(proj, 'Main.hs'), 'module Main where\nmain :: IO ()\nmain = putStrLn "hi"\n');
  const xdg = mkdtempSync(join(tmpdir(), 'agsec-livescan-xdg-'));
  const saved = { fetch: globalThis.fetch, xdg: process.env.XDG_CONFIG_HOME, live: process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE, off: process.env.AGENTIC_SECURITY_OFFLINE };
  process.env.XDG_CONFIG_HOME = xdg;
  delete process.env.AGENTIC_SECURITY_OFFLINE;
  if (live) process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE = '1'; else delete process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE;
  globalThis.fetch = fakeFetch();
  try { return (await runScan(proj, {})).scan; } finally {
    globalThis.fetch = saved.fetch;
    for (const [k, v] of [['XDG_CONFIG_HOME', saved.xdg], ['AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE', saved.live], ['AGENTIC_SECURITY_OFFLINE', saved.off]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

const CABAL = (range) => `cabal-version: 2.4\nname: app\nversion: 0.1\nbuild-type: Simple\nexecutable app\n  main-is: Main.hs\n  default-language: Haskell2010\n  build-depends: base >=4 && <5, aeson ${range}\n`;

test('[live-feed-scan] a scan that queried the feed reports hackage-live as selected and ran; one that did not reports not_selected', async () => {
  const on = await liveScan(CABAL('>=1.0 && <3'), { live: true });
  const m = on.scanHealth.languageCoverage.optionalModes['hackage-live'];
  assert.equal(m.selected, true, JSON.stringify(m));
  assert.equal(m.ran, true, JSON.stringify(m));
  const off = await liveScan(CABAL('>=1.0 && <3'), { live: false });
  const o = off.scanHealth.languageCoverage.optionalModes['hackage-live'];
  assert.equal(o.selected, false, JSON.stringify(o));
  assert.equal(o.status, 'not_selected');
});

test('[live-feed-scan] the finding keeps its match status, reason and declared range (possibly-affected is not affected)', async () => {
  const scan = await liveScan(CABAL('>=1.0 && <3'));
  const hk = normalizeFindings(scan).filter((f) => f.ecosystem === 'hackage' && f.package === 'aeson');
  assert.ok(hk.length > 0, 'the declared aeson range overlaps a real aeson advisory');
  for (const f of hk) {
    assert.ok(['affected', 'possibly-affected'].includes(f.matchStatus), `matchStatus kept on ${f.osvId}: ${f.matchStatus}`);
    assert.equal(typeof f.matchReason, 'string');
    assert.equal(f.declaredRange, '>=1.0 && <3');
  }
  assert.ok(hk.some((f) => f.matchStatus === 'possibly-affected'), 'a range that also admits fixed versions is possibly-affected, and says so');
});

test('[live-feed-scan] liveFeedOptionalState maps every refresh outcome without inventing success', () => {
  assert.deepEqual(liveFeedOptionalState({}, null), { selected: false });
  const sel = { AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE: '1' };
  assert.equal(liveFeedOptionalState(sel, null).result, undefined, 'selected but no refresh happened: no result, so the mode is "did not run"');
  assert.equal(liveFeedOptionalState(sel, { status: 'refreshed' }).result.status, 'ok');
  assert.equal(liveFeedOptionalState(sel, { status: 'current' }).result.status, 'ok');
  assert.equal(liveFeedOptionalState(sel, { status: 'partial', detail: 'x' }).result.status, 'partial');
  assert.equal(liveFeedOptionalState(sel, { status: 'failed', detail: 'x' }).result.status, 'failed');
  assert.equal(liveFeedOptionalState(sel, { status: 'offline', detail: 'x' }).result.ran, false);
});

// Found by the live run: 148 of ~500 advisory rows were `unknown` ("neither a resolved version nor a declared range is known") because a
// dependency declared with no bound at all (`build-depends: aeson`) was carried as "no range". In Cabal that means ANY version, which
// overlaps an advisory exactly as `>=0` does.
test('[live-feed-scan] a dependency declared with no version bound is any-version: possibly-affected, not unknown', () => {
  const files = { 'app.cabal': 'name: app\nversion: 1\nlibrary\n  build-depends: aeson, text >=2 && <3\n' };
  const comps = hackageComponents(files).components;
  const aeson = comps.find((c) => c.name === 'aeson');
  assert.equal(aeson.unbounded, true);
  assert.equal(comps.find((c) => c.name === 'text').unbounded, false, 'a bounded dependency is not unbounded');
  const db = new AdvisoryDb({ records: REAL, source: 'pinned-fixture', generatedAt: '2026-10-01T00:00:00Z', now: Date.parse('2026-10-03T00:00:00Z') });
  const f = evaluateComponents([aeson], db).findings.find((x) => x.osvId === 'HSEC-2023-0001');
  assert.equal(f.matchStatus, 'possibly-affected', 'introduced 0.4.0.0, fixed 2.0.1.0: an unconstrained dependency may or may not resolve into it');
  assert.equal(f.resolution, 'declared-unbounded');
  // the opposite direction: a component with neither a bound nor an unbounded declaration (nothing known) stays unknown
  const none = evaluateComponents([{ name: 'aeson' }], db).statuses.find((x) => x.advisory === 'HSEC-2023-0001');
  assert.equal(none.status, 'unknown');
  // and a resolved version still wins over the unbounded declaration
  const resolved = evaluateComponents([{ ...aeson, version: '2.1.0.0' }], db).statuses.find((x) => x.advisory === 'HSEC-2023-0001');
  assert.equal(resolved.status, 'not-affected');
});

// Found by the live run: with --no-network AND with AGENTIC_SECURITY_OFFLINE=1, a scan of a project that vendors a JavaScript library (hledger-web
// ships jquery) still made real requests to registry.npmjs.org (and pypi.org, crates.io, search.maven.org for other manifests). The OSV lookups
// honoured offline mode; the registry-metadata lookups did not.
test('[live-feed-scan] offline mode makes no registry-metadata request (npm, PyPI, crates.io, Maven)', async () => {
  const comps = [{ ecosystem: 'npm', name: 'jquery', version: '3.0.0' }, { ecosystem: 'pypi', name: 'requests', version: '2.0.0' }, { ecosystem: 'cargo', name: 'serde', version: '1.0.0' }, { ecosystem: 'maven', name: 'x', group: 'g', version: '1' }];
  const saved = { fetch: globalThis.fetch, off: process.env.AGENTIC_SECURITY_OFFLINE };
  const urls = [];
  globalThis.fetch = async (u) => { urls.push(String(u)); return { ok: false, status: 404, json: async () => ({}), text: async () => '' }; };
  try {
    process.env.AGENTIC_SECURITY_OFFLINE = '1';
    const info = await queryRegistries(comps);
    assert.deepEqual(urls, [], `offline must not touch the network: ${urls.join(', ')}`);
    assert.equal(info.size, 0);
    delete process.env.AGENTIC_SECURITY_OFFLINE;
    await queryRegistries(comps);
    assert.ok(urls.some((u) => u.startsWith('https://registry.npmjs.org/')), 'online, the lookup still happens (the test would otherwise prove nothing)');
  } finally {
    globalThis.fetch = saved.fetch;
    if (saved.off === undefined) delete process.env.AGENTIC_SECURITY_OFFLINE; else process.env.AGENTIC_SECURITY_OFFLINE = saved.off;
  }
});
