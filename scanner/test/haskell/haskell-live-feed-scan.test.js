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
import { mkTestTmp } from '../helpers/tmp.js';

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
  const proj = mkTestTmp('agsec-livescan-proj-');
  writeFileSync(join(proj, 'app.cabal'), cabal);
  writeFileSync(join(proj, 'Main.hs'), 'module Main where\nmain :: IO ()\nmain = putStrLn "hi"\n');
  const xdg = mkTestTmp('agsec-livescan-xdg-');
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

// Found by adjudicating the live run: ShellCheck's only freeze file is builders/linux.armv6hf/cabal.project.freeze, a freeze for one release
// builder. It was applied to the ROOT ShellCheck.cabal, so "aeson 2.2.3.0" was reported as the resolved version (status `affected`) of a
// package whose own manifest only declares a range (it should be `possibly-affected`). A freeze or lock file resolves the manifests at or below
// its own directory, not every manifest in the repository.
test('[live-feed-scan] a freeze file resolves only manifests at or below its own directory', () => {
  const cabal = (name) => `name: ${name}\nversion: 1\nlibrary\n  build-depends: base, aeson >=1 && <3\n`;
  const freeze = 'constraints: any.aeson ==2.2.3.0\n';
  const ver = (files, manifest) => hackageComponents(files).components.find((c) => c.name === 'aeson' && c.manifest === manifest).version;
  assert.equal(ver({ 'Root.cabal': cabal('root'), 'builders/arm/cabal.project.freeze': freeze }, 'Root.cabal'), null, 'a builder-specific freeze in a subdirectory does not resolve the root package');
  assert.equal(ver({ 'cabal.project.freeze': freeze, 'pkg/a.cabal': cabal('a') }, 'pkg/a.cabal'), '2.2.3.0', 'a root freeze resolves a package below it');
  assert.equal(ver({ 'server/cabal.project.freeze': freeze, 'server/s.cabal': cabal('s') }, 'server/s.cabal'), '2.2.3.0', 'a freeze next to the manifest resolves it');
  assert.equal(ver({ 'server/cabal.project.freeze': freeze, 'client/c.cabal': cabal('c') }, 'client/c.cabal'), null, 'a sibling directory is not covered');
  const near = ver({ 'cabal.project.freeze': 'constraints: any.aeson ==1.0.0.0\n', 'server/cabal.project.freeze': freeze, 'server/s.cabal': cabal('s') }, 'server/s.cabal');
  assert.equal(near, '2.2.3.0', 'the nearest enclosing freeze wins');
});

// Found by adjudicating the live run: a package's test suite that lists `aeson` with no bound, next to a library that bounds it to a fixed range,
// raised a possibly-affected finding for a version the solver can never pick (7 of 273 package/advisory groups in the corpus). Cabal chooses ONE
// version of a package for every component of a .cabal file, so an unbounded use inherits the unconditional bounds its siblings declare.
test('[live-feed-scan] an unbounded use inherits the unconditional bounds the same manifest declares elsewhere', () => {
  const comps = (cabal) => hackageComponents({ 'app.cabal': cabal }).components.filter((c) => c.name === 'aeson');
  const safe = comps('name: app\nversion: 1\nlibrary\n  build-depends: base, aeson >=2.2.5.1 && <3\ntest-suite t\n  type: exitcode-stdio-1.0\n  main-is: M.hs\n  build-depends: base, aeson\n');
  assert.ok(safe.every((c) => c.declaredRange === '>=2.2.5.1 && <3' && !c.unbounded), JSON.stringify(safe.map((c) => [c.scope, c.declaredRange, c.unbounded])));
  const db = new AdvisoryDb({ records: REAL, source: 'pinned-fixture', generatedAt: '2026-10-01T00:00:00Z', now: Date.parse('2026-10-03T00:00:00Z') });
  const f = evaluateComponents(safe, db).findings.filter((x) => x.osvId === 'HSEC-2026-0007');
  assert.equal(f.length, 0, 'every use is bounded to a fixed range: nothing to report');
  // a conditional sibling is not in force everywhere, so it is NOT inherited
  const cond = comps('name: app\nversion: 1\nflag f\n  default: False\nlibrary\n  if flag(f)\n    build-depends: base, aeson\n  else\n    build-depends: base, aeson >=2.2.5.1\n');
  assert.ok(cond.some((c) => c.unbounded), 'the unbounded branch keeps its meaning');
  // a bound declared in a DIFFERENT manifest is not inherited either
  const other = hackageComponents({ 'a/a.cabal': 'name: a\nversion: 1\nlibrary\n  build-depends: base, aeson >=2.2.5.1\n', 'b/b.cabal': 'name: b\nversion: 1\ntest-suite t\n  type: exitcode-stdio-1.0\n  main-is: M.hs\n  build-depends: base, aeson\n' }).components.filter((c) => c.name === 'aeson');
  assert.ok(other.some((c) => c.unbounded && c.manifest === 'b/b.cabal'));
});

// Found by the live run: scanning aeson-2.3.2.0 itself reported its own test suite's `build-depends: aeson` against the aeson advisories, and
// cabal-install's tree reported `cabal-install`. A dependency on a package this project DEFINES is the workspace package, not a Hackage
// dependency, and an advisory about the project's own (fixed) version is not a finding about a dependency.
test('[live-feed-scan] a dependency on a package the project itself defines is not a Hackage dependency', () => {
  const files = {
    'aeson.cabal': 'name: aeson\nversion: 2.3.2.0\nlibrary\n  build-depends: base, text\ntest-suite t\n  type: exitcode-stdio-1.0\n  main-is: M.hs\n  build-depends: aeson, text\n',
    'sub/package.yaml': 'name: sub\nversion: 1\ndependencies:\n- base\n- aeson\n- sub-extra\nlibrary:\n  source-dirs: src\n',
    'sub-extra/sub-extra.cabal': 'name: sub-extra\nversion: 1\nlibrary\n  build-depends: base\n',
  };
  const names = hackageComponents(files).components.map((c) => c.name);
  assert.ok(!names.includes('aeson'), 'aeson is defined by this project');
  assert.ok(!names.includes('sub-extra'), 'sub-extra is defined by this project');
  assert.ok(names.includes('text') && names.includes('base'), 'real third-party dependencies are kept');
  // the opposite direction: the same dependency in a project that does NOT define it is still a dependency
  const other = hackageComponents({ 'app.cabal': 'name: app\nversion: 1\nlibrary\n  build-depends: base, aeson\n' }).components.map((c) => c.name);
  assert.ok(other.includes('aeson'));
});
