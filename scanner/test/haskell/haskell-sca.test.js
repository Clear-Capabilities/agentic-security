// HS-009: Hackage advisories, reachability and license/supply-chain policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash, generateKeyPairSync, createSign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  AdvisoryDb, normalizeAdvisory, evaluateComponents, matchComponent, rangeToIntervals, osvWireQuery, hackagePurl,
  loadAdvisorySnapshot, buildSnapshot, snapshotBody, reachability, nearNameCandidates, sourceIntegrity, lifecycle, licensePolicy,
} from '../../src/language/haskell-sca.js';
import { analyzeHaskellSupply, collectUsage } from '../../src/language/haskell-supply.js';
import { analyzeHaskellManifests } from '../../src/language/haskell-manifests.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'hackage-advisories');
const FILES = readdirSync(join(DIR, 'records')).filter((f) => f.endsWith('.json')).sort();
const RECORDS = FILES.map((f) => JSON.parse(readFileSync(join(DIR, 'records', f), 'utf8')));
const NOW = Date.parse('2026-10-03T00:00:00Z');
const db = (extra = [], o = {}) => new AdvisoryDb({ records: [...RECORDS, ...extra], source: 'pinned-fixture', generatedAt: '2026-10-01T00:00:00Z', now: NOW, ...o });
const hits = (name, version, declaredRange, d = db()) => evaluateComponents([{ name, version, declaredRange }], d).findings;
const ids = (fs) => fs.map((f) => f.osvId).sort();

test('[HS-009.AC01] the pinned records are the real, unmodified OSV files (sha256 matches provenance)', () => {
  const prov = JSON.parse(readFileSync(join(DIR, 'provenance.json'), 'utf8'));
  assert.ok(FILES.length >= 15);
  for (const f of FILES) {
    const want = (prov.files || prov.records || {})[f] ?? (prov.files || prov.records || {})[f.replace(/\.json$/, '')];
    const sha = createHash('sha256').update(readFileSync(join(DIR, 'records', f))).digest('hex');
    assert.equal(typeof want === 'object' ? want.sha256 : want, sha, f);
  }
});

test('[HS-009.AC01] xml-conduit HSEC-2023-0004: affected below the fix, fixed version and pre-introduction do not match', () => {
  assert.deepEqual(ids(hits('xml-conduit', '1.9.0.0')), ['HSEC-2023-0004']);
  assert.deepEqual(ids(hits('xml-conduit', '0.5.0')), ['HSEC-2023-0004']);   // introduced boundary inclusive
  assert.deepEqual(ids(hits('xml-conduit', '1.9.1.0')), []);                 // fixed boundary exclusive
  assert.deepEqual(ids(hits('xml-conduit', '1.9.1')), []);                   // 1.9.1 == 1.9.1.0 in PVP ordering
  assert.deepEqual(ids(hits('xml-conduit', '0.4.9')), []);                   // before introduced
  assert.deepEqual(ids(hits('xml-conduit', '2.0.0.0')), []);
});

test('[HS-009.AC01] the wire query and purl use the exact Hackage ecosystem, and ranges use PVP ordering not SemVer', () => {
  assert.deepEqual(osvWireQuery('xml-conduit', '1.9.0.0'), { package: { name: 'xml-conduit', ecosystem: 'Hackage' }, version: '1.9.0.0' });
  assert.equal(hackagePurl('xml-conduit', '1.9.0.0'), 'pkg:hackage/xml-conduit@1.9.0.0');
  assert.deepEqual(ids(hits('xml-conduit', '1.10.0.0')), []);                // 1.10 > 1.9 numerically, not lexically
  assert.deepEqual(ids(hits('xml-conduit', '1.9.0.0.5')), ['HSEC-2023-0004']); // five components
});

test('[HS-009.AC01] aliases are deduplicated and the HSEC id is preserved with its CVE/GHSA aliases', () => {
  const withAlias = RECORDS.filter((r) => (r.aliases || []).some((a) => /^(CVE|GHSA)-/.test(a)));
  assert.ok(withAlias.length >= 3);
  const f = hits('xml-conduit', '1.9.0.0')[0];
  assert.match(f.osvId, /^HSEC-/);
  assert.equal(new Set(f.ids).size, f.ids.length);
  const twin = { ...RECORDS.find((r) => r.id === 'HSEC-2023-0004'), id: 'GHSA-xxxx-xxxx-xxxx', aliases: ['HSEC-2023-0004'] };
  const out = hits('xml-conduit', '1.9.0.0', null, db([twin]));
  assert.equal(out.length, 2, 'two records, same package: both listed, each with its own id and aliases');
  for (const r of out) assert.ok(r.ids.includes('HSEC-2023-0004'));
});

test('[HS-009.AC01] unfixed ranges stay affected for every later version (no invented fix)', () => {
  const unfixed = RECORDS.flatMap(normalizeAdvisory === undefined ? [] : (r) => normalizeAdvisory(r).affected.filter((a) => a.unfixed).map((a) => ({ id: r.id, name: a.name })));
  assert.ok(unfixed.length >= 1, 'the pinned corpus contains at least one unfixed range');
  const u = unfixed[0];
  assert.ok(hits(u.name, '99.0.0.0').some((f) => f.osvId === u.id && f.unfixed));
});

test('[HS-009.AC01] detector input is the record alone: renaming ids or stripping metadata cannot change a verdict', () => {
  const stripped = RECORDS.map((r) => ({ ...r, summary: 'x', details: 'x', database_specific: {}, references: [] }));
  const a = ids(hits('xml-conduit', '1.9.0.0'));
  const b = ids(evaluateComponents([{ name: 'xml-conduit', version: '1.9.0.0' }], new AdvisoryDb({ records: stripped, generatedAt: '2026-10-01T00:00:00Z', now: NOW })).findings);
  assert.deepEqual(a, b);
  assert.ok(!readFileSync(fileURLToPath(new URL('../../src/language/haskell-sca.js', import.meta.url)), 'utf8').includes('HSEC-2023-0004'));
});

test('[HS-009.AC01] a hash-pinned snapshot is accepted; a tampered record, wrong pin or bad signature is refused', () => {
  const snap = buildSnapshot(RECORDS, '2026-10-01T00:00:00Z');
  const ok = loadAdvisorySnapshot(snap, { pinnedSha256: createHash('sha256').update(snapshotBody(snap)).digest('hex'), now: NOW });
  assert.equal(ok.ok, true);
  assert.equal(ok.db.integrity.hashPinned, true);
  const tampered = JSON.parse(JSON.stringify(snap)); tampered.records[0].summary += '!';
  assert.equal(loadAdvisorySnapshot(tampered).ok, false);
  assert.equal(loadAdvisorySnapshot(snap, { pinnedSha256: '0'.repeat(64) }).ok, false);
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const sg = createSign('sha256'); sg.update(snapshotBody(snap));
  const sig = sg.sign(privateKey).toString('base64');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  assert.equal(loadAdvisorySnapshot(snap, { signature: sig, publicKeyPem: pem, now: NOW }).db.integrity.signed, true);
  assert.equal(loadAdvisorySnapshot(snap, { signature: Buffer.from('bad').toString('base64'), publicKeyPem: pem }).ok, false);
  assert.equal(loadAdvisorySnapshot(snap, { signature: sig }).ok, false);
});

test('[HS-009.AC02] a resolved call through a qualified, aliased or selective import is reachable', () => {
  const u = collectUsage({
    'A.hs': 'module A where\nimport qualified Text.XML as X\nmain = X.readFile X.def "a"\n',
    'B.hs': 'module B where\nimport Data.Aeson (decode)\nf x = decode x\n',
  });
  assert.equal(reachability('xml-conduit', u.imports, u.callees, ['Text.XML.readFile']).function, 'reachable');
  assert.equal(reachability('aeson', u.imports, u.callees, ['Data.Aeson.decode']).function, 'reachable');
  assert.equal(reachability('xml-conduit', u.imports, u.callees, ['Text.XML.readFile']).import, 'imported');
});

test('[HS-009.AC02] an import with no resolved call, or a package with no module mapping, stays unknown, never unreachable', () => {
  const u = collectUsage({ 'A.hs': 'module A where\nimport qualified Text.XML as X\nmain = pure ()\n' });
  const r = reachability('xml-conduit', u.imports, u.callees, ['Text.XML.parseLBS']);
  assert.equal(r.import, 'imported');
  assert.equal(r.function, 'unknown');
  assert.equal(reachability('xml-conduit', u.imports, u.callees, null).function, 'unknown');
  const nomap = reachability('some-unmodelled-pkg', u.imports, u.callees, ['X.y']);
  assert.equal(nomap.import, 'unknown');
  assert.equal(nomap.function, 'unknown');
  assert.equal(reachability('aeson', u.imports, u.callees, ['Data.Aeson.decode']).import, 'not-imported');
});

test('[HS-009.AC02] an end-to-end project finding carries its reachability tier', () => {
  const files = {
    'a.cabal': 'name: a\nversion: 0.1\nbuild-type: Simple\nlibrary\n  build-depends: base, xml-conduit\n',
    'cabal.project.freeze': 'constraints: any.xml-conduit ==1.9.0.0\n',
    'A.hs': 'module A where\nimport qualified Text.XML as X\nmain = X.readFile X.def "a"\n',
  };
  const r = analyzeHaskellSupply(files, { db: db(), symbols: { 'HSEC-2023-0004': ['Text.XML.readFile'] } });
  const f = r.supplyChain.find((x) => x.osvId === 'HSEC-2023-0004');
  assert.ok(f);
  assert.equal(f.version, '1.9.0.0');
  assert.equal(f.reachabilityTier, 'function-reachable');
  const r2 = analyzeHaskellSupply({ ...files, 'A.hs': 'module A where\nmain = pure ()\n' }, { db: db() });
  assert.equal(r2.supplyChain.find((x) => x.osvId === 'HSEC-2023-0004').reachabilityTier, 'not-imported');
});

test('[HS-009.AC03] an advisory with no CVE alias is still reported; KEV/EPSS are unknown, not zero', () => {
  const noCve = RECORDS.find((r) => !(r.aliases || []).some((a) => /^CVE-/.test(a)) && r.affected.some((a) => a.package.name !== 'base'));
  assert.ok(noCve, 'the corpus has an advisory without a CVE alias');
  const name = noCve.affected.find((a) => a.package.name !== 'base').package.name;
  const f = evaluateComponents([{ name, version: null, declaredRange: '>=0' }], db()).findings.find((x) => x.osvId === noCve.id);
  assert.ok(f);
  assert.equal(f.kev, 'not-applicable');
  assert.equal(f.epss, 'unknown');
  const cve = hits('xml-conduit', '1.9.0.0')[0];
  if (cve.cveAliases.length) assert.equal(cve.kev, 'unknown');                // no KEV data supplied
  const withKev = evaluateComponents([{ name: 'xml-conduit', version: '1.9.0.0' }], db(), { kev: new Set(cve.cveAliases), epss: Object.fromEntries(cve.cveAliases.map((c) => [c, 0.42])) }).findings[0];
  if (cve.cveAliases.length) { assert.equal(withKev.kev, true); assert.equal(withKev.epss, 0.42); }
});

test('[HS-009.AC03] a withdrawn advisory is listed as withdrawn and never matched', () => {
  const derived = { ...RECORDS.find((r) => r.id === 'HSEC-2023-0004'), id: 'HSEC-9999-0001', aliases: [], withdrawn: '2026-01-01T00:00:00Z' }; // derived record, labeled: none of the real records is withdrawn
  const r = evaluateComponents([{ name: 'xml-conduit', version: '1.9.0.0' }], db([derived]));
  assert.ok(!r.findings.some((f) => f.osvId === 'HSEC-9999-0001'));
  assert.ok(r.statuses.some((s) => s.advisory === 'HSEC-9999-0001' && s.status === 'withdrawn'));
});

test('[HS-009.AC03] a missing feed and a stale cache are reported as such, never as clean', () => {
  const none = evaluateComponents([{ name: 'xml-conduit', version: '1.9.0.0' }], null);
  assert.equal(none.feed.status, 'feed-unavailable');
  assert.equal(none.findings.length, 0);
  assert.equal(none.statuses[0].status, 'feed-unavailable');
  const stale = evaluateComponents([{ name: 'xml-conduit', version: '1.9.0.0' }], db([], { generatedAt: '2025-01-01T00:00:00Z' }));
  assert.equal(stale.feed.status, 'stale-cache');
  assert.equal(stale.findings.length, 1, 'a stale feed still matches, but says it is stale');
  assert.equal(stale.findings[0].dataSource.feedStatus, 'stale-cache');
  const r = analyzeHaskellSupply({ 'a.cabal': 'name: a\nversion: 0.1\nlibrary\n  build-depends: xml-conduit\n' }, { db: null });
  assert.ok(r.gaps.some((g) => g.kind === 'advisory-feed-unavailable' && /not a clean result/.test(g.detail)));
});

test('[HS-009.AC03] a GHC-component advisory is attributed to the compiler, with a compiler remediation', () => {
  const f = hits('base', '4.15.0.0');
  assert.ok(f.length >= 1);
  for (const x of f) { assert.equal(x.ghcComponent, true); assert.match(x.remediation, /GHC/); }
  assert.equal(hits('xml-conduit', '1.9.0.0')[0].ghcComponent, false);
});

test('[HS-009.AC03] a declared range alone is possibly-affected, and the version is flagged unresolved', () => {
  const f = hits('xml-conduit', null, '>=1.8 && <2')[0];
  assert.equal(f.matchStatus, 'possibly-affected');
  assert.equal(f.resolution, 'declared-range');
  assert.ok(f.uncertainty.length);
  assert.equal(hits('xml-conduit', null, '>=1.9.1.0').length, 0);
  assert.equal(matchComponent(normalizeAdvisory(RECORDS[0]).affected[0], { name: 'x' }).status, 'unknown');
  assert.equal(rangeToIntervals('>>> nonsense'), null);
});

test('[HS-009.AC03] source-repository dependencies: a floating ref is a finding, a full commit is not', () => {
  const m = analyzeHaskellManifests([{ path: 'cabal.project', text: 'packages: .\nsource-repository-package\n  type: git\n  location: https://github.com/x/y\n  tag: main\nsource-repository-package\n  type: git\n  location: https://github.com/x/z\n  tag: 0123456789abcdef0123456789abcdef01234567\n' }]);
  const si = sourceIntegrity(m);
  assert.equal(si.find((s) => s.location.endsWith('/y')).finding, true);
  assert.equal(si.find((s) => s.location.endsWith('/z')).finding, false);
});

test('[HS-009.AC04] license policy: denied, allowed and unknown stay distinct', () => {
  const comps = [{ name: 'a', version: '1' }, { name: 'b', version: '1' }, { name: 'c', version: '1' }];
  const md = { a: { license: 'GPL-3.0-only' }, b: { license: 'BSD-3-Clause' } };
  const r = licensePolicy(comps, md);
  assert.deepEqual(r.map((x) => x.status), ['denied', 'allowed', 'unknown']);
  assert.equal(licensePolicy(comps, md, { deny: [], allow: ['MIT'] })[1].status, 'not-allowed');
});

test('[HS-009.AC04] lifecycle: deprecated is known only from supplied metadata; otherwise unknown', () => {
  const r = lifecycle([{ name: 'a' }, { name: 'b' }], { a: { deprecated: true, supersededBy: 'a2' } });
  assert.equal(r[0].status, 'deprecated');
  assert.equal(r[0].supersededBy, 'a2');
  assert.equal(r[1].status, 'unknown');
  assert.equal(lifecycle([{ name: 'a' }], null)[0].status, 'unknown');
});

test('[HS-009.AC04] near-name packages are candidates only: unknown without registry evidence, never malicious', () => {
  const c = nearNameCandidates([{ name: 'aesom' }, { name: 'aeson' }, { name: 'my-own-lib' }]);
  assert.equal(c.length, 1);
  assert.equal(c[0].similarTo, 'aeson');
  assert.equal(c[0].status, 'unknown');
  assert.equal(c[0].malicious, false);
  assert.equal(c[0].verdict, 'candidate');
  const withReg = nearNameCandidates([{ name: 'aesom' }], { registry: { aesom: { exists: true, maintainers: ['x'] } } });
  assert.equal(withReg[0].status, 'registered-package-near-name');
  assert.equal(withReg[0].malicious, false);
});

test('[HS-009.AC04] project findings carry data-source, target and scope provenance, and the engine bucket receives them', () => {
  const files = {
    'a.cabal': 'name: a\nversion: 0.1\nbuild-type: Simple\nlibrary\n  build-depends: base, xml-conduit\ntest-suite t\n  type: exitcode-stdio-1.0\n  main-is: T.hs\n  build-depends: base, xml-conduit\n',
    'cabal.project.freeze': 'constraints: any.xml-conduit ==1.9.0.0\n',
    'cabal.project': 'packages: .\nsource-repository-package\n  type: git\n  location: https://github.com/x/y\n  tag: main\n',
  };
  const r = analyzeHaskellSupply(files, { db: db() });
  const vs = r.supplyChain.filter((x) => x.osvId === 'HSEC-2023-0004');
  assert.ok(vs.length >= 1);
  for (const v of vs) {
    assert.equal(v.ecosystem, 'hackage');
    assert.equal(v.purl, 'pkg:hackage/xml-conduit@1.9.0.0');
    assert.equal(v.dataSource.feed, 'pinned-fixture');
    assert.ok(v.target && v.scope);
    assert.equal(v.file, 'a.cabal');
    assert.ok(Number.isInteger(v.line));
  }
  assert.ok(r.supplyChain.some((x) => x.type === 'source_integrity' && x.file === 'cabal.project'));
  assert.ok(r.components.every((c) => c.ecosystem === 'hackage'));
});
