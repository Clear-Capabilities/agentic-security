// NIX-009: Patch-aware Nix vulnerability matching and reachability.
// Suite "nix-sca-patches" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Closures are built through the real NIX-008 importer from format-faithful `nix path-info` /
// `nix derivation show` data. Advisory records are SYNTHETIC OSV-style records (ids SYN-*, CVE-2099-*) for the
// non-Hackage cases; the Haskell cases use the real pinned HSEC records of HS-009.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importNixClosure } from '../../src/language/nix-closure.js';
import { matchNixVulnerabilities, NixAdvisoryData, isNotAnUpstreamVersion, compareUpstream, overlayEvidence, upstreamIdentity } from '../../src/language/nix-sca.js';
import { AdvisoryDb } from '../../src/language/haskell-sca.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, '..', 'fixtures');
const OVERLAY = readFileSync(join(FIX, 'nix-sca', 'overlay.nix'), 'utf8');
const HSEC = readdirSync(join(FIX, 'hackage-advisories', 'records')).map((f) => JSON.parse(readFileSync(join(FIX, 'hackage-advisories', 'records', f), 'utf8')));
const NOW = Date.parse('2026-10-03T00:00:00Z');
const A = '0123456789abcdfghijklmnpqrsvwxyz';
const hh = (i) => { let s = ''; let x = i * 2654435761 % 4294967296; for (let j = 0; j < 32; j++) { s += A[x % 32]; x = (Math.floor(x / 32) + j * 11 + i) % 4294967296; } return s; };
const out = (i, n) => `/nix/store/${hh(i)}-${n}`;
const drv = (i, n) => `/nix/store/${hh(i + 500)}-${n}.drv`;

/** Build a closure for the app plus the given component specs, through the real importer. */
function closureOf(specs) {
  const app = { path: out(1, 'app-1.0'), drv: drv(1, 'app-1.0') };
  const pathinfo = {}; const drvs = {};
  const runtime = []; const buildOnly = [];
  specs.forEach((s, k) => {
    const i = 10 + k;
    s.path = out(i, `${s.pname}-${s.version}`); s.drv = drv(i, `${s.pname}-${s.version}`);
    (s.runtime === false ? buildOnly : runtime).push(s);
    drvs[s.drv] = { outputs: { out: { path: s.path } }, inputSrcs: [], inputDrvs: {}, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: `${s.pname}-${s.version}`, pname: s.pname, version: s.version, out: s.path, outputs: 'out', ...(s.patches ? { patches: s.patches.map((p) => out(900 + p.length, p)).join(' ') } : {}), ...(s.urls ? { urls: s.urls } : {}), ...(s.rev ? { rev: s.rev } : {}), ...(s.env || {}) } };
    if (s.runtime !== false) pathinfo[s.path] = { narHash: 'sha256-x', narSize: 1, references: [], deriver: s.drv };   // a recursive path-info of the target holds only its runtime closure
  });
  pathinfo[app.path] = { narHash: 'sha256-x', narSize: 1, references: [app.path, ...runtime.map((s) => s.path)], deriver: app.drv };
  drvs[app.drv] = { outputs: { out: { path: app.path } }, inputSrcs: [], inputDrvs: Object.fromEntries(specs.map((s) => [s.drv, ['out']])), system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: 'app-1.0', pname: 'app', version: '1.0', out: app.path, buildInputs: runtime.map((s) => s.path).join(' '), nativeBuildInputs: buildOnly.map((s) => s.path).join(' ') } };
  const prov = (cmd) => ({ tool: 'nix', command: cmd, target: { system: 'x86_64-linux', installable: '.#app' }, revision: {}, flakeLockSha256: 'a'.repeat(64), generatedAt: '2026-10-01T00:00:00Z' });
  const c = importNixClosure({ exports: [{ schema: 'nix-path-info-json', data: pathinfo, provenance: prov('nix path-info --json --recursive .#app') }, { schema: 'nix-derivation-show-json', data: drvs, provenance: prov('nix derivation show --recursive .#app') }], expected: { system: 'x86_64-linux', installable: '.#app', flakeLockSha256: 'a'.repeat(64) }, now: NOW });
  const drvEnv = Object.fromEntries(Object.entries(drvs).map(([k, v]) => [k, v.env]));
  return { closure: c, drvEnv };
}

const SYN = (id, aliases, affected, extra = {}) => ({ id, aliases, summary: `synthetic ${id}`, published: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z', affected, ...extra });
const CURL_PURL = 'pkg:github/curl/curl';
const CURL_URL = 'https://github.com/curl/curl/releases/download/curl-8_7_1/curl-8.7.1.tar.xz';
const curlAdv = (extra = {}) => SYN('SYN-CURL-0001', ['CVE-2099-0001', 'GHSA-xxxx-xxxx-xxxx'], [{ package: { ecosystem: 'GitHub', name: 'curl', purl: CURL_PURL }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '8.0.0' }, { fixed: '8.8.0' }] }], ...(extra.aff || {}) }], extra.rec || {});
const data = (records, opts = {}) => new NixAdvisoryData({ records, source: 'pinned-fixture', generatedAt: '2026-10-01T00:00:00Z', now: NOW, ...opts });
const run = (specs, d, extra = {}) => { const { closure, drvEnv } = closureOf(specs); return matchNixVulnerabilities({ closure, drvEnv, data: d, ...extra }); };
const stat = (r, name) => r.findings.filter((f) => f.name === name).map((f) => f.status);
const curl = (over = {}) => ({ pname: 'curl', version: '8.7.1', urls: CURL_URL, ...over });

test('[NIX-009.AC01] a vulnerable upstream version is affected and a fixed version is fixed, by upstream identity', () => {
  const r = run([curl()], data([curlAdv()]));
  assert.deepEqual(stat(r, 'curl'), ['affected']);
  const f = r.findings[0];
  assert.deepEqual(f.ids.sort(), ['CVE-2099-0001', 'GHSA-xxxx-xxxx-xxxx', 'SYN-CURL-0001']);
  assert.equal(f.dataSource.identityAuthority, 'src-derived'); assert.equal(f.dataSource.identityBasis, 'source URL host github');
  assert.deepEqual(f.fixedIn, ['8.8.0']);
  assert.equal(f.nixBuild.system, 'x86_64-linux'); assert.ok(/-curl-8\.7\.1\.drv$/.test(f.nixBuild.derivation));
  const fixed = run([curl({ version: '8.8.0', urls: CURL_URL.replace('8.7.1', '8.8.0') })], data([curlAdv()]));
  assert.deepEqual(stat(fixed, 'curl'), ['fixed']);
  assert.equal(fixed.findings[0].severity, 'info');
  const before = run([curl({ version: '7.9.0' })], data([curlAdv()]));
  assert.deepEqual(before.findings, [], 'before the introduced version: not affected, no finding');
  assert.equal(before.statuses[0].status, 'not-affected'); assert.equal(before.statuses[0].identityMapped, true);
});

test('[NIX-009.AC01] a verified backport needs a patch whose content hash the advisory lists; a CVE-named patch alone does not', () => {
  const fixHash = 'sha256-FIXPATCHHASHFIXPATCHHASHFIXPATCHHASHFIXPATCHH=';
  const adv = curlAdv({ aff: { database_specific: { fix_patches: [{ name: 'curl-fix.patch', sha256: fixHash }] } } });
  const ov = overlayEvidence({ 'overlay.nix': OVERLAY });
  assert.deepEqual(Object.keys(ov).sort(), ['curl-backport', 'curl-bump', 'curl-claim']);
  assert.equal(ov['curl-backport'].patches[0].source, 'fetchpatch');
  assert.equal(ov['curl-backport'].patches[0].sha256, fixHash.replace('sha256-', '').toLowerCase());
  const verified = run([curl({ pname: 'curl-backport' })], data([{ ...adv, affected: [{ ...adv.affected[0], package: { ...adv.affected[0].package, name: 'curl-backport' } }] }]), { overlays: { 'curl-backport': ov['curl-backport'] } });
  assert.deepEqual(stat(verified, 'curl-backport'), ['backported-verified']);
  assert.equal(verified.findings[0].patchEvidence.verified.by, 'content hash matches an advisory fix patch');
  assert.equal(verified.findings[0].severity, 'info');
  // unverified: a derivation patch NAMED after the CVE, no content hash
  const claim = run([curl({ patches: ['CVE-2099-0001.patch'] })], data([curlAdv()]));
  assert.deepEqual(stat(claim, 'curl'), ['possibly-affected']);
  assert.equal(claim.findings[0].patchEvidence.verified, null);
  assert.equal(claim.findings[0].patchEvidence.claims[0].verified, false);
  assert.match(claim.findings[0].matchReason, /UNVERIFIED patch claim/);
  // a patch with a hash that is NOT the advisory's fix is still only a claim
  const wrongHash = run([curl({ pname: 'curl-backport' })], data([{ ...adv, affected: [{ ...adv.affected[0], package: { ...adv.affected[0].package, name: 'curl-backport' }, database_specific: { fix_patches: [{ name: 'curl-fix.patch', sha256: 'sha256-SOMETHINGELSE' }] } }] }]), { overlays: { 'curl-backport': ov['curl-backport'] } });
  assert.notEqual(stat(wrongHash, 'curl-backport')[0], 'backported-verified');
});

test('[NIX-009.AC01] a patched overlay is judged by what it changes: a fixed version override, or an unverified patch', () => {
  const ov = overlayEvidence({ 'overlay.nix': OVERLAY });
  assert.equal(ov['curl-bump'].version, '8.8.0');
  const bump = run([curl({ pname: 'curl-bump' })], data([{ ...curlAdv(), affected: [{ ...curlAdv().affected[0], package: { ecosystem: 'GitHub', name: 'curl-bump', purl: CURL_PURL } }] }]), { overlays: { 'curl-bump': ov['curl-bump'] } });
  assert.deepEqual(stat(bump, 'curl-bump'), ['fixed']);
  assert.equal(bump.findings[0].identity.versionSource, 'overlay');
  assert.equal(bump.findings[0].nixBuild.overlay.versionOverride, '8.8.0');
  const claim = run([curl({ pname: 'curl-claim' })], data([curlAdv()]), { overlays: { 'curl-claim': ov['curl-claim'] } });
  assert.deepEqual(stat(claim, 'curl-claim'), ['possibly-affected']);
  assert.equal(claim.findings[0].nixBuild.patches[0].name, 'CVE-2099-0001.patch');
  assert.equal(claim.findings[0].nixBuild.overlay.file, 'overlay.nix');
});

test('[NIX-009.AC01] source-revision advisories match only a listed commit; an unlisted one is unknown, never guessed', () => {
  const FIXC = 'a'.repeat(40); const BADC = 'b'.repeat(40); const OTHER = 'c'.repeat(40);
  const adv = SYN('SYN-NGX-0001', ['CVE-2099-0100'], [{ package: { ecosystem: 'GIT', name: 'nginx', purl: 'pkg:github/example/nginx' }, ranges: [{ type: 'GIT', repo: 'https://github.com/example/nginx', events: [{ introduced: BADC }, { fixed: FIXC }] }] }]);
  const mk = (rev) => ({ pname: 'nginx', version: 'unstable-2026-09-01', rev, urls: 'https://github.com/example/nginx/archive/x.tar.gz' });
  assert.deepEqual(stat(run([mk(FIXC)], data([adv])), 'nginx'), ['fixed']);
  assert.deepEqual(stat(run([mk(BADC)], data([adv])), 'nginx'), ['affected']);
  const unknown = run([mk(OTHER)], data([adv]));
  assert.deepEqual(stat(unknown, 'nginx'), ['unknown']);
  assert.match(unknown.findings[0].matchReason, /commit ordering is not available/);
});

test('[NIX-009.AC01] wrapped Haskell packages reuse the Hackage version logic with the real HSEC records', () => {
  const hs = (version) => ({ pname: 'xml-conduit', version, env: { libraryHaskellDepends: 'x', isLibrary: '1' } });
  const hackage = new AdvisoryDb({ records: HSEC, source: 'pinned-hsec', generatedAt: '2026-10-01T00:00:00Z', now: NOW });
  const mk = (v) => run([hs(v)], data([], { hackage }));
  assert.deepEqual(stat(mk('1.9.0.0'), 'xml-conduit'), ['affected']);
  assert.equal(mk('1.9.0.0').findings[0].osvId, 'HSEC-2023-0004');
  assert.equal(mk('1.9.0.0').findings[0].dataSource.ecosystem, 'Hackage');
  assert.deepEqual(stat(mk('1.9.1.0'), 'xml-conduit'), [], 'the fixed boundary is exclusive, PVP ordering');
  assert.equal(mk('1.9.1.0').statuses[0].status, 'not-affected');
  assert.deepEqual(stat(mk('1.9.1'), 'xml-conduit'), [], '1.9.1 == 1.9.1.0');
});

test('[NIX-009.AC01] a wrapped Haskell package the Hackage feed never covered (or covered too long ago) is unknown, not "no advisory matches"', () => {
  const hs = { pname: 'xml-conduit', version: '1.9.1.0', env: { libraryHaskellDepends: 'x', isLibrary: '1' } };   // a version OUTSIDE every affected range
  const db = (covered) => new AdvisoryDb({ records: HSEC, source: 'osv-live', generatedAt: '2026-10-02T00:00:00Z', now: NOW, covered });
  const status = (covered) => run([hs], data([], { hackage: db(covered) })).statuses.find((x) => x.name === 'xml-conduit');
  assert.equal(status({ 'xml-conduit': '2026-10-02T00:00:00Z' }).status, 'not-affected', 'covered and outside the range: a real clean verdict');
  const never = status({ aeson: '2026-10-02T00:00:00Z' });
  assert.equal(never.status, 'unknown', 'a feed that never looked this package up cannot clear it');
  assert.match(never.reason, /never covered this package/);
  assert.equal(never.feedCoverage, 'incomplete');
  const old = status({ 'xml-conduit': '2026-05-01T00:00:00Z' });
  assert.equal(old.status, 'unknown', 'coverage older than the age limit cannot clear it either');
  assert.match(old.reason, /longer ago than its age limit/);
  assert.equal(status(null).status, 'not-affected', 'a snapshot that makes no per-package claim behaves as it always did');
});

test('[NIX-009.AC02] a nixpkgs commit or a store hash is never an upstream version, and is never queried', () => {
  assert.match(isNotAnUpstreamVersion('a'.repeat(40)), /git revision/);
  assert.match(isNotAnUpstreamVersion(hh(3)), /store-path hash/);
  assert.match(isNotAnUpstreamVersion('abc1234'), /revision/);
  assert.match(isNotAnUpstreamVersion('unstable'), /moving ref/);
  assert.equal(isNotAnUpstreamVersion('8.7.1'), null);
  for (const bad of ['b'.repeat(40), hh(7)]) {
    const r = run([{ pname: 'curl', version: bad, urls: CURL_URL }], data([curlAdv()]));
    assert.deepEqual(r.findings, []);
    assert.equal(r.statuses[0].status, 'unknown'); assert.match(r.statuses[0].reason, /cannot be queried/);
    assert.equal(r.statuses[0].identity.versionRejected !== null, true);
    assert.equal(r.statuses[0].version, null);
  }
  // the nixpkgs input itself: no version, no match, no invented one
  const nixpkgs = run([{ pname: 'nixpkgs', version: '3'.repeat(40) }], data([curlAdv()]));
  assert.equal(nixpkgs.statuses[0].status, 'unknown');
  assert.equal(upstreamIdentity({ pname: 'x', version: '3'.repeat(40) }, null, null, null).version, null);
});

test('[NIX-009.AC02] ambiguous CPEs, name-only identities and a missing feed stay candidates or unknown', () => {
  const adv = SYN('SYN-SSL-0001', ['CVE-2099-0200'], [{ package: { ecosystem: 'CPE', name: 'ssl', cpe: 'vendora:ssl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }] }]);
  const amb = run([{ pname: 'ssl', version: '1.5.0' }], data([adv]), { meta: { ssl: { identifiers: { possibleCPEs: [{ vendor: 'vendora', product: 'ssl' }, { vendor: 'vendorb', product: 'ssl' }] } } } });
  assert.deepEqual(stat(amb, 'ssl'), ['candidate']);
  assert.match(amb.findings[0].matchReason, /ambiguous/);
  assert.equal(amb.findings[0].severity, 'low');
  const nameOnly = run([{ pname: 'ssl', version: '1.5.0' }], data([SYN('SYN-SSL-0002', [], [{ package: { ecosystem: 'Generic', name: 'ssl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }] }])]));
  assert.deepEqual(stat(nameOnly, 'ssl'), ['candidate']);
  assert.match(nameOnly.findings[0].matchReason, /name-only/);
  const none = run([curl()], null);
  assert.deepEqual(none.findings, []);
  assert.equal(none.statuses[0].status, 'unknown'); assert.match(none.statuses[0].reason, /not a clean result/);
  assert.equal(none.feed.status, 'feed-unavailable');
  const stale = run([curl()], data([curlAdv()], { generatedAt: '2025-01-01T00:00:00Z' }));
  assert.equal(stale.feed.status, 'stale-cache'); assert.equal(stale.findings[0].dataSource.feedStatus, 'stale-cache');
  // an explicit identity (meta.identifiers.purl) is authoritative even without a source URL
  const explicit = run([{ pname: 'curl', version: '8.7.1' }], data([curlAdv()]), { meta: { curl: { identifiers: { purl: CURL_PURL } } } });
  assert.deepEqual(stat(explicit, 'curl'), ['affected']);
  assert.equal(explicit.findings[0].dataSource.identityAuthority, 'explicit');
  assert.ok(compareUpstream('8.8.0', '8.7.1') > 0 && compareUpstream('8.8.0-rc1', '8.8.0') < 0 && compareUpstream('1.2', '1.2.0') === 0);
});

test('[NIX-009.AC03] inclusion in the runtime closure and function reachability are separate evidence tiers', () => {
  const specs = [curl(), curl({ pname: 'curl', version: '8.7.1', runtime: false, urls: CURL_URL })];
  const r = run(specs, data([curlAdv()]), { services: [{ service: 'nginx', packages: ['curl'] }] });
  const tiers = r.findings.map((f) => f.tiers.inclusion).sort();
  assert.deepEqual(tiers, ['build-only', 'runtime-closure']);
  const rt = r.findings.find((f) => f.tiers.inclusion === 'runtime-closure');
  assert.deepEqual(rt.tiers.services, ['nginx']);
  assert.equal(rt.tiers.reachability.function, 'unknown'); assert.equal(rt.tiers.reachability.import, 'unknown');
  assert.match(rt.tiers.reachability.basis, /inclusion only, never that code is called/);
  assert.ok(!r.findings.some((f) => f.tiers.reachability.function === 'reachable'), 'a store path or build input never establishes reachability');
});

test('[NIX-009.AC03] Haskell import and API reachability come from source evidence, and stay unknown without it', () => {
  const hackage = new AdvisoryDb({ records: HSEC, source: 'pinned-hsec', generatedAt: '2026-10-01T00:00:00Z', now: NOW });
  const spec = [{ pname: 'xml-conduit', version: '1.9.0.0', env: { libraryHaskellDepends: 'x' } }];
  const none = run(spec, data([], { hackage }));
  assert.equal(none.findings[0].tiers.reachability.import, 'unknown');
  const usage = { imports: [{ module: 'Text.XML', items: null }], callees: new Set(['Text.XML.readFile']) };
  const reached = run(spec, data([], { hackage }), { haskellUsage: usage, symbols: { 'HSEC-2023-0004': ['Text.XML.readFile'] } });
  assert.equal(reached.findings[0].tiers.reachability.import, 'imported');
  assert.equal(reached.findings[0].tiers.reachability.function, 'reachable');
  assert.equal(reached.findings[0].tiers.inclusion, 'runtime-closure', 'inclusion is carried separately');
  const notImported = run(spec, data([], { hackage }), { haskellUsage: { imports: [], callees: new Set() } });
  assert.equal(notImported.findings[0].tiers.reachability.import, 'not-imported');
  const missing = run(spec, data([], { hackage }), { haskellUsage: { imports: [{ module: 'Text.XML' }], callees: new Set() }, symbols: { 'HSEC-2023-0004': ['Text.XML.parseLBS'] } });
  assert.equal(missing.findings[0].tiers.reachability.function, 'unknown', 'a missing symbol is unknown, not unreachable');
});

test('[NIX-009.AC04] aliases, feed freshness, Nix build identity and absent KEV/EPSS data are all preserved', () => {
  const r = run([curl()], data([curlAdv()]));
  const f = r.findings[0];
  assert.deepEqual(f.cveAliases, ['CVE-2099-0001']);
  assert.equal(f.kev, 'unknown'); assert.equal(f.epss, 'unknown');
  assert.deepEqual(f.feed, { source: 'pinned-fixture', generatedAt: '2026-10-01T00:00:00Z', status: 'current', records: 1 });
  assert.ok(f.nixBuild.storeHash && f.nixBuild.derivation && f.nixBuild.outputs[0].name === 'out');
  const withData = run([curl()], data([curlAdv()]), { kev: new Set(['CVE-2099-0001']), epss: { 'CVE-2099-0001': 0.31 } });
  assert.equal(withData.findings[0].kev, true); assert.equal(withData.findings[0].epss, 0.31);
  const notKev = run([curl()], data([curlAdv()]), { kev: new Set(['CVE-0000-0000']), epss: {} });
  assert.equal(notKev.findings[0].kev, false); assert.equal(notKev.findings[0].epss, 'unknown');
  const noCve = run([curl()], data([curlAdv({ rec: { aliases: [] } })]));
  assert.equal(noCve.findings[0].kev, 'not-applicable');
  assert.equal(noCve.findings[0].osvId, 'SYN-CURL-0001');
});

test('[NIX-009.AC04] no match never erases an unknown mapping, and nixpkgs knownVulnerabilities and licenses are carried', () => {
  const r = run([curl({ pname: 'zlib', version: '1.3.1', urls: undefined }), curl({ pname: 'mystery', version: '9.9' }), curl()], data([curlAdv()]), {
    meta: { zlib: { license: 'Zlib' }, mystery: { knownVulnerabilities: ['CVE-2099-7777 is not fixed upstream'], license: 'GPL-3.0-only' }, curl: { license: { spdxId: 'curl' } } },
  });
  assert.equal(r.summary.components, 3);
  assert.equal(r.summary.matched, 2, 'curl (advisory) and mystery (knownVulnerabilities)');
  assert.equal(r.summary.unmapped, 1, 'zlib: nothing maps it, so "no advisory" is NOT "clean"');
  assert.equal(r.summary.mappedNoMatch, 0);
  const z = r.statuses.find((s) => s.name === 'zlib');
  assert.equal(z.status, 'unknown'); assert.equal(z.identityMapped, false);
  const kv = r.findings.find((f) => f.name === 'mystery');
  assert.equal(kv.status, 'affected'); assert.deepEqual(kv.cveAliases, ['CVE-2099-7777']); assert.equal(kv.dataSource.feed, 'nixpkgs-meta');
  const lic = Object.fromEntries(r.licenses.map((l) => [l.name, l.status]));
  assert.deepEqual(lic, { zlib: 'allowed', mystery: 'denied', curl: 'allowed' });
  const noMeta = run([curl()], data([curlAdv()]));
  assert.equal(noMeta.licenses[0].status, 'unknown');
});
