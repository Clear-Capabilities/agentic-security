// Advisory-own severity on the Nix closure matcher. Closures go through the real importer (same builder shape as
// nix-sca-patches). Wrapped-Haskell cases use the real pinned HSEC records; the non-Hackage cases are SYNTHETIC
// OSV-style records (ids SYN-*, CVE-2099-*).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importNixClosure } from '../../src/language/nix-closure.js';
import { matchNixVulnerabilities, NixAdvisoryData } from '../../src/language/nix-sca.js';
import { AdvisoryDb } from '../../src/language/haskell-sca.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const HSEC = readdirSync(join(FIX, 'hackage-advisories', 'records')).map((f) => JSON.parse(readFileSync(join(FIX, 'hackage-advisories', 'records', f), 'utf8')));
const NOW = Date.parse('2026-10-03T00:00:00Z');
const A = '0123456789abcdfghijklmnpqrsvwxyz';
const hh = (i) => { let s = ''; let x = i * 2654435761 % 4294967296; for (let j = 0; j < 32; j++) { s += A[x % 32]; x = (Math.floor(x / 32) + j * 11 + i) % 4294967296; } return s; };
const out = (i, n) => `/nix/store/${hh(i)}-${n}`;
const drv = (i, n) => `/nix/store/${hh(i + 500)}-${n}.drv`;

function closureOf(specs) {
  const app = { path: out(1, 'app-1.0'), drv: drv(1, 'app-1.0') };
  const pathinfo = {}; const drvs = {};
  specs.forEach((s, k) => {
    const i = 10 + k;
    s.path = out(i, `${s.pname}-${s.version}`); s.drv = drv(i, `${s.pname}-${s.version}`);
    drvs[s.drv] = { outputs: { out: { path: s.path } }, inputSrcs: [], inputDrvs: {}, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: `${s.pname}-${s.version}`, pname: s.pname, version: s.version, out: s.path, outputs: 'out', ...(s.urls ? { urls: s.urls } : {}), ...(s.env || {}) } };
    pathinfo[s.path] = { narHash: 'sha256-x', narSize: 1, references: [], deriver: s.drv };
  });
  pathinfo[app.path] = { narHash: 'sha256-x', narSize: 1, references: [app.path, ...specs.map((s) => s.path)], deriver: app.drv };
  drvs[app.drv] = { outputs: { out: { path: app.path } }, inputSrcs: [], inputDrvs: Object.fromEntries(specs.map((s) => [s.drv, ['out']])), system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: 'app-1.0', pname: 'app', version: '1.0', out: app.path, buildInputs: specs.map((s) => s.path).join(' ') } };
  const prov = (cmd) => ({ tool: 'nix', command: cmd, target: { system: 'x86_64-linux', installable: '.#app' }, revision: {}, flakeLockSha256: 'a'.repeat(64), generatedAt: '2026-10-01T00:00:00Z' });
  const closure = importNixClosure({ exports: [{ schema: 'nix-path-info-json', data: pathinfo, provenance: prov('nix path-info --json --recursive .#app') }, { schema: 'nix-derivation-show-json', data: drvs, provenance: prov('nix derivation show --recursive .#app') }], expected: { system: 'x86_64-linux', installable: '.#app', flakeLockSha256: 'a'.repeat(64) }, now: NOW });
  return { closure, drvEnv: Object.fromEntries(Object.entries(drvs).map(([k, v]) => [k, v.env])) };
}
const data = (records, opts = {}) => new NixAdvisoryData({ records, source: 'pinned-fixture', generatedAt: '2026-10-01T00:00:00Z', now: NOW, ...opts });
const run = (specs, d) => { const { closure, drvEnv } = closureOf(specs); return matchNixVulnerabilities({ closure, drvEnv, data: d }); };

const CURL_URL = (v) => `https://github.com/curl/curl/releases/download/curl-${v.replace(/\./g, '_')}/curl-${v}.tar.xz`;
const curl = (v = '8.7.1') => ({ pname: 'curl', version: v, urls: CURL_URL(v) });
// SYNTHETIC
const curlAdv = (rec = {}, aff = {}) => ({ id: 'SYN-CURL-0001', aliases: ['CVE-2099-0001'], summary: 'synthetic', published: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z', affected: [{ package: { ecosystem: 'GitHub', name: 'curl', purl: 'pkg:github/curl/curl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '8.0.0' }, { fixed: '8.8.0' }] }], ...aff }], ...rec });
const V = (s) => [{ type: 'CVSS_V3', score: s }];
const hs = (pname, version) => ({ pname, version, env: { libraryHaskellDepends: 'x', isLibrary: '1' } });
const hackage = () => new AdvisoryDb({ records: HSEC, source: 'pinned-hsec', generatedAt: '2026-10-01T00:00:00Z', now: NOW });

test('SYNTHETIC generic record: an affected package takes the advisory CVSS severity, not the status default', () => {
  const low = run([curl()], data([curlAdv({ severity: V('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N') })])).findings[0];
  assert.equal(low.status, 'affected'); assert.equal(low.severity, 'low'); assert.equal(low.severityScore, 3.7);
  assert.equal(low.severityBasis, 'CVSS v3.1 base score 3.7 from the advisory');
  const crit = run([curl()], data([curlAdv({ severity: V('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H') })])).findings[0];
  assert.equal(crit.severity, 'critical');
  const named = run([curl()], data([curlAdv({ database_specific: { severity: 'MODERATE' } })])).findings[0];
  assert.equal(named.severity, 'medium'); assert.match(named.severityBasis, /"MODERATE"/);
});

test('SYNTHETIC generic record: with no usable rating the status default and the old basis are kept', () => {
  const f = run([curl()], data([curlAdv()])).findings[0];
  assert.equal(f.severity, 'high'); assert.equal(f.severityBasis, 'the advisory carries no severity rating'); assert.equal('severityScore' in f, false);
  const bad = run([curl()], data([curlAdv({ severity: V('CVSS:3.1/AV:N') })])).findings[0];
  assert.equal(bad.severity, 'high'); assert.match(bad.severityBasis, /missing base metric/);
});

test('a fixed package is never raised by the upstream rating', () => {
  const r = run([curl('8.8.0')], data([curlAdv({ severity: V('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H') })]));
  const f = r.findings[0];
  assert.equal(f.status, 'fixed'); assert.equal(f.severity, 'info'); assert.match(f.severityBasis, /not applied/);
});

test('wrapped Haskell, real HSEC records: the Hackage advisory rating reaches the Nix finding', () => {
  const aeson = run([hs('aeson', '1.5.6.0')], data([], { hackage: hackage() })).findings.find((f) => f.osvId === 'HSEC-2023-0001');
  assert.equal(aeson.status, 'affected');
  assert.equal(aeson.severity, 'medium', 'CVSS 6.5, not the blanket high for an affected status');
  assert.equal(aeson.severityScore, 6.5);
  const xml = run([hs('xml-conduit', '1.9.0.0')], data([], { hackage: hackage() })).findings[0];
  assert.equal(xml.severity, 'high'); assert.equal(xml.severityScore, 7.5);
});
