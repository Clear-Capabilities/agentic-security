// QA-005.AC03: a scanned project is untrusted. It must not be able to vouch for its own advisories, its own freshness or its own
// resolved dependencies. Each test is an attack a pull request could carry, run through the real CLI.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSnapshot } from '../../src/language/haskell-sca.js';

const SCANNER = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = join(SCANNER, 'bin', 'agentic-security.js');
const HSEC_DIR = join(SCANNER, 'test', 'fixtures', 'hackage-advisories', 'records');
const REC = readdirSync(HSEC_DIR).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(HSEC_DIR, f), 'utf8'))).find((r) => r.id === 'HSEC-2023-0004');
const nowIso = () => new Date().toISOString();
const dirs = [];

function project(files) {
  const d = mkdtempSync(join(tmpdir(), 'trust-')); dirs.push(d);
  for (const [rel, text] of Object.entries(files)) { mkdirSync(dirname(join(d, rel)), { recursive: true }); writeFileSync(join(d, rel), typeof text === 'string' ? text : JSON.stringify(text)); }
  return d;
}
function scan(dir, env = {}) {
  const e = { ...process.env, HOME: dir, XDG_CONFIG_HOME: join(dir, '.nocfg'), ...env }; delete e.NODE_TEST_CONTEXT;
  for (const k of ['AGENTIC_SECURITY_HACKAGE_ADVISORIES', 'AGENTIC_SECURITY_NIX_ADVISORIES', 'AGENTIC_SECURITY_NIX_EXPORT']) if (!(k in env)) delete e[k];
  const r = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json', '--no-state'], { encoding: 'utf8', env: e, timeout: 240000, maxBuffer: 64 << 20 });
  const j = JSON.parse(r.stdout);
  return { status: r.status, health: j.scanHealth.status, conds: j.scanHealth.conditions || [], limits: (j.scanHealth.languageCoverage.limitations || []), findings: j.findings };
}

const CABAL = 'cabal-version: 3.0\nname: demo\nversion: 0.1.0.0\nbuild-type: Simple\n\nlibrary\n  exposed-modules: Lib\n  hs-source-dirs: src\n  build-depends: base, xml-conduit >=1.9 && <2\n  default-language: Haskell2010\n';
const hsProject = (extra = {}) => project({ 'demo.cabal': CABAL, 'cabal.project': 'packages: .\n', 'cabal.project.freeze': 'constraints: xml-conduit ==1.9.0.0\n', 'src/Lib.hs': 'module Lib where\nx :: Int\nx = 1\n', ...extra });
const hit = (r) => r.findings.filter((f) => f.package === 'xml-conduit' && f.osvId === 'HSEC-2023-0004').length;

test('[QA-005.AC03] a project that ships its own EMPTY advisory feed cannot hide a vulnerable dependency or make the scan look complete', () => {
  const hostile = hsProject({ '.agentic-security/hackage-advisories.json': buildSnapshot([], nowIso()) });
  const r = scan(hostile);
  assert.notEqual(r.health, 'complete', 'a feed the project wrote must not produce a complete verdict');
  assert.ok(r.conds.some((c) => /IGNORED/.test(c) && /hackage-advisories\.json/.test(c)), `the ignored file is named: ${JSON.stringify(r.conds)}`);
  assert.ok(r.conds.some((c) => /not assessed/i.test(c)));
});

test('[QA-005.AC03] a project-local snapshot is ignored even when it is REAL; the operator feed (env or per-user config) is what counts', () => {
  const feed = buildSnapshot([REC], nowIso());
  const dir = hsProject({ '.agentic-security/hackage-advisories.json': feed });
  const ignored = scan(dir);
  assert.equal(hit(ignored), 0, 'the project-local file is never read, so it is not a source of findings either');
  const viaEnv = scan(dir, { AGENTIC_SECURITY_HACKAGE_ADVISORIES: (() => { const p = join(dir, '..', `op-${Date.now()}.json`); writeFileSync(p, JSON.stringify(feed)); dirs.push(p); return p; })() });
  assert.equal(hit(viaEnv), 1); assert.equal(viaEnv.health, 'complete');
  const cfg = hsProject({});
  mkdirSync(join(cfg, '.opcfg', 'agentic-security'), { recursive: true });
  writeFileSync(join(cfg, '.opcfg', 'agentic-security', 'hackage-advisories.json'), JSON.stringify(feed));
  const viaConfig = scan(cfg, { XDG_CONFIG_HOME: join(cfg, '.opcfg') });
  assert.equal(hit(viaConfig), 1, 'the per-user configuration directory is an operator location');
});

const LOCK = '{"nodes":{"root":{}},"root":"root","version":7}\n';
const LOCK_SHA = createHash('sha256').update(LOCK).digest('hex');
const A = '0123456789abcdfghijklmnpqrsvwxyz';
const hh = (i) => { let s = ''; let x = i * 2654435761 % 4294967296; for (let j = 0; j < 32; j++) { s += A[x % 32]; x = (Math.floor(x / 32) + j * 11 + i) % 4294967296; } return s; };
function nixExport(lockSha, version = '8.7.1') {
  const out = (i, n) => `/nix/store/${hh(i)}-${n}`; const drv = (i, n) => `/nix/store/${hh(i + 500)}-${n}.drv`;
  const app = { path: out(1, 'app-1.0'), drv: drv(1, 'app-1.0') }; const curl = { path: out(10, `curl-${version}`), drv: drv(10, `curl-${version}`) };
  const pathinfo = { [curl.path]: { narHash: 'sha256-x', narSize: 1, references: [], deriver: curl.drv }, [app.path]: { narHash: 'sha256-x', narSize: 1, references: [app.path, curl.path], deriver: app.drv } };
  const drvs = {
    [curl.drv]: { outputs: { out: { path: curl.path } }, inputSrcs: [], inputDrvs: {}, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: `curl-${version}`, pname: 'curl', version, out: curl.path, outputs: 'out', urls: `https://github.com/curl/curl/releases/download/curl-${version.replace(/\./g, '_')}/curl-${version}.tar.xz` } },
    [app.drv]: { outputs: { out: { path: app.path } }, inputSrcs: [], inputDrvs: { [curl.drv]: ['out'] }, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: 'app-1.0', pname: 'app', version: '1.0', out: app.path, buildInputs: curl.path } },
  };
  const prov = (cmd) => ({ tool: 'nix', command: cmd, target: { system: 'x86_64-linux', installable: '.#app' }, revision: {}, flakeLockSha256: lockSha, generatedAt: nowIso() });
  return { exports: [{ schema: 'nix-path-info-json', data: pathinfo, provenance: prov('nix path-info --json --recursive .#app') }, { schema: 'nix-derivation-show-json', data: drvs, provenance: prov('nix derivation show --recursive .#app') }] };
}
const curlAdvisory = { id: 'SYN-CURL-0001', aliases: ['CVE-2099-0001'], summary: 'synthetic', published: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z', affected: [{ package: { ecosystem: 'GitHub', name: 'curl', purl: 'pkg:github/curl/curl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '8.0.0' }, { fixed: '8.8.0' }] }] }] };
const feedFile = () => { const p = join(tmpdir(), `nixfeed-${process.pid}-${Math.random().toString(16).slice(2)}.json`); writeFileSync(p, JSON.stringify({ generatedAt: nowIso(), records: [curlAdvisory] })); dirs.push(p); return p; };
const curlHits = (r) => r.findings.filter((f) => f.package === 'curl' && f.osvId === 'SYN-CURL-0001').length;

test('[QA-005.AC03] an export cannot declare its own freshness: an `expected` block inside the file is ignored and a lock mismatch is refused', () => {
  const forged = { ...nixExport('f'.repeat(64)), expected: { flakeLockSha256: 'f'.repeat(64) } };       // the attacker states what it should be checked against
  const dir = project({ 'flake.nix': '{ outputs = { self }: { }; }\n', 'flake.lock': LOCK, 'nix-export.json': forged });
  const r = scan(dir, { AGENTIC_SECURITY_NIX_ADVISORIES: feedFile() });
  assert.equal(curlHits(r), 0, 'an export made against some other lock contributes nothing');
  assert.ok(r.conds.some((c) => /stale|different flake\.lock/i.test(c)), `the refusal is stated: ${JSON.stringify(r.conds)}`);
  assert.notEqual(r.health, 'complete');
});

test('[QA-005.AC03] an export bound to the real flake.lock is used, but disclosed as project-supplied and unsigned', () => {
  const dir = project({ 'flake.nix': '{ outputs = { self }: { }; }\n', 'flake.lock': LOCK, 'nix-export.json': nixExport(LOCK_SHA) });
  const r = scan(dir, { AGENTIC_SECURITY_NIX_ADVISORIES: feedFile() });
  assert.equal(curlHits(r), 1, 'a correctly bound export is matched like any other');
  assert.ok(r.limits.some((l) => l.kind === 'supply-gap' && l.gap === 'closure-project-supplied'), `the trust level is stated: ${JSON.stringify(r.limits)}`);
});

test('[QA-005.AC03] an export given by the OPERATOR is not labelled project-supplied, and an export with no lock to bind to is unverified', () => {
  const op = join(tmpdir(), `opexport-${process.pid}.json`); writeFileSync(op, JSON.stringify(nixExport(LOCK_SHA))); dirs.push(op);
  const dir = project({ 'flake.nix': '{ outputs = { self }: { }; }\n', 'flake.lock': LOCK });
  const r = scan(dir, { AGENTIC_SECURITY_NIX_ADVISORIES: feedFile(), AGENTIC_SECURITY_NIX_EXPORT: op });
  assert.equal(curlHits(r), 1);
  assert.ok(!r.limits.some((l) => l.gap === 'closure-project-supplied'));
  const nolock = project({ 'flake.nix': '{ outputs = { self }: { }; }\n', 'nix-export.json': nixExport(LOCK_SHA) });
  const u = scan(nolock, { AGENTIC_SECURITY_NIX_ADVISORIES: feedFile() });
  assert.ok(u.conds.some((c) => /unverified|no flake\.lock/i.test(c)), `an unbound export is a condition: ${JSON.stringify(u.conds)}`);
});

const pre = (id, n, v, d = []) => ({ type: 'pre-existing', id, 'pkg-name': n, 'pkg-version': v, depends: d });
const hk = (id, n, v, d) => ({ type: 'configured', id, 'pkg-name': n, 'pkg-version': v, flags: {}, style: 'global', 'pkg-src': { type: 'repo-tar', repo: { type: 'secure-repo', uri: 'http://hackage.haskell.org/' } }, 'pkg-src-sha256': 'b'.repeat(64), 'component-name': 'lib', depends: d });
const plan = (xml) => ({ 'cabal-version': '3.10.2.0', 'compiler-id': 'ghc-9.4.7', os: 'linux', arch: 'x86_64', 'install-plan': [pre('base-4.17.2.1', 'base', '4.17.2.1'), hk(`xml-conduit-${xml}-x`, 'xml-conduit', xml, ['base-4.17.2.1']), { type: 'configured', id: 'demo-0.1.0.0-inplace', 'pkg-name': 'demo', 'pkg-version': '0.1.0.0', flags: {}, style: 'local', 'pkg-src': { type: 'local', path: '/proj/.' }, 'component-name': 'lib', depends: [`xml-conduit-${xml}-x`, 'base-4.17.2.1'] }] });

test('[QA-005.AC03] a forged Cabal plan that contradicts the project\'s own freeze file contributes no versions and says so', () => {
  const feed = (() => { const p = join(tmpdir(), `hsfeed-${process.pid}-${Math.random().toString(16).slice(2)}.json`); writeFileSync(p, JSON.stringify(buildSnapshot([REC], nowIso()))); dirs.push(p); return p; })();
  // honest: freeze says 1.9.0.0 (vulnerable) and the plan agrees
  const honest = hsProject({ 'cabal.project': 'packages: .\nwith-compiler: ghc-9.4.7\n', 'dist-newstyle/cache/plan.json': plan('1.9.0.0') });
  assert.equal(hit(scan(honest, { AGENTIC_SECURITY_HACKAGE_ADVISORIES: feed })), 1);
  // forged: the plan claims the fixed 1.9.1.0 to make the vulnerability disappear, but the freeze pins 1.9.0.0
  const forged = hsProject({ 'cabal.project': 'packages: .\nwith-compiler: ghc-9.4.7\n', 'dist-newstyle/cache/plan.json': plan('1.9.1.0') });
  const r = scan(forged, { AGENTIC_SECURITY_HACKAGE_ADVISORIES: feed });
  assert.ok(r.conds.some((c) => /contradicts the freeze/.test(c)), `the contradiction is a condition: ${JSON.stringify(r.conds)}`);
  assert.equal(hit(r), 1, 'the freeze file, not the plan, supplies the version, so the vulnerability is still reported');
  assert.notEqual(r.health, 'complete');
});

test.after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
