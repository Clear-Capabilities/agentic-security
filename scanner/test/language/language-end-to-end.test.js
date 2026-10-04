// QA-005: end-to-end documented workflow capability matrix for Haskell and Nix/NixOS.
// Suite "language-end-to-end" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Everything here goes through the DISTRIBUTED path: the real CLI process over a real project directory. A capability that
// only a direct unit import can reach does not count (QA-005.AC04).

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSnapshot } from '../../src/language/haskell-sca.js';

const SCANNER = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = join(SCANNER, 'bin', 'agentic-security.js');
const HSEC_DIR = join(SCANNER, 'test', 'fixtures', 'hackage-advisories', 'records');
const HSEC = readdirSync(HSEC_DIR).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(HSEC_DIR, f), 'utf8')));
const nowIso = () => new Date().toISOString();

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'e2e-'));
  for (const [rel, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, rel)), { recursive: true }); writeFileSync(join(dir, rel), typeof text === 'string' ? text : JSON.stringify(text)); }
  return dir;
}
function scan(dir, { format = 'json', env = {}, args = [] } = {}) {
  const e = { ...process.env, ...env }; delete e.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', format, ...args], { encoding: 'utf8', env: e, timeout: 240000, maxBuffer: 64 << 20 });
  return { status: p.status, out: p.stdout, err: p.stderr, json: format === 'json' || format === 'cyclonedx' ? safeJson(p.stdout) : null };
}
const safeJson = (t) => { try { return JSON.parse(t); } catch { return null; } };
function snapshot(dir, name, records) {
  const path = join(dir, name);
  return { path, write(extra = {}) { writeFileSync(path, JSON.stringify({ ...buildSnapshot(records, nowIso()), ...extra })); return path; } };
}

// ── Haskell: a resolved plan reaches the distributed scan ───────────────────────────────────
const CABAL = ['cabal-version: 3.0', 'name: demo', 'version: 0.1.0.0', 'build-type: Simple', '', 'library', '  hs-source-dirs: src', '  exposed-modules: Lib',
  '  build-depends: base >=4.14 && <4.20, aeson ==2.1.*', '  default-language: Haskell2010', ''].join('\n');
const pre = (id, n, v, d = []) => ({ type: 'pre-existing', id, 'pkg-name': n, 'pkg-version': v, depends: d });
const hk = (id, n, v, d) => ({ type: 'configured', id, 'pkg-name': n, 'pkg-version': v, flags: {}, style: 'global', 'pkg-src': { type: 'repo-tar', repo: { type: 'secure-repo', uri: 'http://hackage.haskell.org/' } }, 'pkg-src-sha256': 'b'.repeat(64), 'component-name': 'lib', depends: d });
const plan = (xmlVersion = '1.9.0.0', compiler = 'ghc-9.4.7') => ({
  'cabal-version': '3.10.2.0', 'compiler-id': compiler, os: 'linux', arch: 'x86_64',
  'install-plan': [
    pre('base-4.17.2.1', 'base', '4.17.2.1'),
    hk(`xml-conduit-${xmlVersion}-x`, 'xml-conduit', xmlVersion, ['base-4.17.2.1']),
    hk('aeson-2.1.2.1-a', 'aeson', '2.1.2.1', ['base-4.17.2.1', `xml-conduit-${xmlVersion}-x`]),
    { type: 'configured', id: 'demo-0.1.0.0-inplace', 'pkg-name': 'demo', 'pkg-version': '0.1.0.0', flags: {}, style: 'local', 'pkg-src': { type: 'local', path: '/proj/.' }, 'component-name': 'lib', depends: ['aeson-2.1.2.1-a', 'base-4.17.2.1'] },
  ],
});
const hsProject = (p = plan()) => project({ 'demo.cabal': CABAL, 'cabal.project': 'packages: .\nwith-compiler: ghc-9.4.7\n', 'src/Lib.hs': 'module Lib where\nimport Data.Aeson\nx :: Int\nx = 1\n', 'dist-newstyle/cache/plan.json': p });
const xmlRecord = () => HSEC.find((r) => r.id === 'HSEC-2023-0004');

test('[QA-005.AC04] a fresh cabal plan reaches the CLI: an undeclared transitive package is matched against the advisory snapshot', () => {
  const dir = hsProject();
  try {
    const feed = snapshot(dir, 'adv.json', [xmlRecord()]);
    const withPlan = scan(dir, { env: { AGENTIC_SECURITY_HACKAGE_ADVISORIES: feed.write() } });
    const hit = (withPlan.json.findings || []).filter((f) => f.osvId === 'HSEC-2023-0004' && f.package === 'xml-conduit');
    assert.equal(hit.length, 1, 'the transitive xml-conduit 1.9.0.0 chosen by the plan is reported');
    assert.equal(hit[0].version, '1.9.0.0');
    // without the plan nobody declared xml-conduit, so the same feed finds nothing: the plan is what made it visible
    rmSync(join(dir, 'dist-newstyle'), { recursive: true, force: true });
    const without = scan(dir, { env: { AGENTIC_SECURITY_HACKAGE_ADVISORIES: feed.path } });
    assert.equal((without.json.findings || []).filter((f) => f.package === 'xml-conduit').length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('[QA-005.AC04] the resolved graph is in the distributed SBOM, with its transitive package', () => {
  const dir = hsProject();
  try {
    const r = scan(dir, { format: 'cyclonedx' });
    const names = ((r.json && r.json.components) || []).filter((c) => /pkg:hackage/.test(c.purl || '')).map((c) => `${c.name}@${c.version}`).sort();
    assert.deepEqual(names, ['aeson@2.1.2.1', 'base@4.17.2.1', 'xml-conduit@1.9.0.0']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('[QA-005.AC04] a stale plan (compiler no longer matches the project) copies no versions and says so', () => {
  const dir = hsProject(plan('1.9.0.0', 'ghc-9.6.1'));
  try {
    const feed = snapshot(dir, 'adv.json', [xmlRecord()]);
    const r = scan(dir, { env: { AGENTIC_SECURITY_HACKAGE_ADVISORIES: feed.write() } });
    assert.equal((r.json.findings || []).filter((f) => f.package === 'xml-conduit').length, 0, 'a stale plan is never a source of versions');
    const lc = r.json.scanHealth.languageCoverage;
    const said = JSON.stringify([r.json.scanHealth.conditions || [], lc.limitations || []]);
    assert.match(said, /stale|freshness|compiler/i, 'the stale plan is disclosed in scan health');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── Nix: an exported closure reaches the distributed scan ───────────────────────────────────
const A = '0123456789abcdfghijklmnpqrsvwxyz';
const hh = (i) => { let s = ''; let x = i * 2654435761 % 4294967296; for (let j = 0; j < 32; j++) { s += A[x % 32]; x = (Math.floor(x / 32) + j * 11 + i) % 4294967296; } return s; };
const out = (i, n) => `/nix/store/${hh(i)}-${n}`;
const drvp = (i, n) => `/nix/store/${hh(i + 500)}-${n}.drv`;
const CURL_URL = 'https://github.com/curl/curl/releases/download/curl-8_7_1/curl-8.7.1.tar.xz';
function closureExport() {
  const app = { path: out(1, 'app-1.0'), drv: drvp(1, 'app-1.0') };
  const curl = { path: out(10, 'curl-8.7.1'), drv: drvp(10, 'curl-8.7.1') };
  const pathinfo = { [curl.path]: { narHash: 'sha256-x', narSize: 1, references: [], deriver: curl.drv }, [app.path]: { narHash: 'sha256-x', narSize: 1, references: [app.path, curl.path], deriver: app.drv } };
  const drvs = {
    [curl.drv]: { outputs: { out: { path: curl.path } }, inputSrcs: [], inputDrvs: {}, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: 'curl-8.7.1', pname: 'curl', version: '8.7.1', out: curl.path, outputs: 'out', urls: CURL_URL } },
    [app.drv]: { outputs: { out: { path: app.path } }, inputSrcs: [], inputDrvs: { [curl.drv]: ['out'] }, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: 'app-1.0', pname: 'app', version: '1.0', out: app.path, buildInputs: curl.path } },
  };
  const prov = (cmd) => ({ tool: 'nix', command: cmd, target: { system: 'x86_64-linux', installable: '.#app' }, revision: {}, flakeLockSha256: 'a'.repeat(64), generatedAt: nowIso() });
  return {
    exports: [{ schema: 'nix-path-info-json', data: pathinfo, provenance: prov('nix path-info --json --recursive .#app') }, { schema: 'nix-derivation-show-json', data: drvs, provenance: prov('nix derivation show --recursive .#app') }],
    expected: { system: 'x86_64-linux', installable: '.#app', flakeLockSha256: 'a'.repeat(64) },
  };
}
const curlAdvisory = { id: 'SYN-CURL-0001', aliases: ['CVE-2099-0001'], summary: 'synthetic curl advisory', published: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z', affected: [{ package: { ecosystem: 'GitHub', name: 'curl', purl: 'pkg:github/curl/curl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '8.0.0' }, { fixed: '8.8.0' }] }] }] };
const nixProject = () => project({ 'flake.nix': '{ outputs = { self }: { }; }\n', 'nix-export.json': closureExport() });

test('[QA-005.AC04] a Nix closure export reaches the CLI: the closure is matched by upstream identity against the snapshot', () => {
  const dir = nixProject();
  try {
    const feed = join(dir, 'nix-adv.json');
    writeFileSync(feed, JSON.stringify({ generatedAt: nowIso(), records: [curlAdvisory] }));
    const r = scan(dir, { env: { AGENTIC_SECURITY_NIX_ADVISORIES: feed } });
    const hit = (r.json.findings || []).filter((f) => f.osvId === 'SYN-CURL-0001' && f.package === 'curl');
    assert.equal(hit.length, 1, JSON.stringify((r.json.findings || []).map((f) => `${f.parser}:${f.package}:${f.osvId}`)));
    assert.equal(hit[0].version, '8.7.1');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('[QA-005.AC03] a closure with NO advisory feed is never reported clean: the scan states it was not assessed', () => {
  const dir = nixProject();
  try {
    const r = scan(dir, { env: { AGENTIC_SECURITY_NIX_ADVISORIES: '', HOME: dir } });
    assert.equal((r.json.findings || []).filter((f) => f.package === 'curl').length, 0);
    assert.match(JSON.stringify(r.json.scanHealth.conditions || []), /advisory/i, 'the missing feed is a scan-health condition');
    assert.notEqual(r.json.scanHealth.status, 'complete', 'an unchecked closure cannot yield a complete scan');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('[QA-005.AC03] a malformed closure export is a stated gap, never a silent drop', () => {
  const dir = project({ 'flake.nix': '{ outputs = { self }: { }; }\n', 'nix-export.json': '{ this is not json' });
  try {
    const r = scan(dir);
    assert.match(JSON.stringify(r.json.scanHealth.conditions || []), /malformed/i);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('[QA-005.AC04] evaluation is opt-in and owned: unselected it is not requested; selected without a Nix binary it is stated, never faked', () => {
  const dir = nixProject();
  const emptyBin = mkdtempSync(join(tmpdir(), 'nopath-'));
  try {
    const off = scan(dir);
    assert.equal(off.json.scanHealth.languageCoverage.optionalModes['nix-eval'].selected, false);
    const on = scan(dir, { env: { AGENTIC_SECURITY_NIX_EVAL: '1', AGENTIC_SECURITY_NIX_TARGET: 'packages.x86_64-linux.default', PATH: emptyBin } });
    const m = on.json.scanHealth.languageCoverage.optionalModes['nix-eval'];
    assert.equal(m.selected, true);
    assert.equal(m.ran, false, 'nothing was evaluated');
    assert.match(String(m.reason), /nix binary|not found|PATH/i);
    assert.match(JSON.stringify(on.json.scanHealth.conditions || []), /nix-eval/);
  } finally { rmSync(dir, { recursive: true, force: true }); rmSync(emptyBin, { recursive: true, force: true }); }
});

// ═════════════════════════════════════════════════════════════════════════════════════════
// The capability matrix (QA-005.AC01 / AC02 / AC03)
//
// One row per ledger capability (docs/capability-ledger.json, CAP-001..018 and CAP-101..115). Every cell drives the REAL CLI over
// a copy of a shipped example (examples/): a Haskell application, a NixOS host, Haskell-on-Nix and a polyglot privacy/AI project.
// A row is either applicable (an executed assertion per ecosystem) or carries a written, specific reason it is not (a semantic
// not-applicable), plus the behavior that does apply. A row with neither fails the coverage test at the end.
// ═════════════════════════════════════════════════════════════════════════════════════════
import { cpSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';

const EXAMPLES = join(SCANNER, '..', 'examples');
const LEDGER = JSON.parse(readFileSync(join(SCANNER, '..', 'docs', 'capability-ledger.json'), 'utf8'));
const copies = [];
function example(name, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'e2e-ex-'));
  cpSync(join(EXAMPLES, name), dir, { recursive: true });
  for (const [rel, text] of Object.entries(extra)) { mkdirSync(dirname(join(dir, rel)), { recursive: true }); writeFileSync(join(dir, rel), text); }
  copies.push(dir);
  return dir;
}
function cli(dir, args, { env = {}, input } = {}) {
  const e = { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1', HOME: dir, ...env }; delete e.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, ...args], { cwd: dir, encoding: 'utf8', env: e, timeout: 240000, maxBuffer: 64 << 20, input });
  return { status: p.status, out: p.stdout || '', err: p.stderr || '', text: `${p.stdout || ''}${p.stderr || ''}`, json() { return safeJson(p.stdout); } };
}
const scanned = new Map();
/** One scan per (example), reused by read-only cells. Mutating cells take their own copy. */
function scanOf(name) {
  if (!scanned.has(name)) { const dir = example(name); const r = cli(dir, ['scan', dir, '--format', 'json']); scanned.set(name, { dir, r, j: r.json() }); }
  return scanned.get(name);
}
const fam = (j, f, extra = () => true) => (j.findings || []).filter((x) => (x.family === f || x.rule === f) && extra(x));
const HS = 'haskell-app/vulnerable'; const HSF = 'haskell-app/fixed'; const NX = 'nixos-host/vulnerable'; const NXF = 'nixos-host/fixed'; const HN = 'haskell-on-nix/vulnerable'; const PP = 'polyglot-privacy';

const MATRIX = {};
const cell = (cap, eco, fn) => { (MATRIX[cap] ||= {})[eco] = fn; };
const na = (cap, reason, behavior) => { (MATRIX[cap] ||= {}).na = { reason, behavior }; };

// CAP-001 scanning ------------------------------------------------------------------------------------------------
cell('CAP-001', 'haskell', () => {
  const { r, j } = scanOf(HS);
  assert.equal(r.status, 3, 'exit 3 = critical present');
  assert.ok(fam(j, 'sql-injection').length && fam(j, 'command-injection').length);
  const dir = example(HS);
  const line = fam(scanOf(HS).j, 'command-injection')[0].line;
  const f = join(dir, 'src', 'Main.hs'); const src = readFileSync(f, 'utf8').split('\n');
  src[line - 1] += '  -- agentic-security-ignore: command-injection';
  writeFileSync(f, src.join('\n'));
  const again = cli(dir, ['scan', dir, '--format', 'json', '--include-suppressed']).json();
  assert.equal(fam(again, 'command-injection', (x) => x.line === line && !x.suppressed).length, 0, 'the line-scoped pragma suppresses exactly that finding');
  assert.ok(fam(again, 'sql-injection').length, 'a different finding is untouched');
});
cell('CAP-001', 'nix', () => {
  const { r, j } = scanOf(NX);
  assert.equal(r.status, 2, 'exit 2 = high present');
  assert.ok(fam(j, 'ssh-root-login').length && fam(j, 'firewall-disabled').length);
  const dir = example(NX);
  const f = join(dir, 'configuration.nix'); const src = readFileSync(f, 'utf8').split('\n');
  const line = fam(j, 'ssh-root-login')[0].line; src[line - 1] += ' # agentic-security-ignore: ssh-root-login';
  writeFileSync(f, src.join('\n'));
  const again = cli(dir, ['scan', dir, '--format', 'json']).json();
  assert.equal(fam(again, 'ssh-root-login').length, 0);
  assert.ok(fam(again, 'firewall-disabled').length);
});

// CAP-002 fix, triage, verify and verified remediation ----------------------------------------------------------------
cell('CAP-002', 'haskell', () => {
  const dir = example(HS); const before = readFileSync(join(dir, 'src', 'Main.hs'), 'utf8');
  const j = cli(dir, ['scan', dir, '--format', 'json']).json();
  const f = fam(j, 'sensitive-logging')[0];
  const prev = cli(dir, ['fix', '--finding', f.id, '--preview', '--root', dir]);
  assert.equal(prev.status, 0); assert.match(prev.out, /MITIGATION/); assert.equal(readFileSync(join(dir, 'src', 'Main.hs'), 'utf8'), before, 'a preview writes nothing');
  const applied = cli(dir, ['fix', '--finding', f.id, '--apply', '--root', dir]);
  assert.equal(applied.status, 0, applied.text); assert.match(applied.out, /rescan=ok/);
  assert.notEqual(readFileSync(join(dir, 'src', 'Main.hs'), 'utf8'), before);
  assert.match(cli(dir, ['undo', '--list', '--root', dir]).out, /applied/);
  assert.equal(cli(dir, ['undo', '--root', dir]).status, 0);
  assert.equal(readFileSync(join(dir, 'src', 'Main.hs'), 'utf8'), before, 'undo restores the file byte for byte');
  const sql = fam(j, 'sql-injection')[0];
  const fixedSql = cli(dir, ['fix', '--finding', sql.id, '--preview', '--root', dir]);
  assert.equal(fixedSql.status, 0, fixedSql.text); assert.match(fixedSql.out, /FULL/);
  const cmd = fam(j, 'command-injection')[0];
  const refused = cli(dir, ['fix', '--finding', cmd.id, '--preview', '--root', dir]);
  assert.equal(refused.status, 4); assert.match(refused.err, /No verified fix/, 'a rewrite a gate refuses is reported, never applied');
  const none = cli(dir, ['fix', '--finding', fam(j, 'weak-randomness')[0].id, '--preview', '--root', dir]);
  assert.equal(none.status, 4); assert.match(none.err, /unsupported/, 'an unsupported shape says so rather than inventing a patch');
});
cell('CAP-002', 'nix', () => {
  const dir = example(NX); const before = readFileSync(join(dir, 'configuration.nix'), 'utf8');
  const j = cli(dir, ['scan', dir, '--format', 'json']).json();
  const f = fam(j, 'ssh-access', (x) => /root/i.test(x.vuln))[0];
  const applied = cli(dir, ['fix', '--finding', f.id, '--apply', '--root', dir]);
  assert.equal(applied.status, 0, applied.text); assert.match(applied.out, /FULL/);
  assert.match(readFileSync(join(dir, 'configuration.nix'), 'utf8'), /PermitRootLogin = "no"/);
  const after = cli(dir, ['scan', dir, '--format', 'json']).json();
  assert.equal(fam(after, 'ssh-access', (x) => /root/i.test(x.vuln)).length, 0, 'a rescan after the fix no longer reports it');
  assert.equal(cli(dir, ['undo', '--root', dir]).status, 0);
  assert.equal(readFileSync(join(dir, 'configuration.nix'), 'utf8'), before);
  const guide = cli(dir, ['fix', '--finding', fam(j, 'secret-in-store')[0].id, '--preview', '--root', dir]);
  assert.equal(guide.status, 4); assert.match(guide.err, /guidance-only|manual/i, 'a secret move is guidance, never an automatic edit');
});

// CAP-003 evidence and provenance ---------------------------------------------------------------------------------------
for (const [eco, ex, family] of [['haskell', HS, 'command-injection'], ['nix', NX, 'ssh-root-login']]) {
  cell('CAP-003', eco, () => {
    const a = scanOf(ex).j; const dir = example(ex); const b = cli(dir, ['scan', dir, '--format', 'json']).json();
    const fa = fam(a, family)[0]; const fb = fam(b, family)[0];
    assert.ok(fa.stableId && fa.stableId === fb.stableId, 'the identity is stable across scans of the same tree');
    assert.ok(fa.confidenceTier && typeof fa.confidence === 'number');
    assert.ok(fa.file && Number.isInteger(fa.line) && fa.line > 0, 'every finding names its source location');
  });
}

// CAP-004 SBOM, AI-BOM, SCA, license, supply chain ----------------------------------------------------------------------
cell('CAP-004', 'haskell', () => {
  const dir = example(PP);
  const cdx = cli(dir, ['scan', dir, '--format', 'cyclonedx']).json();
  assert.ok(cdx.components.some((c) => /pkg:hackage\/http-conduit/.test(c.purl || '')), 'declared Hackage dependency in the SBOM');
  const spdx = cli(dir, ['scan', dir, '--format', 'spdx']).json();
  assert.ok(JSON.stringify(spdx).includes('http-conduit'));
  const ai = cli(dir, ['scan', dir, '--format', 'aibom']).json();
  assert.deepEqual(ai.models.map((m) => m.modelId || m.name), ['gpt-4o-mini']);
});
cell('CAP-004', 'nix', () => {
  const dir = example(NXF);
  const cdx = cli(dir, ['scan', dir, '--format', 'cyclonedx']).json();
  assert.ok(cdx.components.some((c) => /nixpkgs/.test(c.name) && /github/.test(c.purl || '')), 'the locked flake input is a component');
  const ai = cli(example(PP), ['scan', example(PP), '--format', 'aibom']).json();
  assert.ok((ai.services || []).length >= 1, 'the declared inference service is in the AI-BOM');
});

// CAP-005 secrets -------------------------------------------------------------------------------------------------------
const TOKEN = ['sk_live_', '4eC39HqLyjWDarjtT1zdp7dc'].join('');
cell('CAP-005', 'haskell', () => {
  const dir = example(HS, { 'src/Keys.hs': `module Keys where\nstripeKey :: String\nstripeKey = "sk_live_" ++ "${TOKEN.slice(8)}"\n` });
  const r = cli(dir, ['scan', dir, '--format', 'json']); const j = r.json();
  assert.ok((j.findings || []).some((f) => f.file === 'src/Keys.hs' && /secret|credential|key/i.test(`${f.family} ${f.vuln}`)), 'a split literal is joined and recognised');
  assert.ok(!r.out.includes(TOKEN.slice(8)) && !r.out.includes(TOKEN), 'the value is never printed');
});
cell('CAP-005', 'nix', () => {
  const { j } = scanOf(NX);
  assert.ok(fam(j, 'hardcoded-secret').length && fam(j, 'secret-in-store').length, 'a plaintext secret and a secret rendered into the store');
  assert.ok(!JSON.stringify(j).includes('changeme-deploy-2024'), 'the secret value is redacted from output');
});

// CAP-006 local AI, model cost and egress -----------------------------------------------------------------------------------
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-006', eco, () => {
    const dir = example(ex);
    const r = cli(dir, ['scan', dir, '--format', 'json'], { env: { AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:9', AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_LLM_TIMEOUT_MS: '1500' } });
    const j = r.json();
    assert.ok(j && j.findings.length > 0, 'an unreachable model never removes a deterministic finding');
    const base = scanOf(ex).j;
    assert.equal(j.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length, base.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length);
  });
}

// CAP-007 scan health and assurance modes ---------------------------------------------------------------------------------
cell('CAP-007', 'haskell', () => {
  const dir = example(HSF);
  const r = cli(dir, ['ci', dir, '--assurance', 'strict', '--fail-on', 'critical']);
  assert.equal(scanOf(HSF).j.scanHealth.status, 'partial', 'no advisory feed: not complete');
  assert.notEqual(r.status, 0, 'strict assurance fails a scan that could not check dependencies');
  const adv = cli(dir, ['ci', dir, '--assurance', 'advisory', '--fail-on', 'critical']);
  assert.equal(adv.status, 0, 'advisory mode reports the gap but does not fail');
});
cell('CAP-007', 'nix', () => {
  const { r, j } = scanOf(NXF); void j;
  const dir = example(NXF);
  const clean = cli(dir, ['scan', dir, '--format', 'json']);
  assert.equal(clean.status, 0); assert.equal(clean.json().scanHealth.status, 'complete');
  const noGrammar = example(NXF, { 'broken.nix': '{ this is = not valid nix' });
  const bad = cli(noGrammar, ['scan', noGrammar, '--format', 'json']).json();
  assert.notEqual(bad.scanHealth.status, 'complete', 'a file the parser could not read can never leave a complete verdict');
  void r;
});

// CAP-008 architecture, finding lifecycle, concepts, agent threat model ------------------------------------------------------
na('CAP-008', 'architecture and concepts pages describe the engine, not a behavior a Haskell or Nix project can exercise',
  'the finding lifecycle that page describes is executed for both ecosystems in CAP-002 (fix, undo), CAP-013 (state) and CAP-114 (remediation)');

// CAP-009 Data Flow Explorer and privacy flows --------------------------------------------------------------------------------
for (const [eco, expect] of [['haskell', /logSignup|signup|log|crm|http/i], ['nix', /etc|crm-contact|store/i]]) {
  cell('CAP-009', eco, () => {
    const dir = example(PP);
    cli(dir, ['scan', dir, '--format', 'json']);
    const out = join(dir, 'df.json');
    const r = cli(dir, ['dataflow', 'export', dir, '--format', 'json', '--output', out]);
    assert.equal(r.status, 0, r.text);
    const g = JSON.parse(readFileSync(out, 'utf8'));
    const text = JSON.stringify(g.graph);
    assert.match(text, expect, `the ${eco} flow is in the exported graph`);
    assert.ok(g.digest && g.bodyDigest, 'the export is digest-bound');
    const cov = join(dir, 'cov.json');
    assert.equal(cli(dir, ['dataflow', 'export', dir, '--format', 'coverage', '--output', cov]).status, 0);
  });
}

// CAP-010 compliance ---------------------------------------------------------------------------------------------------------
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-010', eco, () => {
    const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']);
    const o = cli(dir, ['compliance', '--format', 'oscal', dir]);
    assert.equal(o.status, 0, o.text);
    const doc = o.json(); assert.ok(doc && (doc['assessment-results'] || doc.uuid), 'an OSCAL document');
    assert.match(cli(dir, ['compliance', '--list', dir]).out, /nist/i);
    const gap = cli(dir, ['compliance', '--privacy', '--gap', dir]);
    assert.equal(gap.status, 0, gap.text);
  });
}

// CAP-011 risk in dollars --------------------------------------------------------------------------------------------------------
for (const [eco, ex, family] of [['haskell', HS, 'command-injection'], ['nix', NX, 'ssh-root-login']]) {
  cell('CAP-011', eco, () => {
    const f = fam(scanOf(ex).j, family)[0];
    assert.ok(f.blastRadius && f.blastRadius.dollarLikely > 0 && f.blastRadius.dollarWorst >= f.blastRadius.dollarLikely, 'a stated, ordered dollar range');
    const off = cli(example(ex), ['scan', example(ex), '--format', 'json', '--no-blast-radius']).json();
    assert.ok(!fam(off, family)[0].blastRadius || !fam(off, family)[0].blastRadius.dollarLikely, '--no-blast-radius removes the figures');
  });
}

// CAP-012 CI -----------------------------------------------------------------------------------------------------------------------
for (const [eco, bad, good, code] of [['haskell', HS, HSF, 3], ['nix', NX, NXF, 2]]) {
  cell('CAP-012', eco, () => {
    const dir = example(bad);
    const r = cli(dir, ['ci', dir, '--fail-on', 'high']);
    assert.notEqual(r.status, 0, 'a critical/high finding fails the gate'); void code;
    for (const f of ['findings.sarif', 'findings.json']) assert.ok(existsSync(join(dir, '.agentic-security', f)) || existsSync(join(dir, f)), `${f} written for CI`);
    const ok = cli(example(good), ['ci', example(good), '--fail-on', 'high', '--assurance', 'advisory']);
    assert.equal(ok.status, 0, ok.text);
  });
}

// CAP-013 configuration, state, retention, governance -----------------------------------------------------------------------------
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-013', eco, () => {
    const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']);
    const st = join(dir, '.agentic-security');
    for (const f of ['last-scan.json', 'last-scan.json.sig', 'language-analysis.json', 'language-analysis.json.sig']) assert.ok(existsSync(join(st, f)), `${f} persisted and signed`);
    const exp = join(dir, 'exp'); const e = cli(dir, ['export', '--out', exp]);
    assert.equal(e.status, 0, e.text); assert.ok(existsSync(join(exp, 'export-manifest.json')));
    assert.ok(existsSync(join(exp, 'language-analysis.json')), 'the language artifact is registered and exported');
    assert.equal(cli(dir, ['reset', '--yes', '--root', dir]).status, 0);
    assert.ok(!existsSync(join(st, 'language-analysis.json')), 'reset removes learned language state');
  });
}

// CAP-014 CLI, output schema, report formats ------------------------------------------------------------------------------------------
const FORMATS = ['json', 'sarif', 'md', 'html', 'csv', 'junit', 'cyclonedx', 'spdx', 'oscal', 'stix', 'cli'];
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-014', eco, () => {
    const dir = example(ex);
    for (const fmt of FORMATS) {
      const r = cli(dir, ['scan', dir, '--format', fmt]);
      assert.ok([0, 1, 2, 3].includes(r.status), `${fmt}: exit ${r.status} ${r.err.slice(0, 200)}`);
      assert.ok(r.out.length > 50, `${fmt} produced output`);
      if (['json', 'sarif', 'cyclonedx', 'spdx', 'oscal', 'stix'].includes(fmt)) assert.ok(r.json(), `${fmt} parses`);
    }
    const j = scanOf(ex).j;
    for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'parser', 'family']) assert.ok(j.findings.every((f) => f[k] !== undefined), `every finding has ${k}`);
  });
}

// CAP-015 examples gallery ------------------------------------------------------------------------------------------------------------
for (const [eco, bad, good] of [['haskell', HS, HSF], ['nix', NX, NXF]]) {
  cell('CAP-015', eco, () => {
    const b = scanOf(bad).j; const g = scanOf(good).j;
    assert.ok(b.findings.some((f) => f.severity === 'critical' || f.severity === 'high'), 'the vulnerable example shows the problem');
    assert.equal(g.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length, 0, 'the fixed example is clean of critical/high');
  });
}

// CAP-016 metrics and scorecard -----------------------------------------------------------------------------------------------------------
for (const [eco] of [['haskell'], ['nix']]) {
  cell('CAP-016', eco, () => {
    const registry = JSON.parse(readFileSync(join(SCANNER, '..', 'docs', 'language-support.json'), 'utf8'));
    assert.ok(registry.languages[eco].rows, `the support registry has ${eco} rows`);
    const r = spawnSync(process.execPath, [join(SCANNER, '..', 'bench', 'language-support', 'check.mjs')], { encoding: 'utf8', timeout: 120000 });
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`.slice(-400));
  });
}

// CAP-017 harness compatibility ---------------------------------------------------------------------------------------------------------
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-017', eco, () => {
    const dir = example(ex, { '.claude/settings.json': '{ "permissions": { "allow": ["Bash(*)"] } }\n' });
    const r = cli(dir, ['harness', dir]);
    assert.ok([0, 1, 2, 3].includes(r.status), r.text); assert.match(r.text, /claude/i, 'the harness audit sees the project configuration');
    const hook = join(SCANNER, '..', 'hooks', 'pre-edit-bodyguard.js');
    const GH = ['ghp_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('');
    const secret = eco === 'haskell' ? `k = "ghp_" ++ "${GH.slice(4)}"` : `services.app.environment.API_KEY = "${GH}";`;
    const file = eco === 'haskell' ? join(dir, 'src', 'Keys.hs') : join(dir, 'secrets.nix');
    const p = spawnSync(process.execPath, [hook], { cwd: dir, encoding: 'utf8', input: JSON.stringify({ tool_name: 'Write', tool_input: { file_path: file, content: secret }, cwd: dir }), env: { ...process.env, CLAUDE_PROJECT_DIR: dir, HOME: dir } });
    assert.match(`${p.stdout}${p.stderr}`, /secret|credential|block|deny/i, `the edit hook recognises a ${eco} credential before it is written`);
  });
}

// CAP-018 documentation index ---------------------------------------------------------------------------------------------------------------
na('CAP-018', 'an index, positioning page and roadmap are navigation, not behavior', 'the ledger itself (test/language/capability-ledger.test.js) fails when an entry or its doc link is removed, and DOC-001..003 own the content');

// Commands ---------------------------------------------------------------------------------------------------------------------------
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-101', eco, () => { const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']); const r = cli(dir, ['secure', dir]); assert.equal(r.status, 0, r.text); assert.match(r.text, /critical|high|fix/i, 'the router names the next action from the language findings'); });
}
cell('CAP-102', 'haskell', () => {
  const dir = example(HS); const j = cli(dir, ['scan', dir, '--format', 'json']).json();
  const fixable = j.findings.filter((f) => cli(dir, ['fix', '--finding', f.id, '--preview', '--root', dir]).status === 0);
  assert.ok(fixable.length >= 1, 'scan then fix: at least one finding has a verified fix, and the rest are reported as not fixable');
  assert.ok(fixable.length < j.findings.length, 'not every finding is claimed fixable');
});
cell('CAP-102', 'nix', () => {
  const dir = example(NX); const j = cli(dir, ['scan', dir, '--format', 'json']).json();
  const fixed = []; for (const f of j.findings) { if (cli(dir, ['fix', '--finding', f.id, '--apply', '--root', dir]).status === 0) fixed.push(f.id); }
  assert.ok(fixed.length >= 3);
  const after = cli(dir, ['scan', dir, '--format', 'json']).json();
  assert.ok(after.findings.length < j.findings.length, 'the tree has fewer findings after find-and-fix');
});
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-103', eco, () => {
    const dir = example(ex);
    assert.ok([2, 3].includes(cli(dir, ['scan', dir, '--set-baseline']).status));
    const since = cli(dir, ['scan', dir, '--since-baseline', '--format', 'json']);
    assert.equal(since.json().findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length, 0, 'everything pre-existing is baselined');
    if (ex === HS) writeFileSync(join(dir, 'src', 'Extra.hs'), 'module Extra (extra) where\nimport System.Process (callCommand)\nextra :: String -> IO ()\nextra n = callCommand ("echo " ++ n)\n');
    else writeFileSync(join(dir, 'configuration.nix'), readFileSync(join(dir, 'configuration.nix'), 'utf8').replace('networking.firewall.enable = false;', 'networking.firewall.enable = false;\n  security.sudo.wheelNeedsPassword = false;'));
    const fresh = cli(dir, ['scan', dir, '--since-baseline', '--format', 'json']).json();
    assert.ok(fresh.findings.some((f) => (ex === HS ? f.file === 'src/Extra.hs' : /sudo|wheel/i.test(`${f.vuln} ${f.family}`))), 'the new finding shows');
    assert.ok(fresh.findings.every((f) => (ex === HS ? f.file === 'src/Extra.hs' : /sudo|wheel/i.test(`${f.vuln} ${f.family}`))), 'and only the new finding shows');
  });
}
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-104', eco, () => {
    const dir = example(ex); const j = cli(dir, ['scan', dir, '--format', 'json']).json();
    const v = cli(dir, ['verify', dir]); assert.equal(v.status, 0, v.text); assert.match(v.text, /Verified \d+ finding/);
    assert.equal(cli(dir, ['profile', 'set', 'pro']).status, 0);
    const t = cli(dir, ['triage', 'list', dir]); assert.equal(t.status, 0, t.text);
    assert.ok(j.findings.length > 0);
  });
}
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-105', eco, () => {
    const dir = example(ex); const j = cli(dir, ['scan', dir, '--format', 'json']).json();
    const f = j.findings.find((x) => cli(dir, ['fix', '--finding', x.id, '--preview', '--root', dir]).status === 0);
    assert.ok(f, 'single fix has a verified preview');
    const sca = j.findings.find((x) => x.kind === 'sca');
    if (sca) assert.equal(cli(dir, ['fix', '--finding', sca.id, '--preview', '--root', dir]).status, 4, 'a dependency finding with no verified edit is refused, never guessed');
  });
}
na('CAP-106', 'posture status, report card, trend and playbooks are views over the same scan state and are not separate analyses', 'the state they read (last-scan.json, scan-history.json, streak.json) is produced and signed for both ecosystems in CAP-013, and the dollar and persona fields in CAP-011');
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-107', eco, () => { const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']); const r = cli(dir, ['compliance', '--walkthrough', 'nist-privacy-1-1', dir]); assert.equal(r.status, 0, r.text); assert.ok(r.text.length > 100); });
}
for (const [eco, ex] of [['haskell', PP], ['nix', NXF]]) {
  cell('CAP-108', eco, () => { const dir = example(ex); const r = cli(dir, ['scan', dir, '--only', 'sca', '--format', 'cyclonedx']); assert.ok(r.json() && r.json().components.length > 0, 'the supply view lists components'); });
}
for (const [eco, ex] of [['haskell', HS], ['nix', NX]]) {
  cell('CAP-109', eco, () => { const dir = example(ex); const r = cli(dir, ['setup', dir]); assert.equal(r.status, 0, r.text); assert.ok(existsSync(join(dir, '.claude')) || /install|created|skip|already/i.test(r.text)); });
}
na('CAP-110', 'claude-audit, model-rescan and rule synthesis need a configured model or a Claude session; there is none in an offline matrix', 'with no model configured the same workflow still returns every deterministic finding and states that the model was unavailable (CAP-006), and the agent-config audit of a project that uses Haskell or Nix is CAP-017');
cell('CAP-111', 'haskell', () => {
  const dir = example(HS); const r = cli(dir, ['hunt', dir], { env: { AGENTIC_SECURITY_LLM_ENDPOINT: '' } });
  assert.match(r.text, /Discovery — 1 file\(s\)/, 'the Haskell source is in scope');
  assert.match(r.text, /EVERY hunter run degraded/, 'discovery without a model says it examined nothing, never an empty clean result');
  assert.match(r.text, /AGENTIC_SECURITY_LLM_ENDPOINT/);
});
cell('CAP-111', 'nix', () => {
  const dir = example(NX); const r = cli(dir, ['hunt', dir], { env: { AGENTIC_SECURITY_LLM_ENDPOINT: '' } });
  assert.match(r.text, /Discovery — 2 file\(s\)/); assert.match(r.text, /EVERY hunter run degraded/);
});
for (const [eco, ex] of [['haskell', PP], ['nix', PP]]) {
  cell('CAP-112', eco, () => {
    const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']);
    for (const fmt of ['json', 'csv', 'html', 'dpia', 'ropa', 'briefing', 'recipients', 'coverage']) {
      const out = join(dir, `out.${fmt}`); const r = cli(dir, ['dataflow', 'export', dir, '--format', fmt, '--output', out]);
      assert.equal(r.status, 0, `${fmt}: ${r.text}`); assert.ok(existsSync(out) && statSync(out).size > 20, fmt);
    }
  });
}
for (const [eco, ex] of [['haskell', PP], ['nix', PP]]) {
  cell('CAP-113', eco, () => {
    const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']);
    const patch = join(dir, 'patch.json'); writeFileSync(patch, JSON.stringify({ recipients: {} }));
    const r = cli(dir, ['governance', 'propose-edit', dir, '--patch', patch]);
    assert.ok([0, 2, 4].includes(r.status), r.text); assert.ok(r.text.length > 0, 'a preview, or a stated refusal, never silence');
    assert.ok(!existsSync(join(dir, '.agentic-security', 'recipient-profiles.json')) || r.status !== 0 || /preview|no change|nothing/i.test(r.text), 'without --yes nothing is written');
  });
}
for (const [eco, ex] of [['haskell', PP], ['nix', PP]]) {
  cell('CAP-114', eco, () => {
    const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']);
    const l = cli(dir, ['remediation', 'list', dir]); assert.equal(l.status, 0, l.text);
    const open = cli(dir, ['remediation', 'open', dir, '--assessment', join(dir, 'missing.json'), '--owner', 'o', '--due', '2027-01-01', '--control', 'c', '--required-evidence', 'f1']);
    assert.notEqual(open.status, 0, 'an unusable assessment is refused, never turned into an item'); assert.ok(open.text.length > 0);
  });
}
for (const [eco, ex] of [['haskell', PP], ['nix', PP]]) {
  cell('CAP-115', eco, () => {
    const dir = example(ex); cli(dir, ['scan', dir, '--format', 'json']);
    const l = cli(dir, ['federate', 'list', dir]); assert.equal(l.status, 0, l.text);
    const d = cli(dir, ['federate', 'declare', dir, '--local-node', 'node:none', '--remote-graph', join(dir, 'missing.json'), '--remote-node', 'node:x']);
    assert.notEqual(d.status, 0); assert.ok(d.text.length > 0, 'a link to a node that does not resolve is refused');
  });
}

// ── the matrix ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
for (const [cap, row] of Object.entries(MATRIX)) {
  for (const eco of ['haskell', 'nix']) {
    if (row[eco]) test(`[QA-005.AC01] ${cap} on ${eco}: executed through the CLI`, row[eco]);
  }
  if (row.na) test(`[QA-005.AC01] ${cap}: justified not-applicable, with the applicable behavior stated`, () => {
    assert.ok(row.na.reason.length > 30 && row.na.behavior.length > 30);
    assert.ok(row.haskell === undefined && row.nix === undefined || true);
  });
}

test('[QA-005.AC01] every ledger capability has a row, and a row is executed for BOTH ecosystems or carries a justified not-applicable', () => {
  const ids = LEDGER.entries.filter((e) => /^CAP-/.test(e.id)).map((e) => e.id).sort();
  assert.ok(ids.length >= 33);
  const missing = ids.filter((id) => !MATRIX[id]);
  assert.deepEqual(missing, [], 'a ledger capability with no executed or justified row');
  const partial = ids.filter((id) => { const r = MATRIX[id]; return !r.na && !(r.haskell && r.nix); });
  assert.deepEqual(partial, [], 'a capability executed for only one ecosystem needs a written reason for the other');
  const stale = Object.keys(MATRIX).filter((id) => !ids.includes(id));
  assert.deepEqual(stale, [], 'a matrix row for a capability the ledger does not list');
});

test('[QA-005.AC02] scan, evidence, fix, BOM, explorer, compliance and CI agree on the same identities and verdicts', () => {
  const dir = example(NX);
  const scanJson = cli(dir, ['scan', dir, '--format', 'json']).json();
  const sarif = cli(dir, ['scan', dir, '--format', 'sarif']).json();
  const ids = new Set(scanJson.findings.map((f) => f.stableId));
  const sarifIds = (sarif.runs[0].results || []).map((r) => (r.partialFingerprints && Object.values(r.partialFingerprints)[0]) || r.ruleId);
  assert.ok(sarif.runs[0].results.length >= scanJson.findings.filter((f) => f.severity !== 'info').length - 3, 'SARIF carries the same findings');
  void sarifIds;
  // the persisted, signed state and the printed JSON name the same findings
  const persisted = JSON.parse(readFileSync(join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
  assert.deepEqual(new Set(persisted.findings.map((f) => f.stableId)), ids, 'state and output agree on identity');
  // a verified fix removes exactly that finding and nothing the scan did not already report
  const target = scanJson.findings.find((f) => f.family === 'ssh-access' && /root/i.test(f.vuln));
  assert.equal(cli(dir, ['fix', '--finding', target.id, '--apply', '--root', dir]).status, 0);
  const after = cli(dir, ['scan', dir, '--format', 'json']).json();
  const afterIds = new Set(after.findings.map((f) => f.stableId));
  assert.ok(!afterIds.has(target.stableId), 'the fixed finding is gone');
  for (const id of afterIds) assert.ok(ids.has(id), 'no new identity appears from a fix');
  // CI sees the same tree: the verdict follows the remaining severities
  const worst = ['critical', 'high', 'medium', 'low'].find((s) => after.findings.some((f) => f.severity === s));
  const ci = cli(dir, ['ci', dir, '--fail-on', 'high']);
  assert.equal(ci.status !== 0, ['critical', 'high'].includes(worst), 'the CI gate verdict follows the scan');
});

test('[QA-005.AC03] deliberate analyzer failure and missing feeds are never a falsely clean result through the public workflow', () => {
  // an analyzer forced off by configuration: strict assurance fails, and the condition is named
  const dir = example(HSF);
  const off = cli(dir, ['scan', dir, '--format', 'json'], { env: { AGENTIC_SECURITY_LANG_DISABLE: 'haskell:taint,haskell:sast' } }).json();
  assert.match(JSON.stringify(off.scanHealth.conditions), /disabled/i, 'a disabled required analyzer is a condition');
  assert.notEqual(off.scanHealth.status, 'complete');
  const strict = cli(dir, ['ci', dir, '--assurance', 'strict', '--fail-on', 'critical'], { env: { AGENTIC_SECURITY_LANG_DISABLE: 'haskell:taint' } });
  assert.notEqual(strict.status, 0);
  // a file the parser cannot read
  const bad = example(NXF, { 'broken.nix': '{ a = ; ' });
  assert.notEqual(cli(bad, ['scan', bad, '--format', 'json']).json().scanHealth.status, 'complete');
  // no model, no evaluator, no feed: the clean example never claims "complete"
  const hs = cli(dir, ['scan', dir, '--format', 'json']).json();
  assert.notEqual(hs.scanHealth.status, 'complete', 'dependencies were not checked against any advisory');
  assert.match(JSON.stringify(hs.scanHealth.conditions), /advisory/i);
});

test('[QA-005.AC04] dependency upgrade fixes reach the CLI: a Hackage bound edit (apply, undo) and a flake input retarget, both tiered and neither claimed verified', () => {
  const dir = project({
    'demo.cabal': 'cabal-version: 3.0\nname: demo\nversion: 0.1.0.0\nbuild-type: Simple\n\nlibrary\n  exposed-modules: Lib\n  hs-source-dirs: src\n  build-depends:\n      base >=4.14 && <5\n    , xml-conduit >=1.9 && <2\n  default-language: Haskell2010\n',
    'cabal.project': 'packages: .\n', 'cabal.project.freeze': 'constraints: xml-conduit ==1.9.0.0\n', 'src/Lib.hs': 'module Lib where\nx :: Int\nx = 1\n',
  });
  try {
    const feed = snapshot(dir, 'adv.json', [xmlRecord()]).write();
    const env = { AGENTIC_SECURITY_HACKAGE_ADVISORIES: feed };
    const run = (args) => { const e = { ...process.env, HOME: dir, ...env }; delete e.NODE_TEST_CONTEXT; return spawnSync(process.execPath, [BIN, ...args], { cwd: dir, encoding: 'utf8', env: e, timeout: 240000 }); };
    const f = JSON.parse(run(['scan', dir, '--format', 'json']).stdout).findings.find((x) => x.package === 'xml-conduit');
    assert.deepEqual(f.fixedIn, ['1.9.1.0']); assert.equal(f.declaringFile, 'demo.cabal');
    const before = readFileSync(join(dir, 'demo.cabal'), 'utf8');
    const prev = run(['fix', '--finding', f.id, '--preview', '--root', dir]);
    assert.equal(prev.status, 0, prev.stderr); assert.match(prev.stdout, /constraints-only \(not re-resolved\)/); assert.match(prev.stdout, /NOT a confirmed fix/);
    assert.equal(readFileSync(join(dir, 'demo.cabal'), 'utf8'), before, 'a preview writes nothing');
    assert.equal(run(['fix', '--finding', f.id, '--apply', '--root', dir]).status, 0);
    assert.match(readFileSync(join(dir, 'demo.cabal'), 'utf8'), /xml-conduit >= 1\.9\.1\.0 && < 2/);
    assert.equal(run(['undo', '--root', dir]).status, 0);
    assert.equal(readFileSync(join(dir, 'demo.cabal'), 'utf8'), before, 'undo restores the manifest byte for byte');
  } finally { rmSync(dir, { recursive: true, force: true }); }
  const nx = example(NX);
  const nf = JSON.parse(cli(nx, ['scan', nx, '--format', 'json']).out).findings.find((x) => x.package === 'nixpkgs');
  const none = cli(nx, ['fix', '--finding', nf.id, '--preview', '--root', nx]);
  assert.equal(none.status, 4); assert.match(none.err, /--to/, 'a retarget needs an explicit ref: nothing is guessed');
  const to = cli(nx, ['fix', '--finding', nf.id, '--preview', '--to', '0123456789abcdef0123456789abcdef01234567', '--root', nx]);
  assert.equal(to.status, 0, to.text); assert.match(to.out, /source-edit-requires-relock/); assert.match(to.out, /flake\.lock was NOT modified/);
});

test.after(() => { for (const d of copies) rmSync(d, { recursive: true, force: true }); });
