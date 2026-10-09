// QA-003: resource budgets, adversarial inputs and offline behavior for Haskell and Nix. Tests are tagged [QA-003.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/runScan.js';
import { measureAll, profile } from '../../../bench/language-support/perf.mjs';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const BLOCK_NET = path.join(HERE, 'helpers', 'block-network.cjs');

const mk = (files) => {
  const d = fs.realpathSync(mkTestTmp('qa003-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{}');
  for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), t); }
  return d;
};
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const cliScan = (d, args = [], env = {}, timeout = 120000) => spawnSync(process.execPath, [CLI, 'scan', d, '--format', 'json', ...args], { encoding: 'utf8', timeout, maxBuffer: 1 << 27, env: { ...process.env, NO_COLOR: '1', ...env } });
const json = (r) => { try { return JSON.parse(r.stdout); } catch { return null; } };
const lines = (n, open, close, mid) => `${Array.from({ length: n }, () => open).join('\n')}\n${mid}\n${Array.from({ length: n }, () => close).join('\n')}`;

// ── AC01: performance and resource budgets ───────────────────────────────────────────────────────────────────
test('[QA-003.AC01] a mixed 2,000-file / 20 MiB fixture: cold <= 180 s, peak memory < 2 GiB, three cold and three warm runs, a 10-file incremental under 15 s', { timeout: 1_800_000 }, () => {
  const root = mkTestTmp('qa003-perf-');
  try {
    const r = measureAll(root);
    const prof = profile();
    assert.equal(r.fixture.files, 2000);
    assert.ok(r.fixture.bytes >= 19 * 1024 * 1024 && r.fixture.bytes <= 22 * 1024 * 1024, `fixture is ~20 MiB (${r.fixture.bytes})`);
    assert.equal(r.cold.length, 3); assert.equal(r.warm.length, 3);
    for (const x of [...r.cold, ...r.warm]) assert.ok([0, 1, 2, 3].includes(x.exit), `scan exited ${x.exit}`);
    assert.ok(r.coldMaxMs <= 180_000, `cold scan ${r.coldMaxMs} ms on ${prof.platform}/${prof.arch}, ${prof.logicalCpus} cpus`);
    assert.ok(r.coldP95Ms <= 180_000 && r.warmP95Ms <= 180_000);
    assert.ok(r.peakRssBytes > 0, 'peak resident memory was measured');
    assert.ok(r.peakRssBytes < 2 * 1024 ** 3, `peak RSS ${(r.peakRssBytes / 1024 ** 3).toFixed(2)} GiB must be below 2 GiB`);
    assert.ok(r.incremental.ms <= 15_000, `10-file incremental took ${r.incremental.ms} ms`);
    assert.ok(prof.node && /^v2[4-9]|^v[3-9]\d/.test(prof.node), 'Node 24 or newer');
  } finally { rm(root); }
});

test('[QA-003.AC01] a budget overrun reports partial with the resource limit named, and a scan under attack stays inside a cleanup deadline', async () => {
  const cases = {
    // recursion beyond the parser nesting budget
    deepNesting: { files: { 'deep.nix': `{ a =\n${lines(8000, '(', ')', '1')};\n}\n`, 'Deep.hs': `module A where\nx :: Int\nx =\n${lines(8000, '  (', ')', '  1')}\n` }, expect: /unresolved language construct/ },
    // malformed syntax and binary noise
    garbage: { files: { 'g.hs': Buffer.from(Array.from({ length: 60000 }, (_, i) => (i * 7919) % 256)).toString('latin1'), 'g.nix': '\u0000\u0001{{{{ }}}} ${ ${ ${ "\n'.repeat(500) }, expect: /unresolved language construct/ },
    // a flake.lock far over the manifest read cap
    hugeLock: { files: { 'flake.nix': '{ inputs.a.url = "github:x/a"; outputs = _: {}; }', 'flake.lock': JSON.stringify({ nodes: Object.fromEntries([['root', { inputs: { a: 'n0' } }], ...Array.from({ length: 60000 }, (_, i) => [`n${i}`, { locked: { type: 'github', owner: 'x', repo: `r${i}`, rev: 'a'.repeat(40), narHash: `sha256-${'A'.repeat(43)}=` }, original: { type: 'github', owner: 'x', repo: `r${i}` }, inputs: i % 3 === 0 ? { x: `n${i + 1}` } : {} }])]), root: 'root', version: 7 }) }, expect: /exceed the size cap and were not analysed: flake\.lock/ },
  };
  for (const [name, c] of Object.entries(cases)) {
    const d = mk(c.files);
    try {
      const t0 = Date.now();
      const r = await runScan(d, { deep: true });
      const ms = Date.now() - t0;
      const h = r.scan.scanHealth;
      assert.ok(ms < 60_000, `${name}: finished in ${ms} ms`);
      assert.equal(h.status, 'partial', `${name}: an overrun is partial, never complete`);
      assert.ok((h.conditions || []).some((x) => c.expect.test(x)), `${name}: the limit is named: ${JSON.stringify(h.conditions)}`);
      assert.ok(r.scan.findings !== undefined, `${name}: the scan still returned its result`);
    } finally { rm(d); }
  }
});

test('[QA-003.AC01] import cycles, lazy recursion and dynamic imports finish and stay disclosed, and the other analyzers still report', async () => {
  const d = mk({
    'A.hs': 'module A where\nimport B\na = b\n', 'B.hs': 'module B where\nimport A\nimport System.Process (callCommand)\nb = a\nrun :: String -> IO ()\nrun s = callCommand s\n',
    'x.nix': '{ imports = [ ./y.nix ]; }', 'y.nix': '{ imports = [ ./x.nix ]; services.openssh.enable = true; services.openssh.settings.PermitRootLogin = "yes"; }',
    'configuration.nix': '{ imports = [ ./y.nix ]; }', 'rec.nix': '{ a = b; b = a; c = rec { x = y; y = x; }; }',
  });
  try {
    const t0 = Date.now();
    const r = await runScan(d, { deep: true });
    assert.ok(Date.now() - t0 < 60_000);
    assert.ok(r.scan.findings.some((f) => f.rule === 'ssh-root-login'), 'the Nix analyzer still reports through a cycle');
    assert.ok(r.scan.findings.some((f) => f.cwe === 'CWE-78' && /B\.hs$/.test(f.file)), 'the Haskell analyzer still reports in a module that is part of a cycle');
    assert.equal(r.scan.scanHealth.status, 'partial');
  } finally { rm(d); }
});

// ── AC02: offline behavior ───────────────────────────────────────────────────────────────────────────────────
test('[QA-003.AC02] an offline scan reports its known findings, states the feed limitation, makes no network attempt and needs no GHC, nix or model', () => {
  const d = mk({
    'src/App.hs': 'module App where\nimport System.Process (callCommand)\n\nrun :: IO ()\nrun = do\n  name <- getLine\n  callCommand ("echo " ++ name)\n',
    'app.cabal': 'cabal-version: 3.0\nname: app\nversion: 0.1.0.0\nlibrary\n  build-depends: base, aeson >=2.1\n',
    'configuration.nix': '{ ... }:\n{\n  services.openssh.enable = true;\n  services.openssh.settings.PermitRootLogin = "yes";\n}\n',
  });
  const log = path.join(d, 'net.log');
  try {
    // PATH holds only the directory of this node binary: no ghc, cabal, stack, nix, git or model tool is reachable
    const r = cliScan(d, [], { AGENTIC_SECURITY_NET_LOG: log, NODE_OPTIONS: `--require ${BLOCK_NET}`, PATH: path.dirname(process.execPath), AGENTIC_SECURITY_LLM_ENDPOINT: '', AGENTIC_SECURITY_OFFLINE: '1' });
    const out = json(r);
    assert.ok(out, `scan produced JSON (exit ${r.status}) ${String(r.stderr).slice(-300)}`);
    assert.ok(out.findings.some((f) => f.cwe === 'CWE-78' && /App\.hs$/.test(f.file)), 'the Haskell finding is there');
    assert.ok(out.findings.some((f) => f.rule === 'ssh-root-login'), 'the Nix finding is there');
    const conds = out.scanHealth.conditions || [];
    assert.ok(conds.some((c) => /no Hackage advisory snapshot is loaded/.test(c)), `the missing advisory feed is stated: ${JSON.stringify(conds)}`);
    assert.notEqual(out.scanHealth.status, 'complete', 'an absent feed is never a complete scan');
    const attempts = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim() : '';
    assert.equal(attempts, '', `no network attempt was made:\n${attempts}`);
  } finally { rm(d); }
});

// ── AC03: attacker-controlled paths ─────────────────────────────────────────────────────────────────────────
test('[QA-003.AC03] symlinks and path tricks cannot make the scan read outside the root, and nothing from a hostile tree is executed', () => {
  const outside = mkTestTmp('qa003-out-');
  const marker = path.join(os.tmpdir(), `qa003-pwned-${process.pid}`);
  fs.writeFileSync(path.join(outside, 'Secret.hs'), 'module Secret where\nimport System.Process\nz :: String -> IO ()\nz s = callCommand s\n');
  fs.writeFileSync(path.join(outside, 'secret.nix'), '{ services.openssh.enable = true; services.openssh.settings.PermitRootLogin = "yes"; }');
  const d = mk({
    'ok.hs': 'module Ok where\nok :: Int\nok = 1\n',
    'T.hs': `{-# LANGUAGE TemplateHaskell #-}\nmodule T where\nimport Language.Haskell.TH\n$(runIO (writeFile "${marker}" "pwned") >> return [])\n`,
    'flake.nix': `{ outputs = { self }: { x = builtins.exec [ "touch" "${marker}-nix" ]; y = import /etc/passwd; z = import ../../../../etc/shadow; w = import (builtins.fetchTarball "http://169.254.169.254/x"); }; }`,
    'cabal.project': 'packages: /etc/* ../../../outside/*.cabal\n',
    'app.cabal': 'cabal-version: 3.0\nname: app\nversion: 1\nlibrary\n  build-depends: base\n  hs-source-dirs: /etc, ../../..\n',
    'stack.yaml': 'resolver: lts-22.12\npackages:\n  - ../../../etc\nextra-deps:\n  - /etc/passwd\n',
  });
  try {
    fs.symlinkSync(path.join(outside, 'Secret.hs'), path.join(d, 'Link.hs'));
    fs.symlinkSync(path.join(outside, 'secret.nix'), path.join(d, 'configuration.nix'));
    fs.symlinkSync(outside, path.join(d, 'linkdir'));
    const r = cliScan(d);
    const out = json(r);
    assert.ok(out, `scan produced JSON: ${String(r.stderr).slice(-300)}`);
    for (const f of [...out.findings, ...(out.supplyChain || [])]) assert.ok(!/Secret|secret\.nix|linkdir|\/etc\//.test(String(f.file)), `a finding names a path outside the root: ${f.file}`);
    assert.ok(!out.findings.some((f) => f.rule === 'ssh-root-login'), 'a symlinked configuration.nix outside the root was not read');
    assert.ok(!fs.existsSync(marker) && !fs.existsSync(`${marker}-nix`), 'neither a Template Haskell splice nor builtins.exec was executed');
  } finally { rm(d); rm(outside); for (const m of [marker, `${marker}-nix`]) fs.rmSync(m, { force: true }); }
});

test('[QA-003.AC03] a symlinked state directory or file cannot redirect or overwrite evidence', () => {
  const outside = mkTestTmp('qa003-state-');
  const victim = path.join(outside, 'victim.txt');
  fs.writeFileSync(victim, 'original');
  const d = mk({ 'A.hs': 'module A where\nimport System.Process\nz :: String -> IO ()\nz s = callCommand s\n' });
  try {
    // the whole state directory is a link to somewhere else
    fs.symlinkSync(outside, path.join(d, '.agentic-security'));
    cliScan(d);
    assert.deepEqual(fs.readdirSync(outside).sort(), ['victim.txt'], 'nothing was written through the linked state directory');
    fs.unlinkSync(path.join(d, '.agentic-security'));
    // a single evidence file is a link to a victim file
    fs.mkdirSync(path.join(d, '.agentic-security'));
    fs.symlinkSync(victim, path.join(d, '.agentic-security', 'last-scan.json'));
    cliScan(d);
    assert.equal(fs.readFileSync(victim, 'utf8'), 'original', 'a linked evidence file was not overwritten');
  } finally { rm(d); rm(outside); }
});

test('[QA-003.AC03] a fix target outside the root is refused before any gate runs', async () => {
  const { isRootRelativePath } = await import('../../src/language/fix-lifecycle.js');
  for (const bad of ['../x.hs', '../../etc/passwd', '/etc/passwd', 'a/../../b.nix', 'C:/Windows/x', '', 'a\u0000b']) assert.equal(isRootRelativePath(bad), false, JSON.stringify(bad));
  for (const good of ['src/Svc.hs', 'configuration.nix', 'a/b/c.nix']) assert.equal(isRootRelativePath(good), true);
});

// ── AC04: cancellation, crashes and responsiveness ────────────────────────────────────────────────────────────
test('[QA-003.AC04] cancelling a scan mid-run exits within the deadline and leaves no corrupt or unsigned state', { timeout: 300_000 }, async () => {
  const root = mkTestTmp('qa003-cancel-');
  const { generateFixture } = await import('../../../bench/language-support/perf.mjs');
  try {
    generateFixture(root, 600, 6 * 1024 * 1024);
    const c = spawn(process.execPath, [CLI, 'scan', root, '--format', 'json'], { stdio: ['ignore', 'pipe', 'pipe'] });
    c.stdout.resume(); c.stderr.resume();
    const t0 = Date.now();
    await new Promise((r) => setTimeout(r, 2500));
    c.kill('SIGTERM');
    const code = await new Promise((r) => c.on('exit', (cd, sig) => r({ cd, sig })));
    assert.ok(Date.now() - t0 < 15_000, `exited ${Date.now() - t0} ms after start`);
    assert.ok(code.sig === 'SIGTERM' || code.cd !== 0, 'the cancelled scan did not report success');
    const st = path.join(root, '.agentic-security');
    const f = path.join(st, 'last-scan.json');
    if (fs.existsSync(f)) {
      // either valid and signed, or not trusted: a half-written file must not parse as a complete scan
      let ok = true; try { JSON.parse(fs.readFileSync(f, 'utf8')); } catch { ok = false; }
      assert.ok(ok || !fs.existsSync(`${f}.sig`), 'a truncated last-scan.json never carries a signature');
    }
    // a fresh scan after the cancellation is unaffected
    const again = cliScan(root);
    assert.ok(json(again) && json(again).findings.length > 0, 'a scan after a cancelled one works');
  } finally { rm(root); }
});

test('[QA-003.AC04] the loop controller and worker crash, stale-lease and watchdog scenarios pass', { timeout: 600_000 }, () => {
  const files = ['loop-watchdog.test.js', 'loop-background.test.js', 'loop-manifest.test.js'].map((f) => path.join(SCANNER, '..', 'scripts', 'loop-engineering', 'test', f)).filter((f) => fs.existsSync(f));
  assert.ok(files.length >= 2, 'the loop suites exist');
  const r = spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...files], { encoding: 'utf8', timeout: 580_000, cwd: path.join(SCANNER, '..') });
  assert.equal(r.status, 0, `${String(r.stdout).slice(-1200)}`);
});
