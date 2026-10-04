// X-013: full, diff, watch, baseline and suppression workflows for Haskell and Nix. Tests are tagged [X-013.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runScan } from '../../src/runScan.js';
import { runFullScan } from '../../src/engine.js';
import { diffScans } from '../../src/posture/baseline-compare.js';
import { applySuppressions } from '../../src/posture/suppressions.js';
import { watchProject, _internals as watchInternals } from '../../src/posture/watch-mode.js';
import { impactedFiles, computeLanguageDigests } from '../../src/language/discovery.js';
import { haskellComments, nixComments, languagePragmaOnLine, languagePragmaSuppresses, parsePragma } from '../../src/language/pragma.js';

const HS_STORE = (body) => `module Store where\nimport System.Process (callCommand, callProcess)\nimport Control.Exception (throwIO)\nimport Control.Monad (unless)\n\npersist :: String -> IO ()\npersist x = ${body}\n`;
const HS_HANDLER = 'module Handler where\nimport Store\n\nhandle :: IO ()\nhandle = do\n  name <- getLine\n  persist name\n';
const UNSAFE = 'callCommand ("echo " ++ x)';
const SAFE_AL = 'callProcess "echo" [x]';
const NIX_CONF = (imp) => `{ config, lib, ... }: { imports = [ ${imp} ]; services.openssh.enable = true; services.openssh.settings.PermitRootLogin = "yes"; networking.firewall.allowedTCPPorts = [ 22 ]; }\n`;
const NIX_FORCE = '{ lib, ... }: { services.openssh.settings.PermitRootLogin = lib.mkForce "no"; }\n';
const NIX_PLAIN = '{ ... }: { }\n';

const langFindings = (scan) => (scan.findings || []).filter((f) => /\.(?:l?hs|nix)$/.test(f.file));
const ids = (scan, re = /./) => langFindings(scan).filter((f) => re.test(f.file)).map((f) => `${f.family}@${f.file}`).sort();
async function diffScan(fx, since) { const r = await runScan(fx.root, { changedSince: since, deep: true }); return r.scan; }

test('[X-013.AC01] editing an imported Haskell module re-analyses its importers and removes the obsolete finding', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('src/Store.hs', HS_STORE(UNSAFE)); fx.writeFile('src/Handler.hs', HS_HANDLER); fx.writeFile('README.md', 'x');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('src/Store.hs', HS_STORE(SAFE_AL));              // only the imported module changes
    fx.commit('use the argv form', { date: '2026-01-02T00:00:00Z' });
    const full = await runScan(fx.root, { deep: true });
    const diff = await diffScan(fx, 'HEAD~1');
    const gone = (s) => !langFindings(s).some((f) => f.family === 'command-injection');
    assert.equal(gone(full.scan), true, 'a full scan agrees the argv form has no shell-injection finding');
    assert.equal(gone(diff), true, 'the diff-scoped scan, which sees Store.hs AND its importer, agrees');
    // the same change in the other direction: editing only the caller makes an unchanged sink reachable
    fx.writeFile('src/Store.hs', HS_STORE(UNSAFE)); fx.writeFile('src/Handler.hs', HS_HANDLER.replace('persist name', 'persist name\n  persist "x"'));
    fx.commit('unguard', { date: '2026-01-03T00:00:00Z' });
    fx.writeFile('src/Handler.hs', HS_HANDLER);                  // base for the next diff: Handler is unchanged from the original taint
    fx.commit('restore caller', { date: '2026-01-04T00:00:00Z' });
    fx.writeFile('src/Other.hs', 'module Other where\nimport Store\n\nother :: IO ()\nother = do\n  v <- getLine\n  persist v\n');
    fx.commit('add a second caller', { date: '2026-01-05T00:00:00Z' });
    const added = await diffScan(fx, 'HEAD~1');
    assert.ok(langFindings(added).some((f) => f.family === 'command-injection'), 'a new caller of an UNCHANGED sink module is analysed with that module as context');
  } finally { fx.cleanup(); }
});

test('[X-013.AC01] an imported Nix module, a flake lock and Cabal inputs change results in the right direction', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('configuration.nix', NIX_CONF('./hardening.nix')); fx.writeFile('hardening.nix', NIX_FORCE);
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    const base = await runScan(fx.root, { deep: true });
    assert.equal(langFindings(base.scan).some((f) => f.rule === 'ssh-root-login'), false, 'the imported mkForce wins: no root login finding');
    fx.writeFile('hardening.nix', NIX_PLAIN);                    // ONLY the imported module changes
    fx.commit('drop the control', { date: '2026-01-02T00:00:00Z' });
    const diff = await diffScan(fx, 'HEAD~1');
    assert.ok(langFindings(diff).some((f) => f.rule === 'ssh-root-login'), 'configuration.nix is re-analysed because it imports the changed module');
    // a lock file change widens to every Nix source
    fx.writeFile('flake.nix', '{ inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05"; }; outputs = { self, ... }: { }; }\n');
    fx.writeFile('flake.lock', JSON.stringify({ version: 7, root: 'root', nodes: { root: { inputs: { nixpkgs: 'nixpkgs' } }, nixpkgs: { locked: { type: 'github', owner: 'NixOS', repo: 'nixpkgs', rev: 'a'.repeat(40), narHash: 'sha256-A' }, original: { type: 'github', owner: 'NixOS', repo: 'nixpkgs', ref: 'nixos-24.05' } } } }));
    fx.commit('add lock', { date: '2026-01-03T00:00:00Z' });
    fx.writeFile('flake.lock', JSON.stringify({ version: 7, root: 'root', nodes: { root: { inputs: { nixpkgs: 'nixpkgs' } }, nixpkgs: { locked: { type: 'github', owner: 'NixOS', repo: 'nixpkgs', rev: 'b'.repeat(40), narHash: 'sha256-B' }, original: { type: 'github', owner: 'NixOS', repo: 'nixpkgs', ref: 'nixos-24.05' } } } }));
    fx.commit('bump lock', { date: '2026-01-04T00:00:00Z' });
    const lockDiff = await diffScan(fx, 'HEAD~1');
    assert.ok(langFindings(lockDiff).some((f) => f.rule === 'ssh-root-login'), 'a changed lock re-analyses every Nix source, including ones that did not change');
  } finally { fx.cleanup(); }
});

test('[X-013.AC01] deleting a Haskell source removes its findings and never reports a stale one', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('src/App.hs', 'module App where\nimport System.Process (callCommand)\nrun :: IO ()\nrun = do\n  n <- getLine\n  callCommand ("echo " ++ n)\n');
    fx.writeFile('README.md', 'x');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    assert.ok(langFindings((await runScan(fx.root, { deep: true })).scan).length > 0);
    fs.rmSync(path.join(fx.root, 'src/App.hs'));
    fx.commit('delete it', { date: '2026-01-02T00:00:00Z' });
    const full = await runScan(fx.root, { deep: true }); const diff = await diffScan(fx, 'HEAD~1');
    assert.equal(langFindings(full.scan).length, 0); assert.equal(langFindings(diff).length, 0);
    assert.equal(full.scan._scanMeta.filesScanned >= 0, true);
  } finally { fx.cleanup(); }
});

test('[X-013.AC01] incremental resume equals a fresh scan after an imported module changes (no stale cached result)', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'x013-resume-')); fs.writeFileSync(path.join(root, 'package.json'), '{}');
  try {
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src/Store.hs'), HS_STORE(UNSAFE)); fs.writeFileSync(path.join(root, 'src/Handler.hs'), HS_HANDLER);
    const live = (s) => langFindings(s).filter((f) => f.family === 'command-injection').map((f) => `${f.family}@${f.file}:${f.line}`).sort();
    const first = await runScan(root, { resume: true, deep: true });
    assert.ok(live(first.scan).length >= 1);
    fs.writeFileSync(path.join(root, 'src/Store.hs'), HS_STORE(SAFE_AL));
    const resumed = await runScan(root, { resume: true, deep: true });
    const fresh = await runScan(root, { resume: false, deep: true });
    assert.deepEqual(live(resumed.scan), live(fresh.scan), 'resume equals a fresh scan');
    assert.equal(live(resumed.scan).length, 0, 'the obsolete finding is gone');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('[X-013.AC01] manifest, flag and model inputs invalidate the right files', () => {
  const files = { 'src/A.hs': 'module A where\nimport B\n', 'src/B.hs': 'module B where\n', 'src/C.hs': 'module C where\n', 'configuration.nix': '{ imports = [ ./m.nix ]; }', 'm.nix': '{ }' };
  assert.deepEqual(impactedFiles(files, {}, ['src/B.hs']), ['src/A.hs', 'src/B.hs'], 'a changed module and its importers');
  assert.deepEqual(impactedFiles(files, {}, ['m.nix']), ['configuration.nix', 'm.nix']);
  assert.equal(impactedFiles(files, {}, ['demo.cabal']).length, 5, 'a Cabal change widens to every language source');
  assert.equal(impactedFiles(files, {}, ['cabal.project.freeze']).length, 5);
  assert.equal(impactedFiles(files, {}, ['flake.lock']).length, 5);
  const a = computeLanguageDigests(files, { manifests: { 'demo.cabal': 'flags: +x' }, models: { 'hs-models': 'v1' } });
  const b = computeLanguageDigests(files, { manifests: { 'demo.cabal': 'flags: -x' }, models: { 'hs-models': 'v1' } });
  const c = computeLanguageDigests(files, { manifests: { 'demo.cabal': 'flags: +x' }, models: { 'hs-models': 'v2' } });
  for (const k of a.digests.keys()) { assert.notEqual(a.digests.get(k), b.digests.get(k), `${k}: a flag change invalidates it`); assert.notEqual(a.digests.get(k), c.digests.get(k), `${k}: model data invalidates it`); }
});

test('[X-013.AC02] stable ids survive formatting-only changes, and a new vulnerable sink is never absorbed by an old baseline', async () => {
  const A = 'module App where\nimport System.Process (callCommand)\n\nrun :: IO ()\nrun = do\n  name <- getLine\n  callCommand ("echo " ++ name)\n';
  const FORMATTED = '{- header -}\nmodule App where\n\nimport System.Process (callCommand)\n\n\n-- | doc\nrun :: IO ()\nrun = do\n      name <- getLine\n\n      callCommand ( "echo " ++ name )   -- trailing\n';
  const NEWSINK = `${A}\nrun2 :: IO ()\nrun2 = do\n  other <- getLine\n  callCommand ("ls " ++ other)\n`;
  const sid = async (src) => (await runFullScan({ fileContents: { 'App.hs': src }, depFileContents: {}, deep: true })).findings.filter((f) => f.family === 'command-injection');
  const a = await sid(A); const f = await sid(FORMATTED); const n = await sid(NEWSINK);
  assert.equal(a.length, 1); assert.equal(f.length, 1); assert.equal(n.length, 2);
  assert.equal(f[0].stableId, a[0].stableId, 'blank lines, comments, indentation and spacing do not rotate the id');
  assert.notEqual(f[0].line, a[0].line, '...even though the line moved');
  const diff = diffScans({ findings: a }, { findings: n });
  assert.equal(diff.added.length, 1, 'the second sink is new relative to the baseline');
  assert.equal(diff.unchanged, 1);
  const N1 = '{ config, ... }: { services.openssh.enable = true; services.openssh.settings.PermitRootLogin = "yes"; }\n';
  const N2 = '# comment\n{ config, ... }:\n{\n  services.openssh.enable = true;\n\n  services.openssh.settings.PermitRootLogin = "yes";\n}\n';
  const nid = async (src) => (await runFullScan({ fileContents: { 'configuration.nix': src }, depFileContents: {}, deep: true })).findings.filter((x) => x.parser === 'nixos-hardening');
  const n1 = await nid(N1); const n2 = await nid(N2);
  assert.deepEqual(n1.map((x) => x.rule).sort(), n2.map((x) => x.rule).sort(), 'both rules fire even when they share a line');
  assert.ok(n1.length >= 2, 'two rules of one family on one line stay two findings');
  assert.deepEqual(n1.map((x) => x.stableId).sort(), n2.map((x) => x.stableId).sort(), 'Nix formatting does not rotate ids');
});

test('[X-013.AC03] Haskell and Nix pragmas are comment-aware, rule-scoped, line-scoped and logged', async () => {
  const hs = (line) => `module App where\nimport System.Process (callCommand)\n\nrun :: IO ()\nrun = do\n  name <- getLine\n  ${line}\n`;
  const sup = async (src, file = 'App.hs') => { const s = await runFullScan({ fileContents: { [file]: src }, depFileContents: {}, deep: true }); return { live: s.findings.filter((f) => f.file === file), s }; };
  // 1. a real line comment with the right rule suppresses, and the suppression is in the ledger
  const a = await sup(hs('callCommand ("echo " ++ name) -- agentic-security-ignore: command-injection'));
  assert.equal(a.live.filter((f) => f.family === 'command-injection').length, 0);
  assert.ok(a.s.suppressions && JSON.stringify(a.s.suppressions).includes('command-injection'), 'the ledger records it');
  // 2. a block comment and a bare pragma
  assert.equal((await sup(hs('callCommand ("echo " ++ name) {- agentic-security-ignore: command-injection -}'))).live.filter((f) => f.family === 'command-injection').length, 0);
  assert.equal((await sup(hs('callCommand ("echo " ++ name) -- agentic-security-ignore'))).live.filter((f) => f.family === 'command-injection').length, 0);
  // 3. the wrong rule, a substring of the rule, and a pragma on a different line do not suppress
  for (const src of [hs('callCommand ("echo " ++ name) -- agentic-security-ignore: ssh-root-login'), hs('callCommand ("echo " ++ name) -- agentic-security-ignore: command'), `module App where\nimport System.Process (callCommand)\n\nrun :: IO ()\nrun = do\n  name <- getLine\n  -- agentic-security-ignore: command-injection\n  callCommand ("echo " ++ name)\n`]) {
    assert.equal((await sup(src)).live.filter((f) => f.family === 'command-injection').length, 1, src.split('\n').slice(-3, -1).join(' / '));
  }
  // 4. the words inside a string literal, or as an operator, are not a pragma
  assert.equal((await sup(hs('callCommand ("echo -- agentic-security-ignore: command-injection " ++ name)'))).live.filter((f) => f.family === 'command-injection').length, 1);
  // 5. malformed pragmas suppress nothing and say why
  for (const bad of ['-- agentic-security-ignore command-injection', '-- agentic-security-ignore: bad!rule', '-- agentic-security-ignore:']) {
    const r = await sup(hs(`callCommand ("echo " ++ name) ${bad}`));
    const f = r.live.find((x) => x.family === 'command-injection');
    assert.ok(f, `${bad}: still reported`); assert.match(f.ignorePragmaIgnored || '', /malformed/);
  }
  // Nix: # and block comments; the shell comment INSIDE a string is not a pragma; exact rule ids
  const nix = (tail, mid = '') => `{ config, lib, ... }:\nlet cfg = config.services.mover; in {\n  systemd.services.mover = { script = ''\n    cp g \${cfg.dest}${mid}\n  ''; };${tail}\n}\n`;
  const nixF = (r) => r.live.filter((f) => f.rule === 'nix-shell-injection');
  assert.equal(nixF(await sup(nix(''), 'configuration.nix')).length, 1);
  assert.equal(nixF(await sup(nix('', ' # agentic-security-ignore: nix-shell-injection'), 'configuration.nix')).length, 1, 'a shell comment inside the Nix string is script text, not a Nix pragma');
  const lineOfSink = 4;
  const src = nix('').split('\n'); src[lineOfSink - 1] = `${src[lineOfSink - 1]}`;
  assert.equal(languagePragmaOnLine('c.nix', '{ a = 1; } # agentic-security-ignore: cmdi\n', 1).rules[0], 'cmdi');
  assert.equal(languagePragmaOnLine('c.nix', '{ a = "# agentic-security-ignore: cmdi"; }\n', 1), null);
  assert.equal(languagePragmaOnLine('c.nix', "{ a = ''\n  # agentic-security-ignore: cmdi\n''; }\n", 2), null);
  assert.equal(languagePragmaOnLine('c.nix', '{ a = "${ /* agentic-security-ignore: cmdi */ 1 }"; }\n', 1).rules[0], 'cmdi', 'a comment inside an interpolation is a comment');
  assert.equal(languagePragmaSuppresses(languagePragmaOnLine('c.nix', '{ } # agentic-security-ignore: cmd\n', 1), { rule: 'cmdi', family: 'cmdi' }), false, 'cmd is not cmdi');
  assert.equal(languagePragmaSuppresses(languagePragmaOnLine('c.nix', '{ } # agentic-security-ignore: cmdi, ssh-root-login\n', 1), { rule: 'cmdi' }), true);
  assert.equal(languagePragmaOnLine('A.hs', 'x = a --> b -- agentic-security-ignore\n', 1).bare, true);
  assert.equal(languagePragmaOnLine('A.hs', 'x = a |-- agentic-security-ignore b\n', 1), null, '`|--` is an operator');
  assert.equal(haskellComments('x = "a -- b" -- c\n').length, 1);
  assert.equal(haskellComments("c = '-'\nd = '\"' -- k\n").length, 1);
  assert.equal(nixComments('a = ./x; # y\n/* z */ b = "# no";').length, 2);
  assert.deepEqual(parsePragma(' agentic-security-ignore: a, b '), { bare: false, rules: ['a', 'b'], malformed: null });
});

test('[X-013.AC03] the existing audit and expiry policy applies to Haskell and Nix findings', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'x013-supp-')); fs.writeFileSync(path.join(root, 'package.json'), '{}'); fs.mkdirSync(path.join(root, '.agentic-security'));
  try {
    const s = await runFullScan({ fileContents: { 'App.hs': 'module App where\nimport System.Process (callCommand)\nrun :: IO ()\nrun = do\n  n <- getLine\n  callCommand ("echo " ++ n)\n' }, depFileContents: {}, deep: true });
    const f = s.findings.find((x) => x.family === 'command-injection'); assert.ok(f);
    const write = (accepted) => fs.writeFileSync(path.join(root, '.agentic-security', 'accepted.json'), JSON.stringify({ accepted }));
    write([{ id: f.id, reason: 'reviewed', expires_at: '2099-01-01' }]);
    assert.equal(applySuppressions([f], root, { profile: 'vibecoder' }).length, 0, 'an active acceptance suppresses it');
    write([{ id: f.id, reason: 'reviewed', expires_at: '2020-01-01' }]);
    const kept = applySuppressions([f], root, { profile: 'vibecoder' });
    assert.equal(kept.length, 1); assert.equal(kept[0]._suppressionExpired, true, 'an expired acceptance reopens the finding');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('[X-013.AC04] watch is an owned optional service: bounded trigger, expanded batch, clean shutdown, no unbounded watcher in acceptance scripts', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'x013-watch-'));
  try {
    fs.writeFileSync(path.join(root, 'A.hs'), 'module A where\nimport B\n'); fs.writeFileSync(path.join(root, 'B.hs'), 'module B where\n');
    // a hard time bound around the whole interaction; the service is stopped on EVERY path
    let svc = null;
    let batch;
    try {
      batch = await new Promise((resolve, reject) => {
        const guard = setTimeout(() => reject(new Error('watch did not deliver a batch within its bound')), 8000);
        watchProject(root, (b) => { clearTimeout(guard); resolve(b); }).then((s) => {
          svc = s;
          assert.equal(typeof s.stop, 'function', 'the watcher is an owned service with a stop handle');
          setTimeout(() => fs.writeFileSync(path.join(root, 'B.hs'), 'module B where\nx = 1\n'), 200);
        }, (e) => { clearTimeout(guard); reject(e); });
      });
    } finally { if (svc) await svc.stop(); }
    const rel = batch.map((p) => path.relative(root, p)).sort();
    assert.deepEqual(rel, ['A.hs', 'B.hs'], 'the changed module and its importer');
    // opt-out and idempotent shutdown
    const prev = process.env.AGENTIC_SECURITY_NO_WATCH; process.env.AGENTIC_SECURITY_NO_WATCH = '1';
    try { const off = await watchProject(root, () => {}); assert.equal(off._disabled, true); await off.stop(); } finally { if (prev === undefined) delete process.env.AGENTIC_SECURITY_NO_WATCH; else process.env.AGENTIC_SECURITY_NO_WATCH = prev; }
    assert.equal(watchInternals._isScanable('src/A.hs'), true); assert.equal(watchInternals._isScanable('configuration.nix'), true); assert.equal(watchInternals._isScanable('demo.cabal'), true);
    assert.equal(watchInternals._isScanable('dist-newstyle/build/x.hs'), false); assert.equal(watchInternals._isScanable('.stack-work/x.hs'), false);
    // no acceptance script runs the CLI watcher (it blocks until interrupted)
    const here = path.dirname(new URL(import.meta.url).pathname);
    for (const f of fs.readdirSync(here).filter((x) => x.endsWith('.test.js') && x !== 'language-scan-modes.test.js')) {
      assert.equal(/['"]--watch['"]|scan[^\n]*--watch\b/.test(fs.readFileSync(path.join(here, f), 'utf8')), false, `${f} must not start an unbounded watcher`);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
