// X-008: provenance, falsification, attack paths and posture for Haskell and Nix. Tests are tagged [X-008.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runFullScan } from '../../src/engine.js';
import { buildSnapshot } from '../../src/language/haskell-sca.js';
import { proofTierOf } from '../../src/posture/proof-tier.js';
import { sweepHaskellSiblings } from '../../src/language/haskell-sweep.js';
import { buildProjectIR } from '../../src/ir/index.js';

const HEAD = `{-# LANGUAGE OverloadedStrings #-}
module App where
import Web.Scotty (ActionM, param, text, scotty, post)
import System.Process (callCommand)
import Control.Monad.IO.Class (liftIO)

run :: ActionM ()
run = do
  name <- param "name"
`;
const SAFE = `${HEAD}  liftIO (callCommand "echo hello")\n  text "ok"\n`;
const VULN = `${HEAD}  liftIO (callCommand ("echo " ++ name))\n  text "ok"\n`;
const scan = (files, extra = {}) => runFullScan({ fileContents: files, depFileContents: {}, deep: true, ...extra });
const hsFindings = (s, file = 'App.hs') => s.findings.filter((f) => f.file === file && f.parser === 'IR-TAINT');

test('[X-008.AC01] a Haskell finding is attributed to the commit that introduced it, with a verified parent boundary', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('app/App.hs', SAFE); const c1 = fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('app/App.hs', VULN); const c2 = fx.commit('introduce injection', { date: '2026-02-01T00:00:00Z' });
    fx.writeFile('README.md', 'x'); fx.commit('docs', { date: '2026-03-01T00:00:00Z' });
    const s = await scan({ 'app/App.hs': VULN }, { scanRoot: fx.root });
    const [f] = hsFindings(s, 'app/App.hs');
    assert.ok(f, 'finding present');
    assert.equal(f.findingProvenance.status, 'complete');
    assert.equal(f.findingProvenance.findingOrigin.commit, c2);
    assert.notEqual(f.findingProvenance.findingOrigin.commit, c1);
    assert.equal(f.findingProvenance.limitations.length, 0);
  } finally { fx.cleanup(); }
});

test('[X-008.AC01] a Nix finding decided by an imported control is attributed to the commit that removed the control', async () => {
  const fx = createGitFixture();
  try {
    const conf = (imp) => `{ config, lib, ... }: { imports = [ ${imp} ]; services.openssh.enable = true; services.openssh.settings.PermitRootLogin = "yes"; networking.firewall.allowedTCPPorts = [ 22 ]; }`;
    fx.writeFile('configuration.nix', conf('./hardening.nix')); fx.writeFile('hardening.nix', '{ lib, ... }: { services.openssh.settings.PermitRootLogin = lib.mkForce "no"; }');
    const c1 = fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('configuration.nix', conf('')); fx.writeFile('hardening.nix', '{ ... }: { }');
    const c2 = fx.commit('drop hardening', { date: '2026-02-01T00:00:00Z' });
    fx.writeFile('README.md', 'x'); fx.commit('docs', { date: '2026-03-01T00:00:00Z' });
    const s = await scan({ 'configuration.nix': conf(''), 'hardening.nix': '{ ... }: { }' }, { scanRoot: fx.root });
    const f = s.findings.find((x) => x.rule === 'ssh-root-login');
    assert.ok(f, 'ssh-root-login finding present');
    assert.equal(f.findingProvenance.status, 'complete');
    assert.equal(f.findingProvenance.findingOrigin.commit, c2, 'the control was removed in c2, not introduced in c1');
    assert.notEqual(f.findingProvenance.findingOrigin.commit, c1);
  } finally { fx.cleanup(); }
});

test('[X-008.AC01] a dependency lock revision change is attributed to the commit that moved the pinned version into the advisory range', async () => {
  const fx = createGitFixture();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-feed-'));
  const prevFeed = process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES;
  try {
    const rec = JSON.parse(fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'fixtures', 'hackage-advisories', 'records', 'HSEC-2023-0001.json'), 'utf8'));
    const snap = buildSnapshot([rec], new Date().toISOString());
    fs.writeFileSync(path.join(tmp, 'snap.json'), JSON.stringify(snap));
    process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES = path.join(tmp, 'snap.json');
    const cabal = 'cabal-version: 2.4\nname: demo\nversion: 0.1\nexecutable demo\n  main-is: Main.hs\n  build-depends: base, aeson\n';
    const freeze = (v) => `constraints: any.aeson ==${v},\n             any.base ==4.18.0.0\n`;
    fx.writeFile('demo.cabal', cabal); fx.writeFile('cabal.project.freeze', freeze('2.0.1.0')); fx.writeFile('Main.hs', 'module Main where\nmain :: IO ()\nmain = pure ()\n');
    const c1 = fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('cabal.project.freeze', freeze('1.5.6.0'));
    const c2 = fx.commit('downgrade aeson', { date: '2026-02-01T00:00:00Z' });
    fx.writeFile('README.md', 'x'); fx.commit('docs', { date: '2026-03-01T00:00:00Z' });
    const s = await runFullScan({ fileContents: { 'Main.hs': 'module Main where\nmain :: IO ()\nmain = pure ()\n' }, depFileContents: { 'demo.cabal': cabal, 'cabal.project.freeze': freeze('1.5.6.0') }, scanRoot: fx.root, deep: true });
    const dep = s.supplyChain.find((x) => x.type === 'vulnerable_dep' && x.name === 'aeson');
    assert.ok(dep, 'aeson 1.5.6.0 is in the advisory range');
    assert.equal(dep.findingProvenance.status, 'complete', JSON.stringify(dep.findingProvenance));
    assert.equal(dep.findingProvenance.findingOrigin.commit, c2);
    assert.notEqual(dep.findingProvenance.findingOrigin.commit, c1);
  } finally {
    if (prevFeed === undefined) delete process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES; else process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES = prevFeed;
    fs.rmSync(tmp, { recursive: true, force: true }); fx.cleanup();
  }
});

test('[X-008.AC01] shallow history is disclosed, never claimed as a verified origin', async () => {
  const fx = createGitFixture();
  const clone = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-shallow-'));
  try {
    fx.writeFile('app/App.hs', SAFE); fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('app/App.hs', VULN); fx.commit('introduce', { date: '2026-02-01T00:00:00Z' });
    fx.writeFile('README.md', 'x'); fx.commit('docs', { date: '2026-03-01T00:00:00Z' });
    const dir = path.join(clone, 'r');
    execFileSync('git', ['clone', '-q', '--depth', '1', `file://${fx.root}`, dir], { stdio: 'ignore' });
    const s = await scan({ 'app/App.hs': VULN }, { scanRoot: dir });
    const [f] = hsFindings(s, 'app/App.hs');
    assert.ok(f);
    assert.notEqual(f.findingProvenance.status, 'complete', 'a shallow clone cannot prove an origin');
    assert.ok(f.findingProvenance.limitations.length > 0, 'the limitation is stated');
  } finally { fs.rmSync(clone, { recursive: true, force: true }); fx.cleanup(); }
});

test('[X-008.AC01] a rename after introduction does not produce a confident wrong commit', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('app/App.hs', SAFE); fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('app/App.hs', VULN); const c2 = fx.commit('introduce', { date: '2026-02-01T00:00:00Z' });
    fs.mkdirSync(path.join(fx.root, 'src'), { recursive: true });
    fs.renameSync(path.join(fx.root, 'app/App.hs'), path.join(fx.root, 'src/Moved.hs'));
    const c3 = fx.commit('move file', { date: '2026-03-01T00:00:00Z' });
    const s = await scan({ 'src/Moved.hs': VULN.replace('module App', 'module Moved') }, { scanRoot: fx.root });
    const [f] = hsFindings(s, 'src/Moved.hs');
    assert.ok(f);
    const p = f.findingProvenance;
    const commit = p.findingOrigin && p.findingOrigin.commit;
    assert.ok(commit === null || commit === undefined || commit === c2 || (p.status !== 'complete'), `origin ${commit} (${p.status}) must be the introducing commit or disclosed as uncertain`);
    if (commit === c3) assert.notEqual(p.status, 'complete', 'the rename commit is not the introducer');
  } finally { fx.cleanup(); }
});

test('[X-008.AC02] a dominating, context-matched guard refutes the path; nearby, non-dominating and wrong-context controls do not', async () => {
  const mk = (body) => `module G where\nimport System.Process (callCommand)\nimport Control.Exception (throwIO)\nimport Control.Monad (when, unless)\nimport Data.List (isInfixOf, elem)\n\nrun :: IO ()\nrun = do\n  name <- getLine\n${body}  putStrLn "ok"\n`;
  const dominating = mk('  unless (name `elem` ["status", "uptime"]) $ throwIO (userError "no")\n  callCommand ("run " ++ name)\n');
  const nearbyComment = mk('  -- name = shlex.quote(name)  -- escapeshellarg(name)\n  callCommand ("run " ++ name)\n');
  const wrongValue = mk('  other <- getLine\n  unless (other `elem` ["a", "b"]) $ throwIO (userError "no")\n  callCommand ("run " ++ name)\n');
  const wrongContext = mk('  when (".." `isInfixOf` name) $ throwIO (userError "no")\n  callCommand ("run " ++ name)\n');
  const guarded = await scan({ 'G.hs': dominating });
  const gf = guarded.findings.find((f) => f.file === 'G.hs' && f.cwe === 'CWE-78');
  assert.ok(gf, 'a refuted finding is kept (recall-preserving), never deleted');
  assert.match(gf.proof.verdict, /proven-infeasible/, 'a dominating allow-list refutes the command path');
  for (const [label, src] of [['nearby comment', nearbyComment], ['guard on a different value', wrongValue], ['path-context guard on a command sink', wrongContext]]) {
    const s = await scan({ 'G.hs': src });
    const f = s.findings.find((x) => x.file === 'G.hs' && x.cwe === 'CWE-78');
    assert.ok(f, `${label}: the finding survives`);
    assert.equal(f.quarantined, undefined, `${label}: not quarantined by adjacent text`);
    assert.equal(f.falsification && f.falsification.verdict, 'survived');
    assert.equal(f.proof.verdict, 'feasible', `${label}: the path is still feasible`);
  }
});

test('[X-008.AC02] the sibling sweep accounts every other call of the sink: found === candidates + mitigated', async () => {
  const a = `${HEAD}  liftIO (callCommand ("echo " ++ name))\n  text "ok"\n\nrun2 :: String -> IO ()\nrun2 x = callCommand ("ls " ++ x)\n\nrun3 :: IO ()\nrun3 = callCommand "uptime"\n\ncallCommandLike :: String -> IO ()\ncallCommandLike _ = pure ()\n\nrun4 :: IO ()\nrun4 = callCommandLike "not a sink"\n`;
  const b = `module B where\nimport System.Process (callCommand)\nimport Web.Scotty (ActionM, param)\nimport Control.Monad.IO.Class (liftIO)\nother :: ActionM ()\nother = do\n  p <- param "p"\n  liftIO (callCommand ("cat " ++ p))\n`;
  const s = await scan({ 'A.hs': a, 'B.hs': b });
  const sw = s.rootCauseSweep.sweeps.filter((x) => x.language === 'haskell');
  assert.equal(sw.length, 1);
  const x = sw[0];
  assert.equal(x.found, x.candidates + x.mitigated);
  // `run2 x = callCommand ("ls " ++ x)` takes caller text, so it carries a finding of its own and is not a SIBLING of the
  // reported one; only the constant-argument call remains a candidate sibling.
  assert.deepEqual(x.instances.map((i) => i.line).sort((p, q) => p - q), [17]);
  assert.equal(x.constantArgumentCandidates, 1, 'the literal-argument call is flagged but still a candidate');
  assert.ok(!x.instances.some((i) => /callCommandLike/.test(String(i.line))), 'a different function with a similar name is not a sibling');
  assert.equal(s.rootCauseSweep.totals.found, s.rootCauseSweep.totals.candidates + s.rootCauseSweep.totals.mitigated);
  // a call that already has a finding of its own is counted as mitigated, never dropped
  const ir = buildProjectIR({ 'A.hs': a, 'B.hs': b }).callGraph;
  const fake = [{ id: 'f1', file: 'A.hs', line: 10, parser: 'IR-TAINT', sink: { label: 'hs-sink-system.process.callcommand.cwe-78.0' } }, { id: 'f2', file: 'B.hs', line: 8, parser: 'HS-RULE' }];
  const r2 = sweepHaskellSiblings(fake, ir);
  assert.equal(r2.sweeps[0].mitigated, 1); assert.equal(r2.sweeps[0].found, r2.sweeps[0].candidates + r2.sweeps[0].mitigated);
});

test('[X-008.AC03] no model or configuration mention upgrades a finding to execution-proven; risk carries its assumptions', async () => {
  const s = await scan({ 'App.hs': VULN, 'configuration.nix': '{ config, ... }: { services.openssh.enable = true; services.openssh.settings.PermitRootLogin = "yes"; }' });
  const hs = hsFindings(s)[0];
  assert.ok(hs);
  assert.equal(proofTierOf(hs), 'taint-proven');
  assert.notEqual(hs.proofTier, 'execution-proven');
  assert.ok(hs.modelVersion, 'a model version is recorded');
  const nix = s.findings.find((x) => x.rule === 'ssh-root-login');
  assert.ok(nix);
  assert.equal(proofTierOf(nix), 'unproven', 'a configuration finding is not taint- or execution-proven');
  assert.equal(nix.evidenceKind, 'config');
  for (const f of [hs, nix]) {
    assert.ok(f.riskDollars, 'risk estimate present');
    assert.ok(Array.isArray(f.riskDollars.assumptions) && f.riskDollars.assumptions.length > 0, 'risk carries assumptions');
    assert.ok(f.riskDollars.scenarios && f.riskDollars.scenarioStatus, 'risk is a labeled scenario, not a prediction');
  }
});

test('[X-008.AC03] a Scotty route reaches the reachable entry-point ledger with its finding', async () => {
  const src = `${VULN}\nmain :: IO ()\nmain = scotty 3000 $ do\n  post "/run" run\n`;
  const s = await scan({ 'App.hs': src });
  assert.ok(s.entrypointInventory.entrypoints.some((e) => e.type === 'http' && /App\.hs$/.test(e.file)), JSON.stringify(s.entrypointInventory.entrypoints));
  assert.ok(s.entrypointInventory.entrypoints.some((e) => e.disposition === 'finding'));
});
