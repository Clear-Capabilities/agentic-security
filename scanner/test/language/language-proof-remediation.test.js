// X-009: fix verification, proof witnesses, attestations and the remediation ledger. Tests are tagged [X-009.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  buildNixScriptWitness, runNixScriptWitness, witnessNixFlow, nixFlowTarget, judgeFixWitness, nixFixWitness,
  runHaskellWitness, haskellRunner, PROOF_MARKER,
} from '../../src/language/witness.js';
import { analyzeNixScripts } from '../../src/language/nix-script-taint.js';
import { validateNixFix } from '../../src/language/nix-fix.js';
import { proveFinding } from '../../src/posture/execution-proof.js';
import { proofTierOf } from '../../src/posture/proof-tier.js';
import { readLog, undoLast } from '../../src/posture/fix-history.js';
import * as triage from '../../src/posture/triage.js';
import { buildEvidenceBundle, signEvidenceBundle, verifyEvidenceBundle, ensureKeyPair } from '../../src/posture/evidence-bundle.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const VULN = `{ config, pkgs, lib, ... }:
let cfg = config.services.mover; in {
  systemd.services.mover = {
    script = ''
      cp g \${cfg.dest}
    '';
  };
}
`;
const FIXED = VULN.replace('${cfg.dest}', '${lib.escapeShellArg cfg.dest}');
// a real project root (state is only written inside one): a package.json marks it, like any project
const tmpRoot = () => { const r = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'x009-'))); fs.writeFileSync(path.join(r, 'package.json'), '{}'); return r; };
const finding = () => analyzeNixScripts({ files: { 'configuration.nix': VULN } }).findings.find((f) => f.rule === 'nix-shell-injection');

test('[X-009.AC01] the sandbox is real here, so these witnesses actually execute', () => {
  assert.equal(sandboxAvailable(), true, 'a confinement primitive is required for witnesses to count');
});

test('[X-009.AC01] a real witness reproduces the injection in the vulnerable script and not in the fixed one', () => {
  const f = finding();
  const t = nixFlowTarget({ 'configuration.nix': VULN }, f);
  assert.ok(t, 'the finding maps to a generated-script interpolation');
  const before = witnessNixFlow({ 'configuration.nix': VULN }, t);
  assert.equal(before.status, 'reproduced'); assert.equal(before.ran, true); assert.match(before.observed, /PROVEN/);
  const after = witnessNixFlow({ 'configuration.nix': FIXED }, t);
  assert.equal(after.status, 'not-reproduced'); assert.equal(after.ran, true);
  assert.deepEqual(judgeFixWitness(before, after).verified, true);
});

test('[X-009.AC01] syntax, executable, resource and sandbox failures are never proof', () => {
  const a = analyzeNixScripts({ files: { 'configuration.nix': VULN } });
  const w = buildNixScriptWitness({ script: a.scripts[0], flow: a.flows[0] });
  assert.equal(w.status, 'ready');
  // 1. syntax error
  const bad = runNixScriptWitness({ ...w, code: 'if then fi (\n' });
  assert.equal(bad.status, 'invalid'); assert.match(bad.reason, /syntax error/); assert.equal(bad.ran, false);
  // 2. missing executable
  const noExe = runNixScriptWitness({ ...w, shell: 'definitely-not-a-shell-xyz' });
  assert.equal(noExe.status, 'invalid'); assert.match(noExe.reason, /executable not found/);
  // 3. resource limit: a witness that outlives its budget is invalid, not a refutation
  const slow = runNixScriptWitness({ ...w, code: 'sleep 5\n' }, { timeoutMs: 300 });
  assert.equal(slow.status, 'invalid'); assert.equal(slow.timedOut, true);
  // 4. sandbox disabled: refuses to execute, never runs unconfined
  const off = runNixScriptWitness(w, { force: 'disabled' });
  assert.equal(off.status, 'invalid'); assert.equal(off.ran, false);
  // 5. unsupported shell and an unmatched location
  assert.equal(buildNixScriptWitness({ script: { ...a.scripts[0], shell: 'fish' }, flow: a.flows[0] }).status, 'unsupported');
  assert.equal(buildNixScriptWitness({ script: a.scripts[0], flow: { ...a.flows[0], generatedLocation: { line: 99, startColumn: 3 } } }).status, 'unsupported');
  for (const r of [bad, noExe, slow, off]) assert.notEqual(r.status, 'reproduced');
  assert.equal(fs.existsSync(path.join(process.cwd(), PROOF_MARKER)), false, 'the marker never leaks into the working directory');
});

test('[X-009.AC01] proveFinding records execution-proven only for a marker, with the proof SCOPE kept apart', async () => {
  const a = analyzeNixScripts({ files: { 'configuration.nix': VULN } });
  const w = buildNixScriptWitness({ script: a.scripts[0], flow: a.flows[0] });
  const base = { ...finding(), proofTier: undefined };
  const proven = await proveFinding({ ...base, poc: { lang: 'nix-shell', code: w.code, witness: w } });
  assert.equal(proven.proofTier, 'execution-proven');
  assert.equal(proven.proofEvidence.proofKind, 'generated-script-execution');
  assert.match(proven.proofEvidence.doesNotProve, /deployed host/);
  const broken = await proveFinding({ ...base, poc: { lang: 'nix-shell', code: 'x', witness: { ...w, code: 'if then fi (' } } });
  assert.notEqual(broken.proofTier, 'execution-proven'); assert.equal(broken.proofTier, proofTierOf({ ...base, proofTier: undefined }));
  assert.equal(broken.proofEvidence.ran, false);
  const clean = await proveFinding({ ...base, poc: { lang: 'nix-shell', code: 'x', witness: { ...w, code: 'true\n' } } });
  assert.equal(clean.proofTier, 'proof-failed'); assert.equal(clean.proofEvidence.ran, true);
});

test('[X-009.AC01] a Haskell witness needs a toolchain: without one it is unavailable, never proof', async () => {
  // availability is decided ONCE: two probes in one test can disagree on a loaded machine, and then the assertion tests the probe, not the witness
  const available = haskellRunner().available;
  const r = runHaskellWitness('main :: IO ()\nmain = writeFile "PROVEN" "x"\n');
  if (available) assert.ok(['reproduced', 'invalid'].includes(r.status), `status ${r.status}: ${r.reason || ''}`);
  else { assert.equal(r.status, 'unavailable'); assert.match(r.reason, /no Haskell toolchain|did not start/); }
  const p = await proveFinding({ id: 'h', file: 'A.hs', parser: 'IR-TAINT', poc: { lang: 'haskell', code: 'main :: IO ()\nmain = pure ()\n' } });
  if (!available) { assert.equal(p.proofTier, 'taint-proven'); assert.equal(p.proofEvidence.witnessStatus, 'unavailable'); assert.equal(p.proofEvidence.ran, false); }
});

test('[X-009.AC01] the fix lifecycle runs a witness before and after, and blocks a patch that still reproduces', async () => {
  const f = finding();
  const files = { 'configuration.nix': VULN };
  const ok = await validateNixFix(f, { files, witness: nixFixWitness(f), requireWitness: true });
  assert.equal(ok.status, 'verified', JSON.stringify(ok.reason));
  assert.equal(ok.verified.witness, 'passed');
  assert.equal(ok.gates.witness.verified, true);
  const stillBad = await validateNixFix(f, { files, witness: () => ({ ok: false, verified: false, stillReproduces: true, reason: 'the patched code still reproduces the effect' }) });
  assert.equal(stillBad.status, 'blocked'); assert.match(stillBad.reason, /witness: .*still reproduces/);
  const unjudged = await validateNixFix(f, { files, witness: () => ({ ok: false, verified: false, reason: 'unavailable' }), requireWitness: true });
  assert.equal(unjudged.status, 'blocked');
  const optional = await validateNixFix(f, { files, witness: () => ({ ok: false, verified: false, reason: 'unavailable' }) });
  assert.equal(optional.status, 'verified'); assert.equal(optional.verified.witness, 'not-verified');
  assert.equal(judgeFixWitness({ status: 'invalid', reason: 'x' }, { status: 'not-reproduced' }).verified, false, 'an invalid original verifies nothing');
});

test('[X-009.AC02] apply records the tier and gates in the shared history; undo restores and marks it reverted', async () => {
  const root = tmpRoot();
  try {
    fs.writeFileSync(path.join(root, 'configuration.nix'), VULN);
    const f = { ...finding(), id: 'nix-1' };
    const res = await validateNixFix(f, { files: { 'configuration.nix': VULN }, apply: true, root, witness: nixFixWitness(f) });
    assert.equal(res.status, 'applied');
    assert.equal(fs.readFileSync(path.join(root, 'configuration.nix'), 'utf8'), FIXED);
    const log = readLog(root);
    assert.equal(log.length, 1);
    const e = log[0];
    assert.ok(['FULL', 'MITIGATION', 'WORKAROUND'].includes(e.fixLabel), `fix label ${e.fixLabel}`);
    assert.equal(e.fixLabel, res.label);
    assert.equal(e.verification.witness, 'passed'); assert.equal(e.verification.rescan, true);
    assert.ok(!Number.isNaN(Date.parse(e.appliedAt)), 'an evidence timestamp is kept');
    const undone = await undoLast(root);
    assert.equal(undone.reverted, true); assert.ok(!Number.isNaN(Date.parse(undone.revertedAt)));
    assert.equal(fs.readFileSync(path.join(root, 'configuration.nix'), 'utf8'), VULN, 'byte for byte');
    assert.equal(readLog(root)[0].fixLabel, e.fixLabel, 'the tier survives the undo');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('[X-009.AC02] accepted risk and reopen keep timestamps; an incomplete scan never closes a finding; a regression reopens it', () => {
  const root = tmpRoot();
  try {
    const f = { id: 'nix-shell-injection:configuration.nix:5', file: 'configuration.nix', line: 5, vuln: 'v', severity: 'high', language: 'nix', rule: 'nix-shell-injection' };
    triage.syncWithScan(root, [f], { scanHealth: { status: 'complete' } });
    assert.equal(triage.loadTriage(root).findings[f.id].language, 'nix');
    // 1. a PARTIAL scan that no longer reports it must not close it
    triage.syncWithScan(root, [], { scanHealth: { status: 'partial', conditions: ['language adapter exception(s)'] } });
    let cur = triage.loadTriage(root).findings[f.id];
    assert.equal(cur.state, 'open'); assert.ok(cur.unverified && cur.unverified.reason);
    // 2. a COMPLETE scan that stops reporting it closes it, with a timestamp
    triage.syncWithScan(root, [], { scanHealth: { status: 'complete' } });
    cur = triage.loadTriage(root).findings[f.id];
    assert.equal(cur.state, 'fixed'); assert.ok(Date.parse(cur.fixed_at));
    // 3. it comes back: reopened, with a transition that says why
    triage.syncWithScan(root, [f], { scanHealth: { status: 'complete' } });
    cur = triage.loadTriage(root).findings[f.id];
    assert.equal(cur.state, 'open'); assert.ok(Date.parse(cur.reopened_at));
    const t = triage.loadTriage(root).transitions.filter((x) => x.id === f.id);
    assert.ok(t.some((x) => x.from === 'fixed' && x.to === 'open' && /reported again/.test(x.reason)));
    // 4. accepted risk is a recorded decision with its comment and time
    triage.transition(root, f.id, 'wont-fix', 'accepted: internal-only host');
    const tr = triage.loadTriage(root).transitions.filter((x) => x.id === f.id && x.to === 'wont-fix');
    assert.equal(tr.length, 1); assert.match(tr[0].comment, /internal-only/); assert.ok(Date.parse(tr[0].at));
    triage.syncWithScan(root, [], { scanHealth: { status: 'complete' } });
    assert.equal(triage.loadTriage(root).findings[f.id].state, 'wont-fix', 'a recorded risk acceptance is not overwritten by a rescan');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('[X-009.AC03] signed bundles for Haskell and Nix findings verify, keep their source and tier, and tamper is detected', async () => {
  const dir = tmpRoot();
  try {
    const keys = ensureKeyPair(dir);
    const nix = { ...finding(), id: 'nix-1' };
    const a = analyzeNixScripts({ files: { 'configuration.nix': VULN } });
    const w = buildNixScriptWitness({ script: a.scripts[0], flow: a.flows[0] });
    const proven = await proveFinding({ ...nix, poc: { lang: 'nix-shell', code: w.code, witness: w } });
    const hs = { id: 'hs-1', severity: 'high', file: 'src/App.hs', line: 10, vuln: 'cmd', cwe: 'CWE-78', family: 'cmd', parser: 'IR-TAINT', language: 'haskell', evidenceKind: 'source', originalLocation: { file: 'src/App.hs', line: 10, column: 0 }, chain: [{ file: 'src/App.hs', line: 9, label: 'source' }, { file: 'src/Store.hs', line: 3, label: 'sink' }] };
    for (const f of [proven, hs]) {
      const signed = signEvidenceBundle(buildEvidenceBundle(f, { engineVersion: 'test' }), keys.privateKeyPem);
      assert.deepEqual(verifyEvidenceBundle(signed, keys.publicKeyPem), { ok: true, reason: null });
      assert.equal(signed.finding.language, f.language || 'nix'); assert.ok(signed.finding.file);
      assert.equal(signed.evidence.proofTier, f.proofTier ?? null, 'the bundle carries the tier, a signature does not raise it');
      assert.match(signed.doesNotProve, /never a correctness claim/);
      for (const mutate of [(b) => { b.finding.file = 'other.hs'; }, (b) => { b.evidence.proofTier = b.evidence.proofTier === 'execution-proven' ? 'unproven' : 'execution-proven'; }, (b) => { b.finding.language = 'python'; }]) {
        const t = JSON.parse(JSON.stringify(signed)); mutate(t);
        assert.equal(verifyEvidenceBundle(t, keys.publicKeyPem).ok, false);
      }
    }
    const hsBundle = buildEvidenceBundle(hs, {});
    assert.equal(hsBundle.evidence.taintPath.length, 2, 'the cross-module path is part of the evidence');
    const nixBundle = buildEvidenceBundle(proven, {});
    assert.equal(nixBundle.evidence.proofEvidence.proofKind, 'generated-script-execution', 'configuration proof stays labelled as such');
    assert.equal(nixBundle.evidence.proofTier, 'execution-proven');
    const unproven = buildEvidenceBundle({ ...hs, proofTier: undefined }, {});
    assert.equal(unproven.evidence.proofTier, null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
