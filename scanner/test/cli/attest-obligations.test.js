import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

// Same minimal PHI-to-external-sink shape the obligation-evidence-pack.js
// unit test's own REAL PIPELINE case uses
// (bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi) —
// it does not need to trigger a real HIPAA evidence_supported/gap_detected
// state, only to produce SOME real scan.lineageGraph for the CLI plumbing
// under test here.
const PHI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

// PHI sent over a literal http:// destination — transit-protection.js's
// own AC-03 case, reads a real, ASSESSED 'unprotected' verdict (not
// merely 'not_assessed'), which resolves to a genuine gap_detected
// HIPAA §164.312(e) fact. Confirmed live by the final whole-branch review.
const PHI_HTTP_SOURCE = `function submitPatientRecord(req) {
  const patientRecord = req.body.patient_record;
  fetch('http://insecure-endpoint.example.com/submit', {
    method: 'POST',
    body: JSON.stringify({ record: patientRecord }),
  });
}
`;

function _scanWithLineage(fx) {
  return spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
}

test('attest --obligations: signs a real evidence pack from a real scan with a lineage graph', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  // `scan` exit code encodes the deploy-gate verdict, not scan success —
  // "<=3" is the established convention for "the scan itself completed"
  // across this suite (see test/cli/attest-provenance.test.js).
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const attestR = spawnSync(process.execPath, [CLI, 'attest', '--obligations', 'hipaa-security-rule'], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(attestR.status, 0, `attest --obligations failed: ${attestR.stderr}\n${attestR.stdout}`);

  const outFile = path.join(fx.root, '.agentic-security', 'attestations', 'evidence-pack-hipaa-security-rule.json');
  assert.ok(fs.existsSync(outFile), 'expected evidence-pack-hipaa-security-rule.json to be written');

  const pack = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.equal(pack.schema, 'agentic-security/obligation-evidence-pack@1');
  assert.equal(pack.framework.id, 'hipaa-security-rule');
  assert.ok(pack.signature?.value, 'expected a real signature value');

  // Task-2 review finding (blocking, now fixed): scan.lineageGraph is
  // never present in last-scan.json (stripped before persisting — the
  // real graph lives at .agentic-security/lineage-graph.json, signed
  // separately). Before the fix, attest --obligations silently read
  // scan.lineageGraph anyway, so graphDigest/evidenceIndex were ALWAYS
  // null/empty through the real CLI, even with a real lineage graph on
  // disk and AGENTIC_SECURITY_LINEAGE_DEEP=1 genuinely set. These
  // assertions are the regression guard — they fail against the pre-fix
  // code (graphDigest: null, evidenceIndex: [{...evidence: []}]).
  assert.ok(pack.graphDigest, `expected a real graph digest, got ${pack.graphDigest} — the CLI likely isn't loading .agentic-security/lineage-graph.json`);
  assert.match(pack.graphDigest, /^[0-9a-f]{64}$/);
  assert.ok(pack.evidenceIndex.length >= 1);
  assert.ok(pack.evidenceIndex[0].evidence.length >= 1, 'expected the evidence index to resolve at least one real contributing flow');
  assert.deepEqual(pack.evidenceIndex[0].evidence[0].dataClasses, ['PHI']);

  // Final whole-branch review finding B1 (blocking, now fixed): these
  // three fields read scan.engineVersion/.rulesetVersion/.bundleSha
  // directly, but they actually live under scan.attestation — always
  // null through the real CLI before the fix.
  assert.ok(pack.reproducibility.engineVersion, `expected a real engineVersion, got ${pack.reproducibility.engineVersion}`);
  assert.ok(pack.reproducibility.rulesetVersion, `expected a real rulesetVersion, got ${pack.reproducibility.rulesetVersion}`);
  // bundleSha legitimately reads 'unavailable' when running from src/
  // rather than the published bundle — still a real, non-null value,
  // which is exactly the regression this asserts (pre-fix it was
  // unconditionally null).
  assert.notEqual(pack.reproducibility.bundleSha, null);
});

test('attest --obligations + verify-attestation: a real gap_detected fact is flagged with ⚠️ gaps: N on BOTH surfaces, never hidden among all-zero counts', async (t) => {
  // Final whole-branch review finding R1 (recommended, now fixed): a
  // real, assessed HIPAA transit gap used to print
  // "unknown: 0  manual: 0  accepted exceptions: 0" and nothing else on
  // both the signing side and verify-attestation — an auditor scanning
  // for a gap saw all zeros and a green VALID tick.
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_HTTP_SOURCE);
  fx.commit('add PHI over a literal http:// destination');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const attestR = spawnSync(process.execPath, [CLI, 'attest', '--obligations', 'hipaa-security-rule'], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(attestR.status, 0, `attest --obligations failed: ${attestR.stderr}\n${attestR.stdout}`);
  assert.match(attestR.stdout, /⚠️ gaps: 1/, `expected a ⚠️ gaps flag in attest output, got:\n${attestR.stdout}`);

  const outFile = path.join(fx.root, '.agentic-security', 'attestations', 'evidence-pack-hipaa-security-rule.json');
  const pack = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  const gapFact = pack.facts.find((f) => f.state === 'gap_detected');
  assert.ok(gapFact, `expected a real gap_detected fact in the pack, got states: ${pack.facts.map((f) => f.state).join(', ')}`);

  const verifyR = spawnSync(process.execPath, [CLI, 'verify-attestation', outFile], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(verifyR.status, 0, `verify-attestation failed: ${verifyR.stderr}`);
  assert.match(verifyR.stdout, /⚠️ gaps: 1/, `expected a ⚠️ gaps flag in verify-attestation output, got:\n${verifyR.stdout}`);
});

test('attest --obligations: with no framework id, exits 2 with a usage message', async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-attest-obligations-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tmp, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(tmp, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [] }));

  const r = spawnSync(process.execPath, [CLI, 'attest', '--obligations'], { cwd: tmp, encoding: 'utf8', timeout: 15000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Usage: agentic-security attest --obligations <framework-id>/);
  assert.match(r.stderr, /Bundled frameworks:/);
});

test('verify-attestation: round-trips a real evidence pack end-to-end, and rejects a hand-tampered copy', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const attestR = spawnSync(process.execPath, [CLI, 'attest', '--obligations', 'hipaa-security-rule'], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(attestR.status, 0, `attest --obligations failed: ${attestR.stderr}`);

  const outFile = path.join(fx.root, '.agentic-security', 'attestations', 'evidence-pack-hipaa-security-rule.json');

  const verifyR = spawnSync(process.execPath, [CLI, 'verify-attestation', outFile], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(verifyR.status, 0, `verify-attestation failed: ${verifyR.stderr}\n${verifyR.stdout}`);
  assert.match(verifyR.stdout, /VALID/);
  assert.match(verifyR.stdout, /framework: hipaa-security-rule/);

  // Hand-tamper one field in the written JSON file on disk, then confirm
  // verify-attestation now exits 1 — the same EA-03 proof
  // obligation-evidence-pack.test.js's own unit test performs, but here
  // exercised through the real CLI round trip.
  const pack = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  pack.framework.name = 'Tampered Framework Name';
  fs.writeFileSync(outFile, JSON.stringify(pack, null, 2));

  const tamperedR = spawnSync(process.execPath, [CLI, 'verify-attestation', outFile], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(tamperedR.status, 1);
  assert.match(tamperedR.stderr, /INVALID/);
});
