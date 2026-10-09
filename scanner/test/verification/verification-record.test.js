// X-201: one verification record, emitted by every verification surface.
//
// Each criterion is tested in both directions: the good case passes, and the
// hostile or lazy case (a boolean coercion, a model verdict presented as proof, a
// forged level, an unknown surface) is refused.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { emitVerification, SURFACES, headCommit } from '../../src/posture/verification/emit.js';
import {
  validateVerificationRecord, buildVerificationRecord, VERIFICATION_OUTCOMES, EVIDENCE_KINDS,
} from '../../src/posture/assurance/verification-record.js';
import { migrateRecord, toLegacyVerificationView } from '../../src/posture/assurance/migrations.js';
import { verifyFix } from '../../src/posture/fix-verify.js';
import { verifyFixWithTests } from '../../src/posture/fix-verify-loop.js';
import { proveFinding } from '../../src/posture/execution-proof.js';
import { annotateVerifierVerdicts, verifierVerificationRecords } from '../../src/posture/verifier.js';
import { runAutopilot } from '../../src/posture/autopilot.js';
import { runDiscovery } from '../../src/discovery/index.js';
import { createServer } from '../../src/mcp/server.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const COMMIT = 'b'.repeat(40);
const noSbx = sandboxAvailable() ? false : 'SKIPPED, NOT PASSED: no confinement backend works on this host; the proof legs are UNVERIFIED here';

const RECORD_KEYS = ['schema', 'schemaVersion', 'id', 'hypothesisId', 'commit', 'detectorOrigin', 'oracle', 'attempt', 'outcome', 'reason', 'evidence', 'evidenceRefs', 'scope', 'preconditions', 'confirmationLevel', 'repair'];

function assertRecord(rec, where) {
  assert.ok(rec, `${where}: no verification record was emitted`);
  const v = validateVerificationRecord(rec);
  assert.equal(v.ok, true, `${where}: ${JSON.stringify(v.errors)}`);
  for (const k of RECORD_KEYS) assert.ok(k in rec, `${where}: missing '${k}'`);
  assert.equal(typeof rec.hypothesisId, 'string');
  assert.ok(rec.commit === null || /^[0-9a-f]{40}$/.test(rec.commit), `${where}: commit`);
  assert.equal(typeof rec.detectorOrigin.detector, 'string');
  assert.ok(rec.oracle === null || typeof rec.oracle.id === 'string');
  assert.ok(Number.isInteger(rec.attempt));
  assert.ok(VERIFICATION_OUTCOMES.includes(rec.outcome));
  assert.ok(rec.reason.length > 0);
  assert.ok(Array.isArray(rec.evidenceRefs));
  assert.ok(rec.scope.description.length > 0 && rec.scope.platform);
  return rec;
}

const finding = (over = {}) => ({
  id: 'F1', stableId: 'a1b2c3d4e5f60718', severity: 'high', file: 'app.js', line: 1, vuln: 'Command Injection', cwe: 'CWE-78',
  family: 'command-injection', parser: 'IR-TAINT', ...over,
});

function tmpProject(files = {}) {
  const dir = mkTestTmp('x201-');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fixture"}');
  for (const [rel, c] of Object.entries(files)) fs.writeFileSync(path.join(dir, rel), c);
  return dir;
}

// ---------------------------------------------------------------- AC01

describe('[X-201.AC01] every surface emits the same verification record', () => {
  const shapes = new Map();

  test('[X-201.AC01] fix verification (also what the CLI fix and the MCP tools call)', async () => {
    const dir = tmpProject({ 'app.js': 'export const a = 1;\n' });
    const r = await verifyFix({ scanRoot: dir, originalFindingStableId: 'a1b2c3d4e5f60718', files: { 'app.js': 'export const a = 2;\n' } });
    assert.equal(r.ok, true, 'the pre-existing verdict is unchanged');
    const rec = assertRecord(r.verificationRecord, 'fix-verify');
    assert.equal(rec.hypothesisId, 'a1b2c3d4e5f60718');
    // A static re-scan is not an exploit oracle: nothing executed against the patch.
    assert.equal(rec.outcome, 'not-run');
    assert.equal(rec.attempt, 0);
    assert.equal(rec.repair.status, 'proposed');
    assert.match(rec.repair.patchDigest, /^sha256:[0-9a-f]{64}$/);
    shapes.set('fix-verify', Object.keys(rec).sort().join());
  });

  test('[X-201.AC01] fix verification with a proof-of-concept leg is `inconclusive`, never confirmed or refuted', { skip: noSbx }, async () => {
    const dir = tmpProject({ 'app.js': 'export const a = 1;\n' });
    const firing = { lang: 'js', code: "import fs from 'node:fs'; fs.writeFileSync('PROVEN', 'x');", finding: finding() };
    const quiet = { lang: 'js', code: 'export {};', finding: finding() };
    for (const [poc, label] of [[firing, 'still-exploitable'], [quiet, 'no-longer-proven']]) {
      const r = await verifyFix({ scanRoot: dir, originalFindingStableId: 'a1b2c3d4e5f60718', files: { 'app.js': 'export const a = 2;\n' }, poc });
      assert.equal(r.poc.status, label);
      const rec = assertRecord(r.verificationRecord, `fix-verify/${label}`);
      assert.equal(rec.outcome, 'inconclusive', `${label}: the older sandbox path is not a trusted runner`);
      assert.equal(rec.oracle.kind, 'runtime-replay');
      assert.equal(rec.confirmationLevel, 'none');
    }
  });

  test('[X-201.AC01] the closed fix loop', async () => {
    const dir = tmpProject({ 'app.js': 'export const a = 1;\n' });
    const r = await verifyFixWithTests({ scanRoot: dir, originalFindingStableId: 'a1b2c3d4e5f60718', files: { 'app.js': 'export const a = 2;\n' }, runTests: false });
    assert.equal(r.verdict, 'untested-but-passes', 'the pre-existing verdict is unchanged');
    const rec = assertRecord(r.verificationRecord, 'fix-verify-loop');
    assert.equal(rec.outcome, 'not-run');
    shapes.set('fix-verify-loop', Object.keys(rec).sort().join());
  });

  test('[X-201.AC01] execution proof', { skip: noSbx }, async () => {
    const f = { ...finding(), poc: { lang: 'js', code: "import fs from 'node:fs'; fs.writeFileSync('PROVEN', 'x');" } };
    const proven = await proveFinding(f);
    assert.equal(proven.proofTier, 'execution-proven', 'the pre-existing tier is unchanged');
    const rec = assertRecord(proven.verificationRecord, 'execution-proof');
    assert.equal(rec.outcome, 'inconclusive');
    assert.equal(rec.oracle.kind, 'runtime-replay');
    const none = await proveFinding(finding());
    assert.equal(assertRecord(none.verificationRecord, 'execution-proof/no-poc').outcome, 'not-run');
    shapes.set('execution-proof', Object.keys(rec).sort().join());
  });

  test('[X-201.AC01] the verifier verdicts (and the CLI verify run record)', () => {
    const fs1 = finding({ family: 'sql-injection' });
    const fs2 = finding({ id: 'F2', stableId: 'f2f2f2f2f2f2f2f2', family: 'no-such-family' });
    annotateVerifierVerdicts([fs1, fs2], { fileContents: { 'app.js': 'db.query("select " + id);\n' } });
    const recs = verifierVerificationRecords([fs1, fs2], { commit: COMMIT });
    assert.equal(recs.length, 2);
    recs.forEach((r, i) => assertRecord(r, `verifier/${i}`));
    assert.equal(recs[0].commit, COMMIT);
    shapes.set('verifier', Object.keys(recs[0]).sort().join());
  });

  test('[X-201.AC01] the CLI `verify` command writes the records into its durable run record', () => {
    const dir = tmpProject({ 'app.js': 'db.query("select " + id);\n' });
    fs.mkdirSync(path.join(dir, '.agentic-security'));
    fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [finding({ family: 'sql-injection' })] }));
    const r = spawnSync(process.execPath, [path.join(SCANNER, 'bin', 'agentic-security.js'), 'verify', '--root', dir], { encoding: 'utf8', timeout: 60_000 });
    assert.equal(r.status, 0, r.stderr);
    const runs = fs.readdirSync(path.join(dir, '.agentic-security', 'verifier-runs'));
    assert.equal(runs.length, 1);
    const run = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'verifier-runs', runs[0]), 'utf8'));
    assert.equal(run.verificationRecords.length, 1);
    assertRecord(run.verificationRecords[0], 'cli-verify');
    // The findings written back to last-scan.json are not given the record.
    const back = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
    assert.equal('verificationRecord' in back.findings[0], false);
  });

  test('[X-201.AC01] autopilot', async () => {
    const stages = {
      scan: async () => ({ findings: [{ stableId: 'f1', file: 'a.js', line: 2, vuln: 'Command Injection', severity: 'critical' }] }),
      prove: async () => ({ proofTier: 'execution-proven', proofEvidence: { ran: true } }),
      validate: async () => ({ verdict: 'upheld' }),
      synthesizeFix: async () => ({ patch: { 'a.js': 'fixed' } }),
      verifyFix: async () => ({ ok: true, pocStillFires: false, testsPass: true }),
    };
    const r = await runAutopilot({ stages, commit: COMMIT });
    assert.equal(r.results[0].outcome, 'VERIFIED_FIXED', 'the pre-existing outcome is unchanged');
    const rec = assertRecord(r.results[0].verificationRecord, 'autopilot');
    assert.equal(rec.commit, COMMIT);
    assert.equal(rec.hypothesisId, 'f1');
    assert.equal(rec.outcome, 'inconclusive', 'the chain ran under the older runner: no trusted exploit-negative');
    assert.equal(rec.repair.status, 'proposed');
    shapes.set('autopilot', Object.keys(rec).sort().join());
  });

  test('[X-201.AC01] hunt', async () => {
    const ctx = {
      perFileIR: {}, priorScan: null, triageFeedback: null,
      callGraph: { functions: new Map([['auth.js::login@1', { qid: 'auth.js::login@1', name: 'login', file: 'auth.js' }]]), edges: [] },
      fileContents: { 'auth.js': 'function login(u){ return db.query("select "+u); }' },
    };
    const llmInvoke = async (p) => (/REFUTE/.test(p) ? '{"refuted":false,"reason":"looks real"}'
      : '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat","entryPoint":"u","sink":"db.query"}]}');
    const r = await runDiscovery(ctx, { llmInvoke, lenses: ['injection'] });
    assert.equal(r.fresh.length, 1);
    assert.equal(r.verificationRecords.length, 1);
    const rec = assertRecord(r.verificationRecords[0], 'hunt');
    assert.equal(rec.hypothesisId, r.fresh[0].stableId);
    assert.ok(['not-run', 'inconclusive'].includes(rec.outcome), `a hunt hypothesis is never confirmed here, got ${rec.outcome}`);
    assert.equal('verificationRecord' in r.fresh[0], false, 'advisory findings are not mutated');
    shapes.set('hunt', Object.keys(rec).sort().join());
  });

  test('[X-201.AC01] the MCP verify_fix and apply_fix tools return the same record', async () => {
    const dir = tmpProject({ 'app.js': 'export function ok() { return 1; }\n' });
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    const body = JSON.stringify({ findings: [finding({ file: 'app.js' })] });
    fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), body);
    fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
    const { handleRequest } = createServer({ sessionRoot: dir });
    const call = async (name, args) => JSON.parse((await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })).result.content[0].text);
    const v = await call('verify_fix', { stable_id: 'a1b2c3d4e5f60718', files: { 'app.js': 'export function ok() { return 2; }\n' } });
    const vrec = assertRecord(v.verificationRecord, 'mcp/verify_fix');
    const a = await call('apply_fix', { finding_id: 'F1', confirm: true, dry_run: true, patch: { 'app.js': 'export function ok() { return 2; }\n' } });
    const arec = assertRecord(a.verificationRecord, 'mcp/apply_fix');
    assert.equal(arec.outcome, vrec.outcome);
    assert.equal(a.verified, true, 'the pre-existing flag is unchanged');
    shapes.set('mcp', Object.keys(vrec).sort().join());
  });

  test('[X-201.AC01] all surfaces produced one and the same record shape', () => {
    assert.ok(shapes.size >= 7, `only ${[...shapes.keys()].join(', ')} reported`);
    assert.equal(new Set(shapes.values()).size, 1, `record shapes differ: ${[...shapes.entries()].map(([k, v]) => `${k}=${v}`).join(' | ')}`);
  });

  test('[X-201.AC01] hostile input: an unknown surface, a missing hypothesis, garbage results and a hostile finding never throw or yield a record', () => {
    assert.equal(emitVerification('not-a-surface', {}, { hypothesisId: 'x' }).ok, false);
    assert.equal(emitVerification('fix-verify', {}, {}).ok, false, 'no hypothesis id is not guessed');
    for (const surface of SURFACES.filter((s) => s !== 'oracle')) {
      const r = emitVerification(surface, { proofEvidence: 7, verdict: {}, legs: 'x', discovery: [] }, { hypothesisId: 'h' });
      assert.equal(typeof r.ok, 'boolean');
      if (r.ok) assert.equal(validateVerificationRecord(r.record).ok, true);
    }
    // an oracle emission cannot be made without the oracle runner's fields
    assert.equal(emitVerification('oracle', null, { hypothesisId: 'h' }).ok, false);
    // and one carrying fields that break the record rules is refused by the validator, not trusted
    const lie = emitVerification('oracle', null, {
      hypothesisId: 'h', commit: COMMIT,
      fields: { outcome: 'confirmed', reason: 'trust me', attempt: 1, evidence: [], oracle: { id: 'x', kind: 'model' }, scope: { description: 'd', platform: 'p' }, preconditions: { valid: true } },
    });
    assert.equal(lie.ok, false);
  });

  test('[X-201.AC01] headCommit reads a real commit and refuses a non-repository', () => {
    const dir = mkTestTmp('x201-nogit-');
    assert.equal(headCommit(dir), null);
    assert.equal(headCommit(undefined), null);
  });
});

// ---------------------------------------------------------------- AC02

function recordFor(outcome) {
  const base = {
    hypothesisId: 'hyp-1', commit: COMMIT, detectorOrigin: { detector: 'cmd-inj' }, attempt: 1, reason: `an honest reason for ${outcome}`,
    scope: { description: 'round-trip fixture', platform: process.platform },
  };
  const proof = [{ id: 'proof', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: `sha256:${'1'.repeat(64)}`, source: 'fixture' }];
  const obs = [{ id: 'obs', kind: 'observation', producer: 'tool', digest: `sha256:${'2'.repeat(64)}`, source: 'fixture' }];
  const oracle = { id: 'o', kind: 'runtime-replay', version: '1' };
  switch (outcome) {
    case 'confirmed': return buildVerificationRecord({ ...base, outcome, oracle, evidence: proof, preconditions: { valid: true } });
    case 'refuted': return buildVerificationRecord({ ...base, outcome, oracle, evidence: proof, preconditions: { valid: true } });
    case 'inconclusive': return buildVerificationRecord({ ...base, outcome, oracle, evidence: obs, preconditions: { valid: true } });
    case 'error': return buildVerificationRecord({ ...base, outcome, oracle: null, evidence: [], preconditions: { valid: false } });
    case 'unsupported': return buildVerificationRecord({ ...base, outcome, attempt: 0, oracle: null, evidence: [], preconditions: { valid: false } });
    case 'not-run': return buildVerificationRecord({ ...base, outcome, attempt: 0, oracle: null, evidence: [], preconditions: { valid: false } });
    default: throw new Error(outcome);
  }
}

describe('[X-201.AC02] the six outcomes survive a round trip and legacy consumers get explicit adapters', () => {
  test('[X-201.AC02] each of the six outcomes round-trips through JSON with its id, level and outcome intact', () => {
    assert.deepEqual([...VERIFICATION_OUTCOMES].sort(), ['confirmed', 'error', 'inconclusive', 'not-run', 'refuted', 'unsupported']);
    const seen = new Set();
    for (const outcome of VERIFICATION_OUTCOMES) {
      const rec = recordFor(outcome);
      assert.equal(validateVerificationRecord(rec).ok, true, `${outcome}: ${JSON.stringify(validateVerificationRecord(rec).errors)}`);
      const back = JSON.parse(JSON.stringify(rec));
      assert.deepEqual(back, rec);
      assert.equal(validateVerificationRecord(back).ok, true);
      assert.equal(migrateRecord('verification', back).ok, true, 'a current-format record passes the migration entry point untouched');
      assert.equal(back.outcome, outcome);
      seen.add(back.id);
    }
    assert.equal(seen.size, 6, 'six distinct outcomes must be six distinct records');
  });

  test('[X-201.AC02] the legacy view never coerces: true only for confirmed, false only for refuted, null for the other four', () => {
    const views = Object.fromEntries(VERIFICATION_OUTCOMES.map((o) => [o, toLegacyVerificationView(recordFor(o))]));
    assert.equal(views.confirmed.verified, true);
    assert.equal(views.refuted.verified, false);
    for (const o of ['inconclusive', 'unsupported', 'error', 'not-run']) {
      assert.equal(views[o].verified, null, `${o} must not read as a boolean`);
      assert.equal(views[o].status, o, `${o} keeps its own name for a legacy string consumer`);
    }
    assert.equal(new Set(Object.values(views).map((v) => v.status)).size, 6);
  });

  test('[X-201.AC02] a round-tripped record cannot be promoted by editing it: outcome, level and evidence edits are all caught', () => {
    const inc = JSON.parse(JSON.stringify(recordFor('inconclusive')));
    assert.equal(validateVerificationRecord({ ...inc, outcome: 'confirmed' }).ok, false);
    assert.equal(validateVerificationRecord({ ...inc, outcome: 'refuted' }).ok, false);
    const ref = JSON.parse(JSON.stringify(recordFor('refuted')));
    assert.equal(validateVerificationRecord({ ...ref, outcome: 'confirmed' }).ok, false, 'the id binds the outcome');
    const conf = JSON.parse(JSON.stringify(recordFor('confirmed')));
    assert.equal(validateVerificationRecord({ ...conf, confirmationLevel: 'adjudicated' }).ok, false);
    assert.equal(validateVerificationRecord({ ...conf, evidence: [] }).ok, false);
    assert.equal(validateVerificationRecord({ ...conf, extra: true }).ok, false, 'closed world');
  });

  test('[X-201.AC02] each surface maps its native states to distinct, non-coerced outcomes', () => {
    const verdict = (verifier_verdict, verifier_reason) => emitVerification('verifier', { ...finding(), verifier_verdict, verifier_reason }, { hypothesisId: 'h', commit: null }).record.outcome;
    assert.equal(verdict('verified-exploit', 'poc-exit-0'), 'inconclusive');
    assert.equal(verdict('verified-by-llm', 'llm-accept'), 'inconclusive');
    assert.equal(verdict('verified-sanitizer-absence', 'no-sanitizer-in-window'), 'inconclusive');
    assert.equal(verdict('unverified-by-design', 'family-no-poc:x'), 'unsupported');
    assert.equal(verdict('cannot-verify', 'sandbox-error:boom'), 'error');
    assert.equal(verdict('cannot-verify', 'verifier-exception:x'), 'error');
    assert.equal(verdict('cannot-verify', 'no confinement primitive available on this host; refusing'), 'unsupported');
    assert.equal(verdict('cannot-verify', 'poc-timeout'), 'inconclusive');
    assert.equal(verdict('cannot-verify', 'poc-exit:1'), 'inconclusive');
    assert.equal(verdict('cannot-verify', 'poc-validation-failed:x'), 'not-run');
    assert.equal(verdict(undefined, undefined), 'not-run');
    const proof = (proofEvidence) => emitVerification('execution-proof', { ...finding(), proofEvidence }, { hypothesisId: 'h', commit: null }).record.outcome;
    assert.equal(proof({ tier: 'execution-proven', ran: true }), 'inconclusive');
    assert.equal(proof({ tier: 'proof-failed', ran: true }), 'inconclusive', 'proof-failed is a triage signal, not a refutation');
    assert.equal(proof({ tier: 'taint-proven', ran: false, reason: 'no confinement primitive available; refusing to execute' }), 'unsupported');
    assert.equal(proof({ tier: 'taint-proven', ran: false, witnessStatus: 'error', reason: 'x could not start' }), 'error');
    assert.equal(proof({ tier: 'taint-proven', ran: false, reason: 'no proof-of-concept attached' }), 'not-run');
    // the explicit boolean adapter: a legacy `true` is not a confirmation, a legacy `false` is not a refutation
    const legacy = (v) => migrateRecord('verification', { verified: v }, { hypothesisId: 'h' }).record.outcome;
    assert.equal(legacy(true), 'inconclusive');
    assert.equal(legacy(false), 'inconclusive');
    assert.equal(legacy(null), 'not-run');
  });
});

// ---------------------------------------------------------------- AC03

describe('[X-201.AC03] evidence kinds are distinct and a model verdict never confirms', () => {
  const D = (c) => `sha256:${c.repeat(64)}`;
  const withEvidence = (outcome, evidence, extra = {}) => buildVerificationRecord({
    hypothesisId: 'h', commit: COMMIT, detectorOrigin: { detector: 'd' }, attempt: 1, outcome, reason: 'r', evidence,
    oracle: { id: 'o', kind: 'runtime-replay', version: '1' }, scope: { description: 's', platform: 'p' }, preconditions: { valid: true }, ...extra,
  });

  test('[X-201.AC03] the four evidence kinds are separate, and each constrains who may have produced it', () => {
    assert.deepEqual([...EVIDENCE_KINDS], ['observation', 'inference', 'independent-adjudication', 'trusted-runtime-proof']);
    const ok = (kind, producer) => validateVerificationRecord(withEvidence('inconclusive', [{ id: 'e', kind, producer, digest: D('3') }])).ok;
    assert.equal(ok('observation', 'tool'), true);
    assert.equal(ok('inference', 'model'), true);
    assert.equal(ok('independent-adjudication', 'human'), true);
    assert.equal(ok('independent-adjudication', 'independent-verifier'), true);
    assert.equal(ok('trusted-runtime-proof', 'trusted-runner'), true);
    // the hostile direction: nobody can borrow a stronger kind
    assert.equal(ok('trusted-runtime-proof', 'model'), false);
    assert.equal(ok('trusted-runtime-proof', 'tool'), false);
    assert.equal(ok('trusted-runtime-proof', 'human'), false);
    assert.equal(ok('independent-adjudication', 'model'), false);
    assert.equal(ok('independent-adjudication', 'tool'), false);
    assert.equal(ok('observation', 'model'), false);
  });

  test('[X-201.AC03] a model-generated verdict alone cannot make a confirmed record, however it is dressed', () => {
    const inference = { id: 'e', kind: 'inference', producer: 'model', digest: D('4') };
    assert.equal(validateVerificationRecord(withEvidence('confirmed', [inference])).ok, false);
    const forged = withEvidence('confirmed', [{ id: 'e', kind: 'trusted-runtime-proof', producer: 'model', digest: D('4') }]);
    assert.equal(validateVerificationRecord(forged).ok, false, 'a model cannot label its output runtime proof');
    const modelOracle = withEvidence('confirmed', [{ id: 'e', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: D('4') }], { oracle: { id: 'm', kind: 'model', version: '1' } });
    assert.equal(validateVerificationRecord(modelOracle).ok, false, 'a model oracle can never yield confirmed');
    const modelRefutes = withEvidence('refuted', [{ id: 'e', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: D('4') }], { oracle: { id: 'm', kind: 'model', version: '1' } });
    assert.equal(validateVerificationRecord(modelRefutes).ok, false, 'nor refuted');
  });

  test('[X-201.AC03] every surface that is fed a model verdict lands below confirmed', async () => {
    const llm = emitVerification('verifier', { ...finding(), verifier_verdict: 'verified-by-llm', verifier_reason: 'llm-accept' }, { hypothesisId: 'h', commit: COMMIT });
    assert.equal(llm.record.outcome, 'inconclusive');
    assert.deepEqual(llm.record.evidence.map((e) => [e.kind, e.producer]), [['inference', 'model']]);
    assert.equal(llm.record.confirmationLevel, 'none');
    const hunt = emitVerification('hunt', { ...finding(), discovery: { lens: 'injection', confirmation: { tier: 'taint-confirmed', evidence: { line: 1 } }, refutation: { votes: [{ refuted: false }] } } }, { hypothesisId: 'h', commit: COMMIT });
    assert.equal(hunt.record.outcome, 'inconclusive');
    assert.ok(hunt.record.evidence.some((e) => e.kind === 'inference' && e.producer === 'model'), 'the panel is recorded as inference');
    assert.ok(!hunt.record.evidence.some((e) => ['trusted-runtime-proof', 'independent-adjudication'].includes(e.kind)));
    const panel = emitVerification('autopilot', { outcome: 'NEEDS_REVIEW', validation: 'refuted' }, { finding: finding(), commit: COMMIT });
    assert.equal(panel.record.outcome, 'inconclusive', 'a validator refutation is not a refutation');
  });

  test('[X-201.AC03] independent adjudication is a distinct route to confirmed, and is not runtime proof', () => {
    const adj = withEvidence('confirmed', [{ id: 'a', kind: 'independent-adjudication', producer: 'human', digest: D('5') }], { oracle: { id: 'review', kind: 'human', version: '1' } });
    assert.equal(validateVerificationRecord(adj).ok, true, JSON.stringify(validateVerificationRecord(adj).errors));
    assert.equal(adj.confirmationLevel, 'adjudicated');
    const runtime = withEvidence('confirmed', [{ id: 'p', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: D('6') }]);
    assert.equal(runtime.confirmationLevel, 'runtime-confirmed');
    assert.notEqual(adj.confirmationLevel, runtime.confirmationLevel);
    // a claimed runtime level on adjudication-only evidence is a forged level
    assert.equal(validateVerificationRecord({ ...adj, confirmationLevel: 'runtime-confirmed' }).ok, false);
  });
});
