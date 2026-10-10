// X-204: patch-negative verification. A repair is `verified-fix` only when the exploit reproduces on the original revision,
// does not reproduce on the patched one, and declared functional behaviour is intact, each in an equivalent disposable
// environment. Every criterion is tested in both directions: the good path passes AND each hostile or incomplete path is refused
// with the specific incomplete step named.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyPatchNegative } from '../../src/posture/verification/patch-negative.js';
import { promotePatch } from '../../src/posture/verification/patch-promotion.js';
import { appendRepairRecord, recordPromotion, verificationRepairFor, withRepairStatus } from '../../src/posture/verification/repair-records.js';
import { verifyFix } from '../../src/posture/fix-verify.js';
import { verifyFixWithTests } from '../../src/posture/fix-verify-loop.js';
import { applyVerifiedFix } from '../../src/fix/apply-fix-service.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { validateVerificationRecord } from '../../src/posture/assurance/verification-record.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { getOracle } from '../../src/posture/oracles/registry.js';
import { runInBoundary, DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const COMMIT = 'a1'.repeat(20);
const OTHER_COMMIT = 'b2'.repeat(20);
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true, 'patch-negative-verification': true } } });
const OFF = resolveAssuranceConfig({ env: {}, overrides: { features: {} } });
const ORACLE_ONLY = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });
const PN_ONLY = resolveAssuranceConfig({ env: {}, overrides: { features: { 'patch-negative-verification': true } } });

let boundaryReady = false;
let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const report = await probeControls({});
  const unmet = unmetControls(report, [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  boundaryReady = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); patch-negative execution is UNVERIFIED here`;
});
const needsBoundary = (fn) => (t) => (boundaryReady ? fn(t) : t.skip(whyNot));

const read = (rel) => fs.readFileSync(path.join(SCANNER, 'test', 'fixtures', 'oracles', 'injection-execution', rel), 'utf8');
const VULNERABLE = read('positive/target.mjs');
const FIXED = read('negative/target.mjs');
const SCENARIO = JSON.parse(read('scenario.json'));
const FUNCTIONAL = { export: 'handler', cases: [{ id: 'echo-hello', args: ['hello'], expected: 'hello\n' }] };
// "fixes" that are wrong in the ways the criteria name
const STILL_VULNERABLE = `${VULNERABLE}\n// reviewed\n`;
const BROKEN_BUILD = 'export function handler(input) { return execFileSync( ;\n';
const DELETES_FEATURE = 'export function handler() { return ""; }\n';

const request = (over = {}) => ({
  hypothesisId: 'hyp-patch-1', commit: COMMIT,
  original: { files: { 'target.mjs': VULNERABLE }, entry: 'target.mjs', oracleId: 'injection-execution', inputs: SCENARIO },
  patch: { files: { 'target.mjs': FIXED } },
  functional: { inputs: FUNCTIONAL },
  ...over,
});
const counting = () => {
  const c = { n: 0 };
  c.runOptions = { deps: { runInBoundary: (...a) => { c.n++; return runInBoundary(...a); } } };
  return c;
};
const verify = (over, c = counting()) => verifyPatchNegative(request(over), { config: ON, runOptions: c.runOptions }).then((r) => ({ r, c }));
// other test files run oracles at the same time, so a global count is read after it settles, not once
const settled = async (ok) => { for (let i = 0; i < 150 && !ok(); i++) await new Promise((r) => setTimeout(r, 100)); return ok(); };
const tmpDirs = (prefix) => fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith(prefix));
// A workspace left behind is attributed to THIS test by its content: other test files run oracles at the same time, so a
// global count of oracle workspaces is not a measurement of this test.
const wsSnapshot = () => new Set(tmpDirs('oracle-ws-'));
const leakedWorkspaces = (before, matches) => tmpDirs('oracle-ws-').filter((n) => !before.has(n)).filter((n) => { try { return matches(fs.readFileSync(path.join(os.tmpdir(), n, 'target.mjs'), 'utf8')); } catch { return false; } });

// Only harnesses this test process spawned, or orphans (parent 1), count: a harness belonging to another test file running at the same time has a live parent of its own.
const harnessProcs = () => String(spawnSync('ps', ['-A', '-o', 'ppid=,command='], { encoding: 'utf8' }).stdout).split('\n').filter((l) => l.includes('__oracle_harness') && [1, process.pid].includes(Number(l.trim().split(/\s+/)[0]))).length;

// ---------------------------------------------------------------- AC01

describe('[X-204.AC01] original-positive, patched-negative and functional regression in equivalent disposable environments', () => {
  test('[X-204.AC01] a real fix is verified-fix: exploit confirmed on the original, refuted on the patch, functional cases intact', needsBoundary(async () => {
    const before_ = wsSnapshot();
    const MARK = '\n// pn-ac01-marker\n';
    const marked = { original: { ...request().original, files: { 'target.mjs': VULNERABLE + MARK } }, patch: { files: { 'target.mjs': FIXED + MARK } } };
    const { r, c } = await verify(marked);
    assert.equal(r.status, 'verified-fix', r.summary);
    assert.equal(r.verifiedFix, true);
    assert.equal(r.incompleteStep, null);
    assert.deepEqual(r.steps.map((s) => [s.step, s.status, s.outcome]), [
      ['original-positive', 'passed', 'confirmed'], ['patched-negative', 'passed', 'refuted'],
      ['functional-baseline', 'passed', 'refuted'], ['functional-regression', 'passed', 'refuted'],
    ]);
    assert.equal(c.n, 4, 'four oracle runs, every one through the trust boundary');
    assert.equal(r.records.original.outcome, 'confirmed');
    assert.equal(r.records.patched.outcome, 'refuted');
    assert.equal(r.records.original.commit, COMMIT);
    assert.equal(await settled(() => leakedWorkspaces(before_, (t) => t.includes('pn-ac01-marker')).length === 0), true, 'every disposable workspace was removed');
    assert.equal(await settled(() => harnessProcs() === 0), true, 'no harness process survived');
    assert.match(r.summary, /verified-fix: the exploit reproduced/);
    assert.match(r.summary, /Only the declared scenario and cases were exercised/);
  }));

  test('[X-204.AC01] the runs share one environment identity and cover the exact original and patched content', needsBoundary(async () => {
    const { r } = await verify({});
    const rc = r.receipts;
    const envs = new Set(Object.values(rc).map((x) => digestOf(x.environment)));
    assert.equal(envs.size, 1, 'equivalent environments: one sanitized identity across all four runs');
    assert.equal(rc.original.request.filesDigest, digestOf({ 'target.mjs': VULNERABLE }));
    assert.equal(rc.patched.request.filesDigest, digestOf({ 'target.mjs': FIXED }));
    assert.equal(rc.functionalBaseline.request.filesDigest, rc.original.request.filesDigest);
    assert.equal(rc.functional.request.filesDigest, rc.patched.request.filesDigest);
    assert.equal(rc.original.oracle.logicDigest, rc.patched.oracle.logicDigest, 'the exploit oracle is the same for both revisions');
    assert.equal(rc.original.request.inputsDigest, rc.patched.request.inputsDigest);
    assert.equal(rc.functional.oracle.id, 'functional-regression');
    assert.equal(r.patchDigest, digestOf({ 'target.mjs': FIXED }));
    assert.equal(JSON.stringify(r).includes(os.homedir()), false, 'no host paths in the result');
  }));

  test('[X-204.AC01] the original record carries repair status replay-verified with the id of the patched-negative record', needsBoundary(async () => {
    const { r } = await verify({});
    assert.equal(validateVerificationRecord(r.verificationRecord).ok, true);
    assert.equal(r.verificationRecord.outcome, 'confirmed');
    assert.deepEqual(r.verificationRecord.repair, { status: 'replay-verified', patchDigest: r.patchDigest, replayRecordId: r.records.patched.id });
  }));

  test('[X-204.AC01] verification is a gated feature: off by default, nothing runs, and a reader is told why', async () => {
    const c = counting();
    const off = await verifyPatchNegative(request(), { config: OFF, runOptions: c.runOptions });
    assert.equal(off.status, 'disabled');
    assert.equal(off.verifiedFix, false);
    assert.equal(c.n, 0);
    assert.match(off.reason, /patch-negative-verification/);
    const killed = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_NO_PATCH_NEGATIVE_VERIFICATION: '1' }, overrides: { features: { 'patch-negative-verification': true, 'verification-oracles': true } } });
    assert.equal((await verifyPatchNegative(request(), { config: killed, runOptions: c.runOptions })).status, 'disabled', 'a kill switch beats an enable');
    assert.equal(c.n, 0);
  });
});

// ---------------------------------------------------------------- AC02

describe('[X-204.AC02] an incomplete step prevents verified-fix and is named specifically', () => {
  const notVerified = (r, step, code) => {
    assert.equal(r.status, 'not-verified-fix', r.summary);
    assert.equal(r.verifiedFix, false);
    assert.equal(r.incompleteStep, step);
    assert.equal(r.failureCode, code);
    assert.match(r.summary, new RegExp(`NOT verified-fix: incomplete step '${step}' \\(${code}\\)`));
    assert.notEqual(r.verificationRecord?.repair?.status, 'replay-verified');
  };

  test('[X-204.AC02] an original that does not reproduce the exploit is not verified-fix, and nothing after it runs', needsBoundary(async () => {
    const { r, c } = await verify({ original: { files: { 'target.mjs': FIXED }, entry: 'target.mjs', oracleId: 'injection-execution', inputs: SCENARIO } });
    notVerified(r, 'original-positive', 'original-not-reproduced');
    assert.equal(c.n, 1, 'stopped at the failed step');
    assert.deepEqual(r.steps.map((s) => s.status), ['failed', 'not-run', 'not-run', 'not-run']);
  }));

  test('[X-204.AC02] a patch that is still exploitable is not verified-fix', needsBoundary(async () => {
    const { r } = await verify({ patch: { files: { 'target.mjs': STILL_VULNERABLE } } });
    notVerified(r, 'patched-negative', 'patched-still-exploitable');
    assert.equal(r.steps[0].status, 'passed', 'the original did reproduce');
  }));

  test('[X-204.AC02] a patched revision that does not build is not verified-fix', needsBoundary(async () => {
    const { r } = await verify({ patch: { files: { 'target.mjs': BROKEN_BUILD } } });
    notVerified(r, 'patched-negative', 'patched-build-broken');
    assert.equal(r.steps[1].outcome, 'inconclusive', 'a broken build is never read as a refuted exploit');
  }));

  test('[X-204.AC02] an omitted functional check prevents verified-fix before anything executes', async () => {
    const { r, c } = await verify({ functional: undefined });
    notVerified(r, 'functional-regression', 'functional-omitted');
    assert.equal(c.n, 0);
    const empty = await verify({ functional: {} });
    notVerified(empty.r, 'functional-regression', 'functional-omitted');
  });

  test('[X-204.AC02] a patch that silences the exploit by deleting the feature is caught by the functional check', needsBoundary(async () => {
    const { r } = await verify({ patch: { files: { 'target.mjs': DELETES_FEATURE } } });
    notVerified(r, 'functional-regression', 'functional-regression-detected');
    assert.equal(r.steps[1].status, 'passed', 'the exploit really is gone');
    assert.equal(r.steps[2].status, 'passed', 'the expectations hold on the original');
    assert.equal(r.steps[3].outcome, 'confirmed', 'a regression is the confirmed hypothesis of the functional oracle');
  }));

  test('[X-204.AC02] functional expectations that fail on the ORIGINAL are reported as such, not blamed on the patch', needsBoundary(async () => {
    const wrong = { export: 'handler', cases: [{ id: 'echo-hello', args: ['hello'], expected: 'nope' }] };
    const { r } = await verify({ functional: { inputs: wrong } });
    notVerified(r, 'functional-baseline', 'functional-baseline-invalid');
    assert.equal(r.steps[3].status, 'not-run');
  }));

  test('[X-204.AC02] a changed oracle is not verified-fix: different inputs, a different oracle, or an oracle other than the pinned one', async () => {
    const c = counting();
    const inputs = { ...SCENARIO, benign: 'something else' };
    const a = await verify({ patched: { inputs } }, c);
    notVerified(a.r, 'oracle-consistency', 'oracle-changed');
    const b = await verify({ patched: { oracleId: 'authorization-decision' } }, c);
    notVerified(b.r, 'oracle-consistency', 'oracle-changed');
    const real = getOracle('injection-execution');
    const d = await verify({ pinnedOracle: { id: real.id, version: real.version, logicDigest: `sha256:${'0'.repeat(64)}` } }, c);
    notVerified(d.r, 'oracle-consistency', 'oracle-changed');
    assert.equal(c.n, 0, 'a changed oracle is refused before any run');
  });

  test('[X-204.AC02] no exact revision, a bad request or an unknown oracle is refused up front', async () => {
    const c = counting();
    notVerified((await verify({ commit: null }, c)).r, 'input-validation', 'revision-unbound');
    notVerified((await verify({ commit: 'main' }, c)).r, 'input-validation', 'revision-unbound');
    notVerified((await verify({ patch: { files: {} } }, c)).r, 'input-validation', 'bad-request');
    notVerified((await verify({ hypothesisId: '' }, c)).r, 'input-validation', 'bad-request');
    notVerified((await verify({ original: { files: { 'target.mjs': VULNERABLE }, entry: 'target.mjs', oracleId: 'no-such-oracle', inputs: SCENARIO } }, c)).r, 'input-validation', 'unknown-oracle');
    notVerified((await verify({ original: { files: { 'target.mjs': VULNERABLE }, entry: 'target.mjs', oracleId: 'functional-regression', inputs: FUNCTIONAL } }, c)).r, 'input-validation', 'bad-request');
    const none = await verifyPatchNegative(null, { config: ON });
    assert.equal(none.verifiedFix, false);
    assert.equal(c.n, 0);
  });

  test('[X-204.AC02] a missing prerequisite parks the verification as incomplete, never as a pass', needsBoundary(async () => {
    const c = counting();
    const r = await verifyPatchNegative(request(), { config: PN_ONLY, runOptions: c.runOptions });
    notVerified(r, 'original-positive', 'prerequisite-unmet');
    assert.equal(r.resumable, true, 'enabling the oracle feature is something an operator can do');
    assert.equal(c.n, 0, 'nothing executed');
    const blocked = await verifyPatchNegative(request(), { config: ON, runOptions: { deps: { runInBoundary: async () => ({ blocked: true, executed: false, reasons: ['control read-denial is unproved'] }) } } });
    notVerified(blocked, 'original-positive', 'prerequisite-unmet');
    assert.equal(blocked.steps[0].outcome, 'unsupported');
  }));

  test('[X-204.AC02] runs in different environments are refused as environment-mismatch', needsBoundary(async () => {
    let n = 0;
    const runOptions = { deps: { runInBoundary: async (...a) => { const res = await runInBoundary(...a); n++; return n === 4 ? { ...res, backend: res.backend === 'namespace' ? 'userspace' : 'namespace' } : res; } } };
    const r = await verifyPatchNegative(request(), { config: ON, runOptions });
    notVerified(r, 'environment-equivalence', 'environment-mismatch');
    assert.equal(r.promotion.ok, false);
    assert.ok(r.promotion.reasons.some((x) => x.code === 'environment-mismatch' && x.role === 'functional'));
  }));
});

// ---------------------------------------------------------------- AC03

describe('[X-204.AC03] separate records, and promotion only on receipts that match the exact diff and revision', () => {
  const H = 'hyp-ledger';
  const D1 = `sha256:${'1'.repeat(64)}`;
  const D2 = `sha256:${'2'.repeat(64)}`;
  const fields = (kind, over = {}) => ({ kind, hypothesisId: H, revision: COMMIT, diffDigest: D1, reason: 'because', ...over });

  test('[X-204.AC03] proposal, rejection, application and rollback are separate records, each linked to the one before', () => {
    let l = [];
    const proposed = appendRepairRecord(l, fields('proposed')); l = proposed.records;
    const rejected = appendRepairRecord(l, fields('rejected', { step: 'patched-negative', reason: 'patched-still-exploitable: still exploitable' }));
    assert.equal(rejected.ok, true);
    assert.deepEqual(rejected.records.map((r) => r.kind), ['proposed', 'rejected']);
    assert.equal(rejected.record.previous, proposed.record.id);
    assert.notEqual(rejected.record.id, proposed.record.id);
    assert.equal(Object.isFrozen(rejected.record), true, 'a record is immutable');
    assert.equal(l.length, 1, 'the input ledger is never changed');
    assert.deepEqual(verificationRepairFor(rejected.records, H, D1), { status: 'proposed', patchDigest: D1 }, 'a rejection leaves the CORE-002 repair at proposed');
    // the ledger is per diff: a different diff is a different history
    assert.equal(appendRepairRecord(rejected.records, fields('proposed', { diffDigest: D2 })).ok, true);
    // rejected is terminal
    for (const kind of ['applied', 'rolled-back', 'proposed']) assert.equal(appendRepairRecord(rejected.records, fields(kind)).ok, false, `${kind} after rejected`);
  });

  test('[X-204.AC03] nothing is applied that was not promoted, a promotion cannot be written by hand, and a rollback needs something to undo', () => {
    const proposed = appendRepairRecord([], fields('proposed')).records;
    assert.equal(appendRepairRecord(proposed, fields('applied')).ok, false, 'applied needs a promotion');
    assert.equal(appendRepairRecord([], fields('applied')).ok, false);
    assert.match(appendRepairRecord(proposed, fields('promoted')).errors.join(), /recordPromotion/);
    assert.equal(recordPromotion(proposed, { ok: true, hypothesisId: H, revision: COMMIT, diffDigest: D1, receiptDigests: {}, reasons: [] }).ok, false, 'a hand-built promotion is not accepted');
    assert.equal(appendRepairRecord(proposed, fields('rolled-back')).ok, false, 'nothing to roll back');
    assert.equal(appendRepairRecord(proposed, fields('rejected', { reason: '' })).ok, false, 'a rejection needs a reason');
    assert.equal(appendRepairRecord(proposed, fields('made-up')).ok, false);
    assert.equal(appendRepairRecord(proposed, fields('rejected', { revision: 'main' })).ok, false, 'a revision must be an exact commit');
    assert.equal(appendRepairRecord(proposed, fields('rejected', { diffDigest: 'x' })).ok, false);
    assert.equal(appendRepairRecord(undefined, 'nope').ok, false);
  });

  test('[X-204.AC03] a verified patch is promoted, applied and rolled back as separate records mapped onto the CORE-002 repair status', needsBoundary(async () => {
    const { r } = await verify({});
    assert.deepEqual(r.repairRecords.map((x) => x.kind), ['proposed', 'promoted']);
    const patched = r.records.patched.id;
    assert.deepEqual(verificationRepairFor(r.repairRecords, 'hyp-patch-1', r.patchDigest, patched), { status: 'replay-verified', patchDigest: r.patchDigest, replayRecordId: patched });
    const applied = appendRepairRecord(r.repairRecords, { kind: 'applied', hypothesisId: 'hyp-patch-1', revision: COMMIT, diffDigest: r.patchDigest, reason: 'written' });
    assert.equal(applied.ok, true);
    assert.equal(verificationRepairFor(applied.records, 'hyp-patch-1', r.patchDigest, patched).status, 'applied');
    const back = appendRepairRecord(applied.records, { kind: 'rolled-back', hypothesisId: 'hyp-patch-1', revision: COMMIT, diffDigest: r.patchDigest, reason: 'reverted by the operator' });
    assert.equal(back.ok, true);
    assert.deepEqual(back.records.map((x) => x.kind), ['proposed', 'promoted', 'applied', 'rolled-back']);
    assert.equal(new Set(back.records.map((x) => x.id)).size, 4, 'four distinct records');
    assert.equal(verificationRepairFor(back.records, 'hyp-patch-1', r.patchDigest).status, 'rolled-back');
    const rebuilt = withRepairStatus(r.verificationRecord, verificationRepairFor(back.records, 'hyp-patch-1', r.patchDigest));
    assert.equal(validateVerificationRecord(rebuilt).ok, true);
    assert.equal(rebuilt.repair.status, 'rolled-back');
    assert.equal(r.verificationRecord.repair.status, 'replay-verified', 'the earlier record is not rewritten');
    assert.equal(promotionRecordsHaveReceipts(r.repairRecords), true);
  }));

  const promotionRecordsHaveReceipts = (records) => records.find((x) => x.kind === 'promoted').receiptDigests && Object.keys(records.find((x) => x.kind === 'promoted').receiptDigests).length === 4;

  test('[X-204.AC03] a rejected patch leaves a rejection record naming the step, and no promotion', needsBoundary(async () => {
    const { r } = await verify({ patch: { files: { 'target.mjs': STILL_VULNERABLE } } });
    assert.deepEqual(r.repairRecords.map((x) => x.kind), ['proposed', 'rejected']);
    const rej = r.repairRecords[1];
    assert.equal(rej.step, 'patched-negative');
    assert.match(rej.reason, /patched-still-exploitable/);
    assert.equal(appendRepairRecord(r.repairRecords, { kind: 'applied', hypothesisId: 'hyp-patch-1', revision: COMMIT, diffDigest: r.patchDigest }).ok, false, 'a rejected patch cannot then be applied');
  }));

  test('[X-204.AC03] receipts for the exact diff and revision promote; a receipt for a different diff does not', needsBoundary(async () => {
    const { r } = await verify({});
    const proposal = { hypothesisId: 'hyp-patch-1', revision: COMMIT, originalFiles: { 'target.mjs': VULNERABLE }, patchFiles: { 'target.mjs': FIXED } };
    const good = promotePatch({ proposal, receipts: r.receipts });
    assert.equal(good.ok, true, JSON.stringify(good.reasons));
    assert.equal(good.diffDigest, digestOf({ 'target.mjs': FIXED }));
    assert.equal(good.revision, COMMIT);
    // the same receipts presented for a different diff
    const other = promotePatch({ proposal: { ...proposal, patchFiles: { 'target.mjs': `${FIXED}\n// a different diff\n` } }, receipts: r.receipts });
    assert.equal(other.ok, false);
    assert.ok(other.reasons.some((x) => x.code === 'receipt-diff' && x.role === 'patched'));
    assert.ok(other.reasons.some((x) => x.code === 'receipt-diff' && x.role === 'functional'));
    assert.equal(recordPromotion([], other).ok, false, 'a refused promotion cannot be recorded');
    // a different revision
    const rev = promotePatch({ proposal: { ...proposal, revision: OTHER_COMMIT }, receipts: r.receipts });
    assert.equal(rev.ok, false);
    assert.ok(rev.reasons.some((x) => x.code === 'receipt-revision'));
    // a different hypothesis
    assert.ok(promotePatch({ proposal: { ...proposal, hypothesisId: 'hyp-other' }, receipts: r.receipts }).reasons.some((x) => x.code === 'receipt-hypothesis'));
    // the original files differ from what the receipts covered
    assert.ok(promotePatch({ proposal: { ...proposal, originalFiles: { 'target.mjs': `${VULNERABLE}// edited` } }, receipts: r.receipts }).reasons.some((x) => x.code === 'receipt-diff'));
  }));

  test('[X-204.AC03] a receipt that was copied, hand-built, edited, missing, swapped between roles or reused does not promote', needsBoundary(async () => {
    const { r } = await verify({});
    const proposal = { hypothesisId: 'hyp-patch-1', revision: COMMIT, originalFiles: { 'target.mjs': VULNERABLE }, patchFiles: { 'target.mjs': FIXED } };
    const refused = (receipts, code, role) => {
      const p = promotePatch({ proposal, receipts });
      assert.equal(p.ok, false, `${code} must not promote`);
      assert.ok(p.reasons.some((x) => x.code === code && (role === undefined || x.role === role)), `${code}: ${JSON.stringify(p.reasons)}`);
    };
    const clone = (x) => JSON.parse(JSON.stringify(x));
    refused({ ...r.receipts, patched: clone(r.receipts.patched) }, 'receipt-not-issued', 'patched');
    refused({ ...r.receipts, original: { ...r.receipts.original } }, 'receipt-not-issued', 'original');
    refused({ ...r.receipts, patched: { schema: 'agentic-security/oracle-receipt', issuedBy: 'verifier', settled: { outcome: 'refuted', preconditionsHeld: true }, request: {} } }, 'receipt-not-issued', 'patched');
    refused({ ...r.receipts, functional: undefined }, 'receipt-missing', 'functional');
    refused({ ...r.receipts, patched: r.receipts.original, original: r.receipts.patched }, 'receipt-outcome');
    refused({ ...r.receipts, patched: r.receipts.original }, 'receipt-diff', 'patched');
    assert.throws(() => { r.receipts.patched.settled.outcome = 'confirmed'; }, TypeError, 'an issued receipt is deep-frozen');
    assert.equal(promotePatch({ proposal, receipts: null }).ok, false);
    assert.equal(promotePatch({ proposal: { ...proposal, revision: null }, receipts: r.receipts }).reasons[0].code, 'revision-unbound');
    assert.equal(promotePatch({ proposal: { ...proposal, patchFiles: {} }, receipts: r.receipts }).reasons[0].code, 'bad-proposal');
    assert.equal(promotePatch().ok, false);
    // only a promotion promotePatch returned can be recorded, and a copy of a good one cannot
    const good = promotePatch({ proposal, receipts: r.receipts });
    const proposed = appendRepairRecord([], { kind: 'proposed', hypothesisId: 'hyp-patch-1', revision: COMMIT, diffDigest: good.diffDigest }).records;
    assert.equal(recordPromotion(proposed, { ...good }).ok, false, 'a copy of a good promotion is not a promotion');
    assert.equal(recordPromotion(proposed, good).ok, true);
  }));

  // ------------------------------------------------------------ the integration points, flag on and flag off

  const project = (files) => {
    const root = mkTestTmp('pn-proj-');
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture"}\n');
    fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
    for (const [rel, content] of Object.entries(files)) fs.writeFileSync(path.join(root, rel), content);
    return root;
  };
  const spec = () => ({ original: request().original, functional: { inputs: FUNCTIONAL }, commit: COMMIT });

  test('[X-204.AC03] fix-verify reports verified-fix only through the patch-negative leg, and is unchanged with the flag off', needsBoundary(async () => {
    const root = project({ 'target.mjs': VULNERABLE });
    const base = await verifyFix({ scanRoot: root, originalFindingStableId: 'hyp-patch-1', files: { 'target.mjs': FIXED }, recordMetrics: false });
    const off = await verifyFix({ scanRoot: root, originalFindingStableId: 'hyp-patch-1', files: { 'target.mjs': FIXED }, recordMetrics: false, patchNegative: spec(), assuranceConfig: OFF });
    assert.equal(off.ok, base.ok);
    assert.equal(off.summary, base.summary, 'flag off: the summary is exactly the legacy summary');
    assert.equal(off.fixStatus, undefined, 'flag off: no new verdict field');
    assert.equal(off.patchNegative.status, 'disabled');

    const on = await verifyFix({ scanRoot: root, originalFindingStableId: 'hyp-patch-1', files: { 'target.mjs': FIXED }, recordMetrics: false, patchNegative: spec(), assuranceConfig: ON });
    assert.equal(on.fixStatus, 'verified-fix', on.summary);
    assert.equal(on.ok, base.ok && true);
    assert.match(on.summary, /patch-negative: PASS \(verified-fix\)/);

    const bad = await verifyFix({ scanRoot: root, originalFindingStableId: 'hyp-patch-1', files: { 'target.mjs': STILL_VULNERABLE }, recordMetrics: false, patchNegative: spec(), assuranceConfig: ON });
    assert.equal(bad.fixStatus, 'not-verified-fix');
    assert.equal(bad.ok, false, 'a patch the oracle did not verify is not ok');
    assert.match(bad.summary, /patch-negative: FAIL .* 'patched-negative' \(patched-still-exploitable\)/);
  }));

  test('[X-204.AC03] the closed loop gives verified-fix only with the patch-negative leg, and its legacy verdicts with the flag off', needsBoundary(async () => {
    const root = project({ 'target.mjs': VULNERABLE });
    const args = { scanRoot: root, originalFindingStableId: 'hyp-patch-1' };
    const legacy = await verifyFixWithTests({ ...args, files: { 'target.mjs': FIXED } });
    const off = await verifyFixWithTests({ ...args, files: { 'target.mjs': FIXED }, patchNegative: spec(), assuranceConfig: OFF });
    assert.equal(off.verdict, legacy.verdict, 'flag off: the legacy verdict');
    assert.equal(off.legs.patchNegative, undefined);
    const on = await verifyFixWithTests({ ...args, files: { 'target.mjs': FIXED }, patchNegative: spec(), assuranceConfig: ON });
    assert.equal(on.verdict, 'verified-fix', on.summary);
    assert.equal(on.legs.patchNegative.ok, true);
    const bad = await verifyFixWithTests({ ...args, files: { 'target.mjs': DELETES_FEATURE }, patchNegative: spec(), assuranceConfig: ON });
    assert.equal(bad.verdict, 'verification-failed');
    assert.equal(bad.legs.patchNegative.detail.incompleteStep, 'functional-regression');
  }));

  const signedProject = (files) => {
    const root = project(files);
    const body = JSON.stringify({ findings: [] });
    fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json'), body);
    fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
    return root;
  };
  const finding = { file: 'target.mjs', id: 'F1', stableId: 'hyp-patch-1' };

  test('[X-204.AC03] apply_fix writes only a promoted patch, keeps separate application records, and is unchanged with the flag off', needsBoundary(async () => {
    // flag off: the existing flow applies the patch exactly as before, with no new fields
    const legacyRoot = signedProject({ 'target.mjs': VULNERABLE });
    const legacy = await applyVerifiedFix({ scanRoot: legacyRoot, finding, files: { 'target.mjs': FIXED }, patchNegative: spec(), assuranceConfig: OFF });
    assert.equal(legacy.ok, true, legacy.reason);
    assert.equal(legacy.applied, true);
    assert.equal(legacy.repairRecords, undefined);
    assert.equal(legacy.patchNegative, undefined);
    assert.equal(fs.readFileSync(path.join(legacyRoot, 'target.mjs'), 'utf8'), FIXED);

    // flag on, verified-fix: promoted, then applied, as separate records
    const root = signedProject({ 'target.mjs': VULNERABLE });
    const ok = await applyVerifiedFix({ scanRoot: root, finding, files: { 'target.mjs': FIXED }, patchNegative: spec(), assuranceConfig: ON });
    assert.equal(ok.ok, true, ok.reason);
    assert.equal(ok.applied, true);
    assert.equal(ok.patchNegative.status, 'verified-fix');
    assert.deepEqual(ok.repairRecords.map((x) => x.kind), ['proposed', 'promoted', 'applied']);
    assert.equal(fs.readFileSync(path.join(root, 'target.mjs'), 'utf8'), FIXED);

    // flag on, a patch that does not verify: refused, disk untouched, a rejection record and no application record
    const badRoot = signedProject({ 'target.mjs': VULNERABLE });
    const bad = await applyVerifiedFix({ scanRoot: badRoot, finding, files: { 'target.mjs': STILL_VULNERABLE }, patchNegative: spec(), assuranceConfig: ON });
    assert.equal(bad.ok, false);
    assert.equal(bad.applied, false);
    assert.equal(fs.readFileSync(path.join(badRoot, 'target.mjs'), 'utf8'), VULNERABLE, 'disk untouched');
    assert.deepEqual(bad.repairRecords.map((x) => x.kind), ['proposed', 'rejected']);
    assert.equal(bad.repairRecords[1].step, 'patched-negative');

    // dry run: verified, nothing written, no application record
    const dryRoot = signedProject({ 'target.mjs': VULNERABLE });
    const dry = await applyVerifiedFix({ scanRoot: dryRoot, finding, files: { 'target.mjs': FIXED }, patchNegative: spec(), assuranceConfig: ON, dryRun: true });
    assert.equal(dry.ok, true);
    assert.equal(dry.applied, false);
    assert.deepEqual(dry.repairRecords.map((x) => x.kind), ['proposed', 'promoted']);
    assert.equal(fs.readFileSync(path.join(dryRoot, 'target.mjs'), 'utf8'), VULNERABLE);
  }));

  test('[X-204.AC03] a write that fails after promotion is recorded as its own rollback record', needsBoundary(async (t) => {
    const root = signedProject({});
    fs.mkdirSync(path.join(root, 'sub'));
    fs.writeFileSync(path.join(root, 'sub', 'target.mjs'), VULNERABLE);
    fs.chmodSync(path.join(root, 'sub'), 0o555); // the write (create, rename) into this directory fails
    const sub = { original: { ...request().original, files: { 'sub/target.mjs': VULNERABLE }, entry: 'sub/target.mjs' }, functional: { inputs: FUNCTIONAL }, commit: COMMIT };
    let err = null;
    let result = null;
    try { result = await applyVerifiedFix({ scanRoot: root, finding: { ...finding, file: 'sub/target.mjs' }, files: { 'sub/target.mjs': FIXED }, patchNegative: sub, assuranceConfig: ON }); } catch (e) { err = e; }
    fs.chmodSync(path.join(root, 'sub'), 0o755);
    if (!err && result && result.applied) return t.skip('SKIPPED, NOT PASSED: this process can write into a read-only directory, so the write failure cannot be injected');
    const records = (err && err.repairRecords) || (result && result.repairRecords) || [];
    assert.deepEqual(records.map((x) => x.kind), ['proposed', 'promoted', 'rolled-back'], err ? String(err.message) : JSON.stringify(result));
    assert.match(records[2].reason, /restored/);
    assert.equal(fs.readFileSync(path.join(root, 'sub', 'target.mjs'), 'utf8'), VULNERABLE, 'the original content is intact');
  }));
});
