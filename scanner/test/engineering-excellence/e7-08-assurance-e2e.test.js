// E7-08: a release snapshot with a true positive, a false positive, an unscanned file, a timed-out analyzer, a verified fix, an uncertain context-analysis signal
// and a runtime artifact from another build. The verdict is deterministic, it never says the release is safe while a required scan or verification is incomplete,
// the package is signed and verifies offline, tampering is refused, and every unknown has a reason a person can read.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runFullScan } from '../../src/engine.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { computeScanHealth } from '../../src/pipeline/scan-health.js';
import { runSupervised, summarizeSupervised } from '../../src/pipeline/supervised-analyzers.js';
import { buildFixVerificationRecord, LEG_NAMES, leg } from '../../src/fix/verification-record.js';
import { buildRuntimeExplanation } from '../../src/posture/runtime-explanation.js';
import { buildSnapshotRef } from '../../src/posture/assurance/evidence-registry.js';
import { buildReleasePackage, signReleasePackage } from '../../src/posture/assurance/release-package.js';
import { verifyReleasePackage } from '../../src/posture/assurance/release-package-verify.js';
import { releaseVerdict, verifyStatedVerdict } from '../../src/posture/assurance/release-verdict.js';
import { buildViews, renderText } from '../../src/report/perspectives.js';

setStateWritesEnabled(false);
const FIXTURE_MOD = path.join(path.dirname(new URL(import.meta.url).pathname), 'fixtures', 'supervised-tasks.js');
const kp = crypto.generateKeyPairSync('ed25519'); const PRIV = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }); const PUB = kp.publicKey.export({ type: 'spki', format: 'pem' });
const SNAP = buildSnapshotRef({ commit: 'a'.repeat(40), engineVersion: 'test' });

// ---- the project: real files, one real scan ----------------------------------------------------------------------------------
const APP = "const express = require('express');\nconst { exec } = require('child_process');\nconst app = express();\napp.get('/run', (req, res) => { exec('ls ' + req.query.d); res.end(); });\n";
const HUGE = 'var data = "' + 'x'.repeat(520000) + '";\n'; // over the per-file size limit: the engine skips it
const scanFiles = async (files) => runFullScan({ fileContents: files, scanRoot: null, deep: true });
const clean = await scanFiles({ 'app.js': APP });
const withHuge = await scanFiles({ 'app.js': APP, 'huge.js': HUGE });
const tp = (clean.findings.find((f) => f.parser === 'IR-TAINT') || clean.findings[0]);

// an analyzer that timed out, through the real supervised runner and the real scan-health computation
const supervised = summarizeSupervised(await runSupervised([{ id: 'slow', modulePath: FIXTURE_MOD, exportName: 'infiniteLoop' }, { id: 'ok', modulePath: FIXTURE_MOD, exportName: 'good', args: ['a'] }], { timeoutMs: 700 }));
const healthWith = (scan, analyzerCoverage) => computeScanHealth({ scanMeta: scan._scanMeta, analyzerCoverage, deepStatus: scan.scanHealth && scan.scanHealth.deepAnalysis ? null : null });
const completeHealth = { ...clean.scanHealth, status: 'complete', conditions: [], files: { expected: 1, scanned: 1, skipped: 0, timedOut: 0 }, analyzers: { failed: 0, timedOut: 0 } };
const skippedHealth = healthWith(withHuge, null);
const timedOutHealth = healthWith(clean, supervised.analyzerCoverage);

const TRUE_POSITIVE = { ...tp, id: 'tp-1', stableId: 'sf-tp000001', severity: 'high', proofTier: 'execution-proven' };
const FALSE_POSITIVE = { ...tp, id: 'fp-1', stableId: 'sf-fp000001', severity: 'high', proofTier: 'unproven', triage: { state: 'false_positive', by: 'reviewer-7', reason: 'the value is a constant set at start-up' } };
const DCI_UNCERTAIN = { ...tp, id: 'dci-1', stableId: 'sf-dci00001', severity: 'high', proofTier: 'unproven', contextIntelligence: { counterexample: { state: 'unresolved' } } };
const fixRecord = buildFixVerificationRecord({ findingId: 'tp-1', findingStableId: 'sf-tp000001', mode: 'verify', route: 'deterministic', patchHash: 'sha256:' + 'b'.repeat(64), affectedFiles: ['app.js'], preCommit: 'a'.repeat(40), requiredLegs: ['securityBefore', 'securityAfter', 'newFindingDelta'], securityBefore: leg('passed'), securityAfter: leg('passed'), newFindingDelta: leg('passed') });
const unverifiedFix = buildFixVerificationRecord({ findingId: 'tp-1', findingStableId: 'sf-tp000001', mode: 'verify', route: 'deterministic', patchHash: 'sha256:' + 'b'.repeat(64), affectedFiles: ['app.js'], requiredLegs: ['securityAfter', 'behaviorTests'], securityAfter: leg('passed'), behaviorTests: leg('not_run', { reason: 'no tests were found' }) });
const mismatchedRuntime = buildRuntimeExplanation(DCI_UNCERTAIN, { pathKeys: ['route|/run|app.run'], snapshotIdentity: { commit: 'a'.repeat(40) }, sampling: { state: 'complete' }, reconciled: { edges: [{ key: 'route|/run|app.run', state: 'statically_inferred', confidence: 0.3, matchedRecords: 0, mismatchedRecords: 4, unattestedRecords: 0 }] } });

function assemble({ health = completeHealth, findings = [TRUE_POSITIVE], fix = null, runtime = null, sign = true, verdictOverride = null } = {}) {
  const evidence = [{ kind: 'scan-health', payload: health }];
  findings.forEach((f) => evidence.push({ kind: 'finding', payload: f }));
  if (fix) evidence.push({ kind: 'fix-verification', payload: fix, restsOn: [1] });
  if (runtime) evidence.push({ kind: 'runtime-explanation', payload: runtime });
  const draft = buildReleasePackage({ snapshot: SNAP, evidence });
  const v = verdictOverride || releaseVerdict(draft).verdict;
  const pkg = buildReleasePackage({ snapshot: SNAP, evidence, policyDecisions: [{ id: 'release-verdict', outcome: v, reason: releaseVerdict(draft).statement, policyVersion: '1' }], assertions: [{ id: 'scan-finished', text: 'the scan finished', status: health.status === 'complete' ? 'supported' : 'unknown', reason: health.status === 'complete' ? undefined : 'the scan did not finish cleanly', evidence: health.status === 'complete' ? [0] : [] }] });
  return sign ? signReleasePackage(pkg, PRIV) : pkg;
}
const codes = (r) => [...r.blockers, ...r.unknowns].map((x) => x.code).sort();

test('THE SNAPSHOT WITH EVERY KIND OF PROBLEM: not deployable, each cause named in words, and nothing is called safe', () => {
  const pkg = assemble({ health: { ...timedOutHealth, files: { ...(timedOutHealth.files || {}), unanalysed: 1 } }, findings: [TRUE_POSITIVE, FALSE_POSITIVE, DCI_UNCERTAIN], fix: unverifiedFix, runtime: mismatchedRuntime });
  const r = releaseVerdict(pkg);
  assert.equal(r.verdict, 'not_deployable');
  assert.deepEqual(codes(r), ['ANALYZER_TIMED_OUT', 'CONTEXT_SIGNAL_UNSETTLED', 'FILES_SKIPPED', 'FIX_NOT_VERIFIED', 'PROVEN_OPEN_FINDING', 'RUNTIME_BUILD_MISMATCH', 'SCAN_INCOMPLETE']);
  const text = JSON.stringify(r);
  assert.ok(!/\bsafe\b/i.test(text.replace('That is not a statement that the release is safe.', '')), 'the word safe is only ever used to say it is not claimed');
  for (const x of [...r.blockers, ...r.unknowns]) { assert.ok(x.message.length > 25, x.code); assert.ok(x.evidence.length >= 1, `${x.code} points at the evidence it comes from`); assert.ok(x.evidence.every((d) => /^sha256:[0-9a-f]{64}$/.test(d))); }
  const m = Object.fromEntries([...r.blockers, ...r.unknowns].map((x) => [x.code, x.message]));
  assert.match(m.FILES_SKIPPED, /1 file\(s\) were skipped/); assert.match(m.ANALYZER_TIMED_OUT, /1 analyzer\(s\) timed out, so what they would have found is not in this result/);
  assert.match(m.FIX_NOT_VERIFIED, /a fix for sf-tp000001 is claimed but was not fully verified \(behaviorTests: not_run \(no tests were found\)\)/); assert.match(m.PROVEN_OPEN_FINDING, /sf-tp000001 \(high\) is proven exploitable and is open/);
  assert.match(m.RUNTIME_BUILD_MISMATCH, /came from a different build than the one released/); assert.match(m.CONTEXT_SIGNAL_UNSETTLED, /sf-dci00001 \(high\) rests on a context signal the analysis could not settle \(unresolved\)/);
  assert.equal(r.statement, '5 condition(s) block the release.', '5 blockers (the other two causes are unknowns a person decides)');
});

test('THE REAL ENGINE FEEDS THE POLICY: a real skipped file and a real timed-out analyzer are what the verdict reads, not hand-written numbers', () => {
  assert.ok(withHuge._scanMeta.filesOversizeSkipped >= 1, 'the engine skipped the oversize file'); assert.equal(clean.scanHealth.files.unanalysed, 0); assert.equal(skippedHealth.status, 'partial'); assert.ok(skippedHealth.files.unanalysed >= 1); assert.ok(skippedHealth.conditions.some((c) => /not analysed because they are over the size limit/.test(c)));
  assert.equal(timedOutHealth.analyzers.timedOut, 1); assert.equal(timedOutHealth.status, 'partial');
  const a = releaseVerdict(assemble({ health: skippedHealth, findings: [] }));
  assert.ok(a.blockers.some((b) => b.code === 'FILES_NOT_SCANNED' && /1 of 2 files were not scanned/.test(b.message)), JSON.stringify(a.blockers));
  const b = releaseVerdict(assemble({ health: timedOutHealth, findings: [] }));
  assert.ok(b.blockers.some((x) => x.code === 'ANALYZER_TIMED_OUT') && b.blockers.some((x) => x.code === 'SCAN_INCOMPLETE'));
  assert.equal(releaseVerdict(assemble({ findings: [] })).verdict, 'deployable', 'and a clean complete scan with nothing open is deployable');
});

test('STEP BY STEP: removing the causes one at a time moves the verdict from not_deployable, to needs_review, to deployable, and never past an unresolved cause', () => {
  const v = (o) => releaseVerdict(assemble(o));
  const all = { health: { ...timedOutHealth, files: { ...(timedOutHealth.files || {}), unanalysed: 1 } }, findings: [TRUE_POSITIVE, FALSE_POSITIVE, DCI_UNCERTAIN], fix: unverifiedFix, runtime: mismatchedRuntime };
  assert.equal(v(all).verdict, 'not_deployable');
  const finished = { ...all, health: completeHealth };
  assert.deepEqual(codes(v(finished)), ['CONTEXT_SIGNAL_UNSETTLED', 'FIX_NOT_VERIFIED', 'PROVEN_OPEN_FINDING', 'RUNTIME_BUILD_MISMATCH'], 'the scan is complete now, but a proven finding is open and its fix is unverified');
  assert.equal(v(finished).verdict, 'not_deployable');
  const verified = { ...finished, fix: fixRecord };
  assert.deepEqual(v(verified).blockers.map((b) => b.code), [], 'a fully verified fix clears the proven finding'); assert.equal(v(verified).verdict, 'needs_review', 'what remains is unknown, so a person decides');
  assert.deepEqual(codes(v(verified)), ['CONTEXT_SIGNAL_UNSETTLED', 'RUNTIME_BUILD_MISMATCH']);
  const noRuntime = { ...verified, runtime: null };
  assert.equal(v(noRuntime).verdict, 'needs_review', 'the context signal is still unsettled'); assert.deepEqual(codes(v(noRuntime)), ['CONTEXT_SIGNAL_UNSETTLED']);
  const resolved = { ...noRuntime, findings: [TRUE_POSITIVE, FALSE_POSITIVE] };
  assert.equal(v(resolved).verdict, 'deployable', 'with every cause resolved, and only then'); assert.deepEqual(codes(v(resolved)), []);
  assert.match(v(resolved).statement, /not a statement that the release is safe/);
});

test('NEVER DEPLOYABLE WHILE A REQUIRED SCAN OR VERIFICATION IS INCOMPLETE: each incompleteness alone is enough to withhold it', () => {
  const base = { findings: [] };
  const cases = {
    'scan did not finish': { health: { ...completeHealth, status: 'partial', conditions: ['2 annotator(s) threw and were skipped: x'] } },
    'a file was not scanned': { health: { ...completeHealth, files: { expected: 5, scanned: 4, skipped: 0, timedOut: 0 } } },
    'a file was skipped': { health: { ...completeHealth, files: { expected: 5, scanned: 5, skipped: 1, unanalysed: 1, timedOut: 0 } } },
    'a file timed out': { health: { ...completeHealth, files: { expected: 5, scanned: 5, skipped: 0, timedOut: 1 } } },
    'an analyzer timed out': { health: { ...completeHealth, analyzers: { failed: 1, timedOut: 1 } } },
    'an analyzer failed': { health: { ...completeHealth, analyzers: { failed: 2, timedOut: 0 } } },
    'a claimed fix is not verified': { findings: [TRUE_POSITIVE], fix: unverifiedFix },
  };
  for (const [name, o] of Object.entries(cases)) { const r = releaseVerdict(assemble({ ...base, ...o })); assert.notEqual(r.verdict, 'deployable', name); assert.equal(r.verdict, 'not_deployable', name); assert.ok(r.blockers.length >= 1, name); }
  const noHealth = buildReleasePackage({ snapshot: SNAP, evidence: [{ kind: 'finding', payload: unproven() }] });
  assert.equal(releaseVerdict(noHealth).verdict, 'not_deployable'); assert.equal(releaseVerdict(noHealth).blockers[0].code, 'NO_SCAN_HEALTH');
  assert.equal(releaseVerdict(null).verdict, 'not_deployable'); assert.equal(releaseVerdict({}).verdict, 'not_deployable');
  function unproven() { return { ...tp, proofTier: 'unproven', severity: 'low' }; }
});

test('WAIVERS and FALSE POSITIVES: an honoured waiver is listed and does not block; a false positive without a named person and reason is an unknown, not a pass', () => {
  const r = releaseVerdict(assemble({ findings: [TRUE_POSITIVE] }), { waivedIds: ['sf-tp000001'] });
  assert.equal(r.verdict, 'deployable'); assert.deepEqual(r.waived, ['sf-tp000001']);
  const bare = { ...FALSE_POSITIVE, triage: { state: 'false_positive' } };
  const u = releaseVerdict(assemble({ findings: [bare] })); assert.equal(u.verdict, 'needs_review'); assert.equal(u.unknowns[0].code, 'FALSE_POSITIVE_UNJUSTIFIED');
  assert.equal(releaseVerdict(assemble({ findings: [FALSE_POSITIVE] })).verdict, 'deployable', 'a justified false positive does not block');
  const lowOpen = releaseVerdict(assemble({ findings: [{ ...tp, id: 'low', stableId: 'sf-low', severity: 'low', proofTier: 'unproven' }] })); assert.equal(lowOpen.verdict, 'deployable', 'a low unproven finding is not a blocker');
});

test('DETERMINISTIC: the same package gives the same verdict, reasons and order, whatever order the evidence arrived in', () => {
  const o = { health: timedOutHealth, findings: [TRUE_POSITIVE, FALSE_POSITIVE, DCI_UNCERTAIN], fix: unverifiedFix, runtime: mismatchedRuntime };
  const a = JSON.stringify(releaseVerdict(assemble(o))); const b = JSON.stringify(releaseVerdict(assemble(o)));
  const c = JSON.stringify(releaseVerdict(assemble({ ...o, findings: [DCI_UNCERTAIN, FALSE_POSITIVE, TRUE_POSITIVE], fix: null }))).length > 0;
  assert.equal(a, b); assert.ok(c);
  const p1 = assemble(o); const p2 = assemble(o); assert.equal(JSON.stringify({ ...p1, signature: null }), JSON.stringify({ ...p2, signature: null }), 'the package itself is deterministic apart from the signature');
});

test('THE PACKAGE IS SIGNED, VERIFIES OFFLINE, AND TAMPERING IS REFUSED: a changed verdict, a removed blocker and a lying key-holder are each caught', () => {
  const pkg = assemble({ health: timedOutHealth, findings: [TRUE_POSITIVE], runtime: mismatchedRuntime });
  assert.equal(verifyReleasePackage(pkg, PUB).ok, true); assert.deepEqual(verifyStatedVerdict(pkg), { ok: true, stated: 'not_deployable', computed: 'not_deployable', message: null });
  // someone flips the stated verdict
  const flipped = JSON.parse(JSON.stringify(pkg)); flipped.policy.decisions[0].outcome = 'deployable';
  const f = verifyReleasePackage(flipped, PUB); assert.equal(f.ok, false); assert.ok(f.errors.some((e) => e.code === 'SIGNATURE'));
  // someone removes the evidence that blocks
  const stripped = JSON.parse(JSON.stringify(pkg)); stripped.evidence = stripped.evidence.filter((e) => e.ref.kind !== 'finding'); assert.equal(verifyReleasePackage(stripped, PUB).ok, false);
  // someone edits the scan health to look finished
  const lying = JSON.parse(JSON.stringify(pkg)); lying.evidence[0].payload.status = 'complete'; const l = verifyReleasePackage(lying, PUB); assert.equal(l.ok, false);
  // the key holder signs a package that states a verdict its contents do not support: the signature is valid, the stated verdict is not
  const liar = assemble({ health: timedOutHealth, findings: [TRUE_POSITIVE], runtime: mismatchedRuntime, verdictOverride: 'deployable' });
  assert.equal(verifyReleasePackage(liar, PUB).ok, true, 'the signature is genuine'); const lv = verifyStatedVerdict(liar);
  assert.equal(lv.ok, false); assert.equal(lv.stated, 'deployable'); assert.equal(lv.computed, 'not_deployable'); assert.match(lv.message, /states "deployable" but its own contents give "not_deployable"/);
  assert.equal(verifyStatedVerdict(assemble({ health: completeHealth, findings: [] }, { sign: false })).ok, true);
  const nov = buildReleasePackage({ snapshot: SNAP, evidence: [{ kind: 'scan-health', payload: completeHealth }] }); assert.equal(verifyStatedVerdict(nov).ok, false); assert.match(verifyStatedVerdict(nov).message, /states no release verdict/);
});

test('HUMAN-READABLE UNKNOWNS: the auditor and CISO views carry the verdict, the blockers and the unknowns, in words, with the evidence they rest on', () => {
  const pkg = assemble({ health: timedOutHealth, findings: [TRUE_POSITIVE, DCI_UNCERTAIN], runtime: mismatchedRuntime });
  const views = buildViews(pkg, { verification: verifyReleasePackage(pkg, PUB) });
  assert.equal(views.ciso.verdict.verdict, 'not_deployable'); assert.ok(views.ciso.verdict.blockers.some((b) => /proven exploitable and is open/.test(b)));
  const text = renderText(views, 'ciso'); assert.match(text, /release verdict: not_deployable/); assert.match(text, /blocks: .*proven exploitable/); assert.match(text, /unknown: .*different build/);
  assert.ok(views.auditor.unknowns.some((u) => /scan completeness/.test(u.about) && u.reason.length > 10));
  assert.match(views.auditor.doesNotProve, /real or exploitable/);
});
