// E3-06: the tier matrix. Every completeness tier, in both modes, with the residual risk it carries.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { DEFAULT_POLICY, decidePatchApplication } from '../../src/fix/patch-policy.js';
import { applyVerifiedFix } from '../../src/fix/apply-fix-service.js';
import { buildFixVerificationRecord, evidenceItem, leg, validateFixVerificationRecord } from '../../src/fix/verification-record.js';

const E = evidenceItem({ kind: 'log', sha256: 'a'.repeat(64) });
const ok = () => leg('passed', { evidenceIds: [E.id] });
const nr = (r = 'did not run') => leg('not_run', { reason: r });
function rec(over = {}) {
  return buildFixVerificationRecord({
    findingId: 'F', mode: 'apply', route: 'test', patchHash: 'sha256:' + '3'.repeat(64), affectedFiles: ['a.js'],
    securityBefore: ok(), securityAfter: ok(), exploitProofBefore: ok(), exploitProofAfter: ok(), newFindingDelta: ok(), behaviorPreservation: ok(), behaviorTests: ok(), regressionTests: nr(), lint: leg('not_applicable', { reason: 'none' }), typecheck: leg('not_applicable', { reason: 'none' }), dependencyChecks: leg('not_applicable', { reason: 'none' }),
    requiredLegs: ['securityAfter', 'newFindingDelta', 'behaviorPreservation', 'behaviorTests'], evidence: [E], ...over,
  });
}
const AUTO = { automatic: { enabled: true } };
const low = { severity: 'medium' };
const decideAuto = (r, extra = {}) => decidePatchApplication({ record: r, finding: low, mode: 'automatic', policy: AUTO, ...extra });

const TIERS = {
  FULL: rec(),
  MITIGATION: rec({ behaviorTests: nr('no test command') }),
  WORKAROUND: rec({ workaround: true }),
  unverified: rec({ securityAfter: leg('failed', { evidenceIds: [E.id], reason: 'still present' }) }),
  blocked: rec({ failures: [{ leg: 'behaviorTests', reason: 'the runner crashed' }] }),
};

test('the five tiers are what the matrix says they are, each record is valid, and residual risk follows the tier', () => {
  for (const [tier, r] of Object.entries(TIERS)) { assert.equal(r.fixCompleteness, tier); assert.equal(validateFixVerificationRecord(r).ok, true, tier); }
  assert.equal(TIERS.FULL.residualRisk.level, 'low');
  assert.equal(TIERS.MITIGATION.residualRisk.level, 'medium');
  assert.equal(TIERS.WORKAROUND.residualRisk.level, 'high');
  assert.equal(TIERS.unverified.residualRisk.level, 'unknown');
  assert.equal(TIERS.blocked.residualRisk.level, 'unknown');
  assert.ok(TIERS.WORKAROUND.residualRisk.notes.some((n) => /cause remains/.test(n)));
  assert.ok(rec({ exploitProofAfter: nr('no reproducer') }).residualRisk.level === 'medium', 'FULL without a replay is not low risk');
});

test('requested mode: a person who asked gets FULL, MITIGATION and WORKAROUND applied with their warnings, and never unverified or blocked', () => {
  const d = (r) => decidePatchApplication({ record: r, mode: 'requested' });
  assert.equal(d(TIERS.FULL).decision, 'apply');
  assert.equal(d(TIERS.MITIGATION).decision, 'apply');
  assert.ok(d(TIERS.MITIGATION).warnings.some((w) => /^behaviorTests: not_run/.test(w)), 'the degraded leg travels with the decision');
  assert.equal(d(TIERS.WORKAROUND).decision, 'apply');
  assert.equal(d(TIERS.unverified).decision, 'refuse');
  assert.equal(d(TIERS.blocked).decision, 'refuse');
  for (const r of Object.values(TIERS)) { assert.equal(d(r).preview, true); assert.equal(d(r).undo, true); }
});

test('automatic mode is off by default: even a FULL, low-risk patch is only proposed', () => {
  assert.equal(DEFAULT_POLICY.automatic.enabled, false);
  const r = decidePatchApplication({ record: TIERS.FULL, finding: low, mode: 'automatic' });
  assert.equal(r.decision, 'propose'); assert.match(r.reasons[0], /not enabled/);
});

test('automatic mode, enabled: only FULL with every check passed and low risk is applied; MITIGATION and WORKAROUND are proposed; unverified and blocked are refused', () => {
  assert.equal(decideAuto(TIERS.FULL).decision, 'apply');
  const m = decideAuto(TIERS.MITIGATION);
  assert.equal(m.decision, 'propose');
  assert.ok(m.reasons.some((x) => /needs FULL/.test(x))); assert.ok(m.reasons.some((x) => /behaviorTests did not pass/.test(x)));
  assert.equal(decideAuto(TIERS.WORKAROUND).decision, 'propose');
  assert.equal(decideAuto(TIERS.unverified).decision, 'refuse');
  assert.equal(decideAuto(TIERS.blocked).decision, 'refuse');
});

test('never silently auto-apply with absent tests, an unobservable footprint, or a replay that did not run when policy demands one', () => {
  assert.equal(decideAuto(rec({ behaviorTests: nr('no test command') })).decision, 'propose');
  assert.equal(decideAuto(rec({ behaviorPreservation: nr('unobservable') })).decision, 'propose');
  assert.equal(decideAuto(rec({ exploitProofAfter: nr('no reproducer') })).decision, 'propose', 'residual risk medium is above the low limit');
  assert.equal(decidePatchApplication({ record: rec({ exploitProofAfter: nr('x') }), finding: low, mode: 'automatic', policy: { automatic: { enabled: true, maxResidualRisk: 'medium', requireExploitProof: true } } }).decision, 'propose');
  assert.equal(decidePatchApplication({ record: rec({ exploitProofAfter: nr('x') }), finding: low, mode: 'automatic', policy: { automatic: { enabled: true, maxResidualRisk: 'medium' } } }).decision, 'apply', 'a deliberately wider policy is honoured');
});

test('high and critical severity, high-impact categories and semantic auth changes are proposed, not applied, even when FULL', () => {
  for (const severity of ['high', 'critical']) assert.equal(decideAuto(TIERS.FULL, { finding: { severity } }).decision, 'propose', severity);
  assert.equal(decideAuto(TIERS.FULL, { finding: {} }).decision, 'propose', 'unknown severity is not assumed low');
  const cats = decideAuto(TIERS.FULL, { materialClassification: { highImpactCategories: ['authorization'] } });
  assert.equal(cats.decision, 'propose'); assert.ok(cats.reasons.some((x) => /alters authentication, authorization or cryptography/.test(x)));
  assert.equal(decideAuto(TIERS.FULL, { materialClassification: { highImpactCategories: ['schema'] } }).decision, 'propose');
  assert.equal(decideAuto(TIERS.FULL, { materialClassification: { risk: 'high' } }).decision, 'propose');
  assert.equal(decideAuto(TIERS.FULL, { finding: { severity: 'low' }, materialClassification: { highImpactCategories: [], risk: 'low' } }).decision, 'apply');
});

// ---- through the service ---------------------------------------------------------------------------------------------------

const VULN = "const { exec } = require('child_process');\nexports.ping = (req, cb) => exec('echo ' + req.query.host, (e, out) => cb(e, out));\n";
const GOOD = "const { execFile } = require('child_process');\nexports.ping = (req, cb) => execFile('echo', [String(req.query.host)], (e, out) => cb(e, out));\n";
const TEST = "const app = require('./app');\napp.ping({ query: { host: 'hello' } }, (e, out) => { if (e || !/hello/.test(out)) process.exit(1); });\n";
async function project(tests) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e3f-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', ...(tests ? { scripts: { test: 'node test.js' } } : {}) }));
  fs.writeFileSync(path.join(root, 'app.js'), VULN); if (tests) fs.writeFileSync(path.join(root, 'test.js'), TEST);
  const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
  let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
  const f = scan.findings.find((x) => /CWE-78/.test(x.cwe || ''));
  const st = path.join(root, '.agentic-security'); fs.mkdirSync(st, { recursive: true }); const body = JSON.stringify(scan);
  fs.writeFileSync(path.join(st, 'last-scan.json'), body); fs.writeFileSync(path.join(st, 'last-scan.json.sig'), signLastScan(body));
  return { root, ref: { file: 'app.js', id: f.id, stableId: f.stableId, vuln: f.vuln, severity: f.severity } };
}

test('through the service: an automatic write with no project tests is proposed and the tree is untouched; a requested write is applied with its warning', async () => {
  const p = await project(false);
  try {
    const auto = await applyVerifiedFix({ scanRoot: p.root, finding: { ...p.ref, severity: 'medium' }, files: { 'app.js': GOOD }, applyMode: 'automatic', policy: AUTO });
    assert.equal(auto.applied, false); assert.equal(auto.proposed, true); assert.equal(auto.policyDecision.decision, 'propose');
    assert.equal(fs.readFileSync(path.join(p.root, 'app.js'), 'utf8'), VULN);
    const asked = await applyVerifiedFix({ scanRoot: p.root, finding: p.ref, files: { 'app.js': GOOD } });
    assert.equal(asked.applied, true); assert.equal(asked.policyDecision.decision, 'apply');
    assert.ok(asked.policyDecision.warnings.some((w) => /^behaviorTests: not_run/.test(w)));
    assert.equal(asked.verifiedFull, false);
  } finally { cleanup(p.root); }
});

test('through the service: with tests that pass on the patched tree an enabled automatic write is a FULL-or-propose decision, never a silent MITIGATION', async () => {
  const p = await project(true);
  try {
    const dry = await applyVerifiedFix({ scanRoot: p.root, finding: { ...p.ref, severity: 'medium' }, files: { 'app.js': GOOD }, dryRun: true, applyMode: 'automatic', policy: { automatic: { enabled: true, maxResidualRisk: 'medium' } } });
    assert.equal(dry.fixVerification.behaviorTests.status, 'passed');
    assert.equal(dry.policyDecision.decision, dry.fixVerification.verifiedFull ? 'apply' : 'propose');
    assert.equal(dry.fixVerification.verifiedFull, true);
    const undoable = await applyVerifiedFix({ scanRoot: p.root, finding: { ...p.ref, severity: 'medium' }, files: { 'app.js': GOOD }, applyMode: 'automatic', policy: { automatic: { enabled: true, maxResidualRisk: 'medium' } } });
    assert.equal(undoable.applied, true);
    assert.ok(fs.existsSync(path.join(p.root, '.agentic-security', 'fix-history')), 'undo history exists for the automatic write');
  } finally { cleanup(p.root); }
});
