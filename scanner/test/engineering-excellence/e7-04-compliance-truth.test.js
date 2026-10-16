// E7-04: every control is in one of six states; incomplete data yields no fabricated OSCAL verdict; coverage denominators are explicit; the framework as a
// whole is never declared compliant; existing reports still round-trip.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { TRUTH_STATES, assessFrameworkTruth, classifyControl } from '../../src/posture/compliance-truth.js';
import { complianceRowsFromEvaluation, complianceRowsFromTruth, toOSCALCompliance } from '../../src/report/oscal.js';
import { evaluateFramework } from '../../src/posture/auditor-walkthrough.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const BIN = path.join(ROOT, 'scanner', 'bin', 'agentic-security.js');
const COMPLETE = { scanStatus: 'complete', scanExaminedFiles: true };
const row = (status, control = {}, extra = {}) => ({ control: { id: 'C1', summary: 's', codeTestable: 'yes', mapsTo: ['family:a', 'family:b'], ...control }, status, observations: [], controlRefs: [], ...extra });
const state = (r, ctx = COMPLETE) => classifyControl(r, ctx).state;

test('the six states, and every rule that decides between them', () => {
  assert.deepEqual([...TRUTH_STATES], ['assessed_satisfied', 'assessed_not_satisfied', 'not_assessed', 'not_applicable', 'requires_human_review', 'insufficient_evidence']);
  // satisfied needs: every signal cleared, a complete scan that examined files, adequate evidence, and a control the publisher rates fully code-testable
  assert.equal(state(row('present')), 'assessed_satisfied');
  assert.equal(state(row('present'), { scanStatus: 'partial', scanExaminedFiles: true }), 'insufficient_evidence');
  assert.equal(state(row('present'), { scanExaminedFiles: true }), 'insufficient_evidence', 'a scan of unknown health is not complete');
  assert.equal(state(row('present'), { scanStatus: 'complete', scanExaminedFiles: false }), 'insufficient_evidence');
  assert.equal(state(row('present', {}, { evidence: { tier: 'weak' } })), 'insufficient_evidence');
  assert.equal(state(row('present', {}, { partiallyEvidenced: true })), 'insufficient_evidence');
  assert.equal(state(row('present', { codeTestable: 'partial' })), 'requires_human_review', 'signals cleared, but the rest of the control needs a person');
  assert.equal(state(row('present', { codeTestable: 'no' })), 'requires_human_review');
  assert.equal(state(row('present', { mapsTo: ['family:a'], codeTestable: 'partial' })), 'requires_human_review');
  assert.equal(state(row('present', { mapsTo: ['family:a'], codeTestable: undefined })), 'requires_human_review', 'one scanner signal with no publisher rating is not an obligation satisfied');
  assert.equal(state(row('present', { mapsTo: ['family:a'], codeTestable: 'yes' })), 'assessed_satisfied', 'a control that IS one check can be satisfied by it');
  // failures
  assert.equal(state(row('absent')), 'assessed_not_satisfied');
  assert.equal(state(row('partial', {}, { controlRefs: [{ id: 'f1' }] })), 'assessed_not_satisfied');
  assert.equal(state(row('absent'), { scanStatus: 'partial' }), 'assessed_not_satisfied', 'an open problem is conclusive even when the scan was incomplete');
  assert.equal(state(row('partial')), 'insufficient_evidence', 'partial with nothing attributable is an unverifiable mapping, not a failure');
  // manual
  assert.equal(state(row('manual', { codeTestable: 'no', mapsTo: [] })), 'requires_human_review');
  assert.equal(state(row('manual', { codeTestable: 'yes', mapsTo: [] })), 'not_assessed');
  assert.equal(state(row('manual', { codeTestable: 'partial', mapsTo: [] })), 'not_assessed');
  // unknown status
  assert.equal(state(row('wat')), 'not_assessed'); assert.equal(state(null), 'not_assessed');
  // not applicable is declared, never inferred
  const na = { C1: { reason: 'no payment processing in scope', declaredBy: 'ciso@example' } };
  assert.equal(state(row('present'), { ...COMPLETE, notApplicable: na }), 'not_applicable');
  assert.equal(state(row('absent'), { ...COMPLETE, notApplicable: na }), 'not_applicable');
  assert.equal(state(row('present'), { ...COMPLETE, notApplicable: { C1: { reason: 'x' } } }), 'insufficient_evidence', 'no person named: the declaration is not honoured');
  assert.equal(state(row('present'), { ...COMPLETE, notApplicable: { C1: { declaredBy: 'x' } } }), 'insufficient_evidence');
  assert.equal(state(row('manual', { codeTestable: 'no', id: 'C2', mapsTo: [] }), { ...COMPLETE, notApplicable: na }), 'requires_human_review', 'a declaration for another control does not apply');
});

test('DENOMINATORS: states add up to the controls evaluated, applicable excludes not_applicable, and unevaluated controls are counted', () => {
  const rows = [row('present'), row('absent', { id: 'C2' }), row('manual', { id: 'C3', codeTestable: 'no', mapsTo: [] }), row('present', { id: 'C4', codeTestable: 'partial' }), row('manual', { id: 'C5', codeTestable: 'yes', mapsTo: [] }), row('present', { id: 'C6' })];
  const a = assessFrameworkTruth({ id: 'fw', controlCount: 10 }, rows, { ...COMPLETE, notApplicable: { C6: { reason: 'out of scope', declaredBy: 'owner' } } });
  const d = a.denominators;
  assert.equal(Object.values(d.byState).reduce((x, y) => x + y, 0), 6);
  assert.deepEqual(d.byState, { assessed_satisfied: 1, assessed_not_satisfied: 1, not_assessed: 1, not_applicable: 1, requires_human_review: 2, insufficient_evidence: 0 });
  assert.equal(d.declaredControls, 10); assert.equal(d.evaluatedControls, 6); assert.equal(d.unevaluatedControls, 4);
  assert.equal(d.applicable, 5); assert.equal(d.assessed, 2); assert.equal(d.assessedOfApplicable, 0.4); assert.equal(d.satisfiedOfApplicable, 0.2); assert.equal(d.needAPersonOrMoreEvidence, 3);
  assert.equal(a.frameworkClaim.established, false); assert.match(a.frameworkClaim.statement, /assessed 2 of 5 applicable controls/); assert.match(a.frameworkClaim.statement, /does not establish compliance/);
  assert.ok(a.frameworkClaim.reasons.some((r) => /4 control\(s\) of the framework were not evaluated at all/.test(r)));
  assert.equal(assessFrameworkTruth({ id: 'x' }, [], COMPLETE).denominators.assessedOfApplicable, null, 'no controls: no ratio, not 100% and not 0%');
});

test('THE FRAMEWORK IS NEVER DECLARED COMPLIANT: even when every applicable control is satisfied the claim is about the signals', () => {
  const all = assessFrameworkTruth({ id: 'fw' }, [row('present'), row('present', { id: 'C2' })], COMPLETE);
  assert.equal(all.denominators.satisfiedOfApplicable, 1); assert.equal(all.frameworkClaim.established, false);
  assert.match(all.frameworkClaim.statement, /statement about those signals; it is not a statement that the system complies/);
});

test('OSCAL: only the two assessed states become findings; every other state is an observation with its own remark and no verdict', () => {
  const rows = [row('present'), row('absent', { id: 'C2' }), row('manual', { id: 'C3', codeTestable: 'no', mapsTo: [] }), row('manual', { id: 'C4', codeTestable: 'yes', mapsTo: [] }), row('present', { id: 'C5' }), row('present', { id: 'C6' })];
  const a = assessFrameworkTruth({ id: 'fw', name: 'Framework' }, rows, { scanStatus: 'partial', scanExaminedFiles: true, notApplicable: { C6: { reason: 'r', declaredBy: 'p' } } });
  // under a partial scan nothing "present" may be satisfied
  assert.deepEqual(a.controls.map((c) => c.state), ['insufficient_evidence', 'assessed_not_satisfied', 'requires_human_review', 'not_assessed', 'insufficient_evidence', 'not_applicable']);
  const doc = toOSCALCompliance({ id: 'fw', name: 'Framework' }, complianceRowsFromTruth(a), {});
  const ar = doc.results[0];
  assert.equal(ar.findings.length, 1, 'one finding: the only control with a conclusive result'); assert.equal(ar.findings[0].target.status.state, 'not-satisfied');
  assert.equal(ar.observations.length, 6, 'every control is an observation');
  const remarks = Object.fromEntries(ar.observations.map((o) => [o.props.find((p) => p.name === 'truth-state').value, o.remarks]));
  assert.match(remarks.insufficient_evidence, /Insufficient evidence/); assert.match(remarks.requires_human_review, /Requires human review/); assert.match(remarks.not_assessed, /Not assessed: nothing examined/); assert.match(remarks.not_applicable, /Declared not applicable/);
  const satisfiedCount = JSON.stringify(doc).split('"state":"satisfied"').length - 1;
  assert.equal(satisfiedCount, 0, 'no control is reported satisfied from a partial scan');
});

test('INCOMPLETE DATA yields no fabricated verdict: every control of an unexamined scan is unassessed or insufficient, none satisfied', () => {
  const rows = [row('present'), row('present', { id: 'C2', codeTestable: 'partial' }), row('manual', { id: 'C3', codeTestable: 'no', mapsTo: [] })];
  for (const ctx of [{ scanStatus: 'partial', scanExaminedFiles: true }, { scanStatus: 'complete', scanExaminedFiles: false }, {}]) {
    const a = assessFrameworkTruth({ id: 'fw' }, rows, ctx);
    assert.equal(a.denominators.byState.assessed_satisfied, 0, JSON.stringify(ctx));
    const doc = toOSCALCompliance({ id: 'fw' }, complianceRowsFromTruth(a), {});
    assert.equal(doc.results[0].findings?.length ?? 0, 0, 'no OSCAL finding at all');
  }
});

test('EXISTING REPORTS ROUND-TRIP: the evaluator-status OSCAL export is unchanged, and the truth model leaves the same controls in the same order', () => {
  const fwPath = path.join(ROOT, 'scanner', 'src', 'posture', 'compliance-frameworks', 'nist-800-171-r3.json');
  const fw = JSON.parse(fs.readFileSync(fwPath, 'utf8'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-04-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{}');
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [{ name: 'x' }], filesScanned: 5, _scanMeta: { filesScanned: 5 } };
    const evaluation = evaluateFramework(dir, fw, scan);
    const legacy = toOSCALCompliance(fw, complianceRowsFromEvaluation(evaluation), {});
    const a = assessFrameworkTruth(fw, evaluation, { scanStatus: 'complete', scanExaminedFiles: true });
    assert.equal(a.controls.length, evaluation.length); assert.deepEqual(a.controls.map((c) => c.id), evaluation.map((r) => r.control.id));
    assert.equal(a.denominators.declaredControls, fw.controlCount); assert.equal(a.denominators.unevaluatedControls, Math.max(0, fw.controlCount - evaluation.length));
    // the truth model is never MORE willing to say "satisfied" than the evaluator
    const legacySatisfied = new Set(evaluation.filter((r) => r.status === 'present').map((r) => r.control.id));
    for (const c of a.controls.filter((x) => x.state === 'assessed_satisfied')) assert.ok(legacySatisfied.has(c.id), `${c.id} satisfied only if the evaluator said present`);
    assert.ok(a.denominators.byState.assessed_satisfied <= legacySatisfied.size);
    const truthDoc = toOSCALCompliance(fw, complianceRowsFromTruth(a), {});
    assert.equal(truthDoc.results[0].observations.length, legacy.results[0].observations.length, 'same controls, same observations');
    assert.ok(Array.isArray(legacy.results[0].findings || []));
    assert.equal(legacy.metadata['oscal-version'], '1.1.2'); assert.equal(truthDoc.metadata['oscal-version'], '1.1.2');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('CLI: compliance --report <framework> --truth --format json|oscal, against a real scan, with and without an applicability declaration', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-04-cli-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0' }));
    fs.writeFileSync(path.join(dir, 'app.js'), "const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.send('ok'));\n");
    const sc = spawnSync(process.execPath, [BIN, 'scan', dir, '--no-network'], { encoding: 'utf8', timeout: 200_000 });
    assert.ok(sc.status !== null && sc.status <= 3, sc.stderr);
    const run = (...a) => spawnSync(process.execPath, [BIN, 'compliance', '--root', dir, '--report', 'nist-800-171-r3', ...a], { encoding: 'utf8', timeout: 200_000, cwd: dir });
    const j = run('--truth', '--format', 'json'); assert.equal(j.status, 0, j.stderr);
    const t = JSON.parse(j.stdout);
    assert.equal(t.frameworkId, 'nist-800-171-r3'); assert.equal(t.frameworkClaim.established, false);
    assert.equal(Object.values(t.denominators.byState).reduce((x, y) => x + y, 0), t.controls.length);
    assert.ok(t.controls.every((c) => TRUTH_STATES.includes(c.state)));
    const o = run('--truth', '--format', 'oscal'); assert.equal(o.status, 0, o.stderr);
    const doc = JSON.parse(o.stdout); assert.equal(doc.metadata['oscal-version'], '1.1.2');
    const legacy = run('--format', 'oscal'); assert.equal(legacy.status, 0); assert.ok(JSON.parse(legacy.stdout).results, 'the existing export still works without --truth');
    const first = t.controls[0].id;
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.agentic-security', 'compliance-applicability.json'), JSON.stringify({ 'nist-800-171-r3': { [first]: { reason: 'not in this system\'s boundary', declaredBy: 'system owner' } } }));
    const t2 = JSON.parse(run('--truth', '--format', 'json').stdout);
    assert.equal(t2.controls.find((c) => c.id === first).state, 'not_applicable'); assert.equal(t2.denominators.byState.not_applicable, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
