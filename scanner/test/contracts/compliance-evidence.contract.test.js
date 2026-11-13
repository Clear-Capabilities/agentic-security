// Contract test for compliance control evidence (docs/reference/compliance-evidence-contract.md): the per-control status vocabulary of each
// assessment path (framework evaluator, truth model, privacy assessment), the fields each output carries, the rule that an unassessed or
// manual control never counts as satisfied, and the OSCAL rule that a control nobody decided gets no finding. Every table on the page is
// held against the real output in both directions, and the rules run for real on a tiny inline framework, the bundled privacy framework
// and the real CLI over a hand-written last scan. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { evaluateFramework } from '../../src/posture/auditor-walkthrough.js';
import { assessFrameworkTruth, classifyControl, TRUTH_STATES } from '../../src/posture/compliance-truth.js';
import { assessPrivacyFramework, bucketOf, BUCKETS, PRIVACY_FRAMEWORK_ID } from '../../src/posture/privacy-framework.js';
import { toOSCALCompliance, complianceRowsFromEvaluation, complianceRowsFromTruth, complianceRowsFromPrivacy, oscalToken } from '../../src/report/oscal.js';

process.env.AGENTIC_SECURITY_OFFLINE = '1';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/compliance-evidence-contract.md');
const META = { startedAt: '1970-01-01T00:00:00.000Z' };

// One control per evaluator status, plus one rated code-testable with no check (an engine gap).
const FW = {
  id: 'contract-fw', name: 'Contract framework', publisher: 'test', license: 'test', controlCount: 6,
  controls: [
    { id: 'C-SAT', summary: 'no SQL injection', codeTestable: 'yes', mapsTo: ['family:sql-injection'] },
    { id: 'C-GAP', summary: 'no command injection', codeTestable: 'yes', mapsTo: ['family:command-injection'] },
    { id: 'C-MAN', summary: 'a written policy exists', codeTestable: 'no', mapsTo: [] },
    { id: 'C-ORG', summary: 'an organisational control with a mapping', codeTestable: 'no', mapsTo: ['family:sql-injection'] },
    { id: 'C-EG', summary: 'checkable by code, no check here', codeTestable: 'yes', mapsTo: [] },
    { id: 'Art. 32(1)(a)', summary: 'an id that is not an OSCAL token', codeTestable: 'no', mapsTo: [] },
  ],
};
const FINDING = { id: 'f-cmd', severity: 'high', file: 'a.js', line: 3, vuln: 'Command injection', cwe: 'CWE-78', family: 'command-injection' };
const SCAN = { filesScanned: 1, findings: [FINDING], scanHealth: { status: 'complete' } };
const EMPTY = { filesScanned: 0, findings: [], scanHealth: { status: 'complete' } };

const root = mkTestTmp('agsec-compliance-contract-');
const byId = (rows, id) => rows.find((r) => (r.control ? r.control.id : r.id) === id);
const evaluation = evaluateFramework(root, FW, SCAN);

// ---- the framework evaluator ----
test('evaluator: each row carries exactly the documented fields, and the status vocabulary is the documented four', () => {
  for (const r of evaluation) sameFields(r, fieldsUnder(PAGE, 'Evaluation row'), `evaluation row ${r.control.id}`);
  const seen = [...new Set(evaluation.map((r) => r.status))].sort();
  assert.deepEqual(seen, fieldsUnder(PAGE, 'Evaluator status').sort(), 'the fixture reaches every documented status, and no other');
  assert.equal(byId(evaluation, 'C-SAT').status, 'present');
  assert.equal(byId(evaluation, 'C-GAP').status, 'absent');
  assert.deepEqual(byId(evaluation, 'C-GAP').controlRefs, ['f-cmd']);
  assert.equal(byId(evaluation, 'C-MAN').status, 'manual');
  assert.equal(byId(evaluation, 'C-ORG').status, 'partial', 'a control rated not code-testable is never present');
});

test('evaluator: a scan that examined nothing is not evidence, but a scan with no file count is assessable', () => {
  const empty = evaluateFramework(root, FW, EMPTY);
  assert.equal(byId(empty, 'C-SAT').status, 'partial');
  assert.ok(!empty.some((r) => r.status === 'present'), 'no control is present on a scan that examined nothing');
  const noCount = evaluateFramework(root, FW, { findings: [] });
  assert.equal(byId(noCount, 'C-SAT').status, 'present');
});

// ---- the truth model ----
test('truth: the six states are the documented ones, and every output level carries exactly the documented fields', () => {
  assert.deepEqual([...TRUTH_STATES].sort(), fieldsUnder(PAGE, 'Truth state').sort());
  const truth = assessFrameworkTruth(FW, evaluation, { scanStatus: 'complete', scanExaminedFiles: true });
  sameFields(truth, fieldsUnder(PAGE, 'Truth assessment'), 'truth assessment');
  for (const c of truth.controls) sameFields(c, fieldsUnder(PAGE, 'Truth control'), `truth control ${c.id}`);
  sameFields(truth.denominators, fieldsUnder(PAGE, 'Denominators'), 'denominators');
  assert.deepEqual(Object.keys(truth.denominators.byState).sort(), [...TRUTH_STATES].sort());
  sameFields(truth.frameworkClaim, fieldsUnder(PAGE, 'Framework claim'), 'framework claim');
});

test('truth: only assessed_satisfied counts as satisfied; unassessed and manual controls are counted as needing a person', () => {
  const truth = assessFrameworkTruth(FW, evaluation, { scanStatus: 'complete', scanExaminedFiles: true });
  const state = (id) => truth.controls.find((c) => c.id === id).state;
  assert.equal(state('C-SAT'), 'assessed_satisfied');
  assert.equal(state('C-GAP'), 'assessed_not_satisfied');
  assert.equal(state('C-MAN'), 'requires_human_review');
  assert.equal(state('C-ORG'), 'insufficient_evidence', 'an evaluator partial with no attributed finding carries no verdict');
  assert.equal(state('C-EG'), 'not_assessed');
  const d = truth.denominators;
  assert.equal(d.satisfied, 1);
  assert.equal(d.satisfied, d.byState.assessed_satisfied);
  assert.equal(d.needAPersonOrMoreEvidence, d.byState.requires_human_review + d.byState.insufficient_evidence + d.byState.not_assessed);
  assert.equal(d.assessed + d.needAPersonOrMoreEvidence + d.byState.not_applicable, d.evaluatedControls);
  assert.equal(truth.frameworkClaim.established, false);
  // even a framework where every applicable control is satisfied establishes nothing
  const one = { ...FW, controls: [FW.controls[0]], controlCount: 1 };
  const all = assessFrameworkTruth(one, evaluateFramework(root, one, SCAN), { scanStatus: 'complete', scanExaminedFiles: true });
  assert.equal(all.denominators.satisfied, 1);
  assert.equal(all.frameworkClaim.established, false);
  assert.match(all.frameworkClaim.statement, /not a statement that the system complies/);
});

test('truth: an incomplete or empty scan, and an unsupported not-applicable declaration, carry no verdict', () => {
  const sat = byId(evaluation, 'C-SAT');
  assert.equal(classifyControl(sat, { scanStatus: 'partial', scanExaminedFiles: true }).state, 'insufficient_evidence');
  assert.equal(classifyControl(sat, { scanStatus: 'complete', scanExaminedFiles: false }).state, 'insufficient_evidence');
  assert.equal(classifyControl(sat, { scanStatus: undefined, scanExaminedFiles: true }).state, 'insufficient_evidence');
  assert.equal(classifyControl(sat, { scanStatus: 'complete', notApplicable: { 'C-SAT': { reason: 'out of scope' } } }).state, 'insufficient_evidence');
  assert.equal(classifyControl(sat, { scanStatus: 'complete', notApplicable: { 'C-SAT': { reason: 'out of scope', declaredBy: 'owner' } } }).state, 'not_applicable');
  assert.equal(classifyControl({ control: { id: 'X' }, status: 'something-new' }, { scanStatus: 'complete' }).state, 'not_assessed');
});

// ---- the privacy assessment ----
const privacyScan = { filesScanned: 1, findings: [{ ...FINDING, id: 'f-ecb', family: 'crypto-weak-cipher', cwe: 'CWE-327' }] };
const privacy = assessPrivacyFramework(root, privacyScan);

test('privacy: the buckets are the documented four, and every output level carries exactly the documented fields', () => {
  assert.equal(privacy.frameworkId, PRIVACY_FRAMEWORK_ID);
  assert.deepEqual([...BUCKETS].sort(), fieldsUnder(PAGE, 'Privacy bucket').sort());
  sameFields(privacy, fieldsUnder(PAGE, 'Privacy assessment'), 'privacy assessment');
  sameFields(privacy.summary, fieldsUnder(PAGE, 'Privacy summary'), 'privacy summary');
  for (const c of privacy.controls) {
    sameFields(c, fieldsUnder(PAGE, 'Privacy control'), `privacy control ${c.id}`, ['disclosure']);
    assert.equal('disclosure' in c, c.bucket === 'engine-gap' || c.bucket === 'manual', `${c.id}: disclosure on engine-gap and manual only`);
  }
  assert.ok(privacy.findings.length > 0, 'the fixture produces a gap');
  for (const f of privacy.findings) sameFields(f, fieldsUnder(PAGE, 'Privacy gap finding'), `gap finding ${f.id}`);
  const f = privacy.findings.find((x) => x.id === 'privacy-framework:PR.DS-P1');
  assert.ok(f, 'the weak-cipher finding opens PR.DS-P1');
  assert.equal(f.cwe, 'CWE-359'); assert.equal(f.family, 'privacy-compliance'); assert.equal(f.parser, 'COMPLIANCE'); assert.equal(f.line, 0);
});

test('privacy: engine-gap and manual never count as satisfied, only gap produces a finding, and the rate is over assessed controls', () => {
  const s = privacy.summary;
  for (const b of BUCKETS) assert.equal(s[b], privacy.controls.filter((c) => c.bucket === b).length);
  assert.equal(s.total, s.gap + s['engine-gap'] + s.manual + s.satisfied);
  assert.ok(s['engine-gap'] > 0 && s.manual > 0);
  assert.equal(privacy.findings.length, s.gap);
  assert.deepEqual(privacy.findings.map((f) => f.id).sort(), privacy.controls.filter((c) => c.bucket === 'gap').map((c) => `privacy-framework:${c.id}`).sort());
  assert.ok(privacy.interpretation.includes(`${s.satisfied} of ${s.satisfied + s.gap} assessed controls satisfied`));
  // bucketOf on its own: unmapped is manual or engine-gap by rating, never satisfied; mapped but unassessable is engine-gap
  assert.equal(bucketOf({ control: { mapsTo: [], codeTestable: 'no' }, status: 'manual' }), 'manual');
  assert.equal(bucketOf({ control: { mapsTo: [], codeTestable: 'yes' }, status: 'manual' }), 'engine-gap');
  assert.equal(bucketOf({ control: { mapsTo: ['family:x'], codeTestable: 'yes' }, status: 'present' }, { assessable: false }), 'engine-gap');
  assert.equal(bucketOf({ control: { mapsTo: ['family:x'], codeTestable: 'yes' }, status: 'present' }), 'satisfied');
});

test('privacy: a scan that examined no files assesses nothing and says so first', () => {
  const empty = assessPrivacyFramework(root, { filesScanned: 0, findings: [] });
  assert.equal(empty.assessable, false);
  assert.equal(empty.summary.satisfied, 0);
  assert.equal(empty.summary.gap, 0);
  assert.match(empty.interpretation, /^The scan examined no files, so NO control was assessed\./);
});

// ---- OSCAL ----
function oscalOf(rows) { return toOSCALCompliance(FW, rows, META); }
const decisionOf = (doc, id) => {
  const r = doc.results[0];
  const f = (r.findings || []).find((x) => x.props.find((p) => p.name === 'source-control-id').value === id);
  return f ? f.target.status.state : 'unassessed';
};

test('oscal: the decision vocabulary and the per-path reduction are the documented ones', () => {
  assert.deepEqual(fieldsUnder(PAGE, 'OSCAL decision').sort(), ['not-satisfied', 'satisfied', 'unassessed']);
  const ev = (status) => complianceRowsFromEvaluation([{ control: { id: 'X' }, status }])[0].decision;
  assert.deepEqual(['present', 'partial', 'absent', 'manual', 'new'].map(ev), ['satisfied', 'not-satisfied', 'not-satisfied', 'unassessed', 'unassessed']);
  const tr = (state) => complianceRowsFromTruth({ controls: [{ id: 'X', state }] })[0].decision;
  assert.deepEqual(TRUTH_STATES.map(tr), ['satisfied', 'not-satisfied', 'unassessed', 'unassessed', 'unassessed', 'unassessed']);
  const pr = (bucket) => complianceRowsFromPrivacy({ controls: [{ id: 'X', bucket }], findings: [] })[0].decision;
  assert.deepEqual(BUCKETS.map(pr), ['not-satisfied', 'unassessed', 'unassessed', 'satisfied']);
  // every status named in the reduction table is a real status of its path
  for (const s of [...fieldsUnder(PAGE, 'Evaluator status'), ...TRUTH_STATES, ...BUCKETS]) assert.ok(PAGE.includes(`\`${s}\``), `${s} is on the page`);
});

test('oscal: the document, result, observation and finding carry exactly the documented fields', () => {
  const doc = oscalOf(complianceRowsFromEvaluation(evaluation));
  sameFields(doc, fieldsUnder(PAGE, 'OSCAL document'), 'oscal document');
  assert.equal(doc.results.length, 1);
  const r = doc.results[0];
  sameFields(r, fieldsUnder(PAGE, 'OSCAL result'), 'oscal result', ['findings', 'risks']);
  assert.ok(r.findings && r.risks, 'this fixture has decided and failing controls');
  assert.deepEqual(r.props.map((p) => p.name).sort(), ['controls-reviewed', 'count-not-satisfied', 'count-satisfied', 'count-unassessed', 'framework-id']);
  for (const p of r.props) assert.ok(PAGE.includes(`\`${p.name}\``), `${p.name} is on the page`);
  for (const o of r.observations) sameFields(o, fieldsUnder(PAGE, 'OSCAL observation'), 'oscal observation', ['remarks']);
  for (const f of r.findings) sameFields(f, fieldsUnder(PAGE, 'OSCAL finding'), 'oscal finding', ['related-risks']);
  assert.equal(doc.metadata['oscal-version'], '1.1.2');
});

test('oscal: an unassessed control gets no finding and no risk, only an EXAMINE observation with a remark', () => {
  for (const [label, rows] of [
    ['evaluator', complianceRowsFromEvaluation(evaluation)],
    ['truth', complianceRowsFromTruth(assessFrameworkTruth(FW, evaluation, { scanStatus: 'complete', scanExaminedFiles: true }))],
    ['privacy', complianceRowsFromPrivacy(privacy)],
  ]) {
    const doc = toOSCALCompliance(FW, rows, META);
    const r = doc.results[0];
    const findings = r.findings || []; const risks = r.risks || [];
    const unassessed = rows.filter((x) => x.decision === 'unassessed');
    assert.ok(unassessed.length > 0, `${label}: the fixture has unassessed controls`);
    const findingIds = new Set(findings.map((f) => f.props.find((p) => p.name === 'source-control-id').value));
    for (const u of unassessed) {
      assert.ok(!findingIds.has(u.id), `${label}: unassessed ${u.id} has no finding`);
      const o = r.observations.find((x) => x.props.find((p) => p.name === 'source-control-id').value === u.id);
      assert.deepEqual(o.methods, ['EXAMINE']);
      assert.ok(typeof o.remarks === 'string' && o.remarks.length > 0);
      assert.equal(o.props.find((p) => p.name === 'assessment-status').value, u.statusLabel);
    }
    for (const o of r.observations) if (o.methods[0] === 'TEST') assert.equal(o.remarks, undefined);
    // counts add up
    const n = (name) => Number(r.props.find((p) => p.name === name).value);
    assert.equal(n('count-satisfied') + n('count-not-satisfied') + n('count-unassessed'), n('controls-reviewed'), label);
    assert.equal(n('controls-reviewed'), r.observations.length, label);
    assert.equal(findings.length, n('count-satisfied') + n('count-not-satisfied'), label);
    assert.equal(risks.length, n('count-not-satisfied'), label);
    for (const f of findings) {
      assert.ok(['satisfied', 'not-satisfied'].includes(f.target.status.state));
      assert.equal('related-risks' in f, f.target.status.state === 'not-satisfied');
    }
  }
  const doc = oscalOf(complianceRowsFromEvaluation(evaluation));
  assert.equal(decisionOf(doc, 'C-SAT'), 'satisfied');
  assert.equal(decisionOf(doc, 'C-GAP'), 'not-satisfied');
  assert.equal(decisionOf(doc, 'C-MAN'), 'unassessed');
  // an unrecognised status is still an unassessed observation, named as an exporter defect
  const odd = toOSCALCompliance(FW, complianceRowsFromEvaluation([{ control: { id: 'X' }, status: 'new' }]), META);
  assert.equal(odd.results[0].findings, undefined);
  assert.match(odd.results[0].observations[0].remarks, /defect in the exporter/);
});

test('oscal: a control id that is not a token is rewritten and the original kept', () => {
  const doc = oscalOf(complianceRowsFromEvaluation(evaluation));
  const o = doc.results[0].observations.find((x) => x.props.find((p) => p.name === 'source-control-id').value === 'Art. 32(1)(a)');
  assert.ok(o, 'the original id is on the observation');
  const ids = doc.results[0]['reviewed-controls']['control-selections'][0]['include-controls'].map((c) => c['control-id']);
  assert.ok(ids.includes(oscalToken('Art. 32(1)(a)')));
  for (const id of ids) assert.match(id, /^[\p{L}_][\p{L}\p{N}._-]*$/u);
});

// ---- the real CLI ----
const cli = (cwd, ...a) => spawnSync(process.execPath, [CLI, 'compliance', ...a], { cwd, encoding: 'utf8', timeout: 60000, env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1' } });
function project(scan) {
  const dir = mkTestTmp('agsec-compliance-cli-');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}');
  if (scan) {
    fs.mkdirSync(path.join(dir, '.agentic-security', 'compliance', FW.id), { recursive: true });
    fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify(scan));
    fs.writeFileSync(path.join(dir, '.agentic-security', 'compliance', FW.id, 'controls.json'), JSON.stringify(FW));
  }
  return dir;
}

test('cli: no scan exits 2; a report exits 0; --fail-on gap exits 1 only on the privacy path with a gap', () => {
  assert.equal(cli(project(null)).status, 2);
  const dir = project({ ...privacyScan, scanned: { files: 1 }, scanHealth: { status: 'complete' } });
  const list = cli(dir, '--list', '--format', 'json');
  assert.equal(list.status, 0, list.stderr);
  const fws = JSON.parse(list.stdout);
  for (const f of fws) sameFields(f, fieldsUnder(PAGE, 'Framework list entry'), `framework ${f.id}`);
  assert.equal(fws.find((f) => f.id === FW.id).source, 'project');
  assert.equal(fws.find((f) => f.id === PRIVACY_FRAMEWORK_ID).source, 'bundled');
  const json = cli(dir, '--format', 'json');
  assert.equal(json.status, 0, json.stderr);
  const p = JSON.parse(json.stdout);
  sameFields(p, fieldsUnder(PAGE, 'Privacy assessment'), 'cli privacy assessment');
  assert.ok(p.summary.gap > 0);
  assert.equal(cli(dir, '--fail-on', 'gap').status, 1);
  assert.equal(cli(dir, '--report', FW.id, '--fail-on', 'gap').status, 0, '--fail-on acts on the privacy path only');
  assert.equal(cli(dir, '--report', 'no-such-framework').status, 2);
  const rep = cli(dir, '--report', FW.id, '--format', 'json');
  assert.equal(rep.status, 0, rep.stderr);
  for (const r of JSON.parse(rep.stdout)) sameFields(r, fieldsUnder(PAGE, 'Evaluation row'), `cli evaluation row ${r.control.id}`);
  const truth = cli(dir, '--report', FW.id, '--truth', '--format', 'oscal');
  assert.equal(truth.status, 0, truth.stderr);
  const doc = JSON.parse(truth.stdout);
  assert.equal(decisionOf(doc, 'C-SAT'), 'satisfied');
  assert.equal(decisionOf(doc, 'C-EG'), 'unassessed');
  assert.equal(decisionOf(doc, 'C-MAN'), 'unassessed');
});

test('page: the limits section carries a verification date and no em-dash appears anywhere', () => {
  assert.match(PAGE, /## What this does not do\n\n<!-- limits-verified: \d{4}-\d{2}-\d{2} -->/);
  assert.ok(!PAGE.includes('\u2014'), 'no em-dash on the page');
});
