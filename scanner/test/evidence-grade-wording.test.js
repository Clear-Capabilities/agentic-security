// FR-507 (assurance-hardening PRD): replace certification-style wording
// with evidence-grade wording. UI and docs must distinguish automated
// technical assessment, management attestation, and independent
// certification — three DIFFERENT concepts, not just a generic "this
// isn't certified" caveat.
//
// Real gap found before this module existed: 3 of 4 hand-rolled
// disclaimers (compliance-policy.js, auditor-walkthrough.js, and — in a
// milder form — privacy-framework.js) said "a licensed assessor is
// responsible for the final attestation," which gets the terminology
// BACKWARDS — a licensed assessor produces an independent certification
// / assessment opinion, not a management attestation (that is the
// organization's own leadership's job). oscal.js's docs/OSCAL.md-governed
// wording was already correctly worded in this one respect, but never
// named "independent certification" as a distinct term either.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  ASSURANCE_TIERS, EVIDENCE_GRADE_DISCLAIMER, EVIDENCE_GRADE_DISCLAIMER_SHORT,
} from '../src/posture/evidence-grade-wording.js';

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'evidence-grade-wording-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

test('ASSURANCE_TIERS names all three tiers the PRD requires, each distinctly', () => {
  assert.match(ASSURANCE_TIERS.automatedTechnicalAssessment, /automated technical assessment/i);
  assert.match(ASSURANCE_TIERS.managementAttestation, /management attestation/i);
  assert.match(ASSURANCE_TIERS.managementAttestation, /organization/i);
  assert.match(ASSURANCE_TIERS.independentCertification, /independent certification/i);
  assert.match(ASSURANCE_TIERS.independentCertification, /accredited/i);
});

test('EVIDENCE_GRADE_DISCLAIMER (full) names all three tiers and preserves the existing "does not certify compliance" phrase', () => {
  assert.match(EVIDENCE_GRADE_DISCLAIMER, /does not certify compliance/i);
  assert.match(EVIDENCE_GRADE_DISCLAIMER, /management attestation/i);
  assert.match(EVIDENCE_GRADE_DISCLAIMER, /independent certification/i);
  // The old, backwards phrasing must be gone, not just supplemented.
  assert.doesNotMatch(EVIDENCE_GRADE_DISCLAIMER, /licensed assessor.*responsible for the (final )?attestation/i);
});

test('EVIDENCE_GRADE_DISCLAIMER_SHORT also names all three tiers, not just "not certified"', () => {
  assert.match(EVIDENCE_GRADE_DISCLAIMER_SHORT, /does not certify compliance/i);
  assert.match(EVIDENCE_GRADE_DISCLAIMER_SHORT, /management attestation/i);
  assert.match(EVIDENCE_GRADE_DISCLAIMER_SHORT, /independent certification/i);
});

// ── Every call site actually uses the shared wording, not a fork ────────

test('compliance-policy.js: emitEvidenceJsonLd disclaimer IS the shared full disclaimer verbatim', async () => {
  const { emitEvidenceJsonLd } = await import('../src/posture/compliance-policy.js');
  const report = {
    framework: 'X', version: '1',
    summary: { total: 1, compliant: 1, nonCompliant: 0, notApplicable: 0 },
    controls: [{ id: 'C1', title: 't', status: 'compliant', checks: [], evidence: [] }],
  };
  const jsonld = emitEvidenceJsonLd(report, null);
  assert.equal(jsonld.disclaimer, EVIDENCE_GRADE_DISCLAIMER);
});

test('compliance-policy.js: emitEvidenceMarkdown embeds the shared short disclaimer', async () => {
  const { emitEvidenceMarkdown } = await import('../src/posture/compliance-policy.js');
  const report = {
    framework: 'X', version: '1',
    summary: { total: 1, compliant: 1, nonCompliant: 0, notApplicable: 0 },
    controls: [{ id: 'C1', title: 't', status: 'compliant', checks: [], evidence: [] }],
  };
  const md = emitEvidenceMarkdown(report, null);
  assert.ok(md.includes(EVIDENCE_GRADE_DISCLAIMER_SHORT));
  assert.match(md, /management attestation/i);
  assert.match(md, /independent certification/i);
});

test('oscal.js: toOSCALCompliance remarks name all three tiers, not just "not an attestation"', async () => {
  const { toOSCALCompliance, complianceRowsFromEvaluation } = await import('../src/report/oscal.js');
  const FW = { id: 'demo-fw', name: 'Demo Framework', publisher: 'Demo', url: 'https://example.invalid/fw', license: 'CC0' };
  const EVAL = [
    { control: { id: 'AC-1', summary: 'Access control policy', codeTestable: 'yes' }, status: 'present', observations: ['cleared'] },
  ];
  const META = { startedAt: '2026-08-23T10:00:00.000Z', scanId: 'test-scan' };
  const doc = toOSCALCompliance(FW, complianceRowsFromEvaluation(EVAL), META);
  const remarks = doc.results[0].remarks;
  assert.match(remarks, /management attestation/i);
  assert.match(remarks, /independent certification/i);
  assert.doesNotMatch(remarks, /licensed assessor.*responsible for the (final )?attestation/i);
});

test('privacy-framework.js: the persisted markdown carries the shared short disclaimer, naming all three tiers', async () => {
  const { assessPrivacyFramework, persistPrivacyFramework } = await import('../src/posture/privacy-framework.js');
  const dir = await tmpProject();
  try {
    const scan = { findings: [], components: [], filesScanned: 5, privacyIrBacked: true };
    const result = assessPrivacyFramework(dir, scan);
    persistPrivacyFramework(dir, result);
    const md = await fsp.readFile(path.join(dir, '.agentic-security', 'privacy-framework.md'), 'utf8');
    assert.ok(md.includes(EVIDENCE_GRADE_DISCLAIMER_SHORT));
    assert.match(md, /management attestation/i);
    assert.match(md, /independent certification/i);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('auditor-walkthrough.js: renderWalkthrough carries the shared short disclaimer, naming all three tiers', async () => {
  const { renderWalkthrough } = await import('../src/posture/auditor-walkthrough.js');
  const fw = { id: 'demo-fw', name: 'Demo Framework', publisher: 'Demo', license: 'CC0' };
  const evaluation = [
    { control: { id: 'AC-1', summary: 'Access control policy', codeTestable: 'yes' }, status: 'present', observations: ['cleared'] },
  ];
  const md = renderWalkthrough(fw, evaluation);
  assert.ok(md.includes(EVIDENCE_GRADE_DISCLAIMER_SHORT));
  assert.match(md, /management attestation/i);
  assert.match(md, /independent certification/i);
  assert.doesNotMatch(md, /licensed assessor is responsible for the final attestation/i);
});
