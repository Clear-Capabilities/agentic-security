// Compliance severity-threshold tests (assurance-hardening PRD FR-501/FR-502, A-07).
//
// `evaluateFramework`'s family: mapping used to only count 'critical'/'high'
// findings as "open" — a control with any number of open MEDIUM findings on
// its mapped family rendered "✓ no open critical/high findings", identical
// to a genuinely clean control. posture/privacy-framework.js already solved
// the analogous vacuous-pass problem for its own four-bucket model; this
// closes the same class of gap in the shared evaluator every OTHER
// framework (NIST CSF, OWASP ASVS, GDPR, HIPAA, ...) renders through.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateFramework } from '../src/posture/auditor-walkthrough.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function frameworkFor(id, family) {
  return { name: 'test-framework', controls: [{ id, summary: 'mapped to a real family', mapsTo: [`family:${family}`] }] };
}

test('a control on a real family with ONLY open medium-severity findings no longer reads as clear (the A-07 regression case)', () => {
  const fw = frameworkFor('T1', 'sql-injection');
  const scan = {
    findings: [{ family: 'sql-injection', severity: 'medium', file: 'a.js', line: 1 }],
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.notEqual(result.status, 'present', 'a control with 1+ open medium findings on its mapped family must not read as fully evidenced');
  assert.ok(result.observations.some(o => /open sql-injection finding/.test(o)),
    `expected an observation naming the open finding, got: ${JSON.stringify(result.observations)}`);
});

test('a control on a real family with only open LOW-severity findings still reads "present" (medium is the floor, not low)', () => {
  const fw = frameworkFor('T2', 'sql-injection');
  const scan = {
    findings: [{ family: 'sql-injection', severity: 'low', file: 'a.js', line: 1 }],
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.equal(result.status, 'present', 'low-severity findings must not affect control status — only medium+ per OPEN_FINDING_MIN_SEVERITY');
});

test('a control on a real family with a clean scan still reads "present" (negative control, unchanged by this fix)', () => {
  const fw = frameworkFor('T3', 'sql-injection');
  const [result] = evaluateFramework(HERE, fw, { findings: [], secrets: [], logicVulns: [], supplyChain: [] });
  assert.equal(result.status, 'present');
});

test('critical and high findings still count as open (no regression on the pre-existing behavior)', () => {
  for (const severity of ['critical', 'high']) {
    const fw = frameworkFor('T4', 'sql-injection');
    const scan = {
      findings: [{ family: 'sql-injection', severity, file: 'a.js', line: 1 }],
      secrets: [], logicVulns: [], supplyChain: [],
    };
    const [result] = evaluateFramework(HERE, fw, scan);
    assert.notEqual(result.status, 'present', `severity=${severity} must still count as open`);
  }
});

test('an intent-suppressed or past-decision medium finding does not count as open (suppression is still honored at the new threshold)', () => {
  const fw = frameworkFor('T5', 'sql-injection');
  const scan = {
    findings: [
      { family: 'sql-injection', severity: 'medium', file: 'a.js', line: 1, intentSuppressed: true },
      { family: 'sql-injection', severity: 'medium', file: 'b.js', line: 1, pastDecision: true },
    ],
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.equal(result.status, 'present', 'suppressed/decided findings must not count as open at any severity');
});

test('a finding with no severity set does not count as open (matches prior behavior — absence was never "critical" or "high" either)', () => {
  const fw = frameworkFor('T6', 'sql-injection');
  const scan = {
    findings: [{ family: 'sql-injection', file: 'a.js', line: 1 }], // no severity field
    secrets: [], logicVulns: [], supplyChain: [],
  };
  const [result] = evaluateFramework(HERE, fw, scan);
  assert.equal(result.status, 'present');
});
