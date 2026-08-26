// FR-503 (assurance-hardening PRD): "Require positive evidence for
// satisfaction where the control demands implementation proof | Mere
// artifact existence or absence of findings is insufficient unless the
// mapping explicitly defines it."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadPolicy, verifyPolicy } from '../src/posture/compliance-policy.js';

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'compliance-file-contains-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('FR-503: file-contains passes when the file exists AND matches the required pattern', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, 'workflow.yml'), 'jobs:\n  update:\n    uses: dependabot/fetch-metadata@v1\n');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "Automated dependency updates"
    requires:
      - file-contains: "workflow.yml"
        pattern: "dependabot|renovate"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'compliant');
    assert.match(report.controls[0].checks[0].result.reason, /matches required pattern/);
  } finally { await sess.cleanup(); }
});

test('FR-503: file-contains FAILS when the file exists but does NOT match the pattern — mere existence is not enough', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, 'workflow.yml'), 'jobs:\n  build:\n    runs-on: ubuntu-latest\n');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "Automated dependency updates"
    requires:
      - file-contains: "workflow.yml"
        pattern: "dependabot|renovate"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.match(report.controls[0].checks[0].result.reason, /mere existence is not enough/);
  } finally { await sess.cleanup(); }
});

test('FR-503: file-contains FAILS when the file does not exist at all', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - file-contains: "nonexistent.yml"
        pattern: "anything"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.match(report.controls[0].checks[0].result.reason, /not found/);
  } finally { await sess.cleanup(); }
});

test('FR-503: file-contains with no pattern specified fails with a clear reason, not a crash', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, 'workflow.yml'), 'anything\n');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - file-contains: "workflow.yml"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.match(report.controls[0].checks[0].result.reason, /no pattern/);
  } finally { await sess.cleanup(); }
});

test('FR-503: file-contains with an invalid regex pattern fails gracefully, not a crash', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, 'workflow.yml'), 'anything\n');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - file-contains: "workflow.yml"
        pattern: "["
`);
    const policy = loadPolicy(sess.dir);
    assert.doesNotThrow(() => verifyPolicy(policy, { scanRoot: sess.dir, findings: [] }));
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.match(report.controls[0].checks[0].result.reason, /not a valid regex/);
  } finally { await sess.cleanup(); }
});

test('FR-503: file-exists remains valid and unaffected for controls that genuinely only need existence', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, 'INCIDENT-PLAN.md'), '');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC7.2:
    title: "Security incident response"
    requires:
      - file-exists: "INCIDENT-PLAN.md"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'compliant', 'file-exists must remain a valid, unweakened primitive for controls that opt into it');
  } finally { await sess.cleanup(); }
});

// ── sca-policy-has-entry: incidental TOCTOU fix (self-scan finding while
// touching this same function for FR-503) — read-first-in-try/catch
// replaced an existsSync-then-readFileSync pair. No prior test existed for
// this primitive at all; these prove the fix changed nothing observable.

test('sca-policy-has-entry: no sca-policy.yml at all is non-compliant with a clear reason (post-TOCTOU-fix behavior)', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC1:
    title: "x"
    requires:
      - sca-policy-has-entry: "accept-risk"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.match(report.controls[0].checks[0].result.reason, /sca-policy\.yml not found/);
  } finally { await sess.cleanup(); }
});

test('sca-policy-has-entry: accept-risk entries present is compliant', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'sca-policy.yml'), 'accept-risk:\n  - id: CVE-2020-1\n');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC1:
    title: "x"
    requires:
      - sca-policy-has-entry: "accept-risk"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'compliant');
  } finally { await sess.cleanup(); }
});

test('sca-policy-has-entry: sla buckets present is compliant for type "sla"', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'sca-policy.yml'), 'sla:\n  critical: 7\n');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC1:
    title: "x"
    requires:
      - sca-policy-has-entry: "sla"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'compliant');
  } finally { await sess.cleanup(); }
});

test('sca-policy-has-entry: a present but empty sca-policy.yml is non-compliant, not a crash', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'sca-policy.yml'), '{}\n');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC1:
    title: "x"
    requires:
      - sca-policy-has-entry: "accept-risk"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.match(report.controls[0].checks[0].result.reason, /no accept-risk entries/);
  } finally { await sess.cleanup(); }
});

test('sca-policy-has-entry: a malformed sca-policy.yml is non-compliant with a parse-error reason, not a crash', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'sca-policy.yml'), '{ not: valid: yaml: [[[');
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC1:
    title: "x"
    requires:
      - sca-policy-has-entry: "accept-risk"
`);
    const policy = loadPolicy(sess.dir);
    assert.doesNotThrow(() => verifyPolicy(policy, { scanRoot: sess.dir, findings: [] }));
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.match(report.controls[0].checks[0].result.reason, /parse error/);
  } finally { await sess.cleanup(); }
});
