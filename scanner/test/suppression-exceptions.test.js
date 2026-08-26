// FR-1004 (assurance-hardening PRD): "Implement exception owner, reason,
// scope, compensating control, and expiry" | "Expired exceptions
// automatically reopen findings or fail the gate."
//
// posture/suppressions.js's "pro" schema already had `reason` and
// `expires_at`; this file proves the newly-required `owner`/`scope`/
// `compensating_control` fields are enforced, and — the part that had ZERO
// test coverage before this PRD item, despite being wired into the real
// scan pipeline (bin/agentic-security.js) since before this session — that
// an expired exception genuinely reopens its finding, both at the unit
// level (applySuppressions) and through a real CLI subprocess (D-0024's
// own lesson: prove the real entry point, not just the service function).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateProSuppression, applySuppressions } from '../src/posture/suppressions.js';
import { _internals as approverInternals } from '../src/fix/approver-registry.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: SCANNER, encoding: 'utf8', timeout: 30_000, ...opts });
}

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-suppress-exc-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture"}\n');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}

const FUTURE = '2099-01-01';
const PAST = '2020-01-01';

function fullEntry(overrides = {}) {
  return {
    finding_id: 'F1', file: 'app.js', reason: 'known false positive in this context',
    justification_signed_by: 'jane@example.com', reviewer: 'bob@example.com',
    expires_at: FUTURE, owner: 'jane@example.com', scope: 'this one md5 usage in app.js, legacy hash for a non-security cache key',
    compensating_control: 'output is never used for authentication or integrity — cache key only',
    ...overrides,
  };
}

// ── validateProSuppression: the 3 new required fields ───────────────────────

test('validateProSuppression: owner, scope, and compensating_control are all required — missing any one fails', () => {
  for (const missing of ['owner', 'scope', 'compensating_control']) {
    const entry = fullEntry({ [missing]: undefined });
    const v = validateProSuppression(entry);
    assert.equal(v.ok, false, `expected missing ${missing} to fail validation`);
    assert.ok(v.errors.some(e => e.includes(missing)), `expected an error naming '${missing}', got ${JSON.stringify(v.errors)}`);
  }
});

test('validateProSuppression: a fully-populated entry (all 5 named fields + the two-person rule) passes', () => {
  const v = validateProSuppression(fullEntry());
  assert.equal(v.ok, true, `expected a fully-populated entry to pass: ${JSON.stringify(v.errors)}`);
});

test('validateProSuppression: pre-existing fields (reason/expiry/two-person-rule) are unaffected by the new required fields', () => {
  const v1 = validateProSuppression(fullEntry({ expires_at: PAST }));
  assert.ok(v1.errors.some(e => /expires_at is in the past/.test(e)));
  const v2 = validateProSuppression(fullEntry({ justification_signed_by: 'jane@example.com', reviewer: 'jane@example.com' }));
  assert.ok(v2.errors.some(e => /two-person rule/.test(e)));
});

// ── validateProSuppression + applySuppressions: FR-1002 identity binding ────
// "Bind approvals, exceptions, AND suppressions to verified identities and
// roles | Anonymous or unauthorized high-risk exceptions fail policy."
// Before this fix, justification_signed_by was pure self-reported text,
// never checked against the same authorized-approvers registry FR-307/
// FR-1002 already wired into apply_fix.

test('validateProSuppression: with no registry opt (opts omitted), justification_signed_by is unaffected — pure backward compatibility', () => {
  const v = validateProSuppression(fullEntry());
  assert.equal(v.ok, true);
});

test('validateProSuppression: with a registry configured, an anonymous/empty justification_signed_by is refused', () => {
  const registry = { approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }] };
  const v = validateProSuppression(fullEntry({ justification_signed_by: '   ' }), { registry });
  assert.equal(v.ok, false);
  assert.ok(v.errors.some(e => /not authorized/.test(e)));
});

test('validateProSuppression: with a registry configured, a signer NOT in the registry is refused', () => {
  const registry = { approvers: [{ identity: 'jane@example.com' }] };
  const v = validateProSuppression(fullEntry({ justification_signed_by: 'mallory@example.com' }), { registry });
  assert.equal(v.ok, false);
  assert.ok(v.errors.some(e => /not authorized/.test(e) && e.includes('mallory@example.com')));
});

test('validateProSuppression: with a registry configured, a REGISTERED signer with the required role passes', () => {
  const registry = { approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }] };
  const v = validateProSuppression(fullEntry({ justification_signed_by: 'jane@example.com' }), { registry, requiredRoles: ['security-lead'] });
  assert.equal(v.ok, true, JSON.stringify(v.errors));
});

test('validateProSuppression: with a registry configured, a registered signer LACKING the required role is refused', () => {
  const registry = { approvers: [{ identity: 'jane@example.com', roles: ['junior'] }] };
  const v = validateProSuppression(fullEntry({ justification_signed_by: 'jane@example.com' }), { registry, requiredRoles: ['security-lead'] });
  assert.equal(v.ok, false);
  assert.ok(v.errors.some(e => /not authorized/.test(e) && /lacks a required role/.test(e)));
});

test('applySuppressions (FR-1002, real end-to-end): an unauthorized signer on a suppression for a role-gated family reopens the finding', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(
      path.join(root, '.agentic-security', approverInternals.REGISTRY_FILE),
      JSON.stringify({ approvers: [{ identity: 'mallory@example.com' }], requiredRolesByCategory: { 'auth-missing': ['security-lead'] } }),
    );
    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([fullEntry({ justification_signed_by: 'mallory@example.com' })]));
    const findings = [{ id: 'F1', file: 'app.js', line: 1, vuln: 'demo', severity: 'high', family: 'auth-missing' }];
    const kept = applySuppressions(findings, root, { profile: 'pro' });
    assert.equal(kept.length, 1, 'an unauthorized signer on a role-gated family must reopen the finding, not suppress it');
    assert.ok(kept[0]._suppressionInvalid.some(e => /not authorized/.test(e)));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applySuppressions (FR-1002, real end-to-end): an authorized, correctly-roled signer still suppresses normally', () => {
  const root = mkProject();
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  try {
    fs.writeFileSync(
      path.join(root, '.agentic-security', approverInternals.REGISTRY_FILE),
      JSON.stringify({ approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }], requiredRolesByCategory: { 'auth-missing': ['security-lead'] } }),
    );
    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([fullEntry({ justification_signed_by: 'jane@example.com' })]));
    const findings = [{ id: 'F1', file: 'app.js', line: 1, vuln: 'demo', severity: 'high', family: 'auth-missing' }];
    const kept = applySuppressions(findings, root, { profile: 'pro' });
    assert.equal(kept.length, 0, 'an authorized, correctly-roled signer must still suppress the finding');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applySuppressions (FR-1002): no registry file at all — identity check is a no-op, matching every other opt-in gate in this codebase', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([fullEntry({ justification_signed_by: 'anyone-at-all' })]));
    const findings = [{ id: 'F1', file: 'app.js', line: 1, vuln: 'demo', severity: 'high', family: 'auth-missing' }];
    const kept = applySuppressions(findings, root, { profile: 'pro' });
    assert.equal(kept.length, 0, 'with no registry configured, an unregistered signer must not be refused — opt-in, not default-on');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── applySuppressions: expiry reopens the finding (unit level) ──────────────

test('applySuppressions: a valid, non-expired pro suppression suppresses the finding', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([fullEntry()]));
    const findings = [{ id: 'F1', file: 'app.js', line: 1, vuln: 'demo', severity: 'high' }];
    const kept = applySuppressions(findings, root, { profile: 'pro' });
    assert.equal(kept.length, 0, 'a valid, non-expired suppression must suppress the finding');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applySuppressions (FR-1004): an EXPIRED pro suppression reopens the finding — present in kept, marked _suppressionExpired', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([fullEntry({ expires_at: PAST })]));
    const findings = [{ id: 'F1', file: 'app.js', line: 1, vuln: 'demo', severity: 'high' }];
    const kept = applySuppressions(findings, root, { profile: 'pro' });
    assert.equal(kept.length, 1, 'an expired suppression must reopen the finding, not silently drop it');
    assert.equal(kept[0]._suppressionExpired, true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applySuppressions: an entry missing owner/scope/compensating_control is INVALID and also reopens the finding', () => {
  const root = mkProject();
  try {
    const invalid = fullEntry({ owner: undefined });
    delete invalid.owner;
    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([invalid]));
    const findings = [{ id: 'F1', file: 'app.js', line: 1, vuln: 'demo', severity: 'high' }];
    const kept = applySuppressions(findings, root, { profile: 'pro' });
    assert.equal(kept.length, 1, 'a suppression missing a required field must not suppress');
    assert.ok(Array.isArray(kept[0]._suppressionInvalid));
    assert.ok(kept[0]._suppressionInvalid.some(e => e.includes('owner')));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── Real end-to-end through the CLI (D-0024's lesson: prove the real entry point) ──

test('scan --profile pro (FR-1004): an expired suppression reopens a real, detector-triggering finding', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'app.js'), "const c=require('crypto');const h=c.createHash('md5');\n");

    // First pass: no suppressions.yml — learn the REAL finding's id/file/line/vuln shape.
    const first = run(['scan', root, '--profile', 'pro', '--format', 'json', '--no-network']);
    const firstScan = JSON.parse(fs.readFileSync(path.join(root, '.agentic-security', 'last-scan.json'), 'utf8'));
    const finding = (firstScan.findings || []).find(f => /md5|hash/i.test(f.vuln || '') || f.cwe === 'CWE-328');
    assert.ok(finding, `expected a weak-hash finding in the real scan, got: ${JSON.stringify((firstScan.findings || []).map(f => f.vuln))}`);

    // Second pass: an EXPIRED suppression for that exact finding.
    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([
      fullEntry({ finding_id: finding.id, file: finding.file, expires_at: PAST }),
    ]));
    const second = run(['scan', root, '--profile', 'pro', '--format', 'json', '--no-network']);
    const secondScan = JSON.parse(fs.readFileSync(path.join(root, '.agentic-security', 'last-scan.json'), 'utf8'));
    const stillPresent = (secondScan.findings || []).some(f => f.id === finding.id || (f.file === finding.file && f.line === finding.line && f.vuln === finding.vuln));
    assert.ok(stillPresent, 'an expired exception must reopen the finding — it must still be present in scan output');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('scan --profile pro (FR-1004): a VALID, non-expired suppression for the same finding actually suppresses it', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'app.js'), "const c=require('crypto');const h=c.createHash('md5');\n");
    const first = run(['scan', root, '--profile', 'pro', '--format', 'json', '--no-network']);
    const firstScan = JSON.parse(fs.readFileSync(path.join(root, '.agentic-security', 'last-scan.json'), 'utf8'));
    const finding = (firstScan.findings || []).find(f => /md5|hash/i.test(f.vuln || '') || f.cwe === 'CWE-328');
    assert.ok(finding, `expected a weak-hash finding in the real scan, got: ${JSON.stringify((firstScan.findings || []).map(f => f.vuln))}`);

    fs.writeFileSync(path.join(root, '.agentic-security', 'suppressions.yml'), JSON.stringify([
      fullEntry({ finding_id: finding.id, file: finding.file, expires_at: FUTURE }),
    ]));
    const second = run(['scan', root, '--profile', 'pro', '--format', 'json', '--no-network']);
    const secondScan = JSON.parse(fs.readFileSync(path.join(root, '.agentic-security', 'last-scan.json'), 'utf8'));
    const stillPresent = (secondScan.findings || []).some(f => f.id === finding.id);
    assert.equal(stillPresent, false, 'a valid, non-expired, fully-documented exception must suppress the finding');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
