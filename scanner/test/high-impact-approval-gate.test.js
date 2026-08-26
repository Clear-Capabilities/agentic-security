// High-impact change approval gate (assurance-hardening PRD FR-307).
//
// "Auth, authZ, crypto, PII, schema, infrastructure privilege, and public
// API changes cannot auto-apply without approval evidence." Tests the REAL
// applyVerifiedFix() call path (not posture/material-change.js's classifier
// in isolation) — the same discipline this session has used for every
// other FR: prove the gate blocks the real write, not just that the
// classifier returns the right category.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { applyVerifiedFix } from '../src/fix/apply-fix-service.js';
import { signLastScan } from '../src/posture/integrity.js';

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-high-impact-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture"}\n');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}

function writeSignedScan(root, findings) {
  const stateDir = path.join(root, '.agentic-security');
  const body = JSON.stringify({ findings });
  fs.writeFileSync(path.join(stateDir, 'last-scan.json'), body);
  fs.writeFileSync(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
}

const AUTH_REMOVED_BEFORE = 'function h(req,res){ if(!requireAuth(req)) return res.status(401).end(); doThing(); }\n';
const AUTH_REMOVED_AFTER = 'function h(req,res){ doThing(); }\n';

test('a high-impact change (auth removed) with NO approval evidence is refused before any write', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
    });
    assert.equal(result.ok, false);
    assert.equal(result.applied, false);
    assert.match(result.reason, /high-impact change/);
    assert.match(result.reason, /auth/);
    assert.match(result.reason, /approval evidence/);
    assert.deepEqual(result.materialClassification.highImpactCategories, ['auth']);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_BEFORE, 'the file must be completely untouched by a refused apply');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the SAME high-impact change with complete approval evidence (fixMeta.approval: {approvedBy, reason}) is applied', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'jane@example.com', reason: 'auth removal is intentional — endpoint is now public by design' } },
    });
    assert.equal(result.ok, true, `expected a successful apply: ${result.reason}`);
    assert.equal(result.applied, true);
    assert.deepEqual(result.materialClassification.highImpactCategories, ['auth']);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_AFTER);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('approval evidence missing `reason` (or `approvedBy`) does not satisfy the gate — a placeholder cannot stand in for real evidence', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const missingReason = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'jane@example.com', reason: '' } },
    });
    assert.equal(missingReason.ok, false);

    const missingApprover = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: '', reason: 'intentional' } },
    });
    assert.equal(missingApprover.ok, false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('a routine (non-high-impact) fix is applied without needing any approval evidence at all', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'const a = 1;\n');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'a.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'const a = 2;\n' },
      skipVerification: true,
    });
    assert.equal(result.ok, true, `expected a successful apply: ${result.reason}`);
    assert.deepEqual(result.materialClassification.highImpactCategories, []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('dryRun:true previews a high-impact change WITHOUT approval evidence — nothing is written, but the classification is surfaced so a caller can go collect approval', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      dryRun: true,
    });
    assert.equal(result.ok, true);
    assert.equal(result.applied, false);
    assert.equal(result.dryRun, true);
    assert.deepEqual(result.materialClassification.highImpactCategories, ['auth']);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_BEFORE, 'a dry run must never write');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('a new PII field, a weak-crypto reference, and a schema DDL change are each independently recognized as high-impact and refused without approval', async () => {
  const root = mkProject();
  const cases = [
    { file: 'user.js', before: 'const x = 1;\n', after: 'const ssn = req.body.ssn;\nconst x = 1;\n', category: 'pii' },
    { file: 'auth.js', before: '', after: 'const h = md5(password);\n', category: 'crypto' },
    { file: 'migrate.sql', before: '', after: 'ALTER TABLE users ADD COLUMN ssn TEXT;\n', category: 'schema' },
  ];
  try {
    for (const c of cases) {
      fs.writeFileSync(path.join(root, c.file), c.before);
      writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: c.file }]);
      const result = await applyVerifiedFix({
        scanRoot: root,
        finding: { file: c.file, id: 'F1', stableId: 'a'.repeat(16) },
        files: { [c.file]: c.after },
        skipVerification: true,
      });
      assert.equal(result.ok, false, `expected ${c.category} to require approval`);
      assert.ok(result.materialClassification.highImpactCategories.includes(c.category),
        `expected category '${c.category}', got ${JSON.stringify(result.materialClassification.highImpactCategories)}`);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── FR-1002: approval bound to a verified (operator-registered) identity ──

function writeApproverRegistry(root, doc) {
  fs.writeFileSync(path.join(root, '.agentic-security', 'authorized-approvers.json'), JSON.stringify(doc));
}

test('FR-1002: with NO authorized-approvers registry, approvedBy\'s mere presence still satisfies the gate — unchanged from FR-307', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'anyone@example.com', reason: 'no registry configured, so mere presence is enough' } },
    });
    assert.equal(result.ok, true, `expected success with no registry configured: ${result.reason}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1002: with a registry configured, an approvedBy NOT in the registry is refused — the literal "unauthorized... fail policy" criterion', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, { approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }] });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'mallory@example.com', reason: 'trust me' } },
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /approval rejected/);
    assert.match(result.reason, /not in the authorized-approvers registry/);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_BEFORE, 'the file must be untouched by a rejected approval');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1002: with a registry configured, a REGISTERED approvedBy is accepted', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, { approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }] });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'jane@example.com', reason: 'intentional, reviewed' } },
    });
    assert.equal(result.ok, true, `expected success for a registered approver: ${result.reason}`);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_AFTER);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1002: a per-category required role that the approver lacks is refused, even though the approver IS registered', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, {
      approvers: [{ identity: 'bob@example.com', roles: ['engineering-lead'] }],
      requiredRolesByCategory: { auth: ['security-lead'] },
    });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'bob@example.com', reason: 'I approve this' } },
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /lacks a required role/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1002: an approver WITH the required role for the touched category is accepted', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, {
      approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }],
      requiredRolesByCategory: { auth: ['security-lead'] },
    });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'jane@example.com', reason: 'security-lead review complete' } },
    });
    assert.equal(result.ok, true, `expected success for a role-qualified approver: ${result.reason}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1002: a category with NO configured role requirement accepts any registered approver, even when OTHER categories in the same registry do require one', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, {
      approvers: [{ identity: 'bob@example.com', roles: ['engineering-lead'] }],
      requiredRolesByCategory: { crypto: ['security-lead'] }, // auth has no entry
    });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'bob@example.com', reason: 'engineering-lead approval, no security-lead requirement for auth here' } },
    });
    assert.equal(result.ok, true, `expected success — 'auth' has no requiredRolesByCategory entry: ${result.reason}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── FR-1003: separation-of-duties ────────────────────────────────────────────

test('FR-1003: with separationOfDuties NOT enabled, the patch author approving their own fix is unaffected (unchanged from FR-1002)', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, { approvers: [{ identity: 'jane@example.com' }] });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'jane@example.com', reason: 'self-reviewed' }, author: 'jane@example.com' },
    });
    assert.equal(result.ok, true, `expected success — separationOfDuties is not enabled: ${result.reason}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1003: with separationOfDuties enabled, the patch author cannot also be its approver — refused before any write', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, { approvers: [{ identity: 'jane@example.com' }], separationOfDuties: { enabled: true } });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'jane@example.com', reason: 'self-reviewed' }, author: 'jane@example.com' },
    });
    assert.equal(result.ok, false, `expected refusal — author and approver are the same identity: ${JSON.stringify(result)}`);
    assert.match(result.reason, /separation-of-duties/);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_BEFORE, 'file must be untouched when refused');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1003: with separationOfDuties enabled, a DIFFERENT approver succeeds', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, { approvers: [{ identity: 'jane@example.com' }, { identity: 'bob@example.com' }], separationOfDuties: { enabled: true } });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'bob@example.com', reason: 'independent review' }, author: 'jane@example.com' },
    });
    assert.equal(result.ok, true, `expected success — approver differs from author: ${result.reason}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-1003: with separationOfDuties enabled but NO author supplied, approval proceeds (nothing to compare against)', async () => {
  const root = mkProject();
  try {
    writeApproverRegistry(root, { approvers: [{ identity: 'jane@example.com' }], separationOfDuties: { enabled: true } });
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'auth.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'auth.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'auth.js': AUTH_REMOVED_AFTER },
      skipVerification: true,
      fixMeta: { approval: { approvedBy: 'jane@example.com', reason: 'no author claim in this fixMeta' } },
    });
    assert.equal(result.ok, true, `expected success — no author was claimed to compare against: ${result.reason}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
