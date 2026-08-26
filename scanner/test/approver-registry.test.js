// Approver identity registry (assurance-hardening PRD FR-1002).
//
// "Bind approvals, exceptions, and suppressions to verified identities and
// roles | Anonymous or unauthorized high-risk exceptions fail policy."
// Direct unit tests for the pure functions — the real end-to-end proof
// through applyVerifiedFix() lives in test/high-impact-approval-gate.test.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadApproverRegistry, verifyApprover, requiredRolesFor, checkSeparationOfDuties, _internals } from '../src/fix/approver-registry.js';

function mkProject(registryDoc) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'approver-registry-'));
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  if (registryDoc !== undefined) {
    fs.writeFileSync(path.join(root, '.agentic-security', _internals.REGISTRY_FILE), typeof registryDoc === 'string' ? registryDoc : JSON.stringify(registryDoc));
  }
  return root;
}

// ── loadApproverRegistry ───────────────────────────────────────────────────

test('loadApproverRegistry: no scanRoot returns null', () => {
  assert.equal(loadApproverRegistry(null), null);
  assert.equal(loadApproverRegistry(undefined), null);
});

test('loadApproverRegistry: no registry file present returns null (the common, unconfigured case)', () => {
  const root = mkProject();
  try {
    assert.equal(loadApproverRegistry(root), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('loadApproverRegistry: malformed JSON degrades to null, never throws', () => {
  const root = mkProject('not json{{{');
  try {
    assert.doesNotThrow(() => loadApproverRegistry(root));
    assert.equal(loadApproverRegistry(root), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('loadApproverRegistry: a document with no `approvers` array degrades to null', () => {
  const root = mkProject({ notApprovers: [] });
  try {
    assert.equal(loadApproverRegistry(root), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('loadApproverRegistry: a well-formed registry loads correctly', () => {
  const doc = { approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }] };
  const root = mkProject(doc);
  try {
    assert.deepEqual(loadApproverRegistry(root), doc);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── verifyApprover ──────────────────────────────────────────────────────────

test('verifyApprover: no registry is a no-op — verified true regardless of identity', () => {
  assert.equal(verifyApprover(null, 'anyone', []).verified, true);
  assert.equal(verifyApprover(null, '', []).verified, true, 'even an empty identity passes when no registry is configured — FR-307\'s own presence check already ran first');
});

test('verifyApprover: a registry configured refuses an empty/anonymous identity', () => {
  const registry = { approvers: [{ identity: 'jane@example.com' }] };
  const r = verifyApprover(registry, '', []);
  assert.equal(r.verified, false);
  assert.match(r.reason, /anonymous/);
});

test('verifyApprover: a registry configured refuses an identity not present in it', () => {
  const registry = { approvers: [{ identity: 'jane@example.com' }] };
  const r = verifyApprover(registry, 'mallory@example.com', []);
  assert.equal(r.verified, false);
  assert.match(r.reason, /not in the authorized-approvers registry/);
});

test('verifyApprover: a registered identity with no required roles passes', () => {
  const registry = { approvers: [{ identity: 'jane@example.com' }] };
  assert.equal(verifyApprover(registry, 'jane@example.com', []).verified, true);
});

test('verifyApprover: a registered identity missing a required role is refused, naming the required and actual roles', () => {
  const registry = { approvers: [{ identity: 'jane@example.com', roles: ['engineering-lead'] }] };
  const r = verifyApprover(registry, 'jane@example.com', ['security-lead']);
  assert.equal(r.verified, false);
  assert.match(r.reason, /needs one of: security-lead/);
  assert.match(r.reason, /has: engineering-lead/);
});

test('verifyApprover: a registered identity with ONE of several required roles passes (any() semantics, not all())', () => {
  const registry = { approvers: [{ identity: 'jane@example.com', roles: ['security-lead'] }] };
  assert.equal(verifyApprover(registry, 'jane@example.com', ['data-lead', 'security-lead']).verified, true);
});

test('verifyApprover: an entry with no roles array at all is treated as zero roles, not a crash', () => {
  const registry = { approvers: [{ identity: 'jane@example.com' }] };
  const r = verifyApprover(registry, 'jane@example.com', ['security-lead']);
  assert.equal(r.verified, false);
  assert.match(r.reason, /has: none/);
});

// ── requiredRolesFor ─────────────────────────────────────────────────────────

test('requiredRolesFor: no requiredRolesByCategory configured returns an empty array', () => {
  assert.deepEqual(requiredRolesFor({ approvers: [] }, ['auth', 'crypto']), []);
  assert.deepEqual(requiredRolesFor(null, ['auth']), []);
});

test('requiredRolesFor: returns the union of configured categories, deduplicated', () => {
  const registry = { requiredRolesByCategory: { crypto: ['security-lead'], auth: ['security-lead', 'engineering-lead'] } };
  assert.deepEqual(requiredRolesFor(registry, ['crypto', 'auth']).sort(), ['engineering-lead', 'security-lead']);
});

test('requiredRolesFor: a category with no configured entry contributes nothing — no requirement, not "any role"', () => {
  const registry = { requiredRolesByCategory: { crypto: ['security-lead'] } };
  assert.deepEqual(requiredRolesFor(registry, ['schema']), []);
});

// ── checkSeparationOfDuties (FR-1003) ────────────────────────────────────────

test('checkSeparationOfDuties: not enabled in the registry is a no-op — self-approval passes', () => {
  assert.equal(checkSeparationOfDuties(null, 'jane', 'jane').ok, true);
  assert.equal(checkSeparationOfDuties({ approvers: [] }, 'jane', 'jane').ok, true, 'registry present but separationOfDuties key absent must still be a no-op');
  assert.equal(checkSeparationOfDuties({ separationOfDuties: { enabled: false } }, 'jane', 'jane').ok, true);
});

test('checkSeparationOfDuties: enabled, same author and approver — refused', () => {
  const registry = { separationOfDuties: { enabled: true } };
  const r = checkSeparationOfDuties(registry, 'jane@example.com', 'jane@example.com');
  assert.equal(r.ok, false);
  assert.match(r.reason, /separation-of-duties/);
  assert.match(r.reason, /cannot also be its approver/);
});

test('checkSeparationOfDuties: enabled, same identity but different case/whitespace — still refused (compares normalized)', () => {
  const registry = { separationOfDuties: { enabled: true } };
  const r = checkSeparationOfDuties(registry, ' Jane@Example.com ', 'jane@example.com');
  assert.equal(r.ok, false);
});

test('checkSeparationOfDuties: enabled, different author and approver — passes', () => {
  const registry = { separationOfDuties: { enabled: true } };
  const r = checkSeparationOfDuties(registry, 'jane@example.com', 'bob@example.com');
  assert.equal(r.ok, true);
});

test('checkSeparationOfDuties: enabled but no author supplied — passes (nothing to compare against)', () => {
  const registry = { separationOfDuties: { enabled: true } };
  assert.equal(checkSeparationOfDuties(registry, null, 'jane@example.com').ok, true);
  assert.equal(checkSeparationOfDuties(registry, '', 'jane@example.com').ok, true);
});
