// Approver identity registry (assurance-hardening PRD FR-1002).
//
// FR-307 already refuses to auto-apply a high-impact change (auth/authZ/
// crypto/pii/schema/infra-privilege/public-api) without approval evidence
// — but that evidence (`fixMeta.approval: {approvedBy, reason}`) is
// entirely self-reported: any caller can write ANY string into
// `approvedBy` and satisfy the gate. FR-1002's acceptance criterion is
// "anonymous or unauthorized high-risk exceptions fail policy" — closing
// that gap needs the approver's identity checked against something the
// caller does not control.
//
// "VERIFIED" HERE MEANS "operator-registered", NOT cryptographically
// authenticated. This is a local-first CLI tool with no server, no
// account system, and no multi-tenancy (the same hard line
// posture/fleet.js's own header states for the fleet feature) — there is
// no SSO or session to check a caller's identity against. What IS
// available, and what this module builds on, is the same pattern this
// session has used repeatedly for every other policy surface (egress
// providers, privacy sinks, compliance severity floors): an
// OPERATOR-AUTHORED, committed config file naming who is authorized to
// approve what. An approver not in that list is unauthorized by
// definition — the registry IS the authorization boundary, the same way
// egress/policy.js's allowedProviders list IS the provider boundary.
//
// NO REGISTRY FILE = NO-OP, matching every other policy gate this session
// has built (restricts nothing until an operator opts in). Once a
// registry exists, identity verification is enforced: an anonymous
// approval (empty/missing approvedBy) is refused, and an approvedBy not
// present in the registry is refused — this is the literal "anonymous...
// exceptions fail policy" half of the acceptance criterion. Per-category
// ROLE requirements (the "and roles" half) are themselves operator-
// configured in the same file, via `requiredRolesByCategory` — a category
// with no configured role requirement accepts any registered approver,
// so an operator opts into role-gating one category at a time rather
// than this module guessing which categories need which roles.

import * as fs from 'node:fs';
import { statePath } from '../posture/state-dir.js';

const REGISTRY_FILE = 'authorized-approvers.json';

/**
 * Load the operator's approver registry. Never throws — a missing file
 * (the common case: identity verification not opted into) or a malformed
 * one both degrade to `null`, which `verifyApprover` treats as "no-op".
 *
 * @returns {{approvers: Array<{identity:string, roles?:string[]}>,
 *   requiredRolesByCategory?: Record<string,string[]>}|null}
 */
export function loadApproverRegistry(scanRoot) {
  if (!scanRoot) return null;
  let fp;
  try { fp = statePath(scanRoot, REGISTRY_FILE); } catch { return null; }
  // Read first, check second — an existsSync-then-readFileSync pair is a
  // check-then-use race (this session's own D-0012/D-0022 discipline).
  let raw;
  try {
    raw = fs.readFileSync(fp, 'utf8');
  } catch {
    return null; // ENOENT (no registry configured) or any other read failure
  }
  try {
    const doc = JSON.parse(raw);
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.approvers)) return null;
    return doc;
  } catch {
    return null; // malformed — degrade to no-op rather than blocking every apply
  }
}

/**
 * Check an approver identity against the registry.
 *
 * @param {{approvers: Array<{identity:string, roles?:string[]}>}|null} registry
 * @param {string} identity - the caller-supplied `fixMeta.approval.approvedBy`
 * @param {string[]} [requiredRoles] - roles that satisfy this specific
 *   approval (e.g. the union of `requiredRolesByCategory` entries for the
 *   categories this change touches); empty means "any registered approver".
 * @returns {{verified: boolean, reason: string}}
 */
export function verifyApprover(registry, identity, requiredRoles = []) {
  if (!registry) {
    return { verified: true, reason: 'no authorized-approvers registry configured — identity verification is a no-op until an operator opts in' };
  }
  const trimmedIdentity = typeof identity === 'string' ? identity.trim() : '';
  if (!trimmedIdentity) {
    return { verified: false, reason: 'no approver identity supplied — a registry is configured, so an anonymous approval is refused' };
  }
  const entry = registry.approvers.find((a) => a && a.identity === trimmedIdentity);
  if (!entry) {
    return { verified: false, reason: `approver '${trimmedIdentity}' is not in the authorized-approvers registry` };
  }
  if (requiredRoles.length) {
    const roles = Array.isArray(entry.roles) ? entry.roles : [];
    const hasRole = requiredRoles.some((r) => roles.includes(r));
    if (!hasRole) {
      return {
        verified: false,
        reason: `approver '${trimmedIdentity}' lacks a required role for this change (needs one of: ${requiredRoles.join(', ')}; has: ${roles.join(', ') || 'none'})`,
      };
    }
  }
  return { verified: true, reason: `approver '${trimmedIdentity}' verified` };
}

/**
 * The union of `registry.requiredRolesByCategory[c]` for every category in
 * `categories`, deduplicated. A category with no configured entry
 * contributes nothing — it is not "any role", it is "no role requirement",
 * matching `verifyApprover`'s own empty-array no-op semantics.
 */
export function requiredRolesFor(registry, categories) {
  const map = registry?.requiredRolesByCategory;
  if (!map || typeof map !== 'object') return [];
  const roles = new Set();
  for (const c of categories) {
    const forCategory = Array.isArray(map[c]) ? map[c] : [];
    for (const r of forCategory) roles.add(r);
  }
  return [...roles];
}

/**
 * FR-1003: "a configurable policy can prevent the patch author from
 * self-approving a high-impact fix." Gated the same way every other
 * dimension in this registry is — NO-OP unless an operator opts in, this
 * time via `registry.separationOfDuties.enabled === true`. Without that
 * flag, an author approving their own fix is unaffected, matching
 * FR-1002's own approvedBy-presence-is-enough default. `author` is a
 * second self-reported identity, `fixMeta.author` — this module cannot
 * determine who actually wrote a patch (no VCS blame is consulted; a
 * caller could lie about either field), so like `approvedBy` itself this
 * is a policy check over CLAIMED identities, not a cryptographic one —
 * consistent with the "operator-registered, not authenticated" scope this
 * whole registry already documents above.
 *
 * @param {{separationOfDuties?: {enabled?: boolean}}|null} registry
 * @param {string} author - the caller-supplied `fixMeta.author`
 * @param {string} approvedBy - the caller-supplied `fixMeta.approval.approvedBy`
 * @returns {{ok: boolean, reason: string}}
 */
export function checkSeparationOfDuties(registry, author, approvedBy) {
  if (!registry?.separationOfDuties?.enabled) {
    return { ok: true, reason: 'separation-of-duties is not enabled in the authorized-approvers registry — a no-op until an operator opts in' };
  }
  const trimmedAuthor = typeof author === 'string' ? author.trim().toLowerCase() : '';
  const trimmedApprover = typeof approvedBy === 'string' ? approvedBy.trim().toLowerCase() : '';
  if (!trimmedAuthor) {
    return { ok: true, reason: 'no fixMeta.author supplied — nothing to compare the approver against' };
  }
  if (trimmedAuthor === trimmedApprover) {
    return { ok: false, reason: `separation-of-duties: the patch author ('${author}') cannot also be its approver` };
  }
  return { ok: true, reason: 'approver differs from the patch author' };
}

export const _internals = { REGISTRY_FILE };
