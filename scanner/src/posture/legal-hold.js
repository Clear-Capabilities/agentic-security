// FR-707 (assurance-hardening PRD): "Support legal hold and policy-
// authorized retention exceptions | Legal hold is identity-bound, reasoned,
// time-bounded where applicable, and auditable."
//
// A third instance of the recurring {owner, reason, expires_at} exception
// shape this codebase already uses twice — `posture/suppressions.js`'s
// pro-tier exception (scoped to a FINDING) and `posture/compliance-policy.js`'s
// structured `not-applicable` (scoped to a COMPLIANCE CONTROL). Per D-0025,
// these are deliberately distinct mechanisms serving different subjects, not
// one shared module — this file is the third subject: a STATE ARTIFACT.
//
// Field naming matches the existing two schemas' snake_case convention
// (`owner`, `reason`, `expires_at`) rather than inventing a fourth style.
//
//   identity-bound   -> `owner` (required, who placed the hold and is
//                        accountable for lifting it)
//   reasoned         -> `reason` (required — "we might need this later" is
//                        not a reason; same discipline suppressions.js
//                        already enforces for its own exceptions)
//   time-bounded
//     where applicable -> `expires_at` is OPTIONAL: a null/absent value is
//                        an INDEFINITE hold, which the acceptance
//                        criterion's own "where applicable" phrase
//                        explicitly allows (a genuine legal matter may have
//                        no known end date) — an ISO date value behaves
//                        exactly like FR-506/FR-1004's own expiring
//                        exceptions: once past, the hold is no longer
//                        active and the artifact is exposed to its normal
//                        retention TTL again.
//   auditable        -> persisted as a single JSON array under
//                        `.agentic-security/legal-holds.json` (itself
//                        registered as operator-config — an operator/legal
//                        team's own input, never scanner-written from scan
//                        results), readable via `listLegalHolds`.
//
// Consulted from TWO places, not one: `retention-policy.js#findExpiredArtifacts`
// (defense in depth for any caller reaching it directly) AND `cmdReset`
// itself for its PLAIN (non-`--expired`) path, which deletes every
// registered 'generated' artifact unconditionally and would otherwise blow
// through a hold that only gated TTL expiry.

import * as fs from 'node:fs';
import { statePath, safeWriteState } from './state-dir.js';
import { isRegisteredArtifact } from './artifact-registry.js';

export const LEGAL_HOLD_FILE = 'legal-holds.json';

function _loadRaw(scanRoot) {
  let fp;
  try { fp = statePath(scanRoot, LEGAL_HOLD_FILE); } catch { return []; }
  let raw;
  try { raw = fs.readFileSync(fp, 'utf8'); } catch { return []; }
  try {
    const doc = JSON.parse(raw);
    return Array.isArray(doc) ? doc : [];
  } catch { return []; }
}

/**
 * All legal holds ever recorded for this project, malformed entries
 * dropped rather than throwing. Never filters by expiry — see
 * `isUnderHold`/`listLegalHolds` for that.
 */
export function loadLegalHolds(scanRoot) {
  return _loadRaw(scanRoot).filter(h => h && typeof h === 'object' && typeof h.artifact === 'string' && typeof h.owner === 'string' && typeof h.reason === 'string');
}

/**
 * Is `artifactName` currently protected by an active (non-expired) hold?
 * Returns the matching hold record, or null. Multiple holds on the same
 * artifact are permitted (e.g. two independent legal matters); the first
 * still-active one found is returned.
 */
export function isUnderHold(artifactName, holds, now = Date.now()) {
  for (const h of holds) {
    if (h.artifact !== artifactName) continue;
    if (!h.expires_at) return h; // indefinite hold — always active
    const t = Date.parse(h.expires_at);
    if (!Number.isFinite(t) || t >= now) return h;
  }
  return null;
}

/**
 * Active (non-expired) holds only, unless `includeExpired`. For
 * `legal-hold list` / auditing.
 */
export function listLegalHolds(scanRoot, { includeExpired = false, now = Date.now() } = {}) {
  const holds = loadLegalHolds(scanRoot);
  if (includeExpired) return holds;
  return holds.filter(h => {
    if (!h.expires_at) return true;
    const t = Date.parse(h.expires_at);
    return !Number.isFinite(t) || t >= now;
  });
}

/**
 * Add a legal hold. Validates identity-bound + reasoned up front (both
 * required, non-empty) and that `expires_at`, if given, is a parseable
 * date in the future — an already-expired hold would be a hold that
 * protects nothing, which is never a legitimate request. `artifact` must
 * name a real registered artifact (artifact-registry.js) — a hold on an
 * unrecognised name can never protect anything and almost always means a
 * typo. Returns `{ok:true, hold}` or `{ok:false, reason}`; never throws.
 */
export function addLegalHold(scanRoot, { artifact, owner, reason, expires_at } = {}) {
  if (!artifact || typeof artifact !== 'string') return { ok: false, reason: '--artifact is required' };
  if (!isRegisteredArtifact(artifact)) return { ok: false, reason: `"${artifact}" is not a registered state artifact` };
  if (!owner || typeof owner !== 'string') return { ok: false, reason: '--owner is required (identity-bound)' };
  if (!reason || typeof reason !== 'string') return { ok: false, reason: '--reason is required (reasoned)' };
  if (expires_at) {
    const t = Date.parse(expires_at);
    if (!Number.isFinite(t)) return { ok: false, reason: 'expires_at must be a parseable date' };
    if (t < Date.now()) return { ok: false, reason: 'expires_at is in the past — a hold that already expired protects nothing' };
  }
  const hold = { artifact, owner, reason, expires_at: expires_at || null, created_at: new Date().toISOString() };
  const holds = _loadRaw(scanRoot);
  holds.push(hold);
  const fp = statePath(scanRoot, LEGAL_HOLD_FILE);
  if (!safeWriteState(fp, JSON.stringify(holds, null, 2) + '\n')) {
    return { ok: false, reason: 'state writes are disabled (--no-state) or this is not a safe state directory' };
  }
  return { ok: true, hold };
}

/**
 * Remove every hold on `artifact` (lifting a hold, not letting it expire).
 * Returns the number removed. A no-op (0) if none existed — never an error.
 */
export function removeLegalHold(scanRoot, artifact) {
  const holds = _loadRaw(scanRoot);
  const remaining = holds.filter(h => !(h && h.artifact === artifact));
  const removedCount = holds.length - remaining.length;
  if (removedCount > 0) {
    const fp = statePath(scanRoot, LEGAL_HOLD_FILE);
    safeWriteState(fp, JSON.stringify(remaining, null, 2) + '\n');
  }
  return removedCount;
}
