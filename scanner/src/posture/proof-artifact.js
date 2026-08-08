// Proof-artifact provenance (PRD Epic 1.4 + 7.4).
//
// An `execution-proven` finding is only worth more than a pattern match if a
// reader can tell WHAT was proven and check that the claim was not edited after
// the fact. This module turns the evidence a proof run produced into two things
// a report can carry:
//
//   1. `proofLevel` — the PRD's public vocabulary, mapped from the engine's
//      internal `proofTier`. The engine's names are about analysis provenance;
//      the PRD's are about what a reader may conclude. They are deliberately
//      NOT the same strings, and mapping in one place stops the two vocabularies
//      drifting into each other across reporters.
//
//   2. `proofArtifactSha256` — a digest over the evidence that actually
//      justified the tier: the PoC that ran, the effect observed, the backend it
//      ran on, and the tier claimed. A fix PR can then reference the digest, and
//      anyone re-running the proof can check they are looking at the same
//      artifact rather than a later, friendlier one.
//
// WHAT THE DIGEST IS AND IS NOT. It is tamper-EVIDENCE over the proof record,
// not proof the exploit is real — the execution is what does that. It is also
// not a signature: it commits to content, and anyone can recompute it. Signing
// belongs with `integrity.js`, which already has a key and a provenance story;
// duplicating that here would be a second crypto path for no gain.
//
// Timestamps are deliberately excluded. Two runs that proved the same thing the
// same way should produce the same digest, or the field cannot be used to say
// "this is the artifact the PR was reviewed against".

import crypto from 'node:crypto';

// Engine tier -> PRD proof level. Every tier maps; an unknown tier maps to the
// weakest level rather than being dropped, because a missing level would read
// as "not applicable" instead of "we do not know".
const TIER_TO_LEVEL = Object.freeze({
  'execution-proven': 'PROVEN',
  'proof-failed': 'PROBABLE_FP',
  'taint-proven': 'REACHABLE',
  'unproven': 'PATTERN',
});

export const PROOF_LEVELS = Object.freeze(['PROVEN', 'PROBABLE_FP', 'REACHABLE', 'PATTERN']);

/**
 * The PRD-facing proof level for a finding.
 *
 * Returns null when the finding carries no tier at all — a scan that never ran
 * the proof stage must not have every finding labelled `PATTERN`, which would
 * assert that each was considered and found unprovable.
 */
export function proofLevelOf(finding) {
  const tier = finding?.proofTier;
  if (!tier) return null;
  return TIER_TO_LEVEL[tier] || 'PATTERN';
}

/**
 * Digest over the evidence that justified the tier. Null when there is no
 * evidence to commit to — an absent hash is honest; a hash over nothing is not.
 */
export function proofArtifactDigest(finding) {
  const ev = finding?.proofEvidence;
  if (!ev || !finding?.proofTier) return null;
  // Only fields that constitute the CLAIM. `at` (a timestamp) and `exitCode`
  // are excluded: they vary between identical proofs and would make the digest
  // useless for "same artifact?" comparisons.
  const material = JSON.stringify({
    tier: finding.proofTier,
    ran: ev.ran === true,
    backend: ev.backend ?? null,
    observed: ev.observed ?? null,
    reason: ev.reason ?? null,
    marker: finding.poc?.marker ?? null,
    poc: finding.poc?.code ?? null,
  });
  return crypto.createHash('sha256').update(material).digest('hex');
}

/**
 * The reportable proof block, or null when the finding has no proof standing.
 * One shape, so every reporter says the same thing the same way.
 */
export function proofBlock(finding) {
  const level = proofLevelOf(finding);
  if (!level) return null;
  const ev = finding?.proofEvidence || {};
  return {
    proofLevel: level,
    proofTier: finding.proofTier,
    proofRan: ev.ran === true,
    ...(ev.backend ? { proofBackend: ev.backend } : {}),
    ...(ev.observed ? { proofObserved: ev.observed } : {}),
    // Carried on the weaker levels too: "the PoC ran and nothing happened" is a
    // different statement from "no PoC was attempted", and the reason is what
    // distinguishes them.
    ...(ev.reason ? { proofReason: ev.reason } : {}),
    ...(proofArtifactDigest(finding) ? { proofArtifactSha256: proofArtifactDigest(finding) } : {}),
  };
}

export const _internals = { TIER_TO_LEVEL };
