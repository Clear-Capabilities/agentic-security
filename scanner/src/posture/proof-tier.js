// How strongly a finding is backed by evidence.
//
//   execution-proven — a proof-of-concept RAN inside the sandbox and produced
//                      the predicted observable effect. The strongest claim.
//   proof-failed     — a proof-of-concept ran and did NOT demonstrate the bug.
//                      A triage signal, NOT an automatic false-positive verdict:
//                      absence of proof is not proof of absence.
//   taint-proven     — the analyser's static reasoning found it; nothing executed.
//   unproven         — no analyser backing recorded.
export const PROOF_TIERS = Object.freeze([
  'execution-proven', 'proof-failed', 'taint-proven', 'unproven',
]);

// Parsers that represent real analysis rather than a plain pattern match.
const _ANALYSED = new Set(['IR-TAINT', 'MULTI-SINK']);

export function proofTierOf(finding) {
  if (finding?.proofTier) return finding.proofTier;
  return _ANALYSED.has(finding?.parser) ? 'taint-proven' : 'unproven';
}

export function attachProofTier(finding, evidence) {
  if (!PROOF_TIERS.includes(evidence?.tier)) {
    throw new Error(`unknown proof tier: ${evidence?.tier}`);
  }
  let tier = evidence.tier;
  // Guard the central honesty rule: nothing that did not RUN may be called
  // execution-proven or proof-failed. Fall back to the finding's static standing.
  if (!evidence.ran && (tier === 'execution-proven' || tier === 'proof-failed')) {
    tier = proofTierOf({ ...finding, proofTier: undefined });
  }
  return { ...finding, proofTier: tier, proofEvidence: { ...evidence, tier } };
}
