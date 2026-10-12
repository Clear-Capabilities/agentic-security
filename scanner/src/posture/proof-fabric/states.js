// Evidence state ladder for the Universal Exploit Proof Fabric.
//
// Evidence state is SEPARATE from severity and confidence. It extends, never replaces, the vocabulary that already
// exists: `proof-tier.js` (execution-proven / proof-failed / taint-proven / unproven) and the fix-verify legs
// (`verifiedFull`, `degradedLegs`). `toProofTier` / `fromProofTier` are the explicit bridges.
//
// Transitions are guarded: a state can only be reached from the state directly before it (or by dropping back), so no
// caller can jump a finding to EXPLOIT_CONFIRMED without passing REPRODUCED, or to FIX_VERIFIED without
// FIX_REPLAY_BLOCKED. A degraded or incomplete run NEVER advances a state.
export const EVIDENCE_STATES = Object.freeze([
  'CANDIDATE',
  'STATICALLY_CORROBORATED',
  'REPRODUCER_GENERATED',
  'REPRODUCED',
  'EXPLOIT_CONFIRMED',
  'FIX_REPLAY_BLOCKED',
  'FIX_VERIFIED',
]);

export const stateRank = (s) => EVIDENCE_STATES.indexOf(s);

const REQUIRES_PREDECESSOR = Object.freeze(Object.fromEntries(EVIDENCE_STATES.map((s, i) => [s, i === 0 ? null : EVIDENCE_STATES[i - 1]])));

/**
 * Advance `from` to `to`. Returns { ok, state, reason }. Moving up requires `to` to be exactly the next rung; moving
 * down or staying is always allowed (evidence can be lost, never invented). Unknown states are rejected.
 */
export function advance(from, to) {
  if (!EVIDENCE_STATES.includes(from)) return { ok: false, state: 'CANDIDATE', reason: `unknown current state: ${String(from)}` };
  if (!EVIDENCE_STATES.includes(to)) return { ok: false, state: from, reason: `unknown target state: ${String(to)}` };
  if (stateRank(to) <= stateRank(from)) return { ok: true, state: to, reason: null };
  if (REQUIRES_PREDECESSOR[to] !== from) return { ok: false, state: from, reason: `cannot reach ${to} from ${from}: ${REQUIRES_PREDECESSOR[to]} is required first` };
  return { ok: true, state: to, reason: null };
}

// Bridges to the older vocabulary so existing consumers keep working.
export function toProofTier(state) {
  const r = stateRank(state);
  if (r >= stateRank('EXPLOIT_CONFIRMED')) return 'execution-proven';
  if (r >= stateRank('STATICALLY_CORROBORATED')) return 'taint-proven';
  return 'unproven';
}

export function fromProofTier(tier) {
  if (tier === 'taint-proven') return 'STATICALLY_CORROBORATED';
  // execution-proven under the older single-run marker path is one run, not the 3/3 + independent replay the fabric
  // requires, so it maps to REPRODUCED and never to EXPLOIT_CONFIRMED.
  if (tier === 'execution-proven') return 'REPRODUCED';
  return 'CANDIDATE';
}

// Completeness vocabulary shared with fix-verify: FULL only when nothing was skipped.
export const COMPLETENESS = Object.freeze(['FULL', 'DEGRADED', 'INCOMPLETE']);
