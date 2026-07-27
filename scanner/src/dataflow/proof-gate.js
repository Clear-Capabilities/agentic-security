// Proof-gate precision pass — roadmap item #6 ("perfect multi-language SAST").
//
// The engine produces two INDEPENDENT flow-proof signals that, until now,
// were either informational-only or wired in isolation:
//
//   f.provenClean        (proven-clean.js)   — every reaching path to a SQL
//                                              sink passes a parameterizer.
//   f._provenUnreachable (exploit-prover.js) — a sanitizer on the path emits
//                                              output that cannot contain the
//                                              vuln family's metacharacters.
//
// This pass consolidates them into ONE verdict per finding and applies a
// precision demotion — the central idea of the precision gate:
//
//   "Report only provably-feasible flows. A flow we can PROVE is clean or
//    infeasible is demoted, not dropped — the auditor still sees it, and a
//    severity-based CI gate still fires, but it stops dominating the risk
//    ranking and stops tripping confidence filters."
//
// Output stamped on every finding:
//   f.proof = { verdict, reasons[] }
//     verdict ∈ 'proven-clean' | 'proven-infeasible' | 'feasible' | 'unproven'
//   f.proofGated = true            (only when a demotion was applied)
//
// Demotion policy is deliberately RECALL-PRESERVING:
//   - lower `confidence` by DEMOTE_FACTOR and recompute its tier,
//   - drop `confidenceTier` / `exploitabilityTier` one notch,
//   - record an `exploitabilityFactors` breadcrumb,
//   - leave `severity` UNTOUCHED. The proofs here are heuristic (path-
//     existence / regex-exclusion), so they must never hide a finding from a
//     severity gate. Confidence/exploitability are the safe levers.

const DEMOTE_FACTOR = 0.4;

// Tier ladders, lowest → highest. demoteTier moves one step down.
const CONFIDENCE_TIERS = ['very-low', 'low', 'medium', 'high'];
const EXPLOITABILITY_TIERS = ['low', 'medium', 'high', 'critical'];

function demoteTier(tier, ladder) {
  const i = ladder.indexOf(tier);
  if (i <= 0) return ladder[0];
  return ladder[i - 1];
}

// Decide the proof verdict for a single finding from the upstream signals.
export function verdictForFinding(f) {
  if (f.provenClean === true) {
    const sanitizers = (f.provenanceProof && f.provenanceProof.sanitizers) || [];
    return { verdict: 'proven-clean', reason: sanitizers.length ? `parameterized via ${sanitizers.join(', ')}` : 'sql-parameterizer-on-path' };
  }
  // sanitizer-gate.js — same "proven-clean" demotion, generalised beyond SQL to
  // every family the catalog's `appliesTo` tags cover (xss, url, cmd, ...).
  // Purely additive: it never overrides f.provenClean above.
  if (f.sanitized === true) {
    const sanitizers = (f.sanitizerProof && f.sanitizerProof.sanitizers) || [];
    return { verdict: 'proven-clean', reason: sanitizers.length ? `sanitized via ${sanitizers.join(', ')}` : 'sanitizer-on-path' };
  }
  if (f._provenUnreachable === true) {
    return { verdict: 'proven-infeasible', reason: f._provenUnreachableReason || 'sanitizer-excludes-metacharacters' };
  }
  // A taint finding that reached a sink with attributed sources, for which we
  // could NOT discharge a clean/infeasible proof, is "feasible" — the flows
  // a precision-gated report should lead with. Non-taint findings are simply
  // outside the proof model → "unproven" (no demotion, no claim).
  if (f.parser === 'IR-TAINT') return { verdict: 'feasible', reason: 'reaches-sink, no clean/infeasible proof discharged' };
  return { verdict: 'unproven', reason: 'no flow-proof applicable to this finding class' };
}

// Annotate findings in place. Returns the same array with a non-enumerable
// `_proofGateStats` for benchmarking.
export function annotateProofGate(findings, opts = {}) {
  if (!Array.isArray(findings)) return findings;
  const factor = typeof opts.demoteFactor === 'number' ? opts.demoteFactor : DEMOTE_FACTOR;
  const stats = { gated: 0, feasible: 0, provenClean: 0, provenInfeasible: 0, unproven: 0 };

  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const { verdict, reason } = verdictForFinding(f);
    f.proof = { verdict, reasons: [reason] };

    if (verdict === 'feasible') { stats.feasible++; continue; }
    if (verdict === 'unproven') { stats.unproven++; continue; }

    // proven-clean | proven-infeasible → recall-preserving demotion.
    if (verdict === 'proven-clean') stats.provenClean++; else stats.provenInfeasible++;
    // R13 (PRD §5): make "provably safe" a first-class, queryable verdict — not
    // just a quiet confidence demotion. "We proved this can't fire" is a
    // stronger, rarer claim than any confidence score, and lets the report
    // optionally hide discharged findings (--hide-proven-safe).
    f.provablySafe = true;

    if (typeof f.confidence === 'number') {
      f._confidenceBeforeProofGate = f.confidence;
      f.confidence = Math.max(0.01, Number((f.confidence * factor).toFixed(4)));
    }
    if (f.confidenceTier) f.confidenceTier = demoteTier(f.confidenceTier, CONFIDENCE_TIERS);
    if (f.exploitabilityTier) f.exploitabilityTier = demoteTier(f.exploitabilityTier, EXPLOITABILITY_TIERS);
    if (Array.isArray(f.exploitabilityFactors)) f.exploitabilityFactors.push(`proof:${verdict}`);
    f.proofGated = true;
    stats.gated++;
  }

  Object.defineProperty(findings, '_proofGateStats', { value: stats, enumerable: false, configurable: true });
  return findings;
}

export const _internals = { DEMOTE_FACTOR, CONFIDENCE_TIERS, EXPLOITABILITY_TIERS, demoteTier };
