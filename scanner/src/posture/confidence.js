// Calibrated confidence score (0.0–1.0) per finding.
//
// Layered on top of the existing triage score, evidence count, parser type,
// and sanitizer signals. Maps the engine's various internal trust signals
// into a single normalized field that downstream consumers (Claude Code UX,
// SARIF emit, validator pipelines) can rely on.
//
// Output:
//   f.confidence ∈ [0,1]   — combined confidence the finding is real
//   f.confidenceTier       — 'high' | 'medium' | 'low' | 'very-low'
//
// Existing fields preserved (triageScore/triageLabel are unchanged).

const PARSER_PRIOR = {
  AST: 0.10,        // AST detectors are precise
  CHAIN: 0.12,      // attack chains are confirmed by multiple findings
  CONFIRMED: 0.20,  // explicitly confirmed by cross-file taint
  VALIDATOR: 0.25,  // LLM validator accepted
};

const SEVERITY_PRIOR = {
  critical: 0.85,
  high: 0.75,
  medium: 0.55,
  low: 0.35,
  info: 0.20,
};

export function annotateConfidence(findings) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    // If the finding already shipped with a hand-tuned confidence (e.g. jwt-exp
    // emits 0.85/0.95), keep that but still normalize the tier label.
    let conf = typeof f.confidence === 'number' ? f.confidence : null;
    if (conf == null) {
      conf = SEVERITY_PRIOR[f.severity] ?? 0.40;
      // Triage score in [0,100] is the strongest signal we have today; weight it.
      if (typeof f.triageScore === 'number') {
        conf = 0.5 * conf + 0.5 * (f.triageScore / 100);
      }
      const parserBoost = PARSER_PRIOR[f.parser] || 0;
      conf = Math.min(1, conf + parserBoost);
      if (f.evidence && f.evidence.length > 1) conf = Math.min(1, conf + 0.05 * (f.evidence.length - 1));
      if (f.sanitizerMismatch) conf = Math.min(1, conf + 0.05);
      if (f.isSanitized) conf *= 0.10;
      if (f.routeRooted) conf = Math.min(1, conf + 0.05);
      if (f.guards && f.guards.length) conf *= 0.80;
      if (f.reachable === false) conf *= 0.55;
      // f.unvalidated is set later in the pipeline (llm-validator/index.js,
      // invoked well after this first confidence pass), so it's never true
      // here on a finding's first computation — see applyUnvalidatedPenalty
      // below, the real enforcement point, run after validation. Kept here
      // too so a caller that builds a synthetic finding with
      // unvalidated:true pre-set still gets it applied in one pass.
      if (f.unvalidated) conf *= 0.85;   // LLM validator unavailable
      // f.llmOnly: currently unreachable — no producer anywhere in this
      // codebase ever sets it (grepped). Documented as a no-op rather than
      // silently deleted, since the intent ("LLM-only finding, no Layer-2
      // path") is a real, plausible signal that just isn't wired yet.
      if (f.llmOnly) conf *= 0.70;
    }
    conf = Math.max(0, Math.min(1, conf));
    f.confidence = Math.round(conf * 1000) / 1000;
    f.confidenceTier = _tierFor(f.confidence);
  }
}

// Premortem 3R-15: derive tier from the 2-decimal display value so a
// finding reported as "0.75" never lands in two tiers depending on the
// viewer's rounding (3-decimal raw 0.745 → 2-decimal 0.75 → high).
function _tierFor(confidence) {
  const display = Math.round(confidence * 100) / 100;
  if (display >= 0.75) return 'high';
  if (display >= 0.50) return 'medium';
  if (display >= 0.25) return 'low';
  return 'very-low';
}

// Retroactively applies the unvalidated penalty to findings whose
// confidence was already computed by annotateConfidence BEFORE
// f.unvalidated could be known — annotateConfidence only computes from
// scratch when f.confidence is still null (so hand-tuned detector
// confidences survive untouched), and f.unvalidated is set by
// llm-validator/index.js, which runs well after the pipeline's first
// annotateConfidence pass. Call this once, immediately after LLM
// validation runs (or is skipped). Idempotent: a finding is only
// adjusted once, tracked via f._unvalidatedPenaltyApplied.
export function applyUnvalidatedPenalty(findings) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    if (f._unvalidatedPenaltyApplied) continue;
    f._unvalidatedPenaltyApplied = true;
    if (!f.unvalidated || typeof f.confidence !== 'number') continue;
    f.confidence = Math.round(Math.max(0, Math.min(1, f.confidence * 0.85)) * 1000) / 1000;
    f.confidenceTier = _tierFor(f.confidence);
  }
}
