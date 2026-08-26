// FR-606 (assurance-hardening PRD): the 5-state model-status vocabulary
// reports must distinguish, so an LLM-backed feature never converts "the
// model didn't answer" into an undifferentiated clean result.
//
// Before this module, every degrade path in llm-validator/index.js set the
// SAME finding.validator_verdict ('unvalidated'), with the actual reason
// scattered across an inconsistently-populated free-text field
// (_validatorError: 'egress-policy-denied' | 'cost-ceiling' | 'HTTP 500' |
// an arbitrary exception message | ...unset entirely for the "nothing
// configured" case). A reader — human or downstream tool — had no reliable
// way to answer "did the model tier even run, and if not, why" from that
// shape alone.
//
// Attached to each finding llm-validator touches as
// finding.llmValidationStatus, carrying EXACTLY one of the five values
// below (never a sixth ad-hoc string), and aggregated into a scan-level
// summary via summarizeModelStatus so a reader gets the headline without
// inspecting every finding.
//
// Deliberately NOT stamped on findings the validator skips for reasons
// that have nothing to do with MODEL availability (an SCA locator with no
// line number, a finding with no precise file:line at all) — those already
// have their own honest verdict ('not-applicable') and status; forcing
// them into this taxonomy would misrepresent a finding-suitability
// question as a model-availability one.

export const MODEL_STATUS = Object.freeze({
  // No endpoint resolved at all — no API key, no BYO endpoint, nothing
  // configured. The tier is off, not broken; nothing was attempted.
  DISABLED: 'model-disabled',
  // Something WAS configured, but a policy refused to use it before any
  // network call was attempted — the egress policy's mode:deny/local-only/
  // provider allow-deny lists, the local preset's own loopback-only
  // refusal, or an internal cost-ceiling cap.
  POLICY_BLOCKED: 'policy-blocked',
  // The call was attempted and failed before a usable response arrived —
  // a network error, a timeout, or a non-2xx HTTP status.
  UNAVAILABLE: 'unavailable',
  // A response DID come back, but its content could not be parsed into a
  // usable answer, or failed the challenge/nonce cross-check — the model
  // answered something, just not something usable.
  MALFORMED: 'malformed',
  // A real, validated verdict was produced (including a cache hit of one
  // produced earlier — the model answered at some point; not re-asking is
  // an optimization, not a different outcome).
  COMPLETED: 'completed',
});

const ALL_STATUSES = Object.values(MODEL_STATUS);

/**
 * Aggregate the per-finding llmValidationStatus values into scan-level
 * counts. Findings with no llmValidationStatus at all (not applicable to
 * model availability — see the module header) are counted separately and
 * never silently folded into one of the five buckets.
 */
export function summarizeModelStatus(findings) {
  const counts = Object.fromEntries(ALL_STATUSES.map(s => [s, 0]));
  let notApplicable = 0;
  for (const f of findings || []) {
    const s = f?.llmValidationStatus;
    if (s && Object.prototype.hasOwnProperty.call(counts, s)) counts[s]++;
    else notApplicable++;
  }
  return { counts, notApplicable, total: (findings || []).length };
}
