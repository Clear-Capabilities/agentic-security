// Addition #6 — self-improving recall harness: the SEMANTIC (LLM) JUDGE.
//
// BENCH-ONLY. This module is never imported by the product/scan path — it is a
// measurement aid that lives entirely under bench/. Its job: decide whether an
// emitted finding SEMANTICALLY matches a known vulnerability by class + location
// + root-cause (NOT by string match), which a deterministic matcher cannot do
// (e.g. "improper neutralization in the query builder" vs a `sql-injection`
// finding two frames away). That judgement is what makes recall measurement
// honest for real-world repos where the vuln description and the finding wording
// rarely align verbatim.
//
// OFFLINE-SAFE BY CONSTRUCTION. With no LLM endpoint configured this returns a
// null verdict and NEVER touches the network and NEVER throws. The scorer
// (score.mjs) reads the null verdict's reasoning: the `no-llm-endpoint` sentinel
// means "fall back to the deterministic matcher", so an offline run still
// produces a defensible (if conservative) recall number. Only a genuine judge
// failure (endpoint set, call errored) yields a `judge-error` null that is
// excluded from the denominator.
//
// The live HTTP call is intentionally NOT wired here — `_callJudgeLLM` is a
// clearly-marked stub that throws "not wired". Wiring a real judge would mean
// POSTing the prompt below to $AGENTIC_SECURITY_LLM_ENDPOINT and parsing a
// strict yes/no; do that behind this same signature so callers never change.

/**
 * Adjudicate whether any emitted finding matches one expected known-vuln.
 *   judgeDetection({ expectedFinding, emittedFindings, endpoint }) →
 *     { detected: boolean|null, reasoning: string }
 *
 * No endpoint (arg or $AGENTIC_SECURITY_LLM_ENDPOINT) → { detected:null,
 * reasoning:'no-llm-endpoint: falls back to deterministic matcher' } with no
 * network call. Synchronous on the offline path by design so the offline
 * guarantee (no I/O, no throw) is trivially auditable.
 */
export function judgeDetection({ expectedFinding, emittedFindings, endpoint } = {}) {
  const ep = endpoint
    || (typeof process !== 'undefined' && process.env && process.env.AGENTIC_SECURITY_LLM_ENDPOINT)
    || null;

  if (!ep) {
    return { detected: null, reasoning: 'no-llm-endpoint: falls back to deterministic matcher' };
  }

  // An endpoint IS configured. Attempt the (stubbed) live call, but degrade to a
  // null judge-error rather than throwing — a bench must never crash the caller.
  try {
    const verdict = _callJudgeLLM({ expectedFinding, emittedFindings, endpoint: ep });
    return _normalizeVerdict(verdict);
  } catch (e) {
    return { detected: null, reasoning: `judge-error: ${(e && e.message) || String(e)}` };
  }
}

/**
 * Build the judge prompt (pure — no I/O). Exposed so a live wiring can reuse it
 * and so its shape can be inspected/tested. Asks for a strict class+location+
 * root-cause semantic match, not a string comparison.
 */
export function buildJudgePrompt(expectedFinding = {}, emittedFindings = []) {
  const exp = {
    type: expectedFinding.type || expectedFinding.family || 'unknown',
    location: expectedFinding.location || expectedFinding.file || 'unknown',
    root_cause: expectedFinding.root_cause || expectedFinding.description || '',
  };
  const emitted = (emittedFindings || []).slice(0, 50).map((f) => ({
    id: f.id || f.stableId || f.finding_id || null,
    family: f.family || f.vuln || null,
    cwe: f.cwe || null,
    file: f.file || f.location || null,
    line: f.line ?? null,
  }));
  return [
    'You are grading a security scanner for RECALL against a known vulnerability.',
    'Decide whether ANY emitted finding refers to the SAME vulnerability as the',
    'known one below — judged by vulnerability CLASS, code LOCATION, and ROOT',
    'CAUSE, not by matching strings. Wording will differ; that is expected.',
    '',
    `KNOWN VULNERABILITY: ${JSON.stringify(exp)}`,
    `EMITTED FINDINGS: ${JSON.stringify(emitted)}`,
    '',
    'Answer strictly as JSON: {"detected": true|false, "matched": <finding id or null>, "reasoning": "<one sentence>"}.',
  ].join('\n');
}

/** Coerce a raw judge response into the strict { detected, reasoning } shape. */
function _normalizeVerdict(v) {
  if (!v || typeof v !== 'object') return { detected: null, reasoning: 'judge-error: empty verdict' };
  const d = v.detected === true ? true : v.detected === false ? false : null;
  const reasoning = typeof v.reasoning === 'string' && v.reasoning ? v.reasoning : (d === null ? 'judge-error: unparseable verdict' : 'llm-judge');
  return { detected: d, matched: v.matched != null ? v.matched : null, reasoning };
}

/**
 * STUB — live LLM judge call. NOT WIRED. When an endpoint is configured this is
 * where a real implementation would POST buildJudgePrompt(...) to the endpoint
 * and parse the JSON reply. It throws so that (a) no silent/accidental network
 * call is ever made from the bench, and (b) judgeDetection degrades to a
 * `judge-error` null. Replace the throw with a fetch() to wire a real judge.
 */
function _callJudgeLLM({ expectedFinding, emittedFindings, endpoint }) {
  void buildJudgePrompt(expectedFinding, emittedFindings); // shape-check only
  void endpoint;
  throw new Error('not wired: live LLM judge is intentionally unimplemented (bench-only stub)');
}
