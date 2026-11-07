// Validation dispositions (PRD FR 05).
//
// Four things are kept apart on a finding and never collapsed into one flag:
//   the detector's claim        (vuln, severity, source/sink)
//   independent evidence        (execution proof, reviewer verdicts, refutation)
//   model opinion               (validator_verdict: accept | reject | escalate)
//   the final disposition       (this module)
//
// A model opinion is never sufficient for `confirmed` or `refuted`. `accept`
// cannot confirm; `reject` cannot refute. Only evidence the model did not
// produce can move a finding to either state, so a persuasive or injected
// excerpt cannot change the outcome by itself.

import * as crypto from 'node:crypto';

export const DISPOSITIONS = Object.freeze({
  CONFIRMED: 'confirmed',
  NEEDS_REVIEW: 'needs-review',
  REFUTED: 'refuted',
  HARDENING: 'hardening',
  UNVALIDATED: 'unvalidated',
});

/** Refutation kinds that disprove a claim. Context alone (where the code lives) never does. */
export const REFUTATION_KINDS = Object.freeze([
  'guard-proven', 'sanitizer-proven', 'unreachable-proven', 'constant-input', 'already-patched', 'not-the-claimed-weakness',
]);

const HARDENING_UNTIL_ESTABLISHED = /\b(?:missing timeout|timing (?:attack|comparison|side)|non-constant[- ]time)\b/i;

const _DETERMINISTIC_PARSERS = new Set(['IR-TAINT', 'MULTI-SINK']);
// A structural rule over a modelled API (the Haskell rule families) is a deterministic detector claim without a taint path.
const _STRUCTURAL_PARSERS = new Set(['HS-RULES']);

/** Reasons that are not evidence. A refutation resting on one of these is rejected. */
const NON_EVIDENCE = /\b(?:test|tests|spec|fixture|dev(?:eloper)?[- ]tool|internal|private repo(?:sitory)?|member[- ]only|trusted users?|no (?:known )?exploit|no proof|not exploitable in practice)\b/i;

export function contentFingerprint(text) {
  return crypto.createHash('sha256').update(String(text ?? '')).digest('hex');
}

function fileText(fileContents, file) {
  if (!fileContents || !file) return null;
  const v = fileContents instanceof Map ? fileContents.get(file) : fileContents[file];
  return typeof v === 'string' ? v : null;
}

/** Why the finding no longer matches the code it was raised on, or null when it does. */
function staleReason(f, fileContents) {
  if (!fileContents) return null; // nothing to compare against; not evidence of staleness
  const text = fileText(fileContents, f.file);
  if (text === null) return 'source file is not available in this scan (deleted, moved or out of scope)';
  if (Number.isInteger(f.line)) {
    const n = text.split('\n').length;
    if (f.line < 1 || f.line > n) return `line ${f.line} is outside the file (${n} lines)`;
  }
  if (f.sourceHash && f.sourceHash !== contentFingerprint(text)) {
    return 'file content differs from the content the finding was raised on';
  }
  return null;
}

/**
 * Judge a refutation record. Returns { ok, reason }.
 * A refutation must name a kind, cite evidence, name who or what verified it,
 * and match the snapshot the finding was raised on.
 */
export function judgeRefutation(r, f, fileContents) {
  if (!r || typeof r !== 'object') return { ok: false, reason: 'no refutation recorded' };
  if (!REFUTATION_KINDS.includes(r.kind)) return { ok: false, reason: `refutation kind "${r.kind}" does not disprove a claim` };
  if (!Array.isArray(r.evidenceRefs) || r.evidenceRefs.length === 0) return { ok: false, reason: 'refutation cites no evidence' };
  if (!r.verifier) return { ok: false, reason: 'refutation names no reviewer or verifier' };
  if (NON_EVIDENCE.test(String(r.reason || ''))) return { ok: false, reason: 'refutation rests on context, not on evidence about the claim' };
  const text = fileText(fileContents, f.file);
  if (r.sourceHash) {
    if (text === null || contentFingerprint(text) !== r.sourceHash) return { ok: false, reason: 'refutation was made on different code than the finding now matches' };
  } else {
    return { ok: false, reason: 'refutation carries no source hash, so it cannot be tied to a code snapshot' };
  }
  return { ok: true, reason: r.reason || r.kind };
}

/**
 * Judge a reviewed suppression. Requires rationale, owner, scope, expiry and a
 * content fingerprint; reopens on expiry or when the relevant source changes.
 * Returns { active, reopened, reason }.
 */
export function judgeSuppression(s, f, fileContents, now = Date.now()) {
  if (!s || typeof s !== 'object') return { active: false, reason: 'no suppression recorded' };
  for (const k of ['rationale', 'owner', 'scope', 'expires', 'fingerprint']) {
    if (!s[k]) return { active: false, reason: `suppression is missing ${k}` };
  }
  const exp = Date.parse(s.expires);
  if (!Number.isFinite(exp)) return { active: false, reason: 'suppression expiry is not a date' };
  if (exp <= now) return { active: false, reopened: true, reason: `suppression expired ${s.expires}` };
  const text = fileText(fileContents, f.file);
  if (text === null) return { active: false, reopened: true, reason: 'suppressed source is no longer available' };
  if (contentFingerprint(text) !== s.fingerprint) return { active: false, reopened: true, reason: 'source changed since the suppression was recorded' };
  if (s.rule && f.ruleVersion && s.rule !== f.ruleVersion) return { active: false, reopened: true, reason: 'rule changed since the suppression was recorded' };
  return { active: true, reason: s.rationale };
}

/** Missing-evidence statements derived from what the finding does not carry. */
function missingEvidenceFor(f, extra = []) {
  const out = [...extra];
  if (!f.source && !f.sink && !f.exampleFlows?.length) out.push('no source-to-sink path recorded');
  if (Array.isArray(f.missingEvidence)) out.push(...f.missingEvidence);
  return [...new Set(out)];
}

/**
 * Assign the final disposition. Pure: reads the finding, writes `disposition`
 * and `dispositionDetail`, never touches severity or confidence.
 */
export function assignDisposition(f, { fileContents = null, now = Date.now() } = {}) {
  const detail = { evidence: [], missingEvidence: [], nextCheck: null, reason: '' };
  const done = (disposition, reason, more = {}) => {
    f.disposition = disposition;
    f.dispositionDetail = { ...detail, ...more, reason };
    return disposition;
  };

  // PRD FR 07: these families describe a missing control, not an exploitable weakness, until the finding
  // establishes attacker influence (a taint source) or a secret-dependent comparison.
  if (HARDENING_UNTIL_ESTABLISHED.test(String(f.vuln || '')) && !f.source && !f.secretDependent && f.proofTier !== 'execution-proven') {
    return done(DISPOSITIONS.HARDENING, 'missing-control advice: no attacker-controlled input or secret-dependent comparison is established');
  }
  // Hardening: an improvement with no claim of an exploitable weakness.
  if (f.kind === 'hardening' || f.hardeningAdvice === true) {
    return done(DISPOSITIONS.HARDENING, 'improvement without a demonstrated exploitable weakness');
  }

  // Reviewed suppression, then evidence-backed refutation: the only two exits to refuted.
  if (f.reviewedSuppression) {
    const j = judgeSuppression(f.reviewedSuppression, f, fileContents, now);
    if (j.active) {
      return done(DISPOSITIONS.REFUTED, j.reason, {
        evidence: [{ kind: 'reviewed-suppression', owner: f.reviewedSuppression.owner, scope: f.reviewedSuppression.scope, expires: f.reviewedSuppression.expires }],
        suppressed: true,
      });
    }
    detail.missingEvidence.push(`reviewed suppression no longer applies: ${j.reason}`);
    detail.reopened = !!j.reopened;
  }
  if (f.refutation) {
    const j = judgeRefutation(f.refutation, f, fileContents);
    if (j.ok) {
      return done(DISPOSITIONS.REFUTED, j.reason, {
        evidence: [{ kind: f.refutation.kind, refs: f.refutation.evidenceRefs, verifier: f.refutation.verifier, version: f.refutation.version ?? null }],
      });
    }
    detail.missingEvidence.push(`refutation not accepted: ${j.reason}`);
  }

  // Stale or unattributable source is uncertainty, never a refutation.
  const stale = staleReason(f, fileContents);
  if (stale) {
    return done(DISPOSITIONS.UNVALIDATED, stale, {
      missingEvidence: [...detail.missingEvidence, stale],
      nextCheck: 'supply the matching source or rescan',
    });
  }

  // Confirmed needs evidence the model did not produce.
  const executed = f.proofTier === 'execution-proven';
  const reviewed = Array.isArray(f.reviewerVerdicts) && f.reviewerVerdicts.some((r) => r && r.verdict === 'confirmed' && r.reviewer && Array.isArray(r.evidenceRefs) && r.evidenceRefs.length);
  const conflicting = f.validator_verdict === 'reject' || f.falsification?.verdict === 'blocked'
    || (f.proof && /^proven-/.test(String(f.proof.verdict || '')))
    || (Array.isArray(f.reviewerVerdicts) && f.reviewerVerdicts.some((r) => r && r.verdict === 'refuted'));
  if ((executed || reviewed) && !conflicting) {
    return done(DISPOSITIONS.CONFIRMED, executed ? 'reproduced by an executed test' : 'source path confirmed by an independent reviewer', {
      evidence: [executed ? { kind: 'execution-proof' } : { kind: 'reviewer', reviewers: f.reviewerVerdicts.filter((r) => r.verdict === 'confirmed').map((r) => r.reviewer) }],
    });
  }

  // Conflicting evidence stays needs-review, with the conflict named.
  if (conflicting) {
    const why = [];
    if (f.validator_verdict === 'reject') why.push('a model rejected it, which is an opinion, not a refutation');
    if (f.falsification?.verdict === 'blocked') why.push('a control was found near the path, but the control is not proven to cover this flow');
    if ((executed || reviewed)) why.push('other evidence supports the claim');
    return done(DISPOSITIONS.NEEDS_REVIEW, why.join('; '), {
      missingEvidence: missingEvidenceFor(f, [...detail.missingEvidence, 'a deterministic refutation or a reviewed suppression']),
      nextCheck: 'confirm or refute with the callers, guards and configuration on the matching source',
      conflict: true,
    });
  }

  // A model could not decide, or its reply could not be trusted.
  if (f.validator_verdict === 'escalate') {
    return done(DISPOSITIONS.NEEDS_REVIEW, 'validation could not decide', {
      missingEvidence: missingEvidenceFor(f, detail.missingEvidence),
      nextCheck: 'review the cited span and its callers',
    });
  }

  // Deterministic corroboration (PRD FR 05 flow): a taint path the engine itself traced from a source to a sink, with no control
  // found on it, is a plausible issue awaiting independent review. It is needs-review, not confirmed, and not unvalidated.
  if (_DETERMINISTIC_PARSERS.has(f.parser) && f.source && f.sink && f.validator_verdict !== 'accept') {
    return done(DISPOSITIONS.NEEDS_REVIEW, 'the engine traced a source-to-sink path with no control found; no independent review yet', {
      evidence: [{ kind: 'deterministic-taint-path', parser: f.parser }],
      missingEvidence: missingEvidenceFor(f, [...detail.missingEvidence, 'a reproducible test or an independent reviewer']),
      nextCheck: 'reproduce with a test or have a reviewer trace the path and confirm the callers',
    });
  }

  if (_STRUCTURAL_PARSERS.has(f.parser) && Number.isInteger(f.line) && f.validator_verdict !== 'accept') {
    return done(DISPOSITIONS.NEEDS_REVIEW, 'a structural rule matched a modelled API; no independent review yet', {
      evidence: [{ kind: 'structural-rule', parser: f.parser }],
      missingEvidence: missingEvidenceFor(f, [...detail.missingEvidence, 'whether the flagged value is security-relevant in this context']),
      nextCheck: 'confirm the value is security-relevant and the operation is reachable',
    });
  }

  // Pipeline findings from the structural workflow analysis carry their own input origin, privilege boundary and missing evidence.
  if (typeof f.workflow === 'string' && f.disposition !== undefined) {
    return done(DISPOSITIONS.NEEDS_REVIEW, f.disposition === 'detected' ? 'the workflow analysis traced an untrusted input into a sensitive operation; no independent review yet' : 'the workflow analysis found a plausible issue with unresolved facts', {
      evidence: [{ kind: 'workflow-analysis', workflow: f.workflow, job: f.job ?? null, step: f.step ?? null, inputOrigin: f.inputOrigin ?? null }],
      missingEvidence: missingEvidenceFor(f, detail.missingEvidence),
      nextCheck: 'confirm the privilege boundary and who controls the input',
    });
  }

  // Model errors, no endpoint, spend ceilings: review was not attempted or failed.
  if (['unvalidated', 'not-applicable'].includes(f.validator_verdict) || f.unvalidated === true || !f.validator_verdict) {
    const why = f.validator_skipped_reason || (f.llmValidationStatus ? `model validation ${f.llmValidationStatus}` : 'no review attempted');
    return done(DISPOSITIONS.UNVALIDATED, why, {
      missingEvidence: missingEvidenceFor(f, detail.missingEvidence),
      nextCheck: 'run validation or review manually',
    });
  }

  // Model accepted: plausible, but a model alone cannot confirm.
  return done(DISPOSITIONS.NEEDS_REVIEW, 'a model judged it plausible; no independent evidence yet', {
    missingEvidence: missingEvidenceFor(f, [...detail.missingEvidence, 'a reproducible test or an independent reviewer']),
    nextCheck: 'reproduce with a test or have a second reviewer trace the source path',
  });
}

export function annotateDispositions(findings, opts = {}) {
  const counts = {};
  for (const f of findings) {
    if (!f || f.kind === 'sca') continue;
    const d = assignDisposition(f, opts);
    counts[d] = (counts[d] || 0) + 1;
  }
  return counts;
}

/**
 * Annotate every finding, then move the evidence-backed refuted ones out of the
 * actionable list. They are retained, with reason, verifier and evidence, in the
 * returned `refuted` array for the suppression ledger; nothing is deleted.
 */
export function applyDispositions(findings, opts = {}) {
  const counts = annotateDispositions(findings, opts);
  const kept = [];
  const refuted = [];
  for (const f of findings) (f && f.disposition === DISPOSITIONS.REFUTED ? refuted : kept).push(f);
  return { kept, refuted, counts };
}
