// Explicit version-1 migration adapters (CORE-002).
//
// Two directions, both conservative:
//   - FROM legacy shapes the repository already produces (a proof tier, a
//     boolean "verified", an egress decision, a legacy attestation) INTO version-1
//     records.
//   - FROM a version-1 record INTO a legacy view for consumers that still expect a
//     status string or a boolean.
//
// The rule that governs every mapping: evidence can be lost in translation but
// never invented. Unknown, skipped, unconfirmed, failed-to-run and incomplete
// inputs land on the matching non-positive state. A legacy "true" with no oracle
// evidence is `inconclusive`, never `confirmed`; a legacy "proof-failed" is
// `inconclusive`, never `refuted` (the old tier's own comment says absence of
// proof is not proof of absence). The only path to `confirmed` from a legacy
// shape is an explicit `trustedRunner` assertion by the caller, which supplies
// the trusted-runtime-proof evidence the new contract requires.
//
// What the adapter cannot recover is recorded in `migration` rather than
// dropped: the legacy value and the shape it came from stay on the record.

import {
  SCHEMA_VERSION, isPlainObject, isDigest,
} from './schema-kit.js';
import {
  VERIFICATION_SCHEMA, VERIFICATION_OUTCOMES, buildVerificationRecord, validateVerificationRecord,
} from './verification-record.js';
import {
  OBSERVATION_BINDING_SCHEMA, CAPABILITY_DECISION_SCHEMA, ROUTING_LABEL_SCHEMA, RELEASE_EVIDENCE_SCHEMA,
  observationBindingId, capabilityDecisionId, routingLabelId, releaseEvidenceId, deriveReleaseComplete,
  validateObservationBinding, validateCapabilityDecision, validateRoutingLabel, validateReleaseEvidence,
} from './contracts.js';
import { digestOf } from './identity.js';

const SCHEMAS = Object.freeze({
  verification: [VERIFICATION_SCHEMA, validateVerificationRecord],
  observationBinding: [OBSERVATION_BINDING_SCHEMA, validateObservationBinding],
  capabilityDecision: [CAPABILITY_DECISION_SCHEMA, validateCapabilityDecision],
  routingLabel: [ROUTING_LABEL_SCHEMA, validateRoutingLabel],
  releaseEvidence: [RELEASE_EVIDENCE_SCHEMA, validateReleaseEvidence],
});

function fail(code, message) { return { ok: false, record: null, errors: [{ code, path: '', message }] }; }

/**
 * Entry point. A record carrying a `schema` marker is a current-format record: its
 * major version must be supported, and it is validated, never rewritten. A record
 * without one is treated as legacy and routed to the matching adapter.
 *
 * @param {'verification'|'observationBinding'|'capabilityDecision'|'routingLabel'|'releaseEvidence'} kind
 * @param {object} input
 * @param {object} [ctx] adapter context for legacy input (see each adapter)
 */
export function migrateRecord(kind, input, ctx = {}) {
  const entry = SCHEMAS[kind];
  if (!entry) return fail('UNKNOWN_ENUM', `unknown record kind '${kind}'`);
  if (!isPlainObject(input)) return fail('NOT_AN_OBJECT', 'input must be an object');
  const [schemaName, validate] = entry;
  if (input.schema !== undefined) {
    const v = validate(input);
    return { ok: v.ok, record: v.ok ? input : null, errors: v.errors };
  }
  const adapter = ADAPTERS[kind];
  const out = adapter(input, ctx);
  if (!out.ok) return out;
  const v = validate(out.record);
  return v.ok ? out : { ok: false, record: null, errors: v.errors };
}

// ---------------------------------------------------------------- verification


/**
 * Map a legacy status to a version-1 outcome. Returns `{ outcome, reason }`.
 * Understands: the execution-proof evidence object ({tier, ran, witnessStatus,
 * timedOut, reason}), a boolean `verified`, and a status string.
 */
export function legacyVerificationOutcome(legacy, { trustedRunner = false } = {}) {
  const pe = isPlainObject(legacy.proofEvidence) ? legacy.proofEvidence : (legacy.tier !== undefined ? legacy : null);
  if (pe) {
    const ran = pe.ran === true;
    if (!ran) {
      const reason = pe.reason || 'the proof-of-concept did not execute';
      if (/unsupported|no confinement primitive/i.test(String(pe.reason || ''))) return { outcome: 'unsupported', reason };
      if (pe.witnessStatus === 'error' || /could not start/i.test(String(pe.reason || ''))) return { outcome: 'error', reason };
      if (pe.timedOut) return { outcome: 'inconclusive', reason: pe.reason || 'the proof-of-concept timed out' };
      return { outcome: 'not-run', reason };
    }
    if (pe.tier === 'execution-proven') {
      return trustedRunner
        ? { outcome: 'confirmed', reason: pe.observed || 'legacy execution proof, asserted by a trusted runner' }
        : { outcome: 'inconclusive', reason: 'legacy execution proof predates trusted-runtime-proof classification; re-verify under the trusted verifier to confirm' };
    }
    if (pe.tier === 'proof-failed') return { outcome: 'inconclusive', reason: 'the proof-of-concept ran but did not demonstrate the effect; absence of proof is not refutation' };
    return { outcome: 'inconclusive', reason: `legacy proof tier '${pe.tier}' carries no execution evidence` };
  }
  const raw = legacy.status !== undefined ? legacy.status : legacy.verified;
  if (raw === true) return { outcome: 'inconclusive', reason: 'legacy boolean true carries no oracle evidence' };
  if (raw === false) return { outcome: 'inconclusive', reason: 'legacy boolean false is not a refutation: no applicable oracle or preconditions are recorded' };
  if (raw === null || raw === undefined) return { outcome: 'not-run', reason: 'legacy record has no verification status' };
  if (typeof raw === 'string') {
    const s = raw.toLowerCase();
    if (VERIFICATION_OUTCOMES.includes(s)) {
      if (s === 'confirmed' || s === 'refuted') {
        return { outcome: 'inconclusive', reason: `legacy status '${s}' carries no evidence references, so it is not carried forward as '${s}'` };
      }
      return { outcome: s, reason: `legacy status '${s}'` };
    }
    if (['skipped', 'pending', 'queued', 'disabled'].includes(s)) return { outcome: 'not-run', reason: `legacy status '${s}'` };
    if (['timeout', 'timed-out', 'unconfirmed', 'partial', 'incomplete', 'unknown'].includes(s)) return { outcome: 'inconclusive', reason: `legacy status '${s}'` };
    if (['failed', 'failure', 'errored', 'crash'].includes(s)) return { outcome: 'error', reason: `legacy status '${s}'` };
  }
  return { outcome: 'inconclusive', reason: `unrecognized legacy status ${JSON.stringify(raw)}` };
}

/**
 * Legacy verification result -> version-1 verification record.
 * ctx: { hypothesisId, commit, detectorOrigin, scope, trustedRunner?, oracle? }.
 * Missing context is not invented: without a hypothesisId the adapter refuses.
 */
export function fromLegacyVerification(legacy, ctx = {}) {
  if (!ctx.hypothesisId) return fail('MISSING_FIELD', 'a legacy verification needs a hypothesisId from the caller; it is not guessed');
  const { outcome, reason } = legacyVerificationOutcome(legacy, { trustedRunner: ctx.trustedRunner === true });
  const evidence = [];
  if (outcome === 'confirmed') {
    evidence.push({
      id: 'legacy-runtime-proof', kind: 'trusted-runtime-proof', producer: 'trusted-runner',
      digest: digestOf(legacy.proofEvidence || legacy), source: 'legacy-execution-proof',
    });
  }
  const pe = isPlainObject(legacy.proofEvidence) ? legacy.proofEvidence : legacy;
  const rec = buildVerificationRecord({
    hypothesisId: ctx.hypothesisId,
    commit: ctx.commit ?? null,
    detectorOrigin: ctx.detectorOrigin || { detector: 'legacy-unknown' },
    oracle: outcome === 'confirmed' ? (ctx.oracle || { id: 'legacy-execution-proof', kind: 'runtime-replay' }) : (ctx.oracle ?? null),
    attempt: ['not-run', 'unsupported'].includes(outcome) ? 0 : 1,
    outcome, reason,
    evidence,
    scope: ctx.scope || { description: 'unspecified legacy scope', platform: pe.backend ? String(pe.backend) : 'unknown' },
    migration: { from: 'legacy-verification', legacyValue: JSON.stringify(legacy.status ?? legacy.verified ?? pe.tier ?? null) },
  });
  return { ok: true, record: rec, errors: [] };
}

/**
 * Version-1 record -> view for a legacy consumer. `verified` is true ONLY for a
 * confirmed record and false ONLY for a refuted one; every other state is null, so
 * a consumer that tests `=== true` cannot be told a skipped check passed, and one
 * that tests `=== false` cannot be told an unrun check failed.
 */
export function toLegacyVerificationView(record) {
  return {
    status: record.outcome,
    verified: record.outcome === 'confirmed' ? true : record.outcome === 'refuted' ? false : null,
    confirmationLevel: record.confirmationLevel,
    repairStatus: record.repair?.status ?? 'none',
    reason: record.reason,
  };
}

// ---------------------------------------------------------------- other kinds

function fromEgressDecision(legacy) {
  // posture/egress evaluateEgress(): { allowed, decision, reason, provider, policySource, purpose }.
  // It is an in-process policy check before a call: it explains a decision and is
  // not OS-level isolation, so it can never be recorded as enforced.
  const decision = legacy.decision === 'allow' ? 'allow' : legacy.decision === 'deny' ? 'deny' : 'unsupported';
  const rec = {
    schema: CAPABILITY_DECISION_SCHEMA, schemaVersion: SCHEMA_VERSION,
    taskId: String(legacy.purpose || 'unknown'),
    capability: 'network',
    subject: String(legacy.provider || 'unknown'),
    decision,
    mediation: 'in-process-policy',
    enforced: false,
    backend: null,
    reason: String(legacy.reason || (decision === 'allow' ? 'egress policy allowed the call' : 'no reason recorded')),
    migration: { from: 'egress-decision', legacyValue: JSON.stringify(legacy.decision ?? null) },
  };
  rec.id = capabilityDecisionId(rec);
  return { ok: true, record: rec, errors: [] };
}

function fromLegacyRoutingLabel(legacy) {
  if (!legacy.taskId || !legacy.model) return fail('MISSING_FIELD', 'a legacy routing label needs taskId and model');
  const decided = legacy.correct === true || legacy.correct === false;
  const source = ['adjudication', 'trusted-execution'].includes(legacy.labelSource) ? legacy.labelSource : 'none';
  // A boolean without a named source is not an adjudicated label.
  const outcome = decided && source !== 'none' ? (legacy.correct ? 'correct' : 'incorrect') : (legacy.delayed ? 'delayed' : 'unknown');
  const rec = {
    schema: ROUTING_LABEL_SCHEMA, schemaVersion: SCHEMA_VERSION,
    taskId: String(legacy.taskId),
    taskKind: legacy.taskKind || 'triage',
    stratum: String(legacy.stratum || 'unstratified'),
    model: String(legacy.model),
    outcome,
    labelSource: outcome === 'correct' || outcome === 'incorrect' ? source : 'none',
    migration: { from: 'legacy-routing-label', legacyValue: JSON.stringify(legacy.correct ?? null) },
  };
  rec.id = routingLabelId(rec);
  return { ok: true, record: rec, errors: [] };
}

function fromLegacyRelease(legacy) {
  const claims = (Array.isArray(legacy.checks) ? legacy.checks : []).map((c, i) => {
    const refs = (Array.isArray(c.evidence) ? c.evidence : (c.evidence ? [c.evidence] : [])).filter(r => typeof r === 'string' && (r.startsWith('vrec:') || isDigest(r)));
    const s = String(c.status || '').toLowerCase();
    let status; let gaps = [];
    if (['pass', 'passed', 'ok'].includes(s) && refs.length) status = 'verified';
    else if (['pass', 'passed', 'ok'].includes(s)) { status = 'unverified'; gaps = ['legacy check reported a pass but cites no evidence']; }
    else if (['fail', 'failed'].includes(s)) { status = 'failed'; gaps = [`legacy check '${c.id ?? i}' failed`]; }
    else if (['skip', 'skipped'].includes(s)) { status = 'skipped'; gaps = [`legacy check '${c.id ?? i}' was skipped`]; }
    else { status = 'incomplete'; gaps = [`legacy check '${c.id ?? i}' has status ${JSON.stringify(c.status ?? null)}`]; }
    return { id: String(c.id ?? `check-${i}`), statement: String(c.statement || c.id || `check ${i}`), status, evidenceRefs: refs, gaps };
  });
  const rec = {
    schema: RELEASE_EVIDENCE_SCHEMA, schemaVersion: SCHEMA_VERSION,
    subject: { commit: legacy.commit ?? null, bundleDigest: isDigest(legacy.bundleDigest) ? legacy.bundleDigest : null },
    claims,
    complete: false,
    migration: { from: 'legacy-attestation', legacyValue: JSON.stringify(legacy.verified ?? null) },
  };
  rec.complete = deriveReleaseComplete(rec);
  rec.id = releaseEvidenceId(rec);
  return { ok: true, record: rec, errors: [] };
}

function fromLineageObservation(legacy, ctx) {
  // A lineage RuntimeObservation (id, adapter, windowStart/End, matched*Ids). The
  // observation stays in lineage; only its id is referenced.
  if (!ctx.hypothesisId) return fail('MISSING_FIELD', 'an observation binding needs a hypothesisId from the caller');
  if (!legacy.id) return fail('MISSING_FIELD', 'legacy observation has no id');
  const matched = ['matchedNodeIds', 'matchedEdgeIds', 'matchedFlowIds'].some(k => Array.isArray(legacy[k]) && legacy[k].length > 0);
  const rec = {
    schema: OBSERVATION_BINDING_SCHEMA, schemaVersion: SCHEMA_VERSION,
    hypothesisId: ctx.hypothesisId,
    observationRef: { observationId: String(legacy.id), ...(legacy.adapter ? { adapter: String(legacy.adapter) } : {}) },
    provenance: 'runtime-observation',
    // Matching an observation never shows the sample was complete.
    pathState: matched ? 'runtime-supported' : 'unresolved',
    completeness: 'unknown',
    window: legacy.windowStart && legacy.windowEnd ? { start: String(legacy.windowStart), end: String(legacy.windowEnd) } : undefined,
    migration: { from: 'lineage-runtime-observation', legacyValue: JSON.stringify(legacy.matchMethod ?? null) },
  };
  if (rec.window === undefined) delete rec.window;
  rec.id = observationBindingId(rec);
  return { ok: true, record: rec, errors: [] };
}

const ADAPTERS = Object.freeze({
  verification: (legacy, ctx) => fromLegacyVerification(legacy, ctx),
  observationBinding: fromLineageObservation,
  capabilityDecision: (legacy) => fromEgressDecision(legacy),
  routingLabel: (legacy) => fromLegacyRoutingLabel(legacy),
  releaseEvidence: (legacy) => fromLegacyRelease(legacy),
});

export { fromEgressDecision, fromLegacyRoutingLabel, fromLegacyRelease, fromLineageObservation };
