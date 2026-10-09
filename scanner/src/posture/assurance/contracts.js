// Observation bindings, capability decisions, routing labels and release
// evidence (CORE-002), plus cross-record validation (duplicate ids, dangling
// references). Verification records live in verification-record.js.
//
// Lineage separation: an observation binding refers to a lineage runtime
// observation BY ID ONLY. It never embeds, imports or mutates lineage state;
// lineage owns the graph and this package owns the vulnerability-evidence claim
// that a given observation bears on a given hypothesis.

import {
  SCHEMA_VERSION, makeCtx, result, guardObject, checkHeader, checkFields, checkEnum, checkDigest, checkCommit,
  checkString, checkId, isPlainObject, isDigest,
} from './schema-kit.js';
import { semanticId, ID_PREFIXES } from './identity.js';
import { validateVerificationRecord, verificationClaimKey } from './verification-record.js';

// ---------------------------------------------------------------- observation binding

export const OBSERVATION_BINDING_SCHEMA = 'agentic-security/observation-binding';
export const BINDING_PROVENANCE = Object.freeze(['static-config', 'runtime-observation', 'inferred']);
export const PATH_STATES = Object.freeze(['possible', 'blocked', 'unresolved', 'runtime-supported']);
export const OBSERVATION_COMPLETENESS = Object.freeze(['complete', 'sampled', 'unknown']);

const OB_ALLOWED = [
  'schema', 'schemaVersion', 'id', 'hypothesisId', 'observationRef', 'boundaryRef', 'provenance', 'pathState',
  'completeness', 'window', 'eventDiscriminator', 'migration', 'createdAt',
];
const OB_REQUIRED = ['schema', 'schemaVersion', 'id', 'hypothesisId', 'observationRef', 'provenance', 'pathState', 'completeness'];

// The semantic identity of a binding excludes the event discriminator.
export const OBSERVATION_BINDING_KEY_FIELDS = Object.freeze([
  'hypothesisId', 'observationRef', 'boundaryRef', 'provenance', 'pathState', 'completeness', 'window',
]);

/** Identity of WHAT the binding says, independent of which event delivered it. */
export function observationBindingKey(b) {
  return semanticId('obkey', b, OBSERVATION_BINDING_KEY_FIELDS);
}

/** Id of this binding instance: the key plus the optional explicit event discriminator. */
export function observationBindingId(b) {
  return semanticId(ID_PREFIXES.observationBinding, b, [...OBSERVATION_BINDING_KEY_FIELDS, 'eventDiscriminator']);
}

export function validateObservationBinding(b) {
  const g = guardObject(b);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, b, OBSERVATION_BINDING_SCHEMA)) return result(ctx);
  checkFields(ctx, b, OB_ALLOWED, OB_REQUIRED);
  checkString(ctx, 'hypothesisId', b.hypothesisId);
  if (!isPlainObject(b.observationRef)) ctx.err('BAD_TYPE', 'observationRef', 'must be an object');
  else {
    for (const k of Object.keys(b.observationRef)) if (!['observationId', 'adapter'].includes(k)) ctx.err('UNKNOWN_FIELD', `observationRef.${k}`, 'not part of observationRef');
    checkString(ctx, 'observationRef.observationId', b.observationRef.observationId);
  }
  if (b.boundaryRef !== undefined && b.boundaryRef !== null) checkString(ctx, 'boundaryRef', b.boundaryRef);
  const provOk = checkEnum(ctx, 'provenance', b.provenance, BINDING_PROVENANCE);
  const stateOk = checkEnum(ctx, 'pathState', b.pathState, PATH_STATES);
  const compOk = checkEnum(ctx, 'completeness', b.completeness, OBSERVATION_COMPLETENESS);
  if (b.window !== undefined && b.window !== null) {
    if (!isPlainObject(b.window) || !Object.keys(b.window).every(k => ['start', 'end'].includes(k))) ctx.err('BAD_TYPE', 'window', 'must be {start, end}');
    else { checkString(ctx, 'window.start', b.window.start); checkString(ctx, 'window.end', b.window.end); }
  }
  if (b.eventDiscriminator !== undefined && b.eventDiscriminator !== null) checkString(ctx, 'eventDiscriminator', b.eventDiscriminator);
  if (provOk && stateOk && compOk) {
    if (b.pathState === 'runtime-supported' && b.provenance !== 'runtime-observation') {
      ctx.err('RULE_VIOLATION', 'pathState', `'runtime-supported' requires provenance 'runtime-observation'`);
    }
    if (b.pathState === 'blocked' && b.provenance === 'runtime-observation' && b.completeness !== 'complete') {
      ctx.err('RULE_VIOLATION', 'pathState', `absence in a ${b.completeness} observation cannot establish 'blocked'`);
    }
    if (b.provenance === 'runtime-observation' && !(isPlainObject(b.window) && b.window.start && b.window.end)) {
      ctx.err('RULE_VIOLATION', 'window', `a runtime observation binding must state its observation window`);
    }
  }
  checkId(ctx, b, observationBindingId(b));
  return result(ctx);
}

// ---------------------------------------------------------------- capability decision

export const CAPABILITY_DECISION_SCHEMA = 'agentic-security/capability-decision';
export const CAPABILITY_KINDS = Object.freeze(['filesystem-read', 'filesystem-write', 'command', 'network', 'tool', 'delegation']);
export const CAPABILITY_DECISIONS = Object.freeze(['allow', 'deny', 'blocked', 'unsupported']);
export const CAPABILITY_MEDIATIONS = Object.freeze(['runner', 'proxy', 'in-process-policy', 'hook-advisory', 'none']);

const CD_ALLOWED = [
  'schema', 'schemaVersion', 'id', 'taskId', 'capability', 'subject', 'decision', 'mediation', 'enforced', 'backend',
  'probeDigest', 'reason', 'migration', 'createdAt',
];
const CD_REQUIRED = ['schema', 'schemaVersion', 'id', 'taskId', 'capability', 'subject', 'decision', 'mediation', 'enforced', 'backend', 'reason'];

export const CAPABILITY_DECISION_ID_FIELDS = Object.freeze([
  'taskId', 'capability', 'subject', 'decision', 'mediation', 'enforced', 'backend', 'probeDigest', 'reason',
]);

export function capabilityDecisionId(d) {
  return semanticId(ID_PREFIXES.capabilityDecision, d, CAPABILITY_DECISION_ID_FIELDS);
}

export function validateCapabilityDecision(d) {
  const g = guardObject(d);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, d, CAPABILITY_DECISION_SCHEMA)) return result(ctx);
  checkFields(ctx, d, CD_ALLOWED, CD_REQUIRED);
  checkString(ctx, 'taskId', d.taskId);
  checkEnum(ctx, 'capability', d.capability, CAPABILITY_KINDS);
  checkString(ctx, 'subject', d.subject);
  const decOk = checkEnum(ctx, 'decision', d.decision, CAPABILITY_DECISIONS);
  const medOk = checkEnum(ctx, 'mediation', d.mediation, CAPABILITY_MEDIATIONS);
  if (typeof d.enforced !== 'boolean') ctx.err('BAD_TYPE', 'enforced', 'must be a boolean');
  if (d.backend !== null && d.backend !== undefined) checkString(ctx, 'backend', d.backend);
  if (d.probeDigest !== undefined && d.probeDigest !== null) checkDigest(ctx, 'probeDigest', d.probeDigest);
  checkString(ctx, 'reason', d.reason);
  if (decOk && medOk && d.enforced === true) {
    // A hook response or an in-process check explains a decision; it does not
    // prove isolation. Only the runner or a proxy, with a named backend and an
    // active probe, may claim enforcement.
    if (!['runner', 'proxy'].includes(d.mediation)) ctx.err('RULE_VIOLATION', 'enforced', `mediation '${d.mediation}' cannot claim enforcement`);
    if (!(typeof d.backend === 'string' && d.backend)) ctx.err('RULE_VIOLATION', 'backend', 'an enforced decision must name its backend');
    if (!isDigest(d.probeDigest)) ctx.err('RULE_VIOLATION', 'probeDigest', 'an enforced decision must carry the digest of its active probe evidence');
    if (!['allow', 'deny'].includes(d.decision)) ctx.err('RULE_VIOLATION', 'enforced', `decision '${d.decision}' cannot be enforced`);
  }
  checkId(ctx, d, capabilityDecisionId(d));
  return result(ctx);
}

// ---------------------------------------------------------------- routing label

export const ROUTING_LABEL_SCHEMA = 'agentic-security/routing-label';
export const ROUTING_TASK_KINDS = Object.freeze(['discovery', 'triage', 'verification-planning', 'repair']);
export const ROUTING_OUTCOMES = Object.freeze(['correct', 'incorrect', 'unknown', 'delayed']);
export const ROUTING_LABEL_SOURCES = Object.freeze(['adjudication', 'trusted-execution', 'none']);

const RL_ALLOWED = [
  'schema', 'schemaVersion', 'id', 'taskId', 'taskKind', 'stratum', 'model', 'outcome', 'labelSource', 'verificationRecordId', 'migration', 'createdAt',
];
const RL_REQUIRED = ['schema', 'schemaVersion', 'id', 'taskId', 'taskKind', 'stratum', 'model', 'outcome', 'labelSource'];
export const ROUTING_LABEL_ID_FIELDS = Object.freeze(['taskId', 'taskKind', 'stratum', 'model', 'outcome', 'labelSource', 'verificationRecordId']);

export function routingLabelId(l) {
  return semanticId(ID_PREFIXES.routingLabel, l, ROUTING_LABEL_ID_FIELDS);
}

export function validateRoutingLabel(l) {
  const g = guardObject(l);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, l, ROUTING_LABEL_SCHEMA)) return result(ctx);
  checkFields(ctx, l, RL_ALLOWED, RL_REQUIRED);
  checkString(ctx, 'taskId', l.taskId);
  checkEnum(ctx, 'taskKind', l.taskKind, ROUTING_TASK_KINDS);
  checkString(ctx, 'stratum', l.stratum);
  checkString(ctx, 'model', l.model);
  const outOk = checkEnum(ctx, 'outcome', l.outcome, ROUTING_OUTCOMES);
  const srcOk = checkEnum(ctx, 'labelSource', l.labelSource, ROUTING_LABEL_SOURCES);
  if (l.verificationRecordId !== undefined && l.verificationRecordId !== null) {
    if (typeof l.verificationRecordId !== 'string' || !l.verificationRecordId.startsWith('vrec:')) ctx.err('BAD_ID', 'verificationRecordId', `must be a verification record id ('vrec:...')`);
  }
  if (outOk && srcOk) {
    // Delayed and unknown outcomes are retained, but they cannot carry a source
    // that implies they were adjudicated; a decided label must name its source.
    if (['correct', 'incorrect'].includes(l.outcome) && l.labelSource === 'none') {
      ctx.err('RULE_VIOLATION', 'labelSource', `a '${l.outcome}' label needs an adjudication or trusted-execution source`);
    }
    if (['unknown', 'delayed'].includes(l.outcome) && l.labelSource !== 'none') {
      ctx.err('RULE_VIOLATION', 'labelSource', `an '${l.outcome}' label has no decided source`);
    }
  }
  checkId(ctx, l, routingLabelId(l));
  return result(ctx);
}

// ---------------------------------------------------------------- release evidence

export const RELEASE_EVIDENCE_SCHEMA = 'agentic-security/release-evidence';
export const CLAIM_STATUSES = Object.freeze(['verified', 'failed', 'skipped', 'incomplete', 'unverified']);

const RE_ALLOWED = ['schema', 'schemaVersion', 'id', 'subject', 'claims', 'complete', 'migration', 'createdAt'];
const RE_REQUIRED = ['schema', 'schemaVersion', 'id', 'subject', 'claims', 'complete'];
export const RELEASE_EVIDENCE_ID_FIELDS = Object.freeze(['subject', 'claims', 'complete']);

export function releaseEvidenceId(r) {
  return semanticId(ID_PREFIXES.releaseEvidence, r, RELEASE_EVIDENCE_ID_FIELDS);
}

/** `complete` as the claims support it: every claim verified, no gaps, exact commit and bundle bound. */
export function deriveReleaseComplete(r) {
  if (!isPlainObject(r?.subject) || !r.subject.commit || !r.subject.bundleDigest) return false;
  if (!Array.isArray(r.claims) || r.claims.length === 0) return false;
  return r.claims.every(c => isPlainObject(c) && c.status === 'verified' && (!Array.isArray(c.gaps) || c.gaps.length === 0));
}

export function validateReleaseEvidence(r) {
  const g = guardObject(r);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, r, RELEASE_EVIDENCE_SCHEMA)) return result(ctx);
  checkFields(ctx, r, RE_ALLOWED, RE_REQUIRED);
  if (!isPlainObject(r.subject)) ctx.err('BAD_TYPE', 'subject', 'must be an object');
  else {
    for (const k of Object.keys(r.subject)) if (!['commit', 'bundleDigest', 'policyDigest'].includes(k)) ctx.err('UNKNOWN_FIELD', `subject.${k}`, 'not part of subject');
    checkCommit(ctx, 'subject.commit', r.subject.commit ?? null);
    checkDigest(ctx, 'subject.bundleDigest', r.subject.bundleDigest ?? null, { nullable: true });
    if (r.subject.policyDigest !== undefined && r.subject.policyDigest !== null) checkDigest(ctx, 'subject.policyDigest', r.subject.policyDigest);
  }
  if (typeof r.complete !== 'boolean') ctx.err('BAD_TYPE', 'complete', 'must be a boolean');
  if (!Array.isArray(r.claims)) ctx.err('BAD_TYPE', 'claims', 'must be an array');
  else {
    const seen = new Set();
    r.claims.forEach((c, i) => {
      const p = `claims[${i}]`;
      if (!isPlainObject(c)) { ctx.err('BAD_TYPE', p, 'claim must be an object'); return; }
      for (const k of Object.keys(c)) if (!['id', 'statement', 'status', 'evidenceRefs', 'gaps'].includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, 'not part of a claim');
      if (checkString(ctx, `${p}.id`, c.id)) {
        if (seen.has(c.id)) ctx.err('DUPLICATE_ID', `${p}.id`, `duplicate claim id '${c.id}'`);
        seen.add(c.id);
      }
      checkString(ctx, `${p}.statement`, c.statement);
      const stOk = checkEnum(ctx, `${p}.status`, c.status, CLAIM_STATUSES);
      if (!Array.isArray(c.evidenceRefs)) ctx.err('BAD_TYPE', `${p}.evidenceRefs`, 'must be an array');
      else c.evidenceRefs.forEach((ref, j) => {
        if (typeof ref !== 'string' || !(ref.startsWith('vrec:') || isDigest(ref))) ctx.err('BAD_ID', `${p}.evidenceRefs[${j}]`, `must be a verification record id or a sha256 digest`);
      });
      if (!Array.isArray(c.gaps) || !c.gaps.every(x => typeof x === 'string' && x.trim())) ctx.err('BAD_TYPE', `${p}.gaps`, 'must be an array of non-empty strings');
      if (stOk && Array.isArray(c.evidenceRefs) && Array.isArray(c.gaps)) {
        if (c.status === 'verified' && c.evidenceRefs.length === 0) ctx.err('RULE_VIOLATION', `${p}.evidenceRefs`, `a 'verified' claim must cite evidence`);
        if (c.status === 'verified' && c.gaps.length > 0) ctx.err('RULE_VIOLATION', `${p}.gaps`, `a 'verified' claim cannot list gaps`);
        if (c.status !== 'verified' && c.gaps.length === 0) ctx.err('RULE_VIOLATION', `${p}.gaps`, `a '${c.status}' claim must say what is missing`);
      }
    });
    if (typeof r.complete === 'boolean' && r.complete !== deriveReleaseComplete(r)) {
      ctx.err('RULE_VIOLATION', 'complete', `claimed complete=${r.complete} but the claims and subject support complete=${deriveReleaseComplete(r)}`);
    }
  }
  checkId(ctx, r, releaseEvidenceId(r));
  return result(ctx);
}

// ---------------------------------------------------------------- record set

const VALIDATORS = Object.freeze({
  verificationRecords: validateVerificationRecord,
  observationBindings: validateObservationBinding,
  capabilityDecisions: validateCapabilityDecision,
  routingLabels: validateRoutingLabel,
  releaseEvidence: validateReleaseEvidence,
});

/**
 * Validate a whole set: every record individually, then duplicate ids within and
 * across types, dangling references, and the cross-record honesty rules.
 * Input is `{ verificationRecords, observationBindings, capabilityDecisions, routingLabels, releaseEvidence }`,
 * each an optional array.
 */
export function validateRecordSet(set) {
  const ctx = makeCtx();
  if (!isPlainObject(set)) { ctx.err('NOT_AN_OBJECT', '', 'record set must be an object'); return result(ctx); }
  for (const k of Object.keys(set)) if (!VALIDATORS[k]) ctx.err('UNKNOWN_FIELD', k, `'${k}' is not a record collection`);
  const allIds = new Map();
  for (const [name, validate] of Object.entries(VALIDATORS)) {
    const list = set[name];
    if (list === undefined) continue;
    if (!Array.isArray(list)) { ctx.err('BAD_TYPE', name, 'must be an array'); continue; }
    list.forEach((rec, i) => {
      const r = validate(rec);
      for (const e of r.errors) ctx.err(e.code, `${name}[${i}]${e.path ? '.' + e.path : ''}`, e.message);
      if (isPlainObject(rec) && typeof rec.id === 'string') {
        if (allIds.has(rec.id)) ctx.err('DUPLICATE_ID', `${name}[${i}].id`, `id '${rec.id}' is already used by ${allIds.get(rec.id)}`);
        else allIds.set(rec.id, `${name}[${i}]`);
      }
    });
  }

  const vrecs = new Map((Array.isArray(set.verificationRecords) ? set.verificationRecords : []).filter(isPlainObject).map(r => [r.id, r]));

  // two records with the same claim key but different outcomes are a conflict, not two facts
  const byClaim = new Map();
  for (const [id, r] of vrecs) {
    const key = verificationClaimKey(r);
    const prior = byClaim.get(key);
    if (prior && prior.outcome !== r.outcome) ctx.err('RULE_VIOLATION', `verificationRecords`, `records '${prior.id}' and '${id}' make the same claim with different outcomes ('${prior.outcome}' vs '${r.outcome}')`);
    byClaim.set(key, r);
  }

  for (const [id, r] of vrecs) {
    const rid = r.repair?.replayRecordId;
    if (rid && !vrecs.has(rid)) ctx.err('DANGLING_REF', `verificationRecords.${id}.repair.replayRecordId`, `replay record '${rid}' is not in the set`);
  }
  (Array.isArray(set.observationBindings) ? set.observationBindings : []).filter(isPlainObject).forEach((b, i) => {
    // hypothesis ids are findings' stable ids, not record ids; a binding is dangling only against explicit vrec refs
    if (typeof b.hypothesisId === 'string' && b.hypothesisId.startsWith('vrec:') && !vrecs.has(b.hypothesisId)) {
      ctx.err('DANGLING_REF', `observationBindings[${i}].hypothesisId`, `'${b.hypothesisId}' is not in the set`);
    }
  });
  (Array.isArray(set.routingLabels) ? set.routingLabels : []).filter(isPlainObject).forEach((l, i) => {
    if (l.verificationRecordId && !vrecs.has(l.verificationRecordId)) ctx.err('DANGLING_REF', `routingLabels[${i}].verificationRecordId`, `'${l.verificationRecordId}' is not in the set`);
  });
  (Array.isArray(set.releaseEvidence) ? set.releaseEvidence : []).filter(isPlainObject).forEach((rev, ri) => {
    (Array.isArray(rev.claims) ? rev.claims : []).filter(isPlainObject).forEach((c, ci) => {
      for (const ref of Array.isArray(c.evidenceRefs) ? c.evidenceRefs : []) {
        if (typeof ref === 'string' && ref.startsWith('vrec:')) {
          const v = vrecs.get(ref);
          if (!v) ctx.err('DANGLING_REF', `releaseEvidence[${ri}].claims[${ci}].evidenceRefs`, `'${ref}' is not in the set`);
          else if (c.status === 'verified' && !['confirmed', 'refuted'].includes(v.outcome)) {
            ctx.err('RULE_VIOLATION', `releaseEvidence[${ri}].claims[${ci}]`, `claim is 'verified' but cites '${ref}' whose outcome is '${v.outcome}'`);
          }
        }
      }
    });
  });
  return result(ctx);
}
