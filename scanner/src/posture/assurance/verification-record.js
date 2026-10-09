// The one verification record (CORE-002; X-201 builds every surface on it).
//
// Shape: hypothesis id, commit, detector origin, oracle, attempt, outcome,
// reason, evidence items + references, applicable scope, and a SEPARATE repair
// status.
//
// Structural honesty rules, enforced by the validator (not by convention):
//   1. The six outcomes are distinct: not-run, unsupported, inconclusive, error,
//      refuted, confirmed. Nothing here collapses them to a boolean.
//   2. Evidence kinds are distinct: observation, inference, independent
//      adjudication, trusted runtime proof. Each kind constrains who may have
//      produced it: a model can only ever produce an inference; trusted runtime
//      proof only comes from a trusted runner; an adjudication only from a human
//      or an independent verifier.
//   3. `confirmed` needs referenced evidence of runtime proof or independent
//      adjudication, so a model-generated verdict alone cannot yield it, and the
//      record carries a `confirmationLevel` that must equal the level derived from
//      its evidence ('runtime-confirmed' needs trusted-runtime-proof AND a runtime
//      oracle). A forged level fails the derivation check.
//   4. `refuted` needs an applicable (non-model) oracle, valid preconditions and
//      proving evidence: a missing taint path is not refutation of an
//      authorization or workflow claim.
//   5. Repair status is a different axis from the outcome. `replay-verified`
//      needs the id of the patched-negative verification record.

import {
  SCHEMA_VERSION, makeCtx, result, guardObject, checkHeader, checkFields, checkEnum, checkDigest,
  checkCommit, checkString, checkId, isPlainObject,
} from './schema-kit.js';
import { semanticId, ID_PREFIXES } from './identity.js';

export const VERIFICATION_SCHEMA = 'agentic-security/verification-record';

export const VERIFICATION_OUTCOMES = Object.freeze(['not-run', 'unsupported', 'inconclusive', 'error', 'refuted', 'confirmed']);
export const REPAIR_STATUSES = Object.freeze(['none', 'proposed', 'applied', 'replay-verified', 'rolled-back']);
export const EVIDENCE_KINDS = Object.freeze(['observation', 'inference', 'independent-adjudication', 'trusted-runtime-proof']);
export const EVIDENCE_PRODUCERS = Object.freeze(['model', 'tool', 'human', 'independent-verifier', 'trusted-runner']);
export const ORACLE_KINDS = Object.freeze(['runtime-replay', 'differential', 'static-proof', 'model', 'human', 'none']);
export const CONFIRMATION_LEVELS = Object.freeze(['runtime-confirmed', 'adjudicated', 'none']);

const RUNTIME_ORACLES = ['runtime-replay', 'differential'];
const APPLICABLE_FOR_REFUTATION = ['runtime-replay', 'differential', 'static-proof', 'human'];
const NO_EXECUTION_OUTCOMES = ['not-run', 'unsupported'];

const ALLOWED = [
  'schema', 'schemaVersion', 'id', 'hypothesisId', 'commit', 'detectorOrigin', 'oracle', 'attempt', 'outcome', 'reason',
  'evidence', 'evidenceRefs', 'scope', 'preconditions', 'confirmationLevel', 'repair', 'migration', 'createdAt',
];
const REQUIRED = [
  'schema', 'schemaVersion', 'id', 'hypothesisId', 'commit', 'detectorOrigin', 'oracle', 'attempt', 'outcome', 'reason',
  'evidence', 'evidenceRefs', 'scope', 'preconditions', 'confirmationLevel', 'repair',
];

// Fields that define WHAT was claimed and how it was checked. `createdAt` (a
// clock) and `migration` (how the record was represented) are deliberately not
// here, so neither can move an id.
export const VERIFICATION_ID_FIELDS = Object.freeze([
  'hypothesisId', 'commit', 'detectorOrigin', 'oracle', 'attempt', 'outcome', 'reason', 'evidence', 'evidenceRefs',
  'scope', 'preconditions', 'confirmationLevel', 'repair',
]);

export function verificationRecordId(record) {
  return semanticId(ID_PREFIXES.verification, record, VERIFICATION_ID_FIELDS);
}

/** The identity of the CLAIM (which hypothesis, at which commit, by which oracle, on which attempt), excluding its result. */
export function verificationClaimKey(record) {
  return semanticId('vclaim', record, ['hypothesisId', 'commit', 'oracle', 'attempt']);
}

function referencedEvidence(record) {
  const refs = new Set(Array.isArray(record.evidenceRefs) ? record.evidenceRefs : []);
  return (Array.isArray(record.evidence) ? record.evidence : []).filter(e => isPlainObject(e) && refs.has(e.id));
}

/** The confirmation level the evidence actually supports. Never read from the record's own claim. */
export function deriveConfirmationLevel(record) {
  if (!record || record.outcome !== 'confirmed') return 'none';
  const ev = referencedEvidence(record);
  const runtime = ev.some(e => e.kind === 'trusted-runtime-proof' && e.producer === 'trusted-runner');
  if (runtime && RUNTIME_ORACLES.includes(record.oracle?.kind)) return 'runtime-confirmed';
  const adjudicated = ev.some(e => e.kind === 'independent-adjudication' && ['human', 'independent-verifier'].includes(e.producer));
  return adjudicated ? 'adjudicated' : 'none';
}

function validateEvidenceItem(ctx, e, i) {
  const p = `evidence[${i}]`;
  if (!isPlainObject(e)) { ctx.err('BAD_TYPE', p, 'evidence item must be an object'); return; }
  for (const k of Object.keys(e)) {
    if (!['id', 'kind', 'producer', 'digest', 'source'].includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, `field '${k}' is not part of an evidence item`);
  }
  checkString(ctx, `${p}.id`, e.id);
  const kindOk = checkEnum(ctx, `${p}.kind`, e.kind, EVIDENCE_KINDS);
  const prodOk = checkEnum(ctx, `${p}.producer`, e.producer, EVIDENCE_PRODUCERS);
  checkDigest(ctx, `${p}.digest`, e.digest);
  if (e.source !== undefined && e.source !== null) checkString(ctx, `${p}.source`, e.source);
  if (!kindOk || !prodOk) return;
  if (e.producer === 'model' && e.kind !== 'inference') {
    ctx.err('RULE_VIOLATION', p, `a model-produced item can only be 'inference', not '${e.kind}'`);
  }
  if (e.kind === 'trusted-runtime-proof' && e.producer !== 'trusted-runner') {
    ctx.err('RULE_VIOLATION', p, `'trusted-runtime-proof' can only be produced by a 'trusted-runner', not '${e.producer}'`);
  }
  if (e.kind === 'independent-adjudication' && !['human', 'independent-verifier'].includes(e.producer)) {
    ctx.err('RULE_VIOLATION', p, `'independent-adjudication' can only be produced by a 'human' or 'independent-verifier', not '${e.producer}'`);
  }
  if (e.producer === 'trusted-runner' && !['trusted-runtime-proof', 'observation'].includes(e.kind)) {
    ctx.err('RULE_VIOLATION', p, `a 'trusted-runner' produces 'trusted-runtime-proof' or 'observation', not '${e.kind}'`);
  }
}

export function validateVerificationRecord(record) {
  const g = guardObject(record);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, record, VERIFICATION_SCHEMA)) return result(ctx);
  checkFields(ctx, record, ALLOWED, REQUIRED);

  checkString(ctx, 'hypothesisId', record.hypothesisId);
  checkCommit(ctx, 'commit', record.commit);

  const origin = record.detectorOrigin;
  if (!isPlainObject(origin)) ctx.err('BAD_TYPE', 'detectorOrigin', 'must be an object with a detector name');
  else {
    for (const k of Object.keys(origin)) if (!['detector', 'family', 'parser'].includes(k)) ctx.err('UNKNOWN_FIELD', `detectorOrigin.${k}`, 'not part of detectorOrigin');
    checkString(ctx, 'detectorOrigin.detector', origin.detector);
  }

  const oracle = record.oracle;
  let oracleKind = null;
  if (oracle === null) oracleKind = 'none';
  else if (!isPlainObject(oracle)) ctx.err('BAD_TYPE', 'oracle', 'must be an object or null');
  else {
    for (const k of Object.keys(oracle)) if (!['id', 'kind', 'version'].includes(k)) ctx.err('UNKNOWN_FIELD', `oracle.${k}`, 'not part of oracle');
    checkString(ctx, 'oracle.id', oracle.id);
    if (checkEnum(ctx, 'oracle.kind', oracle.kind, ORACLE_KINDS)) oracleKind = oracle.kind;
  }

  if (!Number.isInteger(record.attempt) || record.attempt < 0) ctx.err('BAD_TYPE', 'attempt', 'must be a non-negative integer');
  const outcomeOk = checkEnum(ctx, 'outcome', record.outcome, VERIFICATION_OUTCOMES);
  checkString(ctx, 'reason', record.reason);

  // evidence items
  const ids = new Set();
  if (!Array.isArray(record.evidence)) ctx.err('BAD_TYPE', 'evidence', 'must be an array');
  else {
    record.evidence.forEach((e, i) => {
      validateEvidenceItem(ctx, e, i);
      if (isPlainObject(e) && typeof e.id === 'string') {
        if (ids.has(e.id)) ctx.err('DUPLICATE_ID', `evidence[${i}].id`, `duplicate evidence id '${e.id}'`);
        ids.add(e.id);
      }
    });
  }
  if (!Array.isArray(record.evidenceRefs)) ctx.err('BAD_TYPE', 'evidenceRefs', 'must be an array of evidence ids');
  else {
    const seen = new Set();
    record.evidenceRefs.forEach((r, i) => {
      if (!ids.has(r)) ctx.err('DANGLING_REF', `evidenceRefs[${i}]`, `evidence reference '${r}' does not resolve to an evidence item in this record`);
      if (seen.has(r)) ctx.err('DUPLICATE_ID', `evidenceRefs[${i}]`, `evidence reference '${r}' listed twice`);
      seen.add(r);
    });
  }

  // scope
  const scope = record.scope;
  if (!isPlainObject(scope)) ctx.err('BAD_TYPE', 'scope', 'must be an object');
  else {
    for (const k of Object.keys(scope)) if (!['description', 'platform', 'backend'].includes(k)) ctx.err('UNKNOWN_FIELD', `scope.${k}`, 'not part of scope');
    checkString(ctx, 'scope.description', scope.description);
    checkString(ctx, 'scope.platform', scope.platform);
    if (scope.backend !== undefined && scope.backend !== null) checkString(ctx, 'scope.backend', scope.backend);
  }

  // preconditions
  const pre = record.preconditions;
  if (!isPlainObject(pre) || typeof pre.valid !== 'boolean') ctx.err('BAD_TYPE', 'preconditions', 'must be an object with a boolean `valid`');

  // repair: a separate axis
  const repair = record.repair;
  if (!isPlainObject(repair)) ctx.err('BAD_TYPE', 'repair', 'must be an object');
  else {
    for (const k of Object.keys(repair)) if (!['status', 'patchDigest', 'replayRecordId'].includes(k)) ctx.err('UNKNOWN_FIELD', `repair.${k}`, 'not part of repair');
    if (checkEnum(ctx, 'repair.status', repair.status, REPAIR_STATUSES)) {
      if (['applied', 'replay-verified', 'rolled-back'].includes(repair.status)) {
        if (repair.patchDigest === undefined || repair.patchDigest === null) ctx.err('RULE_VIOLATION', 'repair.patchDigest', `repair status '${repair.status}' requires a patchDigest`);
      }
      if (repair.patchDigest !== undefined && repair.patchDigest !== null) checkDigest(ctx, 'repair.patchDigest', repair.patchDigest);
      if (repair.status === 'replay-verified' && !(typeof repair.replayRecordId === 'string' && repair.replayRecordId.startsWith('vrec:'))) {
        ctx.err('RULE_VIOLATION', 'repair.replayRecordId', `repair status 'replay-verified' requires the id of the patched-negative verification record`);
      }
    }
  }

  // confirmation level must be what the evidence supports
  const levelOk = checkEnum(ctx, 'confirmationLevel', record.confirmationLevel, CONFIRMATION_LEVELS);
  if (levelOk) {
    const derived = deriveConfirmationLevel(record);
    if (record.confirmationLevel !== derived) {
      ctx.err('RULE_VIOLATION', 'confirmationLevel', `claimed '${record.confirmationLevel}' but the referenced evidence supports '${derived}'`);
    }
  }

  // outcome rules
  if (outcomeOk) {
    const refEv = referencedEvidence(record);
    const hasProof = refEv.some(e => ['trusted-runtime-proof', 'independent-adjudication'].includes(e.kind));
    const attempt = record.attempt;
    if (!NO_EXECUTION_OUTCOMES.includes(record.outcome) && Number.isInteger(attempt) && attempt < 1) {
      ctx.err('RULE_VIOLATION', 'attempt', `outcome '${record.outcome}' requires attempt >= 1`);
    }
    if (NO_EXECUTION_OUTCOMES.includes(record.outcome)) {
      if (Number.isInteger(attempt) && attempt !== 0) ctx.err('RULE_VIOLATION', 'attempt', `outcome '${record.outcome}' means nothing ran, so attempt must be 0`);
      if (refEv.some(e => e.kind === 'trusted-runtime-proof')) ctx.err('RULE_VIOLATION', 'evidence', `outcome '${record.outcome}' cannot cite runtime proof: nothing executed`);
    }
    if (['confirmed', 'refuted'].includes(record.outcome)) {
      if (record.commit === null) ctx.err('RULE_VIOLATION', 'commit', `outcome '${record.outcome}' must be bound to an exact commit`);
      if (oracleKind === 'none') ctx.err('RULE_VIOLATION', 'oracle', `outcome '${record.outcome}' requires an oracle`);
      if (oracleKind === 'model') ctx.err('RULE_VIOLATION', 'oracle', `a model oracle can never yield '${record.outcome}'`);
      if (!hasProof) ctx.err('RULE_VIOLATION', 'evidenceRefs', `outcome '${record.outcome}' requires referenced trusted-runtime-proof or independent-adjudication evidence`);
    }
    if (record.outcome === 'confirmed' && record.confirmationLevel === 'none') {
      ctx.err('RULE_VIOLATION', 'confirmationLevel', `a 'confirmed' record must carry a confirmation level above 'none'`);
    }
    if (record.outcome === 'refuted') {
      if (oracleKind && !APPLICABLE_FOR_REFUTATION.includes(oracleKind)) ctx.err('RULE_VIOLATION', 'oracle', `oracle kind '${oracleKind}' is not applicable for refutation`);
      if (!(isPlainObject(pre) && pre.valid === true)) ctx.err('RULE_VIOLATION', 'preconditions', `'refuted' requires valid preconditions: a check that could not run is not a refutation`);
    }
  }

  checkId(ctx, record, verificationRecordId(record));
  return result(ctx);
}

/** Build a complete, valid-by-construction record from the semantic fields; derives the level and the id. */
export function buildVerificationRecord(fields) {
  const rec = {
    schema: VERIFICATION_SCHEMA,
    schemaVersion: SCHEMA_VERSION,
    hypothesisId: fields.hypothesisId,
    commit: fields.commit ?? null,
    detectorOrigin: fields.detectorOrigin,
    oracle: fields.oracle ?? null,
    attempt: fields.attempt ?? 0,
    outcome: fields.outcome,
    reason: fields.reason,
    evidence: fields.evidence ?? [],
    evidenceRefs: fields.evidenceRefs ?? (fields.evidence ?? []).map(e => e.id),
    scope: fields.scope,
    preconditions: fields.preconditions ?? { valid: false },
    repair: fields.repair ?? { status: 'none' },
  };
  rec.confirmationLevel = deriveConfirmationLevel(rec);
  if (fields.migration) rec.migration = fields.migration;
  if (fields.createdAt) rec.createdAt = fields.createdAt;
  rec.id = verificationRecordId(rec);
  return rec;
}
