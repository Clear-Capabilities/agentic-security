// Separate records for patch application, rejection and rollback (X-204.AC03).
//
// The CORE-002 verification record carries ONE repair status (`none`, `proposed`, `applied`, `replay-verified`,
// `rolled-back`). That field answers "where is this repair now"; it cannot also be the history, and it has no value for a
// rejection. So the history is kept here as an append-only ledger of small records, one per event, each with its own id and
// a link to the record before it. A rollback is therefore a NEW record after an application, not an edit that erases it, and
// a rejection is a record of its own, not a status that vanishes when the patch is dropped.
//
// Rules the ledger enforces, each with a test (the state is per hypothesis and exact diff):
//   proposed   first event for a diff.
//   rejected   from proposed or promoted. Needs a reason; carries the incomplete step when verification caused it. Terminal.
//   promoted   from proposed, and ONLY through `recordPromotion`, which accepts nothing but a result `promotePatch` itself
//              returned `ok: true` for. The generic append refuses this kind, so a caller cannot write a promotion by hand.
//   applied    from promoted only: nothing is applied that was not promoted for that exact diff.
//   rolled-back from applied or promoted (a partial application that was undone). Terminal.
// `verificationRepairFor` maps the ledger onto the CORE-002 repair field; a rejection has no value there, so the record keeps
// `proposed` and the ledger holds the rejection (the enum is a foundation contract this change does not widen).
import { semanticId } from '../assurance/identity.js';
import { buildVerificationRecord, validateVerificationRecord } from '../assurance/verification-record.js';
import { isCommit, isDigest, isPlainObject } from '../assurance/schema-kit.js';
import { isIssuedPromotion } from './patch-promotion.js';

const REPAIR_RECORD_SCHEMA = 'agentic-security/repair-record';
const REPAIR_RECORD_VERSION = '1.0.0';
const REPAIR_KINDS = Object.freeze(['proposed', 'rejected', 'promoted', 'applied', 'rolled-back']);

const ID_FIELDS = ['kind', 'hypothesisId', 'revision', 'diffDigest', 'reason', 'step', 'receiptDigests', 'verificationRecordId', 'previous'];
const TRANSITIONS = Object.freeze({
  proposed: [null],
  rejected: ['proposed', 'promoted'],
  promoted: ['proposed'],
  applied: ['promoted'],
  'rolled-back': ['applied', 'promoted'],
});

function build(fields) {
  const rec = {
    schema: REPAIR_RECORD_SCHEMA, schemaVersion: REPAIR_RECORD_VERSION,
    kind: fields.kind, hypothesisId: fields.hypothesisId, revision: fields.revision ?? null, diffDigest: fields.diffDigest,
    reason: fields.reason ?? null, step: fields.step ?? null, receiptDigests: fields.receiptDigests ?? null,
    verificationRecordId: fields.verificationRecordId ?? null, previous: fields.previous ?? null,
  };
  rec.id = semanticId('rrec', rec, ID_FIELDS);
  return Object.freeze(rec);
}

/** The latest event kind recorded for a hypothesis and exact diff, or null. */
function stateOf(records, hypothesisId, diffDigest) {
  for (let i = records.length - 1; i >= 0; i--) {
    if (records[i].hypothesisId === hypothesisId && records[i].diffDigest === diffDigest) return records[i];
  }
  return null;
}

function check(records, fields) {
  const errs = [];
  if (!REPAIR_KINDS.includes(fields.kind)) errs.push(`unknown repair kind '${fields.kind}'`);
  if (typeof fields.hypothesisId !== 'string' || !fields.hypothesisId) errs.push('hypothesisId is required');
  if (!isDigest(fields.diffDigest)) errs.push('diffDigest must be sha256:<64 hex>');
  if (fields.revision !== undefined && fields.revision !== null && !isCommit(fields.revision)) errs.push('revision must be an exact commit or null');
  if (['rejected', 'rolled-back'].includes(fields.kind) && !(typeof fields.reason === 'string' && fields.reason.trim())) errs.push(`a '${fields.kind}' record needs a reason`);
  if (errs.length) return errs;
  const last = stateOf(records, fields.hypothesisId, fields.diffDigest);
  const from = last ? last.kind : null;
  if (!TRANSITIONS[fields.kind].includes(from)) errs.push(`'${fields.kind}' cannot follow ${from ? `'${from}'` : 'no earlier record'} for this diff`);
  return errs;
}

/**
 * Append one event. Returns a NEW list (the input is never changed) and the record. `promoted` is refused here: use
 * `recordPromotion`. Never throws.
 * @returns {{ ok: boolean, records: object[], record: object|null, errors: string[] }}
 */
export function appendRepairRecord(records, fields) {
  const list = Array.isArray(records) ? records : [];
  if (!isPlainObject(fields)) return { ok: false, records: list, record: null, errors: ['fields must be an object'] };
  if (fields.kind === 'promoted') return { ok: false, records: list, record: null, errors: ['a promotion is recorded only through recordPromotion, from a promotePatch result'] };
  const errors = check(list, fields);
  if (errors.length) return { ok: false, records: list, record: null, errors };
  const last = stateOf(list, fields.hypothesisId, fields.diffDigest);
  const record = build({ ...fields, previous: last ? last.id : null });
  return { ok: true, records: [...list, record], record, errors: [] };
}

/** Record a promotion. Accepts only a result `promotePatch` returned with `ok: true`. */
export function recordPromotion(records, promotion, { verificationRecordId = null } = {}) {
  const list = Array.isArray(records) ? records : [];
  if (!isIssuedPromotion(promotion)) return { ok: false, records: list, record: null, errors: ['not a promotion issued by promotePatch'] };
  const fields = {
    kind: 'promoted', hypothesisId: promotion.hypothesisId, revision: promotion.revision, diffDigest: promotion.diffDigest,
    reason: 'independent verifier receipts match the exact proposed diff and revision', receiptDigests: promotion.receiptDigests, verificationRecordId,
  };
  const errors = check(list, fields);
  if (errors.length) return { ok: false, records: list, record: null, errors };
  const last = stateOf(list, fields.hypothesisId, fields.diffDigest);
  const record = build({ ...fields, previous: last ? last.id : null });
  return { ok: true, records: [...list, record], record, errors: [] };
}

/** The current CORE-002 `repair` object for a diff, derived from the ledger. */
export function verificationRepairFor(records, hypothesisId, diffDigest, patchedRecordId = null) {
  const last = stateOf(Array.isArray(records) ? records : [], hypothesisId, diffDigest);
  if (!last) return { status: 'none' };
  if (last.kind === 'applied') return { status: 'applied', patchDigest: diffDigest };
  if (last.kind === 'rolled-back') return { status: 'rolled-back', patchDigest: diffDigest };
  if (last.kind === 'promoted' && typeof patchedRecordId === 'string' && patchedRecordId.startsWith('vrec:')) {
    return { status: 'replay-verified', patchDigest: diffDigest, replayRecordId: patchedRecordId };
  }
  return { status: 'proposed', patchDigest: diffDigest };
}

/**
 * A copy of a verification record with its repair status replaced, rebuilt and re-validated (the id is recomputed, the
 * confirmation level stays what its evidence supports). Returns null if the result is not a valid record.
 */
export function withRepairStatus(record, repair) {
  if (!isPlainObject(record)) return null;
  const rebuilt = buildVerificationRecord({
    hypothesisId: record.hypothesisId, commit: record.commit, detectorOrigin: record.detectorOrigin, oracle: record.oracle,
    attempt: record.attempt, outcome: record.outcome, reason: record.reason, evidence: record.evidence, evidenceRefs: record.evidenceRefs,
    scope: record.scope, preconditions: record.preconditions, repair,
  });
  return validateVerificationRecord(rebuilt).ok ? rebuilt : null;
}
