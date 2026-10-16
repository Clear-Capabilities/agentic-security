// The patch-level verification record (E3-02): one canonical statement of what was checked about ONE patch, by whichever route produced it.
//
// WHY A SECOND RECORD. posture/assurance/verification-record.js records a verdict on a HYPOTHESIS ("this finding is real"): confirmed,
// refuted, inconclusive. This records what was done to a PATCH ("this change fixes it and breaks nothing"). They are separate axes and the
// patch record points at the hypothesis it concerns; neither contains the other.
//
// HONESTY RULES (enforced by the validator, not by convention)
//   1. Every check is a leg with one of five statuses: passed, failed, blocked, not_run, not_applicable. `not_run` and `blocked` are never
//      `passed`, and `not_applicable` carries a reason, so "did not apply" cannot hide "was not checked".
//   2. `verifiedFull` is DERIVED: true only when every required leg passed and none failed. A record that claims it without that is invalid.
//      `degradedLegs` lists every required leg that did not pass, with the reason.
//   3. A leg may only cite evidence that is in the record, and every evidence item is addressed by its digest.
//   4. `confidence: proven` needs a named policy and evidence; confidence is never inferred from severity.
//   5. A route that ran fewer checks produces a record with those legs `not_run`; it does not produce a shorter record.
//
// Pure: no fs, no clock, no network. The id is content-derived from an allowlist of semantic fields, so timestamps and tool paths cannot
// change it.
import {
  SCHEMA_VERSION, checkCommit, checkDigest, checkEnum, checkFields, checkHeader, checkString, guardObject, isPlainObject, makeCtx, result,
} from '../posture/assurance/schema-kit.js';
import { digestOf, semanticId } from '../posture/assurance/identity.js';

export const FIX_VERIFICATION_SCHEMA = 'agentic-security/fix-verification-record';
export const LEG_STATUSES = Object.freeze(['passed', 'failed', 'blocked', 'not_run', 'not_applicable']);
export const MODES = Object.freeze(['preview', 'verify', 'apply']);
export const COMPLETENESS = Object.freeze(['FULL', 'MITIGATION', 'WORKAROUND', 'unverified', 'blocked']);
export const RESIDUAL_LEVELS = Object.freeze(['none', 'low', 'medium', 'high', 'unknown']);
export const CONFIDENCE_LEVELS = Object.freeze(['proven', 'inferred', 'unknown']);

// The legs a record carries, in canonical order. Each is a { status, evidenceIds, reason } object.
export const LEG_NAMES = Object.freeze([
  'securityBefore', 'securityAfter', 'exploitProofBefore', 'exploitProofAfter', 'newFindingDelta', 'behaviorPreservation',
  'behaviorTests', 'regressionTests', 'lint', 'typecheck', 'dependencyChecks',
]);

// What a leg means when it reads `passed`:
//   securityBefore       the weakness was present on the original code (reproduced or statically established)
//   securityAfter        the weakness is not present on the patched code
//   exploitProofBefore   an exploit succeeded against the original code
//   exploitProofAfter    the same exploit failed against the patched code
//   newFindingDelta      the patch introduced no new finding of equal or higher severity
//   behaviorPreservation intended functionality survived (authorised use still works, the sensitive operation is not simply gone)
//   behaviorTests        the project's tests for the affected scope passed on the PATCHED tree
//   regressionTests      the wider project tests passed on the patched tree
//   lint / typecheck     the configured linter / type checker passed on the patched tree
//   dependencyChecks     dependency manifests and lockfiles are consistent and free of new known advisories
export const LEG_MEANING = Object.freeze({
  securityBefore: 'the weakness was present on the original code',
  securityAfter: 'the weakness is not present on the patched code',
  exploitProofBefore: 'an exploit succeeded against the original code',
  exploitProofAfter: 'the same exploit failed against the patched code',
  newFindingDelta: 'the patch introduced no new finding of equal or higher severity',
  behaviorPreservation: 'intended functionality survived',
  behaviorTests: 'the affected-scope tests passed on the patched tree',
  regressionTests: 'the wider project tests passed on the patched tree',
  lint: 'the configured linter passed on the patched tree',
  typecheck: 'the configured type checker passed on the patched tree',
  dependencyChecks: 'dependency manifests are consistent and carry no new advisory',
});

const ALLOWED = ['schema', 'schemaVersion', 'id', 'findingId', 'findingStableId', 'hypothesisId', 'mode', 'route', 'preCommit', 'preTreeHash', 'postPatchHash', 'patchHash',
  'affectedFiles', ...LEG_NAMES, 'requiredLegs', 'coverage', 'degradedLegs', 'verifiedFull', 'fixCompleteness', 'residualRisk', 'confidence', 'tools', 'failures', 'evidence', 'timestamps'];
const REQUIRED = ['schema', 'schemaVersion', 'id', 'findingId', 'mode', 'route', 'patchHash', 'affectedFiles', ...LEG_NAMES, 'requiredLegs', 'coverage', 'degradedLegs', 'verifiedFull', 'fixCompleteness', 'residualRisk', 'confidence', 'tools', 'failures', 'evidence'];

/** Fields that determine identity. Timestamps, tool paths and evidence locations are deliberately absent. */
export const FIX_RECORD_ID_FIELDS = Object.freeze(['findingId', 'findingStableId', 'mode', 'route', 'preCommit', 'preTreeHash', 'postPatchHash', 'patchHash', 'affectedFiles', ...LEG_NAMES, 'requiredLegs', 'verifiedFull', 'fixCompleteness']);

export const fixRecordId = (record) => semanticId('fvrec', record, FIX_RECORD_ID_FIELDS);

export const leg = (status, { evidenceIds = [], reason = null } = {}) => ({ status, evidenceIds, reason });
export const NOT_RUN = (reason) => leg('not_run', { reason });

/** Content-addressed evidence item. `sha256` is the digest of the bytes it stands for (a log, a scan result, a patch). */
export function evidenceItem({ kind, mediaType = 'text/plain', sha256, uri = null, note = null }) {
  const body = { kind, mediaType, sha256 };
  return { id: `ev:${digestOf(body).slice('sha256:'.length, 'sha256:'.length + 16)}`, ...body, ...(uri ? { uri } : {}), ...(note ? { note } : {}) };
}

/** Required legs that did not pass, as `name: status (reason)`. */
export function degradedLegsOf(record) {
  return record.requiredLegs.filter((n) => record[n].status !== 'passed').map((n) => `${n}: ${record[n].status}${record[n].reason ? ` (${record[n].reason})` : ''}`);
}

/** True only when every required leg passed and no leg failed. Everything else is not a full verification. */
export function deriveVerifiedFull(record) {
  if (LEG_NAMES.some((n) => record[n].status === 'failed')) return false;
  if (record.failures.length) return false;
  return record.requiredLegs.every((n) => record[n].status === 'passed');
}

/**
 * The completeness tier of a verified patch.
 *   blocked      a required leg is blocked, or a failure was recorded
 *   unverified   the weakness is not shown to be gone
 *   FULL         verifiedFull
 *   MITIGATION   the weakness is gone but a required check did not run, or the exploit leg did not run
 *   WORKAROUND   supplied by the caller when the route knows the change reduces exposure without removing the cause
 */
export function deriveCompleteness(record, { workaround = false } = {}) {
  if (record.failures.length || record.requiredLegs.some((n) => record[n].status === 'blocked')) return 'blocked';
  if (record.securityAfter.status !== 'passed') return 'unverified';
  if (LEG_NAMES.some((n) => record[n].status === 'failed')) return 'unverified';
  if (workaround) return 'WORKAROUND';
  return deriveVerifiedFull(record) ? 'FULL' : 'MITIGATION';
}

export function buildFixVerificationRecord(f) {
  const legs = {};
  for (const n of LEG_NAMES) legs[n] = f[n] ? { status: f[n].status, evidenceIds: [...(f[n].evidenceIds || [])], reason: f[n].reason ?? null } : NOT_RUN('the route did not run this check');
  const required = [...new Set(f.requiredLegs || [])].filter((n) => LEG_NAMES.includes(n)).sort((a, b) => LEG_NAMES.indexOf(a) - LEG_NAMES.indexOf(b));
  const rec = {
    schema: FIX_VERIFICATION_SCHEMA, schemaVersion: SCHEMA_VERSION,
    findingId: f.findingId, ...(f.findingStableId ? { findingStableId: f.findingStableId } : {}), ...(f.hypothesisId ? { hypothesisId: f.hypothesisId } : {}),
    mode: f.mode, route: f.route,
    preCommit: f.preCommit ?? null, preTreeHash: f.preTreeHash ?? null, postPatchHash: f.postPatchHash ?? null, patchHash: f.patchHash,
    affectedFiles: [...new Set(f.affectedFiles || [])].sort(),
    ...legs,
    requiredLegs: required,
    failures: (f.failures || []).map((x) => ({ leg: x.leg, reason: String(x.reason).slice(0, 400) })),
    evidence: [...(f.evidence || [])].sort((a, b) => (a.id < b.id ? -1 : 1)),
    residualRisk: f.residualRisk || { level: 'unknown', notes: ['not assessed'] },
    confidence: f.confidence || { level: 'unknown', policy: null, evidenceIds: [] },
    tools: f.tools || { engineVersion: null, verifier: 'unspecified' },
  };
  rec.verifiedFull = deriveVerifiedFull(rec);
  rec.degradedLegs = degradedLegsOf(rec);
  rec.coverage = { required: required.length, passed: required.filter((n) => rec[n].status === 'passed').length, notRun: required.filter((n) => rec[n].status === 'not_run').length, blocked: required.filter((n) => rec[n].status === 'blocked').length, failed: required.filter((n) => rec[n].status === 'failed').length };
  rec.fixCompleteness = f.fixCompleteness && f.fixCompleteness !== 'derive' ? f.fixCompleteness : deriveCompleteness(rec, { workaround: f.workaround === true });
  if (f.timestamps) rec.timestamps = f.timestamps;
  rec.id = fixRecordId(rec);
  return rec;
}

export function validateFixVerificationRecord(record) {
  const g = guardObject(record);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, record, FIX_VERIFICATION_SCHEMA)) return result(ctx);
  checkFields(ctx, record, ALLOWED, REQUIRED);
  checkString(ctx, 'findingId', record.findingId);
  checkString(ctx, 'route', record.route);
  checkEnum(ctx, 'mode', record.mode, MODES);
  checkEnum(ctx, 'fixCompleteness', record.fixCompleteness, COMPLETENESS);
  checkDigest(ctx, 'patchHash', record.patchHash);
  checkDigest(ctx, 'postPatchHash', record.postPatchHash, { nullable: true });
  checkDigest(ctx, 'preTreeHash', record.preTreeHash, { nullable: true });
  checkCommit(ctx, 'preCommit', record.preCommit);
  if (!Array.isArray(record.affectedFiles) || !record.affectedFiles.length || record.affectedFiles.some((x) => typeof x !== 'string' || !x || x.startsWith('/') || x.split('/').includes('..'))) ctx.err('BAD_TYPE', 'affectedFiles', 'must be a non-empty list of repository-relative paths');

  const evidenceIds = new Set();
  if (!Array.isArray(record.evidence)) ctx.err('BAD_TYPE', 'evidence', 'must be a list');
  else record.evidence.forEach((e, i) => {
    const p = `evidence[${i}]`;
    if (!isPlainObject(e)) { ctx.err('BAD_TYPE', p, 'must be an object'); return; }
    for (const k of Object.keys(e)) if (!['id', 'kind', 'mediaType', 'sha256', 'uri', 'note'].includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, 'not part of an evidence item');
    checkString(ctx, `${p}.kind`, e.kind);
    if (typeof e.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(e.sha256)) ctx.err('BAD_DIGEST', `${p}.sha256`, 'must be 64 lowercase hex characters');
    if (typeof e.id !== 'string' || !/^ev:[0-9a-f]{16}$/.test(e.id)) ctx.err('BAD_ID', `${p}.id`, 'must look like ev:<16 hex>');
    else if (evidenceIds.has(e.id)) ctx.err('DUPLICATE_ID', `${p}.id`, `duplicate evidence id ${e.id}`);
    else evidenceIds.add(e.id);
    if (typeof e.uri === 'string' && (/^[a-z]+:\/\/[^/]*@/i.test(e.uri) || /[?&](token|key|secret|password)=/i.test(e.uri))) ctx.err('RULE_VIOLATION', `${p}.uri`, 'an evidence location must not embed credentials');
  });

  for (const n of LEG_NAMES) {
    const l = record[n];
    const p = n;
    if (!isPlainObject(l)) { ctx.err('BAD_TYPE', p, 'must be a leg object'); continue; }
    for (const k of Object.keys(l)) if (!['status', 'evidenceIds', 'reason'].includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, 'not part of a leg');
    checkEnum(ctx, `${p}.status`, l.status, LEG_STATUSES);
    if (!Array.isArray(l.evidenceIds)) ctx.err('BAD_TYPE', `${p}.evidenceIds`, 'must be a list');
    else for (const id of l.evidenceIds) if (!evidenceIds.has(id)) ctx.err('DANGLING_REF', `${p}.evidenceIds`, `cites ${id}, which is not in evidence`);
    if (['not_run', 'not_applicable', 'blocked', 'failed'].includes(l.status) && !(typeof l.reason === 'string' && l.reason.trim())) ctx.err('RULE_VIOLATION', `${p}.reason`, `a leg that is ${l.status} must say why`);
    if (l.status === 'passed' && !l.evidenceIds?.length) ctx.err('RULE_VIOLATION', `${p}.evidenceIds`, 'a leg that passed must cite the evidence of the run');
  }

  if (!Array.isArray(record.requiredLegs) || record.requiredLegs.some((n) => !LEG_NAMES.includes(n))) ctx.err('BAD_TYPE', 'requiredLegs', 'must list leg names');
  else {
    if (new Set(record.requiredLegs).size !== record.requiredLegs.length) ctx.err('DUPLICATE_ID', 'requiredLegs', 'a leg is required once');
    if (!record.requiredLegs.includes('securityAfter')) ctx.err('RULE_VIOLATION', 'requiredLegs', 'securityAfter is always required: a patch that does not show the weakness gone fixes nothing');
    for (const n of record.requiredLegs) if (record[n]?.status === 'not_applicable') ctx.err('RULE_VIOLATION', n, 'a required leg cannot be not_applicable; drop it from requiredLegs with a reason on the leg instead');
  }
  if (!Array.isArray(record.failures)) ctx.err('BAD_TYPE', 'failures', 'must be a list');

  if (record.requiredLegs && Array.isArray(record.failures) && LEG_NAMES.every((n) => isPlainObject(record[n]))) {
    const expectFull = deriveVerifiedFull(record);
    if (record.verifiedFull !== expectFull) ctx.err('RULE_VIOLATION', 'verifiedFull', `verifiedFull is ${record.verifiedFull} but the legs imply ${expectFull}`);
    const expectDegraded = degradedLegsOf(record);
    if (JSON.stringify(record.degradedLegs) !== JSON.stringify(expectDegraded)) ctx.err('RULE_VIOLATION', 'degradedLegs', 'does not list exactly the required legs that did not pass');
    if (record.fixCompleteness === 'FULL' && !expectFull) ctx.err('RULE_VIOLATION', 'fixCompleteness', 'FULL requires verifiedFull');
    if (record.fixCompleteness === 'FULL' && record.securityAfter.status !== 'passed') ctx.err('RULE_VIOLATION', 'fixCompleteness', 'FULL requires securityAfter to have passed');
    if (['FULL', 'MITIGATION', 'WORKAROUND'].includes(record.fixCompleteness) && record.securityAfter.status !== 'passed') ctx.err('RULE_VIOLATION', 'fixCompleteness', `${record.fixCompleteness} requires securityAfter to have passed`);
    if (record.fixCompleteness !== 'blocked' && record.requiredLegs.some((n) => record[n].status === 'blocked')) ctx.err('RULE_VIOLATION', 'fixCompleteness', 'a blocked required leg makes the completeness blocked');
    if (!isPlainObject(record.coverage)) ctx.err('BAD_TYPE', 'coverage', 'must be an object');
  }

  const rr = record.residualRisk;
  if (!isPlainObject(rr)) ctx.err('BAD_TYPE', 'residualRisk', 'must be an object');
  else { checkEnum(ctx, 'residualRisk.level', rr.level, RESIDUAL_LEVELS); if (!Array.isArray(rr.notes)) ctx.err('BAD_TYPE', 'residualRisk.notes', 'must be a list'); }
  const c = record.confidence;
  if (!isPlainObject(c)) ctx.err('BAD_TYPE', 'confidence', 'must be an object');
  else {
    checkEnum(ctx, 'confidence.level', c.level, CONFIDENCE_LEVELS);
    if (c.level === 'proven') {
      if (!(typeof c.policy === 'string' && c.policy)) ctx.err('RULE_VIOLATION', 'confidence.policy', 'proven confidence needs a named proof policy');
      if (!Array.isArray(c.evidenceIds) || !c.evidenceIds.length) ctx.err('RULE_VIOLATION', 'confidence.evidenceIds', 'proven confidence needs evidence');
      else for (const id of c.evidenceIds) if (!evidenceIds.has(id)) ctx.err('DANGLING_REF', 'confidence.evidenceIds', `cites ${id}, which is not in evidence`);
      if (record.exploitProofAfter?.status !== 'passed') ctx.err('RULE_VIOLATION', 'confidence.level', 'proven requires the exploit replay leg to have passed against the patched code');
    }
  }
  if (!isPlainObject(record.tools)) ctx.err('BAD_TYPE', 'tools', 'must be an object');
  if (typeof record.id === 'string' && LEG_NAMES.every((n) => isPlainObject(record[n])) && Array.isArray(record.affectedFiles) && Array.isArray(record.requiredLegs)) {
    const want = fixRecordId(record);
    if (record.id !== want) ctx.err('ID_MISMATCH', 'id', `id does not follow from the record's content (expected ${want})`);
  }
  return result(ctx);
}

/** The shape every pre-existing consumer reads: ok, verified, verifiedFull, degradedLegs. Additive fields are not included. */
export function legacyViewOf(record) {
  const failedAny = LEG_NAMES.some((n) => record[n].status === 'failed') || record.failures.length > 0;
  return {
    ok: !failedAny && record.securityAfter.status === 'passed',
    verified: !failedAny && record.securityAfter.status === 'passed',
    verifiedFull: record.verifiedFull,
    degradedLegs: [...record.degradedLegs],
    completeness: record.fixCompleteness,
  };
}
