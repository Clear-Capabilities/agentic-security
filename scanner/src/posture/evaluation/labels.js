// Adjudicated defect labels, reviewed negatives and finding-to-label matching
// (QA-002.AC01, QA-002.AC02).
//
// Advisory records are CANDIDATE ground truth. A label becomes scoreable only
// after adjudication: at least two distinct reviewers other than whoever
// proposed it, with evidence produced by a human or an independent verifier. A
// CWE alone never identifies a defect: a label needs a reviewed location range,
// and a finding matches only by location (plus family or CWE agreement).
//
// This module can validate that a label SAYS it was independently adjudicated.
// It cannot establish that it was. `synthetic: true` labels are accepted for
// tooling tests and are excluded from every real-code population count
// (`populationCounts`, gates.js).
//
// Pure: no fs, no clock, no network.

import {
  SCHEMA_VERSION, result, guardObject, checkHeader, checkFields, checkEnum, checkString, checkId,
  isPlainObject, checkCommit,
} from '../assurance/schema-kit.js';
import { semanticId } from '../assurance/identity.js';
import { EVIDENCE_PRODUCERS } from '../assurance/verification-record.js';

const DEFECT_LABEL_SCHEMA = 'agentic-security/adjudicated-defect-label';
const NEGATIVE_LABEL_SCHEMA = 'agentic-security/adjudicated-negative';
const ADJUDICATION_STATUSES = Object.freeze(['candidate', 'adjudicated', 'disputed', 'rejected']);
const NEGATIVE_KINDS = Object.freeze(['safe-real', 'patched', 'near-miss']);
const VARIANTS = Object.freeze(['pre', 'post']);
const INDEPENDENT_PRODUCERS = ['human', 'independent-verifier'];

const DEFECT_ID_FIELDS = Object.freeze(['targetId', 'rootCauseId', 'language', 'family', 'location', 'affected']);
const NEGATIVE_ID_FIELDS = Object.freeze(['targetId', 'variant', 'kind', 'language', 'family', 'scope', 'pairedDefectId']);

const defectLabelId = (l) => semanticId('dlab', l, DEFECT_ID_FIELDS);
const negativeLabelId = (l) => semanticId('nlab', l, NEGATIVE_ID_FIELDS);

const DL_ALLOWED = ['schema', 'schemaVersion', 'id', 'targetId', 'rootCauseId', 'affected', 'language', 'family', 'cwe', 'location', 'evidence', 'adjudication', 'proposedBy', 'advisoryRefs', 'synthetic', 'createdAt'];
const DL_REQUIRED = ['schema', 'schemaVersion', 'id', 'targetId', 'rootCauseId', 'affected', 'language', 'family', 'location', 'evidence', 'adjudication', 'proposedBy', 'synthetic'];
const NL_ALLOWED = ['schema', 'schemaVersion', 'id', 'targetId', 'variant', 'kind', 'language', 'family', 'scope', 'pairedDefectId', 'rationale', 'adjudication', 'proposedBy', 'synthetic', 'createdAt'];
const NL_REQUIRED = ['schema', 'schemaVersion', 'id', 'targetId', 'variant', 'kind', 'language', 'family', 'scope', 'rationale', 'adjudication', 'proposedBy', 'synthetic'];

function checkAdjudication(ctx, label) {
  const a = label.adjudication;
  if (!isPlainObject(a)) { ctx.err('BAD_TYPE', 'adjudication', 'must be an object'); return; }
  if (!checkEnum(ctx, 'adjudication.status', a.status, ADJUDICATION_STATUSES)) return;
  if (!Array.isArray(a.reviewers)) { ctx.err('BAD_TYPE', 'adjudication.reviewers', 'must be an array'); return; }
  if (a.status !== 'adjudicated') return;
  const ids = new Set();
  a.reviewers.forEach((r, i) => {
    if (!isPlainObject(r) || !r.reviewerId) { ctx.err('BAD_TYPE', `adjudication.reviewers[${i}]`, 'a reviewer record names reviewerId and verdict'); return; }
    ids.add(r.reviewerId);
    if (r.verdict !== 'confirmed') ctx.err('RULE_VIOLATION', `adjudication.reviewers[${i}].verdict`, 'an adjudicated label needs every reviewer verdict to be confirmed');
    if (isPlainObject(label.proposedBy) && r.reviewerId === label.proposedBy.id) ctx.err('RULE_VIOLATION', `adjudication.reviewers[${i}]`, 'a proposer cannot adjudicate its own label');
  });
  if (ids.size < 2) ctx.err('RULE_VIOLATION', 'adjudication.reviewers', 'an adjudicated label needs at least two distinct reviewers');
  if (a.independent !== true) ctx.err('RULE_VIOLATION', 'adjudication.independent', 'adjudication must be recorded as independent of the label proposer and the detector authors');
}

function checkEvidence(ctx, label) {
  if (!Array.isArray(label.evidence)) { ctx.err('BAD_TYPE', 'evidence', 'must be an array'); return; }
  label.evidence.forEach((e, i) => {
    if (!isPlainObject(e)) { ctx.err('BAD_TYPE', `evidence[${i}]`, 'must be an object'); return; }
    checkString(ctx, `evidence[${i}].ref`, e.ref);
    checkEnum(ctx, `evidence[${i}].producer`, e.producer, EVIDENCE_PRODUCERS);
  });
  if (label.adjudication?.status === 'adjudicated' && !label.evidence.some((e) => INDEPENDENT_PRODUCERS.includes(e?.producer))) {
    ctx.err('RULE_VIOLATION', 'evidence', 'an adjudicated label needs evidence produced by a human or an independent verifier; model output alone is not adjudication');
  }
}

export function validateDefectLabel(l) {
  const g = guardObject(l);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, l, DEFECT_LABEL_SCHEMA)) return result(ctx);
  checkFields(ctx, l, DL_ALLOWED, DL_REQUIRED);
  checkString(ctx, 'targetId', l.targetId);
  checkString(ctx, 'rootCauseId', l.rootCauseId);
  checkString(ctx, 'language', l.language);
  checkString(ctx, 'family', l.family);
  if (typeof l.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');
  if (!isPlainObject(l.affected)) ctx.err('BAD_TYPE', 'affected', 'must name the affected build/commit');
  else checkCommit(ctx, 'affected.commit', l.affected.commit, { nullable: false });
  // The reviewed vulnerable location is mandatory: a CWE-only label cannot exist.
  const loc = l.location;
  if (!isPlainObject(loc)) ctx.err('MISSING_FIELD', 'location', 'a reviewed vulnerable location range is required; a CWE alone does not identify a defect');
  else {
    checkString(ctx, 'location.file', loc.file);
    if (!Number.isInteger(loc.startLine) || !Number.isInteger(loc.endLine) || loc.startLine < 1 || loc.endLine < loc.startLine) {
      ctx.err('BAD_TYPE', 'location', 'startLine/endLine must be positive integers with endLine >= startLine');
    }
  }
  checkAdjudication(ctx, l);
  checkEvidence(ctx, l);
  if (!isPlainObject(l.proposedBy) || !l.proposedBy.id) ctx.err('MISSING_FIELD', 'proposedBy', 'the proposer must be recorded');
  checkId(ctx, l, defectLabelId(l));
  return result(ctx);
}

export function validateNegativeLabel(l) {
  const g = guardObject(l);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, l, NEGATIVE_LABEL_SCHEMA)) return result(ctx);
  checkFields(ctx, l, NL_ALLOWED, NL_REQUIRED);
  checkString(ctx, 'targetId', l.targetId);
  checkString(ctx, 'language', l.language);
  checkString(ctx, 'family', l.family);
  checkString(ctx, 'rationale', l.rationale);
  checkEnum(ctx, 'variant', l.variant, VARIANTS);
  const kindOk = checkEnum(ctx, 'kind', l.kind, NEGATIVE_KINDS);
  if (typeof l.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');
  if (!isPlainObject(l.scope) || !Array.isArray(l.scope.files) || l.scope.files.length === 0) ctx.err('MISSING_FIELD', 'scope', 'a negative must name the files it is negative for');
  if (kindOk && l.kind === 'patched') {
    if (l.variant !== 'post') ctx.err('RULE_VIOLATION', 'variant', 'a patched negative is the fixed (post) variant');
    checkString(ctx, 'pairedDefectId', l.pairedDefectId);
  }
  checkAdjudication(ctx, l);
  if (!isPlainObject(l.proposedBy) || !l.proposedBy.id) ctx.err('MISSING_FIELD', 'proposedBy', 'the proposer must be recorded');
  checkId(ctx, l, negativeLabelId(l));
  return result(ctx);
}

export function buildDefectLabel(fields) {
  const l = { schema: DEFECT_LABEL_SCHEMA, schemaVersion: SCHEMA_VERSION, synthetic: false, evidence: [], ...fields };
  l.id = defectLabelId(l);
  return l;
}
export function buildNegativeLabel(fields) {
  const l = { schema: NEGATIVE_LABEL_SCHEMA, schemaVersion: SCHEMA_VERSION, synthetic: false, ...fields };
  l.id = negativeLabelId(l);
  return l;
}

/** Scoreable = structurally valid AND adjudicated. A candidate (advisory-only) label is never scored. */
export function isScoreable(label) {
  return !!label && label.adjudication?.status === 'adjudicated' && validateAny(label).ok;
}

function validateAny(label) {
  return label?.schema === NEGATIVE_LABEL_SCHEMA ? validateNegativeLabel(label) : validateDefectLabel(label);
}

// ---------------------------------------------------------------- matching

const norm = (p) => String(p || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');

/**
 * Does a finding identify the labelled defect? It must (1) sit in the labelled
 * file, (2) carry a line inside the reviewed range widened by `lineWindow`, and
 * (3) agree on family or CWE. CWE agreement alone, a right-file-wrong-line
 * finding and a finding with no line all fail, each with a distinct reason.
 */
export function matchFinding(finding, label, policy) {
  const lineWindow = Number.isInteger(policy?.lineWindow) ? policy.lineWindow : 3;
  const sameFile = norm(finding?.file) === norm(label?.location?.file);
  const familyOk = !!finding?.family && finding.family === label?.family;
  const cweOk = !!finding?.cwe && !!label?.cwe && String(finding.cwe).toUpperCase() === String(label.cwe).toUpperCase();
  if (!sameFile) return { matched: false, reason: cweOk ? 'cwe-only' : 'wrong-file' };
  const line = Number(finding.line);
  if (!Number.isFinite(line) || line <= 0) return { matched: false, reason: 'no-line' };
  const { startLine, endLine } = label.location;
  if (line < startLine - lineWindow || line > endLine + lineWindow) return { matched: false, reason: cweOk || familyOk ? 'outside-range' : 'wrong-location' };
  if (!familyOk && !cweOk) return { matched: false, reason: 'family-mismatch' };
  return { matched: true, reason: 'location-and-family' };
}

/** Does a finding fall in a negative's scope for the family it is negative for? */
export function matchNegative(finding, negative) {
  const inScope = (negative?.scope?.files || []).map(norm).includes(norm(finding?.file));
  if (!inScope) return { matched: false, reason: 'out-of-scope' };
  if (!finding?.family || finding.family !== negative.family) return { matched: false, reason: 'other-family' };
  return { matched: true, reason: 'family-in-negative-scope' };
}

/**
 * Findings on a target that no adjudicated label accounts for. These are NOT
 * false positives: a genuine, previously unlabelled defect would be hiding
 * among them. They go to a review queue and stay out of precision.
 */
export function reviewQueue(entries) {
  return entries.map((e) => ({ targetId: e.targetId, variant: e.variant, findingId: e.finding?.id || null, file: e.finding?.file || null, line: e.finding?.line ?? null, family: e.finding?.family || null, status: 'needs-adjudication', reason: e.reason }));
}

/** Counts of scoreable, real (non-synthetic) labels by language and family, for population gates. */
export function populationCounts(defects, negatives) {
  const out = { positivesByLanguage: {}, negativesByLanguage: {}, positivesByFamily: {}, syntheticPositives: 0, syntheticNegatives: 0, unadjudicated: 0 };
  for (const l of defects || []) {
    if (!isScoreable(l)) { out.unadjudicated++; continue; }
    if (l.synthetic) { out.syntheticPositives++; continue; }
    out.positivesByLanguage[l.language] = (out.positivesByLanguage[l.language] || 0) + 1;
    out.positivesByFamily[l.family] = (out.positivesByFamily[l.family] || 0) + 1;
  }
  for (const n of negatives || []) {
    if (!isScoreable(n)) { out.unadjudicated++; continue; }
    if (n.synthetic) { out.syntheticNegatives++; continue; }
    out.negativesByLanguage[n.language] = (out.negativesByLanguage[n.language] || 0) + 1;
  }
  return out;
}
