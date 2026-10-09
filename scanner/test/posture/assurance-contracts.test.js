// CORE-002: versioned evidence contracts and stable identities.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  VERIFICATION_OUTCOMES, EVIDENCE_KINDS, buildVerificationRecord, validateVerificationRecord, verificationRecordId,
  deriveConfirmationLevel, verificationClaimKey,
} from '../../src/posture/assurance/verification-record.js';
import {
  validateObservationBinding, validateCapabilityDecision, validateRoutingLabel, validateReleaseEvidence,
  validateRecordSet, observationBindingId, observationBindingKey, capabilityDecisionId, routingLabelId, releaseEvidenceId,
  OBSERVATION_BINDING_SCHEMA, CAPABILITY_DECISION_SCHEMA, ROUTING_LABEL_SCHEMA, RELEASE_EVIDENCE_SCHEMA,
} from '../../src/posture/assurance/contracts.js';
import {
  migrateRecord, toLegacyVerificationView, fromLegacyVerification,
} from '../../src/posture/assurance/migrations.js';
import { digestOf, hypothesisIdFromFinding, canonicalize } from '../../src/posture/assurance/identity.js';
import { computeStableId } from '../../src/posture/stable-id.js';
import * as V from '../../src/posture/assurance/verification-record.js';
import * as C from '../../src/posture/assurance/contracts.js';
import * as K from '../../src/posture/assurance/schema-kit.js';
import * as M from '../../src/posture/assurance/migrations.js';
import { ID_HEX_LEN, ID_PREFIXES } from '../../src/posture/assurance/identity.js';

const COMMIT = 'a'.repeat(40);
const D = (c) => `sha256:${c.repeat(64)}`;

const runtimeEvidence = { id: 'e-run', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: D('1') };
const modelEvidence = { id: 'e-model', kind: 'inference', producer: 'model', digest: D('2') };
const adjudication = { id: 'e-adj', kind: 'independent-adjudication', producer: 'independent-verifier', digest: D('3') };

function verification(over = {}) {
  return buildVerificationRecord({
    hypothesisId: 'h-1', commit: COMMIT, detectorOrigin: { detector: 'ir-taint' },
    oracle: { id: 'replay-1', kind: 'runtime-replay' }, attempt: 1, outcome: 'confirmed', reason: 'marker observed',
    evidence: [structuredClone(runtimeEvidence)], scope: { description: 'sqli in login', platform: 'linux' }, preconditions: { valid: true },
    ...over,
    // never share evidence objects between records: tests mutate them
    ...(over.evidence ? { evidence: structuredClone(over.evidence) } : {}),
  });
}

function codes(r) { return r.errors.map(e => e.code); }

function binding(over = {}) {
  const b = {
    schema: OBSERVATION_BINDING_SCHEMA, schemaVersion: '1.0.0', hypothesisId: 'h-1',
    observationRef: { observationId: 'observation:abc' }, provenance: 'runtime-observation', pathState: 'runtime-supported',
    completeness: 'sampled', window: { start: '2026-10-01T00:00:00Z', end: '2026-10-02T00:00:00Z' }, ...over,
  };
  b.id = observationBindingId(b);
  return b;
}
function decision(over = {}) {
  const d = {
    schema: CAPABILITY_DECISION_SCHEMA, schemaVersion: '1.0.0', taskId: 't1', capability: 'filesystem-write', subject: '/etc/passwd',
    decision: 'deny', mediation: 'runner', enforced: true, backend: 'linux-ns', probeDigest: D('4'), reason: 'outside root', ...over,
  };
  d.id = capabilityDecisionId(d);
  return d;
}
function label(over = {}) {
  const l = {
    schema: ROUTING_LABEL_SCHEMA, schemaVersion: '1.0.0', taskId: 't1', taskKind: 'triage', stratum: 'js/sqli', model: 'm1',
    outcome: 'correct', labelSource: 'adjudication', ...over,
  };
  l.id = routingLabelId(l);
  return l;
}
function release(over = {}) {
  const v = verification();
  const r = {
    schema: RELEASE_EVIDENCE_SCHEMA, schemaVersion: '1.0.0', subject: { commit: COMMIT, bundleDigest: D('5') },
    claims: [{ id: 'c1', statement: 'no confirmed exploit', status: 'verified', evidenceRefs: [v.id], gaps: [] }], complete: true, ...over,
  };
  r.id = releaseEvidenceId(r);
  return { r, v };
}

// ---------------------------------------------------------------- AC01

test('[CORE-002.AC01] valid records of all five kinds validate', () => {
  assert.deepEqual(validateVerificationRecord(verification()).errors, []);
  assert.deepEqual(validateObservationBinding(binding()).errors, []);
  assert.deepEqual(validateCapabilityDecision(decision()).errors, []);
  assert.deepEqual(validateRoutingLabel(label()).errors, []);
  assert.deepEqual(validateReleaseEvidence(release().r).errors, []);
});

test('[CORE-002.AC01] unknown risk-bearing enum values are rejected for every kind', () => {
  const v = verification(); v.outcome = 'passed';
  assert.ok(codes(validateVerificationRecord(v)).includes('UNKNOWN_ENUM'));
  const e = verification(); e.evidence[0].kind = 'vibes';
  assert.ok(codes(validateVerificationRecord(e)).includes('UNKNOWN_ENUM'));
  const o = verification(); o.oracle.kind = 'magic';
  assert.ok(codes(validateVerificationRecord(o)).includes('UNKNOWN_ENUM'));
  const r = verification(); r.repair.status = 'fixed-for-sure';
  assert.ok(codes(validateVerificationRecord(r)).includes('UNKNOWN_ENUM'));
  assert.ok(codes(validateObservationBinding(binding({ pathState: 'reachable' }))).includes('UNKNOWN_ENUM'));
  assert.ok(codes(validateCapabilityDecision(decision({ decision: 'maybe' }))).includes('UNKNOWN_ENUM'));
  assert.ok(codes(validateCapabilityDecision(decision({ mediation: 'vibes' }))).includes('UNKNOWN_ENUM'));
  assert.ok(codes(validateRoutingLabel(label({ labelSource: 'model' }))).includes('UNKNOWN_ENUM'));
  const { r: rel } = release(); rel.claims[0].status = 'passed';
  assert.ok(codes(validateReleaseEvidence(rel)).includes('UNKNOWN_ENUM'));
});

test('[CORE-002.AC01] unsupported major versions are rejected for every kind', () => {
  for (const [rec, fn] of [
    [verification(), validateVerificationRecord], [binding(), validateObservationBinding], [decision(), validateCapabilityDecision],
    [label(), validateRoutingLabel], [release().r, validateReleaseEvidence],
  ]) {
    assert.ok(fn({ ...rec, schemaVersion: '2.0.0' }).errors.some(e => e.code === 'UNSUPPORTED_MAJOR'), rec.schema);
    assert.ok(fn({ ...rec, schemaVersion: '0.9.0' }).errors.some(e => e.code === 'UNSUPPORTED_MAJOR'), rec.schema);
    assert.ok(fn({ ...rec, schemaVersion: 'one' }).errors.some(e => e.code === 'BAD_VERSION'), rec.schema);
    assert.deepEqual(fn({ ...rec, schemaVersion: '1.7.3' }).errors.filter(e => e.code === 'UNSUPPORTED_MAJOR'), []);
  }
  assert.ok(codes(validateVerificationRecord({ ...verification(), schema: 'other/thing' })).includes('SCHEMA_MISMATCH'));
});

test('[CORE-002.AC01] duplicate ids are rejected within and across collections', () => {
  const a = verification();
  assert.ok(codes(validateRecordSet({ verificationRecords: [a, structuredClone(a)] })).includes('DUPLICATE_ID'));
  const dupEvidence = verification({ evidence: [runtimeEvidence, { ...runtimeEvidence }], evidenceRefs: ['e-run'] });
  assert.ok(codes(validateVerificationRecord(dupEvidence)).includes('DUPLICATE_ID'));
  const { r } = release();
  r.claims.push({ ...r.claims[0] });
  assert.ok(codes(validateReleaseEvidence(r)).includes('DUPLICATE_ID'));
  // a record id reused under a different collection
  const l = label(); const d = decision(); d.id = l.id;
  assert.ok(codes(validateRecordSet({ routingLabels: [l], capabilityDecisions: [d] })).includes('DUPLICATE_ID'));
});

test('[CORE-002.AC01] dangling references are rejected', () => {
  const v = verification({ evidenceRefs: ['e-missing'] });
  assert.ok(codes(validateVerificationRecord(v)).includes('DANGLING_REF'));
  const { r } = release();
  assert.ok(codes(validateRecordSet({ releaseEvidence: [r], verificationRecords: [] })).includes('DANGLING_REF'));
  assert.deepEqual(codes(validateRecordSet({ releaseEvidence: [r], verificationRecords: [release().v] })), []);
  assert.ok(codes(validateRecordSet({ routingLabels: [label({ verificationRecordId: 'vrec:0000000000000000' })] })).includes('DANGLING_REF'));
  const repaired = verification({ repair: { status: 'replay-verified', patchDigest: D('6'), replayRecordId: 'vrec:0000000000000000' } });
  assert.ok(codes(validateRecordSet({ verificationRecords: [repaired] })).includes('DANGLING_REF'));
});

test('[CORE-002.AC01] digest formats, commit format, unknown fields and a forged id are rejected', () => {
  const bad = verification(); bad.evidence[0].digest = 'sha256:XYZ';
  assert.ok(codes(validateVerificationRecord(bad)).includes('BAD_DIGEST'));
  assert.ok(codes(validateVerificationRecord(verification({ commit: 'main' }))).includes('BAD_TYPE'));
  assert.ok(codes(validateVerificationRecord({ ...verification(), isSafe: true })).includes('UNKNOWN_FIELD'));
  assert.ok(codes(validateVerificationRecord({ ...verification(), id: 'vrec:0000000000000000' })).includes('ID_MISMATCH'));
  assert.ok(codes(validateVerificationRecord(null)).includes('NOT_AN_OBJECT'));
  assert.ok(codes(validateVerificationRecord({ ...verification(), scope: { platform: 'linux' } })).includes('BAD_TYPE'));
  assert.ok(codes(validateCapabilityDecision(decision({ probeDigest: 'abc' }))).includes('BAD_DIGEST'));
});

test('[CORE-002.AC01] confirmation and refutation rules: a model verdict alone cannot confirm; refutation needs an applicable oracle', () => {
  const modelOnly = verification({ evidence: [modelEvidence], oracle: { id: 'llm', kind: 'model' } });
  assert.ok(!validateVerificationRecord(modelOnly).ok);
  const modelWithRuntimeOracle = verification({ evidence: [modelEvidence] });
  assert.ok(codes(validateVerificationRecord(modelWithRuntimeOracle)).includes('RULE_VIOLATION'));
  // a model cannot be the producer of a proof or an adjudication
  const forgedProof = verification({ evidence: [{ ...modelEvidence, kind: 'trusted-runtime-proof' }] });
  assert.ok(codes(validateVerificationRecord(forgedProof)).includes('RULE_VIOLATION'));
  const forgedAdj = verification({ evidence: [{ ...modelEvidence, kind: 'independent-adjudication' }] });
  assert.ok(codes(validateVerificationRecord(forgedAdj)).includes('RULE_VIOLATION'));
  // a model's output is an inference, never an observation
  const modelObservation = verification({ evidence: [{ ...modelEvidence, kind: 'observation' }], outcome: 'inconclusive', reason: 'x', oracle: null, attempt: 1 });
  assert.ok(codes(validateVerificationRecord(modelObservation)).includes('RULE_VIOLATION'));
  assert.deepEqual(validateVerificationRecord(verification({ evidence: [modelEvidence], outcome: 'inconclusive', reason: 'model suspects it', oracle: null, attempt: 1, evidenceRefs: ['e-model'] })).errors, []);
  // refuted needs proving evidence, not just an oracle and valid preconditions
  const refutedNoProof = verification({ outcome: 'refuted', evidence: [modelEvidence], evidenceRefs: ['e-model'] });
  assert.ok(codes(validateVerificationRecord(refutedNoProof)).includes('RULE_VIOLATION'));
  const refutedUnreferenced = verification({ outcome: 'refuted', evidence: [runtimeEvidence], evidenceRefs: [] });
  assert.ok(codes(validateVerificationRecord(refutedUnreferenced)).includes('RULE_VIOLATION'), 'evidence that is not referenced does not count');
  // a forged confirmation level is caught by derivation
  const forgedLevel = { ...verification({ evidence: [adjudication] }), confirmationLevel: 'runtime-confirmed' };
  forgedLevel.id = verificationRecordId(forgedLevel);
  assert.ok(codes(validateVerificationRecord(forgedLevel)).includes('RULE_VIOLATION'));
  // refuted without valid preconditions or with a model oracle
  const noPre = verification({ outcome: 'refuted', preconditions: { valid: false } });
  assert.ok(codes(validateVerificationRecord(noPre)).includes('RULE_VIOLATION'));
  const modelRefute = verification({ outcome: 'refuted', oracle: { id: 'llm', kind: 'model' } });
  assert.ok(codes(validateVerificationRecord(modelRefute)).includes('RULE_VIOLATION'));
  assert.deepEqual(validateVerificationRecord(verification({ outcome: 'refuted', reason: 'patched build did not reproduce' })).errors, []);
});

test('[CORE-002.AC01] enforcement, routing and release honesty rules', () => {
  assert.ok(codes(validateCapabilityDecision(decision({ mediation: 'hook-advisory' }))).includes('RULE_VIOLATION'));
  assert.ok(codes(validateCapabilityDecision(decision({ probeDigest: undefined }))).includes('RULE_VIOLATION'));
  assert.deepEqual(validateCapabilityDecision(decision({ mediation: 'hook-advisory', enforced: false, probeDigest: undefined, backend: null })).errors, []);
  assert.ok(codes(validateRoutingLabel(label({ labelSource: 'none' }))).includes('RULE_VIOLATION'));
  assert.ok(codes(validateRoutingLabel(label({ outcome: 'delayed' }))).includes('RULE_VIOLATION'));
  assert.deepEqual(validateRoutingLabel(label({ outcome: 'delayed', labelSource: 'none' })).errors, []);
  const { r } = release({ complete: true });
  const lie = { ...r, claims: [{ ...r.claims[0], status: 'skipped', gaps: ['not run'] }], complete: true };
  lie.id = releaseEvidenceId(lie);
  assert.ok(codes(validateReleaseEvidence(lie)).includes('RULE_VIOLATION'));
  const noEvidence = { ...r, claims: [{ ...r.claims[0], evidenceRefs: [] }] };
  noEvidence.id = releaseEvidenceId(noEvidence);
  assert.ok(codes(validateReleaseEvidence(noEvidence)).includes('RULE_VIOLATION'));
  // a verified claim citing a not-run verification record is rejected at set level
  const notRun = verification({ outcome: 'not-run', attempt: 0, evidence: [], oracle: null, reason: 'no backend' });
  const rel = release().r; rel.claims[0].evidenceRefs = [notRun.id]; rel.id = releaseEvidenceId(rel);
  assert.ok(codes(validateRecordSet({ releaseEvidence: [rel], verificationRecords: [notRun] })).includes('RULE_VIOLATION'));
  // observation absence in a sample cannot establish blocked
  assert.ok(codes(validateObservationBinding(binding({ pathState: 'blocked', completeness: 'sampled' }))).includes('RULE_VIOLATION'));
  assert.deepEqual(validateObservationBinding(binding({ pathState: 'blocked', completeness: 'complete' })).errors, []);
  assert.ok(codes(validateObservationBinding(binding({ provenance: 'inferred', pathState: 'runtime-supported' }))).includes('RULE_VIOLATION'));
});

test('[CORE-002.AC01] the six verification outcomes and four evidence kinds stay distinct', () => {
  assert.deepEqual([...VERIFICATION_OUTCOMES], ['not-run', 'unsupported', 'inconclusive', 'error', 'refuted', 'confirmed']);
  assert.deepEqual([...EVIDENCE_KINDS], ['observation', 'inference', 'independent-adjudication', 'trusted-runtime-proof']);
  assert.equal(deriveConfirmationLevel(verification()), 'runtime-confirmed');
  assert.equal(deriveConfirmationLevel(verification({ evidence: [adjudication] })), 'adjudicated');
  // repair status is its own axis and never changes the outcome
  const patched = verification({ repair: { status: 'applied', patchDigest: D('7') } });
  assert.equal(patched.outcome, 'confirmed');
  assert.ok(codes(validateVerificationRecord(verification({ repair: { status: 'applied' } }))).includes('RULE_VIOLATION'));
});

test('[CORE-002.AC01] the closed vocabularies are exactly the documented ones, and every error code the validators emit is declared', () => {
  assert.deepEqual([...V.REPAIR_STATUSES], ['none', 'proposed', 'applied', 'replay-verified', 'rolled-back']);
  assert.deepEqual([...V.EVIDENCE_PRODUCERS], ['model', 'tool', 'human', 'independent-verifier', 'trusted-runner']);
  assert.deepEqual([...V.ORACLE_KINDS], ['runtime-replay', 'differential', 'static-proof', 'model', 'human', 'none']);
  assert.deepEqual([...V.CONFIRMATION_LEVELS], ['runtime-confirmed', 'adjudicated', 'none']);
  assert.deepEqual([...C.BINDING_PROVENANCE], ['static-config', 'runtime-observation', 'inferred']);
  assert.deepEqual([...C.PATH_STATES], ['possible', 'blocked', 'unresolved', 'runtime-supported']);
  assert.deepEqual([...C.OBSERVATION_COMPLETENESS], ['complete', 'sampled', 'unknown']);
  assert.deepEqual([...C.CAPABILITY_KINDS], ['filesystem-read', 'filesystem-write', 'command', 'network', 'tool', 'delegation']);
  assert.deepEqual([...C.CAPABILITY_DECISIONS], ['allow', 'deny', 'blocked', 'unsupported']);
  assert.deepEqual([...C.CAPABILITY_MEDIATIONS], ['runner', 'proxy', 'in-process-policy', 'hook-advisory', 'none']);
  assert.deepEqual([...C.ROUTING_TASK_KINDS], ['discovery', 'triage', 'verification-planning', 'repair']);
  assert.deepEqual([...C.ROUTING_OUTCOMES], ['correct', 'incorrect', 'unknown', 'delayed']);
  assert.deepEqual([...C.ROUTING_LABEL_SOURCES], ['adjudication', 'trusted-execution', 'none']);
  assert.deepEqual([...C.CLAIM_STATUSES], ['verified', 'failed', 'skipped', 'incomplete', 'unverified']);
  // every identity allowlist excludes clocks and migration bookkeeping
  for (const fields of [V.VERIFICATION_ID_FIELDS, C.OBSERVATION_BINDING_KEY_FIELDS, C.CAPABILITY_DECISION_ID_FIELDS, C.ROUTING_LABEL_ID_FIELDS, C.RELEASE_EVIDENCE_ID_FIELDS]) {
    assert.ok(!fields.includes('createdAt') && !fields.includes('migration') && !fields.includes('id'));
  }
  assert.ok(!C.OBSERVATION_BINDING_KEY_FIELDS.includes('eventDiscriminator'));
  // ids have a fixed width and distinct prefixes
  assert.match(verification().id, new RegExp(`^vrec:[0-9a-f]{${ID_HEX_LEN}}$`));
  assert.equal(new Set(Object.values(ID_PREFIXES)).size, 5);
  // validators emit only declared codes, and the small predicates behave
  const emitted = new Set();
  for (const bad of [null, {}, { ...verification(), schemaVersion: '9.0.0' }, { ...verification(), outcome: 'x' }, { ...verification(), id: 'vrec:1' }]) {
    for (const e of validateVerificationRecord(bad).errors) emitted.add(e.code);
  }
  for (const code of emitted) assert.ok(K.ERROR_CODES.includes(code), code);
  assert.equal(K.isCommit('a'.repeat(40)), true);
  assert.equal(K.isCommit('a'.repeat(39)), false);
  assert.equal(K.isNonEmptyString('  '), false);
  assert.equal(K.isNonEmptyString('x'), true);
  assert.equal(K.SCHEMA_VERSION, '1.0.0');
  assert.equal(K.SUPPORTED_MAJOR, 1);
  assert.equal(Number(K.SCHEMA_VERSION.split('.')[0]), K.SUPPORTED_MAJOR, 'what is written is always what is accepted');
});

test('[CORE-002.AC03] each legacy adapter is directly callable and refuses what it cannot ground', () => {
  assert.equal(M.legacyVerificationOutcome({ verified: true }).outcome, 'inconclusive');
  assert.equal(M.legacyVerificationOutcome({ proofEvidence: { tier: 'execution-proven', ran: true } }, { trustedRunner: true }).outcome, 'confirmed');
  assert.equal(M.fromEgressDecision({ decision: 'deny', provider: 'p', purpose: 'x' }).record.enforced, false);
  assert.equal(M.fromLegacyRoutingLabel({ model: 'm' }).ok, false, 'a label without a task id is refused');
  assert.equal(M.fromLegacyRelease({ checks: [] }).record.complete, false, 'no claims is never complete');
  assert.equal(M.fromLineageObservation({ id: 'observation:1' }, {}).ok, false, 'no hypothesis id from the caller is refused');
});

// ---------------------------------------------------------------- AC02

function shuffleKeys(v) {
  if (Array.isArray(v)) return v.map(shuffleKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, shuffleKeys(x)]));
  return v;
}

test('[CORE-002.AC02] identities are deterministic under key order at every depth', () => {
  const v = verification();
  assert.equal(verificationRecordId(shuffleKeys(v)), v.id);
  assert.equal(canonicalize(shuffleKeys(v)), canonicalize(v));
  assert.equal(digestOf(shuffleKeys(v)), digestOf(v));
  assert.deepEqual(validateVerificationRecord(shuffleKeys(v)).errors, []);
  assert.equal(observationBindingId(shuffleKeys(binding())), binding().id);
  assert.equal(capabilityDecisionId(shuffleKeys(decision())), decision().id);
  assert.equal(routingLabelId(shuffleKeys(label())), label().id);
  const { r } = release();
  assert.equal(releaseEvidenceId(shuffleKeys(r)), r.id);
});

test('[CORE-002.AC02] clocks, randomness and migration bookkeeping never reach an id; semantic changes always do', () => {
  const base = verification();
  const later = { ...base, createdAt: '2031-01-01T00:00:00Z', migration: { from: 'x', legacyValue: 'y' } };
  assert.equal(verificationRecordId(later), base.id);
  assert.equal(verification({ createdAt: '2020-01-01T00:00:00Z' }).id, verification({ createdAt: '2099-01-01T00:00:00Z' }).id);
  assert.equal(verification().id, verification().id);
  assert.notEqual(verification({ reason: 'different' }).id, base.id);
  assert.notEqual(verification({ commit: 'b'.repeat(40) }).id, base.id);
  assert.notEqual(verification({ attempt: 2 }).id, base.id);
  assert.notEqual(verificationClaimKey(verification({ attempt: 2 })), verificationClaimKey(base));
  // the claim key does not move with the result
  assert.equal(verificationClaimKey(verification({ outcome: 'inconclusive', evidence: [], reason: 'x' })), verificationClaimKey(base));
});

test('[CORE-002.AC02] an event discriminator changes the observation id but not the semantic key or the finding identity', () => {
  const a = binding();
  const b = binding({ eventDiscriminator: 'delivery-2' });
  const c = binding({ eventDiscriminator: 'delivery-3' });
  assert.notEqual(a.id, b.id);
  assert.notEqual(b.id, c.id);
  assert.equal(observationBindingKey(a), observationBindingKey(b));
  assert.equal(observationBindingKey(b), observationBindingKey(c));
  assert.deepEqual(validateObservationBinding(b).errors, []);
  // finding identity is the existing stable id, untouched by any binding
  const finding = { vuln: 'SQL injection', cwe: 'CWE-89', file: 'src/a.js', line: 3, sink: { snippet: 'db.query(x)' } };
  const hyp = hypothesisIdFromFinding(finding);
  assert.equal(hyp, computeStableId(finding));
  assert.equal(hypothesisIdFromFinding({ ...finding, line: 99 }), hyp);
  assert.equal(binding({ hypothesisId: hyp, eventDiscriminator: 'e1' }).hypothesisId, binding({ hypothesisId: hyp, eventDiscriminator: 'e2' }).hypothesisId);
});

// ---------------------------------------------------------------- AC03

const NON_POSITIVE_LEGACY = [
  { verified: true }, { verified: false }, { verified: null }, {}, { status: 'skipped' }, { status: 'unconfirmed' },
  { status: 'incomplete' }, { status: 'pending' }, { status: 'timeout' }, { status: 'confirmed' }, { status: 'refuted' },
  { status: 'passed' }, { status: 42 }, { status: 'unknown' },
  { proofEvidence: { tier: 'proof-failed', ran: true } },
  { proofEvidence: { tier: 'execution-proven', ran: true, observed: 'marker' } },
  { proofEvidence: { tier: 'taint-proven', ran: false, reason: 'no proof-of-concept attached' } },
  { proofEvidence: { tier: 'unproven', ran: false, reason: 'no confinement primitive available; refusing to execute' } },
  { proofEvidence: { tier: 'unproven', ran: false, witnessStatus: 'error', reason: 'the confinement sandbox could not start' } },
];

test('[CORE-002.AC03] legacy verification fixtures never migrate to confirmed or refuted without trusted evidence', () => {
  for (const legacy of NON_POSITIVE_LEGACY) {
    const out = migrateRecord('verification', legacy, { hypothesisId: 'h-1', commit: COMMIT });
    assert.ok(out.ok, JSON.stringify(legacy) + ' -> ' + JSON.stringify(out.errors));
    assert.ok(!['confirmed', 'refuted'].includes(out.record.outcome), `${JSON.stringify(legacy)} became ${out.record.outcome}`);
    assert.equal(out.record.confirmationLevel, 'none');
    assert.deepEqual(validateVerificationRecord(out.record).errors, []);
    const view = toLegacyVerificationView(out.record);
    assert.equal(view.verified, null, `view of ${JSON.stringify(legacy)} must not be a boolean`);
  }
  // specific mappings
  const m = (l, c = {}) => migrateRecord('verification', l, { hypothesisId: 'h', ...c }).record.outcome;
  assert.equal(m({ verified: null }), 'not-run');
  assert.equal(m({ status: 'skipped' }), 'not-run');
  assert.equal(m({ proofEvidence: { tier: 'unproven', ran: false, reason: 'unsupported poc language: go' } }), 'unsupported');
  assert.equal(m({ proofEvidence: { tier: 'unproven', ran: false, witnessStatus: 'error', reason: 'could not start' } }), 'error');
  assert.equal(m({ proofEvidence: { tier: 'proof-failed', ran: true } }), 'inconclusive');
  // missing context is refused, not guessed
  assert.equal(migrateRecord('verification', { verified: true }).ok, false);
});

test('[CORE-002.AC03] the only legacy path to confirmed is an explicit trusted-runner assertion bound to a commit', () => {
  const legacy = { proofEvidence: { tier: 'execution-proven', ran: true, observed: 'marker written' } };
  const out = fromLegacyVerification(legacy, { hypothesisId: 'h', commit: COMMIT, trustedRunner: true });
  assert.equal(out.record.outcome, 'confirmed');
  assert.equal(out.record.confirmationLevel, 'runtime-confirmed');
  assert.deepEqual(validateVerificationRecord(out.record).errors, []);
  // no commit: the confirmation cannot be bound, so the migration is refused
  const unbound = migrateRecord('verification', legacy, { hypothesisId: 'h', trustedRunner: true });
  assert.equal(unbound.ok, false);
});

test('[CORE-002.AC03] current-format records round-trip unchanged and legacy views never coerce states to booleans', () => {
  for (const outcome of ['not-run', 'unsupported', 'inconclusive', 'error']) {
    const rec = verification({ outcome, attempt: ['not-run', 'unsupported'].includes(outcome) ? 0 : 1, evidence: [], oracle: null, reason: outcome });
    const wire = JSON.parse(JSON.stringify(rec));
    const again = migrateRecord('verification', wire);
    assert.ok(again.ok, outcome);
    assert.deepEqual(again.record, rec);
    const view = toLegacyVerificationView(rec);
    assert.equal(view.verified, null);
    assert.equal(view.status, outcome);
    // feeding the view back through the legacy adapter cannot strengthen it
    const back = migrateRecord('verification', view, { hypothesisId: 'h-1' });
    assert.ok(!['confirmed', 'refuted'].includes(back.record.outcome));
  }
  const confirmed = verification();
  assert.equal(toLegacyVerificationView(confirmed).verified, true);
  assert.equal(toLegacyVerificationView(verification({ outcome: 'refuted' })).verified, false);
  assert.deepEqual(migrateRecord('verification', JSON.parse(JSON.stringify(confirmed))).record, confirmed);
  // an unsupported major version is never silently migrated
  assert.equal(migrateRecord('verification', { ...confirmed, schemaVersion: '2.0.0' }).ok, false);
});

test('[CORE-002.AC03] legacy egress decisions, routing labels, releases and observations migrate without gaining strength', () => {
  const deny = migrateRecord('capabilityDecision', { allowed: false, decision: 'deny', reason: 'mode deny', provider: 'openai', policySource: 'env', purpose: 'validate' });
  assert.ok(deny.ok);
  assert.equal(deny.record.enforced, false, 'an in-process policy check is never recorded as enforced');
  assert.equal(deny.record.mediation, 'in-process-policy');
  const weird = migrateRecord('capabilityDecision', { decision: 'allow-maybe', provider: 'x', purpose: 'p' });
  assert.equal(weird.record.decision, 'unsupported');

  const unlabeled = migrateRecord('routingLabel', { taskId: 't', model: 'm', correct: true });
  assert.equal(unlabeled.record.outcome, 'unknown', 'a bare boolean is not an adjudicated label');
  const labeled = migrateRecord('routingLabel', { taskId: 't', model: 'm', correct: true, labelSource: 'adjudication' });
  assert.equal(labeled.record.outcome, 'correct');
  assert.equal(migrateRecord('routingLabel', { taskId: 't', model: 'm', correct: false, labelSource: 'model' }).record.outcome, 'unknown');

  const rel = migrateRecord('releaseEvidence', {
    commit: COMMIT, bundleDigest: D('9'), verified: true,
    checks: [{ id: 'a', status: 'pass' }, { id: 'b', status: 'skipped' }, { id: 'c', status: 'weird' }, { id: 'd', status: 'pass', evidence: [D('8')] }, { id: 'e', status: 'fail' }],
  });
  assert.ok(rel.ok, JSON.stringify(rel.errors));
  assert.deepEqual(rel.record.claims.map(c => c.status), ['unverified', 'skipped', 'incomplete', 'verified', 'failed']);
  assert.equal(rel.record.complete, false);
  const allPass = migrateRecord('releaseEvidence', { commit: COMMIT, bundleDigest: D('9'), checks: [{ id: 'd', status: 'pass', evidence: [D('8')] }] });
  assert.equal(allPass.record.complete, true);
  const noBinding = migrateRecord('releaseEvidence', { checks: [{ id: 'd', status: 'pass', evidence: [D('8')] }] });
  assert.equal(noBinding.record.complete, false, 'unbound commit/bundle can never be complete');

  const obs = migrateRecord('observationBinding', { id: 'observation:xyz', adapter: 'native-jsonl', windowStart: 'a', windowEnd: 'b', matchedFlowIds: ['f1'] }, { hypothesisId: 'h' });
  assert.ok(obs.ok);
  assert.equal(obs.record.completeness, 'unknown');
  const unmatched = migrateRecord('observationBinding', { id: 'observation:xyz', windowStart: 'a', windowEnd: 'b', matchedFlowIds: [] }, { hypothesisId: 'h' });
  assert.equal(unmatched.record.pathState, 'unresolved');
});

test('[CORE-002.AC03] lineage stays separate: the contracts reference lineage observations by id and import nothing from lineage', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const dir = path.resolve(import.meta.dirname, '../../src/posture/assurance');
  for (const f of fs.readdirSync(dir).filter(n => n.endsWith('.js'))) {
    const text = fs.readFileSync(path.join(dir, f), 'utf8');
    assert.ok(!/from\s+['"][^'"]*\/lineage\//.test(text), `${f} imports lineage`);
  }
});
