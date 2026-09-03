import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REMEDIATION_STATES, REMEDIATION_EVENT_TYPES, ACCEPTED_RISK_REQUIRED_FIELDS,
  foldRemediationItem, foldRemediationLedger, validateOpenPayload,
  validateTransition, evaluateVerificationEvidence,
} from '../../src/lineage/remediation.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function _assessment(overrides = {}) {
  return {
    assessmentId: 'impact:abc123', targetId: 'node:deadbeef', targetKind: 'node',
    traceKind: 'topology_reachable', scope: 'possible',
    graphId: 'graph:aaa', graphDigest: 'f'.repeat(64), snapshotId: 'snapshot:bbb',
    assessmentPath: null, ...overrides,
  };
}

function _openEvent(overrides = {}) {
  return {
    type: 'opened', at: '2026-09-02T00:00:00.000Z', itemId: 'rem-1',
    id: 'rem-1', owner: 'alice', dueDate: '2026-10-01',
    recommendedControl: 'Encrypt the payload before the store write',
    assessment: _assessment(),
    affectedFlowIds: ['flow:1'], affectedNodeIds: ['node:deadbeef'], affectedEdgeIds: [],
    requiredEvidence: ['flow:1'], manualAttestationPermitted: false,
    ...overrides,
  };
}

// ── R1: vocabulary ────────────────────────────────────────────────────

test('R1/1: the state and event vocabularies are exactly the scoping doc\'s own lists, frozen', () => {
  assert.deepEqual([...REMEDIATION_STATES],
    ['open', 'in_progress', 'awaiting_verification', 'verified', 'accepted_risk', 'reopened']);
  assert.deepEqual([...REMEDIATION_EVENT_TYPES],
    ['opened', 'state_changed', 'scan_verification', 'manual_attestation', 'accepted_risk', 'reopened']);
  assert.ok(Object.isFrozen(REMEDIATION_STATES));
  assert.ok(Object.isFrozen(REMEDIATION_EVENT_TYPES));
});

test('R1/2: ACCEPTED_RISK_REQUIRED_FIELDS is PRD line 572\'s exact four-field list', () => {
  assert.deepEqual([...ACCEPTED_RISK_REQUIRED_FIELDS], ['approver', 'reason', 'scope', 'expiration']);
  assert.ok(Object.isFrozen(ACCEPTED_RISK_REQUIRED_FIELDS));
});

test('R1/3: this module is pure — zero imports, and no fs reference anywhere in its source', () => {
  const src = fs.readFileSync(path.resolve(HERE, '../../src/lineage/remediation.js'), 'utf8');
  const specifiers = [...src.matchAll(/^\s*import\s[^;]*?from\s*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.deepEqual(specifiers, [], 'remediation.js must import nothing — it is pure by contract');
  assert.equal(/\bimport\s*\(/.test(src), false, 'no dynamic import either');
  assert.equal(/node:fs|require\(/.test(src), false, 'no fs access of any kind');
});

// ── R2: foldRemediationItem ───────────────────────────────────────────

test('R2/1: an empty event list folds to null', () => {
  assert.equal(foldRemediationItem([]), null);
  assert.equal(foldRemediationItem(null), null);
});

test('R2/2: an event list whose first event is not `opened` folds to null', () => {
  assert.equal(foldRemediationItem([{ type: 'state_changed', state: 'in_progress' }]), null);
});

test('R2/3: an `opened` event alone folds to a fully-shaped item in state open', () => {
  const item = foldRemediationItem([_openEvent()]);
  assert.equal(item.id, 'rem-1');
  assert.equal(item.state, 'open');
  assert.equal(item.owner, 'alice');
  assert.equal(item.dueDate, '2026-10-01');
  assert.equal(item.assessment.graphDigest, 'f'.repeat(64));
  assert.equal(item.assessment.snapshotId, 'snapshot:bbb');
  assert.deepEqual(item.requiredEvidence, ['flow:1']);
  assert.deepEqual(item.affectedFlowIds, ['flow:1']);
  assert.equal(item.manualAttestationPermitted, false);
  assert.deepEqual(item.approvals, []);
  assert.deepEqual(item.exceptions, []);
  assert.equal(item.verificationSnapshotId, null);
  assert.equal(item.history.length, 1);
});

test('R2/4: state_changed events fold forward in order', () => {
  const item = foldRemediationItem([
    _openEvent(),
    { type: 'state_changed', at: '2026-09-03T00:00:00.000Z', itemId: 'rem-1', state: 'in_progress' },
    { type: 'state_changed', at: '2026-09-04T00:00:00.000Z', itemId: 'rem-1', state: 'awaiting_verification' },
  ]);
  assert.equal(item.state, 'awaiting_verification');
  assert.equal(item.history.length, 3);
});

test('R2/5: scan_verification with outcome verified sets state and verificationSnapshotId', () => {
  const item = foldRemediationItem([
    _openEvent(),
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'in_progress' },
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'awaiting_verification' },
    { type: 'scan_verification', at: 'x', itemId: 'rem-1', outcome: 'verified', snapshotId: 'snapshot:ccc' },
  ]);
  assert.equal(item.state, 'verified');
  assert.equal(item.verificationSnapshotId, 'snapshot:ccc');
});

test('R2/6: scan_verification with outcome unverifiable does NOT set verified and records no snapshot', () => {
  const item = foldRemediationItem([
    _openEvent(),
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'in_progress' },
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'awaiting_verification' },
    { type: 'scan_verification', at: 'x', itemId: 'rem-1', outcome: 'unverifiable', reason: 'possible_coverage_regression' },
  ]);
  assert.equal(item.state, 'awaiting_verification');
  assert.equal(item.verificationSnapshotId, null);
});

test('R2/7: manual_attestation sets verified AND pushes an approval that stays distinguishable', () => {
  const item = foldRemediationItem([
    _openEvent({ manualAttestationPermitted: true }),
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'in_progress' },
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'awaiting_verification' },
    { type: 'manual_attestation', at: 'x', itemId: 'rem-1', approver: 'bob', reason: 'control verified out of band' },
  ]);
  assert.equal(item.state, 'verified');
  assert.equal(item.verificationSnapshotId, null, 'a manual attestation supplies no scan evidence');
  assert.equal(item.approvals.length, 1);
  assert.equal(item.approvals[0].approver, 'bob');
  assert.equal(item.approvals[0].evidenceKind, 'manual',
    'PRD line 984: a manual attestation must remain distinguishable from scan evidence forever');
});

test('R2/8: accepted_risk sets accepted_risk and pushes an exception — never reads as verified', () => {
  const item = foldRemediationItem([
    _openEvent(),
    { type: 'accepted_risk', at: 'x', itemId: 'rem-1', approver: 'bob', reason: 'compensating control', scope: 'staging only', expiration: '2026-12-31' },
  ]);
  assert.equal(item.state, 'accepted_risk');
  assert.notEqual(item.state, 'verified');
  assert.equal(item.exceptions.length, 1);
  assert.equal(item.exceptions[0].expiration, '2026-12-31');
});

test('R2/9: reopened sets reopened and carries its reason into history', () => {
  const item = foldRemediationItem([
    _openEvent(),
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'in_progress' },
    { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'awaiting_verification' },
    { type: 'scan_verification', at: 'x', itemId: 'rem-1', outcome: 'verified', snapshotId: 'snapshot:ccc' },
    { type: 'reopened', at: 'x', itemId: 'rem-1', reason: 'drift policy pci-to-log fired on flow:1' },
  ]);
  assert.equal(item.state, 'reopened');
  assert.match(item.history[item.history.length - 1].reason, /drift policy/);
});

test('R2/10: the fold ignores hash-chain fields the ledger layer adds', () => {
  const item = foldRemediationItem([{ ..._openEvent(), prev: 'GENESIS' }]);
  assert.equal(item.state, 'open');
});

test('R2/11: foldRemediationItem never throws on malformed input', () => {
  for (const bad of [undefined, {}, 'x', [null], [{}], [{ type: 'opened' }]]) {
    assert.doesNotThrow(() => foldRemediationItem(bad));
  }
});

// ── R3: foldRemediationLedger ─────────────────────────────────────────

test('R3/1: groups a flat interleaved event stream by itemId, preserving per-group order', () => {
  const events = [
    _openEvent({ id: 'a', itemId: 'a' }),
    _openEvent({ id: 'b', itemId: 'b' }),
    { type: 'state_changed', at: 'x', itemId: 'a', state: 'in_progress' },
    { type: 'accepted_risk', at: 'x', itemId: 'b', approver: 'bob', reason: 'r', scope: 's', expiration: '2026-12-31' },
  ];
  const items = foldRemediationLedger(events);
  assert.deepEqual(Object.keys(items).sort(), ['a', 'b']);
  assert.equal(items.a.state, 'in_progress');
  assert.equal(items.b.state, 'accepted_risk');
});

test('R3/2: an event with no recognizable itemId is skipped, never crashes the whole fold', () => {
  const items = foldRemediationLedger([{ type: 'state_changed', state: 'in_progress' }, _openEvent()]);
  assert.deepEqual(Object.keys(items), ['rem-1']);
});

// ── R4: validateOpenPayload ───────────────────────────────────────────

test('R4/1: a well-formed open payload validates', () => {
  const { valid, errors } = validateOpenPayload(_openEvent());
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('R4/2: every required scalar is checked by name', () => {
  for (const field of ['id', 'owner', 'recommendedControl']) {
    const { valid, errors } = validateOpenPayload(_openEvent({ [field]: '' }));
    assert.equal(valid, false, `${field} must be required`);
    assert.ok(errors.some((e) => e.field === field), `error must name ${field}`);
  }
});

test('R4/3: dueDate must be a YYYY-MM-DD date', () => {
  for (const bad of ['', 'tomorrow', '2026-9-1', '2026/10/01', null]) {
    const { valid } = validateOpenPayload(_openEvent({ dueDate: bad }));
    assert.equal(valid, false, `dueDate ${JSON.stringify(bad)} must be rejected`);
  }
  assert.equal(validateOpenPayload(_openEvent({ dueDate: '2026-10-01' })).valid, true);
});

test('R4/4: every inline assessment identifying field is required (the scoping doc\'s §3 ruling)', () => {
  for (const field of ['assessmentId', 'targetId', 'targetKind', 'traceKind', 'scope', 'graphId', 'graphDigest', 'snapshotId']) {
    const { valid, errors } = validateOpenPayload(_openEvent({ assessment: _assessment({ [field]: '' }) }));
    assert.equal(valid, false, `assessment.${field} must be required`);
    assert.ok(errors.some((e) => e.field === `assessment.${field}`));
  }
  // assessmentPath is the one OPTIONAL inline field.
  assert.equal(validateOpenPayload(_openEvent({ assessment: _assessment({ assessmentPath: null }) })).valid, true);
});

test('R4/5: a missing assessment object is one clear error, not eight', () => {
  const { valid, errors } = validateOpenPayload(_openEvent({ assessment: null }));
  assert.equal(valid, false);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, 'assessment');
});

test('R4/6: requiredEvidence must be a non-empty array of non-empty strings', () => {
  for (const bad of [[], null, 'flow:1', [''], ['flow:1', 2]]) {
    assert.equal(validateOpenPayload(_openEvent({ requiredEvidence: bad })).valid, false,
      `requiredEvidence ${JSON.stringify(bad)} must be rejected`);
  }
});

test('R4/7: validateOpenPayload never throws', () => {
  for (const bad of [null, undefined, 'x', 42, []]) assert.doesNotThrow(() => validateOpenPayload(bad));
});

// ── R5: validateTransition — AC-31's own state machine ────────────────

const _open = () => foldRemediationItem([_openEvent()]);
const _inProgress = () => foldRemediationItem([_openEvent(), { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'in_progress' }]);
const _awaiting = () => foldRemediationItem([_openEvent(), { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'in_progress' }, { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'awaiting_verification' }]);
const _awaitingManualOk = () => foldRemediationItem([_openEvent({ manualAttestationPermitted: true }), { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'in_progress' }, { type: 'state_changed', at: 'x', itemId: 'rem-1', state: 'awaiting_verification' }]);
const _verified = () => foldRemediationItem([...(_awaiting().history), { type: 'scan_verification', at: 'x', itemId: 'rem-1', outcome: 'verified', snapshotId: 'snapshot:ccc' }]);
const _reopened = () => foldRemediationItem([...(_verified().history), { type: 'reopened', at: 'x', itemId: 'rem-1', reason: 'regressed' }]);
const _accepted = () => foldRemediationItem([_openEvent(), { type: 'accepted_risk', at: 'x', itemId: 'rem-1', approver: 'bob', reason: 'r', scope: 's', expiration: '2026-12-31' }]);

test('R5/1: `opened` is valid only when no item exists', () => {
  assert.equal(validateTransition(null, _openEvent()).valid, true);
  const r = validateTransition(_open(), _openEvent());
  assert.equal(r.valid, false);
  assert.match(r.errors[0].message, /already exists/i);
});

test('R5/2: every non-opened event against a null item is rejected', () => {
  for (const type of ['state_changed', 'scan_verification', 'manual_attestation', 'accepted_risk', 'reopened']) {
    const r = validateTransition(null, { type, itemId: 'rem-1', state: 'in_progress' });
    assert.equal(r.valid, false, `${type} against no item must be rejected`);
  }
});

test('R5/3: state_changed to in_progress is valid from open and from reopened only', () => {
  assert.equal(validateTransition(_open(), { type: 'state_changed', state: 'in_progress' }).valid, true);
  assert.equal(validateTransition(_reopened(), { type: 'state_changed', state: 'in_progress' }).valid, true);
  for (const from of [_inProgress(), _awaiting(), _verified(), _accepted()]) {
    assert.equal(validateTransition(from, { type: 'state_changed', state: 'in_progress' }).valid, false,
      `in_progress must be rejected from ${from.state}`);
  }
});

test('R5/4: state_changed to awaiting_verification is valid from in_progress only', () => {
  assert.equal(validateTransition(_inProgress(), { type: 'state_changed', state: 'awaiting_verification' }).valid, true);
  for (const from of [_open(), _awaiting(), _verified(), _accepted(), _reopened()]) {
    assert.equal(validateTransition(from, { type: 'state_changed', state: 'awaiting_verification' }).valid, false,
      `awaiting_verification must be rejected from ${from.state}`);
  }
});

test('R5/5 (AC-31, THE load-bearing rule): state_changed to `verified` is rejected unconditionally, from EVERY state', () => {
  for (const from of [null, _open(), _inProgress(), _awaiting(), _verified(), _accepted(), _reopened()]) {
    const r = validateTransition(from, { type: 'state_changed', state: 'verified' });
    assert.equal(r.valid, false,
      `marking work complete must never reach verified (from ${from ? from.state : 'null'}) — AC-31's own then-clause, PRD line 171`);
    assert.match(r.errors[0].message, /scan_verification|manual_attestation/,
      'the rejection must name the only two events that can reach verified');
  }
});

test('R5/6: state_changed to any other state value is rejected', () => {
  for (const state of ['accepted_risk', 'reopened', 'open', 'nonsense', '', null]) {
    assert.equal(validateTransition(_inProgress(), { type: 'state_changed', state }).valid, false,
      `state_changed to ${JSON.stringify(state)} must be rejected`);
  }
});

test('R5/7: scan_verification is valid from awaiting_verification only, and requires a real outcome', () => {
  assert.equal(validateTransition(_awaiting(), { type: 'scan_verification', outcome: 'verified', snapshotId: 'snapshot:ccc' }).valid, true);
  assert.equal(validateTransition(_awaiting(), { type: 'scan_verification', outcome: 'unverifiable', reason: 'flows_still_present' }).valid, true);
  assert.equal(validateTransition(_awaiting(), { type: 'scan_verification', outcome: 'verified' }).valid, false,
    'outcome verified requires a snapshotId');
  assert.equal(validateTransition(_awaiting(), { type: 'scan_verification', outcome: 'maybe' }).valid, false);
  for (const from of [_open(), _inProgress(), _verified(), _accepted(), _reopened()]) {
    assert.equal(validateTransition(from, { type: 'scan_verification', outcome: 'verified', snapshotId: 's' }).valid, false,
      `scan_verification must be rejected from ${from.state}`);
  }
});

test('R5/8: manual_attestation requires awaiting_verification AND manualAttestationPermitted', () => {
  assert.equal(validateTransition(_awaitingManualOk(), { type: 'manual_attestation', approver: 'bob', reason: 'r' }).valid, true);
  const r = validateTransition(_awaiting(), { type: 'manual_attestation', approver: 'bob', reason: 'r' });
  assert.equal(r.valid, false);
  assert.match(r.errors[0].message, /manualAttestationPermitted|--allow-manual-attestation/);
  assert.equal(validateTransition(_awaitingManualOk(), { type: 'manual_attestation', approver: '', reason: 'r' }).valid, false);
  assert.equal(validateTransition(_awaitingManualOk(), { type: 'manual_attestation', approver: 'bob' }).valid, false);
});

test('R5/9: accepted_risk is valid from every non-terminal state and requires all four fields', () => {
  const payload = { type: 'accepted_risk', approver: 'bob', reason: 'r', scope: 's', expiration: '2026-12-31' };
  for (const from of [_open(), _inProgress(), _awaiting(), _reopened()]) {
    assert.equal(validateTransition(from, payload).valid, true, `accepted_risk must be valid from ${from.state}`);
  }
  for (const from of [_verified(), _accepted()]) {
    assert.equal(validateTransition(from, payload).valid, false, `accepted_risk must be rejected from ${from.state}`);
  }
  for (const field of ACCEPTED_RISK_REQUIRED_FIELDS) {
    const r = validateTransition(_open(), { ...payload, [field]: '' });
    assert.equal(r.valid, false, `accepted_risk must require ${field}`);
    assert.ok(r.errors.some((e) => e.field === field));
  }
});

test('R5/10: reopened is valid from verified only, and always carries a reason', () => {
  assert.equal(validateTransition(_verified(), { type: 'reopened', reason: 'flow reappeared' }).valid, true);
  assert.equal(validateTransition(_verified(), { type: 'reopened' }).valid, false,
    'an automatic reopen must always name what triggered it');
  for (const from of [_open(), _inProgress(), _awaiting(), _accepted(), _reopened()]) {
    assert.equal(validateTransition(from, { type: 'reopened', reason: 'x' }).valid, false,
      `reopened must be rejected from ${from.state}`);
  }
});

test('R5/11: an unrecognized event type is rejected with a clear message, never silently accepted', () => {
  const r = validateTransition(_open(), { type: 'closed' });
  assert.equal(r.valid, false);
  assert.match(r.errors[0].message, /closed/);
});

test('R5/12: validateTransition never throws', () => {
  for (const bad of [null, undefined, 'x', {}, 42]) {
    assert.doesNotThrow(() => validateTransition(_open(), bad));
    assert.doesNotThrow(() => validateTransition(bad, { type: 'reopened', reason: 'x' }));
  }
});

// ── R6: evaluateVerificationEvidence ──────────────────────────────────
// Shapes verified directly against graph-diff.js:135-152 (_removedEntry)
// and :250-256 (changedFlows) — not guessed.

function _diff({ removedFlows = [], changedFlows = [] } = {}) {
  return {
    added: { nodes: [], edges: [], dataElements: [], flows: [] },
    removed: { nodes: [], edges: [], dataElements: [], flows: removedFlows },
    changed: { flows: changedFlows },
  };
}

test('R6/1: every required flow genuinely removed by an application change verifies', () => {
  const d = _diff({ removedFlows: [
    { id: 'flow:1', causeClassification: 'application_change' },
    { id: 'flow:2', causeClassification: 'application_change' },
  ] });
  assert.deepEqual(evaluateVerificationEvidence(d, ['flow:1', 'flow:2']), { outcome: 'verified' });
});

test('R6/2 (PRD line 1975): a coverage regression refuses the WHOLE verification, immediately', () => {
  const d = _diff({ removedFlows: [
    { id: 'flow:1', causeClassification: 'possible_coverage_regression', coverageRegressionReasons: ['sources.matched decreased (9 -> 4)'] },
    { id: 'flow:2', causeClassification: 'application_change' },
  ] });
  const r = evaluateVerificationEvidence(d, ['flow:1', 'flow:2']);
  assert.equal(r.outcome, 'unverifiable');
  assert.equal(r.reason, 'possible_coverage_regression');
  assert.equal(r.flowId, 'flow:1');
  assert.deepEqual(r.coverageRegressionReasons, ['sources.matched decreased (9 -> 4)']);
  assert.equal(r.unsatisfiedFlowIds, undefined, 'an incomplete scan taints the whole verification — no partial answer');
});

test('R6/3: a reidentified flow is unverifiable — a refactor is not a fix', () => {
  const d = _diff({ removedFlows: [{ id: 'flow:1', causeClassification: 'reidentified', reidentifiedTo: 'flow:9' }] });
  const r = evaluateVerificationEvidence(d, ['flow:1']);
  assert.equal(r.outcome, 'unverifiable');
  assert.equal(r.reason, 'reidentified');
  assert.equal(r.reidentifiedTo, 'flow:9');
});

test('R6/4: a flow still present is unverifiable, and EVERY unsatisfied id is reported', () => {
  const d = _diff({ removedFlows: [{ id: 'flow:2', causeClassification: 'application_change' }] });
  const r = evaluateVerificationEvidence(d, ['flow:1', 'flow:2', 'flow:3']);
  assert.equal(r.outcome, 'unverifiable');
  assert.equal(r.reason, 'flows_still_present');
  assert.deepEqual(r.unsatisfiedFlowIds, ['flow:1', 'flow:3'], 'never short-circuit on the first unsatisfied id');
});

test('R6/5 (scope narrowing, deliberate): a flow that merely became MORE PROTECTED does not verify', () => {
  const d = _diff({ changedFlows: [{
    id: 'flow:1', causeClassification: 'application_change',
    changes: [{ field: 'protectionSummary', before: 'unprotected', after: 'protected' }],
  }] });
  const r = evaluateVerificationEvidence(d, ['flow:1']);
  assert.equal(r.outcome, 'unverifiable');
  assert.equal(r.reason, 'flows_still_present');
  assert.deepEqual(r.unsatisfiedFlowIds, ['flow:1'],
    'the "improving transition" heuristic is explicitly out of scope for this first cut — see the module comment');
});

test('R6/6: an empty requiredEvidence list can never verify', () => {
  const r = evaluateVerificationEvidence(_diff(), []);
  assert.equal(r.outcome, 'unverifiable');
  assert.equal(r.reason, 'no_required_evidence');
});

test('R6/7: evaluateVerificationEvidence never throws on a malformed diff', () => {
  for (const bad of [null, undefined, {}, { removed: null }, { removed: { flows: null } }, 'x']) {
    assert.doesNotThrow(() => evaluateVerificationEvidence(bad, ['flow:1']));
    assert.equal(evaluateVerificationEvidence(bad, ['flow:1']).outcome, 'unverifiable');
  }
});
