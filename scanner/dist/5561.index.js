export const id = 5561;
export const ids = [5561];
export const modules = {

/***/ 5561:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   evaluateVerificationEvidence: () => (/* binding */ evaluateVerificationEvidence),
/* harmony export */   foldRemediationLedger: () => (/* binding */ foldRemediationLedger),
/* harmony export */   validateOpenPayload: () => (/* binding */ validateOpenPayload),
/* harmony export */   validateTransition: () => (/* binding */ validateTransition)
/* harmony export */ });
/* unused harmony exports REMEDIATION_STATES, REMEDIATION_EVENT_TYPES, ACCEPTED_RISK_REQUIRED_FIELDS, foldRemediationItem */
// remediation.js — M5 deliverable #6 (Blast-Radius: Remediation Command
// Center, FR-507 + AC-31): the pure RemediationItem contract, its event
// fold, its state machine, and the verification-evidence decision.
//
// Pure by contract — zero imports, no fs, no I/O of any kind, never
// throws. The ledger layer (`posture/remediation-ledger.js`, Task 2 of
// this same sub-project) owns every side effect: file locking, append,
// tolerant read, hash chaining. This module mirrors `governance-edit.js`'s
// own split (that module's own header makes the identical claim for its
// own CLI-write boundary) and the "pure data + pure functions, boundary-
// tested" precedent `flow-grade.js`/`obligation-mapping.js` already set
// in this package.
//
// ── The `verified`-unreachable-from-`state_changed` rule (AC-31) ──────
//
// AC-31's own `then`-clause requires that marking remediation work
// "done" can NEVER, by itself, mark a finding verified — only a real
// scan re-confirming the flow is gone (`scan_verification`) or an
// explicitly-permitted, explicitly-attributed manual attestation
// (`manual_attestation`) may transition an item into `verified`. PRD
// line 171 states the same rule as an explicit non-goal: this deliverable
// must never let "I fixed it" (a human claim) substitute for "the scanner
// re-observed the flow is gone" (an evidence-backed claim) without an
// explicit, auditable manual-attestation opt-in. `validateTransition`
// enforces this by rejecting `state_changed` with `state: 'verified'`
// FIRST, before even looking at the item's current state — the rejection
// is therefore genuinely unconditional, not just unreached from the
// states this module happens to reach today.
//
// ── Deliberate scope narrowing in evaluateVerificationEvidence ────────
//
// A required-evidence flow id is treated as SATISFIED only when it
// appears in `diff.removed.flows` with `causeClassification ===
// 'application_change'` — i.e. the flow is genuinely gone from the graph
// and its disappearance is attributable to an application change, not to
// the scanner simply seeing less than it used to. A flow that is still
// PRESENT in the graph but has merely become MORE PROTECTED (e.g. its
// `protectionSummary` moved from `unprotected` to `protected` — visible
// only as a `changed.flows` entry, never a `removed.flows` entry) is
// explicitly OUT OF SCOPE for this first cut: recognizing an "improving
// transition" as evidence of a fix needs its own deliberate, disclosed
// heuristic (what counts as "protected enough", whether a policy verdict
// change alone should count, etc.) that this module does not attempt.
// A future increment could add it; until then, such a flow reports
// `flows_still_present`, same as a flow with no change at all.
//
// `possible_coverage_regression` is computed DIFF-WIDE by
// `computeGraphDiff` (see `graph-diff.js:328`'s own
// `coverageRegressionReasons`/`flowRemovalCause` — every removed flow in
// one diff shares the SAME cause once any completeness signal regressed)
// — which is why a coverage-regression hit on any of the item's OWN
// required-evidence flows refuses the WHOLE verification immediately (PRD
// line 1975), rather than letting other, seemingly-clean required-
// evidence flows in the same diff verify: an incomplete scan cannot be
// trusted to have honestly seen everything it claims to have not seen.
// (The loop below only ever inspects `diff.removed.flows` entries for
// flows actually named in `requiredEvidenceFlowIds` — an unrelated
// removed flow elsewhere in the same diff is never consulted.)

const REMEDIATION_STATES = Object.freeze([
  'open', 'in_progress', 'awaiting_verification', 'verified', 'accepted_risk', 'reopened',
]);

const REMEDIATION_EVENT_TYPES = Object.freeze([
  'opened', 'state_changed', 'scan_verification', 'manual_attestation', 'accepted_risk', 'reopened',
]);

// PRD line 572's exact four-field list (scoping doc §4.3).
const ACCEPTED_RISK_REQUIRED_FIELDS = Object.freeze(['approver', 'reason', 'scope', 'expiration']);

function _isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function _isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// ── foldRemediationItem / foldRemediationLedger ────────────────────────

/**
 * Folds an ordered event list for ONE remediation item into its current
 * shape, or `null` for an empty/malformed/non-`opened`-first list. Never
 * throws.
 */
function foldRemediationItem(events) {
  if (!Array.isArray(events) || events.length === 0) return null;
  const openEvent = events[0];
  if (!openEvent || openEvent.type !== 'opened') return null;

  const item = {
    id: openEvent.id,
    state: 'open',
    owner: openEvent.owner,
    dueDate: openEvent.dueDate,
    recommendedControl: openEvent.recommendedControl,
    assessment: openEvent.assessment,
    affectedFlowIds: openEvent.affectedFlowIds,
    affectedNodeIds: openEvent.affectedNodeIds,
    affectedEdgeIds: openEvent.affectedEdgeIds,
    requiredEvidence: openEvent.requiredEvidence,
    manualAttestationPermitted: openEvent.manualAttestationPermitted,
    approvals: [],
    exceptions: [],
    verificationSnapshotId: null,
    history: events,
  };

  for (let i = 1; i < events.length; i++) {
    const ev = events[i];
    if (!ev || typeof ev !== 'object') continue;
    switch (ev.type) {
      case 'state_changed':
        item.state = ev.state;
        break;
      case 'scan_verification':
        if (ev.outcome === 'verified') {
          item.state = 'verified';
          item.verificationSnapshotId = ev.snapshotId;
        }
        // an 'unverifiable' outcome changes neither state nor snapshot.
        break;
      case 'manual_attestation':
        item.state = 'verified';
        item.approvals.push({
          approver: ev.approver, reason: ev.reason, at: ev.at, evidenceKind: 'manual',
        });
        // Records a real baseline (final-review fix round 1, Blocking-3):
        // without this, a manually-attested item keeps whatever STALE
        // `verificationSnapshotId` it happened to carry (or `null`,
        // falling back to an even less defensible baseline) forever, and
        // `reopen-check` keeps diffing from that stale anchor — reopening
        // a just-permitted attestation on the very next run even though
        // nothing changed. `ev.snapshotId` is optional (a manual
        // attestation before any lineage scan has ever run is legitimate).
        if (ev.snapshotId) item.verificationSnapshotId = ev.snapshotId;
        break;
      case 'accepted_risk':
        item.state = 'accepted_risk';
        item.exceptions.push({
          approver: ev.approver, reason: ev.reason, scope: ev.scope, expiration: ev.expiration, at: ev.at,
        });
        break;
      case 'reopened':
        item.state = 'reopened';
        // Retires the stale anchor (final-review fix round 1, Blocking-3)
        // so it cannot outlive the verification it belonged to — the next
        // verification (scan or manual) must establish its own baseline.
        item.verificationSnapshotId = null;
        break;
      default:
        // an unrecognized event type is ignored by the fold — validation
        // of proposed events is validateTransition's job, not this one's.
        break;
    }
  }

  return item;
}

/**
 * Groups a flat, interleaved event stream by item id (`ev.itemId`,
 * falling back to `ev.id` on an `opened` event that carries only `id`),
 * preserving per-group insertion order, and folds each group. Events with
 * no resolvable item id are skipped. Groups that fold to `null` are
 * dropped. Never throws.
 */
function foldRemediationLedger(allEvents) {
  const result = {};
  if (!Array.isArray(allEvents)) return result;

  const groups = new Map();
  for (const ev of allEvents) {
    if (!ev || typeof ev !== 'object') continue;
    const itemId = ev.itemId ?? (ev.type === 'opened' ? ev.id : undefined);
    if (!_isNonEmptyString(itemId)) continue;
    if (!groups.has(itemId)) groups.set(itemId, []);
    groups.get(itemId).push(ev);
  }

  for (const [itemId, events] of groups) {
    const item = foldRemediationItem(events);
    if (item !== null) result[itemId] = item;
  }

  return result;
}

// ── validateOpenPayload ─────────────────────────────────────────────────

const _REQUIRED_ASSESSMENT_FIELDS = [
  'assessmentId', 'targetId', 'targetKind', 'traceKind', 'scope', 'graphId', 'graphDigest', 'snapshotId',
];

const _DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Validates an `opened`-event-shaped payload. Returns `{valid, errors}`,
 * `errors` as `[{field, message}]`. Never throws.
 */
function validateOpenPayload(payload) {
  const errors = [];
  const err = (field, message) => errors.push({ field, message });

  if (!_isPlainObject(payload)) {
    err('(payload)', 'payload must be an object');
    return { valid: false, errors };
  }

  for (const field of ['id', 'owner', 'recommendedControl']) {
    if (!_isNonEmptyString(payload[field])) err(field, `${field} is required and must be a non-empty string`);
  }

  if (!_isNonEmptyString(payload.dueDate) || !_DATE_RE.test(payload.dueDate)) {
    err('dueDate', 'dueDate is required and must be a YYYY-MM-DD date');
  }

  if (!_isPlainObject(payload.assessment)) {
    err('assessment', 'assessment is required and must be an object');
  } else {
    for (const field of _REQUIRED_ASSESSMENT_FIELDS) {
      if (!_isNonEmptyString(payload.assessment[field])) {
        err(`assessment.${field}`, `assessment.${field} is required and must be a non-empty string`);
      }
    }
    // assessmentPath is the one OPTIONAL inline field — no check.
  }

  const evidence = payload.requiredEvidence;
  if (!Array.isArray(evidence) || evidence.length === 0 || !evidence.every(_isNonEmptyString)) {
    err('requiredEvidence', 'requiredEvidence is required and must be a non-empty array of non-empty strings');
  }

  return { valid: errors.length === 0, errors };
}

// ── validateTransition — AC-31's own state machine ──────────────────────

/**
 * Validates a proposed event against a remediation item's current state
 * (or `null` for no item yet). Returns `{valid, errors}`, `errors` as
 * `[{field, message}]`. Never throws.
 */
function validateTransition(item, proposedEvent) {
  const errors = [];
  const err = (field, message) => errors.push({ field, message });

  if (!_isPlainObject(proposedEvent)) {
    err('(event)', 'proposed event must be an object');
    return { valid: false, errors };
  }

  const type = proposedEvent.type;

  if (type === 'opened') {
    if (item !== null && item !== undefined) {
      err('type', 'a remediation item with this id already exists — opened is only valid when no item exists');
      return { valid: false, errors };
    }
    return { valid: true, errors: [] };
  }

  // AC-31's own load-bearing rule: state_changed can never reach
  // `verified`. Checked FIRST, before even the "item must exist" check
  // below, so the rejection is genuinely unconditional — reachable from
  // no state at all, including no item — and cannot be routed around by
  // any current state. See this file's own header.
  if (type === 'state_changed' && proposedEvent.state === 'verified') {
    err('state', 'state_changed can never reach verified — only scan_verification or manual_attestation may');
    return { valid: false, errors };
  }

  // Every other event type requires an existing item.
  if (!_isPlainObject(item)) {
    err('type', `${type} is not valid against no item — open the item first`);
    return { valid: false, errors };
  }

  switch (type) {
    case 'state_changed': {
      if (proposedEvent.state === 'in_progress') {
        if (item.state !== 'open' && item.state !== 'reopened') {
          err('state', `state_changed to in_progress is only valid from open or reopened, not ${item.state}`);
        }
      } else if (proposedEvent.state === 'awaiting_verification') {
        if (item.state !== 'in_progress') {
          err('state', `state_changed to awaiting_verification is only valid from in_progress, not ${item.state}`);
        }
      } else {
        err('state', `state_changed to ${JSON.stringify(proposedEvent.state)} is not a recognized transition`);
      }
      break;
    }

    case 'scan_verification': {
      if (item.state !== 'awaiting_verification') {
        err('type', `scan_verification is only valid from awaiting_verification, not ${item.state}`);
        break;
      }
      if (proposedEvent.outcome === 'verified') {
        if (!_isNonEmptyString(proposedEvent.snapshotId)) {
          err('snapshotId', 'a verified outcome requires a snapshotId');
        }
      } else if (proposedEvent.outcome === 'unverifiable') {
        // no further requirement beyond the outcome itself.
      } else {
        err('outcome', `outcome ${JSON.stringify(proposedEvent.outcome)} is not a recognized scan_verification outcome`);
      }
      break;
    }

    case 'manual_attestation': {
      if (item.state !== 'awaiting_verification') {
        err('type', `manual_attestation is only valid from awaiting_verification, not ${item.state}`);
        break;
      }
      if (!item.manualAttestationPermitted) {
        err('manualAttestationPermitted', 'manual attestation is not permitted for this item — it must be opened with --allow-manual-attestation to allow one (open a new item if this one predates that need)');
        break;
      }
      if (!_isNonEmptyString(proposedEvent.approver)) err('approver', 'manual_attestation requires a non-empty approver');
      if (!_isNonEmptyString(proposedEvent.reason)) err('reason', 'manual_attestation requires a non-empty reason');
      break;
    }

    case 'accepted_risk': {
      if (item.state === 'verified' || item.state === 'accepted_risk') {
        err('type', `accepted_risk is not valid from ${item.state}`);
        break;
      }
      for (const field of ACCEPTED_RISK_REQUIRED_FIELDS) {
        if (!_isNonEmptyString(proposedEvent[field])) {
          err(field, `accepted_risk requires a non-empty ${field}`);
        }
      }
      break;
    }

    case 'reopened': {
      if (item.state !== 'verified') {
        err('type', `reopened is only valid from verified, not ${item.state}`);
        break;
      }
      if (!_isNonEmptyString(proposedEvent.reason)) {
        err('reason', 'reopened must always carry a non-empty reason naming what triggered it');
      }
      break;
    }

    default:
      err('type', `${JSON.stringify(type)} is not a recognized remediation event type`);
      break;
  }

  return { valid: errors.length === 0, errors };
}

// ── evaluateVerificationEvidence ────────────────────────────────────────

/**
 * Decides whether a GraphDiff's real, checkable evidence satisfies every
 * flow id a remediation item required evidence for. See this file's own
 * header for the deliberate scope narrowing and the coverage-regression
 * whole-verification-refusal rule. Never throws.
 */
function evaluateVerificationEvidence(diff, requiredEvidenceFlowIds) {
  if (!Array.isArray(requiredEvidenceFlowIds) || requiredEvidenceFlowIds.length === 0) {
    return { outcome: 'unverifiable', reason: 'no_required_evidence' };
  }

  const removedFlows = diff?.removed?.flows;
  const removedById = new Map();
  if (Array.isArray(removedFlows)) {
    for (const entry of removedFlows) {
      if (entry && typeof entry.id === 'string') removedById.set(entry.id, entry);
    }
  }

  const unsatisfiedFlowIds = [];

  for (const flowId of requiredEvidenceFlowIds) {
    const entry = removedById.get(flowId);
    const cause = entry?.causeClassification;

    if (cause === 'possible_coverage_regression') {
      return {
        outcome: 'unverifiable',
        reason: 'possible_coverage_regression',
        flowId,
        coverageRegressionReasons: entry.coverageRegressionReasons,
      };
    }

    if (cause === 'reidentified') {
      return {
        outcome: 'unverifiable',
        reason: 'reidentified',
        flowId,
        reidentifiedTo: entry.reidentifiedTo,
      };
    }

    if (cause === 'application_change') {
      continue; // satisfied
    }

    // Absent from removed.flows entirely, or an unrecognized
    // classification — either way, not satisfied.
    unsatisfiedFlowIds.push(flowId);
  }

  if (unsatisfiedFlowIds.length > 0) {
    return { outcome: 'unverifiable', reason: 'flows_still_present', unsatisfiedFlowIds };
  }

  return { outcome: 'verified' };
}


/***/ })

};
