export const id = 2432;
export const ids = [2432,5561];
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
// — which is why a single coverage-regression hit on ANY removed flow
// refuses the WHOLE verification immediately (PRD line 1975), rather than
// letting other, seemingly-clean flows in the same diff verify: an
// incomplete scan cannot be trusted to have honestly seen everything it
// claims to have not seen.

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
        break;
      case 'accepted_risk':
        item.state = 'accepted_risk';
        item.exceptions.push({
          approver: ev.approver, reason: ev.reason, scope: ev.scope, expiration: ev.expiration, at: ev.at,
        });
        break;
      case 'reopened':
        item.state = 'reopened';
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
        err('manualAttestationPermitted', 'manual attestation is not permitted for this item — reopen with --allow-manual-attestation to permit it');
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


/***/ }),

/***/ 2432:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   appendLedgerEvent: () => (/* binding */ appendLedgerEvent),
/* harmony export */   latestEventHash: () => (/* binding */ latestEventHash),
/* harmony export */   ledgerPaths: () => (/* binding */ ledgerPaths),
/* harmony export */   readLedgerEvents: () => (/* binding */ readLedgerEvents)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_fs_promises__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1455);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(7598);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(1174);
/* harmony import */ var _lineage_remediation_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(5561);
// remediation-ledger.js — M5 deliverable #6 (Blast-Radius: Remediation
// Command Center, FR-507 + AC-31), Task 2 of the sub-project: the IMPURE
// half. `../lineage/remediation.js` (Task 1) ships the pure RemediationItem
// contract — zero imports, no fs, never throws. This module owns every side
// effect that contract needs to become a real, durable, tamper-evident
// record: file locking, JSONL append, tolerant read, and the hash chain.
//
// This is the SECOND `posture/` → `lineage/` import in the codebase
// (`auditor-walkthrough.js`'s `graph:` branch was the first, per
// `posture/CLAUDE.md`'s "First `posture/` → `lineage/` import" section) —
// noted here so the boundary stays a deliberate, documented exception
// rather than an accident.
//
// ── The append-only contract (PRD line 984) ──────────────────────────────
//
// A remediation item's history is never rewritten, only appended to. Every
// decision — owner assignment, a state change, a manual attestation, an
// accepted-risk exception — is a permanent event, never an edit of a prior
// one. `foldRemediationItem`/`foldRemediationLedger` (Task 1) derive an
// item's CURRENT shape by replaying its events forward; nothing here ever
// mutates a written line.
//
// ── Why the physical shape is a JSONL append, not a whole-file rewrite ────
//
// `fix-metrics.js:69`'s `recordFixAttempt` is the precedent this module
// follows: "One writeSync of one newline-terminated line: a concurrent
// reader sees whole records or nothing, and a torn tail is dropped on
// read." `provenance/lifecycle.js:195`'s `updateLifecycle`, by contrast,
// reads the WHOLE store into memory, folds one scan's worth of changes in,
// and rewrites the WHOLE file — safe there because a lifecycle update is a
// single scan touching potentially every finding at once. A remediation
// ledger is the opposite shape: a human, one item at a time, arbitrarily
// interleaved with edits to every OTHER item. A partial rewrite of a shared
// document risks losing every OTHER item's history to a crash or a bug
// mid-rewrite; an append can only ever add a new, independently-readable
// line.
//
// ── Why a lock is still required, despite the append itself being atomic ──
//
// `fs.appendFileSync` of one line is atomic at the OS level, but writing an
// event is not just "append a line" — it is a READ-MODIFY-WRITE: the
// proposed event must be validated (`validateTransition`) against the
// item's CURRENT folded state, which requires reading and folding every
// prior event first. Two concurrent callers each reading the same "before"
// state and then both appending could both validate against a state that
// is stale by the time either write lands — e.g. two racing attempts to
// open the same item, both seeing "no item yet" and both succeeding, when
// exactly one must win. The lock serializes the whole
// read-fold-validate-append sequence into one critical section per event.
//
// `withLock` below is a faithful local PORT of
// `provenance/lifecycle.js:36`'s own `withLock` — NOT an import, because
// that function is not exported (verified directly against the file: it is
// a bare, module-private `async function withLock`). `isProcessAlive` is
// ported alongside it for the same reason.
//
// ── The hash chain ─────────────────────────────────────────────────────
//
// Byte-identical in behavior to `mcp/audit.js`'s own chain (`_sha`,
// `GENESIS`, `_readLastEntryHash`, `verifyAuditLog`, verified directly
// against that file before writing this one): each event carries `prev`,
// the SHA-256 hex digest of the PREVIOUS line's exact serialized JSON text
// (including that line's own `prev` field). The first event's `prev` is
// the literal string `'GENESIS'`. `readLedgerEvents`/`latestEventHash`
// walk forward from GENESIS; a line that fails to `JSON.parse` (a torn
// tail) or whose `prev` does not match the expected running hash (tamper)
// STOPS the walk. Both functions therefore return the longest verifying
// PREFIX of the file — never the full stream when any of it is
// unverifiable, and never a thrown error. See `_walkLedger` below, which
// both exported readers share so they cannot silently disagree on what
// "the last valid line" means.
//
// `appendLedgerEvent` is async and is the SINGLE place `validateTransition`
// is called in this codebase. No CLI command (Task 3) computes validity
// for itself — every proposed event is validated at this one write
// boundary, inside the lock, against the real current folded state.








const GENESIS = 'GENESIS';

function _sha(s) {
  return node_crypto__WEBPACK_IMPORTED_MODULE_3__.createHash('sha256').update(s).digest('hex');
}

function ledgerPaths(scanRoot) {
  return {
    ledgerPath: (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_4__.statePath)(scanRoot, 'remediation', 'items.jsonl'),
    lockPath: (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_4__.statePath)(scanRoot, 'remediation', 'items.lock'),
  };
}

// Shared walk: reads the ledger file (missing → empty), splits on '\n',
// drops empty lines, and walks forward maintaining `expectedPrev` (starting
// at GENESIS) exactly as `mcp/audit.js`'s `verifyAuditLog` does. A parse
// failure or a `prev` mismatch stops the walk without throwing. Returns
// `{events, lastHash}` so `readLedgerEvents`/`latestEventHash` cannot drift
// apart on what "the last valid line" means.
function _walkLedger(scanRoot) {
  const { ledgerPath } = ledgerPaths(scanRoot);
  let raw;
  try {
    raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(ledgerPath, 'utf8');
  } catch {
    return { events: [], lastHash: GENESIS };
  }
  const lines = raw.split('\n').filter(Boolean);
  const events = [];
  let expectedPrev = GENESIS;
  let lastHash = GENESIS;
  for (const line of lines) {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      break; // torn tail — stop, do not throw
    }
    if (!event || typeof event !== 'object' || Array.isArray(event) || event.prev !== expectedPrev) {
      break; // tamper detected — stop, do not throw
    }
    events.push(event);
    lastHash = _sha(line);
    expectedPrev = lastHash;
  }
  return { events, lastHash };
}

// Returns the longest verifying PREFIX of the ledger — never the full
// stream when a tail is torn or a middle line is tampered. Never throws.
function readLedgerEvents(scanRoot) {
  return _walkLedger(scanRoot).events;
}

// GENESIS when the ledger is empty/missing, or when nothing in it verifies.
function latestEventHash(scanRoot) {
  return _walkLedger(scanRoot).lastHash;
}

function isProcessAlive(pid) {
  // POSIX: process.kill(pid, 0) probes existence without sending a signal.
  // EPERM also means the process exists; only ESRCH means dead.
  try { process.kill(pid, 0); return true; }
  catch (e) { return e && e.code === 'EPERM'; }
}

// Faithful local port of `provenance/lifecycle.js:36-88`'s `withLock` — not
// an import, since that function is module-private there. Exclusive `wx`
// open of the lockfile, write the PID, run `fn` in a `try`, `unlink` in
// `finally`. On EEXIST, a stale lock (holding PID not alive, or lockfile
// older than 30s) is reaped, re-reading the lockfile before unlinking so a
// fresh holder taken by another process in the meantime is never raced.
// 25ms retry; 5s timeout throwing a named error.
async function withLock(lockPath, fn) {
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(lockPath), { recursive: true });
  const start = Date.now();
  const TIMEOUT_MS = 5000;
  while (true) {
    try {
      const handle = await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.open(lockPath, 'wx');
      await handle.writeFile(String(process.pid));
      try { await handle.close(); } catch {}
      try {
        return await fn();
      } finally {
        await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.unlink(lockPath).catch(() => {});
      }
    } catch (e) {
      if (e && e.code === 'EEXIST') {
        try {
          const [st, pidStr] = await Promise.all([
            node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.stat(lockPath),
            node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.readFile(lockPath, 'utf8').catch(() => ''),
          ]);
          const pid = parseInt(pidStr.trim(), 10);
          const pidAlive = Number.isFinite(pid) && isProcessAlive(pid);
          const old = Date.now() - st.mtimeMs > 30000;
          if (!pidAlive || old) {
            try {
              // Only unlink if the lockfile still holds the PID we just
              // read, so we don't race the unlink against a fresh lock
              // taken by another process in the meantime.
              const recheck = (await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.readFile(lockPath, 'utf8').catch(() => '')).trim();
              if (recheck === pidStr.trim()) {
                await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.unlink(lockPath);
              }
            } catch {}
            continue;
          }
        } catch {}
        if (Date.now() - start > TIMEOUT_MS) throw new Error('remediation-ledger: lock timed out');
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      throw e;
    }
  }
}

// Resolves the itemId a proposed event refers to, mirroring
// `foldRemediationLedger`'s own grouping fallback exactly (Task 1's
// `../lineage/remediation.js`: `ev.itemId ?? (ev.type === 'opened' ?
// ev.id : undefined)`) — an `opened` event carries `id` (per
// `foldRemediationItem`'s own use of `openEvent.id`), every other event
// type carries `itemId`. Reusing the identical fallback here, rather than
// reading `eventPayload.itemId` alone, is what makes item resolution agree
// with how the ledger will actually be folded on read — an opened event
// for an id that already exists must resolve to that existing item, not
// silently miss it because the payload only carries `id`.
function _resolveItemId(eventPayload) {
  if (!eventPayload || typeof eventPayload !== 'object') return undefined;
  return eventPayload.itemId ?? (eventPayload.type === 'opened' ? eventPayload.id : undefined);
}

// This function is the single place `validateTransition` is called. No CLI
// command computes validity for itself.
async function appendLedgerEvent(scanRoot, eventPayload) {
  const { ledgerPath, lockPath } = ledgerPaths(scanRoot);
  const dir = node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(ledgerPath);

  // Refused BEFORE the lock is taken, so an unsafe/disabled target never
  // even gets a lockfile written into it.
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_4__.isSafeStateDir)(dir)) {
    return {
      valid: false,
      errors: [{ field: '(scanRoot)', message: 'refusing to write — not a recognized project state directory' }],
    };
  }
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_4__.stateWritesEnabled)()) {
    return {
      valid: false,
      errors: [{ field: '(state)', message: 'state writes are disabled (AGENTIC_SECURITY_NO_STATE or setStateWritesEnabled(false))' }],
    };
  }

  return withLock(lockPath, async () => {
    const { events, lastHash } = _walkLedger(scanRoot);
    const items = (0,_lineage_remediation_js__WEBPACK_IMPORTED_MODULE_5__.foldRemediationLedger)(events);
    const itemId = _resolveItemId(eventPayload);
    const item = itemId != null ? (items[itemId] ?? null) : null;

    const { valid, errors } = (0,_lineage_remediation_js__WEBPACK_IMPORTED_MODULE_5__.validateTransition)(item, eventPayload);
    if (!valid) {
      return { valid: false, errors };
    }

    const event = { ...eventPayload, prev: lastHash };
    const line = JSON.stringify(event);
    node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(dir, { recursive: true });
    node_fs__WEBPACK_IMPORTED_MODULE_0__.appendFileSync(ledgerPath, line + '\n', 'utf8');
    return { valid: true, errors: [], event, hash: _sha(line) };
  });
}


/***/ })

};
