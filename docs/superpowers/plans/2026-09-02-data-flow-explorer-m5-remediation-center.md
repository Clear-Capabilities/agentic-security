# Blast-Radius: Remediation Command Center (M5 deliverable #6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a CLI-only, append-only remediation work-item ledger that
satisfies every clause of **AC-31**'s own `then` — affected scope fixed to
the incident snapshot, `verified` unreachable by marking work complete, and
automatic reopening on a later regression — without building the HTTP write
surface, the external ticket/GRC connectors, or the UI this sub-project's
own scoping doc rules out.

Unlike deliverable #5, this deliverable **is** named in the Milestone 5 exit
gate (PRD line 1854: "AC-26, AC-29, and AC-31 …"), so "a narrower first cut
cannot be accused of failing a named exit criterion" is *not* available here.
Surface area is narrowed; AC-31's three properties are not.

**Architecture:** A pure/impure split mirroring deliverable #5's
`governance-edit.js` + `cmdGovernancePropose` shape, one layer deeper:

- `scanner/src/lineage/remediation.js` — **pure**. The contract vocabulary,
  the event fold, the state machine (`validateTransition`), and the
  verification-evidence decision function. No `fs`, no I/O, never throws.
- `scanner/src/posture/remediation-ledger.js` — **impure**. Owns the
  lockfile, the JSONL append, the tolerant read, and the SHA-256 hash chain.
  The single place that calls `validateTransition` — no CLI command decides
  validity for itself.
- `scanner/bin/agentic-security.js` — a new top-level `remediation`
  dispatcher (six verbs). Dry-run by default, `--yes` to write,
  `--base-event` optimistic concurrency, `isSafeStateDir` guard, `auditCall`
  on every real write, exit codes 0/1/2/4.

Reuses, unmodified: `computeGraphDiff` (`lineage/graph-diff.js`),
`loadSnapshots`/`loadSnapshot` (`lineage/graph-snapshot.js`),
`loadDriftPolicies`/`evaluateDriftPolicies` (`lineage/drift-policy.js`),
`validateImpactAssessment` (`lineage/impact-assessment.js`),
`loadApproverRegistry`/`verifyApprover`/`checkSeparationOfDuties`
(`fix/approver-registry.js`), `auditCall` (`mcp/audit.js`),
`statePath`/`isSafeStateDir`/`stateWritesEnabled` (`posture/state-dir.js`).

**Tech Stack:** Node ESM, `node:test`, no new npm dependency.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-remediation-center-scoping.md`
— the authoritative design ruling for this deliverable. Read it in full
before starting Task 1.

---

## Corrections to the scoping doc and to this plan's own brief, verified against live code

Every item below was found by reading the real source, not inferred. Each is
binding on the tasks that follow — where a task step disagrees with the
scoping doc's prose, **this section is the resolution**, and the task step
already reflects it.

1. **`ImpactAssessment` carries no `assessmentId`, no `snapshotId`, and no
   `affectedFlowIds`.** The real record (`impact-engine.js:249-268`,
   validated by `impact-assessment.js:46`) is exactly:
   `{id, version, graphId, graphDigest, targetId, targetKind, scope,
   traceKind, affectedNodeIds, affectedEdgeIds, affectedDataClasses,
   affectedRecipientProfileIds, coverageLimitations, generatedAt}`.
   The scoping doc's §3 inline-field list names `assessmentId` and
   `snapshotId`; neither exists on the record. Resolution:
   - `assessmentId` **is** the record's own `id` (prefixed `impact:`).
   - `snapshotId` is resolved **by the CLI**, not read from the assessment:
     the newest persisted snapshot's `.id` (`loadSnapshots(scanRoot)[0]`),
     or the one `--snapshot <commit>` pins (`loadSnapshot(scanRoot, commit)`).
     `remediation open` **refuses (exit 2) when no snapshot exists** — an
     item with no incident snapshot can never be verified, so opening one
     would be a guaranteed dead end.
   - `affectedFlowIds` is derived, not copied: the sorted, deduplicated union
     of `--required-evidence` and (`targetId` when it starts with `flow:`).
     This is the only real flow-id source available, and it is what makes
     `reopen-check`'s §4.5 "control went away" half implementable.

2. **`--assessment` takes the RAW `dataflow impact assess` report.** Feasible,
   and less friction than hand-extraction: `cmdDataflowImpactAssess`
   (`bin/agentic-security.js:4310-4311`) writes `JSON.stringify(record, null, 2)`
   for `--format json`, so the file on disk *is* the record.
   `remediation open` validates it with `validateImpactAssessment` and exits 2
   naming the failing paths. **Decision: accept the raw report; document it.**

3. **`lifecycle.js`'s `withLock` is NOT exported** (`lifecycle.js:36`,
   `async function withLock(scanRoot, fn)`, no `export`). Reuse is impossible;
   Task 2 writes a faithful local port, the same way `_writeConfigAtomic` was
   a faithful port of `_writeAtomicAndSync` for deliverable #5.

4. **The hash chain: `prev` is the SHA-256 of the previous line's FULL
   serialized JSON text — including that line's own `prev` — and the genesis
   sentinel is the literal string `'GENESIS'`.** Verified against
   `mcp/audit.js`'s real `_sha`/`_readLastEntryHash`/`GENESIS` (`audit.js:52,
   54-62, 101`) and `verifyAuditLog` (`:127`), which re-derives
   `expectedPrev = _sha(lines[i])` over whole lines. This plan's brief guessed
   "the event minus its own `prev` field" and "sha256 of the empty string" —
   both wrong. Mirroring `audit.js` exactly is what lets `readLedgerEvents`
   verify the chain with the same one-line algorithm.

5. **`--against` is a COMMIT key, not a snapshot id.** `cmdDataflowDiff`
   resolves it with `loadSnapshot(targetAbs, againstFlag)`
   (`bin/agentic-security.js:4065`), which reads
   `.agentic-security/lineage-snapshots/<commit>.json`. `remediation verify
   --against <commit>` mirrors that exactly, error message included.

6. **Exit code 4 is already reachable through `main()`'s global catch**
   (`bin/agentic-security.js:5011-5013`, `process.exit(4)`), which is why
   `commands/governance.md` documents exit 4 with no explicit `return 4`
   anywhere in `cmdGovernancePropose`. The remediation commands wrap their
   write in a local `try/catch` that `return`s 4 with a clean, actionable
   message — same observable exit code, no stack trace at an operator.

7. **`scanner/src/posture/CLAUDE.md` must gain a `remediation-ledger.js`
   entry.** The Stop hook (`hooks/session-stop-drift-check.js`) flags any new
   file under `scanner/src/{sast,posture,dataflow}/` not mentioned in that
   subdirectory's own CLAUDE.md. The brief's doc list omitted this; Task 4
   includes it.

8. **Approver gating lives in the CLI, never in `remediation.js`.** The
   scoping doc's §4.3 requires `accepted_risk` be gated through
   `verifyApprover`/`checkSeparationOfDuties` unmodified, but those need
   `loadApproverRegistry(scanRoot)` — real `fs`. `validateTransition` checks
   field *presence* only; `cmdRemediationAcceptRisk` (and `verify
   --manual-attestation`) load the registry and enforce identity **before**
   calling `appendLedgerEvent`. Note both helpers are documented no-ops when
   no `authorized-approvers.json` exists (`approver-registry.js:81-83`,
   `:142-145`) — that is the shipped, inherited contract, not a gap this
   deliverable invents.

9. **`possible_coverage_regression` is diff-wide, not per-flow.**
   `computeGraphDiff` computes `flowRemovalCause` **once** for the whole diff
   (`graph-diff.js:328`), so if any coverage field regressed, *every* removed
   flow carries `causeClassification: 'possible_coverage_regression'` and the
   same `coverageRegressionReasons` array. This makes
   `evaluateVerificationEvidence`'s "refuse the whole verification" rule
   correct by construction, and it is why that rule short-circuits.

---

## Global Constraints

- **CLI-only.** No HTTP route (`POST /api/v1/remediation`, PRD line 1320), no
  frontend/UI work, no change to `scanner/src/server/` — it is read-only by
  design and a genuine write route needs CSRF protection plus a write-
  authorization mechanism distinct from the read-only session token. Same
  ruling, same reasoning, as deliverable #5 (scoping doc §4.1).
- **Dry-run by default.** Every mutating verb (`open`, `update`, `verify`,
  `accept-risk`, `reopen-check`) computes and prints exactly what it WOULD do
  and writes nothing unless `--yes` is supplied. `list` never writes.
- **Exit-code contract, identical to deliverable #5's, plus an explicit 4:**
  `0` success (preview **or** real write); `1` a validation failure (a
  malformed `--assessment`, an illegal state transition, an unverified
  approver); `2` a usage/argument error, an unresolvable snapshot, a
  `--base-event` mismatch, or an `isSafeStateDir` refusal; `4` an unexpected
  I/O error during the append itself — nothing was written and no audit event
  was recorded.
- **`isSafeStateDir` before any write.** Guard
  `path.dirname(ledgerPath)` — i.e. `.agentic-security/remediation/` — before
  any `mkdirSync`/append, matching deliverable #5's own M5 fix. Refuse with
  exit 2 rather than littering a non-project directory.
- **Append-only, never a mutable document.** PRD line 984 is a hard contract.
  The current state of an item is ALWAYS a fold of its events, never a stored
  field, never a derived cache file. A `status` that can be edited in place
  silently loses the history AC-31 depends on.
- **`verified` is unreachable from `state_changed`.** A `state_changed` event
  whose `state` is `'verified'` is rejected unconditionally, from every state,
  with no exception. This is the single most important rule in the whole
  deliverable (AC-31's own `then`; PRD line 171's non-goal). Marking work
  complete reaches `awaiting_verification`, full stop.
- **An incomplete scan can never produce a verification.** Any
  `possible_coverage_regression` in the diff refuses the whole verification
  as `unverifiable` (PRD line 1975), reusing `computeGraphDiff`'s already-
  shipped classification rather than a second opinion.
- **Confidentiality by construction (scoping doc §4.6).** The ledger stores
  only canonical ids, digests, and operator-supplied prose. Never node names,
  destinations, evidence snippets, or recipient facts — so `redact-graph.js`
  is not applicable, because there is nothing in the ledger for it to redact.
- **`auditCall` AND the ledger, never either alone** (scoping doc §4.7).
  `auditCall` records *"someone ran this command"*; the ledger records *"this
  item's state changed."* Both are required on every real write.
- **Artifact classification: `operator-config`, no `retentionClass`.** The
  ledger holds human decisions, approver identities, and accepted-risk
  exceptions. `reset` must never delete it — the `legal-holds.json` case
  (`artifact-registry.js:219`), deliberately NOT `provenance`'s `'generated'`
  (`:168`).
- **Pure/impure split is load-bearing.** `remediation.js` must never import
  `node:fs` or anything that does. `remediation-ledger.js` owns every side
  effect. A boundary test asserts this.
- **No new npm dependency.** No changes to `graph-diff.js`,
  `drift-policy.js`, `graph-snapshot.js`, `impact-engine.js`, or
  `approver-registry.js` — this deliverable is a consumer of all five.
- **Disclosed, not fixed:** `snapshotsComparable` (`graph-snapshot.js:173`)
  checks `schemaVersion` equality and nothing else, so AC-31's "compatible
  rescan evidence" currently means exactly "same schema version." Say so in
  `commands/remediation.md`; do not invent a comparability dimension here.

---

### Task 1: `scanner/src/lineage/remediation.js` — the pure contract, state machine, and verification-evidence decision

The highest-risk, most novel logic in this deliverable, and the one that
encodes AC-31. It gets the most thorough test coverage: every state
transition, every rejection reason, and every
`evaluateVerificationEvidence` outcome.

**Files:**
- Create: `scanner/src/lineage/remediation.js`
- Create: `scanner/test/lineage/remediation.test.js`
- Modify: `scanner/package.json` (`test:lineage`)

**Interfaces (produced):**
- `REMEDIATION_STATES` — `['open','in_progress','awaiting_verification','verified','accepted_risk','reopened']` (frozen)
- `REMEDIATION_EVENT_TYPES` — `['opened','state_changed','scan_verification','manual_attestation','accepted_risk','reopened']` (frozen)
- `ACCEPTED_RISK_REQUIRED_FIELDS` — `['approver','reason','scope','expiration']` (frozen; PRD line 572's exact list, scoping doc §4.3)
- `foldRemediationItem(events) -> item | null`
- `foldRemediationLedger(allEvents) -> {[itemId]: item}`
- `validateOpenPayload(payload) -> {valid, errors}`
- `validateTransition(item, proposedEvent) -> {valid, errors}`
- `evaluateVerificationEvidence(diff, requiredEvidenceFlowIds) -> outcome`

**Interfaces (consumed):** none. This module has **zero imports** — the same
"pure data + pure functions, boundary-tested" precedent `flow-grade.js` and
`obligation-mapping.js` already set in this package.

`errors` is `[{field, message}]` throughout, mirroring `governance-edit.js`'s
own `[{key, message}]` error shape one field-name over (a transition error is
about a field, not a config key).

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/remediation.test.js`:

```js
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/remediation.test.js`
Expected: FAIL — module not found. Read the real output; do not assume.

- [ ] **Step 3: Write `scanner/src/lineage/remediation.js`**

Zero imports. Header comment must record, at minimum:
- What this module is (M5 deliverable #6, FR-507 + AC-31), and that it is
  pure by contract — the ledger layer (`posture/remediation-ledger.js`) owns
  every side effect, mirroring `governance-edit.js`'s own split.
- The `verified`-unreachable-from-`state_changed` rule, in full, with its
  two PRD citations (AC-31's `then`; line 171's non-goal), so a future
  refactor cannot "simplify" it away without reading why it exists.
- The **deliberate scope narrowing** in `evaluateVerificationEvidence`: a
  required-evidence flow is satisfied ONLY when it appears in
  `diff.removed.flows` with `causeClassification === 'application_change'`.
  The "flow still exists but is now more protected" case is out of scope for
  this first cut — an ambiguous, unbuilt "improving transition" heuristic; a
  future increment could add it. Say this in the code, not only here.
- That `possible_coverage_regression` is computed diff-wide by
  `computeGraphDiff` (`graph-diff.js:328`), which is why one hit refuses the
  whole verification rather than one flow.

Implementation notes, in the order they matter:

- `foldRemediationItem(events)`: return `null` for a non-array, an empty
  array, or `events[0].type !== 'opened'`. Otherwise seed the item from the
  `opened` event (`state: 'open'`, `approvals: []`, `exceptions: []`,
  `verificationSnapshotId: null`) and walk the remaining events **in order**,
  applying each: `state_changed` → `item.state = ev.state`;
  `scan_verification` with `outcome === 'verified'` → `state = 'verified'`
  and `verificationSnapshotId = ev.snapshotId` (an `'unverifiable'` outcome
  changes neither); `manual_attestation` → `state = 'verified'` and push
  `{approver, reason, at, evidenceKind: 'manual'}` onto `approvals`;
  `accepted_risk` → `state = 'accepted_risk'` and push
  `{approver, reason, scope, expiration, at}` onto `exceptions`; `reopened`
  → `state = 'reopened'`. `history` is the events array as given. The fold
  reads only `type`/`at`/payload fields and **ignores** `prev` and any other
  chain field the ledger layer stamps on.
  The `evidenceKind: 'manual'` stamp is not decoration — PRD line 984
  requires manual attestations stay distinguishable from scan evidence
  forever, and `R2/7` pins it.
- `foldRemediationLedger(allEvents)`: group by `ev.itemId` (falling back to
  `ev.id` on an `opened` event that carries only `id`), preserving insertion
  order per group; skip any event with no resolvable item id; call
  `foldRemediationItem` per group; drop groups that fold to `null`.
- `validateOpenPayload(payload)`: per the test's exact expectations —
  non-empty-string `id`/`owner`/`recommendedControl`; `dueDate` matching
  `/^\d{4}-\d{2}-\d{2}$/`; an `assessment` object (one error if absent, then
  stop — never eight cascading errors) with non-empty-string `assessmentId`,
  `targetId`, `targetKind`, `traceKind`, `scope`, `graphId`, `graphDigest`,
  `snapshotId`, and an OPTIONAL `assessmentPath`; `requiredEvidence` a
  non-empty array of non-empty strings.
- `validateTransition(item, proposedEvent)`: a `switch` over
  `proposedEvent.type`, implementing the Global Constraints' rules exactly.
  **Order matters in the `state_changed` case: reject
  `state === 'verified'` FIRST, before consulting `item.state` at all**, so
  the rejection is genuinely unconditional and cannot be reached around by
  any current state. Its message must name `scan_verification` and
  `manual_attestation` as the only two routes to `verified` (`R5/5` asserts
  this).
- `evaluateVerificationEvidence(diff, requiredEvidenceFlowIds)`: guard
  non-array/empty `requiredEvidenceFlowIds` → `{outcome: 'unverifiable',
  reason: 'no_required_evidence'}`. Build a `Map` of
  `diff?.removed?.flows` by id (tolerating every level being absent). For
  each required id, in order: a `possible_coverage_regression` hit returns
  immediately; a `reidentified` hit returns immediately; an
  `application_change` hit is satisfied; anything else (absent, or an
  unrecognized classification) collects into `unsatisfiedFlowIds`. After the
  loop, a non-empty `unsatisfiedFlowIds` → `{outcome: 'unverifiable',
  reason: 'flows_still_present', unsatisfiedFlowIds}`; otherwise
  `{outcome: 'verified'}`.

Every exported function returns rather than throws, including on `null`,
`undefined`, and wrong-typed input.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/remediation.test.js`
Expected: PASS, all tests, 0 failures. Read the real output.

- [ ] **Step 5: Wire the test file into `test:lineage`**

Read `scanner/package.json`'s current `test:lineage` script string first,
then append ` test/lineage/remediation.test.js` to its end (it currently
ends with `test/lineage/governance-edit.test.js`).

- [ ] **Step 6: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures. Capture and read `echo $?`.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/remediation.js scanner/test/lineage/remediation.test.js scanner/package.json
git commit -m "feat(lineage): add remediation.js — the pure RemediationItem contract, AC-31 state machine, and verification-evidence rule"
```

---

### Task 2: `scanner/src/posture/remediation-ledger.js` — lock, append, tolerant read, hash chain

**Files:**
- Create: `scanner/src/posture/remediation-ledger.js`
- Create: `scanner/test/posture/remediation-ledger.test.js`
- Modify: `scanner/src/posture/artifact-registry.js`
- Modify: `scanner/package.json` (`test:posture`)

`scanner/test/posture/` is the real, existing home for `posture/`-module
tests (21 files today, all `provenance-*`), wired into `test:posture` —
verified by listing the directory and reading the script, not assumed.

**Interfaces (produced):**
- `ledgerPaths(scanRoot) -> {ledgerPath, lockPath}`
- `readLedgerEvents(scanRoot) -> event[]`
- `latestEventHash(scanRoot) -> string` (`'GENESIS'` when the ledger is empty or missing)
- `appendLedgerEvent(scanRoot, eventPayload) -> Promise<{valid, errors, event, hash}>`

**Interfaces (consumed):** `statePath`/`isSafeStateDir`/`stateWritesEnabled`
from `./state-dir.js`; `validateTransition`/`foldRemediationLedger` from
`../lineage/remediation.js` (Task 1). `node:fs`, `node:fs/promises`,
`node:path`, `node:crypto`.

This is the **second** `posture/` → `lineage/` import in the codebase
(`auditor-walkthrough.js`'s `graph:` branch was the first) — note it in the
module header so the boundary stays a deliberate, documented exception
rather than an accident.

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/posture/remediation-ledger.test.js`. Use a real temp
project directory (`fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-rem-ledger-'))`
plus a `package.json` marker, so `isSafeStateDir` passes) — the same
temp-project helper shape `test/cli/governance-propose-edit.test.js` uses.

Cover, at minimum:

- `L/1` `ledgerPaths` resolves to `.agentic-security/remediation/items.jsonl`
  and `.../items.lock`, both under `statePath` (never a hand-joined string).
- `L/2` `readLedgerEvents` on a missing file returns `[]`, never throws.
- `L/3` A round trip: append an `opened` event, then `readLedgerEvents`
  returns exactly one event carrying `prev: 'GENESIS'`.
- `L/4` Chain continuity: append `opened` then `state_changed`; the second
  event's `prev` equals `sha256(<the first line's exact serialized text>)`,
  computed independently in the test with `crypto.createHash('sha256')` over
  the raw first line read back off disk. This is the guard against the chain
  quietly hashing something else.
- `L/5` `latestEventHash` on an empty/missing ledger is `'GENESIS'`; after
  one append it equals `sha256(<the last line's exact text>)`.
- `L/6` A torn tail is skipped, not fatal: append two valid events, then
  `fs.appendFileSync` a truncated `'{"type":"state_ch'` fragment;
  `readLedgerEvents` returns the two valid events, `latestEventHash` returns
  the hash of the last VALID line, and nothing throws.
- `L/7` A tampered middle line breaks the chain and is reported: rewrite line
  1's `owner` in place; `readLedgerEvents` must not silently return the
  tampered stream as if intact — assert the documented behavior (events up to
  and including the last verifying line are returned; the rest are dropped).
  Pin the exact behavior the implementation chooses, in both directions.
- `L/8` `appendLedgerEvent` REJECTS an illegal transition and writes nothing:
  append `opened`, then attempt `{type: 'state_changed', state: 'verified'}`;
  assert `{valid: false}`, that `errors` names the rule, and that
  `readLedgerEvents` still returns exactly one event. **This is the test that
  proves `validateTransition` is genuinely enforced at the write boundary,
  not merely available.**
- `L/9` `appendLedgerEvent` rejects a second `opened` for an existing item id.
- `L/10` Concurrency: fire ~8 `appendLedgerEvent` calls with
  `Promise.all` against ONE item (a mix of legal and illegal transitions);
  assert every appended line parses, the chain verifies end to end via
  `readLedgerEvents`, no line is interleaved/corrupted, and the folded item's
  final state is one legal outcome. This proves the lock actually serializes
  the read-modify-write.
- `L/11` Stale-lock reaping: write a lockfile containing a PID that is
  certainly dead (e.g. `2147483647`) and confirm `appendLedgerEvent` still
  completes rather than timing out.
- `L/12` `appendLedgerEvent` refuses when `isSafeStateDir` is false (a temp
  dir with no project marker) — returns `{valid: false}` with a reason, and
  creates no `.agentic-security/` directory.
- `L/13` `appendLedgerEvent` refuses when `stateWritesEnabled()` is false
  (use `setStateWritesEnabled(false)` in a `try/finally` that restores it).
- `L/14` `foldRemediationLedger(readLedgerEvents(root))` over a multi-item
  ledger reproduces each item's real state — the end-to-end read path.

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/posture/remediation-ledger.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `scanner/src/posture/remediation-ledger.js`**

Header comment must record: the append-only contract (PRD line 984); why the
physical shape is a JSONL append (`fix-metrics.js:69`'s precedent) rather
than `lifecycle.js:195`'s whole-file rewrite (a partial rewrite of a shared
document can lose every OTHER item on a human-driven, one-item-at-a-time
write); why a lock is still required despite the append being atomic (the
write is a read-modify-write — a transition must be validated against the
current folded state before the event is appended); and that `withLock` is
a faithful local PORT of `lifecycle.js:36`, not an import, because that
function is not exported (verified).

- `ledgerPaths(scanRoot)`:
  ```js
  export function ledgerPaths(scanRoot) {
    return {
      ledgerPath: statePath(scanRoot, 'remediation', 'items.jsonl'),
      lockPath: statePath(scanRoot, 'remediation', 'items.lock'),
    };
  }
  ```
  Both go through `statePath` — never a hand-joined `.agentic-security`
  string. This is what `test/no-stray-state.test.js` and
  `test/artifact-registry-completeness.test.js` both key on, and the
  completeness guard captures the FIRST literal segment (`'remediation'`),
  which is exactly the registry entry name Step 5 adds.

- `_sha(s)` / `GENESIS`: byte-identical in behavior to `mcp/audit.js:52` and
  `:53` — `crypto.createHash('sha256').update(s).digest('hex')` and the
  literal string `'GENESIS'`.

- `readLedgerEvents(scanRoot)`: read the file (missing → `[]`), split on
  `\n`, drop empty lines, and walk forward maintaining `expectedPrev`
  (starting at `GENESIS`), exactly as `verifyAuditLog` (`audit.js:127-146`)
  does. For each line: `JSON.parse` it — a parse failure **stops the walk**
  (a torn tail); a parsed event whose `prev !== expectedPrev` **stops the
  walk** (tamper detected). Push the event, set
  `expectedPrev = _sha(line)`, continue. Return the accumulated prefix.
  Never throws. Document plainly that this returns the longest verifying
  PREFIX — a tampered middle line drops everything after it, which is
  strictly safer than replaying a stream whose integrity is unknown.

- `latestEventHash(scanRoot)`: re-walk with the same routine and return
  `_sha(<last verifying line>)`, or `GENESIS` when nothing verifies. Do this
  by having the walk return `{events, lastHash}` internally so the two
  exported functions cannot drift apart on what "the last valid line" means.

- `withLock(scanRoot, fn)`: a faithful port of `lifecycle.js:36-88` —
  exclusive `wx` open of the lockfile, write `String(process.pid)`, run `fn`
  in a `try`, `unlink` in `finally`; on `EEXIST`, reap when the holding PID
  is not alive (`process.kill(pid, 0)`, treating `EPERM` as alive) **or** the
  lockfile is older than 30s, re-reading the lockfile before unlinking so a
  fresh holder is not raced; 25ms retry; 5s timeout throwing a named error.
  Port `isProcessAlive` alongside it.

- `appendLedgerEvent(scanRoot, eventPayload)`: async. Before taking the lock:
  refuse (`{valid: false, errors: [...]}`) when
  `!isSafeStateDir(path.dirname(ledgerPath))` or `!stateWritesEnabled()`.
  Then, INSIDE the lock: re-read the events, `foldRemediationLedger` them,
  resolve the target item (`items[eventPayload.itemId] ?? null`), call
  `validateTransition(item, eventPayload)`, and **return `{valid: false,
  errors}` without appending** when invalid. When valid: compute
  `prev` from the same walk's `lastHash`, build
  `event = {...eventPayload, prev}`, serialize with `JSON.stringify`, and
  `fs.appendFileSync(ledgerPath, line + '\n', 'utf8')` after
  `fs.mkdirSync(dir, {recursive: true})` — one `appendFileSync` of one
  newline-terminated record, matching `fix-metrics.js:69`'s own choice not
  to use a temp-file dance for a single-record append. Return
  `{valid: true, errors: [], event, hash: _sha(line)}`.
  **This function is the single place `validateTransition` is called.** No
  CLI command computes validity for itself; say so in the header.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scanner && node --test test/posture/remediation-ledger.test.js`
Expected: PASS, 0 failures.

- [ ] **Step 5: Register the artifact**

In `scanner/src/posture/artifact-registry.js`, add to the
**operator-config** section (near `legal-holds.json` at `:219`, whose note
this one deliberately echoes):

```js
  { name: 'remediation', kind: 'dir', classification: 'operator-config', note: 'M5 deliverable #6 remediation work-item ledger (items.jsonl + items.lock) — an APPEND-ONLY record of human decisions: owner assignment, approvals, manual attestations, and accepted-risk exceptions with approver/reason/scope/expiration. WRITTEN by the CLI (`remediation open|update|verify|accept-risk|reopen-check --yes`) but classified operator-config, not generated, deliberately — the same call legal-holds.json makes one entry up: a plain `reset` must never be able to delete the audit trail AC-31 depends on, and nothing regenerates it from a rescan. Deliberately NOT the `provenance` entry\'s `generated` classification (see its own note above): that ledger is scan-derived history a rescan can rebuild; this one is human decisions that cannot be. No retentionClass for the same reason legal-holds.json has none — auto-expiry would silently delete an accepted-risk exception a report may already cite.' },
```

One directory entry covers both `items.jsonl` and `items.lock`, the same
packaging choice `recipient-profiles-backups` made (`:195`) — the registry
only supports exact top-level names, never a nested sub-path.

Verify the entry landed: `grep -n "'remediation'" scanner/src/posture/artifact-registry.js`.

- [ ] **Step 6: Add the `posture/CLAUDE.md` entry (drift-hook requirement)**

`hooks/session-stop-drift-check.js` flags any new file under
`scanner/src/posture/` not mentioned in `scanner/src/posture/CLAUDE.md`.
Add a short paragraph — place it after the "Fix lifecycle" / "Measured fix
loop (R5)" cluster, since it shares `fix-metrics.js`'s append-and-tolerant-
read shape — covering: what `remediation-ledger.js` is (the I/O half of M5
deliverable #6), that it is the SECOND `posture/` → `lineage/` import
(`auditor-walkthrough.js` was the first), that it is the single place
`validateTransition` is enforced, and that its lock is a faithful port of
`provenance/lifecycle.js`'s `withLock` because that function is not
exported.

- [ ] **Step 7: Wire the test file into `test:posture` and run the guards**

Read `scanner/package.json`'s current `test:posture` script first, then
append ` test/posture/remediation-ledger.test.js`.

Run: `cd scanner && npm run test:posture && npm run test:lifecycle`
Expected: PASS, 0 failures both. `test:lifecycle` covers
`artifact-registry-completeness.test.js`, `no-dead-modules.test.js`, and
`no-stray-state.test.js` — all three are directly affected by this task, so
read their results specifically, not just the aggregate.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/posture/remediation-ledger.js scanner/test/posture/remediation-ledger.test.js scanner/src/posture/artifact-registry.js scanner/src/posture/CLAUDE.md scanner/package.json
git commit -m "feat(posture): add remediation-ledger.js — locked, hash-chained, append-only remediation event ledger"
```

---

### Task 3: CLI — `remediation open` / `update` / `accept-risk` / `list` (the scoping doc's 6a half)

No `GraphDiff` or drift-policy dependency in this task. Task 4 adds the two
verbs that consume them.

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Create: `scanner/test/cli/remediation-open-update.test.js`
- Modify: `scanner/package.json` (`test:mcp`)

`test/cli/` + `test:mcp` is deliverable #5's own precedent for a CLI
subprocess test that asserts the real on-disk `mcp-audit.log` format —
`test:mcp`'s stated scope is "MCP server tools + audit log," which these
tests exercise directly.

**Interfaces (produced):**

```
agentic-security remediation open [path] --assessment <impact-report.json>
    --owner <id> --due <YYYY-MM-DD> --control <text>
    --required-evidence <flowId,...> [--id <itemId>] [--snapshot <commit>]
    [--allow-manual-attestation] [--output <file>] [--yes]
agentic-security remediation update [path] --id <itemId>
    --state <in_progress|awaiting_verification> [--base-event <hash>]
    [--output <file>] [--yes]
agentic-security remediation accept-risk [path] --id <itemId> --approver <id>
    --reason <text> --scope <text> --expires <YYYY-MM-DD>
    [--author <id>] [--base-event <hash>] [--output <file>] [--yes]
agentic-security remediation list [path] [--format json|markdown] [--output <file>]
```

**Interfaces (consumed):** `appendLedgerEvent`/`readLedgerEvents`/
`latestEventHash`/`ledgerPaths` (Task 2, exact names verified against that
task's own exports); `foldRemediationLedger`/`validateOpenPayload` (Task 1);
`validateImpactAssessment` (`lineage/impact-assessment.js`);
`loadSnapshots`/`loadSnapshot` (`lineage/graph-snapshot.js`);
`loadApproverRegistry`/`verifyApprover`/`checkSeparationOfDuties`
(`fix/approver-registry.js`); `auditCall` (`mcp/audit.js`);
`isSafeStateDir`/`statePath` (`posture/state-dir.js`).

- [ ] **Step 1: Write the failing CLI test file**

Create `scanner/test/cli/remediation-open-update.test.js`, modelled on
`test/cli/governance-propose-edit.test.js`'s structure (a `_mkTmpProject()`
helper writing a `package.json` marker; `spawnSync(process.execPath, [CLI,
...], {encoding: 'utf8', timeout: 20_000})`).

The fixture needs a real persisted snapshot, since `open` refuses without
one. Write one by hand into
`statePath(root, 'lineage-snapshots', '<commit>.json')` shaped per
`buildGraphSnapshot`'s real output (`{id, version, graphId, schemaVersion,
commit, capturedAt, coverage, graph}`) — a minimal but structurally real
graph is enough for `open`/`update`/`accept-risk`/`list`, which never diff.

Assertions, at minimum:

- `C/1` `open` without `--yes` prints a preview, writes NO `items.jsonl`,
  exits 0, and the preview names the resolved `snapshotId`, `baseEvent`
  (`'GENESIS'`), and the folded would-be item.
- `C/2` `open --yes` writes exactly one JSONL line, exits 0, and appends a
  real audit event — assert `mcp-audit.log` exists and matches
  `/remediation_open/` and `/"outcome":"ok"/`. **Before writing the
  implementation, confirm the real serialization** (`grep -n
  "JSON.stringify(entry)" src/mcp/audit.js` and read the surrounding lines)
  so the regex matches reality; `auditCall` writes compact JSON today.
- `C/3` `open --yes` a second time with the same `--id` exits 1 and appends
  no second line — the duplicate-item rejection surfaces at the CLI.
- `C/4` `open` with a malformed `--assessment` (a JSON file that fails
  `validateImpactAssessment`) exits 2, naming the failing paths, and writes
  nothing.
- `C/5` `open` with NO persisted snapshot exits 2 with a message telling the
  operator to run a scan with `AGENTIC_SECURITY_LINEAGE_DEEP=1` first
  (mirroring `cmdDataflowDiff`'s own wording at `bin/agentic-security.js:4058`).
- `C/6` `open` with a missing required flag (each of `--assessment`,
  `--owner`, `--due`, `--control`, `--required-evidence`) exits 2.
- `C/7` `update --state in_progress --yes` from `open` succeeds and folds to
  `in_progress`.
- `C/8` **(AC-31 at the CLI boundary)** `update --state verified` exits 1,
  writes nothing, and the stderr names `verify` as the only route. Run this
  from `awaiting_verification` — the state a naive implementation is most
  likely to let through.
- `C/9` `update --state awaiting_verification` from `open` (skipping
  `in_progress`) exits 1 and writes nothing.
- `C/10` `--base-event` mismatch exits 2 and writes nothing; `--base-event`
  matching `latestEventHash` succeeds. Get the real hash from a prior
  command's own JSON report, never a hand-computed guess.
- `C/11` `accept-risk --yes` with all four fields succeeds and folds to
  `accepted_risk` with a real exception carrying `expiration`; missing any
  one of `--approver`/`--reason`/`--scope`/`--expires` exits 2 (a usage
  error) — and note `--expires` maps to the `expiration` field.
- `C/12` `accept-risk` with an `authorized-approvers.json` present and an
  UNREGISTERED `--approver` exits 1 with `verifyApprover`'s own reason
  string, and writes nothing. With the approver registered, it succeeds.
- `C/13` `accept-risk` with `separationOfDuties.enabled` and
  `--author === --approver` exits 1 with `checkSeparationOfDuties`' own
  reason, and writes nothing.
- `C/14` `list --format json` returns an array of folded items;
  `list --format markdown` returns a table with the columns
  id/state/owner/dueDate/recommendedControl; both exit 0 on an empty ledger
  (an empty array / an explicit "no remediation items" line — never a crash).
- `C/15` Every mutating verb refuses with exit 2 in a directory with no
  project marker (`isSafeStateDir` false) and creates no
  `.agentic-security/`.
- `C/16` No audit event is appended on a dry run or on any rejected write —
  assert `mcp-audit.log` either does not exist or contains no
  `remediation_*` entry after `C/1`, `C/4`, `C/8`.

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/cli/remediation-open-update.test.js`
Expected: FAIL — `remediation` is not a recognized top-level command yet.

- [ ] **Step 3: Add the four command handlers**

In `scanner/bin/agentic-security.js`, place these next to
`cmdGovernancePropose` (search for `async function cmdGovernancePropose` —
it starts at roughly line 4390; read 20 lines either side first to confirm
the real surroundings before inserting). Check whether `crypto` is already
imported at the top of the file (`grep -n "^import \* as crypto"
bin/agentic-security.js`) and reuse the existing import — it is used by
`_writeConfigAtomic` and `cmdGovernancePropose` already.

A shared private helper does the work every mutating verb repeats, so the
four handlers cannot drift apart on the write contract:

```js
// Shared write path for every mutating `remediation` verb. Order is the
// same one cmdGovernancePropose established and is load-bearing:
//   1. --base-event optimistic-concurrency guard (BEFORE any validation
//      or write) — the append-only analogue of #5's whole-file
//      --base-digest, keyed to the last EVENT hash per the scoping doc's
//      §3 "reuse this shape, with one genuine adaptation."
//   2. isSafeStateDir refusal.
//   3. Dry run: fold the CURRENT ledger, report what WOULD happen, write
//      nothing, exit 0.
//   4. --yes: appendLedgerEvent (which is the ONLY caller of
//      validateTransition), then auditCall — never the reverse, and
//      never auditCall on a rejected or previewed write.
// Returns an exit code; the caller returns it verbatim.
async function _remediationWrite(targetAbs, verb, auditTool, eventPayload, args) {
  // Body: the six responsibilities enumerated immediately below, in that
  // exact order. Nothing else belongs in here — a verb-specific check
  // (flag parsing, approver verification, snapshot resolution) happens in
  // the verb's own handler BEFORE it delegates here.
}
```

`_remediationWrite` responsibilities, precisely:

- Resolve `{ledgerPath}` via `ledgerPaths(targetAbs)`.
- `--base-event`: when supplied, compare against `latestEventHash(targetAbs)`;
  on mismatch write a clear stderr line ("the ledger changed since
  `--base-event` was computed (a concurrent write) — refusing to append.
  Re-read the ledger with `remediation list` and retry.") and `return 2`.
- `--yes` path only: `isSafeStateDir(path.dirname(ledgerPath))` false →
  stderr + `return 2`.
- Dry run (no `--yes`): build the report
  `{verb, itemId, proposedEvent, baseEvent, written: false, wouldBe: <the
  item folded WITH the proposed event appended in memory>}` and emit it to
  `--output` or stdout; `return 0`. Compute `wouldBe` by folding
  `[...readLedgerEvents(targetAbs), eventPayload]` through
  `foldRemediationLedger` — a genuine preview of the resulting state, not a
  restatement of the request. When the proposed event is illegal, the dry run
  must still say so: call `validateTransition` for the PREVIEW only (the
  authoritative call remains the one inside `appendLedgerEvent`) and
  `return 1` with the errors, so `--yes` never surprises an operator who
  previewed first.
- `--yes` path: wrap the append in `try/catch`; on a thrown I/O error write a
  clean message and `return 4` (nothing written, no audit event). On
  `{valid: false}` write each `{field, message}` and `return 1`. On success
  call `auditCall({sessionRoot: targetAbs, tool: auditTool, args: {itemId,
  eventType, baseEvent, eventHash}, outcome: 'ok'})`, emit the report with
  `written: true` and `eventHash` taken verbatim from
  `appendLedgerEvent`'s own `hash` return field (the two names differ
  deliberately: `hash` is the ledger's vocabulary, `eventHash`/`baseEvent`
  the CLI report's), and `return 0`.

`auditTool` values: `'remediation_open'`, `'remediation_update'`,
`'remediation_accept_risk'` (Task 4 adds `'remediation_verify'` and
`'remediation_reopen_check'`).

The four handlers:

- `cmdRemediationOpen(args)` — `args._ = ['remediation', 'open', <path>?]`,
  so the path is `args._[2] || '.'`.
  1. Require `--assessment`, `--owner`, `--due`, `--control`,
     `--required-evidence`; each missing → stderr + `return 2`.
  2. Read and `JSON.parse` the `--assessment` file (unreadable/unparseable →
     `return 2`), then `validateImpactAssessment(record)`; invalid →
     print each `{path, message}` and `return 2`. **This is the raw
     `dataflow impact assess --format json --output` report** — correction
     #2 above.
  3. Resolve the incident snapshot: `--snapshot <commit>` →
     `loadSnapshot(targetAbs, commit)` (null → `return 2` mirroring
     `cmdDataflowDiff`'s own "pass a commit that was actually scanned"
     message); otherwise `loadSnapshots(targetAbs)[0]` (none → `return 2`
     with the "run a scan with `AGENTIC_SECURITY_LINEAGE_DEEP=1` first"
     message). Take `snapshot.id`.
  4. Parse `--required-evidence` as a comma-separated list, trimming and
     dropping empties; empty result → `return 2`.
  5. Build the `opened` payload:
     ```js
     const itemId = args.flags.id || `rem-${crypto.randomBytes(6).toString('hex')}`;
     const requiredEvidence = String(args.flags['required-evidence'])
       .split(',').map((s) => s.trim()).filter(Boolean);
     const affectedFlowIds = [...new Set([
       ...requiredEvidence,
       ...(record.targetId.startsWith('flow:') ? [record.targetId] : []),
     ])].sort();
     const payload = {
       type: 'opened', at: new Date().toISOString(), itemId, id: itemId,
       owner: args.flags.owner, dueDate: args.flags.due,
       recommendedControl: args.flags.control,
       assessment: {
         assessmentId: record.id, targetId: record.targetId,
         targetKind: record.targetKind, traceKind: record.traceKind,
         scope: record.scope, graphId: record.graphId,
         graphDigest: record.graphDigest, snapshotId: snapshot.id,
         assessmentPath: path.resolve(args.flags.assessment),
       },
       affectedFlowIds,
       affectedNodeIds: record.affectedNodeIds ?? [],
       affectedEdgeIds: record.affectedEdgeIds ?? [],
       requiredEvidence,
       manualAttestationPermitted: !!args.flags['allow-manual-attestation'],
     };
     ```
     `affectedFlowIds` is DERIVED, not copied — correction #1 above; add a
     code comment saying so, and saying that `ImpactAssessment` carries no
     `affectedFlowIds` field, so a future reader does not go looking.
  6. `validateOpenPayload(payload)` before touching the ledger; invalid →
     print each `{field, message}` and `return 1`.
  7. Delegate to `_remediationWrite(targetAbs, 'open', 'remediation_open',
     payload, args)`.

- `cmdRemediationUpdate(args)` — require `--id` and `--state`; `--state` must
  be `in_progress` or `awaiting_verification`, and **the CLI rejects
  `--state verified` with its own exit-2 usage message naming
  `remediation verify`** *in addition to* the ledger's own unconditional
  rejection. Two independent guards for the one rule that matters most; the
  CLI guard is the friendlier message, the ledger guard is the one that
  cannot be bypassed. Payload:
  `{type: 'state_changed', at, itemId, state}`. Delegate to
  `_remediationWrite`.

- `cmdRemediationAcceptRisk(args)` — require `--id`, `--approver`,
  `--reason`, `--scope`, `--expires` (each missing → `return 2`);
  `--expires` must match `/^\d{4}-\d{2}-\d{2}$/`. Then, BEFORE the write
  (correction #8):
  ```js
  const { loadApproverRegistry, verifyApprover, checkSeparationOfDuties } =
    await import('../src/fix/approver-registry.js');
  const registry = loadApproverRegistry(targetAbs);
  const v = verifyApprover(registry, args.flags.approver, []);
  if (!v.verified) { process.stderr.write(`agentic-security remediation accept-risk: ${v.reason}\n`); return 1; }
  const sod = checkSeparationOfDuties(registry, args.flags.author, args.flags.approver);
  if (!sod.ok) { process.stderr.write(`agentic-security remediation accept-risk: ${sod.reason}\n`); return 1; }
  ```
  Both are documented no-ops without a registry file — inherit that scope
  statement verbatim rather than restating it differently
  (`approver-registry.js:12-23`). Payload:
  `{type: 'accepted_risk', at, itemId, approver, reason, scope, expiration}`.
  Delegate to `_remediationWrite`.

- `cmdRemediationList(args)` — never writes. `--format` defaults to `json`
  and must be `json` or `markdown` (anything else → `return 2`).
  `foldRemediationLedger(readLedgerEvents(targetAbs))`, sort items by `id`
  for determinism, then either `JSON.stringify(items, null, 2)` (an ARRAY of
  folded items, per the brief) or a Markdown table with columns
  `id | state | owner | dueDate | recommendedControl`, the control column
  truncated (e.g. 60 chars with an ellipsis). Escape every interpolated
  value through local `_remMdInline`/`_remMdCell` helpers — byte-identical in
  behavior to this file's own `_dfDiffMdInline`/`_dfDiffMdCell` /
  `_dfRecipientsMd*` bodies, reimplemented locally per this codebase's
  established per-module-owns-its-own-escaping-helpers convention (an
  unescaped `|` or newline in operator-supplied `recommendedControl` prose
  would otherwise corrupt the table). Write to `--output` or stdout;
  `return 0`. An empty ledger emits `[]` / a "_no remediation items_" line.

- [ ] **Step 4: Wire the top-level dispatch**

`remediation` is a NEW top-level command, a sibling of `governance` — it
writes operator/incident state, never the scanned graph (scoping doc §4.8).
Read the `case 'governance':` block (`bin/agentic-security.js:4838-4850`)
and add a sibling case immediately after it, matching its exact indentation
and brace style:

```js
      case 'remediation': {
        // NOT a `dataflow` subcommand — this writes operator/incident
        // state (the append-only remediation ledger), never the scanned
        // graph. Same distinction that made `governance` its own
        // dispatcher. See _remediationWrite's own header for the full
        // base-event/isSafeStateDir/audit/exit-code contract.
        const sub = args._[1];
        if (sub === 'open') { process.exit(await cmdRemediationOpen(args)); }
        else if (sub === 'update') { process.exit(await cmdRemediationUpdate(args)); }
        else if (sub === 'accept-risk') { process.exit(await cmdRemediationAcceptRisk(args)); }
        else if (sub === 'list') { process.exit(await cmdRemediationList(args)); }
        else {
          process.stderr.write(`agentic-security remediation: unrecognized sub-command "${sub}" — must be one of open|update|verify|accept-risk|reopen-check|list.\n`);
          process.exit(2);
        }
        break;
      }
```

Task 4 adds the `verify` and `reopen-check` branches. The error message
already names all six so a mid-task state never advertises a smaller
surface than the docs.

- [ ] **Step 5: Add the top-level help text**

Find the `Commands:` block containing the `governance propose-edit` line
(`bin/agentic-security.js:168`) and add the four verbs beneath it, in the
same column layout. `verify`/`reopen-check` lines are added in Task 4.

- [ ] **Step 6: Run the CLI test**

Run: `cd scanner && node --test test/cli/remediation-open-update.test.js`
Expected: PASS, all tests. If the audit-log regex needs adjusting to the
real serialized format (per Step 1's own note), iterate here until green —
adjust the TEST to match reality, never the assertion's intent.

- [ ] **Step 7: Rebuild the bundle**

Run: `cd scanner && npm run build`
Expected: exit 0. Confirm via `git status` on the WHOLE `dist/` directory —
never a targeted grep of only `dist/agentic-security.mjs`, per this
session's own repeatedly-proven gotcha.

- [ ] **Step 8: Wire the test file into `test:mcp`**

Read `scanner/package.json`'s current `test:mcp` script first (it currently
ends with `test/cli/governance-propose-edit.test.js`), then append
` test/cli/remediation-open-update.test.js`.

- [ ] **Step 9: Run the scoped suites**

Run: `cd scanner && npm run test:mcp && npm run test:lineage && npm run test:posture`
Expected: PASS, 0 failures, all three. Read each result.

- [ ] **Step 10: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/dist/ scanner/test/cli/remediation-open-update.test.js scanner/package.json
git commit -m "feat(cli): wire remediation open/update/accept-risk/list — dry-run-by-default, base-event guarded, audited"
```

---

### Task 4: CLI — `remediation verify` / `reopen-check` (the AC-31-critical 6b half) + all documentation

6b is **not deferrable**: AC-31 is only satisfied once these two verbs land,
and AC-31 is named in the Milestone 5 exit gate (PRD line 1854).

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Create: `scanner/test/cli/remediation-verify-reopen.test.js`
- Create: `commands/remediation.md`
- Modify: `commands/secure.md`
- Modify: `CLAUDE.md` (root)
- Modify: `scanner/src/lineage/CLAUDE.md`
- Modify: `scanner/package.json` (`test:mcp`)

**Interfaces (produced):**

```
agentic-security remediation verify [path] --id <itemId> [--against <commit>]
    [--manual-attestation --approver <id> --reason <text> [--author <id>]]
    [--base-event <hash>] [--output <file>] [--yes]
agentic-security remediation reopen-check [path] [--drift-policy <file>]
    [--against <commit>] [--output <file>] [--yes]
```

**Interfaces (consumed), beyond Task 3's:** `evaluateVerificationEvidence`
(Task 1); `computeGraphDiff` (`lineage/graph-diff.js:316` — takes
`GraphSnapshot` RECORDS, not graphs, and **throws** on an incomparable pair,
`:319`); `loadDriftPolicies`/`evaluateDriftPolicies`
(`lineage/drift-policy.js:112`, `:235` — the latter returns `{violations}`
and takes `(diff, policies, graphAfter)`); `_validateDriftPolicyFile`
(already private in `bin/agentic-security.js:4006`, reuse it — it takes
`(abs, flag, cmdLabel)` and returns `{ok, message}`).

- [ ] **Step 1: Write the failing CLI test file**

Create `scanner/test/cli/remediation-verify-reopen.test.js`. This fixture
needs **two** persisted snapshots (verification needs a real before/after
pair). Hand-write both under
`statePath(root, 'lineage-snapshots', '<commit>.json')`, each a real
`GraphSnapshot` shape with a matching `schemaVersion` (so
`snapshotsComparable` passes) and a `graph` whose `flows[]`/`nodes[]`/
`edges[]`/`dataElements[]` differ exactly as each case needs. Drive the item
to `awaiting_verification` via the Task 3 verbs before each verify case, so
these tests exercise the real path an operator walks.

Assertions, at minimum:

- `V/1` **Happy path**: the required-evidence flow is present in the
  "before" snapshot and absent from the "after" one, with no coverage
  regression → `verify --yes` exits 0, the item folds to `verified`, and
  `verificationSnapshotId` equals the AFTER snapshot's `id`.
- `V/2` **(PRD line 1975)** The after snapshot's `coverage.sources.matched`
  is LOWER than the before snapshot's → `verify --yes` exits 0 having
  appended a `scan_verification` event with `outcome: 'unverifiable'` and
  `reason: 'possible_coverage_regression'`; the item stays
  `awaiting_verification` and `verificationSnapshotId` stays `null`. **An
  unverifiable outcome is a recorded event, not a silent failure and not a
  non-zero exit** — the ledger must show that verification was attempted and
  refused.
- `V/3` A required-evidence flow still present in the after snapshot →
  `unverifiable` with `reason: 'flows_still_present'` and the real
  `unsatisfiedFlowIds` in the report.
- `V/4` A reidentified flow (same correlation key, different id across the
  two snapshots, which is what makes `computeGraphDiff` classify it
  `reidentified`) → `unverifiable` with `reason: 'reidentified'` and the
  `reidentifiedTo` id. Build the fixture so `computeGraphDiff` genuinely
  emits `causeClassification: 'reidentified'` — assert that first, in the
  same test, so the case cannot silently degrade into a plain remove+add.
- `V/5` **Incomparable snapshots** (differing `schemaVersion`) →
  `computeGraphDiff` throws; the CLI catches it and records an
  `unverifiable` outcome naming the real reason, exit 0. Never an uncaught
  throw, never a silent pass.
- `V/6` `verify` from a state other than `awaiting_verification` exits 1 and
  writes nothing.
- `V/7` `verify --manual-attestation --approver X --reason Y` on an item
  opened WITHOUT `--allow-manual-attestation` exits 1 and writes nothing,
  with stderr naming `--allow-manual-attestation`.
- `V/8` The same with `--allow-manual-attestation` at open time succeeds,
  folds to `verified`, leaves `verificationSnapshotId` null, and records an
  approval carrying `evidenceKind: 'manual'` — assert it via `list --format
  json`, so the "manual evidence stays distinguishable" property is checked
  through the real read path an operator uses.
- `V/9` `--manual-attestation` without `--approver` or without `--reason`
  exits 2; an unregistered approver (with a registry present) exits 1.
- `V/10` **Only one snapshot exists** → `verify` exits 2 with the honest
  "an item cannot be verified until a second lineage scan exists" message
  (mirroring `cmdDataflowDiff`'s own self-diff refusal at
  `bin/agentic-security.js:4085-4088`).
- `V/11` `verify` without `--yes` previews the computed outcome (including
  which required flows are unsatisfied) and appends NOTHING.
- `R/1` `reopen-check --drift-policy <file> --yes` where the policy's
  `new_flow` rule matches a flow that reappeared in the after snapshot →
  the verified item is reopened, the `reopened` event's `reason` names the
  drift-policy rule, and the report labels the finding
  `mechanism: 'drift-policy'`.
- `R/2` `reopen-check --yes` with NO drift policy, where a flow in the
  item's own `affectedFlowIds` appears in `diff.removed.flows` or
  `diff.changed.flows` → the item is reopened with
  `mechanism: 'affected-flow-diff'`. **Both mechanisms must be exercised and
  labelled separately** (scoping doc §4.5).
- `R/3` `reopen-check` only ever considers items in state `verified` — an
  `open`/`in_progress`/`accepted_risk` item is never reopened, even when the
  diff would otherwise match.
- `R/4` `reopen-check` with nothing matching exits 0, reopens nothing, and
  says so.
- `R/5` `reopen-check` without `--yes` previews every would-be reopen and
  appends nothing.
- `R/6` A malformed `--drift-policy` file exits 2 (via the reused
  `_validateDriftPolicyFile`).
- `A/1` `mcp-audit.log` carries a `remediation_verify` entry only on a real
  `--yes` verify, and a `remediation_reopen_check` entry only when
  `reopen-check --yes` actually appended at least one event.

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/cli/remediation-verify-reopen.test.js`
Expected: FAIL — `verify`/`reopen-check` are not recognized sub-commands yet.

- [ ] **Step 3: Add `cmdRemediationVerify`**

Beside the Task 3 handlers. Flow:

1. Require `--id`; missing → `return 2`. Fold the ledger and resolve the
   item; unknown id → `return 1` naming the id.
2. **Manual-attestation branch** (`--manual-attestation`): require
   `--approver` and `--reason` (missing → `return 2`); run
   `loadApproverRegistry`/`verifyApprover`/`checkSeparationOfDuties` exactly
   as `accept-risk` does (`return 1` on refusal, with the helper's own
   reason string). Payload
   `{type: 'manual_attestation', at, itemId, approver, reason}` →
   `_remediationWrite(targetAbs, 'verify', 'remediation_verify', payload,
   args)`. The `manualAttestationPermitted` check is `validateTransition`'s
   job — do not duplicate it here; `V/7` proves it fires through the ledger.
   **Return here.** A manual attestation never computes a diff.
3. **Scan-verification branch** (the default):
   - Resolve the AFTER snapshot exactly as `cmdDataflowDiff` does
     (`bin/agentic-security.js:4055-4074`): `loadSnapshots(targetAbs)`, take
     `[0]` as AFTER; `--against <commit>` → `loadSnapshot(targetAbs, commit)`
     as the BEFORE, else `mostRecentPriorSnapshot(targetAbs,
     afterSnapshot.commit)`. **`--against` is a commit key, not a snapshot
     id** — correction #5.
   - The BEFORE snapshot for a remediation verification is preferentially
     **the item's own incident snapshot** (`item.assessment.snapshotId`) —
     that is what makes AC-31's "fixed to the incident snapshot" clause true
     in the verification too. Resolve it by scanning `loadSnapshots` for a
     record whose `.id` matches. When it is no longer on disk, fall back to
     the `cmdDataflowDiff` resolution above and **say so in the report**
     (`beforeSnapshotSource: 'incident' | 'most-recent-prior'`) rather than
     silently substituting a different baseline. An explicit `--against`
     always wins over both.
   - Zero snapshots, or a resolved BEFORE equal to AFTER → `return 2` with
     the honest "cannot be verified until a second lineage scan exists"
     message.
   - `computeGraphDiff(before, after)` inside a `try/catch` — it **throws**
     on an incomparable pair (`graph-diff.js:319`). On a throw, the outcome
     is `{outcome: 'unverifiable', reason: 'incomparable_snapshots',
     detail: e.message}`, NOT an exit-2 abort: verification was genuinely
     attempted and genuinely refused, and the ledger must record that.
   - Otherwise `evaluateVerificationEvidence(diff, item.requiredEvidence)`.
   - Build the payload: on `verified`, `{type: 'scan_verification', at,
     itemId, outcome: 'verified', snapshotId: afterSnapshot.id}`; on
     `unverifiable`, `{type: 'scan_verification', at, itemId, outcome:
     'unverifiable', reason, ...detail fields}` — carry
     `unsatisfiedFlowIds`/`coverageRegressionReasons`/`reidentifiedTo`
     through verbatim so the ledger records WHY, not just THAT.
   - Delegate to `_remediationWrite`. The report additionally carries
     `beforeSnapshotId`, `afterSnapshotId`, `beforeSnapshotSource`, and the
     full evidence outcome.
   - **A `snapshotsComparable`-passed pair means "same `schemaVersion`" and
     nothing more** (`graph-snapshot.js:173`). Put that sentence in the
     handler's own header comment and in `commands/remediation.md`; do not
     paper over it.

- [ ] **Step 4: Add `cmdRemediationReopenCheck`**

1. Resolve the AFTER snapshot as above; `--against <commit>` pins the BEFORE.
   Fewer than two snapshots → `return 2` with the same honest message.
2. Optional `--drift-policy <file>`: validate via the existing
   `_validateDriftPolicyFile(abs, flag, 'reopen-check')` (reuse, do not
   rewrite — it takes a `cmdLabel` for exactly this) → `return 2` on
   `{ok: false}`. Then `loadDriftPolicies(abs)`.
3. Fold the ledger; iterate items in state `'verified'`, sorted by id.
   For each:
   - Prefer the item's own `verificationSnapshotId` as the BEFORE (that is
     the snapshot its verification was granted against — the only
     defensible baseline for "has it regressed since"), falling back to the
     resolved BEFORE, and record which was used in the report.
   - `computeGraphDiff(before, after)` in a `try/catch`; a throw is recorded
     as a skipped item with its reason, never a crash and never a silent
     pass.
   - **Mechanism A (regression, drift policies):** when a policy file was
     supplied, `evaluateDriftPolicies(diff, policies, afterSnapshot.graph)`
     → `{violations}`. A violation naming one of this item's own
     `affectedFlowIds` (check the violation's own flow id field — read
     `_buildViolation` in `drift-policy.js` for its real shape before
     writing this) is a hit with `mechanism: 'drift-policy'`.
   - **Mechanism B (control went away, direct diff read):** any of this
     item's `affectedFlowIds` appearing in `diff.removed.flows` or
     `diff.changed.flows` is a hit with `mechanism: 'affected-flow-diff'`.
     This exists because `drift-policy.js`'s trigger vocabulary is exactly
     `['new_flow', 'changed_flow']` (`:96`) — there is no `removed_flow`
     trigger, so this half **cannot** be expressed as a drift policy at all.
     Say that in the code comment.
   - **Run BOTH mechanisms and label which produced each finding** (scoping
     doc §4.5). Never collapse them into one unlabelled "reopened" reason.
   - On a hit, the payload is `{type: 'reopened', at, itemId, reason}` where
     `reason` names the mechanism AND the specific trigger (the drift rule
     id, or the flow id and which diff bucket it appeared in).
4. Without `--yes`: report every would-be reopen and append nothing,
   `return 0`. With `--yes`: `appendLedgerEvent` per hit (each independently
   validated — an item that raced into a non-`verified` state between the
   fold and the append is correctly rejected by `validateTransition` and
   reported as skipped, not force-written), then ONE `auditCall` with
   `tool: 'remediation_reopen_check'` carrying the reopened item ids —
   only when at least one event was actually appended.
   `--base-event` is deliberately NOT offered on `reopen-check`: it appends
   N events across N items, so a single whole-ledger token has no coherent
   meaning. Document that omission in `commands/remediation.md` rather than
   leaving a reader to wonder.
5. `return 0` on success (preview or write); `2` for the argument/snapshot
   problems above; `4` from a `try/catch` around the appends.

- [ ] **Step 5: Extend the dispatch and help text**

Add the `verify` and `reopen-check` branches to the `case 'remediation':`
block from Task 3 (the `else` message already names all six). Add both verbs
to the `Commands:` help block beside Task 3's four lines.

- [ ] **Step 6: Run the CLI test**

Run: `cd scanner && node --test test/cli/remediation-verify-reopen.test.js`
Expected: PASS, all tests. Iterate here until green.

- [ ] **Step 7: Write `commands/remediation.md`**

A new top-level dispatcher, mirroring `commands/governance.md`'s exact
format: `description`/`argument-hint` frontmatter (keep `description` under
120 chars — `scripts/lint-command-descriptions.mjs` enforces this and is
only reached by `test:lifecycle`, a real trap a prior sub-project hit), one
`##` section per verb, an `### Options` table per verb, an `### Examples`
block, the exit codes, and the `## Implementation` bash block:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs remediation "$@"
exit $?
```

The doc must state plainly, each as its own sentence:

- **The limitation most likely to surprise a first user** (scoping doc §6):
  *an item opened before a second lineage scan exists cannot be verified at
  all.* `computeGraphDiff` needs two persisted `GraphSnapshot` records, and
  `dataflow diff` already refuses a self-diff for the same reason. Scan
  again after the fix lands, with `AGENTIC_SECURITY_LINEAGE_DEEP=1`, then
  verify. Put this **above** the options tables, not in a footnote.
- `verified` is unreachable by marking work complete. `update --state`
  accepts only `in_progress` and `awaiting_verification`; the only two
  routes to `verified` are a `scan_verification` backed by a real rescan
  diff, and an explicitly permitted `manual_attestation` — which is recorded
  and displayed as MANUAL evidence, forever.
- "Compatible rescan evidence" currently means *the two snapshots share a
  `schemaVersion`* and nothing more (`snapshotsComparable`). Two snapshots
  from genuinely different analyzer configurations are reported comparable.
- An incomplete scan can never produce a verification: any measured coverage
  regression records `unverifiable`, never `verified`.
- The ledger is append-only and classified `operator-config` — `reset` never
  deletes it.
- External ticketing / messaging / GRC / case-management connectors are OUT
  of scope (PRD lines 575, 2071). Note that a finding-keyed GitHub/Linear/
  Jira sync already exists at `scanner/src/integrations/tickets.js` and does
  **not** satisfy PRD line 575's connector contract — extend or replace it
  deliberately, do not build a third.
- The HTTP write surface (`POST /api/v1/remediation`) and any UI are
  deferred, same reasoning as `governance propose-edit`.
- Runtime-observation evidence (FR-505 / Digital Twin) is **not** a
  dependency and is not accepted: nothing implements it anywhere in the
  tree, and AC-31's own `or` is rescan-vs-manual-attestation, never
  rescan-vs-runtime (scoping doc corrections 2 and §7).
- `dueDate` is a plain operator-supplied date. No regulation-derived
  deadline is computed ("72 hours from X") — PRD line 2072 requires that be
  a planning prompt tied to cited policy, never an automatic legal
  determination, which is its own scoped work.
- Exit codes 0/1/2/4, each with the conditions that produce it.
- `reopen-check` takes no `--base-event`, and why.

- [ ] **Step 8: Update `scanner/src/lineage/CLAUDE.md`**

Add a new top-level section, placed after the existing "Milestone 5,
Governance Editing Workflow (deliverable #5) — COMPLETE" section:

**`## Milestone 5, Blast-Radius: Remediation Command Center (deliverable #6) — implementation plan written`**

Write it as an **initial plan note, not a completion note** — this is a plan,
not a shipped-and-reviewed deliverable. Mirror the structure of the
neighbouring sections (a module table plus prose) and cover:

- The load-bearing PRD difference from #5: this deliverable **is** gated by
  a named acceptance criterion (AC-31, in the Milestone 5 exit gate at PRD
  line 1854), so the "no AC gates this" argument that carried #5 is not
  available. Surface area narrows; AC-31's three properties do not.
- The module split: `remediation.js` (pure, zero imports) /
  `posture/remediation-ledger.js` (all fs, the only caller of
  `validateTransition`) / the CLI.
- The storage ruling: append-only JSONL + a hash chain mirroring
  `mcp/audit.js`'s `prev`/`GENESIS` exactly, under a lock ported from
  `provenance/lifecycle.js` (not imported — `withLock` is not exported),
  with current state always a fold and never a stored field.
- The three AC-31 rules, each with its PRD citation.
- The five corrections this plan made against live code (the
  `ImpactAssessment` field gap and how `snapshotId`/`affectedFlowIds` are
  actually resolved; the unexported `withLock`; the real chain semantics;
  `--against` being a commit key; the CLI-owned approver gating).
- The disclosed limitations: `snapshotsComparable` is schemaVersion-only;
  no verification is possible before a second lineage scan; the
  "flow still exists but is more protected" verification case is
  deliberately out of scope for this first cut.
- The explicit out-of-scope list from the scoping doc §7.

- [ ] **Step 9: Update root `CLAUDE.md` and `commands/secure.md`**

Root `CLAUDE.md` line 35: change `12 dispatchers` → `13 dispatchers` and
append `` `remediation` `` to the list after `` `governance` ``. Verify with
`grep -n "13 dispatchers" CLAUDE.md` — confirm the edit landed; an `Edit`
whose `old_string` misses returns "String not found" and changes nothing.

`commands/secure.md`: add task-index rows beside the existing `/governance`
row (line 98):

```
| Open a remediation work item from an impact assessment | `/remediation open --assessment <report.json> --owner <id> --due <YYYY-MM-DD> --control <text> --required-evidence <flowIds> [--yes]` |
| Verify a remediation item against a fresh lineage scan | `/remediation verify --id <itemId> [--yes]` |
| Reopen verified items whose control regressed | `/remediation reopen-check [--drift-policy <file>] [--yes]` |
```

Doing this proactively is deliberate — deliverable #5 had to fix the same
doc drift reactively.

- [ ] **Step 10: Rebuild, wire the test, and run the scoped suites**

Run: `cd scanner && npm run build` — exit 0, then `git status` on the WHOLE
`dist/` directory.

Append ` test/cli/remediation-verify-reopen.test.js` to `test:mcp` (read the
current script string first).

Run: `cd scanner && npm run test:mcp && npm run test:lineage && npm run test:posture && npm run test:lifecycle`
Expected: PASS, 0 failures, all four. `test:lifecycle` is where the
command-description lint and the doc-drift checker live, so a `commands/`
or `CLAUDE.md` mistake surfaces here and nowhere else.

- [ ] **Step 11: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: PASS, 0 failures. Capture and read the real exit code immediately
after (`echo $?`) — do not infer success from output length. Run this in the
**foreground**, or via a real background-and-wait pattern (never
fire-and-forget): two prior M5 sub-projects had real coordination problems
from an implementer backgrounding this exact command and never checking
back. If a Chrome-resource-contention-shaped failure appears (a
`cmd-dataflow-export.test.js` / `export-image.test.js` test failing with a
`null`/killed status, unrelated to anything this task touched), re-run just
that file in isolation to confirm it passes alone before concluding it is
pre-existing environmental flakiness — verify it reproduces the same way,
do not just assume.

- [ ] **Step 12: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/dist/ scanner/test/cli/remediation-verify-reopen.test.js scanner/package.json commands/remediation.md commands/secure.md CLAUDE.md scanner/src/lineage/CLAUDE.md
git commit -m "feat(cli): wire remediation verify/reopen-check — AC-31's rescan-gated verification and automatic reopening"
```

---

## Final Review Checklist (for the coordinator, not a task)

**AC-31's three clauses, each verified against shipped code, not plan text:**

- [ ] *Fixed to the incident snapshot.* Confirm the `opened` event carries
  `graphId`, `graphDigest`, and a real `snapshotId` resolved from a
  persisted snapshot, and that `open` genuinely refuses (exit 2) when none
  exists. Re-read the shipped `cmdRemediationOpen`, do not trust the plan.
- [ ] *Marking work complete does not set `verified`.* Grep the shipped
  `remediation.js` for the `state_changed` case and confirm the
  `state === 'verified'` rejection is the FIRST thing it does, before any
  `item.state` consultation — a rejection placed after a state check is
  reachable-around by construction. Then confirm `R5/5` genuinely fails
  against a deliberately mutated implementation (comment the guard out, run
  the test, restore) — a guard nobody has seen fail is not a guard.
- [ ] *A later regression automatically reopens it.* Confirm BOTH reopen
  mechanisms fire on real fixtures and are labelled distinctly in the
  output, and that `reopen-check` never touches a non-`verified` item.

**Write-path ordering (the same properties #5's own review checked):**

- [ ] `--base-event` is compared BEFORE any validation and before any write.
- [ ] `isSafeStateDir` is checked before any `mkdirSync`/append.
- [ ] `auditCall` fires ONLY on a real write — never on a dry run, never on a
  rejected transition, never on an unverified approver. Confirm by reading
  the shipped code path, then by asserting `mcp-audit.log` after the
  dry-run and rejection tests.
- [ ] `validateTransition` is called from exactly ONE production site
  (`appendLedgerEvent`). Grep the whole `scanner/` tree for the symbol; any
  hit outside `remediation.js`, `remediation-ledger.js`, and the tests is a
  second, drift-prone authority — except the CLI's deliberate PREVIEW call
  in `_remediationWrite`, which must be commented as a preview and must not
  be the thing that gates the write.
- [ ] An unexpected I/O error during the append returns 4 with a clean
  message and leaves the ledger unchanged.

**Integrity:**

- [ ] Independently re-derive the chain: read `items.jsonl` after a
  multi-event test, and confirm each line's `prev` equals
  `sha256(<previous line's exact text>)` with the first being `'GENESIS'` —
  using a hand-written check, not the module's own `readLedgerEvents`.
- [ ] Confirm a hand-tampered middle line is genuinely detected, in both
  directions (tampered → truncated stream; untampered → full stream).

**Cross-task signature consistency:**

- [ ] Every `remediation-ledger.js` function the CLI calls exists with the
  exact name and arity Task 2 shipped — `ledgerPaths(scanRoot)`,
  `readLedgerEvents(scanRoot)`, `latestEventHash(scanRoot)`,
  `appendLedgerEvent(scanRoot, eventPayload)`. `appendLedgerEvent` is
  **async**; confirm every CLI call site awaits it.
- [ ] Every `remediation.js` function the ledger and the CLI call exists
  with the exact name Task 1 shipped, and `evaluateVerificationEvidence` is
  called with `(diff, item.requiredEvidence)` in that order.
- [ ] `computeGraphDiff` is called with SNAPSHOT RECORDS, never graphs, at
  every call site, and every call is inside a `try/catch`.
- [ ] `evaluateDriftPolicies` is called as `(diff, policies, graphAfter)` and
  its `{violations}` return is destructured, not treated as an array.

**Boundaries and docs:**

- [ ] `remediation.js` still has zero imports (`R1/3` proves it — confirm
  the test is actually in `test:lineage`'s file list, not merely written).
- [ ] `scanner/src/posture/CLAUDE.md` mentions `remediation-ledger.js` —
  run a session Stop and confirm the drift hook is quiet.
- [ ] The artifact registry entry is `operator-config` with NO
  `retentionClass`, and `test:lifecycle`'s completeness guard passes.
- [ ] Root `CLAUDE.md` says 13 dispatchers and lists `remediation`;
  `commands/secure.md` has the three new rows; `commands/remediation.md`'s
  frontmatter `description` is under 120 characters.
- [ ] `commands/remediation.md` states the "cannot verify until a second
  lineage scan exists" limitation ABOVE the options tables, and states the
  `snapshotsComparable` schemaVersion-only disclosure.

**Final:**

- [ ] Re-run `npm run build` after ALL doc-only edits land and check
  `git status` on the whole `dist/` directory — the CLI help-text edits do
  touch bundled source, unlike the `.md` edits.
- [ ] `npm test` green with a captured exit code, read in the same turn.
