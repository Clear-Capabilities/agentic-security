# M5, Blast-Radius: Remediation Command Center (deliverable #6): scoping

Per the M5 top-level scoping doc's own row for deliverable #6 ("Large";
depends on #4's `ImpactAssessment` + already-shipped `GraphDiff`/
`drift-policy.js` + ideally #5's write-service pattern). That row is a
scoping-level guess. This document verifies it against the real code and
corrects it in five places — one of them load-bearing enough to change
the whole scope discipline for this sub-project.

---

## 1. What the PRD actually requires (verbatim)

### FR-507's remediation half (PRD lines 569-576)

> Remediation requirements:
>
> - Create local work items linked to canonical claims, affected flows,
>   recommended control, owner, due date, status, approval,
>   exception/acceptance, evidence required, and verification scan.
> - Preserve the original verdict/evidence and show all manual overrides
>   or accepted risks with approver, reason, scope, expiration, and
>   history.
> - A work item can be `verified` only when a subsequent compatible
>   scan/runtime observation supplies the required evidence, or when a
>   manual attestation is explicitly permitted and displayed as manual
>   evidence.
> - Reopening occurs automatically when a verified control regresses or a
>   matching flow reappears.
> - External ticketing, messaging, GRC, or case-management writes are
>   optional integrations and require recipient resolution, explicit
>   authorization, preview, confirmation, and an audit record.
> - Incident exports and work-item data are confidential, local-first,
>   and redact source/recipient details according to export policy.

### AC-31 (PRD lines 1761-1765), verbatim

> ### AC-31: Blast radius and remediation require verification
>
> **Given** a selected compromised provider or failed control affects
> possible and runtime-observed sensitive flows,
> **when** an impact assessment and remediation item are created,
> **then** affected fields, subjects, systems, recipients, jurisdictions,
> obligations, possible/observed partitions, and coverage limitations are
> fixed to the incident snapshot; marking work complete does not set
> `verified` until compatible rescan evidence or an explicitly permitted
> manual attestation satisfies the requirement, and a later regression
> automatically reopens it.

### The `RemediationItem` §10.10 contract row (PRD line 974)

> | `RemediationItem` | Item ID, linked assessment/claims/flows,
> recommended control, owner, due date, state, approvals/exceptions,
> required evidence, verification snapshot, history |

### Four supporting constraints, each load-bearing

- **PRD line 984**: "Work-item state changes are append-only audit
  events; original findings, verdicts, evidence, and manual attestations
  remain distinguishable."
- **PRD line 171** (non-goal): "Closing a remediation item solely because
  a user marked it complete; control verification requires new evidence
  or an explicitly labeled manual attestation."
- **PRD line 1975** (test strategy): "…**incomplete current scans cannot
  produce false remediation**."
- **PRD line 2071** (open-decision table): "Remediation workflow scope |
  Local workflow first; external ticket/GRC integrations only through
  authorized preview-and-confirm connectors."

Plus PRD line 1324's five-part write contract (preview, schema
validation, backup/version guard, user confirmation, append-only audit
event), which names "remediation state" explicitly alongside the
governance edits deliverable #5 already shipped against it.

---

## 2. Five corrections to the M5 top-level doc's own row

### Correction 1 (the load-bearing one): this deliverable IS gated by a real AC — unlike #5

Deliverable #5 (Governance Editing) turned out to have **no** acceptance
criterion anywhere in the PRD, which is what justified its materially
narrower CLI-only cut. **This deliverable is the opposite case.** The
Milestone 5 exit gate (PRD line 1854) reads:

> Exit gate: AC-26, AC-29, and AC-31 plus all declared language/
> performance/accuracy/privacy thresholds pass with published
> limitations.

AC-31 is *named in the exit gate itself*. So the same "a narrower first
cut cannot be accused of failing a named exit criterion" argument that
carried #5 is **not available here**. A narrower cut is still correct on
surface area (no HTTP write route, no external connectors, no UI), but
every clause of AC-31's own `then` must be genuinely satisfied by
whatever ships: fixed-to-snapshot scope, `verified` unreachable by
marking work complete, and automatic reopening on regression. Those three
are the non-negotiable core, and the design below is built around them
rather than around the §10.10 field list.

### Correction 2: AC-31's own "or" is rescan-vs-manual-attestation, not rescan-vs-runtime

The M5 row states FR-505 (Digital Twin) is "a real but explicitly
optional second verification input per **AC-31's own 'or' phrasing**."
AC-31 does not mention runtime at all — its only `or` is between
"compatible rescan evidence" and "an explicitly permitted manual
attestation." The runtime alternative appears in FR-507's own bullet
(line 573, "scan/runtime observation") and the success metric (line 2000,
"compatible rescan/runtime evidence"), neither of which gates the
milestone.

The conclusion the M5 row draws is still right, and in fact **stronger
than it claims**: the gating criterion never mentions runtime evidence,
so Digital Twin is not merely optional — it is absent from the gate.

**And nothing exists to be blocked on.** A repo-wide grep for
`digital.twin` / `DigitalTwin` / `RuntimeObservation` / `runtimeObservation`
over `scanner/src`, `scanner/bin` and `frontend/src` returns **zero
implementation files**. The only hits anywhere are three reserved enum
values and their explanatory comments:
`scanner/src/lineage/obligation-mapping.js:32`'s `'runtime_observed'`
fact type, `scanner/src/lineage/impact-assessment.js:24`'s reserved
`IMPACT_SCOPE_VALUES` member `'observed'`, and prose in
`DESIGN_DESTINATION_RESOLVER.md` / `recipient-profile.js`. There is no
adapter, no observation record, no correlation code, and no artifact.
**Ruling: FR-505 is not a dependency, proven by absence.**

### Correction 3: `lifecycle.js` is a strong precedent, but not for the reason the row gives — and one file, not per-key files

The row calls it "append-only, per-key, file-locked." Verified against
`scanner/src/posture/provenance/lifecycle.js`:

- **Append-only per key: TRUE, with a caveat.** The store is one JSON
  document at `.agentic-security/provenance/lifecycle.json`
  (`lifecycle.js:17`), shaped `{stableId: [event, ...]}`. Events are only
  ever pushed onto a key's array (`lifecycle.js:145`, `:151`) — never
  edited or removed. But the *file* is rewritten whole on every update
  (`lifecycle.js:195`, a plain `fs.writeFileSync` of the entire store).
  "Per-key" means per-key event arrays inside one shared document, **not**
  one file per key. A remediation ledger that mirrors this literally
  inherits a whole-file rewrite on every single-item write.
- **File-locked: TRUE.** `withLock` (`lifecycle.js:36`) takes an exclusive
  `wx` lockfile at `.agentic-security/provenance/lifecycle.lock`, reaps a
  stale lock by PID liveness (`isProcessAlive`, `:83`) or 30s age, retries
  at 25ms, and times out at 5s. It re-reads the lockfile before unlinking
  so it cannot race a fresh holder (`:66`).
- **The API is three functions:** `readLifecycle(scanRoot)` (`:20`),
  `updateLifecycle(scanRoot, currentFindings, {scanId, observedAt, completeScan})`
  (`:159`), `latestOpenIntroduction(store, stableId)` (`:200`). Event
  shape is `{type, commit, authorDate, scanId, observedAt, relatedCommit}`;
  the open-state vocabulary is
  `introduced|reintroduced|reverted|cherry-picked` with `remediated`
  terminal (`:92`, `:145`, `:151`).

**The genuinely transferable idea the M5 row does not name** is
`applyScan`'s `completeScan` guard (`lifecycle.js:118`, comment at
`:106-117`, enforced at `:148`): *a closure claim derived from absence is
only sound if the scan actually looked everywhere it could have looked.*
That is, verbatim, the property PRD line 1975 requires of remediation
("incomplete current scans cannot produce false remediation"). This is
the single most important thing to carry over, and it is a soundness
rule, not a storage shape.

### Correction 4: verification can reuse `GraphDiff`, but `drift-policy.js` only covers the *reopen* half

The row says verification "should be built as a consumer of the
already-shipped `GraphDiff`/`drift-policy.js` engine, not new comparison
logic." Half right.

- **`computeGraphDiff` — genuinely reusable as-is.**
  `scanner/src/lineage/graph-diff.js:316`. Signature is
  `computeGraphDiff(snapshotBefore, snapshotAfter, opts)` — it takes
  **`GraphSnapshot` records, not graphs**, and **throws** (never returns
  an error object) on an incomparable pair (`:319`). Output buckets:
  `added`/`removed` over nodes/edges/dataElements/flows, and
  `changed.flows` over `WATCHED_FLOW_FIELDS` (`:98` —
  `protectionSummary`, `policyVerdict`, `handling`, `coverageStatus`,
  `governanceRefs`).
- **It already computes the exact anti-false-remediation signal AC-31
  needs.** `_coverageRegressionReasons` (compares `sources.matched`,
  `sinks.callStatementSites`, and per-language `filesAnalyzed`) drives
  `flowRemovalCause` (`graph-diff.js:326`): a removed flow under measured
  coverage regression is classified `possible_coverage_regression`, not
  `application_change`. That is PRD line 1975 made computable, already
  shipped. A verification step must treat that classification as
  "unverifiable", never as "fixed."
- **It also already guards against a second false-fix mode.** A flow whose
  `flowId` changed because the analyzer's own `evidenceGrade`/
  `transformationIds` moved gets `causeClassification: 'reidentified'`
  with a `reidentifiedTo`/`reidentifiedFrom` pointer (`:342-377`), rather
  than reading as remove+add. A verification step that naively treats
  `diff.removed.flows` as "the bad flow is gone" would report a refactor
  as a fix without this.
- **`drift-policy.js` does NOT cover verification.** Its trigger
  vocabulary is exactly two values (`drift-policy.js:96`:
  `['new_flow', 'changed_flow']`). There is **no `removed_flow` trigger**,
  so "the flow this item was opened against is gone" cannot be expressed
  as a drift policy at all. `evaluateDriftPolicies(diff, policies, graphAfter)`
  (`:235`) is the right engine for the **reopen** half of AC-31 ("a later
  regression automatically reopens it" — a reappearing flow *is* a
  `new_flow`, a regressing verdict *is* a `changed_flow`), and the wrong
  engine for the verify half. Verification reads `diff.removed.flows` /
  `diff.changed.flows` directly.
- **The comparability check is weaker than "compatible" implies, and must
  be disclosed.** `snapshotsComparable` (`graph-snapshot.js:173`) checks
  **`schemaVersion` equality only** — two snapshots with a genuinely
  different analyzer or config are reported comparable, because
  `graphId`'s own `configHash` component is never populated by any real
  caller. AC-31 says "compatible rescan evidence." Whatever ships must
  either say plainly that "compatible" currently means "same schema
  version," or add a real comparability signal. **Ruling: disclose, do not
  invent** — inventing a comparability dimension here would be a
  `graph-snapshot.js` change with its own blast radius, and the honest
  disclosure is the same discipline every prior sub-project used.

### Correction 5: two things the row calls "genuinely new" already exist

- **Approvals do not need inventing.** The row says "genuinely new fields
  (owner, due date, approvals/exceptions) still need inventing."
  `scanner/src/fix/approver-registry.js` is a real, shipped approvals
  mechanism: `loadApproverRegistry(scanRoot)` (`:50`) reads the
  operator-authored `.agentic-security/authorized-approvers.json`;
  `verifyApprover(registry, identity, requiredRoles)` (`:81`) refuses an
  anonymous or unregistered approver and enforces per-category roles;
  `requiredRolesFor(registry, categories)` (`:112`); and
  `checkSeparationOfDuties(registry, author, approvedBy)` (`:142`)
  implements "the author cannot self-approve." Its own header
  (`:12-23`) is explicit that "verified" means *operator-registered*, not
  cryptographically authenticated — a scope statement this deliverable
  should inherit verbatim rather than restate differently. **Owner and due
  date are genuinely new, and are trivially plain fields.**
- **External ticketing already exists — and is still out of scope, for a
  better reason than the row gives.** `scanner/src/integrations/tickets.js`
  is a shipped two-way GitHub/Linear/Jira sync (`syncTickets`, `:150`)
  with its own `.agentic-security/tickets.json` state file (`:24`), already
  registered in `artifact-registry.js:109` with `retentionClass: 'ticket'`.
  It is keyed by **SAST finding id**, not graph canonical ids, and it
  satisfies none of PRD line 575's five-part connector contract (no
  recipient resolution, no explicit authorization step, no audit record —
  `dryRun` is a preview but not a confirmation gate). Wiring
  `RemediationItem` into it would mean either re-keying that module or
  building a second connector; both are separate scope. **Ruling:
  external connectors OUT, and say that a finding-keyed one already
  exists so a future reader does not build a third.**

---

## 3. What already exists that this deliverable builds on

Everything below is shipped, tested, and read directly for this document.

| Capability | Where | Reusable as-is? |
|---|---|---|
| Impact assessment record | `lineage/impact-assessment.js:46` (`validateImpactAssessment`), `:18` `IMPACT_TARGET_KINDS`, `:24` `IMPACT_SCOPE_VALUES`, `:36` `IMPACT_TRACE_KINDS` | Yes — this is what a remediation item links to |
| Impact computation | `lineage/impact-engine.js:182` `computeImpactAssessment(graph, targetId, opts)`; record literal at `:249` | Yes |
| Graph snapshots | `lineage/graph-snapshot.js:118` `persistGraphSnapshot`, `:130` `loadSnapshots`, `:159` `mostRecentPriorSnapshot`, `:173` `snapshotsComparable` | Yes — already persisted on every `AGENTIC_SECURITY_LINEAGE_DEEP=1` scan |
| Semantic diff | `lineage/graph-diff.js:316` `computeGraphDiff` | Yes (verify half) |
| Drift policies | `lineage/drift-policy.js:112` `loadDriftPolicies`, `:235` `evaluateDriftPolicies` | Yes (reopen half only — no `removed_flow` trigger) |
| Approver identity/roles/SoD | `fix/approver-registry.js:50/:81/:112/:142` | Yes, unmodified |
| Hash-chained audit log | `mcp/audit.js:83` `auditCall({sessionRoot, tool, args, outcome, reason})`, chain field at `:101`, `:127` `verifyAuditLog` | Yes, unmodified |
| Atomic config write | `bin/agentic-security.js:4350` `_writeConfigAtomic` (temp + fsync + chmod-preserve + rename) | Yes — pattern, not import |
| Lock-around-read-modify-write | `posture/provenance/lifecycle.js:36` `withLock`; `posture/fix-history.js:109` `_withLogLock` | Yes — pattern |
| Append-and-read-tolerantly JSONL | `posture/fix-metrics.js:69` (single `appendFileSync` of one newline-terminated record), `:78` `loadFixAttempts` (torn tail dropped, never fatal) | Yes — pattern |
| Signed-graph CLI loader + exit-code contract | `bin/agentic-security.js:3250` (`loadSignedGraph`), used by `cmdDataflowExport`/`cmdDataflowDiff`/`cmdDataflowScenarioApply`/`cmdDataflowImpactAssess` | Yes |

### `fix-history.js` — confirming the row's "weaker precedent" call, with one correction

Confirmed weaker, but "flat mutable-status log" undersells one half and
oversells the other. It IS mutable (an entry gets `revertedAt` stamped in
place) and it IS flat (one log under `.agentic-security/fix-history/`,
`fix-history.js:19`). But it is **also locked** (`_withLogLock`, `:109`,
wrapping `applyFix`/`recover`/`undoLast`/`revertEntryById`/`compactLog`)
and its write primitive `_writeAtomicAndSync` (`:378`) is the *good* part
— it is exactly what `bin/agentic-security.js:4350`'s `_writeConfigAtomic`
was modelled on for deliverable #5. **The record shape is the wrong
precedent; the write primitive is the right one.**

### Deliverable #5's write path — the shape to reuse

`scanner/src/lineage/governance-edit.js` is **pure** (no fs, never throws,
`proposeGovernanceEdit(currentConfig, patch)` at `:149`) and
`cmdGovernancePropose` (`bin/agentic-security.js:4390`) owns every side
effect, in this real order:

1. Parse `--patch`; fail exit 2 (`:4400-4405`).
2. Resolve the target via `statePath`; read the current bytes **exactly
   once**; digest them (`:4409-4411`). The one-read rule is deliberate
   (`:4412-4421`) — it is what makes the digest and the merge base
   provably describe the same bytes.
3. **Version guard before validation and before any write** (`:4430-4437`).
4. Pure validate + merge + diff (`:4439-4444`); a failure exits 1 having
   written nothing.
5. On `--yes` only: `isSafeStateDir` (`:4454`) → backup into a dedicated
   `recipient-profiles-backups/` directory with a
   `<ms>-<8 hex>.bak` name (`:4471-4477`) → `_writeConfigAtomic` (`:4483`)
   → `auditCall` (`:4491-4498`), carrying `beforeDigest` and `backupPath`.
6. Dry-run by default; the report goes to `--output` or stdout (`:4501-4507`).

Exit codes: 0 success (preview or write), 1 validation failure, 2
argument/version-guard problem, 4 unexpected I/O error.

**Ruling: reuse this shape, with one genuine adaptation.** Step 2/3's
whole-file digest is the right guard for a *replaceable document*. It is
the wrong guard for an *append-only log*, where the correct optimistic-
concurrency token is the hash of the last event — which
`mcp/audit.js:101`'s `prev` chain already demonstrates. Adapt, and say so.

### The gap the M5 row does not anticipate: `ImpactAssessment` is never persisted

`cmdDataflowImpactAssess` (`bin/agentic-security.js:4267`) writes the
computed record to a caller-chosen `--output` path (`:4335-4341`) and
**nothing stores it under `.agentic-security/`** — there is no
`impact`/`impact-assessments` entry anywhere in `artifact-registry.js`
(grepped; the only `impact`-adjacent hit in that file is unrelated). So a
`RemediationItem.linkedAssessmentId` would be a dangling reference into a
store that does not exist.

**Ruling: do not build an assessment store.** The remediation item
records the assessment's *identifying and scope-fixing* fields inline —
`assessmentId`, `targetId`, `targetKind`, `traceKind`, `scope`,
`graphId`, `graphDigest`, and the `snapshotId` of the incident snapshot —
plus an optional operator-supplied `assessmentPath` pointing at whatever
file they exported. This is also what makes AC-31's "fixed to the incident
snapshot" clause true *by construction*: the item carries the digest, so
a later reader can prove which graph it was opened against without the
assessment file being available at all.

---

## 4. Design ruling

### 4.1 CLI-only. No HTTP write surface, no UI.

The PRD's own API table names `GET /api/v1/remediation` and
`POST /api/v1/remediation` (lines 1319-1320), but `scanner/src/server/` is
read-only by design and a genuine write route needs CSRF protection plus
a write-authorization mechanism distinct from the read-only session token
— exactly the separately-scoped security work deliverable #5 deferred and
did not touch. Same ruling, same reasoning, same disclosure.

### 4.2 Storage: an append-only JSONL event log under a lock, plus an in-memory fold. Never a mutable `remediation-items.json`.

PRD line 984 ("Work-item state changes are append-only audit events") is
a hard contract, not a preference. A mutable `status` field can be edited
in place and silently lose the history AC-31 depends on.

- **Physical shape: JSONL append**, modelled on
  `posture/fix-metrics.js:69` — one `appendFileSync` of one
  newline-terminated JSON record, and a read path that skips an
  unparseable (torn) line rather than failing (`fix-metrics.js:78-91`).
  Deliberately **not** `lifecycle.js`'s whole-file rewrite (`:195`): that
  is correct for a scan-driven whole-store fold, and wrong for a
  human-driven one-item-at-a-time write, where a partial rewrite can lose
  every *other* item.
- **Concurrency: `lifecycle.js`'s lock, not `fix-metrics.js`'s lock-free
  append.** A remediation write is a read-modify-write (a state
  transition must be validated against the current folded state before
  the event is appended), so it needs the exclusive-lockfile-with-stale-
  reaping shape at `lifecycle.js:36`, adapted to
  `.agentic-security/remediation/items.lock`.
- **Chain: each event carries `prev`**, the SHA-256 of the previous line,
  exactly as `mcp/audit.js:101` does — which gives the ledger its own
  tamper-evidence and gives the CLI its optimistic-concurrency token
  (`--base-event <hash>`), replacing #5's whole-file `--base-digest`.
- **Current state is a fold, never stored.** No derived cache file, no
  second artifact to keep in sync.
- **Path**: `.agentic-security/remediation/items.jsonl` (+ `items.lock`),
  one registered directory covering both — the same packaging choice
  `recipient-profiles-backups` made (`artifact-registry.js:195`) so the
  registry's exact-name matching works.

### 4.3 The `RemediationItem` state machine, kept PRD-literal and minimal

States: `open` → `in_progress` → `awaiting_verification` → `verified`,
plus `accepted_risk` (the exception path) and `reopened`.

The three rules that make AC-31 true, each mapped to its own PRD clause:

1. **Marking work complete sets `awaiting_verification`, never
   `verified`.** There is no CLI path to `verified` that does not carry
   verification evidence. (AC-31's own `then`; PRD line 171's non-goal.)
2. **`verified` is reachable by exactly two event types**, and they stay
   distinguishable forever in the log: `scan_verification` (carrying the
   diff evidence below) and `manual_attestation` (permitted only when the
   item declares `manualAttestationPermitted: true`, and always rendered
   with an explicit "manual evidence" label). (PRD line 573; line 984's
   "manual attestations remain distinguishable".)
3. **`accepted_risk` requires `{approver, reason, scope, expiration}`**
   (PRD line 572's exact field list) and is gated through
   `verifyApprover`/`checkSeparationOfDuties` unmodified. It is an
   exception, never a verification — an `accepted_risk` item never reads
   as `verified`.

Fields, from §10.10 (PRD line 974), all present: item id, linked
assessment (§3's inline identifying fields), `affectedFlowIds` /
`affectedNodeIds` / `affectedEdgeIds` copied from the assessment,
`recommendedControl` (free text), `owner`, `dueDate`, `state`,
`approvals`/`exceptions`, `requiredEvidence`, `verificationSnapshotId`,
and `history` (the fold of this item's own events).

### 4.4 Verification: a real consumer of `computeGraphDiff`, with three refusals

`remediation verify` resolves the item's own incident snapshot as
`before`, the newest persisted snapshot as `after` (`loadSnapshots`,
`graph-snapshot.js:130` — the same resolution `cmdDataflowDiff` already
uses at `bin/agentic-security.js:4056`), and computes
`computeGraphDiff(before, after)`. It then **refuses to set `verified`**
in three cases, each landing the item on an explicit `unverifiable`
outcome event rather than silently failing or silently passing:

- **Incomparable snapshots** — `computeGraphDiff` throws
  (`graph-diff.js:319`); catch it, record the reason.
- **Any `coverageRegressionReasons`** — the diff's own
  `possible_coverage_regression` classification (`graph-diff.js:326`).
  This is PRD line 1975 ("incomplete current scans cannot produce false
  remediation") satisfied by reusing an already-shipped computation, and
  it is the same soundness rule `lifecycle.js:118`'s `completeScan` guard
  encodes for findings.
- **`causeClassification === 'reidentified'`** on the flow the item was
  opened against — the flow did not go away, it was re-minted under a new
  id (`graph-diff.js:342-377`).

Otherwise, `verified` requires the item's `requiredEvidence` to be
genuinely satisfied: each named flow id present in `diff.removed.flows`
with a clean `causeClassification`, or present in `diff.changed.flows`
with a watched-field transition in the improving direction (e.g.
`protectionSummary` `unprotected` → `protected`). The `after` snapshot's
id is stored as `verificationSnapshotId`.

**Disclose**: `snapshotsComparable` (`graph-snapshot.js:173`) currently
means *same `schemaVersion`* and nothing more, so "compatible rescan
evidence" is exactly that strong and no stronger. Do not paper over this.

### 4.5 Reopening: a real consumer of `drift-policy.js`, plus a direct diff read

`evaluateDriftPolicies(diff, policies, graphAfter)`
(`drift-policy.js:235`) covers the regression half of AC-31 natively — a
reappearing flow is a `new_flow` violation, a regressing verdict is a
`changed_flow` violation, and a violation naming a verified item's own
flow/data class/sink reopens it. Because there is no `removed_flow`
trigger (`drift-policy.js:96`), the "a control this item established went
away" case is read directly off `diff.removed.flows`/`diff.changed.flows`
instead. **Both mechanisms, in one `remediation reopen-check` pass — say
plainly which half came from where.**

### 4.6 Confidentiality by construction, not by a redaction pass

PRD line 576 requires work-item data to be confidential and redact
source/recipient details. **Ruling: store only canonical IDs, digests,
and operator-supplied prose — never node names, destinations, evidence
snippets, or recipient facts.** Then `redact-graph.js` is not applicable,
because there is nothing in the ledger for it to redact. This is cheaper
and stronger than adding a redaction pass over a ledger that holds
sensitive content. The one field an operator can put free text into is
`recommendedControl`/`reason`, which is their own prose, not scanned
source.

### 4.7 Audit: `auditCall` **and** the ledger, not either

Every mutating command calls `auditCall` (`mcp/audit.js:83`), exactly as
`cmdGovernancePropose` does (`bin/agentic-security.js:4491`). That records
*"someone ran this command"*. The ledger records *"this item's state
changed"*. They answer different questions and both are required — do not
collapse one into the other.

### 4.8 CLI surface

A new top-level `remediation` command (not a `dataflow` subcommand — this
writes operator/incident state, never the scanned graph; same distinction
that made `governance` its own dispatcher):

```
agentic-security remediation open [path] --assessment <file.json>
    --owner <id> --due <YYYY-MM-DD> --control <text>
    [--required-evidence <flowId,...>] [--output <file>] [--yes]
agentic-security remediation update [path] --id <itemId>
    --state <in_progress|awaiting_verification> [--note <text>] [--yes]
    [--base-event <hash>]
agentic-security remediation verify [path] --id <itemId> [--against <commit>]
    [--manual-attestation --approver <id> --reason <text>] [--yes]
agentic-security remediation accept-risk [path] --id <itemId>
    --approver <id> --reason <text> --scope <text> --expires <YYYY-MM-DD> [--yes]
agentic-security remediation reopen-check [path] [--drift-policy <file>] [--yes]
agentic-security remediation list [path] [--format json|markdown] [--output <file>]
```

Dry-run by default on every mutating verb (`--yes` required to append an
event), matching #5. Exit codes 0/1/2/4, matching #5's contract exactly.

---

## 5. Artifact registry classification — decided now, not later

Deliverable #5's final review found a real Blocking-adjacent gap (I5)
from not thinking about `posture/artifact-registry.js` early. Deciding it
up front:

| Artifact | Ruling |
|---|---|
| `remediation` (dir, covering `items.jsonl` + `items.lock`) | `classification: 'operator-config'`, **no `retentionClass`** |

**Why `operator-config` and not `generated`.** Two precedents pull in
opposite directions. `provenance` (`artifact-registry.js:168`) is
`'generated'` with a deliberate no-`retentionClass` note ("permanent
history, not a cache"), so `reset` *does* delete it. `legal-holds.json`
(`:219`) is *written by the CLI* yet classified `operator-config`
deliberately, with the note: "a plain `reset` must never be able to
delete the very record protecting other artifacts from deletion."

The remediation ledger is the `legal-holds.json` case, and more so: it
holds human decisions, approver identities, and accepted-risk exceptions
with expirations. Deleting it on `reset` is unambiguous data loss and
destroys the append-only audit trail AC-31 requires. **`operator-config`,
no retention class, with a note stating exactly this** — and the note
should name `provenance`'s opposite classification so a future reader
sees the call was made, not missed.

If a future increment ever adds a *derived* artifact (a rendered report),
that one is `generated` with `retentionClass: 'evidence'`. This design
produces none.

---

## 6. Size

**Still Large**, but the shape is different from what the row implies.
The §10.10 field list is cheap; the append-only ledger is a
well-precedented ~200 lines; approvals are a reuse. The real weight is in
the verification path and its refusals, and in the fact that an item
opened before a second lineage scan exists **cannot be verified at all** —
`computeGraphDiff` needs two persisted snapshots, and
`cmdDataflowDiff` already refuses a self-diff for the same reason
(`bin/agentic-security.js:4085-4088`). That is an honest, disclosable
limitation, not a defect, but it is the single thing most likely to
surprise a first user and it must be stated in the command doc.

Recommended split if this needs one: **6a** = the contract + ledger +
`open`/`update`/`list`/`accept-risk` (no verification); **6b** =
`verify`/`reopen-check` (the `GraphDiff`/`drift-policy` consumers). AC-31
is only satisfied once 6b lands, so 6b is not optional and must not be
deferred past the milestone gate — unlike #3b, which genuinely could be.

---

## 7. Out of scope (disclosed, not built)

- **External ticketing / messaging / GRC / case-management connectors**
  (PRD lines 575, 1590, 2071). Explicitly optional in the PRD's own text.
  Note for a future reader: a finding-keyed GitHub/Linear/Jira sync
  already exists at `scanner/src/integrations/tickets.js` and does *not*
  satisfy line 575's connector contract — extend or replace it
  deliberately, do not build a third.
- **The HTTP write surface** (`POST /api/v1/remediation`, PRD line 1320)
  and any frontend/UI work. Same deferral, same reasoning, as #5.
- **Runtime-observation verification evidence** (FR-505 / Digital Twin).
  Not a dependency — nothing exists, and AC-31 does not name it.
  `IMPACT_SCOPE_VALUES`'s reserved `'observed'`
  (`impact-assessment.js:24`) already leaves the door open with no
  breaking change.
- **`affectedObligationIds` on a remediation item.** Deliverable #4 already
  ruled this out and shipped without it, for a real reason
  (`ObligationMapping` records are built on demand per framework
  requirement, never stored on the graph). A remediation item inherits
  that omission rather than reopening the question.
- **A persisted `ImpactAssessment` store.** §3's inline identifying fields
  make one unnecessary for this deliverable.
- **Notification/contractual deadline computation** (PRD line 565, 2072).
  `dueDate` is a plain operator-supplied date. A regulation-derived
  deadline calculator ("72 hours from X") is explicitly *not* built —
  PRD line 2072 requires it be a planning prompt tied to cited policy and
  "never an automatic legal determination," which is its own scoped work.
- **A stronger snapshot-comparability signal.** `snapshotsComparable`
  stays as-is (schemaVersion only); the limitation is disclosed at the
  point of use, not fixed here.
- **Multi-user workflow** beyond `authorized-approvers.json`'s existing
  operator-registered model. `approver-registry.js`'s own scope statement
  ("operator-registered, NOT cryptographically authenticated",
  `:12-23`) is inherited verbatim.
- **Any change to `graph-diff.js`, `drift-policy.js`, `graph-snapshot.js`,
  `impact-engine.js`, or `approver-registry.js`.** This deliverable is a
  consumer of all five. Adding a `removed_flow` drift trigger is a real,
  reasonable follow-up — it is just not needed, because verification reads
  the diff directly.
