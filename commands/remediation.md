---
description: Open, track, verify, and auto-reopen Data Flow Explorer remediation items against real rescan evidence (AC-31).
argument-hint: "open|update|verify|accept-risk|reopen-check|list [path] [flags]"
---

## Remediation

The Blast-Radius Remediation Command Center (FR-507). Turns a `dataflow
impact assess` finding into a tracked work item, with an append-only,
hash-chained ledger recording every decision: owner assignment, state
changes, verification outcomes, manual attestations, and accepted-risk
exceptions. AC-31 (a real PRD acceptance criterion, named in the
Milestone 5 exit gate) is only true because of the two rules below.

**The limitation most likely to surprise a first user: an item opened
before a second lineage scan exists cannot be verified at all.**
`remediation verify`'s default (scan-verification) path needs
`computeGraphDiff` to compare two persisted `GraphSnapshot` records —
exactly the same reason `dataflow diff` refuses a self-diff. Fix the
underlying issue, scan again with `AGENTIC_SECURITY_LINEAGE_DEEP=1` so a
new snapshot is persisted, then verify. Until that second scan exists,
`remediation verify` (without `--manual-attestation`) exits 2 with an
honest message rather than pretending to have compared anything.

**`verified` is unreachable by marking work complete.** `update --state`
accepts only `in_progress` and `awaiting_verification` — attempting
`--state verified` is refused outright. The only two routes to
`verified` are a `scan_verification` event backed by a real rescan diff
(`remediation verify`'s default path) and an explicitly-permitted
`manual_attestation` (`remediation verify --manual-attestation`, only
when the item was opened with `--allow-manual-attestation`) — which is
recorded, and displayed, as MANUAL evidence, forever (`verificationSnapshotId`
stays `null`; the approval carries `evidenceKind: 'manual'`).

**"Compatible rescan evidence" currently means only that the two
snapshots share a `schemaVersion`** (`snapshotsComparable`, checked
before `computeGraphDiff` ever runs). Two snapshots produced by
genuinely different analyzer configurations are reported comparable —
there is no `configHash`-level check yet. This is a disclosed limitation,
not fixed by this deliverable.

**An incomplete scan can never produce a `verified` outcome.** Any
measured coverage regression on the AFTER snapshot (fewer matched
sources, fewer sink call-statement sites, fewer files analyzed for a
language that was analyzed before) makes the WHOLE verification refuse
with `reason: 'possible_coverage_regression'`, even for required-evidence
flows that individually look gone — an incomplete scan cannot be trusted
to have honestly seen everything it claims not to have seen (PRD line
1975).

**The ledger is append-only and classified `operator-config`** — it
records human decisions (owner assignment, approvals, manual
attestations, accepted-risk exceptions) that cannot be regenerated from a
rescan, so `agentic-security reset` never deletes it.

**Out of scope, deliberately:** external ticketing / messaging / GRC /
case-management connectors (PRD lines 575, 2071) — a finding-keyed
GitHub/Linear/Jira sync already exists at
`scanner/src/integrations/tickets.js` and does **not** satisfy PRD line
575's connector contract; extending or replacing it is real, separate
work, not attempted here. The HTTP write surface (`POST
/api/v1/remediation`) and any UI are deferred, same reasoning as
`governance propose-edit`. Runtime-observation evidence (FR-505 / Digital
Twin) is **not** a dependency of AC-31 and is not accepted anywhere in
this dispatcher — nothing in this codebase implements it, and AC-31's own
`or` is rescan-vs-manual-attestation, never rescan-vs-runtime. `dueDate`
is a plain operator-supplied date — no regulation-derived deadline is
computed ("72 hours from X"); that is its own, separately-scoped future
work (PRD line 2072).

### `open`

Opens a new remediation work item against an `ImpactAssessment` report
(`dataflow impact assess --format json --output <file>`), fixed to the
incident's own `GraphSnapshot`.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--assessment <report.json>` | Yes | The raw `dataflow impact assess --format json` output. |
| `--owner <id>` | Yes | Who owns this remediation. |
| `--due <YYYY-MM-DD>` | Yes | A plain operator-supplied due date — never regulation-derived. |
| `--control <text>` | Yes | The recommended control/fix. |
| `--required-evidence <flowId,...>` | Yes | Comma-separated flow ids that must be genuinely gone (or newly satisfy the evidence rule) for verification to succeed. |
| `--id <itemId>` | No | Override the generated item id. |
| `--snapshot <commit>` | No | Pin the incident snapshot to a specific commit rather than the newest persisted one. |
| `--allow-manual-attestation` | No | Permit `remediation verify --manual-attestation` on this item later. Without it, a manual-attestation attempt is refused outright. |
| `--output <file>` | No | Where the preview/result report is written. Omitting prints to stdout. |
| `--yes` | No | Perform the real write. Omitted, this is a dry-run preview. |

### `update`

Advances a remediation item's state. `--state verified` is always
refused — see `verify` below for AC-31's own reasoning.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--id <itemId>` | Yes | The item to update. |
| `--state <in_progress\|awaiting_verification>` | Yes | The only two reachable states via this verb. |
| `--base-event <hash>` | No | Optimistic-concurrency guard against the last ledger event hash. |
| `--output <file>` | No | Where the report is written. |
| `--yes` | No | Perform the real write. |

### `verify`

Verifies a remediation item — the ONLY two routes to `verified`.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--id <itemId>` | Yes | The item to verify. Must currently be `awaiting_verification`. |
| `--against <commit>` | No | A COMMIT KEY (never a snapshot id) resolved via the same mechanism `dataflow diff` uses, pinning the BEFORE snapshot. Without it, the BEFORE snapshot preferentially resolves to the item's own incident snapshot, falling back to the most recent prior snapshot when the incident snapshot is no longer on disk. |
| `--manual-attestation` | No | Switches to the manual-attestation branch — never computes a diff. Requires `--approver`/`--reason`, and requires the item to have been opened with `--allow-manual-attestation` (enforced by the ledger's own `validateTransition`, not this flag). |
| `--approver <id>` | With `--manual-attestation` | Gated on the operator's `authorized-approvers.json` registry when one exists — same mechanism `accept-risk` uses. |
| `--reason <text>` | With `--manual-attestation` | Why manual attestation is being used instead of a rescan. |
| `--author <id>` | No | For separation-of-duties checking against `--approver`. |
| `--base-event <hash>` | No | Optimistic-concurrency guard. |
| `--output <file>` | No | Where the report is written. |
| `--yes` | No | Perform the real write. Without it, previews the computed evidence outcome (including which required-evidence flows are unsatisfied) and appends nothing. |

An **unverifiable** scan-verification outcome is a recorded ledger event,
never a silent failure and never a non-zero exit — `--yes` on an
unverifiable outcome still writes a `scan_verification` event (so the
ledger shows verification was genuinely attempted and refused) and still
exits 0. Exit 1 is reserved for a transition `validateTransition` itself
rejects (item not `awaiting_verification`, an unregistered approver, a
disallowed manual attestation).

### `reopen-check`

Automatically reopens `verified` items whose control has regressed since
verification — the third and final AC-31 property.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--drift-policy <file>` | No | A `{"policies":[...]}` file (same shape `dataflow diff --drift-policy` uses). Enables Mechanism A (drift-policy match). Omitted, only Mechanism B runs. |
| `--against <commit>` | No | A default/fallback BEFORE commit, used only for items whose own `verificationSnapshotId` is no longer on disk. Per item, the preferred BEFORE is always that item's own `verificationSnapshotId` — the snapshot its verification was actually granted against. |
| `--output <file>` | No | Where the report is written. |
| `--yes` | No | Perform the real writes (one `reopened` event per hit item). Without it, previews every would-be reopen and appends nothing. |

Every hit is produced by exactly one of two independently-evaluated,
separately-labelled mechanisms — never collapsed into one unlabelled
reason:

- **`mechanism: 'drift-policy'`** — a `--drift-policy` rule (`new_flow` or
  `changed_flow`) matches a violation whose own flow id names one of the
  item's `affectedFlowIds`.
- **`mechanism: 'affected-flow-diff'`** — any of the item's
  `affectedFlowIds` appears in the diff's `removed.flows` or
  `changed.flows` bucket. This exists because `drift-policy.js`'s trigger
  vocabulary is exactly `new_flow`/`changed_flow` — there is no
  `removed_flow` trigger, so "the control itself disappeared from a later
  scan" cannot be expressed as a drift policy at all.

**No `--base-event`.** `reopen-check` can append events across many
items in one invocation, so a single whole-ledger optimistic-concurrency
token has no coherent meaning — each event is still independently
validated at write time (an item that raced into a non-`verified` state
between the fold and the append is rejected and reported, never
force-written).

### `accept-risk`

Records an accepted-risk exception, gated on the operator's
authorized-approvers registry (and separation-of-duties, when
configured) when one exists.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--id <itemId>` | Yes | The item. |
| `--approver <id>` | Yes | Checked against `authorized-approvers.json` when present. |
| `--reason <text>` | Yes | Why the risk is being accepted. |
| `--scope <text>` | Yes | The scope of the exception. |
| `--expires <YYYY-MM-DD>` | Yes | When the exception lapses. |
| `--author <id>` | No | For separation-of-duties checking. |
| `--base-event <hash>` | No | Optimistic-concurrency guard. |
| `--output <file>` | No | Where the report is written. |
| `--yes` | No | Perform the real write. |

### `list`

Lists every remediation item folded from the ledger.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--format json\|markdown` | No | Default `json`. |
| `--output <file>` | No | Where the listing is written. |

### Examples

```
/remediation open --assessment impact.json --owner alice --due 2026-12-31 \
  --control "Add field-level encryption" --required-evidence flow:abc123 --yes
/remediation update --id rem-abc123 --state in_progress --yes
/remediation update --id rem-abc123 --state awaiting_verification --yes
/remediation verify --id rem-abc123 --yes
/remediation verify --id rem-abc123 --manual-attestation --approver bob --reason "compensating control" --yes
/remediation reopen-check --drift-policy drift-policy.json --yes
/remediation accept-risk --id rem-abc123 --approver carol --reason "compensating control" \
  --scope "production only" --expires 2027-01-01 --yes
/remediation list --format markdown
```

Exit codes: `0` success (both the dry-run-preview path and the real
write path, including an `unverifiable` verify outcome or a
`reopen-check` that reopened nothing); `1` a rejected transition (item
not in the required state, an unregistered/unauthorized approver, a
manual attestation the item was not opened to permit) — never writes;
`2` a usage/argument error, a malformed input file, an
optimistic-concurrency (`--base-event`) rejection, the target not
looking like a real project directory, or (for `verify`) fewer than two
comparable snapshots being available; `4` an unexpected I/O error during
the write itself — nothing was written, and no audit event is recorded
for a failed attempt.

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs remediation "$@"
exit $?
```
