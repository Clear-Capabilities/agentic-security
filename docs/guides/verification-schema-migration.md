# Verification output schema: versions and migration

Every interface that shows a verification (the JSON report, the MCP tools, the text and Markdown reports, and the autopilot
response) presents it through one projection, `agentic-security/verification-view`, version `1.0.0`
(`scanner/src/posture/verification/projection.js`). This page is the migration note for that change: what was added, what did
not change, and how a consumer moves from the previous output to the new one.

## The rule: additive, nothing renamed, nothing removed

No existing field changed its name, its type or its meaning. Every addition appears only on an output that already carries a
version-1 verification record (`agentic-security/verification-record`). A finding, a tool result or an autopilot result without
a record is byte-identical to what it was. The previous output of each interface is pinned as a fixture and the test suite
requires every previous field to still be present with the same value:

| Interface | Previous-schema fixture (`scanner/test/fixtures/verification-compat/`) |
|---|---|
| CLI JSON report (`--format json`, `last-scan.json`) | `report-json.v0.json` |
| MCP `explain_finding` | `mcp-explain-finding.v0.json` |
| Autopilot response (`scripts/autopilot.mjs --json`) | `autopilot-result.v0.json` |

The fixtures were captured from the sources of commit `0a03121b`, the last commit before the shared projection, by running the
deterministic inputs in `inputs.mjs` through `capture.mjs`. To recapture, extract that commit's `scanner/src`, run
`node capture.mjs <extracted>/scanner`, and review the diff.

## What was added

| Where | Field | Meaning |
|---|---|---|
| a finding in the JSON report and in `last-scan.json` | `verificationRecord` | The version-1 record, passed through unchanged (it was previously dropped by the report normalizer). |
| the same | `verificationView` | The shared projection of that record. `null` with `verificationViewErrors` when the record does not validate: a state is never guessed. |
| the same | `verificationReplay` | The typed replay prerequisites a replay attempt reported (`replay/replay.js`), when the producer supplied them. |
| the JSON report, top level | `verificationCoverage` | Trusted non-taint accounting over the findings that carry a record (see below). |
| the JSON report, top level | `advisoryExcluded` | Unpromoted hunt hypotheses a caller put in the finding list. They are excluded from `findings`, listed here (X-207). |
| MCP `explain_finding` | `verificationRecord`, `verificationView` | As above. |
| MCP `verify_fix`, `apply_fix` | `verificationView` | Beside the existing `verificationRecord`. |
| each autopilot result | `verificationView` | Beside the existing `verificationRecord`; `outcome` keeps its native vocabulary and meaning. |
| the text and Markdown reports | a `Verification:` block per finding with a record | The same lines as `verificationView.text`. |
| the hunt report (`runDiscovery`) | `promotions` | Only when the caller opts in with `promote`; see the advisory/gating section. |

The key is `verificationView`, not `verification`. A finding's existing `verification` field is the producer/verifier
separation record (`posture/verification-separation.js`) and keeps its meaning.

## The projection, version 1.0.0

`verificationView` carries, for the same record, identically in every interface:

* `state`: one of `confirmed`, `refuted`, `inconclusive`, `not-run`, `unsupported`, `error`. These stay distinct; none is
  collapsed to a boolean.
* `scope` (description, platform, backend), `oracle`, `attempt`, `commit`, `detectorOrigin`, `preconditions`,
  `confirmationLevel`, `repair`, `reason`.
* `evidence` and `evidenceIds` (and `referencedEvidenceIds`): every evidence item with its kind and producer.
* `replay`: `{ replayable, prerequisites[] }`. Derived prerequisites (`exact-commit`, `runtime-oracle`, `execution-boundary`)
  are computed from the record itself; typed prerequisites a replay attempt reported are merged in by id. Each has a state of
  `met`, `unmet` or `declared`.
* `summary`: what was verified, and what remains untested, in plain words.
* `legacy`: the boolean-style view for older consumers. `verified` is `true` only for `confirmed`, `false` only for `refuted`,
  and `null` for the other four, so a skipped check can never read as a pass.
* `text`: the human-readable lines. The text never labels a partial result "safe" or "fixed"; it states what the check
  established and what it did not, and describes a repair by its own separate status.

No record field is dropped: the test enumerates the record's fields and requires a counterpart for each.

## Trusted-negative accounting

`verificationCoverage` is the first runtime consumer of the trusted-negative denominator
(`oracles/scenario-classes.js`). Only a decided result of an executed oracle of an advertised non-taint class, with proven
preconditions and trusted runtime proof, is counted. Every other record is listed with the reason it was left out (`unsupported`,
`not-run`, `inconclusive`, `error`, `no-executed-oracle`, `malformed`, and so on), so an unsupported or unrun case can never
read as "checked and clean".

## Migrating a consumer

* A consumer that reads the previous fields needs no change.
* A consumer that wants the verification state should read `verificationView.state` (or the record's `outcome`), not infer it
  from `proofTier`, `verifier_verdict` or the autopilot `outcome`. Those native fields keep their own vocabularies, and none of
  them can reach `confirmed` or `refuted` on its own.
* A consumer that needs a boolean should read `verificationView.legacy.verified` and treat `null` as "not established".
* Versioning: `verificationView.schemaVersion` is `1.0.0`. A change that adds a field raises the minor version; one that
  changes the meaning of a field raises the major version and ships with a new fixture set and a new section on this page.
  The record itself is versioned separately (`recordSchemaVersion`, currently `1.0.0`).

## Advisory hypotheses and gating (X-207)

Hunt output is advisory. The report normalizer excludes any hunt hypothesis (`parser: DISCOVERY`, or a `discovery` object)
from every finding list, exit code and output format, and records the exclusion as `advisoryExcluded`. A hypothesis becomes a
finding only through `promoteHypothesis` (`posture/verification/hypothesis-promotion.js`), which needs a verifier receipt that
the promotion code itself verifies, an explicit policy evaluation, and an audit record linking the source hypothesis to the
promoted finding. A confidence score or repeated model agreement is never an input that can satisfy the policy.
