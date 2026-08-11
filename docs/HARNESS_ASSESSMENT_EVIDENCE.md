# Harness Assessment Evidence — wire format (v1.0)

A conforming harness scored under `docs/HARNESS_ASSESSMENT_SPEC.md`'s **Audit Evidence** domain (A-1 through A-6) emits a stream of events matching this document and `docs/schemas/harness-evidence.schema.json`. The schema is the enforceable artefact — this document explains what each field means and why. If they disagree, the schema wins; file the doc as wrong.

## Why a hash chain, not just a log

A-2 ("Integrity-protected storage") and A-3 ("Sessions can be replayed from logs") are both properties of a *tamper-evident* log, not any structured log. Every entry carries `prev_hash`, chaining it to the entry before — an append, a deletion, or a reorder anywhere in the chain breaks every hash after the tamper point. The first entry in a session's chain sets `prev_hash` to the literal string `sha256:GENESIS`. This is the same tamper-evidence shape as this project's own `posture/attestation.js`, applied to the *harness's own operational log* rather than to a scan's findings.

## Entry envelope

Every entry is one JSON object with these top-level fields (see the schema for exact patterns):

| Field | Shape | Purpose |
|---|---|---|
| `schema_version` | `"1.0"` (major.minor) | Which version of this document the entry conforms to. |
| `event_id` | `evt_` + 26-char ULID | Unique, time-sortable event identifier. |
| `trace_id` | `trc_` + 26-char ULID | Groups every event in one logical operation (e.g. one user request that triggers several tool calls) — this is what makes F-4 (self-consistency: intent vs. tool calls) checkable after the fact. |
| `session_id` | `ses_` + 26-char ULID | Groups every event in one harness session. |
| `ts` | RFC 3339 date-time | When the event was recorded. |
| `actor` | `{kind, id}` | Who caused it: `model`, `harness`, `human`, or `tool`. |
| `type` | one of the five below | Which payload shape applies. |
| `prev_hash` | `sha256:GENESIS` or `sha256:<64 hex>` | The hash-chain link (see above). |
| `payload` | object, shape depends on `type` | The event body. |
| `vendor_extensions` | object, optional | Harness-specific fields that don't fit the spec; never required for a control to pass. |

`additionalProperties: false` at the top level — an entry with an extra top-level field is not a valid entry. Put harness-specific data under `vendor_extensions` instead.

## The five event types

### `session_start`

Recorded once per session, before any tool call. Establishes the configuration the rest of the session is checked against: `harness_version`, `spec_version`, the model identity, a `tool_manifest_hash` and `denylist_hash` (so T-1/G-1 can be verified as "this exact config was active," not merely "a config exists somewhere"), the `sensitivity_tiers` map (rate/cost/approval requirements per tier — this is T-3's evidence), and the `environment` (`production`/`staging`/`dev`).

### `tool_call`

One per tool invocation. `sensitivity_tier` must be one of the six tiers (`read-only` through `identity-modifying` — ascending blast radius, matching M-1's "defined blast radius per tool category"). `permitted` + `outcome` + `denial_reason` together are what makes T-4 ("denied calls logged with reason") checkable: a `permitted: false` entry with `denial_reason: null` is non-conforming. `args_hash` (not raw args) is required; `args_redacted` is optional and only for args safe to retain in the clear. `approval` records JIT elevation (T-5) when the tier required it.

### `guardrail_decision`

One per guardrail evaluation — not only the blocks. `decision` is `block` / `allow` / `warn` / `elevate_required`. Recording `allow` decisions too (not just denials) is what makes G-2's rate-limit evidence auditable: `rate_count`/`rate_limit`/`rate_window_s` on an `allow` decision show how close to the ceiling the session ran, which a denial-only log cannot show.

### `validator_outcome`

One per output-validation or consistency check (F-1, F-4). `intent_stated`/`intent_actual`/`intent_divergence` are what F-4 ("self-consistency: intent vs. tool calls") reads — a harness that never populates them cannot reach level 2 on Feedback Loops even if every other control is present, because there is no evidence the check ever ran.

### `session_end`

Recorded once, closing the session. `tail_hash` is the hash of the last entry before this one — a verifier confirms the whole chain resolves to `tail_hash` before trusting `outcome`/`tool_call_count`/`denied_count`. `outcome: fail_closed` records that a failure was handled by refusing rather than degrading — the evidence for M-2/M-3.

## What conformance does and does not prove

Emitting schema-valid entries proves the harness *recorded* these events in a tamper-evident chain. It does not prove the recorded events are the true and complete set of everything that happened — that is a property of the emission code, which the schema cannot see. `A-3` ("sessions can be replayed from logs") is the closest this gets to an external check: if replaying the chain reproduces the session's observable behaviour, the log was complete for that session. Same disclosure discipline as `posture/attestation.js`'s `doesNotProve`: state the boundary, don't imply more than the mechanism delivers.

## Validating a log

```bash
node -e "
const Ajv = require('ajv');
const schema = require('./docs/schemas/harness-evidence.schema.json');
const ajv = new Ajv();
const validate = ajv.compile(schema);
const entry = JSON.parse(process.argv[1]);
console.log(validate(entry) ? 'valid' : validate.errors);
" '<one JSON entry>'
```

(No `ajv` dependency is currently vendored in this repo for this purpose — the snippet above shows the shape of the check; wiring a `harness-evidence:validate` script is tracked as follow-up work, not implemented here.)
