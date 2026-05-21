# Agent Harness Assessment — Evidence Schema

**Version:** 1.0
**Status:** Active
**Companion to:** [HARNESS_ASSESSMENT_SPEC.md](./HARNESS_ASSESSMENT_SPEC.md)

This document defines the wire format a harness must emit to be scored against the
[Spec](./HARNESS_ASSESSMENT_SPEC.md). It is intentionally implementation-agnostic: a
harness can write evidence to a local file, a cloud log bucket, a SIEM, or any other
sink, as long as the shapes match.

The companion JSON Schema files live in `docs/schemas/`:

- `harness-evidence.schema.json` — the union of every entry type.
- `harness-evidence-tool-call.schema.json`
- `harness-evidence-guardrail-decision.schema.json`
- `harness-evidence-validator-outcome.schema.json`
- `harness-evidence-session-start.schema.json`
- `harness-evidence-session-end.schema.json`

A scorer validates a harness's emitted evidence against these schemas as the first step
before assigning rubric levels.

---

## Design principles

1. **One trace, many entries.** Every event in a session shares a `trace_id`. Per-session
   replay is a left-join on this key.
2. **Append-only.** No update or delete operations are defined. Corrections are new
   entries with `correction_of: <prior_event_id>`.
3. **Hash-chained.** Each entry's `prev_hash` is the SHA-256 of the canonical
   serialization of the previous entry. The first entry in a session chains to the
   literal string `GENESIS`.
4. **Self-describing.** Each entry includes a `schema_version` so consumers can decode
   old logs after the schema evolves.
5. **Redactable.** Fields that may contain PII are tagged at the schema level. Redaction
   is performed at emit time, never at consumption — the consumer cannot tell whether a
   redacted field was empty or removed.
6. **Vendor-agnostic.** Provider-specific fields go under `vendor_extensions`. A scorer
   must not require any field outside the standard for any scoring decision.

---

## Common entry envelope

Every entry — regardless of type — has this envelope:

```json
{
  "schema_version": "1.0",
  "event_id":       "evt_01J4QH3X8MZ2YN6F4XQF7Y2P0K",
  "trace_id":       "trc_01J4QH3X8MABCD012345678901",
  "session_id":     "ses_01J4QH3X8MZZZZZ012345678ZZ",
  "ts":             "2026-05-21T18:04:11.663Z",
  "actor":          { "kind": "model" | "harness" | "human" | "tool", "id": "claude-opus-4-7" },
  "type":           "session_start" | "tool_call" | "guardrail_decision" | "validator_outcome" | "session_end",
  "prev_hash":      "sha256:GENESIS" | "sha256:<hex>",
  "payload":        { /* type-specific body, see below */ },
  "vendor_extensions": { /* optional, unconstrained */ }
}
```

Field rules:

- `event_id`: ULID. Sortable by time. Globally unique.
- `trace_id`, `session_id`: ULIDs. Multiple traces may exist inside one session (e.g. a
  sub-agent invocation creates a child trace).
- `ts`: ISO 8601 with millisecond precision, UTC.
- `prev_hash`: SHA-256 over the canonical JSON of the previous entry, hex-encoded with
  `sha256:` prefix. `sha256:GENESIS` only for the first entry in a session.

Canonical JSON for hashing: keys sorted lexicographically, no insignificant whitespace,
UTF-8. Reproducible across implementations.

---

## Per-type payloads

### `session_start`

Captures the harness configuration *as of the moment the session began*. Required for
session replay (PRD §5.4, A-3).

```json
{
  "harness_version":   "agentic-security@0.75.1",
  "spec_version":      "1.0",
  "model": {
    "vendor":  "anthropic",
    "name":    "claude-opus-4-7",
    "version": "20260520",
    "params":  { "temperature": 0.0, "max_tokens": 4096 }
  },
  "tool_manifest_hash":      "sha256:9e1a…",
  "denylist_hash":           "sha256:5f47…",
  "sensitivity_tiers": {
    "read-only":          { "rate_per_min": 60,  "cost_ceiling_usd": null },
    "write-local":        { "rate_per_min": 30,  "cost_ceiling_usd": 1.00 },
    "write-shared":       { "rate_per_min": 10,  "cost_ceiling_usd": 5.00, "requires_approval": true },
    "external-effect":    { "rate_per_min": 5,   "cost_ceiling_usd": 10.00, "requires_approval": true },
    "financial":          { "rate_per_min": 1,   "cost_ceiling_usd": 100.00, "requires_approval": true },
    "identity-modifying": { "rate_per_min": 0,   "cost_ceiling_usd": 0.00,   "requires_approval": true }
  },
  "environment": "production" | "staging" | "dev",
  "user": {
    "id":   "usr_…",
    "role": "internal" | "external" | "admin"
  }
}
```

### `tool_call`

Captures every tool invocation the model made — whether permitted, denied, or errored.

```json
{
  "tool_call_id":       "tc_01J4QH3X8M00000000000000T1",
  "tool_name":          "apply_fix",
  "tool_version":       "1.0",
  "sensitivity_tier":   "write-local",
  "args_hash":          "sha256:7b3e…",
  "args_redacted":      { "path": "src/auth.js", "patch": "<redacted:147b>" },
  "permitted":          true,
  "denial_reason":      null,
  "outcome":            "ok" | "error" | "denied" | "timeout" | "rate_limited" | "cost_limited",
  "outcome_detail":     null,
  "duration_ms":        134,
  "model_reasoning":    null,
  "approval": {
    "required":   false,
    "granted_by": null,
    "granted_at": null,
    "method":     null
  }
}
```

Field rules:

- `args_hash`: SHA-256 of the canonical JSON of the unredacted args. Lets a replayer
  verify a redacted argument set against an out-of-band record.
- `model_reasoning`: included only when the harness has access to it and the policy
  allows. Redacted otherwise. Required field, may be `null`.
- For denied calls, `permitted` is `false`, `denial_reason` is non-null, and `outcome`
  is `denied`. No partial states.

### `guardrail_decision`

Logged whenever a guardrail fires — block, allow-with-warning, or rate-limit. Logged
even when the action would have been permitted anyway, so that "the guardrail ran" is
provable from logs (PRD §5.2).

```json
{
  "guardrail_id":    "destructive-bash:rm-rf-home",
  "guardrail_kind":  "denylist" | "rate_limit" | "cost_limit" | "sandbox" | "untrusted_input_tag" | "semantic_classifier",
  "target_event":    "evt_…",
  "decision":        "block" | "allow" | "warn" | "elevate_required",
  "reason":          "rm -rf with no specific target",
  "denylist_version":"sha256:5f47…",
  "rate_window_s":   60,
  "rate_count":      4,
  "rate_limit":      5
}
```

`denylist_version` MUST match the `denylist_hash` from `session_start`. A mismatch
indicates a guardrail update mid-session, which is itself a scorable event.

### `validator_outcome`

Logged when an output validator runs against a tool result or a final model response
(PRD §5.3).

```json
{
  "validator_id":   "fix-verifier:medium-or-higher",
  "validator_kind": "schema" | "range" | "sanity" | "critic_model" | "consistency",
  "target_event":   "evt_…",
  "verdict":        "pass" | "fail" | "indeterminate",
  "reason":         "original stableId still present in patched file",
  "intent_stated":  "Replace string-concatenated SQL with a parameterized query.",
  "intent_actual":  "Replaced string-concat with template literal; SQL injection still present.",
  "intent_divergence": true
}
```

`intent_stated` / `intent_actual` / `intent_divergence` together implement F-4
(self-consistency).

### `session_end`

Closes the trace. Required to assess M-1/M-2 blast-radius bounds and session-level
metrics.

```json
{
  "outcome":          "ok" | "circuit_broken" | "abandoned" | "fail_closed",
  "tool_call_count":  17,
  "denied_count":     2,
  "validator_failures": 1,
  "circuit_breaker": {
    "tripped":  false,
    "trigger":  null,
    "reset_by": null
  },
  "tail_hash":        "sha256:<hex>"
}
```

`tail_hash` is the hash of the prior entry. Together with `session_start.prev_hash =
sha256:GENESIS` and continuous `prev_hash` chaining, the full session is
tamper-evident; a missing or reordered entry breaks verification from that point.

---

## Optional witnesses

For environments where local-file integrity isn't enough (an attacker with filesystem
write could re-author every entry with fresh `prev_hash` values), entries SHOULD be
mirrored to one or more external witnesses:

```json
{
  "event_id":     "evt_…",
  "trace_id":     "trc_…",
  "session_id":   "ses_…",
  "ts":           "2026-05-21T18:04:11.663Z",
  "prev_hash":    "sha256:…",
  "hash":         "sha256:…"
}
```

Only the metadata, never the payload, is sent to a witness. The witness records its own
sequence; any gap between local-sequence and witness-sequence is evidence of tampering.

Witnesses are P1, not P0 — but the cost of being wrong is high enough that most
production deployments will want one.

---

## Replay

A session can be replayed when, given a `session_id`, a tool returns:

1. The `session_start` payload (model version, prompt, tools available, harness config).
2. The complete ordered sequence of `tool_call`, `guardrail_decision`, and
   `validator_outcome` entries with verified `prev_hash` chain.
3. The `session_end` payload with matched `tail_hash`.

A replay tool MAY supplement the log with out-of-band records (e.g. the unredacted
`args` corresponding to a given `args_hash`) but MUST refuse to display data whose hash
does not match its log entry.

Replay determinism is *not* a requirement on the model — replaying the prompt against
the same model version may produce different outputs. Replay determinism *is* required
on the harness: given the same inputs, the harness's tool-routing, guardrail decisions,
and validator outcomes MUST be reproducible.

---

## Mapping to the spec

| Spec control | Evidence type | Required fields |
|---|---|---|
| T-1, T-3 | `session_start` | `tool_manifest_hash`, `sensitivity_tiers` |
| T-2 | `tool_call` | every model action emits exactly one entry |
| T-4 | `tool_call` | `permitted: false`, `denial_reason`, `outcome: denied` |
| T-5 | `tool_call.approval` | `required: true`, `granted_by`, `granted_at` |
| G-1 | `guardrail_decision` | `guardrail_kind: denylist`, `denylist_version` |
| G-2 | `guardrail_decision` | `guardrail_kind: rate_limit|cost_limit`, rate/cost fields |
| G-3 | `tool_call` | input-source tags in `args_redacted`, plus `approval` for sensitive routes |
| G-4 | `session_start` | sandboxing config captured in `vendor_extensions.sandbox` |
| F-1 | `validator_outcome` | `verdict`, target `tool_call` |
| F-2 | `guardrail_decision` | `guardrail_kind: rate_limit` plus circuit-breaker in `session_end` |
| F-3 | `tool_call.approval` | `granted_by`, `method` |
| F-4 | `validator_outcome` | `intent_stated`, `intent_actual`, `intent_divergence` |
| A-1..A-3 | All entry types | `trace_id`, `prev_hash` chain, `session_start` config snapshot |
| A-4 | (operational) | retention policy outside this schema |
| M-1, M-2 | `session_end` | `circuit_breaker.tripped`, `outcome` values |
| M-3 | `tool_call.approval` | required for `irreversible` sensitivity tiers |
| C-1..C-3 | Cross-cutting | mappings live in `scripts/<framework>/evidence-rules.json` |

---

## Versioning

`schema_version: "1.0"` is the current contract. Minor versions (`1.1`, `1.2`, …) MAY
add optional fields. Major versions (`2.0`) MAY remove or rename fields and require a
spec sign-off. Consumers MUST gracefully degrade when encountering an unknown optional
field.
