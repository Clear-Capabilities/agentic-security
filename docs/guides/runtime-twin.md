# Runtime-Corroborated Security Twin

**Status: new.** Static analysis explains what a flow *can* do; this corroborates what has actually
*happened*, from telemetry the operator already has — without ever requiring a raw request body, a
captured payload, or an identity value to leave the operator's own machine.

## What this reuses, and what is new

The correlation engine is entirely the existing Milestone 5 "Runtime-Corroborated Digital Twin"
machinery (`scanner/src/lineage/runtime-observation.js`/`observation-correlation.js`/
`observation-store.js`): a closed-world `RuntimeObservation` contract that rejects (never redacts) any
field capable of carrying a payload value, a 3-rung match ladder against the already-scanned
`DataFlowGraph v1`, and a non-mutating overlay — the static graph is never altered by a runtime fact.

What was missing was telemetry input: only one hand-authored JSONL format could feed it. This adds:

- Four real telemetry adapters: **OpenTelemetry** JSON trace export, **Envoy** access logs,
  **Kubernetes audit logs**, and a generic JSON-lines **HTTP access log** — each a pure, zero-fs parser
  reading only approved metadata (destination host/port/scheme, service name, protocol/TLS, store
  table, queue topic) and dropping everything else (query strings, headers, usernames, bodies).
- `runtime status` — an honest `runtimeStatus: complete|partial|unavailable` summary. `unavailable`
  is the answer whenever no telemetry was ever imported — never silently reported as "no risk."
- `runtime reconcile` — diagnostic drift detection: which already-imported observations would match
  differently against the CURRENT graph (because the code changed since import). Never auto-rewrites
  the stored match.
- `runtime query` — two real, graph-backed queries, plus honest, named disclosure of the three
  queries this architecture cannot answer at all (see "What this cannot answer" below).

## Quickstart

```bash
AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan .
agentic-security runtime ingest . --adapter envoy-access-log --input envoy.jsonl \
  --window-start 2026-08-01T00:00:00.000Z --window-end 2026-08-31T00:00:00.000Z \
  --environment production --yes
```

```json
{
  "adapter": "envoy-access-log",
  "source": "envoy.jsonl",
  "environment": "production",
  "windowStart": "2026-08-01T00:00:00.000Z",
  "windowEnd": "2026-08-31T00:00:00.000Z",
  "recordCount": 1,
  "matched": 1,
  "unmatched": 0,
  "importId": "obsimport:d38b41ae53ff",
  "written": true
}
```

```bash
agentic-security runtime status . --environment production
```

```json
{
  "runtimeStatus": "partial",
  "telemetryWindow": { "start": "2026-08-01T00:00:00.000Z", "end": "2026-08-31T00:00:00.000Z" },
  "mappingPercentage": 100,
  "unmatchedObservationCount": 0,
  "totalObservationCount": 1,
  "limitations": []
}
```

Before any telemetry is ever imported, the same command honestly reads:

```json
{ "runtimeStatus": "unavailable", "missingTelemetry": true,
  "limitations": ["No runtime observation import exists for this scan — runtimeStatus is 'unavailable', never 'complete' or a silent absence of risk. Import telemetry with `runtime ingest` before relying on this report."] }
```

## The required-fixture killer scenario

`scanner/test/fixtures/runtime-twin/` is a small real app plus 3 telemetry files proving all 5 of the
PRD's named properties in one scenario, end to end against the real CLI
(`scanner/test/cli/runtime-twin-cli.test.js`):

1. A database write (`User.create(email)`) **executes** and is observed `allowed` (k8s-audit-log).
2. An outbound call (`fetch('https://api.stripe.com/...')`) **never executes** — no telemetry names it.
3. An observation naming an unrecognized host (`unknown-shadow-service.internal`) is a **runtime path
   missing from static analysis** — reported `unmatched`, never silently dropped.
4. `req.body.email` (PII) flowing to a third-party analytics call is a **sensitive flow crossing a
   trust boundary** — and, since its destination never resolves to a literal host, it can never be
   runtime-corroborated by any adapter this PRD ships either, a genuine disclosed architectural limit.
5. A queue publish (`sqs.sendMessage(OrdersQueue)`) is observed `denied` — a **path blocked by
   authorization** (envoy-access-log, `response_flags: "UAEX"`).

See that fixture's own `README.md` for the full property-by-property mapping.

## What this cannot answer

`runtime query --list` names three of the PRD's own example queries as honestly unsupported, with a
real reason, rather than silently omitting them:

- *"Show runtime flows absent from the static graph"* — needs a config-declared/auto-correlated edge
  mechanism (M5 7a / M2 F2-F3), both out of scope everywhere in this codebase. Every `RuntimeObservation`
  matches an existing static graph node; it never mints a new one.
- *"Show vulnerable functions actually exercised in production"* — needs function/symbol-level
  telemetry; this adapter set only matches destinations (route/service/table/topic).
- *"Show identities using risky paths"* — the `RuntimeObservation` contract deliberately carries no
  identity field, as a payload-smuggling risk.

## What this does not do

No Data Flow Explorer UI wiring — `scanner/src/server/CLAUDE.md`'s own deferred list already names
`runtime/` among the Milestone 4/5 endpoints the read-only local server does not serve; adding one here
without that file's own scoping-doc-plus-dedicated-test-suite rigor would be a real regression in that
package's security discipline. Use the CLI surface documented here instead. See
`docs/implementation-status/runtime-corroborated-twin.md` for the full, itemized status.
