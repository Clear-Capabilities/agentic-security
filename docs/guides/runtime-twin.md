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
- `runtime query` — five real queries. `runtime edges` reports the per-edge states and `explore . --runtime` writes the views page.

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

## Edge states, identities and two more queries

`runtime edges` reports, for every static edge, one or more of six states: `STATIC_ONLY` (no telemetry was consulted),
`RUNTIME_NOT_OBSERVED` (consulted, nothing trusted seen in the window, which never means unreachable), `RUNTIME_OBSERVED`,
`RUNTIME_BLOCKED` (every recorded decision was `denied`), `RUNTIME_POLICY_VIOLATION` (observed on a flow the privacy policy
prohibits) and `RUNTIME_EXPLOIT_CORRELATED`. That last one needs evidence you supply (`--exploit-evidence file.json`, each entry
naming exactly one edge, flow or node); seeing traffic is never taken as seeing an attack. Only high- and medium-confidence mappings
count. Observations placed on a node with no modelled flow (a refused queue publish) are reported under their node.

Captured from the `test/fixtures/runtime-twin` scenario:

```
# Static vs runtime, per edge

| Edge | State | Observations | Allowed | Denied | Uncertain |
|---|---|---|---|---|---|
| edge:7026967962a4 | RUNTIME_OBSERVED | 1 | 1 | 0 | 0 |
| edge:fbf347827663 | RUNTIME_NOT_OBSERVED | 0 | 0 | 0 | 0 |

## Observed on a node with no modelled flow

| Node | State | Observations | Allowed | Denied |
|---|---|---|---|---|
| node:queue:ade2f784b653 | RUNTIME_BLOCKED | 1 | 0 | 1 |

- RUNTIME_NOT_OBSERVED means "no trusted observation in this window", never "unreachable" or "safe".
- Only high- and medium-confidence mappings count; low-confidence and ambiguous observations stay unmatched and are counted as uncertain.
- RUNTIME_EXPLOIT_CORRELATED requires explicit operator-supplied evidence naming the edge, flow or node; observation alone never sets it.
```

`runtime query runtime-flows-absent-from-static` lists observed destinations the matcher could not place on any static node. They
are candidates, not proof that static analysis missed a path:

```
{
  "query": "runtime-flows-absent-from-static",
  "supported": true,
  "evaluated": true,
  "candidates": [
    {
      "observationId": "observation:f30e060eef83",
      "destination": "host=unknown-shadow-service.internal service=shadow-svc scheme=https",
      "service": null,
      "environment": "production",
      "firstObservedAt": "2026-08-02T12:00:00.000Z",
      "lastObservedAt": "2026-08-02T12:00:00.000Z",
      "eventCountBand": "1"
    }
  ],
  "note": "Unmatched observations are candidates, not proof that static analysis missed a path: the matcher may be too weak to place them."
}
```

`runtime query identities-using-risky-paths` lists identity tokens seen on policy-violating or exploit-correlated edges. Identity is
recorded only when you import with `--record-identity-tokens`, as `idt_` plus 16 hex of a keyed hash under this install's key. The
raw username is in no persisted file. A token is a pseudonym, not anonymity: anyone with the install key and a candidate name can
confirm a match.

## The five Explorer views

`agentic-security explore . --runtime` (also `runtime explore [path] [--out file.html] [--environment production]`) writes one static
page, `.agentic-security/runtime-explorer.html`: **Static**, **Runtime**, **Static vs Runtime**, **Observed high-risk paths**,
**Unexpected runtime paths**, plus every flow as a path ("field -> API -> service -> DB") with the state of each hop. Expand an edge
to see its static evidence and the runtime observations behind its state side by side. The page has no script and a deny-by-default
content policy, every telemetry value in it is escaped, and with no telemetry it says nothing was consulted instead of showing a clean
runtime view. It is a snapshot, not a live server.

## Vulnerable functions in production

`runtime query vulnerable-functions-in-production [path]` evaluates the last scan's findings against the runtime trace at
`.agentic-security/runtime-trace.jsonl` (or `AGENTIC_SECURITY_RUNTIME_TRACE_PATH`) with the same function, line and route matcher the
scan uses, and lists the findings whose path appears in it. Findings not listed are counted as not observed or unknown. That is a
statement about the trace window and its sampling, not about reachability. With no usable trace it answers "not evaluated", never
"none".

## What this cannot answer

- An identity query is only as complete as the identity telemetry: an edge with no identity field contributes nothing, which is not
  evidence that no identity used it.
- The graph itself carries no route or function symbol, so route/function evidence attaches to scan findings, not to graph edges.

## What this does not do

No Data Flow Explorer UI wiring — `scanner/src/server/CLAUDE.md`'s own deferred list already names
`runtime/` among the Milestone 4/5 endpoints the read-only local server does not serve; adding one here
without that file's own scoping-doc-plus-dedicated-test-suite rigor would be a real regression in that
package's security discipline. Use the CLI surface documented here instead. See
`docs/implementation-status/runtime-corroborated-twin.md` for the full, itemized status.
