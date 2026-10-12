# Runtime-Corroborated Security Twin — required fixture

PRD "Runtime-Corroborated Security Twin" (PRD 2) names a required fixture with five properties.
This fixture (`app/app.js` plus the telemetry files in `telemetry/`) satisfies all five in one
small, real application — proven end-to-end by `test/cli/runtime-twin-cli.test.js` against the real
built CLI (`scan` -> `runtime ingest` x3 -> `runtime status`/`reconcile`/`query`), not a unit-test
shortcut.

| # | PRD property | How this fixture demonstrates it |
|---|---|---|
| 1 | one static path executes | `User.create({ email })` (a database write) — observed `allowed` via `telemetry/k8s-audit-db-allowed.jsonl` (`k8s-audit-log` adapter) |
| 2 | one static path does not execute | `fetch('https://api.stripe.com/v1/charges', ...)` — no telemetry file names `api.stripe.com` anywhere; stays `not_observed_in_window` |
| 3 | one runtime path missing from static analysis | `telemetry/http-shadow-unmatched.jsonl` (`http-access-log` adapter) names `unknown-shadow-service.internal`, which matches no graph node — reported `unmatched`, never silently dropped |
| 4 | one sensitive flow crossing a trust boundary | `analytics.track({ userId: email, ... })` — `req.body.email` (PII) flows to an `external` node. Its destination never resolves to a literal host, so no adapter in this PRD can ever corroborate it either — a genuine, disclosed architectural limit (see `docs/implementation-status/runtime-corroborated-twin.md`), not an oversight |
| 5 | one path blocked by authorization | `sqs.sendMessage({ QueueUrl: 'OrdersQueue', ... })` — observed `denied` via `telemetry/envoy-queue-denied.jsonl` (`envoy-access-log` adapter, `response_flags: "UAEX"`) |

## Why three different adapters, not one

The fixture deliberately exercises 3 of the 4 new telemetry adapters this PRD adds
(`k8s-audit-log`, `envoy-access-log`, `http-access-log` — `otel-json` is covered by its own unit
tests in `test/lineage/observation-adapters.test.js` instead, since an OTLP/JSON export document
has no natural place in a JSONL-telemetry-directory fixture), proving the match ladder's three
real rungs against real adapter output:

- rung 1 (`destination_literal`) is NOT exercised in this fixture (the stripe sink deliberately
  gets no telemetry — see property 2) — it is already proven directly in
  `test/lineage/observation-correlation.test.js`.
- rung 2 (`store_table`) via the k8s-audit-log import against `User.create`'s `storeDetail.table`.
- rung 3 (`queue_topic`) via the envoy-access-log import against the SQS `queueDetail.topic`.
