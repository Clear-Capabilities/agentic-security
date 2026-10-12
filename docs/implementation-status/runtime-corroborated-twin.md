# PRD 2 — Runtime-Corroborated Security Twin

**Status as of 2026-10-13: P0 scope complete, honestly bounded (see "Deliberately NOT done" below).**

## What already existed (reused, not rebuilt)

Milestone 5 deliverable #7b ("Runtime-Corroborated Digital Twin," `scanner/src/lineage/CLAUDE.md`'s own
section) already shipped most of this PRD's architecture, under different names, built against the same
`DataFlowGraph v1` this PRD also targets. Per the Shared Engineering Contract ("extend the existing
architecture rather than creating parallel systems"), every item below was extended, never duplicated:

| PRD 2 concept | Existing module | What this PRD added |
|---|---|---|
| Runtime Evidence Schema | `runtime-observation.js` (`RuntimeObservation`, closed-world) | One new attribute key, `network.securityDecision` (closed enum `allowed\|denied`) — see below |
| Initial Telemetry Inputs | `observation-adapters.js` | **Four new adapters**: `otel-json`, `envoy-access-log`, `k8s-audit-log`, `http-access-log` (only `native-jsonl` existed before) |
| Static-to-Runtime Matching | `observation-correlation.js` (3-rung ladder: destination_literal/store_table/queue_topic) | Unchanged — the existing 3 rungs are what the new adapters' output is matched through |
| Runtime Overlay (non-mutating) | `graph.runtimeCorroboration` | Unchanged — already satisfied PRD 2 P0 #4 |
| Runtime Assurance (`runtimeStatus`) | — | New: `runtime-assurance.js` (`computeRuntimeAssurance`), reporting `complete\|partial\|unavailable` plus telemetry window/freshness/mapping-percentage/unmatched counts |
| Security Queries | — | New: `runtime query` with 2 real, graph-backed canned queries, plus honest disclosure of the 3 PRD-named queries this architecture cannot answer |
| CLI | `dataflow observations import/list`, `dataflow twin` | New top-level `runtime` dispatcher (`runtime ingest/status/reconcile/query`) — `ingest` is a thin shim over the existing import command (zero duplicated logic); `status`/`reconcile`/`query` are new, built entirely on the existing correlation/match/store functions |
| Privacy Protection | `runtime-observation.js`'s closed-world validator | Unchanged — already exceeded PRD 2's ask (reject, not redact) |

## What shipped

1. **Four new telemetry adapters** (`scanner/src/lineage/observation-adapters.js`): `parseOtelJsonObservations` (OpenTelemetry JSON trace export — one draft per span, reading only well-known semantic-convention keys), `parseEnvoyAccessLogObservations` (Envoy's default JSON access log, including `response_flags` → `network.securityDecision`), `parseK8sAuditLogObservations` (Kubernetes `audit.k8s.io` JSONL, `objectRef`/`responseStatus.code` → destination/securityDecision, **never** `user.username`), `parseHttpAccessLogObservations` (generic JSON-lines access log). All four are pure (zero imports, no fs), follow the exact `(text, context) -> {drafts, errors}` contract the existing `native-jsonl` adapter established, and drop every field of their source format with no safe, approved destination (query strings, user agents, auth headers, usernames). Registered in `RUNTIME_OBSERVATION_ADAPTERS`/the adapter registry. 27 new tests in `test/lineage/observation-adapters.test.js`.
2. **One new attribute key**: `network.securityDecision` (closed two-value enum `allowed|denied`, deliberately narrower than the generic identifier-value grammar every other scalar attribute gets) — carries PRD 2's "security decision" schema field without widening the closed-world vocabulary into a free-form channel. 4 new tests in `test/lineage/runtime-observation.test.js` (RO/10a-c).
3. **`runtime-assurance.js`** (new module): `computeRuntimeAssurance({importRecords, correlation, now, staleAfterHours})` — pure aggregation, never re-reads a file or re-runs the match ladder. `runtimeStatus` is `'unavailable'` whenever no observation store was ever consulted (never a silent empty report), `'partial'` when anything is unmatched/stale/zero-total, `'complete'` only when every observation matched and nothing is stale. `parseFailures` is honestly always `0` with an explicit disclosure note (a failed import is refused in full and never persisted — AC-29 clause 5 — so there is no on-disk history of parse failures to read). 12 tests.
4. **`runtime` CLI dispatcher** (`bin/agentic-security.js`): `runtime ingest/status/reconcile/query`. `reconcile` re-runs the match ladder against the CURRENT graph for already-imported observations and reports drift from what is stored — diagnostic only, never auto-rewrites the store (preserving `observation-correlation.js`'s own "never silently re-attribute" invariant). `query` supports `internet-facing-to-sensitive` and `sensitive-crossing-boundary` (both real, graph-backed) plus `--list`, and honestly reports `supported: false` with a real reason for the 3 PRD-named queries this architecture cannot answer (see below).
5. **Required fixture**: `scanner/test/fixtures/runtime-twin/` — a small real app (`app.js`) plus 3 telemetry files across 3 of the 4 new adapters, satisfying all 5 of PRD 2's named fixture properties in one scenario. Proven end-to-end against the **real built CLI** (not a unit-test shortcut) in `scanner/test/cli/runtime-twin-cli.test.js`: `scan` → 3× `runtime ingest` → `runtime status`/`reconcile`/`query`, asserting on real output at every step. See that fixture's own `README.md` for the full property-by-property mapping.

## Deliberately NOT done (disclosed, not silently dropped)

- **Data Flow Explorer HTTP server / visual UI wiring** — `scanner/src/server/CLAUDE.md`'s own "What this does NOT do" section already lists `runtime/` among the Milestone 4/5 decision-intelligence endpoints deferred for the read-only S1 server (alongside `stories/`, `scenarios/`, `obligations/`, etc. — none of which have been wired in either). Bolting on an under-reviewed new HTTP endpoint here, without the same scoping-doc-plus-dedicated-test-suite rigor every other endpoint in that file got, would be a real regression in that package's own security discipline. `agentic-security explore . --runtime` is **not implemented**; the `runtime status`/`twin`/`query` CLI surface is the real, working way to read this data today. `frontend/` gets no changes.
- **Authenticated identity in the schema** — PRD 2 names it, but `runtime-observation.js`'s closed-world contract deliberately omits any identity field as a payload-smuggling risk (an identity value is exactly the kind of thing that looks like metadata but carries PII). Not added.
- **Route / function-symbol matching rungs** — the existing 3-rung ladder (destination_literal/store_table/queue_topic) is unchanged. Extending its precedence/ambiguity semantics with a 4th/5th rung needs its own dedicated adversarial review, matching every other increment in `observation-correlation.js`'s own history — not attempted here.
- **`RUNTIME_BLOCKED`/`RUNTIME_POLICY_VIOLATION`/`RUNTIME_EXPLOIT_CORRELATED` edge states** — PRD 2 names 6 edge states; the existing 3-valued `OBSERVATION_LAYERS` is unchanged. `network.securityDecision` records the raw allow/deny fact at the observation level without changing the per-flow layer model — a future increment could build the 3 additional layer values on top of it.
- **3 of PRD 2's own named example queries are architecturally unanswerable** with this contract and are reported as such by `runtime query --list` / a direct query attempt, never silently omitted: `runtime-flows-absent-from-static` (needs a config-declared/auto-correlated edge mechanism — M5 7a / M2 F2-F3, both out of scope everywhere in this codebase), `vulnerable-functions-in-production` (needs function/symbol-level telemetry this adapter set doesn't carry), `identities-using-risky-paths` (no identity field, per the point above).

## Verification

- `npm run test:lineage` (scanner/): 1310/1310 passing (baseline was 1283/1283 before this work).
- `npm run build` + full `npm test` run before pushing (see CLAUDE.md's verification discipline).
- Required-fixture killer scenario proven via the real CLI subprocess (`test/cli/runtime-twin-cli.test.js`), not a unit-test shortcut — all 5 PRD-named properties individually asserted.
