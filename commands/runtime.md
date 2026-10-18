---
description: Ingest runtime telemetry, correlate it against the scanned Data Flow Explorer graph, and report an assurance status.
argument-hint: "ingest|status|reconcile|query [path] [flags]"
---

## Runtime

PRD "Runtime-Corroborated Security Twin" — the literal CLI shape that PRD
names. This is NOT a parallel runtime-overlay engine: `ingest` is a thin
shim over the already-shipped `dataflow observations import`; `status`/
`reconcile`/`query` are new, but built entirely on the already-shipped
`correlateObservations`/`matchObservationToGraph`/observation-store
functions (M5 deliverable #7b, "Runtime-Corroborated Digital Twin").

**Four telemetry adapters.** `--adapter native-jsonl|otel-json|envoy-access-log|k8s-audit-log|http-access-log`.
Each reads a local file (never a live network fetch, matching this
codebase's own no-runtime-cloud-calls convention) and produces only
approved, non-payload metadata (destination host/port/scheme, service
name, protocol/TLS, store table, queue topic, and the one closed
allow/deny `network.securityDecision` enum) — never a raw URL query
string, header, username, or request/response body.

**Three honest `runtimeStatus` values, never a 4th meaning "fine."**
`complete` (every imported observation matched and nothing is stale),
`partial` (telemetry exists but is incomplete/stale/has unmatched
observations), `unavailable` (no observation store was ever consulted —
**never** silently reported as "no runtime risk").

**Edge states and identities.** `runtime edges` gives each static edge `STATIC_ONLY`, `RUNTIME_NOT_OBSERVED`, `RUNTIME_OBSERVED`,
`RUNTIME_BLOCKED`, `RUNTIME_POLICY_VIOLATION` or `RUNTIME_EXPLOIT_CORRELATED` (the last only with `--exploit-evidence`). Import with
`--record-identity-tokens` to keep a keyed-hash identity token per observation; the raw identity is never stored.

**What this cannot answer, disclosed by `runtime query` itself.** Which functions were exercised in production needs
function/symbol-level telemetry and a matching rung this codebase does not have. `runtime query --list` names it alongside the four
it CAN answer.

**No Explorer UI wiring.** `agentic-security explore . --runtime` is
**not implemented** — `scanner/src/server/CLAUDE.md`'s own deferred list
already names `runtime/` among the Milestone 4/5 endpoints the read-only
local server does not serve. Use this CLI surface instead.

### `ingest`

Imports one telemetry export file through one adapter, matches each
record against the current graph, and writes it (same refuse-the-whole-
import-on-any-error contract as `dataflow observations import`, which
this literally delegates to).

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--adapter <name>` | Yes | One of `native-jsonl`, `otel-json`, `envoy-access-log`, `k8s-audit-log`, `http-access-log`. |
| `--input <file>` | Yes | The telemetry export to read. |
| `--window-start <iso>` / `--window-end <iso>` | Yes | The telemetry window this export covers. |
| `--environment <name>` | No | Defaults to `"unspecified"`. |
| `--source <label>` | No | Defaults to the input file's basename. |
| `--retain-until <iso>` | No | Recorded as `retention.expiresAt` — **not currently enforced** (see `dataflow observations import`'s own documented caveat). |
| `--yes` | No | Perform the real write. Omitted, this is a dry-run preview (match counts only, nothing written). |

Exit codes: `0` success (preview or real write); `1` the whole import was
refused (a parse or validation error in ANY record — AC-29 clause 5), or
no local lineage graph exists; `2` a usage/argument error; `4` an
unexpected I/O error writing the store.

### `status`

Reports the Runtime Assurance summary: `runtimeStatus`, the telemetry
window actually imported, freshness of the most recent observed event,
mapping percentage, and every limitation — never a silent "no risk"
when telemetry is missing or stale.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--environment <name>` | No | Scope the correlation to one environment. |
| `--window-start <iso>` / `--window-end <iso>` | No | Scope the correlation to a window. |
| `--format json\|markdown` | No | Defaults to `json`. |

Exit codes: `0` success; `1` no local lineage graph exists; `2` a usage
error.

### `reconcile`

Diagnostic-only: re-runs the match ladder against the CURRENT graph for
every already-imported observation and reports which ones would match
differently now (the graph changed since import) — **never rewrites the
store**. Re-import with `runtime ingest` to actually update a stored
match.

Exit codes: `0` always (an empty store or zero drift is not an error);
`1` no local lineage graph exists.

### `query`

Runs one named, graph-backed query against the current correlation
result.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--list` | No | Lists every supported query (and the disclosed-unsupported ones) instead of running one. |
| `--environment <name>` | No | Scope the correlation. |

Supported: `internet-facing-to-sensitive`, `sensitive-crossing-boundary`.

Exit codes: `0` success (a query result is never empty-as-failure — an
honest empty match list is a valid answer); `1` no local lineage graph
exists; `2` an unrecognized query name, or neither a name nor `--list`
was given.

### Examples

```
/runtime ingest --adapter envoy-access-log --input telemetry/envoy.jsonl \
  --window-start 2026-08-01T00:00:00.000Z --window-end 2026-08-31T00:00:00.000Z \
  --environment production --yes
/runtime status --environment production
/runtime reconcile
/runtime query --list
/runtime edges . --environment production --format markdown
/runtime query runtime-flows-absent-from-static . --environment production
/runtime query sensitive-crossing-boundary --environment production
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs runtime "$@"
exit $?
```
