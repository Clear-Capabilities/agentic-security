---
description: Export/diff/watch the Data Flow Explorer graph, apply a what-if scenario, or assess blast-radius impact.
argument-hint: "export|diff|watch|scenario apply|impact assess|observations import|observations list|twin [path] [options] --output <file> --format <fmt>"
---

## Data Flow Explorer export

Exports the already-scanned lineage graph (run
`AGENTIC_SECURITY_LINEAGE_DEEP=1` with `/scan` first if none exists yet —
this command never triggers a scan itself, matching `/dataflow`'s sibling
`explore` command).

## Formats

| `--format` | Output | Notes |
|---|---|---|
| `png` | Raster image | `--size standard` (1680×945, default) or `--size 2x` (3360×1890) — the two AC-23 pinned sizes. `--width`/`--height` for custom sizes (mutually exclusive with `--size`). Requires a local Chrome/Chromium install. |
| `pdf` | PDF document | Requires Chrome. |
| `svg` | Vector image | Requires Chrome. Only supports `--view architecture` (the default) — other views have no real `<svg>` element to extract. |
| `json` | Data envelope with digest + graph | No Chrome needed. |
| `csv` | One row per flow | No Chrome needed. **Does not support redaction or scoping** — `--no-redact` and `--filter` are both no-ops for this format (a printed warning explains why for each). |
| `html` | Self-contained, offline-viewable report | No Chrome needed to generate (only to raster it afterward, if you also want a png/pdf). Not view-scoped — embeds the full interactive report, not one captured view. |
| `dpia` | Data Protection Impact Assessment (Markdown, GDPR Art. 35 framing) | No Chrome needed. Graph-derived — real flows, real protection verdicts, real governance facts (operator-supplied via `.agentic-security/privacy-governance.json`, or honestly marked `manual_required`). Supports `--filter`; **does not support `--view`/`--no-redact`** (both no-ops with a printed warning, same as `csv`). |
| `ropa` | Record of Processing Activities (Markdown table, GDPR Art. 30 register) | No Chrome needed. One row per (flow × data class) — real source/sink/protection/governance columns. Supports `--filter`; **does not support `--view`/`--no-redact`** (both no-ops with a printed warning, same as `csv`). |
| `briefing` | Executive Risk Story (5-chapter Markdown narrative) | No Chrome needed. Graph-derived — ranks real flows and turns them into a decision-focused narrative (Scope & Confidence, Sensitive-Data Footprint, External Exposure, Control & Governance Gaps, Change & Decisions Needed). `--audience` controls wording/verbosity only, never the underlying facts or ranking. Supports `--filter`; **does not support `--view`/`--no-redact`** (both no-ops with a printed warning, same as `csv`/`dpia`/`ropa`). |
| `recipients` | Third-Party and Cross-Border Recipient Intelligence (Markdown table, FR-506) | No Chrome needed. One row per `graph.recipientProfiles[]` entry — provider/service type/legal entity/processor role/jurisdiction(s)/DPA status/confidence, plus a per-row field-evidence footer disclosing which facts are `code_inferred` (from a real technical-provider catalog match), `declared` (operator-supplied via `.agentic-security/recipient-profiles.json`), or `absent`. Supports `--filter` (narrows by whether any of a recipient's `contributingGraphIds` survive the filtered node set); **does not support `--view`/`--no-redact`** (both no-ops with a printed warning, same as `csv`/`dpia`/`ropa`/`briefing`). |
| `coverage` | Language Coverage (Markdown table, M5 language coverage-tier disclosure) | No Chrome needed. One row per `graph.coverage.languages[]` entry — real per-scan `filesAnalyzed`/`filesExpected` counts alongside a curated `tier` (`full`/`partial`/`pattern-only`/`unknown`) and, when known, a product-level `irTaintRecallPct` dated to `docs/METRICS.md`'s own last measurement. The file counts and the recall figure are never presented as one number — the recall figure is a curated estimate, not something this scan measured. **Does not support `--view`/`--no-redact`/`--filter`** (all three no-ops with a printed warning, same as `csv`). |

Governance facts in `dpia`/`ropa` reflect `.agentic-security/privacy-governance.json` as of the scan that produced the graph, not as of export time — edit that file, then re-scan (`AGENTIC_SECURITY_LINEAGE_DEEP=1`) and re-export to pick up a change.

## Options

- `--view architecture|privacy|trace|inventory` — which view to capture (default: `architecture`). **Only affects `png`/`pdf`/`svg`** — a no-op (with warning) for `json`/`csv`/`html`/`dpia`/`ropa`/`briefing`/`recipients`/`coverage`, which are not view-scoped.
- `--no-redact` — include unredacted content. Honored for `json`/`html`; a no-op (with warning) for `csv`/`dpia`/`ropa`/`briefing`/`recipients`/`coverage`.
- `--filter <path-to-json>` — scope the export to a `{"nodeIds":[...],"edgeIds":[...]}` file. A no-op (with warning) for `csv`/`coverage` (a per-language table has no node/edge-id-scoped meaning to narrow by); **genuinely scopes the graph for `dpia`/`ropa`/`briefing`/`recipients`** (unlike `csv`/`coverage`) — `recipients` narrows by whether any of a profile's `contributingGraphIds` survive `nodeIds` (`edgeIds` has no effect on this format, which has no edge concept).
- `--audience board|ciso|privacy|compliance|regulator|technical` — which audience the `briefing` narrative is written for (default: `technical`). Controls prose register and verbosity only — `board` additionally caps Chapter 2 to its seven most important observations; every other value shows the full, uncapped detail. Never changes the underlying facts, evidence, or chapter order. An unrecognized value is a clear exit-2 error regardless of `--format`; a no-op (with warning) for every format except `briefing`.

`briefing`'s own ranking-factor PRIORITY order (which of the nine factors breaks a tie first) is not yet exposed as its own CLI flag — only the CLI-unreachable `emitDecisionStory(graph, {factorOrder})` API parameter, for a future programmatic caller (e.g. an MCP tool). The default order matches `decision-story.js`'s own `RANKING_FACTORS` sequence.

### Examples

```
/dataflow export --format png --output report.png
/dataflow export --format png --size 2x --output report-2x.png
/dataflow export --format svg --output architecture.svg
/dataflow export --format json --output graph.json --no-redact
/dataflow export --format html --output report.html
/dataflow export --format dpia --output dpia.md
/dataflow export --format ropa --output ropa.md --filter selected-scope.json
/dataflow export --format briefing --output board-briefing.md --audience board
```

## Data Flow Explorer diff

Compares two already-scanned `GraphSnapshot`s (FR-503, Data-Flow Time
Machine) — every scan run with `AGENTIC_SECURITY_LINEAGE_DEEP=1` persists
one, commit-keyed, under `.agentic-security/lineage-snapshots/`, alongside
the single-current-graph artifact `export` reads. This command never
triggers a scan itself, same precedent as `export` above: run at least two
scans (at two different commits) first.

Without `--against`, the comparison is always "the newest scanned commit vs.
the most recent scan before it" — the same "compare against the last scan"
default UX `posture/sbom-diff.js` already established for its own diff
feature (see `scanner/src/lineage/graph-snapshot.js`'s own header for why
the CLI cannot independently resolve "the current commit" any other way).
Pass `--against <commit>` to compare against a specific, already-scanned
commit instead.

### Options

| Flag | Required | Notes |
|---|---|---|
| `--output <file>` | Yes | Where the report is written. |
| `--format json\|markdown` | Yes | `json` emits the raw `GraphDiff` record plus a `violations` array (empty when no `--drift-policy` was given). `markdown` renders a human-readable report — added/removed/changed sections, with any drift-policy violations flagged in their own top section. |
| `--against <commit>` | No | Compare the newest snapshot against this specific prior commit instead of the default "most recent prior scan." Exits 2 if that commit was never scanned. |
| `--drift-policy <path-to-json>` | No | Evaluate a `{"policies":[...]}` rule file (`new_flow`/`changed_flow` triggers — e.g. "a new PHI flow reaching an AI provider," or "a flow's `policyVerdict`/`protectionSummary` regressed") against the diff. Omitting this flag skips policy evaluation entirely — never an error, always an empty `violations` array. A malformed policy file is a clear exit-2 error. |
| `--fail-on-drift` | No | Exit 1 (instead of 0) when `--drift-policy` found any violation. The report is still written either way — this only changes the exit code, matching a CI gate's usual needs. |

Exit codes: `0` on success (no violations, or violations found but
`--fail-on-drift` was not passed); `2` on a usage/argument error (missing
`--output`, missing/invalid `--format`, no snapshot to compare against, an
incomparable snapshot pair, a malformed `--drift-policy` file); `1` when
`--drift-policy` violations were found AND `--fail-on-drift` was passed.

### Examples

```
/dataflow diff --output diff.json --format json
/dataflow diff --output diff.md --format markdown
/dataflow diff --output diff.json --format json --against a1b2c3d
/dataflow diff --output diff.json --format json --drift-policy drift-policy.json --fail-on-drift
```

## Data Flow Explorer watch

Re-runs a deep lineage scan (`AGENTIC_SECURITY_LINEAGE_DEEP=1`, set
automatically) on every debounced file-system change under `path`, and
reports the real `GraphDiff` between the previous and current in-memory
graph on stderr — the live-editing counterpart to `diff` above. Blocks
until `Ctrl-C` (or the process is otherwise terminated) — the same UX
shape `/scan --watch` is documented to have, though this command's own
dispatch was specifically written to avoid a real, measured defect in
that other command (it exits in under a second and never actually
watches — see `scanner/src/lineage/CLAUDE.md`'s "watch-mode graph delta
updates" section for the full account).

**Two deliberate, disclosed scope boundaries — read before relying on
this in a workflow:**

- **Never persists a `GraphSnapshot`.** The "before" state for each
  comparison lives purely in memory for the life of the watch process —
  it never calls `persistGraphSnapshot`, and it never writes to
  `.agentic-security/lineage-snapshots/`. Every rescan before an actual
  `git commit` resolves to the same commit-keyed history slot, so
  persisting on every debounced edit would silently overwrite real,
  committed snapshot history with transient, mid-edit graph state.
  Nothing this command does is visible to a later `dataflow diff` run.
- **Never refreshes `.agentic-security/lineage-graph.json`.** An
  already-running `agentic-security explore` session has no live-reload
  mechanism at all (it loads the graph once, before the server starts),
  so this command intentionally does not chase a target that would not
  be visible anyway. To pick up edits in `explore`, stop the watch, run a
  normal scan (`AGENTIC_SECURITY_LINEAGE_DEEP=1`), and restart `explore`.

### Options

| Flag | Required | Notes |
|---|---|---|
| `--drift-policy <path-to-json>` | No | Same `{"policies":[...]}` rule file `diff` accepts. On each rescan, any triggering rule is printed as a louder, clearly-marked block in the live stderr stream (never a separate file). Omitting this flag skips policy evaluation entirely. A malformed policy file is a clear exit-2 error, before the watcher ever starts. |
| `--fail-on-drift` | No | **Only affects print volume, never the exit code** — there is no single exit code to gate for a process that runs indefinitely. A detected violation prints with a louder marker; the process keeps watching either way. |

No `--output`/`--format` — unlike `export`/`diff`, this command's whole
output IS its live stderr stream.

Exit codes: `2` on a usage/argument error (a malformed `--drift-policy`
file), before the watcher ever starts; `1` when the seed scan cannot
produce a data-flow graph at all (nothing to watch/diff against) — also
before the watcher starts; otherwise the process does not exit on its own
and has no "success" exit code — it runs until stopped.

### Examples

```
/dataflow watch
/dataflow watch ./my-service
/dataflow watch . --drift-policy drift-policy.json --fail-on-drift
```

## Data Flow Explorer scenario apply

Simulates a hypothetical architecture change against the already-scanned
lineage graph (M5, "What-If Architecture Simulator," FR-502) — never
mutates the real scan artifact, and never re-runs a scan. Loads the
already-scanned, already-signed graph (same loader as `export`/`diff`
above), applies the operations declared in `--operations` to a clone of
it, and reports what changed. Every field a scenario overrides carries
`'assumed'` evidence — never real evidence — so a scenario report can
never be mistaken for a genuine re-scan result.

The `--operations` file is a JSON object of the form
`{"operations": [...]}`, where each operation is one of the six
supported kinds: `require_transit_protection`, `apply_handling`,
`remove_entity`, `replace_recipient_fact`, `change_storage_fact`,
`change_governance_fact`. An operation targeting an id that does not
exist in the graph is skipped (reported in the output's
`skippedOperations`, never a fatal error) — a scenario written against an
older snapshot degrades honestly rather than failing outright.

`replace_recipient_fact` overrides only the graph node's `destination`
field — a recipient's legal/jurisdiction/provider facts are not
simulated by this operation.

### Options

| Flag | Required | Notes |
|---|---|---|
| `--operations <path-to-json>` | Yes | The `{"operations":[...]}` file describing the hypothetical change. A malformed file, or an operation of an unrecognized kind, is a clear exit-2 error. |
| `--output <file>` | Yes | Where the delta report is written. |
| `--format json\|markdown` | No | `json` (default) emits the raw delta record (`appliedOperations`, `skippedOperations`, `changedEntities`, `removedEntityIds`). `markdown` renders a human-readable report of the same content. |
| `--privacy-sink-policy <path-to-json>` | No | Re-evaluate each touched flow's `policyVerdict` under this policy file, mirroring `dataflow export`'s own privacy-sink-policy evaluation. Omitting this flag leaves every touched flow's `policyVerdict` untouched. |
| `--environment <name>` | No | The environment context used when re-evaluating `--privacy-sink-policy`. |

Exit codes: `0` on success; `1` when the base lineage graph could not be
loaded (missing/unsigned/tampered/malformed — the same four messages
`export`/`diff` already use); `2` on a usage/argument error (missing
`--operations`/`--output`, an unreadable/malformed `--operations` file,
an operation that fails validation).

### Examples

```
/dataflow scenario apply --operations scenario.json --output delta.json
/dataflow scenario apply --operations scenario.json --output delta.md --format markdown
/dataflow scenario apply --operations scenario.json --output delta.json --privacy-sink-policy policy.json --environment production
```

## Data Flow Explorer impact assess

Computes a blast-radius impact assessment (M5, "Impact Assessment,"
FR-507) over the already-scanned lineage graph — a read-only
computation that never mutates anything, and never re-runs a scan.
Loads the already-scanned, already-signed graph (same loader as
`export`/`diff`/`scenario apply` above), then answers "what is
reachable from this compromised node/edge/flow/data element, per the
graph's own already-scanned evidence."

`--target` accepts a canonical `node:*`/`edge:*`/`flow:*`/`data:*` id
only — no other id shape is recognized. `scope` in the output is always
`'possible'` today: there is no runtime-corroboration layer yet to
report `'observed'` instead (a narrower "confirmed exploited" blast
radius). Within that, two genuinely different traversal semantics
apply depending on the target kind, both disclosed via the output's own
`traceKind` field: a `node:*` target reports `traceKind:
'topology_reachable'` — the pessimistic "everything this compromised
node could push to," since compromising a node genuinely puts
everything reachable from it in the blast radius. An `edge:*`/`flow:*`/
`data:*` target reports `traceKind: 'flow_restricted'` — only the
flows that actually carry that specific edge/flow/data element. The
report still names that edge/flow's own two endpoint nodes (you need
them to know what the compromised channel actually touches), it just
never treats either endpoint as itself fully compromised for finding
everything else reachable from it via unrelated edges.

### Options

| Flag | Required | Notes |
|---|---|---|
| `--target <canonical-id>` | Yes | The compromised entity's canonical id — `node:*`, `edge:*`, `flow:*`, or `data:*`. An unrecognized prefix is a clear exit-2 error. |
| `--output <file>` | Yes | Where the assessment report is written. |
| `--format json\|markdown` | No | `json` (default) emits the raw `ImpactAssessment` record. `markdown` renders a human-readable report — a header tying the report back to the graph/moment it was computed (`id`/`graphId`/`graphDigest`/`generatedAt`), then affected nodes/edges, affected data classes, affected recipients, and any coverage limitations. |

Exit codes: `0` on success; `1` when the base lineage graph could not be
loaded (missing/unsigned/tampered/malformed — the same four messages
`export`/`diff`/`scenario apply` already use), OR when a graph loads
and verifies but is structurally malformed (e.g. missing its own
`nodes`/`edges` arrays — `loadSignedGraph` verifies only the signature,
never the schema, so a signed-but-malformed graph can still reach this
point); `2` on a usage/argument error (missing `--target`/`--output`,
or a `--target` with no recognized canonical-id prefix).

### Examples

```
/dataflow impact assess --target node:abc123 --output impact.json
/dataflow impact assess --target flow:def456 --output impact.md --format markdown
```

## Runtime observations (FR-505)

M5, "Runtime-Corroborated Digital Twin" (deliverable #7, the RUNTIME-OBSERVED
half only — "7b"). Imports operator-exported runtime telemetry (an
OpenTelemetry-adjacent trace export, an access log, a queue's own delivery
metadata) as **metadata-only, closed-world** `RuntimeObservation` records,
matched against the already-scanned lineage graph's own node/edge/flow ids —
never a payload, prompt, response, log message, or any other captured value.

**Four disclosed limitations — read before relying on this in a workflow:**

1. **CLI/JSON only — no UI.** Layer toggles, distinct edge treatment, an
   environment/window selector, and an observation inspector are all
   unbuilt. AC-29's clauses are satisfied at the data/artifact layer only.
2. **One adapter — `native-jsonl`.** OpenTelemetry, gateway/mesh, and cloud
   flow adapters are unbuilt; `--adapter otlp` (or anything else) is a clear
   exit-2 error.
3. **Node-granular corroboration, not flow-granular.** An observation proves
   a destination was contacted — never which of several flows sharing that
   sink did it. A flow whose matched sink is shared with sibling flows reads
   `matchConfidence: 'ambiguous'` for exactly that reason.
4. **`edge.provenance` stays `'code'`, always.** Corroboration is additive
   and is never used to reclassify an edge as `'runtime'`-provenanced.

### `agentic-security dataflow observations import`

Dry-run by default, exactly like `governance propose-edit`/`remediation
open`: without `--yes` this computes and prints exactly what WOULD be
imported and writes nothing; with `--yes` it validates, matches against the
graph, and writes one new immutable file under
`.agentic-security/runtime-observations/` (never overwriting a prior
import), then appends a real `mcp-audit.log` entry.

**Refuses the WHOLE import, never a partial one.** If ANY record in the
input file fails validation — at the adapter's own wire-shape layer, or one
layer up at `RuntimeObservation`'s closed-world validator — the entire
import is rejected and every failing record is named by line/index. A
partial import that silently drops the offending record would misrepresent
what the operator believes the artifact holds.

| Flag | Required | Notes |
|---|---|---|
| `--adapter native-jsonl` | Yes | The only adapter implemented today. Any other value is a clear exit-2 error. |
| `--input <file>` | Yes | The operator-exported observation file. A missing/nonexistent path is a clear exit-2 error. |
| `--source <name>` | No | Defaults to the input file's own basename. |
| `--environment <name>` | No | Defaults to `"unspecified"`. Scopes correlation at `dataflow twin` read time. |
| `--window-start <iso>` / `--window-end <iso>` | Yes | The telemetry export's own time window. Both must be parseable ISO-8601 date-times with `start <= end`, or this is a clear exit-2 error. |
| `--retain-until <iso>` | No | When given, must parse as ISO-8601. Recorded as `retention.expiresAt`; omitted means no expiry was declared by the operator (still swept by the artifact registry's own `retentionClass: 'evidence'`). |
| `--yes` | No | Without it: preview only, nothing written. With it: writes the import and appends an audit event. |

**The native-JSONL wire format** — one JSON object per line, up to 5
top-level keys (`environment`, `attributes`, `eventCountBand`,
`firstObservedAt`, `lastObservedAt`; nothing else is accepted — a
pre-declared `matchedNodeIds`/`id`/`matchMethod`/etc. is rejected, not
ignored):

```
{"environment":"production","attributes":{"destination.host":"api.stripe.com","destination.scheme":"https","tls.version":"1.3"},"eventCountBand":"101-1k","firstObservedAt":"2026-08-02T10:00:00.000Z","lastObservedAt":"2026-08-30T10:00:00.000Z"}
```

`attributes` keys must be drawn from the closed metadata allowlist
(service/workload identity, endpoint/destination identity, protocol/TLS
metadata, schema/attribute NAMES — never a value like a URL, SQL statement,
prompt, or log message); `eventCountBand` is a coarse band
(`1`/`2-10`/`11-100`/`101-1k`/`1k+`), never a raw count.

Exit codes: `0` success (preview or real write); `1` a validation failure (a
rejected record, a malformed adapter input, or a graph-load failure — see
`export`/`diff`'s own four `loadSignedGraph` messages); `2` a usage/argument
error or an unsafe target directory; `4` an unexpected I/O error during the
write itself — nothing was written and no audit event was recorded.

### `agentic-security dataflow observations list`

Read-only, never writes, exit 0 always (an empty store is not an error).
Lists every persisted import — adapter, source, environment, window,
observation count, importedAt, and expiry — **but never an attribute key or
value**, in either the plain-text or `--json` form.

| Flag | Required | Notes |
|---|---|---|
| `--json` | No | Emit the same rows as a JSON array instead of one line of text per import. |

### Examples

```
/dataflow observations import --adapter native-jsonl --input runtime-export.jsonl --environment production --window-start 2026-08-01T00:00:00Z --window-end 2026-08-31T00:00:00Z --yes
/dataflow observations list
/dataflow observations list --json
```

## Runtime Digital Twin layers (AC-29)

`agentic-security dataflow twin` renders every statically possible flow in
the already-scanned graph annotated with a **three-valued** runtime-observed
layer — the AC-29 proof surface. Read-only: never writes into
`.agentic-security/`, never triggers a scan, never mutates the graph.

**Four disclosed limitations — read before relying on this in a workflow:**

1. **CLI/JSON only — no UI.** Same as `observations` above — layer
   toggles, distinct edge treatment, an environment/window selector, and an
   observation inspector are all unbuilt.
2. **One adapter — `native-jsonl`.** The twin can only ever be as complete
   as what an operator has imported through that one adapter.
3. **Node-granular corroboration.** A `RUNTIME OBSERVED` flow whose sink is
   shared with sibling flows reports `matchConfidence: 'ambiguous'` — the
   destination genuinely was contacted, but not provably by this specific
   path.
4. **`edge.provenance` stays `'code'`, always.** A `RUNTIME OBSERVED` layer
   is an ADDITIVE annotation, never a reclassification of the edge itself.

**The three layers, and why there are three, not two:**

- **`RUNTIME OBSERVED`** — a real, imported observation matched this flow's
  own sink node/edge, in the requested environment and window. The
  markdown report shows the match method, match confidence, environment,
  and window for every such flow.
- **`not_observed_in_window`** — a real observation store WAS consulted for
  this flow, and genuinely found nothing for it in the requested
  environment/window. This means the flow was **not observed in the
  selected window** — it does **not** mean the flow does not occur (PRD
  line 2098). An unobserved flow may simply sit outside the telemetry
  window, or the operator's export may not cover that destination at all.
- **`not_evaluated`** — no observation store was consulted at all (nothing
  has ever been imported via `observations import`). This is genuinely
  different from `not_observed_in_window`: the former means "nobody
  checked," the latter means "somebody checked and found nothing." A
  `dataflow twin` run against a project with no imports reports every flow
  `not_evaluated`, never `not_observed_in_window`.

Both statically possible paths always remain visible — `dataflow twin`
never filters, removes, or reorders a graph entity; every flow in the graph
appears in the output exactly once, regardless of its layer.

### Options

| Flag | Required | Notes |
|---|---|---|
| `--output <file>` | Yes | Where the report is written. |
| `--format json\|markdown` | No | `json` (default) emits the raw correlation record (`byFlow`, `observedFlowIds`, `notObservedFlowIds`, `notEvaluatedFlowIds`, `limitations`, ...). `markdown` renders a human-readable report — a header (graph id/digest, environment filter, window), a Layers table (one row per flow: flow id, source label, sink label, layer), a detail section per `RUNTIME OBSERVED` flow, and a Limitations section stating the `not_observed_in_window`/`not_evaluated` distinction explicitly. |
| `--environment <name>` | No | Narrows correlation to observations imported under this exact environment name. |
| `--window-start <iso>` / `--window-end <iso>` | No | Narrows correlation to observations whose own window overlaps this one. |

Exit codes: `0` success; `1` when the base lineage graph could not be
loaded (missing/unsigned/tampered/malformed — the same four messages
`export`/`diff`/`scenario apply`/`impact assess` already use); `2` on a
usage/argument error (missing `--output`, an unrecognized `--format`).

### Examples

```
/dataflow twin --output twin.json
/dataflow twin --output twin.md --format markdown
/dataflow twin --output twin-staging.json --environment staging
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs dataflow "$@"
exit $?
```
