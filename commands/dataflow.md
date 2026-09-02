---
description: Export the Data Flow Explorer graph, or diff two scanned snapshots and evaluate drift policies.
argument-hint: "export|diff [path] [options] --output <file> --format <fmt>"
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

Governance facts in `dpia`/`ropa` reflect `.agentic-security/privacy-governance.json` as of the scan that produced the graph, not as of export time — edit that file, then re-scan (`AGENTIC_SECURITY_LINEAGE_DEEP=1`) and re-export to pick up a change.

## Options

- `--view architecture|privacy|trace|inventory` — which view to capture (default: `architecture`). **Only affects `png`/`pdf`/`svg`** — a no-op (with warning) for `json`/`csv`/`html`/`dpia`/`ropa`/`briefing`, which are not view-scoped.
- `--no-redact` — include unredacted content. Honored for `json`/`html`; a no-op (with warning) for `csv`/`dpia`/`ropa`/`briefing`.
- `--filter <path-to-json>` — scope the export to a `{"nodeIds":[...],"edgeIds":[...]}` file. A no-op (with warning) for `csv`; **genuinely scopes the graph for `dpia`/`ropa`/`briefing`** (unlike `csv`).
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
default `agentic-security dataflow diff` establishes for this feature (see
`scanner/src/lineage/graph-snapshot.js`'s own header for why the CLI cannot
independently resolve "the current commit" any other way). Pass
`--against <commit>` to compare against a specific, already-scanned commit
instead.

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

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs dataflow "$@"
exit $?
```
