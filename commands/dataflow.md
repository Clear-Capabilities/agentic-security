---
description: Export the Data Flow Explorer graph — PNG/PDF/SVG images, JSON/CSV data, or a self-contained HTML report.
argument-hint: "[path] --format png|pdf|svg|json|csv|html --output <file> [--view <name>] [--size standard|2x]"
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
| `csv` | One row per flow | No Chrome needed. **Does not support redaction** — `--no-redact` is a no-op for this format (a printed warning explains why). |
| `html` | Self-contained, offline-viewable report | No Chrome needed to generate (only to raster it afterward, if you also want a png/pdf). |

## Options

- `--view architecture|privacy|trace|inventory` — which view to capture (default: `architecture`).
- `--no-redact` — include unredacted content. Honored for `json`/`html`; a no-op (with warning) for `csv`.
- `--filter <path-to-json>` — scope the export to a `{"nodeIds":[...],"edgeIds":[...]}` file.

## Examples

```
/dataflow --format png --output report.png
/dataflow --format png --size 2x --output report-2x.png
/dataflow --format svg --output architecture.svg
/dataflow --format json --output graph.json --no-redact
/dataflow --format html --output report.html
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs dataflow export "$@"
exit $?
```
