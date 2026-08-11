---
description: Posture + reporting. Status snapshot, A-F report card, harness score, trend, threat model, stack playbook.
argument-hint: "[--status|--report-card|--harness|--trend|--threat|--playbook|--mgmt|--cache]"
---

# /posture

Posture + reporting dispatcher. One command, multiple views.

## Modes

| Flag | Behaviour |
|---|---|
| (default) | **Combined dashboard** — health snapshot + A–F grade + trend arrow in one screen (see below) |
| `--status` | One-screen plugin + project health snapshot — version, last scan, cache size, hook activation, suppressions |
| `--report-card` | Single A–F letter grade + one explanation + one next action |
| `--harness` | Score this project's AI agent harness against the six-domain rubric |
| `--trend` | Findings delta between the last two scans — introduced/fixed/net change |
| `--threat` | Threat model views: STRIDE, personas, playbook, bounty, adversary, surface, boundary, SPOF |
| `--playbook` | Stack-specific posture playbook (Express, FastAPI, Django, Rails, Spring Boot, etc.) |
| `--mgmt` | Posture management surface — auth, network, WAF, telemetry, feature-flag imports |
| `--cache` | **Prompt-cache economics** for this session — cache-hit %, $ saved by caching, $ wasted on avoidable cache misses (model switches / TTL gaps / prefix changes), per-model breakdown. Reads the Claude Code transcript usage; advisory, read-only. |

Add `--json` to any mode to emit machine-readable output for scripting / CI.

## Default dashboard

Bare `/posture` (no flag) renders the three views developers usually want together, in one screen:

1. **Status** — version, last-scan age, hook activation, open findings by severity.
2. **Grade** — the A–F letter from `--report-card` with its one-line rationale.
3. **Trend** — the `↑ / → / ↓` arrow comparing the last two scans (regressing / flat / improving) and the one next action.

If there's no prior scan, the dashboard collapses to a single "run `/scan --all` first" prompt.

## Examples

```bash
/posture                       # status snapshot (default)
/posture --report-card         # A–F grade + next action
/posture --harness             # AI agent harness scoring
/posture --trend               # findings trend
/posture --threat --view stride
/posture --playbook            # stack-specific playbook
/posture --cache               # prompt-cache economics for this session
```

## Implementation

`--harness` and `--trend` below run a real, verified command. `--cache` was already correctly wired. `--status`, `--report-card`, `--threat`, `--playbook`, and `--mgmt` are not yet wired to a concrete invocation — treat any answer for those modes as best-effort narration from context, not a verified command output, until they're fixed the same way.

```bash
FLAG="${1:---status}"
case "$FLAG" in
  --harness)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs harness . ;;
  --trend)
    node -e "
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/security-trend.js').then(m => {
        console.log(JSON.stringify(m.computeTrend('.'), null, 2));
      });
    " ;;
esac
```

`--harness` runs the real `harness` CLI subcommand (`bin/agentic-security.js` → `posture/harness-score.cjs` via `cmdHarness`) — scores this project's `.claude/`, `.cursor/`, `.codex/`, etc. configs against the six-domain rubric.

`--trend` calls `computeTrend()` (`posture/security-trend.js`) directly, reading `.agentic-security/scan-history.json`. That file is populated by `runScan()` itself (`src/runScan.js` calls `appendScanSnapshot` on every scan, CLI or in-process) — no separate wiring needed on the write side. The result is `{ hasTrend, prev, curr, introduced, fixed, delta, critDelta, improving }` when at least two scans exist, or `{ hasTrend: false, message: "Need at least 2 scans..." }` otherwise. Render `introduced`/`fixed`/`delta` as the "findings trend" — there is no weekly bucketing; it's always last-scan-vs-this-scan.

`--cache` runs the `cache-report` CLI subcommand (`scanner/bin/agentic-security.js` → `scanner/src/posture/cache-economics.js`), which parses the Claude Code transcript usage for this session and prints the economics + any detected cache leaks. The same data is available to agents via the `query_cache_telemetry` MCP tool.
