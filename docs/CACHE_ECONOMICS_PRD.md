# PRD — Prompt-Cache Economics (measured, cache-aware token-cost optimization)

**Status:** Phase A (F1–F3) shipped in v0.121.0 · Phase B (F4–F6) shipped in v0.122.0
**Version:** 1.1
**Date:** 2026-06-28
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** A cache-economics capability for the agentic-security plugin: a transcript
telemetry/report engine (`scanner/src/posture/cache-economics.js`), an MCP tool, a
`/posture --cache` CLI surface, a live invalidator-guard hook, and break-even/TTL
extensions to the model-cost advisor. Plus three Phase-B features (depth-first
philosophy, subagent-offload advice, cost HUD/statusline).
**Audience:** Engineering (scanner + hooks), with a product lens on the vibecoder ICP.

---

## 1. Purpose

The plugin already advises a cheaper model+depth per prompt and prefers a
cache-preserving effort drop over a model switch. This PRD makes **prompt-cache
economics** a first-class, *measured* capability — the differentiator neither
OpenRouter (a gateway) nor RouterBench (a benchmark) provides for Claude Code:

1. **Prove** what caching saves and what it wastes, from real transcript usage.
2. **Catch** the silent cache-killers (model switches, mid-session prompt edits,
   TTL gaps) before/after they cost money.
3. **Route** with cache awareness — a model switch is only advised when it pays off
   past its cache-rewarm break-even.

Six features (F1–F6). **F1–F3 ship now (v0.121.0); F4–F6 are specced here for
v0.122.0.** This is a planning + record document; F1–F3 are implemented and the
acceptance criteria below are met by the shipped tests.

---

## 2. Methodology & honesty preface

- **The data is real, on disk.** Claude Code writes per-turn `usage`
  (`cache_read_input_tokens`, `cache_creation_input_tokens`, `input_tokens`,
  `output_tokens`, plus a 5m/1h write split) and `message.model` to
  `~/.claude/projects/<enc>/*.jsonl` (`<enc>` = `CLAUDE_PROJECT_DIR` with `/` and
  `.` → `-`). We price those against per-model rates. **No network, no estimates
  for the report** — only the *advisor's* forward-looking savings remain estimates.
- **Advisory-only still holds.** No hook can switch the model/effort; every feature
  measures or advises. The user acts via `/model` + `/effort`.
- **Cache rates** (claude-api prompt-caching): read ≈ 0.1× input; 5-min write ≈
  1.25×; 1-hour write ≈ 2× input.
- **Transcript locator** prefers a hook-provided `transcript_path`, else derives
  `<enc>` from `CLAUDE_PROJECT_DIR` and takes the latest jsonl; graceful no-op when
  absent. A CJS twin (`hooks/lib/transcript.js`) serves the CJS hooks; a parity test
  keeps it in lockstep with the ESM parser.

---

## 3. Current state (before this PRD)

| Surface | State |
|---|---|
| Per-prompt advisor (`hooks/model-cost-advisor.js`) | Cost+depth heuristic, dial, one-time cache-rewarm penalty (turns-estimated cache size) |
| Cache size signal | Estimated as `turns × 4000` — no real measurement |
| Cache telemetry | None — transcript `usage` unused |
| Invalidator detection | None |
| Eval | `bench/router-replay/` (downgrade-regret, hull advantage) |

---

## 4. Requirements (F1–F6)

### F1 — Cache telemetry + wasted-spend report  ·  Phase A  ·  shipped
- **Definition.** A per-session report: cache-hit %, `$` spent, `$` saved by caching
  (vs. a no-cache counterfactual), `$` invested in cache writes, per-model
  breakdown, and detected leaks.
- **Cache mechanic.** Prices `cache_read` at 0.1× and writes at 1.25×/2× against
  per-model input rates; the saved figure is `uncached − actual`.
- **Code.** `scanner/src/posture/cache-economics.js` — `locateTranscript`,
  `parseTranscriptUsage`, `computeCacheEconomics`, `detectInvalidators`,
  `analyzeTranscript`, `formatCacheReport` (helpers exposed via `_internal`). CLI:
  `cmdCacheReport` (`cache-report` subcommand) in `scanner/bin/agentic-security.js`,
  documented as `/posture --cache` (`commands/posture.md`). MCP:
  `query_cache_telemetry` in `scanner/src/mcp/tools.js` (read-only, returns metrics +
  leaks + a formatted report).
- **Test.** `scanner/test/cache-economics.test.js` against a fixture transcript with
  known numbers (`test/fixtures/cache-economics/session.jsonl`); `mcp.test.js` cases
  for the tool.
- **Acceptance.** Report shows correct `$ saved` and hit ratio on the fixture;
  skips `<synthetic>`/user lines; graceful when no transcript; MCP tool returns
  `_meta.untrusted_excerpts:true`. **Met.**
- **Effort:** M.

### F2 — Silent-invalidator detector ("cache bodyguard")  ·  Phase A  ·  shipped
- **Definition.** (a) Retrospective: attribute cache drops in the transcript to
  `model-switch` / `cache-expired` / `prefix-change`, with wasted-$; surfaced in the
  F1 report. (b) Live: a PreToolUse warning before an edit to a cache anchor.
- **Cache mechanic.** A turn that re-ingests a large prefix cold after a warm prior
  turn is a leak; cache is model-scoped and prefix-matched, so a model change or a
  CLAUDE.md/settings edit invalidates it.
- **Code.** `detectInvalidators` (F1 module). Live hook
  `hooks/cache-invalidator-guard.js` (PreToolUse `Edit|Write`): warns when the target
  is `CLAUDE.md` or `.claude/settings*.json` and a warm cache exists (via
  `hooks/lib/transcript.js`), with the estimated rewarm `$`; throttled, respects
  `AGENTIC_SECURITY_QUIET`, kill switch `AGENTIC_SECURITY_CACHE_GUARD=off`.
- **Test.** `scanner/test/cache-invalidator-guard.test.js` (warns on CLAUDE.md /
  settings with a warm cache; silent on normal files, no cache, QUIET, kill switch);
  detector covered in F1 fixture (model-switch + TTL-gap leaks).
- **Acceptance.** Detector flags exactly the seeded leaks; guard warns only on
  anchors-with-warm-cache and is otherwise silent. **Met.**
- **Effort:** M.

### F3 — Break-even + TTL-aware switching  ·  Phase A  ·  shipped
- **Definition.** The advisor uses the *real* cached size; computes a model switch's
  break-even turn count (`rewarmPenalty / perTurnSaving`); suppresses the switch
  (falling back to a cache-safe effort drop) when it exceeds `breakEvenMaxTurns`; and
  treats an already-cold cache (older than `ttlSeconds`) as free to switch.
- **Cache mechanic.** A switch's one-time rewarm is amortized over the turns it would
  save; past the TTL the cache is already lost, so no penalty applies.
- **Code.** `hooks/model-cost-advisor.js` — `buildAdvice` candidate A computes
  `breakEven` and gates on `breakEvenMaxTurns`; `main()` sources cached size from
  `hooks/lib/transcript.js` `latest()` (0 when stale past `ttlSeconds`), else the
  turns estimate. New config: `ttlSeconds` (300), `breakEvenMaxTurns` (6).
- **Test.** `hooks/model-cost-advisor.test.js` — moderate cache → switch + break-even
  caveat; deep cache → effort drop; cold cache → free switch.
- **Acceptance.** Switch tip shows "worth it past ~N more turns"; deep warm cache
  yields an effort-only tip; stale cache yields an uncaveated switch. **Met.**
- **Effort:** M.

### F4 — Depth-first routing philosophy  ·  Phase B  ·  shipped
- **Definition.** Depth (effort) is the *primary*, cache-safe lever; a model switch is
  the exception, only chosen when it saves *materially* more than the effort drop.
- **Cache mechanic.** Effort changes do not invalidate the tools/system cache; model
  switches do — so the cheapest *safe* win in an ongoing session is usually a depth
  drop.
- **Code.** `buildAdvice` pick logic: a switch (candidate A, cache-busting) is chosen
  over the effort drop (candidate B) only when `A.savings ≥ B.savings × (1 +
  depthFirstMargin)` (default 0.25); two cache-safe candidates compare on savings
  alone. The effort tip states the rationale ("keeps your model and cached context —
  no cache rewarm").
- **Test.** `hooks/model-cost-advisor.test.js` — default margin keeps the 2× switch;
  a high margin flips the pick to the effort drop.
- **Acceptance.** Effort preferred at parity and within the margin; no F3 regression.
  **Met.**
- **Effort:** S.

### F5 — Subagent-offload advice  ·  Phase B  ·  shipped
- **Definition.** When a cheap one-off arrives mid-expensive-session and a cheap-model
  switch is cache-blocked, advise running it as a **Haiku subagent** (own context,
  main cache untouched) instead of switching the main model.
- **Cache mechanic.** A subagent runs in its own context; the main session's warm
  cache is untouched — the cache-preserving way to "use Haiku for the cheap part."
- **Code.** `buildAdvice` records a `suppressedSwitch` (a cost-worthy switch blocked
  by the F3 break-even gate); when `tier==='simple'` and one exists, it returns the
  subagent suggestion (full model saving, cache-safe) in preference to a partial
  effort drop. Config `subagentAdvice` (default true).
- **Test.** Subagent phrasing for (simple + Opus + deep cache); falls back to the
  effort drop when `subagentAdvice:false`; never fires for shallow caches.
- **Acceptance.** Appears only in the deep-cache/cheap-prompt regime; never disturbs
  the main cache for trivial work. **Met.**
- **Effort:** M.

### F6 — Cost HUD / statusline + cache budget  ·  Phase B  ·  shipped
- **Definition.** A live one-line statusline (spend, cache-hit %, $/turn) plus a soft
  per-session budget that biases the `costQualityTradeoff` dial toward cheaper as the
  session's real spend approaches it.
- **Cache mechanic.** Surfaces the F1 metrics continuously; the budget makes the dial
  responsive to actual measured spend.
- **Code.** `renderCacheStatusLine(metrics)` in `cache-economics.js` (mirrors
  `watch-mode.js`); the `cache-statusline` CLI subcommand writes
  `.agentic-security/cache-telemetry.json` and prints the line for a `settings.json`
  `statusLine` command. Budget: `hooks/lib/transcript.js` `sessionSpendUsd` +
  `biasedDial(dial, spend, budget)` in the advisor (config `sessionBudgetUsd`).
- **Test.** `renderCacheStatusLine` shape snapshot + CJS/ESM spend parity
  (`cache-economics.test.js`); `biasedDial` thresholds (`model-cost-advisor.test.js`).
- **Acceptance.** Statusline string is correct/parseable; near/over-budget sessions
  get a more aggressive dial; opt-in (budget defaults off). **Met.**
- **Effort:** M.

---

## 5. Prioritisation & sequencing

| Phase | Features | Release | Rationale |
|---|---|---|---|
| **A** ✅ | F1 telemetry · F2 invalidator detector · F3 break-even/TTL | **v0.121.0** | The measured foundation; F1 also makes every other estimate real |
| **B** ✅ | F4 depth-first · F5 subagent offload · F6 HUD/budget | **v0.122.0** | Positioning + the "wow" surfaces, built on the measured base |

**Out of scope (both phases):** any attempt to auto-switch the model/effort (the
hook schema can't), and changing `cache_control` breakpoints/TTL (the harness owns
them). The plugin measures and advises.

---

## 6. Verification (Phase A, shipped)

- `npm run test:posture` (incl. `cache-economics.test.js`), `npm run test:mcp` (incl.
  the tool cases), `npm run test:lifecycle` (incl. `cache-invalidator-guard.test.js`,
  `no-dead-modules`), and `node --test hooks/model-cost-advisor.test.js` all green;
  full `npm test` + both corpus gates (`bench:cve-replay:check`,
  `bench:router-replay:check`) pass.
- End-to-end: `agentic-security cache-report --transcript <fixture>` prints correct
  economics + a detected leak; the guard hook warns on a CLAUDE.md edit and is silent
  otherwise; the advisor shows a break-even caveat on a warm cache, an effort drop on
  a deep cache, and a free switch on a stale cache.
- No-network/no-spawn invariant holds for the new hooks.
