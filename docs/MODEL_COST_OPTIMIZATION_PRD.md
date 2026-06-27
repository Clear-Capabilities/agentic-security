# PRD — Model-Cost Optimizer (per-prompt model + depth advisor)

**Status:** Draft for review
**Version:** 1.1
**Date:** 2026-06-27
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** A new Claude Code hook bundle in the agentic-security plugin (`hooks/`) that inspects each user prompt, picks the cheapest model + reasoning depth likely to answer it well, and surfaces the token-cost savings — plus its config, `/setup` wiring, and tests. Touches `hooks/hooks.json`, `commands/setup.md`, and `.agentic-security/` runtime state.
**Audience:** Engineering (plugin/hooks), with a product lens on the vibecoder ICP (`docs/POSITIONING.md`).

---

## 1. Purpose

Vibecoders set their default once — usually to the most capable, most expensive setting (e.g. **Opus 4.8 / high effort**) — and then pay that rate on every prompt, including the many that a cheaper model + lower depth (e.g. **Sonnet 4.6 / low**, or **Haiku 4.5**) would answer just as well. There is no in-session signal telling them "this one didn't need Opus."

This feature adds a hook that, per prompt, classifies the work, recommends the cheapest model+depth that should still do the job, and shows the estimated token-cost savings. It honors one hard constraint set by the requester:

- **The selector itself must not add meaningful token cost** — classification is local heuristics, zero LLM calls, no network.

This is a planning document. Nothing here is implemented by this PRD; it is the build spec and the rationale. The deterministic, testable acceptance criteria in each requirement are written so a later implementer can prove each one.

---

## 2. Methodology & honesty preface

Two facts shape every requirement below and must be stated up front so no one re-litigates them mid-build:

1. **A hook cannot switch the model or the reasoning depth.** This was verified against the official Claude Code hooks schema. A `UserPromptSubmit` hook may emit `systemMessage` (shown to the user), `hookSpecificOutput.additionalContext` (injected into Claude's context — it *costs tokens*), and `decision:"block"` + `reason`. **No field on any hook event sets `model` or `effort`.** Those are read-only: `effort` is exposed to hooks as an input object and as the `$CLAUDE_EFFORT` env var; `model` is provided only to `SessionStart` hooks (and "not guaranteed to be present"). There is no `$CLAUDE_MODEL`. The consequence is non-negotiable: **this feature is advisory.** It suggests; the user taps `/model` and `/effort` (one keystroke each). Any design that claims to auto-switch — or that goes "quiet" implying a switch happened — is wrong and would mislead users. There is no auto/silent-switch mode; the feature is per-prompt advice or nothing.

2. **Savings are estimates, not measurements.** Computing exact savings would require token-counting the prompt + projected output, which on the every-prompt path is latency and (for output) unknowable in advance. We use a representative per-tier token profile × the price delta and always label the number "est." Real-token accounting is explicitly out of scope for v1 (R11).

Neither point weakens the feature. Even as a pure advisor it does the one thing the user asked for: it makes the cost of an over-powered default *visible* at the moment of spend, and it quantifies what changing the default would save.

### Pricing & capability reference (source: `claude-api` skill, cached 2026-05-26)

| Model | ID | Input $/1M | Output $/1M | Effort support |
|---|---|---|---|---|
| Claude Opus 4.8 | `claude-opus-4-8` | $5.00 | $25.00 | `low`–`max` (incl. `xhigh`) |
| Claude Sonnet 4.6 | `claude-sonnet-4-6` | $3.00 | $15.00 | `low`–`high` (no `max`) |
| Claude Haiku 4.5 | `claude-haiku-4-5` | $1.00 | $5.00 | **none** — effort param errors |

Effort levels: `low | medium | high | xhigh | max`. `max`/`xhigh` are Opus-tier; Haiku 4.5 rejects the effort parameter entirely (so a Haiku recommendation never carries a depth). These constants live in **one table** in `hooks/model-cost-advisor.js` with a comment pointing here and to the `claude-api` skill for refresh.

---

## 3. Current state — what exists today

| Surface | Mechanism | Reusable for this feature? |
|---|---|---|
| `UserPromptSubmit` hook | `hooks/legacy-alias-redirect.js` — reads stdin `{prompt}`, emits `hookSpecificOutput.additionalContext` | ✅ Same event + I/O contract the advisor needs |
| `SessionStart` hooks | `hooks/session-welcome.js`, `hooks/session-start-self-check.js` | ✅ Where the session `model` capture is wired |
| Config-file pattern | `.agentic-security/bodyguard.json`, `destructive-guard.json` — `{mode, ...}` JSON, `try/catch` → defaults merge (`hooks/pre-edit-bodyguard.js:26`) | ✅ The advisor config copies this shape exactly |
| Hook conventions | CommonJS `.js`, zero deps, `${CLAUDE_PLUGIN_ROOT}` paths, `readStdinJSON()` + timeout guard, `CLAUDE_PROJECT_DIR` for project root | ✅ Followed verbatim |
| `/setup` installer modes | `commands/setup.md` table: `--hooks`, `--ci`, `--bodyguard`, `--destructive-guard` | ✅ New `--model-optimizer` mode slots in |

**Nothing about model/depth advice exists today.** Every component below is new, but every one mirrors an existing sibling — this is a "follow the established hook pattern" build, not greenfield infrastructure.

---

## 4. Gap themes

The requirements cluster into four themes:

- **A. Mechanism & honest UX** — the advisory hook, the no-switch truth (R1–R3).
- **B. The selector** — zero-token heuristic classifier + savings estimate (R4–R6).
- **C. Configuration & install** — config file, env override, `/setup` mode, safe default (R7–R9).
- **D. Quality gates & scope** — tests, acceptance criteria, explicit non-goals (R10–R11).

Each item uses the fixed template: **Gap · Evidence · Recommendation · Why it wins · Effort · Success metric.**

---

## 5. The requirements

### Theme A — Mechanism & honest UX

#### R1. Per-prompt advisor hook (`hooks/model-cost-advisor.js`, `UserPromptSubmit`)
- **Gap:** No signal tells the user when a prompt is over-powered for their current model+depth.
- **Evidence:** `hooks/legacy-alias-redirect.js` is the only `UserPromptSubmit` hook; it proves the stdin `{prompt}` → stdout-JSON contract but does nothing cost-related.
- **Recommendation:** New hook that, on each prompt: (1) loads config (R7); if `mode!=="advise"` exit 0 immediately; (2) loads current model from session state (R3) and current effort from `$CLAUDE_EFFORT`; (3) classifies the prompt (R4) → recommended `{model, effort}`; (4) if the recommendation is a **strict, cheaper downgrade** (R6) and estimated savings ≥ `minSavingsUsd`, emit a single `systemMessage` tip; otherwise emit nothing. Always `exit 0` — never block, never erase the prompt. Use the standard `readStdinJSON()` + 500 ms resolve-guard; total work is synchronous string math.
- **Why it wins:** Puts the cost of an over-powered default in front of the user at the exact moment of spend — the one thing the requester asked for — using the cheapest possible mechanism.
- **Effort:** M.
- **Success metric:** Given a fixture prompt + a state file pinning Opus/high, the hook exits 0 and prints exactly one `systemMessage` line; with `mode:"off"` it produces no output and makes no file reads beyond the config.

#### R2. Use `systemMessage`, never `additionalContext`, for the tip
- **Gap:** The obvious "inject a tip" field (`additionalContext`) is injected into Claude's context and **counts as input tokens** — using it would make a token-saving feature *spend* tokens.
- **Evidence:** Hook schema: `additionalContext` is "injected alongside the submitted prompt for Claude to see" (billed); `systemMessage` is "shown to the user" (out-of-band, not in the model context).
- **Recommendation:** The advisor's only user-visible output channel is `systemMessage`. It must never emit `hookSpecificOutput.additionalContext` and never emit `decision:"block"`.
- **Why it wins:** Keeps the advisor itself net-zero on tokens — directly satisfies the "must not increase token cost" constraint.
- **Effort:** S (a discipline + a test).
- **Success metric:** A test greps the hook's stdout across many fixtures and asserts `additionalContext` and `"decision"` never appear; only `systemMessage` does.

#### R3. Capture the session model at `SessionStart`
- **Gap:** The advisor needs the *current* model to compute a downgrade, but there is no `$CLAUDE_MODEL` and `UserPromptSubmit` never receives the model.
- **Evidence:** Hook docs: only `SessionStart` hooks receive a `model` field, "not guaranteed to be present."
- **Recommendation:** A small capture (extend `hooks/session-start-self-check.js` or add `hooks/session-start-model-capture.js`) that writes `input.model` (when present) to `.agentic-security/model-optimizer-state.json` as `{ model, capturedAt }`. The advisor reads it; if absent/stale it falls back to config `assumedModel` (default `claude-opus-4-8`) and the tip notes the model is assumed.
- **Why it wins:** The only available channel for the model; degrades gracefully when the harness omits it.
- **Effort:** S.
- **Success metric:** With a SessionStart input carrying `model`, the state file appears with that value; with the field omitted, the advisor still runs using `assumedModel` and labels the tip accordingly.

### Theme B — The selector

#### R4. Local heuristic classifier (zero LLM tokens)
- **Gap:** Need to judge prompt complexity without spending tokens or adding latency on the every-prompt path.
- **Evidence:** Constraint from the requester; `additionalContext`/LLM routes all cost tokens.
- **Recommendation:** A pure-Node scoring function over the prompt string, deterministic and unit-testable. Documented rule table (initial weights — tunable):

  | Signal | Effect |
  |---|---|
  | length < 280 chars **and** 0 code fences | → toward `simple` |
  | length > 1500 chars, or ≥ 2 code fences | → toward `complex` |
  | ≥ 1 file path / `src/…` / extension mention | +complex |
  | pasted stack trace / `Error:` / multi-line log | +complex |
  | cheap verbs: `explain|summarize|rename|format|list|what is|define` | +simple |
  | expensive verbs: `refactor|design|debug|architect|migrate|implement|optimize` | +complex |

  Score → tier `simple | medium | complex` → map: `simple → {haiku, —}`, `medium → {sonnet, low|medium}`, `complex → {opus, high}`. The classifier returns a tier + a confidence; the advisor only emits a tip on a **strict cheaper** delta vs. current.
- **Why it wins:** Zero tokens, instant, no network, deterministic — exactly the requester's "don't increase cost" rule, and testable to a fixed table.
- **Effort:** M.
- **Success metric:** A fixture suite of labelled prompts (≥ 20, spanning the three tiers) classifies at the documented tier; the hook makes **zero** network calls and spawns no child process (assert in test).

#### R5. Savings estimate from a per-tier token profile
- **Gap:** Need a dollar figure without token-counting every prompt.
- **Evidence:** Token-count on the hot path adds latency; output size is unknown pre-generation.
- **Recommendation:** Representative per-tier profiles (tunable constants): `simple ≈ 1.5K in / 0.5K out`, `medium ≈ 8K in / 3K out`, `complex ≈ 30K in / 8K out`. Estimated savings = `(currentModelRate − recommendedModelRate)` applied to the tier profile, summing input+output legs. Always rendered with an "est." qualifier and rounded sensibly (e.g. `~$0.04`).
- **Why it wins:** Good-enough magnitude to motivate action, with no measurement cost; honest labelling avoids over-claiming.
- **Effort:** S.
- **Success metric:** Unit test pins the arithmetic for a known tier + model pair (e.g. Opus→Sonnet at `medium`) to an expected `±` rounded value; every rendered figure includes "est."

#### R6. Only ever recommend a strict, cheaper downgrade
- **Gap:** A tip that suggests an equal or pricier option is noise and erodes trust.
- **Evidence:** Pricing table (§2) gives a total order on cost; effort is a secondary axis within a model.
- **Recommendation:** Compute `cost(current)` and `cost(recommended)` from model rate × tier profile (plus an effort tie-breaker within the same model). Emit a tip **only** when `cost(recommended) < cost(current)` by ≥ `minSavingsUsd`. Never suggest upgrading, even if the heuristic reads "complex" while the user is on Haiku (we don't push users to spend more).
- **Why it wins:** Keeps the feature strictly a cost-saver; no surprise "use a bigger model" prompts.
- **Effort:** S.
- **Success metric:** With the user already on Haiku/`simple`, or on Sonnet for a `simple` prompt where savings < threshold, the hook emits nothing; downgrades above threshold always emit.

### Theme C — Configuration & install

#### R7. Config file `.agentic-security/model-optimizer.json` (+ env override)
- **Gap:** Users need to choose the mode and thresholds without editing code.
- **Evidence:** `hooks/pre-edit-bodyguard.js:26` shows the `{mode, ...}` + defaults-merge pattern.
- **Recommendation:** Schema `{ "mode": "off"|"advise", "minSavingsUsd": 0.01, "assumedModel": "claude-opus-4-8" }`, read via the same `try/catch` → defaults-merge idiom. `mode` has exactly two values — `off` (dormant) and `advise` (per-prompt tip). Env override `AGENTIC_SECURITY_MODEL_OPTIMIZER=off` forces the feature off regardless of file (kill switch for CI / scripted sessions). Optional `models` key allows pricing override for self-hosted/rate-negotiated users.
- **Why it wins:** Matches an existing, understood config pattern; one obvious kill switch; no third mode to explain or to mis-imply a silent switch.
- **Effort:** S.
- **Success metric:** Missing file → defaults; partial file → merged; `AGENTIC_SECURITY_MODEL_OPTIMIZER=off` → hook exits 0 with no output even when the file says `advise`.

#### R8. Default **off** (opt-in)
- **Gap:** Surprise per-prompt `systemMessage` output would be unwelcome to a user who didn't ask for it.
- **Evidence:** Plugin convention — guards (`bodyguard`, `destructive-guard`) are opt-in installs, not on-by-default behaviors.
- **Recommendation:** When no config file exists, `mode` defaults to `off`. The feature ships dormant and is turned on explicitly (R9). Document this prominently so it isn't mistaken for "broken."
- **Why it wins:** No surprise output; the user opts in deliberately.
- **Effort:** S.
- **Success metric:** Fresh install with no config produces zero advisor output across a session.

#### R9. `/setup --model-optimizer` install mode
- **Gap:** No discoverable on-ramp to enable the advisor.
- **Evidence:** `commands/setup.md` modes table (`--hooks`, `--bodyguard`, …) is the established install surface.
- **Recommendation:** Add `--model-optimizer [--min-savings <usd>]` that writes `.agentic-security/model-optimizer.json` with `mode:"advise"`. Surface it in the `commands/setup.md` modes table and `--all` description. Wire two hooks into `hooks/hooks.json` (advisor under `UserPromptSubmit`, model capture under `SessionStart`) with small timeouts (2 s each).
- **Why it wins:** One command to enable; consistent with how every other guard is installed.
- **Effort:** S.
- **Success metric:** `/setup --model-optimizer` writes the config with `mode:"advise"`; the two `hooks.json` entries exist and point at the new scripts.

### Theme D — Quality gates & scope

#### R10. Tests — classifier table + advisor I/O
- **Gap:** Heuristics and hook I/O regress silently without coverage.
- **Evidence:** Repo convention: minimal fixtures + Node test runner (`scanner/test/`, CLAUDE.md "Test fixtures").
- **Recommendation:** (a) Classifier unit tests: labelled-prompt fixtures → expected tier. (b) Advisor I/O tests: stdin `{prompt}` + a mocked state/config → assert exact stdout shape (one `systemMessage` in advise; empty in off) and exit 0. (c) A guard test asserting **no network / no child process** in the advisor path.
- **Why it wins:** Locks the two load-bearing behaviors (classification, never-add-cost) against regression.
- **Effort:** M.
- **Success metric:** All three test groups pass; the no-network assertion fails if a `fetch`/`https`/`spawn` is introduced.

#### R11. Explicit non-goals (v1)
- **Gap:** Scope creep toward "real" auto-switching or exact accounting would stall the build and over-promise.
- **Evidence:** §2 — no hook can switch model/effort; exact savings need hot-path token counting.
- **Recommendation:** Out of scope for v1, documented as "future" or "won't build": (1) **any auto/silent/quiet mode** — there is nothing to switch, so a "quiet" mode would only imply a change that never happened; the feature is per-prompt advise or `off`. (2) Any attempt to auto-apply a model/effort change (impossible via hooks; misleading to fake). (3) The **Haiku tie-break classifier** (a borderline-only tiny Haiku call — deferred opt-in). (4) Exact token-counted savings via `count_tokens`. (5) README/CHANGELOG entry, version bump, and the hook implementation itself (a separate follow-up driven by this PRD).
- **Why it wins:** Keeps v1 honest, shippable, and within the hard constraint.
- **Effort:** —.
- **Success metric:** None of the non-goals appear in the v1 implementation; each is noted in the user doc's FAQ / "future" section.

---

## 6. Prioritization (impact × effort)

| Rank | Item | Impact | Effort | Why here |
|---|---|---|---|---|
| 1 | R1 advisor hook | High | M | The feature; nothing works without it |
| 2 | R2 `systemMessage`-only | High | S | Guarantees the net-zero-token promise |
| 3 | R4 heuristic classifier | High | M | The brain; satisfies the no-cost constraint |
| 4 | R7/R8 config + default-off | High | S | Controls the opt-in experience |
| 5 | R3 model capture | Med | S | Needed for accurate downgrade math |
| 6 | R5/R6 savings + strict-downgrade | Med | S | Makes the tip credible and one-directional |
| 7 | R9 `/setup` mode | Med | S | Discoverable on-ramp |
| 8 | R10 tests | Med | M | Regression lock on the two load-bearing behaviors |
| 9 | R11 non-goals | — | — | Keeps v1 honest and bounded |

**Build order:** R7/R8 → R4 → R5/R6 → R3 → R1/R2 → R9 → R10. (Config + classifier first; wire the hook; add install; tests throughout.)
