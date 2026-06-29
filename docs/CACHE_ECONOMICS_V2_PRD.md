# PRD — Cache Economics v2 + Multi-Provider Cost Optimization

**Status:** Phase 1 shipped in v0.125.0 (P1 provider-detect, P2 catalog, F1 cache-hygiene
+ P3 model/depth recommendation as `scanner/src/sast/llm-cost-advisor.js` +
`scanner/src/posture/provider-catalog.js`). Phases 2–4 pending.
**Version:** 1.1
**Date:** 2026-06-29
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** The next wave of the model-cost / prompt-cache program — (a) seven advanced
cache-economics capabilities beyond the shipped v0.121–v0.124 foundation, and (b) a
**multi-provider** extension so the optimizer recommends the right model + reasoning
depth *within the provider the user's app actually uses* (Anthropic, OpenAI, Google
Gemini, xAI Grok). Touches `hooks/`, `hooks/lib/`, `scanner/src/sast/`,
`scanner/src/posture/`, `bench/router-replay/`, and the `/posture`/`/setup` surfaces.
**Audience:** Engineering (scanner + hooks), with a product lens on the
"vibecoder building an AI app" ICP.

---

## 1. Purpose

We've shipped the *measured, cache-aware, advisory* foundation (telemetry report,
silent-invalidator detector, break-even/TTL routing, depth-first, subagent offload,
cost HUD/budget — v0.121.0–v0.124.1). This PRD defines what makes the capability
**materially more powerful**:

1. **Weaponize the scanner.** The plugin's core is static analysis — so make it catch
   the cache-killers in the user's *own* LLM-calling code, not just advise on this
   Claude Code session (F1).
2. **Make every number measured, not estimated** — live pricing + realized-savings
   (F2), so the whole feature is honest and self-calibrating.
3. **Model the cache levers we still hardcode** — TTL tier (F3), compaction (F4),
   pre-warming (F5).
4. **Smarter routing** — cross-session cache warmth (F6) and an outcome-driven,
   self-tuning advisor (F7).
5. **Go multi-provider.** Most apps aren't on Claude. Detect the provider and
   recommend the right model + depth + caching strategy *inside that provider's
   framework* (P1–P4).

This is a planning document; nothing here is implemented by it.

---

## 2. Methodology & honesty preface

- **Advisory vs. implementable.** Inside Claude Code the plugin can only *advise*
  (it can't set the model, effort, TTL, or pre-warm). But for the growing ICP that is
  **building an app** against a provider SDK, the plugin can ship concrete artifacts
  (a linter finding + fix, a pre-warm snippet, a caching refactor). Each feature below
  marks which mode it serves.
- **Provider data must be sourced live — never hardcoded from memory.** Model names
  and prices churn monthly (in June 2026: GPT-5.5, Gemini 3.5 Flash, Grok 4.3,
  Opus 4.8). The PRD pins the *mechanisms* (which are stable) and mandates a
  **maintained provider catalog** fed by each provider's pricing/models API or a
  versioned, dated data file — the same anti-drift discipline the repo already uses
  for Anthropic (the `claude-api` skill) and OSV/KEV. Any code that asserts a specific
  price must read it from the catalog, with a cache-date and an offline fallback.
- **Caching models differ by provider** (verified June 2026 — see §4 matrix). Anthropic
  is *explicit* (manual `cache_control`, a write premium, breakpoints, model-scoped,
  5m/1h TTL). OpenAI and xAI are *automatic* (cached-input discount, no write premium,
  prefix-match). Gemini is *implicit (free) + explicit (storage-priced)*. The economics
  advice and the linter rules must branch on this.

---

## 3. Current state (shipped — do not re-spec)

| Capability | Where | Release |
|---|---|---|
| Per-prompt model+depth advisor (dial, break-even, TTL, depth-first, subagent offload) | `hooks/model-cost-advisor.js` | 0.120–0.122 |
| Cache telemetry report (`/posture --cache`, MCP `query_cache_telemetry`) | `scanner/src/posture/cache-economics.js` | 0.121 |
| Silent-invalidator detector (retrospective + live guard) | `cache-economics.js`, `hooks/cache-invalidator-guard.js` | 0.121 |
| Cost HUD + budget bias | `cache-statusline`, `biasedDial()` | 0.122 |
| Transcript parser (cache size, spend, age) | `hooks/lib/transcript.js` | 0.121–0.122 |
| Router-replay eval harness | `bench/router-replay/` | 0.120 |

Everything below is new.

---

## 4. Provider matrix (verified June 2026 — mechanisms are stable; prices source live)

| Provider | Model ladder (cheap → capable) | Depth knob | Cache model | Write premium? |
|---|---|---|---|---|
| **Anthropic** | Haiku 4.5 → Sonnet 4.6 → Opus 4.8 | `effort` low–max + adaptive thinking | **explicit** `cache_control` breakpoints; read ≈0.1×; prefix-match; model-scoped; 5m/1h TTL | yes (1.25× / 2×) |
| **OpenAI** | GPT-4.1-nano → GPT-5.x-mini → GPT-5.4 → GPT-5.5/Pro; o-series (o3/o4-mini) | `reasoning_effort` (minimal–high) | **automatic**, prefix ≥1024 tok; cached input ≈90% off; Batch/Flex −50% | no |
| **Google Gemini** | Flash-Lite → 3.5 Flash → 3.1 Pro | `thinkingBudget` (tokens, billed as output) | **implicit (free) + explicit** `CachedContent` (storage-priced); cached read ≈90% off | storage only |
| **xAI Grok** | grok-4.1-fast → grok-4.3 / 4.20 | `reasoning_effort` (none–high) | **automatic** cached input ≈85% off | no |

Key cross-provider truth: **a model switch loses the cache on every provider** (caches
are model-scoped), but only Anthropic charges a *write* premium to re-establish it —
elsewhere the penalty is the cold re-read at full (un-discounted) input price. The
break-even math generalizes; the constants differ.

---

## 5. Requirements

### Theme A — Catch the killers, measure the truth

#### F1. Prompt-cache anti-pattern linter (SAST for cache economics)  ·  *implementable*
- **Definition.** A new scanner detector family that flags cache-hostile patterns in
  the user's LLM-calling code, provider-aware (P-themes).
- **Rules (initial).** Non-deterministic content in the cached prefix (`datetime.now()`
  / `uuid4()` / unsorted `json.dumps()` in a system prompt); per-request tool
  re-construction; model switched mid-conversation on a shared history; **Anthropic-
  specific:** large stable prefix with no `cache_control`, a breakpoint past the
  20-block lookback, `temperature`/timestamp interpolated ahead of a breakpoint;
  **OpenAI/xAI:** volatile content placed *before* the static prefix (defeats the
  automatic ≥1024-token prefix match); **Gemini:** explicit `CachedContent` created for
  a low-reuse path (storage cost > savings).
- **Mechanic.** The prefix-match invariant — any byte change before the cached prefix
  invalidates everything after it.
- **Code.** New `scanner/src/sast/prompt-cache-hygiene.js` (follow `skills/add-scan-rule.md`
  + the existing IR/AST in `scanner/src/ir/`); provider detection from P1; emit findings
  with the `riskNote`/inline-explain depth already in `report/index.js`, family
  `prompt-cache-hygiene`, with a concrete fix per rule.
- **Test.** `scanner/test/fixtures/prompt-cache-hygiene/{vulnerable,clean}/` + a detector
  test; add ≥3 entries to `bench/cve-replay`-style coverage (pre fires / post clean).
- **Acceptance.** Detects each rule in a vulnerable fixture, silent on the clean pair;
  zero FP on a correctly-cached prefix; provider-correct (no Anthropic `cache_control`
  rule fired on an OpenAI file).
- **Effort:** M. **Differentiation: highest** — nobody lints for cache-killers.

#### F2. Measured cost model + live pricing + realized-savings loop  ·  *advisory + implementable*
- **Definition.** Replace the hardcoded `TIER_PROFILE` token estimates and static price
  table with **measured** per-tier token distributions (from transcripts) and **live
  pricing** from a provider catalog (P2). `/posture --cache` gains a *realized* view:
  which tips were acted on, and did they pay off.
- **Mechanic.** Real `usage` + real rates → real dollars; closes the estimate→outcome
  loop.
- **Code.** Extend `cache-economics.js` (pricing from catalog, profiles from a rolling
  transcript histogram persisted under `.agentic-security/`); feed
  `bench/router-replay/` measured (quality, cost) so its AIQ becomes real.
- **Test.** Fixture transcripts → expected realized savings; catalog read is disk-cached
  and degrades offline (repo invariant: no runtime cloud dependency).
- **Acceptance.** Savings/break-even use measured profiles + live prices; offline →
  static fallback; realized-savings report matches a seeded transcript.
- **Effort:** M–L.

### Theme B — Model the unmodeled levers

#### F3. TTL-tier recommendation (short vs long cache)  ·  *advisory*
- **Definition.** Analyze the **inter-turn gap distribution** from transcript timestamps
  and recommend the cache TTL that fits the user's rhythm (Anthropic 5-min vs 1-hour;
  the analog elsewhere), with the break-even quantified.
- **Mechanic.** A cache expiring between turns forces a cold re-read; a longer TTL trades
  a higher write premium (Anthropic) for surviving idle gaps.
- **Code.** `cache-economics.js` gap-histogram + a recommender; surface in `/posture --cache`
  and the advisor.
- **Test.** Synthetic gap distributions → expected TTL recommendation + break-even.
- **Acceptance.** Bursty/gappy sessions → recommend long TTL with a positive break-even;
  continuous sessions → short TTL.
- **Effort:** S–M.

#### F4. Compaction-economics advisor  ·  *advisory*
- **Definition.** Detect context **compaction** from the transcript (the `cache_creation`
  spike / compaction marker), price it (a full-prefix rewrite + total invalidation), and
  advise cadence — warn when frequent compaction is thrashing the cache, or when
  compacting too late risks a context-window blowout.
- **Mechanic.** Compaction rewrites the prefix → a full cache write + invalidation of
  everything after.
- **Code.** `cache-economics.js` `detectCompactions(records)` + a cost/cadence note in
  the report.
- **Test.** Fixture with compaction spikes → flagged + priced.
- **Acceptance.** Flags ≥2 compactions in a fixture with the dollar cost; warns on
  thrash (≥N compactions / window).
- **Effort:** M.

#### F5. Cache pre-warming orchestration  ·  *advisory (Claude Code) + implementable (own agent)*
- **Definition.** Detect a session start (or an idle gap nearing TTL) where a large,
  stable prefix will pay a cold write, and advise/emit a **`max_tokens: 0` pre-warm**;
  schedule re-warms before TTL expiry during idle windows. For users' own agent code,
  emit the snippet.
- **Mechanic.** A `max_tokens: 0` request runs prefill and writes the cache, returning
  immediately — eliminating cold-start TTFT/cost on the next real turn.
- **Code.** A SessionStart/idle advisor in the hook layer + a `cache-economics` helper
  that estimates the cold-write cost from the prefix size; provider-aware (only
  Anthropic has a manual write to pre-warm; OpenAI/xAI/Gemini pre-warm implicitly).
- **Test.** Given a large-prefix session, advisor recommends pre-warm with the estimated
  saved cold-start cost; no advice when the prefix is below the cacheable minimum.
- **Acceptance.** Fires only when prefix ≥ provider minimum and the cold-write cost is
  material; degrades on providers without a manual write.
- **Effort:** M.

### Theme C — Smarter routing

#### F6. Cross-session cache-warmth ledger + reuse routing  ·  *advisory*
- **Definition.** Track which `(provider, model, prefix)` caches are warm and when they
  expire across the user's recent/concurrent sessions, and advise: *"you have a warm
  Opus cache from 90 s ago in session X — route this related question there rather than
  starting cold."*
- **Mechanic.** Caches are short-lived and model+prefix scoped; reusing a warm one avoids
  a cold read.
- **Code.** A ledger under `.agentic-security/cache-warmth.json` updated from transcript
  parsing across sessions; a reuse recommender in the advisor.
- **Test.** Two seeded sessions → reuse advice when a warm related cache exists; none when
  expired.
- **Acceptance.** Recommends reuse only within TTL and for a prefix-overlapping task.
- **Effort:** M.

#### F7. Self-tuning advisor + mid-session model-switch interceptor  ·  *advisory*
- **Definition.** (a) Auto-calibrate `costQualityTradeoff` / `breakEvenMaxTurns` per user
  from observed **regret** — if tips are ignored, back off; if accepted and they pay,
  lean in. (b) A `UserPromptSubmit` interceptor that warns *before* a `/model` switch
  mid-session that it'll cost ~$X to re-warm the current cache.
- **Mechanic.** Outcome feedback (did the user act? did spend drop?) drives the dial,
  reusing `biasedDial()` + the transcript outcome data.
- **Code.** Extend the advisor + `hooks/lib/transcript.js` (acceptance inference); a small
  `/model`-detection branch in the UserPromptSubmit path.
- **Test.** Simulated accept/ignore sequences → dial moves monotonically; a `/model x`
  prompt with a warm cache → cost warning.
- **Acceptance.** Dial adapts to feedback within bounds; interceptor fires only on a real
  mid-session switch with a warm cache.
- **Effort:** M.

### Theme P — Multi-provider cost optimization

#### P1. Provider detection  ·  *implementable*
- **Definition.** Detect which LLM provider(s) the user's project targets, per file and
  per project.
- **Mechanic.** Imports/SDK markers + base URLs: `anthropic` / `@anthropic-ai`;
  `openai` / `from openai` / `gpt-*`; `google.generativeai` / `genai` / `gemini-*`;
  `xai` / `grok-*` / `api.x.ai`; plus OpenAI-compatible shims (note the provider may be
  behind a proxy/base_url).
- **Code.** `scanner/src/posture/provider-detect.js` — reuse the IR import graph; return
  `{ provider, confidence, evidence }`. (The `claude-api` skill already documents the
  Anthropic-vs-other marker scan — mirror it.)
- **Test.** Fixtures per provider (+ a multi-provider repo, + a proxy/base_url case) →
  correct detection; ambiguous → low confidence, not a guess.
- **Acceptance.** ≥4 providers detected from idiomatic SDK usage; never misattributes an
  OpenAI file to Anthropic; degrades to "unknown" rather than guessing.
- **Effort:** M.

#### P2. Provider catalog / abstraction (live-sourced)  ·  *foundation*
- **Definition.** A single abstraction capturing, per provider: the **model ladder**
  (id, tier, input/output/cached rates, context window), the **depth knob** (name +
  levels + how it's billed), and the **cache model** (automatic vs explicit; read/write
  multipliers; min prefix; TTL; model-scoped). Fed by each provider's pricing/models API
  or a versioned dated data file; disk-cached; offline fallback.
- **Mechanic.** Normalizes four very different frameworks into one routing/economics
  interface so F1–F7 work uniformly.
- **Code.** `scanner/src/posture/provider-catalog.js` (`{ providers, rateFor, depthAxis,
  cacheModel }`); the Anthropic entry reuses the `claude-api` skill values. **No
  hardcoded prices in logic — read the catalog.**
- **Test.** Catalog loads, has the four providers, each with rates + depth axis + cache
  model; a parity test that the figures carry a `sourcedAt` date.
- **Acceptance.** Adding a provider/model is a catalog edit, not a logic change; offline
  → last-cached catalog; figures dated.
- **Effort:** M (+ ongoing data maintenance).

#### P3. Per-provider model + depth advisor  ·  *implementable (own agent) + advisory*
- **Definition.** Generalize the model-cost advisor across providers: given the project's
  provider (P1) and a prompt's tier, recommend the cheapest **model + depth in *that*
  provider's framework** — e.g. an OpenAI app gets "GPT-5.4 at `reasoning_effort: low`,"
  a Gemini app gets "Flash with a smaller `thinkingBudget`," a Grok app gets
  "grok-4.1-fast at `reasoning_effort: low`."
- **Mechanic.** The same tier→{model, depth} routing, but the ladder and depth knob come
  from the catalog (P2) per provider; the depth knob's *name and billing* differ
  (effort tokens vs thinkingBudget vs reasoning_effort).
- **Code.** Refactor `hooks/model-cost-advisor.js` to consume P2 (replace the hardcoded
  `MODELS`/`TIER_RECO`); provider chosen from P1 (project) or config. Tips name the
  provider-correct model + knob.
- **Test.** Per-provider: a simple prompt → the provider's cheap model+low depth; never
  recommends a cross-provider model.
- **Acceptance.** Advice is always within the detected provider; depth phrased in that
  provider's parameter; Claude Code sessions still default to Anthropic.
- **Effort:** M–L (the refactor is the bulk).

#### P4. Per-provider cache economics  ·  *advisory + implementable*
- **Definition.** Generalize F1–F5 to each provider's cache model: the linter rules (F1),
  savings/telemetry (F2), TTL advice (F3), and pre-warming (F5) branch on whether caching
  is explicit (Anthropic), automatic (OpenAI/xAI), or implicit+explicit (Gemini).
- **Mechanic.** §4 matrix — e.g. no "missing `cache_control`" rule for OpenAI (automatic),
  but a "volatile-prefix-before-static" rule instead; no write premium off-Anthropic, so
  break-even = cold-read recovery only; Gemini explicit-cache advice nets storage cost.
- **Code.** Thread the catalog's `cacheModel` through `cache-economics.js`, the advisor,
  and the linter; per-provider rate constants from P2.
- **Test.** Same scenario across providers → provider-correct economics + rules.
- **Acceptance.** No Anthropic-only assumption leaks into another provider's advice;
  numbers match the catalog per provider.
- **Effort:** M.

---

## 6. Prioritisation & sequencing

| Phase | Items | Rationale |
|---|---|---|
| **1 — foundation** | P1 provider-detect · P2 catalog · F2 measured cost/pricing | Everything else needs provider awareness + live pricing + measured profiles |
| **2 — the on-brand bet** | F1 cache-hygiene linter · P3 per-provider advisor · P4 per-provider economics | Weaponizes the scanner; makes the optimizer multi-provider — the biggest differentiation |
| **3 — the unmodeled levers** | F3 TTL · F4 compaction · F5 pre-warm | Real money levers we currently ignore |
| **4 — smart routing** | F6 cross-session warmth · F7 self-tuning + interceptor | Highest sophistication, built on the measured base |

**Recommended first build:** P1 + P2 + F2 together (the provider-aware, live-priced,
measured backbone), then F1 (the linter) as the flagship. F1 and P3 are the two items
that change the product's reach — from "a Claude Code cost advisor" to "a cache-economics
analyzer for any AI app."

---

## 7. Non-goals

- **No auto-switching / no setting the provider's params for the user.** Inside Claude
  Code the plugin advises; for the user's own code it emits findings/snippets they apply.
- **No hardcoded provider prices in logic** — only the dated, disk-cached catalog (P2).
- **No becoming a gateway** (OpenRouter's job) — we analyze and advise, we don't proxy
  calls.
- **No provider-neutral LLM SDK code generation** beyond the cache-hygiene fix snippets
  (respect the `claude-api` skill boundary: don't write Anthropic SDK into a non-Anthropic
  file, and vice-versa).

---

## 8. Verification (when built)

- Provider fixtures (Anthropic/OpenAI/Gemini/xAI + multi-provider + proxy) drive P1/P3/P4
  tests; F1 ships vulnerable/clean fixture pairs and `cve-replay`-style entries.
- The catalog (P2) is disk-cached with a `sourcedAt` date and an offline fallback — no
  runtime cloud dependency (repo invariant).
- `bench/router-replay/` extended to per-provider corpora; the measured cost model (F2)
  turns its hull-advantage into a real AIQ.
- Full `npm test` + both corpus gates green; no-network/no-spawn invariant on new hooks.

> **Sources (provider mechanics, June 2026 — verify/refresh at implementation):**
> OpenAI [prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching) +
> [pricing](https://developers.openai.com/api/docs/pricing) ·
> Gemini [thinking](https://ai.google.dev/gemini-api/docs/thinking) +
> [models](https://ai.google.dev/gemini-api/docs/models) ·
> xAI [models](https://docs.x.ai/developers/models) · Anthropic via the `claude-api` skill.
