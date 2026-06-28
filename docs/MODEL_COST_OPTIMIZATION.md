# Model-Cost Optimizer

Spend less per prompt. The optimizer watches your prompts and, when one would run
just as well on a cheaper model or lower reasoning depth, it tells you — with the
estimated token-cost savings.

> **The honest one-liner:** it *advises* — it can't switch for you. Claude Code
> hooks have no way to change the model or effort mid-session (verified against the
> official hook schema). So the optimizer shows the cheaper option and you tap
> **`/model`** + **`/effort`** (one keystroke each). In return it never spends a
> single token of its own to do the analysis.

---

## What it does

On each prompt it runs a tiny, **local** check (no LLM call, no network, no added
tokens) that scores the work as **simple**, **medium**, or **complex**, then maps
that to the cheapest sensible model + depth:

| Tier | Looks like | Suggests |
|---|---|---|
| **simple** | short question, no code, "explain / summarize / rename" | **Haiku 4.5** |
| **medium** | some code, a focused change, problem-solving | **Sonnet 4.6**, low–medium effort |
| **complex** | multi-file refactor, design, debugging, architecture | **Opus 4.8**, high effort |

If you're already on the cheapest sensible option, it says nothing. It will **only
ever suggest a cheaper option** — it never nudges you to spend more.

---

## Enable it

The optimizer ships **off**. Turn it on with one command:

```bash
/agentic-security:setup --model-optimizer
```

That writes `.agentic-security/model-optimizer.json` with `mode: "advise"`. You can
also create/edit it by hand:

```json
{
  "mode": "advise",
  "costQualityTradeoff": 7,
  "minSavingsUsd": 0.01,
  "assumedModel": "claude-opus-4-8",
  "assumedCachedTokens": null
}
```

- **`costQualityTradeoff`** — a 0–10 dial (default 7), borrowed from OpenRouter's
  `cost_quality_tradeoff`. `0` = pure quality (never suggests a downgrade); `10` =
  cheapest (suggests on any saving). It sets how eagerly tips appear.
- **`minSavingsUsd`** — an absolute anti-noise floor; sub-cent savings never nag.
- **`assumedCachedTokens`** — leave `null` to let the optimizer estimate your
  growing conversation cache (see "Cache-aware" below); set a number to pin it, or
  `0` to ignore cache cost entirely.

Disable any time — set `"mode": "off"`, or use the kill switch:

```bash
export AGENTIC_SECURITY_MODEL_OPTIMIZER=off
```

---

## The two modes

| Mode | Behavior |
|---|---|
| `off` *(default)* | Does nothing. No output. |
| `advise` | Shows a one-line tip on prompts that could run cheaper. |

### `advise` — a tip when it matters

```
💡 This looks like a simple lookup. Sonnet low would cost ~85% less
   (est. ~$0.04 → ~$0.006). Run:  /model sonnet   then  /effort low
```

The tip is shown to *you* only — it is **not** sent to Claude, so it adds nothing
to your token bill. Act on it or ignore it; the prompt runs either way.

### Cache-aware: it won't tell you to throw away your context

Switching models mid-session discards Claude's **prompt cache** — the cheap
re-read of your conversation so far — and forces the new model to ingest it cold.
Deep into a session that can cost *more* than the model you'd save. So the more
context you've built up, the more the optimizer prefers a **cache-preserving
effort drop on your current model** (e.g. `/effort low` on Opus) over a model
switch:

```
💡 This simple task could run at lower depth — keeps your model and cached
   context. /effort low on Opus 4.8 would cost ~40% less (est. saves ~$0.01).
```

Early in a session (little cache) it still recommends the cheaper model; the
trade-off shifts automatically as your context grows.

It measures the **real** cached size from your session transcript (not a guess),
shows a switch's **break-even** ("worth it past ~N more turns — switching re-warms
the cache"), suppresses switches that won't pay off, and — once your cache has gone
cold past its 5-minute TTL — recommends switching freely again (nothing left to
lose). Tune via `costQualityTradeoff`, `ttlSeconds`, and `breakEvenMaxTurns` in
`.agentic-security/model-optimizer.json`. For a full accounting of what caching
saved or wasted this session, run **`/posture --cache`**.

---

## Current pricing (per 1M tokens)

| Model | Input | Output | Reasoning depth |
|---|---|---|---|
| Opus 4.8 (`claude-opus-4-8`) | $5.00 | $25.00 | `low`–`max` |
| Sonnet 4.6 (`claude-sonnet-4-6`) | $3.00 | $15.00 | `low`–`high` |
| Haiku 4.5 (`claude-haiku-4-5`) | $1.00 | $5.00 | none (no effort knob) |

> Savings figures are **estimates** — they use a representative token profile per
> tier, not a live token count, so treat them as magnitude, not invoice. Pricing
> is current as of the table's source date; if your rates differ you can override
> them in the config `models` key.

---

## FAQ

**Why can't it just switch the model for me?**
Because Claude Code doesn't let any hook do that. The hook system exposes the
current model and effort as read-only; there is no output field to *set* them. So
the honest design is to advise and let you tap `/model` / `/effort`. Anything that
claimed to auto-switch — or to "quietly handle it for you" — would be lying about
what took effect.

**Does the optimizer itself cost tokens?**
No. The classification is plain local logic (length, code blocks, keywords) — zero
LLM calls, zero network. And the tip is delivered out-of-band to you, not injected
into Claude's context, so it never enters your token bill.

**How do I make the tips stop?**
You're seeing them because your default is pricier than your typical prompt needs.
Either switch your *default* to a cheaper model (`/model sonnet`, then `/effort
low`) so most prompts no longer trigger a suggestion, or set `"mode": "off"`.

**It's enabled but I see nothing — is it broken?**
Probably not. It only speaks up when a prompt could run *strictly cheaper* than your
current model+depth by at least `minSavingsUsd`. If you're already on a good-value
setting, silence is correct.

---

## Future

Not in v1, planned: an optional Haiku tie-breaker for borderline prompts (slightly
better accuracy, tiny cost on a minority of prompts), and exact token-counted
savings instead of estimates. True auto-switching is **not** planned — it isn't
possible through the hook system, and we won't fake it.
