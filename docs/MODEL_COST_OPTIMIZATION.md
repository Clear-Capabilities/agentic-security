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

The optimizer ships **on** (`mode: "advise"`) by default. To turn it off for a
project:

```bash
/agentic-security:setup --model-optimizer   # or set AGENTIC_SECURITY_MODEL_OPTIMIZER=off
```

You can also create/edit `.agentic-security/model-optimizer.json` by hand:

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
lose). For a full accounting of what caching saved or wasted this session, run
**`/posture --cache`**.

**Subagent offload.** For a *simple* one-off deep in an expensive session — where
switching your main model would throw away a big warm cache — it suggests running
the prompt as a **Haiku subagent** instead. The subagent answers in its own context
(full cheap-model savings) and leaves your main cache intact.

**Live cost HUD + budget (opt-in).** `cache-statusline` prints a one-liner
(`agentic-security: $0.22 · 51% cached · $0.04/turn`) you can wire into Claude Code's
status line, and writes `.agentic-security/cache-telemetry.json`:

```json
// .claude/settings.json
{ "statusLine": { "type": "command", "command": "agentic-security cache-statusline" } }
```

Set `sessionBudgetUsd` and the optimizer automatically leans more aggressive on cost
as your real spend approaches it.

### Config reference (`.agentic-security/model-optimizer.json`)

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"advise"` | `off` / `advise` |
| `costQualityTradeoff` | `7` | 0 = never downgrade … 10 = cheapest |
| `minSavingsUsd` | `0.01` | absolute anti-noise floor |
| `ttlSeconds` | `300` | cache TTL; older = treat as cold (free to switch) |
| `breakEvenMaxTurns` | `6` | suppress a switch whose cache rewarm needs more turns than this |
| `depthFirstMargin` | `0.25` | a switch must beat the effort drop by this fraction to be chosen |
| `subagentAdvice` | `true` | suggest a Haiku subagent for cache-blocked one-offs |
| `sessionBudgetUsd` | `null` | soft session budget; biases the dial cheaper as spend nears it |
| `assumedModel` | `"claude-opus-4-8"` | fallback when the session model is unknown |
| `interactive` | `false` | opt-in: let you choose via a prompt instead of just reading a tip — see below |
| `interactiveCooldownTurns` | `3` | don't re-raise an unanswered interactive prompt within N turns |

---

## Current pricing (per 1M tokens)

| Model | Input | Output | Reasoning depth |
|---|---|---|---|
| Fable 5 (`claude-fable-5`) | $10.00 | $50.00 | always on |
| Opus 4.8 (`claude-opus-4-8`) | $5.00 | $25.00 | `low`–`max` |
| Sonnet 5 (`claude-sonnet-5`) | $3.00 | $15.00 | `low`–`xhigh` |
| Sonnet 4.6 (`claude-sonnet-4-6`) | $3.00 | $15.00 | `low`–`high` |
| Haiku 4.5 (`claude-haiku-4-5`) | $1.00 | $5.00 | none (no effort knob) |

Fable 5 is priced but never a *suggestion* target — it's the current flagship, so
the optimizer only ever prices it as your starting point, not a downgrade.

> Savings figures are **estimates** — they use a representative token profile per
> tier, not a live token count, so treat them as magnitude, not invoice. Pricing
> is current as of the table's source date; if your rates differ you can override
> them in the config `models` key.

---

## Interactive mode (opt-in)

By default the advisor only ever shows you a tip — you read it, then decide whether
to run `/model`/`/effort` yourself. Set `"interactive": true` to go one step
further: on a prompt where a cheaper option qualifies, the hook hands the
recommendation to Claude (via `additionalContext` — see the cost note below), and
Claude asks you directly with three options:

```
(a) Keep current settings — no action.
(b) Show me the /model command — Claude replies with the exact command to run
    yourself. Claude can't switch its own model, so this is still a manual step.
(c) Use the cheaper model for delegated sub-agent work this session — Claude
    genuinely CAN do this one directly: for the rest of the session, any
    Task/Agent-tool sub-agent it dispatches for cost-sensitive, delegable work
    uses the cheaper model/effort, unless that sub-agent already pins its own
    model (e.g. the triager sub-agents are pinned to Haiku already) or the
    specific task clearly needs more capability.
```

Whatever you pick is **sticky for the session** — Claude won't ask again until a
new session starts (`.agentic-security/model-optimizer-state.json` is reset at
every `SessionStart`, which is what clears the choice). If Claude doesn't act on
a raised prompt at all (e.g. a non-interactive/scripted invocation), the hook
waits `interactiveCooldownTurns` turns before raising it again, rather than
repeating the cost on every subsequent qualifying prompt.

**The trade-off:** this is the one path in this whole feature that costs real
tokens. `additionalContext` (unlike the free `systemMessage` tip) is injected
into Claude's own context and billed as input tokens — and it only fires on
prompts that already qualify for a tip, at most once per cooldown window, and
only for projects that explicitly opt in. Every other install of this plugin
keeps the zero-token guarantee below unchanged.

---

## FAQ

**Why can't it just switch the model for me?**
Because Claude Code doesn't let any hook do that for the *main session* — the
hook system exposes the current model and effort as read-only; there is no
output field to *set* them. So the honest default is to advise and let you tap
`/model` / `/effort`. The one place Claude genuinely can act directly is on its
own delegated sub-agent dispatches, via `"interactive": true` above — and even
there, it's your explicit choice via `AskUserQuestion`, not something applied
silently.

**Does the optimizer itself cost tokens?**
By default, no. The classification is plain local logic (length, code blocks,
keywords) — zero LLM calls, zero network — and the tip is delivered out-of-band
to you, not injected into Claude's context, so it never enters your token bill.
The one exception is `"interactive": true` (opt-in, off by default) — see above.

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
