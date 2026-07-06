---
description: Workflow installers + on-write guards. Hooks, CI, bodyguard, destructive-command guard, model-cost optimizer.
argument-hint: "[--hooks|--ci|--bodyguard|--destructive-guard|--model-optimizer]"
---

# /setup

Workflow + guard installer dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| `--hooks` | Install pre-commit security hook tuned to your project's stack (husky / pre-commit / lefthook / native). `--severity critical|high|medium`, `--diff-only|--full`, `--manager auto|husky|pre-commit|lefthook|native` |
| `--ci` | Generate CI workflow tuned to your CI provider. `--provider auto|github-actions|gitlab-ci|circleci|native`, `--fail-on critical|high|medium` |
| `--bodyguard` | Configure the AI bodyguard PreToolUse hook. Modes: `warn`, `block`, `off`. Per-project forbidden APIs at `.agentic-security/forbidden-apis.yml` |
| `--destructive-guard` | Configure the destructive-Bash-command guard (rm -rf, force-push, etc.). Modes: `warn`, `block`, `off` |
| `--model-optimizer` | Enable the per-prompt model-cost advisor (suggests a cheaper model + depth with est. token savings; advisory only by default — it can't switch for you). Modes: `advise`, `off`. `--quality <0-10>` sets the cost-quality dial (default `7`: `0`=never downgrade, `10`=cheapest); `--min-savings <usd>` is the absolute anti-noise floor; `--interactive` opts into a real `AskUserQuestion` choice (keep defaults / show the `/model` command / apply the cheaper model to delegated sub-agent work this session) instead of a read-only tip — costs a little context on the prompts where it fires, off by default. See `docs/MODEL_COST_OPTIMIZATION.md` |
| `--all` | One-pass setup: installs hooks + CI + bodyguard + destructive-guard with sensible defaults (model-optimizer stays opt-in) |

Bare `/setup` (no flag) prints this mode menu.

## `--all` (one-pass setup)

Runs the four installers in sequence with safe defaults, pausing for confirmation before anything that writes outside `.agentic-security/`:

1. `--hooks` — auto-detected manager, `--severity high`.
2. `--ci` — auto-detected provider, `--fail-on high`.
3. `--bodyguard` — `mode=warn` (non-blocking until the user opts into `block`).
4. `--destructive-guard` — `mode=warn`.

The model-cost optimizer is **not** part of `--all` — it emits per-prompt suggestions, so it stays opt-in via `--model-optimizer`. Mention it once in the summary so the user knows it exists.

Prints a single summary of what was installed and the one command to harden each further.

## Examples

```bash
/setup                                           # show the mode menu
/setup --all                                     # hooks + CI + both guards, defaults
/setup --hooks --severity critical               # husky/pre-commit hook
/setup --ci --provider github-actions            # GitHub Actions workflow
/setup --bodyguard mode=block                    # block insecure edits
/setup --destructive-guard mode=warn             # warn on destructive bash
/setup --model-optimizer                         # enable cheaper-model tips (advise)
/setup --model-optimizer --quality 9             # lean aggressive on cost (dial 9/10)
/setup --model-optimizer --min-savings 0.05      # absolute floor: only ≥ $0.05
/setup --model-optimizer --interactive           # let me choose via AskUserQuestion, not just read a tip
/setup --model-optimizer mode=off                # disable
```

## Implementation

Routes to `posture/workflow-installer.js` (detectProject, buildHookConfig, buildCiConfig), the existing bodyguard hook, and the destructive-guard hook.

`--model-optimizer` writes `.agentic-security/model-optimizer.json`:

```json
{ "mode": "advise", "costQualityTradeoff": 7, "minSavingsUsd": 0.01, "assumedModel": "claude-opus-4-8", "assumedCachedTokens": null, "interactive": false }
```

Set `mode` from the flag (`advise` default, or `off`), `costQualityTradeoff` from `--quality` (0–10, default 7), `minSavingsUsd` from `--min-savings`, and `interactive` to `true` when `--interactive` is passed (default `false`). The advisor (`hooks/model-cost-advisor.js`, UserPromptSubmit) and model capture (`hooks/session-start-model-capture.js`, SessionStart) are already registered in `hooks/hooks.json`, so enabling is purely the config write — no hook installation step. Confirm the config landed (`mode` is `advise`), then point the user at `docs/MODEL_COST_OPTIMIZATION.md`. If `--interactive` was passed, mention explicitly that qualifying prompts will now cost a little extra context (unlike the default tip-only mode) in exchange for a real choice.
