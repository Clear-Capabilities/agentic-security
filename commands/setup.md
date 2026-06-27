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
| `--model-optimizer` | Enable the per-prompt model-cost advisor (suggests a cheaper model + depth with est. token savings; advisory only — it can't switch for you). Modes: `advise`, `off`. `--min-savings <usd>` sets the suggestion threshold (default `0.01`). See `docs/MODEL_COST_OPTIMIZATION.md` |
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
/setup --model-optimizer --min-savings 0.05      # only suggest when est. savings ≥ $0.05
/setup --model-optimizer mode=off                # disable
```

## Implementation

Routes to `posture/workflow-installer.js` (detectProject, buildHookConfig, buildCiConfig), the existing bodyguard hook, and the destructive-guard hook.

`--model-optimizer` writes `.agentic-security/model-optimizer.json`:

```json
{ "mode": "advise", "minSavingsUsd": 0.01, "assumedModel": "claude-opus-4-8" }
```

Set `mode` from the flag (`advise` default, or `off`) and `minSavingsUsd` from `--min-savings`. The advisor (`hooks/model-cost-advisor.js`, UserPromptSubmit) and model capture (`hooks/session-start-model-capture.js`, SessionStart) are already registered in `hooks/hooks.json`, so enabling is purely the config write — no hook installation step. Confirm the config landed (`mode` is `advise`), then point the user at `docs/MODEL_COST_OPTIMIZATION.md`.
