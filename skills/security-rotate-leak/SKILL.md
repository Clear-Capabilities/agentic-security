---
name: agentic-security:security-rotate-leak
description: Rotate a leaked secret end-to-end. Activate on leaked API key, exposed credential, or pushed-secret reports.
---

# Skill — rotate a leaked secret

Activates when the user has discovered (or you've discovered) that a
production credential is in the repo, the chat, or git history. The
clock is running — every hour the value sits exposed is another hour an
attacker has to find it.

## When to fire

- User says "I leaked X" / "I accidentally pushed Y" / "X is in git
  history" / "is this secret bad?"
- The scanner (or `ai-bodyguard` hook) just flagged a hardcoded secret.
- User pastes a high-entropy string and asks "should I rotate this?"
- A `/scan --secrets` run produces a critical-severity hit.
- User mentions they're "rotating keys" or "doing a credential reset."

## What to do — sequenced, do not skip steps

1. **DO NOT print the leaked value back.** Mask it to first-4 + last-4
   chars in any output. The chat transcript itself becomes part of the
   blast radius.

2. **Detect the provider** from the prefix:
   - `sk_live_…`, `rk_live_…` → Stripe
   - `sk-…`, `sk-proj-…` → OpenAI
   - `sk-ant-…` → Anthropic
   - `ghp_…`, `github_pat_…` → GitHub PAT
   - `xoxb-…`, `xoxa-…`, `xoxp-…` → Slack
   - `AKIA…` → AWS access key (16 chars after prefix)
   - `AIza…` → Google API key
   - JWT with `role: service_role` claim → Supabase service-role
   - Service-account JSON (`type: "service_account"`) → GCP

3. **Print the EXACT revoke URL** for that provider's console. Don't
   paraphrase — copy from the canonical list. (See `commands/rotate-key-auto.md`
   for the full provider matrix.)

4. **Estimate blast radius BEFORE the rotation, not after**:
   - Stripe = real money. Check dashboard for unauthorized charges
     in the last 24h BEFORE rotating.
   - AWS = potential crypto-mining bills. Check Billing → Cost Explorer.
   - Supabase service-role = bypasses every RLS rule. Audit the
     `audit_log` table for anomalous reads since the value first appeared.
   - GitHub PAT = potential pushes / forks / settings changes.

5. **Run the active rotation if the user agrees**:
   `/fix --rotate-secret --auto`. This is the only command that touches the
   provider's API for you. Without `--auto`, surface the manual steps
   and stop.

6. **Add `--scrub-history` if the value is in git history.** Rewrites
   history via `git filter-repo` or BFG. Note: irreversible, requires
   force-push to a shared branch — do NOT run without explicit user
   confirmation.

7. **Propose the next step**: `/fix --vault` to migrate the rest of
   the project's env-var surface to a real secrets manager so this
   doesn't happen again.

## Don't

- Don't print the leaked value back to the user un-masked.
- Don't run `--scrub-history` without explicit confirmation. It's
  irreversible and breaks every clone of the repo.
- Don't tell the user to "rotate it later" — every minute counts.
- Don't add the new value to chat. Ask the user to paste it directly
  into `.env` or push it via the deployment platform's CLI.

## Canonical commands

- `/fix --rotate-secret` — guided rotation steps for the detected provider
- `/fix --rotate-secret --auto` — end-to-end (revoke + scrub + push replacement)
- `/fix --rotate-secret --auto --scrub-history` — also purge from git history
- `/fix --vault` — migrate to Doppler / Infisical / platform secrets
