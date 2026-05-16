---
description: ACTIVELY rotate a leaked API key end-to-end. Detects provider, prints the exact revoke commands for that provider's console + CLI, scrubs the value from every file (with backups), and pushes the replacement to Vercel/Fly/Railway/Cloudflare/Netlify if their CLI is installed. Use --scrub-history to also purge the value from git history (git filter-repo / BFG). Distinct from /rotate-secret (which guides) — this does the work.
argument-hint: "<leaked-value> | --scan | --provider <name> --new-value <new> | [--scrub-history]"
---

# Active key rotation

You leaked an API key. The clock is running. Every hour it sits in your repo is another hour an attacker has to find it and bleed your account dry. This command compresses the 30-minute rotation procedure into 30 seconds.

## What it does

1. **Detects the provider** from the key's format (OpenAI `sk-...`, Anthropic `sk-ant-...`, Stripe `sk_live_...`, AWS `AKIA...`, GitHub `ghp_...`, Supabase service-role JWT, Slack `xoxb-...`, Google `AIza...`).
2. **Prints the exact revoke steps** for that provider's console — and the equivalent CLI command if available.
3. **Warns about the specific blast radius** — Stripe = real money, AWS = crypto-mining bills, Supabase service-role = bypasses every RLS rule.
4. **Scrubs the leaked value** from every text file in the repo (with full backups under `.agentic-security/rotation-backups/`).
5. **Pushes the new value** to your deployment platform's env vars (Vercel/Fly/Railway/Cloudflare/Netlify) via their CLI.
6. **Tells you what to audit next** — billing dashboard for the last 24h, git history for other commits of the same value.

## Supported providers

| Provider | Key prefixes | Console |
|---|---|---|
| OpenAI | `sk-...`, `sk-proj-...` | platform.openai.com/api-keys |
| Anthropic | `sk-ant-...` | console.anthropic.com/settings/keys |
| Stripe | `sk_live_...`, `rk_live_...` | dashboard.stripe.com/apikeys |
| AWS | `AKIA[A-Z0-9]{16}` | console.aws.amazon.com/iam |
| GitHub | `ghp_...`, `github_pat_...` | github.com/settings/tokens |
| Supabase service-role | JWT with `role: service_role` | supabase.com/dashboard |
| Slack | `xoxb-...`, `xoxa-...`, `xoxp-...` | api.slack.com/apps |
| Google API | `AIza...` | console.cloud.google.com/apis/credentials |

## Usage

```bash
# Single key (paste the leaked value)
/rotate-key-auto sk-AbCdEf...

# Scan the repo for ALL leaked keys, rotate each
/rotate-key-auto --scan

# Non-interactive (CI mode): force provider + supply replacement
/rotate-key-auto --provider stripe --new-value sk_live_NEW... --yes
```

## How to apply this command

Run the backing script and stream its output to the user:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/rotate-key-auto.py ${ARGS}
```

Where `ARGS` is `${1}` (or `--scan` etc.). The script is interactive by default — when it asks for the new value, paste it from the provider's console. When it asks for confirmation before scrubbing, default to yes.

**Important:** never paste the leaked value or the new value into chat where it might end up in logs. The script reads stdin securely.

## Safety properties

- All file edits are **reversible** — backups under `.agentic-security/rotation-backups/<timestamp>/`.
- The script never logs full key values — only prefix + suffix.
- Working-tree scrub only by default. Pass `--scrub-history` to also rewrite git history (see below).
- Won't auto-push to a deployment platform without explicit `y` confirmation per env var per platform.

## `--scrub-history` — purge from git history

A revoked key in git history is no longer dangerous (it can't be used), but it CAN be embarrassing in an audit, and security teams flag it. Adding `--scrub-history` rewrites history to remove the value.

```bash
/rotate-key-auto sk-leakedValue... --scrub-history
```

What it does:

1. **Refuses if the working tree is dirty** — uncommitted changes would be lost in the rewrite. Commit or stash first.
2. **Refuses if you're not on a clean main/master branch with no in-flight feature branches** — rewriting history with active branches creates orphan commits and confused collaborators. Switch branches and merge first, or pass `--force` to override.
3. **Detects which tool is available**: `git filter-repo` (preferred) > `bfg` (Java jar). Refuses if neither is installed and prints install instructions:
   - `brew install git-filter-repo` or `pip install git-filter-repo`
   - `brew install bfg`
4. **Creates a tagged backup** of the pre-rewrite repo state (`backup/pre-scrub-<timestamp>`) so the rewrite is reversible until you `git push --force`.
5. **Performs the rewrite** with the appropriate tool, replacing the leaked value with `***REVOKED***`.
6. **Prints the manual steps** you must take next:
   - `git push --force` — irreversible. Confirm the team is OK with it first.
   - Force-update protected branches via the GitHub/GitLab UI (settings → branches).
   - Notify any collaborators that they must re-clone — `git pull` will fail post-rewrite.
   - Open a GitHub support ticket to purge cached views (`https://support.github.com/contact/private-information`).

**Audit log**: every `--scrub-history` operation writes `.agentic-security/rotation-history/<timestamp>.json` capturing what was scrubbed, by whom, when, and the pre-/post-rewrite SHAs. Hand this to your security team as evidence the rotation was completed.

## What you must do that the script can't

- **Click "revoke"** in the provider's console. The script doesn't have your console session; it tells you exactly where to click.
- **Set a usage limit** for the new key — every provider above has a hard-cap setting. Set it.
- **Check billing** for unexpected charges in the last 24h. Open the dashboard. Look at the graph.

🛡  agentic-security · created by Clear Capabilities
