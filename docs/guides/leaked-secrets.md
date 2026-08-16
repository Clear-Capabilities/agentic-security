# Responding to a leaked secret

**Goal:** when the scanner finds a hardcoded credential, do the right things in
the right order — because rotating a live key carelessly can break production
or, worse, tip off an attacker before you've assessed the damage.

**Prerequisites:** a scan surfaced a secret (`family: secret` /
`Hardcoded credential`). This is an incident playbook; work top to bottom.

> A committed secret must be treated as **compromised**, even if the repo is
> private. Anyone with clone access, every CI log, and every fork has seen it.
> Removing it from the current file is not enough — it's still in git history.

---

## 1. Don't echo the value

Don't paste the secret into chat, a ticket, or a log while investigating.
Refer to it by location (`auth.js:7`), not by value.

## 2. Identify the provider

The prefix usually tells you who issued it:

| Prefix | Provider |
|---|---|
| `sk-…`, `sk-proj-…` | OpenAI |
| `sk-ant-…` | Anthropic |
| `ghp_…`, `github_pat_…` | GitHub PAT |
| `xoxb-…` / `xoxp-…` | Slack |
| `AKIA…` | AWS access key |
| `AIza…` | Google API key |
| a `service_role` JWT | Supabase service-role |
| `{"type":"service_account"}` | GCP service account |

## 3. Assess blast radius *before* rotating

Rotating first can destroy the evidence you need. Check what the key could have
done and whether it was used:

- **Payment keys** (Stripe) = real money — check the dashboard for unauthorized
  charges in the last 24h first.
- **Cloud keys** (AWS) = surprise bills — check Cost Explorer / billing for
  crypto-mining spikes.
- **Database / service-role keys** (Supabase service-role bypasses every RLS
  rule) — audit access logs for anomalous reads since the value first appeared.
- **Source keys** (GitHub PAT) — check for unexpected pushes, forks, or setting
  changes.

## 4. Revoke and rotate

Revoke at the provider's console, then issue a replacement and move it to a
secret manager or environment variable — never back into the code.

**Guided (Claude Code):**

```text
/agentic-security:fix --finding <id> --rotate-secret
```

Add `--auto` to run the revoke-and-rotate end to end. The guided flow prints
the exact revoke URL for the detected provider and walks the steps in this
order.

## 5. Scrub it from git history

The value lives in every historical commit until you rewrite history:

```text
/agentic-security:fix --finding <id> --rotate-secret --scrub-history
```

This rewrites the affected history. Coordinate with anyone who has the repo
cloned — a history rewrite requires everyone to re-clone or hard-reset — and
force-push only with your team's agreement.

## 6. Verify

Re-scan to confirm the finding is gone from the working tree, and consider a
history sweep for anything else that was committed-then-removed:

```bash
npx @clear-capabilities/agentic-security-scanner scan . --secret-history
```

`--secret-history` walks git history for secrets that were committed and later
deleted — the ones a normal working-tree scan can't see.

---

## Prevent the next one

Install the write-time bodyguard so a hardcoded key is caught as your AI writes
it, before it's ever committed:

```text
/agentic-security:setup --bodyguard
```

And migrate scattered env vars into a managed vault:

```text
/agentic-security:fix --vault
```

---

## Related

- [Fixing vulnerabilities](fixing-vulnerabilities.md) · [Scanning](scanning.md)
- [CI setup](ci-setup.md) — catch secrets at merge time too
