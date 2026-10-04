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

## Haskell and Nix specifics

- **Haskell literals.** A credential assigned to a name (`apiKey = "..."`), joined from literals (`"sk_live_" ++ "..."` or
  `<>`), or embedded in a dependency URL (`https://user:password@host/...` in `cabal.project`) is found. The value is never
  printed or written to state, SARIF, HTML or any other output. Secrets already in git history are found by
  `--secret-history`, the same as for other languages.
- **Nix store exposure.** Anything rendered into the Nix store is readable by every local user, so a secret in a string that
  becomes a store path is a leak even in a private repository: a plaintext credential, a secret interpolated into an
  `environment.etc` file or a unit, one echoed into a build log, and a decrypt-then-copy into the store are separate findings.
- **Alternatives that keep the secret out of the store**: a runtime secret manager's path (for example `age.secrets.<n>.path`
  or `sops.secrets.<n>.path`), systemd `LoadCredential=`, or an `EnvironmentFile` outside the store. These are guidance: the
  scanner does not rewrite them, because moving a credential changes who can read it.
- **Rotation is the same**: treat a value that was ever in a store path or a commit as exposed, rotate it, then scrub history.
- **Before it is written.** The edit hook recognises Haskell and Nix credential assignments, including a literal split across
  `++`, `<>` or `+`, before the edit lands.

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
