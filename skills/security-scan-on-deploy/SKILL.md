---
name: agentic-security:security-scan-on-deploy
description: Run the security scanner. Activate on ship / deploy / launch / "is this safe?" — before the deploy happens.
---

# Skill — scan before deploy

Activates when the user is about to push code to production, asks if their
project is safe to ship, or mentions any of the destructive-prone deploy
commands (`vercel --prod`, `fly deploy`, `wrangler publish`, `npm publish`,
`gh pr merge --auto`).

## When to fire

- User says "I'm about to deploy" / "is this safe to ship?" / "ready to launch?"
- User runs (or asks you to run) a production-deploy command via Bash.
- Conversation references go-live, GA, beta launch, customer migration.
- Right after a session-long feature build, before the merge.

## What to do

1. **Check for fresh scan state.** Read
   `.agentic-security/last-scan.json` mtime. If it's older than
   24 hours OR doesn't exist, run a fresh scan first:
   `/scan --all` for the full surface, or `/scan --uncommitted` if
   the user only edited a few files.

2. **Render the verdict, not the wall of findings.** The user is
   making a deploy decision, not auditing. Lead with:
   - **Safe to deploy** — no critical/high findings → say so in one
     line, mention the streak, offer `/compliance --attestation` to
     generate the badge.
   - **Critical findings present** — refuse to bless the deploy.
     Show the top 3 by exploitability, route to `/fix --all
     --critical` for batch remediation, or recommend wiring the
     CI bench gate so blocking is automatic next time.
   - **High but no critical** — show count, recommend triage via
     `/triage --show --all` before deploy, mention the deploy is
     still possible but flag the risk.

3. **Surface the production-aware filters.** If `/scan --exposed-only`
   has been configured (WAF / auth-middleware / network-policy
   ingest), use it. A finding the WAF already blocks shouldn't
   block the deploy.

4. **Offer one-finding triage flow.** If there's one blocker,
   suggest:
   `/triage --explain <id>` → `/fix --one <id>` → re-scan → ship.
   Don't just list the finding and walk away.

## Don't

- Don't bless a deploy with critical findings open.
- Don't drown the user in 80 medium-severity findings when they
  asked "safe to ship?". They want the verdict.
- Don't run the scanner on every "deploy" mention — check the
  `.agentic-security/last-scan.json` mtime first; reuse if fresh.

## Canonical commands

- `/scan --all` — full sweep
- `/scan --uncommitted` — only the user's recent edits
- `/secure` — vibecoder router; figures out the right next action
- `/compliance --attestation` — generate the badge / deploy-ready attestation
- `/find-and-fix-everything` — batch remediation pass before deploy
