---
name: agentic-security:security-explain-cve
description: Explain a CVE / GHSA / finding in plain English. Activate on CVE-id, GHSA-, or "what is this vuln" questions.
---

# Skill — explain a CVE or finding

Activates automatically when the user references a vulnerability by ID
(`CVE-2024-1234`, `GHSA-jf85-cpcp-j695`) or asks for an explanation of a
specific finding. Don't wait for them to type `/triage --explain`.

## When to fire

- The user pastes a CVE / GHSA id into the chat.
- The user asks "what is X" where X is a CWE class, a vuln name, or an
  advisory ID.
- The user pastes a scanner finding (`[critical] CWE-89 SQL Injection at
  api/users.ts:42`) and asks for context.
- A subagent surfaces a finding and you want to brief the user before
  proposing a fix.

## What to do

1. **Look it up locally first.** Call MCP `lookup_cve({ cve: "CVE-…" })`
   — it returns the cached OSV / KEV / EPSS data with staleness tier.
   If it's there, lead with the cached snapshot (vendor + product + date
   added + KEV status). No network call needed.

2. **Then read the relevant explainer.** If the user has a scan in
   `.agentic-security/last-scan.json` and the CVE matches a finding,
   pull the finding's `description`, `remediation`, and `whyFired`
   evidence — call MCP `explain_finding({ finding_id })`. If they
   don't have a scan yet, fall back to the generic CWE explainer.

3. **Render the explanation in plain English.** Four parts:
   - **What it means** — one sentence in business terms.
   - **How an attacker abuses it** — concrete steps, not abstract risk.
   - **Worst case if unfixed** — tie to money / regulatory / customer impact.
   - **How to fix it** — the literal code change. Cite an existing
     command if there is one (e.g. `/fix --rotate-secret`).

4. **Offer the narrative shape if the user is non-technical.** Suggest
   `/triage --explain --narrative` for the four-act attack story when the
   audience is a builder or a PM, not a security engineer.

## Don't

- Don't invent CVE details from training data. If `lookup_cve` returns
  `present: false`, say "I don't have current data on this CVE — the
  local OSV cache doesn't have it" and offer to run `/scan --all`
  which populates the cache.
- Don't ship the explanation without a fix suggestion. Every
  explanation ends with a concrete next action.
- Don't dump CVSS jargon when the user is asking in business terms.

## Canonical command

If the user wants the explanation as a one-shot CLI output:
`/triage --explain <finding-id-or-CWE-or-vuln-name>` (or `/triage --explain --narrative`
for the attack-story shape).
