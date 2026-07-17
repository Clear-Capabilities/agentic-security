---
name: agentic-security:security-explain
description: Explain or teach a vuln. Activate on a CVE/GHSA id, "what is this vuln", "explain finding", or a Socratic walkthrough.
---

# Skill — explain or teach a vulnerability

Activates when the user references a vulnerability by ID
(`CVE-2024-1234`, `GHSA-jf85-cpcp-j695`) or asks for an explanation of a
specific finding — either as a quick plain-English brief or as a Socratic
teaching walkthrough. Don't wait for them to type `/triage --explain`.

Two modes live here:

- **Plain-English explanation** — a fast, business-terms brief of what a
  CVE / GHSA / finding is and how bad it is.
- **Socratic walkthrough** — teach the finding so the user can spot the
  same bug class themselves next time, instead of just clicking "apply."

## When to fire

- The user pastes a CVE / GHSA id into the chat.
- The user asks "what is X" where X is a CWE class, a vuln name, or an
  advisory ID.
- The user pastes a scanner finding (`[critical] CWE-89 SQL Injection at
  api/users.ts:42`) and asks for context.
- A subagent surfaces a finding and you want to brief the user before
  proposing a fix.
- The user asks "why is this dangerous" / "help me understand X".
- The user references a finding id (`ir-taint:app.js:14:py-cursor-execute`)
  and asks for context.
- The user pastes a vulnerable snippet and asks "what's wrong here".
- The user has accepted ≥3 fixes in a row without asking questions —
  fire the **Socratic walkthrough** automatically to bring them out of
  mechanical-acceptance mode.

**Pick the mode.** Use the plain-English explanation for "what is this /
how bad" and to brief before a fix. Switch to the Socratic walkthrough
when the user wants to *understand* — help me understand, why is this
dangerous, what's wrong here — and not just be told the answer.

## Plain-English explanation (CVE / GHSA / finding)

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

### Don't

- Don't invent CVE details from training data. If `lookup_cve` returns
  `present: false`, say "I don't have current data on this CVE — the
  local OSV cache doesn't have it" and offer to run `/scan --all`
  which populates the cache.
- Don't ship the explanation without a fix suggestion. Every
  explanation ends with a concrete next action.
- Don't dump CVSS jargon when the user is asking in business terms.

## Socratic walkthrough

Use this when the user wants to **understand** a finding, not just read
its remediation field. The default `/triage --explain` and the security-
fixer agent both default to "here's the answer." This mode teaches.

1. **Identify the three actors.** Every taint finding has:
   - **Source** — where attacker-controlled data enters
   - **Sink** — where it executes / leaks / corrupts
   - **Sanitizer** (or its absence) — what's missing between them
   Ask the user to point at each in the snippet BEFORE you explain.

2. **Walk source → sink as a story.** Not "CWE-89 is SQL injection."
   Instead: "An attacker hits this endpoint. Their `?name=` query string
   becomes the `name` variable on line 12. Trace it: line 13 concatenates
   it into `query`. Line 14 passes `query` to `cursor.execute`. The
   database now interprets the attacker's apostrophe as a SQL string
   delimiter."

3. **Ask before showing.** "What payload would make this dump every
   row?" Let the user try first. If they're stuck, give them ONE hint:
   "The attacker needs to escape the SQL string and append a clause
   that always evaluates to true."

4. **Show the fix structurally.** When the user names the payload,
   reveal:
   ```python
   cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
   ```
   And explain: parameterized form sends the value via a SEPARATE
   channel; the database never parses it as SQL.

5. **Verify understanding.** "Why doesn't `name.replace('\\'', '')`
   work as a fix?" Common follow-up traps to test:
   - Naive escape vs. parameterization
   - Validation regex that misses encoded variants
   - Sanitizing at the wrong layer (output instead of input)

6. **Apply the fix together.** Once the user gets it, use
   `synthesize_fix → verify_fix → apply_fix` from the deterministic
   toolchain — same as security-fix-finding, but with the
   understanding earned.

### CWE-specific Socratic patterns

| CWE | Key question to ask first |
|-----|---------------------------|
| CWE-89 (SQLi) | What's the difference between a SQL string literal and a SQL identifier? |
| CWE-79 (XSS) | What HTML metacharacters does the attacker need? Which contexts give them more / less power? |
| CWE-78 (cmd-inj) | What does `/bin/sh -c` parse that `execve` doesn't? |
| CWE-22 (path) | Why doesn't `path.replace('../', '')` work? |
| CWE-918 (SSRF) | What can an attacker reach FROM your server that they can't reach FROM their browser? |
| CWE-502 (deser) | Why is `json.loads` safe but `pickle.loads` not? |
| CWE-94 (SSTI) | What's the difference between rendering a template vs. compiling a template from input? |
| CWE-1321 (proto) | What's the prototype chain? What does `__proto__` write to? |

### Don't

- Don't lecture. Three short Socratic exchanges max before showing the fix.
- Don't dumb it down for senior engineers — gauge level on the first response.
- Don't skip the verify-understanding step. The whole point is they can spot
  the same bug class next time without you.
- Don't move to apply_fix until the user has named the payload OR
  declined further explanation.

## Canonical commands

- `/triage --explain <finding-id-or-CWE-or-vuln-name>` — encyclopedic CWE
  reference (read-only); add `--narrative` for the four-act attack story.
- `/fix <finding-id>` (or `/fix --one <id>`) — apply the fix with verification.
- `/scan` / `/scan --all` — populate the OSV cache, then re-scan after apply
  to confirm clean.

## Why the Socratic mode is here

The security industry has a learned-helplessness problem with
developers: tools say "you have a vulnerability, here's a patch,"
developers click "apply." Six months later the same dev creates the
same bug class. The Socratic mode is the antidote — every finding is also
a teaching moment. Stickiest use comes from junior devs, who become
senior advocates.
