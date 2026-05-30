---
name: agentic-security:security-tutor
description: Walk a finding Socratically. Activate on "explain finding", "why is X dangerous", or a finding-id reference.
---

# Skill — security-tutor (Socratic walkthrough)

Activates when the user wants to **understand** a finding, not just
read its remediation field. The default `/triage --explain` and the security-
fixer agent both default to "here's the answer." This skill teaches.

## When to fire

- User asks "why is this dangerous" / "help me understand X"
- User references a finding id (`ir-taint:app.js:14:py-cursor-execute`)
  and asks for context
- User pastes a vulnerable snippet and asks "what's wrong here"
- User has accepted ≥3 fixes in a row without asking questions —
  fire automatically to bring them out of mechanical-acceptance mode

## What to do

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

## CWE-specific Socratic patterns

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

## Don't

- Don't lecture. Three short Socratic exchanges max before showing the fix.
- Don't dumb it down for senior engineers — gauge level on the first response.
- Don't skip the verify-understanding step. The whole point is they can spot
  the same bug class next time without you.
- Don't move to apply_fix until the user has named the payload OR
  declined further explanation.

## Canonical commands this hands off to

- `/triage --explain <cwe>` — encyclopedic CWE reference (read-only)
- `/fix <finding-id>` — apply the fix with verification
- `/scan` — re-scan after apply to confirm clean

## Why this is here

The security industry has a learned-helplessness problem with
developers: tools say "you have a vulnerability, here's a patch,"
developers click "apply." Six months later the same dev creates the
same bug class. This skill is the antidote — every finding is also a
teaching moment. Stickiest use comes from junior devs, who become
senior advocates.
