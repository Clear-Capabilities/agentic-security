---
description: Run a full security scan (SAST + SCA + Secrets) then triage findings to minimize false positives before reporting.
argument-hint: "[path]"
---
```bash
node /Users/ross/.claude/plugins/cache/clearcapabilities/agentic-security/0.3.1/scanner/dist/agentic-security.mjs scan ${1:-.}
```

After the scan completes, read `.agentic-security/last-scan.json` and triage every finding before presenting results. Do not report raw scanner output — only report the triaged list.

## Triage pipeline (apply in order)

1. **Dedupe by `(file, line, vuln)`** — when two findings share the same location and overlapping vuln type, keep the one with the highest severity and drop the rest.

2. **FP filter** — mark a finding `[FP: <reason>]` and exclude it from the final count if any of the following are true:
   - The file path matches a non-production pattern: `test/`, `spec/`, `fixture/`, `mock/`, `stub/`, `__tests__/`, `*.test.*`, `*.spec.*`, `storybook/`, `docs/`, `examples/`, `codefixes/`
   - The sink is inside a comment or a string that is never assigned to a DOM property or executed
   - The tainted value flows through a known sanitizer before the sink: DOMPurify, escapeHtml, he.escape, validator.escape, parameterize, helmet, xss(), sanitizeHtml, marked.parseInline with sanitize:true
   - For IDOR: an ownership comparison (`UserId !== customer.id`, etc.) with a guard (`throw` / `res.status(401/403)` / `next(new Error(...))`) exists within ±40 lines of the sink, or the WHERE-clause uses an auth-derived value rather than a raw user input
   - For Hardcoded Secret: the value is a placeholder (`changeme`, `xxxx`, `<replace>`, `example`, `your-*`, `TODO`), a test fixture value, or an OAuth URL fragment key (e.g. `access_token=`, `id_token=`)
   - For SQL Injection: the query uses a parameterized form (`$1`, `?`, named params, or an ORM method that escapes by default) with no raw string concatenation of tainted input

3. **Sanitizer downgrade** — if a finding passes the FP filter but its taint path crosses a sanitizer, downgrade severity one tier (critical→high, high→medium, medium→low). Never go below low.

4. **Score exploitability** (0–100) for each surviving finding:
   - Reachable from a route handler? +30
   - Source is HTTP-facing (`req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`)? +25
   - Sink category is critical (RCE, SQLi, Command Injection, SSTI)? +25
   - Touches PII / PHI / PCI data? +10
   - Cross-file taint chain? +10

5. **Chain detection** — if two findings combine into a worse outcome (e.g. SSRF + hardcoded cloud credential = remote credential exfiltration), surface the chain as a single grouped entry above the individual findings.

## Output format

Present a Markdown table of confirmed findings only (exclude FPs):

```
| # | Severity | Score | CWE | File:Line | Vulnerability | Why this matters |
```

- Sort by severity tier (critical first), then by score descending within each tier.
- Cap the table at 30 rows; if more exist, append: `… and N more — run /agentic-security:security-report for the full list.`
- After the table, print one-line counts: `Confirmed: X critical, Y high, Z medium, W low | Suppressed as FP: N`
- If zero confirmed findings: print `No confirmed findings.` and stop.
- Do **not** print the raw JSON or intermediate triage steps.
