# agentic-security

**The security layer for AI-written code.**

You're shipping fast. Your AI writes great code, most of the time. But every so often it glues user input straight into a SQL query, hardcodes an API key, or copies a pattern that was already vulnerable. Two weeks later you get a security report — or a *very* angry email.

`agentic-security` watches every edit, surfaces new vulnerabilities the moment they're introduced, and fixes them — same session, same agent, before you've moved on.

```
You:              Add a /search endpoint that queries products by name.
Claude:           (writes code — one query glues user input straight into SQL)
agentic-security: ⚠ 1 new high-severity finding from this edit
                  [HIGH] CWE-89 SQL Injection (routes/products.js:42)
You:              /agentic-security:security-fix-all --severity high
Claude:           (rewrites to parameterized query, re-runs scan, finding gone)
```

[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-24%2F24%20passing-success)]()
[![Bundle](https://img.shields.io/badge/bundle-1.9MB%20single%20file-orange)]()

---

## Installation

### Claude Code

```
/plugin marketplace add clearcapabilities/agentic-security
/plugin install agentic-security@clearcapabilities
```

When prompted for installation scope, choose **"Install for you (user scope)"** — this makes the plugin available across all your projects without reinstalling.

Then reload the plugin registry:

```
/reload-plugins
```

Then run this once in each project you want to use the shorter command forms:

```
/agentic-security:security-setup
```

That's it. The short forms (`/security-scan-all`, `/security-fix-all`, etc.) will now work in this project alongside the always-available fully-qualified forms.

---

## What's inside

**Commands**
- **security-scan-all** — full sweep: SAST + SCA + secrets + IaC
- **security-fix** — patch one finding, adapted to your code by the fixer subagent
- **security-fix-all** — batch remediation at a severity threshold
- **security-baseline** — save/diff a baseline so only new findings surface
- **security-report** — self-contained interactive HTML report (also: JSON, Markdown, SARIF)
- **security-sca** — dependency CVE scan only
- **security-secrets** — credential leak scan only
- **security-setup** — install project shortcuts (run once per project)
- **nist-ai-600-1** — audit-ready NIST AI 600-1 compliance attestation (122 testable controls)

**Subagents**
- **security-fixer** — reads context, adapts fix templates to your actual code, runs your tests
- **security-triager** — dedupes, scores exploitability, and ranks a finding list for human review
- **sca-malware-analyst** — CLEAN / SUSPICIOUS / MALICIOUS verdict on dependencies using strict grounding rules

**Skills** (auto-trigger based on what you're doing)
- **sast-scan** — activates when you ask "is this safe?" or generate new code
- **sca-scan** — activates when you add/change a dependency or mention a CVE
- **secret-scan** — activates before publishing or when you touch a config file
- **fix-vulnerability** — activates when you ask Claude to fix a security issue
- **nist-ai-600-1** — activates when you ask about NIST AI 600-1, AI RMF compliance, or GenAI audit readiness

**Hooks** (always on)
- **PostToolUse** — scans the file after every edit; surfaces new high/critical findings inline
- **PreToolUse** — blocks `git commit` if new critical findings exist vs. baseline
- **SessionStart** — reminds you to set a baseline if none exists

---

## Tutorial: Fix a deliberately broken app

[**OWASP Juice Shop**](https://github.com/juice-shop/juice-shop) is an app *intentionally* full of security holes, used to teach hacking. We'll point the scanner at it, find a few hundred real bugs, fix the worst ones, and watch the score drop.

**Step 1 — grab the app**

```bash
git clone https://github.com/juice-shop/juice-shop ~/code/juice-shop
cd ~/code/juice-shop
```

**Step 2 — open Claude Code in the cloned repo**

```bash
claude ~/code/juice-shop
```

**Step 3 — scan it**

```
/agentic-security:security-scan-all
```

```
Scan Complete — 296 Findings Across 456 Files

  Critical  ~35   SQL Injection, XSS (DomSanitizer bypasses), IDOR,
                  RCE (VM sandbox), hardcoded RSA key / HMAC secret
  High      ~60   SSRF, Path Traversal, NoSQL Injection, SSTI,
                  JWT bypass, race conditions, SCA CVEs
                  (jsonwebtoken, express-jwt, multer, sequelize)
  Medium   ~100   No rate limiting on auth endpoints, permissive CORS (*),
                  weak randomness, cookie flags, open redirects, timing oracles
  Low/Info  rest  Sync I/O, pagination limits, TODO markers
```

296 confirmed findings, pre-triaged. False positives filtered before you see a single result.

**Step 3 — get a report**

```
/agentic-security:security-report
open security-report.html
```

A self-contained interactive page: severity chart, filterable finding list, fix templates per finding, STRIDE attack coverage overview. One file — email it, attach to a Jira ticket, drop in Slack.

**Step 4 — fix the worst stuff**

```
/agentic-security:security-fix-all --critical
```

Before touching any code, Claude will read the findings and summarise what it's about to change. On a well-known codebase like Juice Shop it will flag that the vulnerabilities are intentional challenges and ask how to proceed. Tell it:

```
please remove all critical vulns. yes i understand juice shop has purposely built vulns but remove all critical vulns anyways
```

Claude then works through each finding in sequence — parameterized queries instead of string concatenation, `bcrypt` instead of MD5, `execFile` instead of `exec`. Each fix is a normal edit you can review or revert. It runs serially because fixing one bug can change another.

**Step 5 — lock in your progress**

```
/agentic-security:security-baseline save
```

From now on, scans only show *new* findings added after this point. The pre-commit hook blocks any commit that introduces new critical bugs.

**Step 6 — generate the after-report, compare**

```
/agentic-security:security-report --output after.html
open after.html
```

Put `before.html` and `after.html` side by side. In less than 20 minutes you went from 35 critical findings to 0.

---

## What it catches

| Vulnerability | What goes wrong |
|---|---|
| **SQL injection** | `' OR 1=1` reads your entire user table |
| **Hardcoded secrets** | Stripe key ends up on GitHub; $4,000 fraud bill |
| **XSS** | A comment runs JS in every visitor's browser, steals sessions |
| **Path traversal** | User requests `../../../etc/passwd`; server serves it |
| **Command injection** | A search box runs shell commands on your server |
| **Weak password storage** | MD5 passwords cracked in minutes after a breach |
| **Vulnerable dependencies** | An `npm install` from months ago has an RCE CVE |
| **Misconfigured infra** | Terraform/Dockerfile/K8s accidentally exposes data publicly |

40+ vulnerability types. Code, dependencies, secrets, and infrastructure files.

**Languages:** JS, TypeScript, Python, PHP, Ruby, Java, Go, Vue, React, Angular, Svelte.
**Dependency manifests:** npm, yarn, pnpm, pip, poetry, Pipfile, composer, Gemfile, go.mod, Cargo, Maven, Gradle, pubspec — 20 formats.
**Infrastructure:** Dockerfile, docker-compose, Kubernetes, Terraform, Helm, GitHub Actions.

---

## What makes it different

**Triage is built in, not bolted on.** Findings are deduplicated, scored, and FP-filtered before you see a single result. Every finding gets an exploitability score (0–100) based on whether it's reachable from a route handler, whether the source is HTTP-facing, and how critical the sink class is. Findings are sorted by score, not just severity label.

**Context-aware false-positive suppression.** Most scanners flag `crypto.createHash('md5')` as a critical password-hashing issue regardless of context. We classify it by surrounding variable names — a cache key or ETag is info-level; a password field is critical. For IDOR, we check whether the lookup uses an auth-derived ownership clause in the WHERE, or whether a post-lookup comparison (`basket.UserId !== customer.id`) with a guard (`throw` / `res.status(403)`) exists nearby — if so, it's not flagged. For XSS, `element.innerHTML === value` (comparison) is distinguished from `element.innerHTML = value` (assignment). For secrets, SQL template literals, OAuth URL fragment keys, and values in `codefixes/`, `test/`, or `fixtures/` paths are suppressed automatically. Sanitizer return values are tracked: `escapeHtml(input); res.send(input)` (return discarded) is still flagged.

**Forward-only taint flow.** The taint engine enforces direction — a source defined *after* the sink cannot create a phantom finding. Cross-file taint tracks up to 5 hops (BFS), following imports and call chains across files and showing the full propagation path.

**CVEs ranked by real-world exploitation.** Every CVE gets an [EPSS](https://www.first.org/epss/) score — the probability it's being actively exploited in the next 30 days. Two CVEs both labeled "high" might show `EPSS:87%` vs `EPSS:2%` in the scan output. Within the same severity tier, the highest-EPSS finding always appears first. Fix the right one first.

**Your code never leaves your machine.** The only network calls are to OSV.dev (dependency CVE lookups) and first.org (EPSS scores). We send only `package@version` strings to OSV — no source code, no file paths.

---

## Philosophy

- **Fix, don't just report** — findings come with canonical fix templates and a subagent that applies them
- **Signal over noise** — false-positive suppression by context, not just by rule
- **Local-first** — one file, no cloud dependency, no code upload
- **Ratchet, don't boil the ocean** — baseline + gate means you improve incrementally without getting paralyzed by legacy debt

---

## NIST AI 600-1 Compliance

NIST AI 600-1 is the Generative AI Profile of the AI Risk Management Framework — 212 controls across four families (Govern, Map, Measure, Manage). `agentic-security` ships a deterministic scanner for the **122 code-testable controls** in that catalog, producing an audit-ready attestation sheet you can hand directly to a customer, auditor, or board.

```
/agentic-security:nist-ai-600-1
```

Or on any path:

```
/agentic-security:nist-ai-600-1 ~/code/my-genai-app
```

**What it produces**

Three files in the current directory:

| File | Use |
|---|---|
| `nist-ai-600-1-attestation.md` | Auditor-ready Markdown — per-control status + evidence |
| `nist-ai-600-1-attestation.csv` | Spreadsheet — one row per control, filterable |
| `nist-ai-600-1-attestation.json` | Machine-readable — suitable for CI gating |

**How the 212 controls are divided**

| Bucket | Controls | Best scanner status |
|---|---|---|
| Code-testable (Yes) | 55 | Compliant |
| Code-testable (Partial) | 67 | Partial + External Attestation Required |
| Organizational only (No) | 90 | _not scanned — policy/contract attestation only_ |

The 90 organizational controls (board oversight, legal alignment, training programs, vendor contracts) cannot be evidenced from source code and are explicitly excluded from scanning. Marking them "Not Compliant" because no code matched would be misleading.

**Multi-signal evidence scoring**

For each testable control the scanner runs three passes:

1. **Manifest pass** — parses `requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json`. A declared library that maps to a control (`opacus` → differential privacy, `fairlearn` → bias mitigation) is the strongest evidence type (weight 5.0).
2. **Import pass** — detects language-specific import statements for 200+ compliance-relevant libraries across Python, JS/TS, Go, and Ruby (weight 4.0).
3. **Keyword + path pass** — matches control-specific terms in code, config, and docs, with weights tiered by file type and a bonus for test coverage.

A **negation filter** discards matches that appear in "we don't yet implement…", "future work", "planned for", "missing", or "lacks" contexts — so a roadmap comment doesn't inflate your score.

**On a well-instrumented GenAI app** (differential privacy, fairness metrics, output watermarking, content filters, red-team CI) the scanner typically surfaces ~70% coverage across the 122 testable controls, with real library declarations and test files as evidence. On a vanilla AppSec codebase it correctly shows ~5% — only the controls that general security tooling addresses.

**Example output row**

```
| MS-2.6-001 | Watermarking / content provenance | Compliant |
| Evidence   | manifest: c2pa-python (requirements.txt) |
|            | import: c2pa (src/output/provenance.py:3) |
|            | code_term: content_credentials (src/output/provenance.py:14) |
```

---

## FAQ

**Will this work on my codebase?**
JS, TS, Python, PHP, Ruby, Java, Go, and most web frameworks — yes. Plus infra files.

**Does it run in the cloud?**
No. Scanner runs on your machine. OSV.dev gets only package names + versions.

**What if I disagree with a finding?**
Add a suppression to `.agentic-security/rules.yml`:
```yaml
suppressions:
  - rule: "MD5/SHA1 Password Hashing"
    files: ["legacy/auth-v1.js"]
    reason: "Migrating to bcrypt in Q3; JIRA-1234"
```

**Can I add custom rules?**
Yes — sources, sinks, and sanitizers in the same `rules.yml`:
```yaml
sinks:
  - pattern: 'db\.executeRaw\('
    vuln: 'SQL Injection (Custom)'
    severity: high
```

**My CI says "319 findings."**
That's a real codebase. Run `/agentic-security:security-baseline save`, commit the baseline file, and from now on you only see *new* problems.

**How is this different from `npm audit`?**
`npm audit` flags every CVE in your tree, including ones in code paths you never call. We filter by vulnerable-call-depth. Also covers 19 other manifest formats besides npm.

---

## Troubleshooting

**Short-form commands disappear mid-session** — Claude Code can evict plugin commands from the active session after long-running tool calls (large scans, multi-file fixes). Two options:
- Run `/reload-plugins` to restore all short-form commands for the rest of the session.
- Use the fully-qualified form instead: `/agentic-security:security-fix-all`, `/agentic-security:security-scan-all`, etc. — these resolve through the plugin skill system and are always available.

---

## Community

- **Issues / bugs:** [github.com/clearcapabilities/agentic-security/issues](https://github.com/clearcapabilities/agentic-security/issues)
- **Email:** ross@clearcapabilities.com

---

## GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request: {}
  push: { branches: [main] }

jobs:
  security:
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    uses: clearcapabilities/agentic-security/.github/workflows/scan.yml@main
    with:
      fail-on: critical
      baseline: ${{ github.event.pull_request.base.sha || 'HEAD~1' }}
```

Every PR gets a comment with severity counts and the top findings. Critical findings block merge.

> If CI fails with `"requesting 'pull-requests: write' but only allowed 'none'"` — the `permissions:` block above is required.

---

## Terminal / CI

```bash
curl -L -o agentic-security.mjs \
  https://raw.githubusercontent.com/clearcapabilities/agentic-security/main/scanner/dist/agentic-security.mjs
node agentic-security.mjs scan .
```

One self-contained 1.9 MB file. No `npm install`, no dependencies.

---

## Contributing

1. Fork the repo and create a branch off `main`
2. Make your change — bug fixes and new vulnerability rules are most welcome
3. Run `npm test` in `scanner/` and make sure all 24 tests pass
4. Open a PR describing what you changed and why

New scanner rules should include a fixture file that triggers the finding and a suppression case that doesn't.

---

## License

[Elastic License 2.0](./LICENSE) — free for any use, including commercial products and internal tools. The one restriction: you can't offer this software as a hosted service to others. Email ross@clearcapabilities.com if you need a different arrangement.

Built by [Ross Young](https://clearcapabilities.com) at Clear Capabilities Inc.

---

<sub>If this saved you from shipping a vulnerability, star the repo and tell another vibe coder.</sub>
