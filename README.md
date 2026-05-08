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

Install for: [Claude Code](#claude-code) · [GitHub Actions](#github-actions) · [Terminal / CI](#terminal--ci)

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

### GitHub Actions

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

### Terminal / CI

```bash
curl -L -o agentic-security.mjs \
  https://raw.githubusercontent.com/clearcapabilities/agentic-security/main/scanner/dist/agentic-security.mjs
node agentic-security.mjs scan .
```

One self-contained 1.9 MB file. No `npm install`, no dependencies.

---

## Commands

```
/agentic-security:security-scan-all               scan everything — SAST + dependencies + secrets
/agentic-security:security-fix-all --severity high  fix everything high and above
/agentic-security:security-baseline save          lock in current findings; only show NEW problems after this
/agentic-security:security-report                 open an interactive HTML report
/agentic-security:security-secrets                secrets-only scan
/agentic-security:security-sca                    dependency vulnerabilities only
/agentic-security:security-fix <id>               fix a single finding by ID
```

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

**Subagents**
- **security-fixer** — reads context, adapts fix templates to your actual code, runs your tests
- **security-triager** — dedupes, scores exploitability, and ranks a finding list for human review
- **sca-malware-analyst** — CLEAN / SUSPICIOUS / MALICIOUS verdict on dependencies using strict grounding rules

**Skills** (auto-trigger based on what you're doing)
- **sast-scan** — activates when you ask "is this safe?" or generate new code
- **sca-scan** — activates when you add/change a dependency or mention a CVE
- **secret-scan** — activates before publishing or when you touch a config file
- **fix-vulnerability** — activates when you ask Claude to fix a security issue

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
/agentic-security:security-scan-all <code_directory_path>
```

```
Agentic Security — 319 finding(s) across 456 file(s)

  Critical    49
  High        93
  Medium      167
  Low         1
  Info        9
```

319 real bugs. Most are clustered in a handful of files. Welcome to a real codebase.

**Step 3 — get a report**

```
/agentic-security:security-report
open security-report.html
```

A self-contained interactive page: severity chart, filterable finding list, fix templates per finding, STRIDE attack coverage overview. One file — email it, attach to a Jira ticket, drop in Slack.

**Step 4 — fix the worst stuff**

```
/agentic-security:security-fix-all --severity critical
```

Before touching any code, Claude will read the findings and summarise what it's about to change. It may ask for confirmation — especially on a well-known codebase like Juice Shop, where it recognises that the vulnerabilities are intentional challenges. Tell it to proceed:

```
fix all 49 critical vulns
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

Put `before.html` and `after.html` side by side. In about 10 minutes you went from 49 critical findings to near-zero, and now have a gate that prevents regressions.

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

**Fewer false positives.** Most scanners flag `crypto.createHash('md5')` as a critical password-hashing issue. We look at variable names and context — if it's a cache key or ETag, it's info-level. We follow actual data flow, so `escapeHtml(input); res.send(input)` (sanitizer return discarded) is still flagged. Test fixtures, translation files, and example values are silently suppressed via a 4-gate filter.

**CVEs ranked by real-world exploitation.** Every CVE gets an [EPSS](https://www.first.org/epss/) score — the probability it's being actively exploited. Two CVEs both labeled "high" now have `exploitability: 87%` vs. `exploitability: 2%`. Fix the right one first.

**Your code never leaves your machine.** The only network call is to OSV.dev, and we send only `package@version` strings. Pass `--no-network` to go fully offline.

---

## Philosophy

- **Fix, don't just report** — findings come with canonical fix templates and a subagent that applies them
- **Signal over noise** — false-positive suppression by context, not just by rule
- **Local-first** — one file, no cloud dependency, no code upload
- **Ratchet, don't boil the ocean** — baseline + gate means you improve incrementally without getting paralyzed by legacy debt

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

**"Unknown command: /security-scan-all"** — either use the fully-qualified form (`/agentic-security:security-scan-all`) which is always available, or run the setup step in your project to install the short forms:
```bash
node $(find ~/.claude/plugins -name "agentic-security.mjs" | sort | tail -1) setup
```

**Short-form commands disappear mid-session** — Claude Code can evict plugin commands from the active session after long-running tool calls (large scans, multi-file fixes). Two options:
- Run `/reload-plugins` to restore all short-form commands for the rest of the session.
- Use the fully-qualified form instead: `/agentic-security:security-fix-all`, `/agentic-security:security-scan-all`, etc. — these resolve through the plugin skill system and are always available.

**CI fails with `'pull-requests: write' but only allowed 'none'`** — add the `permissions:` block shown in the GitHub Actions install section above.

**Scan is slow on a large repo** — use `--changed-since HEAD~5` to scan only modified files.

**Want to see what got suppressed** — run with `--include-suppressed --format json` and inspect the `suppressed` array.

---

## For security engineers

The technical details: AST-based cross-file taint tracking for JS/TS (BFS up to 5 hops), inter-procedural taint for Python, vulnerable-call-depth filtering on every CVE, EPSS + CVSS overlay, 4-gate credential FP filter, structural recognizers for high-entropy non-secrets (UUIDs, hex digests, JWT samples), MD5/SHA1 context classifier, sanitizer effectiveness by data-flow.

CWE coverage: 22, 78, 79, 89, 94, 113, 200, 204, 208, 209, 250, 307, 311, 321, 327, 330, 338, 347, 362, 367, 434, 470, 489, 502, 601, 611, 614, 620, 639, 732, 798, 829, 840, 862, 863, 915, 916, 918, 942, 943, 1004, 1321, 1333, 1336.

The 8 false-positive-reduction specs are in the [GitHub issues](https://github.com/clearcapabilities/agentic-security/issues?q=is%3Aissue+label%3Afp-reduction) — each is a self-contained PRD with the problem, algorithm, and test cases.

---

## Community

- **Issues / bugs:** [github.com/clearcapabilities/agentic-security/issues](https://github.com/clearcapabilities/agentic-security/issues)
- **Email:** ross@clearcapabilities.com

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
