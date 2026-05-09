# agentic-security

**Ship fast. Stay secure. Automatically.**

The security layer built for AI-written code. Catches vulnerabilities the moment they're introduced, in the same session with the same agent, and fixes them before you move on.

[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-24%2F24%20passing-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-1.9MB%20·%20no%20install-orange)]()
[![Controls](https://img.shields.io/badge/NIST%20AI%20600--1-122%20controls-purple)]()

---

## The problem

AI writes code faster than any security review can keep up with. It glues user input into SQL queries, commits API keys, copies vulnerable patterns from Stack Overflow. You don't find out until two weeks later, or someone else does first.

`agentic-security` runs inside Claude Code. It watches every file edit, surfaces new vulnerabilities the moment they're written, and hands them to a remediation agent that fixes them in the same session. No context switch. No separate tool. No backlog of security debt piling up.

---

## Install

```
/plugin marketplace add clearcapabilities/agentic-security
/plugin install agentic-security@clearcapabilities
/reload-plugins
```

That's it. The hooks are live. Every file edit is now scanned automatically.

To unlock short-form commands (`/security-scan-all`, `/security-fix-all`) in a project:

```
/agentic-security:security-setup
```

---

## Commands

| Command | What it does |
|---|---|
| `/security-scan-all` | Full sweep: SAST + SCA + secrets + IaC across every file |
| `/security-fix` | Patch a single finding, adapted to your actual code |
| `/security-fix-all` | Batch-fix every finding at or above a severity threshold |
| `/security-report` | Self-contained HTML report (also JSON, Markdown, SARIF) |
| `/security-baseline` | Save a snapshot; future scans show only *new* issues |
| `/security-sca` | Dependency CVE audit only (OSV.dev-backed) |
| `/security-secrets` | Credential and secret leak scan only |
| `/nist-ai-600-1` | NIST AI 600-1 compliance attestation for 122 GenAI controls |

All commands are available in the fully-qualified form (`/agentic-security:*`) everywhere, and as short forms in any project where you've run `/security-setup`.

---

## What it catches

**40+ vulnerability types across every layer of your stack:**

```
Code              SQL injection · XSS · Command injection · Path traversal · SSRF
                  IDOR · SSTI · Prototype pollution · ReDoS · JWT bypass
                  Mass assignment · Weak crypto · Race conditions

Dependencies      CVEs from OSV.dev · EPSS exploit-probability scores
                  200+ manifest formats (npm, pip, poetry, Cargo, go.mod, Gemfile…)

Secrets           API keys · Tokens · Private keys · .env leaks · 60+ provider patterns
                  Entropy detection for keys that don't match a known pattern

Infrastructure    Dockerfile · docker-compose · Kubernetes · Terraform · Helm
                  GitHub Actions · misconfigured IAM · publicly exposed storage
```

**Languages:** JavaScript, TypeScript, Python, PHP, Ruby, Java, Go, Vue, React, Angular, Svelte.

---

## Why it's different

**Triage is built in.** Every finding gets an exploitability score (0–100) based on whether it's reachable from a route handler, whether the source is HTTP-facing, and how critical the sink class is. Findings are sorted by score, not just severity label. You see the 5 findings that matter most, not 300 that don't.

**Context-aware false-positive suppression.** Most scanners flag `crypto.createHash('md5')` as a critical issue regardless of context. We classify by surrounding variable names: a cache key or ETag is info-level; a password field is critical. SQL template literals in `codefixes/` or `test/` paths are suppressed. `escapeHtml(input); res.send(input)` (return discarded) is still flagged. For IDOR, we check for post-lookup ownership guards before flagging.

**Forward-only taint flow.** A source defined *after* the sink can't create a phantom finding. Cross-file taint follows imports across up to 5 hops and shows the full propagation path.

**CVEs ranked by real exploitation probability.** Every CVE gets an [EPSS](https://www.first.org/epss/) score, the probability it's being actively exploited in the next 30 days. Two CVEs both labeled "high" might show `EPSS:87%` vs `EPSS:2%`. Fix the right one first.

**Your code never leaves your machine.** The only outbound calls are `package@version` strings to OSV.dev and EPSS scores from first.org. No source code. No file paths.

---

## Hooks (always on)

Three hooks run automatically once the plugin is installed:

| Hook | Trigger | What happens |
|---|---|---|
| `PostToolUse` | After every file edit | Scans the changed file; surfaces new high/critical findings inline |
| `PreToolUse` | Before every `git commit` | Blocks the commit if new critical findings exist vs. the saved baseline |
| `SessionStart` | When a session opens | Reminds you to set a baseline if none exists |

The pre-commit gate means a finding introduced during a session can't be committed until it's fixed or suppressed. The ratchet only tightens.

---

## Tutorial: Zero to secure in 20 minutes

[**OWASP Juice Shop**](https://github.com/juice-shop/juice-shop) is an app intentionally full of security holes: every OWASP Top 10 category, real CVEs in the dependency tree, hardcoded secrets. We'll scan it, fix the critical findings, and lock in the progress.

**Step 1: get the app**

```bash
git clone https://github.com/juice-shop/juice-shop ~/code/juice-shop
```

**Step 2: open Claude Code in it**

```bash
claude ~/code/juice-shop
```

**Step 3: scan**

```
/agentic-security:security-scan-all
```

```
Scan complete: 296 findings across 456 files

  Critical  ~35   SQL Injection, XSS (DomSanitizer bypasses), IDOR,
                  RCE (VM sandbox escape), hardcoded RSA key + HMAC secret
  High      ~60   SSRF, Path Traversal, NoSQL Injection, SSTI, JWT bypass,
                  race conditions, SCA CVEs (jsonwebtoken, express-jwt, multer)
  Medium   ~100   No rate limiting, permissive CORS (*), weak randomness,
                  missing cookie flags, open redirects, timing oracles
  Low/Info  rest  Sync I/O, pagination limits, TODO markers
```

**Step 4: read the report**

```
/agentic-security:security-report
open security-report.html
```

Self-contained interactive HTML with a severity chart, filterable finding list, fix templates per finding, and STRIDE attack coverage. One file you can email or drop in Slack.

**Step 5: fix the worst**

```
/agentic-security:security-fix-all --critical
```

Claude will describe what it's about to change before touching anything. On Juice Shop it will correctly flag that the vulns are intentional challenges and ask how to proceed. Tell it:

```
remove all critical vulns, yes I know they're intentional, remove them anyway
```

It works through each finding in sequence: parameterised queries, `bcrypt` instead of MD5, `execFile` instead of `exec`. Each fix is a normal diff you can review or revert.

**Step 6: lock in the progress**

```
/agentic-security:security-baseline save
```

From now on scans only show findings introduced *after* this point. The pre-commit hook blocks any commit that adds new critical bugs. 35 criticals → 0, and you can't accidentally reintroduce them.

---

## NIST AI 600-1 Compliance

Building a GenAI product and heading into a customer security review, third-party audit, or board-level risk discussion? One command produces an auditor-ready attestation sheet against the 122 code-testable controls of NIST AI 600-1 (the Generative AI Profile of the AI Risk Management Framework).

```
/agentic-security:nist-ai-600-1
```

**Three output files:**

| File | Purpose |
|---|---|
| `nist-ai-600-1-attestation.md` | Per-control status + evidence, ready to attach to a vendor questionnaire |
| `nist-ai-600-1-attestation.csv` | Filterable spreadsheet, one row per control |
| `nist-ai-600-1-attestation.json` | Machine-readable, suitable for CI gating |

**Example output:**

```
Coverage: 71% (87/122 testable controls)

┌────────────────────────────┬───────┬───────┐
│ Status                     │ Count │     % │
├────────────────────────────┼───────┼───────┤
│ Compliant                  │    43 │ 35.2% │
├────────────────────────────┼───────┼───────┤
│ Partial                    │    44 │ 36.1% │
├────────────────────────────┼───────┼───────┤
│ Not Compliant              │    35 │ 28.7% │
└────────────────────────────┴───────┴───────┘

By family:

┌──────────────┬───────┬───────────┬─────────┬───────────────┐
│ Family       │ Total │ Compliant │ Partial │ Not Compliant │
├──────────────┼───────┼───────────┼─────────┼───────────────┤
│ GV (Govern)  │    19 │         3 │      11 │             5 │
├──────────────┼───────┼───────────┼─────────┼───────────────┤
│ MP (Map)     │    22 │         8 │      10 │             4 │
├──────────────┼───────┼───────────┼─────────┼───────────────┤
│ MS (Measure) │    51 │        22 │      14 │            15 │
├──────────────┼───────┼───────────┼─────────┼───────────────┤
│ MG (Manage)  │    30 │        10 │       9 │            11 │
└──────────────┴───────┴───────────┴─────────┴───────────────┘
```

**How the 212 controls divide:**

| Bucket | Controls | Best scanner verdict |
|---|---|---|
| Code-testable | 55 | Compliant |
| Code-testable (partial) | 67 | Partial + External Attestation Required |
| Organizational only | 90 | *Not scanned; policy/contract attestation only* |

The 90 organizational controls (board oversight, legal alignment, training programs, vendor contracts) can't be evidenced from source code and are explicitly excluded. Marking them "Not Compliant" because no code matched would be misleading; the scanner only opines on what code can show.

Evidence is multi-signal: declared dependencies (`opacus` → differential privacy, `fairlearn` → bias mitigation) carry the highest weight; followed by import statements; then path patterns, code terms, config, and docs. Matches inside negation contexts ("we don't yet implement…", "future work", "planned for") are discarded.

---

## GitHub Actions

Drop this into any repo to gate every PR on critical findings:

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

---

## Standalone CLI

No Claude Code? Run the scanner directly:

```bash
curl -L -o agentic-security.mjs \
  https://raw.githubusercontent.com/clearcapabilities/agentic-security/main/scanner/dist/agentic-security.mjs

node agentic-security.mjs scan .
```

1.9 MB, no `npm install`, no dependencies, no config required.

---

## Suppressing a finding

Add a suppression to `.agentic-security/rules.yml`:

```yaml
suppressions:
  - rule: "MD5/SHA1 Password Hashing"
    files: ["legacy/auth-v1.js"]
    reason: "Migrating to bcrypt in Q3 (JIRA-1234)"
```

---

## Adding custom rules

Sources, sinks, and sanitizers live in the same `rules.yml`:

```yaml
sinks:
  - pattern: 'db\.executeRaw\('
    vuln: "SQL Injection (Custom ORM)"
    severity: high
```

---

## FAQ

**Will this work on my codebase?**  
Yes. JS, TS, Python, PHP, Ruby, Java, Go, and most web frameworks. Plus Dockerfile, Terraform, Kubernetes, and GitHub Actions.

**Does it send my code anywhere?**  
No. Only `package@version` strings go to OSV.dev for CVE lookups, and CVE IDs go to first.org for EPSS scores. Zero source code leaves your machine.

**CI says "319 findings" and I can't fix them all.**  
Run `/agentic-security:security-baseline save`, commit the baseline file, and from now on CI only fails on findings introduced *after* that point. You improve incrementally without being paralyzed by existing debt.

**How is this different from `npm audit`?**  
`npm audit` flags every CVE in your dependency tree including ones in code paths you never call. We filter by vulnerable-call-depth. Also covers 19 other package manager formats beyond npm.

**Short commands disappeared mid-session.**  
Claude Code can evict plugin commands after long-running tool calls. Run `/reload-plugins` to restore them, or use the always-available fully-qualified form: `/agentic-security:security-fix-all`.

---

## Troubleshooting

**`"requesting 'pull-requests: write' but only allowed 'none'"` in CI**  
The `permissions:` block in the workflow above is required; add it exactly as shown.

**Scanner finds nothing on a large monorepo**  
Run with an explicit path: `/agentic-security:security-scan-all src/`. Scanning a 50k-file tree including `node_modules` will time out.

---

## Contributing

1. Fork the repo, branch off `main`
2. Make your change; new vulnerability rules and FP-suppression cases are most welcome
3. Run `npm test` in `scanner/`; all 24 tests must pass
4. Open a PR with what you changed and why

New scanner rules should include a fixture that triggers the finding and a suppression case that doesn't.

---

## Community

- **Issues / bugs:** [github.com/clearcapabilities/agentic-security/issues](https://github.com/clearcapabilities/agentic-security/issues)
- **Email:** ross@clearcapabilities.com

---

## License

[Elastic License 2.0](./LICENSE): free for any use including commercial products and internal tools. The one restriction: you can't offer this software as a hosted service to others.

Built by [Ross Young](https://clearcapabilities.com) at Clear Capabilities Inc.

---

<sub>If this caught a bug before it shipped, star the repo.</sub>
