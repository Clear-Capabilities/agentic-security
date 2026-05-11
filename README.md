# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[ClearCapabilities.Com](https://clearcapabilities.com)** · Runs inside Claude Code

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.16MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.18.0-blue)]()

---

## Why you need this

Your AI is fast. It's also writing security bugs.

This morning Claude wrote your login route in 9 seconds. Beautiful code. Tests pass.

It also lets anyone in the world log in as admin with a single line of curl.

You don't know this yet. Neither does Claude.

**One command finds it. One command fixes it.**

That command lives inside Claude Code, runs locally on your laptop, and explains every finding in plain English.

---

## Install

In **Claude Code** (recommended — gets you the slash commands):

```
/plugin install agentic-security
```

That's it. Type `/scan-all` to confirm it's working.

For **CI, terminal, or any project anywhere** (no Claude Code required):

```bash
npx @clearcapabilities/agentic-security-scanner scan .
```

The scanner runs entirely on your machine. Nothing leaves your laptop. No signups, no API keys, no cloud.

---

## Two modes. One tool.

Both modes run the same engine. They differ in how much you see and how much you can configure.

### 🎨 Easy Mode

Three commands. The whole product. The default for everyone.

---

#### `/scan-all` — daily, before deploy

**What `/scan-all` scans every run — nine pillars, no configuration required:**

```
       Pillar         What we scan
       ─────────────────────────────────────────────────────────────
       SAST           Taint analysis (regex + AST for JS/TS), Java
                      rule pack, Python helpers.
       SCA            OSV + CISA KEV + EPSS, function-level
                      reachability, dep confusion, typosquat.
       Secrets        50+ credential patterns, high-entropy heuristic,
                      allowlist-aware.
       IaC            Dockerfile, docker-compose, GitHub Actions,
                      Kubernetes manifests.
       LLM            OWASP LLM Top 10 (2025): prompt injection,
                      sensitive disclosure, supply chain, data/model
                      poisoning, improper output handling, excessive
                      agency, system prompt leakage, vector & embedding
                      weakness, misinformation prompts, unbounded
                      consumption. Benchmarked against AIGoat + LLMGoat.
       MCP            Agent-tool audit for over-privileged MCP servers.
       Pipeline       GitHub Actions integrity: floating tags,
                      secret echoes, OIDC misconfig.
       Auth/AuthZ     Broken access control, IDOR, mass assignment,
                      session fixation.
       Container      Base-image EOL, exposed ports, runtime mode.
```

A one-screen verdict. Either you're safe to ship, or you have a short list of things to fix.

```
─────────────────────────────────────────
  ✅  Safe to deploy
─────────────────────────────────────────
```

…or, when there's work to do:

```
─────────────────────────────────────────
  ❌  Not safe to deploy
─────────────────────────────────────────
  • 31 critical · 73 high · 149 advisory

  How many do you want to fix?

     1. Critical only                (31 fixes)
     2. Critical + High              (104 fixes)
     3. Critical + High + Medium     (253 fixes)

  Reply with 1, 2, or 3.

  Or pick a single one:
     /security-scan-all --firehose      see every finding
     /security-fix --finding <id>       fix exactly one
```

The scanner asks which tier you want to fix; reply with the number and `/fix-all` runs the matching `--severity` automatically.

---

#### `/show-findings` — interactive HTML report

Writes a self-contained HTML report to `.agentic-security/findings.html` and opens it in your default browser. The report has severity charts, a filterable findings list, per-finding evidence with the offending code snippet, and the proposed fix template. No external assets, no network required — works offline.

**To view the report:** it usually opens automatically when the command finishes. If it doesn't, open it manually:

```bash
# macOS
open .agentic-security/findings.html

# Linux
xdg-open .agentic-security/findings.html

# Windows
start .agentic-security/findings.html
```

---

#### `/fix-all` — patch findings in batch

Pick a severity tier; `/fix-all` dispatches the security-fixer agent on every finding at or above it. Tiers are **cumulative** — `/fix-all --high` patches critical **+** high. Sequential, test-aware, does not auto-revert on failure.

| Flag | Fixes |
|---|---|
| `/fix-all --critical` (default) | Critical only |
| `/fix-all --high` | Critical + High |
| `/fix-all --medium` | Critical + High + Medium |
| `/fix-all --low` | Everything |

Example — fixing all critical and high-severity findings:

```
> /fix-all --high

Checking git state…   clean ✓
Fixing 104 findings (31 critical + 73 high)…

  ✓  routes/login.ts:34       SQL Injection                → parameterized query
  ✓  lib/insecurity.ts:43     MD5 Password Hashing         → bcrypt (cost 12)
  ✓  routes/b2bOrder.ts:17    RCE via vm.runInContext      → JSON.parse
  ✓  routes/order.ts:35       IDOR                         → ownership check
  …  +100 more

Applied 104 fixes, 0 skipped (tests failed), 0 regressions introduced.
```

That's the entire product. You don't need anything else to ship safer code.

---

### ⚙️ Developer Mode

> **Full taxonomy. SARIF on every scan. CI gates. Audit-grade suppressions. 35+ commands.**

For platform teams, AppSec engineers, and anyone who needs findings outside a chat window. Switch on with:

```bash
agentic-security profile set developer
```

Here's what a scan looks like in developer mode:

```
agentic-security — developer mode  ·  258 finding(s) across 412 file(s)

Severity    File:Line                CWE      CVSS  OWASP     Vuln                       Conf
──────────────────────────────────────────────────────────────────────────────────────────────
🛑 CRITICAL  routes/login.ts:34       CWE-89   9.8   A03:2021  SQL Injection              0.93
🛑 CRITICAL  lib/insecurity.ts:43     CWE-916  8.1   A02:2021  MD5 Password Hashing       0.95
🛑 CRITICAL  routes/b2bOrder.ts:17    CWE-94   9.8   A03:2021  RCE (VM Sandbox Escape)    0.91
⚠️  HIGH     api/files.ts:67          CWE-22   7.5   A01:2021  Path Traversal             0.88
…  +254 more

Critical: 31  High: 73  Medium: 149  Low: 5  Info: 0

Machine-readable output written to .agentic-security/findings.{sarif,json,csv}
```

Every finding carries CWE, CVSS, OWASP, MITRE ATT&CK technique, CAPEC pattern, exploitability score, source/sink reachability, and toxic-combinations scoring. Swap column profiles with `--columns mitre`, `capec`, or `owasp`.

#### What else you unlock

- **Real CI gates** — `agentic-security ci . --fail-on critical`. Auto-detects PR base ref, exits non-zero on policy violations. Pre-commit hook ships in the box.
- **Curated rule packs** — `--pack owasp-top-10`, `cwe-top-25`, `llm-security`, `supply-chain`. Multiple packs union their CWE sets.
- **Audit-grade suppressions** — `.agentic-security/suppressions.yml` with signer ≠ reviewer, rule-version pinning, and mandatory expiry. The kind that survives an actual security review.
- **Triage state machine** — `open → in-progress → fixed | wont-fix | false-positive`, with MTTR trend reports and opened/closed deltas.
- **Org-wide fleet scans** — parallel workers across many repos with rolled-up output. Workspace-aware (Nx, Turborepo, pnpm).
- **Custom YAML rules** — project-local regex/AST rules, severity overrides, scanner-version pins.
- **Integrations** — Slack, Discord, Jira, ServiceNow, GitHub Security tab, GitLab, Splunk, Datadog, Elastic.
- **Four compliance attestations** — NIST AI 600-1 · OWASP ASVS · PCI-DSS 4.0 · SOC 2. Each ships audit-ready CSV + JSON + Markdown evidence, control by control.
- **Posture artifacts** — SBOM (CycloneDX 1.6, SPDX 2.3), AI-BOM (CycloneDX 1.7 ML-BOM), PBOM, API inventory, attack-chain synthesis, adversarial PoC generation.

Every command, flag, and output format is in the **[Developer Guide →](docs/for-appsec-pros.md)**.

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

*Stop shipping the bugs your AI didn't catch.*
