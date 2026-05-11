# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[ClearCapabilities.Com](https://clearcapabilities.com)** · Runs inside Claude Code

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.16MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.22.0-blue)]()

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
/plugin marketplace add https://github.com/clearcapabilities/agentic-security
```

That's it. Type `/scan --all` to confirm it's working.

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

#### `/scan --all` — daily, before deploy

**What `/scan --all` scans every run — nine pillars, no configuration required:**

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
     /show-findings --all  see every finding in HTML
     /fix --one <id>       fix exactly one
```

The scanner asks which tier you want to fix; reply with the number and `/fix --all` runs the matching `--severity` automatically.

---

#### `/show-findings --all` — interactive HTML report

Writes a self-contained HTML report to `reports/findings-<timestamp>.html` and opens it in your default browser. The report has severity charts, a filterable findings list, per-finding evidence with the offending code snippet, and the proposed fix template. No external assets, no network required — works offline.

**To view the report:** it usually opens automatically when the command finishes. If it doesn't, open it manually:

```bash
# macOS
open reports/findings-<timestamp>.html

# Linux
xdg-open reports/findings-<timestamp>.html

# Windows
start reports/findings-<timestamp>.html
```

---

#### `/fix --all` — patch findings in batch

Pick a severity tier; `/fix --all` dispatches the security-fixer agent on every finding at or above it. Tiers are **cumulative** — `/fix --all --high` patches critical **+** high. Sequential, test-aware, does not auto-revert on failure.

| Flag | Fixes |
|---|---|
| `/fix --all --critical` (default) | Critical only |
| `/fix --all --high` | Critical + High |
| `/fix --all --medium` | Critical + High + Medium |
| `/fix --all --low` | Everything |

Example — fixing all critical and high-severity findings:

```
> /fix --all --high

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

> **Full taxonomy. SARIF on every scan. CI gates. Audit-grade suppressions. 13 commands, everything behind flags.**

For platform teams, AppSec engineers, and anyone who needs findings outside a chat window.

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

Every finding carries CWE, CVSS, OWASP, MITRE ATT&CK technique, CAPEC pattern, exploitability score, source/sink reachability, and toxic-combinations scoring.

#### The full command surface

**Scanning**

| Command | What it does |
|---|---|
| `/scan --all` | Full SAST + SCA + secrets sweep — one-screen verdict |
| `/scan --sca` | Dependency CVE audit only (OSV + CISA KEV + EPSS) |
| `/scan --secrets` | Credential and API key sweep (60+ patterns + entropy) |
| `/scan --authz` | Deep auth/authZ audit — JWT, OAuth2, IDOR, session fixation |
| `/scan --mcp` | Audit MCP server configs for agent-host risks |
| `/scan --pipeline` | Audit GitHub Actions; `--format pbom` for Pipeline BOM |
| `/scan --logic` | Semantic business-logic review (intent vs. implementation) |
| `/scan --diff` | Score a git diff by architectural risk (`--since <ref>`) |

**Viewing & analysis**

| Command | What it does |
|---|---|
| `/show-findings --all` | Triage FPs then open an interactive HTML report |
| `/show-findings --kev` | List only CISA KEV findings (actively weaponized CVEs) |
| `/show-findings --chains` | Synthesize multi-finding exploit chains |
| `/show-findings --threat-model` | STRIDE table; add `--llm` for OWASP LLM Top 10 map |

**Fixing**

| Command | What it does |
|---|---|
| `/fix --one <id>` | Patch a single finding via the security-fixer subagent |
| `/fix --all [--critical\|--high\|--medium\|--low]` | Batch-fix by severity tier |
| `/fix --pr [--apply]` | Bundle fixes into a feature branch + PR |

**Deep analysis**

| Command | What it does |
|---|---|
| `/security-poc <id>` | Generate a working exploit payload + regression test |
| `/security-explain <id>` | Plain-English explanation — what, how, worst case, fix |
| `/security-launch-check` | Pre-deploy 10-item checklist (the things beginners miss) |

**Posture management**

| Command | What it does |
|---|---|
| `/security-posture --sbom` | CycloneDX 1.6 or SPDX 2.3 software bill of materials |
| `/security-posture --aibom` | AI/ML Bill of Materials — models, prompts, frameworks |
| `/security-posture --api` | Full API surface map with auth status + data classifications |
| `/security-posture --license` | Enforce license allow/deny policy on all dependencies |
| `/security-posture --drift` | Diff two scan snapshots — lost auth, new findings, new deps |
| `/security-posture --mttr` | Show findings breaching per-severity SLA thresholds |

**Compliance attestation**

| Command | What it does |
|---|---|
| `/produce-compliance-report nist` | NIST AI 600-1 — 122 GenAI controls, audit-ready |
| `/produce-compliance-report asvs` | OWASP ASVS Level 1+2 |
| `/produce-compliance-report pci` | PCI-DSS 4.0 — 12 code-testable controls |
| `/produce-compliance-report soc2` | SOC 2 Common Criteria CC6–CC9 |

**Project meta**

| Command | What it does |
|---|---|
| `/security-status` | Plugin + project health snapshot |
| `/security-grade` | Letter grade (A–F) + README badge snippet |
| `/security-help` | Full command catalog |
| `/security-setup` | Install short-form shortcuts into this project |
| `/security-share` | Ready-to-post content about your security progress |

---

Every flag, output format, CI integration, suppression schema, and custom rule option is documented in the **[Developer Guide →](docs/for-appsec-pros.md)**.

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

*Stop shipping the bugs your AI didn't catch.*
