# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[ClearCapabilities.Com](https://clearcapabilities.com)** · Runs inside Claude Code

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.16MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.25.0-blue)]()

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

> **Every flag, every format, every framework. There's a lot more under the hood.**

Beyond the three easy-mode commands, agentic-security ships a full command surface for platform teams, AppSec engineers, and anyone who wants to go deeper:

```
/agentic-security:scan                  Run the scanner. Default (--all) gives a one-screen verdict.
                                        Focused modes: --sca, --secrets, --authz, --mcp,
                                        --pipeline, --logic, --diff.

/agentic-security:show-findings         Triage FPs then view results. Default (--all) opens an
                                        interactive HTML report. Use --kev for weaponized CVEs,
                                        --chains for exploit chains, or --threat-model [--stride|--llm].

/agentic-security:fix                   Remediate findings. Use --one <id> to patch a single finding,
                                        --all to batch-fix by severity, or --pr to bundle fixes
                                        into a pull request.

/agentic-security:exploit-poc          Generate a working exploit payload + regression test for one
                                        finding (or flag PROBABLE_FP if no payload can be constructed).

/agentic-security:posture-management      Posture management — SBOM, AI-BOM, API inventory, license
                                        policy, drift analysis, and SLA tracking. Use --sbom, --aibom,
                                        --api, --license, --drift, or --mttr.

/agentic-security:compliance-report  Auditor-ready attestation for NIST AI 600-1, OWASP ASVS,
                                             PCI-DSS 4.0, or SOC 2.

/agentic-security:explain      Explain a finding in plain English — what it means, how an
                                        attacker exploits it, the worst case, and how to fix it.

/agentic-security:launch-check Pre-deploy checklist of the 10 things beginners typically
                                        miss before going live.

/agentic-security:report-card        Single letter-grade snapshot (A–F) of your project's security
                                        posture, with one concrete next action.

/agentic-security:social-media        Generate copy-paste-ready posts (Twitter/X, LinkedIn,
                                        Discord/Slack) about your security progress.

/agentic-security:status       One-screen plugin & project health snapshot — version, last
                                        scan time, finding counts, cache size, hook activation.

/agentic-security:help                  Full command catalog with one-line descriptions.
```

For the complete reference — CI integration, SARIF output, audit-grade suppressions, custom rules, org-wide fleet scans, and every flag — read the **[Developer Guide →](https://github.com/clearcapabilities/agentic-security/blob/main/docs/developer-documentation-guide.md)**.

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

*Stop shipping the bugs your AI didn't catch.*
