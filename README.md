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
                      sensitive disclosure, system prompt leakage.
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

  1. routes/login.ts:34
     - db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
     + db.query('SELECT * FROM users WHERE email = $1', [req.body.email])

     Why: An attacker can dump your entire users table.

  Type /show-findings to see the rest, or /fix-all to apply them.
```

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

#### `/fix-all` — patch everything at or above a severity

Sequential, test-aware. Does not auto-revert on failure — stops and tells you which fix broke what.

```
Fixing 3 findings…
  ✓ routes/login.ts:34   SQL Injection      → parameterized query
  ✓ config/db.ts:8       Hardcoded Secret   → moved to env var
  ✓ api/files.ts:67      Path Traversal     → path.join + allowlist

Applied 3 fixes, 0 skipped, 0 regressions introduced.
```

That's the entire product. You don't need anything else to ship safer code.

---

### ⚙️ Developer Mode

For the senior engineer, the platform team, the person who actually reads SARIF. Switch on with:

```bash
agentic-security profile set pro
```

Developer Mode unlocks **35+ commands** and adds: the full finding taxonomy (CWE / CVSS / OWASP / MITRE ATT&CK / CAPEC), machine-readable outputs (SARIF, JSON, JUnit, CSV) on every scan, CI gates, curated rule packs, audit-grade suppressions with reviewer + expiry, a triage workflow with MTTR trends, org-wide fleet scans, custom YAML rules, integrations with Slack / Jira / GitHub Security / SIEM, four compliance attestations (NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2), and posture artifacts (SBOM, AI-BOM, PBOM, API inventory, attack-chain synthesis, PoC generation).

Every command, flag, and output format is documented in the **[Developer Guide →](docs/for-appsec-pros.md)**.

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

*Stop shipping the bugs your AI didn't catch.*
