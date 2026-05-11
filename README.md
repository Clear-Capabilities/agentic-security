# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[ClearCapabilities.Com](https://clearcapabilities.com)** · Runs inside Claude Code

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.16MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.17.1-blue)]()

---

## Your AI is fast.

It's also writing security bugs.

This morning Claude wrote your login route in 9 seconds. Beautiful code. Tests pass.

It also lets anyone in the world log in as admin with a single line of curl.

You don't know this yet. Neither does Claude.

**One command finds it.**

---

## This is `/scan-all`.

Type it. Get one answer.

```
─────────────────────────────────────────
  ✅  Safe to deploy
─────────────────────────────────────────
```

You're done. Push it.

But if you're not safe?

```
─────────────────────────────────────────
  ❌  Not safe to deploy
─────────────────────────────────────────

  1. routes/login.ts:34
     - db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
     + db.query('SELECT * FROM users WHERE email = $1', [req.body.email])

     Why: An attacker can dump your entire users table.

  Type /fix 1 to apply.
```

You type `/fix 1`. Code is patched. Run `/scan-all` again. Green.

That's the entire product.

---

## Two modes. One tool.

### 🎨 Easy Mode

For the vibecoder. The solo founder. The Cursor warrior. The "I just want to ship" generation.

```
/security-onboard      # 30 seconds, once
/scan-all              # daily, before deploy
/fix 1                 # when /scan-all has notes
```

Three commands. We thought about adding more.

We didn't.

### ⚙️ Developer Mode

For the senior engineer. The platform team. The person who actually reads SARIF.

```bash
agentic-security profile set pro
agentic-security scan . --format sarif
agentic-security ci . --fail-on critical          # one-shot CI runner
agentic-security scan --pack owasp-top-10 .       # focus on a curated CWE pack
```

Full taxonomy: CWE / CVSS / OWASP / MITRE ATT&CK. SARIF, JSON, JUnit, CSV — every scan. CI gates. Curated rule packs (`owasp-top-10`, `cwe-top-25`, `llm-security`, `supply-chain`). Pre-commit hook. Slack, Jira, GitHub Security, SIEM. Audit-grade suppressions with reviewer + expiry. Triage workflow with MTTR trends. Org-wide scans across a fleet of repos. Custom rules in YAML.

[Developer guide →](docs/for-appsec-pros.md)

---

## Why people stay

It runs **where you already are.** Inside Claude Code. No new tool to learn. No new tab to keep open. No surveys, no signups.

It runs **on your machine.** Your code never leaves it. No cloud. No phone-home.

It speaks **plain English.** Not "Reflected XSS via unsanitized template literal." Just: *"User input goes straight into your HTML response. Here's the fix."*

It **actually fixes things.** Most security tools tell you to "consider validation." This one writes the diff.

It's **fast.** First scan in under five seconds on most projects. Every save after that is instant.

---

## COVERAGE

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

---

## Install

In Claude Code:

```
/plugin install agentic-security
```

That's it. Now type `/scan-all`.

For CI, command line, or any project anywhere:

```bash
npx @clearcapabilities/agentic-security-scanner scan .
```

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

For licensing inquiries, email **[ross@clearcapabilities.com](mailto:ross@clearcapabilities.com)**.

---

## One more thing.

Every generation of software gets a new superpower.

Cloud made infrastructure instant.  
Git made collaboration instant.  
AI made coding instant.

Now security has to become instant too.

Agentic Security is what happens when security tooling starts —

Running locally.  
Explaining issues in plain English.  
Coding the patch for you.  
And disappearing into your workflow until you need it.

Remember, the best security tools don't slow developers down anymore.

They make shipping safer feel effortless.

---

**🛡 agentic-security** · built with care by **[ClearCapabilities.Com](https://clearcapabilities.com)**

*Stop shipping the bugs your AI didn't catch.*
