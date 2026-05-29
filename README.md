# agentic-security

<img src="docs/brand/patch-bug-scene.svg" align="right" width="220" alt="Patch the mascot side-eyeing a bug on a monitor — agentic-security's signature scene">

### Build faster with an Agentic Workforce. Continuously prove your security controls are actually working.

> Built by **[Clear Capabilities](https://www.clearcapabilities.com/)**.

---

## What you get

<img src="docs/brand/patch-alert.svg" align="right" width="120" alt="Patch · ALERT — finding detected">

```
─────────────────────────────────────────────────────────────────
  ❌  Not safe to deploy  ·  api-billing
─────────────────────────────────────────────────────────────────
   3 critical · 8 high · 22 medium · 41 advisory
   🔥 2 actively exploited in the wild (CISA KEV)
   ✓  1 CONFIRMED (PoC built by /validate-findings)

   [critical] SQL Injection                api/users.ts:42
     Could leak PII for ~5,000 users.
     Estimated cost if exploited: $125k–$1.3M
     Fix:  use parameterized query — db.query('SELECT * FROM users WHERE id = ?', [id])

   [critical] Hardcoded Stripe live key    src/lib/billing.ts:7
     Could enable fraudulent charges against your account.
     Estimated cost if exploited: $50k–$500k (chargebacks + Stripe fees)
     Fix:  rotate via /agentic-security:rotate-secret --auto, then move to env var

   [critical] Missing webhook signature    api/stripe-webhook.ts:12
     Anyone can POST a fake "payment.succeeded" and unlock paid features.
     Estimated cost if exploited: cost of a free subscription × every attacker
     Fix:  stripe.webhooks.constructEvent(rawBody, signature, endpointSecret)

   How many do you want to fix?
     1. Critical only           (3 fixes)
     2. Critical + High         (11 fixes)
     3. Critical + High + Medium (33 fixes)
─────────────────────────────────────────────────────────────────
```

No CVE jargon. The stakes, the cost, the fix.

---

## Install

In **Claude Code** (recommended):

```
/plugin marketplace add https://github.com/Clear-Capabilities/agentic-security
```

In your **terminal** (no Claude Code required):

```bash
npx @clear-capabilities/agentic-security-scanner secure .
```

Also works with Codex, Cursor, and Gemini CLI — [harness setup](docs/HARNESS_COMPATIBILITY.md).

---

## Five commands to know

![agentic-security demo](docs/brand/demo.gif)

**`/agentic-security:secure`** — Don't know what to do? It tells you the single best next step.

```
🛡  agentic-security · next step

  Action:  fix-critical
  Why:     2 critical finding(s) open. Preview each fix, then --apply.
  Run:     agentic-security fix --finding <id> --preview
```

**`/agentic-security:find-and-fix-everything`** — Scan + fix everything in one shot. The security-fixer agent reads your auth library, ORM, and framework before writing each fix, so the patches look like the rest of your code.

**`/agentic-security:scan --all`** — Full 12-pillar sweep: SAST, SCA, secrets, IaC, LLM safety, auth, MCP, pipeline, containers, deploy, supply chain, and trends.

**`/agentic-security:compliance-report`** — Auditor-ready compliance attestation against NIST AI 600-1, OWASP ASVS, or OWASP LLM Top 10 (2025). Pass the framework name to scope it: `/compliance-report nist`, `/compliance-report asvs`, or `/compliance-report llm`.

**`/agentic-security:compliance-fix`** — Routes every Not-Compliant control from your compliance report to the command that closes it, deduped and ordered. Flags controls that require manual or process work so you know what to automate and what to delegate.

38 commands total — [full catalog](commands/help.md).

---

## What makes it different

- **Plain-English findings with dollar-cost estimates.** Best/likely/worst-case exposure, grounded in IBM Cost of a Data Breach 2024 and 25+ public settlement records. Not CVE numbers.
- **Intercepts insecure AI-generated code before it hits disk.** The `/ai-bodyguard` hook blocks SQLi via concat, hardcoded API keys, `eval` on user input, and more — in real time, as your AI writes.
- **12-pillar scan in one command.** SAST, SCA, secrets, IaC, LLM safety, MCP agent-tool audit, auth/authZ, pipeline integrity, containers, deploy config, supply chain, and trend tracking.
- **Function-level reachability across every dependency.** OSV ecosystem_specific parsing, GHSA fix-commit analysis, vendored code fingerprinting, Java IR call-graph matching, and LLM-assisted function extraction — not just a hardcoded hints list.
- **SCA reachability tiers.** Every dependency classified as `function-reachable`, `import-reachable`, `build-only`, `manifest-only`, or `transitive-only` — so you fix what matters.
- **CISA KEV + EPSS prioritization.** Separates "this could theoretically be bad" from "people are running scripts that exploit this today."
- **SARIF codeFlows for taint traces.** Multi-step source-to-sink paths rendered natively in GitHub Code Scanning, DefectDojo, and VS Code SARIF Viewer.
- **One-command fix with preview.** Every patch previewed before write, backed up, revertible. The fixer reads your stack so patches match your code style.
- **Auto-baseline for legacy codebases.** `--set-baseline` snapshots existing findings; `--since-baseline` shows only what's new. Day-one usable on any project.

Deep engine details — [architecture](docs/ARCHITECTURE.md).

---

## What this is NOT

- **Not a SaaS dashboard.** It's a CLI + Claude Code plugin.
- **Not a replacement for a pentester.** Static analysis catches patterns; humans catch business-logic flaws. The `security-logic-reviewer` subagent and `/validate-findings` close part of the gap, not all of it.
- **Not magic.** It can miss novel vulnerabilities, especially anything that requires understanding intent.
- **Not free for resale.** PolyForm Internal Use license. Use it to make your own code safe and secure. Don't repackage it as a competing scanner.

---

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Bundle](https://img.shields.io/badge/bundle-2.30MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.82.0-blue)]()
[![agentic-security](https://img.shields.io/badge/agentic--security-passing-brightgreen)]()

## License

Full legal terms in [LICENSE](./LICENSE).

---

> Built with care by **[Clear Capabilities](https://www.clearcapabilities.com/)**. Found a bug, have a feature idea, want to talk? Please create a GitHub issue.
