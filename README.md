# agentic-security

<img src="docs/brand/patch-bug-scene.svg" align="right" width="220" alt="Patch the mascot side-eyeing a bug on a monitor — agentic-security's signature scene">

### The Claude Code plugin that catches what your AI coding assistant misses.

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

## Three commands to know

**`/agentic-security:secure`** — Don't know what to do? It tells you the single best next step.

```
🛡  agentic-security · next step

  Action:  fix-critical
  Why:     2 critical finding(s) open. Preview each fix, then --apply.
  Run:     agentic-security fix --finding <id> --preview
```

**`/agentic-security:find-and-fix-everything`** — Scan + fix everything in one shot. The security-fixer agent reads your auth library, ORM, and framework before writing each fix, so the patches look like the rest of your code.

**`/agentic-security:scan --all`** — Full 12-pillar sweep: SAST, SCA, secrets, IaC, LLM safety, auth, MCP, pipeline, containers, deploy, supply chain, and trends.

38 commands total — [full catalog](commands/help.md).

---

## What makes it different

- **Plain-English findings with dollar-cost estimates.** Best/likely/worst-case exposure, grounded in IBM Cost of a Data Breach 2024 and 25+ public settlement records. Not CVE numbers.
- **Intercepts insecure AI-generated code before it hits disk.** The `/ai-bodyguard` hook blocks SQLi via concat, hardcoded API keys, `eval` on user input, and more — in real time, as your AI writes.
- **12-pillar scan in one command.** SAST, SCA, secrets, IaC, LLM safety, MCP agent-tool audit, auth/authZ, pipeline integrity, containers, deploy config, supply chain, and trend tracking.
- **Function-level reachability.** Drops SCA findings whose vulnerable function isn't reachable from any route — kills your noisiest bucket.
- **CISA KEV + EPSS prioritization.** Separates "this could theoretically be bad" from "people are running scripts that exploit this today."
- **One-command fix with preview.** Every patch previewed before write, backed up, revertible. The fixer reads your stack so patches match your code style.

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
[![Version](https://img.shields.io/badge/version-0.76.0-blue)]()
[![agentic-security](https://img.shields.io/badge/agentic--security-passing-brightgreen)]()

## License

Full legal terms in [LICENSE](./LICENSE).

---

> Built with care by **[Clear Capabilities](https://www.clearcapabilities.com/)**. Found a bug, have a feature idea, want to talk? Please create a GitHub issue.
