# agentic-security

<img src="docs/brand/patch-bug-scene.svg" align="right" width="220" alt="Patch the mascot side-eyeing a bug on a monitor — agentic-security's signature scene">

<h3>
Build faster with an<br>
Agentic Workforce.<br>
Safe, secure, and compliant<br>
is now the default.
</h3>

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
   ✓  1 CONFIRMED (PoC built by /triage --validate)

   [critical] SQL Injection                api/users.ts:42
     Could leak PII for ~5,000 users.
     Estimated cost if exploited: $125k–$1.3M
     Fix:  use parameterized query — db.query('SELECT * FROM users WHERE id = ?', [id])

   [critical] Hardcoded Stripe live key    src/lib/billing.ts:7
     Could enable fraudulent charges against your account.
     Estimated cost if exploited: $50k–$500k (chargebacks + Stripe fees)
     Fix:  rotate via /agentic-security:fix --rotate-secret --auto, then move to env var

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

In **Claude Code** (recommended) — two steps:

```
/plugin marketplace add https://github.com/Clear-Capabilities/agentic-security
/plugin install agentic-security@clearcapabilities
```

The first command registers the marketplace as a source; the second actually installs the plugin. Then restart Claude Code (or `/reload-plugins`). To update later: `/plugin marketplace update clearcapabilities` followed by `/plugin install agentic-security@clearcapabilities`.

In your **terminal** (no Claude Code required):

```bash
npx @clear-capabilities/agentic-security-scanner secure .
```

**Want a shareable report?** Any scan can export a self-contained, browser-viewable HTML page (severity charts, STRIDE breakdown, filterable findings) — or JSON / Markdown / SARIF:

```bash
npx @clear-capabilities/agentic-security-scanner scan . --format html --output report.html
# open report.html   (formats: html · json · md · sarif · csv)
```

Also works with Codex, Cursor, and Gemini CLI — [harness setup](docs/HARNESS_COMPATIBILITY.md).

---

## Ten commands

![agentic-security demo](docs/brand/demo.gif)

**`/agentic-security:secure`** — Router. Picks the single best next action from project state. Also: `--tour`, `--help`, `--daily`.

**`/agentic-security:find-and-fix-everything`** — One-shot scan + fix every severity in one command. The vibecoder "just make it safe" path.

**`/agentic-security:scan`** — Run the scanner. Modes: full / diff / watch / baseline / archaeology / scanner-meta.

**`/agentic-security:triage`** — Decide on findings. Modes: id / show / explain / validate / tournament / red-team / exploit / query.

**`/agentic-security:fix`** — Remediation. Modes: id / all / pr / sca / compliance / rotate-secret / vault / harden / trim / generate.

**`/agentic-security:posture`** — Posture + reporting. Modes: status / report-card / harness / trend / threat / playbook / mgmt / cache.

**`/agentic-security:compliance`** — Compliance + auditor flows. Modes: report / walkthrough / attestation / audit / pr.

**`/agentic-security:supply`** — Supply chain. Modes: check / sbom / cve-alerts / license.

**`/agentic-security:setup`** — Workflow installers + guards. Modes: hooks / ci / bodyguard / destructive-guard / model-optimizer.

**`/agentic-security:labs`** — Experimental + AI-driven. Modes: claude-audit / model-rescan / synthesize-rule / cross-repo / risk-dollars / time-to-fix / llm.

Every legacy capability is reachable as a mode of one of these dispatchers — run `/secure --help` for the full surface.

---

## Compliance frameworks

`/compliance --report <framework>` generates an auditor-ready attestation that scans your project against:

| Framework | `<framework>` | Coverage map |
|---|---|---|
| NIST AI 600-1 (2024) — Generative AI Profile | `nist` | [coverage](docs/compliance/nist-ai-600-1-coverage.md) |
| OWASP ASVS 4.0.3 — Application Security Verification Standard | `asvs` | [coverage](docs/compliance/owasp-asvs-coverage.md) |
| OWASP LLM Top 10 (2025) | `llm` | [coverage](docs/compliance/owasp-llm-top10-coverage.md) |
| EU AI Act | `eu-ai-act` | [`scripts/eu-ai-act/`](scripts/eu-ai-act/) |

`/compliance --walkthrough <framework>` adds step-by-step auditor narratives with per-control evidence mapping for `nist-csf-2`, `nist-ai-600-1`, `owasp-asvs-5`, `owasp-llm-top-10`, `eu-ai-act`, `gdpr`, `hipaa-security-rule`, and `ccpa` — or bring your own controls at `.agentic-security/compliance/<id>/controls.json`.

---

## What makes it different

- **Plain-English findings with dollar-cost estimates.** Best/likely/worst-case exposure, grounded in IBM Cost of a Data Breach 2024 and 25+ public settlement records. Not CVE numbers.
- **Intercepts insecure AI-generated code before it hits disk.** The `/setup --bodyguard` hook blocks SQLi via concat, hardcoded API keys, `eval` on user input, and more — in real time, as your AI writes.
- **12-pillar scan in one command.** SAST, SCA, secrets, IaC, LLM safety, MCP agent-tool audit, auth/authZ, pipeline integrity, containers, deploy config, supply chain, and trend tracking.
- **Function-level reachability across every dependency.** OSV ecosystem_specific parsing, GHSA fix-commit analysis, vendored code fingerprinting, Java IR call-graph matching, and LLM-assisted function extraction — not just a hardcoded hints list.
- **SCA reachability tiers.** Every dependency classified as `function-reachable`, `import-reachable`, `build-only`, `manifest-only`, or `transitive-only` — so you fix what matters.
- **CISA KEV + EPSS prioritization.** Separates "this could theoretically be bad" from "people are running scripts that exploit this today."
- **SARIF codeFlows for taint traces.** Multi-step source-to-sink paths rendered natively in GitHub Code Scanning, DefectDojo, and VS Code SARIF Viewer.
- **One-command fix with preview.** Every patch previewed before write, backed up, revertible. The fixer reads your stack so patches match your code style.
- **Auto-baseline for legacy codebases.** `--set-baseline` snapshots existing findings; `--since-baseline` shows only what's new. Day-one usable on any project.

Deep engine details — [architecture](docs/ARCHITECTURE.md).

---

## Stop overpaying for tokens

Your agentic workforce runs on tokens. agentic-security watches each prompt and tells you when a cheaper model or lower reasoning depth would answer it just as well — and it's the only tool that does this **cache-aware**, accounting for the prompt cache a model switch would throw away.

```
💡 This simple one-off sits on a deep warm cache (~250k tokens). Switching your
   main model would discard it — instead run this as a Haiku 4.5 subagent: it
   answers in its own context (~84% cheaper) and leaves your Opus 4.8 cache intact.
```

- **Per-prompt model + depth advice.** Suggests the cheapest model + effort that still does the job — you tap `/model` + `/effort`. Zero added tokens; the analysis is purely local.
- **Cache-aware routing.** Prefers a cache-preserving effort drop over a model switch, shows a switch's break-even ("worth it past ~N more turns"), and offloads cheap one-offs to a Haiku subagent so your warm cache survives.
- **Measured, not guessed.** `/posture --cache` reports what prompt caching actually **saved** and **wasted** this session — real dollars parsed from your transcript, no estimates.
- **Cache bodyguard.** Warns *before* an edit to `CLAUDE.md` or `.claude/settings` silently invalidates your cache and forces a costly cold re-read.
- **Live cost HUD + budget.** A statusline one-liner (`$ spent · % cached · $/turn`), and an optional session budget that auto-tightens spend as you approach it.

- **Multi-provider — lints your *own* AI-app code.** Scanning a project that calls Anthropic, OpenAI, Gemini, or xAI? It flags prompt-cache killers (a timestamp/UUID baked into a prompt prefix) and over-provisioned calls (a flagship model at high reasoning depth), and recommends a cheaper model + depth **in that provider's framework** — e.g. an OpenAI app gets "gpt-5.4 at `reasoning_effort: low`."

Opt-in with `/setup --model-optimizer`. Details — [cache economics](docs/MODEL_COST_OPTIMIZATION.md) · [v2 roadmap](docs/CACHE_ECONOMICS_V2_PRD.md).

---

## Language coverage

Eight first-class languages, with cross-language detectors for the OWASP-relevant injection and crypto-misuse classes.

| Language | Vuln-class coverage |
|----------|---------------------|
| JavaScript / TypeScript | full (flow engine + structural) |
| Python | full (flow engine + structural) |
| Java | full |
| Kotlin | full |
| Go | full |
| Ruby | full |
| PHP | full |
| C# | full |

Detected across these languages: SQL injection, command injection, path traversal, LDAP injection, XPath injection, reflected XSS, SSRF, XXE, code injection (eval / SpEL / Groovy / Roslyn / template), insecure deserialization, hardcoded secrets, weak password hashing, weak ciphers (DES/RC4/Blowfish/ECB), static/zero IV, insecure randomness, CSRF, open redirect, HTTP response splitting, and ReDoS — plus the JS/Python-specific classes (prototype pollution, mass assignment) and the LLM/agent-tool surface.

The detectors are precision-first: parameterized queries, escaped output, allow-list guards, CSPRNG-derived IVs, framework CSRF middleware, and token-auth schemes are recognized and **not** flagged.

---

## What this is NOT

- **Not a SaaS dashboard.** It's a CLI + Claude Code plugin.
- **Not a replacement for a pentester.** Static analysis catches patterns; humans catch business-logic flaws. The `security-logic-reviewer` subagent and `/triage --validate` close part of the gap, not all of it.
- **Not magic.** It can miss novel vulnerabilities, especially anything that requires understanding intent.
- **Not free for resale.** PolyForm Internal Use license. Use it to make your own code safe and secure. Don't repackage it as a competing scanner.

---

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Bundle](https://img.shields.io/badge/bundle-2.30MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.125.0-blue)]()
[![agentic-security](https://img.shields.io/badge/agentic--security-passing-brightgreen)]()

## License

Full legal terms in [LICENSE](./LICENSE).

---

> Built with care by **[Clear Capabilities](https://www.clearcapabilities.com/)**. Found a bug, have a feature idea, want to talk? Please create a GitHub issue.
