# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[Clear Capabilities](https://www.clearcapabilities.com/products/agentic-security)**

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![F1](https://img.shields.io/badge/F1%20benchmark-100%25-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.30MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.34.6-blue)]()

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

That's it. Type `/agentic-security:scan --all` to confirm it's working.

For **CI, terminal, or any project anywhere** (no Claude Code required):

```bash
npx @clearcapabilities/agentic-security-scanner scan .
```

The scanner runs entirely on your machine. Nothing leaves your laptop. No signups, no API keys, no cloud.

---

## Two modes. One tool.

Both modes run the same engine. They differ in how much you see and how much you can configure.

### 🎨 Easy Mode

Four commands. The whole product. The default for everyone.

---

#### `/agentic-security:scan --all` runs 12 different scans to secure your code:

```
       Pillar         What we scan
       ─────────────────────────────────────────────────────────────
       SAST           Taint analysis (regex + AST for JS/TS), Java
                      rule pack, Python helpers. 25+ language-specific
                      modules covering SQL injection, XSS, command
                      injection, XXE, JNDI, deserialization, zip-slip,
                      JWT flaws, auth misconfig, Supabase RLS, rate-
                      limit gaps, env hygiene, webhook verification,
                      React client-side XSS, and LLM prompt firewall.
       SCA            OSV + CISA KEV + EPSS, function-level
                      reachability, dep confusion, typosquat,
                      deprecated packages (npm, PyPI, Packagist,
                      crates.io, RubyGems, pub.dev).
       Secrets        60+ credential patterns, high-entropy heuristic,
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
                      session fixation, OAuth/PKCE, multi-tenant scope.
       Container      Base-image EOL, exposed ports, runtime mode.
       Deploy         Vercel, Railway, Fly.io, Netlify, Cloudflare —
                      security headers, HTTPS, preview deployments.
       Stack          Opinionated security playbook for Next.js,
                      Supabase, Stripe, Clerk, Prisma, OpenAI, and 10+
                      more frameworks — specific to what you actually use.
       Trend          Rolling scan history — fixed vs. introduced delta
                      across every commit, sparkline view.
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
     /agentic-security:show-findings --all  see every finding in HTML
     /agentic-security:fix --one <id>       fix exactly one
```

---

#### `/agentic-security:show-findings --all`

Writes a self-contained HTML report to `reports/findings-<timestamp>.html` and opens it in your default browser. Severity charts, filterable findings list, per-finding evidence with offending code snippet, and the proposed fix template. No external assets, no network required — works offline.

---

#### `/agentic-security:fix --all`

Pick a severity tier; `/fix --all` dispatches the security-fixer agent on every finding at or above it. Tiers are **cumulative** — `--high` patches critical + high. Sequential, test-aware, codebase-context-aware (detects your auth library, ORM, and framework before writing the fix).

| Flag | Fixes |
|---|---|
| `--critical` (default) | Critical only |
| `--high` | Critical + High |
| `--medium` | Critical + High + Medium |
| `--low` | Everything |

---

#### `/agentic-security:find-and-fix-everything`

Runs `/scan --all` then immediately `/fix --all --low` — scanning and fixing every finding at every severity tier in one shot.

---

### ⚙️ Developer Mode

> **There's a lot more under the hood.**

#### Core scanning & reporting

| Command | Description |
|---|---|
| `/agentic-security:scan` | Run the scanner. Default `--all` gives a one-screen verdict. Focused modes: `--sca`, `--secrets`, `--authz`, `--mcp`, `--pipeline`, `--logic`, `--diff`. |
| `/agentic-security:show-findings` | Triage FPs then view results. Default `--all` opens an interactive HTML report. Use `--kev` for weaponized CVEs, `--chains` for attack chains, or `--threat-model [--stride\|--llm]`. |
| `/agentic-security:fix` | Remediate findings. `--one <id>` patches a single finding (context-aware), `--all` batch-fixes by severity, `--pr` bundles fixes into a pull request. |
| `/agentic-security:validate-findings` | Build a PoC + regression test that proves a vulnerability before fixing it. Emits `PROBABLE_FP` when no PoC can be constructed. |
| `/agentic-security:explain` | Explain a finding in plain English — what it means, how an attacker abuses it, worst case, and how to fix it. |

#### Vibe-coder essentials (new in 0.32.0)

| Command | Description |
|---|---|
| `/agentic-security:stack-playbook` | Security checklist tailored to your exact stack — Next.js, Supabase, Stripe, Clerk, OpenAI, Prisma, and 10+ more. Copy-paste ready. |
| `/agentic-security:harden` | One-command hardening: adds security headers to `next.config.js`, fixes `.gitignore`, creates `SECURITY.md`, adds `npm audit` script. Safe to run on any project. |
| `/agentic-security:db-audit` | Supabase RLS audit — service-role key exposure, `auth.admin` client-side, `bypassRowLevelSecurity()`, SQL tables without RLS. |
| `/agentic-security:auth-audit` | Auth provider deep-audit — Clerk public routes, `trustHost`, `allowDangerousEmailAccountLinking`, missing `NEXTAUTH_SECRET`, CSRF disabled. |
| `/agentic-security:rate-limit-check` | Find auth, AI, payment, and contact endpoints without rate limiting. Includes copy-paste `@upstash/ratelimit` setup. |
| `/agentic-security:webhook-audit` | Webhook handlers missing signature verification — Stripe, GitHub, Clerk, Svix, Resend, Twilio. |
| `/agentic-security:env-check` | Env hygiene: `NEXT_PUBLIC_` secret leaks, `.env.example` with real values, hardcoded fallbacks, `.env` not in `.gitignore`. |
| `/agentic-security:rotate-secret` | Detect which provider owns a leaked key, find every file referencing it, get platform-specific rotation steps. |
| `/agentic-security:deploy-check` | Platform-specific infra audit: Vercel headers, Railway health check, Fly.io HTTPS, Netlify headers, Cloudflare compat date. |
| `/agentic-security:attack-surface` | Plain-English threat narrative — 3–5 realistic attack scenarios, not CVE IDs. Written for builders, not security engineers. |
| `/agentic-security:prompt-firewall` | LLM app security audit: user input in system prompts, missing `max_tokens`, LLM output→SQL (second-order injection), no output schema validation. |
| `/agentic-security:csp-cors` | Generate exact Content-Security-Policy and CORS config for your stack — reads your actual dependencies and domains. |
| `/agentic-security:security-tests` | Generate failing security regression tests (Jest/Vitest/pytest) and passing fix-validation tests for each finding. |
| `/agentic-security:ci-gate` | Generate `.github/workflows/security.yml` — scans every PR, uploads SARIF, posts PR comments, fails build on critical/high. |
| `/agentic-security:cve-alerts` | Set up daily CVE monitoring + Slack/Discord alerts when new vulnerabilities drop for your dependencies. |
| `/agentic-security:vault-wizard` | Guided migration from `.env` files to Doppler, Infisical, or platform-native secrets management. |
| `/agentic-security:security-trend` | Rolling trend line: findings fixed vs. introduced across scans, sparkline chart, regression detection. |
| `/agentic-security:security-badge` | Shields.io badge for your README and an investor-ready security posture paragraph for due-diligence docs. |

#### Real-time bodyguards (new in 0.34.0)

Active protection at the moment code is written or commands are run. Designed for builders shipping with AI assistants. Configure once; runs forever.

| Command | Description |
|---|---|
| `/agentic-security:ai-bodyguard` | PreToolUse hook that intercepts insecure AI-generated code BEFORE it hits disk. Catches SQLi-via-concatenation, `NEXT_PUBLIC_` secrets, hardcoded API keys, `eval` on user input, `jwt.decode()` without verify, Supabase `service_role` on the client, LLM calls without `max_tokens`, CORS `*` + credentials. Modes: `off` / `warn` / `block`. |
| `/agentic-security:destructive-guard` | PreToolUse hook on `Bash` that blocks foot-guns: `rm -rf` on parent dirs, `DROP TABLE`, `supabase db reset`, `git push --force` to main, `curl \| bash`, `aws s3 rm --recursive`, `docker system prune -a`, `chmod 777`, and 5+ more. Each refusal includes a plain-English why + the safer alternative. |
| `/agentic-security:predeploy-gate` | Blocks production deploys (`vercel --prod`, `fly deploy`, `wrangler publish`, `netlify deploy --prod`, `railway up`) when critical findings or KEV-listed dependencies are present. Two layers — Claude-Code Bash hook AND a sourced shell wrapper for your terminal. |

#### Active rotation & cost control (new in 0.34.0)

| Command | Description |
|---|---|
| `/agentic-security:rotate-key-auto` | ACTIVELY rotates a leaked credential end-to-end. Detects provider (OpenAI / Anthropic / Stripe / AWS / GitHub / Supabase service-role / Slack / Google), prints exact revoke commands, scrubs the value across every file (with backups), and pushes the replacement to Vercel/Fly/Railway/Cloudflare/Netlify env vars via their CLI. Goes beyond `/rotate-secret` which guides — this one does the work. |
| `/agentic-security:llm-cost-ceiling` | Audits every Anthropic / OpenAI call site in your code. Auto-patches missing `max_tokens`. Generates rate-limit middleware tailored to your framework (Next.js App Router / Express / FastAPI). Generates a daily $-spend tracker that throws when the cap is hit. Protection against the #1 LLM-app failure mode: prompt-injection on an uncapped endpoint draining thousands overnight. |

#### Translate the jargon (new in 0.34.0)

| Command | Description |
|---|---|
| `/agentic-security:risk-in-dollars` | Translates each finding's CWE into best/likely/worst-case $ exposure sourced from public incident settlements. Cites the specific regulatory framework whose fines apply (GDPR Art. 33, CCPA, PCI-DSS, HIPAA, NIST AI 600-1). Sort by worst-case to prioritize what to fix first. |
| `/agentic-security:story-explain` | Narrative-form explanation: "Meet Mallory. She visits your `/api/users` page, changes `?id=1` to `?id=2`, and now she's reading your other users' data." 4-act story with named attacker, minute-by-minute timeline, concrete payloads, and the literal fix line. |
| `/agentic-security:daily-checkin` | Daily security digest posted to Slack / Discord / a generic webhook. Shows what changed since yesterday — new findings, resolved findings, KEV alerts — not just totals. Async security awareness without opening a dashboard. |

#### Customer-facing artifacts (new in 0.34.0)

When an enterprise prospect asks "are you secure?", these are what you hand them.

| Command | Description |
|---|---|
| `/agentic-security:security-onepager` | Generates a customer-facing "How we keep your data safe" markdown from your REAL scan posture and detected stack. Live traffic-light state, clean-scan streak, alignment with OWASP ASVS / LLM Top 10 / NIST AI 600-1 / PCI-DSS / SOC 2. PDF-ready via `pandoc`. |
| `/agentic-security:privacy-docs` | Detects every third-party data processor (Stripe, Supabase, Clerk, Sentry, PostHog, GA4, OpenAI, Anthropic, Resend, ...) and generates a tailored `PRIVACY.md` naming each with the exact data they receive + their DPA + sub-processor URLs. Plus optional React cookie-consent component matched to detected analytics providers. Jurisdiction-aware (EU / US-CA / UK / OTHER). |
| `/agentic-security:trust-page` | Writes `/.well-known/security.txt` (RFC 9116, 1-year expiry) and a `/security` page that displays your live posture. Framework-aware: Next.js App Router, Pages Router, or vanilla HTML. Buyers and infosec teams look for both — most vibe-coded apps have neither. |

#### Resilience & onboarding (new in 0.34.0)

| Command | Description |
|---|---|
| `/agentic-security:disaster-playbook` | Generates `DISASTER.md` — a stack-specific incident response runbook with the EXACT commands and URLs you'll need if you get hacked tomorrow. Supabase RLS reset queries, Stripe key roll commands, Vercel rollback steps, AWS IAM-key disable, npm supply-chain triage. Bookmark it BEFORE the incident. |
| `/agentic-security:tutorial` | First-run walkthrough that picks ONE real finding from your project, explains it in plain English, walks you through fixing it with consent at every step, then verifies the fix actually worked. The antidote to "I just installed this and don't know what to do." |

#### Dependency & supply chain

| Command | Description |
|---|---|
| `/agentic-security:trim-dependencies` | Find and remove packages installed but never imported — reduces attack surface and bloat. |
| `/agentic-security:dep-freshness` | Score how stale your direct dependencies are across all ecosystems. |
| `/agentic-security:dep-pinning` | Audit manifests for loose version ranges that allow silent supply-chain injection. |
| `/agentic-security:dep-alternatives` | Find lighter-weight, more actively maintained alternatives to heavy or high-risk dependencies. |
| `/agentic-security:install-script-audit` | Audit every npm package for postinstall/preinstall scripts — the primary supply-chain attack vector. |
| `/agentic-security:vendor-audit` | Find copy-pasted third-party code vendored directly into the repo — invisible to dependency scanners. |

#### Posture & compliance

| Command | Description |
|---|---|
| `/agentic-security:posture-management` | SBOM, AI-BOM, API inventory, license policy, drift analysis, and SLA tracking. |
| `/agentic-security:compliance-report` | Auditor-ready attestation for NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2, or OWASP LLM Top 10 (2025). |
| `/agentic-security:launch-check` | Pre-deploy checklist of the 10 things beginners typically miss before going live. |
| `/agentic-security:report-card` | Single letter-grade (A–F) snapshot with one concrete next action. |
| `/agentic-security:status` | One-screen plugin & project health snapshot — version, last scan time, finding counts, cache size, hook activation. |
| `/agentic-security:social-media` | Generate copy-paste-ready posts (Twitter/X, LinkedIn, Discord/Slack) about your security progress. |
| `/agentic-security:help` | Full command catalog with one-line descriptions and example invocations. |

To learn more read the **[Developer Documentation](https://github.com/clearcapabilities/agentic-security/blob/main/docs/developer-documentation-guide.md)**.

---

## F1 benchmark

The scanner is evaluated against the OWASP Benchmark (2,740 Java test cases), 33 real-world vulnerable apps (NodeGoat, Juice Shop, DVWA, and more), and an adversarial LLM/AI suite. Every rule ships with a `vulnerable/` + `clean/` fixture pair.

### Two F1 numbers — both honest, both reported

| Scoring mode | What it measures | Score |
|---|---|---|
| **Wildcard-relaxed** (default) | "Does the scanner find at least one finding in each vulnerability family this app contains?" — i.e. family-level coverage. This is the mode most published security tool benchmarks use. | **100% on 33/33 benchmarks** |
| **Strict line-level** (`--no-wildcards`) | "Does each emitted finding land on the exact file:line the upstream ground truth labels?" — a much harder bar. | **100% on 30/33** benchmarks after the 0.34.5 curation. **80%** on OWASP Benchmark (engine-bound on Java flow patterns). **25.6%** on SARD Juliet Java (engine recall gap). **n/a** on juliet-c-cpp (no C/C++ GT builder yet). |

Why the gap on the remaining 3? OWASP Benchmark uses `real=true / real=false` labels that hinge on constant-folded if-branches and inner-class flow that regex+AST engines can't reliably distinguish — the planned fix is [tree-sitter Java AST](docs/PRD-owasp-benchmark-strict-100.md) (Tier 2). SARD Juliet has 13k+ expected entries and the engine emits 4.8k — a recall problem, not precision. juliet-c-cpp needs a `buildJulietCppExpected`-style GT builder, mirroring what already exists for Java.

Reproduce either number:

```bash
cd scanner
npm run bench:realworld                           # wildcard-relaxed (default)
node test/benchmark/realworld/bench-realworld.js --all --no-wildcards   # strict
```

Full strict-baseline breakdown per app, plus the roadmap to raise each one, is documented in [`scanner/test/benchmark/STRICT-F1-BASELINE.md`](scanner/test/benchmark/STRICT-F1-BASELINE.md).

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.
