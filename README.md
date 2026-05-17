# agentic-security

<img src="docs/brand/patch-bug-scene.svg" align="right" width="220" alt="Patch the mascot side-eyeing a bug on a monitor — agentic-security's signature scene">

### The Claude Code plugin that catches what your AI assistant misses.

> Built by **[Clear Capabilities](https://www.clearcapabilities.com/)**.

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Bundle](https://img.shields.io/badge/bundle-2.30MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.39.2-blue)]()

---

## The 30-second pitch

This morning, your AI Coding Assistant shipped a new webpage in 9 seconds. Beautiful code. Tests pass.

It also lets anyone in the world log in as admin without even a password and violates data privacy requirements.

You don't know that yet. **Neither does your AI.**

`agentic-security` is the safety net you bolt onto your AI workflow:

- **Find it.** SAST + SCA + secrets + IaC + LLM safety, in one command.
- **Understand it.** Plain-English narrative + cost-of-exploit framing — not CVE jargon.
- **Fix it.** Preview every patch, apply with one command, undo if it breaks anything.

The only thing you give up is the false belief that your AI knew what it was doing.

---

## Install in 30 seconds

In **Claude Code** (recommended — adds 50+ slash commands):

```
/plugin marketplace add https://github.com/Clear-Capabilities/agentic-security
```

Then type `/agentic-security:secure` and let it tell you the next step.

In your **terminal**, anywhere (no Claude Code required):

```bash
npx @clearcapabilities/agentic-security-scanner secure .
```

Same engine. No accounts.

---

## What 30 seconds gets you

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
     Fix:  rotate via /agentic-security:rotate-key-auto, then move to env var

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

That's the default. No CVE numbers. No CWE jargon. The stakes, the cost, the fix.

When the verdict flips green, you get the **approve** face. When it doesn't, you get **alert**.

The mascot (Patch) reacts to whatever your scan actually said.

<p align="center">
  <img src="docs/brand/patch-alert.svg" width="120" alt="Patch · ALERT">
  &nbsp;&nbsp;&nbsp;
  <img src="docs/brand/patch-approve.svg" width="120" alt="Patch · APPROVE">
</p>

---

## Pick your path

| You are… | Start here |
|---|---|
| A builder shipping fast with AI, no security background | [→ Builder Quickstart](#-for-vibecoders--builders) |
| A security engineer or professional developer managing real risk | [→ Pro Quickstart](#-for-security-pros--engineers) |
| Curious | Run `npx @clearcapabilities/agentic-security-scanner scan .` and see what it finds |

---

## What it scans

`agentic-security` runs **12 different scans** in a single sweep:

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

---

## 🎨 For Vibecoders / Builders

You ship features fast. You don't know what a CWE is. You're scared of pushing prod because last time you accidentally deployed a `console.log` of a Stripe key. You want someone to tell you what's wrong, in English, with the fix.

### Two commands cover 90% of what you need

**`/agentic-security:secure`** — when you don't know what to do.

It looks at your project state and tells you the single best next step. No menu, no choice paralysis.

```
🛡  agentic-security · next step

  Action:  fix-critical
  Why:     2 critical finding(s) open. Preview each fix, then --apply.
  Run:     agentic-security fix --finding <id> --preview
```

**`/agentic-security:find-and-fix-everything`** — when you have 10 minutes before lunch.

Runs `/scan --all` then immediately `/fix --all --low` — finds and fixes everything at every severity in one shot. The security-fixer agent reads your auth library, ORM, and framework before writing each fix, so the patches look like the rest of your code.

### Two more vibecoder-shaped commands

**`/agentic-security:scan --uncommitted`** — "what did I just break?" Scans only the files you've changed since your last commit (staged + unstaged + untracked). No git-ref vocabulary, no full-repo wait — same one-screen verdict, scoped to your current edit.

**`/agentic-security:supply-chain-check`** — "is `npm install` safe?" One-screen roll-up across six dep audits (CVE, KEV, pinning, install scripts, vendored code, freshness). Replaces having to remember which of `/dep-pinning`, `/dep-freshness`, `/install-script-audit`, `/vendor-audit`, `/trim-dependencies`, `/dep-alternatives` to run.

### Why findings are different here

Other scanners give you `[CRITICAL] CWE-89 SQL Injection at api/users.ts:42`. You stare at it, you Google it, you give up.

We give you this:

```
[critical] SQL Injection on api/users.ts:42 (CWE-89)
   Could expose PII for ~5,000 users.
   Context: tech / GDPR + CCPA + PCI-DSS · controls: monitoring, mfa

   Estimated cost if exploited:
     Best   :   $85,000   (contained <24h, internal disclosure)
     Likely :  $620,000   (typical SMB outcome — NetDiligence median)
     Worst  :   $5.2M     (full exfil + class action + max regulatory)

   Component breakdown (likely):
     incident response   :   $50,000
     legal counsel       :  $112,500  (multi-jurisdiction)
     notification        :   $25,000  ($5/user × 5,000)
     credit monitoring   :   $37,500  (PII, 1yr, 30% take-up)
     regulatory fines    :   $87,500  (GDPR + CCPA + PCI bands)
     direct damage       :  $112,000  (per-record × industry mult)
     class action        :   $75,000  (US PII exposure)
     lost business       :  $120,000  (IBM 39% rule)

   Comparable: Equifax 2017 SQLi → $1.4B settlement ($9.50/record)
   Fix:  use a parameterized query
         db.query('SELECT * FROM users WHERE id = ?', [id])
```

**Every finding gets a 4-part framing:**

- **Stakes** — what data, how many users, what industry, what jurisdictions
- **3-point cost** — best (P5) / likely (P50) / worst (P95), not a meaningless range
- **Component breakdown** — IR + legal + notification + credit monitoring + regulatory + damage + class action + churn, each computed separately
- **Comparable incident** — a real public settlement to calibrate against (Equifax, T-Mobile, Capital One, Anthem, etc.)

**Plus two trust signals at the top of the verdict:**

- **🔥 Actively exploited (CISA KEV)** — when one of your findings touches a vulnerability that's on CISA's Known Exploited Vulnerabilities catalog. This is the difference between "this could theoretically be bad" and "people are running scripts that exploit this *today*."
- **✓ CONFIRMED** — when `/validate-findings` has built a working PoC against a finding. Filters the "scanner shouted at me" anxiety from the "this is a real bug I can prove" certainty.

The numbers are grounded in **public data sources**: IBM Cost of a Data Breach 2024 (per-industry, per-record costs), NetDiligence Cyber Claims Study 2024 (SMB distributions), HHS OCR HIPAA enforcement records, GDPR Enforcement Tracker medians, and 25+ public settlement records.

Detected automatically per project: **industry** (14 verticals with IBM 2024 cost multipliers), **jurisdiction exposure** (GDPR, CCPA, HIPAA, PCI-DSS, COPPA, FERPA, NIS2, LGPD, and 8 more), **existing controls** (WAF, MFA, SIEM, encryption, IR plan, bug-bounty, SOC2/ISO27001) that discount the estimate.

This is automatic, on by default. Disable with `--no-blast-radius` if you really want.

### The bodyguards (set once, run forever)

| Command | What it does |
|---|---|
| `/agentic-security:ai-bodyguard` | Intercepts insecure AI-generated code BEFORE it hits disk. SQLi via concat, hardcoded API keys, `eval` on user input, `jwt.decode()` without verify, Supabase service-role on the client, LLM call without `max_tokens`. Modes: `off` / `warn` / `block`. |
| `/agentic-security:destructive-guard` | Blocks foot-guns when Claude tries to run them: `rm -rf` on parent dirs, `DROP TABLE`, `git push --force` to main, `curl \| bash`, `chmod 777`, and 8+ more. Plain-English why + safer alternative on every refusal. |
| `/agentic-security:predeploy-gate` | Blocks `vercel --prod` / `fly deploy` / `wrangler publish` / `netlify deploy --prod` / `railway up` when critical findings or KEV-listed deps are present. Hooks into Claude AND your terminal. |
| `/agentic-security:cve-alerts` | Daily Slack/Discord ping when a new CVE drops for any package you use. |
| `/agentic-security:daily-checkin` | Daily security digest to Slack / Discord / generic webhook: what's new since yesterday, what got resolved, which KEV packages landed in your tree. Async awareness without opening a dashboard. |

### The full builder catalog

#### Understand what's wrong (in English)

| Command | What it does |
|---|---|
| `/agentic-security:explain` | Plain-English explanation of a finding — what it means, how an attacker abuses it, worst case, fix. |
| `/agentic-security:story-explain` | "Meet Mallory. She visits `/api/users`, changes `?id=1` to `?id=2`…" 4-act narrative with attacker, timeline, payloads, fix line. Add `--post-mortem` for past-tense + "what we shipped" block — drop straight into a Notion incident write-up or customer email. |
| `/agentic-security:attack-surface` | 3–5 realistic attack scenarios written like stories. No CVE IDs. |
| `/agentic-security:risk-in-dollars` | Each finding's best/likely/worst-case $ exposure, sourced from public incident settlements. Cites GDPR / CCPA / HIPAA / NIST AI 600-1 fines. |
| `/agentic-security:report-card` | Single A–F letter grade with one concrete next action. |
| `/agentic-security:tutorial` | First-run walkthrough: picks one real finding from your project, explains it, walks you through fixing it, verifies it. |

#### Fix it, safely

| Command | What it does |
|---|---|
| `/agentic-security:fix --all` | Pick a tier (`--critical` / `--high` / `--medium` / `--low`); the security-fixer agent patches each one, sequential, test-aware. |
| `agentic-security fix --finding <id> --preview` | Unified-diff preview before any write. `--apply` writes and backs up the original. |
| `agentic-security undo [--all\|--list]` | Atomic revert for the most recent fix. Safer than `git stash` for partial rollbacks. |
| `/agentic-security:harden` | One-command hardening: security headers, `.gitignore`, `SECURITY.md`, `npm audit` script. Idempotent. |
| `/agentic-security:rotate-secret` | Detects which provider owns a leaked key, finds every reference, gives platform-specific rotation steps. Add `--scrub-history` to also rewrite git history via `git filter-repo` / BFG. |
| `/agentic-security:rotate-key-auto` | Goes further: actually revokes, scrubs the value across files, pushes the replacement to Vercel/Fly/Railway/Cloudflare/Netlify env vars via CLI. `--scrub-history` purges git history and writes an audit log to `.agentic-security/rotation-history/`. |
| `/agentic-security:vault-wizard` | Guided migration from `.env` to Doppler, Infisical, or platform-native secrets. |

#### Hardening for the stack you actually use

| Command | What it does |
|---|---|
| `/agentic-security:stack-playbook` | Copy-paste-ready security checklist for Next.js, Supabase, Stripe, Clerk, OpenAI, Prisma, and 10+ more — specific to your combination. |
| `/agentic-security:db-audit` | Supabase RLS audit — service-role exposure, `auth.admin` client-side, missing RLS. |
| `/agentic-security:auth-audit` | Clerk / NextAuth / Auth0 / Lucia — public-route leaks, `trustHost`, missing `NEXTAUTH_SECRET`, CSRF gaps. |
| `/agentic-security:rate-limit-check` | Find auth, AI, payment, and contact endpoints missing rate limits. Copy-paste `@upstash/ratelimit` setup included. |
| `/agentic-security:webhook-audit` | Webhook handlers missing signature verification — Stripe, GitHub, Clerk, Svix, Resend, Twilio. |
| `/agentic-security:env-check` | `NEXT_PUBLIC_` leaks, `.env.example` with real values, hardcoded fallbacks, `.env` not gitignored. |
| `/agentic-security:csp-cors` | Generates exact CSP + CORS headers for your stack from your actual dependency list. |
| `/agentic-security:prompt-firewall` | LLM app gaps: user input in system prompts, missing `max_tokens`, LLM-output→SQL, no output validation. |
| `/agentic-security:llm-cost-ceiling` | Auto-patches missing `max_tokens`; generates rate-limit middleware + daily $-spend tracker that throws when capped. |
| `/agentic-security:deploy-check` | Vercel / Railway / Fly / Netlify / Cloudflare — security headers, HTTPS, preview-deployment leaks. |
| `/agentic-security:launch-check` | The 10 things builders typically miss before going live. |

#### Things to hand a customer or investor

| Command | What it does |
|---|---|
| `/agentic-security:security-badge` | Shields.io badge for your README + due-diligence-ready security posture paragraph. |
| `/agentic-security:security-onepager` | Customer-facing "How we keep your data safe" page generated from your real posture. PDF-ready. |
| `/agentic-security:privacy-docs` | Detects every third-party data processor (Stripe, Supabase, Clerk, Sentry, OpenAI, …) and generates a tailored `PRIVACY.md` + cookie-consent component. Jurisdiction-aware. |
| `/agentic-security:trust-page` | Writes `/.well-known/security.txt` (RFC 9116) + a `/security` page with your live posture. |
| `/agentic-security:disaster-playbook` | Stack-specific `DISASTER.md` with EXACT commands you'll need if you get hacked tomorrow. Bookmark BEFORE the incident. |
| `/agentic-security:social-media` | Copy-paste-ready posts (Twitter/X, LinkedIn, Discord/Slack) about your security progress. |

---

## 🔧 For Security Pros / Engineers

You triage findings for a living. Most scanners drown you in noise, are impossible to extend, and make every PR review feel like archaeology. You need depth, customization, integration, and audit-defensible output.

### What sets it apart

- **Function-level reachability.** Drops SCA findings whose vulnerable function isn't reachable from any route — kills your noisiest bucket.
- **EPSS-aware prioritization.** Every CVE finding decorated with EPSS score + percentile (FIRST.org). CVEs with percentile ≥ 95% get tagged `exploited-now` and bumped one severity tier so they sort to the top. KEV layered on top.
- **Custom rule DSL.** Semgrep-lite YAML rules in `.agentic-security/rules/*.yml`. `rule test` harness over `vulnerable/` + `clean/` fixtures.
- **Two-way ticket sync.** GitHub Issues / Linear / Jira. Idempotent state in `.agentic-security/tickets.json`.
- **Deterministic mode.** Byte-stable output + rule-pack lockfile (`rules.lock.json`) for audits and CI baselines.
- **Diff-aware.** `--pr` mode scans only changed files; auto-detects PR base from GitHub / GitLab / Buildkite / Bitbucket env vars.
- **Standards-shaped output.** SARIF, JUnit, CycloneDX (SBOM + ML-BOM + PBOM), SPDX. Drops directly into existing dashboards.

### 5-minute pro setup

```bash
# 1. Flip to pro mode (lowers confidence threshold, shows full taxonomy,
#    writes SARIF + CSV every scan, audit-grade suppression schema).
npx @clearcapabilities/agentic-security-scanner profile set pro

# 2. Lock the rule-pack version for reproducible scans across the team.
npx @clearcapabilities/agentic-security-scanner rules lock

# 3. Wire two-way ticket sync (dry-run first).
npx @clearcapabilities/agentic-security-scanner tickets sync \
   --provider github --severity high --dry-run

# 4. Add a CI gate that fails on critical findings new since the PR base.
npx @clearcapabilities/agentic-security-scanner ci . --fail-on critical

# 5. Generate compliance attestation evidence.
npx @clearcapabilities/agentic-security-scanner scan . --format aibom > ai-bom.json
```

### The full pro catalog

#### Deep scanning, validation, and reporting

| Command | What it does |
|---|---|
| `/agentic-security:scan` | Full SAST + SCA + secrets sweep. Focused modes: `--sca`, `--secrets`, `--authz`, `--mcp`, `--pipeline`, `--logic`, `--diff`. SARIF + JSON + CSV written every scan. |
| `agentic-security scan --pr [ref]` | Diff-aware: only scan files changed since the PR base. Auto-detects GitHub / GitLab / Buildkite / Bitbucket env vars. |
| `agentic-security scan --deterministic` | Reproducible mode: stable-sorts findings, zeros timing/scanId, forces `--no-network`, verifies `rules.lock.json`. Required for byte-stable CI baselines. |
| `agentic-security rules lock` | Pin the active rule-pack hash + scanner version in `.agentic-security/rules.lock.json`. |
| `/agentic-security:show-findings` | Triage UI. `--all` opens an interactive HTML report. `--kev` filters to weaponized CVEs, `--chains` shows attack chains, `--threat-model [--stride\|--llm]` builds a model. |
| `/agentic-security:validate-findings` | Build a PoC + regression test that proves a vulnerability before fixing. Emits `PROBABLE_FP` when no PoC can be constructed. |

#### Customization and rule authoring

| Command | What it does |
|---|---|
| `agentic-security rule list \| test <glob>` | Author custom YAML rules in `.agentic-security/rules/*.yml` (regex / `allOf` / `notMatch` / `window`). The `rule test` harness reports PASS / FAIL on `vulnerable/` + `clean/` fixture pairs. |
| `agentic-security rules validate` | Lint `.agentic-security/rules.yml` for schema errors, invalid regex, severity overrides, disabled rules. |
| `agentic-security packs list` | Curated rule packs: `owasp-top-10`, `cwe-top-25`, `llm-security`, `supply-chain`. Activate with `--pack`. |

#### Integrations and workflow

| Command | What it does |
|---|---|
| `agentic-security tickets sync --provider github\|linear\|jira` | Two-way sync findings ↔ tickets. Creates issues for new findings, closes tickets when findings drop. State in `.agentic-security/tickets.json`. Supports `--dry-run`. |
| `/agentic-security:fix --pr` | Bundle fixes into a feature branch and open a PR. Default dry-run; `--apply` to commit. Skips test-failing fixes; never amends or force-pushes. |
| `/agentic-security:ci-gate` | Generates `.github/workflows/security.yml` — runs on every PR, uploads SARIF to GitHub Security tab, posts PR comments, fails on critical/high. |
| `agentic-security org-scan --repos <list>` | Fleet scan across N repos with bounded concurrency. Per-repo + rolled-up JSON output. |
| `agentic-security triage list \| assign \| transition \| trend` | Per-finding state machine with MTTR + opened/closed deltas. Persists to `.agentic-security/triage.json`. |
| `/agentic-security:security-trend` | Rolling trend line: fixed vs. introduced delta across scans, sparkline, regression detection. |

#### LLM red-teaming

| Command | What it does |
|---|---|
| `/agentic-security:llm-redteam` | Send 30+ adversarial prompts (security, privacy, harmful, bias, misinformation, agentic, coding-agent) through your LLM endpoint with 7 attack-strategy mutations (DAN, base64, ROT13, role-play, authority, hypothetical, multilingual, chained-context). Static `--scan` mode catches missing defenses without making any LLM calls. |
| `/agentic-security:jailbreak-detector` | Faster focused subset — runs the canonical "make this harmful" prompt through each known jailbreak family. Reports DEFENDED / JAILBROKEN / PARTIAL per family. |
| `/agentic-security:llm-eval` | Generate a [promptfoo](https://www.promptfoo.dev)-compatible YAML eval suite committable to your repo as a CI gate. |

#### Dependency, supply chain, and posture

| Command | What it does |
|---|---|
| `/agentic-security:posture-management` | SBOM, AI-BOM, API inventory, license policy, drift, MTTR / SLA tracking. |
| `/agentic-security:compliance-report` | Auditor-ready attestation for NIST AI 600-1, OWASP ASVS, or OWASP LLM Top 10 (2025). |
| `/agentic-security:compliance-fix` | Routes every Not-Compliant control from `/compliance-report` to the agentic-security command that closes it, deduped + ordered. Flags controls that require manual / process work. |
| `/agentic-security:trim-dependencies` | Find and remove packages installed but never imported. |
| `/agentic-security:dep-freshness` | Score how stale your direct dependencies are across all ecosystems. |
| `/agentic-security:dep-pinning` | Audit manifests for loose version ranges that allow silent supply-chain injection. |
| `/agentic-security:dep-alternatives` | Lighter-weight, more actively maintained alternatives to heavy or high-risk dependencies. |
| `/agentic-security:install-script-audit` | Every npm package's postinstall/preinstall scripts — the primary supply-chain attack vector. |
| `/agentic-security:vendor-audit` | Copy-pasted third-party code vendored directly into the repo — invisible to dependency scanners. |
| `/agentic-security:security-tests` | Generate failing security regression tests + passing fix-validation tests for each finding (Jest / Vitest / pytest). |
| `/agentic-security:status` | One-screen plugin & project health snapshot — version, last scan, finding counts, cache size, hook activation. |
| `/agentic-security:help` | Full command catalog, ICP-segmented (🎨 Vibecoder lane / 🔧 Pro lane / 🤝 Both). |

The full reference lives in the **[Developer Documentation](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/developer-documentation-guide.md)**.

---

## How it works

```
                       ┌──────────────────────────────────┐
                       │    fileContents (your code)      │
                       └──────────────────┬───────────────┘
                                          │
                       ┌──────────────────▼───────────────┐
              ┌────────┤   engine.js   (taint + AST)      ├────────┐
              │        └──────────────────┬───────────────┘        │
              │                           │                        │
   ┌──────────▼──────────┐  ┌─────────────▼─────────┐  ┌───────────▼──────────┐
   │ SAST (25+ modules)  │  │ SCA (OSV+KEV+EPSS,    │  │ Secrets (60+ patterns │
   │ SQLi, XSS, AuthZ,   │  │ function-reachability,│  │ + entropy heuristic) │
   │ XXE, JWT, RLS, MCP, │  │ dep-confusion,        │  │                      │
   │ LLM, prompt-firewall│  │ typosquat, SARIF      │  │                      │
   └──────────┬──────────┘  └─────────────┬─────────┘  └───────────┬──────────┘
              │                           │                        │
              └───────────────────────────┼────────────────────────┘
                                          │
                       ┌──────────────────▼───────────────┐
                       │   posture/ enrichment pipeline    │
                       │  triage · suppressions · packs    │
                       │  EPSS · blast-radius · KEV        │
                       │  scorecard · custom-rules         │
                       └──────────────────┬───────────────┘
                                          │
                       ┌──────────────────▼───────────────┐
                       │           reporters               │
                       │  CLI · JSON · SARIF · JUnit · CSV │
                       │  HTML · CycloneDX · SPDX · PBOM   │
                       │  AI-BOM · ship-verdict · pro-table│
                       └──────────────────┬───────────────┘
                                          │
              ┌───────────────────────────┼─────────────────────────┐
              ▼                           ▼                         ▼
     last-scan.json              SARIF → GitHub Security    tickets sync
     (drives /fix, /report,      Tab / DefectDojo /         (GH Issues /
      /chain, /trend, /badge)    pipeline integrations      Linear / Jira)
```

The whole engine ships as a single 2.6 MB ESM bundle (`dist/agentic-security.mjs`). Pure Node ≥ 20. No native deps. No daemon. No background process.

---

## What this is NOT

We try to be honest about the boundaries.

- **Not a SaaS dashboard.** It's a CLI + Claude Code plugin.
- **Not a replacement for a pentester.** Static analysis catches patterns; humans catch business-logic flaws. The `security-logic-reviewer` subagent and `/validate-findings` close part of the gap, not all of it.
- **Not magic.** It can miss novel vulnerabilities, especially anything that requires understanding intent.
- **Not free for resale.** PolyForm Internal Use license. Use it to make your own code safe and secure, Don't repackage it as a competing scanner.

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

---

> Built with care by **[Clear Capabilities](https://www.clearcapabilities.com/)**. Found a bug, have a feature idea, want to talk? [ross@clearcapabilities.com](mailto:ross@clearcapabilities.com)
