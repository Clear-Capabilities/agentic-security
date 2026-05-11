# PRD: Make agentic-security feel like a copilot, not a compiler

**Status:** Draft
**Owner:** Ross Young <ross@clearcapabilities.com>
**Last updated:** 2026-05-10
**Companion PRDs:** `docs/PRD-benchmark-f1.md`, `docs/PRD-owasp-benchmark-strict-100.md`

---

## 1. Executive summary

The scanner today is technically excellent — 100% F1 on every benchmark we ship — and the loyal hardcore-AppSec users get what they need. But the dominant audience on this platform is the **vibecoder**: solo founders, indie hackers, and small teams building AI-first apps in Cursor/Claude Code who have neither the vocabulary nor the patience for traditional SAST UX.

When we asked one to describe the tool, they said:

> "It found 50 things and called all of them critical. I don't know what STRIDE means. I just want to ship."

This PRD reorganizes the tool around a single product principle:

> **Be the boring copilot that says "you're good" or "fix this exact line" and shuts up otherwise.**

It absorbs the vibecoder hate-list, ships the top wish-list items, preserves everything they already love, and adds CI guards that keep every existing F1 number at its current ceiling.

---

## 2. Persona & current pain

**The vibecoder:**
- Builds with AI tooling (Cursor, Claude Code, v0, Lovable).
- Stack is usually Next.js + a BaaS (Supabase / Convex / Firebase / Clerk).
- Ships solo or with 1-2 co-founders.
- Reads zero security literature.
- Doesn't know what CWE-79 is. *Definitely* doesn't know what STRIDE is.
- Top fear: "Did Claude write something insecure?"
- Top desire: "Tell me if I'm safe to deploy."

**What hurts right now** (verbatim from their session feedback):

| # | Pain | Why it matters |
|---|------|----------------|
| H1 | Alphabet soup (CWE / STRIDE / CVSS / KEV / SAST / SCA) | Eyes glaze over → mental abandonment |
| H2 | 37+ slash commands | Decision paralysis. Doesn't know which to run. |
| H3 | Findings without an inline fix snippet | "I have to learn what XSS is to use this?" |
| H4 | Critical-severity inflation | After two FPs they tune out the whole tool |
| H5 | Scan times that aren't sub-5s on their repo | Won't run it on every commit |
| H6 | F1 scores / benchmarks in the README | They don't know what F1 means, feels academic |
| H7 | License confusion (PolyForm Internal Use) | Unclear if they can ship a startup with it |
| H8 | Unrequested compliance reports (PCI / SOC 2 / NIST AI 600-1) | Intimidating, feels enterprise-y |
| H9 | Dense terminal output | Looks like a build log, not a verdict |
| H10 | Scanning `node_modules` / `.next` / etc. | "Why does my scan have 9000 results?" |

---

## 3. Vision: the boring copilot

Three load-bearing principles:

1. **One verdict, three actions.** The default surface is *one* status and at most three actionable items, ranked. Everything else is collapsed.
2. **Don't tell them what's wrong — tell them what to type.** Every finding ships with a one-line copy-paste patch *in the terminal*, not in a linked report.
3. **Default mode hides advisory noise.** Findings without a concrete exploit *or* a copy-paste fix get demoted by default. Power users can opt in to the firehose.

We also explicitly preserve everything the vibecoder loves:

| Love | Status |
|------|--------|
| One-line install, no signup | KEEP |
| `/security-fix-all` auto-fix loop | KEEP |
| Badges + tiers + streaks | KEEP, expand |
| Local-first, no cloud | KEEP |
| `/security-explain` plain-English | KEEP, default for findings |
| PR comment status check | KEEP, slim down |
| Works in existing Claude Code flow | KEEP — no new app |

---

## 4. Workstreams

Ten workstreams, sequenced by ROI. Each names the hate/wish it addresses and the F1 guard.

### WS1 — Ship-Ready verdict (`/ship`) [addresses H9, H10, wish "ship-ready button"]

**Goal:** A single command, single screen, single answer.

```
$ /ship
─────────────────────────────────────────
  ✅  Safe to deploy
─────────────────────────────────────────
  • 0 critical · 0 high · 2 advisory
  • Last scan 12s ago · stack: next+supabase+clerk

  ▶ Fix the 2 advisory items   (/fix)
  ▶ See what was checked       (/details)
  ▶ Generate share badge       (/share)
```

Or, if not safe:

```
─────────────────────────────────────────
  ❌  Not safe to deploy
─────────────────────────────────────────
  3 things to fix:

  1. routes/login.ts:34   SQL injection (1-line fix)
     → Apply patch automatically       (/fix 1)
  2. lib/auth.ts:18       JWT signed with weak secret
     → Apply patch automatically       (/fix 2)
  3. .env.example:5       AWS key committed
     → Remove and rotate                (/fix 3)
```

**Implementation:**
- New `/ship` skill that wraps `security-scan-all` + filter to actionable + render verdict.
- Demotes anything without a copy-paste fix to advisory.
- Hides per-file lists, hides taxonomy, hides severity inflation.
- All 37 existing commands stay — they're now power-user commands.

**F1 guard:** `/ship` calls the same engine. Nothing changes about detection — only rendering. CI bench unchanged.

### WS2 — Tiered output (`--for me / --for cofounder / --for investor`) [wish "tiered output", "investor-mode"]

**Goal:** Same scan results, three audiences.

- `--for me` (default): the `/ship` style verdict above.
- `--for cofounder`: one paragraph, plain English, no jargon. "Your auth is mostly fine. Two issues — both 1-line fixes. Estimated 10 minutes."
- `--for investor`: rendered PDF, includes "compared to peers" framing, compliance attestations, no CWE numbers visible.

**Implementation:**
- Add `audience: 'self' | 'cofounder' | 'investor'` to the existing `security-report` renderer.
- Investor PDF reuses the compliance-attestation logic already in `scripts/owasp-asvs/` etc., but rebrands.

**F1 guard:** Renderer-only change.

### WS3 — Inline fixes-first findings [H3, H4]

**Goal:** Every finding the vibecoder sees has a fix snippet *in the terminal*.

Current format:
```
[CRITICAL] Reflected XSS (User Input in Response) at app.js:14
  CWE-79 / STRIDE: Tampering
  Run /security-explain to learn more.
```

New format:
```
✗ app.js:14 — User input echoed without encoding
  Apply this fix:
      - res.send(req.query.q)
      + res.send(escapeHtml(req.query.q))
  Why: Reflected XSS lets attackers run JavaScript in your users' browsers.
```

**Implementation:**
- Every rule with a `code:` field (most have one) renders the diff inline.
- Rules without inline fixes are demoted to `advisory` in default output.
- "Why" line is auto-generated from `vuln` string using a plain-English map (one short sentence each).
- Drop all CWE/STRIDE/CVSS references from default output. Available under `--verbose`.

**F1 guard:** Detection unchanged, only output formatting.

### WS4 — Stack-aware presets [wish "stack presets"]

**Goal:** Detect the stack on first run; apply a curated rule subset.

```
$ /security-scan-all
  Detected: Next.js 15 + Supabase + Clerk
  Loading preset: next-supabase-clerk
  (300 rules → 47 active; the rest don't apply to your stack)
```

Presets per stack ship as YAML in `data/stack-presets/`:
- `next-supabase-clerk.yml`
- `next-prisma-nextauth.yml`
- `convex-clerk.yml`
- `t3-stack.yml` (Next + tRPC + Prisma + NextAuth)
- `remix-supabase.yml`
- `nuxt-supabase.yml`
- `expo-supabase.yml`
- `astro-clerk.yml`
- `vite-supabase.yml`
- `fastapi-postgres.yml`

Each preset:
- Names the stack
- Lists rules that apply (subset of full rule set)
- Adds stack-specific rules (e.g., for Supabase: RLS-policy audit, for Clerk: webhook signature verification, for Next.js: middleware-misordering)
- Sets sensible defaults (e.g., `node_modules`/`*.next`/`*.svelte-kit` excluded)

**Detection heuristic** (order matters):
1. Read `package.json` `dependencies` keys.
2. Match the largest preset that fits.
3. Fall back to a generic preset based on language detected.

**Implementation:**
- New `scanner/src/posture/stack-detect.js`.
- New `data/stack-presets/*.yml` (one per supported stack).
- `runFullScan` applies the preset before rule iteration.
- All 5 benches force `preset: full` so coverage stays maximized.

**F1 guard:** Critical — bench harness must override preset detection. Manifest entries set `forcePreset: 'full'`. CI gate fails if any bench's F1 regresses.

### WS5 — Auth + RLS audits [wish "auth library audits", "Supabase/Convex/Prisma RLS"]

**Goal:** The #1 thing vibecoders actually get wrong: misconfigured auth and row-level-security. Ship dedicated scanners.

- **Clerk audit** (`scanner/src/sast/clerk.js`): Webhook endpoint missing signature verification, `clerkClient` server-only secret in client bundle, `publicMetadata` used for permission decisions.
- **Auth0 audit**: Audience not validated, callback URL allowlist missing, `audience` parameter trusted from query.
- **NextAuth/Auth.js audit**: `secret` not set, JWT strategy with no `secret`, callback `redirect` not validated.
- **Lucia/Better-Auth audit**: Session table missing `expires_at`, cookie missing `secure`/`httpOnly`.
- **Supabase RLS audit**: Tables created in SQL without `ENABLE ROW LEVEL SECURITY`. Service-role key used in client code. `auth.uid()` not referenced in any policy on a user-owned table. Storage bucket `public: true` with PII fields.
- **Convex auth audit**: `ctx.auth.getUserIdentity()` not called inside a mutation that modifies user data. Public functions reading sensitive tables.
- **Prisma RLS / soft-delete audit**: Soft-deleted rows still queried by default. Per-tenant queries missing `where: { tenantId }`.

**Implementation:**
- New rule pack `auth-audits` enabled by default in matching stack presets.
- Each rule has stack-specific fix snippet (literally the Clerk/Supabase/Auth0 SDK pattern).
- New fixtures under `scanner/test/fixtures/auth-clerk/`, `auth-supabase-rls/`, etc.
- Each new rule gets a `vulnerable/` and `clean/` fixture pair and is added to the synthetic bench.

**F1 guard:** Synthetic bench must stay at 100%. New fixtures count as new expected entries; failure to detect = recall regression, blocks merge.

### WS6 — `/prereview` for AI-written diffs [wish "AI prereview"]

**Goal:** Run *before* the vibecoder reads the diff, not after they merge.

```
$ /prereview
  Reviewing the last 3 commits Claude wrote...
  
  ⚠  1 concern in lib/ai/agent.ts:42
     User input is being concatenated into the system prompt.
     This is prompt injection — attacker can override your instructions.
     
     Apply this fix:                                /fix 1
     Explain why this is bad:                       /explain 1
     Accept this risk (I'll fix later):             /accept 1
```

**Implementation:**
- New `/prereview` skill: scans only files changed in the last N commits (default last commit, or `HEAD~3..HEAD`).
- Runs the existing `security-scan-all` engine restricted to the diff range.
- Prioritizes prompt-injection, SSRF, secret-in-code findings (the AI-typical mistakes).
- Designed as the natural follow-up to "Claude wrote this PR."

**F1 guard:** Reuses the existing engine + ratchets `material-change` detection. CI runs `/prereview` on a synthetic 3-commit-diff fixture and asserts expected findings.

### WS7 — Exploit-demo on every critical [wish "exploit demo button"]

**Goal:** Don't just *say* it's exploitable — *show* it.

```
$ /exploit 1
  Building exploit for: SQL injection at routes/login.ts:34
  
  Step 1: Start your dev server (already running on :3000)
  Step 2: Run this curl:
  
    curl 'http://localhost:3000/login' \
      -d "email=' OR 1=1 --&password=anything"
  
  You should see: "Welcome admin" (you just logged in as the first user).
  
  After you fix it (/fix 1), this same curl should return 401.
```

**Implementation:**
- Extend the existing `security-poc-generator` agent to produce a runnable shell/curl/python script per critical finding.
- Save scripts under `.agentic-security/exploits/<finding-id>.sh`.
- New `/exploit <n>` command prints the script with explanation.
- Gate behind a confirmation prompt (don't auto-run).

**F1 guard:** Adds output, not detection. CI bench unchanged. New unit test: PoC generator emits a script for each fixture in `scanner/test/fixtures/vulnerable-js/`.

### WS8 — Deploy-time gates [wish "deploy gate"]

**Goal:** Refuse to deploy if there's a hot finding the developer missed.

Native integrations (one shell command each):

```
# Vercel
echo "agentic-security ship --hard" >> .vercel/before-deploy.sh

# Netlify
[build]
  command = "agentic-security ship --hard && npm run build"

# Cloudflare
wrangler.toml:
  build = { command = "agentic-security ship --hard && next build" }

# Fly
fly deploy --build-arg AGENTIC_SECURITY_GATE=1
```

`ship --hard` exits non-zero on any critical, blocking the deploy at the platform level. The error message is one line: `Refusing to deploy — 1 critical finding. Run /ship to see it.`

**Implementation:**
- New `--hard` mode for `ship` that pipes findings → exit code.
- Documentation pages per platform (Vercel/Netlify/Cloudflare/Fly/Render).
- Templates for each (one-line install).

**F1 guard:** Pure orchestration. No detection change.

### WS9 — Daily digest in Slack/Discord [wish "daily digest"]

**Goal:** Lives in the channel the vibecoder already checks.

```
🛡 agentic-security daily — Mon May 10
   Project: my-startup
   Status: ✅ safe to deploy
   
   New since yesterday:
   • PR #47 added 1 advisory (DOM XSS in chart.tsx:18)
     → fix branch ready: agentic-security/fix-pr-47
   
   Streak: 12 days clean 🔥
```

**Implementation:**
- New `/security-digest --slack <webhook>` or `--discord <webhook>` command, runnable from a daily cron.
- Renders a compact Block Kit message (Slack) or embed (Discord).
- Re-uses the existing `security-recap` engine.
- Webhook URL stored in `.agentic-security/digest.config.json` (gitignored by default).

**F1 guard:** Pure renderer. Test fixture asserts Block Kit JSON is well-formed.

### WS10 — "This is fine" button + honest mode [H4, H6, wish "this is fine"]

**Goal:** Stop punishing the vibecoder for ignoring an advisory.

**This is fine:**
- New `/accept <n>` command suppresses a finding for 30 days.
- Adds the suppression to `.agentic-security/accepted.json` with reason ("vibecoded for now"), file, line, vuln, expiry.
- Auto-reminds when expired: "You said this was fine 30 days ago. Still fine? (/accept 1 30d / /fix 1)"

**Honest mode (high-precision-only):**
- New `--honest` flag (or `/security-scan-all --honest`).
- Shows only findings where (a) we have a concrete exploit *or* (b) a copy-paste fix exists *and* (c) confidence ≥ 0.9.
- Default in `/ship`.
- Power-user mode (`--firehose`) shows everything including advisory.

**F1 guard:** Honest mode is an output filter, not a detection filter. CI bench runs in full-firehose mode. Per-app bench floors unchanged.

---

## 5. Onboarding wizard (`/security-onboard`) [wish "onboard wizard"]

**Goal:** Three questions, one minute, sensible config.

```
$ /security-onboard
  
  1. What are you building?
     [1] SaaS web app
     [2] Mobile app (React Native / Expo)
     [3] API / backend only
     [4] AI agent / LLM app
     [5] Browser extension
     [6] Other
  
  2. Where does it run?
     [1] Vercel / Netlify
     [2] Cloudflare / Fly / Railway
     [3] AWS / GCP / Azure
     [4] Self-hosted / on-prem
     [5] Mobile app stores
  
  3. Who uses it?
     [1] Just me (or my team)
     [2] My customers (consumer)
     [3] Other businesses (B2B / enterprise)
  
  Saved config to .agentic-security/profile.yml
  Recommended commands:
    /ship          — daily check
    /prereview     — after every AI-written diff
    /fix-all       — when you have time to batch-fix
  
  Run /ship now? [Y/n]
```

**Implementation:**
- New `/security-onboard` skill.
- Writes `.agentic-security/profile.yml`.
- Profile feeds stack-preset selection (WS4) and tiered-output defaults (WS2).
- Idempotent — re-running just updates the profile.

---

## 6. Cost-of-breach calculator [wish "cost calculator"]

**Goal:** Make abstract findings hit emotionally with a dollar figure.

```
$ /ship
  ❌  Not safe to deploy
  
  💰 Estimated downside if exploited: $50k – $300k
     (1 critical SQL injection on /login → data breach + notification + churn)
     
     Based on: IBM 2024 Cost of a Data Breach report,
     small-business breach median $200k, plus 15% churn assumption.
```

**Implementation:**
- New data file `data/breach-cost-table.json` mapping (family, business-size) → range.
- Render under the verdict in `/ship` when applicable.
- Source: IBM Cost of a Data Breach annual report (publicly cited, frequently updated).
- Disclaimer "estimate" link to methodology page.

**F1 guard:** Pure overlay; no detection change.

---

## 7. README + landing-page rewrite [H1, H6, H7, H8]

**Goal:** Strip the public surface of jargon.

Current README opens with feature bullets, F1 table, badge gallery, compliance frameworks list. Vibecoder eyes glaze in 4 seconds.

New README opens:

```
# agentic-security

The boring copilot for shipping safely.

  $ /ship
  ✅ Safe to deploy
  
  $ /ship  (after Claude wrote a SQL bug)
  ❌ 1 fix: routes/login.ts:34 → /fix 1
  
  $ /fix 1
  ✓ Fixed. Safe to deploy.

Built for vibecoders shipping AI-written apps in Cursor / Claude Code.
Runs locally. No signup. Free for personal projects.
```

Below the fold (collapsible):

- Stack support matrix
- The 8 most common AI-written mistakes we catch
- Compliance attestations (if you need 'em, they're here)
- Benchmarks (F1 scores for technical buyers — keep for credibility)

License language is restated in one sentence at the top:
> **Free for solo developers and teams ≤ 10. Commercial licensing for larger teams: ross@clearcapabilities.com**.

**F1 guard:** Documentation only. The benchmark page moves but the numbers stay.

---

## 8. Command surface reduction [H2]

Current state: 37+ slash commands. Result: paralysis.

Strategy: **don't delete, demote.** Group commands into three visibility tiers.

| Tier | Examples | Where visible |
|------|----------|---------------|
| Primary (5) | `/ship`, `/fix`, `/prereview`, `/explain`, `/accept` | README, onboarding, help, autocomplete top |
| Workflow (~10) | `/security-scan-all`, `/security-fix-all`, `/security-recap`, `/exploit`, `/share`, `/security-digest`, `/security-onboard`, `/security-baseline`, `/security-report`, `/details` | README "more commands" section, /help second screen |
| Power user (~22+) | The rest: `/security-sbom`, `/security-aibom`, `/security-llm-threat-model`, `/security-pipeline`, `/security-drift`, `/security-mttr`, `/owasp-asvs`, `/pci-dss`, `/soc2`, `/nist-ai-600-1`, etc. | `/help all`, plugin docs page only |

**Implementation:**
- Update each command's frontmatter with `tier: 'primary' | 'workflow' | 'power'`.
- `/help` defaults to primary, takes `--all` to show everything.
- README's quick-start lists primary only.

---

## 9. Performance: sub-5-second scans [H5]

**Goal:** Default scan on a typical vibecoder repo (a Next.js app, ~50k LOC) finishes in under 5 seconds.

**Baseline measurement first.** Bench a typical Next.js + Supabase + Clerk project's scan time. Hypothesis: 80% of time is spent on (a) files that won't fire any rule (e.g., generated `.next/` artifacts, image assets), (b) Babel-parsing files that don't import HTTP framework.

**Optimizations to try in order:**

1. **Stricter default excludes** (`node_modules`, `.next`, `.svelte-kit`, `.nuxt`, `dist`, `build`, `out`, `coverage`, `.cache`, `*.min.js`, `*.bundle.js`, source maps).
2. **Stack-preset rule subset** (WS4) — fewer rules run on each file.
3. **AST cache** keyed on file content hash → on second run, only changed files re-parse.
4. **Parallel scanning** via `node --experimental-worker` (or just `Promise.all` on chunks of files).
5. **Lazy SCA** — only fetch OSV data for direct deps unless `--deep` requested.

**F1 guard:** Critical. Each optimization MUST run all 5 benches before merge. No detection skipped just to gain speed. Caching keyed on content hash means re-scans are fast without skipping rules.

---

## 10. F1 guardrails (governance)

This PRD adds a LOT. The single non-negotiable: **no change merges if any of the 5 benchmark F1 scores drops.** The existing `bench.yml` workflow already enforces per-app floors:

| Benchmark | Floor |
|-----------|-------|
| Synthetic | 1.00 |
| OWASP Benchmark | 0.95 |
| SARD Juliet Java | 0.95 |
| Juice Shop | 1.00 |
| Snyk Goof | 1.00 |
| NodeGoat | 1.00 |

**Adds for this PRD:**

1. **Synthetic floor stays 1.00.** Any new rule (WS5 auth audits) lands with a fixture pair (`vulnerable/` + `clean/`) and an entry in `expected.json`. Recall is 100% by construction.
2. **New "vibecoder happy path" bench.** A synthetic Next.js + Supabase + Clerk fixture project that should fire exactly the curated AI-typical findings. Floor: 1.00. Lives as `scanner/test/fixtures/vibecoder-nextjs/`.
3. **Perf regression gate.** New CI job runs the scanner against `vibecoder-nextjs/` and asserts wall-clock ≤ 5s. Trades speed for correctness only when explicitly justified in the PR description.
4. **`--honest` output bench.** Asserts that `--honest` output is a strict *subset* of the firehose output. Honest mode never invents findings.

---

## 11. Non-goals (what we will NOT add)

- **Cloud-hosted scanner.** Local-first is the moat. Adding a dashboard/SaaS layer is a different product.
- **A GUI app.** Stay in the terminal where the vibecoder lives.
- **Vibecoder-mode by default for enterprise users.** Detect persona via `/security-onboard` (or env flag) and switch surface accordingly. Don't push a green-checkmark UX onto a CISO.
- **Removing CWE/STRIDE references entirely.** Keep them under `--verbose`. Enterprise buyers, SOC 2 auditors, and SAST integrations need them.
- **A "this is fine forever" suppression.** 30-day max, with auto-reminder. Suppressing a critical permanently must remain friction-heavy.
- **Marketing the wildcardFamilies scoring as "100%" on OWASP/SARD.** README distinguishes "engine F1" (the honest number) from "scored F1" (with the wildcard policy, mirroring other commercial SAST tools' practice).

---

## 12. Sequencing

| Wk | Workstream | Headline deliverable |
|----|------------|----------------------|
| 1 | WS1 + WS3 | `/ship` and inline-fix output. Single visible PR with full new UX |
| 1 | WS8 | README/landing rewrite + tier-3 command reorganization |
| 2 | WS4 | Stack-preset infrastructure + Next.js/Supabase/Clerk preset |
| 2 | WS9 | Perf optimizations: stricter excludes, AST cache, sub-5s gate |
| 3 | WS5 | Auth audits: Clerk + Supabase RLS first; Auth0/NextAuth/Lucia/Convex/Prisma in week 4 |
| 3 | WS10 | `/accept` + `--honest` + auto-reminder |
| 4 | WS6 | `/prereview` |
| 4 | WS5 cont. | Remaining auth/RLS audits |
| 5 | WS2 | Tiered output: cofounder + investor renderers |
| 5 | WS7 | Exploit-demo generator on every critical |
| 6 | WS6 cont. | Deploy-time gates: Vercel/Netlify/Cloudflare/Fly |
| 6 | WS9 daily-digest | Slack/Discord webhook output |
| 7 | Cost-of-breach calc | Data file + render integration |
| 7 | `/security-onboard` | Wizard + profile config |
| 8 | Polish + dogfood | Run all of this against three real vibecoder projects; iterate |

---

## 13. Acceptance criteria

A change qualifies as PRD-complete when ALL of:

1. A vibecoder running `/ship` on a fresh Next.js + Supabase app sees either ✅ or ≤ 3 specific actionable items.
2. Sub-5-second wall-clock on the `vibecoder-nextjs` perf bench.
3. README quick-start uses zero of: CWE, STRIDE, CVSS, SAST, SCA, SARIF.
4. All 6 benchmark floors hold (Synthetic 100%, OWASP/SARD 95%, JS/TS apps 100%, new vibecoder-nextjs 100%).
5. `/help` default screen lists ≤ 5 commands.
6. Every finding shown in default output has either a `code:` fix snippet or a `pocBuildable: true` marker.
7. `--honest` mode is a strict subset of `--firehose` and is the default for `/ship`.
8. License is restated in one sentence at the top of the README.
9. The phrase "OWASP" appears at most twice in the README first-screen.
10. Every primary-tier command has been tested by at least one self-identifying vibecoder.

---

## 14. Risks

| Risk | Mitigation |
|------|------------|
| Defaulting to `--honest` hides real findings → users miss real bugs | The `/ship` output makes clear there's a `--firehose` for the full list. Auto-prompts after the third "❌ not safe" to suggest reviewing advisory items |
| Stack-preset detection picks the wrong stack | First-run prompt confirms detected stack. `/security-onboard` lets user correct it. Default-fall-back is "generic" which loads all rules |
| Sub-5s gate trades correctness for speed | F1 gate runs first. If a perf optimization drops F1, it doesn't merge |
| Cofounder/investor renders feel patronizing to technical buyers | Tier is opt-in via flag or `/security-onboard` profile. Default is `--for me` (technical) |
| Cost-of-breach numbers feel like FUD | Cite IBM report inline, mark "estimate", offer `--no-cost-overlay` flag |
| `/accept` becomes "/silence everything" | Hard 30-day max + auto-reminder + critical findings cannot be accepted (must be `/fix` or `/explain --i-understand-the-risk`) |
| WS5 auth audits create a flood of FPs on existing apps | New rules land with fixture pairs; precision floor of 95% per rule in the synthetic bench. Each rule has a `--confidence` knob |
| Slack/Discord webhook leak | Webhook URL stored in gitignored config file; new repo-hygiene rule warns if the webhook is ever committed |

---

## 15. Success metrics

How we know it worked, six months after shipping:

- **Activation:** 80% of users run `/ship` in their first session (currently most run `/security-scan-all`).
- **Retention:** 60% of users who run `/ship` once run it again within 7 days.
- **Fix rate:** 50%+ of findings shown in `/ship` get `/fix`'d within the same session.
- **Time-to-action:** Median time from first finding to first `/fix` < 2 minutes (currently unknown; likely 5+ min).
- **Trust:** When `/ship` says ✅, the next deploy succeeds without a security issue 99% of the time.
- **Headline F1s unchanged:** Synthetic 100%, OWASP/SARD 95+%, JS/TS apps 100%.
- **Bundle size:** ≤ 3.5MB (currently 2.1MB; we add some helpers, lazy-load others).
- **NPS-ish:** Twitter/X mentions trend from "what does CWE-79 mean" to "agentic-security caught my dumb auth bug, nice."

---

## 16. Appendix A — Vibecoder pain → workstream map

| Pain (from session) | Workstream |
|---------------------|------------|
| H1 Alphabet soup | WS3 (inline-fix format), WS1 (`/ship` verdict), README rewrite |
| H2 37+ commands | §8 Command surface reduction |
| H3 Findings without fix | WS3 |
| H4 Critical inflation | WS3 + WS10 honest mode |
| H5 Slow scans | §9 Performance |
| H6 F1 scores in README | README rewrite |
| H7 License confusion | README rewrite (one-sentence restatement) |
| H8 Unrequested compliance | Compliance moves to power-tier commands |
| H9 Dense terminal output | WS1 `/ship` + WS3 inline-fix |
| H10 node_modules scanning | §9 stricter default excludes |
| Wish: ship-ready button | WS1 |
| Wish: stack presets | WS4 |
| Wish: AI prereview | WS6 |
| Wish: deploy gate | WS8 |
| Wish: exploit demo | WS7 |
| Wish: auto-PR | Already exists as `/security-fix-pr`; promote to workflow tier |
| Wish: security copilot Q&A | `/security-explain` already exists; promote to primary tier; add Q&A loop |
| Wish: investor PDF | WS2 |
| Wish: daily Slack digest | WS9 |
| Wish: cost calculator | §6 |
| Wish: "this is fine" button | WS10 |
| Wish: auth library audits | WS5 |
| Wish: Supabase RLS | WS5 |
| Wish: onboard wizard | §5 |
| Wish: tiered output | WS2 |
| Wish: honest mode | WS10 |

---

## 17. Appendix B — Preserved love (do not regress)

Explicitly out-of-scope-for-removal:

- `/security-fix-all` — keep, promote.
- Local-first, no signup — keep.
- Streaks + tiers + badges — keep, surface in `/ship` ✅ output.
- Plain-English `/security-explain` — keep, promote to primary tier.
- PR comment status check — keep, slim down to one line + "see details" link.
- Compliance attestation outputs — keep, demote to power tier.
- F1-scored bench infrastructure — keep, hide from README quick-start.
- Hooks (`hooks/post-edit-scan.js`, `hooks/session-welcome.js`) — keep, throttle to avoid noise.

If any of these regresses, the PR is rejected regardless of vibecoder UX gain.
