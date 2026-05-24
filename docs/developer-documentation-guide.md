<img src="brand/patch-bug-scene.svg" align="right" width="180" alt="Patch the mascot side-eyeing a bug on a monitor">

# agentic-security — Developer Guide

> The full reference. For the marketing-friendly overview, see [README.md](../README.md). This document assumes you read code, write rules, and own a CI pipeline.
>
> Brand canon (mascot, palette, type, lockups): [`docs/brand/patch-mascot.html`](brand/patch-mascot.html).

The 30-second tour for engineers:

- **One ESM bundle.** `dist/agentic-security.mjs` is a 2.6 MB single-file CLI. Pure Node ≥ 24, no native deps, no daemon. Pipes directly into shell, CI, IDE, or any wrapper.
- **One state directory.** Every artifact lives under `.agentic-security/` in your repo: `last-scan.json`, `findings.{json,sarif,csv,junit.xml}`, `triage.json`, `tickets.json`, `fix-history/`, `rules.lock.json`, `scan-history.json`, integrations config. Easy to gitignore, easy to inspect, easy to ship.
- **Four output personas.** Vibecoder (one-screen verdict + plain English) / Pro (full taxonomy, CSV+SARIF, audit suppressions) / CI (SARIF+JUnit+JSON+exit code per `--fail-on`) / machine (JSON pipe).
- **Designed to be extended.** Custom rule DSL (Semgrep-lite), per-project rule overrides, rule packs, SARIF ingest from external tools, two-way ticket sync, deterministic mode + lockfile.

If you want to skip ahead: [QUICKSTART](#quickstart) · [ARCHITECTURE](#architecture) · [COMMANDS](#commands) · [RECIPES](#recipes) · [OUTPUT FILES](#output-files) · [INTEGRATIONS](#integrations) · [CI/CD](#cicd) · [FINDINGS SCHEMA](#findings-schema).

---

```
NAME
       agentic-security — SAST + SCA + secrets + IaC + LLMSecOps scanner
       with audit-grade suppressions, machine-readable output, and
       integrations for the security stack you already run.

VERSION
       0.76.0

SYNOPSIS
       agentic-security [--profile pro] COMMAND [ARGS] [OPTIONS]

       Claude Code slash commands (preferred interface):

       Core scanning & fixing:
       /scan [PATH] [--all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff]
       /fix [--one <id>] [--all [--severity]] [--pr [--apply]]
       /show-findings [--all|--kev|--chains|--threat-model]
       /validate-findings <finding-id>
       /explain <finding-id|CWE-N|vuln-name>

       Pro & vibecoder essentials:
       /secure [path] [--launch]
       agentic-security fix --finding <id> [--preview|--apply]
       agentic-security undo [--all|--list]
       agentic-security tickets sync --provider <github|linear|jira> [--dry-run]
       agentic-security rules lock
       agentic-security rule list | rule test <fixture-glob>
       agentic-security scan --pr [ref]
       agentic-security scan --deterministic
       (auto-on) EPSS exploit-prediction enrichment via FIRST.org
       (auto-on) Blast-radius / cost framing per finding

       Auto-update behavior:
              Every /scan invocation first runs an auto-update check via
              scripts/auto-update-check.js. If the throttle window
              (default: 24h) has elapsed, /scan instructs Claude Code to
              run `/plugin marketplace update agentic-security` to refresh
              the plugin to the latest version. Throttle and on/off switch
              live in .agentic-security/auto-update.json:
                {"enabled": true, "throttleHours": 24, "lastCheck": <epoch>}
              To disable entirely: {"enabled": false}.

       Stack hardening:
       /stack-playbook
       /harden
       /audit --target db                                (was /db-audit)
       /audit --target auth                              (was /auth-audit)
       /audit --target rate-limit                        (was /rate-limit-check)
       /audit --target webhook                           (was /webhook-audit)
       /audit --target env                               (was /env-check)
       /rotate-secret [secret-value-or-finding-id]
       /audit --target deploy                            (was /deploy-check)
       /threat --view surface                            (was /attack-surface)
       /audit --target prompt                            (was /prompt-firewall)
       /audit --target csp-cors                          (was /csp-cors)
       /generate --type tests [--finding <id>|--all|--critical]  (was /security-tests)
       /ci [--severity critical|high|medium] [--comment] [--apply]  (was /ci-gate)
       /cve-alerts [--slack <url>|--discord <url>] [--apply]
       /vault-wizard [doppler|infisical|vercel|railway]
       /security-trend
       /security-attestation [--format badge|onepager|page]

       Real-time bodyguards:
       /ai-bodyguard [on|off|warn|block|status]
       /destructive-guard [on|off|warn|block|status]
       /ci --predeploy [install|check|status|off]        (was /predeploy-gate)

       Active rotation & cost control:
       /rotate-secret --auto <value|--scan> [--yes]
       /audit --target llm-cost [--apply] [--generate-middleware]  (was /llm-cost-ceiling)
                         [--generate-tracker --daily-cap-dollars N]

       Translate the jargon:
       /risk-in-dollars [--top N] [--json]
       /explain --narrative <finding-id|--random|--worst>  (was /story-explain)
       /daily-checkin [--setup|--slack <url>|--discord <url>|--crontab]

       Customer-facing artifacts (all from one command — picks format by flag):
       /security-attestation                            (badge — default)
       /security-attestation --format onepager [--company NAME] [--contact EMAIL]
       /security-attestation --format page --contact <email> [--pgp <url>]
       /generate --type privacy [--jurisdiction EU|US-CA|UK|OTHER] [--generate-banner]  (was /privacy-docs)

       Resilience & onboarding:
       /generate --type disaster [--stack supabase,stripe,vercel,...]  (was /disaster-playbook)
       /tutorial

       Dependency & supply chain (one command, per-check views via --show):
       /supply-chain-check                              (full rollup)
       /supply-chain-check --show pinning               (was /dep-pinning)
       /supply-chain-check --show freshness             (was /dep-freshness)
       /supply-chain-check --show alternatives          (was /dep-alternatives)
       /supply-chain-check --show install-scripts       (was /install-script-audit)
       /supply-chain-check --show vendored              (was /vendor-audit)
       /trim [--what code|deps]                         (was /trim-dead-code + /trim-dependencies)

       Posture & compliance:
       /posture-management [--sbom|--aibom|--api|--license|--drift|--mttr]
       /compliance-report [nist|asvs|llm]
       /status
       /report-card
       /audit --target launch                            (was /launch-check)
       /generate --type social                           (was /social-media)
       /help

DESCRIPTION
       agentic-security is a Claude Code plugin and standalone CLI for catching
       the security defects that AI-assisted development introduces and the
       traditional ones the AI inherits from training data. It emits SARIF +
       JSON + CSV every scan, and supports the workflow security engineers
       actually use: triage state, audit-grade suppressions, org-wide fleet
       scans, and custom rules.

       Evaluated against a structured ground-truth benchmark harness with
       a `--blind` mode that strips answer-key markers (FLAW comments, CWE
       folder names) before scoring, so the published numbers measure the
       engine — not pattern-matching against the test corpus's own labels.
       See BENCHMARK.md for the three scoring modes, reproducibility instructions,
       and the published per-family blind-mode baseline table.

       Coverage pillars:

         SAST        Taint analysis (regex + AST) for JS/TS, Java, Python.
                     25+ language-specific modules: SQL injection, XSS, command
                     injection, XXE, JNDI (Log4Shell), Java deserialization,
                     zip-slip, JWT flaws, auth provider misconfig (Clerk,
                     NextAuth, Auth0, Lucia), Supabase RLS audit, rate-limit
                     gaps, env hygiene, webhook signature verification, React
                     client-side XSS/localStorage, C/C++, C#, Go, Rust,
                     Solidity smart contracts, LLM prompt firewall.
         SCA         OSV + CISA KEV + EPSS, function-level reachability,
                     dep confusion, typosquat detection, deprecated packages
                     (npm, PyPI, Packagist, crates.io, RubyGems, pub.dev).
         Secrets     60+ credential patterns, high-entropy heuristic,
                     allowlist-aware, provider-specific rotation guidance.
         IaC         Dockerfile, docker-compose, GitHub Actions, Kubernetes.
         Deploy      Vercel, Railway, Fly.io, Netlify, Cloudflare Workers —
                     security headers, HTTPS enforcement, preview deployments,
                     health checks, compat dates.
         LLM         OWASP LLM Top 10 (2025) + prompt firewall (system prompt
                     contamination, missing max_tokens, LLM output→SQL/exec,
                     output schema validation).
         MCP         Agent-tool audit for over-privileged MCP servers.
         Pipeline    GitHub Actions: floating tags, secret echoes,
                     OIDC misconfig, write-all permissions.
         Auth/AuthZ  Broken access control, IDOR, mass assignment,
                     session fixation, JWT confusion, OAuth2 PKCE, Clerk/
                     NextAuth misconfig, dangerous email account linking.
         Container   Base-image EOL, exposed ports, runtime mode.
         Compliance  NIST AI 600-1, OWASP ASVS, OWASP LLM Top 10 (2025).
         Stack       Opinionated security playbook for Next.js, Supabase,
                     Stripe, Clerk, NextAuth, Prisma, Drizzle, OpenAI,
                     Anthropic, LangChain, MongoDB, Firebase, tRPC, FastAPI,
                     Django, and more.
         Trend       Rolling scan-history snapshots, fixed/introduced delta,
                     sparkline view, regression detection.
```

---

## ARCHITECTURE

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
   │ SAST (40+ modules)  │  │ SCA (OSV+KEV+EPSS,    │  │ Secrets (60+ patterns│
   │ SQLi, XSS, AuthZ,   │  │ function-reachability,│  │ + entropy heuristic) │
   │ XXE, JWT, RLS, MCP, │  │ dep-confusion,        │  │                      │
   │ LLM, prompt-firewall│  │ typosquat, SARIF      │  │                      │
   └──────────┬──────────┘  └─────────────┬─────────┘  └───────────┬──────────┘
              │                           │                        │
              └───────────────────────────┼────────────────────────┘
                                          │
       ┌──────────────────────────────────▼──────────────────────────────────┐
       │  Phase-1/2/3/4 Deep Engine  (opt-in: AGENTIC_SECURITY_DEEP=1)       │
       │                                                                     │
       │  ir/       Intermediate Representation — normalized CFG + cross-    │
       │            file callgraph emitted by per-language frontends, walked │
       │            by dataflow/. parser-js · parser-py · parser-java · ssa  │
       │            class-hierarchy (CHA + RTA) · function-as-value registry │
       │                                                                     │
       │  dataflow/ engine (interprocedural taint, k=1 monovariant)          │
       │            access-paths (P1.1) · receiver-context (P1.2)            │
       │            higher-order (P1.3) · backward slicing (P1.4)            │
       │            implicit-flow (P1.5) · RHS tabulation (P2.1)             │
       │            summaries · exception-flow (P3.4)                        │
       │            symbolic-exec (P3.1) · numeric-domain (P3.2)             │
       │            async-sequencing (P3.3) · sanitizer-proof (P4.2)         │
       │            incremental (P4.3) · string-domain (P4.4)                │
       │            polyglot embeddings (P4.7) · catalog (140+ entries)      │
       │                                                                     │
       │  llm-validator/  Layer-3 LLM accept/reject/escalate per finding     │
       │                  (opt-in: AGENTIC_SECURITY_LLM_VALIDATE=1)          │
       └──────────────────────────────────┬──────────────────────────────────┘
                                          │
                       ┌──────────────────▼───────────────┐
                       │   posture/ enrichment pipeline    │
                       │  triage · suppressions · packs    │
                       │  EPSS · blast-radius · KEV        │
                       │  scorecard · custom-rules         │
                       │  schema-aware bridges (P4.1)      │
                       │  cross-lang openapi/grpc/graphql  │
                       │  /orm/iac-reachability/queues     │
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

       Sideband consumers:
         mcp/    JSON-RPC 2.0 server — exposes 6 tools to any MCP-speaking
                 agent (Claude Code / Cursor / Cline / Aider / Codex).
         lsp/    Language-Server-Protocol server — powers JetBrains, Neovim,
                 and VS Code plugins via textDocument/publishDiagnostics.
```

> **What is `ir/`?** **IR** stands for **Intermediate Representation** — the
> normalized in-memory graph between raw source code and analysis. It's the
> standard compiler / static-analysis layer (LLVM has "LLVM IR", CodeQL has
> "QL", Semgrep has "Generic AST"; ours is plain `ir/`). Per-language frontends
> (`parser-js`, `parser-py`, `parser-java`) walk the source AST and emit one
> shared shape: a per-function CFG with typed nodes (`entry`, `exit`, `assign`,
> `call`, `return`, `if`, `loop-header`, `throw`, `noop`), a cross-file call
> graph keyed by stable function `qid`, a class hierarchy (CHA + RTA) for
> virtual-dispatch narrowing, and SSA form (Cytron/Ferrante φ-placement) so
> each variable redefinition is a distinct name. Having an IR is what lets
> `dataflow/` be language-agnostic: the taint engine never has to know whether
> the code was originally JS, Python, or Java — it walks IR.

### Data flow at a glance

1. `runScan()` walks the tree under `--changed-since` / `--pr` filters; yields `{ fileContents, depFileContents }` to the engine.
2. `runFullScan()` runs every SAST module per file, builds the cross-file taint + reachability graphs, and emits raw findings into `scan.{findings, secrets, logicVulns, supplyChain, components, routes}`.
3. The CLI applies the **enrichment pipeline** in order: SARIF ingest → suppressions (inline, custom, soft-acceptance) → rule overrides → rule packs → custom-rule pattern DSL → EPSS → blast-radius → optional `--deterministic` post-processing.
4. The CLI writes `findings.{json, sarif, csv, junit.xml}` to `.agentic-security/`, persists `last-scan.json` for downstream commands, and appends a snapshot to `scan-history.json`.
5. `normalizeFindings()` projects the raw schema into the canonical wire format consumed by every reporter.

### Repository layout

```
       scanner/
         bin/                        # CLI entry points:
           agentic-security.js       #   primary CLI dispatch
           agentic-security-mcp.js   #   MCP server (stdio JSON-RPC)
           agentic-security-lsp.js   #   LSP server (IDE integration)
           agentic-security-rule.js  #   custom-rule authoring + test harness
           agentic-security-diff.js  #   scanner-vs-scanner diff harness
         dist/agentic-security.mjs   # Bundled single-file CLI (built artifact)
         src/engine.js               # Main SAST/SCA/secrets orchestrator
         src/runScan.js              # Filesystem driver + readTree
         src/sast/                   # 40+ language/family modules
         src/sca/                    # OSV/KEV reachability, container, dep-confusion
         src/secrets/                # 60+ pattern matchers + entropy
         src/ir/                     # Phase-1/2 IR — Intermediate Representation,
                                     # the normalized graph the dataflow engine walks
                                     # (opt-in via AGENTIC_SECURITY_DEEP=1):
                                     #   parser-js (Babel) · parser-py · parser-java
                                     #   callgraph · class-hierarchy (CHA + RTA)
                                     #   ssa (Cytron/Ferrante φ-placement)
         src/dataflow/               # Interprocedural taint engine + extensions:
                                     #   engine · catalog (140+ entries) · summaries
                                     #   access-paths (P1.1) · receiver-context (P1.2)
                                     #   higher-order · backward · implicit-flow
                                     #   tabulation (RHS) · path-feasibility
                                     #   exception-flow (P3.4) · symbolic-exec (P3.1)
                                     #   numeric-domain (P3.2) · async-sequencing (P3.3)
                                     #   sanitizer-proof (P4.2) · string-domain (P4.4)
                                     #   incremental (P4.3) · polyglot (P4.7)
         src/llm-validator/          # Layer-3 LLM accept/reject/escalate per finding
                                     #   (opt-in via AGENTIC_SECURITY_LLM_VALIDATE=1)
         src/mcp/                    # MCP server — 6 tools any MCP-speaking agent
                                     # can call (scan_diff, query_taint,
                                     # explain_finding, apply_fix, verify_fix,
                                     # synthesize_fix). Stdio JSON-RPC 2.0 over NDJSON.
         src/lsp/                    # LSP server (powers JetBrains/Neovim/VS Code)
         src/posture/                # Enrichment + reporting glue:
                                     #   epss · blast-radius · custom-rules
                                     #   deterministic · fix-history · router
                                     #   triage · suppressions · packs · confidence
                                     #   stable-id · clustering · exploitability
                                     #   reachability-filter · learning · fix-verify
                                     #   schema-aware-bridge (P4.1)
                                     #   cross-lang-{openapi,grpc,graphql,orm,queues}
                                     #   iac-reachability · fix-plan · path-predicates
                                     #   validator-metrics · deploy-platform
                                     #   stack-playbook · security-trend
         src/integrations/           # Slack/Discord/Teams/PagerDuty webhooks +
                                     # GitHub/GitLab PR comments + Jira/Linear/
                                     # ServiceNow/GitHub-Issues two-way ticket sync
         src/report/                 # CLI/JSON/SARIF/JUnit/CSV/HTML renderers
         test/                       # Node test runner suite (470 main + 26 cpp)
       commands/                     # 38 slash-command markdown files
       agents/                       # 7 sub-agent system prompts
       hooks/                        # 5 Claude Code event-driven scripts
       ide/jetbrains/                # LSP4IJ-backed JetBrains plugin
       ide/nvim/                     # Native-LSP Neovim plugin (Lua)
       ide/vscode/                   # VS Code extension (TS source)
       bench/cve-replay/             # F1 ≥ 0.85 measurement scaffolding
       scripts/ci-templates/         # CI configs (GitLab/CircleCI/Buildkite/Jenkins)
       .claude-plugin/plugin.json    # Plugin manifest (declares MCP, hooks, agents)
       .agentic-security/            # Per-project runtime state (gitignored)
```

---

## SETUP

```
       agentic-security profile set pro
```

Flips the defaults: full taxonomy visible (CWE/CVSS/OWASP/MITRE/CAPEC),
confidence threshold lowered (≥0.3 vs. ≥0.9 in vibecoder mode), all
commands and flags accessible, SARIF + CSV written on every scan,
suppression schema upgraded to audit-grade.

Confirm with:

```
       agentic-security profile show
```

---

## QUICKSTART

Five minutes from `npx` to a working pro setup with a CI gate, ticket sync, and a deterministic baseline.

### 1. Install and confirm

```bash
       npx @clear-capabilities/agentic-security-scanner version
       # → agentic-security 0.35.0 · created by ClearCapabilities.Com
```

Or globally, if you prefer the short alias `as`:

```bash
       npm install -g @clear-capabilities/agentic-security-scanner
       as version
```

### 2. Flip into pro mode

```bash
       agentic-security profile set pro
```

Lowers confidence threshold to ≥ 0.3, surfaces full taxonomy
(CWE / CVSS / OWASP / MITRE ATT&CK / CAPEC), writes SARIF + CSV every scan,
upgrades suppressions to audit-grade.

### 3. Run your first scan

```bash
       agentic-security scan . --pack owasp-top-10 --format pro
```

Writes `.agentic-security/findings.{json, sarif, csv}` and prints the pro
table. Your team's noise floor is now visible. Triage it once.

### 4. Lock the rule-pack version

```bash
       agentic-security rules lock
       # → wrote .agentic-security/rules.lock.json
       #   scanner: 0.35.0  rulePackHash: 40669df8f5856e18
```

Required if you want byte-stable scans for audits, regression baselines,
and reproducibility across the team. Re-run after upgrading.

### 5. Wire CI

```bash
       # Generates .github/workflows/security.yml that runs on every PR,
       # uploads SARIF, posts review comments, and fails on critical/high.
       agentic-security ci . --fail-on critical
       # — OR via the slash command, with an opinionated workflow file —
       # claude /agentic-security:ci --apply
```

### 6. Wire ticket sync (optional, dry-run first)

```bash
       # GitHub Issues — uses the gh CLI, no extra auth needed.
       agentic-security tickets sync --provider github --severity high --dry-run

       # Linear — needs LINEAR_API_KEY + a team UUID.
       LINEAR_API_KEY=lin_api_… \
         agentic-security tickets sync --provider linear \
                                       --team-id <team-uuid> --severity high

       # Jira — needs JIRA_BASE_URL, JIRA_EMAIL, JIRA_TOKEN, JIRA_PROJECT_KEY.
       agentic-security tickets sync --provider jira --severity critical
```

Idempotent. Re-running creates issues for new findings, closes tickets for
resolved findings, no-ops if nothing changed.

### 7. Make it auditable

```bash
       agentic-security scan . --deterministic --format sarif --output baseline.sarif
```

Stable-sorts findings, zeros timing/scanId, refuses to run if the lockfile
doesn't match. Commit `baseline.sarif` to your repo as the regression
baseline; future PRs run `--changed-since` against it.

### 8. (Pro tip) Author one custom rule

```bash
       mkdir -p .agentic-security/rules
       cat > .agentic-security/rules/no-internal-bypass.yml <<'YAML'
       id: my-org/no-internal-bypass-header
       title: "x-internal-bypass header is debug-only"
       severity: critical
       cwe: CWE-287
       languages: [javascript, typescript]
       match:
         pattern: 'request\.headers\[\s*['"'"'"]x-internal-bypass['"'"'"]'
       message: "x-internal-bypass should never appear in production paths."
       remediation: "Remove the header check or guard it behind NODE_ENV !== 'production'."
       YAML
       agentic-security rule test "src/**/*.ts"
```

Custom rules ship findings exactly like built-ins, with the prefix
`custom:<id>:<file>:<line>` so you can filter them downstream.

---

## COMMANDS

### Core scanning & fixing

```
       scan [PATH]
              Full SAST + SCA + secrets + IaC sweep. PATH defaults to cwd.
              Writes findings.{json,sarif,csv} to .agentic-security/.
              Also appends a snapshot to scan-history.json for /security-trend.

       fix --one <id>
              Emit the canonical patch template for one finding. The
              security-fixer subagent applies it to the affected file with
              full codebase context — detects auth library, ORM, and
              framework before writing the fix.

       fix --all [--critical|--high|--medium|--low]
              Batch-fix every finding at or above the severity tier.
              Cumulative: --high fixes critical + high. Default: --critical.

       fix --pr [--apply] [--branch <name>] [--severity critical|high|all]
              Bundle fixes into a feature branch and open a pull request.
              Default is dry-run; pass --apply to commit changes.

       triage list | assign | transition | trend
              Per-finding state machine. List by status, severity, or
              assignee. Trends compute MTTR + opened/closed deltas.

       org-scan --repos <list> [--workers N]
              Fleet scan. Workspace-aware (Nx, Turborepo, pnpm).
              Per-repo + rolled-up JSON output.

       rules validate
              Lint .agentic-security/rules.yml for schema errors, invalid
              regex, severity overrides, and disabled rules.
```

### Vibe-coder essentials

```
       stack-playbook
              Detect the project's tech stack from package.json /
              requirements.txt and output an opinionated, copy-paste-ready
              security checklist for the specific combination of frameworks
              in use. Supports: Next.js, Supabase, Stripe, Clerk, NextAuth,
              Prisma, Drizzle, OpenAI, Anthropic, LangChain, MongoDB,
              Firebase, tRPC, FastAPI, Django, and email providers.

       harden
              One-command security hardening. Applies 7 safe automated
              changes to the project:
                1. .env* entries added to .gitignore
                2. Security headers injected into next.config.js
                3. npm audit script added to package.json
                4. .env.example created from .env with placeholders
                5. Security disclosure section added to README
                6. SECURITY.md created
                7. *.pem / *.key / serviceAccountKey.json added to .gitignore
              Prints applied/skipped/failed per step. Safe to run multiple
              times (idempotent per item).

       audit --target db
              Surfaces all database security findings from last-scan.json:
              Supabase service-role key exposure, NEXT_PUBLIC_ vars leaking
              service keys, auth.admin called client-side, bypassRowLevel-
              Security() in query chains, SQL tables without RLS enabled,
              raw pg Pool/Client in request handlers, and SQL injection.
              Provides remediation steps and severity breakdown.

       audit --target auth
              Deep-audits the authentication layer. Covers: allowDangerous-
              EmailAccountLinking, trustHost: true (CSRF bypass), missing
              NEXTAUTH_SECRET, weak or hardcoded session secrets, hardcoded
              OAuth clientSecret, CSRF protection disabled, Clerk sensitive
              paths in publicRoutes, session cookies without secure/sameSite,
              JWT alg:none, algorithm confusion, JWT without expiry.

       audit --target rate-limit
              Find API endpoints missing rate limiting by category:
                auth    — login/register/forgot/verify (brute-force risk)
                ai      — generation/chat/inference (cost explosion risk)
                payment — stripe/checkout/pay (card-testing risk)
                contact — forms/newsletter/waitlist (spam risk)
              Prints copy-paste @upstash/ratelimit setup for serverless
              and express-rate-limit for Node servers.

       audit --target webhook
              Audit webhook handlers for missing cryptographic signature
              verification. Detects provider (Stripe, GitHub, Clerk, Svix,
              Resend, Twilio) from imports and URL patterns. Fires only when
              ALL signals are present: webhook path + body read + no verify.
              Explains the fake-payment attack vector and provides provider-
              specific fix snippets including raw-body parser requirements.

       audit --target env
              Runtime + scan-based environment hygiene report:
                • .env* files absent from .gitignore
                • .env* files tracked in git (git ls-files check)
                • NEXT_PUBLIC_*SECRET/KEY/TOKEN vars in env files
                • .env.example / .env.sample with real-looking values
                • process.env.X || "real-fallback" in source code
                • dotenv loaded in non-entry files

       rotate-secret [value]
              Given a secret value or finding ID, detects the provider
              (OpenAI, Anthropic, Stripe, GitHub, AWS, Supabase, Slack,
              SendGrid, Resend, Twilio) from the key prefix/pattern. Lists
              every file referencing the secret. Provides platform-specific
              rotation steps (Vercel / Railway / Fly / Render / Netlify).
              Ends with post-rotation verification checklist and git-history
              purge advice.

       audit --target deploy
              Platform-specific infra security audit. Detects platform from
              config files and checks:
                Vercel   — security headers in vercel.json / next.config.js,
                           public preview deployments
                Railway  — health check configuration
                Fly.io   — force_https, auto_stop_machines
                Netlify  — security headers in netlify.toml
                Cloudflare Workers — compatibility_date in wrangler.toml
              Provides copy-paste remediation for each platform.

       threat --view surface
              Gathers scan statistics (severity counts, KEV deps, attack
              chains, unauth state routes) and instructs Claude to synthesise
              a plain-English threat narrative — 3–5 realistic attack
              scenarios with attacker steps, impact, likelihood, and
              single-line fix per scenario. Written for builders, not
              security engineers.

       audit --target prompt
              Surfaces all LLM/AI security findings:
                • User input concatenated into system prompts (prompt
                  injection via system prompt contamination)
                • Missing max_tokens cap (cost explosion / DoS)
                • LLM output used as SQL/shell/eval input (second-order
                  injection — critical severity)
                • LLM response consumed without schema validation
              Gate: all rules require an LLM API import to fire (zero
              impact on non-AI codebases).

       audit --target csp-cors
              Reads package.json for external services (Supabase, Stripe,
              Clerk, OpenAI, analytics, Sentry, Intercom) and instructs
              Claude to generate exact Content-Security-Policy and CORS
              config for the detected framework and deployment platform.
              Outputs ready-to-paste header blocks for Next.js, Express,
              and Vercel JSON.

       generate --type tests [--finding <id>|--all|--critical]
              Detects the project's test framework (Vitest, Jest, pytest,
              Node test runner) and instructs Claude to generate per-finding
              test files with:
                • A failing test proving the vulnerability is exploitable
                • A passing test proving the fix works
              Uses real imports from the affected file, not mocks. Outputs
              as security/<slug>-security.test.{js|ts|py}.

       ci [--severity critical|high|medium] [--comment] [--apply]
              Generates .github/workflows/security.yml that:
                • Runs on pull_request and push to main
                • Uploads SARIF to GitHub Security tab
                • Posts a PR review comment with finding counts and
                  top findings (with --comment)
                • Fails the build on findings at --severity threshold
              Default threshold: high. Pass --apply to write the file.

       cve-alerts [--slack <url>|--discord <url>] [--apply]
              Generates:
                • scripts/cve-monitor.mjs — checks OSV for new CVEs
                  across all installed packages, tracks seen IDs in
                  .agentic-security/cve-alert-state.json, posts to
                  Slack/Discord webhook when new CVEs drop
                • .github/workflows/cve-alerts.yml — daily 8am UTC cron
              Pass --apply to write the files. Set CVE_ALERT_URL secret
              in GitHub Actions for notifications.

       vault-wizard [doppler|infisical|vercel|railway]
              Inventories all env vars across .env*, classifies them as
              sensitive (SECRET/KEY/TOKEN/PASSWORD patterns) vs. config,
              and instructs Claude to generate a step-by-step migration
              guide to the specified vault including CLI commands, CI
              integration snippets, and post-migration cleanup instructions.
              Auto-detects platform if target not specified.

       security-trend
              Reads .agentic-security/scan-history.json (appended by every
              scan) and renders:
                • Bar-chart sparkline of total findings over time
                • Fixed vs. introduced delta between last two scans
                • Net change with colour coding (green=improving)
                • List of newly introduced finding IDs
              Each /scan --all run automatically appends a snapshot.

       security-attestation (default — badge format)
              Computes letter grade (A–F) from last-scan.json and generates:
                • Shields.io badge Markdown for README
                • Professional security posture paragraph for investor
                  due-diligence questionnaires or pitch decks
```

### Pro & vibecoder essentials

```
       secure [PATH] [--launch] [--json] [--run]
              Smart router. Inspects project state and prints the single
              best next action — no menu, no choice paralysis. Decision
              tree:
                no prior scan        → run `scan .`
                criticals open       → `fix --finding <id> --preview`
                highs open           → `/show-findings`
                mediums only         → `/report-card`
                last scan > 7 days   → re-scan
                clean                → `/security-attestation`
                --launch + criticals → BLOCK
                --launch + clean     → `/audit --target launch`
              --run auto-executes the recommended `agentic-security ...`
              command. --json emits the decision as a struct for piping.

       fix --finding <id> --preview | --apply
              --preview shows a unified diff (3 lines of context) of the
              proposed change without writing. --apply writes the change
              and stores the original under .agentic-security/fix-history/
              with a log entry in fix-history/log.json. Both modes require
              a mechanical replacement (f.fix.replacement or
              f.fix.replaceLine) — for free-form fixes use the
              security-fixer subagent which produces a replacement first.

       undo [--all|--list]
              Revert the most recent un-reverted fix from history.
              --all reverts every applied fix in reverse order.
              --list prints the fix history with applied/reverted state.
              Atomic per-fix backups; safer than `git stash` for
              partial-rollback scenarios.

       tickets sync --provider <github|linear|jira> [--severity high]
                    [--repo OWNER/REPO] [--team-id ID] [--dry-run]
              Two-way sync between findings and ticket systems:
                • Creates a ticket for every open finding ≥ severity
                  that does not already have one tracked in
                  .agentic-security/tickets.json.
                • Closes tickets whose findings are no longer present.
              GitHub uses the gh CLI (no extra auth). Linear needs
              LINEAR_API_KEY + --team-id. Jira needs JIRA_BASE_URL,
              JIRA_EMAIL, JIRA_TOKEN, JIRA_PROJECT_KEY env vars.
              Idempotent: re-running is a no-op once everything matches.
              tickets list             — print all tracked tickets

       rules lock
              Compute the current rule-pack content hash (union of every
              named pack's CWE set) and write rules.lock.json with the
              scanner version. Required for --deterministic. Re-run
              after upgrading agentic-security to refresh the lock.

       rule list | rule test <fixture-glob>
              Custom pattern-rule DSL — Semgrep-lite. Rules live in
              .agentic-security/rules/*.yml. Schema:
                id: my-org/no-eval
                title: "Use of eval() is forbidden"
                severity: high
                cwe: CWE-95
                languages: [javascript, typescript]
                match:
                  pattern: "\\beval\\s*\\("
                  notMatch: "// safe-eval-allowed"
                  # OR allOf: [regex1, regex2] within `window: 50` lines
                message: "eval() bypasses static-analysis controls."
              The `rule test` harness runs every rule against every file
              in the glob and prints PASS / FAIL (false positive) /
              FAIL (missed). Files containing 'vulnerable' in the path
              are expected to fire; 'clean' files are expected not to.

       scan --pr [REF]
              Diff-aware mode: only scan files changed since REF.
              Without an explicit ref, auto-detects the PR base from
              GITHUB_BASE_REF / CI_MERGE_REQUEST_TARGET_BRANCH_NAME /
              BUILDKITE_PULL_REQUEST_BASE_BRANCH /
              BITBUCKET_PR_DESTINATION_BRANCH; falls back to origin/main.
              Uses the existing --changed-since plumbing under the hood.

       scan --deterministic
              Reproducible mode for audits, baselines, and CI:
                • Verifies .agentic-security/rules.lock.json matches
                  the current scanner version + rule-pack hash.
                • Forces --no-network (no OSV / EPSS network calls).
                • Stable-sorts every findings array by file → line →
                  vuln → id.
                • Zeros out scanId / startedAt / durationMs so the JSON
                  output is byte-identical for the same input.
              Exits 4 with a diff if the lockfile doesn't match.

       (auto-on) EPSS exploit-prediction enrichment
              Every CVE-bearing finding decorated with epssScore +
              epssPercentile from FIRST.org. Cached under
              ~/.claude/agentic-security/epss-cache/ for 24h.
              Findings with percentile ≥ 0.95 get tags: ["exploited-now"]
              and a one-tier severity bump (medium→high→critical) so
              they sort to the top. Disable with --no-epss.

       (auto-on) Blast-radius / cost framing — world-class model (v0.37+)
              Every finding stamped with a blastRadius object:
                scope: 'paying-users'|'all-users'|'admin-only'|'public'
                dataAtRisk: ['pii','payment','phi','rce','credentials',...]
                userCount: <estimated from project signals>
                industry: <14 verticals classified from deps + schema>
                jurisdictions: ['GDPR','CCPA','HIPAA','PCI-DSS',...]
                controlsApplied: ['waf','mfa','monitoring',...]
                dollarBest / dollarLikely / dollarWorst: three-point
                           estimate (P5 / P50 / P95)
                dollarLow / dollarHigh: backward-compat aliases
                components: { incidentResponse, legal, crisisPR,
                              notification, creditMonitoring,
                              regulatoryFines, directDamage, classAction,
                              lostBusiness } — each a {low, likely, high}
                dominantDriver: <largest-contributing component>
                comparable: <real public incident citation>
                confidence: 'high' | 'medium' | 'low'
                narrative: plain-English one-liner with citation
              Empirical sources cited inline: IBM Cost of a Data Breach
              2024, NetDiligence Cyber Claims Study 2024, HHS OCR HIPAA
              enforcement records, GDPR Enforcement Tracker, public
              settlements (Equifax $1.4B, Capital One $190M, T-Mobile
              $350M, Anthem $115M, etc.). No LLM call, no network.
              Disable with --no-blast-radius.
```

### Real-time bodyguards

```
       ai-bodyguard [on|off|warn|block|status]
              PreToolUse hook on Edit / Write / MultiEdit. Scans the
              content the agent is about to write BEFORE it hits disk.
              High-precision rules with near-zero FP rate:
                • SQL injection via string concatenation
                • exec()/spawn()/os.system() with template strings
                • NEXT_PUBLIC_*SECRET / NEXT_PUBLIC_*API_KEY (browser leak)
                • Hardcoded sk-/ghp_/xoxb-/AKIA/pk_live_ credentials
                • dangerouslySetInnerHTML without sanitize
                • eval()/new Function() on user input
                • jwt.decode() instead of jwt.verify()
                • Supabase service_role key in client-side code
                • LLM messages.create() without max_tokens
                • CORS '*' + Allow-Credentials: true
              Config: .agentic-security/bodyguard.json
                {"mode": "warn"|"block"|"off", "skipPaths": [...]}
              Block mode returns exit 2 + stderr msg (Claude Code denial
              signal). Warn mode prints to stderr but allows the edit.

       destructive-guard [on|off|warn|block|status]
              PreToolUse hook on Bash. Pauses on commands vibe-coders
              most often regret. 13 critical/high patterns:
                CRITICAL:  rm -rf on parent dirs, rm -rf with no target,
                           DROP TABLE / DROP DATABASE / TRUNCATE,
                           supabase db reset, git push --force to main,
                           git push --force any branch, aws s3 rm --recursive
                HIGH:      git reset --hard, git clean -fdx, vercel --prod,
                           curl|bash, chmod 777, docker system prune -a
              Config: .agentic-security/destructive-guard.json
                {"mode": "block"|"warn"|"off", "extraPatterns": [{...}]}
              Add custom patterns: each entry {name, re, severity, why,
              instead}. Override per-command with AS_GATE_OVERRIDE=1.

       ci --predeploy [install|check|status|off]
              Two-layer block on prod deploys:
                • PreToolUse Bash hook (catches direct prod commands
                  inside Claude Code)
                • Shell wrapper functions sourced from
                  scripts/predeploy-gate.sh (intercepts in the user's
                  own terminal: vercel, fly, flyctl, wrangler, netlify,
                  railway)
              Gate checks:
                1. last-scan.json exists
                2. Scan is no older than require_recent_scan_hours
                3. Zero findings at block_on severities (default critical)
                4. Zero KEV-listed dependencies (when block_on_kev: true)
              Config: .agentic-security/predeploy-gate.json
                {"block_on": ["critical"], "block_on_kev": true,
                 "require_recent_scan_hours": 24}
              Bypass once: AS_GATE_OVERRIDE=1 <command>
```

### Active rotation & cost control

```
       rotate-secret --auto <value> | --scan [--yes]
              ACTIVELY rotate a leaked credential end-to-end.
              Provider detection by prefix:
                openai                sk-...,  sk-proj-...
                anthropic             sk-ant-...
                stripe                sk_live_..., rk_live_...
                aws                   AKIA[A-Z0-9]{16}
                github                ghp_..., github_pat_...
                supabase-service-role JWT with role=service_role
                slack                 xoxb-/xoxa-/xoxp-...
                google-api            AIza...
              For each detected provider:
                1. Print exact revoke commands (console URL + CLI)
                2. Print blast-radius warning (Stripe = real money,
                   AWS = crypto-mining, Supabase service-role = RLS bypass)
                3. Prompt for new value (or read from --new-value)
                4. Scrub leaked value across all text files
                   (with backups in .agentic-security/rotation-backups/)
                5. Push new value to detected deploy platforms:
                   vercel env / fly secrets / railway variables /
                   wrangler secret / netlify env:set
                6. Print final audit checklist (billing dashboard,
                   git history grep, history rewrite caveat)
              --scan walks the repo, finds all leaked keys, rotates each.
              --yes skips confirmation prompts (CI / non-interactive).

       audit --target llm-cost [--apply] [--generate-middleware]
                        [--generate-tracker --daily-cap-dollars N]
              Audit every LLM call site, enforce cost ceilings.
              Detected SDKs (by file ext + pattern):
                JS/TS:  anthropic.messages.create,
                        openai.chat.completions.create,
                        openai.completions.create (legacy)
                Python: client.messages.create (Anthropic),
                        client.chat.completions.create (OpenAI)
              Recognized cap keys: max_tokens, max_completion_tokens
              (OpenAI o1/o3), max_output_tokens (Gemini).
              --apply        Auto-patch missing max_tokens (default: 1024).
                             JS/TS: injects as first prop in object literal.
                             Python: injects as first kwarg.
                             Conservative — leaves complex call shapes alone.
              --generate-middleware
                             Writes drop-in rate-limit middleware tailored
                             to detected framework:
                               next → middleware/llm-rate-limit.ts
                               express/fastify → middleware/llm-rate-limit.ts
                               python → middleware/llm_rate_limit.py
                             Defaults: 20 calls / IP / 60s window.
              --generate-tracker --daily-cap-dollars N
                             Writes lib/llm-spend-tracker.ts:
                               trackAndGate({dailyCapUsd, model,
                                             inputTokens, outputTokens})
                             Throws SpendCeilingExceeded once cap is hit.
                             Pricing table for Claude/GPT-4o models is
                             baked-in; override per project.
              Exit 1 if any uncapped calls remain — suitable for CI gate.
```

### Translate the jargon

```
       risk-in-dollars [--top N] [--json]
              Translate each finding's CWE into best-/likely-/worst-case
              dollar exposure. Sourced from public incident settlements
              (Capital One $190M for SSRF, T-Mobile $350M for IDOR, Equifax
              $1.4B for SQLi, etc.). 19 CWE classes mapped with named
              scenarios + specific regulatory triggers (GDPR Art. 33,
              CCPA, HIPAA, NIST AI 600-1, EU AI Act).
              Default sort: worst-case descending.
              Data source: scripts/data/dollar-risk-bands.json (editable).

       explain --narrative <finding-id> | --random | --worst
              Narrative-form explanation instead of CWE jargon. 4-act
              structure:
                Setup           — what the app does, where the bug lives
                Meet <Name>     — attacker persona matched to vuln class
                The attack      — minute-by-minute, present tense, concrete
                                  URLs and payloads (not "an attacker would")
                The aftermath   — customer ticket, regulator clock, $ cost
                What stops this — the literal 2–3 line code fix
              Attacker personas mapped to vuln classes (SQLi → competitor
              doing recon; IDOR → curious user; hardcoded key → bot; ...).

       daily-checkin [--setup|--slack <url>|--discord <url>|--webhook <url>]
                     [--crontab|--rescan|--project-name NAME]
              Post a daily security digest to messaging tools.
              Digest shape:
                Open counts (critical/high/medium)
                New findings since last digest (with file:line, top 5)
                Resolved finding count
                KEV (known-exploited) package count
              State in .agentic-security/daily-checkin-last.json —
              fingerprints from last run drive the new/resolved diff.
              Renderers: plain text, Slack Block Kit, Discord embeds,
              generic JSON. --crontab prints suggested cron line.
              --rescan forces a fresh scan before building the digest
              (otherwise reads last-scan.json).
```

### Customer-facing artifacts

```
       security-attestation --format onepager [--company NAME] [--contact EMAIL]
                         [--output PATH] [--print]
              Customer-facing "How we keep your data safe" markdown.
              Auto-derived sections:
                Posture summary  Live counts + traffic-light state +
                                 clean-scan streak from streak.json
                Stack            Detected frameworks
                Practices        Conditional — only includes practices
                                 the scan output actually evidences
                                 (Supabase RLS audit only if Supabase
                                 detected, Stripe webhook integrity
                                 only if Stripe detected, etc.)
                Data handling    TLS, encryption-at-rest, least-access
                Incident response  24h ack / 72h initial / GDPR Art. 33
                Frameworks       OWASP ASVS, LLM Top 10, NIST AI 600-1
                                 alignment statement
              Output is markdown — convert to PDF with `pandoc SECURITY.md
              -o SECURITY.pdf --pdf-engine=xelatex`.

       generate --type privacy [--company NAME] [--contact EMAIL]
                    [--jurisdiction EU|US-CA|UK|OTHER]
                    [--generate-banner]
              Detect every third-party data processor and generate a
              tailored PRIVACY.md. 14 providers mapped:
                Stripe, Supabase, Clerk, Auth0, Sentry, PostHog,
                Mixpanel, GA4, OpenAI, Anthropic, Vercel Analytics,
                Cloudflare Analytics, Resend, SendGrid.
              Each processor entry includes:
                Purpose, exact data received, DPA URL, sub-processors URL,
                cookies set (if any), category (auth/payment/analytics/ai)
              Jurisdiction adds the appropriate rights clause (GDPR/UK
              GDPR/CCPA/generic). --generate-banner writes a React
              cookie-consent component to components/CookieBanner.tsx
              with localStorage persistence + analyticsConsent event.

       security-attestation --format page --contact <email> [--pgp <url>] [--canonical-url <url>]
              Generates three artifacts:
                1. public/.well-known/security.txt
                   RFC 9116 compliant. Contact, Expires (1y), Preferred-
                   Languages, optional Encryption (PGP), Canonical, Policy.
                2. public/security-posture.json
                   Live snapshot (counts, streak, last-scan) consumed by
                   the page below at build time.
                3. /security page tailored to framework:
                   Next.js App Router → app/security/page.tsx
                   Next.js Pages Router → src/pages/security.tsx
                   Vanilla → public/security/index.html
              Page shows traffic-light state, critical/high/medium counts,
              clean-streak days, last-scan time, practices block, and the
              disclosure contact channel.
              Re-run periodically — security.txt has a 1-year expiry.
```

### Resilience & onboarding

```
       generate --type disaster [--stack supabase,stripe,vercel,...]
                         [--output PATH] [--print]
              Generate a stack-specific incident-response runbook
              (DISASTER.md) BEFORE you get hacked. Detects platforms:
                Supabase, Stripe, Vercel, Fly, Auth0, Clerk, AWS, npm
              Sections (each with exact commands, queries, URLs):
                Universal first-10-minutes triage
                Supabase: service-role rotation, RLS audit, PITR,
                          force re-auth, suspected DB write triage
                Stripe: roll keys, audit charges, dispute fraud,
                        Radar rules, webhook secret rotation
                Vercel: bad-deploy rollback, paused auto-deploys,
                        compromised-dep redeploy, function budget
                Auth0 / Clerk: revoke sessions, rotate client secret
                AWS: disable IAM key, hunt crypto-mining instances,
                     lock public S3, GuardDuty enable
                npm: pin out bad package, rebuild, audit install
                     scripts, rotate every cred the script could read
                After the fire: disclosure (GDPR 72h), postmortem,
                                regression test
              Templates parameterised with actual env var names.

       tutorial
              First-run walkthrough that picks ONE real finding from the
              user's project, explains it in plain English, walks them
              through fixing it with consent at every step, then
              verifies the fix actually worked.
              Flow:
                0. Orient. Run a scan if none exists.
                1. Pick a teachable finding (high/critical with named
                   CWE in {89,78,22,79,639,918,798}; skip TOCTOU /
                   license / indeterminate)
                2. Show ±15 lines of context around the finding
                3. Show 2-line attacker timeline + real-world incident
                4. Show the fix with consent prompt
                5. Re-scan affected file, confirm finding is gone
                6. Suggest next 3 commands by name
              Rules: ONE finding only, ask before acting, match user's
              pace, no shaming, end with concrete next steps.
```

### Dependency & supply chain

```
       trim --what deps [PATH] [--dry-run] [--include-dev]
              Find installed packages never imported in source code.
              Reports per-package on-disk size and transitive dep count.
              Default is --dry-run; pass --apply to execute removals.

       supply-chain-check --show freshness
              Score how stale direct dependencies are across all ecosystems.
              Stale deps are the primary CVE accumulation vector.

       supply-chain-check --show pinning
              Audit manifests for loose version ranges that allow silent
              supply-chain injection. Flags unpinned deps and missing
              lockfiles.

       supply-chain-check --show alternatives
              Find heavy or high-risk dependencies with lighter-weight,
              native, or more actively maintained alternatives.

       supply-chain-check --show install-scripts
              Audit every npm package (direct and transitive) for
              postinstall/preinstall scripts — the primary supply-chain
              attack vector in the npm ecosystem.

       supply-chain-check --show vendored
              Find copy-pasted or bundled third-party code vendored directly
              into the repo — invisible to dependency scanners and never
              receiving security updates.

       digest --slack <url> | --discord <url>
              POST a structured digest payload to a Slack/Discord webhook.

       profile show | set | detect
              Persona master switch. detect uses heuristic signals
              (SECURITY.md, CI workflow named *security*, etc.).

       packs list
              List available rule packs (owasp-top-10, cwe-top-25,
              llm-security, supply-chain).
```

---

## RECIPES

Worked examples for the workflows pros set up most often. Every recipe is copy-pasteable.

### Block PRs that introduce new critical findings

Two-step pattern: snapshot a baseline once, then `--changed-since` against it on every PR.

```bash
       # ── one time, on the protected branch ──
       agentic-security scan . --deterministic \
                               --format sarif \
                               --output .agentic-security/baseline.sarif
       git add .agentic-security/baseline.sarif .agentic-security/rules.lock.json
       git commit -m "security: pin baseline + rule-pack lockfile"

       # ── on every PR (CI) ──
       agentic-security ci .                # auto-detects PR base ref
       # exits 1 if there are NEW critical findings vs. main; exits 0 otherwise.
```

`agentic-security ci` writes the three CI artifacts (`findings.json`,
`findings.sarif`, `findings.junit.xml`) plus a one-line stderr summary
formatted for GitHub Actions log highlighting.

### Author + share a rule pack

Rule packs in `.agentic-security/rules/` can be committed to your repo and
shared across projects via a tarball or git submodule.

```yaml
       # .agentic-security/rules/stripe-webhook-must-verify.yml
       id: my-org/stripe-webhook-must-verify
       title: "Stripe webhook handler missing constructEvent()"
       severity: critical
       cwe: CWE-345
       languages: [javascript, typescript]
       match:
         allOf:
           - 'app\.(post|use)\([^)]*[''"]\/.*stripe.*webhook'
           - 'req\.(body|rawBody)'
         notMatch: 'stripe\.webhooks\.constructEvent\('
         window: 60
       message: "Stripe webhook handler reads req.body without verifying the
                 stripe-signature header. Anyone can POST a fake event."
       remediation: |
         const sig = req.headers['stripe-signature'];
         const event = stripe.webhooks.constructEvent(rawBody, sig, endpointSecret);
```

Test it before checking in:

```bash
       agentic-security rule test "test/fixtures/**/*.{ts,js}"
       # → Loaded 1 rule(s); testing against N file(s).
       #     [PASS] my-org/stripe-webhook-must-verify → fixtures/vulnerable/handler.ts:12
       #     [FAIL (false positive)] … → fixtures/clean/handler.ts:14   (oops, regex too loose)
```

### Sync findings to your existing tracker

The `tickets sync` command is **idempotent** and safe to run on a cron.
State persists in `.agentic-security/tickets.json`; re-runs no-op on
unchanged findings.

```bash
       # Cron: every 15 minutes, ensure GitHub Issues mirrors the latest scan.
       */15 * * * *  cd /repo && \
                     agentic-security scan . --no-network && \
                     agentic-security tickets sync --provider github --severity high
```

Closed manually in GitHub but still in scan? `tickets sync` won't reopen
it — the state file remembers the closure. Closed in scan but still open
in GitHub? Next sync auto-closes the issue.

### Filter SCA noise: only reachable + actively-exploited

EPSS percentile + reachability is the highest-signal SCA filter we ship.

```bash
       agentic-security scan . --pack supply-chain \
                               --sca-reachable-only \
                               --format pro \
                               --columns mitre
       # then filter the JSON for what actually matters in CI:
       jq '.findings[] | select(.exploitedNow == true and .reachable == true)' \
          .agentic-security/findings.json
```

Combined with `--deterministic`, this gives you a stable, prioritized
queue you can copy into Jira / Linear without re-triaging across runs.

### Custom suppressions with audit trail

For mature teams: every suppression carries a `reason` and a
`reviewedBy` field, both surfaced in the CSV / SARIF / SBOM exports.

```yaml
       # .agentic-security/rules.yml
       suppressions:
         - rule: "Hardcoded Credential Check"
           files: ["src/test/fixtures/**/*"]
           reason: "Test fixture, not production code."
           reviewedBy: "alice@team"
           reviewedAt: "2025-04-12"
         - rule: "Reflected XSS"
           files: ["src/internal/admin/preview.tsx"]
           reason: "Admin-only path, output rendered through DOMPurify upstream."
           reviewedBy: "bob@team"
           reviewedAt: "2025-04-12"
```

Vibecoder mode allows soft suppressions that auto-expire after 30 days
(`agentic-security accept --finding <id> --reason "vibecoded"`); pro mode
only honors hard suppressions in `rules.yml`.

### Generate auditor-ready compliance evidence

```bash
       agentic-security scan . --deterministic
       claude /agentic-security:compliance-report nist     # NIST AI 600-1
       claude /agentic-security:compliance-report asvs     # OWASP ASVS
       claude /agentic-security:compliance-report llm      # OWASP LLM Top 10
```

Each report cross-references concrete scan evidence, lockfile hash, and
scanner version — the receipts an auditor wants instead of a checkbox.

### Build a custom CLI wrapper

The scanner exports its public API for embedding:

```js
       import { runScan } from '@clear-capabilities/agentic-security-scanner';

       const { scan, meta } = await runScan('.', { changedSince: 'origin/main' });
       const critical = scan.findings.filter(f => f.severity === 'critical');
       if (critical.length) process.exit(1);
```

See `scanner/src/index.js` for the full export surface.

---

## OPTIONS

```
       --format FORMAT
              Output: cli, json, md, sarif, csv, html, cyclonedx, spdx,
              pbom, aibom, aibom-md.

       --columns SET
              Pro-mode column profile for the cli renderer:
                standard  CWE + CVSS + OWASP
                mitre     ATT&CK technique + tactic
                capec     CAPEC attack-pattern number
                owasp     OWASP Top 10 category

       --confidence N
              Override the per-profile confidence threshold (0.0–1.0).

       --firehose
              Show ALL findings (ignore confidence threshold). Useful for
              audits, debugging, or feeding a downstream filter.

       --honest
              High-confidence-only view (≥0.9). Strict subset of
              --firehose.

       --severity {critical|high|medium|low|info}
              Exit-code threshold for CI gating.

       --only {sast|sca|secrets}
              Limit to one pillar.

       --sca-reachable-only
              Drop SCA findings where the vulnerable function is not
              reachable from any route handler.

       --ingest-sarif <glob>
              Merge external SARIF (gitleaks, Trivy, Checkov, Bandit)
              into this scan. Findings dedupe by fingerprint.

       --scorecard
              Enrich SCA components with OSSF Scorecard scores.

       --no-network
              Skip OSV / registry / EPSS / KEV queries (offline mode).

       --pack <name>[,<name>...]
              Focus on a CWE allowlist: owasp-top-10, cwe-top-25,
              llm-security, supply-chain. Multiple packs union their sets.

       --output FILE
              Write the rendered report to FILE.
```

---

## OUTPUT FILES

Every scan writes to `.agentic-security/` in the project root:

```
       findings.json    Normalized findings, programmable schema.
       findings.sarif   SARIF 2.1.0 for GitHub Security tab, GitLab, etc.
       findings.csv     Spreadsheet / BigQuery / executive reports.
       last-scan.json   Live state consumed by /fix, /show-findings,
                        /posture-management, /audit --target db|auth|
                        rate-limit|webhook|env|deploy|prompt|csp-cors|
                        llm-cost|launch, /threat --view surface,
                        /security-attestation, /generate --type tests,
                        /security-trend.
       scan-history.json  Rolling window (30 scans) for /security-trend.
                          Appended automatically on every scan.
       cve-alert-state.json  Seen CVE IDs for /cve-alerts deduplication.
       suppressions.yml Audit-grade suppression records.
       rules.yml        Custom rules, severity overrides, version pins.
       triage.json      Triage state machine.
       integrations.yml Webhooks + API tokens (gitignored).
       profile.yml      Persona profile (pro|vibecoder).
       streak.json      Security grade history and achievements.
       auto-update.json  /scan auto-update throttle + on/off switch.
                         Schema: {enabled, throttleHours, lastCheck}.
       bodyguard.json   /ai-bodyguard config (mode + skipPaths).
       destructive-guard.json  /destructive-guard config (mode + extraPatterns).
       predeploy-gate.json     /ci --predeploy config (block_on, KEV, freshness).
       daily-checkin.json      /daily-checkin webhook destinations + min severity.
       daily-checkin-last.json  Fingerprint store for digest deltas.
       rotation-backups/<ts>/   Backups created by /rotate-secret --auto before scrub.
       poc-cache/        Per-finding PoC verdicts from /validate-findings.
       poc/<id>/         Generated PoC tests, variants.json, etc.
```

---

## HOOKS

The plugin ships five runtime hooks that the Claude Code harness invokes
automatically. Registered via `hooks/hooks.json`:

```
       SessionStart
              hooks/session-welcome.js
              Prints the welcome banner with last-scan summary.
              First session per project: full lockup (Patch mascot +
              "agentic-security" wordmark, see hooks/mascot.js). Returning
              sessions: one-line streak greeting.

       PreToolUse  (matcher: Edit|Write|MultiEdit)
              hooks/pre-edit-bodyguard.js
              Real-time AI-coding bodyguard. Scans the proposed content
              BEFORE write with high-precision rules for the bugs vibe-
              coders most often ship by accident (SQLi via concat,
              NEXT_PUBLIC_ secrets, dangerouslySetInnerHTML, JWT without
              verify, Supabase service-role on the client, LLM call with
              no max_tokens, etc.). Exits 2 to deny (block mode + critical
              pattern) or 0 with stderr message (warn mode). Reads
              .agentic-security/bodyguard.json. ~10ms.

       PreToolUse  (matcher: Edit|Write|MultiEdit)
              hooks/conversation-context.js
              Injects open findings + recent /fix history + pending
              fix-plans for the file being edited as conversation context
              so Claude doesn't re-introduce a just-fixed vuln. ~2ms.

       PreToolUse  (matcher: Bash)
              hooks/pre-bash-guard.js
              Intercepts destructive shell commands before they run —
              rm -rf, DROP TABLE, supabase db reset, git push --force to
              main, curl | bash, chmod 777, aws s3 rm --recursive, docker
              system prune -a, and 10+ other foot-guns. Critical patterns
              return exit 2 (deny); high patterns return exit 0 with
              stderr warning. Reads .agentic-security/destructive-guard.json.
              ~5ms.

       PostToolUse  (matcher: Edit|Write|MultiEdit)
              hooks/post-edit-scan.js
              Scans the directory of the edited file, surfaces NEW high/
              critical findings. Throttled per-file ≤1/5s.
```

All hooks read JSON event payloads on stdin per the Claude Code hook
contract, are stdlib-only (no `node_modules` dependency at the hook
level), and degrade silently if their config file is missing.

To disable a hook without uninstalling the plugin:

```json
{
  "mode": "off"
}
```

Written to the relevant `.agentic-security/<hook>.json` file.

---

## MCP SERVER

agentic-security ships an MCP (Model Context Protocol) server at
`scanner/bin/agentic-security-mcp.js`, registered under
`.claude-plugin/plugin.json#mcpServers`. It is also reachable as
`agentic-security mcp`. Transport: JSON-RPC 2.0 over NDJSON on stdin/stdout.

Six tools are exposed — any MCP-speaking agent (Claude Code, Cursor CLI,
Codex CLI, Cline, Aider) can call them:

```
       scan_diff(files)
              Re-scan a specific file list. Fast, scoped scan that returns
              findings limited to those paths. Used by /fix to verify a
              proposed patch is local.

       query_taint(source, sink)
              Ask the engine "is there a flow from X to Y?". Exposes the
              interprocedural taint engine as a queryable graph for agents
              doing custom analysis.

       explain_finding(finding_id)
              Plain-English finding explanation. Same content surface as
              the /explain slash command.

       synthesize_fix(finding_id)
              Returns the proposed replacement text + bounds for one
              finding. No file writes. Used as a planning step before
              apply_fix.

       verify_fix(stable_id, files)
              Re-scan + run the project linter against the proposed files.
              No writes. Returns ok:false with a structured reason when
              the patch doesn't actually remove the original finding or
              introduces new ≥medium findings.

       apply_fix(finding_id, confirm, dry_run?)
              Actually write the patch. Refuses unless last-scan.json HMAC
              verifies and confirm:true. Honours dry_run.
```

**Safety rails (mapped to the OWASP MCP top-10):**

- **MCP09 — kill switch.** `AGENTIC_SECURITY_MCP_DISABLED=1` exits the bin
  and refuses every `tools/call`.
- **Session root pinning.** Fixed at boot via `--root` arg,
  `AGENTIC_SECURITY_MCP_ROOT` env, or cwd. All tool paths are confined
  under it via lstat + realpath (symlinks refused).
- **MCP03 / MCP06 — output is data, not instructions.** Tool outputs
  include `_meta.untrusted_excerpts:true` so the agent treats scanner
  output as data, not instructions. `apply_fix` refuses unless
  last-scan.json HMAC verifies.
- **MCP01 / MCP10 — secret hygiene.** All tool outputs and audit args are
  redacted of known credential shapes (AWS, GitHub, Slack, Anthropic,
  OpenAI, Stripe, JWT, PEM private keys, hardcoded password literals).
- **MCP08 — audit log.** `.agentic-security/mcp-audit.log` (NDJSON, hash-
  chained — verify with `verifyAuditLog`) records every `tools/call`.
- **MCP04 / MCP09 — fleet visibility.** `initialize` response includes
  `serverInfo.codeFingerprint` (SHA-256 of MCP source files) so operators
  can detect unauthorized builds.

---

## AGENTS

The plugin ships seven sub-agents in `agents/`. Each agent is a markdown
system prompt loaded by the Claude Code harness; commands invoke them
via the Agent tool.

```
       security-poc-generator
              For ONE finding, build a PoC input + a regression test
              (framework-idiomatic), trace the data flow step-by-step,
              and emit 3-5 adversarial variants for confirmed TPs.
              Emits PROBABLE_FP when a static blocker is found,
              REFUSED for out-of-tree paths, INDETERMINATE_BY_CLASS
              for vuln families that cannot be reliably proven by a
              sub-minute regression test. Used by /validate-findings.

       security-fixer
              Apply remediation patches for individual findings.
              Reads the affected file, applies the canonical fix
              template adapted to the surrounding code, re-runs tests
              if available. Used by /fix.

       security-triager
              Score, dedupe, and rank a finding list by risk. Produces
              a sorted, deduped list ready for human or AI consumption.
              Used by /triage and /show-findings.

       security-chain-synthesizer
              Combine individual findings into multi-step attack chains
              (e.g., IDOR + missing auth = account takeover). Used by
              /show-findings --chains.

       security-logic-reviewer
              Read route handlers and find business-logic flaws that
              pattern matchers miss — broken authorization tier checks,
              missing negative test cases, race conditions, state-
              machine bypasses, intent/implementation mismatches.

       security-material-change
              Score the security materiality of a git diff. Separates
              routine refactors from architectural risk — auth removed,
              new endpoints, new prompts with user input, new shell
              calls, new IaC privilege grants. Used by PR review flows.

       sca-malware-analyst
              Per-component CLEAN/SUSPICIOUS/MALICIOUS verdict for
              third-party dependencies. Used after /supply-chain-check
              when you need to decide whether a vuln is malware vs an
              ordinary CVE.
```

---

## IDE INTEGRATIONS

The same engine ships as an LSP server that powers all editor plugins.
Bin entry: `scanner/bin/agentic-security-lsp.js`. The server wraps
`runScan` and emits `textDocument/publishDiagnostics` to the editor.

```
       ide/jetbrains/
              LSP4IJ-backed JetBrains plugin (IntelliJ / PyCharm /
              GoLand / WebStorm / RubyMine / PhpStorm). ~100 LoC +
              plugin.xml. Build with `./gradlew buildPlugin`.

       ide/nvim/
              Native-LSP Neovim plugin (Lua). Attaches the bundled
              LSP server on filetype-matched buffers. Install via
              lazy.nvim or vim-plug.

       ide/vscode/
              VS Code extension. Source in `ide/vscode/src/extension.ts`.
              Built and packaged separately.
```

All three surface the same findings inline as the CLI emits — diagnostics
are keyed by stableId, so navigating between IDE and CLI references the
same identity.

---

## EXIT STATUS

```
       0   Clean — no findings at or above --severity
       1   Findings at low or medium severity
       2   Findings at high severity
       3   Findings at critical severity
       4   Engine error (parse failure, IO, malformed config)
```

CI gating example — blocks the pipeline on any critical finding:

```bash
       agentic-security scan . --severity critical
```

Or use the generated workflow from `/ci --apply`.

---

## FINDINGS SCHEMA

Every finding produced by the scanner includes:

```json
{
  "id":          "module:RULE_ID:file/path.js:42",
  "title":       "Human-readable title",
  "vuln":        "Canonical vulnerability name (used for bench family mapping)",
  "severity":    "critical | high | medium | low | info",
  "file":        "relative/path/to/file.js",
  "line":        42,
  "description": "What the vulnerability is and how it is exploited",
  "remediation": "Exact fix, often with code snippet",
  "cwe":         "CWE-89",
  "kev":         false,
  "toxicityScore": 0–100,
  "triageScore":   0–100
}
```

Severity values in order: `critical`, `high`, `medium`, `low`, `info`.

---

## SUPPRESSIONS

Suppressions are structured, reviewed, and auditable. Stored in
`.agentic-security/suppressions.yml`:

```yaml
       - finding_id: c14d...
         file: lib/admin.js
         line: 47
         cwe: CWE-798
         rule_version: 0.34.0
         reason: |
           Hardcoded credential is in a test fixture, not a production
           code path. Verified via call-graph analysis (no production
           caller).
         justification_signed_by: alice@team.example.com
         reviewer: bob@team.example.com
         reviewed_at: 2026-05-13T14:30:00Z
         expires_at: 2026-11-13T00:00:00Z
         ticket: SEC-1247
```

Validation rules:
- signer must differ from reviewer (two-person rule)
- expires_at must be in the future
- critical-severity findings cannot be suppressed without `--accept-critical`
- rule_version is pinned: a newer scanner re-surfaces the finding unless
  the suppression is re-approved

Lint with:

```
       agentic-security rules validate
```

Inline per-line suppression (source code):

```js
       const key = "hardcoded"; // agentic-security-ignore: hardcoded-secret
```

---

## TRIAGE

State machine: `open` → `in-progress` → (`fixed` | `wont-fix` | `false-positive`).
Findings auto-transition to `fixed` when the scanner no longer detects them.

```
       agentic-security triage list --status open --severity critical
       agentic-security triage assign SEC-0042 alice@team
       agentic-security triage transition SEC-0042 in-progress
       agentic-security triage transition SEC-0042 fixed \
              --comment "Patched in PR #94"
       agentic-security triage trend --since 30
```

`trend` output:

```
       Opened:  47
       Closed:  52
       Net:     -5 (improving)
       Open:    critical=2 high=8 medium=15 low=4
       MTTR median: 3.2 days
```

State is persisted to `.agentic-security/triage.json`.

---

## CUSTOM RULES

`.agentic-security/rules.yml`:

```yaml
       version: 0.34.0

       severityOverrides:
         "Hardcoded Credential Check": medium

       disable:
         - "Verify x-powered-by Header is Disabled"

       custom:
         - id: internal-auth-bypass
           regex: 'if\s*\(\s*request\.headers\[\s*[''"]x-internal-bypass[''"]'
           vuln: "Internal Auth Bypass Header"
           severity: critical
           cwe: CWE-287
           description: "x-internal-bypass is debug-only. Never in prod."
           fix: "Remove the x-internal-bypass header check."
```

### Pattern-rule DSL — `.agentic-security/rules/*.yml`

Standalone, Semgrep-lite rules that produce findings directly without dataflow modeling. Each YAML file in `.agentic-security/rules/` defines one or more rules:

```yaml
       id: my-org/no-eval
       title: "Use of eval() is forbidden"
       severity: high
       cwe: CWE-95
       languages: [javascript, typescript]   # or [any] / [python] / [go] / ...
       match:
         pattern: "\\beval\\s*\\("            # single regex (gm flags)
         # OR allOf: [regex1, regex2, ...]    # all must match within `window` lines
         # window: 50                          # default 50 lines
         # notMatch: "// safe-eval-allowed"   # kill switch
       message: "eval() bypasses our static-analysis controls."
       remediation: "Use JSON.parse for data; use a sandboxed VM for code."
```

Test fixture pairs (`vulnerable/foo.js` + `clean/foo.js`):

```
       agentic-security rule list
       agentic-security rule test "test/fixtures/**/*.js"
```

The harness reports `PASS` when a rule fires on `vulnerable/`, `FAIL (false positive)` when it fires on `clean/`, and `FAIL (missed)` when it doesn't fire on `vulnerable/`.

### Rule-pack lockfile — `.agentic-security/rules.lock.json`

```
       agentic-security rules lock
       # → wrote .agentic-security/rules.lock.json
       #   scanner: 0.35.0  rulePackHash: 40669df8f5856e18

       agentic-security scan --deterministic
       # Verifies the lockfile, refuses to run on mismatch.
```

Required for audit-defensible scans (compliance reports, regression baselines, byte-stable CI artifacts).

---

## INTEGRATIONS

Configuration in `.agentic-security/integrations.yml` (gitignored).

```
       Jira / ServiceNow
              Body builders produce issue payloads; pipe to your
              existing client.

       GitHub Security tab / GitLab
              SARIF auto-written every scan. Upload via
              github/codeql-action/upload-sarif@v3.
              Use /ci --apply to generate a full workflow.

       Slack / Discord
              Webhook digest with critical/high/medium counts +
              top 3 findings. Use /cve-alerts for daily CVE push alerts.

       SIEM (Splunk / Datadog / Elastic)
              One JSON event per finding, with source_attribution and
              rule_version for correlation.

       Two-way ticket sync
              agentic-security tickets sync --provider github|linear|jira
              Creates issues for new findings, closes them when findings
              drop. Idempotent state in .agentic-security/tickets.json.
              GitHub uses the `gh` CLI (no extra auth).
              Linear needs LINEAR_API_KEY + --team-id.
              Jira needs JIRA_BASE_URL, JIRA_EMAIL, JIRA_TOKEN,
              JIRA_PROJECT_KEY.
              --dry-run plans without writing.
              `agentic-security tickets list` prints all tracked tickets.
```

---

## CI/CD

Auto-generated GitHub Actions workflow (recommended):

```
       /ci --apply --severity high --comment
```

Manual CI runner (auto-detects PR base ref):

```bash
       npx @clear-capabilities/agentic-security-scanner ci . --fail-on critical
```

Raw scan with SARIF upload to GitHub Security tab:

```yaml
       - uses: actions/checkout@v4
       - uses: actions/setup-node@v4
         with: { node-version: '24' }
       - run: |
           npx @clear-capabilities/agentic-security-scanner scan . \
             --format sarif --output security.sarif
       - uses: github/codeql-action/upload-sarif@v3
         with: { sarif_file: security.sarif }
```

Pre-commit framework hook (`.pre-commit-config.yaml`):

```yaml
       - repo: https://github.com/Clear-Capabilities/agentic-security
         rev: v0.34.0
         hooks:
           - id: agentic-security
```

Runs `agentic-security ci --baseline HEAD --fail-on high` against
staged changes and blocks the commit on any high or critical finding.

Rule packs for focused scans:

```bash
       agentic-security scan --pack owasp-top-10 .
       agentic-security scan --pack cwe-top-25 .
       agentic-security scan --pack llm-security .
       agentic-security scan --pack supply-chain .
       agentic-security packs list
```

---

## ENVIRONMENT

```
       AGENTIC_SECURITY_OFFLINE=1
              Skip OSV / EPSS / KEV / Scorecard fetches.

       AGENTIC_SECURITY_SCORECARD=1
              Enable OSSF Scorecard enrichment (outbound API calls).

       AGENTIC_SECURITY_POC=1
              Demote findings the engine cannot generate a PoC for.

       DEBUG_BENCH_FILTER=1
              Verbose logging for the benchmark category filter.

       CVE_ALERT_URL
              Slack or Discord webhook URL for /cve-alerts monitor script.
```

---

## COMPLIANCE

Framework attestations (Claude Code slash commands):

```
       /compliance-report nist    NIST AI 600-1 (122 GenAI controls)
       /compliance-report asvs    OWASP ASVS Level 1+2
       /compliance-report llm     OWASP LLM Top 10 (2025)
```

Bill of materials formats:

```bash
       agentic-security scan --format cyclonedx     # CycloneDX 1.6 SBOM
       agentic-security scan --format spdx          # SPDX 2.3
       agentic-security scan --format aibom         # CycloneDX 1.7 ML-BOM
       agentic-security scan --format pbom          # Pipeline BOM
```

Posture management artifacts:

```
       /posture-management --sbom           CycloneDX 1.6 or SPDX 2.3
       /posture-management --aibom          CycloneDX 1.7 ML-BOM (AI components)
       /posture-management --api            API surface map (md/json/openapi)
       /posture-management --license        License allow/deny policy enforcement
       /posture-management --drift          Diff two scan snapshots
       /posture-management --mttr           SLA breach report
```

---

## SEE ALSO

```
       commands/            Slash-command definitions for the Claude Code plugin.
       agents/              Sub-agent system-prompt definitions.
       hooks/               PreToolUse + PostToolUse + SessionStart hook scripts.
       scripts/             Compliance helpers + standalone Python scripts:
                              rotate-secret-auto.py
                              audit-llm-cost.py
                              risk-in-dollars.py
                              generate-disaster.py
                              daily-checkin.py
                              attestation-onepager.py
                              generate-privacy.py
                              attestation-page.py
                              predeploy-gate.sh
                              run-poc-tests.py
       scripts/data/        Data files (dollar-risk-bands.json, etc.).
       scripts/validator/   /validate-findings backing infrastructure
                              (detect-framework.mjs, run-test.mjs,
                              chain_rules.json, post_exploit_templates.json,
                              risk-context.mjs, refusal-classes.mjs, etc.).
       .claude-plugin/      Plugin manifest.
       CLAUDE.md            Codebase conventions and architecture.
       LICENSE              Full license terms.
```

---

## AUTHOR

Built by **[ClearCapabilities.Com](https://clearcapabilities.com)**.
Maintainer: Ross Young <ross@clearcapabilities.com>.

---

## BUGS

Report at <https://github.com/Clear-Capabilities/agentic-security/issues>.

---

# TUTORIAL

The following exercises walk through the tool from first scan to auditor-ready
compliance evidence. Work through them in order; each exercise builds on the
state left by the previous one.

---

## Exercise 1 — First scan

**Goal:** run a full scan, understand the output, and know what files were
written.

```
/scan --all
```

Or from the CLI:

```bash
agentic-security scan .
```

**What to look for:**

- The one-line verdict at the top: `SAFE TO DEPLOY` (green) or `NOT SAFE` (red).
- The severity breakdown: `critical=N high=N medium=N low=N`.
- The three output files written to `.agentic-security/`:
  - `findings.json` — full machine-readable results
  - `findings.sarif` — for GitHub / GitLab Security tabs
  - `findings.csv` — for spreadsheet or executive review
  - `scan-history.json` — automatically appended for `/security-trend`

**Checkpoint:** open `.agentic-security/findings.json` and confirm it has a
`findings` array. Note one finding ID — you'll use it in Exercise 3.

---

## Exercise 2 — Focused scans

Each pillar can be run independently.

**Dependency CVE audit only:**

```
/scan --sca
```

Backed by OSV.dev. Look for `kev: true` entries — these are on the CISA Known
Exploited Vulnerabilities catalog and should be treated as P0.

**Secrets sweep:**

```
/scan --secrets
```

Covers 60+ provider patterns (AWS, GCP, GitHub, Stripe, etc.) and high-entropy
heuristics. Any hit: rotate immediately with `/rotate-secret`, move to a secrets
manager with `/vault-wizard`, audit git history with `git log -S <value>`.

**Auth/AuthZ deep audit:**

```
/scan --authz
/audit --target auth
```

The `--authz` flag covers JWT algorithm confusion, hardcoded JWT secrets, missing
`algorithms:[]`, OAuth2 PKCE, redirect_uri validation, session fixation, and
multi-tenant queries. `/audit --target auth` surfaces provider-specific misconfigurations
(Clerk, NextAuth, Auth0, Lucia, Better Auth).

**Database security:**

```
/audit --target db
```

Supabase-aware: RLS disabled, service-role key exposed client-side, admin API
in browser code, bypassed row-level security, raw pg connections in handlers.

**AI/LLM app security:**

```
/scan --logic
/audit --target prompt
```

`--logic` invokes the business-logic reviewer. `/audit --target prompt` surfaces
LLM-specific risks: system prompt contamination, missing max_tokens, model
output used as SQL/exec input (second-order injection), no output validation.

**MCP server audit:**

```
/scan --mcp
```

Reads `claude_desktop_config.json`, `.mcp.json`, `mcp_servers.json`. Flags
untrusted install vectors, hardcoded API keys, filesystem servers with broad
access, dangerous capability names.

**GitHub Actions pipeline audit:**

```
/scan --pipeline
```

Finds floating tags (`@latest`, `@main`), secret echoes, `write-all`
permissions, OIDC misconfigurations, `github.event.*` script injection.

**Platform infrastructure:**

```
/audit --target deploy
```

Checks your actual deployment config files: Vercel headers, Railway health
checks, Fly.io HTTPS, Netlify headers, Cloudflare Workers compat date.

**Diff review (before merging a branch):**

```
/scan --diff
/scan --diff --since main
```

Scores the git diff by architectural risk. Risk levels:
- `critical` — auth removed, new shell call → run `/validate-findings` + `/fix --one`
- `high` → run `/validate-findings`
- `medium`/`low`/`none` → safe to merge

---

## Exercise 3 — Understand a finding

Use the finding ID you noted in Exercise 1.

```
/explain <finding-id>
```

You can also explain by CWE or by name fragment:

```
/explain CWE-89
/explain SQL Injection
```

The output is a plain-English card with four sections:
1. What this means
2. How an attacker abuses it
3. Worst case if not fixed
4. How to fix it

**Advanced:** compare the plain-English explanation to the raw finding fields:

```bash
jq '.findings[] | select(.id == "<your-id>")' .agentic-security/findings.json
```

Fields to understand: `cwe`, `toxicityScore`, `kev`, `owaspCategory`.

---

## Exercise 4 — Validate a finding (optional)

Before applying a fix, confirm the finding is real.

```
/validate-findings <finding-id>
```

The PoC generator reads the affected file, constructs a concrete exploit payload,
and emits a Playwright regression test. If it cannot construct a payload it emits
`PROBABLE_FP` — use this to suppress false positives with justification.

---

## Exercise 5 — Apply fixes

Apply a fix to a single finding:

```
/fix --one <finding-id>
```

The security-fixer agent reads the affected file, its imports, the auth
middleware, the ORM/DB helpers it calls, and the route registration — then
applies the fix in the idiom of your specific stack (not a generic template).

Batch-fix all critical and high findings:

```
/fix --all --high
```

Bundle all fixes into a pull request (dry-run by default):

```
/fix --pr --severity high --apply
```

---

## Exercise 6 — Security trend

Run a second scan after applying fixes, then view the trend:

```
/scan --all
/security-trend
```

The trend view shows a sparkline bar chart, the number of findings introduced
vs. fixed, and a net delta. Green = improving, red = regressing.

---

## Exercise 7 — Harden the project

Apply safe automated infrastructure improvements:

```
/harden
```

Then review the changes:

```bash
git diff
```

The command prints what it applied, what it skipped (already configured), and
what failed. Review before committing.

---

## Exercise 8 — Stack-specific playbook

Get a checklist tailored to your exact stack:

```
/stack-playbook
```

For a Next.js + Supabase + Stripe app, this surfaces ~30 opinionated items
specific to how those three systems interact — not generic OWASP advice.

---

## Exercise 9 — Set up CI security gate

Generate and apply a GitHub Actions workflow:

```
/ci --apply --severity high --comment
```

This creates `.github/workflows/security.yml`. Push it, open a PR, and the
scanner runs automatically — failing the build if critical/high findings are
introduced and posting a review comment with the summary.

---

## Exercise 10 — Generate compliance evidence

```
/compliance-report nist
```

Outputs an auditor-ready mapping of scan findings to NIST AI 600-1 controls.
Also available: `/compliance-report asvs` (OWASP ASVS Level 1+2) and
`/compliance-report llm` (OWASP LLM Top 10). Use `/security-attestation` to
generate the investor-ready paragraph and README badge.

---

## Exercise 11 — Set up CVE monitoring

```
/cve-alerts --slack https://hooks.slack.com/... --apply
```

Creates `scripts/cve-monitor.mjs` and `.github/workflows/cve-alerts.yml`.
Add `CVE_ALERT_URL` as a GitHub Actions secret, enable the workflow, and
your team gets notified at 8am UTC whenever a new CVE drops for any of your
installed packages.

---

## Exercise 12 — Turn on the real-time bodyguards

The bodyguard hooks give you protection at the moment code is written or
commands are run — distinct from the post-edit scanner. Two hooks, both
configurable:

```
/ai-bodyguard warn          # try in warn mode first (default)
/destructive-guard block    # default — blocks rm -rf, force-push to main, etc.
```

After running each, the relevant `.agentic-security/<hook>.json` is
written. Verify by trying a known-bad operation in Claude Code:

- For `/ai-bodyguard`: ask Claude to "write a Next.js route that takes a
  user id from the URL and returns SELECT * FROM users WHERE id = ${id}".
  In warn mode you'll see a stderr explanation. In block mode the edit
  is refused with exit 2.
- For `/destructive-guard`: ask Claude to run `rm -rf /` or
  `DROP TABLE users`. The hook blocks the call with a plain-English
  reason + the safer alternative.

When you're confident, escalate `/ai-bodyguard` from `warn` → `block`.

---

## Exercise 13 — Cap your LLM costs

Critical before you ship any AI feature.

```
/audit --target llm-cost                  # audit
/audit --target llm-cost --apply          # auto-patch missing max_tokens
/audit --target llm-cost --generate-middleware   # rate-limit per IP per minute
/audit --target llm-cost --generate-tracker --daily-cap-dollars 50
```

Each step is a separate decision. Review with `git diff` before
committing the patches.

---

## Exercise 14 — Generate the customer-facing trust artifacts

When an enterprise prospect asks "are you secure?" you want three
artifacts ready:

```
/security-attestation --format page --contact security@myapp.com --canonical-url https://myapp.com
/security-attestation --format onepager --company "My App Inc." --contact security@myapp.com
/generate --type privacy --jurisdiction US-CA --generate-banner
```

After these run, you have:

- `public/.well-known/security.txt` — the file every infosec team checks
- `app/security/page.tsx` (or vanilla HTML) — your live-posture trust page
- `SECURITY.md` — sales-ready one-pager
- `PRIVACY.md` — privacy policy tailored to your actual data processors
- `components/CookieBanner.tsx` — React consent banner matched to your
  analytics

Convert SECURITY.md to PDF for sales emails:

```bash
pandoc SECURITY.md -o SECURITY.pdf --pdf-engine=xelatex
```

---

## Exercise 15 — Have a disaster plan BEFORE you need one

```
/generate --type disaster
```

Writes `DISASTER.md` with stack-specific incident-response commands.
Bookmark it. Re-run when your stack changes (the runbook is generated,
not authored — it goes stale fast).

---

## Exercise 16 — Block accidental prod deploys

```
/ci --predeploy install
```

Default config: blocks on any critical finding OR any KEV-listed
dependency OR if last scan is older than 24h. Tighten by setting
`block_on: ["critical", "high"]` in `.agentic-security/predeploy-gate.json`.

In your terminal, source the shell wrapper for protection outside Claude
Code:

```bash
echo 'source ${CLAUDE_PLUGIN_ROOT}/scripts/predeploy-gate.sh' >> ~/.zshrc
```

Verify:

```bash
vercel deploy --prod
# 🚦  agentic-security pre-deploy gate
#     ✅  Safe to deploy. Proceeding...
```

Bypass once: `AS_GATE_OVERRIDE=1 vercel deploy --prod`.

---

## Exercise 17 — Wire up the daily check-in

```
/daily-checkin --setup
```

Interactive prompt for Slack/Discord webhooks. Then add to your crontab
or GitHub Actions schedule (see `/daily-checkin --crontab` for the line).

The digest shows what changed since yesterday — not just today's totals.
State persists in `.agentic-security/daily-checkin-last.json`.

---

## SAST MODULE REFERENCE

The scanner's SAST layer is composed of independently-loadable modules.
Each exports one or more `scan*()` functions returning `Finding[]`.

| Module | File | Key detections |
|--------|------|----------------|
| Core taint | `engine.js` | SQL injection, XSS, command injection, SSRF, path traversal, IDOR, mass assignment, prototype pollution, ReDoS, timing oracle |
| Auth/AuthZ | `sast/authz.js` | JWT alg:none, JWT hardcoded secret, missing algorithms, OAuth PKCE, redirect_uri allowlist, session fixation, multi-tenant scope |
| Auth provider | `sast/auth-provider.js` | Clerk/NextAuth/Auth0/Lucia misconfig: trustHost, allowDangerousEmailAccountLinking, missing NEXTAUTH_SECRET, weak secrets, CSRF disabled |
| Business logic | `sast/logic.js` | IDOR, state-machine bypasses, coupon abuse, race conditions |
| Client-side | `sast/client-side.js` | dangerouslySetInnerHTML w/o sanitizer, localStorage tokens, open redirect, postMessage no-origin, client eval |
| C/C++ | `sast/cpp.js` | Buffer overflow, strcpy/sprintf, integer overflow, use-after-free |
| C# | `sast/csharp.js` | Deserialization, SQL injection |
| DB/RLS | `sast/db-rls.js` | Supabase service-role key exposure, auth.admin client-side, bypassRowLevelSecurity, SQL tables without RLS, raw pg in handlers |
| Env hygiene | `sast/env-hygiene.js` | NEXT_PUBLIC_ secret vars, .env.example real values, hardcoded fallbacks, dotenv in non-entry files |
| Go | `sast/go-extended.js` | Go-specific security patterns |
| Host header | `sast/host-header.js` | Host header injection |
| Java deserialization | `sast/java-deserialization.js` | Unsafe Java deserialization |
| JNDI | `sast/jndi.js` | JNDI injection (Log4Shell family) |
| JWT expiry | `sast/jwt-exp.js` | JWT without expiry, weak signing |
| LLM | `sast/llm.js` | Prompt injection, LLM safety patterns |
| LLM OWASP | `sast/llm-owasp.js` | OWASP LLM Top 10 (2025) coverage |
| MCP audit | `sast/mcp-audit.js` | MCP / agent-tool security |
| Model load | `sast/model-load.js` | torch.load, pickle, trust_remote_code |
| Pipeline | `sast/pipeline.js` | CI/CD pipeline integrity |
| Prompt firewall | `sast/prompt-firewall.js` | User input in system prompt, missing max_tokens, LLM output→SQL/exec, no output validation |
| Prompt template | `sast/prompt-template.js` | Prompt template injection |
| Rate limit | `sast/rate-limit.js` | Missing rate limiting on auth/AI/payment/contact endpoints |
| Rust | `sast/rust.js` | Unsafe blocks, memory patterns |
| Solidity | `sast/solidity.js` | Smart contract vulnerabilities |
| Webhook | `sast/webhook.js` | Missing Stripe/GitHub/Clerk/Svix/Resend/Twilio signature verification |
| XXE | `sast/xxe.js` | XML External Entity injection |
| Zip-slip | `sast/zip-slip.js` | Path traversal in archive extraction |

---

## BENCHMARK HARNESS

The scanner is evaluated against structured ground-truth benchmarks. Every
rule ships with a `vulnerable/` + `clean/` fixture pair in `test/fixtures/`.

Run benchmarks locally:

```bash
cd scanner && npm run bench               # in-repo fixture suite
npm run bench:realworld                    # all real-world apps
npm run bench:realworld -- --app nodegoat
npm run bench:realworld -- --app juice-shop
npm run bench:llm-goats                    # LLM/AI adversarial suite
```

**Always run in blind mode** to measure the engine instead of label leakage
from the test corpora:

```bash
node test/benchmark/realworld/bench-realworld.js --app sard-juliet-java --blind
node test/benchmark/realworld/bench-realworld.js --all --blind
```

`--blind` produces a sanitized copy of the corpus (FLAW / POTENTIAL FLAW
comments stripped, OWASP template marker comments removed, `@WebServlet`
category prefixes opaqued) and sets `AGENTIC_SECURITY_BLIND_BENCH=1` so the
scanner disables every rule that reads benchmark answer keys:

- `juliet-shape.js` — emits one finding per `/* POTENTIAL FLAW */` marker
- `applyJuliet*Suppressions` — folder→family suppression
- `_javaWebServletCategory` — reads `@WebServlet("/cmdi-NN/…")` URL prefix
- `_hasOwasp*Safe` template-marker suppressors in `java-bench-extras.js`
- OWASP dead-branch + Juliet OIS+BAIS suppressors inside `findSuppressionLines`

What's still active under blind mode (genuine static analysis):

- All `cpp.js` / `java*.js` / `csharp.js` family rules
- `cpp-dataflow.js` (intra-procedural use-after-free / null-deref / alloc-size)
- `java-collection-passthrough.js` (real Java taint propagation)
- ARGV_FORM / PARAMETERIZED_PS / XSS-helper-sanitizer recognition (real safe
  patterns that exist in any codebase, not just benchmarks)
- `java-ast-folding.js` (AST-level constant folding)

Always report precision, recall, and raw TP/FP/FN per family. A bare summary
metric on a benchmark you tuned against is uninformative; the per-family
breakdown shows where the engine is genuinely strong vs. where it's empty.

When adding new rules:
1. Gate on at least 2 signals before firing (never single-regex)
2. Include `_NONPROD_RE` to exclude test/fixture/spec paths
3. Verify with `npm run bench` AND `--blind` before committing
4. Never read folder names, file paths, or comment markers that exist only
   in benchmark corpora — that's label leakage and produces inflated numbers

