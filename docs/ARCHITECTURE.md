# Architecture

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
       │  Deep Engine — opt-in via AGENTIC_SECURITY_DEEP=1                    │
       │                                                                      │
       │  ir/        Intermediate Representation — normalized graph between  │
       │             source and analysis. JS/TS · Python · Java frontends     │
       │             emit shared CFG + cross-file callgraph +                 │
       │             SSA + class-hierarchy (CHA + RTA)                        │
       │  dataflow/  forward + backward interproc taint · access-paths ·      │
       │             receiver-context · higher-order · implicit-flow ·        │
       │             RHS tabulation · symbolic-exec (numeric range domain) ·  │
       │             async-sequencing · exception-flow · sanitizer-proof ·    │
       │             string-domain · polyglot (SQL/JNDI/LDAP/HTML/shell) ·    │
       │             incremental (file-hash + summary cache)                  │
       │  llm-validator/  optional Layer-3 LLM accept/reject/escalate         │
       └──────────────────────────────────┬──────────────────────────────────┘
                                          │
                       ┌──────────────────▼───────────────┐
                       │   posture/ enrichment pipeline    │
                       │  triage · suppressions · packs    │
                       │  EPSS · blast-radius · KEV        │
                       │  scorecard · custom-rules         │
                       │  schema-aware bridges · iac-reach │
                       │  cross-lang openapi/grpc/graphql  │
                       │  /orm/queues · confidence·learning│
                       └──────────────────┬───────────────┘
                                          │
                       ┌──────────────────▼───────────────┐
                       │          scan assurance           │
                       │  coverage-ledger · scan-health    │
                       │  per-file × per-analyzer roll-up  │
                       │  egress-policy · allow/deny gate  │
                       │  on every outbound LLM call       │
                       └──────────────────┬───────────────┘
                                          │
                       ┌──────────────────▼───────────────┐
                       │           reporters               │
                       │  CLI · JSON · SARIF · JUnit · CSV │
                       │  HTML · CycloneDX · SPDX · PBOM   │
                       │  AI-BOM · ship-verdict · pro-table│
                       │  OSCAL                            │
                       └──────────────────┬───────────────┘
                                          │
              ┌───────────────────────────┼─────────────────────────┐
              ▼                           ▼                         ▼
     last-scan.json              SARIF → GitHub Security    tickets sync
     (drives /fix, /report,      Tab / DefectDojo /         (GH Issues /
      /chain, /trend, /badge)    pipeline integrations      Linear / Jira)

       Sideband interfaces:
         mcp/        JSON-RPC 2.0 server — 17 tools any MCP-speaking agent
                     (Claude Code / Cursor / Cline / Aider / Codex) can call.
                     Hash-chained audit log; OWASP MCP top-10 hardened.
         lsp/        Language-Server-Protocol — powers JetBrains, Neovim, and
                     VS Code plugins via textDocument/publishDiagnostics.
         hooks/      5 Claude Code hook event types: SessionStart,
                     UserPromptSubmit (alias redirect + model-cost advisor,
                     one dispatcher process), PreToolUse (bodyguard +
                     conversation-context + cache-invalidator, one dispatcher
                     process — the security-critical bodyguard block runs
                     first and short-circuits the advisory hooks),
                     PostToolUse (post-edit scan, offers a one-tap fix),
                     Stop (drift check).
         agents/     9 sub-agents: poc-generator, fixer, triager, sca-
                     triager, chain-synthesizer, logic-reviewer, material-
                     change, malware-analyst, refactor-cleaner.
```

## Data Flow Explorer (separate subsystem)

A deliberately isolated second pipeline — not a mode of the engine above.
Where the diagram above answers "is this line dangerous," this one answers
"where does this piece of sensitive data actually go, across my whole
architecture, and what protects it at every hop." It shares only pure,
stateless utilities with the taint engine (never live taint state), and is
opt-in per scan via `AGENTIC_SECURITY_LINEAGE_DEEP=1`.

```
                     ┌──────────────────────────────────┐
                     │   fileContents + a real scan     │
                     └──────────────────┬───────────────┘
                                        │
     ┌──────────────────────────────────▼──────────────────────────────────┐
     │  scanner/src/lineage/  — the DataFlowGraph v1 contract + engines     │
     │                                                                      │
     │  schema.js / ids.js / protection.js / classification.js              │
     │             the graph contract: stable content-hash IDs, the        │
     │             transit/at-rest/handling protection-verdict model,      │
     │             data classes (PII/PHI/PCI/financial) + AI contexts      │
     │  field-identity engine  interprocedural, context-sensitive taint    │
     │             purpose-built for this graph (k-CFA summaries, its own  │
     │             fixed-point worklist) — never the SAST dataflow/        │
     │             engine's own live state                                │
     │  path provenance DAG   why a field reached a sink, not just that   │
     │             it did — bounded backward reconstruction, truncation   │
     │             honestly distinguished from "no flow"                  │
     │  source/sink/transform registries   reclassify the existing SAST/  │
     │             SCA catalogs into the graph's own vocabulary           │
     │  graph-builder.js   projects the above into nodes/edges/flows —    │
     │             one node per REGISTRY DECISION, so node count is       │
     │             bounded by taxonomy, not repository size               │
     │  protection analyzers   transit (TLS presence+validity) ·          │
     │             at-rest (encryption-before-store) · handling           │
     │             (mask/hash/tokenize/encrypt — never synonyms) ·        │
     │             policy verdict (operator-declared sink permissions)    │
     └──────────────────────────────────┬──────────────────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              ▼                         ▼                         ▼
   ┌───────────────────┐   ┌────────────────────────┐  ┌──────────────────────┐
   │ scanner/src/server/│   │ export-*.js / scripts/  │  │ decision-intelligence │
   │ agentic-security   │   │ dataflow export         │  │ extensions            │
   │ explore — local,   │   │ png/pdf/svg/json/csv/   │  │ scenario (what-if     │
   │ read-only,         │   │ html/dpia/ropa/         │  │ simulation) · impact  │
   │ loopback-only HTTP │   │ briefing/recipients/    │  │ (blast radius) ·      │
   │ server + a         │   │ coverage                │  │ remediation (hash-    │
   │ zero-build-step    │   │                          │  │ chained ledger) ·     │
   │ frontend prototype │   │                          │  │ observations/twin     │
   │ (4 linked views)   │   │                          │  │ (runtime corroboration│
   │                    │   │                          │  │ , metadata-only) ·    │
   │                    │   │                          │  │ federate (declared    │
   │                    │   │                          │  │ cross-repo edges)     │
   └────────────────────┘   └──────────────────────────┘  └───────────────────────┘
```

Every write surface above (`governance propose-edit`, `remediation open`,
`federate declare`) goes through the same reviewable contract: preview,
version guard, backup, hash-chained audit event — never a silent
hand-edit. Full command reference — [CLI reference](reference/cli.md);
narrative walkthrough — [Data Flow Explorer guide](guides/data-flow-explorer.md).

---

**Methodology layer.** On top of the deterministic engine, a set of default-on posture
annotators add agentic-hunter discipline (see the Agentic Methodology PRD (removed post-implementation)):
`falsification` (refute each taint finding — demote the ones a control blocks, recall-
preserving), `entrypoint-inventory` (attack-surface coverage ledger on `scan.entrypointInventory`),
`root-cause-sweep` (find sibling instances of a confirmed bug, on `scan.rootCauseSweep`),
`model-routing` (per-CWE dispatch-model hint on `finding.dispatchModel`), and `fix-honesty-gate`
(residual-risk guard + FULL/MITIGATION/WORKAROUND completeness tiers on applied fixes). A
`util/untrusted.js` helper plus `docs/AGENT_THREAT_MODEL.md` harden the agent surface against
untrusted scanned content. A judged real-world recall harness lives at `bench/realworld-recall/`.

**OSCAL.** One of the reporters above emits NIST OSCAL 1.1.2 —
specifically `assessment-results` documents only, never `catalog`,
`profile`, `component-definition`, `system-security-plan`, or
`assessment-plan`/POA&M, because only `assessment-results` describes
"something examined a system and reports what it found." Every control
verdict is binary — `satisfied` or `not-satisfied` — so a control this
run never assessed gets no finding at all, rather than a fabricated
verdict; that honesty constraint is deliberate and load-bearing, not an
accident of the schema. Deterministic, produced from `scan --format
oscal` or `compliance --format oscal`. Full detail: [OSCAL](OSCAL.md).

**Scan assurance.** `pipeline/coverage-ledger.js` computes a per-file ×
per-analyzer verdict — `completed`, `failed`, `timed_out`, or
`skipped_by_policy` — for every one of the 121 wrapped detectors, so
coverage is a computed fact rather than an assumption; `pipeline/scan-health.js`
rolls that up, together with annotator errors, deep/lineage status, and
feed freshness, into one `scan.scanHealth.status` of `complete` or
`partial`, so a scan that hit trouble never reports the same shape as a
clean one just because it happened to find nothing. Full walkthrough:
[Scan health](walkthroughs/scan-health.md).

**Egress policy.** Every outbound call this codebase makes to an LLM
provider — from `llm-validator/`, `discovery/`, the posture LLM
annotators, and the SCA function extractor — is evaluated by
`egress/policy.js` before the prompt is built and before any HTTP client
dials out. `mode: deny`/`local-only`, provider/model/role/region/path
allow-deny lists, a max-context-token cap, and a regulated-profile
approved-provider check can each independently deny a call; a denied
call produces no network request, only a sanitized decision object.
Full walkthrough: [Model egress](walkthroughs/model-egress.md).

The whole engine ships as a single ~3.6 MB ESM bundle (`dist/agentic-security.mjs`). Pure Node >= 24. No native deps. No daemon by default — `scan --watch` opts into a long-running incremental-rescan process.
