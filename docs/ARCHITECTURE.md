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

       Sideband interfaces:
         mcp/        JSON-RPC 2.0 server — 12 tools any MCP-speaking agent
                     (Claude Code / Cursor / Cline / Aider / Codex) can call.
                     Hash-chained audit log; OWASP MCP top-10 hardened.
         lsp/        Language-Server-Protocol — powers JetBrains, Neovim, and
                     VS Code plugins via textDocument/publishDiagnostics.
         hooks/      4 Claude Code hook event types: SessionStart,
                     PreToolUse (bodyguard + destructive-guard),
                     PostToolUse (post-edit scan), Stop (drift check).
         agents/     8 sub-agents: poc-generator, fixer, triager, chain-
                     synthesizer, logic-reviewer, material-change, malware
                     -analyst, refactor-cleaner.
```

The whole engine ships as a single 2.6 MB ESM bundle (`dist/agentic-security.mjs`). Pure Node >= 24. No native deps. No daemon. No background process.
