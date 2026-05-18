# PRD: agentic-security → Sentinel-Parity Evolution

| Field | Value |
|---|---|
| Document Status | Draft v1.0 |
| Last Updated | 2026-05-18 |
| Author | Ross Young (ross@clearcapabilities.com) |
| Source | Gap analysis of agentic-security v0.39.2 against the Sentinel PRD |
| Review Cycle | Per-phase exit |

---

## 1. Executive Summary

This PRD specifies the work required to evolve the existing `agentic-security` Claude Code plugin from a high-coverage **pattern + heuristic** scanner into a hybrid **symbolic-dataflow + LLM-reasoning + auto-remediation** platform on par with the Sentinel PRD. The plugin already has broad surface area (50+ slash commands, 30+ SAST modules, MCP server, dependency CVE/KEV/EPSS, compliance attestations, vibecoder UX). The remaining work is depth: a real code graph, an interprocedural taint engine, an inline LLM validator stage, cross-language flow tracking, and a closed-loop remediation pipeline.

The target is **F1 ≥ 0.90 on OWASP Benchmark v1.2** and **F1 ≥ 0.85 on an internal CVE-replay benchmark** across the top 8 GA languages, while preserving the plugin's existing vibecoder-lane ergonomics.

This is a multi-quarter program. Work is sequenced so each phase ships a usable product, not a half-built foundation.

### Implementation status (as of 2026-05-18)

| Goal | Status |
|---|---|
| G1 OWASP Benchmark F1 ≥ 0.90 (blind, strict) | **Met on the benchmark** (F1 = 0.907). **Real-world Java generalization NOT validated**. The precision lifters that close this number are tuned to OWASP-Benchmark file shape — see `bench/README.md` for the explicit caveat. |
| G1 CVE-replay F1 ≥ 0.85 | **NOT delivered**. Corpus = 1 synthetic starter entry. Populating to 500 hand-labeled entries is a labeling project that has not been funded. Do not market this as delivered. |
| Per-language F1 across 8 GA languages | **NOT measured** for any language other than Java (OWASP Benchmark v1.2 is Java-only). |
| Performance @ 1M LoC | **NOT measured**. PRD §9.1 targets unverified at scale. |

---

## 2. Problem Statement

The current scanner has excellent breadth — many vuln classes, many languages, many integrations — but the analysis core is shallow:

- **No IR**, no call graph, no SSA, no path-feasibility checking → recall ceiling on bugs that cross function boundaries.
- **LLM is user-invoked, not pipelined** (`/validate-findings`, `security-poc-generator` agent) → finding precision is bound to regex specificity, not semantic reasoning.
- **No cross-language taint** → flows that cross HTTP/gRPC/GraphQL/SQL boundaries terminate at the boundary.
- **Fix loop is open** — `/fix` applies patches but does not re-scan, run project linters on the patch, or auto-downgrade to a fix plan when verification fails.
- **No language frontends for Kotlin, Ruby, PHP** beyond file-extension detection.
- **Slash-command UX gaps**: no `/triage` interactive mode, no `/why-not <CWE>` recall spot-check, no `/query` SentQL prompt, no streaming UX, no pre-commit/pre-push git hooks.

These gaps are the constraint on hitting F1 ≥ 0.90; no amount of additional regex rules will close them.

---

## 3. Goals & Non-Goals

### 3.1 Goals

- **G1**: Ship a real Layer-1 code graph (AST + CFG + PDG + call graph + SSA) for Python, JavaScript/TypeScript, and Java by end of Phase 1.
- **G2**: Ship an interprocedural symbolic taint engine (Layer 2) with field/index/context sensitivity and SMT-backed path feasibility for the same three languages by end of Phase 2.
- **G3**: Ship an inline LLM validator stage (Layer 3) that emits a calibrated 0.0–1.0 confidence score per finding, with deterministic caching by `(path, code, prompt, model-version)` hash.
- **G4**: Close the remediation loop — every `/fix` re-scans the patched code, runs the project's existing linters, and either confirms or auto-downgrades to a "fix plan."
- **G5**: Cross-language taint tracking across **HTTP/REST (OpenAPI-aware)**, **gRPC (`.proto`-aware)**, **GraphQL**, and **SQL (ORM round-trip)**.
- **G6**: Add SAST modules for **Kotlin**, **Ruby**, **PHP**.
- **G7**: Add slash commands `/triage` (interactive), `/why-not <CWE>` (recall spot-check), `/query` (SentQL + NL→DSL), plus streaming finding UX.
- **G8**: Hit F1 ≥ 0.90 on OWASP Benchmark v1.2 and F1 ≥ 0.85 on an internal 500-CVE replay suite.

### 3.2 Non-Goals (this PRD)

- Managed cloud service / SOC 2 / FedRAMP. The plugin remains self-hosted; cloud is a separate product decision.
- Full formal verification — Sentinel-class "high confidence," not theorem-proven.
- DAST, CSPM, runtime EDR.
- Replacing the vibecoder-lane commands. Those are net-positive and remain.
- Mobile-specific (Android intent / iOS URL scheme) analyzers — Phase 4+ in Sentinel; out of scope here.
- C/C++ pointer-analysis investment — separate program.
- Swift, Rust beyond the current module — Phase 4+.

---

## 4. Architecture (target state)

Four cooperating layers. Each is opt-in via config so the existing pattern scanner remains available for fast, offline, deterministic runs.

```
┌─────────────────────────────────────────────────────────────┐
│ Claude Code plugin (slash commands, MCP, agents, hooks)     │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ Orchestrator (scanner/src/runScan.js, engine.js)            │
└──────────────────────────┬──────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
┌──────▼──────┐  ┌─────────▼────────┐  ┌──────▼──────────┐
│ Code Graph  │  │  Taint Engine    │  │ LLM Validator   │
│ (Layer 1)   │──│   (Layer 2)      │──│   (Layer 3)     │
│ NEW         │  │   NEW            │  │   NEW (inline)  │
└─────────────┘  └──────────────────┘  └─────────┬───────┘
                                                  │
                                       ┌──────────▼─────────┐
                                       │ Remediation        │
                                       │ Synthesizer (L4)   │
                                       │ EXTEND /fix        │
                                       └────────────────────┘
```

Existing modules — pattern SAST, SCA, secrets, posture, MCP server, integrations, compliance — remain as the **fast path** and as a fallback when Layer 1–3 are unavailable. The new layers are additive, not a rewrite.

---

## 5. Functional Requirements

### 5.1 Layer 1 — Code Graph & IR (NEW)

**FR-L1-1**: Implement a unified IR with AST, CFG, PDG, and SSA representations.
- New directory: `scanner/src/ir/`
- One submodule per frontend: `ir/python/`, `ir/js/`, `ir/java/`
- Reuse battle-tested parsers: `tree-sitter` for JS/TS/Python; `javaparser` (via JNI shim or `javalang`-style Node port) for Java
- Output a stable IR JSON schema persisted under `.agentic-security/ir-cache/<sha256-of-file>.json`

**FR-L1-2**: Inter-procedural call graph builder.
- Virtual dispatch resolution via type lattice
- Framework-entry-point recognition (Flask `@route`, Spring `@RequestMapping`, Express `app.get`, FastAPI `@app.get`, Next.js route conventions) lives in the IR layer, not per-rule
- Output: `CallGraph` with nodes, edges, and entry-point set

**FR-L1-3**: Type inference for Python and TS (gradual/structural).
- For TS, use the TypeScript compiler API directly
- For Python, infer from annotations + simple flow-based propagation (no full Hindley-Milner)

**FR-L1-4**: IR cache invalidation by file content hash. Re-parse only on change.

**FR-L1-5**: GA languages for Phase 1: Python, JavaScript/TypeScript, Java. Kotlin, Ruby, PHP follow in Phase 3 (FR-L1-6).

**FR-L1-6**: Kotlin frontend reuses Java IR via Kotlin-to-Java bytecode bridge; Ruby and PHP via tree-sitter.

### 5.2 Layer 2 — Symbolic Dataflow Engine (NEW)

**FR-L2-1**: Forward + backward taint propagation engine.
- New directory: `scanner/src/dataflow/`
- Sources, sinks, sanitizers configured in `scanner/src/dataflow/catalog/` — start with ~500 framework/library entries
- Field-sensitive: `obj.tainted_field` flows independently of `obj.clean_field`
- Index-sensitive: `arr[0]` vs `arr[1]` tracked separately when indices are constants
- Context-sensitive: k-CFA configurable (default k=1)

**FR-L2-2**: Path-sensitive feasibility check via SMT.
- Bind to a Z3 binding (`z3-solver` npm package or shell out to `z3`)
- Paths whose path conditions are UNSAT are pruned before they become findings
- Configurable timeout per path; fall back to "assume feasible" on timeout (logged)

**FR-L2-3**: Heap modeling sufficient for collections.
- Map/Dict: key-sensitive when key is a string literal; field-summary otherwise
- List/Array: element summary; index-sensitive when indices are constants
- Sets: element summary

**FR-L2-4**: Recall-first tuning. Layer 2 emits candidate findings with no FP filtering; Layer 3 prunes.

**FR-L2-5**: Graceful fallback. When Layer 1 IR is missing for a file, Layer 2 falls back to the existing pattern scanner with explicit `low_confidence: true` flag.

### 5.3 Layer 3 — LLM Validator (NEW)

**FR-L3-1**: Validator runs per candidate finding from Layer 2.
- Input: source-to-sink path, surrounding code context (configurable line window, default ±20), framework prior
- Prompt template versioned and pinned per release
- Output: `{verdict: accept|reject|escalate, confidence: 0.0-1.0, reasoning: string}`
- New module: `scanner/src/llm-validator/`

**FR-L3-2**: Calibrated combined confidence score on every finding.
- `combined = w1 * layer2_score + w2 * llm_confidence`
- Weights calibrated on the internal CVE-replay benchmark; recalibrated each release

**FR-L3-3**: Deterministic cache.
- Key: `sha256(file_content || path_signature || prompt_version || model_id)`
- Persisted at `.agentic-security/llm-cache/<key>.json`
- Cache hit → byte-identical output; cache miss → call model

**FR-L3-4**: Layer-2 path required for "accept." LLM-only findings (e.g., from semantic bug-class detection) ship with explicit `llm_only: true` and a lower-severity badge.

**FR-L3-5**: Source/sink/sanitizer discovery sub-pipeline.
- One-shot per repo: LLM proposes candidates from the codebase, persisted to `.agentic-security/discovered-catalog.yml`
- Subsequent runs use the discovered catalog plus the built-in one

**FR-L3-6**: Graceful degradation. When no LLM is configured or the call fails, scanner emits findings labeled `unvalidated: true` and clearly flags reduced precision in `/show-findings`.

**FR-L3-7**: Per-CWE precision/recall metrics persisted to `.agentic-security/validator-metrics.json` after each scan that has a ground-truth set.

### 5.4 Layer 4 — Remediation Synthesizer (EXTEND existing `/fix`)

**FR-L4-1**: Patch generation bounded to ≤ 3 files and ≤ 100 LoC.
- When the fix exceeds those bounds, emit a **fix plan** (numbered steps with file/line anchors) instead of a patch

**FR-L4-2**: Every patch ships with a synthesized regression test.
- Reuses `/security-tests` infrastructure
- Test must fail on pre-fix code and pass on post-fix code

**FR-L4-3**: Sandboxed PoC generation (already shipped via `security-poc-generator`).
- Confirm PoC labels and refuses-to-execute-against-live-infra invariants hold

**FR-L4-4**: **Closed-loop verification.** After applying a patch in a scratch worktree:
- Re-run Layers 1–3 on the patched code
- Confirm the original finding is gone
- Confirm no new findings of equal or higher severity were introduced
- Run the project's existing linters on the patched files (detect via `eslint`, `ruff`, `mypy`, `checkstyle`, `golangci-lint`, etc. presence)
- If any check fails → downgrade to "suggested fix, manual review required"

**FR-L4-5**: Project-style adherence.
- Index surrounding code's naming conventions, indentation, import style; pass these as constraints to the patch generator
- Verify by running the project's linter on the patch

### 5.5 Cross-Language Taint (NEW)

**FR-X-1**: HTTP/REST boundary tracking.
- Parse OpenAPI/Swagger specs when present
- Match server-side route handler signatures to client-side `fetch`/`axios`/`requests`/`http.get` call sites
- Propagate taint across the boundary using request/response field names

**FR-X-2**: gRPC boundary tracking via `.proto` introspection.
- Parse `.proto` files at scan time
- Match generated stub call sites to service implementations
- Propagate taint via field names in request/response messages

**FR-X-3**: GraphQL boundary tracking.
- Parse GraphQL schema (SDL or introspection JSON)
- Track resolver-to-resolver flows
- Track client query → server resolver flows

**FR-X-4**: SQL / ORM round-trip taint.
- When a tainted value is written to column `C` of table `T`, subsequent reads from `T.C` are tainted (within the scan boundary)
- Cover top ORMs: SQLAlchemy, Django ORM, ActiveRecord, Hibernate, Prisma, Sequelize, GORM

**FR-X-5**: Out of scope for this PRD: Kafka/SQS/Pub/Sub topic-identity taint. File/object-storage taint (S3/GCS). Both deferred to a post-GA cross-channel-taint program.

### 5.6 New Detection Modules

| New module | Coverage |
|---|---|
| `sast/mass-assignment.js` | Mass assignment / over-posting (Rails, Django, Spring, Express body-parsers) |
| `sast/prototype-pollution.js` | Prototype pollution dedicated detector (currently only a sanitizer regex) |
| `sast/csrf.js` | CSRF on state-changing routes (POST/PUT/DELETE without token / sameSite / origin check) |
| `sast/toctou.js` | Time-of-check / time-of-use races (filesystem, auth-check-then-act) |
| `sast/nosql-injection.js` | MongoDB `$where`, Mongoose query injection, DynamoDB query expression injection |
| `sast/ldap-injection.js` | Tainted strings into LDAP filter expressions |
| `sast/xpath-injection.js` | Tainted strings into XPath expressions |
| `sast/ssrf-cloud-metadata.js` | SSRF awareness for 169.254.169.254, GCP `metadata.google.internal`, Azure IMDS |
| `sast/mutation-xss.js` | mXSS via `innerHTML` round-trip / DOMParser re-serialization |
| `sast/deserialization-gadgets.js` | Gadget-chain reachability check across classpath for Java/.NET/PHP/Python pickle/Ruby Marshal |

Each ships with the standard fixture pair (`vulnerable/` + `clean/`) and a `test/<name>.test.js`.

### 5.7 Precision Engineering

**FR-PREC-1**: Calibrated confidence score on every finding (FR-L3-2).

**FR-PREC-2**: Reachability filter.
- Use the Layer-1 call graph
- Finding in a function with no path from any entry point → demoted to `info` severity with `unreachable: true`
- Configurable: `--include-unreachable` to disable demotion

**FR-PREC-3**: Composite exploitability score.
- Inputs: severity, reachability-from-entry-point, auth gating on the path (auth middleware present?), config-derived mitigations (CSP header in headers config?, WAF rules ingested?), public exploit availability (KEV + EPSS, already shipped)
- Output: 0.0–1.0 exploitability score persisted on each finding
- New module: `scanner/src/posture/exploitability.js`

**FR-PREC-4**: Active learning loop.
- User triage decisions from `/triage` (mark TP / FP / won't-fix) persist to `.agentic-security/triage-feedback.json`
- On next scan, feedback is consulted; FP-marked findings are suppressed with rationale; per-project priors adjust validator thresholds

**FR-PREC-5**: Stable finding IDs across refactors.
- Hash inputs: `(rule_id, normalized_sink_signature, normalized_path_shape)` — *not* file path or line number
- A refactor that moves the bug keeps the same ID; a fix that removes the bug retires the ID

**FR-PREC-6**: Root-cause clustering.
- Multiple flows that converge on the same sink expression collapse into one finding with N example paths
- The single finding is what `/fix` operates on (one patch fixes all flows)

### 5.8 Query DSL — SentQL

**FR-DSL-1**: Extend the existing `custom-rules.js` YAML DSL with:
- An `llm_validate:` clause: `llm_validate: { prompt: "is this exploitable?", min_confidence: 0.7 }`
- Path constraint blocks: `path_must_traverse: [<predicate>]`, `path_must_not_traverse: [<predicate>]`
- Cross-language composition: rules can reference sources/sinks across files of different languages

**FR-DSL-2**: Versioned, signed rule packs.
- Each rule pack ships with a manifest containing version + signature
- Signature verified at load; unsigned packs allowed only with explicit `--allow-unsigned-packs`

**FR-DSL-3**: Natural language → SentQL translation in Claude Code.
- New slash command `/query` accepts NL input
- Plugin invokes Claude with a translation prompt; emits SentQL YAML preview before saving

### 5.9 Claude Code UX

**FR-UX-1**: New slash commands.
- `/triage` — interactive triage mode. Cycle through ranked findings; keys: `t` (TP), `f` (FP + reason), `w` (won't-fix + reason), `n` (next), `p` (previous). Writes to `.agentic-security/triage-feedback.json`.
- `/why-not <CWE>` — recall spot-check. Reports which sources, sinks, and sanitizers for that CWE were considered and why no finding was reported. Surfaces gaps in the catalog.
- `/query [NL or SentQL]` — open a SentQL prompt; accepts NL and translates.

**FR-UX-2**: Streaming finding UX.
- Layer-2 candidate findings appear immediately with `pending_validation: true`
- Layer-3 validation results update findings in place
- For large scans, a live cost estimate is shown (token count × per-token rate, where configured)

**FR-UX-3**: Pre-commit and pre-push git hooks (opt-in).
- `agentic-security install-hooks` adds husky-style hooks
- Pre-commit: scoped scan of staged files; block on new critical findings
- Pre-push: diff-scan against the merge base of the target branch

**FR-UX-4**: Conversation awareness.
- When Claude Code edits a file, the plugin's hook injects relevant prior findings and recent fixes for that file into the next-turn context
- New hook: `hooks/edit-context-inject.js`
- Prevents Claude from re-introducing a vulnerability it just fixed

### 5.10 Integrations

**FR-INT-1**: SARIF 2.1.0 emission with custom extensions:
- `confidence` (0.0–1.0)
- `exploitability` (0.0–1.0)
- `cluster_size` (number of flows in the cluster)
- `validator_verdict` (accept/reject/escalate, or `unvalidated`)

**FR-INT-2**: CI provider matrix.
- Add: GitLab CI, CircleCI, Buildkite, Jenkins
- Each gets a turnkey config template under `scripts/ci-templates/`
- `/ci-gate` extended to detect provider and emit the right template

**FR-INT-3**: Ticketing.
- Add: ServiceNow (REST), PagerDuty (events API)
- Extend `scanner/src/integrations/tickets.js`

**FR-INT-4**: Messaging.
- Add Microsoft Teams (Incoming Webhook + Adaptive Card)
- Extend `scanner/src/integrations/index.js`

**FR-INT-5**: IDE.
- New JetBrains IntelliJ Platform plugin (IntelliJ/PyCharm/GoLand/WebStorm). LSP-backed; reuses scanner's daemon mode.
- New Neovim plugin via LSP.
- Deferred to Phase 4 if Phase 2/3 slip.

---

## 6. Non-Functional Requirements

**NFR-1 Performance.**
- Incremental scan (changed files only): ≤ 30 s for a 1M-LoC monorepo on standard CI (16 vCPU / 32 GB)
- Cold full scan: ≤ 6 min same target
- Per-file IDE rescan: ≤ 500 ms for cached findings; ≤ 5 s for newly-edited file
- Memory ceiling: ≤ 12 GB peak for the 1M-LoC scan

**NFR-2 Determinism.**
- Same source + same scanner version + same ruleset + same model version → byte-identical SARIF (modulo timestamps)
- LLM cache key includes model version; cache hits are byte-deterministic
- `--deterministic` flag skips Layer 3 entirely; uses Layer 1+2 only

**NFR-3 Offline-first.**
- IR build, Layer 2 analysis, and pattern scanner must all work fully offline
- Layer 3 requires an LLM endpoint; absence triggers `unvalidated: true` flag, not a hard failure
- OSV/KEV/EPSS lookups remain disk-cached (already shipped)

**NFR-4 Backwards compatibility.**
- Existing slash commands, MCP server, hooks, settings all continue to work
- New layers are opt-in via `sentinel.layers = ["pattern", "ir", "taint", "validator"]` in config; default in v1.x of this PRD is `["pattern"]`, flipped to all layers in v2.x once stable

**NFR-5 Graceful degradation.**
- If IR build fails for a file → fall back to pattern scanner on that file with `low_confidence`
- If Layer 2 times out on a function → emit candidate as `unanalyzed` with file/line, no path
- If Layer 3 unavailable → emit findings as `unvalidated`
- Never fail the whole scan because one layer failed on one file

**NFR-6 Security.**
- Source code never leaves customer infra unless the operator configures an external LLM endpoint
- LLM cache encrypted at rest (per-project key, derived from a user-supplied master key in `.agentic-security/key.txt`)
- MCP hardening (already shipped) extended to cover new tools

---

## 7. Success Metrics

| Metric | Target | Baseline (current plugin) |
|---|---|---|
| F1, OWASP Benchmark v1.2 | ≥ 0.90 | TBD — measure on entry |
| F1, internal CVE-replay (500 CVEs, top-25 CWE, 8 langs) | ≥ 0.85 | TBD |
| FP rate on a 10k-finding OSS corpus | ≤ 5% | TBD |
| Auto-fix acceptance rate (PR merged unmodified) | ≥ 60% | TBD |
| Mean incremental scan, 1M LoC | ≤ 30 s | TBD |
| Mean full scan, 1M LoC | ≤ 6 min | TBD |
| Per-finding Layer-3 cache hit rate (CI re-runs) | ≥ 90% | N/A |
| Languages with Layer 1+2 coverage at end of Phase 3 | 7 (Py, JS, TS, Java, Go, Kotlin, Ruby) | 0 |
| New CWE coverage (modules added per §5.6) | 10 new dedicated detectors | 0 |

Baselines for the F1 metrics are captured in Phase 0 (see §8) before any Layer-1 work starts.

---

## 8. Roadmap

### Phase 0 — Measurement & Scaffolding (Weeks 1–4)

- Stand up the **internal CVE-replay benchmark**: 500 hand-curated CVEs, pre/post-fix code, top-25 CWE, 8 GA languages. Persist under `bench/cve-replay/`.
- Wire up OWASP Benchmark v1.2 as a CI job; record F1 baseline.
- Wire up SecuriBench Micro and SARD/Juliet as CI jobs.
- Define the IR JSON schema; freeze v0.
- New `scanner/src/ir/` directory with the schema, no frontends yet.

### Phase 1 — Layer 1 + 2 for JS/TS/Python/Java (Weeks 5–18)

- IR frontends for JS/TS (tree-sitter), Python (tree-sitter + type-hint inference), Java (`javaparser` port or JNI shim).
- Call graph builder with virtual-dispatch resolution.
- Taint engine in `scanner/src/dataflow/` — forward propagation, field-/index-sensitive, k=1 context-sensitive.
- SMT path feasibility via Z3 bindings.
- Sources/sinks/sanitizers catalog (~500 entries) under `scanner/src/dataflow/catalog/`.
- Pattern scanner kept as the fast path; new layers behind `--layers=ir,taint`.
- Target: F1 ≥ 0.85 on OWASP Benchmark v1.2.

### Phase 2 — Layer 3 validator + Layer 4 closed loop (Weeks 19–28)

- LLM validator in `scanner/src/llm-validator/` with prompt-template versioning and the deterministic cache.
- Calibrated confidence score; per-CWE precision/recall metrics file.
- `/fix` extended with re-scan-after-patch and project-linter run.
- Fix-plan emission when patch exceeds the ≤ 3 files / ≤ 100 LoC budget.
- Source/sink/sanitizer discovery sub-pipeline.
- Target: F1 ≥ 0.90 on OWASP Benchmark v1.2.

### Phase 3 — Cross-language taint + UX + new detection modules (Weeks 29–40)

- Cross-language taint across HTTP/REST (OpenAPI), gRPC (`.proto`), GraphQL, and SQL/ORM round-trip.
- New detection modules per §5.6 (10 modules).
- Slash commands `/triage`, `/why-not`, `/query`; streaming UX; pre-commit/pre-push hooks; conversation-awareness hook.
- Active learning loop (FR-PREC-4); stable finding IDs (FR-PREC-5); root-cause clustering (FR-PREC-6).
- Kotlin / Ruby / PHP frontends (FR-L1-6).

### Phase 4 — Integrations + scale (Weeks 41–52)

- CI templates for GitLab/CircleCI/Buildkite/Jenkins.
- Ticketing for ServiceNow + PagerDuty.
- Microsoft Teams adapter.
- JetBrains plugin and Neovim LSP.
- 50M-LoC scalability stress test; horizontal-scaling story for cloud-curious customers (deferred to a separate cloud PRD if pursued).

Each phase ships a usable, gated release. The current `agentic-security` plugin remains functional throughout — new layers are additive and opt-in until stability metrics clear the gate.

---

## 9. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| IR frontend complexity blows up timeline | High | High | Reuse mature parsers (tree-sitter, javaparser); freeze v0 IR schema early; resist scope creep to AST-level perfection |
| LLM validator hallucinates accept on FPs | Med | High | Require Layer-2 path for accept (FR-L3-4); calibrate per-CWE thresholds; feedback loop from `/triage`; per-release recalibration on CVE-replay benchmark |
| Auto-fix introduces subtle regression | Med | High | Synthesized regression tests gate apply; project-linter gate; opt-in by severity tier; downgrade to fix-plan when verification fails |
| LLM cost makes per-scan economics painful | Med | Med | Aggressive cache-by-hash; small-model first-pass with escalation; pattern-scanner fast path always available; `--deterministic` skips Layer 3 entirely |
| Determinism breaks across model versions | High | Med | Cache key includes model version; pin model per scanner release; emit a diff report when model is upgraded; `--deterministic` mode untouched |
| Cross-language taint creates new FP class (false flows across services that don't actually call each other) | High | Med | Match flows by *evidence* (OpenAPI spec, `.proto` import, GraphQL schema), not by name heuristics alone; emit `cross_language: true` flag and a confidence penalty; surface example call sites in finding payload |
| New layers slow the scanner enough that the existing fast-path users opt out | Med | Med | Layers are opt-in; pattern fast path always preserved; per-file timeouts; daemon mode for IDE/Claude-Code use |
| Breadth of detection modules in §5.6 dilutes focus | Med | Med | Build modules in priority order tied to CVE-replay benchmark coverage gaps; don't ship a module until it passes precision threshold on the OSS-FP corpus |
| Vibecoder commands become an afterthought during depth work | Low | Med | Phase 1–3 do not touch vibecoder commands; Phase 4 dedicates capacity to keep them current |

---

## 10. Open Questions

1. **LLM endpoint configuration story** — single config slot (current model), or pluggable provider abstraction (OpenAI / Anthropic / on-prem)?
2. **Z3 distribution** — bundle the binary, or require operator install? Bundling complicates licensing; not bundling complicates onboarding.
3. **`bench/cve-replay/` corpus** — assemble in-house, or license a curated set? In-house is slower but fully controllable.
4. **Validator prompt-template versioning** — semver per template, or per release? Per release is simpler; per template gives finer-grained cache hit rates.
5. **Cross-language taint without an OpenAPI spec** — refuse to flow, or fall back to name-similarity heuristics with a confidence penalty?
6. **JetBrains plugin** — write fresh against the IntelliJ Platform SDK, or ship a thin LSP-backed plugin and let LSP do the work? The latter is faster but limits UX richness.

---

## 11. Out of Scope (for clarity)

These appeared in the Sentinel PRD but are explicitly **not** in this gap-closure PRD:

- Managed cloud service, multi-tenant SaaS, SOC 2 / ISO 27001 / FedRAMP certification.
- Mobile-specific (Android intent, iOS URL scheme) analyzers.
- Swift, C/C++ pointer analysis beyond the existing `cpp-dataflow` module.
- Kafka / SQS / Pub/Sub topic-identity taint; S3 / GCS object-storage taint.
- 99.9% SLA, single-tenant ephemeral containers — relevant only if a cloud service is launched.
- Full formal verification / theorem proving.
- Replacing human AppSec judgment on architectural / trust-boundary design.

---

*End of document.*
