# PRD — Making the agentic layer best-in-class: verification, completeness & integrity

**Status:** ✅ All 7 additions shipped (v1) — per-item status inline in §3; follow-ups noted where a v1 has a deeper v2. (Originally drafted 2026-07-17 as a backlog.)
**Version:** 1.0
**Date:** 2026-07-17
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** The *agentic / methodology* layer that sits **above** the deterministic SAST/SCA
engine — how findings are verified and falsified, how coverage is guaranteed, how fixes are
kept honest, how the agents defend themselves, how model budget is spent, and how the tool
measures and improves its own real-world recall. Complements, and does not overlap,
`docs/SAST_SCA_IMPROVEMENT_PRD.md` (R1–R25), which covers the deterministic engine's depth.

---

## 1. Purpose & honesty preface

`docs/SAST_SCA_IMPROVEMENT_PRD.md` already plans the engine-depth work (deep-engine
default-on, k>1 context sensitivity, call-graph SCA reachability, semantic IaC, DAST-lite,
independent corpus, etc.). This PRD identifies the **7 highest-impact additions in the layer
that PRD does not cover**: the methodology and product-integrity machinery that makes an
*agent-driven* security tool trustworthy.

Two framing facts, grounded in a direct read of the current pipeline (not the marketing
surface):

1. **We are deterministic-engine-first.** Our differentiator is a real interprocedural taint
   engine, a cross-file call graph, and a broad surface (SAST + SCA + secrets + IaC + SBOM +
   compliance + MCP audit). Every addition below is designed **deterministic-first, offline-
   capable**, with any LLM tier strictly opt-in and degrading to a deterministic default —
   consistent with the "no runtime cloud calls by default" convention.

2. **Trust, not depth, is the current ceiling.** The engine already finds a lot. What it does
   *not* yet do is (a) actively try to *disprove* each finding by default, (b) prove it looked
   at the whole attack surface, (c) find every sibling of a confirmed bug, (d) keep its own
   fixes honest, (e) defend its agents against the untrusted code they read, (f) spend model
   budget by vulnerability class, or (g) measure and self-improve on real-world recall. These
   are the seven items below.

**None of the 7 restate R1–R25.** Where an item sits adjacent to an R-item, it says so and
describes the distinct mechanism. This is a planning document; nothing here is implemented by
it.

---

## 2. Current-state gaps (grounded in a module-level audit)

> **Update (shipped):** every gap in this section is now addressed by the additions in §3 —
> see each addition's **Status** line. This section is retained as the rationale that motivated
> the work, describing the engine *before* these additions landed.

Each gap was verified against the actual modules, not assumed.

- **Falsification only demotes; it never acts.** `dataflow/proof-gate.js` consolidates the
  flow proofs (`provenClean` + `_provenUnreachable`) into a demotion that lowers confidence
  ×0.4, is taint-only, and never touches severity or drops a finding. The only drop-on-
  disproof path is `llm-validator` on a confident `reject`, which no-ops without an LLM
  endpoint. `posture/three-agent-pipeline.js` (adversary → defender → auditor) is manual, one
  finding at a time (`/triage --deep`), and short-circuits to a static "uncertain"
  verdict offline. `dataflow/sanitizer-proof.js` (verifies a project-local sanitizer actually
  neutralizes its CWE family) is **built but unwired**. There is no default "for each finding,
  find the control that blocks it and demote unless it survives."
- **No entry-point enumeration, no coverage artifact.** The deep engine iterates every
  function with an empty taint state and discovers sources *inline* from `dataflow/catalog.js`
  patterns. There is **no CLI-argv, message-queue/consumer, or multipart/file-upload source**
  in the catalog, and no structure that enumerates "all N ways data enters this app, and the
  disposition of each."
- **No sweep from a confirmed finding.** `posture/semantic-clone.js` clusters *already-
  emitted* findings by normalized AST-token shape; `posture/clustering.js` is within-file
  only. Nothing takes a confirmed bug and re-scans the whole repo for sibling instances no
  detector fired on.
- **Fix verification is weaker than it looks.** `posture/fix-verify.js` (the write gate
  behind `apply_fix`/`verify_fix`) is **scan + lint only** — it treats "the same engine
  stopped firing" as proof, with no independent oracle and no test execution. The test-running
  loop `posture/fix-verify-loop.js::verifyFixWithTests` is **orphaned (no production caller —
  referenced only by its own test and the changelog)**; `mcp/tools.js` even carries a stale
  comment claiming that loop runs the regression test, but the wiring was never connected.
  `posture/deterministic-fix.js` has exactly **two** templated rules (weak-hash→sha256, TLS
  verify-on); everything else is LLM-composed bytes gated only by same-engine rescan. There is
  no gate that rejects a fix whose *claim* over-reaches.
- **Agent self-defense is partial and uneven.** `llm-validator` is nonce-fenced, challenge-
  token'd and fail-closed; the MCP server is OWASP-MCP-Top-10 hardened (`_confine` + HMAC on
  `last-scan.json` + an attempt budget); `_CONFINEMENT.md` governs edit paths. But the
  **triager / chain-synthesizer / poc-generator / fixer** agents embed finding text (from
  potentially hostile code) into prompts, findings are **rendered into PR/issue/ticket bodies**
  (`integrations/tickets.js`, `pr-comment.js`) without a systematic escaping/injection story,
  and there is no test matrix asserting these paths resist attack.
- **Model choice is vuln-class-blind.** There is **no per-CWE/severity model routing** anywhere.
  `hooks/model-cost-advisor.js` keys on prompt *difficulty* (a local heuristic) and can only
  *advise* (hooks are read-only on the main session's model), acting on delegated sub-agents
  only in opt-in interactive mode. `bench/router-replay/baseline.json` reports the router
  currently **dominated** by a single model (hullAdvantage −0.046, regret 0.25), and its
  corpus is generic coding prompts, not security findings.
- **Every benchmark is exact-match; none measures real-world recall with a judge.** A search
  for LLM-judge logic across `bench/` returns nothing — `cve-replay/runner.mjs` and
  `independent-eval/score.mjs` are regex/label exact-match. `bench/bigquery-github/` scans ~40k
  real files but measures **FP-density only, no recall**, at file (not repo) granularity, with
  gitignored output. There is no find→diagnose→propose-fix loop.

**One place we are clearly ahead** and should not disturb: `posture/blast-radius.js` is a
**dollar breach-cost model** (per-record cost tables, industry/jurisdiction multipliers, named
comparable breaches) — richer than a structural reach estimate. Keep it.

---

## 3. The 7 proposed additions

Fixed template per item: **Gap · Evidence · What to build · Where it plugs in · Why it wins ·
ICP fit · Effort · Not-a-dup-of-R#.**

### Addition 1 — Default falsification pass ("prove it can't be blocked, or demote")

> **Status: ✅ SHIPPED (this session).** `posture/falsification.js`, default-on in `engine.js`
> after the proof gate (opt-out `AGENTIC_SECURITY_NO_FALSIFICATION=1`); 8 tests. Verified
> recall-preserving — genuine cve-replay `pre` vulns survive (0 false blocks), corpus 185/185
> intact. Optional LLM "argue the opposing case" tier activates only when an endpoint is set.

- **Gap.** No default-on stage tries to *refute* a finding and act on the refutation; the
  posture is recall-preserving by design.
- **Evidence.** `dataflow/proof-gate.js` demotes only (confidence ×0.4, taint-only, never
  drops); `llm-validator` drops only on a confident `reject` and no-ops without an endpoint;
  `three-agent-pipeline.js` is manual and per-finding; `dataflow/sanitizer-proof.js` is built
  but unwired.
- **What to build.** A default posture stage that, for each finding, enumerates the specific
  controls between source and sink (context-matched sanitizer, dominating guard, validated-
  upstream constraint, type constraint) and **demotes to a quarantine tier unless the finding
  survives**. Add an **optional LLM tier** (reuse the adversary/auditor agents) that argues the
  opposing case with cited eliminations over survivors, gated on an endpoint.
- **Where it plugs in.** New annotator after `annotateProofGate` in `engine.js`; **wire the
  already-written `dataflow/sanitizer-proof.js`** and extend `dropGuardedFindings`; the LLM tier
  promotes `posture/three-agent-pipeline.js` from per-finding to batch.
- **Why it wins.** Refute-don't-just-find is the strongest false-positive lever available, and
  a deterministic default makes it work offline with no config or API key.
- **ICP.** Vibecoder (fewer false alarms out of the box).
- **Effort.** M (guard/sanitizer primitives exist; the work is wiring + a quarantine tier +
  calibration so it never drops a true positive).
- **Not a dup of R#.** R13 is static proof of *safety* (proof-carrying clears); R14 is
  *dynamic* confirmation. This is deterministic falsification of the *finding* as a default
  ranking/quarantine stage.

### Addition 2 — Attack-surface completeness inventory

> **Status: ✅ SHIPPED (this session).** `posture/entrypoint-inventory.js` → `scan.entrypointInventory`
> (HTTP/queue/cron/CLI/env/upload/webhook, disposition per entry + coverage table); 15 tests.
> Best paired with R6 (engine PRD) to also seed taint roots from the non-HTTP surfaces.

- **Gap.** No enumeration of entry points and no coverage artifact; findings are reported
  without a denominator.
- **Evidence.** The deep engine discovers sources *inline* from `dataflow/catalog.js`; there
  is no CLI-argv, message-queue, or multipart source in the catalog, and nothing that itemizes
  the full entry surface with a per-entry disposition.
- **What to build.** An `entrypoint-inventory` pass enumerating every attacker-reachable entry
  point (HTTP handlers, gRPC methods, queue/event consumers, cron/scheduled jobs, CLI argv,
  env, webhooks, file processors, second-order store reads) with a **disposition per entry**
  (traced-safe / finding / not-reachable / no-input) and a **per-entry-point pass/fail coverage
  table** in the report.
- **Where it plugs in.** New `scanner/src/posture/entrypoint-inventory.js`, feeding both (a)
  taint **roots** (so the engine seeds non-HTTP surfaces) and (b) a report block; reuses the
  existing route/OpenAPI synthesis (`genOpenAPI`) and `annotateReachability`.
- **Why it wins.** "We looked at all 34 ways data enters your app; here's the disposition of
  each" is a completeness claim no finding list can make, and it structurally fixes the
  backend/event-driven blind spot (route-only discovery goes blind on queues and cron).
- **ICP.** Vibecoder (transparency — "did it even look at my queue consumer?").
- **Effort.** L.
- **Not a dup of R#.** R6 proposes entry-point discovery *as taint roots*; this adds the
  auditable **coverage ledger** and the non-HTTP surfaces R6 doesn't itemize. Build together.

### Addition 3 — Root-cause sweep with total-count accounting

> **Status: ✅ SHIPPED (this session).** `posture/root-cause-sweep.js` → `scan.rootCauseSweep`;
> 6 tests; the `found = candidates + mitigated` accounting invariant is enforced so no sibling
> instance is silently dropped.

- **Gap.** No pass takes a confirmed finding and searches the repo for sibling instances the
  detectors missed.
- **Evidence.** `posture/semantic-clone.js` clusters *already-emitted* findings by AST-token
  shape; `posture/clustering.js` is within-file only. Neither re-scans from a confirmed bug.
- **What to build.** A `root-cause-sweep` pass that, for each confirmed/high-confidence
  finding, derives a **source pattern** (the vulnerable construction) and a **sink pattern**
  (the dangerous op), searches all production files + transitive callers, re-runs the gate
  pipeline on each hit, and reports **"N found / M candidate / K already mitigated"** so no
  instance is silently dropped.
- **Where it plugs in.** New `scanner/src/posture/root-cause-sweep.js`, invoked post-scan and
  in `/fix`; reuses `semantic-clone.js`'s shape hasher and the IR call graph.
- **Why it wins.** The most common way a pattern scanner embarrasses a user is finding 1 of 6
  identical bugs. Total-count accounting turns "found it here" into "found all K instances,
  here's the ledger."
- **ICP.** Vibecoder ("find all of them, not just the one").
- **Effort.** M.
- **Not a dup of R#.** New — no R-item covers a confirmed-finding-driven repo sweep.

### Addition 4 — Meta-security: self-hardening the agent surface

> **Status: ✅ SHIPPED (v1, this session).** `util/untrusted.js` (escape / fence / host-allowlist /
> redact / secure-write) + `docs/AGENT_THREAT_MODEL.md`; escaping wired into `pr-comment.js` +
> `integrations/tickets.js`; 34 tests (untrusted + agent-hardening). **Follow-up (v2):**
> `fenceUntrusted` / `isAllowedFetchHost` are built + tested but not yet threaded into every
> LLM-prompt and enrichment-fetch call site — tracked as next targets in the threat-model doc.

- **Gap.** Untrusted, attacker-authored code and finding text reach several LLM calls and
  several rendered outputs without a systematic, tested threat model.
- **Evidence.** Hardening today is real but uneven: `llm-validator` is nonce-fenced and fail-
  closed; the MCP server is `_confine`/HMAC/attempt-budget hardened; `_CONFINEMENT.md` governs
  edit paths. But the triager / chain-synthesizer / poc-generator / fixer agents ingest finding
  text into prompts, the tool renders findings into PR/issue/ticket bodies
  (`integrations/tickets.js`, `pr-comment.js`), and there is no test matrix asserting these
  paths resist injection, SSRF via finding-embedded URLs, markup injection, or audit leakage.
- **What to build.** A `docs/AGENT_THREAT_MODEL.md` enumerating every untrusted-content →
  (LLM | output | filesystem | network) path, plus a **test suite** and the fixes it forces:
  data-not-instructions fencing on every agent prompt that embeds finding text; output-escaping
  when rendering findings into issue/PR/ticket bodies; URL host allow-listing before any
  finding-derived fetch (SSRF); secret-redaction + restrictive file mode on any audit/scratchpad
  the agents write.
- **Where it plugs in.** New doc + `scanner/test/agent-hardening/` suite; fixes at the render
  points (`integrations/`, `pr-comment.js`), the agent prompt builders (`agents/*.md`), and the
  scratchpad/audit writers.
- **Why it wins.** A security product that can be turned against its user by the code it scans
  is a headline liability, and it is procurement-grade table stakes for scanning third-party
  code or running autonomously. It is also *our* category (LLMSecOps): we should model the
  attacks on ourselves at least as rigorously as we model our customers'.
- **ICP.** Pro / trust, but protects every user.
- **Effort.** M–L (mostly audit + tests + targeted fixes; primitives largely exist).
- **Not a dup of R#.** Absent from R1–R25 entirely (that PRD is about detection depth, not the
  tool's own attack surface).

### Addition 5 — Capability-based (CWE/severity) model routing for subagent dispatch

> **Status: ✅ SHIPPED (this session).** `posture/model-routing.js`; stamps `finding.dispatchModel`
> (strongest for crypto/auth/critical, mid for injection, cheapest for low-sev hardening) in
> `engine.js`; 12 tests. **Follow-up (v2):** cost-advisor-hook integration and re-corpusing
> `bench/router-replay` on real security findings (today it grades generic coding prompts).

- **Gap.** No routing table matches a vulnerability class to a model; model choice is cost-only
  and, by our own bench, not beating a single model.
- **Evidence.** No per-CWE/severity routing exists. `hooks/model-cost-advisor.js` keys on prompt
  *difficulty* and can only advise; `bench/router-replay/baseline.json` shows the router
  dominated by one model (hullAdvantage −0.046, regret 0.25) on a generic-coding corpus. The
  `subagentOverride` plumbing to apply a per-dispatch model already exists (per `CLAUDE.md`).
- **What to build.** A declarative **CWE/severity → model** policy — Critical + crypto / auth /
  deserialization → strongest model; injection / XSS / SSRF → mid; low-severity single-file →
  cheapest — applied when dispatching the fixer / triager / PoC / chain-synthesizer subagents,
  overriding the vuln-class-blind difficulty heuristic. Re-corpus `router-replay` with real
  **security-finding** labels so its quality is measured on the actual workload.
- **Where it plugs in.** Extend `hooks/model-cost-advisor.js` + the subagent-dispatch convention
  in `CLAUDE.md`; re-corpus `bench/router-replay/`.
- **Why it wins.** Spends model budget where correctness matters (crypto/auth fixes get the
  strong model; header-hardening gets the cheap one) — cutting cost and raising fix quality —
  and gives `router-replay` a workload where a smart router can beat the single-model hull.
- **ICP.** Both (cost for vibecoder, quality for pro).
- **Effort.** S–M (policy table + dispatch wiring; the override mechanism exists).
- **Not a dup of R#.** The R-set is silent on model routing.

### Addition 6 — Self-improving recall harness: judged external-repo hunting + miss-analyzer

> **Status: ✅ SHIPPED (v1, this session).** `bench/realworld-recall/` (score / judge /
> analyze-misses / runner + a labeled smoke corpus) + 16 tests; the miss-analyzer names the
> pipeline stage that dropped a finding and proposes a fix. **Note:** a real recall *number*
> needs a user-supplied commit-pinned corpus + an LLM endpoint — the judge degrades to null
> offline and is bench-only, never in the product scan path.

- **Gap.** No semantic (LLM) judging, no external-repo recall surface, and no
  find→diagnose→propose-fix loop.
- **Evidence.** Every `bench/` verdict is regex/label exact-match (`cve-replay/runner.mjs`,
  `independent-eval/score.mjs`); `bench/bigquery-github/` measures FP-density only, at file
  granularity, no recall, output gitignored. Exact-match judging is weakest exactly where it
  matters most (business-logic, authz, multi-step chains), because "did the emitted vuln string
  match the expected name" is brittle.
- **What to build.** A `realworld-recall` harness that scans real external repos **pinned to
  exact commits**, **LLM-judges** detection semantically (same class + location + root-cause,
  not the exact ID/wording), keeps **cross-run regression history**, and runs a **miss-analyzer**
  that pinpoints which pipeline stage dropped a known finding (which detector, which posture
  filter, which taint gap) and proposes the concrete rule/detector/prompt change.
- **Where it plugs in.** New `bench/realworld-recall/`; an `analyze-misses` mode under `/labs`;
  the semantic judge as a bench-only LLM call (never in the product scan path). Pair with R16's
  independent corpus so the same repos feed both precision (R16) and recall (here).
- **Why it wins.** This is the engine that makes the tool *get better over time* rather than only
  *not regress*. Semantic judging is the only honest way to score the hard classes, and the
  miss-analyzer converts every miss into a prioritized rule fix.
- **ICP.** Pro / internal (the quality flywheel behind "best-in-class").
- **Effort.** L (data curation + judge prompt + miss-analyzer; judging is bench-only).
- **Not a dup of R#.** R16 is corpus curation + P/R/F1 + Brier/ECE (deterministic scoring). This
  is the **semantic-judge + self-diagnosis loop** and the **external-repo recall surface** R16
  doesn't cover. Complementary.

### Addition 7 — Deterministic honesty gates on fix/finding output

> **Status: ✅ SHIPPED (this session).** `posture/fix-honesty-gate.js` (hand-wave residual guard,
> cited-file:line requirement for FP/safe verdicts, FULL/MITIGATION/WORKAROUND tiers), consumed
> by `fix-verify.js` when fix metadata is supplied; 24 tests. The previously-orphaned test loop
> (`fix-verify-loop.js::verifyFixWithTests`) is now wired into `mcp/apply_fix` behind
> `AGENTIC_SECURITY_FIX_RUN_TESTS=1`.

- **Gap.** Nothing rejects the tool's *own* over-claiming or incomplete output, and the fix
  oracle is weaker than it appears.
- **Evidence.** `posture/fix-verify.js` is **scan + lint only** — it treats "the same engine
  stopped firing" as proof, with no independent oracle and no test execution; the test-running
  `posture/fix-verify-loop.js::verifyFixWithTests` is **orphaned (no production caller)**, and
  `mcp/tools.js` even carries a stale comment implying it runs. `posture/deterministic-fix.js`
  has 2 rules; everything else is LLM-composed bytes gated only by same-engine rescan. There is
  no honesty gate and no fix-completeness tier.
- **What to build.** A `fix-honesty-gate` module invoked by `apply_fix`/`verify_fix` and the
  report writer: (a) a **residual-risk honesty guard** that rejects vague-assurance prose
  ("adequately handled," "properly validated," "future work") in favor of a named residual
  vector; (b) a **cited-file:line requirement** for any "false-positive" or "provably-safe"
  verdict; (c) **fix-completeness tiers** (FULL / MITIGATION / WORKAROUND) computed from
  mechanical signals (sink signature changed? all callers routed through the fix? a test that
  fails pre-fix and passes post-fix?), surfaced on every applied fix; and (d) **wiring the
  orphaned test-execution loop** so a fix's regression test is actually run, not just written.
- **Where it plugs in.** New `scanner/src/posture/fix-honesty-gate.js`; call it from the MCP
  `apply_fix`/`verify_fix` toolchain and the reporters; adopt/wire `posture/fix-verify-loop.js`.
- **Why it wins.** "Finds it, fixes it, and won't lie to you about how completely" is the trust
  layer under autofix. A fix that ships a partial workaround labeled as a full fix is worse than
  no fix; mechanical honesty gates make that impossible.
- **ICP.** Both (autofix a vibecoder can trust; audit-grade for pro).
- **Effort.** M.
- **Not a dup of R#.** R25 is the closed-loop autofix + regression-test loop. This adds the
  **integrity/honesty layer** on top (and finishes wiring the loop R25 assumes exists).

---

## 4. Prioritization

> **Update:** all seven landed in a single session; the ranking below is retained as the
> rationale for the order they were built (and the order to *deepen* the v1s in follow-up work).

Biased toward "highest trust-per-unit-effort" and "vibecoder-first, then pro."

| Rank | Addition | Why first |
|---|---|---|
| 1 | **#1 Default falsification** | Biggest FP-reduction lever; deterministic + offline; reuses unwired code |
| 2 | **#7 Fix honesty gates** | Makes autofix trustworthy; finishes an orphaned loop; modest effort |
| 3 | **#3 Root-cause sweep** | Kills the "found 1 of 6" embarrassment; reuses the clone hasher |
| 4 | **#5 Capability model routing** | Cheap; raises fix quality; fixes a bench that's currently dominated |
| 5 | **#2 Completeness inventory** | Structural blind-spot fix + a strong trust artifact (pairs with R6) |
| 6 | **#4 Meta-security threat model** | Credibility gate for autonomous / third-party scanning |
| 7 | **#6 Self-improving recall harness** | The long-horizon quality flywheel (pairs with R16) |

### Suggested sequencing

- **Phase 1 — Trust the verdict (vibecoder-facing):** #1, #7, #3. Fewer false alarms, honest
  fixes, no missed siblings — the three things a vibecoder feels immediately.
- **Phase 2 — Cost & coverage:** #5, #2. Route budget to where correctness matters; show the
  full attack surface.
- **Phase 3 — Institutional trust & the flywheel:** #4, #6. Harden ourselves; measure and
  self-improve on real-world recall.

---

## 5. Risks & non-goals

- **Precision guards are mandatory.** #1 and #3 can *demote or quarantine* findings — every
  recall-affecting change ships with corpus proof (`bench:cve-replay:check`, both directions)
  before default-on, per `CLAUDE.md`'s verification discipline. Non-goal: any silent recall loss.
- **Keep LLM tiers opt-in and offline-degrading.** #1's LLM tier, #6's semantic judge, and #4's
  harder cases touch an LLM; all stay opt-in and must degrade to a deterministic default,
  consistent with "no runtime cloud calls by default." The semantic judge is **bench-only** —
  never in the product scan path.
- **Meta-security is scoped to our own surface.** #4 hardens the agents/renderers/audit paths;
  it is not a general WAF or a runtime IDS.
- **Non-goals:** an autonomous "file PRs against strangers' repos" runtime (out of scope here);
  replacing R1–R25 (this complements the engine PRD, it does not restate it).

---

## 6. Appendix — evidence index

Primary modules read for this assessment (agentic-security working tree):

- **Framing/UX:** `docs/{ARCHITECTURE,SAST_SCA_IMPROVEMENT_PRD,MODEL_COST_OPTIMIZATION,HARNESS_COMPATIBILITY}.md`;
  `commands/{secure,scan,fix,labs,triage}.md`; `agents/{_CONFINEMENT,security-fixer,security-poc-generator}.md`.
- **Dataflow:** `scanner/src/dataflow/{index,engine,catalog,summaries,proof-gate,exploit-prover,sanitizer-proof,path-feasibility,smt-feasibility,formal-verify,points-to,ifds,tabulation}.js` (+ `dataflow/CLAUDE.md`).
- **Posture:** `scanner/src/posture/{three-agent-pipeline,adversary-agent,defender-agent,auditor-agent,proof-gate,clustering,semantic-clone,blast-radius,counterfactual,confidence,calibration,holdout-eval,exploitability,exploitability-probability,fix-verify,fix-verify-loop,deterministic-fix,regression-test-gen,router,model-rescan,adversarial-self-test,detector-fuzz,llm-redteam}.js` (+ `posture/CLAUDE.md`).
- **Toolchain / integrations:** `scanner/src/mcp/tools.js` (+ `mcp/CLAUDE.md`); `scanner/src/llm-validator/*`; `scanner/src/integrations/tickets.js`; `scanner/src/pr-comment.js`; `hooks/model-cost-advisor.js`.
- **Benches:** `bench/{cve-replay/runner.mjs, independent-eval/{runner,score}.mjs, router-replay/{runner.mjs,baseline.json}, bigquery-github/README.md, agent-tasks/security-fixer/*}`.
