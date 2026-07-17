# PRD — Making `/scan --all` the best SAST/SCA engine available

**Status:** Partially shipped — **16 of 25 shipped, 9 partial, 0 open** (verified against current code, 2026-07-17). See the status dashboard in §4.1. This remains the backlog/rationale; the "gap" wording in each item describes the state *before* it shipped.
**Version:** 1.0
**Date:** 2026-05-31
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** The `/scan --all` pipeline (`commands/scan.md` → `ship` → `engine.js#runFullScan`) and everything it transitively invokes (SAST detectors, the Layer-1/2/3 dataflow stack, the SCA pipeline, the posture annotation pipeline).
**Audience:** Engineering (scanner core), with a product lens on what differentiates us.

---

## 1. Purpose

Identify the **25 highest-impact changes** that would move `/scan --all` from "a broad, precise pattern-and-structural scanner with an opt-in flow engine" to "the most capable SAST+SCA engine a developer can run." Every recommendation here is anchored to a **verified fact about the current code**, not a generic best-practice wishlist. The constraint the requester set — *"implemented only after understanding what isn't in the tool today"* — is the organizing principle: each item names the gap, cites the evidence, and proposes the build.

This is a planning document. Nothing here is implemented by this PRD; it is the backlog and the rationale.

---

## 2. Methodology & honesty preface

> **Update (2026-07-17):** the two honesty points below have since moved. **(1)** The deep
> interprocedural taint engine is now **default-on** for local scans (R1 shipped —
> `bin/agentic-security.js`), so the "default scan is shallower" caveat no longer holds by
> default. **(2)** Independent-corpus measurement (R16) is still **partial** — the harness
> exists but the real corpus isn't wired, so the "superiority claims are aspirational" point
> stands. The original text is kept below as the rationale that motivated the work.

This assessment came from a direct read of the pipeline, not from the marketing surface. Two things must be stated up front because they shape every recommendation:

1. **The default scan is shallower than the architecture suggests.** The field-sensitive, value-context-sensitive interprocedural taint engine (`src/dataflow/`, the documented crown jewel) is **opt-in only**. `AGENTIC_SECURITY_DEEP` is not set by `bin/agentic-security.js` or `src/runScan.js`; `engine.js:8062` reads it straight from the environment, and deep-mode findings are emitted `unvalidated` (`engine.js:8096-8099`). So the default `/scan --all` is carried by ~80 regex/structural detectors plus intra-file AST taint (`performAnalysis`, `engine.js:1520`) and a heuristic import-graph cross-file pass (`crossFileTaint`, `engine.js:374`). **The single biggest latent capability in the codebase is not switched on.**

2. **"F1 = 1.000" is measured on a 185-entry, self-authored corpus** (`bench/cve-replay/corpus-baseline.json`, every entry `pre:TP post:TN`). That gate is excellent for *regression protection* and the verification discipline around it is genuinely strong. It is **not** evidence of category superiority — a self-built corpus where we wrote both the vulnerable and fixed sample cannot establish precision/recall against the messy real world. Claiming "superior to any other tool" requires measurement against **independent, adversarial, real-world corpora** (R16). Until then, superiority claims are aspirational.

Neither point is a criticism of the work — the foundations (IR for 8 languages, a real taint lattice, a centralized guard-recognition pass, a calibration/held-out discipline, a signed-state model) are unusually strong. The opportunity is that **most of the differentiating machinery exists but is gated, partial, or unmeasured.** A large fraction of the impact below is "finish and turn on what's already half-built," which is far cheaper than greenfield.

---

## 3. Current state — what `/scan --all` actually does today

Grounded inventory of the pipeline, in execution order (`engine.js#runFullScan`, line 7339+):

| Stage | Mechanism | Default? | Notes / evidence |
|---|---|---|---|
| Per-file detectors (~80) | Regex + structural, per-language | ✅ on | The bulk of `runFullScan`'s loop, `engine.js:7349-7444` |
| Intra-file AST taint | `performAnalysis` / `performASTAnalysis` | ✅ on | JS + Java AST; line 596 / 1520 |
| Cross-file taint | Import-graph heuristic | ✅ on | `crossFileTaint`, line 374 — not the real flow engine |
| Stored / session taint | Registry + heuristic | partial | stored-taint **opt-in** (`AGENTIC_SECURITY_STORED_TAINT`) |
| Call graph + route reachability | `buildCallGraph` + `annotateReachability` | ✅ on | line 4501 / 4659 |
| **Deep interprocedural taint** | `runDeepAnalysis` (k=1 value-context) | ❌ **off** | `AGENTIC_SECURITY_DEEP` gate, line 8062; findings `unvalidated` |
| SCA | `parseManifests` → `queryOSV` → EPSS → KEV | ✅ on | line 7593-7613; 11 ecosystems |
| SCA function reachability | **Regex** `funcName(` match | ✅ on | `markUsedVulnFunctions`, line 5756; documented FN on aliases/dynamic dispatch |
| Secrets | Pattern (60+) + entropy | ✅ on | `scanCredentials` / `scanEntropySecrets` |
| IaC / container / pipeline / MCP / harness | Regex + JSON/YAML walk | ✅ on | `scanIaC`, `scanContainer` (Dockerfile-only), `scanPipeline`, `scanMCP` |
| Posture annotation pipeline | defaults → stableId → cluster → reachability-filter → confidence → calibration → exploitability → mitigation-composite → persona → why-fired | ✅ on | order in `posture/CLAUDE.md` |
| Static proof gate | `proven-clean` + `proof-gate` | ✅ on | recall-preserving demotion only |
| LLM validator (Layer 3) | `llm-validator/` | ❌ off | `AGENTIC_SECURITY_LLM_VALIDATE` |
| Incremental cache / parallel | `incremental.js` / `engine-parallel.js` | ❌ off | flag-gated |

**Languages:** IR parsers exist for JS/TS, Python, Java, Kotlin, Go, PHP, Ruby, C# (`src/ir/parser-*.js`). Flow-engine maturity is real for **JS/Py/Java**; the other five are primarily **structural/regex** despite the README's "full" label. Tree-sitter (rust/solidity/cpp/c/swift/dart) is opt-in.

**SCA ecosystems:** npm, pypi, packagist, rubygems, golang, cargo, maven, gradle (no transitives), pub, conan, vcpkg, cmake. Data: OSV + CISA KEV + FIRST EPSS, disk-cached, offline-degrading. Plus typosquat/dep-confusion, vendored-lib detection, SARIF ingest, sigstore verify, binary metadata (opt-in).

---

## 4. Gap themes

The 25 recommendations cluster into five themes:

- **A. Core engine depth & precision** — the flow engine is the differentiator and it's gated/partial (R1–R6).
- **B. SCA / supply-chain depth** — reachability is regex-grade; container & malware analysis are thin (R7–R12).
- **C. Validation & false-positive elimination** — the path to "trust the verdict" (R13–R17).
- **D. Coverage breadth & new surfaces** — IaC, API, agentic, authZ, cross-service (R18–R22).
- **E. Performance, scale & workflow** — adoption gates: speed, PR-native, autofix (R23–R25).

Each item below uses a fixed template: **Gap · Evidence · Recommendation · Why it wins · Effort · Success metric.**

---

## 4.1 Status dashboard (verified against current code, 2026-07-17)

**16 shipped · 9 partial · 0 open.** Each verdict was checked against the actual module + test
in the tree; a ✅ means the gap is closed, 🟡 means the capability shipped for a subset of the
recommendation's scope (a "finish what's built" item). The item text in §5 is the *original*
gap, retained as rationale.

| R# | Recommendation | Status | Evidence / remaining scope |
|----|----------------|--------|-----------------------------|
| R1 | Deep taint default-on | ✅ Shipped | `bin/agentic-security.js` sets `AGENTIC_SECURITY_DEEP=1` for local (non-CI) scans |
| R2 | k>1 call-string + access-path entry | 🟡 Partial | field-sensitive lattice + `k2-summary-cache.js` shipped; call-string still k=1, opt-in (rec asked k=2) |
| R3 | Go/PHP/Ruby/C#/Kotlin flow parity | 🟡 Partial | Go + Kotlin flow-taint (`test/flow-parity.test.js`); PHP/Ruby/C# still structural |
| R4 | Implicit / collection-element taint | ✅ Shipped | `dataflow/index.js` + `test/collection-taint.test.js` |
| R5 | Context-aware sanitizer adequacy | 🟡 Partial | `sast/wrong-context-sanitizer.js` covers ~3 classes; not the ≥6-class context lattice |
| R6 | Non-HTTP entrypoint discovery | ✅ Shipped | `sast/event-entrypoint.js` + `posture/entrypoint-inventory.js` |
| R7 | Call-graph SCA reachability | ✅ Shipped | `sca/import-reachability.js` (JS/TS/Py/Java; others still regex fallback) |
| R8 | Container image + OS-pkg CVE | 🟡 Partial | `sca/image-packages.js` (dpkg/apk→OSV); no OCI/tarball layer reader yet |
| R9 | Static malicious install-script | ✅ Shipped | `sca/install-script-analysis.js` + `test/install-script.test.js` |
| R10 | Gradle transitive graph | ✅ Shipped | `_parseGradleDependencies` (consent-based; `sca/CLAUDE.md` doc stale) |
| R11 | VEX / OpenVEX / CSAF output | 🟡 Partial | `report/index.js#toVex` emits OpenVEX; no ingest/round-trip yet |
| R12 | SCA decision-first verdict | ✅ Shipped | `posture/sca-verdict.js` default-on (5-verdict enum) |
| R13 | Provably-safe first-class | ✅ Shipped | `dataflow/proof-gate.js` `provablySafe` + `test/proof-safe.test.js` |
| R14 | DAST-lite PoC execution | 🟡 Partial | `posture/verifier-ephemeral.js` has real docker exec but is unwired into scan/commands |
| R15 | Live secret + git-history sweep | ✅ Shipped | `secret-live-check.js` + `secret-history.js` (both opt-in, not default) |
| R16 | Independent corpus + held-out calibration | 🟡 Partial | harness shipped (`bench/independent-eval/`, `holdout-eval.js`); real corpus not wired (smoke fixture) |
| R17 | Provenance dedup / corroboration | ✅ Shipped | `posture/provenance.js` (corroborationCount / multiSignal) |
| R18 | Semantic IaC | 🟡 Partial | Terraform var-resolution shipped; no CloudFormation/Bicep/Helm, no `terraform plan` JSON |
| R19 | OWASP API Top-10 (BOLA/BFLA) | ✅ Shipped | `sast/api-authz.js` default-on over the route inventory |
| R20 | Agentic/LLM loop taint | ✅ Shipped | `sast/agent-untrusted-flow.js` (untrusted→priv-sink, mediation defuses) |
| R21 | AuthZ / RBAC-tier model | ✅ Shipped | `sast/rbac-consistency.js` |
| R22 | Cross-service dataflow | ✅ Shipped | `sast/cross-service.js` (client→route edge inference, contract-free) |
| R23 | Incremental + parallel default | 🟡 Partial | incremental default only for diff-scoped; `engine-parallel.js` unwired (parallel not default) |
| R24 | PR-native diff-scoped | ✅ Shipped | `pr-delta.js` + `--pr`/`--changed-since`; whole-repo still the zero-flag default |
| R25 | Closed-loop autofix + build-verified SCA | ✅ Shipped | `fix-verify-loop.js` wired into `mcp/apply_fix` (this session) + `sca-upgrade.js` (test-gate+rollback) |

The 9 partials are honest "finish what's built" gaps — the machinery shipped for a subset of the
scope the recommendation named. None of the 25 is fully open.

---

## 5. The 25 recommendations

### Theme A — Core engine depth & precision

#### R1. Promote the deep interprocedural taint engine to default-on, with a time budget
- **Gap:** The strongest analysis we own does not run in the default scan.
- **Evidence:** `engine.js:8062` (`_deepRequested = env.AGENTIC_SECURITY_DEEP === '1'`); nothing sets it in `bin/` or `runScan.js`; deep findings ship `unvalidated` (`engine.js:8096`).
- **Recommendation:** Make deep mode the default for interactive/local scans under a wall-clock budget (reuse the existing `AGENTIC_SECURITY_DEEP_TIMEOUT_MS`/`DEEP_FN_LIMIT`), degrading to structural-only on timeout with a visible note. Keep it off in CI unless opted in (CI is time-bounded). Run deep-mode findings through the same dedup/confidence/calibration pipeline (already wired) and **drop the blanket `unvalidated` tag** once they pass the proof gate (R13).
- **Why it wins:** Interprocedural field-sensitive taint is the line between "grep with taste" and a real SAST engine. We already built it; competitors charge for it. Turning it on is the highest impact-per-effort item in this document.
- **Effort:** M (gating + budget UX + benchmarking; the engine exists).
- **Success metric:** Recall on an independent corpus (R16) up ≥15 pts vs structural-only, with default-scan p95 latency within the budget on a 50k-LOC repo.

#### R2. Add k>1 call-string context sensitivity and access-path-granular entry contexts
- **Gap:** Context is value-abstraction only (which params are tainted), monovariant call-string; two paths reaching a helper with the same tainted-arg shape share a summary, and entry granularity is param-level not access-path.
- **Evidence:** `src/dataflow/CLAUDE.md` "what we still do NOT model" — explicitly lists call-string (k>1) and access-path entry granularity.
- **Recommendation:** Extend `SummaryCache` keying to an optional bounded call-string (k=2) and to access-path-level entry states (`f(obj)` with `obj.a` tainted ≠ `obj.b`). Keep the per-function context cap; spend the budget where it changes a verdict.
- **Why it wins:** Removes a whole class of FPs (over-merged summaries) and FNs (under-distinguished entries) that real codebases hit constantly via shared utility/helper layers.
- **Effort:** L (worklist + cache redesign, careful budgeting).
- **Success metric:** Net FP+FN reduction on the helper/utility-heavy slice of the independent corpus; no >2× regression in deep-mode p95.

#### R3. Bring Go/PHP/Ruby/C#/Kotlin to true flow-based taint parity
- **Gap:** README says "full" for 8 languages; in reality five are carried by structural/regex detectors, and the IR parsers for them are partial.
- **Evidence:** `parser-{go,php,rb,cs,kt}.js` exist (258–403 LOC) but the deep flow engine's maturity and catalog coverage are JS/Py/Java-centric; `sast/CLAUDE.md` describes the five as "taint-independent structural" recall closers.
- **Recommendation:** For each language: (a) complete the CFG lowering the taint engine consumes, (b) expand `catalog.js` sources/sinks/sanitizers for that language's top frameworks, (c) add per-language fixtures proving *flow* (not just structural) detection. Then update the README matrix to distinguish "flow" from "structural."
- **Why it wins:** Honest, defensible breadth. "8 languages with real interprocedural taint" is a claim almost no competitor can make across this set.
- **Effort:** XL (five languages; phase by ecosystem demand — Go and C# first).
- **Success metric:** Each language passes a flow-only fixture suite (tainted source → helper → sink across functions/files) with the structural detectors disabled.

#### R4. Model implicit/indirect flow and collection-element taint
- **Gap:** Implicit flow is conservative-off; container element taint (arrays/maps/sets, deserialized object graphs) is weak.
- **Evidence:** `dataflow/CLAUDE.md`: `implicit-flow.js` "conservative-by-default"; IR expr shapes track `array`/`object` but element-level taint propagation is limited.
- **Recommendation:** Add opt-in-then-default implicit-flow for the high-value pattern (`if (tainted) sink(constant)` control dependence) with a precision guard; model element taint so `arr.push(tainted); sink(arr[i])` and `map[k]=tainted; sink(map[k])` propagate.
- **Why it wins:** Closes a common real-world FN class (data laundered through a collection or a control-flow branch) that pattern matchers and naive taint both miss.
- **Effort:** M.
- **Success metric:** New fixtures for collection-laundering and control-dependence pass without raising corpus FP.

#### R5. Context-aware sanitizer adequacy model
- **Gap:** Sanitizer recognition is largely "a sanitizer is present," not "the *right* sanitizer for *this* sink context." Only the HTML-in-URL case is modeled.
- **Evidence:** `sast/wrong-context-sanitizer.js` (HTML encoder in URL context, narrow); guard recognition in `dropGuardedFindings` is per-family but binary.
- **Recommendation:** Introduce a sanitizer-context lattice: each sanitizer declares the contexts it neutralizes (HTML-body, HTML-attr, JS, URL, SQL-identifier vs value, shell-arg, path). A finding is cleared only if the sanitizer on the path matches the sink's context. Encode the common mismatches (e.g., `escapeHtml` before a `system()` call) as high-confidence findings.
- **Why it wins:** Wrong-context sanitization is a top source of *real* bugs that other scanners silently clear. This converts a current blind spot into a differentiating finding class.
- **Effort:** M.
- **Success metric:** Detect ≥6 wrong-context classes; zero new FP on correctly-sanitized fixtures.

#### R6. Whole-program entrypoint discovery (frameworks, DI, events, consumers)
- **Gap:** Reachability is rooted in regex-discovered HTTP routes; non-HTTP entrypoints (message-queue consumers, cron/scheduled tasks, event handlers, gRPC services, DI-instantiated beans, CLI commands) are under-modeled as taint sources/roots.
- **Evidence:** `scanRoutes` (line 1540) and `annotateReachability` (line 4659) are route-centric; `ROUTE_PATTERNS` drive entrypoint discovery.
- **Recommendation:** Add an entrypoint-discovery layer that enumerates framework-registered handlers (Spring `@KafkaListener`/`@Scheduled`, Celery tasks, Express/Nest, gRPC service impls, Lambda handlers, CLI argv) and feeds them as taint roots + reachability anchors.
- **Why it wins:** Backend/event-driven services are where the high-severity bugs live and where route-only scanners go blind.
- **Effort:** L.
- **Success metric:** Reachability + taint fire on a queue-consumer→sink fixture and a scheduled-task→sink fixture across Java/Python/Node.

### Theme B — SCA / supply-chain depth

#### R7. Call-graph-precise SCA function reachability for all ecosystems
- **Gap:** Function-level reachability is a regex scan for `funcName(`, with documented FN on aliased imports and dynamic dispatch.
- **Evidence:** `markUsedVulnFunctions` (`engine.js:5756`); `sca/CLAUDE.md` Gotchas — "regex-based … FN on aliased imports … dynamic dispatch." Only Java deep-mode uses the real call graph (`engine.js:8101+`).
- **Recommendation:** Drive SCA reachability from the Layer-1 IR/call graph (resolve imports/aliases, member calls, re-exports) for every language with a parser, not just Java-in-deep-mode. Keep regex as the fallback when no parser is available. Tie into R1 so it runs by default.
- **Why it wins:** Reachability is *the* SCA precision lever — "you import lodash but never call the vulnerable function" is the difference between 200 noise findings and 12 real ones. Doing it with a real call graph (not regex) is what makes the reachability claim credible.
- **Effort:** M (reuse call graph from R1/R6).
- **Success metric:** On a fixture importing a vuln pkg via alias + dynamic dispatch, reachability is correct where regex is wrong; SCA findings-to-triage down ≥30% on a real app.

#### R8. Container image + OS-package CVE scanning
- **Gap:** Container analysis is Dockerfile-text only — EOL base detection + synthesized components from `apt/apk` lines. No actual image layers, no OS-package CVE matching.
- **Evidence:** `sca/container.js` (107 LOC, "No Docker daemon required"); `sca/CLAUDE.md`.
- **Recommendation:** Add optional image scanning: read an image tarball / OCI layout (no daemon needed), enumerate installed OS packages (apk/dpkg/rpm databases) and language packages baked into layers, match against OSV/distro advisories. Report base-image + app-dep CVEs in one view.
- **Why it wins:** "Scan my repo AND the image I ship" closes the gap between source-time and deploy-time. This is table stakes for the container-native buyer and we only do half of it.
- **Effort:** L.
- **Success metric:** Detect known CVEs in a deliberately-vulnerable public base image; no daemon dependency.

#### R9. Static behavioral analysis of malicious packages (install scripts, obfuscation, exfil)
- **Gap:** Supply-chain *malware* detection is typosquat (Levenshtein) + dependency-confusion + an LLM-driven `sca-malware-analyst` agent. No static behavioral signal on the package contents themselves.
- **Evidence:** `sca/dep-confusion.js`; the malware verdict path is the LLM agent, not a deterministic detector.
- **Recommendation:** Add a deterministic install-time-behavior detector: flag `postinstall`/`preinstall` scripts that spawn shells, fetch+exec remote code, read env/credentials, or are heavily obfuscated; flag packages whose published tarball diverges from its repo (provenance mismatch via sigstore data we already fetch). Feed the agent with these signals instead of relying on it cold.
- **Why it wins:** The last three years of high-profile supply-chain attacks (event-stream, ua-parser-js, xz) were install-script/obfuscation attacks. A deterministic detector here is a headline differentiator and reduces LLM cost/latency.
- **Effort:** M.
- **Success metric:** Catch the canonical malicious-postinstall patterns on a curated sample; integrate signal into the agent's verdict.

#### R10. Gradle (and remaining) transitive dependency graphs
- **Gap:** Gradle is direct-deps-only; no transitive graph. Documented deferral.
- **Evidence:** `sca/CLAUDE.md` — "gradle … **not transitive**"; Open work — "Gradle dependency-graph integration … deferred."
- **Recommendation:** Resolve Gradle transitives by parsing the output of an opt-in `gradle dependencies`/`dependencyInsight` (or the lockfile when present), mirroring the Maven `dependency-tree.txt` path that already works. Never shell out without consent.
- **Why it wins:** The JVM enterprise market is split Maven/Gradle; transitive coverage on only one is a hard blocker in that segment (most CVEs are transitive).
- **Effort:** M.
- **Success metric:** Transitive CVEs detected on a Gradle fixture with a known vulnerable transitive.

#### R11. VEX output + reachability-backed suppression interchange
- **Gap:** We compute rich reachability tiers but don't emit them as a standard interchange artifact others can consume; suppressions are local pragmas only.
- **Evidence:** SCA finding shape has `reachabilityTier` (`sca/CLAUDE.md`) but no VEX/OpenVEX/CSAF export; suppression is `// agentic-security-ignore`.
- **Recommendation:** Emit **OpenVEX/CSAF** statements: for each CVE, our reachability verdict (`not_affected` + justification `vulnerable_code_not_in_execute_path` when unreachable, `affected` when route-reachable-via-function). Round-trip: accept upstream VEX to suppress.
- **Why it wins:** "We don't just find CVEs, we tell you (and your downstream) which ones can't fire, in a format your other tools and auditors accept." This is a procurement-grade differentiator and reduces customer triage to near-zero on transitive noise.
- **Effort:** M.
- **Success metric:** Valid OpenVEX emitted and re-ingested; auditor-acceptable justification codes.

#### R12. Reachability + KEV + EPSS composite triage as the default SCA verdict
- **Gap:** The composite-risk + auto-triage machinery exists (`sca-policy.js`, `sca-triager` agent, composite fields) but the default SCA output is still a finding list, not a decision.
- **Evidence:** `posture/sca-policy.js` (235 LOC), `compositeRisk`/`compositeRiskTier` in the finding shape, but `/scan --sca` lists deps.
- **Recommendation:** Make the default SCA surface emit a per-dep verdict (AUTO_MERGE_PATCH / WAIT / MANUAL_REVIEW / ACCEPT_RISK / WONT_FIX) derived from composite risk × KEV × EPSS × reachability × policy, with `--exposed-only` semantics applied by default and the full list one flag away.
- **Why it wins:** Turns SCA from "here are 300 CVEs" into "fix these 5 now, auto-merge these 40, ignore these 255 (here's why)." Decision-first output is the product.
- **Effort:** S–M (wiring; logic exists).
- **Success metric:** Default SCA output is a ranked decision list; manual-review queue ≤10% of raw findings on a real app.

### Theme C — Validation & false-positive elimination

#### R13. Expand the static proof gate and make "provably safe" first-class
- **Gap:** The proof gate only *demotes confidence* (recall-preserving) and covers a narrow set (SQL parameterizer, unreachable). We never tell the user "this is provably safe."
- **Evidence:** `proof-gate.js` / `proven-clean.js` — "recall-preserving demotion (lowers confidence … never severity)."
- **Recommendation:** Broaden proof coverage (constant-folding, full sanitization on all paths, type-narrowing, allow-list domination) and add an explicit `proof.verdict = "safe"` surface for findings we can discharge. Optionally suppress proven-safe by default with a `--show-proven-safe` escape hatch.
- **Why it wins:** Proof-carrying *clears* is the rarest and most trusted SAST capability. "We proved this can't happen" is a stronger claim than any competitor's confidence score.
- **Effort:** M–L.
- **Success metric:** ≥X% of a category (e.g., SQLi) on a real app discharged as provably-safe, validated by manual audit with zero missed TPs.

#### R14. DAST-lite: confirm exploitability by executing a PoC against an ephemeral instance
- **Gap:** PoC generation is static (curl/Nuclei/Playwright text); the verifier scaffolding exists but isn't a real dynamic confirmation loop in `/scan --all`.
- **Evidence:** `posture/verifier-ephemeral.js`, `payloadsForFinding`/`genCurls` (`engine.js:6112/8832`) — generation, not execution.
- **Recommendation:** For reachable web findings, optionally spin up the app in an ephemeral sandbox, fire the generated PoC, and attach a `dynamically_confirmed: true|false` verdict. Strictly opt-in, sandboxed, and scoped to code the user owns.
- **Why it wins:** A finding that's been *fired and observed* is unarguable. Static+dynamic agreement is the highest-trust signal in the industry and almost no SAST tool closes that loop.
- **Effort:** XL (sandboxing, app-launch heuristics — leverage the `run` skill patterns).
- **Success metric:** End-to-end confirmation on the vulnerable-js fixture and one real app; zero false "confirmed."

#### R15. Live secret validation + automatic git-history secret sweep
- **Gap:** Secrets are *detected* (pattern + entropy) but not *validated* (is it live?), and history scanning is advice in the skill, not automated.
- **Evidence:** `scanCredentials`/`scanEntropySecrets`; `/scan --secrets` text says "audit git history" as a manual step; `security-rotate-leak` skill is advisory.
- **Recommendation:** Add opt-in provider-specific validation (zero-or-low-cost "whoami"-style checks) to label a secret `live | dead | unknown`, and a default git-history blob sweep so a key removed from `HEAD` but present in history is still caught.
- **Why it wins:** "This AWS key is *live* and was committed 40 commits ago" is a P0; "you have a high-entropy string" is noise. Live-vs-dead is the triage that matters and history sweep catches the most dangerous case.
- **Effort:** M.
- **Success metric:** Live/dead verdict for the top 10 providers; history sweep catches a planted-then-removed key.

#### R16. Independent corpus + per-family held-out calibration gating
- **Gap:** Quality is measured on a 185-entry self-authored corpus; the calibration seed is tiny (n<30 for several families); we cannot substantiate "superior."
- **Evidence:** `bench/cve-replay/corpus-baseline.json` (185, all self-authored `pre/post`); `posture/CLAUDE.md` — seed "n < 30 for several families."
- **Recommendation:** Stand up an **independent** evaluation harness against real-world adversarial corpora we did *not* author (OWASP Benchmark — bench-shape OFF, public CVE-fix pairs harvested blind, a held-out third-party set), report precision/recall/F1 *and* Brier/ECE per family, and gate confidence-tier claims on measured precision. Treat the self-corpus strictly as regression protection.
- **Why it wins:** This is the prerequisite for *any* superiority claim. It also surfaces the real weak families to prioritize. Without it, the rest of this PRD is unfalsifiable.
- **Effort:** L (data curation is the cost).
- **Success metric:** Published per-family P/R/F1 on ≥2 independent corpora; confidence tiers calibrated (ECE < 0.1) on held-out data.

#### R17. Finding-provenance dedup graph — one issue, many signals
- **Gap:** ~80 detectors overlap; the same underlying bug can surface as several findings from regex + structural + flow emitters. Dedup exists but is pairwise.
- **Evidence:** `dedupeFindingsWithEvidence` (`engine.js:5630`) prefers flow over structural at the same sink — pairwise, not a global merge.
- **Recommendation:** Build a provenance graph keyed on (sink site, data path, CWE) that merges *all* signals for one issue into a single finding carrying the union of evidence and the strongest verdict, with a global rank. The user sees N real issues, each with "confirmed by: flow + structural + dynamic."
- **Why it wins:** Noise is the #1 reason SAST gets turned off. "One issue, corroborated by multiple independent analyses" is both quieter and *more* trustworthy than many tools' single-signal output.
- **Effort:** M.
- **Success metric:** Findings-to-distinct-issues ratio ≈1.0 on a multi-detector-overlap fixture; corroboration count surfaced.

### Theme D — Coverage breadth & new surfaces

#### R18. First-class IaC semantic analysis (Terraform/CloudFormation/Bicep/Helm)
- **Gap:** IaC is regex/line-based (`scanIaC`) plus point detectors (`k8s-admission`, `cloud-iam`); no variable/module resolution, no plan/state awareness.
- **Evidence:** `scanIaC` (`engine.js:2172`); integration detectors gated in the `NO_INTEGRATION` block (line 7434).
- **Recommendation:** Parse HCL/CloudFormation/Bicep/Helm into a resource graph with variable and module resolution, evaluate security properties on the resolved graph (public S3, open SG, over-broad IAM, unencrypted volume, missing log/retention), and optionally consume `terraform plan` JSON for ground-truth resolved values.
- **Why it wins:** Cloud misconfig is the most common breach cause; regex IaC misses anything indirected through a variable or module. Resolved-graph IaC puts us level with dedicated IaC scanners inside the same tool.
- **Effort:** L–XL.
- **Success metric:** Detect a public-bucket/open-SG defined via module+variable that the regex pass misses.

#### R19. OWASP API Top 10 driven by the auto-inferred spec
- **Gap:** We already synthesize OpenAPI/HAR from routes (`genOpenAPI`, line 7191) and classify data fields, but don't run API-specific authorization checks (BOLA/BFLA, mass assignment at the API layer, unauthenticated state-changers).
- **Evidence:** `genOpenAPI`/`genHAR` exist; `authz.js`, `mass-assignment.js` are code-level, not spec-level.
- **Recommendation:** Use the inferred route/spec inventory to check object-level (BOLA) and function-level (BFLA) authorization: every object-ID-taking handler must enforce ownership; every privileged action must enforce role. Flag inconsistent auth across siblings (one sibling checks, another doesn't).
- **Why it wins:** BOLA/BFLA are the top API breaches and are *structurally invisible* to line-level pattern matching — but visible once you have the route inventory we already build.
- **Effort:** M (reuse route inventory + authz primitives).
- **Success metric:** Flag the classic "GET /orders/:id with no ownership check" and the "sibling endpoint missing the auth its peers have" patterns.

#### R20. Deep agentic/LLM threat model — taint across the agent loop
- **Gap:** LLM/agent detectors exist (`llm-owasp`, `prompt-firewall`, `stored-prompt-injection`, `rag-poisoning`, `agent-tool-escalation`) but are largely pattern-level, not a dataflow from untrusted content to a tool invocation.
- **Evidence:** `scanStoredPromptInjection`, `scanRAGPoisoning`, `scanAgentToolEscalation` (line 7424-7426) — per-file pattern detectors.
- **Recommendation:** Model the agent loop as taint: untrusted source (user msg, retrieved doc, tool output, MCP server description) → LLM context → tool call with side effects (shell, fs, http, db). Flag when untrusted content can reach a high-privilege tool without a mediation step. This is the natural extension of our taint engine into the product's own differentiating domain (LLMSecOps).
- **Why it wins:** This is *our* category. No mainstream SAST/SCA tool models prompt-injection-to-tool-call as dataflow. Owning this is the clearest "superior to any other tool" claim available, because the others aren't even in the room.
- **Effort:** L.
- **Success metric:** Detect retrieved-doc → tool-call escalation across a fixture agent; integrate with R5 (mediation = sanitizer).

#### R21. Authn/authZ semantic model — tenancy, RBAC tiers, ownership-IDOR
- **Gap:** `--authz` covers JWT/OAuth/session config and multi-tenant query filters via patterns; it doesn't model role tiers or object-ownership across handlers.
- **Evidence:** `scan.md` `--authz` description; `security-logic-reviewer` agent does this but is LLM/manual, not engine.
- **Recommendation:** Infer the auth model (roles, tenant key, ownership relations) from the codebase and check enforcement consistency: every query touching a tenant-scoped table filters by tenant; every privileged route is gated by the right tier; object reads verify ownership. Promote the logic-reviewer's heuristics into deterministic engine checks where possible.
- **Why it wins:** Broken authorization (OWASP A01) is the #1 web risk and the least pattern-detectable; a semantic model here is durable differentiation.
- **Effort:** L.
- **Success metric:** Flag a tenant-leak query and an RBAC-tier bypass that pattern rules miss; <FP target on correctly-gated peers.

#### R22. Cross-service / cross-language dataflow beyond contract artifacts
- **Gap:** Cross-language taint exists but is contract-artifact-driven (OpenAPI/proto/graphql/queue config); it doesn't link an actual HTTP/queue *client call* in service A to the *handler* in service B by inference.
- **Evidence:** `posture/cross-lang-*.js` parse contracts; no client-call→server-handler inference.
- **Recommendation:** Infer service edges from code (an HTTP client call to `/orders/:id`, a queue `publish('jobs', payload)`) and link them to the matching handler/consumer to carry taint across the boundary even without a shared contract file.
- **Why it wins:** Microservice and polyglot monorepos are where data crosses trust boundaries unobserved; inferring the edges (not requiring a contract) is rare and high-value.
- **Effort:** XL.
- **Success metric:** Taint carried from a producer call in service A to a sink in consumer B across a fixture, contract-file-free.

### Theme E — Performance, scale & workflow

#### R23. Incremental + cached + parallel analysis as the default
- **Gap:** Incremental (`incremental.js`) and parallel (`engine-parallel.js`) exist but are flag-gated; default is single-pass, single-process.
- **Evidence:** `bin/agentic-security.js:329` (incremental behind flag/env); `engine-parallel.js` present but not the default path.
- **Recommendation:** Make diff-aware incremental scanning + multi-core execution the default, with a content-addressed cache of per-file IR and findings, and deterministic merge (preserve `--deterministic` SARIF guarantee). Full scan on demand.
- **Why it wins:** Speed is an adoption gate. A scanner that re-analyzes 200k LOC every run won't survive in CI or pre-commit. "Scan only what changed, in parallel, in seconds" is what makes the deep engine (R1) affordable to leave on.
- **Effort:** M–L (exists; needs to be the default + cache correctness).
- **Success metric:** Warm incremental scan of a 1-file change in a 100k-LOC repo < a few seconds; byte-identical SARIF vs full scan for changed files.

#### R24. PR-native, diff-scoped default mode
- **Gap:** PR delta/comment modules exist (`pr-comment.js`, `pr-delta.js`, `material-change.js`) but the default verdict is whole-repo, which floods PRs with pre-existing findings.
- **Evidence:** `src/pr-comment.js`, `src/pr-delta.js`; `commands/scan.md --diff/--uncommitted` are separate modes.
- **Recommendation:** Provide a first-class CI mode that baselines existing findings and blocks only net-new ones introduced by the PR, posting inline annotations on changed lines (build on `ci` skill + `pr-delta`). Make this the documented default for the CI workflow generator.
- **Why it wins:** "Block what this PR adds, don't re-litigate the backlog" is the only SAST CI posture teams tolerate long-term. It's the difference between adoption and a disabled check.
- **Effort:** M.
- **Success metric:** PR comment shows only net-new findings on a fixture PR; baseline drift handled.

#### R25. Closed-loop autofix with regression tests + build-verified SCA upgrades, measured
- **Gap:** The fix toolchain (`synthesize_fix → verify_fix → apply_fix`, `regression-test-gen.js`, `synthesize_sca_upgrade`) exists but isn't presented as a measured, default remediation loop, and SCA upgrades aren't build-verified.
- **Evidence:** MCP fix tools + `posture/fix-verify.js`/`regression-test-gen.js`/`sca-upgrade.js`.
- **Recommendation:** Make `/scan --all → /fix` a closed loop that (a) for SAST, applies the fix, generates a regression test that fails pre-fix and passes post-fix, and re-scans to confirm closure; (b) for SCA, performs the upgrade *and runs the project build/tests* to confirm non-breakage before proposing the PR. Track and surface an **auto-fix acceptance rate**.
- **Why it wins:** "Finds it, fixes it, proves the fix, proves it didn't break the build" is the full remediation loop — the thing buyers actually want and almost no tool delivers end-to-end. The acceptance-rate metric is how we prove it.
- **Effort:** L.
- **Success metric:** ≥X% of fixes land with a passing regression test and green build; measured acceptance rate published per release.

---

## 6. Prioritization

> **Update (2026-07-17):** most of the do-first set has landed — R1, R7, R12, R17, R20, R24 are
> ✅ shipped; R16 and R23 are 🟡 partial (the highest-value remaining "finish what's built" work).
> See the §4.1 dashboard. The ranking below is kept as the original rationale.

Impact × effort, biased toward "turn on / finish what exists." **Do-first (highest impact-per-unit-effort):**

| Rank | Item | Why first |
|---|---|---|
| 1 | **R1** deep engine default-on | Largest latent capability, modest effort |
| 2 | **R16** independent corpus & calibration | Prerequisite to *prove* anything; surfaces real weak spots |
| 3 | **R7** call-graph SCA reachability | Biggest SCA precision lever; reuses R1's graph |
| 4 | **R12** SCA decision-first output | Logic exists; turns lists into decisions |
| 5 | **R23** incremental/parallel default | Makes R1 affordable; adoption gate |
| 6 | **R17** provenance dedup | Kills the noise that gets scanners disabled |
| 7 | **R20** agentic taint | Clearest "no competitor is here" differentiator |
| 8 | **R24** PR-native default | Adoption gate for CI |

**High-impact, larger build:** R3 (8-language flow parity), R13 (proof-carrying safe), R14 (DAST-lite), R18 (semantic IaC), R21 (authZ model).
**Targeted wins:** R4, R5, R8, R9, R10, R11, R15, R19, R25.
**Strategic / longer horizon:** R2 (k>1), R6 (entrypoints), R22 (cross-service).

### Suggested sequencing

- **Phase 1 — Turn on the engine, prove it:** R1, R16, R23, R17. (Default depth + measurement + speed + noise control.)
- **Phase 2 — SCA from list to decision:** R7, R12, R11, R10, R8, R9, R15.
- **Phase 3 — Trust the verdict:** R13, R5, R14, R25.
- **Phase 4 — Own the differentiating surfaces:** R20, R19, R21, R18.
- **Phase 5 — Depth & reach:** R3, R4, R6, R2, R22.

---

## 7. What "superior to any other SAST/SCA tool" means here (success definition)

We can credibly claim category leadership when, measured on **independent** corpora (R16):

1. **Depth:** real interprocedural taint on by default across the 8 IR languages (R1, R3), with k>1 where it pays (R2).
2. **Precision:** provenance-merged (R17), proof-cleared (R13), context-sanitizer-aware (R5) — measurably fewer FPs than the incumbents at equal recall.
3. **SCA that decides:** call-graph reachability (R7) → VEX (R11) → per-dep verdict (R12), not a CVE dump.
4. **Trust:** static+dynamic agreement on reachable web bugs (R14); live-secret verdicts (R15).
5. **A surface no one else covers:** prompt-injection-to-tool-call as dataflow (R20).
6. **Fits the workflow:** incremental/parallel (R23), PR-native (R24), closed-loop fix (R25).

The honest one-line bar: **the only tool that runs real interprocedural taint by default across 8 languages, decides which CVEs can actually fire, proves a class of findings safe, confirms the rest dynamically, and is the only one that models the agent loop — measured on corpora we didn't write.**

---

## 8. Risks & non-goals

- **Latency vs depth (R1/R2/R14):** deeper analysis costs time. Mitigated by budgets (already in code) + incremental/parallel (R23). Non-goal: unbounded whole-program analysis with no time cap.
- **Network/runtime posture:** R8/R9/R14/R15 touch network or execution. All must stay **opt-in, sandboxed, offline-degrading**, consistent with the "no runtime cloud calls by default" convention. Non-goal: any default that phones home or executes downloaded code.
- **FP budget:** every recall feature (R4, R6, R20, R22) must ship with precision guards and corpus proof before default-on. The verification discipline in `CLAUDE.md` is the gate; nothing here exempts it.
- **Independent-eval honesty (R16):** until measured externally, we describe capabilities, not rankings. No "beats tool X" claim without the corpus to back it.
- **Non-goals:** memory-safety/binary exploitation analysis, full DAST/IAST product surface, and a hosted multi-tenant backend are out of scope for this PRD.

---

## 9. Appendix — evidence index

Primary files read for this assessment: `commands/scan.md`; `scanner/CLAUDE.md`; `scanner/src/{sast,dataflow,ir,posture,sca}/CLAUDE.md`; `scanner/src/engine.js` (runFullScan 7339+, deep gate 8062, SCA 7593-7660, reachability 4659, dedup 5630, markUsedVulnFunctions 5756, genOpenAPI 7191); `scanner/src/ir/parser-*.js` (8 languages); `scanner/bin/agentic-security.js` (ship/format path, incremental flag); `bench/cve-replay/corpus-baseline.json` (185 entries, 2026-06-01); `README.md` Language-coverage section.
