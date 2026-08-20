# PRD: World-Class Across All Ten Features

**Status:** Draft for review. Nothing here is implemented by writing it.
**Owner:** Ross Young / Clear Capabilities Inc.
**Date:** 2026-08-20
**Engine version measured:** 0.138.0
**Scope:** The whole product — `scanner/src/` (all layers), `bench/`, `commands/`, `agents/`, `ide/`, `scripts/`.
**Audience:** Engineering.

**Relationship to `docs/WORLD_CLASS_DETECTION_PRD.md`:** that document owns Features 1 and 2
(pattern/structural detection and the taint engine) and its themes are not restated here.
This document covers the other eight, and states the one structural problem they share.

---

## 1. The thesis

This project's stated moat is *provable, measurable, reproducible* security. Measured
against its own standard, that claim is currently supported for **two** of the ten
features and unsupported for the other eight — not because those eight are bad, but
because **nothing measures them against code this project did not write.**

### 1.1 What is actually measured today

| Feature | Accuracy instrument | Labels by | Verdict |
|---|---|---|---|
| 1. Pattern & structural (SAST) | `bench/independent` (315 real advisories) | third party | **measured** |
| 2. IR & taint | `bench/layer-recall` + `bench/independent --deep` | third party | **measured** |
| 3. Supply chain & SCA | none | — | **unmeasured** |
| 4. Secrets, IaC, containers | 3 self-authored corpus entries | this project | **unmeasured** |
| 5. AI / LLM security | 2 self-authored corpus entries | this project | **unmeasured** |
| 6. Remediation | `bench/agent-tasks/security-fixer` | this project | partial |
| 7. Evidence & assurance | `bench/proof-corpus` | this project | partial |
| 8. Compliance & reporting | none | — | **unmeasured** |
| 9. Product surfaces | none | — | **unmeasured** |
| 10. Measurement & release | the gates themselves | n/a | **measured** |

`scripts/corpus-provenance-check.mjs`, run 2026-08-20, reports **100.0% of
`bench/cve-replay` entries are self-authored fixtures** and says so in its own output:
*"its detection rate is at the ceiling by construction, since an entry is only admitted
once it scores."* Exactly **1 entry of 215 (0.5%) is `execution-proven`.**

### 1.2 The measured baseline for the two features that *are* instrumented

From `bench/independent/RESULT.json`, 2026-08-19, engine 0.138.0, 309 scored / 6 unscored:

| | value |
|---|---|
| localized recall (**the claim**) | **11/309 = 3.56%** |
| localized precision | 11/25 = 44.00% |
| fix-discrimination | 9/11 = 81.8% |
| wide recall / precision (diagnostic) | 13.27% / 53.95% |
| taint's share of localized TPs | **1 of 12** (deep configuration) |

Per language, and this is the sharpest signal in the document:

| language | n | recall |
|---|---:|---:|
| javascript | 20 | 30.0% |
| typescript | 37 | 13.5% |
| java | 21 | 9.5% |
| python | 57 | 8.8% |
| c# | 15 | 6.7% |
| php | 55 | 5.5% |
| **go** | **72** | **0.0%** |
| **ruby** | **32** | **0.0%** |

**104 of 309 entries — a third of the population — are in two languages where the
engine finds nothing at all.** By CWE, the zeros are just as concentrated:
CWE-200 (0/19), CWE-20 (0/18), CWE-863 (0/11), CWE-770 (0/8), CWE-287 (0/7).

### 1.3 The rule this PRD is built on

> **No feature gets new capability until it has an instrument that can fail.**

This is not process for its own sake. It is the lesson this codebase has already paid
for three times, documented in its own history:

- `WORLD_CLASS_DETECTION_PRD.md` §8d: five detector families built across four rounds
  with no measurement in between, all five silent on the real population, because "the
  rules were written from this document's root-cause prose, not from the vulnerable
  files."
- `docs/METRICS.md`: the taint table sat ~5× stale (11% published vs 54% actual) because
  `bench:layer-recall:check` gates on a **floor** — a 31 → 116 improvement passed it
  exactly as a no-op would.
- 2026-08-19: `rate-limit.js` had silently discarded **every finding it ever produced,
  project-wide, since it was written.** Unit tests passed throughout.

Each was invisible to unit tests and visible only to an instrument scoring against code
nobody here wrote.

---

## 2. Goals and non-goals

### Goals

1. Every one of the ten features has an accuracy instrument whose labels come from
   outside this project, reported with `{n, d}` and a held-out slice.
2. The two zero-recall languages (go, ruby — a third of the population) come off zero.
3. Fix-discrimination stays ≥ 80% as recall rises; a finding that survives its own fix
   is not a detection.
4. Every published number states the configuration that produced it.

### Non-goals (stated so they are not silently attempted)

- **Raising the wide/file-scoped number.** It is the diagnostic, not the claim. Moving it
  without moving localized recall is benchmark gaming, which the mutation gate exists to
  catch and which this project refuses on principle.
- **Domain-oracle classes.** "Which npm env var enables auto-confirm", "which IPv6 textual
  form is loopback" — these need a curated dataset, not analysis. Out of scope unless a
  data source is adopted deliberately.
- **Native/protocol/parser-internal correctness** — browser internals, HTTP/2 framing,
  URI differential parsing. Genuinely outside a multi-language source analyzer.
- **Chasing every language to parity.** Go and Ruby are 104 entries; Kotlin has none in
  this population. Prioritize by measured frequency, not by symmetry.

---

## 3. Feature 1 — Pattern & structural detection (SAST)

**Measured today:** localized recall 3.56%, precision 44.00%. Owned by
`WORLD_CLASS_DETECTION_PRD.md`; only the parts that document does not cover appear here.

**The gap this document adds: the two zero languages.** Go (0/72) and Ruby (0/32) are not
a tuning problem — a rule that fires zero times across 72 real advisories is absent, not
mistuned. `sast/CLAUDE.md` documents Go and Ruby structural detectors that exist, so the
question is why they never match.

**Work.**

- **F1.1 — Root-cause the Go zero, entry by entry.** 72 entries is enough to be
  conclusive. For each, record which stage dropped it using the
  `recon-entrypoint → detector → taint → posture-filter → proof-gate` attribution that
  `bench/realworld-recall/analyze-misses.mjs` already implements. Publish the histogram
  before writing a single rule.
- **F1.2 — Same for Ruby (32 entries).**
- **F1.3 — Fixture-first rebuild for whichever stage dominates.** Extract the real
  vulnerable snippet from each target entry into a fixture, write the rule until it fires
  on that fixture *and stays silent on the `post/` revision*, then re-measure. Per §8d,
  re-measure after **each** family, never after a batch.
- **F1.4 — Close the three still-silent families.** `CONVENTION`, `REDIRECT-TOCTOU` and
  `CODEGEN` produce zero findings on the real population; `OWNERSHIP-AUTHZ` and `RESOURCE`
  now fire, so the shape is reachable.

**Exit gate.** Go and Ruby each ≥ 5% localized recall, with the per-stage histogram
published for both; no regression in the six languages already non-zero; mutation gate
green.

---

## 4. Feature 2 — Intermediate Representation & taint engine

**Measured today:** 116/215 (54%) of corpus detections attributed to `IR-TAINT`; on the
real population, taint contributes **1 of 12** localized TPs at roughly 2× runtime and
+2 false positives.

That contrast is the whole story: **taint looks dominant on fixtures written here and is
nearly invisible on code that was not.** The corpus is taint-shaped because it was
written by the people who wrote the taint engine.

**Work.**

- **F2.1 — A taint-specific third-party instrument.** `bench/layer-recall` measures
  attribution over a self-authored corpus and therefore cannot answer "is our taint engine
  good." Build the same per-layer attribution over `bench/independent`, reported per
  language, so the 1-of-12 figure has a trend line.
- **F2.2 — Finish container/collection taint.** 9 of 10 probed shapes now flow
  (`test/container-taint.test.js`); the open one is Python comprehensions
  (`[x for x in request.args.getlist(...)]`). Also unmodelled: cross-file/stored flow
  beyond the current registry, and multi-source provenance pairs (T3.4).
- **F2.3 — Entry-point breadth (T3.1 remainder).** SDK/network-response sources and
  library-mode public-API parameters. For a library the caller *is* the attacker; that
  may warrant a mode rather than a heuristic.
- **F2.4 — Kill the two remaining hang classes.** Six entries exceed the 600 s per-entry
  watchdog, all Java, all very large trees. They are excluded honestly today, but an
  engine that cannot finish a large Java repository in ten minutes is a product problem,
  not only a benchmark one. Profile before optimizing.
- **F2.5 — Reclaim the comment-stripping cost.** The comment-blindness fix cost 5.7%
  end-to-end after two optimizations (from 19.7%). `blankComments` is now on the hot path
  for every file; a lexer-level integration would remove the separate pass entirely.

**Exit gate.** Taint's attributable share of localized TPs is **> 1** and rising, measured
per phase; no per-language FP-budget regression; the 6 unscored entries drop to ≤ 2.

---

## 5. Feature 3 — Supply chain & SCA

**Measured today: nothing.** `posture/` carries `sbom.js`, `sbom-diff.js`, `epss.js`,
`license-{graph,policy,attributions}.js`, `reachability-filter.js`, `iac-reachability.js`
and OSV/KEV enrichment. There is **no bench directory for any of it.** Function-level
reachability — the headline SCA claim in the README — has never been scored against a
labelled set.

This is the largest unmeasured surface in the product, and it is the one customers most
often verify independently, because they can: an SCA result is checkable against a
public advisory database in minutes.

**Work.**

- **F3.1 — `bench/sca-replay`, third-party labelled.** Pin N repositories at a commit with
  a *known* dependency-vulnerability set from GitHub Advisory / OSV, and score
  precision/recall over **direct + transitive** vulnerable packages. Same doctrine as
  `bench/independent`: unfetchable is UNSCORED, never a miss.
- **F3.2 — Score reachability as its own claim.** "Vulnerable version present" and "the
  vulnerable *function* is reachable" are different assertions with different error costs.
  A false "unreachable" is a missed exploit; a false "reachable" is noise. Report them
  separately, each with `{n, d}`, and publish the demotion rate.
- **F3.3 — SBOM conformance, mechanically.** Validate emitted SBOMs against the CycloneDX
  and SPDX schemas in CI. "We emit an SBOM" is worth nothing if a consumer's parser
  rejects it; this is a cheap, binary, external check.
- **F3.4 — KEV/EPSS freshness as a gate.** The catalogs are disk-cached with no staleness
  bound. A KEV catalog six months old silently understates risk. Add an age assertion and
  surface the catalog date in every report that uses it.
- **F3.5 — Malicious-package detection, honestly scoped.** `sca-malware-analyst` emits
  CLEAN/SUSPICIOUS/MALICIOUS verdicts with no measured accuracy. Either score it against
  a labelled set of known-malicious packages, or downgrade its output to advisory until
  it is scored.

**Exit gate.** `bench/sca-replay` publishes precision/recall for vulnerable-dependency
detection and, separately, for reachability, with a held-out slice; SBOM schema
validation runs in CI; no KEV/EPSS figure is published without its catalog date.

---

## 6. Feature 4 — Secrets, IaC, containers & deploy

**Measured today: three self-authored corpus entries** (`tf-open-ingress-shape`,
`hardcoded-stripe-key`, `mcp-untrusted-install-shape`). Secrets detection has a known,
deliberate design decision — the credential scanners read **raw source**, so a key
committed inside a comment is still reported — which is correct, but has never been
scored for precision on real repositories.

**Work.**

- **F4.1 — Secrets precision against a labelled corpus.** Secret detection is the feature
  most likely to produce alert fatigue, and the one with the best available ground truth:
  repositories with known planted secrets, plus a negative set of high-entropy strings
  that are *not* secrets (hashes, base64 assets, lockfile integrity fields, UUIDs). Report
  precision and recall separately; the negative set is the harder half.
- **F4.2 — Verified-vs-unverified secrets.** A live credential and a rotated one are
  different findings with different urgency. Where a provider offers a safe validation
  endpoint, and **only with explicit opt-in**, distinguish them. Never validate by default:
  it is an outbound call carrying a secret.
- **F4.3 — IaC coverage measured against a real corpus.** `iac-terraform.js` and
  `IAC_PATTERNS` cover Terraform; Kubernetes manifests, Helm charts, CloudFormation and
  Bicep are the gaps. Score against public misconfiguration corpora rather than
  self-authored fixtures.
- **F4.4 — Container image scanning is absent.** `scanContainer` reads Dockerfiles. It does
  not read an image. Decide deliberately: either scan built images (base-image CVEs,
  layer secrets, non-root, pinned digests) or state in the README that image scanning is
  out of scope. The current silence reads as coverage.
- **F4.5 — Deploy-time gate telemetry.** `/setup --ci` and the pre-deploy gate exist;
  nothing measures whether they *block* what they should. Replay a set of known-bad diffs
  through the gate and assert the exit code, both directions.

**Exit gate.** Secrets precision/recall published against a third-party corpus including a
negative set; IaC scored on a public corpus; container-image scanning either shipped with
a bench or explicitly declared out of scope in the README.

---

## 7. Feature 5 — AI / LLM security

**Measured today: two self-authored corpus entries.** This is the product's most
differentiated surface — 14 modules spanning prompt injection, RAG poisoning, MCP audit,
agent-tool escalation, model loading — and its least verified.

It is also the area where **the threat model is still moving**, which argues for
measuring against an external, versioned benchmark rather than a corpus written here.

**Work.**

- **F5.1 — Adopt an external prompt-injection benchmark.** Score against a published,
  third-party injection corpus rather than fixtures. Report per-technique, not as one
  aggregate: direct injection, indirect/RAG, encoding-obfuscated and multi-turn have
  genuinely different detection profiles and an aggregate hides which one is weak.
- **F5.2 — MCP audit against real servers.** `mcp-audit.js` claims OWASP MCP Top 10
  coverage. Score it against a corpus of real published MCP servers, including
  known-malicious tool definitions. Tool-poisoning and rug-pull (a tool whose definition
  changes after approval) are the two shapes with no detector today.
- **F5.3 — Agent-trust-boundary taint.** `agent-untrusted-flow.js` and
  `agent-tool-escalation.js` are pattern-based. The real shape is a dataflow one: tool
  output → model context → tool invocation. Model it in the taint engine, where
  `@mcp.tool()` parameters are already sources (T3.1), rather than as regexes.
- **F5.4 — The comment-blindness carve-out needs its own test.** 20 detectors deliberately
  read raw source because for an agentic tool, instructions hidden in a comment *are* the
  attack. That decision is currently protected only by a code comment. It needs a test
  asserting a prompt-injection payload inside a comment **is** still reported — the
  inverse of `test/comment-blindness.test.js`.
- **F5.5 — AI-BOM against a standard.** AI-BOM output should validate against CycloneDX's
  ML-BOM extension, mechanically, or be labelled proprietary.

**Exit gate.** Per-technique prompt-injection scores against an external corpus; MCP audit
scored against real servers; agent trust-boundary flow modelled in the taint layer with a
localized-TP delta; the raw-source carve-out pinned by a test.

---

## 8. Feature 6 — Remediation

**Measured today:** `bench/agent-tasks/security-fixer` exists — the only feature outside
detection with a task-level bench. The deterministic toolchain
(`synthesize_fix → verify_fix → apply_fix`) is the right architecture: the agent calls
tools, it does not edit files directly.

**The unmeasured claim is durability.** A fix that removes the finding is not necessarily
a fix that preserves behaviour, and nothing currently proves it does.

**Work.**

- **F6.1 — Score fixes on three axes, not one:** (a) does the finding disappear;
  (b) **does the project's own test suite still pass**; (c) does an independent verifier
  agree the vulnerability is gone. Today (a) dominates, and (a) alone is satisfiable by
  deleting code.
- **F6.2 — Regression-test generation is the durable artifact.** The PoC generator already
  emits framework-idiomatic tests. Every applied fix should land with the test that fails
  on the vulnerable revision and passes on the fixed one — that is what stops the bug
  returning, and it is checkable.
- **F6.3 — Measure fix *correctness* on the independent population.** For an advisory
  entry, the upstream fix commit is available. Compare our synthesized fix against the one
  the maintainers actually shipped, semantically. This is a rare, genuinely third-party
  ground truth for remediation and nobody is using it.
- **F6.4 — Confinement, adversarially tested.** `agents/_CONFINEMENT.md` defines a
  reserved-write list. Test it the way a boundary should be tested: attempt writes outside
  the tree, through symlinks, through `..` traversal, and assert refusal.
- **F6.5 — Report the honest failure rate.** Publish the proportion of findings where fix
  synthesis is declined or fails verification. A remediation feature that silently
  attempts everything is less trustworthy than one that declines 40% and says so.

**Exit gate.** Fix quality reported on all three axes with `{n, d}`; every auto-applied fix
carries a regression test; confinement has an adversarial test suite.

---

## 9. Feature 7 — Evidence & assurance

**Measured today:** the strongest-architected feature in the product. Proof tiers
(`execution-proven` / `proof-failed` / `taint-proven` / `unproven`), Ed25519 evidence
bundles verifiable by public key, per-install HMAC run attestation, and
`verification-separation.js` enforcing producer/verifier independence.

**The gap is adoption, not architecture: exactly 1 corpus entry of 215 (0.5%) is
`execution-proven`.** The tier that carries the strongest claim is almost never reached.

**Work.**

- **F7.1 — Raise execution-proven coverage.** It is the difference between "a pattern
  matched" and "we ran it and it did the thing." Target the families where a sub-minute
  sandboxed PoC is realistic (injection with a reachable entry point) and report coverage
  as a standing metric, per family, so the honest ceiling becomes visible.
- **F7.2 — Make `INDETERMINATE_BY_CLASS` a first-class, published number.** The PoC
  generator already declines classes it cannot prove. Publishing *which* classes and what
  share of findings they represent is more credible than a high proof rate.
- **F7.3 — Third-party bundle verification, tested end to end.** `verify-attestation` is
  tested in-repo. The claim is that *someone else* with only the public key can verify.
  Test it from a clean environment with no repo checkout — that is the actual claim.
- **F7.4 — Calibration on held-out data, continuously.** `holdout-eval.js` and the
  held-out discipline exist; `calibration-drift.js` exists. Wire drift detection into the
  release gate so a miscalibrated confidence surface fails the build rather than being
  noticed later.
- **F7.5 — Sandbox escape resistance. ~~Not started~~ → ALREADY SATISFIED; this entry was
  wrong when written.** Verified 2026-08-20 by reading the code rather than assuming from
  the feature list. `src/sandbox/` is a dedicated module with a 362-line `CLAUDE.md`, three
  backends (`userspace`, `namespace`, `disabled`), functional rather than presence-based
  backend detection, and **43 passing tests** across `test/sandbox-escape.test.js` and
  `test/sandbox.test.js` — including adversarial cases for out-of-root writes, filesystem
  re-binding, parent-environment leakage, outbound network, wall-clock overrun and fork
  storms. `runConfined` never throws (documented there as the classic route to unconfined
  execution). The proof evidence already records which `backend` produced an
  `execution-proven` verdict, so a third party reading a bundle can see what confinement
  actually held.

  Two limitations are **already pinned by tests that assert the gap exists** rather than
  hidden: the timeout bounds the direct child but does not reap the process tree, and fork-
  storm containment is relative to ambient load, not absolute. Those are the honest residual
  risk, and they are disclosed where a reader will find them.

  **F7.1 is therefore NOT blocked**, and the phasing below is corrected accordingly. The
  remaining work here is narrow and optional: surface the two known gaps in the
  user-facing output of an execution-proven claim, not only in the module's tests.

  *Why this entry was wrong:* it was written from the feature inventory in §1, which lists
  what each feature *is*, not from `src/sandbox/`. That is the same error §8d of
  `WORLD_CLASS_DETECTION_PRD.md` records — "the rules were written from this document's
  root-cause prose, not from the vulnerable files" — reproduced in a document whose own
  governing rule is *measure first*. Recorded rather than quietly edited, because a PRD that
  hides its own misses is worth less than one that does not.

**Exit gate.** Execution-proven coverage published per family with a stated ceiling;
third-party verification demonstrated from a clean environment; calibration drift gates
the release; sandbox threat model documented and tested.

---

## 10. Feature 8 — Compliance & reporting

**Measured today: nothing, and this is the feature where being wrong is most expensive** —
a compliance artifact is read by auditors and regulators who will not re-derive it.

Four coverage maps exist (`docs/compliance/`), and `scripts/nist-compliance/` builds the
NIST AI 600-1 catalog from its source spreadsheet with a gate asserting they match. That
gate is good and should be the template for the rest.

**Work.**

- **F10.1 — Every framework mapping gets a provenance gate.** NIST AI 600-1 has one
  (`controls.json` matches the spreadsheet). ASVS, LLM Top 10, Privacy Framework and EU AI
  Act do not. A mapping nobody can trace to its published source is an assertion, not
  evidence.
- **F10.2 — Distinguish "we check this" from "we check this well."** A control mapped to a
  detector with 5% recall is *covered* in the map and uncovered in reality. Carry the
  measured recall of the backing detector into the coverage map, or mark the control
  `partially-evidenced`. This is the single highest-integrity change in this document.
- **F10.3 — Never claim a control the scanner cannot evidence.** Audit every mapping for
  controls that are organizational rather than technical (policy, training, governance).
  Mark them explicitly out of scope rather than implying tooling satisfies them.
- **F10.4 — Framework version pinning and drift.** Frameworks are revised. Pin the revision
  in every emitted attestation and fail the gate when the upstream source changes without
  a corresponding mapping review.
- **F10.5 — Report determinism as a published property.** `--deterministic` should make
  SARIF byte-identical run to run; `bench/determinism` exists. Extend it to every emitted
  format (SARIF, JUnit, SBOM, attestation) and state it in the docs — auditors care that
  the same input yields the same artifact.

**Exit gate.** Every framework mapping traceable to a pinned published source with a
gate; coverage maps carry the measured strength of the backing detector; determinism
verified for all emitted formats.

---

## 11. Feature 9 — Product surfaces & integrations

**Measured today: nothing.** Ten slash-command dispatchers, an MCP server with 17 tools,
an LSP, three IDE distributions (JetBrains, Neovim, VS Code), and hooks. The engine is
gated heavily; **the surfaces that carry it to users are not gated at all.**

The consequence is asymmetric: a detection regression is caught by four benches, while a
broken IDE extension ships silently.

**Work.**

- **F11.1 — Smoke every surface in CI.** LSP: start, initialize, publish diagnostics on a
  known-vulnerable fixture, shut down. MCP: enumerate tools, call each read-only tool,
  assert the two write tools refuse out-of-tree paths. IDE packages: build and install.
  None of this is deep testing; all of it is currently absent.
- **F11.2 — Time-to-first-finding as a tracked metric.** The ICP is vibecoder-first
  (`docs/POSITIONING.md`). For that user the binding constraint is how long until the
  first useful result, not aggregate F1. Measure it on a cold cache for a mid-size repo,
  and treat a regression as a gate failure.
- **F11.3 — Incremental / changed-files-only scanning.** `incremental.js` exists behind a
  flag. Full-repo scan latency is the reason the pre-commit path is painful; a measured
  incremental mode is the fix. Gate on correctness parity: incremental results must equal
  full-scan results for the changed set.
- **F11.4 — Fail loudly, not silently.** The `rate-limit.js` defect — a detector that
  discarded 100% of its own findings, project-wide, undetected — is a *class*. Add a
  startup self-check asserting every registered detector produced ≥ 1 finding on the
  polyglot fixture corpus, and fail the build when one goes dark.
- **F11.5 — One documented golden path per surface.** Each integration should have a
  single tested end-to-end walkthrough, exercised in CI, so documentation drift is a test
  failure rather than a support ticket.

**Exit gate.** Every surface has a CI smoke test; time-to-first-finding tracked with a
regression gate; a dark detector fails the build.

---

## 12. Feature 10 — Measurement & release

**Measured today:** the most mature feature, and still the source of three defects found
in a single day on 2026-08-19.

| defect | consequence |
|---|---|
| `bench/independent` had no per-entry timeout | one entry hung a run for 6 h; 129 entries unscored; **every previously published figure came from a harness that could stall silently** |
| `bench:layer-recall:check` gates on a floor | a 31 → 116 improvement passed like a no-op; published table stale ~5× for weeks |
| neither local gate nor pre-push hook sets `CI=1` | 8 tests passed locally and failed in hosted CI; the engine emits a CI-skip notice tagged `parser: 'IR-TAINT'` that the tests counted as a finding |

**Work.**

- **F12.1 — Run the suite under CI conditions in the pre-push gate.** `CI=true
  GITHUB_ACTIONS=true npm test` catches the third defect above in seconds. This is the
  cheapest item in this document and should land first.
- **F12.2 — Gates assert equality, not floors, where a rise is also news.** A floor gate
  cannot distinguish "unchanged" from "much better", which is precisely how a baseline
  rots. Either compare exactly and require deliberate re-baselining, or emit a loud
  notice on improvement.
- **F12.3 — Every long-running bench gets a watchdog.** `bench/independent` now has one.
  `layer-recall`, `proof-corpus`, `polyglot` and `realworld-recall` do not.
- **F12.4 — Grow the independent population toward 750+ and enforce the held-out slice.**
  It is 315 today with 64 held out. Prioritize Go and Ruby entries, since those are the
  measured zeros, and Kotlin, which has none.
- **F12.5 — Expand the mutation gate.** It is the anti-overfitting control and has **12
  cases**. Every new detector family should ship a metamorphic pair (verdict must hold)
  and an adversarial near-miss (verdict must flip). Scale it with the engine.
- **F12.6 — Publish the honest scorecard, prominently.** 3.56% localized recall is a low
  number. Publishing it, with the methodology that makes it low, is a stronger market
  position than a corpus-derived F1 that does not survive contact with real code — and it
  is the only position consistent with the project's stated moat.

**Exit gate.** CI-condition run in the pre-push gate; every bench has a watchdog; no gate
is floor-only without a stated reason; population ≥ 500 with Go/Ruby prioritized;
mutation gate ≥ 30 cases.

---

## 13. Phasing

| Phase | Scope | Why here |
|---|---|---|
| **P0 — Cheap integrity** | ~~F12.1, F12.2, F12.3, F11.4, F7.5~~ — **LANDED 2026-08-20** (`2aae26e`, `243e744`) | Each closed a class of silent failure already observed. F7.5 turned out to be already satisfied (see above) and blocks nothing. |
| **P1 — Instrument the unmeasured** | F3.1–F3.2, F4.1, F5.1, F6.1, F11.1 | Nothing in P2 is trustworthy without these. Expect published numbers to *fall*. |
| **P2 — The measured zeros** | F1.1–F1.4, F2.1–F2.2, F12.4 | Go + Ruby are a third of the population; the per-stage histogram decides the work. |
| **P3 — Depth per feature** | F3.3–F3.5, F4.2–F4.5, F5.2–F5.5, F6.2–F6.5, F7.1–F7.4 | Capability, once each area can prove it moved. |
| **P4 — Integrity of the claim** | F10.1–F10.5, F11.2–F11.5, F12.5–F12.6 | Compliance and surfaces last: they publish what the earlier phases establish. |

**P0 and P1 block the rest.** Running P2–P4 against the current instruments would produce
numbers nobody should trust, in either direction.

### P0 outcome, recorded 2026-08-20

Landed in `2aae26e` and `243e744`, both gated and on `origin/main` with hosted CI green:

- **F12.1** — `test:ci-parity` (104 tests, 45 s) in the pre-push gate *before* the 4-minute
  suite, plus a static invariant. The invariant's first draft was useless and **its own red
  check proved it**: it matched the bare identifier, which the `finally` restore lines kept
  present while the file was broken. It now requires an assignment.
- **F12.2** — layer-recall gates on equality; improvement fails too, verified in both
  directions against the real corpus.
- **F12.3** — shared `bench/_lib/watchdog.mjs` with 5 tests; `bench/polyglot` skipped on
  purpose (read-denied by the committed `.claude/settings.json`).
- **F11.4** — detector liveness, which **found two dead detectors on its first run** and
  both were then fixed: `k8s-admission` (the documented `kind:` content check had never been
  implemented, so Kubernetes worked only for repos naming a directory `k8s/`) and
  `install-script` (`package.json` fails `shouldScan`, so the rule was never invoked).
  `KNOWN_DARK` is empty.

**The k8s fix needed BOTH admission gates**, which is the durable lesson: `runScan` admits a
file into `fileContents`, then `runFullScan` re-filters that same list with `shouldScan()`
at `engine.js:7980`. With only the first opened, the predicate returned true, the walker
collected the files, and the scan still returned zero.

Blast radius measured rather than assumed: 16 of 1129 YAML files newly admitted (1.4%), all
in fixtures/caches; self-scan unchanged at 427 — a drift that was **predicted and did not
happen**.

---

## 14. Success criteria

Measured on the **held-out slice**, in both configurations, with the strict metric:

1. **Ten instruments, one per feature**, each labelled by a third party, each reporting
   `{n, d}`, each with a held-out slice never read during development.
2. **Go and Ruby off zero** (≥ 5% localized recall each), with no regression elsewhere.
3. **Fix-discrimination ≥ 80% sustained** as recall rises.
4. **Taint's attributable share of localized TPs > 1 and rising**, reported per phase. If
   Feature 2's work completes and taint still contributes ~1, that is a finding to act on,
   not to explain away.
5. **Every compliance control carries the measured strength of its backing detector.**
6. **No published number without its configuration**, and no corpus-derived figure printed
   adjacent to an independent-population figure without saying which analysis ran.

---

## 15. Risks

| Risk | Mitigation |
|---|---|
| Instrumenting eight features is a very large scope | Each instrument is independently shippable and ends in a published number; P0 alone is worth landing. |
| The honest numbers look like a catastrophic regression | Publish both figures with the methodology stated, exactly as `bench/independent/README.md` already did when recall fell 33.6% → 12.7%. A number that drops because it became true is the value proposition working. |
| Fitting to 315 known answers | Held-out slice never read during development; mutation gate; corpus-provenance check already refuses self-authored entries as accuracy evidence. |
| Recall work explodes false positives | Every feature carries its own FP budget; fixed upstream revisions are real-world negative controls, far stronger than synthetic clean fixtures. |
| Adding benches slows the gate past usability | Benches are measurements, not gates, unless explicitly promoted; the pre-push gate stays cheapest-fail-first. |
| Secret validation (F4.2) exfiltrates a live credential | Explicit opt-in only, never default, provider-sanctioned endpoints only, and never for a secret the user has not already flagged. |

---

## 16. Open questions

- **Does "analyze as a library" warrant a distinct mode?** For a library the public API *is*
  the trust boundary; for an application it is not. Same code, different correct answer.
- **Should container-image scanning be in scope at all?** It is a crowded space with mature
  tools. Declaring it out of scope may be stronger than a shallow implementation.
- **Is convention-deviation (Theme 6) a detector or its own product surface?** "You deviated
  from your own pattern" is a different claim from "this is exploitable" and may deserve
  its own severity model.
- **What is the honest ceiling on execution-proven?** Before investing in F7.1, estimate
  what share of findings are provable by a sub-minute sandboxed PoC. If it is 15%, that
  number should be published as the ceiling rather than pursued indefinitely.
- **Should the independent population include languages with no current detector coverage?**
  Adding Kotlin/Rust entries would lower the headline while measuring something real. This
  document's bias says yes, but it should be a deliberate decision.

---

## 17. Reproducing every number in §1

```bash
cd scanner
npm run bench:independent -- --json          # localized/wide recall, per-language, per-CWE
npm run bench:independent -- --deep --json   # taint's attributable share
npm run bench:layer-recall                   # per-layer, per-language attribution
node ../scripts/corpus-provenance-check.mjs  # self-authored share of bench/cve-replay
```

Committed artifacts: `bench/independent/RESULT.json` (2026-08-19, engine 0.138.0, 309
scored / 6 unscored), `bench/layer-recall/baseline.json`, `docs/METRICS.md`.
