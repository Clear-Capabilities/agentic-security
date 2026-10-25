# Implementation status: GA promotion

**Product:** Agentic Security. **Source:** the GA promotion PRD (an untracked root working document). **Registry:** [`docs/capabilities.yaml`](../capabilities.yaml). **Bar:** [the GA bar](../how-it-works/maturity-model.md#the-ga-bar).

This page is the promotion record. A capability is promoted only when its row here shows evidence for every criterion, and the registry change is the same commit.

## Phases

| Phase | Content | Status |
|---|---|---|
| 0 | The GA bar in the registry and the checker; the bar applied to the twelve capabilities that were already GA; the limits sections they depend on | Done. Tagged as 0.180.0, whose hosted release gate failed on the SCA replay check (see below), so it ships in 0.181.0 |
| 1 | Wave 1: hardening and measurement promotions that need no new runtime dependency | Three promoted in 0.181.0 (sibling sweep, blast radius, federation); four held, with the evidence below brought up to date in 0.184.0 |
| 2 | Wave 2: promotions that need a real container engine, registry, signing tool or local model in hosted CI | Three promoted in 0.183.1 (exploit proof, proof-gated fix, source-to-artifact provenance) and one in 0.184.0 (runtime corroboration); four held with the evidence below |
| 3 | Wave 3: Labs to Preview interface freezes, and the strategic metrics reported as product numbers | Five Labs capabilities frozen and moved to Preview in 0.182.0; strategic metrics reported from 0.182.0 |

Phase 0 changed what GA means, not what is GA. Wave 1 is the first set of promotions made against the bar.

## Phase 0: what was built

- **Registry fields.** A GA record carries `since`, `contract`, `contractTest`, `gate`, `platforms` and `limits`. A Preview record carries `contract` or a dated `contractNote`.
- **Mechanical checks** in `scripts/check-positioning-docs.mjs` (`bar` and `limits` rules): every named page, test, gate, job and section must exist; the contract test must be run by a scanner test script; the gate must be a check `scripts/release-check.mjs` evaluates; at least one platform job must be Linux; the limits section must carry a `limits-verified` date no more than 90 days before the checkout's HEAD commit. Both directions are tested in `scanner/test/docs-positioning.test.js`.
- **Two new release checks.** `contract-conformance` runs exactly the contract tests the registry names (`scripts/check-ga-contracts.mjs`). `sca-replay-gate` runs the dependency-risk bench in a check mode that compares to the committed result and fails on a drop beyond half a point of version recall or precision, or on a lost scored entry. It fetches the pinned manifests and queries the public advisory database, so it needs network and is not part of the offline pre-push gate.
- **Limits sections written** where a GA capability had none: assurance modes, model egress, AI-written-code guardrails, CI gating, scanning (including the measured dependency-matching figures).

## The twelve existing GA capabilities against the bar

| Capability | Contract page | Contract test | Gate | Limits section |
|---|---|---|---|---|
| Deterministic security analysis | output schema | `finding-schema.test.js` | `corpus-gate` | trust and limitations, known limits |
| Dependency risk with function-level reachability | [dependency finding contract](../reference/dependency-finding-contract.md) (0.184.0, was the output schema) | `contracts/dependency-finding.contract.test.js` (was `sca-verdict.test.js`) | `sca-replay-gate` (new) | scanning, what a scan does not do |
| Taint flow and reachability corroboration | [taint flow contract](../reference/taint-flow-contract.md) (0.184.0, was the finding evidence walkthrough) | `contracts/taint-flow.contract.test.js` (was `reachability-claim.test.js`) | `layer-recall-gate` | METRICS, reading it honestly |
| Falsification of findings | finding evidence walkthrough | `falsification.test.js` | `mutation-gate` | trust and limitations, what a clean result means |
| Fix synthesis | fixing vulnerabilities | `fix-verify-loop.test.js` | `fix-verification-gate` | verified remediation, what verification does not establish |
| Verified remediation | verified remediation | `fix-verify-tests.test.js` | `fix-verification-gate` | verified remediation, what verification does not establish |
| Scan health | scan health | `scan-health.test.js` | `contract-conformance` | scan health, what it does not tell you |
| Assurance gate modes | assurance modes | `assurance-mode.test.js` | `contract-conformance` | assurance modes, what they do not do |
| Model egress policy | model egress | `egress-policy.test.js` | `contract-conformance` | model egress, what egress policy does not do |
| AI-written-code guardrails | AI engineering role page | `bodyguard.test.js` | `contract-conformance` | AI engineering, what the guardrails do not do |
| MCP server and agent-tool audit | MCP tool contract | `mcp-protocol-smoke.test.js` | `contract-conformance` | MCP tool contract, what the classification means |
| CI gating | CI setup | `ci-templates.test.js` | `contract-conformance` | CI setup, what CI gating does not do |

All twelve pass the mechanical criteria. None was demoted.

## Wave 1: decisions and evidence

Seven capabilities were assessed. Three met the bar and were promoted in 0.181.0. Four did not, and the reason for each is a measured result, not a missing document.

### Promoted

| Capability | Contract page | Contract test | Gate | What was built |
|---|---|---|---|---|
| Repository-wide sibling sweep | [sibling sweep contract](../reference/root-cause-sweep.md) | `contracts/root-cause-sweep.contract.test.js` | `sibling-sweep-gate` (new, equality) | `bench/sibling-sweep`: eight seeded sink kinds plus a 150-sibling case. A defect the bench exposed was fixed: a chain of argument-less calls such as `Runtime.getRuntime().exec(x)` anchored on its first call, so unrelated uses of `Runtime.getRuntime()` counted as siblings |
| Blast-radius assessment | [blast radius](../security-graph/blast-radius.md#contract) | `contracts/blast-radius.contract.test.js` | `blast-radius-gate` (new, equality) | `bench/blast-radius`: 300 seeded graphs, 7856 targets, compared with an independent reference |
| Cross-repository graph federation | [federation contract](../reference/federation.md) | `contracts/federation.contract.test.js` | `contract-conformance` | A contract test that runs the real commands and checks both graph files are byte-identical afterwards |

The measured limits are on each capability's page and are not softened. The sweep finds every same-shape copy (159 of 159) but only 1 of 9 siblings whose argument is built another way, and it can match a mention in a comment. Blast radius agrees with its specification on every seeded target, which says nothing about how faithful a real graph is.

### Held, and why

Re-checked against the code in 0.184.0. Two of the four held figures in the original record were out of date, and one was hard to meet by construction.

| Capability | Held at | Evidence |
|---|---|---|
| Code Boundaries security graph | Preview | The lineage accuracy corpus passes 17 of 24 cases, with 7 capability-tier failures. Four are source categories the JavaScript catalog has no entry for (`http-upload`, `cli-argument`, `storage-read`, `user-input`): adding them to the shared taint catalog would also make them taint sources for the whole engine, so it needs a lineage-only source catalog, not an entry. Two are aliasing and interprocedural shapes that need changes to the field-identity driver, and one is an unsupported sink. The corpus is JavaScript only. Per-language measured taint recall is 58% for JavaScript and 66% for Python |
| Deterministic context intelligence | Preview | **Flask is no longer the gap.** The analysis now sees SQLAlchemy ORM operations (`Model.query...`, session writes, chained deletes) and judges ownership at the first write rather than the first read. On the application-shaped benchmark that took Flask from 6 of 10 routes unresolved to 0 (3 true positives, 7 true negatives) and Express precision from 82% to 100% (12 of 12), with 100% recall. 2 routes remain unresolved because the router-mount prefix is not composed into the route path. The cases are self-labelled and synthetic, so these figures are not accuracy on real applications, and only the SQLAlchemy data layer is covered for Python |
| Compliance control evidence | Preview | **The gap named here is closed.** All 10 bundled frameworks now have a per-control coverage map, generated from the framework files and checked for staleness (`scripts/compliance-coverage.mjs`, run by the doc-drift gate), and the README counts are checked against them. What stays Preview is the coverage itself: most frameworks are selective subsets of a much larger standard, and the maps say so |
| Finding provenance from Git history | Preview | **The recorded figures were stale.** Renamed files are followed since E7-02 and the labelled corpus passes 13 of 13 (it was recorded as 12 of 13). Coverage is 83.8% of eligible findings (393 of 469) on this project's own source in deep mode against a 95% target, because 64 findings come from whole-project analyses that a single-file replay cannot reproduce. Cold-cache overhead is 24 times against a 1.3 times target, measured on a 15-finding fixture where the scan itself takes 44 milliseconds: the cost is roughly 70 milliseconds of git work per file, so the ratio cannot reach the target on a small project. The guide now states these numbers |

These four stay in the registry as Preview with their limits written.

## Wave 3: Labs to Preview (interface freezes)

Preview is not GA. Each move below gives the capability a reference page that lists every field, flag and exit code, and a compatibility test that runs the real commands and fails when the output gains or loses a field the page does not list. The record `version` changes in the same commit as the page when a field does.

| Capability | Contract page | Contract test | What else was done |
|---|---|---|---|
| Eval Lab and model router | [Eval Lab report](../reference/eval-lab-report.md) | `contracts/eval-lab-report.contract.test.js` | The report is built from a stand-in model arm and the deterministic baseline; a cost not reported is proven `null`, not zero. The SARD integration stays "not built" because the lab's custody rule forbids answer keys |
| Fleet scanning and dependency blast radius | [Fleet contract](../reference/fleet-contract.md) | `contracts/fleet.contract.test.js` | Runs a real `fleet scan` over two fixture repositories; the manifest key lists are exported from the validator so the page cannot drift from them |
| Finding-to-rule compiler | [Rule compiler contract](../reference/rule-compiler-contract.md) | `contracts/rule-compiler.contract.test.js` | Drives synthesize, evaluate, promote, status and regress over a fixture finding; a rule that fires on the safe code it is held to exits 1; a tampered ledger refuses to run. The "not yet merged" branch note on the status pages was stale (merged as #86) and is corrected |
| Release assurance | [Release assurance contract](../reference/release-assurance-contract.md) | `contracts/release-assurance.contract.test.js` | New `release-package build\|verify` command replaces the demo-script assembly. New release check `release-assurance-gate` builds a package from a scan, requires the independent offline verifier to accept it, and requires it to refuse a lowered severity, a restated verdict and an unsigned scan |
| Detection and response | [Detection and response contract](../reference/dnr-contract.md) | `contracts/dnr.contract.test.js` | The exposure window now joins the artifact provenance graph: `dnr window --artifact-graph` places a deployment that names only an image digest at the commit the image declares, refuses a record that disagrees with its image, and never infers a commit the image does not declare |

### Stays Labs, with exit criteria

- **Runner-level capability enforcement.** Linux is `partially-verified` (only the controls the hosted `sandbox-linux` job proves), mediated network is unsupported and macOS runs are `host-proved`. It leaves Labs when every control is proven by `sandbox-linux` and mediated network is either supported or removed from the advertised set.
- **Detector spec synthesis.** A drafting aid for a human reviewer with no measurable output. Promoting it would claim a precision it cannot have.

### Preview limits that remain

The five stay Preview because each says something is still being hardened: Eval Lab has no SARD integration and small written datasets; fleet is local to one machine with a toy scaling measurement; the rule compiler is text matching and nothing measures learning independently of the compiler's own corpus; release assurance is signed by the holder's own key and is not certified by anyone else; `dnr` has three renderers that were never run against a live product. Learn gets no GA capability from this wave, by design.

## Wave 2: hosted evidence and decisions

Four hosted jobs now run in `ci.yml`, each against the real tool and each failing (never skipping) when the tool is missing: `proof-linux`, `proof-container`, `artifact-real` and `local-model`. The first three are blocking checks, so the release gate's hosted-CI check (`remote-ci-green`) refuses a commit on which they are red. `local-model` stays informational (see below).

### Promoted in 0.183.1

| Capability | Contract | Hosted evidence | What the first real run found |
|---|---|---|---|
| Execution-backed exploit proof | [exploit proof contract](../reference/exploit-proof-contract.md) | `proof-linux`: 36 of 36 reproductions, 0 false confirmations, 3 of 3 timeouts degraded. `proof-container` (docker 28.0.4): 36 of 36, 0 false, 3 of 3. macOS: 39 of 39 (committed earlier). All committed under `bench/proof-fabric/` | The container leg's first run confirmed only 30 of 36: Java proofs could not start because the runner replaced the image's `PATH` (`javac: not found`). Fixed, and the container result committed is the corrected one |
| Proof-gated fix | the same page | The proof gate bench runs on both Linux jobs and matches its baseline: 0 of 15 unsafe fixes applied, 1 of 8 safe fixes applied, 7 refused for want of a reproducer | Generation covers three classes, so the gate applies few fixes by design: it fails closed. The three-class scope is written into the contract |
| Source-to-artifact provenance | [artifact provenance contract](../reference/artifact-provenance-contract.md) | `artifact-real`: docker 28.0.4, a registry container and cosign 2.4.1; archive, engine and registry inputs agree (10 advisories), the clean image has 3, signed/other key/unsigned give `verified`/`invalid`/`missing`, source patched is flagged (7) and source equal is not (0). `bench/artifact-real/RESULT.json` | Three product defects: a source scan limited to SCA was read as having no advisories, so a source on the same vulnerable version looked fixed; cosign's wrong-key message was classified `missing`; a key-signed image from a registry with no transparency log could not be verified. All fixed with tests, and `--ignore-tlog` added as an explicit opt-in. The guide's stale limits (no engine, no registry, stand-in only) were rewritten |

### Promoted in 0.184.0

| Capability | Contract | Hosted evidence | What the first real exports found |
|---|---|---|---|
| Runtime corroboration of the scanned graph | [runtime corroboration contract](../reference/runtime-corroboration-contract.md) | `telemetry-capture` (now a blocking check) runs the real OpenTelemetry JavaScript SDK with its OTLP exporter, Envoy 1.31.2, nginx 1.27.5 and a kind cluster with the kube-apiserver audit log on, and records the files they write, untouched, with a manifest of tool, version, command and digest. The packs are in `scanner/test/fixtures/telemetry-packs/`. Each adapter parses its pack with no error (3 spans, 6 Envoy lines, 4 nginx lines, 79 audit events) and every record passes the observation contract | Two false security decisions. The Envoy adapter read any response flag as a denial, so an upstream failure (`UF`) and a missing route (`NR`) were reported as `denied`; the Kubernetes adapter read any status of 400 or more as a denial, so on the real audit log (2 forbidden, 4 not found, 1 conflict) it would have reported 7 denials instead of 2. Both now decide only on an authorization outcome. The recorder itself had two bugs the real tools exposed (an upstream that could not answer because the recorder blocked its own event loop, and Envoy buffering its access log) |

### Held, and why

| Capability | Held at | Evidence |
|---|---|---|
| Local model support | Preview, contract frozen | The [contract](../reference/local-models-contract.md) and its test freeze the loopback rule (against a table of accepted and refused endpoints), both preset configurations and the closed set of Ollama error codes, and pin that a refused endpoint makes no request and a failed one never falls back to another provider. `local-model` ran a real Ollama server with `qwen3.5:2b` on a 4-CPU hosted runner and every contract check passed, but the model cannot finish its work there: the validation scan took 389 seconds for 19 findings and produced only `escalate` (6) and `unvalidated` (3), and the Eval Lab model arm completed 0 of 5 attempts. The job stays informational |
| Model-assisted validation | Preview, contract frozen | The [contract](../reference/model-validation-contract.md) and its test now exist, with a recorded-reply replay harness (`test/helpers/model-replay.js`) that plays eleven written replies through the real validator: well-formed accept, reject and escalate, a reply with the wrong challenge, file or line, no JSON, an unknown verdict, an injection note, an error status and a dead connection. The replies are written to the documented shape, not captured from a model, and the page says so. The live path still returned no `accept` or `reject` to measure, and no precision is published for the model's own judgments |
| Agentic discovery (hunt) | Preview, contract frozen | The [contract](../reference/agentic-discovery-contract.md) and its test now exist and play recorded replies through the real pipeline. Writing them found two defects, both fixed: a hunter reply whose candidates had no file and line was dropped without a word, and `--forget-refuted`, named in the tool's own output, was not read by the command. The hosted run still hunted 0 of 3 areas with no candidates, so there is no hunt precision to publish; publishing a number would invent one |
| Haskell and Nix/NixOS analysis | Preview | Needs unseen-shape targets met and one measurement on a second sealed holdout. The unseen split has been measured, so tuning the engine against its known failures would be fitting to it, and a holdout authored for this purpose by the engine's own maintainer cannot be independent, so it is not manufactured here |

## Reviewed criteria and open gaps

**G2 (both-direction tests).** Reviewed by reading each contract test's cases on 2026-10-19. The two that were weaker than the bar wants are closed in 0.184.0: dependency risk and taint now have contract pages and tests over the finding's own fields (`contracts/dependency-finding.contract.test.js`, `contracts/taint-flow.contract.test.js`), each checking both directions.

**G7 (honest degradation).** Audited for the capabilities this programme promoted or froze. Each path below produces a named state and has a test:

| Capability | Way it can fail to run | Named state | Test |
|---|---|---|---|
| Dependency risk | Offline with nothing cached, or the advisory service did not answer | `scanHealth.freshness.advisories` with `unanswered` and `source`, status `partial`, and a condition saying an empty result is not evidence of safety. **This was a gap:** such a scan used to report `complete` | `contracts/dependency-finding.contract.test.js` |
| Dependency risk | The vulnerable function cannot be checked | `functionReachable: unknown`, never `unreachable` | same |
| Taint flow | No nameable source | `source: null`, no invented hops | `contracts/taint-flow.contract.test.js` |
| Exploit proof | No container engine, or only local confinement | `unavailable`, or `DEGRADED` completeness | `contracts/exploit-proof.contract.test.js` |
| Proof-gated fix | No reproducer for the class | refused as `no-reproducer` | the `bench/fix-verification` proof gate, whose baseline records 7 refusals for want of a reproducer and fails on any change |
| Artifact provenance | No signature, wrong key, no key, no dependency data in the source | `missing`, `invalid`, `unavailable`, and a refusal that names the cause | `contracts/artifact-provenance.contract.test.js` |
| Runtime corroboration | Nothing imported, unmatched or stale telemetry | `unavailable`, `partial` with limitations | `contracts/runtime-corroboration.contract.test.js` |
| Model validation | No endpoint, a refused endpoint, a failed call, an unusable reply | `model-disabled`, `policy-blocked`, `unavailable`, `malformed` | `contracts/model-validation.contract.test.js` |
| Agentic discovery | A failed call, an exhausted budget, a cap, a discarded candidate | `degraded` runs, `budgetExhausted`, `candidatesCapped` and a reason for each. **This was a gap:** discarded candidates were silent | `contracts/agentic-discovery.contract.test.js` |
| Federation | No local graph, a moved remote export | `stillValid: null`, `remote.ok: false` with a reason | `contracts/federation.contract.test.js` |
| Sibling sweep | Garbage input, a list over the cap | an empty result, `instancesTruncated` with exact counts | `contracts/root-cause-sweep.contract.test.js` |

The twelve capabilities that were GA before this programme are covered by the scan health, assurance mode, fix verification and egress tests, which exercise named degraded states. They were not audited path by path here.

## Not done

- **Haskell and Nix/NixOS** stays Preview for want of an independent second holdout (above).
- **The three model capabilities** stay Preview with frozen contracts. GA needs a measured number, and the only model a hosted runner can run produces none.
- **The four Wave 1 capabilities** stay Preview, with the measured reasons above. Code Boundaries needs a lineage-only source catalog and field-identity changes; provenance needs whole-project analyses it cannot replay, and its overhead target cannot be met on a cold cache; the context analysis still needs router-mount composition and covers one Python data layer.
- **`local-model` stays an informational check**, because the model it runs cannot finish the work it is checking.
