# Implementation status: GA promotion

**Product:** Agentic Security. **Source:** the GA promotion PRD (an untracked root working document). **Registry:** [`docs/capabilities.yaml`](../capabilities.yaml). **Bar:** [the GA bar](../how-it-works/maturity-model.md#the-ga-bar).

This page is the promotion record. A capability is promoted only when its row here shows evidence for every criterion, and the registry change is the same commit.

## Phases

| Phase | Content | Status |
|---|---|---|
| 0 | The GA bar in the registry and the checker; the bar applied to the twelve capabilities that were already GA; the limits sections they depend on | Done. Tagged as 0.180.0, whose hosted release gate failed on the SCA replay check (see below), so it ships in 0.181.0 |
| 1 | Wave 1: hardening and measurement promotions that need no new runtime dependency | Three promoted in 0.181.0 (sibling sweep, blast radius, federation); four held with the evidence below |
| 2 | Wave 2: promotions that need a real container engine, registry, signing tool or local model in hosted CI | Not started |
| 3 | Wave 3: Labs to Preview interface freezes, and the strategic metrics reported as product numbers | Five Labs capabilities frozen and moved to Preview in 0.182.0; strategic metrics not yet done |

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
| Dependency risk with function-level reachability | output schema | `sca-verdict.test.js` | `sca-replay-gate` (new) | scanning, what a scan does not do |
| Taint flow and reachability corroboration | finding evidence walkthrough | `reachability-claim.test.js` | `layer-recall-gate` | METRICS, reading it honestly |
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

| Capability | Held at | Evidence |
|---|---|---|
| Code Boundaries security graph | Preview | The lineage accuracy corpus passes 17 of 24 cases, with 7 capability-tier failures (a missing `http-body`, `database`, `storage-read`, `user-input`, `http-upload` or `cli-argument` node, and flows through an alias or a helper function that were not connected). The corpus is JavaScript only. Per-language measured taint recall is 58% for JavaScript and 66% for Python |
| Deterministic context intelligence | Preview | The application-shaped benchmark settles 31 of 39 routes. Flask is the gap: 6 of its 10 routes are unresolved and none of the settled Flask routes is a true positive. Express precision is 82% (2 false positives in the ownership families). The cases are self-labelled and synthetic |
| Compliance control evidence | Preview | There are 10 bundled frameworks and per-control coverage maps for 5 of them, which the README records as a known gap. The coverage maps are hand-maintained, with no gate that checks their counts against the framework files |
| Finding provenance from Git history | Preview | Known-origin accuracy is 92.3% against a 98% target, coverage 91.2% against 95%, and cold-cache overhead roughly 27 times against a 1.3 times target. Renamed files resolve to `partial`. This needs engine work, not documentation |

These four stay in the registry as Preview with their limits written. They are the Phase 1 backlog, in this order: provenance (engine), the lineage corpus failures, a compliance coverage generator, then Flask context resolution.

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

## Reviewed criteria and open gaps

G2 (both-direction tests) was reviewed by reading each contract test's cases on 2026-10-19. Ten of the twelve have cases in both directions for the claims on their pages. Two are weaker than the bar wants, and Phase 1 owes them stronger contract tests:

- **Dependency risk.** `sca-verdict.test.js` pins the triage verdict rules, not the dependency finding's own fields. The measured behavior is gated by `sca-replay-gate`, but a contract test over the `vulnerable_dep` finding shape is still to be written.
- **Taint and reachability.** `reachability-claim.test.js` pins how the reachability claim is published (unknown is first class, every rate carries its denominator). The flow itself is gated by `layer-recall-gate` and `mutation-gate` rather than by a contract test over its output fields.

G7 (honest degradation) has not yet been audited per capability. The scan health, assurance mode, fix verification and egress tests exercise named degraded states, but the per-capability audit the PRD calls for is part of Phase 1.

## Not done

Wave 2, the strategic metrics from Wave 3, and the four Wave 1 capabilities held above. In particular, the hosted CI legs that need a real container engine, a registry, a signing tool and a local model have not been written or run, and the measurements that sit below their own targets (finding provenance accuracy, coverage and overhead; Haskell and Nix unseen shapes) have not moved.
