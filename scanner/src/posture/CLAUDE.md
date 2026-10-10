# scanner/src/posture/

Annotators that run **after** every detector has emitted, plus state stores read by slash commands. 90+ modules — almost all small. Pattern: each module exports a function the engine wires into the annotation pipeline (`annotateX(findings, ctx)`), or a state-read/write helper (`loadX(scanRoot)`).

## What goes where (categories, not exhaustive)

**Annotation pipeline (mutate findings in place — order matters in `engine.js`)**
`finding-defaults` → `stable-id` → `clustering` → `reachability-filter` → `confidence` → `calibration` → `exploitability` → `mitigation-composite` → `persona-prioritization` → `why-fired`. The order is encoded in `engine.js`; if you add an annotator, decide whether it consumes upstream signals (confidence, family, parser) and place it after those.

**Calibration + held-out evaluation** — `calibration.js`, `calibration-drift.js`, `validator-metrics.js`, `holdout-eval.js`. The seed corpus lives at `calibration-seed.json`; held-out labels are taken via `loadLabeledJsonl`. Brier and ECE both live in `holdout-eval.js`; never reintroduce a "fit-on-the-table" version.

**Published accuracy scorecard (R3)** — `accuracy-scorecard.js`. Pure aggregation + markdown/JSON rendering for `docs/SCORECARD.md`; the impure driver that performs the corpus and self-scan runs is `scripts/scorecard.mjs` (`npm run scorecard`). Every rate is carried as `{n, d}` and rendered through `formatRate()` so a percentage can never appear without its denominator; entries a run could not score are excluded from every denominator *and* disclosed by name. No F1 is emitted — see the module header for why, and don't add one without a labelled real-world population to measure precision over.

**Cross-language taint** — `cross-lang-{openapi,grpc,graphql,orm,queues,meta}.js`. Each parses a contract artifact (`openapi.json`, `*.proto`, `*.graphql`, queue config) and emits a chain finding when the same data crosses a language boundary into another module's finding.

**Risk amplification** — `epss.js`, `kev` (in `version.js`), `blast-radius.js`, `crown-jewels.js`, `exploitability.js`, `bounty-prediction.js`, `risk-in-dollars` (lives in `scripts/`, not here).

**Secrets lifecycle** — `secret-history.js` (git-history blob sweep for committed-then-removed secrets, behind `--secret-history`), `secret-live-check.js` (opt-in, offline-degrading live/dead/unknown labeling via a read-only provider "whoami"; behind `--validate-secrets`).

**Production-posture ingest** — `auth-posture-import.js`, `network-policy-import.js`, `telemetry-ingest.js`, `waf-ingest.js`, `feature-flags.js`. These read customer-side YAML and convert to mitigation flags consumed by `mitigation-composite.js`.

**Fix lifecycle** — `fix-history.js` (apply + backup + recover), `fix-verify.js` (**five legs, not "re-scan + lint"**: rescan + lint + the project test suite + the fix-honesty gate + a PoC re-check, and it appends one record per attempt to `.agentic-security/fix-metrics.jsonl` — see `mcp/CLAUDE.md`'s `verify_fix` row, which had the same stale "no writes" claim), `fix-plan.js` (oversized-patch fallback — **not currently wired to anything**, see the dead-module allowlist), `regression-test-gen.js`, `deterministic-fix.js` (safe context-independent literal-swap patch synthesis — md5/sha1→sha256, TLS verify-off→on — materialized on demand by `mcp/synthesize_fix`; every patch still passes through `apply_fix`'s inline verify before it lands).

**Measured fix loop (R5)** — `fix-metrics.js`. `verifyFix` times each stage
(`rescan`/`lint`/`tests`/`honesty`) and appends one record per attempt to
`.agentic-security/fix-metrics.jsonl`; `summarizeFixDurations` turns those into
the reported distribution, surfaced on `scan.fixMetrics` and as a stderr line
on human formats. Distinguish it from `time-to-fix.js`, which *estimates*
engineering hours from family and patch shape before anything runs — this
module reports only what was observed.

Three bucketing rules are load-bearing and each has a test that fails if
relaxed: **failed attempts never enter the validated distribution** (a failed
verification short-circuits, so blending them makes a worse pipeline look
faster); **"tests skipped" is bucketed apart from "tests passed"**
(`validatedWithoutTests`, since a project with no detectable suite reaches
`ok:true` on a weaker and much cheaper check); and **per-stage timings come
from validated runs only** (a failed run truncates every stage after the
failure point). Buckets partition the attempts, so the counts always sum.
Percentiles are nearest-rank — every figure reported is a duration some run
actually took — and are flagged `reliable:false` below n=10 rather than hidden
or quoted as settled. Recording goes through `isSafeStateDir`, so it declines
rather than creating a stray state dir outside a project.

**Remediation ledger (M5 deliverable #6)** — `remediation-ledger.js`. The
I/O half of Blast-Radius: Remediation Command Center (FR-507 + AC-31) —
locking, JSONL append, tolerant read, and a hash chain over
`.agentic-security/remediation/items.jsonl`/`items.lock`, matching
`fix-metrics.js`'s own append-and-tolerant-read shape above (one
newline-terminated record per `appendFileSync`, a torn tail dropped on
read, never a whole-file rewrite). The pure state machine it writes
through — `foldRemediationItem`/`foldRemediationLedger`/
`validateTransition` — lives at `../lineage/remediation.js`, making this
the SECOND `posture/` → `lineage/` import in the codebase
(`auditor-walkthrough.js`'s `graph:` branch was the first — see "First
`posture/` → `lineage/` import" below). `appendLedgerEvent` is the single
place `validateTransition` is enforced; no CLI command computes validity
for itself. Its `withLock` is a faithful local PORT of
`provenance/lifecycle.js`'s own `withLock` — not an import, since that
function is not exported.

**Agentic verification** — `verifier.js`, `verifier-target.js`, `verifier-ephemeral.js`, `harness-discovery.js`, `adversary-agent.js`, `defender-agent.js`, `auditor-agent.js`, `three-agent-pipeline.js`.

**Methodology additions (Agentic Methodology PRD, removed post-implementation)** — default-on annotators/artifacts that layer the agentic-hunter methodology on the deterministic engine:
- `falsification.js` — default falsification pass. For each taint-style finding, tries to DISPROVE it (locate a context-matched control on the path, reusing `dataflow/sanitizer-proof.js`'s shape rules read-only); a blocked finding is demoted + `quarantined`, never removed and never severity-touched (recall-preserving, like `proof-gate`). Wired after `annotateProofGate`. Opt out: `AGENTIC_SECURITY_NO_FALSIFICATION=1`. Optional LLM tier over survivors when an endpoint is configured.
- `entrypoint-inventory.js` — attack-surface completeness ledger. Enumerates every entry point (HTTP/queue/cron/CLI/env/upload/webhook) with a disposition each; on `scan.entrypointInventory`.
- `root-cause-sweep.js` — from confirmed findings, finds sibling instances detectors missed with total-count accounting (`found === candidates + mitigated`); on `scan.rootCauseSweep`. Searches the corpus **once per distinct sink pattern**, not once per finding — findings deriving the same pattern share one walk and one set of (read-only) match records. The counts are always exact; the materialised `instances` list is a bounded sample (`INSTANCE_SAMPLE_LIMIT`, 100) and says so via `instancesTruncated`. Both properties are load-bearing on large corpora: the per-finding walk was O(findings × corpus-bytes) and the instance records were O(findings × matches), which together exhausted a 6 GB heap on a 40k-file suite. If you touch this module, keep the own-site exclusion **per pattern group** — resolving it globally makes a group subtract an exclusion it never matched and drives counts negative.
- `model-routing.js` — capability-based CWE/severity→model policy; stamps `finding.dispatchModel` (strongest for crypto/auth/critical, mid for injection, cheapest for low-sev hardening) for cost-sensitive subagent dispatch.
- `fix-honesty-gate.js` — deterministic honesty gates on fix output: a residual-risk hand-wave guard, a cited-file:line requirement for any FP/safe verdict, and FULL/MITIGATION/WORKAROUND completeness tiers. `fix-verify.js` accepts a `fixMeta` param and consults this gate when it is present (`if (fixMeta && typeof fixMeta === 'object')`). Both `mcp/apply_fix` and `mcp/verify_fix` now expose an optional `fixMeta: {residual, verdict, evidence, signals}` input property and pass it straight through — `fixMeta` is inherently agent-self-reported (only the caller claiming a fix worked knows its own residual-risk reasoning), so the fix was exposing the property, not computing anything server-side. On `apply_fix`'s patch path this is stronger than advisory: `verifyFixCore`'s own `ok` formula already folds in `honesty.ok`, and the inline re-verify already gates the write on `ok` — so a hand-wave residual or an uncited false-positive verdict in `fixMeta` blocks the write itself. The closed-loop test leg (`fix-verify-loop.js`) is separately wired into `mcp/apply_fix` behind `AGENTIC_SECURITY_FIX_RUN_TESTS=1` and does not (yet) thread `fixMeta` through — that path still bypasses the honesty gate.
- **The PoC-re-check leg is now genuinely reachable, without a schema change.** `verifyFixCore` accepts a `poc` param and, when given one with `poc.code` set, re-runs the proof harness against the patched files (`fix-verify.js`, the `pocLeg` block). `mcp/tools.js`'s `verify_fix` `inputSchema` still has no `poc` property — instead of widening it to make the caller resupply PoC data it never had, the handler looks up the original finding server-side from `last-scan.json` via `stable_id` (best-effort, `allowUnsigned: true` — a missing/tampered scan just means no PoC is available, not a `verify_fix` failure) and passes its `f.poc` straight through. Since `annotatePocs` attaches an HTTP-shaped `f.poc` by default on every scan (see the "Operator entry point" section below), any finding with a matching CWE template gets its PoC re-checked automatically on every `verify_fix` call — no agent-side plumbing required. `tests`/`honesty`/`poc` are all forwarded in the response (previously silently dropped).

**Relevance scoping (R6 + R9)** — `relevance.js`. Turns the two existing *inventories* into *inputs*: `entrypoint-inventory.js` supplies the attack surface, `threat-model.js` supplies assets/boundaries/STRIDE, and `annotateRelevance(findings, ctx)` scores each finding by how reachable and how threat-modelled it is. Sets `entrypointReachable: true|false|null`, `relevance` (0..1), `relevanceTier: 'direct'|'indirect'|'unreachable'|'unknown'`, `relevanceFactors[]`, and re-ranks `exploitability` (ordinal priority, ×1.15 direct / ×0.6 unreachable, floored at 0.05, tier label recomputed on the same thresholds `annotateExploitability` uses). Reachability is a forward BFS over a literal-specifier import graph (JS/TS relative + Python dotted + Java FQCN) starting at every entry-point file.

Its contract is **recall-preserving, same precedent as `falsification.js` / `dataflow/proof-gate.js`**: it never removes a finding, never touches `severity`, and never asserts `unreachable` without positive evidence — a negative verdict additionally requires the intra-repo import graph to be hole-free *along the reachable set* (an unresolved relative import or a non-literal `require(x)` in a reachable file hides a possible edge, so every would-be `unreachable` degrades to `unknown`). `null`/`'unknown'` is a first-class state and is **not** the same as `false`. Wired in `engine.js` after the entry-point inventory is built and after every finding has been appended (multi-sink and cross-language chains included) so nothing escapes annotation; this is the one annotator that deliberately runs after `why-fired`.

**Enforced verification separation (R7)** — `verification-separation.js`. The falsification pass could already try to *disprove* a finding; what it could not do was prove the checker was not the producer. This module supplies that structural guarantee:

- `recordProducer(finding, producerId)` stamps provenance **write-once** — a later party cannot re-stamp itself as producer to manufacture separation.
- `assertSeparation(finding, verifierId)` refuses when verifier === producer, and **fails closed** when no producer was recorded (unestablishable separation is not separation).
- `recordVerdict(finding, {verifierId, lens, verdict, reason})` runs that check itself, so there is no path to a recorded verdict that skips it. `lens` is the perspective (`'control-flow'`, `'reachability'`, `'data-shape'`, `'llm-review'`); `verdict ∈ 'upheld'|'refuted'|'undecided'`. One verifier gets one vote per lens — a re-vote replaces rather than stuffs.
- `consensusOf(finding) -> {verdict, upheld, refuted, undecided, lenses[]}` — majority, `'undecided'` on a tie or on no verdicts.

Producer ids are namespaced `detector:<parser>`, verifier ids `verifier:<name>`, so the two spaces cannot collide. **Nothing throws** (posture convention): every entry point returns `{ok:false, refused:true, reason}`.

Contract is **recall-preserving, same precedent as `falsification.js` / `proof-gate.js`**: a `refuted` verdict never removes a finding and never touches `severity`. It is a triage signal, not a deletion.

Wired in `falsification.js`: the detector is stamped as producer, the falsification pass records under `VERIFIER_FALSIFICATION` on the `control-flow` lens, and the optional LLM tier records separately under `VERIFIER_LLM_REVIEW` on the `llm-review` lens — which is what makes a contested finding legible *as contested* (upheld vs refuted → consensus `undecided`) instead of resolved by whoever spoke last. Result lands on `finding.verification = {producer, verdicts[], consensus}`.

**Run attestation (R4)** — `attestation.js`. Turns determinism from an implementation property into something a third party can check. `computeRunAttestation({findings, engineVersion, rulesetVersion, bundleSha, root, sign})` returns `{digest, algorithm, findingCount, engineVersion, rulesetVersion, bundleSha, canonicalisation, proves, doesNotProve, signature?}`; `verifyRunAttestation(attestation, {findings, …})` re-derives and returns `{ok, reason}`.

Canonicalisation is an **allowlist, not a denylist** — each finding reduces to `id ⇥ severity ⇥ file ⇥ line ⇥ cwe ⇥ vuln`, rows sorted, multiplicity preserved. That is what makes the digest independent of emission order, run ids, timestamps, durations, separator style, and the absolute prefix (when `root` is given), while a changed severity/file/line/rule id/cwe or a finding appearing or disappearing all change it. A new volatile field cannot leak in without being added to the allowlist deliberately. `parser` and `family` are deliberately **excluded**: `parser` records which analysis engine fired, which is environment-sensitive (the Python AST path vs. its regex fallback), so including it would report an environment difference as a findings difference.

**What it proves / does not prove** — the attestation carries both statements inline, and both are asserted by a test so they cannot be quietly dropped. It proves two finding sets with the same digest under the same canonicalisation are the same findings from the same engine/ruleset/bundle. It does **not** prove cross-machine reproducibility — no second machine was compared, and this repo makes no such claim. Signing reuses `integrity.js`'s per-install HMAC key handling verbatim (`signLastScan`); no second key mechanism was introduced. `verifyLastScan` is *not* reused because it verifies against a sibling `.sig` file whereas an attestation carries its signature inline, so verification re-signs and compares in constant time. Being symmetric, the signature is tamper-evidence for the operator, not third-party non-repudiation.

Wired in `bin/agentic-security.js` after every filter and after `makeDeterministic`, over `normalizeFindings(scan)` — i.e. it attests the set that actually ships — and surfaced as `attestation` in `toJSON`. `bundleSha` is read from the sidecar next to the *running* bundle and is `'unavailable'` when running from source, rather than reporting a dist hash that may not correspond to this run.

**`verifyRunAttestation` now has two real callers.** `agentic-security verify-attestation <file>` auto-detects whether the given JSON is an evidence bundle (`.finding`+`.signature`, verified via `evidence-bundle.js`'s Ed25519 path, unchanged) or a run attestation (`.digest`+`.canonicalisation`, either bare or embedded under a full `last-scan.json`'s `.attestation` field) and dispatches accordingly. A run attestation isn't self-contained the way a bundle is — verifying it means re-scanning the project (`--against <path>`, default `.`) and confirming the fresh scan reproduces the attested digest, which is the actual, meaningful claim this artifact makes ("does this codebase, scanned now, match what was attested earlier"). Separately, `scripts/release-check.mjs`'s `attestation-self-check` gate round-trips a synthetic finding set through compute→verify (and a mutated copy through verify, which must fail) on every release, catching a broken canonicalisation or signing path before it ships — independent of whether any project ever calls `verify-attestation` on a real artifact.

**Issuer and trust basis (CORE-003.AC03).** `evidence-bundle.js` signs an `issuance` block inside the canonical bytes (only when present, so pre-existing bundles keep their signatures): issuer id and key fingerprint, `trustBasis: 'self-issued-local-key'`, `independentlyCertified: false`, and a plain statement. `verifyEvidenceBundle` returns `trustBasis`/`issuer`/`trustNote`; a bundle with no `issuance` verifies and is reported `none-declared` (never as trusted); an unknown basis, an `independentlyCertified: true` claim, or an issuer fingerprint that is not the verifying key is rejected even when validly signed. The only basis this build can verify is the local one: a third-party basis needs a trust-root policy that does not exist here. A signed run attestation carries the same self-issued label. `verify-attestation` exit codes are unchanged. Signing keys are protected from workers by `sandbox/trust-boundary.js` (see `sandbox/CLAUDE.md`). Suite: `test/evidence-issuer.test.js`.

**Integrity + signing** — `integrity.js` (per-install HMAC for `last-scan.json`), `rule-pack-signing.js`. The HMAC key lives at `$XDG_CONFIG_HOME/agentic-security/scan-key`; override via `$AGENTIC_SECURITY_HMAC_KEY`. Premortem-derived; do not regress to hostname-derived.

**Rule lifecycle** — `custom-rules.js` (YAML pattern DSL), `rule-overrides.js` (`disable:` gated on signature), `rule-packs.js`, `rule-synthesis.js` (proposes suppressions from triage feedback), `ruleset-version.js`.

**First `posture/` → `lineage/` import.** `auditor-walkthrough.js`'s `graph:` mapping branch (Data Flow Explorer M4 sub-project 6b) imports `evaluateGraphFlowPredicate`/`buildObligationMappingFromGraphPredicate` from `../lineage/obligation-predicates.js` — the first time any module in this directory has reached into `lineage/` (previously a one-way boundary: `lineage/` never imports `posture/`, and nothing here imported it back). It mints a real `ObligationMapping` record (see `scanner/src/lineage/CLAUDE.md`) from `scan.lineageGraph` when present, purely additively — never touching the pre-existing `anySignal`/`allCleared`/`anyCleared`/`hasUnverifiableMapping` status machinery.

**NIST Privacy Framework 1.1 (`privacy-framework.js`)** — assessment + remediation
over the bundled `compliance-frameworks/nist-privacy-1-1.json` (all 104 controls).
Sits on top of `auditor-walkthrough.js`'s evaluator and adds the half a narrative
cannot give you: a gap becomes a FINDING (`family: privacy-compliance`,
`CWE-359`) carrying an actionable remediation, so it flows through triage and
`/fix`.

Four buckets, and the bucket is always stated: `gap` (mapped signal failing —
the ONLY bucket that emits a finding), `engine-gap` (NIST rates it code-testable
but this engine has no signal — disclosed by name, never a pass), `manual` (NIST
rates it not code-testable), `satisfied`. NIST's own `codeTestable` rating is
carried per control and is what separates "nobody checked" from "we checked and
it is fine" — 48 of 104 are governance controls no scanner can assess, and
reporting those as passed is the failure mode the module exists to prevent.

Two guards are load-bearing. **Findings are opt-in**
(`AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1`); the assessment always lands on
`scan.privacyFramework` and at `.agentic-security/privacy-framework.{json,md}`,
but appending to `scan.findings` by default would change every severity count
and gate verdict downstream. And the **vacuous-satisfaction guard**: a
`family:`-mapped control clears when no findings of that family are open, which
is also true of a scan that read zero files — so when nothing was examined every
mapped control degrades to `engine-gap` instead of reporting as satisfied. That
one was caught by the module's own test, not in review.

**Posture artifacts** — `sbom.js`, `aibom.js`, `api-inventory.js`, `threat-model.js`, `trust-boundary-diagram.js`, `stack-playbook.js`, `deploy-platform.js`, `license-policy.js`, `material-change.js`, `mttr.js`, `streak.js`, `accuracy-scorecard.js` (see "Published accuracy scorecard (R3)" above — this line previously named a bare "scorecard" module that never existed under that filename), `security-trend.js`.

**Why this fired** — `why-fired.js`. Runs LAST so it reflects every annotation. Customer-facing provenance.

## Conventions

- **Mutate or copy?** Annotators that set finding fields mutate in place. Helpers that derive a *new* finding list (clustering, dead-code) return a new array.
- **State files.** All state goes under `.agentic-security/` (scan root) or `~/.config/agentic-security/` (per-install). Never write to the scanner source tree.
- **Annotation order matters.** If your annotator reads `f.confidence`, run it after `annotateConfidence`. If it reads `f.exploitability`, run it after `annotateExploitability`. Wire in `engine.js`, not in `index.js`.
- **No throwing.** Every annotation in `engine.js` is wrapped `try { … } catch (_) {}`. Your annotator must degrade gracefully — set `null` on the field and continue.
- **Dead-module test.** `npm run test:lifecycle` fails the build if you export a public symbol from a posture module that no other source file imports. Wire it in `engine.js` (or allowlist it with a written reason in `test/no-dead-modules.test.js`).

## Assurance contracts, baseline and rollout config — `assurance/` (11 modules)

Foundation for the differentiation work (CORE-001, CORE-002, CORE-004). All of it is pure or read-only, and **nothing in it is wired into `engine.js` or the scan/report path**: a default scan is byte-for-byte unaffected, which `test/posture/assurance-config.test.js` pins. Consumers (X-201 and later) import it directly.

- **`identity.js`**: ids for evidence records. Reuses `canonicalJson` (`evidence-bundle.js`) and `computeStableId` (`stable-id.js`, a hypothesis id is a finding's stable id). An id is a hash over an **allowlist** of semantic fields, so clocks (`createdAt`) and migration bookkeeping can never reach it. Prefixes `vrec/obind/capd/rlab/rev` are distinct from lineage's, and nothing here imports `lineage/` (a test checks that).
- **`schema-kit.js`**: validator primitives. Closed-world (unknown fields rejected), typed error codes, supported major version 1 only, `sha256:<64 hex>` digests.
- **`verification-record.js`**: the one verification record. Six distinct outcomes, a SEPARATE repair status, four evidence kinds. Structural rules: a model can only produce `inference`; `confirmed` needs referenced trusted-runtime-proof or independent-adjudication evidence; `confirmationLevel` must equal the level derived from the evidence (a forged level fails); `refuted` needs an applicable non-model oracle, valid preconditions and proving evidence.
- **`contracts.js`**: observation binding (references a lineage observation by id only; absence in a sampled observation cannot establish `blocked`), capability decision (only runner/proxy mediation with a backend and an active-probe digest may claim `enforced`; a hook or in-process check never can), routing label (a decided label must name an adjudication or trusted-execution source), release evidence (`complete` is derived, never trusted), and `validateRecordSet` for duplicate ids, dangling references and conflicting claims.
- **`migrations.js`**: explicit v1 adapters from legacy shapes (proof tier, boolean verified, egress decision, attestation, lineage observation) and a legacy view back out. Evidence can be lost, never invented: a legacy `true` is `inconclusive`, `proof-failed` is `inconclusive` not `refuted`, and the only route to `confirmed` is an explicit `trustedRunner` assertion bound to a commit. The legacy view's `verified` is `true` only for confirmed and `false` only for refuted, otherwise `null`.
- **`config.js`**: the unified feature configuration. Reuses the env/`.agentic-security/*.yml` mechanism. Precedence: kill switch (`AGENTIC_SECURITY_NO_ASSURANCE` or `AGENTIC_SECURITY_NO_<FEATURE>`) > explicit override > `AGENTIC_SECURITY_ASSURANCE_<FEATURE>` > `.agentic-security/assurance.yml` > default (everything off). **A project file can never enable a `high-risk-execution` feature** (the file lives in the scanned repo); invalid configuration fails closed; unsupported platforms return a typed `unsupported` with the disclosure. `runFeature` returns typed `blocked`/`unsupported`/`degraded`/`disabled` results and never prompts.
- **`bounded-io.js`**: `guardedModelCall` is the only route for new model/network calls. It owns no HTTP client (the transport is injected): feature gate, then `evaluateEgress` BEFORE the payload exists, then `redactPayload`, then the request-size limit, then deadline plus bounded retries, then output cap, with every decision appended to the existing egress audit chain. `readFileBounded`, `capOutput`, `withDeadline`, `retryBounded` enforce the limits `config.js` claims; `maxMemoryMiB` is carried for a runner and disclosed as not enforced here.
- **`baseline.js`, `baseline-inventory.js`**: baseline capture (`scripts/baseline-capture.mjs`, `npm run baseline:capture`). Read-only; records HEAD, dirty paths, exact source and bundle digests, tool versions, entry points, the seven mappings and an 18-entry capability inventory (implemented / partial / unsupported / unmeasured, every path and exported symbol verified at capture time, a missing one is a reported problem). Unknown facts are `{status:'unknown', reason}` with no value. `evaluateBaseline` invalidates exactly the capabilities whose cited files changed and lists unrelated user changes as retained/introduced. The manifest is machine-specific, so it is generated on demand and not committed. When you change a capability's source or tests, update its inventory entry in the same change.

- **`rollout.js`, `rollback.js` (REL-002).** Staged rollout and rollback. `rollout.js`: the three stages (`offline-fixtures`, `shadow-canary`,
  `opt-in-supported`), the documented gates per feature and stage (`gatesFor`, `describeRollout`), an append-only ledger (`newLedger`), `promote`
  (one stage at a time, every gate needs evidence that names its own suite and carries a sha256; the kill switch and an unsupported platform
  block it; policy versions are never reused) and `effectiveMode` (an enabled feature below opt-in runs as `fixtures` or `shadow` and can never
  change an outcome). `rollback.js`: `READER_POLICY` (per record kind, whether a previous reader is retained; four kinds honestly say no),
  `planRollback`/`applyRollback` (restore the last known-good stage, append a `rollback` event, FLAG evidence and claims `stale` or
  `incompatible`, never delete or rewrite), `EvidenceStore`/`guardedFeatureRun` (append-only, a thrown feature records a failure and costs no
  evidence), and the known break: `verifyWithPreCore003Reader` is a faithful copy of the verifier before the `issuance` block existed, which
  rejects every newly signed bundle; `exportLegacyBundle` is the migration path (verifies the original first, re-signs without issuance,
  returns a sidecar carrying the dropped trust basis). Pure, consumed by tests and `docs/guides/assurance-rollout-and-rollback.md`; nothing in
  the scan path imports them. Suite: `test/release-closure/` (`npm run test:release-closure`). The release closure itself (the plan, the
  commit-bound record, the judge) is `scripts/release-closure.mjs`, not a posture module.

Tests: `test/posture/assurance-{baseline,contracts,config}.test.js`, all in `test:posture`.

## One verification record, trusted oracles and replay (X-201, X-202, X-203)

Built on `assurance/` (the record schema, migrations, config) and `sandbox/trust-boundary.js` (the boundary). Three
directories, all consumed rather than wired into the default scan: a default scan is unchanged, and every addition to an
existing output is an additive field.

**`verification/emit.js`: the one emit function (X-201).** `emitVerification(surface, source, ctx)` is what every
verification surface calls to get the version-1 record (`{ ok, record, legacy, errors }`, never throws, validated before it
returns). Surfaces and where they call it: `fix-verify.js` (`verificationRecord` on the result, which the MCP `verify_fix` and
`apply_fix` tools forward), `fix-verify-loop.js`, `execution-proof.js` (`proveFinding` result), `verifier.js`
(`verifierVerificationRecords`, called by the CLI `verify` command into its `verifier-runs/` run record, never onto the findings that
are written back to `last-scan.json`), `autopilot.js` (`rec.verificationRecord`, `commit` option), `discovery/index.js` (hunt:
`verificationRecords`, advisory) and `oracles/oracle.js` (the `oracle` surface). The rule for every mapping: evidence is lost,
never invented, so no legacy surface can reach `confirmed` or `refuted`. A PoC run under the older sandbox path is `inconclusive`
(not a trusted runner; `proof-failed` is a triage signal, not a refutation), a static re-scan with no exploit oracle is `not-run`,
a family with no oracle is `unsupported`, a harness failure is `error`, a model verdict is `inference` evidence only. Only
`oracle` emissions carry trusted-runner evidence, because only `oracles/oracle.js` builds them.

Legacy consumers: nothing existing was renamed or removed. For a consumer that wants a status or a boolean, `toLegacyVerificationView`
(`assurance/migrations.js`, also returned as `legacy`) maps `verified` to `true` only for `confirmed` and `false` only for `refuted`,
`null` for the other four, and carries `status` with the real outcome name, so a skipped check can never read as a pass and an unrun
check never as a failure. Native vocabularies keep their own fields (`proofTier`, `verifier_verdict`, autopilot `outcome`, fix-verify
`ok`); the record sits beside them as `verificationRecord`. A boolean `true` migrated from a legacy record is `inconclusive`.

**`oracles/` (X-202).** `oracle.js` is the adapter contract (`validateOracleSpec`, `defineOracle`) and the runner (`runOracle`).
`adapters.js` holds the five class adapters (injection-execution, authorization-decision, state-transition,
side-effect-reachability, parser-resource), `registry.js` the frozen registry and `oracleManifest()`, the machine-readable
description X-208 gates on (class, prerequisites, platforms with an honest per-platform status, budgets, negative controls,
fixture locations, limitations, logic digest). Fixtures: `test/fixtures/oracles/<class>/{positive,negative,inconclusive}`.
- A run is: feature gate (`verification-oracles`, off by default, operator-only), request validation (closed-world: labels,
  verdicts and receipts are never accepted; reserved `__oracle_*` names and path escapes are refused), prerequisite check
  (an unmet one is `unsupported` with a typed reason and the target is never executed), a fresh workspace plus a verifier-owned
  evidence directory outside it, the target through `runInBoundary` ONLY (a test pins that `oracle.js` imports no other way to
  run code), a digest check of the adapter's own harness (a target that rewrote it makes the run `error`), then verifier-side
  interpretation of what the run left behind, read after the whole process tree is dead. The settled status comes from
  `settleVerification` with `observedBy: 'verifier'` evidence; a decided result (`confirmed`/`refuted`) additionally needs an
  exact commit, else it is held at `inconclusive`.
- `refuted` needs the adapter's own precondition (a benign control passed); a target that failed to load, exited early or never
  reported is `inconclusive`. A run cut by its deadline decides nothing except for the parser/resource class, where the supervisor's
  own deadline observation IS the measurement.
- Receipts are issued only by `runOracle` (a WeakSet records them; they are deep-frozen; a copy or hand-built one is not
  `isIssuedReceipt`). They carry the observed output (capped), the logic digest, sanitized environment metadata (an allowlist: no
  hostname, paths or environment values) and the record id. Unsigned: signing belongs to the signer domain.
- Platforms: macOS (userspace backend) is the only host these have been executed on. Linux is declared `unverified` in the
  manifest and cannot be `supported`; today the boundary refuses to run on the namespace backend, which the runner reports as
  `unsupported`. Changing what an adapter asserts means bumping its `version` (the harness text and version feed `logicDigest`).
- KNOWN LIMIT: the target is imported into the harness process. A target written to recognise the oracle's payload and forge the
  effect artifact is not distinguishable from a real injection; the oracle bounds the effect it tests, it is not a defence
  against a target built to fool it. Tamper controls cover what a worker or target can do to adapter logic, labels, receipts and
  status text.

**`replay/replay.js` (X-203).** A replay manifest pins the repository commit, the patch hash, the fixture hash, the toolchain
(runtime version, platform, architecture, and a container digest when there is one), the oracle id, version and logic digest, the
inputs and the budgets. It is a description of an oracle run, not a second runner: `replayManifest` ends in `runOracle`, so the
supervised process tree, output cap and cleanup are the existing ones. It rejects, and nothing executes, on a content hash that does
not match, an oracle that changed since the manifest was made, a scope wider than "exactly the named oracle, no network,
workspace-only writes", a budget over the oracle's ceiling, an unsafe file path or an unknown field. Missing toolchain, container
runtime or image, a denied network (acquisition is never attempted: this build fetches nothing), a disabled feature or a boundary
that cannot run are typed prerequisites with `resumable` set honestly; the attempt is parked (`awaiting-prerequisites`) and
`resume` re-evaluates the prerequisites against the real host (a claim that they are met does nothing). Outcome while parked is
`not-run` (or `unsupported` when this build can never meet it, such as container execution, which is not implemented), with no
evidence; nothing is substituted for the execution that did not happen. Toolchain identity is exact. Persistence of attempts is
the caller's (the attempt object is plain data). Suites: `test/verification/{verification-record,oracle-adapters,replay-manifest}.test.js`
(`npm run test:verification`).

## Patch-negative verification and non-taint classes (X-204, X-205)

Same posture as the three directories above: consumed, not wired into the default scan, every output addition additive, and
nothing changes with the feature flags off. Suites: `test/verification/{patch-negative,non-taint-classes}.test.js`
(`npm run test:verification`).

**`verification/patch-negative.js` (X-204).** `verifyPatchNegative(req, { config, runOptions })` is `verified-fix` only when four
`replayManifest` runs (so each is pinned, boundary-confined and receipted) show: the exploit oracle CONFIRMS on the original
revision, REFUTES on original-plus-diff, and the `functional-regression` oracle (the requester's declared cases) is clean on the
original (a baseline: wrong expectations are reported, not blamed on the patch) and on the patched revision. It stops at the first
non-passing step and names it: the result carries `incompleteStep` and a typed `failureCode` (`original-not-reproduced`,
`patched-still-exploitable`, `patched-build-broken`, `functional-omitted`, `functional-baseline-invalid`,
`functional-regression-detected`, `oracle-changed`, `revision-unbound`, `prerequisite-unmet` (resumable where stated),
`environment-mismatch`, `promotion-refused`) and a `summary` that says what was and was not exercised. Gate: the
`patch-negative-verification` feature (high-risk execution, operator-only, off by default) plus `verification-oracles`.
Wiring: `fix-verify.js` (`verifyFix({ patchNegative, assuranceConfig })` adds `patchNegative` and `fixStatus`, and `ok` requires
`verified-fix`), `fix-verify-loop.js` (a `patchNegative` leg and the `verified-fix` verdict) and `fix/apply-fix-service.js`
(`applyVerifiedFix({ patchNegative })` writes only a promoted patch and returns `repairRecords`). With the flag off or no request,
those return exactly what they did before.

**`verification/patch-promotion.js`.** `promotePatch({ proposal, receipts })` re-derives the diff digest and revision from the
PROPOSAL and refuses any receipt that was not issued by `runOracle` (`isIssuedReceipt`: copies and hand-built receipts fail), that
covers different content than the exact diff on the original revision, that was issued for another commit or hypothesis, whose
oracle or inputs differ between the original and patched runs, whose environment identity differs, or that is reused in two roles.
Receipts are valid inside the verifier's process only; carrying a promotion across processes needs a signing domain (not here).

**`verification/repair-records.js`.** The CORE-002 record has one repair status and no value for a rejection, so the history is an
append-only ledger of separate, frozen, chained records: `proposed`, `rejected`, `promoted` (only through `recordPromotion`, which
accepts nothing but a result `promotePatch` returned `ok`), `applied` (only after a promotion for that exact diff) and
`rolled-back`. `verificationRepairFor`/`withRepairStatus` map the ledger onto the CORE-002 `repair` field (`replay-verified` carries the
patched-negative record id); a rejection leaves it at `proposed` because the foundation enum is not widened here. The ledger is
returned to the caller and not persisted: persisting it would need an artifact-registry classification.

**New adapters.** `replay-idempotency` (a factory receiving a recording stand-in for the effect: a request and a distinct request
are delivered as a control, then the same request is redelivered, and the verifier counts effects) and `functional-regression`
(declared cases against expected JSON values; the hypothesis is that behaviour REGRESSED, so a clean patch is `refuted`). Both have
the usual positive, negative and inconclusive fixtures under `test/fixtures/oracles/`.

**`oracles/scenario-classes.js` (X-205).** The supported-class manifest for non-taint defects, surfaced as
`oracleManifest().nonTaint`: tenant authorization and privileged action (REUSE `authorization-decision`), workflow order (REUSES
`state-transition`), bounded resource exhaustion (REUSES `parser-resource`) and replay/idempotency (the new adapter). Each class
lists what the requester must supply, its fixtures (`test/fixtures/non-taint/<class>/{positive,negative,scenario.json}`, application-style
code), its limitations and the report lines a reader sees; every `runOracle` result additionally carries a `disclosure`
(prerequisites, platform statement, limitations, class report). Unsupported non-taint classes (concurrent races, CSRF, authentication
throttling) are named with a reason. `judgeNonTaintHypothesis` is the rule that taint absence is never an input to a refutation:
without an executed oracle of the class's own adapter with proven preconditions the outcome is `not-run` (or `unsupported`); the hunt
mapper in `verification/emit.js` uses it. `trustedNegativeDenominator` counts only decided results of an executed oracle of an
advertised class with proven preconditions and trusted runtime proof, and lists every exclusion with its reason (its runtime consumer is `verificationCoverage` in
`verification/projection.js`, which the JSON report, the CLI report and the MCP/autopilot surfaces use for the trusted-negative line).

Not verified: Linux (the oracle platform statements stay `unverified`); only the declared exploit scenario and functional cases are
exercised, never the patch's correctness elsewhere.

## One projection for every interface, advisory/gating separation, conformance (X-206, X-207, X-208)

Same posture as the sections above: consumed, not wired into the default scan, every output addition additive and present only
when a verification record is. Suites: `test/verification/{interface-equivalence,advisory-gating,oracle-conformance}.test.js`
(`npm run test:verification`). Docs: `docs/guides/verification-schema-migration.md`, `docs/guides/verification-oracle-conformance.md`.

**`verification/projection.js` (X-206).** `projectVerification(record, { replay })` is the ONE place a record becomes something a
person or another tool reads: state, scope, oracle, evidence ids, replay prerequisites (derived from the record, plus the typed
ones a replay attempt reported), a what-was-verified / what-was-not summary, the legacy boolean view, and `text` lines. The JSON
report (`report/index.js` `normalizeFindings`), the CLI and Markdown reports (`verificationBlock`), MCP `explain_finding`,
`verify_fix` and `apply_fix`, and the autopilot response (`serializeAutopilotResult`, used by `scripts/autopilot.mjs --json`) all
call it; none formats its own verification text. The key is **`verificationView`**, never `verification`: a finding's existing
`verification` field is the producer/verifier separation record (`verification-separation.js`) and a first draft of this work
collided with it. An invalid record yields `verificationView: null` plus `verificationViewErrors`, never a guessed state. The text
never says "safe" or "fixed" for a partial result (a lint-style test covers every state, every repair status and the wording the real
surfaces emit; the fix-verify leg's native status word `fixed` is deliberately not echoed into a record reason). `verificationCoverage`
wraps `trustedNegativeDenominator`. Previous output schemas are pinned in `test/fixtures/verification-compat/`.

**`verification/advisory-state.js`, `verification/hypothesis-promotion.js` (X-207).** Hunt (`discovery/`) is advisory.
`writeAdvisoryState` is the only way advisory code writes: a closed file-name allowlist (the one hunt memory file), authoritative names
refused, write to a temp file and rename (a symlink or hard link planted at the target is replaced, never written through), the state
directory must resolve inside the project root. `discovery/memory.js` `saveMemory` uses it. `normalizeFindings` excludes any hunt
hypothesis (`parser: DISCOVERY` or a `discovery` object) from every finding list and exit code and records `advisoryExcluded`.
`promoteHypothesis({ hypothesis, result, policy })` is the only crossing: it verifies (not just checks presence of) a receipt issued by
`runOracle` (`isIssuedReceipt`), bound to the hypothesis and an exact commit and to a valid record settled `confirmed` at the
`runtime-confirmed` level, applies an EXPLICIT policy (fail-closed on an unknown key; the receipt rules are mandatory and cannot be
waived; `minConfidence`/`minAgreement` can only add a requirement), reuses `verification-separation.js` for hunter != verifier, and
returns a frozen audit record for every decision (`promoted`, `rejected`, `unsupported`, `inconclusive`) with no clock in it.
`runDiscovery` calls it only when `opts.promote = { policy, verify }` is given. The audit record is returned, not persisted:
persisting needs an artifact-registry classification and a signing domain, which are not decided here.

**`oracles/conformance.js` and `scripts/verification-conformance-check.mjs` (X-208).** One contract over every registered adapter:
static (class scope, budgets under `BUDGET_CEILINGS`, negative controls with an on-disk fixture, verifier-side evidence logic bound by
a digest, fixtures and logic pinned in `test/fixtures/oracles/conformance-pins.json`) and execution (state mappings, issued and frozen
receipts, three tamper attempts, an unavailable prerequisite, cancellation, replay). Wired into `scripts/release-check.mjs`
(`verification-conformance-gate`, in `RELEASE_GROUPS['benches-b']`) and, static half only, the pre-push gate
(`verification-conformance-static`). Where the boundary cannot run, execution is reported `not-run`, never passed; `--require-execution`
makes that a failure. A new adapter must be pinned deliberately (`--update-pins`).

## Frozen evaluation protocol, label custody and layer ablations: `evaluation/` (QA-001, QA-002, QA-003)

Offline measurement tooling, consumed by `scripts/evaluation.mjs` (`npm run evaluation -- <cmd>`, `npm run evaluation:synthetic`) and
`test:evaluation`. Nothing here is wired into `engine.js` or the scan path, and a test pins that no module outside `evaluation/`
imports it. **It builds machinery, not evidence.** No real adjudicated population, no real sealed set and no independent human
review exist in this repository, so every real-code gate reads `insufficient-population` or `unmeasured`; the exercised suite
(`synthetic.js`, fixtures in `test/fixtures/evaluation-synthetic/`) is authored by the tooling's developers and flagged
`synthetic: true` everywhere, and `gates.js` refuses to count it toward any minimum. Do not quote a score from the synthetic suite
as engine accuracy.

- **`protocol.js` (QA-001).** `freezeProtocol` validates a draft and returns a deep-frozen protocol with `protocolHash` (a digest over
  every semantic field). It pins engine/bundle digest, a clean measurement tree, tool and model versions, dataset licences, per-target
  pre/post commits and tree digests, scope, matching policy, limits, thresholds and split membership. Thresholds are the PRD section 5
  floor (`PREREGISTERED_THRESHOLDS`) and may be stricter, never looser or missing. `amendProtocol` yields a new versioned protocol with a
  field diff and empty `comparableWith`; with ANY result bound to the protocol's hash it refuses (`POST_RESULT_CHANGE`), so a threshold,
  matching rule or denominator cannot move after results are observed. `deriveSuccessorProtocol` is the only way forward and rejects a
  sealed target a result already consumed (`SEALED_REUSE`). A target removed from the population must appear in `retired` with a reason
  and stays in `originalTargetIds`. `assertBoundToProtocol` rejects a run scored under any other hash.
- **`grouping.js`.** Union-find over pair id, normalised upstream (a fork resolves to its parent), advisory ids, commits and template
  fingerprints; `assignSplits` places whole groups by a salted hash, `splitStraddles` is the check the protocol validator runs.
- **`labels.js` (QA-002).** Defect labels need a root-cause id, affected commit, language, family, a reviewed location RANGE (a CWE
  alone cannot be a label), evidence, and adjudication with at least two distinct reviewers who are not the proposer, recorded as
  independent, plus non-model evidence. A candidate (advisory-only) label is valid data and never scoreable. Negatives are `safe-real`,
  `patched` (post variant, paired to a defect) and `near-miss`. `matchFinding` matches by location plus family or CWE; CWE-only,
  wrong-file, no-line and out-of-range each fail with a distinct reason. A finding with no line cannot be localised, so it never
  matches (this is why the pattern-only layer scores zero on the synthetic suite: it reports no line, not a defect of the harness).
  This module can validate that a label SAYS it was independently adjudicated, not that it was.
- **`custody.js` (QA-002.AC03).** The custodian (verifier domain, role `custodian`) is the only writer of the label store; read needs the
  trust-domain `sealed-labels` read grant and the sealed hash to match. `protectedTermsFrom` / `guardPrompt` / `auditWorkspace` /
  `stageWorkspace` keep advisory prose, evidence refs, benchmark names, fixed-source hints, answer-key file names, advisory ids and
  symlinks out of anything the engine or a prompt sees; a leaking tree is quarantined (removed, recorded as an outcome, never scanned).
  These are PATTERN checks over known terms, not proof against a paraphrase. Process-level read denial of the label directory is the
  sandbox boundary's job (`runInBoundary({ labelDirs })`, which reports `blocked` where the host cannot prove the control).
- **`runner.js`, `scan-child.js` (QA-003).** `runEvaluation` records, per target and variant, status (`completed|timeout|error|unavailable|
  quarantined`), findings, duration, cost (null when unmeasured, never zero), failure reason and input/output hashes. The engine runs in a
  child process (killed by process group on timeout) over a staged copy, with a scrubbed environment. Run identity covers protocol,
  engine, layer, provider, model, settings, cache, budget, seed, replicate, split and every target digest; labels are not part of it.
  A tree that differs from the digest pinned in the protocol is refused. `runReplicates` checks deterministic reproduction and requires
  at least three replicates for the stochastic (model-assisted) layer; `runAblations` runs `deterministic-only`, `deep-taint` and
  `model-assisted` over identical targets and refuses incomparable configurations. `model-assisted` is `unavailable` without
  `AGENTIC_SECURITY_LLM_ENDPOINT`, recorded as such.
- **`score.js`.** End-to-end scoring: a timeout, error, unavailable or quarantined known positive is a MISS. Conditional-on-completion
  metrics are reported beside it, labelled, never instead of it. False positives are counted only on adjudicated negatives. Findings no
  adjudicated label accounts for go to a review queue and `unscored` (with counts and reasons), never auto-FP. Targets with no
  adjudicated label are `unlabeled-target`.
- **`gates.js`.** Judges a sealed-split score against the protocol's own thresholds. `pass` needs the population minimums (>=100 real,
  adjudicated, non-synthetic sealed positives and negatives per core language, >=30 positives per family) AND a measured value over the
  threshold; otherwise `insufficient-population` or `unmeasured`. A protocol failing its hash check, or a score from another protocol, is
  `rejected`. The interval-lower-bound gate is `unmeasured` until the interval method is implemented (QA-004), so `overall` cannot be
  `pass` in this build. `accuracy-scorecard.js` relays a gate report in an `evaluationGates` section (`summarizeEvaluationGates`),
  forcing `unmeasured` for a synthetic or unmarked report; `scripts/scorecard.mjs` reads the gate report from the independent bench directory
  when one has been written (none exists today).

Tests: `test/evaluation/{protocol,grouping,labels,custody,runner,gates-scorecard}.test.js` (`npm run test:evaluation`).
## Executable invariants, approval, scenarios and the business-state oracle: `invariants/` (X-401 to X-404)

Same posture as the verification directories above: consumed, not wired into the default scan, every output addition additive, and
everything off unless the **`invariant-scenarios`** feature (high-risk execution, operator-only, off by default) is enabled; running a
scenario also needs `verification-oracles`. Suite: `npm run test:invariants` (`test/invariants/`, executed tests skip loudly where the
trust boundary cannot run). Linux stays `unverified`: nothing here claims a Linux outcome. X-405 to X-408 (shrinking, repair
verification, coverage and export, the held-out ablation) are described in the section after this one.

- **`schema.js` + `expressions.js` (X-401).** The versioned invariant document: scope (an explicit application, entry, factory and
  environment), tenants, actors, resources, allowed transitions, FORBIDDEN outcomes and an oracle binding. Five classes
  (tenant-isolation, privilege-constraint, value-conservation, workflow-order, idempotency). Declarative only: forbidden outcomes are
  expressions from a closed grammar (`EXPRESSIONS`), every string in them matches a conservative charset, so no field can carry code;
  an op outside the grammar is rejected. Rejects ambiguous identities (duplicate actor/resource/transition/store key), dangling
  references, a missing, unregistered or wrong-class oracle binding, and preserves author, revision and review state. The id is a
  hash of the CONTENT (not the review), so an approval binds to exactly what was reviewed and an edit is a different contract.
  `expressions.js` exists so the oracle adapter can validate expressions without importing the schema (the schema imports the
  oracle registry; the registry imports the adapters).
- **`lifecycle.js` (X-402).** Inferred versus approved. `inferredInvariant` builds a PROPOSED skeleton (inferred, with source
  evidence and an uncertainty, authored by a model or by code); miners reuse it: `specification-mining.js` (`mineInvariantProposals`),
  `business-logic.js` (`mineWorkflowInvariants`), `logic-claims.js` (`invariantFromLogicClaim`) and the discovery lenses
  (`discovery/lenses.js` `invariantProposalFor`, surfaced by `runDiscovery` as `invariantProposals` only when asked AND the feature is
  on). The approval ledger is append-only, hash-chained and HMAC-signed under the per-install key (`integrity.js`): a transition
  records who, why, from, to, the authority it rests on, and the previous record. Only a HUMAN named by an explicit local reviewer
  policy (or verified by `fix/approver-registry.js`) can approve, reject or supersede; a model, code or the proposer cannot, and with
  no policy nothing can be approved. `classifyViolation` calls a settled `confirmed` result an APPROVED violation (may gate) only
  when the ledger verifies and says approved, else a CANDIDATE violation (advisory); a document that merely claims approval is a
  candidate, and a result without a receipt `runOracle` issued is `unverified`. `violationReport` keeps the two groups apart.
  Limits, stated: symmetric HMAC is tamper-evidence for the operator, not third-party non-repudiation; the reviewer identity is a
  claim checked against the operator's list, not authenticated; dropping the LAST record is not detectable; persistence is the
  caller's (the ledger is plain data).
- **`scenarios.js` (X-403).** `generateScenarios(invariant, { fixture, seed, bounds, config })`: five families (cross-tenant access,
  privilege change, reordered workflow, duplicate request, concurrent operations), each with synthetic tenants and actors, a seeded
  setup, a control sequence, an attack sequence, the forbidden outcomes and a cleanup. Bounded by actors, depth, requests,
  scheduling (a parallel group is at most 4 steps with a SEEDED start order) and time (the budget becomes the run deadline); every
  bound has a hard ceiling and an over-ceiling request is rejected, not clamped. Deterministic given the seed (no clock; ids are
  hashes). Confined to contracts scoped to a `disposable-fixture` and to fixture files the caller supplies; a shared/production
  scope, missing setup or a scenario that cannot be built is `unsupported` with its reason. `runScenario` builds a replay manifest
  (`replay/replay.js`) so the environment, toolchain and oracle logic digest are pinned, then runs it. `run.js` (`verifyInvariant`)
  is the one orchestration: generate, replay each scenario, classify against the ledger, report.
- **`business-state` oracle (X-404)** in `oracles/adapters.js` (class `business-state`, `requiresFeature: 'invariant-scenarios'`,
  fixtures `test/fixtures/oracles/business-state/`, pinned like every adapter). The harness gives the application an in-memory
  durable store and an effect recorder (`ctx.store`, `ctx.emit`), plays a control sequence and the attack sequence TWICE (a
  disagreement is `inconclusive`, never a verdict), and logs every durable write and emitted effect. `state-assertions.js`
  evaluates the forbidden outcomes VERIFIER-SIDE over that log after the tree is dead: durable writes, leaked content, totals,
  state moves and repeated effects decide; the response status is recorded in the event sequence and never decides, so a handler
  answering 403 after writing another tenant's record is a violation. A forbidden outcome reached by the control flow counts too.
  `refuted` needs the control flow to have visibly worked (durable effect, no error, clean, cleaned up). The result carries a
  bounded `report` (preconditions, sanitized snapshots with secret-looking fields redacted, the event sequence, per-assertion
  results with stable `ievd:` evidence ids); the ids are record evidence and the report digest is bound into the receipt.
  Two small additive changes to shared code: `oracle.js` supports an optional per-adapter `requiresFeature` and optional
  `judged.report`/`judged.evidenceItems`; `conformance.js` enables an adapter's `requiresFeature` for its execution checks.
- **Limits, not hidden.** The application is a factory returning `(ctx, key, payload)` actions over an in-memory store: durable state
  held in a real database, queue or file system is not observed. Concurrency is cooperative scheduling in one process (interleavings
  at await points), not parallel execution. A clean result covers only the declared bounded scenario. A target that recognises the
  oracle and forges its own log entries is not distinguishable from a real violation (the limit every adapter states).
- **`deployment-ablation.js` (X-308).** A frozen, SYNTHETIC deployment-context ablation: the same source deployed under an exploitable and a
  non-exploitable boundary configuration (`test/fixtures/deployment-ablation/`, seven cases, fourteen instances, kubernetes and compose
  deployments). `freezeAblationSet` hash-pins each source tree, each deployment tree, the labels and the graph arm's decision rule and binds
  the cases into a QA-001 protocol (`synthetic: true`, never counted toward a real-population gate); `verifyFrozenSet` refuses any drift
  before a measurement. `runPairedAblation` scores a source-only arm (the QA-003 child-process scan) and a graph-enabled arm (the shipped
  `runBoundaries` path plus a frozen demotion rule: demote only on `blocked`, or `none-found` in a graph with no gap) on the same
  instances and reports paired counts (false positives reduced, confirmed defects added, baseline confirmed defects lost, false positives
  added), precision, recall, runtime and coverage (unresolved, stale and unbound reported apart). Uncertainty is a SIMPLE paired case
  bootstrap, labelled as such: the grouped bootstrap of QA-004 is not in this base. `adapterValidation` marks an adapter validated only with
  a positive and a negative fixture and no lost defect; `docs/guides/deployment-aware-support.md` may claim only those (a test compares).
  CLI: `npm run evaluation -- deployment-ablation [--json] [--write-frozen]`. The cases, labels and rule are authored by the tooling's
  developers and one case exists because an earlier rule lost a defect on it, so the set is a mechanism check, not an estimate.

Tests: `test/evaluation/{protocol,grouping,labels,custody,runner,gates-scorecard}.test.js` (`npm run test:evaluation`); the X-308 ablation is tested in `test/deployment/differentiation-ablation.test.js` (`npm run test:deployment`).

## Shrinking, repair verification, coverage and the held-out ablation (X-405 to X-408)

Same posture as above: consumed, not wired into the default scan, behind `invariant-scenarios`, every output addition additive. Suites:
`test/invariants/{scenario-shrinking,invariant-repair,business-coverage,invariant-ablation}.test.js`. Guide: `docs/guides/business-logic-invariants.md`.

- **`invariants/shrink.js` (X-405).** `shrinkScenario(scenario, { fixture, commit, config, budget })`: a greedy removal search (an attack step,
  one member of a parallel group, a control step, a seed record), each candidate replayed through `runScenario` (so manifest, boundary,
  receipt), kept only if it settles `confirmed` with every precondition held AND the same authoritative failing assertion (the first
  violated outcome in the contract's order; identified by forbidden-outcome id and phase). Units a surviving step addresses, or that
  carry an asserted marker, are guarded (recorded with a reason, never silently skipped). Budget: `maxRuns` and `timeBudgetMs`, each with
  a hard ceiling and rejected, not clamped, above it; `minimal: true` only when a full pass kept nothing more. One confirming replay
  sits outside the budget. `reproductionSignals` is a PATTERN check over the fixture text for clocks, randomness, timers, network and
  package imports; `reproducibility.blockedBy` names concurrency (cooperative scheduling, two fresh runs disagreed), external
  dependencies and prerequisites. `checkMinimization` re-derives from the two scenarios that the minimized one is a removal-subset
  (invariant, fixture, actors, forbidden outcomes untouched; no step added; no sequence emptied; no referenced record dropped);
  `verifyShrinkRecord` recomputes the digest, id and receipt links. `scenarios.js` gained `deriveScenario` (same pinned scenario, new
  inputs, recomputed limits and id) and `exerciseOf`; `run.js` gained an optional `shrink` input and an `exercise` field per result.
- **`invariants/repair.js` (X-406).** `verifyInvariantRepair` composes `verifyPatchNegative` (business-state as the declared behaviour
  check: `req.functional.oracleId` and `promotePatch`'s `functionalOracle` are the two small additive changes in `verification/`) with
  preservation legs for every other APPROVED contract on the fixture (baseline and patched, a pre-existing violation is not blamed on
  the patch). Needs the violated contract approved in a verifying ledger or nothing runs. Blockers carry codes from `REASON_CODES`;
  `reasonCodeFor` maps every patch-negative failure code and sends an unknown one to `setup-failed`. A preservation failure after a
  promotion appends a `rejected` repair record. `patch-negative.js` now also counts a failed business-state control flow
  (`observed.preconditions`) as a broken revision. A verified repair builds a regression artifact (exact patch, invariant document and
  approval evidence, scenario, one pinned manifest per leg with its expected outcome, secret-checked); `runRegressionArtifact`
  re-executes it from the artifact alone, `validateRegressionArtifact` detects an edit without running. Receipts do not cross a
  process; the artifact crosses by re-execution. The approval evidence in it is a digest and a transition id: checking the HMAC needs
  the operator's key.
- **`invariants/coverage.js`, `export.js`, `project-input.js`, `cli.js` (X-407).** `businessCoverage` reports inventory by the VERIFIED
  ledger, exercised actors/states/transitions from executed scenarios only, and gaps (`GAP_CODES`) that running more of the same cannot
  remove; it always states it is a bounded sample. `invariantCoverageFields` is the one place a surface asks for the additive
  `invariantCoverage` field (`report/index.js` JSON and CLI); flag off or nothing attached returns `{}`, pinned by
  `test/fixtures/invariant-compat/`. `exportScenarios` builds the reproducible package (no fixture source; a scenario holding
  secret-looking content is withheld by path; claims `exhaustive: false`); `verifyScenarioExport` detects edits. CLI:
  `agentic-security invariants export|coverage|regress`; MCP: `invariant_scenario_export` (`mcp/invariant-tools.js`, read-only).
- **`evaluation/invariant-ablation.js` (X-408).** Three arms (source-only engine scan, inferred contract, approved contract) over a frozen
  synthetic benchmark (`test/fixtures/invariant-benchmark/`, `manifest.json` + `pin.json`, loader fails closed), one denominator and one
  budget, flags produced before any label is read, Wilson intervals, paired counts, unique findings, scenario cost, and per-class
  claims that are `supported` only from executed evidence meeting the registered policy (nothing executed is `unmeasured`). Driver:
  `npm run bench:invariant-ablation -- run|verify|pin` (`scripts/invariant-ablation.mjs`). SYNTHETIC: authored and labelled by the
  developers, no independent adjudication; a figure from it is not engine accuracy and not a real-world benefit claim.
- **Limits, not hidden.** Same as the section above (in-memory store, cooperative concurrency, only declared outcomes). A shrunk
  scenario is a smaller reproduction, not a root cause. A verified repair covers the declared scenario, workflows and the other
  contracts' bounded scenarios only. Linux is not claimed anywhere here.
- **`interval.js`, `report.js` (QA-004).** `groupedBootstrap` is the registered `grouped-bootstrap-95` method: percentile bootstrap over GROUPS
  (grouping.js), 2000 resamples, seed = first 32 bits of sha256(protocolHash + statistic name), `unmeasured` with the reason below 10 independent
  groups. `wilsonInterval` covers the completion rate. `buildAccuracyReport` publishes raw counts first, then P/R/F1 by language and family,
  micro and macro, completion with an interval, and every disclosed gap (unscored labels and findings, negatives whose scan failed). A stratum below
  the protocol's floor is `unmeasured` with raw counts and a separate `descriptive` figure. `score.js` now carries `perTarget` tallies (what the
  bootstrap resamples) and scores repeated alerts of one flaw as ONE false positive (`clusterAlerts`, `alertsCollapsed`); `alertBurden` reports the
  raw alerts a reviewer reads beside the root causes, so deduplication never hides burden. `checkPopulationsDisjoint` refuses a target in two of
  regression, development, sealed, operational.
- **`economics.js` (QA-004.AC03).** `accountCosts` keeps model, tool, cache (USD) and human-review (MINUTES) apart, treats an entry with no amount as
  unmeasured (never zero; the ratios become lower bounds), and divides ALL machine spend, failed and duplicate attempts included, by DISTINCT confirmed
  root causes and validated fixes. A confirmed outcome must name its root cause so a duplicate cannot be counted twice.
- **`why-missed.js` (QA-005).** `classifyMiss` names the earliest failed stage for a labelled DEVELOPMENT miss (scan-execution, parser-ir,
  source-modelling, propagation, sink-modelling, filters, suppression, deduplication, attribution) or `unknown` with a reason. A candidate observed
  downstream (a reported finding, a dedupe loser, a ledger drop) is checked first because it proves the earlier stages worked. Evidence comes from
  `scan-child.js` in `diagnose` mode (the suppression ledger incl. guard-recognized drops with finding id, CWE, family and the dominating guard line;
  dedupe and rejected-guard stage evidence behind `AGENTIC_SECURITY_STAGE_EVIDENCE=1`, diagnostic only; sources, sinks, IR lowering).
  `collectDiagnostics` refuses any sealed target. `compareMisses` gives before and after stage counts, the recovered defects with the stage that lost
  each, and names new false positives instead of netting them. `dev-cases.js` builds the development case suite (`test/fixtures/engine-mechanisms/`,
  every label flagged synthetic) that `scripts/dev-recovery.mjs` runs against ANY engine checkout, so a before and after is a measurement.
- **`release-gate.js` (QA-007).** `evaluateReleaseGates` wraps `gates.js` (which now computes the per-language F1 lower bound from the grouped bootstrap
  and adds the integrity gates `answer-key-leaks` and `denominator-intact`, and `no-regression-vs-baseline`) and decides whether a NEW accuracy claim is
  allowed. The baseline comes only from a verified ledger: `appendSealedEvaluation` / `verifyLedger` (hash chain) / `signLedger` (the custodian signs the
  head, so a rebuilt chain does not verify). `assessReleaseClaim` blocks a different detector digest (`detectorDigestOf`, evaluation tooling excluded) on
  already-consumed sealed targets (`fresh-sealed-population-required`); old results are retained as evaluation-only. `signGateReport` signs an AGGREGATE
  verdict (no per-case outcome) with a local Ed25519 key, trust basis `self-issued-local-key`, never independent certification.
- **`bakeoff.js` (QA-008.AC02).** The bake-off manifest, generic comparator slots (no tool is named anywhere), adapters that mark an unavailable slot
  `not-evaluated` with a typed reason, a comparability check (identical workload digest and verification standard) and a claim guard: accuracy and
  cost claims only between evaluated, comparable participants; `superiority` is always `none claimed`. Scoring is `comparison.js`, unchanged.
  Docs: `docs/guides/bakeoff-recipe.md`; the offline reproduction is `scripts/public-reproduction.mjs` (`npm run reproduce:mini`).

Tests: `test/evaluation/{protocol,grouping,labels,custody,runner,gates-scorecard,reporting,why-missed,guard-dominance,engine-mechanisms,release-gate,publication}.test.js` (`npm run test:evaluation`; the two engine files are also in `test:dataflow`). Guides: `docs/guides/{evaluation-reporting,miniature-reproduction,bakeoff-recipe,engine-mechanism-evidence}.md`.

## Release assurance, portable evidence and resumable portfolios: `portfolio/` (X-701 to X-708)

Same posture as the sections above: consumed, not wired into the default scan. The one place it touches shipped output is the verdict
wording, and that is additive behind the `portfolio-assurance` feature (`assurance/config.js`, default off, so flag-off output is
byte-identical and no pinned fixture changed). **It builds machinery, not evidence**: no real release or portfolio exists, every
fixture is flagged `synthetic: true`, and nothing here claims real-world assurance. Linux enforcement stays `unverified`; no Linux
outcome is asserted. Suite: `npm run test:portfolio` (`test/portfolio/`).

- **`manifest.js` (X-701).** `buildManifest` / `validateManifest`: the release assurance manifest on the assurance schema kit and
  `identity.js` (id prefix `ram`, allowlisted fields, no clock). Binds subject repository and commit, dependency revisions, build
  artifact digests, scope, graph snapshot digest, invariant versions and verification receipts. Every mandatory check is in exactly one
  of completed / incomplete / unsupported / waived (incomplete and unsupported name their gaps, a waiver names its approver and reason),
  and the blocking policy (id, digest, severity) is part of the record. Validation rejects evidence not bound to a declared receipt,
  a receipt whose commit is not the bound commit of its repository, a mandatory check listed nowhere, and coverage or `complete` that
  disagrees with the lists. Residual risks and coverage are machine-readable fields.
- **`bundle.js` (X-702).** The portable bundle: an index file (bundle.json) plus `blobs/<sha256 hex>`. `exportBundle` writes the sanitized
  findings (closed field set, snippets stay behind, secret shapes redacted, then refused if any survive), provenance, replay manifests,
  toolchain identities and the cited receipts, index last. `verifyBundle` is the OFFLINE verifier (fs and crypto only, executes nothing
  from the bundle): re-hashes every blob, rejects symlinks, oversize, bad names, missing roles, a modified index, a manifest that fails
  validation and a cited receipt that is absent, and DISCLOSES replay prerequisites without attempting a replay. `importBundle`
  verifies first, confines every destination, never overwrites. Limits are `BUNDLE_LIMITS`.
- **`signing.js` (X-703).** `signAssuranceClaim` is a signer-domain act (`sandbox/trust-domains.js`, default deny: worker, target and
  verifier are refused before a key is touched). The key lives in its own `assurance-signing/` directory (reusing `ensureKeyPair`) and may
  be required to differ from the scan evidence key. The signed claim names manifest id and digest, bundle digest, commit, blocking policy,
  coverage, the bounded headline, signer id, key id and the assurance policy. `verifyAssuranceClaim` is offline against an explicit
  trust-root policy (`buildTrustPolicy`): unknown root, revoked root, a basis this build cannot verify, a tampered claim, a tampered or
  missing bundle and a claim that does not match the bundle's manifest are each typed failures. The only verifiable basis is
  `self-issued-local-key`, `independentlyCertified` is always false and inside the signed bytes. Private key material is never in an
  envelope, policy, error or output.
- **`wording.js` (X-703.AC03).** `assuranceStatement` renders "No blocking findings in completed supported checks", then scope, then
  gaps, then the not-a-guarantee line. `report/index.js` `toShipVerdict` and `integrations/index.js` digests use it only when
  `portfolioAssuranceEnabled` (option, else the assurance configuration); otherwise the old "Safe to deploy" strings are untouched.
- **`work-units.js` (X-704).** `planPortfolio` (authorized repositories only, exact commits, stable `wu:` ids), a seven-state machine with
  lease expiry, retry count and a hash-chained attempt record per unit (rewriting an attempt fails `verifyStore`), idempotent lease /
  start / complete / fail by attempt id (a duplicate completion verifies once; a stale attempt, such as a zombie after lease expiry,
  is refused), `progressOf` counting only verified units, locked atomic persistence (`openStore`, `mutateStore`; a corrupt store is an
  error, never a reset) and `runPortfolio` (bounded concurrency, an executor that throws fails its unit). `fleet.js` `runFleet` accepts
  `portfolioVerified` (from `fullyVerifiedRepositories`) and skips those repositories like a resumed completed one.
- **`resume.js` (X-705).** Every verified result records one digest per dimension (code, policy, graph, invariant, oracle, toolchain;
  `scan-checkpoint.js` `computeRunKey` / `computeGlobalKey` supply the code and toolchain digests). `planResume` reuses a unit only on a
  full match; any other change `applyResume` invalidates: the old result moves to `stale` (inspectable with `inspectStale`), the unit
  returns to pending in a new generation, `assessClaims` marks dependent claims stale. A graph-only change is narrowed by the drift
  module (`lineage/deployment/drift.js` `planRescan`): a unit bound to hypotheses is reused only if the plan is complete and all its
  hypotheses are in `skipped`; anything else fails closed.

Tests: `test/portfolio/{manifest,bundle,signing,work-units,resume}.test.js` (`npm run test:portfolio`).
## Calibrated model routing: `routing/` (X-601 to X-608)
- **`scheduler.js` (X-706).** Bounded scheduling over the store. `scheduleNext` admits and leases ONE unit in a single locked transaction
  (`mutateStore`), after checking five limits at two levels (portfolio and per repository: wall time, provider spend, requests, storage,
  plus concurrency) against what is used PLUS what in-flight attempts have reserved PLUS the unit's own estimate. A unit with no
  estimate is not leased (unknown is never zero). A refusal is `at-capacity` (a wait) or `exhausted` (will not recover), reported per
  unit and per scope, and a refusal changes nothing. An attempt that ends with no usage report is charged its whole reservation; a
  reported overrun is recorded (`overruns`) and shrinks what remains. Wall time is also enforced while a unit runs (the executor's
  `signal` aborts at the unit's wall estimate). Fairness: priority is a WEIGHT (integer 1..8, default 1), never an order; the next lease
  goes to the admissible repository with the lowest `leasesGranted / weight` (ties: repository name, then unit id), so a 120-unit
  repository cannot starve a 1-unit one, weight 8 against 1 is served about eight times as often with the light one still served early,
  and a repository that was blocked is owed service when it returns. A blocked or over-budget repository is skipped with a reason, never
  waited on; an unaffordable unit does not block a cheaper sibling. `routingBudgetFor` hands the routing policy (`routing/decide.js`) the
  smaller of the portfolio and repository dollar remainders, less reservations; `chargeModelSpend` charges a routing decision at its
  upper cost bound and refuses a blocked or unbounded decision. No provider is called here. `createCancelScope().cancel` takes a scope
  (`{unitId}`, `{repository}` or `{all}`; an empty scope is refused, never read as cancel-all), records it in the ledger so a process
  that did not receive the call still honours it, aborts in-process attempts (work started with `ctx.spawn` runs under
  `sandbox/supervise.js`, which ends the whole process tree and reports survivors), releases a lease ONLY when the attempt settled with no
  survivor, otherwise leaves it to expire (so no other worker can start the unit while a descendant may live) and never re-leases it.
  Verified units and receipts are untouched; the report is `incomplete` with the reason. `heartbeat` renews the lease and records a
  heartbeat in one transaction; `runScheduled` heartbeats every `HEARTBEAT.intervalMs` (5 s) while an attempt runs and takes an optional
  `backend`, probed before every lease (an unavailable one stops the run as `blocked`). Limits: the driver's heartbeat proves the
  controlling process is alive, not that an in-process executor is making progress (the wall bound handles that); tree termination is
  verified on the macOS userspace backend only and Linux enforcement stays `unverified`.
- **`progress.js` (X-707).** ONE projection (`buildProgressView`) for the CLI, the MCP tool and the fleet summary, in the pattern of
  `lineage/deployment/projection.js`. It keeps apart verified units (the only progress), blocked / failed / canceled / stale units with
  reasons, per-repository coverage (fully-verified, partial, incomplete, not-started), per-limit budget (limit, used, reserved,
  remaining; an unenforced limit says so), pending human review (blocked units plus `reviewItemsFromInvariantCoverage` and
  `reviewItemsFromBoundaryContexts`), and every worker with its age, `live` or `stale` (stale after `HEARTBEAT.staleAfterMs`, 15 s;
  silent workers are measured from their lease). `aggregateFindings` deduplicates by `stableId` ONLY, keeps every occurrence
  (repository, environment, release, commit, file, line, severity) and lists affected releases separately; a finding with no stable id
  is listed apart, never merged. `completion` states that a finished controller is not every unit verified and not any repository
  passing (`passAssessment: 'not-implied'`). Additive behind `portfolio-assurance`: `attachPortfolioProgress` returns the SAME rollup
  object when the feature is off, `renderFleetSummary` adds a PORTFOLIO clause only when the field is present, and
  `test/fixtures/portfolio/pre-change-pins.json` (generated by `test/portfolio/make-pins.mjs` from code before the change) pins the
  fleet rollup, summary and HTML. CLI `agentic-security portfolio progress`; MCP `portfolio_progress` (read-only, `mcp/portfolio-tools.js`).
- **`backend.js` (X-708).** The storage backend interface (`probe`, `storeFile`, `withExclusive`, fenced `acquireLease` / `renewLease` /
  `releaseLease`) and a file-lock reference implementation. `createLocalBackend` makes its directory; `createSharedBackend` requires a
  marker written by an explicit `initSharedBackend`, so an unmounted path, an empty mount point, a symlink or a damaged marker is a typed
  `blocked` (`openBackend` returns `{ ok: false, state: 'blocked', code }` and no backend; there is deliberately no fallback argument,
  and a blocked open creates nothing). A backend that disappears mid-run stops `runScheduled` as `blocked` without recreating the
  directory or writing anywhere else. Lease semantics, each tested with two REAL processes: mutual exclusion, monotonic fence, expiry
  takeover, a replaced holder refused on renew and release. NOT claimed: network-filesystem safety (`describe()` reports it
  `unverified`; the operator must verify exclusive-create atomicity on that mount), cross-host clock agreement, or race-free stale-lock
  recovery (narrow window, documented). `exportState` / `verifyStateExport` / `importState`: one self-checking, secret-checked file for an
  air-gapped machine; import verifies first and never overwrites.
- **`retention.js` (X-708.AC01).** Retention by class (`replay-evidence`, `metadata`, `model-trace`, `secret`; defaults 365 / 730 / 30 / 0
  days, ceilings 1095 / 1825 / 90 / 7, an over-ceiling setting is clamped and disclosed). Order: a required current receipt (named in
  `currentReceiptIds`, or `requiredBy` a unit that is `verified` in the store NOW) is never deleted and an expired one is reported as
  `expiredButRequired`; then a legal hold (validated and checked with `legal-hold.js`'s `isUnderHold`; by id, class or repository; a
  malformed hold refuses the whole plan); then expiry. An unclassified or malformed record is kept and reported. `applyRetention` re-plans
  against the live store, confines paths to the root (traversal, absolute paths, symlinks and directories refused), and logs each deletion
  to a hash-chained log BEFORE removing the file (no log, no deletion; a broken log blocks every deletion). The log holds digests and sizes,
  never content. CLI `agentic-security portfolio retention plan|apply|verify-log`.

Tests: `test/portfolio/{manifest,bundle,signing,work-units,resume,scheduler,progress,retention,backend}.test.js` (`npm run test:portfolio`).
`test/portfolio/proc-worker.mjs` is the child process the multi-process consistency tests spawn; it is not a test file.
## Calibrated model routing: `routing/` (X-601 to X-604)

Extends `model-routing.js`, `model-trust.js`, the provider catalog and cache economics; consumed, not wired into the scan or the interactive advisor. Everything is behind the **`model-routing`** feature (`assurance/config.js`, model-network risk, off by default, kill switch `AGENTIC_SECURITY_NO_MODEL_ROUTING`). With it off, `routeModelWithPolicy` returns exactly what `routeModelWithTrust` returns, and `test/routing/unchanged-when-off.test.js` recomputes the routing, trust, cache-economics, catalog and advisor outputs against `test/fixtures/routing/pre-change-pins.json` (generated from the code before any routing edit). Suite: `npm run test:routing`. **Machinery, not evidence:** no real routing outcome or adjudicated task exists in this repository, every population in the tests is SYNTHETIC (`test/helpers/routing-fixtures.js`), and the section 5 routing gate reads `unmeasured` (synthetic) or `insufficient-population`, never `pass`. No cost or quality improvement is claimed anywhere.

- **`outcomes.js` (X-601).** Routing task record (kind: discovery, triage, verification-planning, repair; language; vulnerability class; context tokens and bucket; required capabilities; data class), the stratum key `kind|language|class|bucket` and its coarser parents, and the outcome record. `deriveRoutingLabel` is the only way to a decided label: independent adjudication (a human or verifier service that is not the model or its provider, with the adjudication version) or trusted execution (a `vrec:` verification record). Provider agreement, self-reported confidence, accepted suggestions, model judgement and majority vote are refused (`NOT_A_TRUTH_LABEL`) and the outcome is recorded `unknown`. Outcome records keep every status (failed, timeout, cancelled, provider-error, partial, blocked) and unknown or delayed correctness; an unreported count is `null`, never 0. `createOutcomeLedger` has no remove or overwrite.
- **`economics.js` (X-602).** `priceBookFromCatalog` builds the versioned price book from `provider-catalog.js` (the catalog's dated snapshot stays the single price table). `costOf` splits input, cached input, output, retries and tool execution, and names price version, currency and billing basis. Unknown is `null` or a bounded `[lower, upper]` estimate, never 0 (an unpriced model, a subscription basis, an unreported token count, an unknown cache split, an unmeasured tool cost). A prediction goes in `predicted` and never fills `measured`. `cache-economics.js` (which prices Claude Code's own transcript) and `hooks/model-cost-advisor.js` are deliberately unchanged and pinned.
- **`adapter.js` (X-602.AC03).** `createProviderAdapter(...).invoke` has no HTTP client: it goes through `guardedModelCall` (feature gate, egress policy before the prompt exists, redaction, request cap, deadline, bounded retries, audit chain) with an INJECTED transport. Telemetry is built from an allowlist (provider, model, endpoint host only, status, a fixed failure code, token counts, cache state, latency, byte counts); it never carries the prompt, the response, an error message or a credential. Provider failures, partial responses, cancellation, timeouts and cache hits each yield an outcome record.
- **`calibration.js` (X-603).** `buildCalibration` fits per (model, version, stratum) quality on HELD-OUT outcomes with a time split, a model-version split (versions are never pooled) and group disjointness (a group on both sides is removed from the held-out side and counted). Uncertainty is `groupedBootstrap` from `evaluation/interval.js` (`unmeasured` below 10 groups). The label `reliable` needs at least 200 paired adjudicated tasks overall, 30 per stratum (`ROUTING_MINIMUMS`, a config cannot lower them), a measured interval and a stable development-versus-held-out rate; a synthetic population only ever gets `reliable-synthetic`. Otherwise the stratum carries `fallback-parent` (a reliable coarser stratum, named), `shifted` or `insufficient-evidence`, and an explicit fallback (`parent-stratum` or `baseline-model`). The artifact records the dataset hash, config hash, adjudication versions, counts and every exclusion by reason, and `verifyCalibration` rebuilds it byte for byte. `routingPopulationGate` is the population half of the PRD section 5 routing row only; the paired quality, cost and latency comparison is `promotion.js` (X-605).
- **`decide.js` (X-604).** `routeConstrained` applies availability, capability, privacy (the egress policy, or a capability-manifest egress check), context window, reliable and fresh quality evidence whose LOWER bound meets the minimum, interval width and budget BEFORE minimising measured cost or latency. Every candidate lists all of its failing constraints. When nothing is acceptable the result is `fallback` (the existing capability route, only if it passes capability, privacy, context and budget, with quality marked UNVERIFIED) or `blocked` with a code; a constraint is never relaxed to find a route. `routeModelWithPolicy` in `model-routing.js` is the entry point; a blocked decision returns `model: null, blocked: true`.
- **Limits, not hidden.** The provider catalog carries prices and cache models but not capabilities or context windows, so `candidateFromCatalog` takes them from the operator and an unknown window is rejected. Catalog prices are a dated snapshot. Cost bounds cover model tokens only. Telemetry redaction depends on the egress redaction patterns, which are pattern checks, not proof against every secret shape.
- **`shadow.js` (X-605.AC01).** `createShadowRecorder().shadow()` records what `routeConstrained` WOULD pick and returns the production route it was given, the same object. It holds no transport or adapter (a test pins that the source cannot call a provider), so no paid call is possible by construction. A disabled routing control records nothing.
- **`promotion.js` (X-605.AC02, AC03).** `freezeTaskSet` fixes the evaluation tasks by hash; `replayPaired` pairs each frozen task's baseline arm with the arm the shadow decision chose, from recorded outcomes. It issues a provider call only with BOTH an injected `invoke` and a bounded authorization (`authorizedBy`, finite `maxCalls`, `maxUsd`, `perCallUsdCeiling`, all under `REPLAY_LIMITS`); an `invoke` without them is refused (`UNBOUNDED_REPLAY`), an unknown cost is charged at the ceiling, and a replay that hits its bound is `truncated`. `evaluatePromotion` judges the PRD section 5 routing row (200 paired adjudicated overall, 30 per promoted stratum, quality difference lower bound above -0.02, median cost 20% lower or quality +0.05 at no higher median cost, p95 latency 1.2x) with the grouped bootstrap. Verdict precedence: `invalid` > `unmeasured` (synthetic) > `insufficient-population` > `fail` > `pass`. Invalidations: `cherry-picked` (pairs differ from the frozen set), `dropped-tasks` (no pair: no shadow record, missing or ambiguous outcome, bound reached), `unbounded-replay`, `truncated-replay`, `replay-edited`, `frozen-set-edited`. A failure status, a timeout, a blocked proposal or an unserved task is not-correct in the comparison and is reported, never dropped; an unadjudicated pair is counted apart and never imputed; an unknown cost or latency leaves the criterion unmet. The quality-gain path is stricter than the PRD wording (the lower bound must clear zero too).
- **`drift.js`, `canary.js` (X-606).** `snapshotRoutingBasis` records what a policy was promoted on; `assessDrift` compares it with the present (model version, price entry, schema, recent decided quality) and returns a documented `fallback` or `shadow` state; `applyInvalidations` derives a calibration whose affected estimates are `invalidated` (quality, version, schema) or lose their measured cost (pricing), so `routeConstrained` refuses them. A cost-invalidated model ranks behind one with a valid measured cost, by the existing ranking rule. `createCanary` is finite by construction (no limits, no canary): task count, spend budget, error rate, consecutive-error outage, incorrect rate; a trip restores the known-good policy and only appends receipts. `activate` needs a `pass` promotion verdict. `routeUnderDrift` is the state-aware entry point.
- **`feedback.js` (X-607).** `createFeedbackStore`: actors (human or verifier-service) registered with a key sign each record (HMAC); the first accepted label is the immutable original, a change is a correction citing the entry it corrects; an allowlist of fields is kept and the names of dropped fields only; unauthorized, unverifiable, tampered, duplicate and poisoned feedback is quarantined with a count and reason, and `applyToOutcomes` is what a calibration should be built from. `authorizePayload` / `sendToProvider` need the task policy AND the egress policy (or a capability manifest check) to allow source or evidence, and send only through the guarded adapter. Limit: a trusted-execution label cannot be recomputed from the outcome alone, so a flip of one is not detected here.
- **`receipts.js`, `control.js`, `report.js` (X-608).** `createReceiptLog` is a hash-linked log of every shadow decision, replay, promotion, drift, canary, rollback and feedback decision (`exportReceipts`, `verifyReceiptChain`; tamper evidence, not a signature). `resolveRoutingControl` (option, then `AGENTIC_SECURITY_ROUTING`, then default; a bad value fails closed to `disabled`) is honoured by `routeModelWithPolicy` (disabled keeps the capability route, `pin:<model>` selects that model). `buildRoutingReplayReport` / `renderRoutingReport` / `buildPolicyCard` restate the verdict with exact denominators, intervals, measured cost, cache states and latency percentiles, restrict claims to the strata and model versions the gate passed, and keep unsupported strata and unmet gates listed. Reproduce offline with `npm run reproduce:routing` (`scripts/routing-replay.mjs`, controls, `--fault`); guide `docs/guides/routing-replay.md`. Everything in the tests and the script is generated and `synthetic`; the gate reads `unmeasured`, never `pass`, on it, and no advantage is claimed.

## Execution-proof tiers (R2)

`proof-tier.js` + `execution-proof.js` add a fourth axis to a finding's
credibility, orthogonal to `confidence`/`exploitability`: whether the bug was
*run*, not just reasoned about.

**The five proof classes** (`poc-inprocess.js`), and what each observes:

| Family | Evidence |
|---|---|
| `command-injection`, `code-injection` | the injected payload itself writes the marker |
| `webhook-missing-signature-verification` | the handler is observed *accepting* an unsigned request |
| `sql-injection` | the payload reaches a stubbed driver inside the **SQL text** rather than as a bound parameter |
| `path-traversal` | a sentinel planted outside the served directory comes back out of the handler |

The last two need no running application, which is the point: the SQL question
("text or bound parameter?") is settled where the query crosses into the driver,
and the traversal question is settled by what the handler hands back. A
parameterised query and a `basename`-guarded read both reach `proof-failed` by
**execution**, not by a source pattern.

Classes deliberately absent, with reasons, are listed in the module header —
IDOR (needs two identities and a populated store; a PoC built on invented state
proves something about the invention), SSRF (the sandbox denies egress, so a
failed fetch is confinement talking), XSS (a marker file cannot observe a DOM).

`extraFiles` on a PoC carries support files that are **not** the vulnerable
source (the SQL driver stub). `mergePocFiles` merges it under `requires`, which
always wins — otherwise a template could replace the code it is supposed to
exploit and prove a fact about itself.

**The four tiers** (`PROOF_TIERS`, most-proven first):

- `execution-proven` — a generated PoC ran inside the sandbox and the sandbox
  observed the predicted effect (a marker file the PoC's payload should have
  written showed up). The strongest claim the pipeline can make.
- `proof-failed` — a PoC ran and the marker did **not** appear. This is a
  **triage signal, not a false-positive verdict**. Absence of proof is not
  proof of absence: the PoC may be wrong, the param key may be misinferred,
  or the vulnerable path may need state the single-shot PoC didn't set up.
  Never auto-close or downgrade severity off `proof-failed` alone.
- `taint-proven` — the analyser's static reasoning (`IR-TAINT`/`MULTI-SINK`)
  found it; nothing executed. This is `proofTierOf()`'s default when no
  execution evidence has been attached.
- `unproven` — no analyser backing recorded at all (e.g. `REGEX` parser).

**Why a marker file, not an exit code.** The sandbox cannot reliably
distinguish "the payload was denied by confinement" from "the payload ran
and happened to exit 0" — both look like a clean exit from the parent
process's point of view. A marker file the PoC only writes *if its exploit
path actually executes* turns that ambiguity into a directly observable
fact: the file exists, or it doesn't. Exit code alone is used only for
timeout/crash detection, never as the proof signal itself.

**The backend is recorded in every evidence object** (`proofEvidence.backend`,
e.g. `'userspace'`) because not all confinement backends carry the same
guarantee. Two backends now carry a verified-by-execution escape contract:
`userspace` (verified on the macOS development host) and `namespace`, which
implements write confinement as well as network isolation (read-only rebind of
the mount tree, read-write rebind of the sandbox root, capability drop before
exec) and whose escape suite has now **RUN and passed on a Linux host in CI** —
see `sandbox/CLAUDE.md` for the host and the eight cases. `execution-proven`
evidence from either of those backends stands on an executed escape contract.
The `disabled` backend never produces evidence at all: it refuses to run,
which is why the tier stays static rather than becoming `proof-failed`.
Keep reading `proofEvidence.backend` anyway — it is what makes a tier
re-auditable when a backend's contract changes, and a backend added later
starts out unverified by default. `attachProofTier()` also enforces the demotion
guard: `ran:false` can never yield `execution-proven` or `proof-failed`,
regardless of what tier was requested — it falls back to the finding's
static standing (`proofTierOf`).

**`ran` means the PoC executed, not that `runConfined` returned.** A sandbox
that could not start (`status:'error'` — confinement binary missing, namespaces
denied) and a refusal (`status:'disabled'`) both leave the PoC unexecuted, so
`execution-proof.js` records `ran:false` and a reason naming the sandbox
failure, leaving the finding at its static tier. Calling that `proof-failed`
would report a broken sandbox as a failed exploit attempt — a claim about the
*finding* derived from evidence that only concerns the *host*.

`proofTier`/`proofEvidence` are copied through `report/index.js`'s
`normalizeFindings()` only when the annotator actually attached them —
never synthesised at the report layer.

## Corpus auto-enrolment (R2's differentiator)

`corpus-enroll.js` + `corpus-match.js` turn an execution-proven finding into a
permanent CVE-replay corpus entry, so every exploit the pipeline proves once is
defended by the baseline gate forever.

**`corpus-match.js` is shared with the gate on purpose.** `bench/cve-replay/runner.mjs`
imports `matcherFor`/`preHit`/`postHit` from it. If enrolment verified a
candidate with a different matcher than the gate scores with, it would commit
entries that fail CI. The pre/post asymmetry (pre matches `vuln` OR `family`
and regex-tests `cwe`; post is strict on `vuln` and exact on `cwe`) is
reproduced verbatim from the runner — `bench/cve-replay/CONTRIBUTING.md` records
it as known imprecision, and changing it would re-verdict the whole committed
baseline, which is a corpus migration rather than a refactor.

**Nothing is written that has not been scored.** `enrollProvenFinding` builds
the entry in a temp dir, scans `pre/` and `post/`, and moves it into the corpus
only on `pre:TP post:TN`. There is no force flag, and `scoreCandidate` is
deliberately unexported so no caller can score by one route and write by
another — that unscored-write path is the v0.106.0 mistake this module would
otherwise automate. Refusals also cover: a tier that disagrees with its own
`proofEvidence`, `ran !== true`, an `execution-proven` tier with nothing
observed, a missing `post/` (never synthesised by deleting the vulnerable
line — it would pass for the wrong reason), a `post/` identical to `pre/`, a
path escaping the entry dir, a `pre/` not containing the finding's file, and a
duplicate id. The manifest's `vuln_match` is regex-escaped so an unrelated
detector cannot satisfy the entry.

**New entries land in `capability/`, never `regression/`.** `regression/` is
the CI-gated tier and graduation into it is a human decision with a stated
policy; an automated writer must not decide what blocks everyone's build.

**Operator entry point:** `scripts/enroll-proven-finding.mjs <project>`
(`--dry-run` scores without writing). It proves findings itself — **but the
scan pipeline DOES attach an HTTP-shaped `f.poc` by default** (`annotatePocs`,
`engine.js`, unconditional — not behind a flag; findings with no matching CWE
template get `f.poc: null`). What the scan pipeline does NOT do by default is
the *sandbox execution proof* that promotes a finding to the
`execution-proven` tier: that pass is genuinely opt-in
(`AGENTIC_SECURITY_PROVE=1`), so `last-scan.json` never contains an
`execution-proven` finding from an ordinary scan on its own — this file
previously conflated "attaches a poc" with "promotes to execution-proven,"
which are two different passes with two different default states. Enrolment
still proves findings itself via its own sandboxed run, independent of
whichever tier `last-scan.json` shipped with. Enrolment additionally needs
fixed content
(`finding.fix.patch`) for `post/`; a proven finding with no fix is reported as
skipped, not dropped. After enrolling, refresh the baseline
(`npm run bench:cve-replay:update-baseline`) and commit it.

## Scan checkpointing / resume (R8)

`scan-checkpoint.js` lets an interrupted scan resume instead of restarting, which
is what caps usable repository size today. **Opt-in only**: `AGENTIC_SECURITY_RESUME=1`
(or `runScan(root, {resume:true})`). Default behaviour is byte-for-byte unchanged
and nothing is written.

**What is checkpointed.** Only the per-file loop in `engine.js#runFullScan` — the
one place per-file work happens. Each completed file's *entire* contribution is
persisted (routes, findings, taint sources/sinks/sanitizers, logic vulns, secrets,
at-rest/in-transit ciphers, the suppression-log delta, and the per-file taint
result the cross-file pass reads), not just its findings. Everything after the
loop — cross-file taint, gadget detection, the whole annotation pipeline — re-runs
from scratch, so nothing that depends on the global picture can be stale by
construction. On replay, `pfr[p]`'s arrays are rebuilt as slices of the aggregate
arrays, so object identity between the two matches an uninterrupted run exactly.

**The property.** A resumed scan must produce the same finding set as an
uninterrupted one; a checkpoint that silently drops findings turns a slow scan
into a quietly incomplete one, which is worse than no checkpoint. `test/scan-checkpoint.test.js`
asserts this end-to-end: a child process is hard-exited (`process.exit`, no
unwinding) partway through a real scan, the resumed scan is compared against a
genuinely uninterrupted one, and the fixture is asserted to exercise every
channel inside the replayed prefix so a dropped channel cannot go unnoticed.

**Invalidation is deliberately blunt.** The run key covers engine version,
ruleset version, bundle SHA, a content hash of every scanned and dependency file
(which subsumes mtime), and every `AGENTIC_SECURITY_*` env switch. If any of it
moved, the checkpoint is discarded and the scan starts clean. Redoing work is
slow; resuming stale work is a correctness bug.

**Crash safety: append-and-fsync.** JSONL — one header line pinning the run key,
then one record per file carrying a SHA-256 of its own payload, each written with
a single `writeSync` and `fsyncSync`'d before the next file is analysed. Recovery
reads forward while records verify and truncates at the last byte that did, so a
torn or tampered tail is dropped rather than resumed into. Nothing is rewritten
in place. Values JSON cannot round-trip (Date/RegExp/Map/function/…) are refused
rather than recorded lossily — that file just gets rescanned. On clean completion
the checkpoint is removed, so the next run cannot resume consumed state.

State lives at `<scanRoot>/.agentic-security/scan-checkpoint.jsonl`; like every
other module here, nothing throws — a failure to open, read or append degrades to
"no checkpoint", i.e. a normal full scan.

## The autonomous loop, the fleet, and the two things that judge them

**`autopilot.js`** is the chain — scan → prove → validate → fix → **re-verify** —
and nothing else. Every stage is injected, so the orchestration is testable
without an engine or a model; `scripts/autopilot.mjs` is where the real stages
get wired (a real scan, a real sandboxed exploit, a deterministic-then-model fix,
and the real gate).

The rule that makes it safe to automate: a fix is applied **only** if the PoC
that proved the bug no longer fires **and** the test suite still passes. Anything
else is `NEEDS_REVIEW` and is not written. A re-scan proves the *detector* went
quiet; only re-running the exploit proves the hole is shut. Gates are ON by
default — `apply` is an explicit opt-in — and the outcome set (`OUTCOMES`) is
closed, because the report groups on it and an undeclared value would vanish
from every count. `maxFindings` is reported as `capped`, never applied silently.

The CLI refuses to start with no confinement backend (the gate's verdict
requires executing something) and refuses a dirty git tree by default (the test
leg writes the candidate patch to disk and restores it in a `finally`, so a
clean tree is what makes a crash recoverable). A VERIFIED_FIXED reached with no
test runner detected is counted and reported separately — the exploit stopped
firing, but nothing checked the application still works.

**`fleet.js`** rolls many repositories into one offline page. `renderFleetHtml`
emits no scripts and no external references, and a repo that FAILED to scan
always forces a non-zero exit: an unscanned repo is unknown, not clean.

**`logic-claims.js` (PRD Epic 6)** is the business-logic tier's other half. The
deterministic side already existed (`sast/logic.js`, `posture/business-logic.js`);
what did not was any way to be *wrong* about a claim from the reviewing agent,
which is prose and was the only tier nothing could disagree with. Three offline
lenses can refute one: `citation` (the file exists and the line is inside it),
`quotation` (the quoted snippet is at the cited line ±3), and `corroboration`
(for kinds that assert something checkable — "this route has no authentication"
against a handler that plainly authenticates). Verdicts go through
`verification-separation.js`, so a lens can never vote on a claim it produced.
Recall-preserving: a refuted claim is `quarantined`, never deleted, never
severity-touched. Wired in `engine.js`, which reads
`.agentic-security/logic-claims.json` from the scan root and lands the results
on `scan.logicVulns` with a summary at `scan.logicClaims`.

**`comparison.js` (PRD Epic 7.2)** scores this engine head-to-head against
participants **the operator supplies** — the repository ships the harness and the
answer key, never a participant, and a test asserts no tool name appears in
either file. Two properties are the whole module: every rate is computed over the
**intersection** of entries *all* participants completed (two tools scored over
different subsets are not comparable, and the difference is invisible in the
output), and an entry a participant could not run is **unscored**, never counted
as a miss. Matching is CWE-only so nobody is scored on this engine's vocabulary.
Driver: `scripts/comparison.mjs`, over the CVE-replay corpus.

**State artifact registry (assurance-hardening PRD FR-701/FR-703)** — `artifact-registry.js`. The registry `cmdReset` (bin/agentic-security.js) now iterates instead of two hardcoded WIPE/WIPE_DIRS Sets. Every known `.agentic-security/` artifact is classified `generated` (scanner-written, safe to delete on reset) or `operator-config` (hand- or agent-authored input, never deleted) — built from an audit of every `statePath()`/`stateDir()` call site, not guessed from filenames; several looked generated by name but turned out to be inputs (`.agentic-security/logic-claims.json`, `.agentic-security/exploit-history.jsonl`, `.agentic-security/cve-alerts.json`, `.agentic-security/network-policy.json`, `.agentic-security/current-intent.md` — see the module's own header for the evidence behind each). Guarded by a completeness test (`test/artifact-registry-completeness.test.js`) that scans for every `statePath()`/`stateDir()` literal and fails if one isn't registered — a `no-dead-modules.test.js`-style drift guard, not a snapshot.

## Finding provenance — `provenance/` (20 modules)

The only SUBDIRECTORY under `posture/`, because it is a pipeline rather than an
annotator: twenty small modules that together answer "which commit introduced
this finding, and how sure are we?" Everything outside the subdirectory sees one
function, `annotateGitProvenance(findings, ctx)` from `coordinator.js`, wired in
`engine.js` after every finding has been appended.

**Read the naming rule before you touch anything here.** The exported function is
`annotateGitProvenance` — NOT `annotateProvenance` (taken by
`sca/sigstore-verify.js`, build attestations) and NOT `annotateFindingProvenance`
(taken by `posture/provenance.js`, parser-corroboration signals). `engine.js`
imports all three; either alternative name is a duplicate binding, and the second
takes a findings array as its first argument exactly like this one, so a wrong
import would RUN rather than fail. The field is `finding.findingProvenance`,
never bare `.provenance` — `finding.provenance` and `supplyChainEntry.provenance`
are both pre-existing unrelated fields.

**The pipeline**, in call order — all LIVE-WIRED into `engine.js`'s scan unless noted:

| Module | Answers |
|---|---|
| `coordinator.js` | the integration point — budget, cache, per-finding dispatch, the terminal-status guarantee |
| `git-evidence.js` | the only Git wrapper (`getRepoState`, `blameLine`, `candidateCommitsForLine`, `getBlobAtCommit`, `commitMeta`) |
| `origin-resolver.js` | which commit introduced a SAST finding |
| `dag-walk.js` | (M3 §3.1) non-first-parent DAG walk + revert/cherry-pick detection for `--provenance deep` |
| `predicate-replay.js` | was this finding's condition true at commit X (calls `runFullScan` on that commit's blobs) |
| `sca-origin.js` | which commit moved a directly-declared dependency version into an advisory's vulnerable range |
| `transitive-sca.js` | (M3 §3.2) the same question for a TRANSITIVE dependency, re-deriving lockfile ancestry per historical commit |
| `branch-entry.js` | which branch/PR merge brought the origin commit into the current branch |
| `evidence-attribution.js` | the path:line:commit triples for source / sink / manifest |
| `confidence.js` | HIGH / MEDIUM / LOW plus the reasons behind it |
| `lifecycle.js` | the introduce / remediate / reintroduce ledger |
| `cache.js` | per-(HEAD, stableId, ruleset, boundary, mode) memo under its own top-level `.agentic-security/provenance-cache/` (split out from `provenance/` so it can carry a `'cache'` retentionClass the permanent lifecycle ledger must not get — see artifact-registry.js) |
| `schema.js` | the status/method/role/confidence enums, `emptyProvenance`, `redactFindingProvenance`, `isProvenanceHealthy` |
| `validate.js` | shape assertion for tests |
| `missing-control-resolver.js` | (M3 §3.3, FR-PROV-017) when a previously-observed safeguard disappeared — **wired into `coordinator.js`**: `resolveMissingControlOrigin` calls `resolveMissingControl` for any finding with `missingControlCandidate:true` (today, `sast/rate-limit.js`'s findings) |
| `providers/config.js`, `providers/github.js`, `providers/gitlab.js` | (M3 §3.4, FR-PROV-022) GitHub/GitLab PR-metadata + CODEOWNERS fetch, config resolved from `.agentic-security/provenance-providers.yml` / token env vars — **wired into `coordinator.js`**: `resolveProviderConfig` is resolved once per scan in `annotateGitProvenance`, and `fetchPRMetadata`/`fetchCodeowners` are called per `complete`-status finding (capped, see `MAX_PROVIDER_ENRICHMENTS_PER_SCAN`), landing on `findingProvenance.providerEnrichment` |
| `repo-lineage.js` | (M4 §4.2) loads + fully verifies an operator-declared `.agentic-security/repo-lineage.json` cross-repo link (local clones only, no remote fetch) — used by `origin-resolver.js`'s root-commit case, not a standalone-unwired module |
| `ai-authorship.js` | (M4 §4.3) extensible AI-authorship verifier registry (`registerAIAuthorshipVerifier`/`resolveAIAuthorship`), defaults to `{status:'unknown', verifier:null}` with nothing registered (today's real state) — wired into `origin-resolver.js`'s `originFrom`, so every SAST `findingOrigin` carries `aiAuthorship`; scoped to SAST only, not direct/transitive SCA origins |

**Four invariants, each with a test that fails if you relax it:**

- **Terminal status, always.** After `annotateGitProvenance` returns, every
  finding carries a `findingProvenance` with one of `complete` / `partial` /
  `uncommitted` / `not_available` / `budget_exhausted` / `error`. There is no
  path — missing git binary, malformed finding, downstream throw — that leaves
  the field absent. `engine.js` additionally backstops every channel OUTSIDE
  the `_runAnnotator` wrapper, because that wrapper swallows throws —
  `findings` and `supplyChain` with a full not_available/error catch-all as
  before; since Task 11, `secrets` and blameable `logicVulns` go through REAL
  resolution (real stableIds backfilled, real `annotateGitProvenance` calls
  made), so their outside-the-wrapper coverage narrowed to a defensive
  catch-all for whatever the real call somehow didn't reach, plus the 3
  synthetic-line `logicVulns` producers (`license-policy:`/`deploy-platform:`/
  `stack-playbook:`), which stay on a permanent, principled not_available —
  never routed through `resolveOrigin` at all, not merely deferred.
- **Never false certainty.** A shallow clone cannot reach `complete`; an
  unverifiable parent boundary degrades to `partial` with its reason carried
  through. `origin-resolver.js` decides this on the `shallow` flag of the
  repoState object, and it must come from the REAL `getRepoState()` — pass it a
  stub and the guarantee is gone.
- **The lifecycle ledger only closes findings on a COMPLETE scan.** `applyScan`'s
  remediation pass turns absence into the claim "this was fixed," which is sound
  only if the scan looked everywhere. `runScan.js` computes `completeScan` (false
  for `--changed-since`/`--pr` and for caller-supplied `fileContents`) and threads
  it through `runFullScan` to `updateLifecycle`. `updateLifecycle` is also gated on
  the `scanRoot` being **a directory that exists** — not merely truthy.
  `resolveProjectRoot` honours a caller-supplied scanRoot only when it resolves to
  a real directory; for `null`, for a typo'd path, or for a file, it falls back to
  walking up from the PROCESS CWD. Both doors led to the same corruption: a scan
  that never looked at your project writing your project's ledger, and then —
  finding nothing while still claiming `completeScan` — remediating every open
  finding in it. `agentic-security scan ./typo` is the reachable form. This repo's
  own checkout accumulated a 1.1 MB ledger of spurious events that way.
- **One budget for the whole scan.** `engine.js` computes ONE `deadlineAt` and
  passes it to all five of its `annotateGitProvenance` calls (SAST findings,
  direct SCA deps, transitive SCA deps per Task 7, then secrets and blameable
  logicVulns per Task 11); a caller-supplied `deadlineAt`/`perFindingBudgetMs`
  wins over the coordinator's own computation. Inside, each finding gets
  `max(2s, remaining/count)` so one deep-history finding cannot starve the rest.
  `budget_exhausted` is the one result that is **never cached** — it is a property
  of the run, not the repository, and caching it would pin a timeout in place
  until HEAD moved.

**Re-entrancy brake.** `predicate-replay.js` calls `runFullScan` back on historical
blobs, so every internal re-scan must pass `provenance:false` or the pass recurses
without bound. Present callers: `history-scan.js` (×3), `pr-delta.js`,
`fix-verify.js`, `compare.js`; `lsp/server.js` uses the wider
`withStateWritesDisabled`.

**Privacy.** Author emails are collected but redacted by `redactFindingProvenance`
at every output boundary (`report/index.js`, `mcp/tools.js`) unless
`AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL=1` / `--include-author-email`. Separately,
`AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS=1` / `--pseudonymize-authors` (PRD Section 8)
replaces `authorName` with a stable `Contributor-XXXXXXXX` pseudonym instead of
withholding it — `redactFindingProvenance` applies the same treatment to
`providerEnrichment.reviewers`/`codeowners` (FR-PROV-022's PR-reviewer logins and
raw CODEOWNERS lines), not just `findingOrigin`. Both `report/index.js` and
`mcp/tools.js` read the env var per call to build the redaction options
(`mcp/tools.js` deliberately never reads `AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL`
itself — an agent caller gets no raw email regardless of that flag); the
`auditor-walkthrough.js` narrative reads it too, for the one `earliestOrigin`
field that bypasses `redactFindingProvenance` entirely (see that module's own
comment on why).

**At rest, `provenance/cache.js` stores the UNREDACTED record, on purpose.**
Redaction is a read-time/output-time concern — the same cached record gets
replayed back out through `redactFindingProvenance` differently per output
call (default vs. `--include-author-email` vs. `--pseudonymize-authors`), which
only works if the cache holds one raw, policy-independent copy. Pre-redacting
at write time would freeze whichever policy was active when the entry was
cached, breaking that per-call flexibility for every later reader (second
independent Finding Provenance PRD audit). The accepted mitigation is a
permissions floor, not encryption: every `cacheSet` chmods the entry file to
`0600` and the `provenance-cache/` directory to `0700` (same posture as
`integrity.js`'s per-install HMAC key). This defeats other local users/processes
reading the cache; it does not defeat root or the same OS user. See
`cache.js`'s own header for the full tradeoff writeup, including why
encryption-at-rest was considered and deferred.

## Gotchas

- The seed `calibration-seed.json` is small (n < 30 for several families). Don't treat it as a held-out set — that's `holdout-eval.js`'s job, against an externally-supplied JSONL.
- `learning.js` (active-learning loop) is **opt-in** behind `AGENTIC_SECURITY_LEARN=1` and has a quorum gate. Do not lower the quorum default without thinking about what a malicious-PR-author could suppress.
- `why-fired.js` is the provenance surface customers screenshot. If you change its shape, downstream reports break — bump a version string and migrate consumers.
