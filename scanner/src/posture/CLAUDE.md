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

**Fix lifecycle** — `fix-history.js` (apply + backup + recover), `fix-verify.js` (closed-loop re-scan + lint), `fix-plan.js` (oversized-patch fallback), `regression-test-gen.js`, `deterministic-fix.js` (safe context-independent literal-swap patch synthesis — md5/sha1→sha256, TLS verify-off→on — materialized on demand by `mcp/synthesize_fix`; every patch still passes through `apply_fix`'s inline verify before it lands).

**Agentic verification** — `verifier.js`, `verifier-target.js`, `verifier-ephemeral.js`, `harness-discovery.js`, `adversary-agent.js`, `defender-agent.js`, `auditor-agent.js`, `three-agent-pipeline.js`.

**Methodology additions (`docs/AGENTIC_METHODOLOGY_PRD.md`)** — default-on annotators/artifacts that layer the agentic-hunter methodology on the deterministic engine:
- `falsification.js` — default falsification pass. For each taint-style finding, tries to DISPROVE it (locate a context-matched control on the path, reusing `dataflow/sanitizer-proof.js`'s shape rules read-only); a blocked finding is demoted + `quarantined`, never removed and never severity-touched (recall-preserving, like `proof-gate`). Wired after `annotateProofGate`. Opt out: `AGENTIC_SECURITY_NO_FALSIFICATION=1`. Optional LLM tier over survivors when an endpoint is configured.
- `entrypoint-inventory.js` — attack-surface completeness ledger. Enumerates every entry point (HTTP/queue/cron/CLI/env/upload/webhook) with a disposition each; on `scan.entrypointInventory`.
- `root-cause-sweep.js` — from confirmed findings, finds sibling instances detectors missed with total-count accounting (`found === candidates + mitigated`); on `scan.rootCauseSweep`. Searches the corpus **once per distinct sink pattern**, not once per finding — findings deriving the same pattern share one walk and one set of (read-only) match records. The counts are always exact; the materialised `instances` list is a bounded sample (`INSTANCE_SAMPLE_LIMIT`, 100) and says so via `instancesTruncated`. Both properties are load-bearing on large corpora: the per-finding walk was O(findings × corpus-bytes) and the instance records were O(findings × matches), which together exhausted a 6 GB heap on a 40k-file suite. If you touch this module, keep the own-site exclusion **per pattern group** — resolving it globally makes a group subtract an exclusion it never matched and drives counts negative.
- `model-routing.js` — capability-based CWE/severity→model policy; stamps `finding.dispatchModel` (strongest for crypto/auth/critical, mid for injection, cheapest for low-sev hardening) for cost-sensitive subagent dispatch.
- `fix-honesty-gate.js` — deterministic honesty gates on fix output: a residual-risk hand-wave guard, a cited-file:line requirement for any FP/safe verdict, and FULL/MITIGATION/WORKAROUND completeness tiers. Consumed by `fix-verify.js` when the caller supplies fix metadata; the closed-loop test leg (`fix-verify-loop.js`) is wired into `mcp/apply_fix` behind `AGENTIC_SECURITY_FIX_RUN_TESTS=1`.

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

**Integrity + signing** — `integrity.js` (per-install HMAC for `last-scan.json`), `rule-pack-signing.js`. The HMAC key lives at `$XDG_CONFIG_HOME/agentic-security/scan-key`; override via `$AGENTIC_SECURITY_HMAC_KEY`. Premortem-derived; do not regress to hostname-derived.

**Rule lifecycle** — `custom-rules.js` (YAML pattern DSL), `rule-overrides.js` (`disable:` gated on signature), `rule-packs.js`, `rule-synthesis.js` (proposes suppressions from triage feedback), `ruleset-version.js`.

**Posture artifacts** — `sbom.js`, `aibom.js`, `api-inventory.js`, `threat-model.js`, `trust-boundary-diagram.js`, `stack-playbook.js`, `deploy-platform.js`, `license-policy.js`, `material-change.js`, `mttr.js`, `streak.js`, `scorecard.js`, `security-trend.js`.

**Why this fired** — `why-fired.js`. Runs LAST so it reflects every annotation. Customer-facing provenance.

## Conventions

- **Mutate or copy?** Annotators that set finding fields mutate in place. Helpers that derive a *new* finding list (clustering, dead-code) return a new array.
- **State files.** All state goes under `.agentic-security/` (scan root) or `~/.config/agentic-security/` (per-install). Never write to the scanner source tree.
- **Annotation order matters.** If your annotator reads `f.confidence`, run it after `annotateConfidence`. If it reads `f.exploitability`, run it after `annotateExploitability`. Wire in `engine.js`, not in `index.js`.
- **No throwing.** Every annotation in `engine.js` is wrapped `try { … } catch (_) {}`. Your annotator must degrade gracefully — set `null` on the field and continue.
- **Dead-module test.** `npm run test:lifecycle` fails the build if you export a public symbol from a posture module that no other source file imports. Wire it in `engine.js` (or allowlist it with a written reason in `test/no-dead-modules.test.js`).

## Execution-proof tiers (R2)

`proof-tier.js` + `execution-proof.js` add a fourth axis to a finding's
credibility, orthogonal to `confidence`/`exploitability`: whether the bug was
*run*, not just reasoned about.

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
guarantee. The kernel-namespace backend is unverified on this host and, even
where available, only confines network — it does **not** confine writes.
Treat `execution-proven` evidence from a non-`userspace` backend as weaker
than the same tier from `userspace` until that backend's write confinement
is independently verified. `attachProofTier()` also enforces the demotion
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

## Gotchas

- The seed `calibration-seed.json` is small (n < 30 for several families). Don't treat it as a held-out set — that's `holdout-eval.js`'s job, against an externally-supplied JSONL.
- `learning.js` (active-learning loop) is **opt-in** behind `AGENTIC_SECURITY_LEARN=1` and has a quorum gate. Do not lower the quorum default without thinking about what a malicious-PR-author could suppress.
- `why-fired.js` is the provenance surface customers screenshot. If you change its shape, downstream reports break — bump a version string and migrate consumers.
