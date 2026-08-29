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

**Integrity + signing** — `integrity.js` (per-install HMAC for `last-scan.json`), `rule-pack-signing.js`. The HMAC key lives at `$XDG_CONFIG_HOME/agentic-security/scan-key`; override via `$AGENTIC_SECURITY_HMAC_KEY`. Premortem-derived; do not regress to hostname-derived.

**Rule lifecycle** — `custom-rules.js` (YAML pattern DSL), `rule-overrides.js` (`disable:` gated on signature), `rule-packs.js`, `rule-synthesis.js` (proposes suppressions from triage feedback), `ruleset-version.js`.

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

## Gotchas

- The seed `calibration-seed.json` is small (n < 30 for several families). Don't treat it as a held-out set — that's `holdout-eval.js`'s job, against an externally-supplied JSONL.
- `learning.js` (active-learning loop) is **opt-in** behind `AGENTIC_SECURITY_LEARN=1` and has a quorum gate. Do not lower the quorum default without thinking about what a malicious-PR-author could suppress.
- `why-fired.js` is the provenance surface customers screenshot. If you change its shape, downstream reports break — bump a version string and migrate consumers.
