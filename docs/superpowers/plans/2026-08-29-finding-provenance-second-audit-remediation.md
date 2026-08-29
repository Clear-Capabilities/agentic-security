# Finding Provenance — Second-Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the real gaps a second, independent audit found between the Finding Provenance PRD's literal text and the actually-shipped code, after the first 10-item remediation plan (`docs/superpowers/plans/2026-08-28-finding-provenance-prd-completion.md`) was already fully implemented and reviewed. Fix the verified security defect first; then work through the rest of the audit's own materiality ranking.

**Architecture:** No new subsystem. Every task is a targeted fix or a wiring gap closed inside the existing `scanner/src/posture/provenance/` module, `engine.js`, `bench/provenance*/`, or documentation. No task introduces new detectors, new schema versions, or new CLI surface beyond what's already planned per-task below.

**Tech Stack:** Same as the rest of the scanner — Node ≥ 24, ESM, `node --test`.

**Spec:** The binding authority is the PRD itself: `Agentic-Security-Finding-Provenance-PRD.docx` (repo root, extract via `textutil -convert txt -stdout` — it is a binary file, the `Read` tool cannot open it). This plan's tasks are the direct output of a full independent re-audit against that document; the audit's own findings (quoted inline per task below) are the argument for each task, not a paraphrase to re-derive.

## Global Constraints

- **Work happens directly on `main`, no worktree** — same standing execution mode as the first remediation plan in this session. All commits land on `main` directly; nothing is pushed to origin without separate, explicit user confirmation.
- **Continuous execution.** Do not pause between tasks to check in. The user has already approved the full scope ("fix the security defect first then do the rest") — execute the whole plan, task 1 first, then the rest in the order below (which mirrors the audit's own materiality ranking).
- **Verification discipline** (root `CLAUDE.md`, binding, do not relax it): confirm every edit actually landed by re-reading the file; never state a test number or gate result without having just run it in this turn; capture real exit codes; wipe stray `.agentic-security/` dirs from bench corpora before running gate checks; rebuild (`npm run build`) after any `src/` change before relying on the bundle.
- **Suppression/pragma, findings-schema, and ESM conventions**: as documented in the root `CLAUDE.md` and `scanner/CLAUDE.md` — unchanged by this plan.
- **No task in this plan may weaken an existing safety/privacy guarantee** established by the first remediation plan (terminal-injection sanitization, symlink-escape protection, the anti-fabrication guarantee for synthetic `logicVulns`, the shared per-scan provider-enrichment cap, pseudonymization reaching every output boundary). Any task touching adjacent code must re-run that guarantee's existing regression tests and confirm they still pass.
- **Honesty over a forced "done."** Task 6 (performance) in particular may not be fully closeable to the PRD's literal ≤30% target with safe, in-scope changes — the first remediation plan's own Task 10 already spent the cheapest available optimization and fell short by design analysis, not oversight. Where a task cannot fully close its gap, implement what is safely achievable, and report the honest remaining gap — do not claim closure that isn't real.
- **Model selection**: security-relevant tasks (1) and cross-cutting/highest-risk tasks (2, 6) get task-scoped review on a capable model (opus), matching this session's established pattern for stakes-appropriate review.

---

### Task 1: Harden provenance's git subprocess invocations against a hostile repository (SECURITY — do first)

**Audit finding (verbatim):** "Verified arbitrary code execution when scanning a hostile repository (Section 8 control 3, FR-PROV-024). `git-evidence.js`'s `_run` invokes git with no config hardening. A repo whose `.git/config` sets `core.fsmonitor` to a script gets that script executed by `getRepoState`'s `git status --porcelain`. I proved it: a fixture with `core.fsmonitor` pointing at a marker-writing script → `getRepoState()` alone wrote the marker. It also fires on a full scan *with* `--no-provenance` (other scanner git calls share the exposure)... The project already knows this class: `secret-history.js:65` passes `--no-textconv`. `git-evidence.js` passes nothing. `commitDiff`'s `git show -U0` is additionally exposed to `.gitattributes` `textconv` drivers."

**Files:**
- Modify: `scanner/src/posture/provenance/git-evidence.js` (the `_run` helper and every git invocation site in this module)
- Investigate + modify if needed: other git-invoking modules the audit flagged as sharing the exposure (`secret-history.js` already has partial hardening — check what it does and whether it's complete; grep the whole `scanner/src/` tree for other raw `git` subprocess calls that read repository state)
- Test: new test file or extend `scanner/test/posture/provenance-git-evidence.test.js`

- [ ] **Step 1: Reproduce the exploit first, as a failing test**

Before touching the fix, write a test that builds a git fixture (use `createGitFixture()` from `scanner/test/helpers/build-git-fixture.js`) whose `.git/config` sets a hostile `core.fsmonitor` (or another hook-shaped config key — pick whichever the audit's own repro used, verify by reading its available config keys) pointing at a script that writes a marker file outside the repo (e.g. to a tmpdir). Call the real `git-evidence.js` function that triggers it (`getRepoState()`, per the audit) against that fixture. Assert the marker file does NOT get created. This test must FAIL against the current code — run it and confirm the failure before proceeding, so the fix is provably closing a real hole, not a hypothetical one.

- [ ] **Step 2: Harden every git invocation in `git-evidence.js`**

Find the module's `_run` helper (or equivalent — every git subprocess call should funnel through one place; if it doesn't today, that's itself worth fixing as part of this task so hardening is applied uniformly rather than per-call-site). Add config flags that disable the hostile surfaces the audit named:

- `-c core.fsmonitor=` (empty value disables it)
- `-c core.hooksPath=/dev/null` (or the platform-correct null-device equivalent — confirm `/dev/null` works as a hooks path on this project's supported platforms, or use an empty existing directory if not)
- `--no-textconv` on any `git show`/`git diff` invocation (the audit specifically calls out `commitDiff`'s `git show -U0` as exposed to `.gitattributes` textconv drivers)
- `GIT_CONFIG_NOSYSTEM=1` and `GIT_TERMINAL_PROMPT=0` in the subprocess environment (not as `-c` flags — these are env vars)

Apply this to literally every git invocation in the module, not just the one the repro test exercises — grep for `spawnSync`/`execFileSync`/`exec(` (whatever this module actually uses) and confirm no call site is missed.

- [ ] **Step 3: Audit other git-invoking modules for the same exposure**

The audit noted this "fires on a full scan *with* `--no-provenance`... other scanner git calls share the exposure" and that `secret-history.js` already has partial hardening (`--no-textconv` only, per the audit's exact quote). Grep the whole `scanner/src/` tree for other modules that shell out to `git` to read repository state (not just the provenance module). For each one found: confirm whether it's already adequately hardened, and if not, apply the same hardening from Step 2. Do not scope-creep into unrelated git-invoking code that has nothing to do with reading potentially-hostile repo state (e.g., code that only touches this project's own trusted repo) — use judgment, and record which modules you checked and your reasoning for each in your report, so the reviewer can verify the sweep was real and not partial.

- [ ] **Step 4: Confirm the repro test now passes, and add coverage for the other hardened surfaces**

Re-run the Step 1 test — it must now PASS. Add additional test cases for `--no-textconv` (a `.gitattributes` with a hostile textconv driver on the file `commitDiff` reads) and for `core.hooksPath` if you can construct a fixture that would otherwise fire a hook during one of this module's read operations (post-checkout hooks don't fire on `git show`/`git log` — verify which git operations in this module could plausibly trigger a hook at all before writing a test that can't actually prove anything; document your reasoning if a particular hardening flag has no exploitable path through this module today and is defense-in-depth only).

- [ ] **Step 5: Run the full provenance test suite plus a broader regression check**

Run `cd scanner && node --test test/posture/provenance-*.test.js test/security/provenance-*.test.js` (foreground) and confirm no regressions — the hardening flags must not change output for a well-behaved repository (this project's own repo, and every existing fixture). Run `npm run bench:cve-replay:check` and `npm run bench:self-scan:check` (wiping stray `.agentic-security` dirs first) to confirm the hardening doesn't change detection behavior anywhere in the wider scanner.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/git-evidence.js [other modified files] [test files]
git commit -m "$(cat <<'EOF'
fix(security): harden provenance git subprocess calls against hostile repo config

A second independent PRD audit found and verified this exploitable:
git-evidence.js invoked git with no config hardening, so a repository
whose .git/config sets core.fsmonitor to a script gets that script
executed by getRepoState()'s own git status call -- a security scanner
that can be made to execute arbitrary code by the untrusted repository
it's scanning, directly contradicting FR-PROV-024 / PRD Section 8's
"never run repository hooks or untrusted build scripts" requirement.

[describe exact fix + verification]

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QeYBFfb2HefSGibC6SbAUS
EOF
)"
```

---

### Task 2: Bind detector/ruleset version into the cache key and evidence digest

**Audit finding (verbatim):** "The cache key and the evidence digest are not actually bound to the detector/ruleset version (FR-PROV-028, Data Contract 'Evidence integrity'). `coordinator.js:343` feeds `makeCacheKey({detectorVersion: ctx.rulesetVersion})`, and `engine.js:10354` sets `rulesetVersion: process.env.AGENTIC_SECURITY_RULESET_VERSION || null`. That env var is essentially never set... Consequences: (a) upgrading the scanner does **not** invalidate cached provenance, even though detector behaviour changed... (b) `computeDigest`'s `rulesetVersion` binding is always `null`. `engine.js:8664` already computes a **real** effective ruleset version via `_effectiveRulesetVersion(scanRoot)` for a different purpose, ~1700 lines earlier in the same file — the fix is one line."

**Files:**
- Modify: `scanner/src/engine.js` (the `rulesetVersion` field construction, ~line 10354 — re-locate exactly, this plan's own earlier tasks shifted line numbers repeatedly)
- Test: `scanner/test/posture/provenance-cache.test.js` and/or `scanner/test/posture/provenance-coordinator.test.js` (whichever already covers cache-key/digest construction — check both)

- [ ] **Step 1: Re-locate and verify the audit's claim**

Find `_effectiveRulesetVersion(scanRoot)` in `engine.js` and confirm it's a real, already-computed value used elsewhere in the same scan (per the audit, ~1700 lines before the provenance block). Find the current `rulesetVersion: process.env.AGENTIC_SECURITY_RULESET_VERSION || null` construction and confirm the audit's characterization (the env var is essentially never set in practice — check whether any CLI flag or config sets it, or whether it's truly dead).

- [ ] **Step 2: Wire the real value in**

Replace the env-var-only source with `_effectiveRulesetVersion(scanRoot)` (call it once per scan if it isn't already cheap/idempotent — check its cost; if it's expensive, ensure it's not recomputed 5 times for the 5 `annotateGitProvenance` calls, mirroring this plan's own established "one shared value in `provenanceCtx`" pattern from `deadlineAt` and the provider-enrichment cap). Keep the env var as an optional override if there's a legitimate reason an operator would want to pin a different value (check whether the PRD or existing code implies this is desirable) — otherwise, prefer the real computed value outright.

- [ ] **Step 3: Confirm both consumers now see the real value**

Confirm `analysisBasis.ruleset` in a real scan's output is no longer `null` (run a real scan against a small fixture and check). Confirm `makeCacheKey`'s `detectorVersion` component and `computeDigest`'s `rulesetVersion` binding both now use the real value.

- [ ] **Step 4: Add a regression test proving the invalidation property**

Write a test that: computes a cache key (or a full cached provenance record) with one ruleset version, then simulates a ruleset version change (however `_effectiveRulesetVersion` derives its value — likely from `package.json` version or a rules-file hash; read its implementation first) and confirms the cache key changes / a cached record is treated as stale. This is the actual property FR-PROV-028 requires — pin it, don't just check the field isn't `null`.

- [ ] **Step 5: Run and verify**

Run `cd scanner && npm run test:posture` (foreground). Confirm no cache-related regressions — a ruleset-version change now genuinely invalidating cache entries could interact with existing cache tests that assumed a stable `null` value; find and fix any that do.

- [ ] **Step 6: Commit**

---

### Task 3: Fix the rename reason-code misattribution and the dead `renameAmbiguous` value

**Audit finding (verbatim):** "The fallback reason code is **misattributed** — `predicate-never-confirmed-in-candidates`, not a rename reason. `confidence.js:21` defines `rename_ambiguous`, but `coordinator.js:429` hardcodes `renameAmbiguous: false`, so it is dead code."

**Files:**
- Modify: `scanner/src/posture/provenance/coordinator.js` (~line 429, re-locate)
- Modify if warranted: `scanner/src/posture/provenance/confidence.js`
- Test: extend `scanner/test/posture/provenance-coordinator.test.js` or the rename fixture test in `bench/provenance-accuracy/`

**Scope note:** this task fixes the MISATTRIBUTION and DEAD CODE the audit found — it does NOT attempt to make rename-tracking actually follow a rename end-to-end (that's a real, separately-scoped engine capability gap already honestly disclosed in the first remediation plan's own close-out; re-read `bench/provenance-accuracy/fixtures/rename.mjs`'s header for the full root-cause trace before starting, so this task's fix is consistent with — not contradicting — that existing honest disclosure).

- [ ] **Step 1: Re-locate and read the current code**

Find the current `renameAmbiguous: false` hardcode in `coordinator.js` and the `rename_ambiguous` definition in `confidence.js`. Determine: was `renameAmbiguous` ever meant to be computed from a real signal (a rename detected by git but not confidently followed), or was it speculatively added and never wired? Read git history/blame on these lines if it helps clarify intent, but don't over-invest — the fix is about honesty, not necessarily about making the field do more than it safely can.

- [ ] **Step 2: Fix the reason-code misattribution**

When `replayAt`'s candidate search fails specifically because the target file was renamed (not just genuinely absent from history) — this is exactly the case `bench/provenance-accuracy/fixtures/rename.mjs`'s header already traces precisely — the emitted reason should say something rename-specific, not the generic `predicate-never-confirmed-in-candidates`. Determine whether the code path can actually detect "this specific failure is rename-shaped" (e.g., because `git log --follow` or an equivalent rename-aware git call CAN find prior history for the file under an old name, even though the predicate-replay path itself doesn't handle it) — if it can distinguish this case cheaply, add a more specific reason string (e.g. `rename-detected-not-followed`) alongside the existing generic one, rather than trying to solve the underlying rename-following gap. If distinguishing the case cheaply isn't actually possible without doing the real rename-follow work (which is out of scope), it's acceptable to leave the reason code as-is but ensure it's not actively MISLEADING — read the current string's exact wording and judge honestly whether it's simply generic (acceptable, though non-ideal) or actively wrong (must fix).

- [ ] **Step 3: Resolve the dead `renameAmbiguous` field**

Either (a) wire it to a real signal if Step 1/2's investigation surfaced one that's cheap and safe to compute, or (b) if no real signal is available without the larger rename-follow work, remove the hardcoded `false` and the field itself if it's not read anywhere downstream that would break on its absence (check callers/schema first — this is a schema field, so removing it may need the same care Task-scoped work in the first remediation plan gave schema changes: check `emptyProvenance`, `validateFindingProvenance`, any consumer). If removal isn't safe (a consumer expects the field to exist), leave it present but`null`/`undefined` rather than a hardcoded misleading `false`, and comment honestly why it's inert today.

- [ ] **Step 4: Run and verify**

Run the rename fixture in `bench/provenance-accuracy/` and confirm it still (honestly) shows the same FAIL — this task doesn't change the underlying accuracy number, only the honesty of the surrounding metadata. Run `cd scanner && npm run test:posture` and the accuracy bench.

- [ ] **Step 5: Commit**

---

### Task 4: Render `ageBasis`/confidence wherever a finding's age is shown

**Audit finding (verbatim):** "`mttr.js:44-59` sets `ageBasis` + `provenAgeDays` correctly — but only onto `persistedScan` (`last-scan.json`), *after* the report body is rendered, so no emitted report carries it. `grep -rn ageBasis scanner/src/report scanner/bin` → **zero renderers**. And `renderSlaSummary` (`mttr.js:111-113`) prints `"median open age Nd"` with no basis and no confidence — a direct miss on 'Reports never show an age without its basis and confidence.'"

**Files:**
- Modify: `scanner/src/posture/mttr.js` (`renderSlaSummary` and wherever else age is rendered)
- Modify: whichever `scanner/src/report/` renderer(s) emit an age-bearing field, if any beyond `mttr.js`
- Test: extend `scanner/test/mttr.test.js` (or wherever `renderSlaSummary` is currently tested)

- [ ] **Step 1: Find every place a finding's age is rendered to a human**

Grep for age-related output across `scanner/src/posture/mttr.js`, `scanner/src/report/`, and `scanner/bin/agentic-security.js`. The audit named `renderSlaSummary` specifically; confirm whether there are others.

- [ ] **Step 2: Thread `ageBasis` (+ its confidence) into each renderer**

`mttr.js` already computes `ageBasis`/`provenAgeDays` correctly per the audit — the gap is purely that renderers don't receive or print it. Update `renderSlaSummary` (and any other renderer found in Step 1) to accept the basis/confidence alongside the raw age number, and print both — e.g. `"median open age 12d (proven origin, HIGH confidence)"` vs `"median open age 12d (first-seen fallback — origin not proven)"`. Match this codebase's existing terse, information-dense CLI output style (look at neighboring output lines for tone/format).

- [ ] **Step 3: Add regression tests**

Pin that the rendered string differs correctly between a proven-origin case and a first-seen-fallback case — the exact property the PRD acceptance requires ("Reports never show an age without its basis and confidence").

- [ ] **Step 4: Run and verify**

`cd scanner && node --test test/mttr.test.js` plus a broader `npm run test:report` if age rendering touches that scope.

- [ ] **Step 5: Commit**

---

### Task 5: Wire `computeProvenanceCoverage` into a real, running scorecard generation path

**Audit finding (verbatim):** "Provenance coverage... Unmeasured. `computeProvenanceCoverage` exists (`accuracy-scorecard.js:276`), is unit-tested, and is wired into `buildScorecard` — but `scripts/scorecard.mjs` never passes `inputs.scan`, so it evaluates to `{measuredThisRun:false}`. The committed `docs/scorecard.json` has **no `provenanceCoverage` key at all**."

**Context:** this was flagged as a deliberate deferral at the end of the first remediation plan specifically because it required a real design decision — which corpus to scan live, and at what cost/time budget — that wasn't specified. This task makes that decision and implements it.

**Files:**
- Modify: `scripts/scorecard.mjs`
- Possibly modify: `scanner/src/posture/accuracy-scorecard.js` if `buildScorecard`'s `inputs.scan` contract needs adjusting to fit a real corpus scan's shape

- [ ] **Step 1: Decide which corpus to scan live, and read `computeProvenanceCoverage`'s actual denominator requirements first**

Read `computeProvenanceCoverage(scan)` in `accuracy-scorecard.js` to confirm exactly what shape of `scan` object it needs (per the first plan's Task 6 ledger note: P0-scoped denominator = `scan.findings` + `scan.secrets` + `scan.supplyChain` filtered to direct deps). `scripts/scorecard.mjs` already runs several corpus harnesses (`bench/cve-replay/runner.mjs`, `bench/self-scan/measure.mjs`, `bench/layer-recall/runner.mjs`) — determine whether any of them already performs a real `runScan`/`runFullScan` call internally whose raw scan object could be captured and reused (cheapest option), or whether a NEW, minimal live scan needs to be added purely to feed this metric. The self-scan harness (scanning this project's own `scanner/src`) is the most likely reusable candidate — check whether `bench/self-scan/measure.mjs` exposes its raw scan object via its `--json` output or only aggregated counts.

- [ ] **Step 2: Implement the live scan feed**

If an existing harness's raw scan is reusable: modify it to also emit the raw `scan` (or the specific fields `computeProvenanceCoverage` needs) via its `--json` output, and have `scripts/scorecard.mjs` pass that through to `buildScorecard({..., scan: ...})`. If a new minimal scan is genuinely needed: add the smallest one that can produce a meaningful P0-scoped denominator (a self-scan of `scanner/src` with `provenance` enabled is the natural choice, matching what `bench/self-scan` already does) — be mindful of `scripts/scorecard.mjs`'s existing cost profile (it already runs multiple corpus harnesses; don't double the runtime without reason, prefer reusing an existing scan's output over adding a second full scan).

- [ ] **Step 3: Confirm the metric now appears in real output**

Run `cd scanner && npm run scorecard` (the real command) and confirm `docs/scorecard.json` now genuinely contains a `provenanceCoverage` key with `measuredThisRun: true` and real numbers, and `docs/SCORECARD.md` renders the corresponding section. Report the REAL measured coverage percentage — do not guess it.

- [ ] **Step 4: Update `docs/scorecard.json`/`docs/SCORECARD.md`**

Per root `CLAUDE.md`'s documented release process, these are committed artifacts regenerated via `npm run scorecard`. Commit the regenerated versions alongside this task's code change.

- [ ] **Step 5: Run and verify**

`cd scanner && npm run test:posture` (for `accuracy-scorecard.test.js` and anything scorecard-adjacent) plus `npm run scorecard:check`.

- [ ] **Step 6: Commit**

---

### Task 6: Further reduce provenance replay overhead where safely possible, and fix the performance bench's own measurement gaps

**Audit finding (verbatim):** "**Measured this turn: `22.64x` ratio (1385 ms with, 61 ms without)**... That is ~2160% overhead, not ≤30%... **Memory overhead is not computed at all** (only a with-provenance heap delta; no without-provenance comparison, no ratio). No p95 (single run). No warm-cache arm, so FR-PROV-029's 'publishes cold/warm results' is unmet... this bench is wired into **no gate**."

**Scope, read carefully:** this task has TWO distinct halves with different honesty expectations:

1. **Measurement honesty (must fully close):** the bench itself has real, fixable gaps — no memory-overhead ratio, no p95 methodology, no warm-cache arm, and it's ungated. These are process/measurement bugs independent of whether the underlying number ever hits 30%, and should be fixed properly.
2. **The actual overhead number (may not fully close):** the first remediation plan's Task 10 already implemented the cheapest safe optimization (skipping the annotator pipeline during replay) and got a real ~26% reduction, honestly falling short of the ≤30% *overhead* target (not to be confused with the 26% *reduction*, which the second audit correctly flagged as a different, easily-confused number). This task should investigate whether further safe reduction is achievable, implement what's genuinely safe, and REPORT THE HONEST REMAINING GAP if the target still isn't closed — do not force a number, do not weaken correctness to hit it.

**Files:**
- Modify: `bench/provenance/runner.mjs` (measurement methodology fixes)
- Modify: `scanner/src/posture/provenance/predicate-replay.js`, `scanner/src/engine.js` (only if a genuine further safe optimization is found)
- Modify: `scripts/pre-push-gate.mjs` or wherever the equivalent perf gate is already wired (confirm current wiring first) if it needs adjustment for a new warm/cold split

- [ ] **Step 1: Fix the memory-overhead measurement**

Read `bench/provenance/runner.mjs`'s current heap measurement. It currently only records a with-provenance heap delta. Add a matching without-provenance measurement and compute a real ratio, the same shape as the existing time-overhead ratio. Update `BASELINE.json`'s schema and the check logic accordingly (this is a new baseline dimension — treat it the same care as any other baseline change: measure a real number, don't invent one, and update via the project's existing `update-baseline` convention if one exists for this bench).

- [ ] **Step 2: Add a p95 methodology**

A single run is not a p95. Run the timed scan N times (choose a reasonable N — look at how `bench/cve-replay` or other benches in this repo handle repeated-measurement statistics for precedent, or use a sensible default like 10-20 runs) and compute a real p95 for both time and memory. Update the reported/gated number to be the p95, not a single sample.

- [ ] **Step 3: Add a warm-cache arm**

The PRD requires cold AND warm results to be published. Add a second measurement pass that runs against a warm provenance cache (the same fixture, scanned twice, with the second run's cache hit timed separately) and report both cold and warm p95s.

- [ ] **Step 4: Wire the bench into a real gate**

Confirm the current state (the audit says it's in NO gate — verify this is still true, package.json script existence isn't gating). Wire `bench:provenance:check` into `scripts/pre-push-gate.mjs` (matching `bench:cve-replay:check`/`bench:self-scan:check`'s existing precedent) if it isn't already, or into `scripts/release-check.mjs` if pre-push is deliberately reserved for faster checks only (check the existing gate's documented cost budget in root `CLAUDE.md`'s "Pre-push gate" section before deciding which — the perf bench's own runtime cost matters for this decision, measure it).

- [ ] **Step 5: Investigate further safe overhead reduction**

With the accurate p95/memory measurement now in place from Steps 1-3, investigate whether any further SAFE reduction is available beyond Task 10's `skipAnnotators` work. Candidates worth a quick look (do not commit to implementing all of these — investigate, then implement only what's genuinely safe and worthwhile): (a) whether `predicate-replay.js`'s per-candidate-commit nested scan could avoid re-parsing files that didn't change between adjacent candidate commits; (b) whether the fixed ~39ms per-call overhead (noted in existing code comments) has a further reducible component now that annotators are skipped; (c) whether the reference fixture the bench measures against is representative — a measurement artifact inflating the ratio would be worth fixing even without an engine change. Do NOT weaken any correctness or safety property (the `computeStableId` byte-identical invariant from Task 10 of the first plan, the anti-fabrication guarantee, etc.) to chase this number — if the investigation finds no safe further win, or only a marginal one, implement the marginal win if truly safe and simple, otherwise stop and report the honest remaining gap.

- [ ] **Step 6: Run and verify, report the real final numbers**

Run the fixed bench for real, multiple times if needed to confirm stability, and report: the real p95 time-overhead ratio, the real p95 memory-overhead ratio, cold and warm, against the PRD's literal ≤30%/≤20% targets. State plainly whether these are now met, and if not, by how much, matching this project's own "report failures as failures" discipline.

- [ ] **Step 7: Commit**

---

### Task 7: Schema-fidelity cluster — dead evidence-attribution roles, `historyCoverage.boundaryCommit`, `firstObserved` cache-miss risk, missing `stableId` on 3 channels

**Audit findings (verbatim, four related items):**

1. "`evidenceAttribution`'s `removed_guard`, `guard`, `config`, and `secret` roles are dead code. Nothing in `scanner/src` sets `step.removedGuard`; the other three are never constructed. The PRD's own worked example emits a `removed_guard` node."
2. "`historyCoverage.boundaryCommit` is hardcoded `null` in all four construction sites — so Scenario F's 'identifies the shallow boundary' is unmet, `--provenance-since` never appears in the emitted record, and the digest's 'history boundary' input is inert."
3. "`firstObserved` is the current scan, and only *looks* correct because of the cache... A cache miss (HEAD moves, the 7-day `cache` TTL fires, cache cleared) silently resets it to 'now'. The lifecycle ledger already stores the true first `introduced` event and is never read back."
4. "`stableId` is emitted only on the SAST channel. `report/index.js:253` is the sole site; the secrets/logic/SCA normalization branches omit it... A consumer cannot recompute the `evidenceDigest` for three of four channels."

**Files:**
- Modify: `scanner/src/posture/provenance/evidence-attribution.js` (roles)
- Modify: `scanner/src/posture/provenance/coordinator.js` (`historyCoverage.boundaryCommit`, `firstObserved`)
- Modify: `scanner/src/report/index.js` (`stableId` emission — the ~line 253 site, generalize to all channels)
- Test: extend the relevant existing provenance test files per sub-item

This is one task because all four are small, related schema-fidelity fixes discovered by the same audit pass and touch the same subsystem — but treat each as an independently-verifiable sub-fix; don't let one's complexity block the others landing.

- [ ] **Step 1 (role coverage): Wire `removed_guard` for the one existing case that can set it, and decide honestly on the other three**

The `guard-removal` fixture/scenario already exists in this codebase (referenced by FR-PROV-006's semantic-boundary-validation work) — check whether the code path that DETECTS a removed guard could ALSO set `step.removedGuard: true` on the relevant evidence-attribution step cheaply, since the detection logic already exists even if the role-tagging doesn't. If yes, wire it and add a test asserting a `removed_guard`-shaped node appears for that scenario. For `guard`/`config`/`secret` roles: determine per-role whether any current detector's evidence naturally maps to one (e.g., does a secrets-provenance finding's evidence attribution belong under a `secret` role rather than the generic `sink` it currently gets, per the audit's own earlier finding that "a secret finding gets role `sink`"?). Wire what's cheap and correct; for anything that would require new detector-side work beyond this task's scope, leave it undone but replace any misleading "supported" implication in comments/docs with an honest "not currently emitted by any detector" note, matching this project's established honesty convention.

- [ ] **Step 2 (`historyCoverage.boundaryCommit`): compute the real value**

Find all four construction sites (per the audit). The value should reflect the actual git history boundary the scan operated within — likely derived from `--provenance-since` when set, or from the shallow-clone boundary (`git rev-list --max-parents=0` or the shallow grafts file) when the repo is shallow. Wire the real value at each site; if a site genuinely has no boundary concept (e.g., a scan with neither `--provenance-since` nor a shallow clone), `null` remains correct there — the fix is making it non-null where a real boundary exists, not eliminating `null` universally.

- [ ] **Step 3 (`firstObserved`): read back the true first-observed event from the lifecycle ledger**

On a cache miss, instead of defaulting `firstObserved` to the current scan, check the lifecycle ledger (which the audit confirms already stores the true first `introduced` event) for this finding's `stableId` and use its earliest recorded `introduced` event if one exists, falling back to the current scan only when the ledger genuinely has no prior record (a truly new finding). This closes the actual gap: two consecutive scans with a cold cache and an intervening cache-clear should still report the same `firstObserved` if the lifecycle ledger has history for this finding.

- [ ] **Step 4 (`stableId` on all channels): generalize the SAST-only emission site**

Read the current `report/index.js` site (~line 253) that emits `stableId` only for the SAST channel. Generalize it (or add equivalent emission at the secrets/logic/SCA normalization branches) so every channel that carries a `findingProvenance` also carries its `stableId` in output — this is what lets an external consumer recompute `evidenceDigest` independently, which the PRD's schema section requires. Confirm this doesn't break the existing golden cross-format-parity tests (extend them instead — they should now assert `stableId` presence on all 4 channels, not just SAST).

- [ ] **Step 5: Run and verify all four sub-fixes together**

`cd scanner && npm run test:posture && npm run test:report` (foreground). Confirm the cross-format golden tests, the lifecycle tests, and the evidence-attribution tests all still pass with the new, stricter assertions this task adds.

- [ ] **Step 6: Commit**

---

### Task 8: Gate the known-origin-accuracy bench into CI

**Audit finding (verbatim):** "The known-origin-accuracy bench is ungated... `bench:provenance-accuracy:check` is in no gate at all, so the 12/13 number can silently rot."

**Files:**
- Modify: `scripts/pre-push-gate.mjs` or `scripts/release-check.mjs` (whichever is the right home — see below)

- [ ] **Step 1: Decide which gate**

Measure `bench:provenance-accuracy:check`'s real runtime (`time npm run bench:provenance-accuracy:check`). Compare against the pre-push gate's documented cost budget (root `CLAUDE.md`'s "Pre-push gate" section states its current full-pass cost — roughly 2.5-3.5 min). If adding this bench keeps the pre-push gate within a reasonable budget, wire it there (matching `bench:cve-replay:check`/`bench:self-scan:check`'s precedent, which are already pre-push-gated). If it's too slow for pre-push, wire it into `scripts/release-check.mjs` instead (matching how the dependency-currency check is deliberately reserved for release time per root `CLAUDE.md`'s own documented rationale) — and update root `CLAUDE.md`'s "Pre-push gate" section's own list of what it runs, either way, so the doc stays accurate (this project has been bitten by exactly this class of doc-drift multiple times already this session).

- [ ] **Step 2: Wire it, matching the existing gate script's pattern exactly**

Read how `bench:cve-replay:check`/`bench:self-scan:check` are invoked in whichever gate script you chose, and add the new check the same way (same error-handling shape, same "unrunnable check is a FAILURE not a skip" convention).

- [ ] **Step 3: Verify both directions**

Prove the gate now runs this check: run the gate script for real and confirm the accuracy bench's output appears. Prove it actually fails the gate on a bad input — temporarily (in a throwaway local check, never committed) make the accuracy bench fail and confirm the gate script's exit code goes non-zero, then revert.

- [ ] **Step 4: Commit**

---

### Task 9: Documentation — required compliance disclaimer, user-facing docs, stale CHANGELOG

**Audit findings (verbatim, three related items):**

1. "The PRD's **REQUIRED DISCLAIMER** ('does not prove developer intent, control operation outside code, organizational compliance, or certification') appears **nowhere** in shipped code or docs."
2. "No user-facing documentation for Finding Provenance exists — `README.md` and `docs/` ... never mention it; only `commands/triage.md:119` references `--provenance`. The PRD's Definition of Done requires documentation of semantics, limitations, privacy defaults, policy behavior, and commands."
3. "The CHANGELOG's `Unreleased` section is stale. It documents M0–M2 only. It says `deep` mode... 'runs `standard` in this release' — no longer true... It lists six new flags... there are now **seven**; `--pseudonymize-authors` is missing. M3..., M4..., and the PRD-completion work... have no entries."

**Files:**
- Modify: `CHANGELOG.md` (repo root — confirm exact filename/location first)
- Modify: wherever compliance-provenance output is rendered (`auditor-walkthrough.js`'s `deriveComplianceProvenance` output, and/or the compliance report renderer that consumes it — find the real consumer)
- Create: user-facing documentation for Finding Provenance — likely `docs/` (check existing doc structure/conventions in `docs/` first, e.g. `docs/POSITIONING.md`'s style, and whether a `docs/PROVENANCE.md` or similar is the right shape, or whether it belongs as a section in an existing doc)

- [ ] **Step 1: Add the required disclaimer to compliance-provenance output**

Find where `deriveComplianceProvenance`'s output actually reaches a human (compliance report rendering). Add the PRD's disclaimer text (verbatim or a faithful paraphrase — check the PRD's exact wording via the extracted text) at that boundary, so anyone reading a compliance-provenance claim sees the limitation alongside it. Do not add it so prominently that it drowns out the actual finding — match this project's existing pattern for similar disclaimers elsewhere (e.g. the evidence bundle's `doesNotProve` string) for tone/placement precedent.

- [ ] **Step 2: Write user-facing documentation**

Cover: what Finding Provenance is (one paragraph), the status values and what each means, the privacy defaults (email withheld by default, pseudonymization flag), the policy flags (`--require-provenance`, `--assurance strict`), the known limitations (rename-tracking degrades to partial, shallow clones can't always resolve, performance overhead on replay-heavy scans), and the exact CLI commands (`agentic-security scan --provenance`, `--include-author-email`, `--pseudonymize-authors`, `--provenance-timeout`, `--provenance-since`, `agentic-security attest`, `agentic-security verify-attestation`). Ground every flag name and status value in the real current code — do not write from memory of what should exist, check `scanner/bin/agentic-security.js`'s actual flag list and `schema.js`'s actual status enum.

- [ ] **Step 3: Fix the CHANGELOG**

Update the `Unreleased` section (or add proper dated entries if this project has since cut releases that should have covered this — check `scanner/package.json`'s current version and whether M3/M4/the two remediation plans correspond to already-released versions that need their own retroactive entries, or whether they're still genuinely unreleased). Fix the "deep mode runs standard" claim (no longer true). Fix "six flags" → count the real current number and list them (the audit found seven with `--pseudonymize-authors` missing — recount from live `agentic-security.js`, don't just add one to six blindly, since other tasks in this plan may not add new flags but should be double-checked). Add entries for M3 (deep DAG, transitive SCA, missing-control, providers), M4 (signed bundles, cross-repo lineage, AI authorship), and the two remediation plans' work.

- [ ] **Step 4: Commit**

---

### Task 10: Redact author email in the on-disk provenance cache at rest

**Audit finding (verbatim):** "The on-disk provenance cache stores raw author emails, unredacted. PRD Section 8 says the cache 'stores content-addressed results without … unnecessary personal data.' I read the cache files written into my fixture: `authorName= Jamie Chen | authorEmail= a@b.c`, in plaintext under `.agentic-security/provenance-cache/`, regardless of the default-off email policy and unaffected by `--pseudonymize-authors`. The redaction happens only at the output boundary."

**Files:**
- Modify: `scanner/src/posture/provenance/cache.js`

**Design consideration, resolve before implementing:** the cache stores the FULL provenance record so it can be replayed back out through `redactFindingProvenance` at each output boundary with whatever policy that specific output call wants (default vs. `--include-author-email` vs. `--pseudonymize-authors` — three different possible presentations of the SAME cached record, chosen per-call). If the cache stores an ALREADY-redacted record, that per-call flexibility breaks — every reader would get whichever policy was in effect at CACHE-WRITE time, not what they actually asked for at CACHE-READ time. Read `cache.js` and `coordinator.js`'s actual cache read/write flow to confirm this concern is real before deciding an approach; if it is, the fix is likely file-system-level (encrypt or restrict permissions on the cache directory) or a genuinely separate at-rest concern (e.g., storing the raw email hashed/reversibly-encrypted at rest, decrypted only transiently when serving a read that requests it) rather than stripping the field outright. Do not break the existing three-ways-to-present-one-cached-record property to fix this — if no safe fix preserves that property, document the tradeoff honestly and choose the smallest safe mitigation (e.g., restrictive file permissions on the cache directory as a floor, even if full at-rest redaction isn't achievable without breaking the flexibility property).

- [ ] **Step 1: Confirm the actual tension exists**

Trace a cache write and read in `cache.js`/`coordinator.js`. Confirm whether the SAME cached record really does get read back and re-redacted differently per output call (if pseudonymization is genuinely applied fresh at each read against a stable cached raw record, the tension above is real). If it turns out the cache is ALREADY written post-redaction somehow (unlikely per the audit's direct evidence, but verify), this task's scope changes.

- [ ] **Step 2: Implement the smallest safe mitigation**

Based on Step 1's finding, implement either: (a) restrictive file permissions (0600/0700) on the cache directory/files if not already applied — check current permissions first; (b) if genuinely safe without breaking the flexibility property, encrypt-at-rest with a per-install key (this project already has a per-install HMAC key pattern for `last-scan.json` integrity — a similar per-install key could serve here, check `$XDG_CONFIG_HOME/agentic-security/scan-key`'s existing precedent); or (c) if neither is a clean fit within this task's reasonable scope, document the tradeoff clearly in `cache.js`'s own header comment and in `posture/CLAUDE.md`'s privacy section, and implement at minimum the file-permission floor.

- [ ] **Step 3: Test**

If permissions were tightened: a test confirming the cache directory/files are created with the tighter mode. If encryption was added: a test confirming a raw email substring does NOT appear in the on-disk cache file bytes, while a normal read-back still produces the correct value.

- [ ] **Step 4: Commit**

---

### Task 11: Stabilize the flaky `attest-provenance` test

**Audit finding (verbatim):** "One flaky test in the provenance suite... `test/cli/attest-provenance.test.js` › 'verify-attestation: round-trips a real provenance bundle end-to-end' (`r.status === null`, i.e. its 15s `spawnSync` timeout fired under parallel load; the same file gives its `scan` step 60s). Run alone, the file is 4/4 green... This is a timing-fragile test, not a product bug — but it can flake in CI."

**Files:**
- Modify: `scanner/test/cli/attest-provenance.test.js`

- [ ] **Step 1: Find the 15s timeout and raise it to match the file's own 60s precedent**

Find the specific `spawnSync` call with a 15s timeout in this test file. Per the audit, the SAME file already gives its `scan` step 60s — raise this call's timeout to match (or to whatever value is consistent with this file's own established budget for a real CLI subprocess call under load).

- [ ] **Step 2: Verify**

Run the test file alone (should already pass) and, if feasible, alongside a representative chunk of the suite to sanity-check the timeout increase actually helps under contention (this machine's documented flakiness pattern makes a guaranteed repro hard — a reasonable-effort check is enough, don't chase a guaranteed reproduction).

- [ ] **Step 3: Commit**

---

## End-of-plan: final build + whole-branch verification

After Task 11 (the last task), before the final whole-branch review:

- [ ] Run `cd scanner && npm run build 2>&1 | tail -20` (foreground, timeout 120000) and confirm it completes without error.
- [ ] Run `cd scanner && npm test` (foreground; this machine has documented, pre-existing subprocess-CLI-under-load flakiness in the full suite — if it exits non-zero, collect the union of failing test files across 2-3 attempts and verify each passes in an isolated, smaller `node --test` invocation before concluding "no regression," matching the exact method used at the close of the first remediation plan).
- [ ] Run `cd scanner && npm run bench:cve-replay:check` and `npm run bench:self-scan:check` (wiping stray `.agentic-security` dirs first).
- [ ] Run `cd scanner && npm run bench:provenance:check` and `npm run bench:provenance-accuracy:check` — read and report the REAL numbers (Task 6/8 will have changed both this bench's methodology and its gating).
- [ ] Run `cd scanner && npm run scorecard:check` (Task 5 wired live scorecard data — confirm this still passes).
- [ ] Run `node --test test/no-dead-modules.test.js test/check-doc-drift.test.js test/artifact-registry-completeness.test.js` explicitly.
- [ ] Confirm `git status --porcelain` is clean (aside from the pre-existing untracked PRD `.docx`).
