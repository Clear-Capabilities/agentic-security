# GA Gap Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gaps the GA programme ledger reports on 0.195.31 (83 named reasons, 38/253 records): make release evidence identify what it measured, measure the current engine on independent real code, raise recall on the measured misses, and prepare every Preview/Labs registry row so promotion is an evidence decision, not paperwork.

**Architecture:** Four engineering phases inside the repo, plus a decision list only the owner can close. Phase 1 fixes two defects that make records impossible to pass however good the engine is. Phase 2 produces the first current-engine independent measurement since 0.172.0. Phase 3 is a measured improvement loop on the development split only, one miss cluster per sub-plan. Phase 4 fills the registry GA bar truthfully, without changing any maturity.

**Tech Stack:** Node ≥ 24 ESM, `node --test`, the existing scripts (`scripts/scorecard.mjs`, `scripts/ga-program/ledger.mjs`, `bench/independent/realcode.mjs`, `scripts/engineering-excellence/independent-baseline.mjs`, `scripts/release-prepare.mjs`, `scripts/release-check.mjs`).

**Spec:** `AGENTIC_SECURITY_CURRENT_CAPABILITIES_GA_PLAN.PRD` (untracked, repo root) and the generated `docs/ga-program/STATUS.md`. The ledger is the acceptance source; this plan never edits a record's status by hand.

## Global Constraints

- `docs/capabilities.yaml` is the only source of maturity. No task in this plan changes a `maturity:` value.
- No answer-key signals, no label-keyed rules, no relabelling, no re-scoring the sealed split. Iterate on the development split only; the validation split is read once per cluster, at its exit.
- Never lower or edit a realcode floor in place. A successor baseline needs `realcode.mjs approve --supersede` with a stated reason, and it is out of scope here.
- No other tool's name appears in shipped code, docs or commit messages.
- No em-dashes in prose (docs, commit messages, changelog).
- An unrunnable check is a failure, never a skip. Every gate change is shown to exit 0 on good input AND non-zero on bad input.
- After touching `scanner/src/` or `scanner/bin/`, run `npm run build` before relying on the bundle.
- Every release goes through `node scripts/ship.mjs`; never `--no-verify`, never force-push.

## Review Focus

1. **A scorecard regenerated during a version bump.** Expected: it is refused or marked dirty, never committed as clean. (Task 1, test `refuses a dirty tree`.)
2. **A later commit that touches more than the two scorecard files.** Expected: the identity check fails, because the recorded commit no longer describes the shipped tree. (Task 1, test `fails when HEAD differs from the measured commit beyond the scorecard`.)
3. **A current-engine run that exists but has not been approved as baseline.** Expected: the scorecard and the ledger both report it as measured, judged against the approved floors. (Task 2, test `latest run of the current engine is judged against approved floors`.)
4. **A run whose identity is invalid (dirty commit, bundle digest mismatch).** Expected: `measured_not_release_grade`, the ledger record stays blocked. (Task 2, test `invalid identity blocks`.)
5. **A recall fix that also fires on `post/`.** Expected: localized precision is reported beside recall, and the cluster's exit criterion requires precision not to drop below the floor. (Task 4, exit criterion.)

---

## Phase 0: Decisions only the owner can make (not code)

These block 142 of the 215 manual records. The plan cannot close them; it lists the exact ask so they can be answered in one sitting.

| # | Decision | Records unblocked | What "done" looks like |
|---|---|---|---|
| D1 | Name a person for each of the 6 roles (security evaluation lead, graph/analysis lead, language/supply-chain lead, inference/evaluation engineer, platform security engineer, assurance engineer). One person may hold several. | 36 (GA-01) | `owner.person` set in `docs/ga-program/ledger.json` for every capability |
| D2 | Select pilot repositories and a maintainer for GA-12 subcapabilities | 46 (GA-12) | a pinned list (repo URL, commit) recorded in the ledger's `program` block |
| D3 | Acquire an independently adjudicated sealed population and name its custodian (GA-02); the dev/validation splits in `bench/independent/` are not sealed | 15 + 10 + 4 that depend on GA-02 | custodian named; `scripts/evaluation.mjs freeze` run on the protocol |
| D4 | Reserve hosted Linux confinement capacity (GA-08) and real-model hardware (GA-06) | 13 + 6 | runner labels exist in `.github/workflows/` |
| D5 | Clean-machine verifier and compliance-mapping reviewer (GA-11) | 9 | reviewer named, date set |
| D6 | Haskell coverage FR 04 benchmark and pilot data | FR 04 | data delivered to the `feat/git-aware-scope` worktree |

Phases 1 to 4 do not wait on any of these.

---

## Phase 1: Make evidence identity passable

### Task 1: Scorecard measured on a clean tree, every release

**Why:** all 36 `EVIDENCE-IDENTITY` records fail with "measured on a dirty worktree". Root cause: `scripts/release-prepare.mjs:84` regenerates the scorecard mid-bump, while every version file is uncommitted, so `worktreeClean` is false by construction on every release.

**Files:**
- Create: `scripts/scorecard-finalize.mjs`
- Modify: `scripts/release-prepare.mjs:84` (remove the scorecard step; print the finalize command as the last instruction)
- Modify: `scripts/release-check.mjs` (new check `scorecard-identity`, in the publish-blocker set beside `scorecard-freshness`)
- Modify: `scripts/ship/lib.mjs` (add `scorecard-identity` to the eight post-merge publish blockers, making nine; update the count wherever CLAUDE.md states it)
- Modify: `scanner/package.json` (script `"scorecard:finalize": "node ../scripts/scorecard-finalize.mjs"`; add the new test file to `test:posture`)
- Test: `scanner/test/scorecard-finalize.test.js`

**Interfaces:**
- Produces: `export function scorecardIdentity({ repo, scorecard, head }) -> { ok: boolean, reasons: string[] }` in `scripts/scorecard-finalize.mjs`. Pure apart from `git diff --name-only <scorecard.provenance.commit> HEAD`, which the caller passes in as `changedSince: string[]`. Signature therefore: `scorecardIdentity({ scorecard, version, changedSince })`.
- Produces: CLI `node scripts/scorecard-finalize.mjs [--no-commit]`: exit 2 if the tree is dirty (excluding `docs/SCORECARD.md`, `docs/scorecard.json`), otherwise runs `npm run scorecard`, asserts `measurement.cleanMeasurement === true`, then `git add` + `git commit` of exactly those two files with message `docs: scorecard for <version>, clean measurement at <short commit>`.

- [ ] **Step 1: Write the failing tests** in `scanner/test/scorecard-finalize.test.js`:
  - `refuses a dirty tree`: in a temp git repo built with `test/helpers/build-git-fixture`, an untracked `x.js` makes the CLI exit 2 and write nothing.
  - `passes when only scorecard files changed since the measured commit`: `scorecardIdentity({ scorecard: { provenance: { commit: C, worktreeClean: true, engineVersion: '1.0.0' }, measurement: { cleanMeasurement: true, engineVersion: '1.0.0' } }, version: '1.0.0', changedSince: ['docs/SCORECARD.md', 'docs/scorecard.json'] }).ok === true`.
  - `fails when HEAD differs from the measured commit beyond the scorecard`: same input with `changedSince` containing `scanner/src/engine.js` gives `ok === false` and a reason matching `/scanner\/src\/engine\.js/`.
  - `fails on a version mismatch`: `version: '1.0.1'` gives a reason matching `/1\.0\.0/`.
  - `fails when the measurement is not clean`: `worktreeClean: false` gives `ok === false`.
- [ ] **Step 2: Run and see them fail:** `cd scanner && node --test test/scorecard-finalize.test.js` → FAIL (module not found).
- [ ] **Step 3: Implement** `scorecardIdentity` and the CLI. Reuse the scorecard's exclusion list (`:(exclude)docs/SCORECARD.md`, `:(exclude)docs/scorecard.json`) from `scripts/scorecard.mjs:231` rather than retyping it: export it from there as `SCORECARD_OUTPUTS`.
- [ ] **Step 4: Run and see them pass.** Same command → PASS.
- [ ] **Step 5: Wire `scorecard-identity` into `release-check.mjs`** and add the two-direction test to `scanner/test/release-check.test.js`: `scorecard-identity passes on a finalized scorecard` and `scorecard-identity fails after a source commit on top`.
- [ ] **Step 6: Remove the scorecard step from `release-prepare.mjs`**; its final printed line becomes `next: commit the bump, then npm run scorecard:finalize`. Update the `release-prepare` test that pins the step list.
- [ ] **Step 7: Prove it on the real tree.** On a clean checkout of this branch: `cd scanner && npm run scorecard:finalize`, then `node ../scripts/ga-program/ledger.mjs --milestone | grep -c EVIDENCE-IDENTITY` → `0`. Then `node ../scripts/release-check.mjs --only scorecard-identity; echo $?` → `0`. Make an empty-content edit to a source file, commit it, re-run → non-zero. Reset that commit.
- [ ] **Step 8: Update docs** (`CLAUDE.md` "Shipping a release" and "Cutting a release quickly": the bump is now release-prepare, commit, scorecard:finalize, ship) and run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 9: Commit:** `fix: the scorecard is finalized on a clean tree after the bump commit, and a release check refuses one that no longer identifies the shipped tree`

### Task 2: The independent-accuracy record reads the current run and computes its verdict

**Why:** `independentAccuracyCurrent` in `scripts/ga-program/ledger.mjs:56-67` reads `bench/independent/RESULT.json` (engine 0.141.0, no identity fields) and `BASELINE.json.verdict`, a field `realcode.mjs approve` never writes. The record cannot pass even after a perfect run. Separately, `readApprovedIndependentRun` in `scripts/scorecard.mjs:131` reads only the approved run, so a fresh run of the current engine is reported `unmeasured` until someone moves the floors, which is the wrong incentive.

**Files:**
- Modify: `scripts/ga-program/ledger.mjs:56-67` and the `ctx` built at `:164`
- Modify: `scripts/scorecard.mjs:131-139` (read the latest run of the current engine; pass the approved floors' verdict alongside)
- Modify: `scanner/src/posture/accuracy-scorecard.js` `summarizeMeasurement` (accept `verdict` and publish `currentEngineRealcodeVerdict`)
- Test: `scanner/test/ga-program.test.js`, `scanner/test/accuracy-scorecard.test.js`

**Interfaces:**
- Consumes: `loadBaseline(runsDir)`, `latestRunId(runsDir)`, `evaluate({ floors, current, tier: 'release' })` from `bench/independent/realcode.mjs` (all exported today).
- Produces: `ctx.realcode = { runId, run, verdict }` in the ledger, where `run` is `runs/<latestRunId>/RESULT.json` and `verdict` is `evaluate(...)` against `loadBaseline().floors`. `independentAccuracyCurrent(ctx)` passes iff `run.engineVersion === ctx.version`, `run.identity.measurementValid === true`, and `verdict.status === 'passed'`. Evidence path `bench/independent/runs/<runId>/RESULT.json`.
- Produces: `docs/scorecard.json` `measurement.currentEngineRealcodeVerdict: 'passed'|'failed'|'blocked'|'insufficient_population'|'unmeasured'`.

- [ ] **Step 1: Write the failing tests** in `scanner/test/ga-program.test.js`, each with a temp runs dir (the ledger's `evaluate` gains a `runsDir` option, defaulting to `bench/independent/runs`):
  - `latest run of the current engine is judged against approved floors`: copy `floors-a72968195aa1.json` + `BASELINE.json` into the temp dir, plus a synthetic run `r2` with `engineVersion` = the tree's version, `identity.measurementValid: true`, and per-language localized rates above the floors → record `passed`, evidence path names `r2`.
  - `historical run blocks`: `r2.engineVersion = '0.172.0'` → `blocked`, detail matches `/historical/` (keeps the existing assertion at line 51 true).
  - `invalid identity blocks`: `measurementValid: false` → `blocked`, detail matches `/not valid/`.
  - `a regression fails`: `r2` go recall `0` → `blocked`, detail matches `/regression/`.
- [ ] **Step 2: Run and see them fail:** `cd scanner && node --test test/ga-program.test.js` → the new tests FAIL.
- [ ] **Step 3: Implement** the ledger change and the scorecard change. Remove the read of the top-level `bench/independent/RESULT.json` from the ledger's ctx. The scorecard keeps it only for the historical section.
- [ ] **Step 4: Add the scorecard test** `summarizeMeasurement publishes the computed realcode verdict` in `scanner/test/accuracy-scorecard.test.js`; run `node --test test/accuracy-scorecard.test.js test/ga-program.test.js` → PASS.
- [ ] **Step 5: Verify on the real tree:** `node scripts/ga-program/ledger.mjs --check; echo $?` → `0`, and `--milestone` still lists `INDEP-ACCURACY` as blocked with "historical" (no current run exists yet; Task 3 creates it).
- [ ] **Step 6: Commit:** `fix: the GA independent-accuracy record judges the latest current-engine run against the approved floors instead of reading a verdict field nothing writes`

---

## Phase 2: Measure the current engine

### Task 3: Fresh independent run on the released engine

**Files:**
- Create: `bench/independent/runs/<newRunId>/` (written by the tool)
- Modify: `docs/scorecard.json`, `docs/SCORECARD.md` (via `scorecard:finalize`)

- [ ] **Step 1: Plan the run** from a clean tree at the release commit: `cd scanner && npm run ee:independent-baseline -- --plan --per-language 30 --splits dev,validation --chunk 20`. Expected: a new run id printed, `plan.json` written. The script measures committed HEAD in a throwaway worktree, so editing the tree afterwards cannot change what is measured.
- [ ] **Step 2: Run it in the background**, using absolute paths and a single backgrounding mechanism: `node /Users/ross/code/agentic-security/scripts/engineering-excellence/independent-baseline.mjs --run --run <id> --chunk-timeout-min 90`. The last run took about 4 hours (13:30 to 17:28). Check with `--status --run <id>`, never by re-launching.
- [ ] **Step 3: Merge:** `--merge --run <id>`. Expected: `RESULT.json` with `identity.measurementValid: true` and `scoring.denominators.reconciles: true`.
- [ ] **Step 4: Judge:** `cd scanner && node ../bench/independent/realcode.mjs check --tier release --run <id>; echo $?`. Record the exit code and the verdict line verbatim. Do not approve or supersede floors.
- [ ] **Step 5: Forensics:** `npm run bench:independent:forensics -- --run <id>` → `runs/<id>/FORENSICS.md`. This ranked cluster table is Phase 3's input.
- [ ] **Step 6: Finalize the scorecard** (Task 1) and confirm `node scripts/ga-program/ledger.mjs --milestone` no longer says "no current-engine independent accuracy record". If the verdict is not `passed`, the record stays blocked and the milestone line says why; report the verdict as it is.
- [ ] **Step 7: Commit** the run directory (minus `logs/` if `.gitignore` excludes it) and the scorecard: `bench: independent run <id> on <version>, localized F1 <x> (n/d), release-tier verdict <status>`.

---

## Phase 3: Raise recall on the measured misses (development split only)

The 0.172.0 forensics (`bench/independent/runs/a72968195aa1/FORENSICS.md`) ranked 272 localized misses. Task 3 re-ranks them on the current engine. The expected order, to be confirmed by that run:

| Cluster | 0.172.0 count | Share |
|---|---|---|
| no detector rule fired near the defect (`no_detector_candidate`) | 151 | 55.5% |
| no source recognised in the defect file | 44 | 16.2% |
| no source recognised at all | 27 | 9.9% |
| right location, wrong family (`wrong_file_or_cwe`) | 22 | 8.1% |
| no sink recognised near the defect | 10 | 3.7% |
| source and sink recognised, no flow | 7 | 2.6% |

### Task 4: One sub-plan per cluster, top down

Each cluster gets its own plan file (`docs/superpowers/plans/<date>-recall-<cluster>.md`), written only after reading that cluster's entries in the new FORENSICS.md, because the fix depends on which CWEs and languages dominate it. This task fixes the loop every sub-plan follows:

- [ ] **Step 1: Pick the cluster and split it by (language, CWE).** Use `bench/independent/why-missed.mjs --run <id> --ids <dev-split ids in the cluster>`. Never open a validation or sealed entry's source while designing a rule.
- [ ] **Step 2: For each (language, CWE) bucket with at least 5 dev entries,** write the rule the way `scanner/src/sast/CLAUDE.md` describes: a minimal `vulnerable/` + `clean/` fixture pair under `scanner/test/fixtures/<rule>/`, written from the CWE's general shape, not copied from an entry. TDD as usual: failing fixture test, rule, passing test.
- [ ] **Step 3: Regression gates:** `npm run test:sast`, `npm run bench:cve-replay:check`, `npm run bench:mutation:check`, `npm run bench:self-scan:check`. Any equality-baseline drift (layer recall) is re-baselined deliberately with `docs/METRICS.md` synced.
- [ ] **Step 4: Dev-split re-measure** of only the cluster's dev entries: `npm run bench:independent -- --deep --ids <ids>`. Report localized recall AND precision with n/d.
- [ ] **Step 5: Exit criterion, checked once:** the cluster's validation entries are scored a single time. The cluster exits when validation localized recall rises and localized precision stays at or above the realcode floor for every language touched. If validation does not move, the cluster is recorded as not generalizing, and the rule ships only if it is correct on its own fixtures and does not lower precision.
- [ ] **Step 6: Ship each cluster as its own release** through `ship.mjs`, with the measured before/after (n/d) in the changelog entry.

After the top three clusters, re-run Task 3 in full, so the next ranking is measured, not assumed.

---

## Phase 4: Registry rows ready for an evidence decision

The `registry-ga-bar` record passes only on promotion, and promotion needs the other records. This phase does not pass records; it removes the metadata work, so a capability is promoted the day its evidence lands. **No `maturity:` changes.**

### Task 5: Fill the GA bar fields truthfully

**Files:**
- Modify: `docs/capabilities.yaml` (the rows below)
- Create (where missing): `docs/reference/<id>-contract.md` with a `## What it does not do` section, and `scanner/test/contracts/<id>.contract.test.js`
- Modify: `scanner/package.json` (each new contract test goes into `test:posture`, which the hosted `test-shard` job runs)

| Group | Rows | Missing |
|---|---|---|
| A | agentic-discovery, rule-compiler, finding-provenance, detection-and-response, local-models | `platforms` |
| B | context-intelligence, code-boundaries, graph-precision | `gate`, `platforms` |
| C | model-validation, fleet-scan, strategic-metrics, eval-lab, release-assurance | `gate`, `limits`, `since`, `platforms` |
| D | language-depth-haskell-nix, compliance-evidence, detector-spec-synthesis (Labs), capability-enforcement (Labs) | all six |

- [ ] **Step 1: For each row, prove the platform before writing it.** A row may carry `platforms: [linux:test-shard]` only if its `contractTest` file appears in a script that `test-shard` runs: `grep -c '<contract test file>' scanner/package.json` ≥ 1 and the script is in the shard union (`scanner/test/ci-test-shards.test.js` pins it). For Group D, use the job that really exercises it (`language-suites`/`language-gates` for Haskell/Nix, `sandbox-linux` for capability-enforcement). Never list a job that doesn't run the test.
- [ ] **Step 2: `gate`** is the release-check id that fails when the contract breaks; `contract-conformance` (runs every registry contract test) is correct for any row whose contract test exists.
- [ ] **Step 3: `since`** is the version the contract was frozen (from its `contractNote` or the changelog), never the current version by default.
- [ ] **Step 4: `limits`** points at an anchor that exists; `scripts/check-ga-contracts.mjs` verifies it.
- [ ] **Step 5: Group D contracts** are written from the code as it is today (what the module promises, what it refuses), with a contract test that pins the frozen record shape. Write one row at a time, each with its own commit.
- [ ] **Step 6: Verify both directions:** `node scripts/check-ga-contracts.mjs; echo $?` → 0. Temporarily point one row's `platforms` at `linux:no-such-job` → non-zero. Revert. Then `npm run docs:check-positioning`, `node scripts/check-doc-drift.mjs --gate`, `node scripts/ga-program/ledger.mjs --check`, `npm run test:posture`.
- [ ] **Step 7: Regenerate** `node scripts/ga-program/ledger.mjs --render` and confirm each row's REG-BAR detail now reads "needs nothing but the promotion itself".
- [ ] **Step 8: Commit per group:** `docs: GA bar fields for <rows>, each platform job verified to run its contract test; no maturity change`

---

## Out of scope for this plan (each needs its own spec first)

- **Roadmap capabilities** `security-learning-rate`, `live-runtime-observation`, `connected-production-detection`: no implementation exists. Each starts with a brainstorming session and a PRD. `security-learning-rate` is the cheapest: it needs a measurement independent of the rule compiler's own corpus, which Phase 2's runs could supply.
- **GA-12 subcapabilities, GA-08 isolation proof, GA-06 real-model qualification, sealed-population gates:** blocked on D2, D4 and D3 respectively.
- **Threat-model staging / independent / attested-runner items:** need infrastructure outside the repo.

## Order and expected effect

| Order | Work | Records it can move | Wall clock |
|---|---|---|---|
| 1 | Task 1 | 36 EVIDENCE-IDENTITY → passed | about half a day |
| 2 | Task 2 | makes 10 INDEP-ACCURACY passable | about half a day |
| 3 | Task 3 | 10 INDEP-ACCURACY → passed if the release verdict passes; first current-engine accuracy figure | 4 to 5 hours of unattended run |
| 4 | Task 5 | 0 directly; turns 17 promotions into evidence-only decisions | 1 to 3 days (Group D dominates) |
| 5 | Task 4, per cluster | the real accuracy number; GA-02 records once D3 lands | ongoing |
| any | Phase 0 decisions | up to 142 manual records | owner's time |
