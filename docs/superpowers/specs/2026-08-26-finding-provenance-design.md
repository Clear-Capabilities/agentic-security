# Design — Finding Provenance (P0: schema, standard local provenance, assurance integration)

**Status:** Approved (design phase). Implementation not yet started.
**Date:** 2026-08-26
**Source:** `Agentic-Security-Finding-Provenance-PRD.docx` ("Finding Introduction & Provenance", v1.0, prepared for Clear Capabilities, dated 2026-08-27).
**Author:** Ross Young / Clear Capabilities Inc. (design captured by Claude, session-driven)
**Scope:** `scanner/src/` (new `posture/provenance/` module family, `engine.js` pipeline wiring, `report/index.js`, `pipeline/finding-schema.js`, `posture/mttr.js`, `posture/privacy-framework.js`, `posture/auditor-walkthrough.js`, `posture/fix-history.js`, `bin/agentic-security.js` flags) plus new fixtures/benchmarks under `scanner/test/` and `bench/provenance/`.
**Audience:** Engineering (scanner core).

---

## 1. Why this exists

Today a finding explains *what* is wrong and *where*. It doesn't explain *when* the underlying condition became true, whether it entered through the current PR or was inherited debt, or whether a safeguard was removed later. Line-level `git blame` cannot answer this reliably — the PRD's own product decision states it plainly:

> Do not equate Git blame with vulnerability origin. The feature must distinguish the commit that last touched a line, the commit that made the finding true, the commit that introduced it to the target branch, and the first scan that observed it.

This design implements the PRD's **P0 release scope only** — Milestones 0–2 (schema/fixtures, standard local provenance, assurance/output integration). P1 (transitive SCA origin, non-linear DAG analysis, provider PR metadata, missing-control regressions) and P2 (signed attestations, cross-repo lineage, AI-authorship metadata) are explicitly out of scope for this design and are called out inline wherever this design touches ground they'll later extend.

### Scope decisions made during brainstorming (binding for this design)

1. **SCA line tracking.** Manifest/lockfile parsers (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`, `Cargo.toml`, etc.) are extended to record the declaration line, so direct-dependency provenance (FR-PROV-014) gets real line-level blame rather than file-level content search.
2. **Cross-file taint findings** get full origin/boundary provenance in this phase, but walking **first-parent ancestry only** — non-linear DAG traversal (merges/reverts/cherry-picks as first-class lifecycle events) stays P1 per FR-PROV-010.
3. **Core origin-resolution algorithm:** blame-seeded candidate set + linear semantic replay (see §4.3), not bisection. Bisection assumes the finding-condition predicate toggles at most once across history, which a required acceptance scenario (fix → reintroduce) violates; candidate-seeded linear replay handles it correctly at acceptable cost because candidates come from blame/log, not full history.

### FRs in scope for this design

Epic A: FR-PROV-001 – 009 (FR-PROV-010, deep DAG, is P1 — excluded).
Epic B: FR-PROV-011 – 014, FR-PROV-016 (FR-PROV-015 transitive SCA and FR-PROV-017 missing-control regression are P1 — excluded).
Epic C: FR-PROV-018 – 021 (FR-PROV-022 provider enrichment and FR-PROV-023 signed evidence are P1/P2 — excluded, but §7's `--provenance deep` flag and §6's `evidenceDigest` field are built as forward-compatible stubs for them).
Epic D: FR-PROV-024 – 029, all P0, all in scope.

---

## 2. Product semantics this design must not violate

Carried directly from the PRD (§2), because every module below is judged against these:

- **Finding origin** ≠ **line attribution** ≠ **first observed**. These are three different objects in the schema (§6), never collapsed into one.
- Required language: "introduced in a commit authored by…", never "caused by…" or "developer responsible". "Earliest observable" when history is shallow/truncated/rewritten. "Uncommitted" for working-tree findings, author never inferred from local Git config.
- **Confidence model** (High/Medium/Low/Unknown) per the PRD's table — implemented as a deterministic rule table in `confidence.js` (§4.6), not a heuristic score.
- Non-goals stay non-goals: no intent/culpability/negligence inference, no reconstruction of history destroyed by force-push/rebase/squash, no remediation-owner assignment from authorship alone.

---

## 3. Pipeline

```
runFullScan() [engine.js]
  │
  ├─ ... existing detector / dedupe / cross-file / deep-mode IR pipeline ...
  ├─ annotateGitHistory()        (existing, unchanged — blame seed input)
  ├─ ... annotateMitigationComposite, persona-prioritization, _v3 reports ...
  ├─ annotateWhyFired()          (existing, unchanged)
  ├─ SCA / multi-sink correlation passes  (existing, unchanged)
  │
  ├─▶ annotateProvenance(scan.findings, ctx)      ← NEW: coordinator.js
  ├─▶ annotateProvenance(scan.supplyChain, ctx)   ← NEW: same coordinator, SCA finding-type strategy
  │
  ├─ annotateRelevance()         (existing, unchanged — runs after, per its own "reflects final state" precedent)
  ├─ buildEntrypointInventory()  (existing, unchanged)
  └─ return scan

[bin/agentic-security.js, post toJSON(scan)]
  ├─ stampFindingTimestamps()    (existing mttr.js — now also reads finding.provenance for ageBasis)
  └─ [posture/compliance evaluators, invoked separately over the scanned findings]
       └─ gap rows gain controlRefs + derived provenance summary (§7.3)
```

The provenance stage plugs in **after `annotateWhyFired` and the SCA/multi-sink correlation blocks, before `annotateRelevance`** — the same "runs last, reflects final state" position those two modules already establish, and it needs `annotateGitHistory`'s blame output as one of its candidate-seed inputs (§4.3).

---

## 4. Architecture components

New module family under `scanner/src/posture/provenance/`, matching the existing `posture/` convention (small, single-purpose files):

| Module | Responsibility |
|---|---|
| `coordinator.js` | `annotateProvenance(findings, ctx)` entry point. Schedules per-finding enrichment under budget (§8.4), guarantees a terminal `provenance` object on every finding even on error/timeout/non-Git (never appends findings, never drops them). |
| `git-evidence.js` | Read-only Git plumbing: repo identity, HEAD, dirty/staged state, shallow/grafted detection, `log -L`, blame porcelain, `show <ref>:<path>`, rename tracking (`--follow`/`-M`). Extends `posture/git-history.js` (existing blame becomes the candidate-seed step) rather than duplicating it. |
| `predicate-replay.js` | "Does this finding's condition hold in this historical blob" — single-file replay via `git show <ref>:<path>` → IR parse → the one compatible detector, reusing the pattern `history-scan.js` already established for full-repo historical scans, but scoped to one file/one detector for cost control. |
| `origin-resolver.js` | Implements §4.3: seeds candidates from `git-evidence.js`, walks oldest→newest, calls `predicate-replay.js` at each candidate and its first parent, returns `findingOrigin` + `historyCoverage`. |
| `branch-entry.js` | FR-PROV-004: resolves the commit that introduced the condition to the *selected target branch* (often a merge/squash), separately from the graph-origin commit. |
| `evidence-attribution.js` | FR-PROV-005: per-evidence-node blame (source/sink/guard/removed_guard/config/secret/manifest/lockfile) — never collapses multiple evidence nodes into one author. |
| `lifecycle.js` | FR-PROV-013: builds ordered introduce/remediate/reintroduce events (§5.1). |
| `confidence.js` | Deterministic rule table → `{level, score, reasons[]}` per the PRD's Confidence model table (§2 above). |
| `cache.js` | Content-addressed disk cache, repo-local (§5.2). |
| `validate.js` | Schema enforcement (§6.2). |

### 4.1 Compatible-detector set for P0

Single-file SAST/secret/IaC rules: replay via `predicate-replay.js` against one historical blob. Cross-file taint findings: same replay mechanism, scoped to the small file set the flow touches, first-parent ancestry only (scope decision #2). Direct SCA: no detector replay at all — manifest/lockfile diff walk instead (§4.2). Compliance-derived gaps: no independent resolution — inherited summary only (§7.3). Anything with no compatible replay path (rule shape has changed since the historical commit) falls back to `method: "line-attribution"`, confidence capped at `medium`, per FR-PROV-006.

### 4.2 Direct SCA origin strategy

Manifest parsers gain a recorded declaration line (scope decision #1). Origin resolution walks `git log -p -- <manifest>` (and lockfile where present), diff-parses each revision's declared/resolved version, and checks it against the OSV vulnerable-range data already fetched for the finding. Origin is the first commit where the resolved version falls in-range. This is a version-range predicate, not a detector replay — `predicate-replay.js` is not involved here.

### 4.3 Origin-resolution algorithm (the core of the feature)

**Approach chosen: blame-seeded candidate set + linear semantic replay.**

1. Seed candidates via `git log -L <line>,<line>:<path>` (or the blame porcelain chain) — the ordered list of commits that ever touched the relevant evidence lines/file. This avoids walking full history for the common case.
2. Walk that candidate list **oldest → newest**, bounded by `--provenance-since`/`--provenance-timeout` (§8.4).
3. At each candidate, replay the compatible detector against the historical blob (`predicate-replay.js`) for both the candidate commit and its first parent.
4. Origin = earliest candidate where the predicate holds **and** is absent in the first-parent boundary (FR-PROV-003's acceptance criterion — sanitizer-removal fixtures must resolve to the removal commit, not the original source/sink lines).
5. This is not order-assuming, so it handles reintroduction (PRD Scenario E) correctly — unlike bisection, which was rejected specifically because it assumes a single toggle.

Rejected alternatives (documented for future readers, not re-litigated): bisection (O(log n) replay calls, but breaks under reintroduction without added monotonicity-detection complexity — noted as a possible `--provenance deep` optimization, not built now); blame-only with no semantic replay (fastest, but explicitly forbidden by the PRD's top-line product decision and FR-PROV-006's acceptance test).

---

## 5. Lifecycle, caching, and state persistence

### 5.1 Lifecycle store

New repo-local state file `.agentic-security/provenance/lifecycle.json`, keyed by `stableId` (the existing semantic fingerprint in `posture/stable-id.js` — already line-independent, no changes needed there). Same directory family and file-locking discipline as `fix-history/log.json` (reuse its `_withLogLock` pattern rather than inventing a new one). Each entry is an ordered event array: `{type: introduced|remediated|reintroduced, commit, authorDate, scanId, observedAt}`.

Every scan diffs current findings against this store by `stableId`:
- New `stableId` → `introduced` event, dated from `findingOrigin.authorDate` when `status:"complete"`, else from `firstObserved`.
- Previously-open `stableId` now absent → `remediated` event.
- A `stableId` with a prior `remediated` event that reappears → `reintroduced` event.

Current age always uses the **latest open** introduction (last `introduced`/`reintroduced` not yet followed by a `remediated`). This is additive to `mttr.js`'s existing `firstSeenAt`/`lastSeenAt` (which stay as-is, answering the different question of scan-cadence survival) — not a replacement.

### 5.2 Age/SLA basis wiring (FR-PROV-019)

`mttr.js` gains logic reading `finding.provenance` to pick `ageBasis`:
- `finding_origin` — status `complete`, age = now − `findingOrigin.authorDate`.
- `earliest_observable` — status `partial`, same computation, flagged.
- `first_observed` — status `not_available`/`error`, age = now − `firstObserved.observedAt` (today's existing behavior).
- `uncommitted` — age = now − `firstObserved.observedAt`, tagged distinctly (no commit to anchor to).

Runs where `mttr.js` already runs (post `toJSON(scan)` in `bin/agentic-security.js`), since `provenance` is attached to findings inside `engine.js` before that point — no ordering change needed.

### 5.3 Provenance cache (FR-PROV-028)

Separate from the lifecycle store — caches the expensive *origin-resolution computation*, not the lifecycle narrative. Repo-local at `.agentic-security/provenance/cache/`, **not** the global `~/.claude/agentic-security/osv-cache/`: provenance results are repo+commit-specific and carry author names, so a global directory would mix unrelated repos' author data for no benefit. Same bespoke pattern as the existing OSV cache (`sha256(key)` → JSON file), but purely content-addressed, **no TTL** — the key already includes repo identity + HEAD + finding fingerprint + detector/ruleset version + history boundary + mode, so a changed HEAD or ruleset naturally produces a new key. A force-push/rebase that rewrites history without changing HEAD is a documented, accepted limitation, not something this design detects.

---

## 6. Data model and schema enforcement

### 6.1 Schema

The `provenance` object follows the PRD's Data Contract (§6 of the PRD) exactly: `schemaVersion`, `status`, `findingOrigin`, `branchIntroduction`, `firstObserved`, `evidenceAttribution[]`, `method`, `confidence`, `historyCoverage`, `analysisBasis`, `limitations[]`. One addition not shown in the PRD's example JSON: **`evidenceDigest`** — a sha256 hex digest binding stable finding ID + repo identity + HEAD + origin/branch-entry commits + evidence-node locations/blob IDs + detector/ruleset version + history boundary + method + confidence reasons + limitations, per the PRD's "Evidence integrity" section. This is the *unsigned* digest only — Ed25519 signing (FR-PROV-023) is P2 and not built here; the digest exists now so a future signer has something stable to attach to without a schema break.

Enumerations (verbatim from the PRD): `status`: `complete | partial | not_available | uncommitted | budget_exhausted | error`. `method`: `semantic-history-replay | dependency-graph-diff | line-attribution | scan-history | none`. `confidence.level`: `high | medium | low | unknown`. `evidenceAttribution.role`: `source | sink | guard | removed_guard | transformation | config | secret | manifest | lockfile | other`. `ageBasis`: `finding_origin | earliest_observable | first_observed | uncommitted`.

### 6.2 Enforcement, not just observability

`pipeline/finding-schema.js`'s `FINDING_FIELD_GROUPS` gets `provenance` added as **required**. `describeFindingCompleteness()` is promoted from observability-only to an actual gate via the new `validate.js`, used in tests/CI (FR-PROV-001's "schema validation rejects a finding with a missing provenance object"). At runtime the actual guarantee comes from `coordinator.js` itself — same pattern as `finding-defaults.js` backfilling `parser`/`family` — it always attaches a terminal `provenance` object (worst case `{status:"error", ...}`), so the reject-path in `validate.js` is a correctness backstop that a normal scan should never hit, not a runtime throw wired into the hot path.

### 6.3 Terminal-status decision tree

Git unavailable/error → `error`. Finding only in working tree/index → `uncommitted`. Budget expired mid-resolution → `budget_exhausted`. History shallow/grafted and boundary reached without resolving → `partial` + earliest-observable wording. Fully resolved with parent-boundary verified → `complete`. No Git repo at all (`--no-provenance` or non-Git dir) → `not_available`.

---

## 7. Output rendering, compliance, and CLI

### 7.1 Output parity (FR-PROV-018)

Every format (`toJSON`, `toCSV`, `toMarkdown`, `toJUnit`, `toSARIF`, `toHTML`, `toSTIX`, `toVex`, `toCLI`, `toProTable`) already consumes `normalizeFindings(scan)`'s flat array — `provenance` is carried through there, one change gives parity everywhere. Author-email redaction (FR-PROV-021) happens at the same choke point: **hidden by default in every format, including JSON** (not just the "export" formats the PRD's acceptance criterion names — raw JSON gets handed to dashboards/CI just as often), `--include-author-email` unlocks it uniformly. Untrusted-metadata sanitization (FR-PROV-026 — author name, commit message) reuses whatever HTML-escaping `report/index.js` already applies to finding descriptions, plus a terminal control-sequence strip for the CLI block.

SARIF specifically: result-level `properties` gets `...(f.provenance ? {provenance: redacted} : {})`, following the exact spread convention already used for the proof/confidence blocks there; run-level `invocations[0].properties` gets a scan-wide summary (history coverage, analysis mode) alongside the existing `rulesetVersion` fields.

### 7.2 CLI detail view

`/agentic-security:triage --explain <id> --provenance` renders the PRD's UX-section block (Introduced/Branch entry/First observed/Age basis/Evidence/Boundary proof/Method/Confidence/History) via a new `renderProvenanceDetail(finding)`. Stays out of the default findings-list view — full detail only on `--explain`/detail requests, to avoid clutter.

### 7.3 Compliance `controlRefs` (FR-PROV-016)

The gap row shape in `privacy-framework.js`/`auditor-walkthrough.js` gains `controlRefs: [findingId, ...]` plus a *derived* provenance summary (not a copy of any one finding's object): `{derivedFrom: [findingId...], earliestOrigin: {commit, authorDate, authorName}, confidence, limitations}`. "Earliest proven origin among contributing open findings": among currently-open contributors, prefer `status:"complete"` entries and take the minimum `authorDate`; if none are complete, fall back through the same status hierarchy `ageBasis` uses. Compliance evaluation already runs against findings that carry `provenance` by the time the evaluator sees them, so this needs no new pipeline ordering — only reading the field. This is a genuine capability addition (compliance mapping is scan-level today, per `pipeline/finding-schema.js:55`'s existing comment), not a bolt-on.

### 7.4 Fix records

`fix-history.js` entries gain `provenanceAtFix: {commit, authorDate, ageBasis, ageDays}`, snapshotted at `applyFix()` time. Additive only — no change to the existing two-phase-commit log structure.

### 7.5 CLI flags

`--provenance standard|deep`, `--no-provenance`, `--require-provenance`, `--provenance-since <ref>`, `--provenance-timeout <duration>`, `--include-author-email`, wired into `bin/agentic-security.js`.

Honesty constraint: **`--provenance deep` is accepted but this release implements standard-mode semantics only.** It prints a clear "deep mode ships in a later release, running standard" notice rather than silently behaving as if FR-PROV-010's non-linear DAG handling exists. `--require-provenance` hooks into the existing `scanHealth` partial-health signal — downgrades scan health, never severity-based exit codes, per FR-PROV-020.

---

## 8. Safety, privacy, and performance

### 8.1 Read-only Git access, no worktrees

All `git-evidence.js` operations are plumbing that never touches the working tree: `log`/`log -L`, `show <ref>:<path>` (retrieves historical blob content directly — no checkout), `blame --porcelain`, `ls-tree`, `rev-parse`. This covers every P0 need, so isolated temp-snapshot worktrees are skipped entirely (simpler, and inherently satisfies FR-PROV-024 — there's no checkout step to get wrong). All args pass as separate `execFileSync` argv elements, never shell-interpolated, matching `git-history.js`'s existing pattern. Path confinement: reject any path escaping the repo root after symlink resolution, reject `..`-traversal and malformed refs before they reach argv, treat submodule boundaries as a hard stop (`status:"not_available"` + limitation, not cross-repo resolution).

### 8.2 Secret safety (FR-PROV-025)

For secret-family findings, `predicate-replay.js` and `evidence-attribution.js` never persist historical blob content, matched substrings, or diff snippets anywhere — not in the provenance object, not in the cache, not in error messages (replay calls for secret-family findings are wrapped with output scrubbing so an exception can't stringify raw blob content into a log line). Canary test (PRD Scenario J): a known secret value seeded into fixture history must be absent from every output artifact and diagnostic log, byte-for-byte.

### 8.3 Zero network/LLM calls, by construction

Nothing in the provenance path calls out to an LLM or remote service — FR-PROV-022 provider enrichment is P1 and not built here, so there's no network client to gate in the first place. Tested via an integration test that runs standard-mode provenance with network access blocked and confirms zero output difference.

### 8.4 Bounded execution

`coordinator.js`: global deadline defaults to 60s (`--provenance-timeout` overrides), per-finding sub-budget = `max(2s, global/estimatedFindingCount)`, concurrency capped by a fixed semaphore (default 4 concurrent git subprocesses — new, simple counter; no existing pool to reuse). Deadline checked between candidate evaluations, not mid-subprocess — a hung `git show` is reaped by its own subprocess timeout (reusing `git-history.js`'s existing 1.5s-per-call convention).

### 8.5 Performance SLO and benchmark

New `bench/provenance/` corpus (small/medium/large synthetic histories) with `npm run bench:provenance:check`, mirroring `bench:layer-recall:check`'s structure — publishes cold/warm wall-clock and peak-memory, fails CI if standard-mode overhead exceeds 30% p95 wall-clock / 20% p95 peak-memory versus the same scan without provenance (FR-PROV-029).

### 8.6 Determinism

Repeated scans at identical HEAD/ruleset/mode/boundary must produce byte-identical provenance after excluding inherently scan-time-variant fields (`firstObserved.observedAt`, `firstObserved.scanId`) — the same carve-out FR-PROV-002's acceptance criterion already applies to repository-level provenance, applied consistently to finding-level provenance too.

---

## 9. Test plan

New `scanner/test/helpers/build-git-fixture.js` — programmatically constructs throwaway git repos with controlled commit history/dates/authors (nothing like this exists in the repo today). Backs fixture-based integration tests under `scanner/test/fixtures/provenance/<scenario>/` for each PRD acceptance scenario in scope:

- **A. Direct introduction** — commit adds vulnerable construct, safe parent → high confidence, parent-absence proven.
- **B. Guard removal** — source/sink old, later commit removes sanitizer → origin is the removal commit (FR-PROV-006's defining test).
- **C. Rename** — file renamed after introduction → origin follows lineage, or reports ambiguity with a reason code.
- **D. Merge** — feature-branch origin + main-branch merge entry both shown (first-parent only, per scope decision #2).
- **E. Reintroduction** — fix then recreate → lifecycle has introduce/remediate/reintroduce, age uses latest open introduction. This is the scenario that rules out bisection (§4.3).
- **F. Shallow clone** — finding present at oldest available commit → `earliest observable`, `partial`, low confidence, shallow boundary identified.
- **G. Uncommitted change** — working-tree-only finding → `uncommitted`, author unknown, no email.
- **H. Compliance derivation** — gap links to finding, inherits proven introduction (§7.3).
- **J. Secret safety** — canary secret absent from all output/cache/log artifacts (§8.2).
- **K. Provenance failure** — Git history resolution errors → finding still emitted, `status:"error"`, strict policy alone determines scan-health impact.
- **L. Determinism** — repeated scans, identical provenance + digest (§8.6).

(Scenario I, missing-control regression, is FR-PROV-017 — P1, excluded here.)

Additional layers per the PRD's Quality section: unit tests (fingerprints, Git parsing, graph traversal, confidence rules, redaction, schema validation, digests), fault injection (corrupt objects, missing parents, invalid UTF-8, timeouts, cancellation, cache corruption, unavailable Git), golden-output tests per format, security tests (path traversal, symlink escape, terminal injection, HTML injection, secret leakage, malicious author names, hostile commit messages, hostile filenames), and the determinism/performance benchmark from §8.5–8.6.

---

## 10. Open items deliberately deferred (not ambiguity — explicit non-scope)

These are named so the implementation plan doesn't accidentally scope-creep into them:

- FR-PROV-010 (non-linear DAG: merges/reverts/cherry-picks as distinct lifecycle events beyond first-parent), FR-PROV-015 (transitive SCA origin), FR-PROV-017 (missing-control regression), FR-PROV-022 (provider PR/CODEOWNERS enrichment) — all P1.
- FR-PROV-023 (signed evidence attestations), cross-repository lineage, signed AI-generation metadata, fleet analytics — all P2.
- `--provenance deep`'s true non-linear-DAG behavior — flag exists now (forward-compatible), behavior does not.

## 11. Definition of done for this design's scope

All in-scope FRs (§1) have passing automated tests. `provenance` is a required, enforced field on every emitted finding (`validate.js` + `coordinator.js` guarantee). All acceptance scenarios in §9 pass. No historical analysis mutates the repository, runs repository code, or leaks a canary secret. Standard-mode performance/memory SLOs pass on `bench/provenance/`. Compliance gap rows carry `controlRefs` and inherited provenance. Documentation (this file, plus user-facing docs written during implementation) explains semantics, limitations, privacy defaults, and commands. Independent review confirms "first introduced" is never emitted from line blame alone (FR-PROV-006's cross-cutting acceptance bar).
