# Design — Finding Provenance M2 (P0 completion), M3 (P1), M4 (P2)

**Status:** Approved (design phase). Implementation not yet started.
**Date:** 2026-08-27
**Source:** `Agentic-Security-Finding-Provenance-PRD.docx`, and the gap audit performed against the shipped M0+M1 work (session of 2026-08-26/27).
**Author:** Ross Young / Clear Capabilities Inc. (design captured by Claude, session-driven)
**Prior spec:** `docs/superpowers/specs/2026-08-26-finding-provenance-design.md` (M0+M1, shipped — `origin.main` at `94bf4a2` as of this writing).
**Scope:** `scanner/src/` (compliance evaluators, `report/index.js`'s remaining format renderers, `posture/mttr.js`, `posture/fix-history.js`, new `posture/provenance/{missing-control-resolver,transitive-sca,dag-walk,providers/*}.js`, `posture/evidence-bundle.js` extension, `posture/fleet.js` extension) plus new fixtures/benchmarks under `scanner/test/` and `bench/provenance/`.
**Audience:** Engineering (scanner core).

---

## 1. Why this exists

The M0+M1 spec and plan explicitly scoped out everything covered here, naming it "Plan B" and, separately, P1/P2. This document is that follow-through, plus one correction the gap audit surfaced: **two requirements tagged P0 in the PRD (FR-PROV-016 compliance derivation, FR-PROV-019 age/SLA basis) were never built**, despite the M0+M1 spec listing them as in-scope for the overall P0 design. They were silently dropped when M0+M1's plan decomposed into "Plan A" without carrying them forward. This document does not repeat that mistake — every item below is enumerated against the PRD text, not against what was convenient to build next.

**Confirmed gaps, verified against the current codebase, not assumed:**
- `controlRefs` does not exist anywhere (`grep -rn controlRefs src/` → one comment noting its absence).
- `mttr.js` has zero references to `findingProvenance`/`ageBasis` — age is still pure wall-clock.
- `toSARIF`/`toCSV` carry zero `findingProvenance` references (column-explicit renderers, confirmed empty). `toHTML` gets the field *incidentally* (it embeds the whole normalized finding array as a JSON blob) but renders nothing from it.
- `fix-history.js` has zero `findingProvenance`/`provenanceAtFix` references — the fix-record surface named in the original spec's §7.4 was never built.
- Measured overhead against `--provenance-timeout`-unbounded standard mode: **88%–1000%+**, against a 30% p95 target (FR-PROV-029). This is not "unmeasured" — it is measured and known to fail.
- `scan.secrets` and `scan.logicVulns` are unconditionally stamped `not_available` in `engine.js` — no real origin resolution ever runs for these two channels. (This is a documented M0+M1 scope decision, not a new finding, but it bears on M2/M3 design below since some M3 work would need `stableId` support on these channels first — see §2.6.)
- No dedicated rename fixture (PRD Scenario C) exists anywhere in the test suite.
- `bench/provenance/` does not exist.

---

## 2. M2 — completing P0

### 2.1 FR-PROV-016, compliance derivation

**Only `privacy-framework.js` emits per-control findings today** (`family: privacy-compliance`, `CWE-359`). Every other framework (`auditor-walkthrough.js`: NIST CSF 2, NIST AI 600-1, OWASP ASVS 5, OWASP LLM Top 10, GDPR, CCPA, HIPAA Security Rule) produces aggregate report *rows* per control (`present`/`absent`/`manual`/`partial`), not individual findings. This asymmetry drives the design:

- **`privacy-framework.js`**: extend the existing gap-finding object with `controlRefs: [findingId, ...]` (the specific findings whose `family`/rule matched this control's `mapsTo`) and a derived summary:
  ```js
  derivedProvenance: {
    derivedFrom: [findingId, ...],
    earliestOrigin: { commit, authorDate, authorName } | null,
    confidence: 'high'|'medium'|'low'|'unknown',
    limitations: [...],
  }
  ```
  "Earliest proven open condition" (PRD wording): among the `controlRefs` findings that are still open, prefer `findingProvenance.status === 'complete'` entries and take the minimum `authorDate`; if none are complete, fall back through the same status hierarchy `ageBasis` uses (§2.3). If zero contributing findings have resolved provenance, `earliestOrigin: null`, `confidence: 'unknown'`.

- **`auditor-walkthrough.js`** (the shared evaluator behind six frameworks): its `bucketOf()` function already resolves each control against the finding population via `mapsTo` — extend it to *also* collect the matching finding ids for `gap`-bucket controls (not `present`/`manual`/`satisfied`, which have no "gap" to attribute), and attach the same `controlRefs`/`derivedProvenance` shape to the report *row*, not to `scan.findings` — this evaluator does not emit findings and this design does not change that. This satisfies FR-PROV-016 across every framework using this evaluator without restructuring how any of them work.

- **Acceptance (Scenario H):** a privacy-compliance gap finding derived from an unmasked-email-in-logs finding must show `controlRefs` containing that finding's id, and `derivedProvenance.earliestOrigin` matching that finding's `findingProvenance.findingOrigin` when the underlying finding resolved `complete`.

### 2.2 FR-PROV-018, full output-format parity

| Format | Current state | M2 work |
|---|---|---|
| JSON, CLI, MCP tool | ✅ done (M0+M1) | none |
| SARIF | not touched | thread `findingProvenance` (redacted) into per-result `properties`, matching the exact spread convention already used for confidence/proof blocks there; run-level summary (history coverage, mode) into `invocations[0].properties` |
| CSV | not touched | flat columns: `provenanceStatus`, `provenanceCommit`, `provenanceAuthorDate`, `provenanceConfidence` — a nested object has no natural CSV representation, so this is a deliberate flattening, not full fidelity |
| HTML | gets the data by accident (embedded JSON blob), renders nothing | add an actual provenance panel per finding in the rendered page, reusing `explainProvenance`'s content (not a second, divergent renderer) |
| Markdown | not touched | a text block per finding, same content/format as the CLI block |
| Compliance reports | not touched | `controlRefs`/`derivedProvenance` from §2.1 render in whatever format the compliance report already uses (markdown/JSON — check `auditor-walkthrough.js`'s existing render path before adding a new one) |
| Baseline files (`last-scan.json`) | ✅ done — this *is* `toJSON`'s output | none |
| Fix records | not touched | `fix-history.js`'s `applyFix()` gains a `provenanceAtFix: {commit, authorDate, ageBasis, ageDays}` snapshot at fix time, as the original spec's §7.4 described and M0+M1 never built |
| JUnit, STIX, VEX | not touched | **out of scope, deliberately** — these are externally-constrained exchange formats (JUnit is a test-result schema, STIX/VEX are threat-intel schemas) with no natural provenance extension point matching what this feature produces. Documented as a scope line, not silently dropped. |

**Acceptance:** golden-file tests across JSON/CLI/SARIF/CSV/HTML/Markdown prove semantic parity — the same finding's `findingProvenance.status`/`findingOrigin.commit` (where applicable to that format's fidelity) appears consistently, not silently different or absent, per FR-PROV-018's own acceptance criterion.

### 2.3 FR-PROV-019, age/SLA basis

Wire `mttr.js` exactly as the original spec's §5.2 described (never built): read `finding.findingProvenance`, pick `ageBasis`:
- `finding_origin` — status `complete`, age = now − `findingOrigin.authorDate`.
- `earliest_observable` — status `partial`, same computation, flagged.
- `first_observed` — status `not_available`/`error`/`budget_exhausted`, age = now − `firstObserved.observedAt` (today's existing wall-clock behavior).
- `uncommitted` — age = now − `firstObserved.observedAt`, tagged distinctly.

Runs where `mttr.js` already runs (post-`toJSON(scan)` in `bin/agentic-security.js`) — `findingProvenance` is already attached by that point, no ordering change needed. `ageBasis` and both the proven and wall-clock ages are exposed on the finding so a report can show both and explain the discrepancy, not silently swap one number for another.

### 2.4 Performance — the real blocker for FR-PROV-029

Building `bench/provenance/` + a CI gate against an 88%–1000% baseline would ship a benchmark that's red on day one, or worse, a benchmark quietly calibrated to a bad number. **Fix the cost first, then gate it.**

Diagnosed root causes (from the final M0+M1 review's own measurements):
1. `predicate-replay.js` re-runs `runFullScan` per candidate commit with no batching or short-circuiting — for a finding with N candidate commits, that's N full (if small) re-scans.
2. The LSP path runs fully uncached (`withStateWritesDisabled` also disables the provenance cache) — every keystroke-triggered save pays the full cost with zero memoization.
3. No early-exit: `origin-resolver.js` walks the full candidate list even after finding a `complete` result in some paths (verify and fix if confirmed).

Fixes, in order of expected impact:
- **Cache within a single scan, not just across scans.** Two findings with the same `stableId` and history boundary currently each pay their own candidate walk — a per-scan in-memory memo (keyed the same as the disk cache) avoids redundant work without touching the disk-cache design.
- **LSP-specific:** allow the provenance cache specifically (not the rest of state-writes) on the LSP path — the earlier review already named this as the fix (`withStateWritesDisabled` disabling *more* than it needs to for this one subsystem). This needs a narrower on/off switch than the blanket `stateWritesEnabled()` flag currently provides — add a second, provenance-cache-specific override that `lsp/server.js` can enable independently of the broader state-write guard.
- **Batch `predicate-replay.js`'s historical scans** where candidates are adjacent commits touching the same small file set — investigate whether a single multi-ref scan can answer multiple candidates' predicates in one `runFullScan` pass (this needs a spike before committing to the approach — see the plan's task breakdown).

**Then**, build `bench/provenance/`: a corpus of small/medium/large synthetic git histories (`build-git-fixture.js` already exists and is reusable), a `bench:provenance:check` script mirroring `bench:layer-recall:check`'s structure, publishing cold/warm wall-clock and peak-memory, gating on **the number actually measured after the fixes above**, not a pre-committed 30% figure that may still be wrong.

### 2.5 Strict policy / scan health

Extend `--require-provenance`'s existing scanHealth integration (built in the M0+M1 final-review fix wave) into a real `strict` assurance-mode tier: `pipeline/assurance-mode.js`'s `evaluateAssuranceMode()` gains a check that a `strict`-mode scan with any finding outside `['complete', 'uncommitted']` fails the gate — matching how it already fails on a stale KEV catalog or an annotator error. This makes "strict cares about overall scan completeness" (the module's own documented philosophy) actually include provenance completeness, not just detector/analyzer completeness.

### 2.6 Prerequisite note: secrets/logicVulns still won't get real resolution in M2

M0+M1 deliberately deferred real origin resolution for `scan.secrets`/`scan.logicVulns` (no `stableId` support on those channels). M2's `ageBasis`/`controlRefs` work reads whatever `findingProvenance.status` a finding already has — for these two channels that's still always `not_available`, so their compliance/SLA output will honestly show `first_observed`/`unknown` rather than a fabricated better answer. Wiring real `stableId` + resolution for these channels is **not** in M2's scope; flagging it here so the M2 implementer doesn't accidentally expand scope to "fix" something that's working as designed.

---

## 3. M3 — P1

### 3.1 FR-PROV-010, deep DAG analysis (makes `--provenance deep` real)

Currently `--provenance deep` is accepted but silently behaves as `standard` (an honest stub, per the M0+M1 CLI task). This builds the real thing:

- **Non-first-parent walk.** `origin-resolver.js`'s candidate walk currently only follows first-parent ancestry (scope decision from M0+M1). Deep mode explores every parent of a merge commit — a vulnerability entering via a merged feature branch, not mainline, needs this to resolve correctly. Implementation: extend `git-evidence.js` with a `getAllParents(scanRoot, sha)` (already has `getParents` per the original design's §4.3 — confirm it's still there and used) and have `origin-resolver.js`'s deep-mode path recurse into non-first parents when the first-parent walk doesn't resolve.
- **Revert detection.** A commit whose diff is the exact inverse of an earlier commit — detected via the conventional `Revert "..."` message prefix (git's own convention when using `git revert`) cross-checked against actual diff inversion (message alone is spoofable/unreliable) — is a distinct lifecycle event type, not a coincidental reintroduction pattern. Extends `lifecycle.js`'s event vocabulary.
- **Cherry-pick detection.** `git cherry-pick -x` leaves a `(cherry picked from commit <sha>)` trailer in the new commit's message. When present, link the cherry-picked commit's lifecycle event back to the original — a cherry-pick is not a fresh introduction, it's propagation of an existing one across branches.
- New module: `posture/provenance/dag-walk.js`, consumed by `origin-resolver.js` only when `mode === 'deep'`.

### 3.2 FR-PROV-015, transitive dependency origin

Parses the lockfile's actual dependency tree (not just the manifest) to find which direct dependency's version bump pulled a vulnerable transitive version into the graph, then walks `git log -p` on the lockfile. New module `posture/provenance/transitive-sca.js`, following `sca-origin.js`'s established pattern (own version comparator already exists there, reused not reimplemented). This directly narrows the `engine.js` backstop that currently defers every transitive `vulnerable_dep` — after this ships, only genuinely unresolvable transitives (no lockfile, or a lockfile format not yet parsed) fall through to `not_available`.

### 3.3 FR-PROV-017, missing-control regression

Architecturally inverted from every resolver built so far: "when did a previously-observed safeguard disappear," not "when did a bad pattern appear." New module `posture/provenance/missing-control-resolver.js`:
- Only claims an origin when history proves BOTH a prior commit where the control was present AND a later commit where it's absent — walking backward from HEAD.
- If the control is absent at every reachable commit (including the repository's own root), status is `unknown` — **never** attributed to the root commit, per FR-PROV-017's explicit acceptance criterion. This is the one resolver in the whole feature where "no evidence of removal" must NOT collapse to "introduced at the beginning" the way a present-condition finding would.
- Detector-agnostic: takes a caller-supplied predicate function (matching predicate-replay.js's existing "replay the detector, compare stableId" pattern) rather than hardcoding what "a control" looks like per finding type.

### 3.4 FR-PROV-022, provider enrichment

`posture/provenance/providers/{github,gitlab}.js` — each implements a common interface (`fetchPRMetadata(commitSha, config)`, `fetchCodeowners(config)`) reading PR number, reviewers, approvals, CODEOWNERS from the configured host's API, using whatever HTTP client convention the OSV-fetch path already establishes. Strictly opt-in: no provider is consulted unless a config block (`.agentic-security/provenance-providers.yml` or an env var naming the provider + token) is explicitly present. Offline-mode test: `origin-resolver`/`coordinator` output must be byte-identical with and without provider config present, when no config is given — proving zero incidental network calls, matching the exact test shape already used for the OSV-hermeticity fix in M0+M1.

### 3.5 Rename fixture (FR-PROV-007 completion) and Scenario I

- New test in `provenance-origin-resolver.test.js` (or a new file): a fixture where the vulnerable file is renamed after introduction (via `git mv`-equivalent: write new path, remove old, commit), proving `origin-resolver` (via `git-evidence.js`'s `candidateCommitsForFile`'s `--follow`) either correctly follows the pre-rename lineage or reports an explicit ambiguity reason code — never silently loses the origin.
- Scenario I test for §3.3's missing-control resolver: a required policy file absent from all visible history resolves `unknown`/`first_observed`, never falsely attributed to the repository's first commit.

---

## 4. M4 — P2

### 4.1 FR-PROV-023, signed evidence

Reuses `posture/evidence-bundle.js`'s existing Ed25519 infrastructure (already shipped for finding-level bundles — `crypto.generateKeyPairSync('ed25519')`, keys at the existing key directory) rather than a new crypto mechanism. The `evidenceDigest` field (unsigned stub, present since M0+M1's `coordinator.js`) becomes signable: extend `evidence-bundle.js` (or add a small sibling, `provenance-evidence-bundle.js`, if the existing module's shape doesn't generalize cleanly — decide during implementation, not here) so `agentic-security attest --provenance <finding-id>` produces a signed bundle over the same allowlisted fields `evidenceDigest` already binds (stable finding id, repo identity, HEAD, origin/branch-entry commits, evidence-node locations, method, confidence reasons, limitations). `verify-attestation` already auto-detects bundle shape — extend its detection to recognize this bundle type too, reusing the existing dispatch rather than adding a parallel CLI verb.

### 4.2 Cross-repository lineage

Git has no native cross-repo history. Operator-declared linkage: `.agentic-security/repo-lineage.json` — `{ "linkedFrom": { "path": "../old-repo-clone", "atCommit": "<sha-in-this-repo-where-history-was-imported>" } }`. When `origin-resolver`'s candidate walk reaches this repo's root commit without resolving, and a lineage config is present and the linked path is a real, locally-reachable git repo, continue the walk there. Scoped to **local clones only** — no automatic remote fetch, matching the "no runtime cloud calls" convention. This is inherently best-effort (the operator must know and declare the link); the result carries a `historyCoverage.crossRepoLineage: true` marker so a reader knows the answer crossed a repository boundary.

### 4.3 Signed AI-generation metadata

No concrete external signed-commit-metadata standard exists yet to target. Build an extensible verification hook: `posture/provenance/ai-authorship-verifiers/` — a registry a future verifier plugs into (`registerAIAuthorshipVerifier(name, verifyFn)`), consulted by `coordinator.js` when resolving `findingOrigin`. With nothing registered (today's real state), `aiAuthorship` stays `unknown` on every finding — matching the PRD's own explicit default ("Unknown unless signed, verifiable generation metadata exists"). This is deliberately a hook, not a hardcoded vendor integration, since building against a standard that doesn't exist yet would be guessing.

### 4.4 Fleet analytics

Extends `posture/fleet.js` (already aggregates multiple repos into one offline HTML page, already refuses to silently treat an unscanned repo as clean) with provenance/lifecycle rollups: oldest proven-origin debt across the fleet (sorted by `findingOrigin.authorDate` where `status === 'complete'`, falling back honestly for repos without complete provenance), and time-to-remediation computed from `ageBasis`-aware ages (§2.3) rather than wall-clock, surfaced per-repo and fleet-wide.

---

## 5. Safety, testing, and definition of done

Every module in M2/M3/M4 inherits the M0+M1 invariants verbatim — they are not re-litigated per module, they are the floor every new module must clear:
- Terminal status always present, never left `undefined`.
- Never false certainty (a resolver that can't prove absence reports `partial`/`unknown`, never guesses).
- Read-only Git access only; no new module runs `checkout`/`merge`/hooks.
- No new module persists raw secret/blob content anywhere.
- No new npm dependency without a documented reason (matches this codebase's established no-`simple-git`/no-`ajv` convention).
- Deterministic output for a fixed HEAD (excluding the same volatile-field carve-out already established).
- No runtime network call without an explicit, documented opt-in and offline-degrades-gracefully test (FR-PROV-022's own acceptance criterion, and the pattern this codebase already uses for OSV/KEV/EPSS).

**Definition of done for M2:** compliance gap rows/findings carry `controlRefs`; SARIF/CSV/HTML/Markdown/fix-records carry the field with format-appropriate fidelity, proven by golden-file tests; `mttr.js` reports both proven and wall-clock age with `ageBasis` disclosed; the measured performance overhead is published (not assumed) and a `bench/provenance/` gate exists against that real number; `--assurance strict` genuinely fails on incomplete provenance.

**Definition of done for M3:** `--provenance deep` genuinely explores non-linear ancestry and distinguishes revert/cherry-pick lifecycle events from ordinary reintroduction; a transitive SCA finding gets a real origin when the lockfile data supports it; a missing-control finding never falsely attributes to the repo's first commit; provider enrichment adds zero network calls when unconfigured, proven by a hermetic test; the rename fixture and Scenario I both pass.

**Definition of done for M4:** a provenance evidence bundle can be signed and independently verified; a cross-repo-linked finding's origin resolves through the declared lineage when locally reachable, and is honestly marked when it isn't; the AI-authorship hook exists and defaults to `unknown` with nothing registered; fleet reports show provenance-aware, not wall-clock-only, debt age.
