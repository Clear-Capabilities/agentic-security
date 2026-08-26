# Assurance Hardening PRD — Final Report

**Date:** 2026-08-25
**Session end state:** cycle 64 of a maximum 100
**Repository:** `/Users/ross/code/agentic-security`, branch `main`, HEAD unchanged at `f57f496` throughout

## Headline result

**65 of 73 FR-* requirements verified.** 8 of 10 epics are fully, genuinely closed. The only work remaining is two large, well-understood items — each with a concrete, evidence-based decomposition plan already on record — deliberately not rushed within this session's bounded loop.

| Epic | Status |
|---|---|
| E1 — Deterministic finding contract | ✅ 8/8 closed |
| E2 — SAST engine restructuring | ⏳ 1/8 (FR-206 only; FR-201–205/207/208 deferred as a unit, D-0008/D-0028) |
| E3 — Reachability and exploitability | ✅ 8/8 closed |
| E4 — Privacy by design and data governance | ⏳ 7/8 (FR-403 open, 2 of its own 4 implementation steps done, D-0041/D-0042) |
| E5 — Compliance evidence and GRC integration | ✅ 8/8 closed |
| E6 — Model/data egress controls | ✅ 7/7 closed |
| E7 — State, retention, and deletion governance | ✅ 7/7 closed |
| E8 — Risk communication and dollar estimates | ✅ 6/6 closed |
| E9 — Independent effectiveness and release quality | ✅ 7/7 closed |
| E10 — Enterprise policy and fleet operation | ✅ 6/6 closed |

## What remains, and why it was not attempted

**E2 (7 FRs: FR-201, 202, 203, 204, 205, 207, 208).** Deferred as a unit across this entire session (D-0008, reaffirmed with concrete file:line evidence in D-0028). `engine.js`'s per-file detector loop has an estimated 150–200 individual call sites in one dense, minified function protected by one broad try/catch — restructuring it safely requires a small isolation helper built first, then migrating call sites in small, gate-verified batches, never one mechanical pass. This is comparable in scope and risk to a significant refactor of the engine's core loop and was never attempted without that deliberate multi-cycle plan in hand.

**FR-403 (E4's last item, P0 — the highest-priority item remaining in the entire PRD).** "Track flows through sanitization, masking, hashing, encryption, serialization, storage, logs, responses, analytics, email, files, object storage, queues, and outbound APIs | Integration tests cover direct, aliased, interprocedural, and cross-file flows plus safe transformations."

A fresh, evidence-based survey (D-0039) found this is genuinely large — not another case of "mostly built, just needs evidence," which described roughly 60% of this session's other closed items. `privacy-taint.js` does its own shallow, per-file, name/regex-based matching and shares no machinery with the general k=1 taint engine, which already has real interprocedural/cross-file tracking (a catalog-driven source/sink/sanitizer model, `SummaryCache`, `callGraph.resolve()`) proven on SQL injection, XSS, command injection, XXE, and others.

A concrete 4-step decomposition (D-0041), grounded by reading the actual `catalog.js`/`summaries.js`/`ir/callgraph.js`/`sanitizer-gate.js` code rather than architectural summary, found the underlying machinery is already family-agnostic — proven by how XXE was added to 5 languages as pure catalog-entry additions with zero engine changes. **Steps 1 and 2 of that plan are done, tested, and gate-verified this session:**

1. ✅ **A `privacy-leak` (CWE-359) sink catalog** (`dataflow/privacy-catalog.js`) covering all 9 sink categories FR-403 names.
2. ✅ **A declaration-based source matcher** (`matchPrivacyDeclSource(s)`, same file) so a PII/PHI/PCI-classified variable name becomes a taint source, reusing the existing, already-tested `privacy-taxonomy.js` classifier.
3. ⏳ **Wire both into the real CFG walk** as an opt-in second lattice, bench-compared against the current shallow pass before ever becoming default. **This is where genuine regression risk begins.**
4. ⏳ **Cut the default scan path over** — a one-way door, landed last, only after step 3 is independently proven.

A real, non-obvious correction was found and fixed *during* step 1's implementation, not anticipated by the original plan (D-0042): naively merging the new sink catalog into the general engine's shared `CATALOG` — which the XXE precedent seemed to justify — would have made every already-active general security source (`req.body`, `req.query`, etc.) immediately trigger spurious "privacy leak" findings at ordinary `console.log`/`fetch`/`sendMail` calls, because the general engine's taint state is a shared boolean with no per-family filtering. The fix (keeping the new catalog in a genuinely isolated, currently-unconsumed file) was verified inert via zero corpus drift, zero self-scan drift, and a fully clean test suite — proving today's scan behavior is provably unchanged.

Step 3 was explicitly not started this session: it is materially different in kind from steps 1–2 (a live wiring into the default-adjacent code path, needing a genuine before/after recall comparison, not just "tests still pass") and deserves its own dedicated, unhurried cycle.

## What this session actually built (by epic, roughly chronological)

- **E5 (compliance evidence):** evidence binding to repository/commit/scope/engine/ruleset/analyzer-health/mapping-version with a tamper-evident digest (FR-504); evidence freshness/owner/reviewer/exception/expiry with `stale`/`gap` statuses (FR-506); Ed25519 signing of the full evidence document, not just the digest (FR-505); a `file-contains` primitive so compliance controls can demand real evidence, not just file existence (FR-503); a stable export API with schema version and documented status semantics (FR-508).
- **E10 (fleet):** signed, portable policy bundles with org/repo/environment inheritance (FR-1001); repository inventory, policy drift, and assurance-health rolled into fleet output (FR-1006).
- **E9 (independent evaluation):** published false-positive adjudication methodology across the full 920-entry false-negative population (FR-905); longitudinal production feedback measurement aggregating 5 previously-separate mechanisms — user suppression, accepted risk, invalid finding, fixed finding, verification outcome (FR-907).
- **E7 (state governance):** default/maximum TTL enforcement by artifact class with an operator-override ceiling (FR-702); manifest-based export and deletion reporting, including a new `export` CLI command (FR-706); identity-bound, reasoned, time-bounded legal holds enforced at both the retention-policy and reset-command layers (FR-707); confidential-state encryption with a real fail-closed gate and a local AES-256-GCM provider (FR-705).
- **E8 (risk communication):** a genuine 5-input gate before any "likely organizational loss" framing is permitted (FR-802); ranges, assumptions, model version, and confidence on every dollar estimate (FR-803); conservative/base/severe scenario comparison built on the same computation as the range, not a second model (FR-805); opt-in, privacy-preserving calibration validation against real accepted-risk and realized-incident outcomes (FR-806).
- **E4 (privacy, partial):** two of four steps toward real interprocedural/cross-file privacy taint tracking (FR-403), described above.

## Verification discipline maintained throughout

Every one of the above was closed only after: real tests (unit + integration, several hundred added across this session), the full `npm test` gate (grew from roughly 4500 to 4627 tests over the session, run to completion with a captured real exit code — never assumed), the CVE-replay corpus gate (215/215, zero drift, every time), the self-scan precision gate (each drift individually reviewed against the actual finding, not rubber-stamped — including one genuine bug found and fixed via this discipline, a real TOCTOU in the FR-806 cycle), a clean build with every new dist chunk explicitly staged (never committed), and a smoke test. All 4 state files (`assurance-hardening-state.json`, `-status.md`, `-decisions.md`, `-handoff.md`) were checkpointed after every cycle.

**One real process error was caught and corrected mid-session, transparently:** cycles 57–59 incorrectly narrated "Epic E7 is fully closed" while FR-705 was still pending — the per-FR ledger in `state.json` was never wrong, only the prose summary layered on top of it. Caught in cycle 60 by cross-checking every epic-closure claim directly against `state.json`'s per-FR statuses, corrected in the live handoff document, and recorded as a lesson (re-verify epic-closure claims this way going forward) rather than silently fixed.

**42 decision records** (`assurance-hardening-decisions.md`) document every material architectural choice made along the way, each with its own investigation, decision, consequence, and reversibility assessment — including several genuine mid-implementation corrections (D-0031, D-0032, D-0042) where the original plan turned out to be subtly wrong and was fixed before landing, not after.

## Current repository state (verify before trusting any of the above)

```
git log -1 --oneline   → f57f496 (unchanged session-start HEAD, no new commit)
git status --short . | grep '^ D'   → (empty — zero unexpected tracked deletions)
git diff --cached --name-only   → exactly 6 dist chunks, staged (not committed) per D-0027:
    scanner/dist/1.index.js
    scanner/dist/144.index.js
    scanner/dist/552.index.js
    scanner/dist/730.index.js
    scanner/dist/736.index.js
    scanner/dist/920.index.js
ps aux | grep -i "node.*agentic-security|npm run|node --test"   → (empty — no running processes)
```

**Nothing has been committed or pushed at any point in this session.** The working tree is a clean, fully reviewable diff, ready to be committed by whoever reviews it, with the single deliberate exception of the 6 staged (not committed) dist chunks the build produced and `test/dist-chunks-tracked.test.js` requires to be tracked.

## Recommended next steps

1. **Review and commit** the current diff (65 verified requirements' worth of real, tested, gated code) — nothing has been committed this session by design.
2. **FR-403 step 3**, when picked up: build the before/after recall comparison harness first, then wire `dataflow/privacy-catalog.js`'s two matchers into `dataflow/engine.js`'s CFG walk as a flag-gated, genuinely isolated second lattice (D-0042). Do not skip to step 4.
3. **E2**, when picked up: follow D-0028's decomposition exactly — a small isolation helper first, then migrate detector call sites in small, gate-verified batches.
4. Continue the established verification discipline for both: real tests, the full 5-step gate (`npm test` → corpus → self-scan → build → smoke), and a state-file checkpoint after every unit of real progress.
