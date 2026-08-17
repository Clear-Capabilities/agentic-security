# Design — Independent-population re-measurement, root-cause, and language-coverage mining

**Status:** Approved.
**Date:** 2026-08-17
**Author:** Ross Young / Clear Capabilities Inc. (design captured by Claude, session-driven)
**Scope:** `bench/independent/` (measurement + mining harness) and whatever `scanner/src/` fixes the audit turns up as obvious wins.
**Audience:** Engineering (scanner core).

---

## 1. Why this exists

`DETECTION_GAP_REMEDIATION_PRD.md`'s final finding (R16) is the one open thread left from that PRD: six themes of independently-verified, unit-tested fixes landed against the detection pipeline, and the independent, real-world (GHSA-labelled) population's recall did not move — 12.7% (14/110), unchanged byte-for-byte between 2026-08-09 and the 2026-08-15 re-measurement on engine 0.136.10. That PRD explicitly declined to decide what happens next: "candidate next steps, not decided here."

This design operationalizes those candidate steps:
1. root-cause a sample of the 96 false negatives to find out whether the true explanation is "shape doesn't occur in these 110 advisories" or "a real detection was masked downstream";
2. mine or synthesize independent-population entries in Java/C#/Kotlin/PHP/Go/Ruby, all currently at exactly zero entries, so future engine work targeting those languages has any chance of being visible to this instrument at all;
3. follow the milestone-gated re-measurement discipline the prior PRD named but did not follow — re-measure after mining and after any inline fix, not just once at the end.

Per this session's own scoping decisions: root-cause **all 96** FNs (not a sample), mining covers **all six** currently-zero languages with **no entry cap**, and any obvious-win fix found during root-causing is applied inline rather than deferred to a separate PRD.

## 2. Pipeline

```
1. Re-measure baseline (wipe state, fresh bench:independent run)
        │
        ├──▶ 2. why-missed.mjs sanity check (2-3 known entries)
        │           │
        │           ▼
        ├──▶ 3. why-missed.mjs run over all 96 FN entries
        │           │
        │           ▼
        ├──▶ 4. Batch agent dispatch (~8-10 agents, ~10-12 entries each)
        │           │
        │           ▼
        ├──▶ 5. Synthesis pass (cross-batch pattern check)
        │           │
        │           ▼
        ├──▶ 6. Fix obvious wins inline + re-gate + re-measure
        │
        └──▶ 7. Mining track (concurrent with 2-6): 6 languages, no cap
                    │
                    ▼
                8. Materialise + score new entries, merge into manifest

9. Write docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md + update README.md pointer + regenerate RESULT.json
```

Steps 2-6 (root-cause track) and step 7-8 (mining track) are independent and run concurrently — mining doesn't need the FN list, and root-causing doesn't need new languages present.

## 3. Components

### 3.1 Re-measure baseline
Wipe `.agentic-security/` state from every cached `bench/independent/cache/*/pre|post` tree (per `CLAUDE.md`'s "wipe scan state before benchmarking" rule — the same rule that caught the contamination bug documented in `bench/independent/README.md`), then run `npm run bench:independent -- --json` on the current engine version. This locks the exact 96-entry FN list this session audits — it may differ slightly from the 2026-08-15 snapshot if anything shifted an entry's outcome since.

### 3.2 `bench/independent/why-missed.mjs` (new script)
Input: an entry ID, or `--all` to run every current FN.

For each entry, re-scans `pre/` (deep mode) and reports, mechanically, why the labelled CWE didn't produce a match:
- **`no-finding-at-all`** — nothing fired anywhere in the fix commit's changed files, for any CWE family related to the label.
- **`finding-present-but-suppressed:<mechanism>`** — a candidate finding existed before one of: an ignore-pragma match near the sink, `_guardMatchNearSinkIdentifier` guard-window drop, `unreachable:true` reachability demotion, dead-code demotion, or a sanitizer-index kill. Reuses each mechanism's existing internal signal (e.g. `engine.js`'s own drop/demote paths) rather than re-implementing detection logic — the point is to surface what the engine already decided and why, not re-decide it.
- **`finding-present-wrong-file-or-cwe`** — something fired, but not in the advisory's files or not matching the labelled CWE (the harness's own known scoring boundary, restated per-entry rather than only in aggregate).
- **`scan-error`** — the entry couldn't be scanned; reported by name, matches the harness's existing UNSCORED handling philosophy (never silently folded into a miss).

Output: one JSON object per entry, written under `bench/independent/why-missed-output/` (gitignored, same treatment as `cache/`).

This is a diagnostic script, not shipped detector logic. Before trusting it across all 96 entries, sanity-check it against 2-3 entries whose root cause I already know from earlier reading in this session (or determine by hand) and confirm the bucket matches.

### 3.3 Batch agent dispatch
~8-10 `Agent` tool calls (plain Agent tool, not Workflow — no orchestration opt-in given this session), each receiving:
- its slice of ~10-12 FN entries: id, CWE, language, repo, fix-commit URL, pre/post cache paths;
- that slice's `why-missed.mjs` output;
- the root-cause method: two top-level categories per R16's own framing —
  1. **shape doesn't occur / genuine capability gap**, itself split per the Tier-1 vs Tier-4 distinction `TAINT_RECALL_80PCT_PRD.md` §1.1 used: *missing catalog coverage* (source and sink both real, no catalog entry connects them) vs. *deeper engine/IR gap* (the flow shape itself isn't modelled — cross-file, stored, container-element, etc.);
  2. **masked downstream** — confirmed by the entry's `why-missed.mjs` suppression bucket, verified against the actual pre/post diff rather than taken on faith from the mechanical signal alone.
- instruction to read the real fix-commit diff and fixture files before concluding (the mechanical bucket is a starting signal, not the verdict), and to flag any entry whose root cause looks like a small, localized, low-risk fix as an "obvious win" candidate with a concrete proposed change.

Each agent returns structured per-entry verdicts (schema-enforced): `{id, category, subcategory, evidence, fixCandidate: bool, fixDescription?}`.

### 3.4 Synthesis pass
Done directly, not delegated — the one step Approach B's own stated weakness (batches can't see each other's findings) requires a human/orchestrator pass for. Cross-reference all returned verdicts for:
- a single suppression mechanism recurring across many entries (the exact kind of thing a per-batch agent, seeing only 10-12 entries, could easily miss);
- clusters by category/language that suggest a shared root cause rather than 96 independent ones.

### 3.5 Fix obvious wins inline
From the synthesized findings, apply fixes that are small, low-risk, and directly evidenced (per this session's "audit + fix obvious wins inline" scoping). After each fix:
- run the relevant scoped test (`test:dataflow` / `test:sast` / `test:mcp`, whichever the touched code implies);
- run `npm test`;
- run `npm run bench:cve-replay:check` — the regression corpus must not drift; a fix that improves the independent number by breaking the regression net is not a fix;
- re-run `bench:independent` to confirm the fix actually moved the number, not just that it looked correct on inspection. This is the specific discipline R16 documents as having been skipped last time.

Fixes that are not small/low-risk get written up as candidates in the final doc, not attempted here — consistent with "a finding to act on in a future PRD" for anything bigger.

### 3.6 Mining track
Runs concurrently with 3.2-3.5. Per language:

| Language | Ecosystem flag | Notes |
|---|---|---|
| Java | `maven` | GHSA doesn't separate Java/Kotlin at ecosystem level |
| Kotlin | `maven` | disambiguated per-file by `LANG_BY_EXT` extension, same as Java |
| C# | `nuget` | not in `mine.mjs`'s current default ecosystem list — must pass explicitly |
| PHP | `composer` | |
| Go | `go` | already in default list but yielded zero so far — re-run explicitly and confirm why |
| Ruby | `rubygems` | already in default list but yielded zero so far — re-run explicitly and confirm why |

No `--limit` cap — take everything `mine.mjs` finds admissible (CWE + single fix commit + admissible source-file extension) per language. Then `npm run bench:independent:materialise` and `npm run bench:independent` for just the new entries, merged into `manifest.json` alongside the existing 110.

**Named risk:** `mine.mjs` shells out to `gh api`, which returned HTTP 503 earlier this session. If it's still unavailable when this track runs, that's a blocker to report plainly — not a reason to fabricate or hand-author entries, which would reintroduce exactly the self-labelling problem this whole track exists to avoid.

### 3.7 Write-up
`docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md` — per-entry table (id, language, CWE, category, subcategory, evidence, fix status) plus a rollup (category breakdown counts, recall before/after any inline fixes, new per-language entry counts and their own recall from mining). `bench/independent/README.md` gets a short pointer to the new doc rather than the full findings inlined. `RESULT.json` regenerated fresh at the very end, reflecting whatever inline fixes landed and the expanded manifest.

## 4. Testing / gating

- `why-missed.mjs`: sanity-checked against 2-3 known entries before trusting its output at scale; no corpus fixture requirement since it's diagnostic tooling, not a shipped detector.
- Any inline fix: scoped test + `npm test` + `bench:cve-replay:check`, both directions verified (exit code captured), per `CLAUDE.md`'s verification discipline.
- Every number in the final write-up traces to a command run during this session — no remembered or assumed figures.
- Mining: entries only admitted by `mine.mjs`'s existing blind-to-the-engine admission criteria (CWE + single fix commit) — this session does not loosen or special-case that gate to hit a language-coverage target.

## 5. Non-goals

- P3/P4 of `TAINT_ENGINE_IMPROVEMENT_PRD.md` (depth graduation, cross-file/stored taint) — explicitly deferred to a separate design per the earlier scope-decomposition conversation.
- Fixing anything root-causing surfaces that isn't small/low-risk — written up as a candidate, not attempted here.
- ROADMAP.md's R13/R16 Tier 2 items — unrelated track, out of scope.
