# Data Flow Explorer — M1 Sub-project D, Increment 2: `source-registry.js`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `scanner/src/lineage/source-registry.js`, reclassifying `scanner/src/dataflow/catalog.js`'s 180 source entries into `DataFlowGraph v1`'s `SOURCE_CATEGORIES`/`NODE_KINDS`/`coverageStatus` vocabulary, per the accepted, independently-reviewed design in `scanner/src/lineage/DESIGN_REGISTRIES.md` §9's D2 checklist (items 1-5). This increment's design phase is already complete (D1, merged) — this is mechanical implementation against a hardened, already-tested design; the mapping tables and coverage-status rule were proven correct in D1's own PoC (`test/lineage/registry-mapping-poc.test.js`) through a full design review + fix round + scoped re-review, each independently re-verifying every claim against the live catalog.

**Architecture:** `source-registry.js` is a pure reclassification layer — it imports `CATALOG` from `../dataflow/catalog.js` and nothing else from `dataflow/` (no matcher, no engine), and exports `reclassifySource(entry)`. It does not run analysis or pattern-matching; it consumes catalog entries as data and maps them onto the DataFlowGraph v1 vocabulary `schema.js` already defines.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_REGISTRIES.md` in full — this is the binding ADR. §9.0 (the `category`→`subtype` field mapping), §9's D2 checklist (items 1-5), §4 (`PROVENANCE_MAP`, 12 rows), §4.1 (`AGENT_TOOL_REFINEMENT`, 8 rows), §4.2 (the `language === 'cpp'` descriptor-generic refinement), §4.3 (`NO_PROVENANCE_OVERRIDES`, 82 rows), §6 (the `coverageStatus` decision procedure, all five values including when `manual` applies — D2 must NEVER emit `manual`, per item 5), §7.1 (node-kind assignment — always `'source'` for D2), §9.1 (who owns the override table and the PoC-deletion protocol — read this carefully, it directly governs this task's own Step 4/5).

## Global Constraints

- `source-registry.js` must import `CATALOG` from `../dataflow/catalog.js` and NOTHING else from `dataflow/`. No `engine.js`, no matcher internals.
- Must NEVER import `dataflow/engine.js` or `dataflow/summaries.js`, matching this whole PRD's established isolation principle.
- Must NOT modify `catalog.js`, `catalog-expanded.js`, or `schema.js` — this task consumes them, never changes them.
- The registry's own field is `category`; a `DataFlowGraph v1` node's field is `subtype` — `source-registry.js` emits `category`, and must NOT emit a field literally named `subtype` (§9.0's own stated guard against a decision object accidentally validating as a node without passing through Sub-project E's future graph builder).
- `coverageStatus` must NEVER be `manual` for this registry (§9's D2 item 5) — if you find yourself reaching for `manual`, that's a sign of a design misunderstanding; stop and re-read §6.
- The completeness guards (provenance key set, override key set, each asserted equal to the LIVE catalog's, both directions) must ship as PERMANENT tests, not PoC-only assertions — D1's own PoC already mutation-proved these fail correctly; port that property, don't weaken it.
- Every existing test suite this task touches or reads from must keep passing — run `npm run test:lineage` AND `npm run test:dataflow` before and after any change (this whole sub-project reads real `dataflow/` catalog data, so both scopes are relevant).
- Follow this repo's root `CLAUDE.md` verification discipline: every claim about coverage (does the registry classify every real catalog entry correctly, does the completeness guard actually fail when it should) must be demonstrated by running real code in this task, not asserted from the design doc's own prose.

## Coordination with D3

D2 and D3 (`sink-registry.js`) are designed to run in PARALLEL, in separate worktrees, each touching disjoint files (D2 never touches `sink-registry.js` or anything sink-related; D3 never touches `source-registry.js`). Both absorb a DISJOINT HALF of `test/lineage/registry-mapping-poc.test.js` (D2: the source tables/guards; D3: the sink/privacy ones) — per §9.1's explicit protocol, **whichever of D2/D3 lands SECOND deletes the PoC file**, after confirming the OTHER increment's absorption is already complete. This task's own Step 4/5 below are written assuming D2 might land either first or second — check the actual state of `test/lineage/registry-mapping-poc.test.js` at execution time (has D3 already landed and removed its own half? has it deleted the file already?) and follow §9.1's protocol exactly, not this plan's own assumption about ordering.

---

### Task 1: Implement `source-registry.js`, port the source-side tables and guards, wire into the permanent suite

**Files:**
- Create: `scanner/src/lineage/source-registry.js`
- Modify or absorb from: `scanner/test/lineage/registry-mapping-poc.test.js` (port the source-side tests into a new permanent file — see Step 3)
- Create: `scanner/test/lineage/source-registry.test.js` (the permanent test file for this module)
- Modify: `scanner/package.json` (wire the new test file into `test:lineage`; remove the PoC's entry ONLY if this task is the second-lander per §9.1's protocol — check D3's state first)
- Modify: `scanner/src/lineage/CLAUDE.md` (new module-table row for `source-registry.js`)
- Read only: `scanner/src/lineage/DESIGN_REGISTRIES.md` in full (the binding spec — read it end to end, not just the D2 checklist, since §4/§4.1/§4.2/§4.3/§6/§7.1/§9.0/§9.1 are all load-bearing for this task), `scanner/test/lineage/registry-mapping-poc.test.js` in full (the source of truth for the exact table contents — port the DATA faithfully, but treat `DESIGN_REGISTRIES.md`'s own prose as authoritative for the DECISION PROCEDURE if the two ever seem to differ), `scanner/src/dataflow/catalog.js` (in full, to understand the real entry shape you're reclassifying), `scanner/src/lineage/schema.js` (the target `SOURCE_CATEGORIES`/`NODE_KINDS` vocabulary).

**Interfaces:**
- Consumes: `CATALOG` (exported from `../dataflow/catalog.js`) — specifically its `kind: 'source'` entries, each `{kind, id, language, framework, match, argIndex, vuln, label, provenance}`-shaped (confirm the exact shape against the live file, don't assume from this plan's own paraphrase).
- Produces: `reclassifySource(entry)`, exported from `scanner/src/lineage/source-registry.js`, returning `{kind: 'source', category, coverageStatus, externality, reason}` (per §9.0's shape — confirm `externality`'s role for a SOURCE specifically, since §7.5's externality table may be sink-focused; check).

- [ ] **Step 1: Read `DESIGN_REGISTRIES.md` in full, then the PoC's source-side content, then `catalog.js`**

Do not start from the PoC's prototype tables as if they were self-explanatory — `DESIGN_REGISTRIES.md`'s prose is the authority on WHY each mapping decision was made, and you'll need that reasoning to write accurate code comments and to correctly handle any real catalog entry the PoC's own examples didn't happen to cover.

- [ ] **Step 2: Implement `source-registry.js`**

Export `reclassifySource(entry)`. Internally:
- Port `PROVENANCE_MAP` (§4, 12 rows: `http-body`, `url-param`, `header`, `network`, `agent-tool`, `cookie`, `path-param`, `env`, `file-read`, `cli`, `url-fragment`, `stdin`) from the PoC, verbatim in content, adjusted only for being real shipped code rather than PoC-local.
- Port `AGENT_TOOL_REFINEMENT` (§4.1, 8 rows).
- Port the `language === 'cpp'` descriptor-generic-I/O refinement (§4.2) — this is the correction D1's own fix round added (demoting `cpp-recv`/`cpp-recvfrom`/`cpp-read`/`cpp-fgets`/`cpp-fread` to `partial` for the `FILE*`/fd-ambiguity reason) — get this right, it's not in the ORIGINAL `PROVENANCE_MAP`, it's a refinement applied on top of it.
- Port `NO_PROVENANCE_OVERRIDES` (§4.3, 82 rows) — this is the single largest piece of content in this task; port it completely and exactly, don't sample or approximate. Per §9.1, THIS is the table's new permanent home — the PoC's own copy becomes redundant once this lands.
- Node kind is always `'source'` (§7.1) — no branching needed here, unlike D3's sink-side node-kind table.
- Implement the `coverageStatus` decision procedure per §6 exactly (modeled/partial/candidate/unsupported — NEVER `manual`, per this task's own Global Constraints).

- [ ] **Step 3: Write `source-registry.test.js`, porting the source-side tests from the PoC**

Port every source-side test from `registry-mapping-poc.test.js` (identify which tests are source-scoped vs sink-scoped — read the PoC file's own structure/section comments to tell them apart cleanly) into this new permanent file, re-pointed at the shipped `reclassifySource`. At minimum, this must include:
- **The completeness guards** (§9's D2 item 4): the provenance key set and the override key set, EACH asserted equal to the live `CATALOG`'s actual distinct-value sets, in BOTH directions (nothing in the registry that isn't in the catalog; nothing in the catalog that isn't covered by the registry). These must be REAL, mutation-tested guards — after writing them, do your own mutation test: temporarily add a hand-built catalog-shaped entry with a provenance value NOT in your `PROVENANCE_MAP`, confirm the guard fails, then remove it and confirm clean. This is the single most important test in this task.
- A representative sample of real reclassifications end-to-end (mirroring D1's own PoC step 3.2).
- The `cpp` refinement's own dedicated test (mirroring D1's own `D1/5e`), proving the 5 demoted entries are `partial` with the right reason, and that non-cpp entries in the same provenance buckets stay `modeled`.
- An honest `unsupported`/`candidate` case, proven against real entries.

- [ ] **Step 4: Resolve the PoC's fate per §9.1's protocol**

Check the current state of `test/lineage/registry-mapping-poc.test.js` and `package.json`. If D3 has ALREADY landed and confirmed its own sink-side absorption is complete (check git log / the file's own remaining content — if only sink-side tests remain, D3 has already absorbed its half), THEN this task is the second-lander: delete the PoC file, remove its `package.json` `test:lineage` entry, and remove it from `src/lineage/CLAUDE.md`'s table, all in this task's own commit. If D3 has NOT yet landed (the PoC still contains both source-side and sink-side content, or D3's own commits aren't in this branch's history), then this task is the FIRST lander: absorb only the source-side content into `source-registry.test.js` as Step 3 describes, but do NOT delete the PoC file or its `package.json` entry — leave it in place for D3 to use, and note in your own commit message that you are the first-lander per §9.1's protocol.

- [ ] **Step 5: `scanner/src/lineage/CLAUDE.md` — new module-table row**

Add a `source-registry.js` row to the appropriate module table, describing the module's role, the mapping tables it carries, the completeness-guard property, and the `coverageStatus` distribution on the real catalog (89 modeled reduced to 84 modeled/14 partial per D1's own cpp refinement, 82 candidate, 0 unsupported — confirm these numbers are still accurate against what you actually shipped, don't just copy them from this plan).

- [ ] **Step 6: Run the full scoped suite and doc-drift check**

```bash
npm run test:lineage
npm run test:dataflow
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/source-registry.js scanner/test/lineage/source-registry.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
# If you are the second-lander per Step 4:
# git rm scanner/test/lineage/registry-mapping-poc.test.js
git commit -m "feat(lineage): implement source-registry.js (Sub-project D, increment D2)"
```
