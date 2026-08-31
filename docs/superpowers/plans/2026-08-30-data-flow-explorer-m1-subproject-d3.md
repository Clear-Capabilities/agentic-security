# Data Flow Explorer — M1 Sub-project D, Increment 3: `sink-registry.js`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `scanner/src/lineage/sink-registry.js`, reclassifying `scanner/src/dataflow/catalog.js`'s 194 sink entries AND `scanner/src/dataflow/privacy-catalog.js`'s 18 category-tagged entries into `DataFlowGraph v1`'s `SINK_CATEGORIES`/`NODE_KINDS`/`coverageStatus` vocabulary, per the accepted, independently-reviewed design in `scanner/src/lineage/DESIGN_REGISTRIES.md` §9's D3 checklist (items 1-6). This increment is larger than D2 (`source-registry.js`) — more categories (29 vs 21), a second input catalog to reconcile (`privacy-catalog.js`, whose own category vocabulary does NOT exactly match `schema.js`'s), and it closes FR-203 (an unresolved dynamic destination must still produce a node, never silently disappear) — a requirement D2's source side has no equivalent of. This increment's design phase is already complete (D1, merged) — this is mechanical implementation against a hardened, already-tested design; the mapping tables and coverage-status rule were proven correct in D1's own PoC (`test/lineage/registry-mapping-poc.test.js`) through a full design review + fix round + scoped re-review.

**Architecture:** `sink-registry.js` is a pure reclassification layer, exporting TWO functions (not one, unlike D2) because it has two structurally different input catalogs: `reclassifySink(entry)` for `catalog.js`'s `kind: 'sink'` entries (keyed on CWE/`vuln`), and `reclassifyPrivacySink(entry)` for `privacy-catalog.js`'s entries (keyed on `category`) — these are deliberately separate functions, not a unified dispatcher, because `privacy-catalog.js` is deliberately NOT merged into `CATALOG` (merging it would make every already-active general source spuriously trigger privacy-leak findings — an existing, deliberate architectural boundary this task must respect, not "fix").

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_REGISTRIES.md` in full — this is the binding ADR. §9.0 (the `category`→`subtype` field mapping), §9's D3 checklist (items 1-6, the most detailed of any checklist item in this document — item 5 alone, closing FR-203, is as long as D2's entire checklist), §5.1 (`CWE_MAP`, 20 rows), §5.2 (the CWE-79 `framework` refinement), §5.3 (`PRIVACY_CATEGORY_MAP`, 9 rows — note: NINE, not the eight an earlier draft assumed; `thirdPartySdk` needs special handling per item 4), §6 (the `coverageStatus` decision procedure), §7.1 (`CATEGORY_NODE_KIND` — sink-side node kind assignment is NOT uniformly `'sink'`, unlike D2's uniform `'source'`; branches by category), §7.1's biconditional note (the `kind === 'process' iff coverageStatus === 'unsupported'` guard, and its documented fragility once AI-sink detection eventually lands — not this task's problem to fix, but the test must ship as specified), §7.5 (`CATEGORY_EXTERNALITY`), §16.7's carried-forward note (the `kind: 'unresolved'`/`coverageStatus: 'partial'`/`externality: 'unknown'` rule for a DIFFERENT, degraded-analysis case — do not confuse this with FR-203's own `unresolved` case, item 5's own text explicitly warns against conflating them), §9.1 (who owns the override/mapping tables and the PoC-deletion protocol).

## Global Constraints

- `sink-registry.js` must import `CATALOG` from `../dataflow/catalog.js` and the privacy catalog from `../dataflow/privacy-catalog.js`, and NOTHING else from `dataflow/`.
- Must NEVER import `dataflow/engine.js` or `dataflow/summaries.js`.
- Must NOT modify `catalog.js`, `catalog-expanded.js`, `privacy-catalog.js`, or `schema.js`.
- Must NOT merge `privacy-catalog.js`'s entries into a unified dispatch with `CATALOG`'s sink entries — keep `reclassifySink`/`reclassifyPrivacySink` as two separate functions, per this task's own Architecture section and §9's D3 item 1.
- **Never silently drop an `unsupported` entry** (§9's D3 item 3) — the 82 `unsupported`-classified sink entries (or whatever the real current count is — confirm against the live catalog, don't assume D1's own count is still exactly current) must still produce a `kind: 'process'` node with a non-empty `reason`, never be excluded from the registry's output. This is explicitly called out as "the single easiest way to violate AC-11 and FR-201" — treat it as load-bearing, not optional polish.
- **FR-203 must be closed** (§9's D3 item 5) — a recognized sink whose destination cannot be resolved gets `kind: 'unresolved'`, category RETAINED (not nulled), `externality: 'unknown'`, `coverageStatus` UNCHANGED from whatever the category mapping already assigned (do not conflate this with the separate, C6-carried-forward degraded-analysis `unresolved` case, which DOES get `coverageStatus: 'partial'` for an unrelated reason — read item 5's own explicit warning against conflating the two).
- The completeness/count-pin guards (provenance-equivalent key sets for both catalogs, the measured-count pins from §4.3/§5.1/§5.2) must ship as PERMANENT, mutation-tested tests — this repo's own `bench/layer-recall` has already demonstrated that a floor-only gate lets a stale published number survive for weeks; these must be EQUALITY pins, not floors.
- Every existing test suite this task touches or reads from must keep passing — run `npm run test:lineage` AND `npm run test:dataflow` before and after any change.
- Follow this repo's root `CLAUDE.md` verification discipline: every claim about coverage must be demonstrated by running real code in this task.

## Coordination with D2

D2 (`source-registry.js`) and D3 are designed to run in PARALLEL, in separate worktrees, touching disjoint files. Both absorb a DISJOINT HALF of `test/lineage/registry-mapping-poc.test.js` — per §9.1's explicit protocol, **whichever of D2/D3 lands SECOND deletes the PoC file**, after confirming the OTHER increment's absorption is already complete. This task's own Step 5 below is written assuming D3 might land either first or second — check the actual state of `test/lineage/registry-mapping-poc.test.js` at execution time and follow §9.1's protocol exactly.

---

### Task 1: Implement `sink-registry.js`, port the sink-side + privacy-side tables and guards, close FR-203, wire into the permanent suite

**Files:**
- Create: `scanner/src/lineage/sink-registry.js`
- Create: `scanner/test/lineage/sink-registry.test.js` (the permanent test file for this module)
- Modify: `scanner/package.json` (wire the new test file into `test:lineage`; remove the PoC's entry ONLY if this task is the second-lander per §9.1's protocol — check D2's state first)
- Modify: `scanner/src/lineage/CLAUDE.md` (new module-table row for `sink-registry.js`)
- Read only: `scanner/src/lineage/DESIGN_REGISTRIES.md` in full, `scanner/test/lineage/registry-mapping-poc.test.js` in full (the source of truth for exact table contents — port data faithfully, treat the design doc's prose as authoritative for the decision procedure), `scanner/src/dataflow/catalog.js` (the sink entries' real shape), `scanner/src/dataflow/privacy-catalog.js` (in full — this is a SEPARATE catalog from `catalog.js`, read it fresh, don't assume its shape from `catalog.js`'s own conventions), `scanner/src/lineage/schema.js` (the target `SINK_CATEGORIES`/`NODE_KINDS` vocabulary).

**Interfaces:**
- Consumes: `CATALOG` (from `../dataflow/catalog.js`, `kind: 'sink'` entries) and the privacy catalog's own exported array (from `../dataflow/privacy-catalog.js` — confirm its exact export name by reading the live file).
- Produces: `reclassifySink(entry)` and `reclassifyPrivacySink(entry)`, both exported from `scanner/src/lineage/sink-registry.js`, each returning `{kind, category, coverageStatus, externality, reason}` (§9.0's shape) — note `kind` here is NOT uniformly `'sink'` the way D2's source `kind` is uniformly `'source'`; it branches per `CATEGORY_NODE_KIND` (§7.1), and can be `'unresolved'` for the FR-203 case (item 5) or `'process'` for the `unsupported` case (item 3).

- [ ] **Step 1: Read `DESIGN_REGISTRIES.md` in full, then the PoC's sink-side and privacy-side content, then `catalog.js`/`privacy-catalog.js`**

Read §9's D3 checklist item 5 (FR-203) and its surrounding §16.7-carried-forward material especially carefully — this is the most subtle part of this task, and the design doc itself devotes unusual care to distinguishing FR-203's `unresolved` case from the separate degraded-analysis `unresolved` case. Get this distinction right; conflating them is the single most likely mistake in this task.

- [ ] **Step 2: Implement `sink-registry.js`**

`reclassifySink(entry)`:
- Port `CWE_MAP` (§5.1, 20 rows) from the PoC.
- Port the CWE-79 `framework` refinement (§5.2).
- Implement `CATEGORY_NODE_KIND` (§7.1) — the sink-side node-kind assignment table, which branches by category (not uniformly `'sink'`).
- Implement `CATEGORY_EXTERNALITY` (§7.5).
- Preserve the `unsupported` → `kind: 'process'` node with its reason string, per this task's own Global Constraints — do NOT drop these entries.
- Implement FR-203's `kind: 'unresolved'` handling (§9's item 5) — read the design doc's own exact field-by-field specification (category retained, externality `'unknown'`, coverageStatus unchanged from the category mapping, reason naming the blocking expression) and implement it precisely, not from this plan's own paraphrase.

`reclassifyPrivacySink(entry)`:
- Port `PRIVACY_CATEGORY_MAP` (§5.3, 9 rows — confirm this is 9 against the live `privacy-catalog.js`, not the 8 an earlier draft assumed).
- Implement the `thirdPartySdk` handling per item 4: NOT a silent `analytics` mapping — mark it as a known, disclosed open item (`coverageStatus: 'partial'`, with a reason stating the ambiguity a match-time consumer could later resolve), never guess which of `analytics`/`monitoring`/`external-api`/`collaboration` it actually is.

Implement the `coverageStatus` decision procedure per §6 for both functions.

- [ ] **Step 3: Write `sink-registry.test.js`, porting the sink-side and privacy-side tests from the PoC**

Port every sink-side and privacy-side test from `registry-mapping-poc.test.js` into this new permanent file, re-pointed at the shipped `reclassifySink`/`reclassifyPrivacySink`. At minimum:
- **Completeness guards** for BOTH catalogs (the CWE key set against `CATALOG`'s live sink entries, the privacy category key set against `privacy-catalog.js`'s live entries), each mutation-tested by you directly (add a hand-built entry with an unmapped classification value, confirm the guard fails, remove it, confirm clean).
- **The `unsupported` → `process` preservation test** (§9's item 3) — proving these entries are NEVER dropped from the reclassified output, with the non-empty-reason assertion (mirroring D1's own `D1/1e`) and the `kind === 'process'` iff `coverageStatus === 'unsupported'` biconditional (mirroring D1's own `D1/3c`) — both must ship as specified, including the fragility this biconditional has once AI-sink detection eventually lands (a comment noting this, per the design doc's own §7.1 note, is sufficient — you are not fixing that fragility, just not silently weakening the assertion because of it).
- **FR-203's own dedicated test**: a fixture proving a recognized-but-dynamically-unresolvable sink gets `kind: 'unresolved'`, retained category, `externality: 'unknown'`, and a reason naming the blocking expression — AND a SEPARATE test proving this is structurally distinct from the degraded-analysis `unresolved` case (different `coverageStatus` behavior, per §9's item 5's own explicit warning against conflating them).
- **The `thirdPartySdk` open-item test**: proving it resolves to `partial` with a disclosed-ambiguity reason, never a silent guess.
- The measured-count pins (§4.3/§5.1/§5.2's numbers) as equality assertions, not floors.

- [ ] **Step 4: Resolve the PoC's fate per §9.1's protocol**

Check the current state of `test/lineage/registry-mapping-poc.test.js` and `package.json`, exactly as D2's own plan describes. If D2 has already landed and absorbed its own half, this task is the second-lander: delete the PoC file and its `package.json`/CLAUDE.md references in this task's own commit. If D2 has not yet landed, this task is the first-lander: absorb only the sink/privacy-side content, leave the PoC and its wiring in place for D2, and note the ordering in your commit message.

- [ ] **Step 5: `scanner/src/lineage/CLAUDE.md` — new module-table row**

Add a `sink-registry.js` row describing the module's role, both mapping tables, the two-function split rationale, the FR-203 handling, the `thirdPartySdk` open item, and the `coverageStatus` distribution on the real catalog (confirm current numbers against what you actually shipped).

- [ ] **Step 6: Run the full scoped suite and doc-drift check**

```bash
npm run test:lineage
npm run test:dataflow
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/sink-registry.js scanner/test/lineage/sink-registry.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
# If you are the second-lander per Step 4:
# git rm scanner/test/lineage/registry-mapping-poc.test.js
git commit -m "feat(lineage): implement sink-registry.js, close FR-203 (Sub-project D, increment D3)"
```
