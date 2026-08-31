# Data Flow Explorer — M1 Sub-project D, Increment 1: Reclassification Mapping + Coverage-Status Design Spike

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve, and prove against real parsed code, the design for reclassifying the scanner's existing, already-proven `catalog.js`/`privacy-catalog.js` source/sink detection into `scanner/src/lineage/schema.js`'s `DataFlowGraph v1` node-kind/category vocabulary — the exact `catalog.js` entry → `SOURCE_CATEGORIES`/`SINK_CATEGORIES`/`NODE_KINDS` mapping table, and the `coverageStatus` (`modeled`/`partial`/`candidate`/`unsupported`/`manual`) assignment rule FR-101/AC-01 require. This is a design-and-PoC increment, mirroring every prior sub-project's own first-increment precedent in this PRD (Sub-project A's Decision 1, Sub-project C's C1) — it produces a committed design-doc addendum and a proof-of-concept regression test; the mechanical implementation of `source-registry.js`/`sink-registry.js` is a follow-up increment (D2/D3), not this one.

**Architecture:** `source-registry.js`/`sink-registry.js` (D2/D3's job, not built here) will be thin reclassification layers reading `scanner/src/dataflow/catalog.js`'s `CATALOG` (and `catalog-expanded.js`/`privacy-catalog.js`) as pure INPUT — never re-deriving pattern-matching logic those modules already implement and that the existing benchmark corpus already proves. This increment's job is entirely upstream of that: settle the mapping table and the coverage-status rule so D2/D3 have nothing left to design, only to implement.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-d-scoping.md` (the sub-project scoping doc — §1's verbatim PRD quotes, §2's grounded gap analysis, §3's recommended-not-decided design direction are this task's starting point) and `scanner/src/lineage/schema.js` (the binding target vocabulary — `NODE_KINDS`, `SOURCE_CATEGORIES`, `SINK_CATEGORIES`, `TRANSFORM_KINDS` — read the LIVE file, not the scoping doc's own paraphrase of it) and `scanner/src/dataflow/catalog.js`/`catalog-expanded.js`/`privacy-catalog.js` (the existing detection catalogs this increment reclassifies).

## Global Constraints

- This increment must NOT reimplement any pattern-matching `catalog.js`/`engine.js` already does — it consumes catalog ENTRIES (their `provenance`/`category`/`label`/`vuln` fields) as data, never re-derives what a call site matches.
- Must NOT touch `scanner/src/dataflow/catalog.js`, `catalog-expanded.js`, `privacy-catalog.js`, or `scanner/src/lineage/schema.js` unless this task's own research finds a genuine, narrow gap (e.g. a `SOURCE_CATEGORIES`/`SINK_CATEGORIES` value schema.js is missing that the PRD's own FR-101/FR-201 category lists require) — if so, name it precisely as a finding, don't patch it silently, and treat any such change as maximally conservative (additive only).
- `scanner/src/lineage/` may import PURE utilities from `scanner/src/dataflow/` per this whole PRD's established isolation principle (verified in every prior increment's review) — reading `catalog.js`'s exported `CATALOG` array is data consumption, not importing taint-engine mutable state, and is consistent with that principle; confirm this reading is correct before relying on it, don't assume.
- Every existing test suite this increment touches or reads from must keep passing — run `npm run test:lineage` and `npm run test:dataflow` before AND after any change (both scopes are relevant here, unlike Sub-project C's own lineage-only scope, since this increment reads real `dataflow/` catalog data).
- Follow this repo's root `CLAUDE.md` verification discipline: every claim about the mapping (does every distinct `provenance`/`category` string in the real catalogs get a mapping decision, does the coverage-status rule behave correctly on real entries) must be demonstrated by running real code against the actual, current `catalog.js`/`privacy-catalog.js`/`schema.js` files in this task, not asserted from the scoping doc's own already-somewhat-stale sampling.

---

### Task 1: Resolve and document the reclassification mapping + coverage-status rule, with a proof-of-concept

**Files:**
- Create: `scanner/src/lineage/DESIGN_REGISTRIES.md` (mirrors `DESIGN_INTRAPROCEDURAL.md`'s and `DESIGN_PATH_PROVENANCE.md`'s own role — the binding ADR for Sub-project D, the same way those two documents bind Sub-projects A/B and C respectively).
- Create: `scanner/test/lineage/registry-mapping-poc.test.js` (a throwaway-named PoC test file, mirroring every prior sub-project's own first-increment precedent).
- Read only: `scanner/src/dataflow/catalog.js`, `scanner/src/dataflow/catalog-expanded.js`, `scanner/src/dataflow/privacy-catalog.js` (all three, in full — this task's central job is reading every distinct classification string these files actually contain, not sampling a few examples), `scanner/src/lineage/schema.js` (in full — the target vocabulary), `scanner/src/dataflow/CLAUDE.md` (for the catalogs' own documented shape/conventions), `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §11-12 (FR-101 through FR-205, already partially quoted in the scoping doc but read the PRD's own full text, not just the scoping doc's excerpts) and §25 (AC-01, AC-11 — the acceptance criteria this mapping's `coverageStatus` output must satisfy).

**Interfaces:**
- Consumes: `catalog.js`'s exported `CATALOG` array (and whatever `catalog-expanded.js`/`privacy-catalog.js` export — confirm their exact export shape by reading, don't assume it matches `catalog.js`'s), `schema.js`'s exported `NODE_KINDS`/`SOURCE_CATEGORIES`/`SINK_CATEGORIES`/`TRANSFORM_KINDS` constants.
- Produces (for the follow-up D2/D3 implementation increments to consume — do not implement `source-registry.js`/`sink-registry.js` themselves in this task, just settle their exact design in the addendum and prove it via the PoC):
  - **The complete mapping table.** Every DISTINCT `provenance` string (source entries) and every distinct classification signal sink entries carry (read the actual field name — the scoping doc calls it `vuln` for sink entries, confirm this against the live code) actually present in `CATALOG`, PLUS every distinct `category` string in `privacy-catalog.js`, each mapped to either a `SOURCE_CATEGORIES`/`SINK_CATEGORIES` value or explicitly marked unmapped (with a stated reason and a `coverageStatus` consequence — see below). This must be a COMPLETE enumeration, not a sample — write a small script/test that extracts every distinct value programmatically (`new Set(CATALOG.filter(e => e.kind === 'source').map(e => e.provenance))`, or whatever the real field structure turns out to require) and confirm the mapping table's own keys match that set exactly, so nothing is silently missed.
  - **The `privacy-catalog.js` ↔ `schema.js` `SINK_CATEGORIES` reconciliation**, entry by entry — the scoping doc's own §2 already found these vocabularies overlap but don't match exactly (`privacy-catalog.js`: `log`/`response`/`storage`/`queues`/`email`/`file`/`outbound`/`third-party`; `schema.js`: 28 finer-grained values). Resolve each of `privacy-catalog.js`'s 8 categories to one or more `SINK_CATEGORIES` values (a coarse category like `storage` may need to split across `database`/`object-storage`/`cache` depending on the entry's own other fields — check what other fields each entry actually carries before assuming a 1:1 or 1:many mapping).
  - **The `coverageStatus` assignment rule**, concretely — not just "the four values exist" but the exact DECISION PROCEDURE: given a catalog entry, when is it `modeled` (confidently, unambiguously mapped) vs `partial` (mapped but with some caveat — define what caveat) vs `candidate` (a plausible but unconfirmed mapping) vs `unsupported` (no mapping exists, entry excluded from the reclassified inventory but NOT silently dropped from AC-01's own "shows both connected and disconnected... with status" requirement) vs `manual` (schema.js's fifth value — check when this one applies; the scoping doc's own text names it but never explains it, so this is a genuine open question this task must resolve, not carry forward unexamined). Prove this rule against real entries from all three catalog files, not hypothetical ones.
  - **Node-kind assignment.** A reclassified source entry needs a `NODE_KINDS` value (almost certainly `'source'`, but confirm — check whether any `catalog.js` source entry might reasonably map to `'boundary'` or another kind instead) and a reclassified sink entry likewise (`'sink'`, `'external'`, `'store'`, `'queue'`, `'log'`, `'api'` are all plausible candidates depending on category — decide the rule, don't hand-wave it as "always sink").
  - **Whether any `SOURCE_CATEGORIES`/`SINK_CATEGORIES` value schema.js defines has ZERO catalog entries that map to it today** (a real, disclosable gap — FR-101/FR-201's own category lists are broader than what any existing detection catalog covers; name which categories are currently unreachable and whether that's expected — e.g. GraphQL/gRPC categories might have zero `catalog.js` coverage today if this scanner's JS/TS detection doesn't yet pattern-match those frameworks — confirm by checking, don't assume).
  - **Whether `catalog.js`'s entries carry enough information to determine `externality`/`boundary` status** (schema.js's node contract — check what fields it requires) — if not, name this as a gap D2/D3 must either close with a sensible default or explicitly leave `unknown`.

- [ ] **Step 1: Read the current state (grounding, not a step that produces a diff)**

Read `catalog.js`, `catalog-expanded.js`, `privacy-catalog.js`, `schema.js` in full. Read the PRD's FR-101 through FR-205 in full (not just the scoping doc's excerpts — the scoping doc may have paraphrased or trimmed something material). Read AC-01 and AC-11 in full.

- [ ] **Step 2: Extract the complete, real distinct-value sets**

Write a small script or the PoC test's own setup code that programmatically enumerates: every distinct source-entry classification string in `CATALOG` (and confirm whether `catalog-expanded.js` contributes any source entries at all, or is sanitizer-only as the scoping doc's line-count breakdown suggests — verify, don't assume), every distinct sink-entry classification string in `CATALOG`, every distinct `category` value in `privacy-catalog.js`. Print/log these sets and use them as the ground truth the mapping table must cover completely — this is the single most important verification step in this task, since an incomplete enumeration silently undermines everything built on top of it.

- [ ] **Step 3: Build the PoC harness**

Write `scanner/test/lineage/registry-mapping-poc.test.js`. Prototype the mapping table and coverage-status rule as local functions (mirroring every prior sub-project's own design-task PoC convention — shipped source under `src/` stays unmodified by this task). At minimum, prove:

1. **Complete coverage**: every distinct value Step 2 extracted has an entry in the mapping table (or an explicit, justified `unsupported` marking) — a test that fails loudly if a new catalog entry's classification string is ever added without updating the mapping.
2. **A representative sample of real reclassifications**, end to end: take 5-10 real `CATALOG` entries (a mix of source/sink, a mix of languages/frameworks) and show the exact `{kind, subtype/category, coverageStatus}` triple your rule produces for each, with reasoning.
3. **The `privacy-catalog.js` reconciliation**, proven on real entries: at least one entry from each of `privacy-catalog.js`'s 8 categories, showing which `SINK_CATEGORIES` value(s) it resolves to.
4. **An honest `unsupported` case**: find or construct a real catalog entry (or confirm none exists, which is itself a finding) whose classification string has no confident mapping, and show the coverage-status rule marks it `unsupported` rather than silently excluding it.
5. **The `TRANSFORM_KINDS` confirmation** (D4 depends on this increment settling `TRANSFORM_KINDS` is stable and complete — a lightweight check, not a full transform-catalog design, which is D4's own job): confirm `schema.js`'s `TRANSFORM_KINDS` values exactly match §10.6's PRD text (already quoted in the scoping doc, but re-verify against the live PRD text and the live `schema.js` export in this task).

- [ ] **Step 4: Decide, and write `DESIGN_REGISTRIES.md`**

Using Step 2/3's PROVEN results, write the design document mirroring `DESIGN_INTRAPROCEDURAL.md`'s/`DESIGN_PATH_PROVENANCE.md`'s own style: the complete mapping table (as an actual table or structured list, not prose), the coverage-status decision procedure, the node-kind assignment rule, the `privacy-catalog.js` reconciliation, disclosed gaps (unreachable categories, missing `externality` data, the `manual` coverage-status value's actual meaning and trigger condition), and a "what the follow-up implementation increments (D2 source-registry, D3 sink-registry) must do" checklist in the file/line-precise style this PRD's every prior increment has established.

- [ ] **Step 5: Verify nothing existing regressed**

Run `npm run test:lineage` and `npm run test:dataflow` from `scanner/`. All pre-existing tests in both scopes must still pass — this task adds only new, isolated files.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/DESIGN_REGISTRIES.md scanner/test/lineage/registry-mapping-poc.test.js
git commit -m "docs(lineage): design Sub-project D's catalog-to-schema reclassification mapping + coverage-status rule, with PoC"
```

---

## Post-Task-1 note

This plan gains its implementation task(s) here, scoped exactly to what `DESIGN_REGISTRIES.md`'s checklist specifies, once Task 1's addendum is committed and reviewed. Do not pre-write them — the checklist does not exist yet at the time this plan file was first saved. (D2 and D3, per the parent scoping doc's own recommended sequencing, may end up as separate plan files rather than further tasks in this one, given they can run in parallel once D1 lands and are sized independently — this decision itself is deferred to when D1's own design is in hand.)
