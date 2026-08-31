# Lineage Schema Hotfix: `node.subtype` Nullability Parity

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix a real, measured Milestone-0 contract inconsistency: `scanner/src/lineage/validate.js` (the hand-rolled structural validator) never inspects `node.subtype` at all — it silently accepts `null`, an absent field, or even a bare number — while `scanner/src/lineage/dataflow-graph.schema.json` (the JSON-Schema-dialect twin `validate.js` is supposed to stay in parity with) declares `subtype` `required` and typed `string`, which would reject exactly the `null` case a real, common, already-shipped scenario produces. `scanner/src/lineage/source-registry.js`/`sink-registry.js` (Sub-project D, merged) map their own `category: null` decisions directly onto `node.subtype` — and 82 of 194 (42%) of D3's own shipped sink entries genuinely produce `category: null` for ordinary, non-error reasons (e.g. `js-exec`/`js-eval`-style code-execution CWEs with no data destination to categorize). `subtype: null` is the CORRECT design, not a bug to route around — the JSON Schema is what's wrong, and this hotfix relaxes it to match `validate.js`'s already-correct behavior, while also tightening `validate.js`'s own currently-too-loose check (a bare number currently passes silently) and closing the specific gap in `json-schema-parity.test.js` that let this drift go undetected. This bug was found and precisely characterized during Sub-project E, increment E1's design spike; this hotfix applies the fix as its own reviewed increment, sequenced before Sub-project E's E2/E3, since those increments will be the first to produce real `subtype: null` nodes from a live scan.

**Architecture:** Three small, coordinated changes: (1) relax `dataflow-graph.schema.json`'s `$defs.node.required`/`subtype` type declaration to accept `null`, (2) tighten `validate.js` to actively check `subtype` is `string | null` (not silently accept any type), (3) extend `json-schema-parity.test.js` to compare each `$defs.<entity>.required` array against `validate.js`'s own required-key set, so a future divergence of THIS kind — not just an enum drifting — fails loudly instead of silently, closing the exact blind spot that let this one go unnoticed.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies. No JSON-Schema validator library exists in this repo's dependency tree and none should be added — reason about the schema file's own `required`/`type` keywords directly, the same method Sub-project E's own E1 review used to verify this finding.

**Spec:** The exact inconsistency was found and verified during Sub-project E's E1 review (`.superpowers/sdd/2026-08-31-data-flow-explorer-m1-subproject-e1/`, not committed — an SDD working artifact; read `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` §11 instead, which records this escalation, and `scanner/src/lineage/CLAUDE.md`'s own Sub-project E1 module-table entry, item 4 in its numbered list). Read `scanner/src/lineage/schema.js` (§10.3's node contract, already encoded there — confirm `subtype`'s role in that module too, it should already be treated as optional/nullable there if anywhere), `scanner/src/lineage/validate.js` in full (the hand-rolled validator — confirm directly that it never inspects `subtype` today, per the E1 review's own grep-confirmed finding), `scanner/src/lineage/dataflow-graph.schema.json` in full (the JSON-Schema twin — confirm the exact `$defs.node.required`/`type` declaration for `subtype`), `scanner/test/lineage/json-schema-parity.test.js` in full (confirm it only compares enum arrays plus top-level envelope required keys today, never `$defs.<entity>.required`), `scanner/src/lineage/source-registry.js`/`sink-registry.js` (confirm the real `category: null` numbers — 82/194 sink entries — by running their own live tests/exports, not by trusting this plan's own quoted figure).

## Global Constraints

- `subtype: null` must remain LEGAL — this is the corrected understanding, not something to "fix away." Do not make the JSON Schema require a non-null string; that would make the schema MORE wrong, not less.
- `subtype` absent (the field simply not present on a node object) should also be considered — confirm from `schema.js`'s own node contract and from how `source-registry.js`/`sink-registry.js`'s `category: null` decisions are actually meant to be written onto a node (does D's own `DESIGN_REGISTRIES.md` §9.0 say the field should be `subtype: null` or `subtype` omitted entirely, for a `category: null` decision? Re-read that section — do not assume).
- Must tighten `validate.js` to genuinely check `subtype`'s type (currently it accepts anything, including a number, silently) — but the tightened check must still accept `null` and (per whatever Step 1 confirms about the absent-vs-null question) whatever the correct absent/present rule is.
- Must NOT modify `source-registry.js`, `sink-registry.js`, `transform-catalog.js`, `catalog.js`, `privacy-catalog.js`, or any Sub-project D test file — those are already correct and were the evidence this hotfix's fix is grounded in, not modules this hotfix touches.
- Must NOT modify `scanner/src/lineage/fixtures/build-flagship-fixture.mjs` or `flagship-graph.json` unless Step 4's re-validation finds the flagship fixture itself now fails the corrected schema (the E1 review's own investigation found 0 of the flagship's 14 nodes would fail the node-level JSON-Schema check either way, since all 14 carry string subtypes — confirm this yourself, don't assume it's still true).
- Every existing test suite this task touches or reads from must keep passing — run `npm run test:lineage` before AND after any change.
- Follow this repo's root `CLAUDE.md` verification discipline throughout — every claim about what currently validates and what the fix changes must come from running real code in this task.

---

### Task 1: Relax the JSON Schema, tighten `validate.js`, and close the parity-test blind spot

**Files:**
- Modify: `scanner/src/lineage/dataflow-graph.schema.json` (relax `subtype`'s type declaration)
- Modify: `scanner/src/lineage/validate.js` (add an active `subtype` type check)
- Modify: `scanner/test/lineage/json-schema-parity.test.js` (add the `$defs.<entity>.required`-vs-`validate.js` comparison)
- Modify: `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` (§11's escalation entry — mark it RESOLVED, with the commit reference)
- Read only: `scanner/src/lineage/schema.js`, `scanner/src/lineage/DESIGN_REGISTRIES.md` §9.0 (the `category`→`subtype` mapping decision — confirm the null-vs-absent question from here), `scanner/src/lineage/fixtures/flagship-graph.json` (confirm every node's `subtype` is currently a string, so this change doesn't regress that fixture).

**Interfaces:**
- Consumes: nothing new.
- Produces: no new exports — `validateGraph`'s signature is unchanged; only its internal checks gain one new active check.

- [ ] **Step 1: Confirm the exact current state and the null-vs-absent question**

Read `validate.js` in full; grep for `subtype` and confirm it is genuinely never inspected (per the E1 review's own finding). Read `dataflow-graph.schema.json`'s `$defs.node` block and confirm the exact current `required`/`type` declaration for `subtype`. Read `DESIGN_REGISTRIES.md` §9.0 to settle whether a `category: null` registry decision is meant to produce `subtype: null` or an absent `subtype` field on the eventual node — this determines exactly what both `validate.js`'s new check and the schema's relaxed declaration must accept. Confirm live, by running `reclassifySink()` on a real `category: null`-producing entry and checking what Sub-project D's own tests assume the eventual node field looks like (they may not construct a full node at all, since D never writes to `subtype` — check what `DESIGN_REGISTRIES.md` §9.0 itself says a future Sub-project E graph builder should write, since D deliberately deferred writing `subtype` to E).

- [ ] **Step 2: Relax `dataflow-graph.schema.json`**

Change `subtype`'s type declaration to accept the value(s) confirmed correct by Step 1 (most likely `{"type": ["string", "null"]}`, keeping it in `required` if absent-vs-present were resolved as "always present, sometimes null" — or removing it from `required` if the correct answer is "sometimes absent entirely"; use Step 1's own finding, not a guess).

- [ ] **Step 3: Tighten `validate.js`**

Add an active check: if `node.subtype` is present, it must be a string or `null` — anything else (a number, an object, an array, `undefined` used in a way distinct from absence) is a validation error, added to the same `errors[]` array every other node-level check already uses. Confirm this doesn't break the flagship fixture (`flagship-graph.json`, whose 14 nodes all currently carry string subtypes) or any other currently-passing test.

- [ ] **Step 4: Extend `json-schema-parity.test.js`**

Add a new test that, for each `$defs.<entity>` in the schema JSON with a `required` array, compares that array against the actual set of fields `validate.js` treats as REQUIRED for that entity kind (this may require reading `validate.js`'s own logic carefully to determine what it currently treats as required per entity — document this mapping explicitly in the test's own comments, since `validate.js` doesn't necessarily group its checks the same way the JSON Schema's `$defs` does). This is the fix for the actual root cause the E1 review named: the parity test's blind spot to `$defs.*.required`, not just enum arrays.

- [ ] **Step 5: Prove the fix live**

Construct a node object with `subtype: null` (mirroring a real `category: null` sink reclassification) and confirm: `validateGraph()` still accepts it (unchanged, correct behavior); a hand-evaluation of the corrected JSON Schema's own `required`/`type` keywords (the same method the E1 review used, since no JSON-Schema library exists in this repo) now ALSO accepts it, where it previously would have rejected it. Also confirm a node with `subtype: 12345` (a bare number) is now REJECTED by `validate.js` (closing the tightening half of this fix) where it previously silently passed.

- [ ] **Step 6: Update `DESIGN_GRAPH_BUILDER.md` §11's escalation entry**

Mark the schema/validator escalation RESOLVED, with the commit hash once committed, stating the exact fix (schema relaxed to `string | null`, `validate.js` tightened to actively check the type, `json-schema-parity.test.js` extended to compare `required` arrays not just enums).

- [ ] **Step 7: Run the full scoped suite and doc-drift check**

```bash
cd scanner
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 8: Commit**

```bash
git add scanner/src/lineage/dataflow-graph.schema.json scanner/src/lineage/validate.js scanner/test/lineage/json-schema-parity.test.js scanner/src/lineage/DESIGN_GRAPH_BUILDER.md
git commit -m "fix(lineage): relax node.subtype schema nullability, tighten validate.js, close parity-test blind spot (found during Sub-project E1)"
```
