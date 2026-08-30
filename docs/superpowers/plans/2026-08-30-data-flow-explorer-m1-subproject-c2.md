# Data Flow Explorer — Milestone 1, Sub-project C, Increment 2: Full Intraprocedural Provenance Instrumentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Instrument every remaining `resolveExprIdentities` case and every remaining `step()` CFG-node case with hop recording, completing intraprocedural provenance coverage. Increment C1 already built and proved the mechanism (the `ctx.recordHop` accumulator, progressive stamping, `contributingKeys` for Decision 6) against 4 representative sites. This increment is **mechanical, not exploratory**: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md`'s §10 is a complete, already-reviewed (by two separate opus-tier reviews across increment C1) instrumentation checklist giving the exact `fromPath`/`toPath`/`widenReason`/`lossReason` rule for every single case. Implement the checklist; do not re-derive it.

**Architecture:** No new mechanism. Every site in this increment uses the exact same pattern C1 already established: call `ctx?.recordHop?.({...})` (or, for sites needing Decision 6's contributing-key resolution, `ctx?.recordHop` guarding a `contributingKeysAllIds` call) at exactly the point each case already produces or consumes an identity. Read C1's existing `ident`/`object`/`assign`(normal)/`return` instrumentation in the current `engine.js` as your primary reference implementation for HOW to wire a new site — the pattern is uniform across all of them.

**Tech Stack:** Node.js ESM, `node:test`, `scanner/src/lineage/engine.js` (existing, extended additively), `scanner/src/ir/parser-js.js` (real JS/TS parser, for the final coverage proof).

**Spec:** `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` — READ IT IN FULL, especially §10.1 and §10.2 (the exact checklist this plan implements) and §2.2's null-`fromPath`-annotation-semantics clause (added by a design review — governs every `production` case whose `fromPath` is `null`). Also `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md` for this increment's place in the overall Sub-project C sequence.

## Global Constraints

- **`field-identity.js` is READ-ONLY**, exactly as in C1. `contributingKeysAllIds`/`contributingKeys` in `engine.js` are already exported/available from C1 — reuse them, do not duplicate.
- **Backward compatibility is the primary acceptance bar, exactly as in C1.** With no recorder supplied, every observable output of `resolveExprIdentities`/`analyzeFunctionFieldIdentity`/`summaries.js`/`driver.js` must stay byte-identical. C1's own "write-only invariant" test (in `test/lineage/engine-provenance.test.js`) already proves this property for the 4 sites it covers — this increment must extend that SAME test (adding more fixtures/sites to its coverage, not writing a parallel, weaker mechanism) rather than relying on narrower, per-site assertions alone.
- **Follow §10's checklist exactly, including its "verdict of 'emits nothing, because…'" rule for the genuine do-nothing cases** (per §10.1/§10.2's own table — `literal`, `unknown`/`default`, and a handful of `step()` node kinds are true no-ops; most other cases DO emit something, even the structure-flattening ones like `array`/`tpl`/`binary` — read the table itself rather than assuming from this summary which cases are which). Do not skip a case with no comment explaining why — the design doc is explicit that a silently-skipped case is exactly the failure mode that let Sub-project A's own rounds 3-5 each ship an unexamined site.
- **Do not touch `summaries.js` or `driver.js`.** §10.3 explicitly reserves cross-file/interprocedural sites for increment C3 — this increment is intraprocedural-only, matching C1's own scope discipline.
- **`field-identity.js`, and every pre-existing test file across Sub-projects A/B/C1**, must show zero diff. Only `engine.js` and `test/lineage/engine-provenance.test.js` may change (plus `package.json` if a new test file is added — it should not be; extend the existing `engine-provenance.test.js`).
- All new/changed code must keep `npm run test:lineage` fully green (220 tests pass on `main` today — confirm this exact count before starting).

---

## Task 1: `resolveExprIdentities`'s remaining cases

**Files:**
- Modify: `scanner/src/lineage/engine.js`
- Test: `scanner/test/lineage/engine-provenance.test.js`

**Interfaces:**
- Consumes: `DESIGN_PATH_PROVENANCE.md` §10.1 (binding spec for every case in this task), the existing `ident`/`object` instrumentation in `engine.js` (the pattern to follow), `contributingKeysAllIds` (already defined in `engine.js` from C1).
- Produces: hop recording for every remaining `resolveExprIdentities` case: all four `member` sub-cases (path/no-wildcard, path/wildcard, non-path-base/`prop!=='*'`, non-path-base/`prop==='*'`), `array`, `tpl`, `binary`, `logical`, `union`, `call` (both unresolved and resolved-via-`ctx.resolveCallSummary`), `assign-expr`. Also give `literal`/`unknown`/`default` their explicit "emits nothing, because…" verdict per §10's own rule (a one-line comment is sufficient where the design doc already states the reasoning — do not invent new reasoning).

- [ ] **Step 1: Read the current state of everything first**

Read `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md`'s §10.1 in full (it is the literal spec for this task — table rows give exact `fromPath`/`toPath`/`widenReason` per case). Read the CURRENT `resolveExprIdentities` in `engine.js` in full (509+ lines, extended by C1) to see exactly how `ident`/`object` are instrumented today — this is your template. Read `test/lineage/engine-provenance.test.js` in full to understand the existing test structure (the "write-only invariant" test, the §6 worked-example test, the `REQUIRED_FIELDS` check, `dedupeHops`) — you will extend these, not replace them.

- [ ] **Step 2: Write the failing tests first**

For each case this task instruments, add a test proving:
(a) the hop record(s) emitted are correct per §10.1's table (right `kind`/`subKind`/`fromPath`/`toPath`/`widenReason`/`dataElementId`),
(b) `field-identity.js`'s untouched status and the existing "write-only invariant" mechanism still pass — EXTEND the existing write-only-invariant test's fixture list with at least 3 new fixtures exercising THIS task's new sites (a `member` read, a ternary, a resolved call), rather than writing a separate, parallel byte-identical-output test.

Use real parsed source (`parseJsFile`) for each new case, matching C1's own established style — hand-built CFG-node mocks are acceptable ONLY where C1's own tests already used them for a comparable purpose (e.g. `nodeId`-from-worklist-key proofs).

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/engine-provenance.test.js`
Expected: FAIL for every new assertion (nothing implemented yet); the PRE-EXISTING C1 tests must still PASS unchanged.

- [ ] **Step 4: Implement, case by case, checking off §10.1's table as you go**

Wire each case per the design doc's exact table row. Two rows deserve extra care (the design doc itself flags these):
- `member` (path branch, wildcard): `fromPath` must be `definitePrefixBeforeWildcard(path)`, **never** the raw `'*'`-containing path (Decision 5 — this is the exact bug class the design doc treats as most consequential to get wrong).
- `call` (resolved via `ctx.resolveCallSummary`): `subKind: 'call-resolved'`, `widenReason: null` — this increment records only that a resolved call contributed; the actual cross-function stitch is explicitly C3's job (§10.1's own note), do not attempt it here.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/engine-provenance.test.js`
Expected: PASS, all tests including every new one, and every C1-era test unchanged and still passing.

- [ ] **Step 6: Confirm zero regression to every pre-existing lineage test file**

Run: `cd scanner && npm run test:lineage`
Expected: PASS. Confirm via `git diff --stat` that `field-identity.js` and every OTHER pre-existing test file (`field-identity.test.js`, `engine-expr-resolver.test.js`, `engine-walker.test.js`, `engine-integration.test.js`, `summaries.test.js`, `driver.test.js`) show zero diff — only `engine.js` and `engine-provenance.test.js` should appear.

- [ ] **Step 7: Confirm the isolation principle still holds**

Run: `grep -n "from '../dataflow/engine\|from '../dataflow/summaries" scanner/src/lineage/engine.js`
Expected: no output.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/test/lineage/engine-provenance.test.js
git commit -m "feat(lineage): instrument resolveExprIdentities's remaining cases for path provenance (Sub-project C, increment 2, Task 1)"
```

---

## Task 2: `step()`'s remaining cases + full intraprocedural coverage proof

**Files:**
- Modify: `scanner/src/lineage/engine.js`
- Test: `scanner/test/lineage/engine-provenance.test.js`

**Interfaces:**
- Consumes: `DESIGN_PATH_PROVENANCE.md` §10.2 (binding spec), Task 1's completed `resolveExprIdentities` instrumentation (this task's coverage proof exercises BOTH together).
- Produces: hop recording for `step()`'s three remaining cases (`assign` target-not-a-string, `assign` wildcard target, `call` bare statement), plus one comprehensive real-parser integration test proving full intraprocedural coverage (every case from §10.1 AND §10.2 exercised together in a single, realistic function).

- [ ] **Step 1: Implement the three remaining `step()` cases**

Per §10.2's table exactly:
- `assign`, target not a string: `lossReason: 'unsupported-target'`. The design doc's own corrected note is explicit that resolving `node.source` for this purpose GENUINELY emits real in-half hops (not discarded computation) — do not suppress those; let them fire and join with this row's loss marker.
- `assign`, wildcard target: `toPath: definitePrefixBeforeWildcard(node.target)` (never the raw wildcard path — same Decision 5 discipline as Task 1's `member` wildcard case), `subKind: 'assign-weak'`, `widenReason: 'dynamic-property-key'`, one record per `(containerPath, id)`.
- `call` (bare call statement): `subKind: 'call-arg'`, write-out, `toPath: null`.

Do NOT add anything for `assign`'s kill (`removeIdentitiesAt`) — §10.2's own table already gives this an explicit "no row of its own, and that is correct" verdict; nothing to implement.

- [ ] **Step 2: Write and run tests for these three cases (TDD — write failing tests, implement, confirm passing)**

Follow the same pattern as Task 1: real-parser fixtures, assert the exact hop shape per §10.2's table, confirm `field-identity.js` and every pre-existing test file remain untouched.

- [ ] **Step 3: Write ONE comprehensive real-parser coverage-proof test**

Construct a single, realistic function (or a small set of them) exercising EVERY case from §10.1 and §10.2 that emits a hop — member reads (both wildcard and non-wildcard), array/template/binary/logical/ternary constructs, a resolved and an unresolved call, an assign-expr, a wildcard write, an unsupported-target write, a bare call statement, alongside C1's own `ident`/`object`/`assign`(normal)/`return`. Assert: (a) every expected `(kind, subKind)` combination appears at least once in the collected hops, (b) the "emits nothing" cases (`literal`, `unknown`) genuinely produce none, (c) `field-identity.js`-observable output (returnFacts/mutatedParams/widenings/exitState) for this SAME fixture is identical whether or not a recorder is attached — extending the write-only-invariant test one more time, not asserting this as a separate, disconnected fact.

- [ ] **Step 4: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 220 prior (as of `main` at this branch's start) plus every new test from both tasks, 0 failures.

- [ ] **Step 5: Confirm the isolation principle and file-scope discipline one final time**

Run the same grep from Task 1's Step 7. Run `git diff main --stat` (from the worktree) and confirm ONLY `scanner/src/lineage/engine.js` and `scanner/test/lineage/engine-provenance.test.js` differ from `main` (plus this plan's own doc file and the SDD ledger, which don't count as source).

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/test/lineage/engine-provenance.test.js
git commit -m "feat(lineage): instrument step()'s remaining cases, full intraprocedural coverage proof (Sub-project C, increment 2, Task 2)"
```

---

## Post-implementation: update `scanner/src/lineage/CLAUDE.md`

After both tasks are reviewed and clean:
- Update the Sub-project C section header from "increment 1... four sites only" to reflect increment 2's full intraprocedural coverage.
- Update the `engine.js` row's own description to reflect that intraprocedural instrumentation is now COMPLETE (§10.1/§10.2's checklist fully implemented) — cross-file/interprocedural sites (§10.3) remain C3's job, unchanged.
- Update "What is NOT here yet" to move C2 from "still ahead" to done, matching every prior increment's own established pattern in this file.

This is not a separate task — fold it into a final `docs(lineage): ...` commit after both tasks.
