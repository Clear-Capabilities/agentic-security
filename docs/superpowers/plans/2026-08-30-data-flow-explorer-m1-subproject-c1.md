# Data Flow Explorer — Milestone 1, Sub-project C, Increment 1: Path Provenance Design Spike

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the single highest-uncertainty design question in Sub-project C — HOW to record provenance/predecessor information as data flows through the field-identity engine, WITHOUT rewriting or destabilizing `field-identity.js`'s core state shape (`Map<accessPath, Set<dataElementId>>`), which took Sub-project A six rounds of adversarial review to harden. Mirrors Sub-project A's own precedent exactly: a short design note first, backed by a small, real-code proof-of-concept — not a paper design alone, and not a full implementation either.

**Architecture:** Add an OPTIONAL, additive "hop recorder" accumulator, threaded through `resolveExprIdentities`/`step`/`analyzeFunctionFieldIdentity` alongside the existing `ctx` parameter (the exact mechanism Sub-project B's increment 2 already used to add interprocedural resolution without touching `field-identity.js` at all — this plan reuses that precedent, not invents a new one). When present, each of the engine's existing "three hop types" (production / selection / write-out — the framework `DESIGN_INTRAPROCEDURAL.md` and every subsequent round of review already established and hardened) additionally pushes a hop record describing what just happened. When absent, ZERO behavior change — every one of the ~211 existing lineage tests must pass completely unmodified.

**Tech Stack:** Node.js ESM, `node:test`, `scanner/src/lineage/engine.js` (existing, extended additively), `scanner/src/ir/parser-js.js` (real JS/TS parser, for the real-code proof).

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` (repo root) — FR-303 (path reconstruction: "retain a compact predecessor/provenance DAG... must not eagerly materialize every possible path"), §18.4 (path-explosion controls). This plan also argues from `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md`'s own C1 row and §3 ("Recommended design direction").

## Global Constraints

- **`field-identity.js` is READ-ONLY for this plan.** Its `Map<accessPath, Set<dataElementId>>` state shape, and every one of its exported functions (`emptyState`/`identitiesAt`/`addIdentity`/`removeIdentitiesAt`/`joinStates`/`statesEqual`/`hashState`), stays byte-for-byte unmodified. Provenance recording is an ADDITIVE, PARALLEL mechanism — never a change to what `state` itself contains. If you find yourself wanting to add a field to the Map's value type, stop: that re-opens the entire FR-301 correctness surface Sub-project A spent six rounds closing, and is explicitly out of scope for this increment (and arguably any future one, absent a very strong, separately-argued reason).
- **Backward compatibility is the primary acceptance bar.** Every existing test in `test/lineage/field-identity.test.js`, `test/lineage/engine-expr-resolver.test.js`, `test/lineage/engine-walker.test.js`, `test/lineage/engine-integration.test.js`, `test/lineage/summaries.test.js`, and `test/lineage/driver.test.js` must pass completely unmodified, with zero edits to any of those files. This plan only ADDS a new, optional mechanism.
- **This is a design spike + small POC, not a full implementation.** Do not attempt to instrument every one of `resolveExprIdentities`'s cases (`ident`, `member` ×2, `object`, `array`, `tpl`, `binary`, `logical`, `union`, `call`, `assign-expr`) or every `step()` CFG-node case (`assign` ×2, `call`, `return`). Full coverage is increment C2's explicitly separate, larger job. This plan's Task 2 instruments a small, deliberately representative SUBSET (named in Task 2 below) sufficient to prove the mechanism works end-to-end against real parsed code — resist the urge to expand scope just because a pattern is now obviously repeatable across more cases.
- **Isolation principle still applies.** No new import from `scanner/src/dataflow/engine.js` or `scanner/src/dataflow/summaries.js`.
- All new/changed code must keep `npm run test:lineage` fully green.

---

## Task 1: The design note (ADR)

**Files:**
- Create: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md`

**Interfaces:**
- Consumes: nothing new — this is a pure documentation task, informed by reading the current `engine.js`/`field-identity.js`/`summaries.js`/`driver.js` and this plan's own Architecture section.
- Produces: a design document that Task 2 (this same plan) and every future increment of Sub-project C implement against.

- [ ] **Step 1: Read the existing design precedents first**

Read, in full: `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md` (the ADR Sub-project A itself produced — this new document should match its style: worked examples, explicit decision statements, not just prose) and the "three hop types" framework as currently documented in `scanner/src/lineage/CLAUDE.md`'s `engine.js` row (production / selection / write-out, and the durable invariant statement they subsume: *"every path component the IR supplies must be either a real property name or an explicitly modeled unknown, and every kill must be justified as a strong update on a definite, uniquely-identified location"*). Also read the current, exact text of `resolveExprIdentities` and `step()` in `scanner/src/lineage/engine.js` (509 lines total) — every case this design needs to eventually cover.

- [ ] **Step 2: Resolve and document the hop record shape**

Propose and justify a concrete shape. A reasonable starting point, which you should adjust based on what you actually learn writing Task 2's proof-of-concept rather than treating as fixed in advance:

```js
{
  kind: 'production' | 'selection' | 'write-out',  // which of the three existing hop TYPES this is
  subKind: string,   // which specific case, e.g. 'ident', 'object', 'assign', 'return' — for debugging/DAG-node-typing later
  fromPath: string | null,   // source access path, if this hop has one (null when there's no prior path, e.g. a hop originating at a fresh object literal with no aliasing base)
  toPath: string | null,     // destination access path, if this hop has one (null for a hop with no "landing" location, e.g. a `return` — it exits the function, not a path)
  dataElementId: string,     // ONE hop record per identity, not per Set — see the decision note below
  nodeId: string,            // the CFG node id where this hop was recorded
  line: number,
  widened: boolean,          // carries the engine's existing widened flag through for free — this is FR-306's raw material
}
```

Document explicitly (as its own decision, with reasoning, in the ADR): **why one hop record per `dataElementId`, not one record carrying a `Set` of ids.** (Reasoning to evaluate, confirm or revise: keeping hops atomic and per-identity is what lets a LATER path-reconstruction query distinguish "these two distinct data elements took the same structural route" from "this one route carries N elements" — collapsing to a Set-valued hop would just defer this explosion to path-reconstruction time instead of recording it once, up front, and risks silently merging two elements' provenance the same way Sub-project A's own six rounds fought hard to prevent at the STATE level. If your own investigation in Task 2 finds a good reason to revise this, revise it and document why.)

- [ ] **Step 3: Resolve and document the accumulator injection mechanism**

Document the exact function-signature changes: how a caller opts in (an object parameter alongside/inside the existing `ctx`, e.g. `ctx.recordHop(hopRecord)` as an optional callback — mirror the EXACT pattern `ctx.resolveCallSummary` already established in Sub-project B increment 2, for consistency, unless you find a concrete reason it doesn't fit), and confirm/document that every existing recursive call site inside `resolveExprIdentities` and `step()` already threads `ctx` through unconditionally — meaning the SAME threading already carries a hop recorder with zero additional plumbing, once one case is instrumented to call it.

- [ ] **Step 4: Document the explicit checklist for full coverage (for increment C2, not this plan)**

List every one of `resolveExprIdentities`'s cases and `step()`'s CFG-node cases (already enumerated in this plan's Global Constraints) with a one-line note on which hop TYPE(s) each one represents and what its `fromPath`/`toPath` would be — this is the checklist increment C2 executes in full. Do not implement all of them here; this is planning material for the NEXT increment, produced now while the design is fresh, matching the precedent `DESIGN_INTRAPROCEDURAL.md` itself set (a design note that explicitly scopes out what's deferred, not silent about it).

- [ ] **Step 5: Self-review against Sub-project A's own hard-won lessons**

Before finishing, check this design against the SAME three failure patterns that let bugs survive multiple rounds of Sub-project A's own review (documented in `scanner/src/lineage/CLAUDE.md`): (1) a fixed-count claim about how many sites need instrumentation (don't hand-count; state the enumeration principle instead — "every case in the switch," not "these N cases"); (2) limiting the check to `resolveExprIdentities`'s own switch and forgetting `step()`'s CFG-node cases sit outside it; (3) assuming every path component is a real, distinct property name rather than an explicitly-modeled unknown (`'*'`) — does a hop record for a wildcard-write (`bag[k] = ...`) need special handling, or does `toPath` naturally carry the `'*'`-suffixed path already, same as the existing write-out logic? Document the answer.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/DESIGN_PATH_PROVENANCE.md
git commit -m "docs(lineage): design spike for path provenance recording (Sub-project C, increment 1, Task 1)"
```

---

## Task 2: Minimal proof-of-concept against real parsed code

**Files:**
- Modify: `scanner/src/lineage/engine.js`
- Test: `scanner/test/lineage/engine-provenance.test.js` (NEW FILE)

**Interfaces:**
- Consumes: Task 1's design note (this same plan) as the binding spec for the shape/mechanism — if Task 1's own design turns out to be wrong or incomplete once you try to implement it for real, fix Task 1's document too (with a clear note on what changed and why) rather than silently diverging code from doc.
- Produces: a working, tested proof that the accumulator mechanism functions end-to-end against real parsed JS/TS source, covering a deliberately small, representative subset of hop sites — NOT full coverage (that's increment C2).

- [ ] **Step 1: Choose the representative subset**

Instrument exactly these four sites (a deliberately minimal but genuinely representative slice — one intraprocedural production case, the write-out case that stores an identity, and the case that marks a function's exit, which any future interprocedural stitching will need):

1. `resolveExprIdentities`'s `case 'ident'` — the simplest production case (a value flows verbatim from one path to the read site).
2. `resolveExprIdentities`'s `case 'object'` — production case for a freshly-constructed structured value (no `fromPath`, since a literal has no prior aliasing source — confirm this against Task 1's design and adjust `fromPath: null`'s semantics if reality disagrees).
3. `step()`'s `case 'assign'` (the normal, non-wildcard write-out branch only — skip the wildcard-write branch for this POC, that's part of C2's fuller coverage) — the hop that actually STORES an identity at a target path.
4. `step()`'s `case 'return'` — the hop that marks an identity reaching the function's exit (no `toPath`, per Task 1's design).

- [ ] **Step 2: Write the failing tests**

Create `scanner/test/lineage/engine-provenance.test.js`. Cover, at minimum:
- Calling `resolveExprIdentities`/`analyzeFunctionFieldIdentity` with NO hop-recorder present produces byte-identical results to calling them today (a regression guard proving the mechanism is genuinely opt-in) — pick one existing scenario from `engine-integration.test.js` and confirm identical output with/without this task's changes present in the file (i.e., confirm the OLD call signature/behavior is unaffected).
- A real, parsed JS/TS example (via `parseJsFile`) exercising all four instrumented sites in one function — e.g. something shaped like `function f(user) { const u = user; const o = { email: u.email }; return o; }` — with a hop recorder supplied, asserting the recorded hops are correct and complete for exactly those four sites: an `ident`-kind hop for `u = user`-equivalent, an `object`-kind hop for the object literal's construction, an `assign`-kind write-out hop for each `const` binding this shape lowers to, and a `return`-kind hop for the final return.
- Confirm hop records are genuinely PER-IDENTITY, not per-Set, using a scenario with 2+ distinct identities flowing through the same construct (e.g. `{email: u.email, ssn: u.ssn}`) — assert you get 2 separate hop records, not 1 carrying both ids.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/engine-provenance.test.js`
Expected: FAIL (nothing implemented yet).

- [ ] **Step 4: Implement**

Wire the accumulator into the four sites per Task 1's design, threading it exactly the way `ctx` already flows through every existing recursive call (no new plumbing beyond what Sub-project B's increment 2 already established as the pattern).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/engine-provenance.test.js`
Expected: PASS.

- [ ] **Step 6: Confirm zero regression to every pre-existing test**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 211 prior + this task's new tests, with EVERY pre-existing test file showing zero diff (`git diff --stat` should show only `engine.js` modified among source files, plus the one new test file — confirm no existing test file was touched).

- [ ] **Step 7: Wire the new test file into `test:lineage`**

`scanner/package.json`'s `test:lineage` script is an explicit file list (confirmed in a prior increment, not a glob) — add `test/lineage/engine-provenance.test.js` to it.

- [ ] **Step 8: Confirm the isolation principle still holds**

Run: `grep -n "from '../dataflow/engine\|from '../dataflow/summaries" scanner/src/lineage/engine.js`
Expected: no output.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/test/lineage/engine-provenance.test.js scanner/package.json
git commit -m "feat(lineage): minimal proof-of-concept for hop-based path provenance recording (Sub-project C, increment 1, Task 2)"
```

---

## Post-implementation: update `scanner/src/lineage/CLAUDE.md`

After both tasks are reviewed and clean:
- Add a new "Milestone 1, Sub-project C, increment 1 (path provenance design spike)" section, following the exact style/rigor of the existing Sub-project A/B sections — this document's own convention is extensive, worked-example-backed documentation, not a one-line stub.
- Point to `DESIGN_PATH_PROVENANCE.md` as the binding design reference for future Sub-project C increments, the same way `DESIGN_INTRAPROCEDURAL.md` is pointed to for Sub-project A.
- Update "What is NOT here yet" to reflect that Sub-project C has now started (increment C1 done; C2 through C6 per the scoping doc — do not claim more than C1 delivers).

This is not a separate task — fold it into a final `docs(lineage): ...` commit after both tasks, matching the established pattern from every prior increment in Sub-projects A and B.
