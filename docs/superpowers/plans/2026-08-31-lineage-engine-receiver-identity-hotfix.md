# Lineage Engine Hotfix: Unresolved-Call Receiver Identity

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix a real, measured bug in `scanner/src/lineage/engine.js`'s unresolved-`call` handling: it unions field-identity from a call's arguments (`expr.args`) but never from the RECEIVER of a method call (`expr.callee.object` when `expr.callee.kind === 'member'`), silently dropping an identity that flows through a method call on it. `pan.slice(0, 4)` loses `pan`'s identity entirely; `pan + 'x'` and `String(pan)` keep it. This makes `bench/data-lineage/fixtures/js-api-to-log-masked` — the lineage corpus's own mask-then-log fixture, AC-02's worked example — produce ZERO flows through the shipped engine. This bug was found and precisely characterized (including a proven, narrow fix and a proven zero-regression blast radius) during Sub-project E, increment E1's design spike; this hotfix applies that fix as its own reviewed increment, sequenced before Sub-project E's E2 so the fix lands before E1's own PoC tests (which currently pin the buggy numbers) get absorbed into permanent suites.

**Architecture:** A minimal, additive change to one `case 'call'` branch in `engine.js`. `dataflow/engine.js` (the sibling taint engine) already solves this exact problem via `_calleeReceiverTainted`; this package never inherited that precedent. This fix does not need to port that mechanism wholesale — only to union the receiver's own resolved identities into the unresolved-call's flat result, the same way arguments already are.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** The exact bug location and fix were already found and verified during Sub-project E's E1 review (`.superpowers/sdd/2026-08-31-data-flow-explorer-m1-subproject-e1/`, not committed — an SDD working artifact; read `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` §11 instead, which records this escalation as shipped documentation) — `engine.js`'s `resolveExprIdentities`, the unresolved branch of `case 'call'`, currently around lines 538-542 (line numbers may have shifted; find it by reading the file, not by trusting this plan's line numbers). Also read `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md` in full — this is the binding ADR `engine.js` was built against, and any change to it must respect the invariants that document already hardened (the "structure-preserving vs. structure-flattening" distinction in particular: is a call's receiver's identity something this fix should preserve `byPath` structure for, or only union flatly? Read the ADR's own reasoning for `call`'s existing args-handling to decide, don't invent a new rule).

## Global Constraints

- This is a narrow, additive fix to ONE branch of ONE function in `engine.js`. Do not refactor, rename, or restructure anything else in the file.
- Must NOT modify `field-identity.js` (the state shape itself is untouched by this fix — confirmed by the E1 review's own investigation).
- Must NOT modify `summaries.js`, `driver.js`, `path-store.js`, `path-query.js`, `flow-grade.js`, any Sub-project D registry, or any Sub-project D/E test file, EXCEPT where Sub-project E's own E1 PoC tests currently pin the buggy (pre-fix) numbers — those specific tests are allowed and expected to change as a DIRECT, disclosed consequence of this fix (see Step 3), never silently.
- The fix must be proven, by running the real parser, to correctly resolve a case like `pan.slice(0, 4)` retaining `pan`'s identity — not just asserted from reading the diff.
- The fix must be proven to cause ZERO regressions in every pre-existing Sub-project A/B/C/D test — the E1 review's own investigation found exactly this fix produces 460/464 with the ONLY 4 failures being Sub-project E's own not-yet-absorbed PoC tests that pin the pre-fix numbers (see Step 3). Reproduce this yourself; do not assume the review's own number is still exactly current, since other work may have landed since.
- Follow this repo's root `CLAUDE.md` verification discipline throughout — every claim about "what this fixes" and "what stays unaffected" must come from running real code in this task.

---

### Task 1: Fix the receiver-identity gap, prove it, and update the four affected E1 PoC tests

**Files:**
- Modify: `scanner/src/lineage/engine.js` (the fix itself)
- Modify: `scanner/test/lineage/graph-builder-poc.test.js` (the 3-4 E1 PoC tests whose numbers move as a direct, disclosed consequence — E1/4, E1/6, E1/13's pinned counts, and E1/14 which currently pins the BUG's existence and must now assert the bug is FIXED, per Sub-project E's own absorption-protocol note that E1/14 is about "seeding reaching a sink")
- Modify: `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` (§11's escalation entry — mark it RESOLVED, with the commit reference, rather than leaving it recorded as an open escalation)
- Read only: `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md` (in full — the binding ADR for this file's own invariants), `scanner/src/dataflow/engine.js`'s `_calleeReceiverTainted` (the sibling engine's own solution to the analogous problem, read for structural precedent only — do not import anything from `dataflow/`), `bench/data-lineage/fixtures/js-api-to-log-masked/` (the fixture this bug currently breaks), `scanner/test/lineage/engine-provenance.test.js` and `engine-integration.test.js` (the existing regression suites this change must not break).

**Interfaces:**
- Consumes: nothing new.
- Produces: no new exports — `resolveExprIdentities`'s existing signature and return shape are unchanged; only its unresolved-call branch's internal behavior changes.

- [ ] **Step 1: Read `engine.js`'s unresolved-`call` branch, `DESIGN_INTRAPROCEDURAL.md`'s reasoning for `call`, and `dataflow/engine.js`'s `_calleeReceiverTainted`**

Confirm the exact current location and shape of the bug (line numbers may have moved since E1's own investigation). Confirm `DESIGN_INTRAPROCEDURAL.md`'s own stated rule for why `call` is currently a "structure-flattening" case (flat + `widened: true`, never `byPath`) — decide whether the receiver's identities should be unioned into the SAME flat result (matching how `expr.args` already are), or whether the receiver deserves `byPath` treatment. The E1 review's own finding (`obj.f(pan)`: the arg carries structure, the receiver drops entirely) suggests receiver identities should be unioned the SAME way argument identities already are — flat, into the unresolved call's own flat result — but confirm this is consistent with the ADR's own invariant before implementing, don't assume.

- [ ] **Step 2: Implement the fix**

In the unresolved branch of `case 'call'`: when `expr.callee.kind === 'member'`, recursively resolve `expr.callee.object` (the receiver) via `resolveExprIdentities`, and union its `flat` identities into the branch's own `flat` result, the same way each argument's `flat` identities already are. Confirm via a real-parser test that `pan.slice(0, 4)` inside a function that also does something with `pan` downstream now KEEPS `pan`'s identity (mirroring the E1 review's own verification: `pan.slice(0,4)` → previously `[]`, now must equal what `pan + 'x'` already correctly returns).

- [ ] **Step 3: Run the full lineage suite, and update the E1 PoC tests whose numbers move as a direct, disclosed consequence**

Run `npm run test:lineage` from `scanner/`. Confirm the failure set is EXACTLY the Sub-project E E1 PoC tests that pin pre-fix numbers (as of this plan's writing: `E1/4`, `E1/6`, `E1/13` in `graph-builder-poc.test.js`, which pin now-stale hop/node/ledger counts, and `E1/14`, which currently asserts the bug's existence) — if any OTHER test fails, STOP and investigate; that would mean the fix has a wider blast radius than the E1 review measured, and this task must not proceed past that without understanding why. For each of the (expected) four failing tests: re-measure the correct post-fix number by running the real code yourself (do not guess or extrapolate from this plan's own text), update the test's pinned assertion to the new correct value, and update `E1/14` specifically to assert the FIX (e.g. that `js-api-to-log-masked` now produces a non-zero path count, matching the receiver-free control fixture's own structure) rather than the bug. Add a one-line comment at each updated assertion noting which commit/task fixed the underlying number, so a future reader isn't confused by a "why did this number change" question with no trail.

- [ ] **Step 4: Update `DESIGN_GRAPH_BUILDER.md` §11's escalation entry**

Find the escalation entry recording this bug (§11, "escalates five things E cannot fix" per the CLAUDE.md's own summary of that section). Mark it RESOLVED — state the fix's exact mechanism (receiver identity unioned into the unresolved call's flat result), the commit hash once committed, and that Sub-project E's E1 PoC tests were updated as a direct, disclosed consequence (per Step 3) rather than being silently left stale.

- [ ] **Step 5: Run the full scoped suites and doc-drift check**

```bash
cd scanner
npm run test:lineage
npm run test:dataflow
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/test/lineage/graph-builder-poc.test.js scanner/src/lineage/DESIGN_GRAPH_BUILDER.md
git commit -m "fix(lineage): resolve unresolved-call receiver identity in engine.js (found during Sub-project E1)"
```
