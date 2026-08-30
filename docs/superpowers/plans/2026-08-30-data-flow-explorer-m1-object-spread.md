# Data Flow Explorer Milestone 1: Object Spread/Rest Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the known, documented limitation flagged in `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md`'s object-spread bullet — object spread (`{...user}`) and object rest (`const {...rest} = user`) are silently dropped entirely by `scanner/src/ir/parser-js.js`, a real FR-301/FR-306 violation (a false negative — the identity vanishes, not merged, not flattened) confirmed pre-existing since the parser's first commit. Fix both, reusing the field-identity engine's already-built, already-tested wildcard machinery (rounds 5/6 of the prior plan) wherever it applies, and verify the fix's effect on the SHARED taint engine (`scanner/src/dataflow/`), which consumes the same parser and was independently confirmed to have the identical blindness.

**Architecture:** Both fixes are small, precise, parser-level changes (`scanner/src/ir/parser-js.js`) plus one new branch in the lineage engine's already-existing `resolveExprIdentities`'s `object` case (`scanner/src/lineage/engine.js`). No new design spike is needed — the fix was fully worked out in a research pass before this plan was written (see each task's Interfaces section for the exact reasoning). The destructuring-rest fix requires ZERO lineage-engine changes: it reuses the wildcard-selection mechanism rounds 5/6 already built and tested (`obj[k]` — a statically-unknown computed key resolves the container's aggregate, flagged widened) by representing a rest binding's source as the identical `{kind:'member', object: <source>, prop: '*'}` shape. The spread fix requires one new, small branch in the lineage engine, plus a parser change that changes NOTHING about existing behavior for non-spread properties.

**Tech Stack:** Same as the parent plan — plain ESM, Node's built-in `node:test`, the real Babel-based JS/TS parser (`@babel/core`).

**Spec:** `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`'s "Update, post-implementation" note (records this as an explicit follow-up item from Sub-project A). `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md`'s object-spread bullet (the known-limitation note this plan closes). Read `scanner/src/lineage/CLAUDE.md` and `scanner/src/dataflow/CLAUDE.md` before starting.

## Global Constraints

- **This touches shared parser infrastructure** (`scanner/src/ir/parser-js.js`), consumed by both `scanner/src/lineage/` and `scanner/src/dataflow/` (the taint engine). Every task in this plan must run BOTH `npm run test:lineage` AND `npm run test:dataflow` — a change here that only checks `test:lineage` is not verified.
- **Every consumer of `ObjectExpression`'s `props` array outside `scanner/src/lineage/` was audited before this plan was written** — confirmed (via `grep -rn "\.props\b\|prop\.key\|p\.key\b" scanner/src/dataflow/*.js scanner/src/sast/*.js`) that `scanner/src/dataflow/engine.js` (lines 359, 430-431, 628, 647), `scanner/src/dataflow/higher-order.js` (line 186-187), and `scanner/src/dataflow/privacy-deep-walker.js` (line 129) all read ONLY `p.value`, never `p.key` — so a spread property's new shape (`{spread: true, value: <expr>}`, no `key` field) is compatible with every existing consumer without any changes there, and several of them will gain correct taint/privacy detection through object spread as a natural side effect (previously: `sink({...tainted})` was invisible to the taint engine, since the property carrying `tainted` was filtered out of `props` before any consumer ever saw it). Re-confirm this audit is still accurate before implementing — do not trust this plan's citation blindly if the file has changed since this plan was written.
- **Do not touch array spread/rest in this plan.** `[...xs]` (array spread) is already handled — `exprOf`'s `SpreadElement` case unwraps it transparently, a deliberate, already-documented design choice (see `DESIGN_INTRAPROCEDURAL.md`'s array-literal bullet). Array DESTRUCTURING rest (`const [a, ...rest] = arr`) has a separate, lower-severity imprecision (rest currently gets attributed to one specific array index rather than "everything from there on") that this plan does not fix — array handling's imprecision is already an accepted, documented limitation, and this narrower array-rest quirk is a further degree of that same accepted imprecision, not the "silently vanishes entirely" failure mode object spread/rest has. Note it in this plan's final docs update as an out-of-scope observation, do not fix it.
- **Run `cd scanner && npm run test:lineage`, `npm run test:dataflow`, `npm run test:sast`, and `npm run test:smoke` after every task** and report the exact pass/fail count from the run you just executed. The broader test scripts matter here specifically because this plan touches shared parser infrastructure real scans depend on.
- **No placeholders, no invented pseudocode presented as real.** This plan's code was verified against the real files before being written into task briefs — implementers should still re-read the current file state before editing, since line numbers may have shifted.

---

## Task 1: Fix object rest in destructuring (`const {a, ...rest} = user`)

**Files:**
- Modify: `scanner/src/ir/parser-js.js`
- Test: `scanner/test/lineage/engine-integration.test.js` (real-parser integration test)
- Test: `scanner/test/parser-js.test.js` or the nearest existing parser-level test file for this construct if `test/lineage/` isn't the right home for a taint-engine-facing assertion — check what test file already covers destructuring/rest-adjacent parser behavior and add there too if appropriate (see Step 4)

**Background:** `lhsPath`'s `ObjectPattern` branch (currently around line 213-224 — re-read it, line numbers may have shifted) already calls the shared `resolveObjectKey(p)` helper (built in round 5/6 of the parent plan) for every property in the pattern, including a `RestElement` node — and `resolveObjectKey` ALREADY correctly returns `'*'` for a `RestElement` (it has no `.key`/`.computed`, so `resolveObjectKey`'s else-branch falls through to its `'*'` default). The ONLY bug: the `alias` field is built via `lhsPath(p.value)` — but a `RestElement` node has NO `.value` property; its bound identifier lives at `.argument`. So `lhsPath(p.value)` evaluates to `lhsPath(undefined)`, which returns `null` (per `lhsPath`'s own first line: `if (!n) return null;`). Confirm this yourself by reading the current `lhsPath` code and Babel's `RestElement` AST shape before proceeding — do not trust this paragraph blindly.

The CONSUMER of this shape (the `VariableDeclarator` visitor's `object-pattern` handling, currently around line 499-508) already does `const alias = typeof p.alias === 'string' ? p.alias : null; if (!alias) continue;` — with `alias` currently always `null` for a rest property, this loop silently SKIPS it, emitting no CFG node at all. Once `alias` correctly resolves to the rest variable's name, this SAME existing loop will automatically emit `{ kind: 'assign', target: '<rest-var-name>', source: { kind: 'member', object: initExpr, prop: '*' } }` — no changes needed to the consumer at all, since `p.key` is already `'*'` for a rest property.

**This `{kind:'member', object: initExpr, prop:'*'}` shape is EXACTLY the same shape a computed-unknown-key read (`obj[k]`) already produces**, and rounds 5/6 of the parent plan already built and tested (via mutation testing) the machinery that correctly resolves it: `scanner/src/lineage/engine.js`'s `resolveExprIdentities`, `case 'member':`, path-succeeds branch, already special-cases a path ending in `.*` (and, since round 6, ANY position of `*` in the path) by resolving the CONTAINER's full aggregate via `identitiesAt` and flagging the result `widened: true`. This is exactly the correct, safe, sound behavior for a rest binding: it conservatively includes ALL of the source object's fields (a real over-approximation, since real JS `rest` technically excludes whatever was destructured by name elsewhere in the same pattern — e.g. `const {email, ...rest} = user` should exclude `email` from `rest`, but this fix's `rest` will include it too) — this over-approximation is the deliberate, documented, SAFE direction (never drops a real flow; occasionally reports one extra field that technically shouldn't be there), consistent with this whole plan's established philosophy throughout the parent plan's 6 rounds. Excluding sibling-destructured keys precisely would require tracking the full set of named bindings in the same pattern before processing the rest element — real, non-trivial extra complexity, explicitly out of scope for this fix.

**Interfaces:**
- Consumes: `resolveObjectKey(p)` (already exists, unchanged), `lhsPath` (modified by this task), the EXISTING wildcard-selection machinery in `resolveExprIdentities`'s `member` case (already exists, unchanged — this task's whole point is that no engine-level code needs to change).
- Produces: nothing new for other code — this is a parser-only fix whose effect is observed end-to-end via `analyzeFunctionFieldIdentity`.

- [ ] **Step 1: Confirm the current behavior is broken, with a failing test, via the real parser**

Add to `scanner/test/lineage/engine-integration.test.js` (read the file first to match its existing helper/import style exactly):

```js
test('object rest in destructuring binds to the source object\'s full aggregate, flagged widened (fixes a documented, pre-existing gap: rest was previously silently dropped entirely)', () => {
  const src = `
    function f(user) {
      const { email, ...rest } = user;
      return rest;
    }
  `;
  const fn = /* parse and extract `f`, mirroring this file's existing helper usage exactly */;
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  // `rest` conservatively includes BOTH fields (the safe over-approximation
  // this task's brief documents — real JS would exclude `email`, but this
  // fix does not attempt that precision) and the read is flagged widened.
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn']);
});
```

Run: `cd scanner && node --test test/lineage/engine-integration.test.js`
Expected: FAIL — `rest` currently carries nothing (`returnFacts` empty or missing this entry), confirming the pre-fix bug for real.

- [ ] **Step 2: Fix `lhsPath`'s `ObjectPattern` branch in `scanner/src/ir/parser-js.js`**

Find the current code (re-read it — do not assume the exact current line numbers or byte-for-byte text match what's quoted below without checking):

```js
if (n.type === 'ObjectPattern') {
  return { kind: 'object-pattern', props: (n.properties || []).map(p => ({
    key: resolveObjectKey(p),
    alias: lhsPath(p.value),
  }))};
}
```

Change the `alias` computation to use `.argument` for a `RestElement`, `.value` for everything else:

```js
if (n.type === 'ObjectPattern') {
  return { kind: 'object-pattern', props: (n.properties || []).map(p => ({
    key: resolveObjectKey(p),
    // A `RestElement` (`const {a, ...rest} = obj`) has its bound
    // identifier at `.argument`, not `.value` (only a real `ObjectProperty`
    // has `.value`) — using `.value` unconditionally here made `lhsPath`
    // resolve to `null` for every rest binding, so the consumer's
    // `if (!alias) continue;` guard silently skipped it entirely (a real,
    // pre-existing FR-306 violation: the rest binding vanished with no
    // trace, not merged, not flattened — a final review of an earlier
    // plan found and documented this, not fixed then).
    // `resolveObjectKey(p)` already correctly resolves to `'*'` for a
    // RestElement (it has no `.key`/`.computed`), which is exactly the
    // right marker: the consumer already treats a `'*'`-keyed destructured
    // binding as a computed-unknown-key selection
    // (`{kind:'member', object: initExpr, prop: '*'}`), and the lineage
    // engine's existing wildcard-selection machinery (built for `obj[k]`)
    // already resolves that correctly — conservatively aggregating the
    // source's full field set, flagged widened. No engine-level change
    // needed for this fix.
    alias: lhsPath(p.type === 'RestElement' ? p.argument : p.value),
  }))};
}
```

- [ ] **Step 3: Run the test from Step 1 to verify it now passes**

Run: `cd scanner && node --test test/lineage/engine-integration.test.js`
Expected: PASS.

- [ ] **Step 4: Check whether the taint engine (`scanner/src/dataflow/`) also has a rest-related test gap worth closing**

Search `scanner/test/` for any existing test covering object rest destructuring in the taint engine's own test suite (e.g. `grep -rln "\.\.\.rest\|RestElement" scanner/test/`). If one exists and currently expects the "rest is dropped" behavior, it may need updating (confirm what it actually asserts before touching it — don't assume). If none exists, decide whether to add one to whatever the closest existing taint-flow test file is (e.g. `scanner/test/container-taint.test.js` or similar — check what covers destructuring today) proving `const {a, ...rest} = source; sink(rest);` now flows taint where it previously didn't. Use your judgment on whether this is warranted scope for this task — a quick, real-parser `runScan`-style test proving the taint engine gained recall here (not just that it didn't regress) is valuable evidence this fix has the intended cross-engine effect, but don't let this expand into unrelated taint-engine work.

- [ ] **Step 5: Run the full relevant test suites**

Run: `cd scanner && npm run test:lineage` — expect all prior tests plus Step 1's new test, 0 failures.
Run: `cd scanner && npm run test:dataflow` — expect 0 failures, 0 regressions (this is the critical check given the shared parser).
Run: `cd scanner && npm run test:sast` — expect 0 failures.
Run: `cd scanner && npm run test:smoke` — expect 0 failures.
Report every exact count from the runs you just executed.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/ir/parser-js.js scanner/test/lineage/engine-integration.test.js
git commit -m "fix(ir,lineage): object rest in destructuring binds to the source's field aggregate instead of vanishing"
```

---

## Task 2: Fix object spread in object literals (`{...user}`)

**Files:**
- Modify: `scanner/src/ir/parser-js.js`
- Modify: `scanner/src/lineage/engine.js`
- Test: `scanner/test/lineage/engine-expr-resolver.test.js` (hand-built state/expr — the object-literal spread mechanics)
- Test: `scanner/test/lineage/engine-integration.test.js` (real parser)

**Background:** `ObjectExpression`'s prop-building code (currently around line 116-139 — re-read it, do not assume the exact current text) filters `n.properties` to `p.type === 'ObjectProperty'` only, discarding `SpreadElement` nodes entirely — `{...user}` and `{}` are byte-identical in the emitted IR. This is a genuine, pre-existing, undocumented-until-now false negative: `return {...user};` currently resolves to no identity at all, even though `const c = user; return c;` (the exact same semantic content, different syntax) correctly resolves to everything `user` carries.

**The fix has two parts — a parser change and a new lineage-engine branch.**

**Part A — parser (`scanner/src/ir/parser-js.js`'s `ObjectExpression` case)**: represent a spread element as its own distinct property shape (`{spread: true, value: <resolved spread expression>}`, no `key` field) instead of filtering it out. Find the current code:

```js
case 'ObjectExpression':  return {
  kind: 'object',
  props: (n.properties || []).filter(p => p.type === 'ObjectProperty' && p.key).map(p => ({
    key: resolveObjectKey(p),
    value: exprOf(p.value),
  })),
};
```

Change to:

```js
case 'ObjectExpression':  return {
  kind: 'object',
  // A `SpreadElement` (`{...user}`) previously fell out of the `.filter`
  // entirely — `{...user}` and `{}` were byte-identical in the emitted
  // IR, a real, pre-existing false negative (the identity vanishes, not
  // merged, not flattened — found and documented but not fixed by a
  // final review of an earlier plan). Represented here as a distinct
  // `{spread: true, value: <expr>}` shape (no `key` field) rather than a
  // regular `{key, value}` property, so `scanner/src/lineage/engine.js`'s
  // `resolveExprIdentities` can merge the spread source's OWN field
  // structure directly into this object's structure (see that file for
  // the full mechanism) — a DIFFERENT, more precise handling than a
  // computed-unknown-key property gets (that case folds into one opaque
  // residual bucket; a spread's contents are fully known, just not yet
  // assigned a key in THIS literal, so they can and should stay
  // field-distinguished). Every consumer of `expr.props` outside this
  // package (scanner/src/dataflow/engine.js, higher-order.js,
  // privacy-deep-walker.js — audited before this change) reads only
  // `p.value`, never `p.key`, so this shape is compatible with all of
  // them without any change there — and several gain correct taint/
  // privacy detection through object spread as a direct result, since
  // the spread's value is no longer silently absent from `props`.
  props: (n.properties || []).map(p => {
    if (p.type === 'SpreadElement') return { spread: true, value: exprOf(p.argument) };
    if (p.type !== 'ObjectProperty' || !p.key) return null;
    return { key: resolveObjectKey(p), value: exprOf(p.value) };
  }).filter(Boolean),
};
```

**Part B — lineage engine (`scanner/src/lineage/engine.js`'s `resolveExprIdentities`, `case 'object':`)**: handle a `prop.spread` property by merging its resolved `byPath` directly into the containing object's own `byPath` (at the TOP level — spreading copies properties as top-level siblings, not nested under a key), rather than treating it like a normal named property. Find the current code (from round 5's fix c — re-read it, confirm the exact current text before editing):

```js
case 'object': {
  const flat = new Set();
  const byPath = new Map();
  for (const prop of expr.props) {
    const r = resolveExprIdentities(state, prop.value);
    for (const id of r.flat) flat.add(id);
    if (prop.key === '*') {
      continue;
    }
    const propResidual = residualFlat(r.flat, r.byPath);
    if (propResidual.size > 0) {
      const existing = byPath.get(prop.key) ?? new Set();
      byPath.set(prop.key, new Set([...existing, ...propResidual]));
    }
    for (const [subPath, ids] of r.byPath) {
      const fullPath = `${prop.key}.${subPath}`;
      const existing = byPath.get(fullPath) ?? new Set();
      byPath.set(fullPath, new Set([...existing, ...ids]));
    }
  }
  return { flat, byPath, widened: false };
}
```

Add a spread branch BEFORE the `prop.key === '*'` check (a spread property has no `.key` at all, so it must be handled first, distinctly):

```js
case 'object': {
  const flat = new Set();
  const byPath = new Map();
  for (const prop of expr.props) {
    const r = resolveExprIdentities(state, prop.value);
    for (const id of r.flat) flat.add(id);
    if (prop.spread) {
      // Object spread ({...src}) copies ALL of src's own properties onto
      // this object as TOP-LEVEL siblings — merge the spread source's
      // byPath structure directly into this object's own byPath,
      // preserving field-level distinctness (a spread's contents are
      // fully known, unlike a computed-unknown-key property, which is
      // why this is a different branch from the `prop.key === '*'` case
      // below, not the same one).
      for (const [subPath, ids] of r.byPath) {
        const existing = byPath.get(subPath) ?? new Set();
        byPath.set(subPath, new Set([...existing, ...ids]));
      }
      continue;
    }
    if (prop.key === '*') {
      continue;
    }
    const propResidual = residualFlat(r.flat, r.byPath);
    if (propResidual.size > 0) {
      const existing = byPath.get(prop.key) ?? new Set();
      byPath.set(prop.key, new Set([...existing, ...propResidual]));
    }
    for (const [subPath, ids] of r.byPath) {
      const fullPath = `${prop.key}.${subPath}`;
      const existing = byPath.get(fullPath) ?? new Set();
      byPath.set(fullPath, new Set([...existing, ...ids]));
    }
  }
  return { flat, byPath, widened: false };
}
```

**Interfaces:**
- Consumes: `resolveExprIdentities` (recursive self-call, already exists), `residualFlat`/`unionOfByPath` (already exist from round 2, unchanged).
- Produces: nothing new for other code — `object`'s existing `{flat, byPath, widened}` output contract is unchanged in shape, just more complete for spread-containing object literals.

- [ ] **Step 1: Write failing tests, both levels, before implementing**

Add to `scanner/test/lineage/engine-expr-resolver.test.js` (hand-built state/expr, mirror the file's existing style):

```js
test('an object literal spread merges the source\'s fields as top-level siblings, preserving field-level distinctness (fixes a documented, pre-existing gap: spread was previously silently dropped entirely)', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn']]);
  const expr = { kind: 'object', props: [{ spread: true, value: { kind: 'ident', name: 'user' } }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:email', 'data:ssn']);
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
});

test('a spread combined with an explicit named property both contribute, without collapsing into one coarse fact', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn'], ['other.name', 'data:name']]);
  const expr = {
    kind: 'object',
    props: [
      { spread: true, value: { kind: 'ident', name: 'user' } },
      { key: 'name', value: { kind: 'member', object: { kind: 'ident', name: 'other' }, prop: 'name' } },
    ],
  };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
  assert.deepEqual([...r.byPath.get('name')], ['data:name']);
});
```

Run: `cd scanner && node --test test/lineage/engine-expr-resolver.test.js` — expect FAIL (spread not yet handled — `prop.spread` doesn't exist as a recognized case yet, so these tests either throw or produce empty `byPath`).

Add to `scanner/test/lineage/engine-integration.test.js` (real parser):

```js
test('object spread in a real parsed object literal keeps fields isolated, matching the equivalent explicit-property form (regression for a documented gap)', () => {
  const src = `
    function combine(user) {
      const c = { ...user };
      return c.email;
    }
  `;
  const fn = /* parse and extract `combine`, mirror this file's existing helper usage */;
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'spreading user into c must not merge ssn into an email-only read');
});

test('returning a spread object directly aggregates every field (complementary to the isolation test above)', () => {
  const src = `
    function combine(user) {
      return { ...user };
    }
  `;
  const fn = /* ... */;
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn']);
});
```

Run: `cd scanner && node --test test/lineage/engine-integration.test.js` — expect the two new tests to FAIL against the pre-fix code (confirm this for real, don't assume).

- [ ] **Step 2: Implement Part A (parser change) exactly as specified above**

- [ ] **Step 3: Implement Part B (lineage-engine `object` case change) exactly as specified above**

- [ ] **Step 4: Run all four new tests to verify they now pass**

Run: `cd scanner && node --test test/lineage/engine-expr-resolver.test.js test/lineage/engine-integration.test.js`
Expected: PASS, all new tests, plus everything pre-existing still passing.

- [ ] **Step 5: Verify the taint-engine side effect is real and correct, not just "doesn't crash"**

Write a quick, throwaway `node -e` script (do not commit it) that parses a small real source snippet like:
```js
function sink(x) {}
function f(req) {
  const body = { ...req.query };
  sink(body);
}
```
through `scanner/src/dataflow/engine.js`'s real taint analysis path (find the right entry point — check how existing `scanner/test/dataflow/*.test.js` files invoke a scan, e.g. via `runScan` against a temp file, matching the established pattern from earlier work on this parser) and confirm `req.query`'s taint now genuinely reaches `sink`'s argument through the spread — this is the concrete proof the cross-engine fix works, not just that nothing broke. Report what you found in your task report, including the exact snippet and result. If you find the taint engine does NOT pick this up (e.g. some other gate blocks it), investigate why and report clearly rather than asserting success — do not claim this works without having actually observed it.

- [ ] **Step 6: Run the full relevant test suites**

Run: `cd scanner && npm run test:lineage` — expect 0 failures.
Run: `cd scanner && npm run test:dataflow` — expect 0 failures, 0 regressions (critical, given the shared parser and engine.js changes touching how taint flows through spread now).
Run: `cd scanner && npm run test:sast` — expect 0 failures.
Run: `cd scanner && npm run test:smoke` — expect 0 failures.
Report every exact count from the runs you just executed.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/ir/parser-js.js scanner/src/lineage/engine.js scanner/test/lineage/engine-expr-resolver.test.js scanner/test/lineage/engine-integration.test.js
git commit -m "fix(ir,lineage): object spread merges the source's fields instead of vanishing entirely"
```

---

## Task 3: Update documentation to reflect both fixes

**Files:**
- Modify: `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md`
- Modify: `scanner/src/lineage/CLAUDE.md`
- Modify: `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Rewrite `DESIGN_INTRAPROCEDURAL.md`'s object-spread bullet**

The current bullet (added when this gap was found and deliberately left unfixed) says object spread/rest is a "KNOWN, UNFIXED LIMITATION." Rewrite it to describe the fix: spread merges the source's `byPath` as top-level siblings (Task 2); rest reuses the existing wildcard-selection machinery, over-approximating by including sibling-destructured keys rather than precisely excluding them (Task 1, with the tradeoff stated explicitly, not glossed over). Note the confirmed side effect on the taint engine (Task 2 Step 5's finding). Note array rest's separate, lower-severity, still-unfixed imprecision (Task 1's out-of-scope note) so it isn't confused with the now-fixed object case.

- [ ] **Step 2: Update `scanner/src/lineage/CLAUDE.md`'s matching note**

Update the corresponding "KNOWN, UNFIXED LIMITATION" sentence added when this gap was found (search for "object spread/rest" in the file) to reflect the fix, consistent with Step 1's rewrite — keep it concise, pointing to the ADR for the full story rather than duplicating it.

- [ ] **Step 3: Update the parent scoping doc's follow-up note**

`docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`'s "Update, post-implementation" paragraph (added when this gap was found) currently describes object spread/rest as a deferred follow-up recommended for "whichever future sub-project picks this up." Update it to record that this specific plan closed it, with the commit/plan reference, so a future reader doesn't think it's still open.

- [ ] **Step 4: Run the full relevant test suites one more time**

Run: `cd scanner && npm run test:lineage && npm run test:dataflow` — confirm 0 failures (docs-only change, but re-verify per this project's discipline of never assuming a mutation landed without checking).

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md scanner/src/lineage/CLAUDE.md docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md
git commit -m "docs(lineage): record the object spread/rest fix, close out the documented known-limitation note"
```

---

## Self-Review Notes (from the plan author)

- **Spec coverage:** both halves of the documented gap (object literal spread, destructuring rest) are covered by Tasks 1-2. Array rest's separate, lower-severity imprecision is explicitly noted as out of scope in the Global Constraints, not silently ignored.
- **Type/interface consistency check:** Task 1's fix produces a `{kind:'member', object, prop:'*'}` source shape that Task 2 doesn't touch and doesn't need to — they're independent parser-level changes to two different AST node kinds (`ObjectPattern`/`RestElement` for Task 1, `ObjectExpression`/`SpreadElement` for Task 2). Task 2's `{spread: true, value}` prop shape is new and consumed only by the `resolveExprIdentities` `object` case this same task modifies — no other file needs to know about it, confirmed via the pre-plan audit cited in Global Constraints.
- **Verification discipline**: every task requires running `test:dataflow` in addition to `test:lineage`, per this plan's Global Constraints — this is the one thing every round of the parent plan's saga would have caught immediately if a fix here broke shared parser behavior, so it's treated as non-optional throughout, not just at the end.
