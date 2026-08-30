# Data Flow Explorer Milestone 1, Sub-project B, Increment 2: `resolveExprIdentities`'s `call` Case Consults Real Summaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `resolveExprIdentities`'s `call` case a real path to a resolved callee's summary instead of always treating every call as unresolved (the current behavior: union of argument identities, `widened: true`). This is the single most important integration point named in Sub-project B's own scoping document — the piece that makes a resolved function CALL behave, from the caller's point of view, like the callee's real field-identity return facts, not a coarse approximation.

**Architecture:** `resolveExprIdentities(state, expr, ctx)` gains a third, optional parameter — `ctx` — threaded through every recursive self-call (unchanged behavior when `ctx` is omitted, so all 176 of Sub-project A/B1's existing 2-argument call sites keep working exactly as before). `ctx.resolveCallSummary`, when present, is an OPAQUE callback `(calleeExpr, callArgs, callerState) => summary | null` — `resolveExprIdentities` itself never learns anything about qids, call-graph resolution, or the cache; it just asks the callback "do you know what this call resolves to?" and uses the answer if there is one. This keeps the boundary between "pure expression resolution" (`engine.js`, unchanged in spirit) and "how a call gets resolved to a real function" (a caller-injected concern) clean — and is exactly why increment B3 (real call-graph integration) can plug in a completely different `resolveCallSummary` implementation later without touching `resolveExprIdentities` again. `scanner/src/lineage/summaries.js` gains `createCallSummaryResolver(cache, lookupCallee)`, a small factory that builds a `resolveCallSummary` closure wired to a `FieldIdentitySummaryCache` — `lookupCallee` is itself injected (a hand-built name-to-function map for this increment's own tests; a real call-graph-backed resolver for B3).

**Tech Stack:** Same as prior increments — plain ESM, Node's built-in `node:test`, the real Babel-based JS/TS parser for Task 2's integration test.

**Spec:** `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-b-scoping.md`'s "B2" entry. Read `scanner/src/lineage/CLAUDE.md` (the `summaries.js` and `engine.js` module-table rows) and `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md` before starting — the invariant this document states about `resolveExprIdentities`'s structure-preserving/structure-flattening cases still governs the `call` case's design in this increment (a RESOLVED call is genuinely structure-preserving now — its result can carry real `byPath` structure from the callee's summary — while an UNRESOLVED call remains structure-flattening, exactly as before).

## Global Constraints

- **Every existing 2-argument call site of `resolveExprIdentities(state, expr)` must keep working unchanged.** `ctx` is optional; omitting it must be behaviorally identical to every one of Sub-project A/B1's 176 already-passing tests. Do not change any existing test's expected output in this plan — if a change to `resolveExprIdentities` breaks an existing test, that's a sign the threading was done wrong, not a sign the old test needs updating.
- **`engine.js` must never import from `summaries.js`.** The dependency direction stays one-way (`summaries.js` depends on `engine.js`, never the reverse) — `resolveExprIdentities`'s new `call`-case branch only ever calls the OPAQUE `ctx.resolveCallSummary` callback; it has zero knowledge of `FieldIdentitySummaryCache`, `entryStateFromCall`, or any other `summaries.js` symbol.
- **Run `cd scanner && npm run test:lineage` after every task** and report the exact pass/fail count. New test files must be added to `scanner/package.json`'s `"test:lineage"` script.
- **No placeholders.** Every code block in this plan is real, derived from the actual current files — but re-read `scanner/src/lineage/engine.js`'s `resolveExprIdentities` yourself before editing, since this plan quotes the WHOLE function and a small drift since this plan was written would matter.

---

## Task 1: Thread `ctx` through `resolveExprIdentities`, add the `call`-case integration, add `createCallSummaryResolver`

**Files:**
- Modify: `scanner/src/lineage/engine.js`
- Modify: `scanner/src/lineage/summaries.js`
- Test: `scanner/test/lineage/engine-expr-resolver.test.js`
- Test: `scanner/test/lineage/summaries.test.js`

**Interfaces:**
- Consumes: nothing new at the `field-identity.js` level — this task only restructures `engine.js`'s existing function signature and `summaries.js`'s existing exports.
- Produces: `resolveExprIdentities(state, expr, ctx?)` (backward-compatible signature change); `createCallSummaryResolver(cache, lookupCallee) → resolveCallSummary` in `summaries.js`, where `lookupCallee(calleeExpr) → {qid, fn} | null` is itself caller-injected.

- [ ] **Step 1: Read the current `resolveExprIdentities` in full, confirm it matches this plan's description, then write failing tests**

Re-read `scanner/src/lineage/engine.js`'s `resolveExprIdentities` function now, before writing anything — confirm the case list and each case's exact current body matches what this plan assumes (`ident`, `member`, `literal`/`unknown`, `object`, `array`, `tpl`, `binary`, `logical`, `union`, `call`, `assign-expr`, `default`). If something differs, adapt Step 3's replacement accordingly rather than blindly pasting it.

Add to `scanner/test/lineage/engine-expr-resolver.test.js` (mirror the file's existing `stateWith`/import style):

```js
test('resolveExprIdentities without a ctx argument behaves exactly as before (backward compatibility)', () => {
  const state = stateWith([['user.email', 'data:email']]);
  const r = resolveExprIdentities(state, { kind: 'ident', name: 'user' });
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
});

test('a call with no ctx.resolveCallSummary falls back to the existing unresolved-call behavior (union of args, widened)', () => {
  const state = stateWith([['secret', 'data:x']]);
  const expr = { kind: 'call', callee: { kind: 'ident', name: 'someFn' }, args: [{ kind: 'ident', name: 'secret' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:x']);
  assert.equal(r.widened, true);
});

test('a call resolves via ctx.resolveCallSummary when it returns a summary, bypassing the unresolved fallback entirely', () => {
  const state = stateWith([['user', 'data:should-not-appear']]);
  const expr = { kind: 'call', callee: { kind: 'ident', name: 'known' }, args: [{ kind: 'ident', name: 'user' }] };
  const ctx = {
    resolveCallSummary: (calleeExpr) => {
      assert.equal(calleeExpr.name, 'known');
      return { returnFlat: new Set(['data:from-summary']), returnByPath: new Map([['field', new Set(['data:nested'])]]) };
    },
  };
  const r = resolveExprIdentities(state, expr, ctx);
  assert.deepEqual([...r.flat], ['data:from-summary'], 'must use the summary\'s return facts, not the args-union fallback');
  assert.deepEqual([...r.byPath.get('field')], ['data:nested'], 'byPath from the summary must be forwarded, not dropped');
  assert.equal(r.widened, false, 'a genuinely resolved call is not a widened/unknown flow');
});

test('a call with ctx.resolveCallSummary present but returning null falls back to the unresolved behavior for THAT call (per-call, not global)', () => {
  const state = stateWith([['secret', 'data:x']]);
  const expr = { kind: 'call', callee: { kind: 'ident', name: 'unknownFn' }, args: [{ kind: 'ident', name: 'secret' }] };
  const ctx = { resolveCallSummary: () => null };
  const r = resolveExprIdentities(state, expr, ctx);
  assert.deepEqual([...r.flat], ['data:x']);
  assert.equal(r.widened, true);
});

test('ctx threads through nested constructs so a call INSIDE an object literal / ternary / template also resolves via the summary', () => {
  const state = stateWith([['user', 'data:x']]);
  const ctx = { resolveCallSummary: () => ({ returnFlat: new Set(['data:resolved']), returnByPath: new Map() }) };
  const objExpr = { kind: 'object', props: [{ key: 'a', value: { kind: 'call', callee: { kind: 'ident', name: 'f' }, args: [] } }] };
  const r1 = resolveExprIdentities(state, objExpr, ctx);
  assert.deepEqual([...r1.byPath.get('a')], ['data:resolved']);

  const ternaryExpr = { kind: 'union', branches: [{ kind: 'call', callee: { kind: 'ident', name: 'f' }, args: [] }, { kind: 'literal', value: 1 }] };
  const r2 = resolveExprIdentities(state, ternaryExpr, ctx);
  assert.deepEqual([...r2.flat], ['data:resolved']);
});
```

Add to `scanner/test/lineage/summaries.test.js`:

```js
import { createCallSummaryResolver } from '../../src/lineage/summaries.js'; // add to the existing import line from that file, don't duplicate the import statement

test('createCallSummaryResolver returns null when lookupCallee cannot resolve the call', () => {
  const cache = new FieldIdentitySummaryCache();
  const resolver = createCallSummaryResolver(cache, () => null);
  const result = resolver({ kind: 'ident', name: 'unknownFn' }, [], emptyState());
  assert.equal(result, null);
});

test('createCallSummaryResolver computes and caches a real summary via analyzeFunctionFieldIdentity when lookupCallee resolves', () => {
  const cache = new FieldIdentitySummaryCache();
  // function copyEmail(source) { return source.email; }
  const calleeFn = {
    params: ['source'],
    cfg: {
      entry: 'c0', exit: 'c1',
      nodes: {
        c0: { kind: 'entry', line: 1, succ: ['c1'], pred: [] },
        c1: { kind: 'return', line: 1, succ: [], pred: ['c0'], value: { kind: 'member', object: { kind: 'ident', name: 'source' }, prop: 'email' } },
      },
    },
  };
  const resolver = createCallSummaryResolver(cache, (calleeExpr) => (calleeExpr.name === 'copyEmail' ? { qid: 'test::copyEmail', fn: calleeFn } : null));
  const callerState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = resolver({ kind: 'ident', name: 'copyEmail' }, [{ kind: 'ident', name: 'user' }], callerState);
  assert.deepEqual([...result.returnFlat], ['data:email']);
  assert.equal(cache.size(), 1, 'the computed summary must be cached');
});

test('createCallSummaryResolver unions identities across ALL of a function\'s return sites, not just the first (a genuine correctness improvement over increment B1\'s own single-return-site test shortcut)', () => {
  const cache = new FieldIdentitySummaryCache();
  // function pick(a, b, flag) { if (flag) { return a.x; } return b.y; }
  const calleeFn = {
    params: ['a', 'b', 'flag'],
    cfg: {
      entry: 'c0', exit: 'c3',
      nodes: {
        c0: { kind: 'entry', line: 1, succ: ['c1'], pred: [] },
        c1: { kind: 'if', line: 1, succ: ['c2', 'c3'], pred: ['c0'], cond: { kind: 'ident', name: 'flag' } },
        c2: { kind: 'return', line: 1, succ: [], pred: ['c1'], value: { kind: 'member', object: { kind: 'ident', name: 'a' }, prop: 'x' } },
        c3: { kind: 'return', line: 1, succ: [], pred: ['c1'], value: { kind: 'member', object: { kind: 'ident', name: 'b' }, prop: 'y' } },
      },
    },
  };
  const resolver = createCallSummaryResolver(cache, () => ({ qid: 'test::pick', fn: calleeFn }));
  let callerState = addIdentity(emptyState(), 'p.x', 'data:p-x');
  callerState = addIdentity(callerState, 'q.y', 'data:q-y');
  const result = resolver({ kind: 'ident', name: 'pick' }, [{ kind: 'ident', name: 'p' }, { kind: 'ident', name: 'q' }, { kind: 'literal', value: true }], callerState);
  assert.deepEqual([...result.returnFlat].sort(), ['data:p-x', 'data:q-y'], 'both return sites\' identities must be present, not just one');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/engine-expr-resolver.test.js test/lineage/summaries.test.js`
Expected: FAIL — `resolveExprIdentities` doesn't accept/use `ctx` yet, `createCallSummaryResolver` doesn't exist yet.

- [ ] **Step 3: Update `resolveExprIdentities` in `scanner/src/lineage/engine.js`**

Replace the ENTIRE function (from `export function resolveExprIdentities(state, expr) {` through its closing `}`) with:

```js
export function resolveExprIdentities(state, expr, ctx) {
  if (!expr) return noIdentity();

  switch (expr.kind) {
    case 'ident': {
      const path = accessPathOf(expr);
      if (!path) return noIdentity();
      const flat = identitiesAt(state, path);
      const byPath = new Map();
      for (const [candidatePath, ids] of state) {
        if (candidatePath !== path && pathIsCoveredByPrefix(candidatePath, path)) {
          const subPath = candidatePath.slice(path.length + 1);
          const existing = byPath.get(subPath) ?? new Set();
          byPath.set(subPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'member': {
      const path = accessPathOf(expr);
      if (path) {
        if (pathHasWildcard(path)) {
          const basePath = definitePrefixBeforeWildcard(path);
          const flat = basePath ? identitiesAt(state, basePath) : new Set();
          return { flat, byPath: new Map(), widened: flat.size > 0 };
        }
        const flat = identitiesAt(state, path);
        const byPath = new Map();
        for (const [candidatePath, ids] of state) {
          if (candidatePath !== path && pathIsCoveredByPrefix(candidatePath, path)) {
            const subPath = candidatePath.slice(path.length + 1);
            const existing = byPath.get(subPath) ?? new Set();
            byPath.set(subPath, new Set([...existing, ...ids]));
          }
        }
        return { flat, byPath, widened: false };
      }

      const base = resolveExprIdentities(state, expr.object, ctx);
      if (expr.prop === '*') {
        return { flat: new Set(base.flat), byPath: new Map(), widened: base.flat.size > 0 };
      }
      const baseResidual = residualFlat(base.flat, base.byPath);
      const flat = new Set(baseResidual);
      const byPath = new Map();
      for (const [subPath, ids] of base.byPath) {
        if (subPath === expr.prop) {
          for (const id of ids) flat.add(id);
        } else if (subPath.startsWith(`${expr.prop}.`)) {
          const rebased = subPath.slice(expr.prop.length + 1);
          const existing = byPath.get(rebased) ?? new Set();
          byPath.set(rebased, new Set([...existing, ...ids]));
          for (const id of ids) flat.add(id);
        }
      }
      return { flat, byPath, widened: base.widened };
    }

    case 'literal':
    case 'unknown':
      return noIdentity();

    case 'object': {
      const flat = new Set();
      const byPath = new Map();
      for (const prop of expr.props) {
        const r = resolveExprIdentities(state, prop.value, ctx);
        for (const id of r.flat) flat.add(id);
        if (prop.spread) {
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

    case 'array': {
      const flat = new Set();
      for (const el of expr.elements) {
        const r = resolveExprIdentities(state, el, ctx);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'tpl': {
      const flat = new Set();
      for (const part of expr.parts) {
        const r = resolveExprIdentities(state, part, ctx);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'binary': {
      const left = resolveExprIdentities(state, expr.left, ctx);
      const right = resolveExprIdentities(state, expr.right, ctx);
      return { flat: new Set([...left.flat, ...right.flat]), byPath: new Map(), widened: false };
    }

    case 'logical': {
      const left = resolveExprIdentities(state, expr.left, ctx);
      const right = resolveExprIdentities(state, expr.right, ctx);
      const flat = new Set([...left.flat, ...right.flat]);
      const byPath = new Map();
      for (const r of [left, right]) {
        for (const [subPath, ids] of r.byPath) {
          const existing = byPath.get(subPath) ?? new Set();
          byPath.set(subPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'union': {
      const flat = new Set();
      const byPath = new Map();
      for (const branch of expr.branches) {
        const r = resolveExprIdentities(state, branch, ctx);
        for (const id of r.flat) flat.add(id);
        for (const [subPath, ids] of r.byPath) {
          const existing = byPath.get(subPath) ?? new Set();
          byPath.set(subPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'call': {
      // NEW (Sub-project B, increment 2): if the caller supplied a
      // resolver and it recognizes this specific call, use the resolved
      // callee's REAL return facts (both flat and byPath, so a caller
      // selecting one field off a resolved call's structured return value
      // gets the same field-level precision as any other structure-
      // preserving construct) instead of the generic unresolved-call
      // fallback below. This is what makes `resolveExprIdentities`'s
      // structure-preserving/structure-flattening invariant (see
      // DESIGN_INTRAPROCEDURAL.md) genuinely true for a call now: a
      // RESOLVED call is structure-preserving (forwards byPath); an
      // UNRESOLVED one remains structure-flattening (flat + widened),
      // exactly as before this increment.
      if (ctx?.resolveCallSummary) {
        const summary = ctx.resolveCallSummary(expr.callee, expr.args ?? [], state);
        if (summary) {
          return { flat: new Set(summary.returnFlat), byPath: new Map(summary.returnByPath), widened: false };
        }
      }
      const flat = new Set();
      for (const arg of expr.args ?? []) {
        const r = resolveExprIdentities(state, arg, ctx);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: flat.size > 0 };
    }

    case 'assign-expr': {
      const r = resolveExprIdentities(state, expr.source, ctx);
      return { flat: r.flat, byPath: r.byPath, widened: r.widened };
    }

    default:
      return noIdentity();
  }
}
```

The only SEMANTIC changes from the current version: (1) every recursive self-call now passes `ctx` through; (2) the `call` case gains the `ctx?.resolveCallSummary` branch before its existing fallback. Every other line is byte-identical to what's already there — confirm this yourself with a diff before moving on, don't just trust this plan's transcription.

- [ ] **Step 4: Add `createCallSummaryResolver` to `scanner/src/lineage/summaries.js`**

Add this import to the file's existing import lines (extend, don't duplicate, if `analyzeFunctionFieldIdentity` isn't already imported — check first):

```js
import { analyzeFunctionFieldIdentity } from './engine.js';
```

Add the new export (near the bottom of the file, or wherever fits the file's existing organization):

```js
// Builds a `resolveCallSummary` closure — the shape `resolveExprIdentities`'s
// `call` case now consults (see engine.js) — wired to a real
// FieldIdentitySummaryCache. `lookupCallee` is itself injected and
// deliberately opaque to this function: this increment's own tests pass a
// simple hand-built name-to-function map; increment B3's real call-graph
// integration will pass a resolver backed by `scanner/src/ir/callgraph.js`
// instead, without this function (or `resolveExprIdentities`) needing to
// change at all.
export function createCallSummaryResolver(cache, lookupCallee) {
  return function resolveCallSummary(calleeExpr, callArgs, callerState) {
    const resolved = lookupCallee(calleeExpr);
    if (!resolved) return null;
    const { qid, fn } = resolved;
    const entryState = entryStateFromCall(fn.params, callArgs, callerState);
    return cache.compute(qid, entryState, (es) => {
      const result = analyzeFunctionFieldIdentity(fn, es);
      // Union across EVERY return site, not just the first — a function
      // with multiple return statements (e.g. an early-return branch)
      // must have all of them reflected, not just whichever happened to
      // be recorded first. This is a genuine correctness improvement over
      // increment B1's own round-trip test's `returnFacts[0]` shortcut
      // (that test only ever exercised a single-return-site function, so
      // the shortcut was harmless there — this shared, reusable resolver
      // is the right place to do it correctly going forward).
      const returnFlat = new Set();
      for (const rf of result.returnFacts) {
        for (const id of rf.identities) returnFlat.add(id);
      }
      return {
        returnFlat,
        returnByPath: new Map(), // still flat-only — see B1's disclosed limitation in CLAUDE.md; not closed by this increment either
        mutatedParams: result.mutatedParams,
        widenings: result.widenings,
      };
    });
  };
}
```

- [ ] **Step 5: Run to verify tests pass**

Run: `cd scanner && node --test test/lineage/engine-expr-resolver.test.js test/lineage/summaries.test.js`
Expected: PASS, all tests including the new ones.

- [ ] **Step 6: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage` — expect PASS, 176 pre-existing + however many this task added, 0 failures. Report the exact count.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/src/lineage/summaries.js scanner/test/lineage/engine-expr-resolver.test.js scanner/test/lineage/summaries.test.js
git commit -m "feat(lineage): resolveExprIdentities's call case consults real summaries via an injected resolver (Sub-project B, increment 2)"
```

---

## Task 2: Real-parser integration test

**Files:**
- Test: `scanner/test/lineage/engine-integration.test.js`

**Interfaces:**
- Consumes: `createCallSummaryResolver`, `FieldIdentitySummaryCache` (from `summaries.js`); `resolveExprIdentities`, `analyzeFunctionFieldIdentity` (from `engine.js`, both unchanged in their own contracts by this task).
- Produces: nothing new — this task proves Task 1's mechanism against REAL parsed JS/TS source, the same discipline every prior increment/plan in this whole PRD effort has followed before considering a piece "proven."

- [ ] **Step 1: Write a failing test**

Add to `scanner/test/lineage/engine-integration.test.js` (mirror this file's existing real-parser helper usage):

```js
test('a resolved call to a real, separately-parsed function returns its actual field identity, not the generic unresolved-call fallback (Sub-project B, increment 2, real parser)', () => {
  const src = `
    function copyEmail(source) {
      return source.email;
    }
    function caller(user) {
      return copyEmail(user);
    }
  `;
  // Parse the whole source once, extract BOTH functions (mirror this
  // file's existing helper — it should give you a way to get every
  // function in the parsed IR, or call it twice with different function
  // names if that's the file's established pattern; check before
  // assuming).
  const calleeFn = /* extract `copyEmail` */;
  const callerFn = /* extract `caller` */;

  const cache = new FieldIdentitySummaryCache();
  const lookupCallee = (calleeExpr) => (calleeExpr.kind === 'ident' && calleeExpr.name === 'copyEmail' ? { qid: 'copyEmail', fn: calleeFn } : null);
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);

  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  // Drive `caller`'s own analysis with ctx wired in — this requires
  // `analyzeFunctionFieldIdentity` to forward `ctx` down into
  // `resolveExprIdentities` wherever `step()` resolves an expression. Read
  // `engine.js`'s `step()` and `analyzeFunctionFieldIdentity()` yourself —
  // if `step()` doesn't currently accept/forward a `ctx`, you will need to
  // add that threading too (mirroring exactly how Task 1 threaded `ctx`
  // through `resolveExprIdentities`'s own recursive calls) before this
  // test can pass. This is real, in-scope work for this task if it turns
  // out `step()`/`analyzeFunctionFieldIdentity` don't already forward a
  // ctx parameter — do not skip it or work around it; if the threading
  // is more involved than expected, do it properly and disclose exactly
  // what you found and changed in your report.
  const result = analyzeFunctionFieldIdentity(callerFn, entryState, { resolveCallSummary });

  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'the call to copyEmail must resolve to its real return fact (only email, since copyEmail only reads source.email), not the generic widened union-of-args fallback (which would have included data:ssn too)');
});
```

Before finalizing this test, actually read `scanner/src/lineage/engine.js`'s `step()` function and `analyzeFunctionFieldIdentity()` to determine whether `ctx` needs to be threaded through them too (Task 1 only touched `resolveExprIdentities` itself) — `step()` calls `resolveExprIdentities(stateIn, node.source)` (in the `assign` case) and `resolveExprIdentities(stateIn, node.value)` (in the `return` case) without a third argument today. If a `return` statement's value is a `call` expression (as in this test's `caller` function), `step()`'s `return` case must also pass `ctx` through, or this test cannot possibly pass no matter how correct Task 1's own change is. Investigate this for real before writing the rest of this task — this is a genuine, disclosed uncertainty this plan could not resolve without you reading the current code, not something to guess at.

- [ ] **Step 2: Investigate and, if needed, thread `ctx` through `step()` and `analyzeFunctionFieldIdentity()`**

If Step 1's investigation confirms `step()`/`analyzeFunctionFieldIdentity()` do NOT currently forward a `ctx` parameter to their own internal `resolveExprIdentities` calls, add it: `analyzeFunctionFieldIdentity(fn, entryState, ctx)` should pass `ctx` down into `step(node, incoming, widenings, ctx)`, and `step()`'s own `resolveExprIdentities(stateIn, node.source)`/`resolveExprIdentities(stateIn, node.value)` calls (in its `assign` and `return` cases respectively) should become `resolveExprIdentities(stateIn, node.source, ctx)`/`resolveExprIdentities(stateIn, node.value, ctx)`. Also check the `call` CFG-node-kind case in `step()` (the one that resolves bare call-statement arguments for widening purposes) — does it need the same threading? Reason through whether it does and act accordingly, documenting your reasoning in your report either way.

Confirm this change (if made) doesn't break ANY of the now-176+ existing tests that call `analyzeFunctionFieldIdentity(fn, entryState)` with no third argument — `ctx` must be optional here too, exactly like it is in `resolveExprIdentities`.

- [ ] **Step 3: Run to verify the test passes**

Run: `cd scanner && node --test test/lineage/engine-integration.test.js`
Expected: PASS.

- [ ] **Step 4: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage` — expect PASS, 0 failures, report the exact count.

- [ ] **Step 5: Commit**

```bash
git add scanner/test/lineage/engine-integration.test.js scanner/src/lineage/engine.js
git commit -m "test(lineage): real-parser integration proof for the call-summary resolver, thread ctx through step()/analyzeFunctionFieldIdentity if needed (Sub-project B, increment 2)"
```

(Adjust the file list in this commit if Step 2 required no changes to `engine.js` beyond Task 1's own — in that case, omit `scanner/src/lineage/engine.js` from this commit and say so plainly in your report.)

---

## Self-Review Notes (from the plan author)

- **Spec coverage:** this increment covers exactly B2's scope per the parent Sub-project B document — `resolveExprIdentities`'s `call` case now has a real resolution path, still with NO real call-graph integration (`lookupCallee` stays hand-built/injected in every test here, matching the scoping doc's own "the 'is this call resolved' question is answered by a caller-supplied lookup function in this increment, deferred to B3 for the real thing").
- **Known, disclosed uncertainty**: Task 2 Step 1/2 explicitly flags that whether `step()`/`analyzeFunctionFieldIdentity()` need their own `ctx`-threading update is NOT something this plan's own research resolved with full certainty — it assigns a real investigation step with a designed fallback (thread it, mirroring Task 1's own pattern) rather than asserting a fact the plan author couldn't fully verify without re-reading the whole CFG-walker function line by line at plan-writing time.
- **Type/interface consistency check:** `ctx.resolveCallSummary`'s signature (`(calleeExpr, callArgs, callerState) => summary | null`) is used identically in Task 1's `resolveExprIdentities` change and `createCallSummaryResolver`'s own return value — no mismatch. `createCallSummaryResolver`'s `lookupCallee(calleeExpr) => {qid, fn} | null` shape is deliberately the SAME shape increment B3's real call-graph resolver will need to produce (`scanner/src/ir/callgraph.js`'s `resolveKnownCallee` already returns a resolved function object per the Sub-project B scoping document's own research — B3's job is adapting that into this exact `{qid, fn}` shape, not redesigning this interface).
