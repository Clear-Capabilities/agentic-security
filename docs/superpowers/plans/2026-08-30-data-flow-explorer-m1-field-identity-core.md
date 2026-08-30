# Data Flow Explorer Milestone 1, Sub-project A: Field-Identity Engine Core (Design Spike + Intraprocedural) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the field-identity state representation and single-function (intraprocedural) tracking engine for the Milestone 1 lineage engine — the piece every other Milestone 1 sub-project depends on. Produces a design record (ADR) settling the reuse boundary against the existing taint engine, plus working, tested code that, given a function's real parsed IR and a caller-supplied set of "these parameters/paths carry these data elements" facts, computes which data elements end up in the return value(s) and in mutated parameters — preserving multiple distinct field identities through the function body without merging them (FR-301).

**Architecture:** New code lives entirely under `scanner/src/lineage/` (`field-identity.js`, and additions to `engine.js`). It structurally mirrors the existing taint engine's CFG worklist algorithm (`scanner/src/dataflow/engine.js`'s `analyzeFunction`) as a proven *pattern*, but uses an entirely new state shape (`Map<accessPath, Set<dataElementId>>` instead of `Set<accessPath>`) because the existing `SummaryCache`/taint state is documented as parameter-granularity-only and would silently merge distinct fields, directly violating FR-301. Per PRD §18.1, this package may reuse `scanner/src/dataflow/access-paths.js`'s pure path-string operations (no taint state, confirmed reusable) but must never import `scanner/src/dataflow/engine.js` or touch its taint state. No interprocedural resolution, no path-DAG, no source/sink registry integration, and no `DataFlowGraph v1` graph output happen in this plan — those are later sub-projects (B, C, D, E per the scoping document) that consume this plan's output shape.

**Tech Stack:** Plain ESM (`scanner/src/` convention — see root `CLAUDE.md`), Node's built-in `node:test` + `node:assert/strict` (matches `scanner/test/lineage/`'s existing convention), the real JS/TS IR parser (`scanner/src/ir/parser-js.js`) for Task 5's integration tests.

**Spec:** `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md` (Sub-project A's entry in that document — read it first for the milestone-level context and the four decisions it already made), `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §13 (FR-301 specifically), §18.1 (reuse boundary). Read `scanner/src/lineage/CLAUDE.md` and `scanner/src/dataflow/CLAUDE.md` before starting any task.

## Global Constraints

- **Never import `scanner/src/dataflow/engine.js` or touch its taint state.** `scanner/src/lineage/CLAUDE.md` states this explicitly; it is a hard architectural boundary, not a style preference (PRD §3.1, §18.1).
- **`scanner/src/dataflow/access-paths.js`'s exported functions (`accessPathOf`, `pathIsCoveredByPrefix`, `isCoveredBy`, `canonicalize`, `joinSets`, `hashSet`, `setsEqual`, `addPath`, `removePathAndDescendants`) ARE allowed reuse** — confirmed pure (operate only on path strings and `Set<string>`, no taint-specific state) — per PRD §18.1's "may reuse pure IR, call-graph, access-path, string-domain, and schema-parsing utilities." This plan's Task 1 records this decision in the ADR and updates `scanner/src/lineage/CLAUDE.md`'s reuse-boundary sentence (which currently names only `dataflow/privacy-taxonomy.js`) to also name `dataflow/access-paths.js`.
- **All new code is pure / no DOM, no CLI wiring, no `runScan` integration in this plan.** This is intraprocedural analysis only, invoked directly by tests with hand-supplied entry facts — not yet wired into any scan pathway. That wiring is a later sub-project's job.
- **Every fixture-fact claim in a test must be verified against the real IR shape**, not assumed from this plan's prose. This plan's code was designed from a research pass over the real `scanner/src/ir/parser-js.js`, `scanner/src/dataflow/access-paths.js`, and `scanner/src/dataflow/engine.js` — but destructuring's exact CFG lowering (the code before line ~194 of `parser-js.js`) was NOT read during that research pass and is flagged explicitly in Task 4/5 below as something an implementer must read directly before writing that specific handling.
- **Run `cd scanner && npm run test:lineage` after every task** and report the exact pass/fail count from the run you just executed. New test files must be added to `scanner/package.json`'s `"test:lineage"` script (an explicit file list, not a glob) and to whatever broader script(s) feed `npm test`'s union — check `scanner/CLAUDE.md` for which scoped scripts compose the full gate before assuming a new file is covered.
- **No placeholders, no invented pseudocode presented as real.** Where this plan is uncertain about a real shape (destructuring lowering), it says so explicitly and assigns a verification step — it does not guess and present the guess as fact.

---

## Task 1: Design ADR — field-identity state model and reuse boundary

**Files:**
- Create: `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md`
- Modify: `scanner/src/lineage/CLAUDE.md` (the reuse-boundary sentence)

**Interfaces:**
- Produces: a design record every later task in this plan (and Sub-project B) cites by section name rather than re-deriving. No code.

- [ ] **Step 1: Write `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md`**

Create this file with the following content (adapt wording only where you find a factual error against the real codebase — do not alter the substance of a decision without flagging it in your task report):

```markdown
# Intraprocedural Field-Identity Engine — Design Record

Scope: Sub-project A of Milestone 1 (see
`docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`).
Single-function analysis only. No interprocedural resolution, no path DAG,
no registry integration.

## 1. State shape

`Map<accessPath: string, Set<dataElementId: string>>` — for each access path
reachable in a function, the set of data-element IDs it carries. This is the
direct fix for FR-301: the existing taint engine's state
(`scanner/src/dataflow/access-paths.js`'s `Set<accessPath>`, boolean per
path) cannot distinguish "this path carries data element X" from "this path
carries data element Y" — only "this path is tainted." The existing
interprocedural summary cache (`scanner/src/dataflow/summaries.js`) is
explicitly documented as parameter-granularity only ("`f(obj)` with obj.foo
tainted is treated the same as obj.bar tainted") — reusing that state shape
would silently violate FR-301 the first time a benchmark case exercised two
distinct fields on the same object parameter. This is a hard fork, decided
here, not left to a later task to discover partway through implementation.

## 2. Reuse boundary (binding on every later task and sub-project)

**Reused directly, as pure utilities, unmodified:**
- `scanner/src/dataflow/access-paths.js`'s `accessPathOf`,
  `pathIsCoveredByPrefix`, `isCoveredBy` — all operate purely on path
  strings, no taint state involved. Confirmed by reading the file: none of
  its exports take or return taint-specific state.
- The real JS/TS IR shape from `scanner/src/ir/parser-js.js` — consumed
  as-is, never reimplemented.

**Structurally mirrored (same algorithm, new state type), never imported:**
- `scanner/src/dataflow/engine.js`'s `analyzeFunction` worklist loop (forward
  dataflow analysis, explicit worklist, join-via-repeated-merge at CFG
  branch-rejoin points, no separate "join node" concept — a rejoin is just
  a point that receives more than one predecessor's merged state over the
  worklist's lifetime). This package's own `analyzeFunctionFieldIdentity`
  (Task 4) copies this ALGORITHM, not this file's code or state.

**Never reused, must be reimplemented for field-identity semantics:**
- `access-paths.js`'s `addPath`/`removePathAndDescendants`/`joinSets` — these
  operate on `Set<string>` (presence/absence). Field identity needs
  Map-shaped equivalents that union *label sets* per path on join, not just
  path presence. See `field-identity.js` (Task 2).
- `scanner/src/dataflow/summaries.js`'s `SummaryCache` — out of scope for
  this plan (interprocedural is Sub-project B), but its `_hashState`
  approach (canonicalize then hash) is worth mirroring conceptually once
  Sub-project B needs a cache key over field-identity state; `field-identity.js`
  ships a `hashState` now specifically so Sub-project B doesn't have to
  retrofit one onto an already-shipped state shape.

**Forbidden absolutely:** importing `scanner/src/dataflow/engine.js` or
touching its live taint `Set<accessPath>` state. Per
`scanner/src/lineage/CLAUDE.md` and PRD §3.1/§18.1.

## 3. Ancestor/descendant semantics (deliberately asymmetric, mirrors access-paths.js)

An ancestor path's recorded identity IS visible when querying a descendant
path (`identitiesAt(state, 'obj.email')` includes any identity recorded at
`'obj'` itself) — mirrors `access-paths.js`'s `isCoveredBy`: a coarser fact
is sound information about everything under it. The reverse does NOT hold:
a descendant's identity is never visible when querying its ancestor
(`identitiesAt(state, 'obj')` does NOT include an identity recorded only at
`'obj.email'`) — asking about the whole object doesn't imply you learn a
fact that was only ever established about one of its fields.

Unlike boolean taint (where recording a fact at a coarser path makes any
existing finer-path fact redundant and `access-paths.js`'s `addPath` prunes
it away), field-identity state does **not** prune a descendant entry when an
ancestor gains a *different* identity — `obj` carrying data element X and
`obj.email` carrying data element Y are both real, independently meaningful
facts that must coexist (this coexistence IS FR-301's core requirement).
Pruning is deliberately NOT implemented as an optimization in this first
slice — `field-identity.js`'s state can carry redundant entries (an
ancestor and descendant both recording the same identity); this affects
efficiency, never correctness, since `identitiesAt`'s union already handles
it. Left as a documented, deferred optimization, not built now, per this
project's "don't design for hypothetical future requirements" convention.

## 4. Per-construct handling (JS/TS, this plan's scope)

- **Assignment** (`target: string`, `source: exprDesc`): resolve `source`'s
  identities, clear stale facts at `target` and its descendants
  (reassignment invalidates whatever was there), write the resolved
  identities at `target`.
- **Object literals**: each property's value is resolved recursively and
  attributed to `target.<key>` (dotted, nested objects produce dotted
  sub-paths like `target.a.b`) — this is the concrete mechanism that proves
  FR-301: two properties on one object literal, from two different data
  elements, land at two different access paths in the state, never merged.
- **Array literals**: flattened, no index sensitivity — matches
  `access-paths.js`'s own documented limitation (no `[i]`/`[*]` support;
  "index sensitivity is a follow-on"). An array carrying two different
  fields at two different indices is not distinguishable in this slice;
  this is an accepted, documented limitation, not silently wrong (every
  element's identities are still recorded, just flattened into one bag
  rather than per-index).
- **Member access** (property read): resolves via `accessPathOf` +
  `identitiesAt` — no new logic needed, this is what those functions exist
  for.
- **Template literals and string concatenation (`binary`/`logical` with
  string operators, `tpl` interpolation)**: DO propagate identity normally
  (not flagged as widened/implicit). Rationale: the underlying value is
  genuinely and traceably present in the result — this is different in kind
  from FR-306's "implicit and widened" category, which is about flows whose
  connection to the original field is inferred/approximate (an unresolved
  call, a dynamic property key), not flows where the field's actual value is
  verbatim embedded in a larger string. This is a real design call, stated
  explicitly here so it isn't silently assumed by whichever task implements
  the resolver.
- **Unresolved function calls** (every call in this plan's scope, since no
  registry/summary integration exists yet): the call's result is treated as
  conservatively carrying the union of its arguments' resolved identities,
  but flagged as a **widening event** (`{atPath, dataElementIds, reason,
  line}`) — a side list the engine returns alongside its main state, never
  silently dropped. This satisfies the project's "never launder identity
  into a clean value" principle (mirrors PRD §18.4's "never translate 'path
  budget exhausted' into 'no path'" spirit) without requiring this plan to
  build the registry integration that would let some calls resolve
  precisely (that's Sub-project D's job).
- **Destructuring**: NOT resolved in this design record — the real IR
  lowering for `const {a, b} = x` was not read during this plan's research
  pass (parser-js.js's destructuring-to-CFG lowering lives before the
  section that was read). Task 4/5 must read that code directly before
  implementing destructuring handling; see those tasks' explicit
  verification steps. This ADR intentionally does not assert a shape it
  cannot back with a real code citation.
- **Ternary/conditional expressions** (`union` kind, both branches kept by
  the parser — never resolved to one): both branches' identities are
  unioned, matching the conservative "either could execute" semantics the
  worklist's branch-join already uses at the CFG level.
- **`unknown`-kind expressions** (JSX, anything the parser doesn't handle):
  resolve to "carries no identity" — fails open, matching the general IR
  contract's own `unknown` CFG-node-kind treatment. Not flagged as a
  coverage gap by this plan (that accounting is AC-11/coverage-ledger
  territory — Sub-project E's job, not this one's).

## 5. What this plan explicitly does NOT build (so later sub-projects don't assume it's here)

Interprocedural call resolution and summaries (Sub-project B); the path DAG
(Sub-project C); any connection to the source/sink registry or
transformation-kind catalog (Sub-project D); any `DataFlowGraph v1` output
(Sub-project E); any wiring into `runScan`/the CLI. This plan's output is
consumed directly by tests with hand-supplied entry facts, nothing else,
by design.
```

- [ ] **Step 2: Update `scanner/src/lineage/CLAUDE.md`'s reuse-boundary sentence**

Find the sentence describing what this package may import from `dataflow/` (per this plan's research, it currently reads approximately: *"this package may read pure, stateless exports from `dataflow/privacy-taxonomy.js` but must never import `scanner/src/dataflow/engine.js` or touch its taint state"*). Read the file yourself to get the exact current wording (do not trust this plan's paraphrase), then extend it to also name `dataflow/access-paths.js` as allowed pure reuse, per this task's ADR §2. Keep everything else in that file unchanged — this is a one-sentence factual update, not a rewrite.

- [ ] **Step 3: Commit**

```bash
git add scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md scanner/src/lineage/CLAUDE.md
git commit -m "docs(lineage): design record for intraprocedural field-identity engine"
```

---

## Task 2: `field-identity.js` — the Map-based state module

**Files:**
- Create: `scanner/src/lineage/field-identity.js`
- Test: `scanner/test/lineage/field-identity.test.js`

**Interfaces:**
- Consumes: `pathIsCoveredByPrefix` from `scanner/src/dataflow/access-paths.js` (per Task 1's ADR §2, confirmed pure reuse).
- Produces: `emptyState()`, `identitiesAt(state, path)`, `addIdentity(state, path, dataElementId)`, `removeIdentitiesAt(state, path)`, `joinStates(a, b)`, `statesEqual(a, b)`, `hashState(state)` — all exported. Task 3 (`resolveExprIdentities`) and Task 4 (`analyzeFunctionFieldIdentity`) both consume this module directly.

- [ ] **Step 1: Write failing tests**

Create `scanner/test/lineage/field-identity.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  emptyState, identitiesAt, addIdentity, removeIdentitiesAt, joinStates, statesEqual, hashState,
} from '../../src/lineage/field-identity.js';

test('emptyState has no identities anywhere', () => {
  assert.equal(identitiesAt(emptyState(), 'x').size, 0);
});

test('addIdentity records an identity at an exact path', () => {
  const s = addIdentity(emptyState(), 'user.email', 'data:email');
  assert.deepEqual([...identitiesAt(s, 'user.email')], ['data:email']);
});

test('addIdentity is a no-op if the identity is already recorded at that exact path', () => {
  const s1 = addIdentity(emptyState(), 'x', 'data:a');
  const s2 = addIdentity(s1, 'x', 'data:a');
  assert.ok(statesEqual(s1, s2));
});

test('an ancestor path\'s identity is visible when querying a descendant path', () => {
  const s = addIdentity(emptyState(), 'user', 'data:whole-object');
  assert.deepEqual([...identitiesAt(s, 'user.email')], ['data:whole-object']);
});

test('a descendant path\'s identity is NOT visible when querying its ancestor', () => {
  const s = addIdentity(emptyState(), 'user.email', 'data:email');
  assert.equal(identitiesAt(s, 'user').size, 0);
});

test('two distinct fields on the same object coexist without merging (FR-301 core case)', () => {
  let s = emptyState();
  s = addIdentity(s, 'combined.email', 'data:email');
  s = addIdentity(s, 'combined.ssn', 'data:ssn');
  assert.deepEqual([...identitiesAt(s, 'combined.email')], ['data:email']);
  assert.deepEqual([...identitiesAt(s, 'combined.ssn')], ['data:ssn']);
  assert.equal(identitiesAt(s, 'combined').size, 0, 'no identity was ever recorded at the object root itself');
});

test('removeIdentitiesAt clears the exact path and every descendant, leaving unrelated paths untouched', () => {
  let s = emptyState();
  s = addIdentity(s, 'x.a', 'data:a');
  s = addIdentity(s, 'x.b', 'data:b');
  s = addIdentity(s, 'y', 'data:c');
  const cleared = removeIdentitiesAt(s, 'x');
  assert.equal(identitiesAt(cleared, 'x.a').size, 0);
  assert.equal(identitiesAt(cleared, 'x.b').size, 0);
  assert.deepEqual([...identitiesAt(cleared, 'y')], ['data:c']);
});

test('removeIdentitiesAt on an exact leaf path only clears that path, not siblings', () => {
  let s = emptyState();
  s = addIdentity(s, 'x.a', 'data:a');
  s = addIdentity(s, 'x.b', 'data:b');
  const cleared = removeIdentitiesAt(s, 'x.a');
  assert.equal(identitiesAt(cleared, 'x.a').size, 0);
  assert.deepEqual([...identitiesAt(cleared, 'x.b')], ['data:b']);
});

test('joinStates unions label sets for a path present in both states', () => {
  const a = addIdentity(emptyState(), 'x', 'data:a');
  const b = addIdentity(emptyState(), 'x', 'data:b');
  const joined = joinStates(a, b);
  assert.deepEqual([...identitiesAt(joined, 'x')].sort(), ['data:a', 'data:b']);
});

test('joinStates keeps a path present in only one of the two states', () => {
  const a = addIdentity(emptyState(), 'x', 'data:a');
  const joined = joinStates(a, emptyState());
  assert.deepEqual([...identitiesAt(joined, 'x')], ['data:a']);
});

test('statesEqual is true for two states built differently but holding the same facts', () => {
  let s1 = emptyState();
  s1 = addIdentity(s1, 'x', 'data:a');
  s1 = addIdentity(s1, 'y', 'data:b');
  let s2 = emptyState();
  s2 = addIdentity(s2, 'y', 'data:b');
  s2 = addIdentity(s2, 'x', 'data:a');
  assert.ok(statesEqual(s1, s2));
});

test('statesEqual is false when a label set differs', () => {
  const s1 = addIdentity(emptyState(), 'x', 'data:a');
  const s2 = addIdentity(emptyState(), 'x', 'data:b');
  assert.ok(!statesEqual(s1, s2));
});

test('hashState is stable regardless of insertion order', () => {
  let s1 = emptyState();
  s1 = addIdentity(s1, 'x', 'data:a');
  s1 = addIdentity(s1, 'y', 'data:b');
  let s2 = emptyState();
  s2 = addIdentity(s2, 'y', 'data:b');
  s2 = addIdentity(s2, 'x', 'data:a');
  assert.equal(hashState(s1), hashState(s2));
});

test('hashState differs when facts differ', () => {
  const s1 = addIdentity(emptyState(), 'x', 'data:a');
  const s2 = addIdentity(emptyState(), 'x', 'data:b');
  assert.notEqual(hashState(s1), hashState(s2));
});

test('addIdentity and removeIdentitiesAt never mutate their input state (pure/immutable contract)', () => {
  const original = addIdentity(emptyState(), 'x', 'data:a');
  const originalHash = hashState(original);
  addIdentity(original, 'x', 'data:b');
  removeIdentitiesAt(original, 'x');
  assert.equal(hashState(original), originalHash, 'input state must be unchanged after calling either function on it');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/field-identity.test.js`
Expected: FAIL — `field-identity.js` doesn't exist yet.

- [ ] **Step 3: Implement `scanner/src/lineage/field-identity.js`**

```js
import { pathIsCoveredByPrefix } from '../dataflow/access-paths.js';

// State: Map<accessPath: string, Set<dataElementId: string>>. See
// scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md for the full design
// rationale (why this shape instead of dataflow/access-paths.js's
// Set<accessPath>, ancestor/descendant asymmetry, why redundant
// ancestor+descendant entries are an accepted, deferred optimization).

export function emptyState() {
  return new Map();
}

export function identitiesAt(state, path) {
  const result = new Set();
  const exact = state.get(path);
  if (exact) for (const id of exact) result.add(id);
  for (const [candidatePath, ids] of state) {
    if (candidatePath !== path && pathIsCoveredByPrefix(path, candidatePath)) {
      for (const id of ids) result.add(id);
    }
  }
  return result;
}

export function addIdentity(state, path, dataElementId) {
  const current = state.get(path);
  if (current && current.has(dataElementId)) return state;
  const next = new Map(state);
  next.set(path, new Set([...(current ?? []), dataElementId]));
  return next;
}

export function removeIdentitiesAt(state, path) {
  const next = new Map();
  for (const [p, ids] of state) {
    if (p === path || pathIsCoveredByPrefix(p, path)) continue;
    next.set(p, ids);
  }
  return next;
}

export function joinStates(a, b) {
  const next = new Map(a);
  for (const [path, ids] of b) {
    const current = next.get(path);
    next.set(path, current ? new Set([...current, ...ids]) : new Set(ids));
  }
  return next;
}

export function statesEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const [path, ids] of a) {
    const other = b.get(path);
    if (!other || other.size !== ids.size) return false;
    for (const id of ids) if (!other.has(id)) return false;
  }
  return true;
}

export function hashState(state) {
  return [...state.entries()]
    .map(([path, ids]) => `${path}=${[...ids].sort().join(',')}`)
    .sort()
    .join('|');
}
```

- [ ] **Step 4: Run to verify all tests pass**

Run: `cd scanner && node --test test/lineage/field-identity.test.js`
Expected: PASS, all 14 tests.

- [ ] **Step 5: Wire into `test:lineage` and confirm the full lineage suite still passes**

Add `test/lineage/field-identity.test.js` to `scanner/package.json`'s `"test:lineage"` script file list. Run: `cd scanner && npm run test:lineage` — expected: PASS, previous lineage tests plus these 14, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/field-identity.js scanner/test/lineage/field-identity.test.js scanner/package.json
git commit -m "feat(lineage): add field-identity state module (Map<path, Set<dataElementId>>)"
```

---

## Task 3: Expression identity resolver

**Files:**
- Create: `scanner/src/lineage/engine.js` (this task only adds `resolveExprIdentities`; Task 4 adds the CFG walker to the same file)
- Test: `scanner/test/lineage/engine-expr-resolver.test.js`

**Interfaces:**
- Consumes: `identitiesAt` from `field-identity.js` (Task 2); `accessPathOf` from `scanner/src/dataflow/access-paths.js` (pure reuse per Task 1's ADR).
- Produces: `resolveExprIdentities(state, expr) → { flat: Set<dataElementId>, byPath: Map<subPath: string, Set<dataElementId>>, widened: boolean }`. Task 4's CFG walker is the consumer.

- [ ] **Step 1: Write failing tests**

Create `scanner/test/lineage/engine-expr-resolver.test.js`. These construct `exprDesc` objects by hand (matching the real shapes from `scanner/src/ir/parser-js.js` — `{kind:'ident',name}`, `{kind:'member',object,prop}`, `{kind:'literal',value}`, `{kind:'object',props:[{key,value}]}`, `{kind:'array',elements}`, `{kind:'tpl',parts}`, `{kind:'call',callee,args}`, `{kind:'binary',op,left,right}`, `{kind:'logical',op,left,right}`, `{kind:'union',branches}`) and hand-built states from Task 2's `field-identity.js` — no real IR parsing needed for this task:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { resolveExprIdentities } from '../../src/lineage/engine.js';

function stateWith(pairs) {
  let s = emptyState();
  for (const [path, id] of pairs) s = addIdentity(s, path, id);
  return s;
}

test('ident resolves via the state at that exact variable name', () => {
  const state = stateWith([['user', 'data:x']]);
  const r = resolveExprIdentities(state, { kind: 'ident', name: 'user' });
  assert.deepEqual([...r.flat], ['data:x']);
  assert.equal(r.widened, false);
});

test('member resolves via the dotted access path', () => {
  const state = stateWith([['user.email', 'data:email']]);
  const r = resolveExprIdentities(state, { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' });
  assert.deepEqual([...r.flat], ['data:email']);
});

test('literal never carries an identity', () => {
  const r = resolveExprIdentities(emptyState(), { kind: 'literal', value: 'hello' });
  assert.equal(r.flat.size, 0);
});

test('object literal attributes each property to its own byPath sub-key, distinctly (FR-301 core case)', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn']]);
  const expr = {
    kind: 'object',
    props: [
      { key: 'email', value: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
      { key: 'ssn', value: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'ssn' } },
    ],
  };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:email', 'data:ssn']);
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
});

test('nested object literal produces dotted sub-paths', () => {
  const state = stateWith([['x', 'data:inner']]);
  const expr = { kind: 'object', props: [{ key: 'a', value: { kind: 'object', props: [{ key: 'b', value: { kind: 'ident', name: 'x' } }] } } ] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.byPath.get('a.b')], ['data:inner']);
});

test('array literal flattens all elements, no index sensitivity', () => {
  const state = stateWith([['a', 'data:1'], ['b', 'data:2']]);
  const expr = { kind: 'array', elements: [{ kind: 'ident', name: 'a' }, { kind: 'ident', name: 'b' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:1', 'data:2']);
  assert.equal(r.byPath.size, 0);
});

test('template literal interpolation propagates identity, NOT flagged as widened', () => {
  const state = stateWith([['email', 'data:email']]);
  const expr = { kind: 'tpl', parts: [{ kind: 'ident', name: 'email' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:email']);
  assert.equal(r.widened, false);
});

test('binary (string concatenation) propagates identity from both sides, not widened', () => {
  const state = stateWith([['a', 'data:1'], ['b', 'data:2']]);
  const expr = { kind: 'binary', op: '+', left: { kind: 'ident', name: 'a' }, right: { kind: 'ident', name: 'b' } };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:1', 'data:2']);
  assert.equal(r.widened, false);
});

test('logical (?? / ||) propagates identity from both sides, not widened', () => {
  const state = stateWith([['a', 'data:1']]);
  const expr = { kind: 'logical', op: '??', left: { kind: 'ident', name: 'a' }, right: { kind: 'literal', value: 'default' } };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:1']);
});

test('ternary (union) merges both branches conservatively', () => {
  const state = stateWith([['a', 'data:1'], ['b', 'data:2']]);
  const expr = { kind: 'union', branches: [{ kind: 'ident', name: 'a' }, { kind: 'ident', name: 'b' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:1', 'data:2']);
});

test('an unresolved call is flagged as widened when its arguments carry an identity', () => {
  const state = stateWith([['secret', 'data:x']]);
  const expr = { kind: 'call', callee: { kind: 'ident', name: 'someFn' }, args: [{ kind: 'ident', name: 'secret' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:x']);
  assert.equal(r.widened, true);
});

test('an unresolved call with no identity-carrying arguments is NOT flagged as widened', () => {
  const expr = { kind: 'call', callee: { kind: 'ident', name: 'someFn' }, args: [{ kind: 'literal', value: 1 }] };
  const r = resolveExprIdentities(emptyState(), expr);
  assert.equal(r.flat.size, 0);
  assert.equal(r.widened, false);
});

test('unknown-kind expression resolves to no identity, fails open', () => {
  const r = resolveExprIdentities(emptyState(), { kind: 'unknown' });
  assert.equal(r.flat.size, 0);
  assert.equal(r.widened, false);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/engine-expr-resolver.test.js`
Expected: FAIL — `engine.js` doesn't exist yet / doesn't export `resolveExprIdentities`.

- [ ] **Step 3: Implement `resolveExprIdentities` in `scanner/src/lineage/engine.js`**

```js
import { accessPathOf } from '../dataflow/access-paths.js';
import { identitiesAt } from './field-identity.js';

function noIdentity() {
  return { flat: new Set(), byPath: new Map(), widened: false };
}

export function resolveExprIdentities(state, expr) {
  if (!expr) return noIdentity();

  switch (expr.kind) {
    case 'ident':
    case 'member': {
      const path = accessPathOf(expr);
      return { flat: path ? identitiesAt(state, path) : new Set(), byPath: new Map(), widened: false };
    }

    case 'literal':
    case 'unknown':
      return noIdentity();

    case 'object': {
      const flat = new Set();
      const byPath = new Map();
      for (const prop of expr.props) {
        const r = resolveExprIdentities(state, prop.value);
        for (const id of r.flat) flat.add(id);
        if (r.flat.size > 0) {
          const existing = byPath.get(prop.key) ?? new Set();
          byPath.set(prop.key, new Set([...existing, ...r.flat]));
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
        const r = resolveExprIdentities(state, el);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'tpl': {
      const flat = new Set();
      for (const part of expr.parts) {
        const r = resolveExprIdentities(state, part);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'binary':
    case 'logical': {
      const left = resolveExprIdentities(state, expr.left);
      const right = resolveExprIdentities(state, expr.right);
      return { flat: new Set([...left.flat, ...right.flat]), byPath: new Map(), widened: false };
    }

    case 'union': {
      const flat = new Set();
      for (const branch of expr.branches) {
        const r = resolveExprIdentities(state, branch);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'call': {
      const flat = new Set();
      for (const arg of expr.args ?? []) {
        const r = resolveExprIdentities(state, arg);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: flat.size > 0 };
    }

    case 'assign-expr': {
      // Nested assignment-as-expression (e.g. `if ((x = getUser()).isAdmin)`)
      // is read-only here: resolves what the expression VALUE carries but
      // does NOT write into `x` in `state` — see
      // scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md §4 for why this is a
      // deliberate, documented limitation, not an oversight.
      const r = resolveExprIdentities(state, expr.source);
      return { flat: r.flat, byPath: new Map(), widened: r.flat.size > 0 };
    }

    default:
      return noIdentity();
  }
}
```

- [ ] **Step 4: Run to verify all tests pass**

Run: `cd scanner && node --test test/lineage/engine-expr-resolver.test.js`
Expected: PASS, all 14 tests.

- [ ] **Step 5: Wire into `test:lineage`, run the full lineage suite**

Add `test/lineage/engine-expr-resolver.test.js` to `scanner/package.json`'s `"test:lineage"` list. Run `cd scanner && npm run test:lineage` — expected PASS, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/test/lineage/engine-expr-resolver.test.js scanner/package.json
git commit -m "feat(lineage): add resolveExprIdentities expression resolver"
```

---

## Task 4: CFG walker — `analyzeFunctionFieldIdentity`

**Files:**
- Modify: `scanner/src/lineage/engine.js` (adds to the file Task 3 started)
- Test: `scanner/test/lineage/engine-walker.test.js`

**Interfaces:**
- Consumes: everything from `field-identity.js` (Task 2) and `resolveExprIdentities` (Task 3, same file).
- Produces: `analyzeFunctionFieldIdentity(fn, entryState) → { exitState, returnFacts: [{nodeId, line, identities: Set}], mutatedParams: Map<paramName, Set<dataElementId>>, widenings: [{atPath, dataElementIds, reason, line}] }`. This is Sub-project A's final output shape — Sub-project B (interprocedural) consumes it directly.

**Before implementing:** read `scanner/src/dataflow/engine.js`'s `analyzeFunction` function (the real forward-worklist loop this task structurally mirrors — search for that function name) to confirm the exact fixed-point termination semantics (when the outer loop stops re-processing a node) match what's written below. This plan's pseudocode was derived from a research pass over that function but was not re-verified line-by-line against it — treat the code below as "the right algorithm, cross-check the exact loop-termination details before trusting them blindly," per this plan's own Global Constraints.

- [ ] **Step 1: Write failing tests**

Create `scanner/test/lineage/engine-walker.test.js`. These hand-build small CFG objects matching the real shape (`{entry, exit, nodes: {id: Node}}`, `Node = {kind, line, succ, pred, ...kind-specific fields}`) — no real parser needed:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyState, addIdentity, identitiesAt } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';

test('a straight-line assignment chain propagates identity through to the return', () => {
  // function f(user) { const email = user.email; return email; }
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n3',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'email', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'return', line: 1, succ: ['n3'], pred: ['n1'], value: { kind: 'ident', name: 'email' } },
        n3: { kind: 'exit', line: 1, succ: [], pred: ['n2'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});

test('reassignment clears stale identity at that path', () => {
  // function f(user) { let x = user.email; x = user.name; return x; }
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n4',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'name' } },
        n3: { kind: 'return', line: 3, succ: ['n4'], pred: ['n2'], value: { kind: 'ident', name: 'x' } },
        n4: { kind: 'exit', line: 3, succ: [], pred: ['n3'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.name', 'data:name');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:name'], 'x must carry only the LAST assignment\'s identity, not both');
});

test('a branch join unions identities from both paths (conservative: either could have executed)', () => {
  // function f(user, flag) { let x; if (flag) { x = user.email; } else { x = user.name; } return x; }
  const fn = {
    params: ['user', 'flag'],
    cfg: {
      entry: 'n0', exit: 'n5',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'if', line: 1, succ: ['n2', 'n3'], pred: ['n0'], cond: { kind: 'ident', name: 'flag' } },
        n2: { kind: 'assign', line: 2, succ: ['n4'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n3: { kind: 'assign', line: 3, succ: ['n4'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'name' } },
        n4: { kind: 'return', line: 4, succ: ['n5'], pred: ['n2', 'n3'], value: { kind: 'ident', name: 'x' } },
        n5: { kind: 'exit', line: 4, succ: [], pred: ['n4'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.name', 'data:name');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:name']);
});

test('mutatedParams reports identities written onto a parameter\'s own path by the function body', () => {
  // function f(target, user) { target.copiedEmail = user.email; }
  const fn = {
    params: ['target', 'user'],
    cfg: {
      entry: 'n0', exit: 'n2',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'target.copiedEmail', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'exit', line: 1, succ: [], pred: ['n1'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.mutatedParams.get('target')], ['data:email']);
});

test('an unresolved call\'s widening event is recorded, not silently dropped', () => {
  // function f(secret) { return someFn(secret); }
  const fn = {
    params: ['secret'],
    cfg: {
      entry: 'n0', exit: 'n2',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'return', line: 1, succ: ['n2'], pred: ['n0'],
          value: { kind: 'call', callee: { kind: 'ident', name: 'someFn' }, args: [{ kind: 'ident', name: 'secret' }] } },
        n2: { kind: 'exit', line: 1, succ: [], pred: ['n1'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'secret', 'data:x');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.equal(result.widenings.length, 1);
  assert.equal(result.widenings[0].reason, 'unresolved-call');
  assert.deepEqual(result.widenings[0].dataElementIds, ['data:x']);
});

test('a simple loop back-edge converges (does not infinite-loop) and preserves the identity carried around it', () => {
  // function f(user) { let x = user.email; while (cond) { } return x; }
  // (loop body doesn't touch x — this just proves the worklist terminates on a back-edge)
  const fn = {
    params: ['user', 'cond'],
    cfg: {
      entry: 'n0', exit: 'n5',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'loop-header', line: 2, succ: ['n3', 'n4'], pred: ['n1', 'n3'] },
        n3: { kind: 'noop', line: 2, succ: ['n2'], pred: ['n2'] },
        n4: { kind: 'return', line: 3, succ: ['n5'], pred: ['n2'], value: { kind: 'ident', name: 'x' } },
        n5: { kind: 'exit', line: 3, succ: [], pred: ['n4'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/engine-walker.test.js`
Expected: FAIL — `analyzeFunctionFieldIdentity` doesn't exist yet.

- [ ] **Step 3: Implement `analyzeFunctionFieldIdentity` in `scanner/src/lineage/engine.js`** (append to the file from Task 3)

```js
import { joinStates, statesEqual, identitiesAt } from './field-identity.js'; // extend the existing import from field-identity.js in this file

function step(node, stateIn, widenings) {
  switch (node.kind) {
    case 'assign': {
      const resolved = resolveExprIdentities(stateIn, node.source);
      let state = removeIdentitiesAt(stateIn, node.target);
      for (const id of resolved.flat) state = addIdentity(state, node.target, id);
      for (const [subPath, ids] of resolved.byPath) {
        for (const id of ids) state = addIdentity(state, `${node.target}.${subPath}`, id);
      }
      if (resolved.widened && resolved.flat.size > 0) {
        widenings.push({ atPath: node.target, dataElementIds: [...resolved.flat], reason: 'unresolved-call', line: node.line });
      }
      return { state, returnFact: null };
    }

    case 'call': {
      for (const arg of node.args ?? []) {
        const r = resolveExprIdentities(stateIn, arg);
        if (r.flat.size > 0) {
          widenings.push({ atPath: null, dataElementIds: [...r.flat], reason: 'unresolved-call-arg', line: node.line });
        }
      }
      return { state: stateIn, returnFact: null };
    }

    case 'return': {
      const resolved = node.value ? resolveExprIdentities(stateIn, node.value) : { flat: new Set(), widened: false };
      if (resolved.widened && resolved.flat.size > 0) {
        widenings.push({ atPath: null, dataElementIds: [...resolved.flat], reason: 'unresolved-call', line: node.line });
      }
      return { state: stateIn, returnFact: resolved.flat };
    }

    case 'entry':
    case 'exit':
    case 'noop':
    case 'loop-header':
    case 'if':
    case 'throw':
    case 'unknown':
    default:
      return { state: stateIn, returnFact: null };
  }
}

export function analyzeFunctionFieldIdentity(fn, entryState) {
  const nodes = fn.cfg.nodes;
  const work = [fn.cfg.entry];
  const inStates = new Map([[fn.cfg.entry, entryState]]);
  const outStates = new Map();
  const widenings = [];
  const returnFacts = [];

  while (work.length) {
    const nid = work.shift();
    const node = nodes[nid];
    const incoming = inStates.get(nid) ?? emptyState();
    const { state: out, returnFact } = step(node, incoming, widenings);
    if (returnFact && returnFact.size > 0) {
      returnFacts.push({ nodeId: nid, line: node.line, identities: returnFact });
    }

    const prevOut = outStates.get(nid);
    const merged = prevOut ? joinStates(prevOut, out) : out;
    if (!prevOut || !statesEqual(prevOut, merged)) {
      outStates.set(nid, merged);
      for (const succ of node.succ ?? []) {
        const prevIn = inStates.get(succ);
        const newIn = prevIn ? joinStates(prevIn, merged) : merged;
        if (!prevIn || !statesEqual(prevIn, newIn)) {
          inStates.set(succ, newIn);
          work.push(succ);
        }
      }
    }
  }

  const exitState = outStates.get(fn.cfg.exit) ?? emptyState();
  const mutatedParams = new Map();
  for (const param of fn.params) {
    const ids = identitiesAt(exitState, param);
    if (ids.size > 0) mutatedParams.set(param, ids);
  }

  return { exitState, returnFacts, mutatedParams, widenings };
}
```

(Add `emptyState`, `removeIdentitiesAt`, `addIdentity` to this file's existing `field-identity.js` import line from Task 3 rather than duplicating an import statement — Task 3 already imports `identitiesAt`; extend that one import line to cover everything this task additionally needs.)

**A note on the `returnFacts` filter (`if (returnFact && returnFact.size > 0)`):** a `return` node reached with genuinely no identity-carrying value should not appear in `returnFacts` at all — an empty entry would be indistinguishable from "this return statement was never analyzed," which is a real ambiguity worth avoiding. If your test fixtures need to assert on "this function has a return with no identity," assert on `returnFacts.length === 0` or absence, not on a present-but-empty entry.

- [ ] **Step 4: Run to verify all tests pass**

Run: `cd scanner && node --test test/lineage/engine-walker.test.js`
Expected: PASS, all 6 tests. If the loop-convergence test hangs or the join test produces the wrong result, revisit Step 3's cross-check against the real `analyzeFunction` in `scanner/src/dataflow/engine.js` — the worklist termination condition is the most likely source of a subtle bug here.

- [ ] **Step 5: Wire into `test:lineage`, run the full lineage suite**

Add `test/lineage/engine-walker.test.js` to `scanner/package.json`'s `"test:lineage"` list. Run `cd scanner && npm run test:lineage` — expected PASS, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/test/lineage/engine-walker.test.js scanner/package.json
git commit -m "feat(lineage): add analyzeFunctionFieldIdentity CFG worklist walker"
```

---

## Task 5: Integration tests against real parsed JS/TS IR (destructuring + end-to-end proof)

**Files:**
- Test: `scanner/test/lineage/engine-integration.test.js`
- Possibly modify: `scanner/src/lineage/engine.js` (only if destructuring needs new handling — see Step 1)

**Interfaces:**
- Consumes: the real IR parser from `scanner/src/ir/parser-js.js` (find its exact exported function name and signature yourself — it was not pinned down precisely by this plan's research pass); `analyzeFunctionFieldIdentity` (Task 4).
- Produces: nothing new for other code — proves the whole pipeline (Tasks 2–4) works against real parser output, not just hand-built fixtures, and resolves the one open question this plan deliberately left open (destructuring).

- [ ] **Step 1: Investigate destructuring's real CFG lowering BEFORE writing this task's tests**

Read `scanner/src/ir/parser-js.js` in full, focusing on how a `VariableDeclarator` with an `ObjectPattern`/`ArrayPattern` id (e.g. `const {email, ssn} = user`) or a destructured function parameter gets turned into CFG nodes. Per this plan's Task 1 ADR §4, one of two things is true, and you must determine which before writing Step 2's tests:

- **(a)** The parser already lowers a destructuring declarator into multiple simple `assign` CFG nodes, each with a plain string `target` (e.g. `email`) and a `member`-kind `source` (e.g. `{kind:'member', object:{kind:'ident',name:'user'}, prop:'email'}`) — in which case Task 4's existing `step()` `assign` case handles destructuring with **zero new code**, and this task is purely a testing task.
- **(b)** The parser produces something else (a distinct CFG node kind, or an `assign` node whose `target`/`source` has a compound/pattern shape) — in which case this task must add a new case to `step()` (in `scanner/src/lineage/engine.js`) that walks the pattern and attributes each destructured binding to its own path, mirroring the per-property attribution logic `resolveExprIdentities`'s `object` case already uses (Task 3). Design and implement this new case following that same pattern (recursive per-binding resolution, each binding's identity written via `addIdentity` at its own variable-name path) before proceeding to Step 2.

State clearly in your task report which of (a) or (b) was true and what you found — this is a real, disclosed discovery this plan's own research pass could not make (it explicitly did not read this section of the parser), not a minor detail to skip over.

- [ ] **Step 2: Write integration tests using the real parser**

Create `scanner/test/lineage/engine-integration.test.js`. Find the real exported parse function from `scanner/src/ir/parser-js.js` (confirm its exact name/signature — likely something like `parseJsFile(source, filename)` or similar returning the `{functions, topLevel}` shape, but verify against the real export list rather than assuming) and use it to parse small, real JS source strings (write them to a temp file if the parser requires a file path, matching whatever the real function needs — check `scanner/test/interproc-k2.test.js` for the real pattern of getting source into the parser, per this plan's own research). At minimum, cover:

1. **FR-301's core proof case, end-to-end from real parsed source**: a function building an object from two distinct fields, e.g.
   ```js
   function combine(user) {
     return { email: user.email, ssn: user.ssn };
   }
   ```
   Parse it, call `analyzeFunctionFieldIdentity` with an entry state where `user.email` carries `data:email` and `user.ssn` carries `data:ssn`, and assert the resulting `returnFacts` entry's identities include both, AND (if you extend `resolveExprIdentities`'s per-return tracking to expose `byPath` at the return-fact level — check whether Task 4's `returnFacts` shape as written captures `byPath` at all; if it doesn't, that's fine for this plan's scope, but the test should assert on what you can actually observe, not on a field this plan didn't build) that the flat identity set contains both `data:email` and `data:ssn` and never collapses them into one merged fact.

2. **Destructuring** (using whatever shape Step 1 determined is real): a function like
   ```js
   function extract(user) {
     const { email, ssn } = user;
     return email;
   }
   ```
   parsed for real, entry state with `user.email`/`user.ssn` set, asserting the return fact contains only `data:email`, not `data:ssn` — proving destructuring correctly extracts one field without conflating it with its sibling.

3. **Template literal propagation from real source**:
   ```js
   function greet(user) {
     return `Hello ${user.email}`;
   }
   ```
   asserting the return fact contains `data:email`, and no widening event was recorded (per the ADR's template-literal design decision).

Each test must parse REAL source through the REAL parser — no hand-built IR objects in this file (that was Tasks 2–4's job; this task exists specifically to catch any place a hand-built fixture didn't match reality).

- [ ] **Step 3: Run to verify tests pass**

Run: `cd scanner && node --test test/lineage/engine-integration.test.js`
Expected: PASS. If a test fails because the real parsed IR shape differs from what Tasks 3/4 assumed (e.g. a `member` node's `prop` field is shaped differently than expected), fix the discrepancy at its root — in `resolveExprIdentities`/`step()` if the fix is general, or note it as a plan-deviation in your report if it reveals a wrong assumption elsewhere in this plan.

- [ ] **Step 4: Wire into `test:lineage`, run the full lineage suite one more time**

Add `test/lineage/engine-integration.test.js` to `scanner/package.json`'s `"test:lineage"` list. Run `cd scanner && npm run test:lineage` — expected PASS, 0 failures, full count reported in your final report.

- [ ] **Step 5: Commit**

```bash
git add scanner/test/lineage/engine-integration.test.js scanner/src/lineage/engine.js scanner/package.json
git commit -m "test(lineage): integration tests against real parsed JS/TS IR, resolve destructuring handling"
```

---

## Self-Review Notes (from the plan author)

- **Spec coverage:** FR-301 (multi-label identity preservation) is directly proven by Task 2's "two distinct fields coexist" test and Task 5's real-parser integration test. The reuse boundary (§18.1) is settled in Task 1's ADR and enforced by every later task's imports. Widening/implicit-flow marking (FR-306, partial — only the "unresolved call" trigger, not the full taxonomy) is built via the `widenings` side-channel in Task 4, honestly scoped as partial in the ADR §5. Interprocedural (FR-302), path DAG (FR-303), and everything registry/graph-output-related are explicitly out of scope per the ADR §5 and the parent scoping document — not gaps in this plan, deliberate boundaries.
- **Known, disclosed uncertainty:** destructuring's real CFG shape (Task 5, Step 1) — this plan does not pretend to know it; it assigns a verification step with two designed fallback paths rather than guessing.
- **Type/interface consistency check:** `resolveExprIdentities`'s return shape (`{flat, byPath, widened}`, Task 3) is consumed identically in Task 4's `step()` (`assign` and `return` cases) and in Task 5's assertions. `analyzeFunctionFieldIdentity`'s return shape (`{exitState, returnFacts, mutatedParams, widenings}`, Task 4) is what Task 5 asserts against and what the plan's own Goal section describes as this sub-project's final deliverable — consistent throughout.
