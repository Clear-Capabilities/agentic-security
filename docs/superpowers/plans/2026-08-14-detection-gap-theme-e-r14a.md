# Detection-gap PRD R14(a) — annotation/decorator-shaped framework sources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Layer-2 taint catalog a way to recognize framework-annotation-shaped sources — Spring `@RequestParam`/`@PathVariable`/`@RequestBody`, ASP.NET Core `[FromQuery]`/`[FromBody]`/`[FromForm]`, NestJS `@Query()`/`@Body()` — so a controller-method parameter carrying one of these decorators is treated as tainted at function entry, the same way `req.body` is treated as tainted when read inside a function body today.

**Architecture:** A new catalog `match.type: 'annotation'` kind, keyed by bare decorator/attribute name in a new `ANNOTATION_INDEX`. Three language frontends (C#, JS/TS, Java) are extended to populate a new, purely additive IR field — `fn.paramAnnotations: [{index, name, decorator}]` — populated only where a parameter carries a decorator/attribute; absent or empty for every other function. The taint engine gains one new helper, `_unionAnnotationTaint(fn, entrySet)`, called at every one of the 8 existing `analyzeFunction(...)` call sites in `engine.js`, unioning any annotation-matched parameter names into that call's entry-taint state. This treats annotation-derived taint as an invariant fact about the function (like its signature), not something that depends on the calling context — correct because a decorator's presence never changes between calls.

**Tech Stack:** Node.js ESM, `@babel/parser` (JS/TS), `java-parser` (Java), hand-rolled regex parser (C#).

## Global Constraints

- **`fn.params` never changes shape.** It stays `['string', ...]` exactly as documented in `scanner/src/ir/CLAUDE.md`'s IR shape contract. `fn.paramAnnotations` is a NEW, OPTIONAL, side-channel field — present only on functions with at least one annotated parameter, absent (`undefined`, never `[]`) on every other function. `ir/CLAUDE.md` documents a real prior incident (`parser-js.js:168-177`'s header comment) where a richer per-param object shape silently broke every `fn.params` consumer for a release cycle because nothing threw — do not repeat that mistake by touching `fn.params` itself anywhere in this plan.
- **`fn.paramAnnotations` shape**, fixed across all three producing parsers:
  ```js
  fn.paramAnnotations = [
    { index: 0, name: 'q', decorator: 'RequestParam' },
    { index: 1, name: 'id', decorator: 'PathVariable' },
  ];
  ```
  `index` is the parameter's 0-based position (informational only, not consumed by this plan — kept for future k>1 call-string work per `dataflow/CLAUDE.md`'s stated scope gaps). `name` is the parameter's own name, exactly as it appears in `fn.params` at that index (this is the field the engine actually unions into the taint set). `decorator` is the bare decorator/attribute name with no `@`, brackets, or arguments (`RequestParam`, not `@RequestParam` or `RequestParam(...)`).
- **Annotation-derived taint is call-site-invariant.** It must be unioned into the entry-taint Set at every `analyzeFunction` call site in `engine.js` (8 total, enumerated in Task 2), not just the empty-entry base pass — a controller method that also happens to be called directly in-repo (e.g. from a test) must still see its annotation-tainted params, even under a real caller's own entry-state shape. Do not special-case "only the base pass."
- **Do not touch `SummaryCache`'s cache-key semantics.** The cache key passed to `summaryCache.compute(qid, entry, ...)` / `summaryCache.get(fn.qid, entry)` stays exactly the caller-driven `entry`/`fields`/`taintedEntry` Set it is today — annotation taint is unioned in only for the value passed to `analyzeFunction` itself, immediately at the call site, never for the cache key. This is correct (not a shortcut): annotation taint is a function-invariant fact, identical for every call to that qid, so it does not need to vary the cache key.
- **Accepted, documented risk: no import-binding verification for decorator names.** Matching is by bare decorator name (e.g. `Query`) scoped by `language` (via the existing `_languageAllowed` catalog helper) — the same precision level every other catalog match kind (`call`, `member`, `global`) already has, and the same false-positive class the catalog's own header premortem already documents for bare C/C++ callee names. A same-named, unrelated decorator in the same language (e.g. a hypothetical Java `@Query` from a different, non-Spring library) could collide. This is explicitly accepted for this plan, not silently ignored — Task 6 must call it out in the docs update, matching how the codebase already documents this class of risk elsewhere rather than pretending it doesn't exist.
- **Byte-identical behavior for every existing fixture with no annotated parameters.** `fn.paramAnnotations` is absent for such functions, `_unionAnnotationTaint` becomes a no-op passthrough (returns the original Set instance unchanged, not a copy), and no new catalog entry fires. This is the concrete, testable form of "strictly additive" for this plan.

---

### Task 1: Catalog schema — `annotation` match kind

**Files:**
- Modify: `scanner/src/dataflow/catalog.js`
- Test: create `scanner/test/catalog-annotation-source.test.js`

**Interfaces:**
- Consumes: the existing `_languageAllowed(entry, file)` function (`catalog.js:853`, unexported/local — already used by `matchSource`), the existing `CATALOG` array and its per-entry `{kind, id, language, framework, match, ...}` shape (`catalog.js:22-38` header comment).
- Produces: `export function matchAnnotationParams(paramAnnotations, file)` — takes `fn.paramAnnotations` (or `undefined`/`[]`) and a file path, returns a `Set<string>` of parameter NAMES (not indices) whose decorator matched a `kind: 'source'` catalog entry of type `'annotation'`, scoped by language via `_languageAllowed`. Returns an empty `Set` (never `null`/`undefined`) for empty/absent input.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/catalog-annotation-source.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchAnnotationParams } from '../src/dataflow/catalog.js';

test('matchAnnotationParams: empty/absent input returns an empty Set', () => {
  assert.deepEqual(matchAnnotationParams(undefined, 'App.java'), new Set());
  assert.deepEqual(matchAnnotationParams([], 'App.java'), new Set());
});

test('matchAnnotationParams: a matching Spring decorator taints its param name', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    'UserController.java'
  );
  assert.ok(result.has('q'));
  assert.equal(result.size, 1);
});

test('matchAnnotationParams: multiple annotated params, only catalogued decorators taint', () => {
  const result = matchAnnotationParams(
    [
      { index: 0, name: 'q', decorator: 'RequestParam' },
      { index: 1, name: 'id', decorator: 'PathVariable' },
      { index: 2, name: 'svc', decorator: 'Autowired' },
    ],
    'UserController.java'
  );
  assert.ok(result.has('q'));
  assert.ok(result.has('id'));
  assert.ok(!result.has('svc'), '@Autowired is not a source-shaped annotation and must not taint');
  assert.equal(result.size, 2);
});

test('matchAnnotationParams: language scoping — a Java-only decorator name does not fire on a C# file', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    'Controller.cs'
  );
  assert.equal(result.size, 0, '@RequestParam is Spring/Java-scoped; must not match on a .cs file');
});

test('matchAnnotationParams: ASP.NET Core [FromQuery] taints its param name on a .cs file', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'FromQuery' }],
    'Controller.cs'
  );
  assert.ok(result.has('q'));
});

test('matchAnnotationParams: NestJS @Query() taints its param name on a .ts file', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'Query' }],
    'app.controller.ts'
  );
  assert.ok(result.has('q'));
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/catalog-annotation-source.test.js`
Expected: FAIL — `matchAnnotationParams` is not exported yet.

- [ ] **Step 3: Implement the schema addition**

In `scanner/src/dataflow/catalog.js`, find the index-building loop (around line 980-1002, the one building `CALLEE_INDEX`/`MEMBER_INDEX`/`GLOBAL_INDEX`). Add a fourth index and a fourth branch:

```js
const ANNOTATION_INDEX = new Map();
```

(add this declaration alongside the existing three `const ..._INDEX = new Map();` lines)

```js
  } else if (e.match.type === 'annotation' && e.match.name) {
    const k = e.match.name;
    if (!ANNOTATION_INDEX.has(k)) ANNOTATION_INDEX.set(k, []);
    ANNOTATION_INDEX.get(k).push(e);
  }
```

(add as a new `else if` branch in the same loop that builds the other three indexes, after the existing `global` branch)

Then add the new exported matcher function, near the other exported `match*` functions (after `matchMemberWriteSink`, around line 1150-1160):

```js
// R14(a): annotation/decorator-shaped framework sources (Spring @RequestParam,
// ASP.NET Core [FromQuery], NestJS @Query()). Unlike matchSource/matchSinkOrSanitizer,
// this does not consult an expression encountered while walking a CFG node —
// there is no CFG node for "this function's own declared parameter list." It is
// consulted once per function, against the IR's paramAnnotations side-channel,
// by engine.js's _unionAnnotationTaint before each analyzeFunction call.
export function matchAnnotationParams(paramAnnotations, file) {
  const tainted = new Set();
  if (!paramAnnotations || !paramAnnotations.length) return tainted;
  for (const pa of paramAnnotations) {
    const hits = ANNOTATION_INDEX.get(pa.decorator);
    if (!hits) continue;
    for (const e of hits) {
      if (e.kind !== 'source') continue;
      if (!_languageAllowed(e, file)) continue;
      tainted.add(pa.name);
      break;
    }
  }
  return tainted;
}
```

Now add the catalog entries themselves. Find a sensible location among the existing `source` entries (e.g. near the other `java`/`cs`/`js` source entries) and add:

```js
  // R14(a): annotation/decorator-shaped framework sources.
  { kind: 'source', id: 'java-spring-requestparam',  language: 'java', framework: 'spring', match: { type: 'annotation', name: 'RequestParam' },  label: '@RequestParam (Spring)' },
  { kind: 'source', id: 'java-spring-pathvariable',  language: 'java', framework: 'spring', match: { type: 'annotation', name: 'PathVariable' },  label: '@PathVariable (Spring)' },
  { kind: 'source', id: 'java-spring-requestbody',   language: 'java', framework: 'spring', match: { type: 'annotation', name: 'RequestBody' },   label: '@RequestBody (Spring)' },
  { kind: 'source', id: 'java-spring-requestheader',  language: 'java', framework: 'spring', match: { type: 'annotation', name: 'RequestHeader' }, label: '@RequestHeader (Spring)' },
  { kind: 'source', id: 'cs-aspnet-fromquery',   language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromQuery' },   label: '[FromQuery] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-frombody',    language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromBody' },    label: '[FromBody] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-fromform',    language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromForm' },    label: '[FromForm] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-fromroute',   language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromRoute' },   label: '[FromRoute] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-fromheader',  language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromHeader' },  label: '[FromHeader] (ASP.NET Core)' },
  { kind: 'source', id: 'js-nestjs-query',   language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Query' },   label: '@Query() (NestJS)' },
  { kind: 'source', id: 'js-nestjs-body',    language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Body' },    label: '@Body() (NestJS)' },
  { kind: 'source', id: 'js-nestjs-param',   language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Param' },   label: '@Param() (NestJS)' },
  { kind: 'source', id: 'js-nestjs-headers', language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Headers' }, label: '@Headers() (NestJS)' },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/catalog-annotation-source.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing catalog test coverage to confirm no regressions**

Run: `cd scanner && node --test test/catalog-expanded.test.js test/catalog-dotted-callee-lookup.test.js test/phase2-scoping.test.js`
Expected: ALL PASS unchanged — the new index/branch is additive and must not affect any existing `call`/`member`/`global` matching.

- [ ] **Step 6: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/catalog-annotation-source.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/dataflow/catalog.js scanner/test/catalog-annotation-source.test.js scanner/package.json
git commit -m "feat(dataflow): PRD R14(a) — add annotation/decorator match kind to the taint catalog"
```

---

### Task 2: Engine plumbing — union annotation taint at every `analyzeFunction` call site

**Files:**
- Modify: `scanner/src/dataflow/engine.js`
- Test: create `scanner/test/annotation-taint-engine.test.js`

**Interfaces:**
- Consumes: `matchAnnotationParams(paramAnnotations, file)` from Task 1 (import it into `engine.js` alongside the existing `matchSource`/`matchSinkOrSanitizer`/`matchMemberWriteSink` imports).
- Produces: a new local helper `_unionAnnotationTaint(fn, entrySet)` in `engine.js`, called at all 8 `analyzeFunction(...)` invocation sites, replacing the taint-state argument at each call. This task does NOT touch any real-world parser — it proves the plumbing works by hand-constructing an IR fixture with `paramAnnotations` set directly (Tasks 3-5 give real parsers the ability to populate that field).

This task's fixture uses a Java-shaped file path with a hand-built IR object — you do not need `java-parser` or any real parsing to test this task; you are testing `engine.js`'s consumption of the `paramAnnotations` field, not any parser's production of it.

- [ ] **Step 1: Write the failing test**

Create `scanner/test/annotation-taint-engine.test.js`. Read `scanner/test/receiver-type-and-nested-calls.test.js` first for this codebase's existing pattern of hand-constructing a `perFileIR`/`callGraph` pair and calling `runTaintEngine` directly (do not use `runScan`/real file parsing for this task — that comes in Tasks 3-5's end-to-end tests). Match that file's exact construction style. Your fixture:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runTaintEngine } from '../src/dataflow/engine.js';

test('R14(a): a paramAnnotations-tainted parameter reaches a sink even with no caller-supplied taint', () => {
  // Simulates: public String show(@RequestParam String q) { Statement.execute(q); }
  // No in-repo caller passes tainted data — this is exactly the shape of a
  // Spring controller method invoked by the framework via reflection, which
  // the empty-entry base pass (engine.js's main analysis loop) must catch.
  const fn = {
    qid: 'UserController.java::UserController::show@3',
    name: 'UserController.show',
    line: 3,
    params: ['q'],
    paramAnnotations: [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    file: 'UserController.java',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 3, succ: ['n3'], pred: ['n1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 4, succ: [], pred: ['n2'] },
      },
    },
  };
  const perFileIR = { 'UserController.java': { file: 'UserController.java', functions: [fn], topLevel: null } };
  const callGraph = { functions: new Map([[fn.qid, fn]]), edges: [], callersOf: new Map() };
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'UserController.java' && /command injection|sql injection/i.test(f.vuln || ''));
  assert.ok(hit, `expected an annotation-sourced finding, got: ${JSON.stringify(findings.map(f => f.vuln))}`);
});

test('R14(a): a function with no paramAnnotations is unaffected (no false positive)', () => {
  const fn = {
    qid: 'Helper.java::Helper::show@3',
    name: 'Helper.show',
    line: 3,
    params: ['q'],
    // no paramAnnotations field at all
    file: 'Helper.java',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 3, succ: ['n3'], pred: ['n1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 4, succ: [], pred: ['n2'] },
      },
    },
  };
  const perFileIR = { 'Helper.java': { file: 'Helper.java', functions: [fn], topLevel: null } };
  const callGraph = { functions: new Map([[fn.qid, fn]]), edges: [], callersOf: new Map() };
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'Helper.java');
  assert.equal(hit, undefined, 'q is an untainted local parameter with no annotation and no caller-supplied taint — must not fire');
});
```

Adjust the exact `cfg` node shape/`vuln` regex to match whatever `test/receiver-type-and-nested-calls.test.js` or `test/java-taint-flow.test.js` actually uses for a minimal hand-built Java-shaped call-sink fixture — the illustrative code above must produce a real finding once Task 2 is implemented; if the sink catalog entry you're matching against (`executeQuery`) needs a specific receiver shape or `argIndex`, read `catalog.js`'s `java-stmt-executeQuery` entry (`language: 'java', framework: 'jdbc'`) to confirm the exact match requirements before finalizing this fixture.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/annotation-taint-engine.test.js`
Expected: the first test FAILs (no finding — `paramAnnotations` isn't consumed yet); the second passes already (status quo).

- [ ] **Step 3: Implement `_unionAnnotationTaint` and wire it into all 8 call sites**

In `scanner/src/dataflow/engine.js`, add the import (alongside the existing catalog imports near the top of the file):

```js
import { matchAnnotationParams } from './catalog.js';
```

Add the helper function (near `analyzeFunction`'s definition, or any other local helper — follow the file's existing convention for where local `_`-prefixed helpers live):

```js
// R14(a): annotation-derived taint is a function-invariant fact — identical
// for every call to this qid — so it is unioned into the per-call-site entry
// state, never into the SummaryCache key (that stays exactly what the caller
// supplied). Returns the ORIGINAL Set unchanged when there's nothing to add,
// so callers that never touch annotation-shaped params pay zero extra cost.
function _unionAnnotationTaint(fn, entrySet) {
  if (!fn.paramAnnotations || !fn.paramAnnotations.length) return entrySet;
  const extra = matchAnnotationParams(fn.paramAnnotations, fn.file);
  if (!extra.size) return entrySet;
  return new Set([...entrySet, ...extra]);
}
```

Now wire it into each of the 8 call sites (verify exact line numbers against the current file — they may have shifted slightly since this plan was written; find each by searching for `analyzeFunction(`):

1. Line ~284: `try { analyzeFunction(fn, entry, inner); } catch {}` → `try { analyzeFunction(fn, _unionAnnotationTaint(fn, entry), inner); } catch {}`
2. Line ~713: same pattern, same replacement.
3. Line ~847: same pattern, same replacement.
4. Line ~1194: `try { analyzeFunction(fn, entry, ctx); } catch {}` → `try { analyzeFunction(fn, _unionAnnotationTaint(fn, entry), ctx); } catch {}` (the `entry` here is `new Set()` from the k=2/empty pre-pass at line ~1180 — do not touch the `summaryCache.get(fn.qid, entry)` cache-key call a few lines above it, only the `analyzeFunction` call itself).
5. Line ~1263: `try { analyzeFunction(fn, fields, ctx); } catch {}` → `try { analyzeFunction(fn, _unionAnnotationTaint(fn, fields), ctx); } catch {}`
6. Line ~1298: `try { analyzeFunction(fn, taintedEntry, ctx); } catch {}` → `try { analyzeFunction(fn, _unionAnnotationTaint(fn, taintedEntry), ctx); } catch {}`
7. Line ~1348: `analyzeFunction(fn, new Set(), callContext);` → `analyzeFunction(fn, _unionAnnotationTaint(fn, new Set()), callContext);` (this is the MAIN empty-entry base pass — the one a Spring/ASP.NET/NestJS controller method with no in-repo caller is actually analyzed through; this is the single most important of the 8 sites).
8. Line ~1383: `try { analyzeFunction(cbFn, cbEntry, inner); } catch {}` → `try { analyzeFunction(cbFn, _unionAnnotationTaint(cbFn, cbEntry), inner); } catch {}` (note: `cbFn`/`cbEntry`, not `fn`/`entry` — this is the higher-order-callback analysis site).

Do not touch any `summaryCache.compute(qid, entry, ...)` or `summaryCache.get(fn.qid, entry)` call — only the `analyzeFunction(...)` call itself at each site, per the Global Constraint above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/annotation-taint-engine.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing dataflow test coverage to confirm no regressions**

Run: `cd scanner && npm run test:dataflow`
Expected: ALL PASS, including every pre-existing test — confirms the passthrough (no-op for functions without `paramAnnotations`) holds for the entire existing test suite.

- [ ] **Step 6: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/annotation-taint-engine.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/dataflow/engine.js scanner/test/annotation-taint-engine.test.js scanner/package.json
git commit -m "feat(dataflow): PRD R14(a) — union annotation-derived taint at every analyzeFunction call site"
```

---

### Task 3: C# — extract `[FromQuery]`/`[FromBody]`/etc. attributes

**Files:**
- Modify: `scanner/src/ir/parser-cs.js`
- Test: `scanner/test/parser-cs-kt.test.js` (extend) or create `scanner/test/parser-cs-annotations.test.js` — check which existing file already covers `parser-cs.js` params and extend that one if it fits cleanly, otherwise create a new file.

**Interfaces:**
- Consumes: nothing new — the raw per-parameter text (`paramsText`/`p`, around `parser-cs.js:273-280`) already contains the attribute text (`[FromQuery] string q`) before the existing trailing-identifier extraction discards everything but the last identifier.
- Produces: `fn.paramAnnotations` populated for C# functions with at least one `[Attribute]`-prefixed parameter, per the Global Constraints' fixed shape.

This is the cheapest of the three language tasks — the data is already sitting in a local variable at the exact point params are built; it only needs to be read before it's discarded, not newly parsed.

- [ ] **Step 1: Write the failing test**

Read the current `scanner/src/ir/parser-cs.js` around lines 266-285 (param extraction) in full before writing the test, to confirm the exact current variable names (`paramsText`, the per-param loop variable, etc. — these may have shifted slightly). Then add a test (in `test/parser-cs-kt.test.js` if there's already a params-focused describe block for C#, otherwise a new `test/parser-cs-annotations.test.js`):

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCSharpFile } from '../src/ir/parser-cs.js';

test('parseCSharpFile: [FromQuery] attribute on a parameter populates fn.paramAnnotations', () => {
  const code = `
public class UserController {
    public string Show([FromQuery] string q) {
        return q;
    }
}
`;
  const ir = parseCSharpFile('UserController.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('Show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q'], 'fn.params must stay plain strings, unaffected by this change');
  assert.ok(fn.paramAnnotations, 'expected paramAnnotations to be populated');
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'FromQuery' }]);
});

test('parseCSharpFile: a parameter with no attribute gets no paramAnnotations entry', () => {
  const code = `
public class Helper {
    public string Show(string q) {
        return q;
    }
}
`;
  const ir = parseCSharpFile('Helper.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('Show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.ok(!fn.paramAnnotations || fn.paramAnnotations.length === 0, 'no attribute present — paramAnnotations must be absent or empty');
});

test('parseCSharpFile: multiple parameters, only the attributed one is recorded', () => {
  const code = `
public class UserController {
    public string Show([FromQuery] string q, string extra) {
        return q;
    }
}
`;
  const ir = parseCSharpFile('UserController.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('Show'));
  assert.deepEqual(fn.params, ['q', 'extra']);
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'FromQuery' }]);
});
```

The export is `parseCSharpFile` (`scanner/src/ir/parser-cs.js:266`), confirmed directly against the current file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-cs-annotations.test.js` (or whichever file you added the tests to)
Expected: FAIL — `paramAnnotations` isn't populated yet.

- [ ] **Step 3: Implement attribute extraction**

Read the current per-parameter mapping code in `parser-cs.js` (around lines 274-280) in full. It currently does something shaped like:

```js
const params = paramsText.split(',').map(p => {
  const t = p.trim();
  const last = t.replace(/=.*$/, '').trim().split(/\s+/).pop();
  return last && /^[A-Za-z_][\w]*$/.test(last) ? last : null;
}).filter(Boolean);
```

Extend it to ALSO extract a leading `[AttributeName]` or `[AttributeName(...)]` from each raw parameter text `p` (before it's trimmed/reduced to just the trailing identifier), collecting matches into a side array. A C# parameter attribute is written `[AttributeName]` or `[AttributeName("arg")]` immediately before the type: `[FromQuery] string q`. Rewrite the mapping to build both `params` and `paramAnnotations` in one pass:

```js
const paramAnnotations = [];
const params = paramsText.split(',').map((p, idx) => {
  const t = p.trim();
  const attrMatch = t.match(/^\[\s*([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*\]/);
  const last = t.replace(/=.*$/, '').trim().split(/\s+/).pop();
  const name = last && /^[A-Za-z_][\w]*$/.test(last) ? last : null;
  if (attrMatch && name) {
    paramAnnotations.push({ index: idx, name, decorator: attrMatch[1] });
  }
  return name;
}).filter(Boolean);
```

Note: `idx` from `.map((p, idx) => ...)` is the index into the RAW comma-split array, which is correct since `paramAnnotations`'s `index` field is documented as informational/positional and every parameter (attributed or not) occupies one slot in that same split — even though `.filter(Boolean)` at the end removes `null` entries from `params`, the `idx` values pushed into `paramAnnotations` were captured before filtering, so they still correspond to `paramsText.split(',')`'s original positions, not `params`'s post-filter positions. This is consistent with how the field is defined (informational only, not consumed by Task 2's logic, which matches on `name` not `index`) — verify this reasoning holds by reading the actual current code before implementing, since `idx`-vs-post-filter-position mismatches are exactly the kind of subtle bug this note exists to prevent.

Then, in the function-record construction (wherever `params` is assigned onto the pushed function object, likely `params,` in an object literal), add:

```js
...(paramAnnotations.length ? { paramAnnotations } : {}),
```

— conditionally spread so the field is genuinely ABSENT (not an empty array) when there's nothing to report, matching the Global Constraint.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-cs-annotations.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing C# test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-cs-kt.test.js`
Expected: ALL PASS unchanged — `fn.params` output must be byte-identical to before this change for every existing fixture.

- [ ] **Step 6: End-to-end test — the PRD's own ASP.NET Core success shape**

Add one more test (same file) proving the full pipeline (Task 1 catalog + Task 2 engine + this task's parser extraction) together, via a real `runScan`:

```js
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

test('R14(a) end-to-end: ASP.NET Core [FromQuery] flowing to a command-injection sink is detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14a-cs-'));
  fs.writeFileSync(path.join(dir, 'PingController.cs'), `
public class PingController {
    public string Ping([FromQuery] string host) {
        System.Diagnostics.Process.Start("ping", host);
        return "ok";
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an annotation-sourced finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
```

Check `catalog.js` for an existing C# process/command-execution sink entry (e.g. search for `Process.Start` or similar) before finalizing this fixture's sink call — use whatever sink shape is already catalogued for C#, adjusting the fixture if `Process.Start` isn't itself catalogued.

Run: `cd scanner && node --test test/parser-cs-annotations.test.js`
Expected: PASS.

- [ ] **Step 7: Wire into `test:dataflow`**

In `scanner/package.json`, add your new test file to the `test:dataflow` script's file list (skip if you extended `test/parser-cs-kt.test.js`, which is already wired).

- [ ] **Step 8: Commit**

```bash
git add scanner/src/ir/parser-cs.js scanner/test/parser-cs-annotations.test.js scanner/package.json
git commit -m "feat(ir): PRD R14(a) — extract ASP.NET Core attribute-shaped sources in the C# parser"
```

---

### Task 4: JS/TS — extract NestJS `@Query()`/`@Body()`/etc. decorators

**Files:**
- Modify: `scanner/src/ir/parser-js.js`
- Test: create `scanner/test/parser-js-annotations.test.js`

**Interfaces:**
- Consumes: nothing new — Babel's parser (already configured with the `decorators-legacy` plugin per `parser-js.js`'s existing `parserOpts`) already attaches a `decorators` array to each raw `param` node object at the exact point `enterFn`'s param-lowering map (`parser-js.js`, around lines 178-188) runs; that code currently reads only `p.type`/`p.name`/`p.left`/`p.argument` and discards `p.decorators` entirely.
- Produces: `fn.paramAnnotations` populated for JS/TS functions with at least one decorated parameter.

- [ ] **Step 1: Write the failing test**

Create `scanner/test/parser-js-annotations.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../src/ir/parser-js.js';

test('parseJsFile: a NestJS @Query() decorator on a parameter populates fn.paramAnnotations', () => {
  const code = `
class UserController {
  show(@Query() q) {
    return q;
  }
}
`;
  const ir = parseJsFile('user.controller.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q'], 'fn.params must stay plain strings, unaffected by this change');
  assert.ok(fn.paramAnnotations, 'expected paramAnnotations to be populated');
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'Query' }]);
});

test('parseJsFile: an undecorated parameter gets no paramAnnotations entry', () => {
  const code = `
class Helper {
  show(q) {
    return q;
  }
}
`;
  const ir = parseJsFile('helper.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.ok(!fn.paramAnnotations || fn.paramAnnotations.length === 0);
});

test('parseJsFile: multiple parameters, only decorated ones are recorded', () => {
  const code = `
class UserController {
  show(@Query() q, @Body() body, extra) {
    return q;
  }
}
`;
  const ir = parseJsFile('user.controller.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.deepEqual(fn.params, ['q', 'body', 'extra']);
  assert.deepEqual(fn.paramAnnotations, [
    { index: 0, name: 'q', decorator: 'Query' },
    { index: 1, name: 'body', decorator: 'Body' },
  ]);
});
```

The export is `parseJsFile` (`scanner/src/ir/parser-js.js:154`), confirmed directly against the current file. Confirm whether `.ts` files with decorators need a specific file-extension or parser-option path through `parseJsFile` by reading the file's dispatch logic before finalizing — the `decorators-legacy` Babel plugin is already unconditionally enabled per the earlier research (`parser-js.js:648-663`), so this should be a non-issue, but verify against current code.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-js-annotations.test.js`
Expected: FAIL — `paramAnnotations` isn't populated yet.

- [ ] **Step 3: Implement decorator extraction**

Read the current param-lowering code in `parser-js.js` (around lines 161-200, `enterFn`, specifically the `.map()` over `path.node.params` or equivalent around lines 178-188) in full before implementing — confirm the exact current shape, since R13(b) and other work in this codebase has touched `parser-js.js` substantially.

A Babel param node with a decorator has a `decorators` array: `[{ type: 'Decorator', expression: { type: 'CallExpression', callee: { type: 'Identifier', name: 'Query' }, arguments: [] } }]` (confirmed structure — a NestJS-style `@Query()` decorator; TS also allows a bare `@Foo` decorator with no call, where `expression` is directly an `Identifier` rather than a `CallExpression` wrapping one — handle both shapes).

Extend `enterFn`'s param-lowering to also build a `paramAnnotations` array alongside the existing `params` array, in the same `.map()`/loop (do not add a second full pass over the params — build both from the one existing traversal):

```js
const paramAnnotations = [];
const params = rawParams.map((p, idx) => {
  const decoratorNodes = p.decorators || (p.left && p.left.decorators) || [];
  for (const d of decoratorNodes) {
    const expr = d.expression;
    const decoratorName = expr?.type === 'CallExpression' ? expr.callee?.name : expr?.name;
    // Only record when the parameter itself resolves to a plain identifier —
    // decorators on destructured params are rare and out of scope for this plan.
    if (decoratorName && p.type === 'Identifier') {
      paramAnnotations.push({ index: idx, name: p.name, decorator: decoratorName });
    }
  }
  // ... existing p.type dispatch (Identifier / ObjectPattern / ArrayPattern / AssignmentPattern / RestElement) unchanged ...
});
```

Adapt this to the EXACT existing code shape you find (the existing `.map()` callback's parameter name, whether it's `rawParams` or `path.node.params` inline, the exact existing `if (p.type === 'Identifier') return p.name; ...` chain) — the illustrative code above shows the two things that must be added (decorator detection, `paramAnnotations` accumulation) without disturbing the existing return-value logic that builds `params` itself. Do not change what `params` contains or its ordering.

Then, in the function-record construction (`enterFn`'s `fn = {...}` object literal, or `exitFn`'s push — wherever `params` is assigned), add the same conditional-spread pattern as Task 3:

```js
...(paramAnnotations.length ? { paramAnnotations } : {}),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-js-annotations.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing JS parser test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-js-decorators.test.js test/parser-js-if-else-cfg.test.js && npm run test:dataflow`
Expected: ALL PASS unchanged, including `test/parser-js-decorators.test.js` specifically (this file already exists and tests decorator-adjacent behavior — read it first to understand what it currently covers, and make sure this task's change doesn't regress anything it already asserts).

- [ ] **Step 6: End-to-end test — the PRD's own NestJS success shape**

Add a `runScan`-based end-to-end test (same pattern as Task 3 Step 6):

```js
test('R14(a) end-to-end: NestJS @Query() flowing to a code-injection sink is detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14a-nest-'));
  fs.writeFileSync(path.join(dir, 'app.controller.ts'), `
class AppController {
  ping(@Query() cmd) {
    eval(cmd);
  }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an annotation-sourced finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
```

- [ ] **Step 7: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-js-annotations.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/ir/parser-js.js scanner/test/parser-js-annotations.test.js scanner/package.json
git commit -m "feat(ir): PRD R14(a) — extract NestJS decorator-shaped sources in the JS/TS parser"
```

---

### Task 5: Java — net-new parameter name extraction plus annotation extraction

**Files:**
- Modify: `scanner/src/ir/parser-java.js`
- Test: create `scanner/test/parser-java-annotations.test.js`

**Interfaces:**
- Consumes: nothing new — `java-parser`'s CST already exposes both parameter names AND their annotations at `methodDeclarator.children.formalParameterList[0].children.formalParameter[]`, confirmed by direct inspection of this repo's actual installed `java-parser` version:
  ```
  formalParameter.children.variableParaRegularParameter[0].children = {
    variableModifier: [ { children: { annotation: [ { children: {
      At: [...], typeName: [ { children: { Identifier: [ { image: 'RequestParam' } ] } } ],
      // present only for annotations with arguments, e.g. @PathVariable("id"):
      LBrace: [...], elementValue: [...], RBrace: [...]
    } } ] } } ],
    unannType: [...],
    variableDeclaratorId: [ { children: { Identifier: [ { image: 'q' } ] } } ],
  }
  ```
- Produces: BOTH real `fn.params` (currently hardcoded `[]` — this is a genuine gap-fill, not scope creep; see the note below) AND `fn.paramAnnotations` for Java functions.

**Why real param extraction is in scope here, not a separate task:** `scanner/src/ir/parser-java.js:338` currently has `const params = []; // params extraction deferred` — Java interprocedural taint has never had real parameter names. The PRD's own R14(a) success metric names Spring specifically ("A Spring controller method with a `@RequestParam` flowing to a `JdbcTemplate.query` call is detected") — Java is the headline example, not an optional extra. Extracting parameter names and their annotations both come from the exact same CST subtree (`formalParameterList`) in one walk, so doing them as two separate tasks would mean walking the same CST twice for no benefit. This task closes both gaps together.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-java-annotations.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';

test('parseJavaFile: real parameter names are now extracted (was [] before this task)', async () => {
  const code = `
public class UserController {
    public String show(String q, int id) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q', 'id']);
});

test('parseJavaFile: @RequestParam and @PathVariable populate fn.paramAnnotations', async () => {
  const code = `
public class UserController {
    public String show(@RequestParam String q, @PathVariable("id") int id) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q', 'id']);
  assert.ok(fn.paramAnnotations);
  assert.deepEqual(fn.paramAnnotations, [
    { index: 0, name: 'q', decorator: 'RequestParam' },
    { index: 1, name: 'id', decorator: 'PathVariable' },
  ]);
});

test('parseJavaFile: a method with no annotated parameters gets no paramAnnotations entry', async () => {
  const code = `
public class Helper {
    public String show(String q) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('Helper.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.deepEqual(fn.params, ['q']);
  assert.ok(!fn.paramAnnotations || fn.paramAnnotations.length === 0);
});

test('parseJavaFile: an unrelated annotation (e.g. @Deprecated-style, non-source-shaped) is still recorded in paramAnnotations — catalog filtering, not parser filtering, decides relevance', async () => {
  const code = `
public class UserController {
    public String show(@Nullable String q) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'Nullable' }]);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-java-annotations.test.js`
Expected: FAIL — `fn.params` is still `[]`, `paramAnnotations` doesn't exist.

- [ ] **Step 3: Implement parameter and annotation extraction**

Read the current `walkForMethods` function in `scanner/src/ir/parser-java.js` in full (around lines 318-357) before implementing — confirm the exact current structure, since this plan's line numbers may have drifted.

Replace the line `const params = []; // params extraction deferred` with real extraction. The method's parameter list lives at `md.children?.methodHeader?.[0]?.children?.methodDeclarator?.[0]?.children?.formalParameterList?.[0]` OR `md.children?.methodDeclarator?.[0]?.children?.formalParameterList?.[0]` (mirror the exact same dual-path fallback pattern the existing code already uses one line above for `name`, since `methodDeclaration` vs `methodHeader` nodes apparently nest differently depending on which `k` matched in the outer loop — read the existing `name` extraction's two-path fallback immediately above and follow the identical pattern for consistency).

```js
const fpl = md.children?.methodHeader?.[0]?.children?.methodDeclarator?.[0]?.children?.formalParameterList?.[0]
  || md.children?.methodDeclarator?.[0]?.children?.formalParameterList?.[0];
const paramAnnotations = [];
const params = (fpl?.children?.formalParameter || []).map((fp, idx) => {
  const vp = fp.children?.variableParaRegularParameter?.[0];
  const paramName = vp?.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image || null;
  const variableModifiers = vp?.children?.variableModifier || [];
  for (const vm of variableModifiers) {
    const ann = vm.children?.annotation?.[0];
    const decoratorName = ann?.children?.typeName?.[0]?.children?.Identifier?.[0]?.image;
    if (decoratorName && paramName) {
      paramAnnotations.push({ index: idx, name: paramName, decorator: decoratorName });
    }
  }
  return paramName;
}).filter(Boolean);
```

Then, in the function-record push (the `functions.push({...})` call a few lines below, which currently includes `params,`), add:

```js
...(paramAnnotations.length ? { paramAnnotations } : {}),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-java-annotations.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing Java test coverage to confirm no regressions**

Run: `cd scanner && node --test test/java-taint-flow.test.js`
Expected: ALL PASS. Since `fn.params` was previously always `[]` for every Java function, this change is a strict expansion (params now populated where they weren't) — confirm no existing test asserted `params: []` as an expected value anywhere (grep `test/java-taint-flow.test.js` and any other Java-touching test file for `params` assertions before running, so a legitimate expected-value change doesn't surprise you mid-run).

- [ ] **Step 6: End-to-end test — the PRD's own Spring success shape**

Add a `runScan`-based end-to-end test proving the full pipeline, using the PRD's own named success metric shape (a JDBC sink, since the PRD explicitly calls out `JdbcTemplate.query`):

```js
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

test('R14(a) end-to-end: Spring @RequestParam flowing to a JDBC sink is detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14a-spring-'));
  fs.writeFileSync(path.join(dir, 'UserController.java'), `
public class UserController {
    public String show(@RequestParam String q) throws Exception {
        java.sql.Statement stmt = null;
        stmt.executeQuery(q);
        return q;
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an annotation-sourced finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
```

- [ ] **Step 7: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-java-annotations.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/ir/parser-java.js scanner/test/parser-java-annotations.test.js scanner/package.json
git commit -m "feat(ir): PRD R14(a) — extract real Java parameter names and Spring annotation-shaped sources"
```

---

### Task 6: Full-gate verification and documentation

**Files:**
- Modify: `docs/DETECTION_GAP_REMEDIATION_PRD.md` (R14(a) status entry)
- Modify: `CHANGELOG.md`
- Modify: `scanner/src/ir/CLAUDE.md` (document the new `paramAnnotations` IR field in the shape contract)
- Rebuild: `scanner/dist/agentic-security.mjs` + `.sha256`

No new production code in this task — wiring, verification, and documentation only, following the same discipline as R13's and R14(b)'s own final tasks (do not patch a regression by updating a baseline; a real gate failure is a real finding to fix, not a number to paper over).

- [ ] **Step 1: Run the full test:dataflow scope**

Run: `cd scanner && npm run test:dataflow`
Expected: all green, including every test file added in Tasks 1-5.

- [ ] **Step 2: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: all green (exit 0).

- [ ] **Step 3: Run the benchmark gates**

Run, each from `scanner/`:
```bash
npm run bench:cve-replay:check
npm run bench:mutation:check
npm run bench:layer-recall:check
npm run bench:self-scan:check
```
Expected: all PASS with no drift. Before running, wipe scan state per root CLAUDE.md: from the repo root, `find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +`.

- [ ] **Step 4: Rebuild the bundle**

Run: `cd scanner && npm run build`
Expected: `dist/agentic-security.mjs` and its `.sha256` sidecar both update.

- [ ] **Step 5: Run the smoke test against the rebuilt bundle**

Run: `cd scanner && npm run smoke`
Expected: PASS.

- [ ] **Step 6: Document the new IR field in the shape contract**

In `scanner/src/ir/CLAUDE.md`, find the "IR shape contract" code block (the one showing `{ file, functions: [{qid, name, line, params, file, cfg}], topLevel }`). Add `paramAnnotations` as a documented, optional field, e.g.:

```
      params: ['arg1', 'arg2', ...],
      paramAnnotations: [{index, name, decorator}],  // R14(a): OPTIONAL — present only
                                                        // when a param carries a recognized
                                                        // framework decorator/attribute.
                                                        // Populated by parser-cs.js,
                                                        // parser-js.js, parser-java.js.
```

- [ ] **Step 7: Update the PRD status**

In `docs/DETECTION_GAP_REMEDIATION_PRD.md`, find the running status log (the section with the dated R13/R14(b) entries added previously) and add a dated entry describing: what landed (catalog `annotation` match kind, engine plumbing at all 8 call sites, three language extractors — C#, JS/TS, Java — with Java's real parameter extraction as a genuine gap-fill alongside the annotation work), the accepted bare-decorator-name false-positive risk (documented, not silently ignored, matching this project's existing convention for the same risk class elsewhere), and the exact gate results from Steps 1-3. Note the full Theme E (R13 + R14) is now complete.

- [ ] **Step 8: Update CHANGELOG.md**

Add an entry under the appropriate "Unreleased" heading describing: annotation/decorator-shaped source detection for Spring, ASP.NET Core, and NestJS controller parameters, and the Java real-parameter-extraction gap-fill that came with it.

- [ ] **Step 9: Commit**

```bash
git add docs/DETECTION_GAP_REMEDIATION_PRD.md CHANGELOG.md scanner/src/ir/CLAUDE.md scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "chore: wire R14(a) tests into test:dataflow, update PRD status, CHANGELOG, and IR shape docs"
```
