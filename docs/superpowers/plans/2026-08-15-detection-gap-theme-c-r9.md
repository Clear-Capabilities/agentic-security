# R9 — Wire `callSitesFromCfg` into Java's parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `scanner/src/ir/parser-java.js` never sets `fn.calls` on any function it emits — the shared, language-agnostic `callSitesFromCfg` helper (`scanner/src/ir/call-sites.js`) exists precisely for this and is already wired into 6 of the codebase's other 8 CFG-producing parsers (C#, Kotlin, PHP, Go, C++, Ruby, and Python-CST). Java is the one significant gap left. This plan wires it in, the same mechanical way Ruby's own dedicated fix (`test/parser-rb-calls.test.js`) already did it.

**Architecture:** One import + one field addition (`calls: callSitesFromCfg(cfg)`) in the single place `parser-java.js` constructs a function IR object. No new lowering logic — `call-sites.js`'s own doc comment states it "reads only the IR contract documented in `./CLAUDE.md`" and is deliberately language-agnostic; Java's CFG nodes (`call`, `assign`, `return`, `if`) already match that contract, since R8 just finished making sure Java's CFG walk recurses into every one of those node kinds inside control-flow bodies too.

**Tech Stack:** Node.js, ESM, `node:test`.

## Global Constraints

- **No new call-extraction logic.** `callSitesFromCfg` already exists and is proven correct across 6 other parsers (including one, `parser-cs.js`, that has near-identical CFG shapes to Java's own new R8 code, and `parser-rb.js`, whose own dedicated wiring task is the direct precedent for this one). This task is wiring only — if you find yourself writing a new expression walker, stop, you've misread the task.
- **`fn.calls` absence vs. presence is a documented failure mode.** Per `ir/CLAUDE.md`'s own Ruby row: "an absent array is indistinguishable from 'this function calls nothing,'" and `callgraph.js`'s edges/`callersOf`/`resolveKnownCallee` (all read at `callgraph.js:146`, `for (const c of (fn.calls || []))`) are built entirely from `fn.calls`. Before this fix, EVERY Java function in every scanned Java codebase silently contributes zero call-graph edges — this is not a partial gap, it's total, for the whole language.
- **This closes R9 as scoped in the PRD's own 2026-08-15 status entry**: R9's original two-part scope was (a) real Java parameter extraction, and (b) wiring `callSitesFromCfg` once R8 landed real CFG call nodes for the statement kinds Java calls live inside. Part (a) already landed as a side effect of R14(a) Task 5 (`fn.params` is real, not `[]`, and has been since that commit). R8 landed part (b)'s prerequisite. This plan is only part (b).
- **Byte-identical behavior for everything except the new `calls` field.** No other part of the emitted function IR (`qid`, `name`, `line`, `params`, `cfg`, `file`, `paramAnnotations`) should change in shape or value.

---

### Task 1: Wire `callSitesFromCfg` into `parser-java.js`

**Files:**
- Modify: `scanner/src/ir/parser-java.js` (add the import near the top alongside the existing `blankComments` import at line 24; add the `calls` field where the function object is constructed, around line 541-552)
- Test: `scanner/test/parser-java-calls.test.js` (new file, mirrors `scanner/test/parser-rb-calls.test.js`)

**Interfaces:**
- Consumes: `callSitesFromCfg(cfg)` from `./call-sites.js` — signature `(cfg: {entry, exit, nodes}) => Array<{site, callee, args, line}>`. Already imported this exact way by `parser-cs.js:49`, `parser-kt.js:69`, `parser-php.js:44`, `parser-go.js:24`, `parser-rb.js:24`.
- Produces: every function object in `parseJavaFile(...).functions` now carries a real `calls` array (was previously absent/undefined). `callgraph.js`, `dataflow/index.js`, and `tabulation.js` all already read `fn.calls` generically (no Java-specific branch needed anywhere downstream — this is exactly why the helper is language-agnostic).

- [ ] **Step 1: Add the import**

In `scanner/src/ir/parser-java.js`, near the existing imports (the file currently imports `blankComments` from `../sast/_comment-strip.js` at line 24), add:

```js
import { callSitesFromCfg } from './call-sites.js';
```

- [ ] **Step 2: Write the failing test**

Create `scanner/test/parser-java-calls.test.js`:

```js
// PRD R9: parseJavaFile never emitted `fn.calls` at all — ir/CLAUDE.md
// documents this only for Ruby and the Python regex fallback; Java had it
// unconditionally too, for every Java file, always. tabulation.js,
// dataflow/index.js and callgraph.js all read `fn.calls` to build
// cross-function call edges — an absent array is indistinguishable from
// "this function calls nothing," which left callgraph.js's edges/
// callersOf/resolveKnownCallee permanently empty for Java, disabling
// dead-code-demotion accuracy and any interprocedural signal that
// specifically depends on call-graph resolution (rather than the generic
// tainted-call-argument fallback in engine.js's exprTaint).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';
import { buildCallGraph } from '../src/ir/callgraph.js';

test('parseJavaFile emits fn.calls for both statement-position and RHS-embedded calls', () => {
  const ir = parseJavaFile('App.java', `
public class App {
  String buildQuery(String id) {
    return "SELECT * FROM t WHERE id=" + id;
  }
  void handler(String uid) {
    String sql = buildQuery(uid);
    db.execute(sql);
  }
}
`);
  assert.ok(ir, 'expected a parsed IR');
  const handler = ir.functions.find(f => f.name === 'App.handler');
  assert.ok(handler, 'expected a handler function');
  assert.ok(Array.isArray(handler.calls), 'fn.calls must be an array, not absent');
  const callees = handler.calls.map(c => c.callee);
  assert.ok(callees.includes('buildQuery'), `expected buildQuery in fn.calls, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('db.execute'), `expected db.execute in fn.calls, got: ${JSON.stringify(callees)}`);
});

test('buildCallGraph resolves a real edge for a Java call site (was always empty for every Java function)', () => {
  // buildCallGraph's actual signature (confirmed by reading callgraph.js
  // and mirroring test/parser-rb-calls.test.js's identical Ruby test):
  // buildCallGraph(perFileIR, fileContents) where perFileIR is a
  // { [filename]: ir } map — NOT an array, and NOT called with just [ir].
  // It returns { functions, edges, callersOf, resolve, resolveKnownCallee }
  // — edges is an ARRAY of { caller, site, callee, calleeName, line }
  // objects, and callersOf is a Map<calleeQid, edge[]>, not a Set.
  const ir = parseJavaFile('App.java', `
public class App {
  void buildCmd(String id) {
    Runtime.getRuntime().exec("echo " + id);
  }
  void handler(String id) {
    buildCmd(id);
  }
}
`);
  const callGraph = buildCallGraph({ 'App.java': ir }, {});
  const handlerFn = ir.functions.find(f => f.name === 'App.handler');
  const buildCmdFn = ir.functions.find(f => f.name === 'App.buildCmd');
  assert.ok(handlerFn && buildCmdFn, 'expected both functions in the IR');
  assert.ok(callGraph.callersOf.has(buildCmdFn.qid),
    `expected buildCmd to have a recorded caller; callersOf keys: ${JSON.stringify([...callGraph.callersOf.keys()])}`);
  const resolved = callGraph.resolveKnownCallee('buildCmd', 'App.java');
  assert.equal(resolved, buildCmdFn.qid, 'resolveKnownCallee must resolve the Java call site to the real function');
});

test('a call inside a control-flow body (R8 shape) is still captured in fn.calls', () => {
  // R9 is only useful because R8 already made sure calls inside if/for/
  // try/switch bodies are reachable in the CFG at all — this test pins
  // the R8+R9 combination end-to-end, not just a bare-statement call.
  const ir = parseJavaFile('App.java', `
public class App {
  void handler(String id, boolean flag) {
    if (flag) {
      db.execute(id);
    }
  }
}
`);
  const handler = ir.functions.find(f => f.name === 'App.handler');
  assert.ok(handler, 'expected a handler function');
  const callees = handler.calls.map(c => c.callee);
  assert.ok(callees.includes('db.execute'), `expected db.execute (inside if-body) in fn.calls, got: ${JSON.stringify(callees)}`);
});
```

Read `scanner/src/ir/callgraph.js` first to confirm the exact shape `buildCallGraph` returns (specifically what `cg.edges` is keyed/valued by) before relying on the second test's assertions verbatim — adjust only if the actual shape differs from what's assumed above, keeping the test's actual intent (a real, non-empty call-graph edge exists from `handler` to `buildCmd`) unchanged.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd scanner && node --test test/parser-java-calls.test.js`
Expected: FAIL — `handler.calls` is `undefined`, so `Array.isArray(handler.calls)` is false.

- [ ] **Step 4: Add the `calls` field**

In `scanner/src/ir/parser-java.js`, in the function-object-construction block (currently around line 541-552):

```js
            functions.push({
              qid: `${file}::${className || 'class'}::${name}@${methodLine}`,
              name: className ? `${className}.${name}` : name,
              line: methodLine,
              params,
              cfg: buildCfgFromBody(body),
              file,
              ...(paramAnnotations.length ? { paramAnnotations } : {}),
            });
```

becomes (capture the CFG into a local so it's built once, not twice — the original code called `buildCfgFromBody(body)` inline; keep that single call and reuse its result):

```js
            const cfg = buildCfgFromBody(body);
            functions.push({
              qid: `${file}::${className || 'class'}::${name}@${methodLine}`,
              name: className ? `${className}.${name}` : name,
              line: methodLine,
              params,
              cfg,
              file,
              calls: callSitesFromCfg(cfg),
              ...(paramAnnotations.length ? { paramAnnotations } : {}),
            });
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd scanner && node --test test/parser-java-calls.test.js`
Expected: PASS, all 3 tests.

- [ ] **Step 6: Run the full existing Java test surface to confirm no regression**

Run: `cd scanner && node --test test/parser-java-control-flow.test.js test/parser-java-annotations.test.js test/dataflow*.test.js`
(Adjust the glob to whatever the existing Java-touching test files actually are — check `ls test/*java*.test.js test/*dataflow*.test.js` first.) Expected: all pass, unchanged pass counts from before this task's change (confirm by running the same command against `HEAD~1` if in doubt).

Run: `cd scanner && npm run test:dataflow`
Expected: PASS, count should be exactly 3 higher than main's current baseline (verify the exact pre-task number by running this on a clean checkout first) — the 3 new tests, nothing else moves.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/ir/parser-java.js scanner/test/parser-java-calls.test.js
git commit -m "fix(ir): R9 — wire callSitesFromCfg into Java's parser

parser-java.js never emitted fn.calls, leaving every Java function's
call-graph edges permanently empty (callgraph.js reads fn.calls
exclusively). Wires the same shared, language-agnostic helper 6 other
parsers already use — no new call-extraction logic, matching the
identical precedent set by Ruby's own dedicated fix."
```

---

## Post-task: update docs

After Task 1 passes review, update `scanner/src/ir/CLAUDE.md`'s Java row to document that `fn.calls` is now real (mirroring how the Ruby row documents its own identical fix — see the existing Ruby row for the exact phrasing pattern), and add a dated status entry to `docs/DETECTION_GAP_REMEDIATION_PRD.md` closing R9. This is small enough to fold into Task 1's own commit rather than a separate task — do it as part of Task 1's implementation, in the same commit or an immediately following one, and it is in scope for Task 1's own review.
