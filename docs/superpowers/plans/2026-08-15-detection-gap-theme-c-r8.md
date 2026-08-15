# Detection-gap PRD R8 — braced control-flow body recursion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the Java, C#, Kotlin, and PHP Layer-1 IR parsers from dropping or mangling statements inside braced control-flow bodies (`if`/`for`/`try`/`switch`/`while`/`do`). Today, for all four languages, a sink call sitting inside a conditional or loop is either silently absent from the CFG or folded into a bogus node — capping deep-mode taint recall near zero for these languages regardless of any catalog or interprocedural work, since there's nothing in the IR for those passes to operate on.

**Architecture:** Each language's fix is scoped independently because the four parsers are architecturally distinct — Java has a real CST (`java-parser`) and an existing recursive tree-walker (`walkStmts`) that merely needs new node-type branches; PHP has a real recursive CFG builder (`_buildCfg`, added by prior work in this PRD) whose statement-splitter never flushes on a closing `}`, so if/while/foreach only work when the construct is the LAST statement in scope; C# and Kotlin have NO recursive CFG builder at all today — both are a flat, single-pass loop over top-level-split statements, and both need a genuinely new recursive builder, ported from the already-proven pattern in `parser-cpp.js` (a leading-keyword match, a balanced-delimiter scan for the condition and the body, then recursion into the body text). All four fixes adopt the PRD's own explicitly-sanctioned "linear-but-complete" first pass — every statement gets a CFG node, in source order, branch/join structure is NOT modeled beyond what each language's parser already does today — this is a strict improvement over the current drop/mangle behavior, not a request to build real branch-sensitive CFGs.

**Tech Stack:** Node.js ESM. Java via `java-parser` (real CST). C#, Kotlin, PHP via hand-rolled regex/brace-counting parsers (no new dependencies).

## Global Constraints

- **"Linear-but-complete" is the target, not real branch/join CFGs.** Every one of the four fixes in this plan emits one CFG node per statement, in source order, connected linearly (`prev.succ.push(id)`). For constructs that already have partial real branch/join structure (PHP's `if`/`while`/`foreach`, which emit a real `noop` join node with two incoming edges), preserve that existing shape for the constructs that already have it — do not simplify PHP's existing if/while/foreach to pure-linear. For every NEW construct this plan adds (Java's `for`/`try`/`switch`/`do`, PHP's `try`/`switch`, C#'s and Kotlin's entire recursive builders), match whichever pattern that language's OWN existing code already establishes: Java's existing `if`/`while` are pure linear fall-through (no join node) — new Java constructs follow that. PHP's existing `if`/`while`/`foreach` use a real join node — new PHP constructs (`try`/`switch`) follow that. C# and Kotlin have no precedent to match (this is their first control-flow handling at all) — both should use the simpler pure-linear model, mirroring `parser-cpp.js`'s own proven approach exactly (no join nodes at all, every statement including ones nested inside control-flow just appends to one continuous chain).
- **A recursion-depth guard is required on every new recursive builder** (C#, Kotlin, and PHP's newly-generalized `_buildCfg`), mirroring `parser-cpp.js`'s `if (depth > 12) return;` (`parser-cpp.js:730`). Java's fix does not need one — `walkStmts`'s existing recursion is already naturally bounded by the CST's own depth (java-parser will not produce a pathologically deep CST for realistic input the way a text-based recursive-descent-style split could for adversarial input).
- **Byte-identical behavior for every existing straight-line fixture.** None of the four languages currently has ANY test fixture with a sink inside a control-flow body (confirmed by research — every existing Java/C#/Kotlin/PHP test file, in `scanner/test/`, uses straight-line bodies exclusively). This means there is zero risk of an existing test asserting the CURRENT (broken) drop/mangle behavior as "expected" — every fix in this plan is a strict, testable addition. Still: run every existing test file for the language you're touching and confirm it passes completely unchanged, since a regression in ordinary straight-line lowering is a real risk even though a regression in control-flow lowering specifically is not (there's nothing to regress there yet).
- **Do not introduce a shared cross-language statement-splitting/CFG-building module.** This codebase's own convention (confirmed by research: `parser-go.js` and `parser-cpp.js`, the two working references, do NOT share code with each other despite solving nearly the same problem) is that each hand-rolled parser is self-contained. Each task in this plan writes its own local helper functions (e.g. a balanced-delimiter matcher), even where the logic is very similar across languages (C# and Kotlin's new builders will look almost identical to each other) — do not refactor toward a shared helper as part of this plan.
- **The C++ `}`-flush pattern (flush a statement boundary the instant a `}` brings the shared brace/paren/bracket depth counter back to 0) is safe to port directly for PHP, but NOT safe to port directly for C# or Kotlin.** PHP has no `{}`-based object/collection-initializer syntax (PHP arrays use `[...]`, a different bracket, tracked by the same depth counter but not the `}`-specific trigger), so a bare `}`-reaching-0 flush cannot mis-fire mid-statement. C# and Kotlin BOTH have `{}`-based object/collection initializers and lambda bodies (`new Foo { X = 1 }`, `{ x, y -> x + y }`) that close a `}` at depth 0 while still being part of one larger statement — a naive `}`-flush there would fragment a single legitimate statement into bogus multi-node garbage. This is why C#/Kotlin's fix is the fuller "match a leading keyword FIRST, then balanced-scan for the condition and body" pattern (never blindly flushing on every `}`), while PHP's fix can be the simpler splitter-level flush.
- **Follow the task order below.** Java is smallest and safest (proves the "linear fall-through, additive branches" pattern this whole plan leans on). PHP is next-smallest (real infrastructure already exists, needs generalizing — but touches code that was very recently and carefully stabilized by prior work in this same PRD, so care is warranted). C# and Kotlin are the two largest, most novel tasks (both need a genuinely new recursive CFG builder) — do C# first since its plan text below is the most complete reference; Kotlin's implementer should read C#'s landed code before starting, since the two tasks are structurally near-identical.

---

### Task 1: Java — extend `walkStmts` to recurse into `for`/`try`/`switch`/`do`/bare blocks

**Files:**
- Modify: `scanner/src/ir/parser-java.js`
- Test: create `scanner/test/parser-java-control-flow.test.js`

**Interfaces:**
- Consumes: the existing `walkStmts(stmtNode)` recursive function (`parser-java.js:221` onward, nested inside `buildCfgFromBody`), the existing `emit(node)` closure it calls to append a CFG node, `exprFromCst(node)` for lowering conditions/expressions, `_lineOf(node)` for line attribution — all unchanged, all reused exactly as the existing `ifStatement`/`whileStatement` branches already use them.
- Produces: `walkStmts` gains 5 new `if (kids.X)` branches. No change to the IR shape contract, no change to any exported function signature.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-java-control-flow.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name.includes(fnName));
  assert.ok(fn, `expected a function matching "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

test('parseJavaFile: a sink inside a for-loop body is captured', async () => {
  const code = `
public class C {
    public void run(String[] ids) throws Exception {
        java.sql.Statement stmt = null;
        for (String id : ids) {
            stmt.executeQuery(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'executeQuery'), 'expected an executeQuery call node inside the for-loop body');
});

test('parseJavaFile: a sink inside a basic (three-clause) for-loop body is captured', async () => {
  const code = `
public class C {
    public void run(String[] ids) throws Exception {
        java.sql.Statement stmt = null;
        for (int i = 0; i < ids.length; i++) {
            stmt.executeQuery(ids[i]);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'executeQuery'));
});

test('parseJavaFile: a sink inside a plain try/catch/finally body is captured', async () => {
  const code = `
public class C {
    public void run(String id) {
        java.sql.Statement stmt = null;
        try {
            stmt.executeQuery(id);
        } catch (Exception e) {
            log(id);
        } finally {
            cleanup(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'executeQuery'), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the catch-body call');
  assert.ok(calls.some(c => c.callee === 'cleanup'), 'expected the finally-body call');
});

test('parseJavaFile: a sink inside try-with-resources is captured (the idiomatic JDBC shape)', async () => {
  const code = `
public class C {
    public void run(java.sql.Connection conn, String id) throws Exception {
        try (java.sql.Statement stmt = conn.createStatement()) {
            stmt.executeQuery(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'executeQuery'), 'expected the try-with-resources body sink');
  assert.ok(calls.some(c => c.callee === 'createStatement'), 'expected the resource-opening call itself to be lowered');
});

test('parseJavaFile: a sink inside a switch-case body is captured', async () => {
  const code = `
public class C {
    public void run(int n, String id) {
        switch (n) {
            case 1:
                log(id);
                break;
            default:
                cleanup(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the case-1 body call');
  assert.ok(calls.some(c => c.callee === 'cleanup'), 'expected the default body call');
});

test('parseJavaFile: a sink inside a do-while body is captured', async () => {
  const code = `
public class C {
    public void run(String id) {
        int i = 0;
        do {
            log(id);
            i++;
        } while (i < 3);
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the do-while body call');
});

test('parseJavaFile: a sink inside a bare nested block (no keyword) is captured', async () => {
  const code = `
public class C {
    public void run(String id) {
        {
            log(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the bare-block body call');
});

test('parseJavaFile: an end-to-end runScan detects a source flowing through a for-loop into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-java-'));
  fs.writeFileSync(path.join(dir, 'C.java'), `
public class C {
    public void run(String[] ids) throws Exception {
        java.sql.Statement stmt = null;
        for (String id : ids) {
            stmt.executeQuery(id);
        }
    }
    public void handle(javax.servlet.http.HttpServletRequest req) throws Exception {
        String[] ids = { req.getParameter("id") };
        run(ids);
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for a sink inside a for-loop, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-java-control-flow.test.js`
Expected: every test except possibly the bare-block one FAILs (no `executeQuery`/`log`/`cleanup` call nodes found, since `walkStmts` currently drops these statements entirely).

- [ ] **Step 3: Implement the new `walkStmts` branches**

Read the current `walkStmts` function in `scanner/src/ir/parser-java.js` (around lines 221-291) in full before editing — confirm the exact current line numbers and the `emit`/`exprFromCst`/`_lineOf` call shapes used by the existing `ifStatement`/`whileStatement` branches, since this plan's illustrative code must match that exact established pattern.

Add five new branches to `walkStmts`, immediately after the existing `whileStatement` branch:

```js
    if (kids.forStatement) {
      const f = kids.forStatement[0];
      // Both basicForStatement (`for(init;test;step)`) and
      // enhancedForStatement (`for(T x : xs)`) wrap a `statement` child for
      // the loop body — same shape whileStatement already walks.
      const basic = f.children?.basicForStatement?.[0];
      const enhanced = f.children?.enhancedForStatement?.[0];
      const inner = basic || enhanced;
      const cond = basic?.children?.expression?.[0];
      emit({ kind: 'loop-header', cond: cond ? exprFromCst(cond) : null, line: _lineOf(f), succ: [] });
      for (const sub of (inner?.children?.statement || [])) walkStmts(sub);
    }
    if (kids.doStatement) {
      const d = kids.doStatement[0];
      const cond = d.children?.expression?.[0];
      emit({ kind: 'loop-header', cond: cond ? exprFromCst(cond) : null, line: _lineOf(d), succ: [] });
      for (const sub of (d.children?.statement || [])) walkStmts(sub);
    }
    if (kids.tryStatement) {
      const t = kids.tryStatement[0];
      emit({ kind: 'noop', line: _lineOf(t), succ: [] });
      // Plain `try { ... }` has a direct `block` child. Try-with-resources
      // (`try (Resource r = ...) { ... }` — the idiomatic JDBC shape) wraps
      // in a distinct `tryWithResourcesStatement` intermediate node with
      // its own `resourceSpecification` (the resource declaration itself,
      // e.g. `Statement stmt = conn.createStatement()`) and `block`. Both
      // shapes are walked so a tainted receiver used in the resource
      // declaration is caught, not just the body.
      const twr = t.children?.tryWithResourcesStatement?.[0];
      if (twr) {
        const resSpec = twr.children?.resourceSpecification?.[0];
        // resourceSpecification -> resourceList -> resource[] -> each a
        // localVariableDeclaration-shaped resource; reuse the existing
        // localVariableDeclarationStatement lowering shape directly rather
        // than duplicating it, by walking each resource as if it were one.
        const resources = resSpec?.children?.resourceList?.[0]?.children?.resource || [];
        for (const r of resources) {
          const vdecl = r.children?.localVariableDeclaration?.[0] || r;
          const declarators = vdecl?.children?.variableDeclaratorId ? [vdecl] : (vdecl?.children?.variableDeclaratorList?.[0]?.children?.variableDeclarator || []);
          for (const d of declarators) {
            const target = d.children?.variableDeclaratorId?.[0]?.children?.Identifier?.[0]?.image;
            const initExpr = d.children?.variableInitializer?.[0]?.children?.expression?.[0] || d.children?.expression?.[0];
            if (target) emit({ kind: 'assign', target, source: initExpr ? exprFromCst(initExpr) : { kind: 'unknown' }, line: _lineOf(r), succ: [] });
          }
        }
        const twrBlock = twr.children?.block?.[0];
        if (twrBlock) walkStmts(twrBlock);
      } else if (t.children?.block) {
        walkStmts(t.children.block[0]);
      }
      const catches = t.children?.catches?.[0]?.children?.catchClause || [];
      for (const cc of catches) {
        const cblock = cc.children?.block?.[0];
        if (cblock) walkStmts(cblock);
      }
      const fin = t.children?.finally_?.[0] || t.children?.finally?.[0];
      const finBlock = fin?.children?.block?.[0];
      if (finBlock) walkStmts(finBlock);
    }
    if (kids.switchStatement) {
      const sw = kids.switchStatement[0];
      const cond = sw.children?.expression?.[0];
      emit({ kind: 'if', cond: cond ? exprFromCst(cond) : null, line: _lineOf(sw), succ: [] });
      const groups = sw.children?.switchBlock?.[0]?.children?.switchBlockStatementGroup || [];
      for (const g of groups) {
        const bss = g.children?.blockStatements?.[0];
        if (bss) walkStmts(bss);
      }
    }
    if (kids.statementWithoutTrailingSubstatement?.[0]?.children?.block && !kids.block) {
      // Bare nested block `{ ... }` with no leading keyword. The generic
      // `statementWithoutTrailingSubstatement` branch above already
      // recurses into this node, but never checked for a `block` child —
      // this walks it directly using the exact same
      // `block -> blockStatements -> blockStatement` shape the top of this
      // function already handles for the method body itself.
    }
    if (kids.block) {
      for (const b of kids.block) walkStmts(b);
    }
```

Read the last two added branches carefully before finalizing: the `statementWithoutTrailingSubstatement` case (already an existing branch a few lines above, at `if (kids.statementWithoutTrailingSubstatement) { for (const s of kids.statementWithoutTrailingSubstatement) walkStmts(s); }`) already recurses into each `statementWithoutTrailingSubstatement` node — and each of THOSE nodes may itself have a `block` child directly. Since `walkStmts` is called recursively on that node, and this new final `if (kids.block)` branch handles any node (not just `statementWithoutTrailingSubstatement`) that has a `block` child, the empty placeholder branch above is redundant with the final `if (kids.block)` branch and should be REMOVED — only add the final `if (kids.block) { for (const b of kids.block) walkStmts(b); }` branch, not both. Verify this by tracing through the actual CST shape for a bare `{ log(id); }` block (confirmed by this task's own research: `statementWithoutTrailingSubstatement[0].children.block[0]`) — the recursive call into `statementWithoutTrailingSubstatement` already lands on a node whose `kids.block` this new branch picks up.

Also verify the exact CST key name for `finally` — `java-parser`'s grammar may expose it as `finally_` (trailing underscore, since `finally` is a JS reserved-adjacent identifier pattern some parsers avoid) or as `finally` directly; the illustrative code above checks both defensively (`t.children?.finally_?.[0] || t.children?.finally?.[0]`), but confirm the real key by running the Step-4 direct-CST-inspection check below before trusting either guess.

- [ ] **Step 4: Confirm exact CST key names before finalizing**

Before running the tests, write and run a small throwaway Node script (not committed) that parses a Java `try (Resource r = x()) { ... } catch (E e) { ... } finally { ... }` block using this repo's own `java-parser` dependency (`import { parse } from 'java-parser'`), and dumps the `tryStatement` node's `children` keys, the `tryWithResourcesStatement` node's `children` keys, the `resourceSpecification`/`resourceList`/`resource` node shapes, and the `finally`-clause key name. Adjust the Step 3 code to match whatever the real key names turn out to be — the illustrative code above is a close, evidence-based approximation from this plan's own research, but CST key names must be confirmed against the actual installed `java-parser` version before being trusted verbatim.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-java-control-flow.test.js`
Expected: PASS.

- [ ] **Step 6: Run the full existing Java test coverage to confirm no regressions**

Run: `cd scanner && node --test test/java-taint-flow.test.js test/parser-java-annotations.test.js`
Expected: ALL PASS unchanged.

- [ ] **Step 7: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-java-control-flow.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/ir/parser-java.js scanner/test/parser-java-control-flow.test.js scanner/package.json
git commit -m "feat(ir): PRD R8 — Java: recurse into for/try/switch/do/bare-block bodies"
```

---

### Task 2: PHP — flush the statement splitter on `}`, add `try`/`switch` recognizers, add a recursion guard

**Files:**
- Modify: `scanner/src/ir/parser-php.js`
- Test: create `scanner/test/parser-php-control-flow.test.js`

**Interfaces:**
- Consumes: the existing `_splitStatements(body)` function (`parser-php.js:47-105`), the existing `_buildCfg(bodyText, nodes, prevId, startLine)` recursive function (`parser-php.js:390-448`), `_addNode`, `_linkNodes`, `_lowerExpr`, `_lowerStmt` — all unchanged.
- Produces: `_splitStatements` gains a new flush trigger (a `}` returning the shared depth counter to 0); `_buildCfg` gains two new recognizer branches (`try`/`catch`/`finally`, `switch`/`case`) matching the existing `if`/`while`/`foreach` pattern (real join node); `_buildCfg` gains a recursion-depth parameter and guard.

**Why fixing the splitter alone resolves the existing if/while/foreach "must be last statement" bug**, without touching those three regexes at all: today, `_splitStatements` glues everything from `if (...) { ... }` through the next `;` at depth 0 into ONE blob — so a statement following the if-block, or a second control-flow construct in the same scope, gets appended into the same blob, and the `$`-anchored `ifMatch` regex then fails to match (since the blob no longer ends immediately after the if-block's closing `}`), falling through to a bogus node. Once `_splitStatements` flushes a boundary the instant a `}` returns depth to 0, `if (...) { ... }` becomes its own independent split entry, and whatever follows it (another statement, another `if`) becomes a SEPARATE entry in the same `stmts` array `_buildCfg`'s loop already iterates over — so `ifMatch`/`whileMatch`/`foreachMatch` will now match cleanly without any change to those regexes themselves.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-php-control-flow.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

test('parsePhpFile: a sink inside an if-block is captured even when a statement follows it', () => {
  const code = `<?php
function f($conn) {
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
        mysqli_query($conn, $id);
    }
    return $id;
}
`;
  const ir = parsePhpFile('f.php', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the if-body sink to survive a trailing return statement');
});

test('parsePhpFile: a second if-block in the same scope is not swallowed by the first', () => {
  const code = `<?php
function f($conn) {
    if (true) {
        $a = 1;
    }
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
        mysqli_query($conn, $id);
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const fn = ir.functions.find(f => f.name === 'f');
  const ifNodes = Object.values(fn.cfg.nodes).filter(n => n.kind === 'if');
  assert.equal(ifNodes.length, 2, 'expected both if-blocks to produce their own if node');
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the second if-block\\'s sink to be captured');
  const assigns = Object.values(fn.cfg.nodes).filter(n => n.kind === 'assign' && n.target === '$id');
  assert.ok(assigns.length >= 1, 'expected $id = $_GET[\\'id\\'] to be captured as a real assign node, establishing taint provenance');
});

test('parsePhpFile: a sink inside a try/catch body is captured', () => {
  const code = `<?php
function f($conn, $sql) {
    try {
        $x = mysqli_query($conn, $sql);
    } catch (Exception $e) {
        log_error($e);
    }
    return $x;
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'log_error'), 'expected the catch-body call');
});

test('parsePhpFile: a sink inside a switch/case body is captured', () => {
  const code = `<?php
function f($x) {
    switch ($x) {
        case 1:
            $y = $_GET['cmd'];
            shell_exec($y);
            break;
        default:
            noop();
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'shell_exec'), 'expected the case-1 body sink');
  assert.ok(calls.some(c => c.callee === 'noop'), 'expected the default body call');
});

test('parsePhpFile: a lambda/closure passed as a call argument is NOT mis-split by the new brace-flush trigger', () => {
  const code = `<?php
function f($arr) {
    usort($arr, function($a, $b) {
        return $a - $b;
    });
    return $arr;
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'usort'), 'expected the usort call itself to still be captured as ONE call node, not fragmented by the closure\\'s internal braces');
  assert.equal(calls.filter(c => c.callee === 'usort').length, 1, 'the closure body must not produce a spurious extra usort-adjacent node');
});

test('parsePhpFile: end-to-end runScan detects a source flowing through a try-block into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-php-'));
  fs.writeFileSync(path.join(dir, 'index.php'), `<?php
function run($conn) {
    try {
        $id = $_GET['id'];
        mysqli_query($conn, $id);
    } catch (Exception $e) {
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for a sink inside try, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-php-control-flow.test.js`
Expected: every test except the lambda-safety one and possibly the runScan one FAILs.

- [ ] **Step 3: Fix `_splitStatements` to flush on `}` reaching depth 0**

Read the current `_splitStatements` function (`parser-php.js:47-105`) in full before editing — the line-tracking logic (`bufLine`/`curLine`, the `push` helper) was carefully built by very recent prior work in this PRD (R14(b)) and must be preserved exactly for the new flush path too.

Add a new branch, immediately after the existing `if (c === '{' || c === '(' || c === '[') depth++;` / `if (c === '}' || c === ')' || c === ']') depth--;` pair:

```js
    if (c === '{' || c === '(' || c === '[') depth++;
    if (c === '}' || c === ')' || c === ']') {
      depth--;
      // R8: a `}` that returns the shared depth counter to 0 ends a
      // braced control-flow body (if/while/foreach/try/switch) — flush a
      // statement boundary here too, not just on `;` at depth 0. PHP has
      // no `{}`-based object/array-literal syntax (arrays use `[...]`,
      // tracked by the same counter but not this trigger), so this cannot
      // mis-fire mid-expression the way it would for a language with `{}`
      // object initializers. A `}` that closes a lambda/closure body
      // passed as a call argument (`usort($arr, function($a,$b){...})`)
      // does NOT trigger this — that `}` returns depth from 2 to 1 (still
      // inside usort's outer `(`), not to 0.
      if (c === '}' && depth === 0) {
        push(c);
        const t = buf.trim();
        if (t) out.push({ text: t, line: bufLine ?? curLine });
        buf = '';
        bufLine = null;
        continue;
      }
    }
```

Note this new branch must be checked BEFORE the existing `if (c === ';' && depth === 0)` branch a few lines below (since both are triggered independently per-character, order between them doesn't actually matter here — but make sure the new branch's `continue` doesn't accidentally skip the existing `push(c); if (c === '\n') curLine++;` fallthrough at the bottom of the loop for the `}` character itself; the illustrative code above calls `push(c)` explicitly before flushing so the `}` character is included in the flushed statement text, matching what `ifMatch`'s regex expects to see).

- [ ] **Step 4: Run the lambda-safety test in isolation first**

Run: `cd scanner && node --test test/parser-php-control-flow.test.js` filtering to just that one test (or run the whole file and check its specific result) — confirm the `usort`-with-closure test passes BEFORE moving on, since this is the highest-risk part of Step 3 and should be validated in isolation before layering more changes on top.

- [ ] **Step 5: Add `try`/`catch`/`finally` and `switch`/`case` recognizer branches to `_buildCfg`, and a recursion-depth guard**

Read the current `_buildCfg` function (`parser-php.js:390-448`) in full. Add a `depth` parameter (defaulting to `0`) and a guard at the top, matching `parser-cpp.js:730`'s pattern:

```js
function _buildCfg(bodyText, nodes, prevId, startLine, depth = 0) {
  if (depth > 12) return prevId;
  const stmts = _splitStatements(bodyText);
```

Update every existing recursive call within `_buildCfg` (the `if`/`while`/`foreach` branches' own `_buildCfg(...)` calls) to pass `depth + 1` as a fifth argument.

Add two new recognizer branches, following the exact same real-join-node pattern the existing `whileMatch` branch uses (since PHP's own established precedent for NEW constructs added to this function is the real-branch/join model, per this plan's Global Constraints):

```js
    const tryMatch = s.match(/^try\s*\{([\s\S]*)\}\s*catch\s*\(([^)]*)\)\s*\{([\s\S]*)\}(?:\s*finally\s*\{([\s\S]*)\})?\s*$/s);
    if (tryMatch) {
      const tryNode = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, prev, tryNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      const tryTail = _buildCfg(tryMatch[1], nodes, tryNode, line + 1, depth + 1);
      const catchNode = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, tryTail, catchNode);
      const catchTail = _buildCfg(tryMatch[3], nodes, catchNode, line + 1, depth + 1);
      let tail = catchTail;
      if (tryMatch[4]) {
        const finallyNode = _addNode(nodes, { kind: 'noop', line });
        _linkNodes(nodes, tail, finallyNode);
        tail = _buildCfg(tryMatch[4], nodes, finallyNode, line + 1, depth + 1);
      }
      _linkNodes(nodes, tail, join);
      prev = join;
      continue;
    }

    const switchMatch = s.match(/^switch\s*\((.+?)\)\s*\{([\s\S]*)\}\s*$/s);
    if (switchMatch) {
      const switchNode = _addNode(nodes, { kind: 'if', cond: _lowerExpr(switchMatch[1]), line });
      _linkNodes(nodes, prev, switchNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      // PHP switch/case bodies fall through by default (no per-case
      // braces) — lower the whole switchBlock body as ONE linear sequence
      // under the switch node, matching this plan's "linear-but-complete"
      // target rather than modeling per-case branch/skip semantics.
      const bodyTail = _buildCfg(switchMatch[2], nodes, switchNode, line + 1, depth + 1);
      _linkNodes(nodes, bodyTail, join);
      prev = join;
      continue;
    }
```

Insert both new branches into the existing `if`/`while`/`foreach`/fallthrough chain in `_buildCfg`, before the final `_lowerStmt(s, line)` fallthrough call — order relative to the existing three branches doesn't matter (each is a distinct, non-overlapping regex match), but they must come before the generic fallthrough.

Note: `case`/`break`/`default` keywords themselves will fall through to `_lowerStmt` as individual statements once the switch body is recursively split — `_lowerStmt` doesn't recognize `case N:` or `default:` or bare `break;` as anything meaningful and will return `null` for them (dropped silently, matching this plan's "linear-but-complete" scope — case LABELS are not modeled, only the statements between them), which is acceptable per the PRD's own explicit "even a linear-but-complete lowering... is a strict improvement" allowance. Confirm this is the actual behavior (not a crash) by running the switch test in Step 2/6.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-php-control-flow.test.js`
Expected: PASS.

- [ ] **Step 7: Run the full existing PHP test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-php-rb.test.js test/parser-php-module-level.test.js test/parser-rb-calls.test.js test/engine-recall.test.js test/string-interpolation-taint.test.js`
Expected: ALL PASS unchanged. Pay particular attention to `test/parser-php-module-level.test.js` (the R14(b) module-level `<module>` tests) and any test asserting exact line numbers — the `_splitStatements` change touches the same function R14(b)'s line-tracking fix carefully rebuilt; confirm no line-number regression for any existing assertion.

- [ ] **Step 8: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-php-control-flow.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/ir/parser-php.js scanner/test/parser-php-control-flow.test.js scanner/package.json
git commit -m "feat(ir): PRD R8 — PHP: flush statement splitter on brace-close, add try/switch recursion, add recursion guard"
```

---

### Task 3: C# — build a new recursive CFG builder, ported from `parser-cpp.js`'s proven pattern

**Files:**
- Modify: `scanner/src/ir/parser-cs.js`
- Test: create `scanner/test/parser-cs-control-flow.test.js`

**Interfaces:**
- Consumes: the existing `_lowerStmt(text, line)` function (unchanged — still lowers a single leaf statement's text into an assign/call/return/throw node), `_lowerExpr` (unchanged), `callSitesFromCfg` (unchanged, still runs post-parse over the final CFG). Does NOT touch the completely separate, already-fixed `paramAnnotations`/`attrRegex` parameter-extraction code (confirmed isolated by this plan's research — parameter text is consumed before body extraction ever runs, and the fix in this task touches only body-statement text).
- Produces: `parseCSharpFile`'s current flat, single-pass `for (let idx = 0; idx < stmts.length; idx++)` loop is REPLACED by a call to a new recursive function (this task adds `_buildCfg`, mirroring the name every other language's equivalent function already uses). The overall `parseCSharpFile` function signature and its `functions.push({...})` shape are unchanged — only how the `cfg` object gets built changes internally.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-cs-control-flow.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCSharpFile } from '../src/ir/parser-cs.js';

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

test('parseCSharpFile: a sink inside an if-block is captured, including a statement following it', () => {
  const code = `
public class C {
    public string Find(string id) {
        if (id != null) {
            var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + id);
            db.Execute(cmd);
        }
        return null;
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'Find');
  assert.ok(calls.some(c => c.callee === 'Execute' || c.callee === 'db.Execute'), 'expected the if-body sink call, got: ' + JSON.stringify(calls));
});

test('parseCSharpFile: a sink inside a for-loop body is captured', () => {
  const code = `
public class C {
    public void Run(string[] ids) {
        for (int i = 0; i < ids.Length; i++) {
            db.Execute(ids[i]);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee?.endsWith('Execute')));
});

test('parseCSharpFile: a sink inside a try/catch body is captured', () => {
  const code = `
public class C {
    public void Run(string id) {
        try {
            db.Execute(id);
        } catch (Exception e) {
            Log(id);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee?.endsWith('Execute')), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'Log'), 'expected the catch-body call');
});

test('parseCSharpFile: a sink inside a switch-case body is captured', () => {
  const code = `
public class C {
    public void Run(int n, string id) {
        switch (n) {
            case 1:
                Log(id);
                break;
            default:
                Cleanup(id);
                break;
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee === 'Log'));
  assert.ok(calls.some(c => c.callee === 'Cleanup'));
});

test('parseCSharpFile: a collection/object initializer is NOT mis-split by the new brace-aware recursion', () => {
  const code = `
public class C {
    public void Run() {
        var list = new List<int> { 1, 2, 3 };
        var opts = new Options { Name = "x", Value = 1 };
        Process(list, opts);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee === 'Process'), 'expected Process to be captured as one clean call, not fragmented by the collection/object initializer braces');
});

test('parseCSharpFile: a lambda passed as a call argument is NOT mis-split', () => {
  const code = `
public class C {
    public void Run(List<int> xs) {
        xs.ForEach(x => { Process(x); });
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee === 'ForEach' || c.callee === 'xs.ForEach'), 'expected the ForEach call itself to be captured as one node');
});

test('parseCSharpFile: existing straight-line ASP.NET source-to-sink shape is unaffected', () => {
  const code = `
public class PingController {
    public string Ping([FromQuery] string host) {
        System.Diagnostics.Process.Start("ping", host);
        return "ok";
    }
}
`;
  const ir = parseCSharpFile('PingController.cs', code);
  const fn = ir.functions.find(f => f.name === 'Ping');
  assert.ok(fn);
  assert.deepEqual(fn.params, ['host']);
  assert.ok(fn.paramAnnotations);
  const calls = Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
  assert.ok(calls.length >= 1, 'expected the straight-line body to still lower correctly, unaffected by this task\\'s recursive-builder rewrite');
});

test('parseCSharpFile: end-to-end runScan detects a source flowing through an if-block into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-cs-'));
  fs.writeFileSync(path.join(dir, 'C.cs'), `
public class C {
    public void Run(string id) {
        if (id != null) {
            var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
            db.ExecuteQuery(cmd);
        }
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-cs-control-flow.test.js`
Expected: the control-flow-body tests FAIL (sinks inside `if`/`for`/`try`/`switch` bodies are currently invisible); the two safety tests (collection initializer, lambda) currently PASS since C#'s flat linear model happens not to mis-split those shapes today — confirm this and treat any surprise failure there as a signal to investigate before proceeding, not something to work around.

- [ ] **Step 3: Implement the new recursive `_buildCfg`**

Read the current `_splitStatements` function (`parser-cs.js:42-65`) and the current `parseCSharpFile` function's CFG-building section (the flat `for` loop, roughly lines 335-350) in full before editing.

Add a new `_buildCfg` function to `parser-cs.js`, mirroring `parser-cpp.js`'s `emit()` closure pattern (ported to this file's own naming/helper conventions — C# has no `_addNode`/`_linkNodes` helpers today, unlike PHP; this task adds minimal local equivalents or inlines the node/link bookkeeping directly, matching whichever is less disruptive to the surrounding code once you're looking at it):

```js
// R8: recursive statement-splitting + CFG builder, replacing the previous
// flat single-pass loop. Ported from parser-cpp.js's `emit()` — the
// already-proven, working reference for exactly this shape of problem in
// this codebase's hand-rolled-parser style. Unlike PHP's fix (a bare
// `}`-reaching-depth-0 flush is safe there, since PHP has no `{}` object
// literals), C# DOES have `{}`-based collection/object initializers
// (`new Foo { X = 1 }`) and lambda bodies that close a `}` at depth 0
// while still being part of ONE larger statement — so this does NOT
// blindly flush on every `}`. Instead: match a leading control-flow
// keyword FIRST, balanced-scan for its condition and its `{...}` body,
// and recurse ONLY into that matched body — every other `}` (including a
// collection initializer's or a lambda's) is left completely alone by
// this mechanism and continues to be handled by the ordinary `;`-splitting
// `_splitStatements` already does.
function _matchDelim(text, openIdx, openCh, closeCh) {
  let depth = 0;
  let inStr = null;
  let escape = false;
  for (let i = openIdx; i < text.length; i++) {
    const c = text[i];
    if (escape) { escape = false; continue; }
    if (inStr) {
      if (c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; continue; }
    if (c === openCh) depth++;
    else if (c === closeCh) { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function _buildCfg(bodyText, nodes, prevId, startLine, depth = 0) {
  if (depth > 12) return prevId;
  let prev = prevId;
  let stmtLine = startLine;
  const stmts = _splitStatements(bodyText);
  for (const raw of stmts) {
    const s = raw.trim();
    if (!s) { continue; }
    const hm = s.match(/^(if|while|for|foreach|switch|else\s+if|else|do|try|catch)\b/);
    if (hm) {
      const kwNorm = hm[1].replace(/\s+/g, ' ').trim();
      let p = hm[0].length;
      while (p < s.length && /\s/.test(s[p])) p++;
      let condRaw = null, afterHeader = p;
      if (s[p] === '(') {
        const closeIdx = _matchDelim(s, p, '(', ')');
        if (closeIdx !== -1) {
          condRaw = s.slice(p + 1, closeIdx);
          afterHeader = closeIdx + 1;
        }
      }
      const needsCond = /^(?:if|while|for|foreach|switch|else if|catch)$/.test(kwNorm);
      if (needsCond && condRaw !== null) {
        const id = `n${Object.keys(nodes).length}`;
        nodes[id] = { kind: 'if', line: stmtLine, cond: _lowerExpr(condRaw), succ: [], pred: [prev] };
        nodes[prev].succ.push(id);
        prev = id;
      }
      let rest = s.slice(afterHeader);
      const lead = rest.match(/^\s*/)[0].length;
      if (rest[lead] === '{') {
        const closeRel = _matchDelim(rest, lead, '{', '}');
        if (closeRel !== -1) {
          prev = _buildCfg(rest.slice(lead + 1, closeRel), nodes, prev, stmtLine + 1, depth + 1);
        }
      } else if (rest.trim()) {
        prev = _buildCfg(rest, nodes, prev, stmtLine + 1, depth + 1);
      }
      stmtLine += (raw.match(/\n/g) || []).length + 1;
      continue;
    }
    const bare = s.match(/^\{([\s\S]*)\}$/);
    if (bare) {
      prev = _buildCfg(bare[1], nodes, prev, stmtLine + 1, depth + 1);
      stmtLine += (raw.match(/\n/g) || []).length + 1;
      continue;
    }
    const node = _lowerStmt(s, stmtLine);
    stmtLine += (raw.match(/\n/g) || []).length + 1;
    if (!node) continue;
    const id = `n${Object.keys(nodes).length}`;
    nodes[id] = { ...node, succ: [], pred: [prev] };
    nodes[prev].succ.push(id);
    prev = id;
  }
  return prev;
}
```

Now replace `parseCSharpFile`'s existing flat loop (the section building `nodes`/`prev`/iterating `stmts` directly) with a call into this new function:

```js
    const nodes = {};
    nodes.entry = { kind: 'entry', line: startLine, succ: [], pred: [] };
    nodes.exit  = { kind: 'exit',  line: startLine, succ: [], pred: [] };
    const tail = _buildCfg(extracted.body, nodes, 'entry', startLine);
    nodes[tail].succ.push('exit');
    nodes.exit.pred.push(tail);
    const cfg = { entry: 'entry', exit: 'exit', nodes };
```

Note the new `_buildCfg` generates node ids via `n${Object.keys(nodes).length}` (a running count, since `entry`/`exit` and every emitted node all share the same `nodes` object) rather than the old loop's `n${idx}` (which was the STATEMENT index, not a node count) — this is a deliberate, necessary change since a single top-level "statement" (an `if` block) can now expand into multiple CFG nodes (the `if` node itself plus every statement inside its body), so id generation can no longer be keyed to the original flat statement array's index. Confirm no other code anywhere reads or depends on the exact string shape of these C# node ids (grep `parser-cs.js` and any test file for a hardcoded `"n0"`/`"n1"`-style id before finalizing) — if something does, adjust the id-generation scheme to preserve whatever contract exists, but per this plan's research, no such external dependency was found.

Remove the old flat-loop code entirely once the new call is wired in — do not leave both paths present.

- [ ] **Step 4: Run the two safety tests in isolation first**

Run the collection-initializer and lambda tests specifically before running the full new test file — these are the highest-risk cases (the exact scenario this plan's Global Constraints section warns about) and should be validated before moving on.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-cs-control-flow.test.js`
Expected: PASS.

- [ ] **Step 6: Run the full existing C# test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-cs-kt.test.js test/parser-cs-annotations.test.js`
Expected: ALL PASS unchanged, including the ASP.NET Core annotation-extraction tests (confirming this task's changes to statement-body lowering genuinely don't interact with the separate, already-fixed parameter-annotation-extraction code path) and the `new Type(concat)` stack-overflow-guard tests already in `parser-cs-kt.test.js`.

- [ ] **Step 7: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-cs-control-flow.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/ir/parser-cs.js scanner/test/parser-cs-control-flow.test.js scanner/package.json
git commit -m "feat(ir): PRD R8 — C#: replace the flat CFG loop with a recursive builder that recurses into braced control-flow bodies"
```

---

### Task 4: Kotlin — build a new recursive CFG builder, mirroring Task 3's C# builder exactly

**Files:**
- Modify: `scanner/src/ir/parser-kt.js`
- Test: create `scanner/test/parser-kt-control-flow.test.js`

**Interfaces:**
- Consumes: the existing `_lowerStmt(text, line)` function (unchanged), `_lowerExpr` (unchanged), `callSitesFromCfg` (unchanged).
- Produces: `parseKotlinFile`'s current flat single-pass loop is replaced by the same `_buildCfg` pattern Task 3 just landed for C#, adapted for Kotlin's own syntax differences (most importantly: Kotlin statement separators are `\n` OR `;`, not `;`-only, and Kotlin's control-flow keyword set includes `when` in place of/alongside `switch`).

**Read Task 3's landed `scanner/src/ir/parser-cs.js` changes before starting this task** — this task is structurally near-identical (same underlying problem: a flat linear CFG loop needs replacing with the same keyword-match + balanced-scan + recurse pattern), and the C# implementation is the concrete, already-reviewed reference to adapt rather than re-deriving from `parser-cpp.js` independently.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-kt-control-flow.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseKotlinFile } from '../src/ir/parser-kt.js';

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

test('parseKotlinFile: a sink inside an if-block is captured, including a statement following it', () => {
  const code = `
fun find(id: String?): String? {
    if (id != null) {
        val cmd = "SELECT * FROM users WHERE id=" + id
        db.execute(cmd)
    }
    return null
}
`;
  const ir = parseKotlinFile('f.kt', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'find');
  assert.ok(calls.some(c => c.callee === 'execute' || c.callee === 'db.execute'), 'expected the if-body sink, got: ' + JSON.stringify(calls));
});

test('parseKotlinFile: a sink inside a for-loop body is captured', () => {
  const code = `
fun run(ids: List<String>) {
    for (id in ids) {
        db.execute(id)
    }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee?.endsWith('execute')));
});

test('parseKotlinFile: a sink inside a try/catch body is captured', () => {
  const code = `
fun run(id: String) {
    try {
        db.execute(id)
    } catch (e: Exception) {
        log(id)
    }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee?.endsWith('execute')), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the catch-body call');
});

test('parseKotlinFile: a sink inside a when-block body is captured', () => {
  const code = `
fun run(n: Int, id: String) {
    when (n) {
        1 -> log(id)
        else -> cleanup(id)
    }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the when-branch-1 call');
});

test('parseKotlinFile: a trailing lambda argument is NOT mis-split', () => {
  const code = `
fun run(xs: List<Int>) {
    xs.forEach { x -> process(x) }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'forEach' || c.callee === 'xs.forEach'), 'expected the forEach call itself to be captured as one node');
});

test('parseKotlinFile: existing straight-line Ktor source-to-sink shape is unaffected', async () => {
  // Exact fixture from test/parser-cs-kt.test.js's own
  // "Kotlin Ktor source -> cmd sink fires via dataflow engine" test
  // (lines 68-80), reused verbatim here as a direct before/after
  // comparison point for this task's rewrite of the CFG builder.
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-kt-ktor-'));
  fs.writeFileSync(path.join(dir, 'App.kt'), `
fun handle(call: Any) {
  val host = call.parameters
  Runtime.getRuntime().exec("ping " + host)
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  assert.ok(scan && Array.isArray(scan.findings), 'scan must produce findings array on Kotlin input, unaffected by this task\\'s CFG-builder rewrite');
});

test('parseKotlinFile: end-to-end runScan detects a source flowing through an if-block into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-kt-'));
  fs.writeFileSync(path.join(dir, 'f.kt'), `
fun run(id: String?) {
    if (id != null) {
        val cmd = "SELECT * FROM t WHERE id=" + id
        db.executeQuery(cmd)
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-kt-control-flow.test.js`
Expected: the control-flow-body tests FAIL; the lambda-safety test's current pass/fail status should be confirmed and understood before proceeding (Kotlin's trailing-lambda syntax, `xs.forEach { x -> ... }`, has no parentheses around the lambda body at all — unlike C#'s `xs.ForEach(x => { ... })` — so this is a genuinely different shape from C#'s equivalent test and needs its own dedicated verification, not just an assumption that C#'s safety analysis transfers unchanged).

- [ ] **Step 3: Implement the new recursive `_buildCfg`, adapted from Task 3's C# version**

Read Task 3's landed `_buildCfg` and `_matchDelim` in `scanner/src/ir/parser-cs.js` in full. Port both to `scanner/src/ir/parser-kt.js`, with these Kotlin-specific adjustments:

1. **Statement splitting**: Kotlin's existing `_splitStatements` (`parser-kt.js:34-63`) already splits on `\n` OR `;` at depth 0 (unlike C#, which splits on `;` only) — reuse Kotlin's OWN existing `_splitStatements` unchanged; do not port C#'s version. The new `_buildCfg` calls Kotlin's existing splitter exactly as today's flat loop already does.
2. **Keyword set**: Kotlin's control-flow keywords are `if`/`while`/`for`/`when`/`else`/`do`/`try`/`catch` — note `when` replaces `switch`, and Kotlin's `when` can be used both as a statement (what this task models) and as an expression (out of scope, matching this task's "not modeling branch semantics, just recursing into bodies" scope). Adjust the header-match regex accordingly: `/^(if|while|for|when|else\s+if|else|do|try|catch)\b/`.
3. **Trailing-lambda call syntax** (`xs.forEach { x -> process(x) }`, no parentheses before the `{`): confirm whether this shape is already handled correctly by the EXISTING (pre-this-task) Kotlin lowering before assuming the new recursive builder needs special-casing for it — if the existing `_lowerStmt`'s call-matching regex already treats `forEach { ... }` as an opaque single call (collapsing the lambda, consistent with the module's own header comment "lambdas (collapsed to opaque expression)"), then the new `_buildCfg`'s header-keyword regex simply won't match `forEach` (it's not one of the control-flow keywords), so this call falls through to the ordinary `_lowerStmt` leaf-statement path unchanged — verify this is what actually happens rather than assuming it, since it's the crux of the lambda-safety test.
4. **Node id generation**: same change as Task 3 — Kotlin's existing loop uses `n${idx}` keyed to the flat statement array's index; the new recursive builder needs a running node-count-based id scheme instead, exactly as Task 3's C# fix does.

Replace `parseKotlinFile`'s existing flat loop with a call to the new `_buildCfg`, mirroring exactly how Task 3 restructured `parseCSharpFile`.

- [ ] **Step 4: Run the trailing-lambda safety test in isolation first**

Confirm this specific case before running the full suite — it's Kotlin's own distinct highest-risk shape (different from C#'s parenthesized-lambda shape).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-kt-control-flow.test.js`
Expected: PASS.

- [ ] **Step 6: Run the full existing Kotlin test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-cs-kt.test.js`
Expected: ALL PASS unchanged, including the pre-existing Kotlin smoke test and the Ktor end-to-end test.

- [ ] **Step 7: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-kt-control-flow.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/ir/parser-kt.js scanner/test/parser-kt-control-flow.test.js scanner/package.json
git commit -m "feat(ir): PRD R8 — Kotlin: replace the flat CFG loop with a recursive builder that recurses into braced control-flow bodies"
```

---

### Task 5: Full-gate verification, `bench/layer-recall` baseline update, and documentation

**Files:**
- Modify: `docs/DETECTION_GAP_REMEDIATION_PRD.md` (R8 status entry)
- Modify: `CHANGELOG.md`
- Modify: `scanner/src/ir/CLAUDE.md` (per-language parser table — update the Java/Kotlin/C#/PHP rows' known-limitation notes)
- Possibly modify: `bench/layer-recall/BASELINE.json` (see Step 3 — an increase here is an EXPECTED, positive outcome of this plan, not drift to suppress)
- Rebuild: `scanner/dist/agentic-security.mjs` + `.sha256`

No new production code in this task — wiring, verification, and documentation only, following the same discipline as every other final task in this PRD (a real gate finding is a real finding to fix, not a number to paper over).

- [ ] **Step 1: Run the full test:dataflow scope**

Run: `cd scanner && npm run test:dataflow`
Expected: all green, including every test file added in Tasks 1-4.

- [ ] **Step 2: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: all green (exit 0).

- [ ] **Step 3: Run `bench:layer-recall:check` and interpret the result correctly**

Run: `cd scanner && npm run bench:layer-recall:check`

Unlike every other task in this PRD so far (which landed via dedicated unit tests with NO expected corpus-recall change), this plan's whole point is closing a real, measurable recall gap — Java's baseline was `1/25` and Kotlin's was `0/20` IR-TAINT recall per this plan's own research, specifically because real corpus fixtures' sinks sit inside control-flow bodies this fix now lowers correctly. **An INCREASE in Java/Kotlin/C#/PHP taint-layer recall here is the expected, desired outcome of this plan — do not treat it as unexpected drift.** If the check fails because counts increased, that is the gate correctly detecting genuine improvement; run `npm run bench:layer-recall:check:update-baseline` (or whatever this repo's equivalent baseline-update command is — check `bench/layer-recall/CONTRIBUTING.md` or its `package.json` script name) and commit the updated baseline, documenting the exact before/after numbers in this task's docs update (Step 6). If any count DECREASED for a language this plan didn't touch (Go, C++, JS, Python, Ruby), that is real drift and must be investigated as a genuine regression, not baselined away.

- [ ] **Step 4: Run the remaining benchmark gates**

Run, each from `scanner/`:
```bash
npm run bench:cve-replay:check
npm run bench:mutation:check
npm run bench:self-scan:check
```
Expected: all PASS with no drift. Before running, wipe scan state per root CLAUDE.md: from the repo root, `find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +`.

- [ ] **Step 5: Rebuild the bundle and smoke-test**

Run: `cd scanner && npm run build && npm run smoke`
Expected: bundle + sidecar rebuilt; smoke test PASS.

- [ ] **Step 6: Update the PRD status**

In `docs/DETECTION_GAP_REMEDIATION_PRD.md`, add a dated status entry (matching the detail level of the R13/R14 entries already in the file) covering: what landed per language (Java's additive `walkStmts` extension including the try-with-resources special case; PHP's splitter-flush fix plus try/switch generalization plus recursion guard, and the "fixing the splitter alone resolves the existing if/while/foreach bug" finding; C#'s and Kotlin's new recursive `_buildCfg` builders replacing their prior flat linear CFGs, both ported from `parser-cpp.js`'s proven pattern); the exact before/after `bench:layer-recall` numbers from Step 3; any fix-round history from the SDD execution of this plan (to be filled in as tasks actually complete — do not write this section until Tasks 1-4 and their reviews are done). Note whether R9 (Java `fn.calls` derivation, blocked on R8's real CFG nodes existing for the statement kinds calls live in) is now unblocked, and whether its own remaining scope is narrower than originally rated given R14(a) already delivered Java's real parameter extraction as a side effect.

- [ ] **Step 7: Update CHANGELOG.md**

Add an entry under the appropriate "Unreleased" heading describing the four-language control-flow-body recursion fix and its measured recall impact.

- [ ] **Step 8: Update `scanner/src/ir/CLAUDE.md`'s per-language parser table**

Find the rows for Java, C#, Kotlin, and PHP. Remove or update any note that describes control-flow bodies as unmodeled/dropped (e.g. Java's row currently doesn't mention this explicitly per this plan's research, but check for any stale "if/while support was fixed in some prior version, other constructs remain unmodeled"-style note and correct it; C#'s and Kotlin's module header comments — `parser-cs.js`'s own "What we do NOT model... control flow (if/for/while/switch)" and `parser-kt.js`'s equivalent — should also be corrected in those files directly, not just in `CLAUDE.md`, since Tasks 3-4 already touch those files' headers as part of implementing the fix — confirm each task's implementer actually did this, since it's easy to forget).

- [ ] **Step 9: Commit**

```bash
git add docs/DETECTION_GAP_REMEDIATION_PRD.md CHANGELOG.md scanner/src/ir/CLAUDE.md scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
# also: bench/layer-recall/BASELINE.json (or equivalent) if Step 3 required an update
git commit -m "chore: wire R8 tests into test:dataflow, update layer-recall baseline, PRD status, CHANGELOG, and per-language docs"
```
