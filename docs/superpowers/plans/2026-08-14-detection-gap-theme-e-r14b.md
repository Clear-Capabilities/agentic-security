# Detection-gap PRD R14(b) — non-JS top-level IR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Python, PHP, and Ruby the same Layer-2 (interprocedural taint) coverage for top-level (non-function) code that JS/TS already has via its synthetic `<module>` function — so a flat vulnerable script (`<?php system($_GET['cmd']);`) gets IR-TAINT coverage, not just Layer-1 regex/structural detection.

**Architecture:** For each of the three languages' function-extraction passes, compute the source ranges NOT consumed by any real function/method declaration, lower that residual ("gap") text through the same statement-lowering machinery already used for real function bodies, and — **only when the result contains at least one CFG node that isn't `entry`/`exit`/`noop`** — append it to the file's `functions[]` array as a synthetic `<module>` function, exactly mirroring the shape (not the unconditional-creation behavior — see Global Constraints) of JS's existing `Program`-level `<module>` (`scanner/src/ir/parser-js.js:276`).

**Tech Stack:** Node.js ESM (PHP/Ruby/Python-regex-fallback parsers), Python 3 stdlib `ast` (Python CST helper, invoked via subprocess).

## Global Constraints

- **Conditional inclusion, not unconditional.** JS's `<module>` is created for every file, even ones with zero top-level statements (verified empirically during research). This plan deliberately does **NOT** mirror that for Python/PHP/Ruby: `<module>` is added to `functions[]` (and `topLevel` set to its qid) **only when its CFG has at least one node whose `kind` is not `entry`, `exit`, or `noop`**. Rationale: nearly every existing test fixture for these three parsers is function-only with no top-level statements; unconditional creation would change `ir.functions.length` and `ir.topLevel` for those fixtures for no benefit, breaking or requiring updates to tests that have nothing to do with this fix. Conditional inclusion is strictly additive — zero existing fixtures gain a `<module>` entry; only genuinely-new top-level-statement-bearing files do.
- **`fn.params` stays `['string', ...]`.** The IR shape contract (`scanner/src/ir/CLAUDE.md`) fixes params as plain strings. `<module>` always gets `params: []` — never touch this field's shape.
- **Reuse existing statement-lowering, do not reinvent it.** PHP's `<module>` CFG is built by feeding gap text through the *existing* `_buildCfg`/`_splitStatements` functions already used for real function bodies (same call, different input text) — no new statement-classification logic. Same for Ruby. Same principle for Python: the CST path reuses `CfgBuilder.lower()`, the regex fallback reuses `buildCfg()`.
- **Do not touch `fn.calls` derivation.** PHP/Ruby already compute `calls: callSitesFromCfg(cfg)` per function generically; apply the identical call to the new `<module>` entry, no separate logic.
- **Byte-identical behavior for every existing function-only fixture.** After this plan, running the existing test suites (`test/parser-php-rb.test.js`, `test/parser-py-cst.test.js`, `test/parser-rb-calls.test.js`, and anything under `test:dataflow` that touches these three languages) must show **zero** diffs in `functions.length`, `topLevel`, or any existing finding — this is the concrete, testable form of "strictly additive" for this plan. If a task's own testing surfaces such a diff, that is a bug in the task, not an acceptable side effect.
- **The dead-code severity exemption (Task 5) is the one deliberate exception to "byte identical."** It changes JS's own existing `<module>`-scoped findings from demoted-one-tier to full severity, because module-level code has no caller by construction and was never actually "dead" — this was a real latent bug independent of R14(b), documented during research. This is a severity **increase** for a small number of existing findings (never a decrease, never a removal), consistent with this project's recall-preserving/severity-only-ever-restored convention. Call this out explicitly in the task's commit message and the final docs update — do not let it look like accidental scope creep.

---

### Task 1: Python CST helper — synthesize `<module>` lowering

**Files:**
- Modify: `scanner/src/ir/parser-py.helper.py:588-598` (`_process_one`)
- Test: `scanner/test/parser-py-cst.test.js`

**Interfaces:**
- Consumes: `CfgBuilder` class (`parser-py.helper.py:268-317` — constructor `CfgBuilder(fn_name: str)` auto-creates `self.entry`/`self.exit`/`self.nodes`; `.lower(body: list[ast.stmt]) -> None` lowers a statement list into the CFG, linking `entry → … → exit` internally); `_qid(file: str, name: str, line: int) -> str` (`:67-69`).
- Produces: for a `.py` file with genuine top-level statements, `functions` gains one entry `{qid, name: "<module>", line: 1, params: [], file, cfg: {entry, exit, nodes}}` and `topLevel` is that entry's qid (both were previously always `None`/`null`). For a function-only file, behavior is unchanged (`topLevel: None`, `functions` unchanged).

Note: these tests only run when `python3` is available (`_maybe` gating already used throughout `parser-py-cst.test.js` — check the top of the file for the exact pattern and follow it for any new test in this task).

- [ ] **Step 1: Write the failing tests**

Add to `scanner/test/parser-py-cst.test.js` (find the existing `_maybe(...)` gating helper near the top of the file and use it, matching the pattern of test `#16` already in the file):

```js
_maybe('module-level top-level statements are lowered into a synthetic <module> function', async () => {
  const code = `import os

cmd = request.args
os.system(cmd)
`;
  const [ir] = await parsePythonFilesBatch([{ file: 'flat.py', content: code }]);
  assert.ok(ir);
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod, 'expected a synthetic <module> function for top-level statements');
  assert.equal(ir.topLevel, mod.qid);
  const nodes = Object.values(mod.cfg.nodes);
  const assigns = nodes.filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === 'cmd'), 'expected the module-level cmd assignment');
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.some(c => c.callee === 'os.system'), 'expected the module-level os.system call');
});

_maybe('a function-only file gets no <module> entry (conditional inclusion, unchanged behavior)', async () => {
  const code = `def f(x):
    return x + 1
`;
  const [ir] = await parsePythonFilesBatch([{ file: 'funcs_only.py', content: code }]);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1, 'no synthetic <module> entry should be added when there is no real top-level content');
  assert.equal(ir.topLevel, null);
});

_maybe('a nested function/class at module scope does not itself count as module content', async () => {
  // _lower_stmt already emits a noop placeholder for a FunctionDef/ClassDef
  // encountered while lowering a statement list (see parser-py.helper.py
  // :506-515) — this must not make the module CFG look non-trivial on its
  // own. Confirms the "at least one non-noop node" gate, not just "any node".
  const code = `class Foo:
    def bar(self):
        return 1
`;
  const [ir] = await parsePythonFilesBatch([{ file: 'class_only.py', content: code }]);
  assert.ok(ir);
  assert.equal(ir.functions.find(f => f.name === '<module>'), undefined);
  assert.equal(ir.topLevel, null);
});
```

Check the top of `parser-py-cst.test.js` for how `parsePythonFilesBatch` is imported and how `_maybe` is defined — reuse both exactly as they already exist in the file; do not redefine them.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-py-cst.test.js`
Expected: the first new test FAILs (`mod` is `undefined`) if python3 is available in this environment; the other two pass already (they assert today's behavior). If python3 is unavailable, all three report as skipped via `_maybe` — note this in your report and still implement Step 3, since CI environments do have python3.

- [ ] **Step 3: Implement the `<module>` lowering**

In `scanner/src/ir/parser-py.helper.py`, replace `_process_one` (currently lines 588-598):

```python
def _process_one(file: str, content: str) -> dict[str, Any]:
    if not isinstance(content, str):
        return {"file": file, "functions": [], "topLevel": None, "_error": "content-not-string"}
    if len(content) > 1_000_000:
        return {"file": file, "functions": [], "topLevel": None, "_error": "file-too-large"}
    try:
        tree = ast.parse(content, filename=file)
    except SyntaxError as e:
        return {"file": file, "functions": [], "topLevel": None, "_error": f"syntax-error: {e.msg} (line {e.lineno})"}
    fns = _extract_functions(tree, file)
    # R14(b): lower top-level (module-scope) statements into a synthetic
    # <module> function, mirroring parser-js.js's Program-level lowering.
    # Only included when it carries real content — a FunctionDef/ClassDef
    # encountered here lowers to a noop placeholder (_lower_stmt already
    # does this so nested defs aren't double-counted; see _extract_functions
    # above, which independently captures them via ast.walk), so a
    # function-only file must not gain a <module> entry just because its
    # single top-level statement happens to be a def.
    mod_builder = CfgBuilder("<module>")
    mod_builder.lower(tree.body)
    mod_has_content = any(
        n.get("kind") not in ("entry", "exit", "noop")
        for n in mod_builder.nodes.values()
    )
    top_level_qid = None
    if mod_has_content:
        top_level_qid = _qid(file, "<module>", 1)
        fns.append({
            "qid": top_level_qid,
            "name": "<module>",
            "line": 1,
            "params": [],
            "file": file,
            "cfg": {
                "entry": mod_builder.entry,
                "exit": mod_builder.exit,
                "nodes": mod_builder.nodes,
            },
        })
    return {"file": file, "functions": fns, "topLevel": top_level_qid}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-py-cst.test.js`
Expected: PASS (or skip, if python3 unavailable — report this explicitly either way).

- [ ] **Step 5: Run the full existing test file to confirm no regressions**

Run: `cd scanner && node --test test/parser-py-cst.test.js`
Expected: ALL tests in the file PASS, including every pre-existing test (confirms conditional inclusion left every other fixture's `functions`/`topLevel` untouched).

- [ ] **Step 6: Commit**

```bash
git add scanner/src/ir/parser-py.helper.py scanner/test/parser-py-cst.test.js
git commit -m "feat(ir): PRD R14(b) — synthesize <module> lowering for Python top-level statements (CST path)"
```

---

### Task 2: Python regex fallback — synthesize `<module>` lowering

**Files:**
- Modify: `scanner/src/ir/parser-py.js` (`extractFunctions`, `parsePythonFile`)
- Test: create `scanner/test/parser-py-module-level.test.js`
- Modify: `scanner/package.json` (`test:dataflow` script — add the new test file)

**Interfaces:**
- Consumes: `buildCfg(fn)` (`parser-py.js:222-248`, takes `fn.body: [{line, text}]`, returns `{entry, exit, nodes}`); `blankComments(text, 'py')` (imported at the top of the file — confirm the exact import statement when editing).
- Produces: `parsePythonFile(file, raw)` gains the same conditional `<module>` behavior as Task 1, for the indentation-based regex fallback parser. `extractFunctions` additionally returns which source lines it consumed, so the caller can compute the complement.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-py-module-level.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePythonFile } from '../src/ir/parser-py.js';

test('parsePythonFile (regex fallback): top-level statements lower into a synthetic <module> function', () => {
  const code = `import os

cmd = request.args
os.system(cmd)
`;
  const ir = parsePythonFile('flat.py', code);
  assert.ok(ir);
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod, 'expected a synthetic <module> function for top-level statements');
  assert.equal(ir.topLevel, mod.qid);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === 'cmd'));
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'os.system'));
});

test('parsePythonFile (regex fallback): a function-only file gets no <module> entry', () => {
  const code = `def f(x):
    return x + 1
`;
  const ir = parsePythonFile('funcs_only.py', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.topLevel, null);
});

test('parsePythonFile (regex fallback): top-level statements interleaved with a function are all captured', () => {
  const code = `x = request.args

def helper(y):
    return y

os.system(x)
`;
  const ir = parsePythonFile('interleaved.py', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2, 'expected helper() plus the synthetic <module>');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === 'x'), 'expected the pre-function assignment');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'os.system'), 'expected the post-function call');
  const helper = ir.functions.find(f => f.name === 'helper');
  assert.ok(helper, 'the real function must still be extracted unchanged');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-py-module-level.test.js`
Expected: FAIL (no `<module>` produced yet).

- [ ] **Step 3: Implement gap tracking in `extractFunctions` and module lowering in `parsePythonFile`**

In `scanner/src/ir/parser-py.js`, modify `extractFunctions` (currently lines 170-218) to also return the set of consumed 1-indexed line numbers and the full `lines` array:

```js
function extractFunctions(text, file) {
  const lines = blankComments(text, 'py').split('\n');
  const fns = [];
  const consumed = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const head = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/.exec(line);
    if (!head) continue;
    const indent = head[1].length;
    const name = head[2];
    let p = head[0].length, depth = 1, inStr = false, q = '';
    for (; p < line.length; p++) {
      const c = line[p];
      if (inStr) { if (c === '\\') { p++; continue; } if (c === q) inStr = false; continue; }
      if (c === '"' || c === "'") { inStr = true; q = c; continue; }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') { depth--; if (depth === 0) break; }
    }
    if (depth !== 0) continue;
    const paramsText = line.slice(head[0].length, p);
    const after = line.slice(p + 1);
    if (!/^\s*(?:->\s*[^:]+)?:\s*(?:#.*)?$/.test(after)) continue;
    const params = _splitArgs(paramsText).map(s => s.trim().split(/[:=]/)[0].trim()).filter(Boolean);
    consumed.add(i + 1);
    const body = [];
    let j = i + 1;
    while (j < lines.length) {
      const l = lines[j];
      if (l.trim() === '') { body.push({ line: j + 1, text: '' }); consumed.add(j + 1); j++; continue; }
      const li = l.match(/^(\s*)/)[1].length;
      if (li <= indent) break;
      body.push({ line: j + 1, text: l.slice(indent + 4) });
      consumed.add(j + 1);
      j++;
    }
    fns.push({
      qid: `${file}::module::${name}`,
      name,
      line: i + 1,
      params,
      body,
    });
  }
  return { fns, consumed, lines };
}
```

Add a new function immediately after it, building the `<module>` body from lines `extractFunctions` did NOT consume:

```js
// R14(b): the complement of extractFunctions' consumed lines is the
// module-level (top-level) statement text, lowered through the same
// buildCfg() every real function body already uses. Only line text is
// needed — buildCfg/_classifyLine already trim() before matching, so
// leading indentation on a stray line is harmless.
function _moduleLevelBody(lines, consumed) {
  const body = [];
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    if (consumed.has(lineNo)) continue;
    body.push({ line: lineNo, text: lines[i] });
  }
  return body;
}
```

Now modify `parsePythonFile` (currently lines 294-312):

```js
export function parsePythonFile(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return null;
  if (!/\.py$/i.test(file)) return null;
  if (raw.length > 1_000_000) return null;
  const { fns: fnRecs, consumed, lines } = extractFunctions(raw, file);
  const functions = fnRecs.map(fn => ({
    qid: fn.qid,
    name: fn.name,
    line: fn.line,
    params: fn.params,
    cfg: buildCfg(fn),
    file,
  }));
  const modBody = _moduleLevelBody(lines, consumed);
  const modCfg = buildCfg({ body: modBody });
  const modHasContent = Object.values(modCfg.nodes).some(n => n.kind !== 'entry' && n.kind !== 'exit');
  let topLevel = null;
  if (modHasContent) {
    const modQid = `${file}::module::<module>`;
    functions.push({ qid: modQid, name: '<module>', line: 1, params: [], cfg: modCfg, file });
    topLevel = modQid;
  }
  return {
    file,
    functions,
    topLevel,
  };
}
```

Note: `buildCfg`'s `_classifyLine` already returns `null` (no node created) for unrecognized text, so `modHasContent` needs no noop-filter here — unlike Python's CST path, this parser never emits an explicit `noop` node for a "recognized but not taint-relevant" construct; unrecognized lines simply produce no node at all. Confirm this by reading `_classifyLine` (lines 250-286) before implementing — if that has changed since this plan was written, adjust the gate to also exclude `noop` for safety.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-py-module-level.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing parser-py test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-py-module-level.test.js` and search for any other existing test file that imports `parsePythonFile` (`grep -rl "parser-py.js" scanner/test/`) and run those too.
Expected: ALL PASS, no changes to any existing fixture's `functions`/`topLevel`.

- [ ] **Step 6: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-py-module-level.test.js` to the `test:dataflow` script's file list (append it after `test/member-write-and-loop-taint.test.js`, matching the existing space-separated list style).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/ir/parser-py.js scanner/test/parser-py-module-level.test.js scanner/package.json
git commit -m "feat(ir): PRD R14(b) — synthesize <module> lowering for Python top-level statements (regex fallback)"
```

---

### Task 3: PHP — synthesize `<module>` lowering via gap computation

**Files:**
- Modify: `scanner/src/ir/parser-php.js` (`parsePhpFile`)
- Test: create `scanner/test/parser-php-module-level.test.js`
- Modify: `scanner/package.json` (`test:dataflow` script)

**Interfaces:**
- Consumes: `_buildCfg(bodyText, nodes, prevId, startLine)` (`parser-php.js:266-328` — unchanged, reused as-is); `_addNode`, `_linkNodes`, `_lineAt`, `_qid` (all existing, unchanged); `callSitesFromCfg` (imported at top of file, already used).
- Produces: `parsePhpFile(file, code)` returns a non-null IR for a file with **zero** `function` declarations but real top-level code (previously returned `null` for the whole file — the exact motivating gap: `<?php system($_GET['cmd']);`). For a file with functions and no top-level statements, behavior is unchanged.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-php-module-level.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';

test('parsePhpFile: a flat script with no function declarations still produces an IR via a synthetic <module>', () => {
  const code = `<?php
system($_GET['cmd']);
`;
  const ir = parsePhpFile('flat.php', code);
  assert.ok(ir, 'previously this returned null for the whole file — the exact R14(b) gap');
  assert.equal(ir.functions.length, 1);
  const mod = ir.functions[0];
  assert.equal(mod.name, '<module>');
  assert.equal(ir.topLevel, mod.qid);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'));
});

test('parsePhpFile: a function-only file gets no <module> entry (conditional inclusion, unchanged behavior)', () => {
  const code = `<?php
function getUser($id) {
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    return $result;
}
`;
  const ir = parsePhpFile('app.php', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1, 'no synthetic <module> entry should be added — no real top-level content in this fixture');
  assert.equal(ir.topLevel, null);
});

test('parsePhpFile: top-level statements before and after a function declaration are both captured', () => {
  const code = `<?php
$cmd = $_GET['cmd'];
function helper($x) {
    return $x;
}
system($cmd);
`;
  const ir = parsePhpFile('interleaved.php', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2, 'expected helper() plus the synthetic <module>');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === '$cmd'), 'expected the pre-function assignment');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'), 'expected the post-function call');
  const helper = ir.functions.find(f => f.name === 'helper');
  assert.ok(helper, 'the real function must still be extracted unchanged');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-php-module-level.test.js`
Expected: first two behave partly (second already passes, since it's today's status quo); the first and third FAIL (`ir` is `null` for the flat-script case; `functions.length` is 1, not 2, for the interleaved case).

- [ ] **Step 3: Implement gap computation and `<module>` lowering**

In `scanner/src/ir/parser-php.js`, modify `parsePhpFile` (currently lines 330-372):

```js
export function parsePhpFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.(?:php|phtml)$/i.test(file)) return null;
  if (code.length > 1_000_000) return null;

  const functions = [];
  const spans = []; // {start, end}: source ranges fully consumed by a matched function (signature through closing brace)
  FUNC_RE.lastIndex = 0;
  _nid = 0;
  let m;
  while ((m = FUNC_RE.exec(code)) !== null) {
    const name = m[1];
    const paramsText = m[2] || '';
    const params = paramsText.split(',').map(p => {
      const t = p.trim();
      if (!t) return null;
      const vm = t.match(/\$(\w+)/);
      return vm ? '$' + vm[1] : null;
    }).filter(Boolean);
    const braceIdx = code.indexOf('{', m.index + m[0].length - 1);
    if (braceIdx < 0) continue;
    const extracted = _extractBody(code, braceIdx);
    if (!extracted) continue;
    const startLine = _lineAt(code, m.index);
    const nodes = {};
    const entry = _addNode(nodes, { kind: 'entry', line: startLine });
    const exit = _addNode(nodes, { kind: 'exit', line: startLine });
    const tail = _buildCfg(extracted.body, nodes, entry, startLine + 1);
    _linkNodes(nodes, tail, exit);
    const cfg = { entry, exit, nodes };
    functions.push({
      qid: _qid(file, name, startLine, extracted.body),
      name, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
    });
    spans.push({ start: m.index, end: extracted.end });
    FUNC_RE.lastIndex = extracted.end;
  }

  // R14(b): lower top-level (module-scope) statements into a synthetic
  // <module> function, mirroring parser-js.js's Program-level lowering.
  // The "gap" text is everything NOT inside a matched function's
  // [signature, closing-brace) span, fed through the same _buildCfg used
  // for real function bodies — no new statement-classification logic.
  spans.sort((a, b) => a.start - b.start);
  const modNodes = {};
  const modEntry = _addNode(modNodes, { kind: 'entry', line: 1 });
  const modExit = _addNode(modNodes, { kind: 'exit', line: 1 });
  let modTail = modEntry;
  let cursor = 0;
  for (const span of spans) {
    if (span.start > cursor) {
      const gap = code.slice(cursor, span.start);
      modTail = _buildCfg(gap, modNodes, modTail, _lineAt(code, cursor));
    }
    cursor = Math.max(cursor, span.end);
  }
  if (cursor < code.length) {
    const gap = code.slice(cursor);
    modTail = _buildCfg(gap, modNodes, modTail, _lineAt(code, cursor));
  }
  _linkNodes(modNodes, modTail, modExit);
  const modHasContent = Object.values(modNodes).some(n => n.kind !== 'entry' && n.kind !== 'exit');
  let topLevel = null;
  if (modHasContent) {
    const moduleCfg = { entry: modEntry, exit: modExit, nodes: modNodes };
    const modQid = _qid(file, '<module>', 1, code);
    functions.push({
      qid: modQid,
      name: '<module>', line: 1, params: [], file,
      cfg: moduleCfg,
      calls: callSitesFromCfg(moduleCfg),
    });
    topLevel = modQid;
  }

  return functions.length ? { file, functions, topLevel } : null;
}
```

Note the `functions.length ?` guard at the return is now effectively "does this file have a real function OR real top-level content" — a file that's genuinely empty (or just `<?php` with nothing else) still correctly returns `null`, since `modHasContent` stays false and no functions were matched.

`_buildCfg` never emits an explicit `noop` node for unrecognized text (confirm this still holds by re-reading `_lowerStmt`, lines 192-214, before implementing — it returns `null` for anything unmatched, and `_buildCfg`'s loop skips a `null` node entirely without adding one), so `modHasContent`'s simpler two-value check (`!== 'entry' && !== 'exit'`) is correct here, unlike Python's CST path which needed an explicit `noop` exclusion.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-php-module-level.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing PHP test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-php-rb.test.js test/parser-php-module-level.test.js`
Expected: ALL PASS, including every pre-existing PHP test in `parser-php-rb.test.js` unchanged.

- [ ] **Step 6: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-php-module-level.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/ir/parser-php.js scanner/test/parser-php-module-level.test.js scanner/package.json
git commit -m "feat(ir): PRD R14(b) — synthesize <module> lowering for PHP top-level statements"
```

---

### Task 4: Ruby — synthesize `<module>` lowering via gap computation

**Files:**
- Modify: `scanner/src/ir/parser-rb.js` (`parseRubyFile`)
- Test: create `scanner/test/parser-rb-module-level.test.js`
- Modify: `scanner/package.json` (`test:dataflow` script)

**Interfaces:**
- Consumes: `_buildCfg(bodyText, nodes, prevId, startLine)` (`parser-rb.js:246-291` — unchanged, reused as-is); `_addNode`, `_linkNodes`, `_lineAt`, `_qid` (existing, unchanged); `callSitesFromCfg` (imported at top of file, already used).
- Produces: same shape of fix as Task 3, for Ruby. `parseRubyFile(file, code)` returns a non-null IR for a flat script with zero `def` declarations but real top-level code.

This task is structurally identical to Task 3 — same gap-computation approach — against `DEF_RE`/`_extractRubyBody` instead of `FUNC_RE`/`_extractBody`.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/parser-rb-module-level.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRubyFile } from '../src/ir/parser-rb.js';

test('parseRubyFile: a flat script with no def declarations still produces an IR via a synthetic <module>', () => {
  const code = `system(params[:cmd])
`;
  const ir = parseRubyFile('flat.rb', code);
  assert.ok(ir, 'previously this returned null for the whole file — the exact R14(b) gap');
  assert.equal(ir.functions.length, 1);
  const mod = ir.functions[0];
  assert.equal(mod.name, '<module>');
  assert.equal(ir.topLevel, mod.qid);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'));
});

test('parseRubyFile: a def-only file gets no <module> entry (conditional inclusion, unchanged behavior)', () => {
  const code = `def show(request)
  name = request.input('name')
  return name
end
`;
  const ir = parseRubyFile('controller.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1, 'no synthetic <module> entry should be added — no real top-level content in this fixture');
  assert.equal(ir.topLevel, null);
});

test('parseRubyFile: top-level statements before and after a def are both captured', () => {
  const code = `cmd = params[:cmd]
def helper(x)
  return x
end
system(cmd)
`;
  const ir = parseRubyFile('interleaved.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2, 'expected helper() plus the synthetic <module>');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === 'cmd'), 'expected the pre-def assignment');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'), 'expected the post-def call');
  const helper = ir.functions.find(f => f.name === 'helper');
  assert.ok(helper, 'the real function must still be extracted unchanged');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/parser-rb-module-level.test.js`
Expected: first and third FAIL, matching Task 3's pattern.

- [ ] **Step 3: Implement gap computation and `<module>` lowering**

In `scanner/src/ir/parser-rb.js`, modify `parseRubyFile` (currently lines 293-339):

```js
export function parseRubyFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.rb$/i.test(file)) return null;
  if (code.length > 1_000_000) return null;

  const functions = [];
  const spans = []; // {start, end}: source ranges fully consumed by a matched def (header through matching `end`)
  DEF_RE.lastIndex = 0;
  _nid = 0;
  let m;
  while ((m = DEF_RE.exec(code)) !== null) {
    const name = m[1];
    const paramsText = m[2] || '';
    const params = paramsText.split(',').map(p => {
      const t = p.trim().replace(/\s*=\s*.*$/, '').replace(/^[*&]+/, '');
      return t && /^\w+$/.test(t) ? t : null;
    }).filter(Boolean);
    const defLineEnd = code.indexOf('\n', m.index + m[0].length);
    if (defLineEnd < 0) continue;
    const extracted = _extractRubyBody(code, defLineEnd + 1);
    if (!extracted) continue;
    const startLine = _lineAt(code, m.index);
    const nodes = {};
    const entry = _addNode(nodes, { kind: 'entry', line: startLine });
    const exit = _addNode(nodes, { kind: 'exit', line: startLine });
    const tail = _buildCfg(extracted.body, nodes, entry, startLine + 1);
    _linkNodes(nodes, tail, exit);
    const cfg = { entry, exit, nodes };
    functions.push({
      qid: _qid(file, name, startLine, extracted.body),
      name, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
    });
    spans.push({ start: m.index, end: extracted.end });
    DEF_RE.lastIndex = extracted.end;
  }

  // R14(b): lower top-level (module-scope) statements into a synthetic
  // <module> function, mirroring parser-js.js's Program-level lowering.
  // Same gap-computation approach as parser-php.js's Task 3 twin.
  spans.sort((a, b) => a.start - b.start);
  const modNodes = {};
  const modEntry = _addNode(modNodes, { kind: 'entry', line: 1 });
  const modExit = _addNode(modNodes, { kind: 'exit', line: 1 });
  let modTail = modEntry;
  let cursor = 0;
  for (const span of spans) {
    if (span.start > cursor) {
      const gap = code.slice(cursor, span.start);
      modTail = _buildCfg(gap, modNodes, modTail, _lineAt(code, cursor));
    }
    cursor = Math.max(cursor, span.end);
  }
  if (cursor < code.length) {
    const gap = code.slice(cursor);
    modTail = _buildCfg(gap, modNodes, modTail, _lineAt(code, cursor));
  }
  _linkNodes(modNodes, modTail, modExit);
  const modHasContent = Object.values(modNodes).some(n => n.kind !== 'entry' && n.kind !== 'exit');
  let topLevel = null;
  if (modHasContent) {
    const moduleCfg = { entry: modEntry, exit: modExit, nodes: modNodes };
    const modQid = _qid(file, '<module>', 1, code);
    functions.push({
      qid: modQid,
      name: '<module>', line: 1, params: [], file,
      cfg: moduleCfg,
      calls: callSitesFromCfg(moduleCfg),
    });
    topLevel = modQid;
  }

  return functions.length ? { file, functions, topLevel } : null;
}
```

Same note as Task 3: `_buildCfg`'s `_lowerStmt` (lines 184-210) never emits an explicit `noop` for unrecognized text, so the two-value `modHasContent` check is correct — confirm this still holds before implementing.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/parser-rb-module-level.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full existing Ruby test coverage to confirm no regressions**

Run: `cd scanner && node --test test/parser-php-rb.test.js test/parser-rb-calls.test.js test/parser-rb-module-level.test.js`
Expected: ALL PASS, including every pre-existing Ruby test unchanged.

- [ ] **Step 6: Wire into `test:dataflow`**

In `scanner/package.json`, add `test/parser-rb-module-level.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/ir/parser-rb.js scanner/test/parser-rb-module-level.test.js scanner/package.json
git commit -m "feat(ir): PRD R14(b) — synthesize <module> lowering for Ruby top-level statements"
```

---

### Task 5: Exempt `<module>`-named functions from dead-code severity demotion

**Files:**
- Modify: `scanner/src/dataflow/engine.js:1402-1416`
- Test: `scanner/test/dataflow-deadcode-severity.test.js`

**Interfaces:**
- Consumes: nothing new — this is a one-line change to an existing conditional.
- Produces: an IR-TAINT finding whose `_funcQid` resolves to a function named `<module>` (in ANY language, including JS, which already creates this synthetic function unconditionally) is never demoted by the dead-code-suppression pass, regardless of whether it has a recorded caller (module-level code has no caller by construction — this is not "dead", it's the file's entry point).

**Why this task exists and why it's in scope for this plan:** research for this plan found that JS's own pre-existing `<module>` findings are *already* silently demoted one severity tier today (`critical` → `high`), because module-level code is never the target of a call-graph edge and `<module>` doesn't match the existing route/handler/controller/middleware/endpoint exemption regex. Tasks 1-4 give Python/PHP/Ruby a `<module>` function for the first time — without this fix, their flat-script findings would inherit the identical one-tier demotion, quietly undercutting the whole point of R14(b) (a `critical` flat-script command-injection finding demoted to `high` is still a real detection, but a materially weaker one than the fix is meant to deliver). This is called out as a deliberate, evidence-based exception to "strictly additive/byte-identical" in this plan's Global Constraints — it only ever *raises* severity for existing findings, never lowers or removes one.

- [ ] **Step 1: Write the failing test**

Add to `scanner/test/dataflow-deadcode-severity.test.js`, matching the file's existing `mkTmp` + `runScan(dir, { deep: true, deepInCi: true })` pattern exactly (see the two existing tests in the file):

```js
test('a <module>-scoped finding is exempt from dead-code demotion — module code has no caller by construction', async () => {
  // A flat top-level script has no recorded caller for its synthetic
  // <module> function (nothing "calls" module scope), so before this fix
  // it fell into the same demotion the handler/route/controller/middleware/
  // endpoint regex was added to prevent for real entry points.
  const dir = mkTmp({
    'app.js': `
const cp = require('child_process');
const secret = process.env.SECRET_CMD;
cp.exec(secret);
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  const f = irFindings[0];
  assert.equal(f._inDeadCode, undefined, '<module>-scoped code has no caller by construction — it must not be marked dead code');
  assert.equal(f.severity, 'critical', `severity must not be demoted for module-scope code, got ${f.severity}`);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/dataflow-deadcode-severity.test.js`
Expected: FAIL (`finding.severity` is `'high'`, demoted).

- [ ] **Step 3: Implement the exemption**

In `scanner/src/dataflow/engine.js`, modify line 1412:

```js
    if (calledQids.has(f._funcQid)) continue;
    if (fn.name === '<module>' || /handler|route|controller|middleware|endpoint/i.test(fn.name || '')) continue;
    f._inDeadCode = true;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/dataflow-deadcode-severity.test.js`
Expected: PASS, all tests in the file (including the two pre-existing ones) green.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/dataflow/engine.js scanner/test/dataflow-deadcode-severity.test.js
git commit -m "fix(dataflow): exempt <module>-scoped findings from dead-code severity demotion"
```

---

### Task 6: Full-gate verification and documentation

**Files:**
- Modify: `docs/DETECTION_GAP_REMEDIATION_PRD.md` (R14(b) status entry)
- Modify: `CHANGELOG.md`
- Rebuild: `scanner/dist/agentic-security.mjs` + `.sha256`

No production code changes in this task — wiring/verification/docs only, following the same discipline as R13's own Task 6 (do not patch a regression by updating a baseline; if the full gate finds something new, that is a real finding to fix, not a number to paper over).

Tasks 1-4's own tests confirm the IR *shape* (correct CFG nodes for module-level code) but never run the full taint engine — they don't yet prove the PRD's actual success metric: "a flat PHP/Python/Ruby script with source→sink on the same top-level statement list is detected." This task closes that gap with genuine end-to-end `runScan` tests before declaring R14(b) done.

- [ ] **Step 1: Write and verify end-to-end detection tests for all three languages**

Create `scanner/test/r14b-module-level-e2e.test.js`, following the `mkTmp` + `runScan(dir, { deep: true, deepInCi: true })` pattern from `scanner/test/dataflow-deadcode-severity.test.js` (Task 5):

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14b-e2e-'));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('R14(b) success metric: a flat PHP script (source+sink on the top-level statement list, no function) is detected', async () => {
  const dir = mkTmp({
    'index.php': `<?php
system($_GET['cmd']);
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat PHP script, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
});

test('R14(b) success metric: a flat Ruby script (source+sink on the top-level statement list, no def) is detected', async () => {
  const dir = mkTmp({
    'app.rb': `system(params[:cmd])
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat Ruby script, got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
});

test('R14(b) success metric: a flat Python script (source+sink on the top-level statement list, no def) is detected — CST/auto path', async () => {
  const dir = mkTmp({
    'app.py': `import os

os.system(request.args)
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat Python script (CST path), got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
});

test('R14(b) success metric: a flat Python script is detected via the regex-fallback path too', async () => {
  const dir = mkTmp({
    'app.py': `import os

os.system(request.args)
`,
  });
  const prevParser = process.env.AGENTIC_SECURITY_PY_PARSER;
  process.env.AGENTIC_SECURITY_PY_PARSER = 'regex';
  try {
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const irFindings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
    assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the flat Python script (regex path), got: ${JSON.stringify((scan.findings || []).map((f) => f.parser))}`);
  } finally {
    if (prevParser === undefined) delete process.env.AGENTIC_SECURITY_PY_PARSER;
    else process.env.AGENTIC_SECURITY_PY_PARSER = prevParser;
  }
});
```

Run: `cd scanner && node --test test/r14b-module-level-e2e.test.js`
Expected: all four PASS once Tasks 1-5 are complete (this step runs AFTER Tasks 1-5, so treat any failure here as a real bug in one of those tasks — trace it back rather than adjusting this test to fit). If the Python CST test fails specifically because `python3` is unavailable in this environment, note that explicitly rather than silently skipping — check whether `pythonParserDegradation()` (see `scanner/src/ir/CLAUDE.md`) reports a fallback and treat this test's environment-dependence the same way the rest of the codebase already does for CST-path tests.

- [ ] **Step 2: Wire the new test file into `test:dataflow`**

In `scanner/package.json`, add `test/r14b-module-level-e2e.test.js` to the `test:dataflow` script's file list.

- [ ] **Step 3: Commit**

```bash
git add scanner/test/r14b-module-level-e2e.test.js scanner/package.json
git commit -m "test(dataflow): PRD R14(b) — end-to-end detection tests for flat PHP/Ruby/Python scripts"
```

- [ ] **Step 5: Run the full test:dataflow scope**

Run: `cd scanner && npm run test:dataflow`
Expected: all green, including every test file added in Tasks 1-5 and Step 1 above.

- [ ] **Step 6: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: all green (exit 0). If anything fails, diagnose and fix before proceeding — do not skip to the next step with a red gate.

- [ ] **Step 7: Run the benchmark gates**

Run, each from `scanner/`:
```bash
npm run bench:cve-replay:check
npm run bench:mutation:check
npm run bench:layer-recall:check
npm run bench:self-scan:check
```
Expected: all PASS with no drift. `bench:layer-recall:check` may show a taint-recall increase for py/php/rb if any of the 210 corpus entries happen to be flat top-level scripts — if it does, that is a genuine improvement to report accurately, not something to suppress; if it doesn't change, that's expected too (R14(b) lands via dedicated unit tests, not new corpus entries, matching R13's own precedent).

Before running `bench:self-scan:check` and the cve-replay/mutation checks, wipe scan state per root CLAUDE.md: `find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +` (run from repo root, not `scanner/`).

- [ ] **Step 8: Rebuild the bundle**

Run: `cd scanner && npm run build`
Expected: `dist/agentic-security.mjs` and its `.sha256` sidecar both update.

- [ ] **Step 9: Run the smoke test against the rebuilt bundle**

Run: `cd scanner && npm run smoke`
Expected: PASS.

- [ ] **Step 10: Update the PRD status**

In `docs/DETECTION_GAP_REMEDIATION_PRD.md`, find the "Status Log" (or equivalent running log — check the exact heading used for the R13 entry added previously) and add a dated entry analogous in detail and honesty to the existing R13 entry: what landed (Python CST + regex fallback, PHP, Ruby, all four gated on real top-level content, not unconditional creation like JS), the deliberate deviation from unconditional `<module>` creation and why (test-fixture blast radius), the dead-code severity exemption fix and why it was in scope, the end-to-end success-metric tests from Step 1, and the exact gate results from Steps 5-7 (test counts, cve-replay/mutation/layer-recall/self-scan pass/fail). Note R14(a) (annotation/decorator-shaped sources) remains open and is scoped separately.

- [ ] **Step 11: Update CHANGELOG.md**

Add an entry under the appropriate "Unreleased" heading (check the existing heading convention from the R13 entry) describing: non-JS top-level IR for Python/PHP/Ruby (the four language paths), and the dead-code severity fix for `<module>`-scoped findings (call out that this is a severity increase for existing JS findings, not new detection).

- [ ] **Step 12: Commit**

```bash
git add docs/DETECTION_GAP_REMEDIATION_PRD.md CHANGELOG.md scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "chore: wire R14(b) tests into test:dataflow, update PRD status and changelog"
```
