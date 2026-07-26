# Java IR frontend — measured defects and follow-on starting point

**Status:** documentation only. No code in `scanner/src/` changes as part of this record. It exists so a future rebuild of the Java IR frontend starts from measurement, not rediscovery.

**Context:** `docs/PROOF_CORPUS_PRD.md` §2.3 listed Java in the **Deep IR** tier ("first-class parser + proven interprocedural taint") alongside JS/TS and Python. That claim was never true and was never measured. A prior phase's goal statement also named Java as one of three languages expected to produce interprocedural findings. This document is the measurement that corrects both, and the PRD has been updated in the same commit to move Java to the **Syntactic** tier with a footnote pointing here.

## Reproduction

Run from `scanner/`, in this session:

```bash
cd /Users/ross/code/agentic-security/scanner
cat > /tmp/T.java <<'EOF'
public class T {
    public String helper(String x) {
        return x;
    }
    public void main2(String r) {
        String v = helper(r);
        Runtime.getRuntime().exec(v);
    }
}
EOF
cat > /tmp/jt.mjs <<'EOF'
import * as fs from 'node:fs';
const { buildProjectIRAsync } = await import('/Users/ross/code/agentic-security/scanner/src/ir/index.js');
const { perFile } = await buildProjectIRAsync({ 'T.java': fs.readFileSync('/tmp/T.java','utf8') });
for (const fn of perFile['T.java'].functions) {
  console.log(JSON.stringify({name:fn.name, qid:fn.qid, line:fn.line, params:fn.params, nodes:Object.keys(fn.cfg.nodes), calls:fn.calls}));
}
EOF
node /tmp/jt.mjs
```

Raw output observed this session:

```
{"name":"T.helper","qid":"T.java::T::helper","line":0,"params":[],"nodes":["jn1","jn2"]}
{"name":"T.main2","qid":"T.java::T::main2","line":0,"params":[],"nodes":["jn3","jn4"]}
```

(`calls` is absent from both records — `JSON.stringify` drops the `undefined` key. Not one of the four defects tracked below, but it means `fn.calls` cannot be relied on for Java either, whatever `tabulation.js` / `callgraph.js` do with it for other languages.)

## The four defects

### 1. CFG contains only `entry`/`exit`

Observed: `"nodes":["jn1","jn2"]` for `helper` and `"nodes":["jn3","jn4"]` for `main2` — two nodes each, for a function whose body is a one-line `return` and a two-statement block respectively. No `return`, `assign`, or `call` node is ever produced.

Source: `scanner/src/ir/parser-java.js:135-141` defines `buildCfgFromBody` to allocate exactly one `entry` and one `exit` node (`nodes[entry] = { id: entry, kind: 'entry', succ: [] }`, `nodes[exit] = { id: exit, kind: 'exit', succ: [] }`) and wires `entry -> exit` directly (line 223, `nodes[prev].succ.push(exit)` with `prev` never advanced past `entry`). It is called at `parser-java.js:274` (`cfg: buildCfgFromBody(body, 0)`) with a real `block` CST node (`md.children.methodBody[0].children.block[0]`, line 267) — the body is captured, but the CST navigation inside `buildCfgFromBody` never descends into it to emit statement nodes. This is the same shape of work the C++ parser needed for its CFG lowering (`docs/superpowers/plans/2026-07-25-cpp-ir-parser.md`), not yet done for Java.

### 2. `params` is hardcoded empty

Observed: `"params":[]` on both functions, despite `helper(String x)` and `main2(String r)` each declaring one parameter.

Source: `parser-java.js:266` — `const params = []; // params extraction deferred`. The comment is explicit that this is a known gap, not an oversight discovered here.

### 3. Every function reports `line: 0`

Observed: `"line":0` on both `helper` (declared at source line 2) and `main2` (declared at source line 5).

Source: `parser-java.js:272` — the function record is built with `line: 0` hardcoded, and `buildCfgFromBody(body, 0)` (line 274) is also passed a literal `0` rather than a resolved line number from the CST.

### 4. `qid` omits the `@line#sha` suffix every other parser emits

Observed: `"qid":"T.java::T::helper"` and `"qid":"T.java::T::main2"`.

Source: `parser-java.js:270` — `` qid: `${file}::${className || 'class'}::${name}` ``. Compare the IR shape contract in `scanner/src/ir/CLAUDE.md`: `'file.py::name@line#sha'` — a stable cross-file identifier that disambiguates same-named functions/methods across a codebase by line and a content hash. Java's `qid` is just `file::Class::name`, which collides for overloaded methods (same class, same name, different signature — routine in Java) and carries no way to distinguish two methods that happen to share a qid after a rename or move. `class-hierarchy.js` and the `stableId` machinery both key off the `@line#sha` shape; Java's `qid` does not conform to what they expect.

## Why this makes interprocedural taint impossible regardless of `fn.calls`

Even if `parser-java.js` populated `fn.calls` correctly for `helper` being invoked from `main2`, the taint engine has nothing to propagate through: the CFG has no statement nodes to carry a tainted value from parameter to return (defect 1), there is no parameter to seed as tainted in the first place (defect 2), diagnostics and dedup keys built from `line` collapse every finding in a file to the same location (defect 3), and cross-file/cross-class resolution keyed on `qid` can silently merge or miss methods because the identifier isn't unique per definition (defect 4). Each defect independently blocks the flow-engine path from function boundary in to function boundary out; together they mean Java is, today, a parser that extracts function *names* and nothing else usable by `scanner/src/dataflow/`.

## Follow-on starting point

The nearest template for the rebuild is `docs/superpowers/plans/2026-07-25-cpp-ir-parser.md` — it took a language from no first-class IR parser to Structural IR tier (real CFG, connected call graph, measured parse coverage) in eight tasks, hand-rolled with no new dependencies, following the same `_lowerStmt` / `_lowerExpr` / `_qid` shape already established by `parser-cs.js` and `parser-go.js`. Java already has a CST (`java-parser` npm package) where C++ had none, so the frontend rebuild should be a subset of that plan's scope: statement lowering into `buildCfgFromBody` (defect 1), real parameter extraction from `methodDeclarator` (defect 2), line resolution from CST location info (defect 3), and a qid conforming to the `file::name@line#sha` contract (defect 4) — no new parser architecture required, just finishing the one that exists.

No `scanner/src/` file is touched by this document.
