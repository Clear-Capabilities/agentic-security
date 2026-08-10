# C++ First-Class IR Parser — Implementation Plan (PRD Workstream B)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give C and C++ a first-class IR parser so they reach the taint engine, call graph, and class-hierarchy analysis like the other supported languages, and prove it with an interprocedural finding plus a measured parse-coverage number on a real multi-million-line codebase.

**Architecture:** A hand-rolled parser (`scanner/src/ir/parser-cpp.js`) following the established `parser-cs.js` / `parser-go.js` template — brace-balanced translation-unit splitting, statement splitting, expression lowering, linear CFG. It reuses the battle-tested brace splitter already proven in `sast/cpp-dataflow.js` rather than inventing a new one. Cross-translation-unit calls resolve through a project-wide qualified-name index, because C++ splits declaration from definition and file-local name resolution alone would leave the call graph empty.

**Tech Stack:** Node ≥ 24, ESM, `node:test` + `node:assert/strict`, `node:crypto`. No new dependencies. No tree-sitter, no libclang (see Design Decisions below).

## Global Constraints

Copied from `CLAUDE.md`, `scanner/CLAUDE.md`, and the Proof Corpus PRD §6. (removed post-implementation) Every task's requirements implicitly include this section.

- **ESM only.** `import`/`export`. No CommonJS anywhere in `scanner/src/`.
- **Node ≥ 24.** Verified present: v24.16.0.
- **No new npm dependencies.**
- **Rebuild after `src/` changes.** `cd scanner && npm run build`. Unit tests run against `src/` and need no rebuild.
- **Confirm every mutation landed.** After any edit, re-read the region or grep for the exact string added.
- **Numbers require the run that produced them.** Never state a coverage figure or test count unless it came from a command executed in the same session.
- **New test files must be wired into a scoped script** in `scanner/package.json` or they never run in CI. This parser's tests belong to `test:dataflow`.
- **Corpus discipline.** A `bench/cve-replay/` entry must score `pre:TP post:TN` before it is added. Then `npm run bench:cve-replay:check` → `npm run bench:cve-replay:update-baseline` → commit the regenerated baseline.
- **Wipe scan state before benchmarking.** `find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +`.
- **Never name any external or competitor tool** in code, comments, docs, or commit messages.
- **Findings schema.** Every finding needs `{ id, severity, file, line, vuln, cwe, description, remediation, parser, family }`.

## Branch Prerequisite

This plan depends on the IR parse-coverage instrumentation (`AGENTIC_SECURITY_IR_STATS`) that currently lives in branch `docs/proof-corpus-prd` (**PR #42, not yet merged to `main`**). That instrument is the acceptance measurement for Task 8.

Branch from `docs/proof-corpus-prd`, not from `main`:

```bash
git checkout docs/proof-corpus-prd
git pull
git checkout -b feat/cpp-ir-parser
```

If PR #42 has already merged by the time you start, branch from `main` instead and confirm `scanner/src/ir/ir-stats.js` exists before proceeding.

---

## Design Decisions (already settled — do not relitigate)

**Hand-rolled, not tree-sitter.** A C++ grammar exists, but `web-tree-sitter` and `tree-sitter-wasms` are optional dependencies the build explicitly excludes (`ncc build … -e web-tree-sitter -e tree-sitter-wasms`), so the shipped bundle does not carry them. Building first-class C++ support on them would make C++ conditional on deps the product lacks — reproducing the exact weakness this work removes.

**Hand-rolled, not libclang.** Native bindings violate the no-native-deps posture, `compile_commands.json` would be required, and the project never compiles its scan targets.

**Target tier is Structural IR, not compiler fidelity.** CFG produced, call graph connected, taint flowing through obvious paths. Templates, overload resolution, and exact virtual dispatch are explicitly out of scope (PRD §6.5).

---

## Verified Facts About the Existing Code

Each was confirmed by reading the source. They shape the design; do not assume otherwise.

| Fact | Evidence | Consequence |
|---|---|---|
| C/C++ files already reach the scanner's file map | `CODE_EXTS` (`engine.js:576`) contains `c, cc, cpp, cxx, h, hh, hpp, hxx` | No file-collection change needed; the parser will receive these files |
| `ir/index.js` dispatches on extension and has **no** C/C++ branch | `buildProjectIR` / `buildProjectIRAsync` | C++ never reaches the taint engine today — this is the entire gap |
| `buildClassHierarchy` is **not** Babel-dependent | `class-hierarchy.js:34-87` walks `perFileIR` only | PRD §6.8 overstated this. CHA works off qid shape and needs no C++-specific extractor |
| CHA recovers a class from the qid tail `Class.method`, splitting on the **first** dot | `class-hierarchy.js:50-53` | The C++ qid tail must be `Class.method`, NOT `Ns::Class::method`, or class recovery breaks |
| CHA **never** populates `extends` for any language | `class-hierarchy.js:57` sets `extends: null`; nothing writes it | Inheritance needs a new, language-neutral input. This plan adds `ir.classes` |
| The taint catalog matches a callee by its **last segment**, and accepts string callees | `catalog.js:797-810` | C++ dotted/`::` callees work if the parser emits string callees, as Go does |
| Files > 500 KB and very dense files are skipped before IR | `engine.js:7403` | Those files never enter the coverage denominator — the 85% bar is over files actually offered to the parser |
| `sast/cpp-dataflow.js` has a proven brace-balanced function splitter | `_findFunctions`, written specifically to avoid catastrophic regex backtracking | Reuse its algorithm; it only captures bare identifiers, so it needs qualified-name support |

---

## File Structure

| File | Responsibility |
|---|---|
| `scanner/src/ir/parser-cpp.js` | *Create.* The IR frontend: translation-unit splitting, qualified-name capture, params, statement/expression lowering, CFG construction, class collection. |
| `scanner/src/ir/index.js` | *Modify.* Dispatch C/C++ extensions in both `buildProjectIR` and `buildProjectIRAsync`; re-export `parseCppFile`. |
| `scanner/src/ir/callgraph.js` | *Modify.* Add a project-wide qualified-name index so cross-translation-unit calls resolve. |
| `scanner/src/ir/class-hierarchy.js` | *Modify.* Consume an optional `ir.classes` array to populate `extends`. Language-neutral. |
| `scanner/src/dataflow/catalog.js` | *Modify.* Add C/C++ sources, sinks, and sanitizers. |
| `scanner/test/parser-cpp.test.js` | *Create.* Unit tests for the parser. Wired into `test:dataflow`. |
| `scanner/test/cpp-integration.test.js` | *Create.* Cross-TU resolution, CHA inheritance, end-to-end taint. Wired into `test:dataflow`. |
| `bench/cve-replay/capability/CVE-*-cpp-*/` | *Create.* Ten C/C++ corpus entries. |
| the Proof Corpus PRD | *Modify.* Correct §6.8's claim that CHA is Babel-only; record the measured Godot result. |

---

## Task 1: Parser core — translation units, qualified names, params

**Files:**
- Create: `scanner/src/ir/parser-cpp.js`
- Test: `scanner/test/parser-cpp.test.js`
- Modify: `scanner/package.json` (add test to `test:dataflow`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `parseCppFile(file: string, code: string) → { file, functions: Fn[], classes: Cls[], topLevel: null } | null`
  - `Fn = { qid, name, qname, line, params: string[], file, isDeclaration: boolean, cfg }`
  - `Cls = { name, bases: string[], line }`
  - `qid` format: `<file>::<Class>.<method>@<line>#<sha8>` for methods, `<file>::<name>@<line>#<sha8>` for free functions. **The tail joins class and method with a dot** because `class-hierarchy.js:50-53` splits on the first dot to recover the class name.
  - `qname` format: `Ns::Class::method` (full C++ qualification, `::`-joined), or plain `name` when unqualified. Task 4 indexes on this.
  - `_internals` export carrying `{ _splitTopLevelCommas, _extractBody, _lineAt, _qid, _findFunctions, _parseParams }` for testing.

- [ ] **Step 1: Write the failing test**

Create `scanner/test/parser-cpp.test.js`:

```javascript
// Tests for the C/C++ IR frontend.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCppFile } from '../src/ir/parser-cpp.js';

test('parseCppFile: captures a free function with params', () => {
  const code = `
#include <string>
void handle(const std::string& name, int count) {
  int total = count;
  return;
}
`;
  const ir = parseCppFile('a.cpp', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'handle');
  assert.equal(fn.qname, 'handle');
  assert.deepEqual(fn.params, ['name', 'count']);
  assert.equal(fn.isDeclaration, false);
  assert.equal(fn.file, 'a.cpp');
  assert.ok(fn.cfg && fn.cfg.nodes.entry && fn.cfg.nodes.exit);
});

test('parseCppFile: captures an out-of-line method definition with qualified name', () => {
  const code = `
void Parser::consume(char* buf) {
  int x = 1;
}
`;
  const ir = parseCppFile('p.cpp', code);
  assert.equal(ir.functions.length, 1);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'consume');
  assert.equal(fn.qname, 'Parser::consume');
  assert.match(fn.qid, /^p\.cpp::Parser\.consume@\d+#[0-9a-f]{8}$/,
    'qid tail must join class and method with a dot so CHA can recover the class');
});

test('parseCppFile: captures a namespaced out-of-line method', () => {
  const code = `
int core::Buffer::size(int n) {
  return n;
}
`;
  const ir = parseCppFile('b.cpp', code);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'size');
  assert.equal(fn.qname, 'core::Buffer::size');
  assert.match(fn.qid, /::Buffer\.size@/, 'qid uses the immediate class, not the namespace');
});

test('parseCppFile: captures in-class method definitions and the class record', () => {
  const code = `
class Reader : public Base, private Mixin {
public:
  int read(int fd) {
    int n = fd;
    return n;
  }
};
`;
  const ir = parseCppFile('r.cpp', code);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'read');
  assert.equal(ir.functions[0].qname, 'Reader::read');
  assert.equal(ir.classes.length, 1);
  assert.equal(ir.classes[0].name, 'Reader');
  assert.deepEqual(ir.classes[0].bases.sort(), ['Base', 'Mixin']);
});

test('parseCppFile: records header declarations without bodies as declarations', () => {
  const code = `
class Reader {
public:
  int read(int fd);
  void close();
};
`;
  const ir = parseCppFile('r.h', code);
  const names = ir.functions.map(f => f.name).sort();
  assert.deepEqual(names, ['close', 'read']);
  assert.ok(ir.functions.every(f => f.isDeclaration === true));
  assert.equal(ir.functions[0].qname, 'Reader::read');
});

test('parseCppFile: handles reference, pointer, const and defaulted params', () => {
  const code = `
void f(const char* src, std::string& dst, int n = 10, Foo<Bar> baz) {
  int y = n;
}
`;
  const ir = parseCppFile('f.cpp', code);
  assert.deepEqual(ir.functions[0].params, ['src', 'dst', 'n', 'baz']);
});

test('parseCppFile: constructors and destructors are captured', () => {
  const code = `
Widget::Widget(int size) {
  int s = size;
}
Widget::~Widget() {
  int z = 0;
}
`;
  const ir = parseCppFile('w.cpp', code);
  const names = ir.functions.map(f => f.name).sort();
  assert.deepEqual(names, ['Widget', '~Widget']);
});

test('parseCppFile: control-flow keywords are not mistaken for functions', () => {
  const code = `
void f(int n) {
  if (n > 0) { int a = 1; }
  while (n) { int b = 2; }
  for (int i = 0; i < n; i++) { int c = 3; }
  switch (n) { case 1: break; }
}
`;
  const ir = parseCppFile('c.cpp', code);
  assert.equal(ir.functions.length, 1, 'only f is a function');
  assert.equal(ir.functions[0].name, 'f');
});

test('parseCppFile: comments and strings containing braces do not break splitting', () => {
  const code = `
// a comment with { and }
void f() {
  const char* s = "a { brace } in a string";
  int x = 1;
}
`;
  const ir = parseCppFile('s.cpp', code);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'f');
});

test('parseCppFile: qid is stable for unchanged bodies and differs when the body changes', () => {
  const a = parseCppFile('x.cpp', 'void f() {\n int x = 1;\n}\n');
  const b = parseCppFile('x.cpp', 'void f() {\n int x = 1;\n}\n');
  const c = parseCppFile('x.cpp', 'void f() {\n int x = 2;\n}\n');
  assert.equal(a.functions[0].qid, b.functions[0].qid);
  assert.notEqual(a.functions[0].qid, c.functions[0].qid);
});

test('parseCppFile: rejects bad input without throwing', () => {
  assert.equal(parseCppFile(null, 'void f(){}'), null);
  assert.equal(parseCppFile('a.cpp', null), null);
  assert.equal(parseCppFile('a.cpp', 42), null);
  const empty = parseCppFile('a.cpp', '');
  assert.ok(empty);
  assert.deepEqual(empty.functions, []);
});

test('parseCppFile: an unterminated body does not hang or throw', () => {
  const ir = parseCppFile('u.cpp', 'void f() {\n int x = 1;\n');
  assert.ok(ir, 'must return a record rather than throwing');
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/parser-cpp.test.js
```

Expected: FAIL — `Cannot find module '../src/ir/parser-cpp.js'`.

- [ ] **Step 3: Write the implementation**

Create `scanner/src/ir/parser-cpp.js`:

```javascript
// C / C++ IR frontend.
//
// Hand-rolled, following the parser-cs.js / parser-go.js template. See
// the Proof Corpus PRD §6.3 for why this is not tree-sitter or libclang:
// the build excludes the tree-sitter deps from the bundle, and libclang would
// require native bindings plus a compile database we deliberately never build.
//
// The translation-unit splitter is the brace-balanced algorithm proven in
// sast/cpp-dataflow.js (written that way because a regex approach exhibited
// catastrophic backtracking on real headers), extended here to capture
// qualified names like `core::Buffer::size`.
//
// What we model:
//   - free functions, out-of-line methods (Ns::Class::method), constructors,
//     destructors, in-class method definitions
//   - header declarations (no body) recorded with isDeclaration: true
//   - parameters including refs, pointers, const, templates, default args
//   - class records with base classes, for class-hierarchy analysis
//
// What we do NOT model (PRD §6.5 — this list is a contract):
//   - templates (parsed; type parameters erased — one record per template,
//     not one per instantiation)
//   - operator overloading semantics beyond string building
//   - exact virtual dispatch (approximated via CHA)
//   - try/catch edges (throw is a node; handler edges are not built)
//   - pointer aliasing beyond direct assignment
//   - function-like macros, token pasting, conditional-compilation selection
//   - goto, multiple-inheritance vtable layout, placement new

import * as crypto from 'node:crypto';

const CPP_EXT_RE = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i;

// Keywords that are followed by `(...)  {` but are not functions.
const _NON_FN_KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'switch', 'catch', 'do', 'return', 'sizeof',
  'and', 'or', 'not', 'new', 'delete', 'throw', 'case', 'default',
]);

// Guard rails so a pathological file cannot dominate a scan.
const _MAX_FUNCTIONS = 5000;
const _LOOKBACK = 400;

export function cppExtRe() { return CPP_EXT_RE; }

// ── comment / string blanking ───────────────────────────────────────────────
// Replace comment and string bodies with spaces, preserving length and line
// structure so every index and line number computed later stays valid.
function _blank(src) {
  const out = src.split('');
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') { out[i] = ' '; i++; }
      continue;
    }
    if (c === '/' && d === '*') {
      out[i] = ' '; out[i + 1] = ' '; i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] !== '\n') out[i] = ' ';
        i++;
      }
      if (i < n) { out[i] = ' '; out[i + 1] = ' '; i += 2; }
      continue;
    }
    if (c === '"' || c === "'") {
      const quote = c;
      i++;
      while (i < n) {
        if (src[i] === '\\') { out[i] = ' '; if (i + 1 < n) out[i + 1] = ' '; i += 2; continue; }
        if (src[i] === quote) { out[i] = ' '; i++; break; }
        if (src[i] !== '\n') out[i] = ' ';
        i++;
      }
      continue;
    }
    i++;
  }
  return out.join('');
}

function _lineAt(src, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < src.length; i++) if (src[i] === '\n') line++;
  return line;
}

function _qid(file, tail, line, body) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  return `${file}::${tail}@${line}#${sha}`;
}

// Split `a, b<c, d>, e(f, g)` on top-level commas only.
function _splitTopLevelCommas(s) {
  const out = [];
  let depth = 0, buf = '';
  for (const ch of String(s || '')) {
    if (ch === '(' || ch === '[' || ch === '<' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '>' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { out.push(buf); buf = ''; continue; }
    buf += ch;
  }
  if (buf.trim()) out.push(buf);
  return out;
}

// `const std::string& name` → 'name'; `int n = 10` → 'n'; `void` → null.
function _parseParams(text) {
  const params = [];
  for (const raw of _splitTopLevelCommas(text)) {
    let t = raw.replace(/=.*$/s, '').trim();
    if (!t || t === 'void' || t === '...') continue;
    // Array suffix: `char buf[10]` → `char buf`
    t = t.replace(/\[[^\]]*\]\s*$/, '').trim();
    const m = t.match(/([A-Za-z_]\w*)\s*$/);
    if (m && !_NON_FN_KEYWORDS.has(m[1])) params.push(m[1]);
  }
  return params;
}

// Body extraction by brace counting over already-blanked source.
function _extractBody(blank, openBrace) {
  let depth = 1;
  let i = openBrace + 1;
  while (i < blank.length && depth > 0) {
    const c = blank[i];
    if (c === '{') depth++;
    else if (c === '}') depth--;
    if (depth === 0) return { start: openBrace + 1, end: i };
    i++;
  }
  return null; // unterminated — caller skips
}

// Walk back from a `(` to capture a possibly-qualified name: `core::Buffer::size`,
// `~Widget`, `operator+` is deliberately NOT captured (out of scope).
function _nameBefore(blank, lparen) {
  let end = lparen - 1;
  while (end >= 0 && /\s/.test(blank[end])) end--;
  if (end < 0) return null;
  let start = end;
  while (start >= 0 && /[A-Za-z0-9_:~]/.test(blank[start])) start--;
  start++;
  const raw = blank.slice(start, end + 1);
  if (!raw || !/^[~A-Za-z_][\w:~]*$/.test(raw)) return null;
  if (raw.includes(':') && !raw.includes('::')) return null; // label, not scope
  return raw;
}

// Find enclosing class for an index, from collected class spans.
function _enclosingClass(classSpans, idx) {
  let best = null;
  for (const c of classSpans) {
    if (idx > c.open && idx < c.close) {
      if (!best || c.open > best.open) best = c;
    }
  }
  return best ? best.name : null;
}

// Collect `class X : public A, private B {` / `struct X {` spans.
function _findClasses(blank) {
  const spans = [];
  const re = /\b(?:class|struct)\s+([A-Za-z_]\w*)\s*(?::([^{;]*))?\{/g;
  let m;
  while ((m = re.exec(blank)) !== null) {
    const open = m.index + m[0].length - 1;
    const body = _extractBody(blank, open);
    if (!body) continue;
    const bases = [];
    if (m[2]) {
      for (const part of _splitTopLevelCommas(m[2])) {
        const b = part.replace(/\b(?:public|private|protected|virtual)\b/g, '').trim();
        const last = b.split('::').pop();
        if (last && /^[A-Za-z_]\w*$/.test(last)) bases.push(last);
      }
    }
    spans.push({ name: m[1], bases, line: _lineAt(blank, m.index), open, close: body.end });
  }
  return spans;
}

// Find every function definition (with body) and declaration (no body).
function _findFunctions(blank, classSpans) {
  const found = [];
  const n = blank.length;
  let i = 0;
  while (i < n && found.length < _MAX_FUNCTIONS) {
    const ch = blank[i];
    if (ch !== '(') { i++; continue; }
    // Match the closing paren for this `(`.
    let depth = 1, j = i + 1;
    while (j < n && depth > 0) {
      if (blank[j] === '(') depth++;
      else if (blank[j] === ')') depth--;
      j++;
    }
    if (depth !== 0) break;
    const paramText = blank.slice(i + 1, j - 1);
    const name = _nameBefore(blank, i);
    if (!name) { i++; continue; }
    const bare = name.split('::').pop();
    if (!bare || _NON_FN_KEYWORDS.has(bare)) { i++; continue; }
    if (name.length > _LOOKBACK) { i++; continue; }

    // After the params: skip const/noexcept/override/final/ref-qualifiers.
    let k = j;
    while (k < n && /[\s\w&]/.test(blank[k])) {
      // Stop if we hit something that starts a body or ends a declaration.
      if (blank[k] === '{' || blank[k] === ';') break;
      k++;
    }
    const term = blank[k];
    if (term === '{') {
      const body = _extractBody(blank, k);
      if (!body) { i = j; continue; }
      found.push({
        name, paramText,
        line: _lineAt(blank, i),
        bodyStart: body.start, bodyEnd: body.end,
        isDeclaration: false,
        nameIdx: i,
      });
      i = body.end + 1;
      continue;
    }
    if (term === ';') {
      // A declaration only counts when it sits inside a class body — otherwise
      // it is very likely a call statement or a prototype we do not need.
      const cls = _enclosingClass(classSpans, i);
      if (cls) {
        found.push({
          name, paramText,
          line: _lineAt(blank, i),
          bodyStart: null, bodyEnd: null,
          isDeclaration: true,
          nameIdx: i,
        });
      }
      i = k + 1;
      continue;
    }
    i = j;
  }
  return found;
}

export function parseCppFile(file, code) {
  if (typeof file !== 'string' || typeof code !== 'string') return null;
  const blank = _blank(code);
  const classSpans = _findClasses(blank);
  const raw = _findFunctions(blank, classSpans);

  const functions = [];
  for (const f of raw) {
    const bare = f.name.split('::').pop();
    const explicitScope = f.name.includes('::')
      ? f.name.slice(0, f.name.lastIndexOf('::'))
      : null;
    const enclosing = _enclosingClass(classSpans, f.nameIdx);
    // Fully-qualified name for the cross-TU index.
    const qname = explicitScope
      ? `${explicitScope}::${bare}`
      : (enclosing ? `${enclosing}::${bare}` : bare);
    // The class used in the qid tail is the IMMEDIATE class — the last scope
    // segment — because class-hierarchy.js splits the tail on its first dot.
    const ownerClass = explicitScope ? explicitScope.split('::').pop() : enclosing;
    const tail = ownerClass ? `${ownerClass}.${bare}` : bare;
    const bodyText = f.isDeclaration ? '' : code.slice(f.bodyStart, f.bodyEnd);

    functions.push({
      qid: _qid(file, tail, f.line, bodyText || `${qname}@decl`),
      name: bare,
      qname,
      line: f.line,
      params: _parseParams(f.paramText),
      file,
      isDeclaration: f.isDeclaration,
      cfg: _buildCfg(bodyText, f.line),
    });
  }

  return {
    file,
    functions,
    classes: classSpans.map(c => ({ name: c.name, bases: c.bases, line: c.line })),
    topLevel: null,
  };
}

// Statement lowering arrives in Task 2; for now every body yields a
// well-formed entry→exit CFG so the IR shape contract holds from the start.
function _buildCfg(_bodyText, line) {
  const nodes = {
    entry: { kind: 'entry', line, succ: ['exit'], pred: [] },
    exit: { kind: 'exit', line, succ: [], pred: ['entry'] },
  };
  return { entry: 'entry', exit: 'exit', nodes };
}

export const _internals = {
  _blank, _splitTopLevelCommas, _parseParams, _extractBody,
  _lineAt, _qid, _findFunctions, _findClasses, _nameBefore,
};
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/parser-cpp.test.js
```

Expected: PASS, 12 tests. If the qualified-name tests fail, the fault is almost certainly in `_nameBefore` or the `explicitScope` split — fix those rather than weakening the assertions, because Task 4 and Task 5 both depend on `qname` and the dotted qid tail being exactly right.

- [ ] **Step 5: Wire the test into `test:dataflow`**

In `scanner/package.json`, append ` test/parser-cpp.test.js` to the end of the `"test:dataflow"` value, immediately before the closing quote.

- [ ] **Step 6: Confirm the wiring landed and the scope still passes**

```bash
cd /Users/ross/code/agentic-security/scanner && grep -c 'test/parser-cpp.test.js' package.json && npm run test:dataflow 2>&1 | tail -8
```

Expected: `grep -c` prints `1`, and the dataflow suite passes.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/parser-cpp.js scanner/test/parser-cpp.test.js scanner/package.json
git commit -m "feat(ir): add C/C++ IR frontend — functions, qualified names, classes

Hand-rolled parser following the parser-cs.js/parser-go.js template, reusing
the brace-balanced splitting approach proven in sast/cpp-dataflow.js.

Captures free functions, out-of-line methods, constructors, destructors,
in-class definitions, and header declarations (isDeclaration: true), plus a
per-file class record with base classes.

The qid tail joins class and method with a dot (Class.method) rather than ::
because class-hierarchy.js splits the tail on its first dot to recover the
class name. The fully-qualified C++ name is carried separately as qname for
cross-translation-unit resolution."
```

---

## Task 2: Statement and expression lowering

**Files:**
- Modify: `scanner/src/ir/parser-cpp.js` (replace the placeholder `_buildCfg`)
- Modify: `scanner/test/parser-cpp.test.js` (append tests)

**Interfaces:**
- Consumes: `parseCppFile` from Task 1.
- Produces: CFG nodes conforming to the IR contract in `scanner/src/ir/CLAUDE.md` — `kind` ∈ `entry|exit|noop|assign|call|if|return|throw|unknown`, each with `line`, `succ[]`, `pred[]`; `assign` carries `target` + `source`; `call` carries `callee` + `args[]`; `if` carries `cond`; `return` carries `value`.
- Expression shapes: `{kind:'literal'|'ident'|'member'|'binary'|'tpl'|'call'|'unknown'}` exactly as the other parsers emit. **Callees are emitted as dotted/`::` strings**, matching `parser-go.js`, because `catalog.js:797` matches string callees by last segment.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/parser-cpp.test.js`:

```javascript
function nodesOf(ir, idx = 0) {
  return Object.values(ir.functions[idx].cfg.nodes);
}

test('lowering: assignments capture target and source', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  int x = n;\n  y = 3;\n}\n');
  const assigns = nodesOf(ir).filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === 'x' && a.source.kind === 'ident' && a.source.name === 'n'));
  assert.ok(assigns.some(a => a.target === 'y' && a.source.kind === 'literal'));
});

test('lowering: calls emit a dotted string callee and lowered args', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* p) {\n  system(p);\n  obj.run(p);\n  ptr->exec(p);\n  ns::go(p);\n}\n');
  const calls = nodesOf(ir).filter(n => n.kind === 'call');
  const callees = calls.map(c => c.callee).sort();
  assert.deepEqual(callees, ['ns::go', 'obj.run', 'ptr.exec', 'system'],
    'member and arrow access both normalise to dotted form; :: is preserved');
  assert.ok(calls.every(c => Array.isArray(c.args)));
});

test('lowering: assignment from a call keeps the call as the source', () => {
  const ir = parseCppFile('a.cpp', 'void f() {\n  char* p = getenv("PATH");\n}\n');
  const a = nodesOf(ir).find(n => n.kind === 'assign');
  assert.equal(a.target, 'p');
  assert.equal(a.source.kind, 'call');
  assert.equal(a.source.callee, 'getenv');
});

test('lowering: return and throw carry their value', () => {
  const ir = parseCppFile('a.cpp', 'int f(int n) {\n  if (n) { throw n; }\n  return n;\n}\n');
  const ns = nodesOf(ir);
  assert.ok(ns.some(n => n.kind === 'return' && n.value && n.value.name === 'n'));
  assert.ok(ns.some(n => n.kind === 'throw'));
});

test('lowering: if produces an if node carrying the condition', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  if (n > 0) {\n    int a = n;\n  }\n}\n');
  const ns = nodesOf(ir);
  const iff = ns.find(n => n.kind === 'if');
  assert.ok(iff, 'expected an if node');
  assert.ok(iff.cond);
  assert.ok(ns.some(n => n.kind === 'assign' && n.target === 'a'),
    'the if body must be lowered, not dropped');
});

test('lowering: loop bodies are lowered', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  for (int i = 0; i < n; i++) {\n    int b = n;\n  }\n  while (n) {\n    int c = n;\n  }\n}\n');
  const targets = nodesOf(ir).filter(n => n.kind === 'assign').map(n => n.target);
  assert.ok(targets.includes('b'), 'for-body assignment must be lowered');
  assert.ok(targets.includes('c'), 'while-body assignment must be lowered');
});

test('lowering: string concatenation becomes a template so taint flows through', () => {
  const ir = parseCppFile('a.cpp', 'void f(std::string user) {\n  std::string q = "SELECT " + user;\n}\n');
  const a = nodesOf(ir).find(n => n.kind === 'assign' && n.target === 'q');
  assert.equal(a.source.kind, 'tpl');
  assert.ok(a.source.parts.some(p => p.kind === 'ident' && p.name === 'user'));
});

test('lowering: sprintf-family calls lower their arguments', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* user) {\n  char buf[64];\n  sprintf(buf, "%s", user);\n}\n');
  const c = nodesOf(ir).find(n => n.kind === 'call' && n.callee === 'sprintf');
  assert.ok(c);
  assert.ok(c.args.some(a => a.kind === 'ident' && a.name === 'user'));
});

test('lowering: every node is reachable from entry and the CFG is well formed', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  int x = n;\n  g(x);\n  return;\n}\n');
  const cfg = ir.functions[0].cfg;
  const seen = new Set();
  const stack = [cfg.entry];
  while (stack.length) {
    const id = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    for (const s of cfg.nodes[id].succ) {
      assert.ok(cfg.nodes[s], `succ ${s} must exist`);
      assert.ok(cfg.nodes[s].pred.includes(id), `pred link back from ${s} to ${id}`);
      stack.push(s);
    }
  }
  assert.ok(seen.has(cfg.exit), 'exit must be reachable from entry');
  assert.equal(seen.size, Object.keys(cfg.nodes).length, 'no orphan nodes');
});

test('lowering: a declaration has an empty but valid CFG', () => {
  const ir = parseCppFile('r.h', 'class R {\npublic:\n  int read(int fd);\n};\n');
  const cfg = ir.functions[0].cfg;
  assert.equal(cfg.entry, 'entry');
  assert.equal(cfg.nodes.entry.succ[0], 'exit');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/parser-cpp.test.js 2>&1 | tail -20
```

Expected: the ten new tests FAIL (the placeholder `_buildCfg` emits only entry and exit); the twelve from Task 1 still pass.

- [ ] **Step 3: Write the implementation**

In `scanner/src/ir/parser-cpp.js`, replace the placeholder `_buildCfg` function with the following, and add the helpers above it:

```javascript
// ── expression lowering ─────────────────────────────────────────────────────

// Split on a top-level binary operator, respecting nesting.
function _splitTopLevel(s, op) {
  const out = [];
  let depth = 0, buf = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    if (depth === 0 && ch === op) { out.push(buf); buf = ''; continue; }
    buf += ch;
  }
  out.push(buf);
  return out;
}

// Normalise `a->b->c` and `a.b.c` to dotted form; `::` is preserved as scope.
function _normaliseCallee(s) {
  return s.replace(/->/g, '.').trim();
}

function _lowerExpr(text) {
  const s = String(text || '').trim().replace(/;$/, '').trim();
  if (!s) return { kind: 'unknown' };

  // String concatenation — checked before the literal rule, or `"a" + x`
  // would be swallowed whole as a literal and taint could not flow.
  if (s.includes('+')) {
    const parts = _splitTopLevel(s, '+');
    if (parts.length > 1 && parts.every(p => p.trim())) {
      return { kind: 'tpl', parts: parts.map(_lowerExpr) };
    }
  }
  if (/^"/.test(s) || /^'/.test(s)) return { kind: 'literal', value: s };
  if (/^-?\d/.test(s)) return { kind: 'literal', value: s };
  if (/^(?:true|false|nullptr|NULL)$/.test(s)) return { kind: 'literal', value: s };

  // Cast: `(char*)expr` → lower the inner expression.
  const cast = s.match(/^\(\s*[A-Za-z_][\w:\s*&<>]*\)\s*(.+)$/s);
  if (cast && !/^\(\s*\)/.test(s)) return _lowerExpr(cast[1]);

  // Call: name(args) / a.b(args) / a->b(args) / ns::f(args)
  const call = s.match(/^([A-Za-z_][\w:.]*(?:->[A-Za-z_]\w*)*)\s*\((.*)\)$/s);
  if (call) {
    const callee = _normaliseCallee(call[1]);
    const bare = callee.split(/[.:]/).pop();
    if (!_NON_FN_KEYWORDS.has(bare)) {
      return { kind: 'call', callee, args: _splitTopLevelCommas(call[2]).map(_lowerExpr) };
    }
  }

  // Address-of / dereference: taint passes through transparently.
  const unary = s.match(/^[&*]\s*(.+)$/s);
  if (unary) return _lowerExpr(unary[1]);

  // Member read: a.b / a->b / ns::CONST
  if (/^[A-Za-z_][\w:.]*(?:->[A-Za-z_]\w*)*$/.test(s) && /[.:>]/.test(s)) {
    const d = _normaliseCallee(s);
    const idx = d.lastIndexOf('.');
    if (idx > 0) {
      return { kind: 'member', object: _lowerExpr(d.slice(0, idx)), prop: d.slice(idx + 1) };
    }
    return { kind: 'ident', name: d };
  }

  // Array index: `buf[i]` → treat as the base identifier.
  const idxm = s.match(/^([A-Za-z_]\w*)\s*\[.*\]$/s);
  if (idxm) return { kind: 'ident', name: idxm[1] };

  if (/^[A-Za-z_]\w*$/.test(s)) return { kind: 'ident', name: s };

  // Comparison / arithmetic — keep both sides so taint survives.
  for (const op of ['==', '!=', '<=', '>=', '<', '>', '-', '*', '/', '%']) {
    const parts = _splitTopLevel(s, op.length === 1 ? op : '\u0000');
    if (op.length === 1 && parts.length > 1 && parts.every(p => p.trim())) {
      return { kind: 'binary', op, left: _lowerExpr(parts[0]), right: _lowerExpr(parts.slice(1).join(op)) };
    }
  }
  return { kind: 'unknown' };
}

// ── statement splitting ─────────────────────────────────────────────────────

// Split a body into top-level statements. Blocks (`{...}`) are returned whole
// so the caller can recurse into them.
function _splitStatements(body) {
  const out = [];
  let depth = 0, buf = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '{') depth++;
    if (c === '}') {
      depth--;
      buf += c;
      if (depth === 0) { out.push(buf); buf = ''; }
      continue;
    }
    if (c === ';' && depth === 0) {
      const t = buf.trim();
      if (t) out.push(t);
      buf = '';
      continue;
    }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function _lowerStmt(stmt, line) {
  const s = stmt.trim();
  if (!s || s === '{' || s === '}') return null;

  if (/^return\b/.test(s)) {
    const v = s.replace(/^return\b/, '').trim();
    return { kind: 'return', line, value: v ? _lowerExpr(v) : null };
  }
  if (/^throw\b/.test(s)) {
    return { kind: 'throw', line, value: _lowerExpr(s.replace(/^throw\b/, '')) };
  }
  if (/^(?:break|continue|goto\b)/.test(s)) return { kind: 'noop', line };

  // Assignment. The type prefix is optional: `int x = e`, `x = e`, `a->b = e`.
  // `==`, `!=`, `<=`, `>=` must not match, hence the negative lookarounds.
  const asg = s.match(/^(?:[A-Za-z_][\w:<>,*&\s]*?\s+)?([A-Za-z_][\w:.\->\[\]]*?)\s*(?<![=!<>+\-*/%])=(?!=)\s*(.+)$/s);
  if (asg) {
    const target = _normaliseCallee(asg[1]).replace(/\[.*\]$/, '');
    return { kind: 'assign', line, target, source: _lowerExpr(asg[2]) };
  }

  // Statement-form call.
  const call = s.match(/^([A-Za-z_][\w:.]*(?:->[A-Za-z_]\w*)*)\s*\((.*)\)$/s);
  if (call) {
    const callee = _normaliseCallee(call[1]);
    const bare = callee.split(/[.:]/).pop();
    if (!_NON_FN_KEYWORDS.has(bare)) {
      return { kind: 'call', line, callee, args: _splitTopLevelCommas(call[2]).map(_lowerExpr) };
    }
  }
  return { kind: 'unknown', line, text: s.slice(0, 200) };
}

// ── CFG construction ────────────────────────────────────────────────────────

function _buildCfg(bodyText, startLine) {
  const nodes = {
    entry: { kind: 'entry', line: startLine, succ: [], pred: [] },
    exit: { kind: 'exit', line: startLine, succ: [], pred: [] },
  };
  let counter = 0;
  let prev = 'entry';
  const link = (id) => {
    nodes[prev].succ.push(id);
    nodes[id].pred.push(prev);
    prev = id;
  };

  // Emit statements linearly. Control-flow headers become `if` nodes and their
  // blocks are recursed into, so bodies are never dropped — the same
  // straight-line treatment parser-go.js and parser-cs.js use.
  const emit = (text, lineBase, depth) => {
    if (depth > 12) return;
    for (const stmt of _splitStatements(text)) {
      const line = lineBase;
      const head = stmt.match(/^\s*(if|while|for|switch|else\s+if|else|do|try|catch)\b\s*(?:\((.*?)\))?\s*([\s\S]*)$/);
      if (head) {
        const kw = head[1].trim();
        const cond = head[2];
        const rest = head[3] || '';
        if (cond !== undefined && cond !== null && /^(?:if|while|for|switch|else if)$/.test(kw)) {
          const id = `n${counter++}`;
          // `for (init; test; step)` — surface the test as the condition.
          const condText = kw === 'for' ? (_splitTopLevel(cond, ';')[1] || cond) : cond;
          nodes[id] = { kind: 'if', line, cond: _lowerExpr(condText), succ: [], pred: [] };
          link(id);
          // `for` init is an assignment worth capturing.
          if (kw === 'for') {
            const init = _splitTopLevel(cond, ';')[0];
            const initNode = init && _lowerStmt(init, line);
            if (initNode && initNode.kind === 'assign') {
              const iid = `n${counter++}`;
              nodes[iid] = { ...initNode, succ: [], pred: [] };
              link(iid);
            }
          }
        }
        const block = rest.match(/\{([\s\S]*)\}\s*$/);
        if (block) emit(block[1], line, depth + 1);
        else if (rest.trim()) emit(rest, line, depth + 1);
        continue;
      }
      const bare = stmt.match(/^\{([\s\S]*)\}$/);
      if (bare) { emit(bare[1], line, depth + 1); continue; }
      const node = _lowerStmt(stmt, line);
      if (!node) continue;
      const id = `n${counter++}`;
      nodes[id] = { ...node, succ: [], pred: [] };
      link(id);
    }
  };

  if (bodyText) {
    // Attribute each statement to the function's start line plus the newline
    // count preceding it. Cheap and good enough for finding attribution, the
    // same approximation parser-cs.js makes.
    const lines = bodyText.split('\n');
    let offset = 0;
    for (const chunk of lines) {
      if (chunk.trim()) emit(chunk, startLine + offset + 1, 0);
      offset++;
    }
  }

  nodes[prev].succ.push('exit');
  nodes.exit.pred.push(prev);
  return { entry: 'entry', exit: 'exit', nodes };
}
```

Also extend the `_internals` export at the bottom of the file to include the new helpers:

```javascript
export const _internals = {
  _blank, _splitTopLevelCommas, _parseParams, _extractBody,
  _lineAt, _qid, _findFunctions, _findClasses, _nameBefore,
  _lowerExpr, _lowerStmt, _splitStatements, _buildCfg,
};
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/parser-cpp.test.js 2>&1 | tail -8
```

Expected: PASS, 22 tests.

**If the line-attribution approach in `_buildCfg` causes statements spanning multiple lines to be split incorrectly**, prefer correctness of the CFG over precision of the line number: a statement attributed to the wrong line is a cosmetic defect, a dropped statement is a missed vulnerability. Say so in your report if you make that trade.

- [ ] **Step 5: Run the full dataflow scope for regressions**

```bash
cd /Users/ross/code/agentic-security/scanner && npm run test:dataflow 2>&1 | tail -8
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/parser-cpp.js scanner/test/parser-cpp.test.js
git commit -m "feat(ir): lower C/C++ statements and expressions into a CFG

Adds statement splitting, expression lowering, and CFG construction to the
C/C++ frontend. Control-flow headers become if nodes and their blocks are
recursed into so bodies are never dropped.

Callees are emitted as dotted strings (a->b normalises to a.b, :: preserved),
matching parser-go.js, because the taint catalog matches string callees by
their last segment. String concatenation lowers to a template so taint flows
through \"SELECT \" + user."
```

---

## Task 3: Dispatch C/C++ in the IR builder

**Files:**
- Modify: `scanner/src/ir/index.js`
- Modify: `scanner/src/ir/CLAUDE.md` (parser table)
- Test: `scanner/test/cpp-integration.test.js` (create)
- Modify: `scanner/package.json` (add the new test to `test:dataflow`)

**Interfaces:**
- Consumes: `parseCppFile` from Task 1.
- Produces: C/C++ files present in `buildProjectIR(...).perFile` and `buildProjectIRAsync(...).perFile`; `parseCppFile` re-exported from `scanner/src/ir/index.js`.

- [ ] **Step 1: Write the failing test**

Create `scanner/test/cpp-integration.test.js`:

```javascript
// C/C++ integration: dispatch, cross-TU call resolution, class hierarchy, taint.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR, buildProjectIRAsync } from '../src/ir/index.js';

test('buildProjectIR: dispatches every C/C++ extension', () => {
  const files = {
    'a.cpp': 'void f() { int x = 1; }\n',
    'b.cc': 'void g() { int x = 1; }\n',
    'c.cxx': 'void h() { int x = 1; }\n',
    'd.c': 'void i() { int x = 1; }\n',
    'e.hpp': 'class E { public: int m(); };\n',
    'f.h': 'class F { public: int m(); };\n',
    'g.hh': 'class G { public: int m(); };\n',
    'h.hxx': 'class H { public: int m(); };\n',
  };
  const { perFile } = buildProjectIR(files);
  for (const name of Object.keys(files)) {
    assert.ok(perFile[name], `${name} must produce an IR record`);
    assert.ok(perFile[name].functions.length >= 1, `${name} must yield a function`);
  }
});

test('buildProjectIRAsync: dispatches C/C++ alongside Java', async () => {
  const { perFile } = await buildProjectIRAsync({
    'a.cpp': 'void f() { int x = 1; }\n',
    'b.js': 'function g(){ var y = 1; }\n',
  });
  assert.ok(perFile['a.cpp'], 'C++ must be dispatched in the async path too');
  assert.ok(perFile['b.js'], 'JS must still be dispatched');
});

test('buildProjectIR: C++ does not disturb other languages', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'void f() { int x = 1; }\n',
    'b.py': 'def g():\n    y = 1\n',
    'c.go': 'package main\nfunc h() {\n\tx := 1\n}\n',
  });
  assert.ok(perFile['a.cpp']);
  assert.ok(perFile['b.py']);
  assert.ok(perFile['c.go']);
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -12
```

Expected: FAIL — `a.cpp must produce an IR record`, because `ir/index.js` has no C/C++ branch.

- [ ] **Step 3: Add the import**

In `scanner/src/ir/index.js`, find:

```javascript
import { parseRubyFile } from './parser-rb.js';
```

Add immediately after it:

```javascript
import { parseCppFile } from './parser-cpp.js';
```

- [ ] **Step 4: Add the dispatch branch to BOTH builders**

There are two functions with near-identical dispatch chains: `buildProjectIR` (sync) and `buildProjectIRAsync`. In **each**, find this branch:

```javascript
    } else if (/\.rb$/i.test(file)) {
      const ir = parseRubyFile(file, code);
      if (ir) perFile[file] = ir;
    }
```

and extend it to:

```javascript
    } else if (/\.rb$/i.test(file)) {
      const ir = parseRubyFile(file, code);
      if (ir) perFile[file] = ir;
    } else if (/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(file)) {
      const ir = parseCppFile(file, code);
      if (ir) perFile[file] = ir;
    }
```

Both occurrences must be changed. Missing the async one means Java-inclusive scans silently lose C++.

- [ ] **Step 5: Re-export the parser**

At the bottom of `scanner/src/ir/index.js`, add `parseCppFile` to the existing `export { … }` list.

- [ ] **Step 6: Confirm all three edits landed**

```bash
cd /Users/ross/code/agentic-security/scanner
grep -c "parser-cpp.js" src/ir/index.js
grep -c "parseCppFile(file, code)" src/ir/index.js
grep -c "parseCppFile" src/ir/index.js
```

Expected: `1`, then `2` (one dispatch per builder), then `4` (import, two dispatches, re-export). If the second count is `1`, you edited only one builder — fix it.

- [ ] **Step 7: Run the tests**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -8
```

Expected: PASS, 3 tests.

- [ ] **Step 8: Wire the new test file into `test:dataflow` and confirm**

Append ` test/cpp-integration.test.js` to the `"test:dataflow"` value in `scanner/package.json`, then:

```bash
cd /Users/ross/code/agentic-security/scanner && grep -c 'test/cpp-integration.test.js' package.json && npm run test:dataflow 2>&1 | tail -8
```

Expected: `1`, then green.

- [ ] **Step 9: Update the parser table in the IR guide**

In `scanner/src/ir/CLAUDE.md`, the "## Parsers" table lists one row per language. Add a row for C/C++ recording that `parser-cpp.js` is hand-rolled, and amend the long-tail tree-sitter row so it no longer claims `cpp`/`c` among the languages with no first-class parser.

- [ ] **Step 10: Full gate and rebuild**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test 2>&1 | tail -12 && npm run build 2>&1 | tail -3
```

Expected: green, and the bundle plus `.sha256` regenerated. `ir/index.js` feeds the whole engine, so the full suite is required here.

- [ ] **Step 11: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/index.js scanner/src/ir/CLAUDE.md scanner/test/cpp-integration.test.js scanner/package.json scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "feat(ir): dispatch C/C++ files to the new frontend

Wires parser-cpp.js into both buildProjectIR and buildProjectIRAsync. C and
C++ source now reaches the call graph, class-hierarchy analysis, SSA, and the
taint engine for the first time — previously those extensions had no dispatch
branch at all, so the files were read and then dropped."
```

---

## Task 4: Cross-translation-unit call resolution

**Files:**
- Modify: `scanner/src/ir/callgraph.js`
- Modify: `scanner/test/cpp-integration.test.js` (append tests)

**Interfaces:**
- Consumes: `fn.qname` and `fn.isDeclaration` from Task 1; dispatch from Task 3.
- Produces: `buildCallGraph` resolves a call whose callee matches a `qname` defined in another file. Definitions win over declarations. The returned shape `{ functions, edges, callersOf, resolve }` is unchanged.

**Why this matters:** C++ splits declaration from definition. `Foo::bar()` is declared in `foo.h` and defined in `foo.cpp`, and callers include only the header. Without a project-wide qualified-name index, essentially every cross-TU call resolves to nothing and the call graph is worthless — which is precisely the metric that separates a real IR from a syntactic one.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/cpp-integration.test.js`:

```javascript
test('call graph: resolves a cross-translation-unit method call', () => {
  const files = {
    'buf.h': 'class Buffer {\npublic:\n  void fill(char* src);\n};\n',
    'buf.cpp': 'void Buffer::fill(char* src) {\n  int n = 1;\n}\n',
    'main.cpp': 'void run(Buffer* b, char* p) {\n  b->fill(p);\n}\n',
  };
  const { callGraph } = buildProjectIR(files);
  const resolved = callGraph.edges.filter(e => e.callee);
  assert.ok(resolved.length >= 1, 'at least one edge must resolve across files');
  const target = callGraph.functions.get(resolved[0].callee);
  assert.ok(target, 'the resolved callee must be a known function');
});

test('call graph: a definition wins over a header declaration', () => {
  const files = {
    'buf.h': 'class Buffer {\npublic:\n  void fill(char* src);\n};\n',
    'buf.cpp': 'void Buffer::fill(char* src) {\n  int n = 1;\n}\n',
    'main.cpp': 'void run(Buffer* b, char* p) {\n  b->fill(p);\n}\n',
  };
  const { perFile, callGraph } = buildProjectIR(files);
  const defQid = perFile['buf.cpp'].functions[0].qid;
  const declQid = perFile['buf.h'].functions[0].qid;
  const edge = callGraph.edges.find(e => e.callee);
  assert.equal(edge.callee, defQid, 'must resolve to the definition');
  assert.notEqual(edge.callee, declQid, 'must not resolve to the declaration');
});

test('call graph: a free function resolves across files by qualified name', () => {
  const files = {
    'util.cpp': 'namespace util {\nvoid helper(char* s) {\n  int n = 1;\n}\n}\n',
    'main.cpp': 'void go(char* p) {\n  util::helper(p);\n}\n',
  };
  const { callGraph } = buildProjectIR(files);
  assert.ok(callGraph.edges.some(e => e.callee), 'namespaced free function must resolve');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -15
```

Expected: the three new tests FAIL — no edge resolves, because resolution is file-local.

- [ ] **Step 3: Build the qualified-name index in `buildCallGraph`**

In `scanner/src/ir/callgraph.js`, inside `buildCallGraph`, find where the per-file maps are populated (alongside `functions` and `byNameInFile`). Add a project-wide index built in the same pass:

```javascript
  // Project-wide qualified-name index. C++ splits declaration from definition
  // (`Foo::bar` declared in a header, defined in a .cpp), so a file-local
  // lookup resolves almost nothing. Definitions take precedence over
  // declarations, which are indexed only as a fallback.
  const byQname = new Map();
  for (const ir of Object.values(perFileIR || {})) {
    for (const fn of (ir && ir.functions) || []) {
      if (!fn.qname) continue;
      const existing = byQname.get(fn.qname);
      if (!existing || (existing.isDeclaration && !fn.isDeclaration)) {
        byQname.set(fn.qname, fn);
      }
      // Also index the bare method name so `b->fill(p)` — which carries no
      // class qualification at the call site — can still find `Buffer::fill`,
      // but only when that bare name is unambiguous project-wide.
      const bare = fn.qname.includes('::') ? fn.qname.split('::').pop() : null;
      if (bare) {
        const key = `~bare~${bare}`;
        if (byQname.has(key)) {
          if (byQname.get(key) !== null && byQname.get(key).qname !== fn.qname) {
            byQname.set(key, null); // ambiguous — refuse to guess
          }
        } else {
          byQname.set(key, fn);
        }
      }
    }
  }
```

Then, inside the `resolve` function, before its final `return null;`, add:

```javascript
    // Qualified-name resolution (C++ header/source pairing). Try the name as
    // written, then its dotted form re-expressed with `::`, then the
    // unambiguous bare name.
    if (name) {
      const direct = byQname.get(name);
      if (direct && !direct.isDeclaration) return direct.qid;
      const colonised = name.replace(/\./g, '::');
      const viaColon = byQname.get(colonised);
      if (viaColon && !viaColon.isDeclaration) return viaColon.qid;
      const bare = name.includes('.') || name.includes('::')
        ? name.split(/[.:]+/).pop()
        : name;
      const viaBare = byQname.get(`~bare~${bare}`);
      if (viaBare && !viaBare.isDeclaration) return viaBare.qid;
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -8
```

Expected: PASS, 6 tests.

- [ ] **Step 5: Verify no regression in other languages' call graphs**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/callgraph-resolve.test.js 2>&1 | tail -6 && npm run test:dataflow 2>&1 | tail -6
```

Expected: both green. The new resolution runs only after the existing rules fail and only for functions carrying a `qname`, which no other parser emits today — but confirm rather than assume.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/callgraph.js scanner/test/cpp-integration.test.js
git commit -m "feat(ir): resolve cross-translation-unit calls via qualified names

C++ splits declaration from definition, so file-local name resolution leaves
essentially every cross-TU call unresolved. Adds a project-wide qualified-name
index consulted after the existing rules, with definitions taking precedence
over header declarations and ambiguous bare names refused rather than guessed."
```

---

## Task 5: Class hierarchy — populate `extends` from IR

**Files:**
- Modify: `scanner/src/ir/class-hierarchy.js`
- Modify: `scanner/test/cpp-integration.test.js` (append tests)
- Modify: the Proof Corpus PRD (correct §6.8)

**Interfaces:**
- Consumes: `ir.classes = [{name, bases, line}]` from Task 1.
- Produces: `buildClassHierarchy(perFileIR).classes.get(name).extends` populated from `ir.classes[].bases`. Shape otherwise unchanged.

**A correction to the PRD:** §6.8 claims `class-hierarchy.js` "walks Babel ASTs and is JS/TS-only." That is wrong — `buildClassHierarchy` (`class-hierarchy.js:34-87`) reads `perFileIR` only, recovering class names from the qid tail's `Class.method` shape, which is language-neutral. What it genuinely lacks is any population of `extends`: line 57 sets `extends: null` and nothing ever writes it, for *any* language. So no C++-specific extractor is needed; what is needed is a language-neutral inheritance input. Fix the PRD text as part of this task.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/cpp-integration.test.js`:

```javascript
import { buildClassHierarchy, resolveMethod } from '../src/ir/class-hierarchy.js';

test('class hierarchy: recovers C++ classes and their base classes', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'class Base {\npublic:\n  int run() { return 1; }\n};\nclass Derived : public Base {\npublic:\n  int extra() { return 2; }\n};\n',
  });
  const cha = buildClassHierarchy(perFile);
  assert.ok(cha.classes.get('Base'), 'Base must be recovered');
  assert.ok(cha.classes.get('Derived'), 'Derived must be recovered');
  assert.equal(cha.classes.get('Derived').extends, 'Base');
});

test('class hierarchy: the recovered method name is bare, not suffixed', () => {
  // Regression guard. class-hierarchy.js recovers methodName as
  // tail.slice(dotIdx + 1), which for a qid tail of `Class.method@line#sha`
  // yields `method@line#sha`. Class recovery was always correct; method
  // recovery was not, which silently broke every resolveMethod() lookup.
  const { perFile } = buildProjectIR({
    'a.cpp': 'class Base {\npublic:\n  int run() { return 1; }\n};\n',
  });
  const cha = buildClassHierarchy(perFile);
  const methods = [...cha.classes.get('Base').methods];
  assert.deepEqual(methods, ['run'],
    'method names must be bare — no @line#sha suffix');
});

test('class hierarchy: an inherited method resolves through the extends chain', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'class Base {\npublic:\n  int run() { return 1; }\n};\nclass Derived : public Base {\npublic:\n  int extra() { return 2; }\n};\n',
  });
  const cha = buildClassHierarchy(perFile);
  const hit = resolveMethod(cha, 'Derived', 'run');
  assert.ok(hit, 'run must resolve on Derived via Base');
  assert.equal(hit.className, 'Base');
});

test('class hierarchy: multiple inheritance keeps the first base and does not throw', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'class A { public: int m() { return 1; } };\nclass B { public: int n() { return 2; } };\nclass C : public A, public B { public: int o() { return 3; } };\n',
  });
  const cha = buildClassHierarchy(perFile);
  assert.ok(['A', 'B'].includes(cha.classes.get('C').extends));
});

test('class hierarchy: languages without ir.classes are unaffected', () => {
  const { perFile } = buildProjectIR({ 'b.js': 'class Foo { bar(){ return 1; } }\n' });
  const cha = buildClassHierarchy(perFile);
  assert.ok(cha.classes instanceof Map, 'still returns the documented shape');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -15
```

Expected: the `extends` assertions FAIL (currently always `null`).

- [ ] **Step 3a: Fix the polluted method name**

This is a pre-existing defect surfaced by Task 1's review, and it must be fixed here or the inheritance test above cannot pass. `class-hierarchy.js` recovers the method name from the qid tail as:

```javascript
      const methodName = tail.slice(dotIdx + 1);
```

For a qid tail of `Class.method@line#sha` that yields `method@line#sha`, so `cls.methods` fills with suffixed garbage and `resolveMethod`'s `cls.methods.has(methodName)` can never match a bare name. Class-name recovery was always correct; method-name recovery never was.

No existing parser emits a dot in its qid tail today, so this code path is currently dead for every other language and the fix cannot regress them — but confirm that claim yourself with a grep before relying on it. Change the line to strip the suffix:

```javascript
      const methodName = tail.slice(dotIdx + 1).replace(/@\d+#[0-9a-f]+$/, '');
```

- [ ] **Step 3b: Consume `ir.classes` in `buildClassHierarchy`**

In `scanner/src/ir/class-hierarchy.js`, inside the `for (const [file, ir] of Object.entries(perFileIR))` loop, add this block **before** the existing qid-based method loop:

```javascript
    // Language-neutral inheritance input. A parser may attach a `classes`
    // array to its IR record; parser-cpp.js does. Nothing else populates
    // `extends`, for any language, so this is purely additive.
    if (Array.isArray(ir.classes)) {
      for (const c of ir.classes) {
        if (!c || !c.name) continue;
        let cls = classes.get(c.name);
        if (!cls) {
          cls = { name: c.name, file, line: c.line || 0, methods: new Set(), extends: null };
          classes.set(c.name, cls);
        }
        // v1 keeps a single base: the CHA walk in resolveMethod follows one
        // chain. Multiple inheritance is flattened to the first base, which is
        // a deliberate over-simplification recorded in PRD §6.8.
        if (!cls.extends && Array.isArray(c.bases) && c.bases.length) {
          cls.extends = c.bases[0];
        }
      }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -8
```

Expected: PASS, 10 tests.

- [ ] **Step 5: Correct the PRD**

In the Proof Corpus PRD §6.8, replace the claim that `class-hierarchy.js` "today walks Babel ASTs and is JS/TS-only" with an accurate statement: `buildClassHierarchy` is already language-neutral, reading `perFileIR` and recovering classes from the qid tail's `Class.method` shape; what it lacked was any population of `extends` for any language, which this work adds via an optional `ir.classes` array. Keep the note that multiple inheritance is flattened to the first base.

- [ ] **Step 6: Run the dataflow scope**

```bash
cd /Users/ross/code/agentic-security/scanner && npm run test:dataflow 2>&1 | tail -6
```

Expected: green.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/ir/class-hierarchy.js scanner/test/cpp-integration.test.js the Proof Corpus PRD
git commit -m "feat(ir): populate class-hierarchy extends from an optional ir.classes array

buildClassHierarchy was already language-neutral — it reads perFileIR and
recovers classes from the qid tail — but nothing ever populated extends, for
any language, so resolveMethod's inheritance walk was dead code. Parsers may
now attach a classes array with base names; parser-cpp.js does.

Corrects PRD 6.8, which described this module as Babel-only."
```

---

## Task 6: C/C++ taint sources, sinks, and an end-to-end flow

**Files:**
- Modify: `scanner/src/dataflow/catalog.js`
- Modify: `scanner/test/cpp-integration.test.js` (append tests)

**Interfaces:**
- Consumes: string callees from Task 2; cross-TU resolution from Task 4.
- Produces: catalog entries with `language: 'cpp'`. Entry shape must match the existing documented shape exactly: `{ kind, id, language, framework, match: { type: 'call', callee }, argIndex, vuln: { name, severity, cwe, remediation }, label, provenance }`.

**Note on the existing C/C++ detectors:** `sast/cpp.js` already flags `strcpy`, `system`, and friends syntactically, and stays as-is — it catches bugs with no reachable source. Taint-confirmed flows raise confidence on the same finding rather than duplicating it; deduplication happens by `stableId` in the posture pipeline. Do not remove or gate the syntactic rules.

**Critical fact about how the catalog matches — verified, and it changes how these tests must be written.** `CALLEE_INDEX` (`catalog.js:725-732`) is keyed by **callee name alone**. There is no language filtering at match time: `filterByProvenance` filters on `source === 'official'`, not on `language`. The `language` field is metadata for reporting, not a matching constraint.

The consequence: **four of the callees below already match today via other languages' entries.** Verified by direct query against the current catalog:

| Callee | Already matched by | Effect |
|---|---|---|
| `getenv` | `py-os-getenv`, `java-system-getenv`, `kt-env-var` | already a recognised source for any language |
| `system` | `php-system`, `rb-system`, `py-os-system`, `py-os-system-v2` | already a recognised sink |
| `popen` | `py-os-popen` | already a recognised sink |
| `realpath` | `php-core-realpath` | already a recognised sanitizer |

Two things follow, and both matter:

1. **A test that merely asserts "some hit exists" for those four is vacuous** — it passes without any new code. Every test below therefore asserts on the **C-specific entry** (`id` beginning `cpp-`), not on the mere existence of a match.
2. **`matchSource` returns only the first matching source.** For `getenv` that will remain the Python entry regardless of what you add, because it appears earlier in `CATALOG`. That is functionally fine — taint still flows — but it means the C entry for a colliding name must be verified by inspecting `CATALOG` directly rather than through `matchSource`. `matchSinkOrSanitizer` returns *all* hits as an array, so sinks can be checked through it.

Adding the C entries for colliding names is still correct: they carry the right label, provenance, CWE, remediation wording, and `argIndex` for C, which the Python and PHP entries do not.

- [ ] **Step 1: Write the failing tests**

Append to `scanner/test/cpp-integration.test.js`:

```javascript
import { matchSource, matchSinkOrSanitizer, CATALOG } from '../src/dataflow/catalog.js';

// Helper: find the C-specific entry for a callee. Asserting on `cpp-` ids is
// what keeps these tests non-vacuous — `getenv`, `system`, `popen` and
// `realpath` already match via other languages' entries, so a bare
// "something matched" assertion would pass with no new code at all.
function cppEntry(callee, kind) {
  return CATALOG.find(e =>
    e.language === 'cpp' &&
    e.kind === kind &&
    e.match && e.match.type === 'call' && e.match.callee === callee);
}

test('catalog: C/C++ sources exist as C-specific entries', () => {
  for (const callee of ['getenv', 'recv', 'recvfrom', 'read', 'fread', 'fgets', 'gets', 'scanf']) {
    const e = cppEntry(callee, 'source');
    assert.ok(e, `a cpp source entry for ${callee} must exist`);
    assert.ok(e.id.startsWith('cpp-'), `${callee} entry id must be namespaced cpp-`);
    assert.ok(e.provenance, `${callee} must declare a provenance`);
  }
});

test('catalog: non-colliding C sources are returned by matchSource', () => {
  // These four have no pre-existing entry under another language, so the C
  // entry is the one matchSource returns — a real end-to-end check.
  for (const callee of ['recv', 'recvfrom', 'fread', 'fgets']) {
    const hit = matchSource({ kind: 'call', callee, args: [] });
    assert.ok(hit, `${callee} must be a recognised source`);
    assert.equal(hit.kind, 'source');
    assert.equal(hit.language, 'cpp', `${callee} must resolve to the C entry`);
  }
});

test('catalog: C/C++ sinks exist as C-specific entries with the right CWE', () => {
  const cases = [
    ['system', 'CWE-78'], ['popen', 'CWE-78'], ['execl', 'CWE-78'],
    ['strcpy', 'CWE-120'], ['strcat', 'CWE-120'], ['sprintf', 'CWE-120'],
    ['memcpy', 'CWE-787'], ['fopen', 'CWE-22'], ['dlopen', 'CWE-114'],
  ];
  for (const [callee, cwe] of cases) {
    const e = cppEntry(callee, 'sink');
    assert.ok(e, `a cpp sink entry for ${callee} must exist`);
    assert.equal(e.vuln.cwe, cwe, `${callee} must carry ${cwe}`);
  }
});

test('catalog: the C sink is reachable through matchSinkOrSanitizer', () => {
  // matchSinkOrSanitizer returns ALL hits, so the C entry must be among them
  // even for a callee another language already claims.
  for (const callee of ['system', 'strcpy', 'memcpy']) {
    const hits = matchSinkOrSanitizer(callee);
    assert.ok(hits, `${callee} must match`);
    assert.ok(hits.some(h => h.language === 'cpp' && h.kind === 'sink'),
      `the cpp sink for ${callee} must be among the returned hits`);
  }
});

test('catalog: every C/C++ sink carries a complete vuln descriptor', () => {
  const cppSinks = CATALOG.filter(e => e.language === 'cpp' && e.kind === 'sink');
  assert.ok(cppSinks.length >= 9, 'expected at least nine C/C++ sinks');
  for (const s of cppSinks) {
    for (const key of ['name', 'severity', 'cwe', 'remediation']) {
      assert.ok(s.vuln && s.vuln[key], `${s.id}: vuln.${key} is required by the findings schema`);
    }
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(s.vuln.severity),
      `${s.id}: severity must be one of the five documented values`);
    assert.ok('argIndex' in s, `${s.id}: argIndex is required so the engine knows which argument matters`);
  }
});

test('catalog: C/C++ sanitizers exist and declare an effect', () => {
  for (const callee of ['realpath', 'snprintf', 'strncpy']) {
    const e = cppEntry(callee, 'sanitizer');
    assert.ok(e, `a cpp sanitizer entry for ${callee} must exist`);
    assert.ok(e.effect, `${callee} must declare an effect`);
  }
});

test('end-to-end: taint flows from a C++ source to a sink across the call graph', () => {
  const files = {
    'util.h': 'class Util {\npublic:\n  void execute(char* cmd);\n};\n',
    'util.cpp': 'void Util::execute(char* cmd) {\n  system(cmd);\n}\n',
    'main.cpp': 'void run(Util* u) {\n  char* p = getenv("CMD");\n  u->execute(p);\n}\n',
  };
  const { perFile, callGraph } = buildProjectIR(files);
  // The source is recognised at the assignment RHS.
  const runFn = perFile['main.cpp'].functions.find(f => f.name === 'run');
  const asg = Object.values(runFn.cfg.nodes).find(n => n.kind === 'assign' && n.target === 'p');
  assert.ok(matchSource(asg.source), 'getenv must be recognised as a source');
  // The sink is recognised inside the callee.
  const execFn = perFile['util.cpp'].functions[0];
  const sinkCall = Object.values(execFn.cfg.nodes).find(n => n.kind === 'call' && n.callee === 'system');
  assert.ok(sinkCall, 'system(cmd) must be lowered as a call node');
  assert.ok(matchSinkOrSanitizer(sinkCall.callee), 'system must be a catalog sink');
  // The two are connected by a resolved call-graph edge.
  const edge = callGraph.edges.find(e => e.callee === execFn.qid);
  assert.ok(edge, 'the call from run() to Util::execute must resolve across files');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -15
```

Expected: the four new tests FAIL — the catalog has no `cpp` entries.

- [ ] **Step 3: Add the catalog entries**

In `scanner/src/dataflow/catalog.js`, inside the `CATALOG` array, add a clearly delimited C/C++ block:

```javascript
  // ─── SOURCES (C / C++) ─────────────────────────────────────────────────────
  { kind: 'source', id: 'cpp-getenv',  language: 'cpp', framework: null, match: { type: 'call', callee: 'getenv'  }, label: 'getenv()',  provenance: 'env' },
  { kind: 'source', id: 'cpp-recv',    language: 'cpp', framework: null, match: { type: 'call', callee: 'recv'    }, label: 'recv()',    provenance: 'network' },
  { kind: 'source', id: 'cpp-recvfrom',language: 'cpp', framework: null, match: { type: 'call', callee: 'recvfrom'}, label: 'recvfrom()',provenance: 'network' },
  { kind: 'source', id: 'cpp-read',    language: 'cpp', framework: null, match: { type: 'call', callee: 'read'    }, label: 'read()',    provenance: 'file' },
  { kind: 'source', id: 'cpp-fread',   language: 'cpp', framework: null, match: { type: 'call', callee: 'fread'   }, label: 'fread()',   provenance: 'file' },
  { kind: 'source', id: 'cpp-fgets',   language: 'cpp', framework: null, match: { type: 'call', callee: 'fgets'   }, label: 'fgets()',   provenance: 'file' },
  { kind: 'source', id: 'cpp-gets',    language: 'cpp', framework: null, match: { type: 'call', callee: 'gets'    }, label: 'gets()',    provenance: 'stdin' },
  { kind: 'source', id: 'cpp-scanf',   language: 'cpp', framework: null, match: { type: 'call', callee: 'scanf'   }, label: 'scanf()',   provenance: 'stdin' },

  // ─── SINKS (C / C++) ───────────────────────────────────────────────────────
  { kind: 'sink', id: 'cpp-system', language: 'cpp', framework: null, match: { type: 'call', callee: 'system' }, argIndex: 0,
    vuln: { name: 'Command injection via system()', severity: 'critical', cwe: 'CWE-78', remediation: 'Use execve() with an argument vector instead of passing a shell string; never interpolate untrusted input into a command.' } },
  { kind: 'sink', id: 'cpp-popen', language: 'cpp', framework: null, match: { type: 'call', callee: 'popen' }, argIndex: 0,
    vuln: { name: 'Command injection via popen()', severity: 'critical', cwe: 'CWE-78', remediation: 'Use a pipe with execve() and an argument vector rather than a shell command string.' } },
  { kind: 'sink', id: 'cpp-execl', language: 'cpp', framework: null, match: { type: 'call', callee: 'execl' }, argIndex: 0,
    vuln: { name: 'Command injection via execl()', severity: 'critical', cwe: 'CWE-78', remediation: 'Validate the executable path against an allow-list; never build it from untrusted input.' } },
  { kind: 'sink', id: 'cpp-strcpy', language: 'cpp', framework: null, match: { type: 'call', callee: 'strcpy' }, argIndex: 1,
    vuln: { name: 'Buffer overflow via strcpy()', severity: 'high', cwe: 'CWE-120', remediation: 'Use strncpy() or snprintf() with an explicit destination size.' } },
  { kind: 'sink', id: 'cpp-strcat', language: 'cpp', framework: null, match: { type: 'call', callee: 'strcat' }, argIndex: 1,
    vuln: { name: 'Buffer overflow via strcat()', severity: 'high', cwe: 'CWE-120', remediation: 'Use strncat() or snprintf() with an explicit destination size.' } },
  { kind: 'sink', id: 'cpp-sprintf', language: 'cpp', framework: null, match: { type: 'call', callee: 'sprintf' }, argIndex: 'all',
    vuln: { name: 'Buffer overflow via sprintf()', severity: 'high', cwe: 'CWE-120', remediation: 'Use snprintf() with an explicit destination size.' } },
  { kind: 'sink', id: 'cpp-memcpy', language: 'cpp', framework: null, match: { type: 'call', callee: 'memcpy' }, argIndex: 2,
    vuln: { name: 'Buffer overflow via unchecked memcpy() length', severity: 'high', cwe: 'CWE-787', remediation: 'Bound the copy length by the destination size before copying.' } },
  { kind: 'sink', id: 'cpp-fopen', language: 'cpp', framework: null, match: { type: 'call', callee: 'fopen' }, argIndex: 0,
    vuln: { name: 'Path traversal via fopen()', severity: 'high', cwe: 'CWE-22', remediation: 'Canonicalise with realpath() and confirm the result stays within an allowed base directory.' } },
  { kind: 'sink', id: 'cpp-dlopen', language: 'cpp', framework: null, match: { type: 'call', callee: 'dlopen' }, argIndex: 0,
    vuln: { name: 'Untrusted library load via dlopen()', severity: 'critical', cwe: 'CWE-114', remediation: 'Load only from a fixed, trusted path; never build the library path from untrusted input.' } },

  // ─── SANITIZERS (C / C++) ──────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'cpp-realpath', language: 'cpp', framework: null, match: { type: 'call', callee: 'realpath' }, effect: 'strip' },
  { kind: 'sanitizer', id: 'cpp-snprintf', language: 'cpp', framework: null, match: { type: 'call', callee: 'snprintf' }, effect: 'strip' },
  { kind: 'sanitizer', id: 'cpp-strncpy',  language: 'cpp', framework: null, match: { type: 'call', callee: 'strncpy'  }, effect: 'strip' },
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/ross/code/agentic-security/scanner && node --test test/cpp-integration.test.js 2>&1 | tail -8
```

Expected: PASS, 16 tests.

**Expect the `matchSource` test to be the fragile one.** It asserts `hit.language === 'cpp'` for `recv`, `recvfrom`, `fread` and `fgets` — callees verified to have no pre-existing entry today. If a future catalog addition claims one of those names first, that test fails legitimately: `matchSource` returns only the first hit. The correct response is to move that callee into the `CATALOG`-inspection test alongside the colliding ones, not to drop the language assertion.

- [ ] **Step 5: Full gate and rebuild**

```bash
cd /Users/ross/code/agentic-security/scanner && npm test 2>&1 | tail -12 && npm run build 2>&1 | tail -3
```

Expected: green. The catalog is consumed by every language's taint analysis, so the full suite matters here.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/dataflow/catalog.js scanner/test/cpp-integration.test.js scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "feat(dataflow): add C/C++ taint sources, sinks and sanitizers

Sources cover environment, network, file and stdin input. Sinks cover command
injection, buffer overflow, path traversal and untrusted library load, each
carrying a complete vuln descriptor per the findings schema. Sanitizers cover
bounded copies and path canonicalisation.

The syntactic rules in sast/cpp.js stay as they are — they catch bugs with no
reachable source. Taint-confirmed flows raise confidence on the same finding
rather than duplicating it."
```

---

## Task 7: C/C++ corpus entries

**Files:**
- Create: ten directories under `bench/cve-replay/capability/`, each with `manifest.json`, `pre/`, `post/`
- Modify: `bench/cve-replay/corpus-baseline.json` (regenerated, not hand-edited)

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces: ten corpus entries, each scoring `pre:TP post:TN`.

**The corpus contract** (`bench/cve-replay/CONTRIBUTING.md`): each entry is a directory with `manifest.json`, a `pre/` tree containing the vulnerable shape, and a `post/` tree containing the fixed shape. Keep each to one to three files — the runner reads each as a tiny project. Entries whose original code cannot be reproduced are named with a `-shape` suffix.

`manifest.json` schema:

```json
{
  "cve": "CVE-YYYY-NNNNN-shape",
  "cwe": "CWE-78",
  "family": "command-injection",
  "language": "cpp",
  "summary": "one-line description",
  "expected": { "file": "vuln.cpp", "vuln_match": "command|CWE-78" },
  "source": "synthetic-shape-of-disclosed-cve",
  "added_at": "2026-07-25"
}
```

- [ ] **Step 1: Write one entry end-to-end and confirm it scores before writing the rest**

Create `bench/cve-replay/capability/cpp-cmdi-getenv-system-shape/`:

`manifest.json`:
```json
{
  "cve": "cpp-cmdi-getenv-system-shape",
  "cwe": "CWE-78",
  "family": "command-injection",
  "language": "cpp",
  "summary": "Environment-derived string reaches system() unvalidated",
  "expected": { "file": "vuln.cpp", "vuln_match": "command|CWE-78" },
  "source": "synthetic-shape-of-disclosed-cve",
  "added_at": "2026-07-25"
}
```

`pre/vuln.cpp`:
```cpp
#include <cstdlib>

void run_backup() {
  char* target = getenv("BACKUP_TARGET");
  char cmd[512];
  sprintf(cmd, "tar czf backup.tar.gz %s", target);
  system(cmd);
}
```

`post/vuln.cpp`:
```cpp
#include <cstdlib>
#include <unistd.h>

void run_backup() {
  char* target = getenv("BACKUP_TARGET");
  if (!target) return;
  char* const argv[] = {(char*)"tar", (char*)"czf", (char*)"backup.tar.gz", target, NULL};
  execv("/usr/bin/tar", argv);
}
```

- [ ] **Step 2: Score that single entry and confirm `pre:TP post:TN`**

```bash
cd /Users/ross/code/agentic-security
find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} + 2>/dev/null
cd scanner && npm run bench:cve-replay 2>&1 | grep -i 'cpp-cmdi-getenv-system-shape' 
```

Expected: the entry reports `pre:TP post:TN`. **If it does not, stop and fix the cause before writing nine more entries** — an undetectable fixture is exactly the mistake the corpus gate exists to catch, and discovering it once is far cheaper than ten times. Report which side failed and why.

- [ ] **Step 3: Write the remaining nine entries**

Same structure, one directory each. Cover these shapes, all of which the Task 6 catalog supports:

| Directory | CWE | Shape |
|---|---|---|
| `cpp-cmdi-popen-shape` | CWE-78 | network-read string reaches `popen()` |
| `cpp-bof-strcpy-shape` | CWE-120 | `recv()` buffer copied with `strcpy()` into a fixed array; fixed with `strncpy()` and an explicit size |
| `cpp-bof-strcat-shape` | CWE-120 | `getenv()` value appended with `strcat()`; fixed with `snprintf()` |
| `cpp-bof-sprintf-shape` | CWE-120 | `fgets()` input formatted with `sprintf()`; fixed with `snprintf()` |
| `cpp-oob-memcpy-shape` | CWE-787 | attacker-controlled length passed to `memcpy()`; fixed by bounding against the destination size |
| `cpp-path-fopen-shape` | CWE-22 | `getenv()` path opened with `fopen()`; fixed with `realpath()` plus a prefix check |
| `cpp-dlopen-shape` | CWE-114 | environment-derived library path passed to `dlopen()`; fixed with a fixed trusted path |
| `c-cmdi-argv-system-shape` | CWE-78 | `argv[1]` reaches `system()` in a `.c` file; fixed with `execv()` |
| `cpp-xtu-cmdi-shape` | CWE-78 | **cross-translation-unit**: source in `main.cpp`, sink in `util.cpp` behind a header declaration — this one specifically exercises Task 4's resolution |

The cross-TU entry is the most valuable of the ten: it is the only corpus entry that fails if header/source pairing regresses.

- [ ] **Step 4: Score the whole corpus**

```bash
cd /Users/ross/code/agentic-security
find bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} + 2>/dev/null
cd scanner && npm run bench:cve-replay 2>&1 | tail -30
```

Record the real per-entry verdicts. Every one of the ten must be `pre:TP post:TN`. Any that is not gets fixed or removed — it does not get added with a failing score.

- [ ] **Step 5: Confirm no pre-existing entry regressed, then regenerate the baseline**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run bench:cve-replay:check 2>&1 | tail -20; echo "CHECK_EXIT=$?"
```

The check compares against the committed baseline and fails on any drift. New entries will show as drift — that is expected. What must NOT appear is a verdict change on any pre-existing entry. Read the output and confirm that before continuing.

```bash
cd /Users/ross/code/agentic-security/scanner && npm run bench:cve-replay:update-baseline 2>&1 | tail -5
```

- [ ] **Step 6: Prove the gate works in both directions**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run bench:cve-replay:check >/dev/null 2>&1; echo "clean baseline exit=$?"
cp ../bench/cve-replay/corpus-baseline.json /tmp/baseline.bak
node -e "
const fs=require('fs');const p='../bench/cve-replay/corpus-baseline.json';
const b=JSON.parse(fs.readFileSync(p,'utf8'));
const k=Object.keys(b).find(x=>typeof b[x]==='object'&&b[x]!==null);
b[k]=Array.isArray(b[k])?[]:{...b[k],__corrupted:true};
fs.writeFileSync(p,JSON.stringify(b,null,2));
"
npm run bench:cve-replay:check >/dev/null 2>&1; echo "corrupted baseline exit=$?"
cp /tmp/baseline.bak ../bench/cve-replay/corpus-baseline.json
npm run bench:cve-replay:check >/dev/null 2>&1; echo "restored baseline exit=$?"
```

Expected: `0`, then non-zero, then `0`. A gate that only ever passes is not a gate. If the corrupted run also exits 0, the gate is not enforcing and that is a blocking finding.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/cve-replay/capability/ bench/cve-replay/corpus-baseline.json
git commit -m "test(corpus): add ten C/C++ replay entries

Covers command injection, buffer overflow, out-of-bounds write, path
traversal and untrusted library load across .c and .cpp, all scoring
pre:TP post:TN. One entry is deliberately cross-translation-unit — source in
one file, sink in another behind a header declaration — so a regression in
qualified-name call resolution fails the corpus rather than passing silently.

Baseline regenerated and the gate proven in both directions."
```

---

## Task 8: Measure on Godot — the acceptance test

**Files:**
- Modify: `bench/proof-corpus/manifest.json` (pin `godot`)
- Modify: `bench/proof-corpus/README.md` (record the before/after)
- Modify: the Proof Corpus PRD (record the measured result against §6.12)

**Interfaces:**
- Consumes: everything from Tasks 1–7, plus the `AGENTIC_SECURITY_IR_STATS` instrument from PR #42.
- Produces: the measured parse coverage and call-graph figures that PRD §6.12 criteria 2, 3, 4 and 7 are judged against.

**This task is long-running** — Godot is a multi-million-line C++ codebase. Use background execution and polling. The manifest gives `godot` a 3600-second budget and scopes it to first-party trees (`core`, `modules`, `scene`, `servers`, `editor`), excluding vendored `thirdparty/`.

- [ ] **Step 1: Capture the pre-parser baseline BEFORE anything else**

The whole point of the before/after is that the "before" is measured with the parser absent. Check out the merge-base of this branch, build, and scan:

```bash
cd /Users/ross/code/agentic-security
git stash list  # ensure a clean tree first
BASE=$(git merge-base docs/proof-corpus-prd HEAD)
git checkout "$BASE" -- scanner/src/ir/ scanner/src/dataflow/catalog.js 2>/dev/null || echo "no pre-state to restore — see note"
```

**If that checkout is impractical**, the honest alternative is to measure "before" by temporarily disabling the dispatch: comment out the C/C++ branch in both builders in `scanner/src/ir/index.js`, rebuild, scan, then restore. Whichever route you take, **state in your report exactly how the baseline was obtained** — a before/after where the "before" was never actually run is worthless.

- [ ] **Step 2: Pin and clone Godot**

```bash
cd /Users/ross/code/agentic-security/scanner
node ../bench/proof-corpus/runner.mjs --only godot --refresh-pins
```

Expected: a full 40-character SHA printed and written to the manifest. Confirm it landed:

```bash
cd /Users/ross/code/agentic-security && node -e "
const m=require('/Users/ross/code/agentic-security/bench/proof-corpus/manifest.json');
const t=m.targets.find(x=>x.id==='godot');
if(!/^[0-9a-f]{40}\$/.test(t.commit||'')){console.error('FAIL: not pinned');process.exit(1);}
console.log('godot pinned', t.commit, 'scope', JSON.stringify(t.scope));
"
```

- [ ] **Step 3: Run the scan with the parser enabled**

```bash
cd /Users/ross/code/agentic-security/scanner
npm run build
node ../bench/proof-corpus/runner.mjs --only godot 2>&1 | tail -20
```

Run this in the background and poll — it can take tens of minutes and may approach the 3600-second budget.

- [ ] **Step 4: Read the real numbers**

```bash
cd /Users/ross/code/agentic-security && node -e "
const s=require('/Users/ross/code/agentic-security/bench/proof-corpus/results/summary.json');
const t=s.targets.find(x=>x.id==='godot');
console.log('status', t.status, 'exit', t.scan.exitCode, 'timedOut', t.scan.timedOut);
console.log('wall_s', Math.round(t.scan.wallMs/1000), 'rss_mb', Math.round(t.scan.peakRssKb/1024));
console.log('determinism', JSON.stringify(t.determinism));
console.log('coverage', JSON.stringify(t.coverage.byLanguage.cpp));
console.log('callGraph', JSON.stringify(t.coverage.callGraph));
"
```

- [ ] **Step 5: Judge against PRD §6.12 and report honestly**

The seven acceptance criteria, with how each is judged:

1. Contract-conformant IR, `npm run test:dataflow` green — from Tasks 1–3.
2. **Parse coverage ≥ 85% on Godot's first-party C++ tree.** Compare `coverage.byLanguage.cpp.pct` against 85.
3. **Call graph resolves a non-trivial number of cross-TU calls**, reported as an absolute number against the Phase-2 baseline of effectively zero. Use `coverage.callGraph.resolvedEdges`.
4. At least one end-to-end interprocedural C++ taint finding — proven by the Task 6 test and the Task 7 cross-TU corpus entry.
5. ≥ 10 C/C++ corpus entries at `pre:TP post:TN` — from Task 7.
6. No regression: full `npm test` green and `bench:cve-replay:check` clean.
7. **Godot stays within its declared time budget.** `timedOut` must be `false`.

**If criterion 2 or 4 fails, PRD §6.12 commits in advance to publishing the shortfall rather than hiding it.** Report C++ as remaining at Syntactic tier, record the real figure, and list the failing files from the sidecar's `failures[]` array in the gap section. Do not retry until a better number appears, and do not narrow the scope to flatter the result — the manifest's declared scope is fixed.

- [ ] **Step 6: Record the result**

Update `bench/proof-corpus/README.md` with a Godot row carrying the real figures, including `functionless`, and a before/after line for parse coverage and resolved call-graph edges. Update the Proof Corpus PRD §2.3's support-tier table: move C/C++ from *Syntactic* to *Structural IR* **only if** criteria 2, 3 and 4 all passed. If they did not, leave the tier unchanged and add a line stating what was measured and what remains.

- [ ] **Step 7: Final gate**

```bash
cd /Users/ross/code/agentic-security/scanner
npm test 2>&1 | tail -12; echo "TEST_EXIT=$?"
npm run bench:cve-replay:check >/dev/null 2>&1; echo "CORPUS_EXIT=$?"
```

Expected: both exit 0.

- [ ] **Step 8: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/proof-corpus/manifest.json bench/proof-corpus/README.md bench/proof-corpus/results/summary.json the Proof Corpus PRD
git commit -m "test(proof-corpus): measure the C/C++ parser on Godot

Pins Godot and records the measured parse coverage, call-graph resolution,
wall time and peak RSS with the C/C++ frontend enabled, against the
pre-parser baseline. Figures come from the run in this commit.

Judged against PRD 6.12; the support-tier table is updated only for criteria
that actually passed."
```

---

## Self-Review

**Spec coverage — PRD §6:**

| PRD requirement | Task |
|---|---|
| §6.2 the gap: no `parser-cpp.js` reaching the IR contract | 1, 2 |
| §6.3 hand-rolled, not tree-sitter or libclang | 1 (recorded in the module header) |
| §6.4 module plan: `parser-cpp.js`, `index.js`, `class-hierarchy.js`, `catalog.js` | 1, 3, 5, 6 |
| §6.5 modelled/not-modelled scope contract | 1 (verbatim in the module header) |
| §6.6 qualified naming and qid stability | 1 (qid-stability test) |
| §6.7 header/source pairing via a qualified-name index | 4 |
| §6.8 class hierarchy | 5 (plus a correction to the PRD's own claim) |
| §6.9 sources, sinks, sanitizers; syntactic rules retained | 6 |
| §6.10 promoting `cpp-dataflow.js` | **Deferred** — see below |
| §6.11 unit / fixture / corpus / real testing loop | 1, 2, 7, 8 |
| §6.12 seven acceptance criteria | 8 (judged explicitly, criterion by criterion) |

**Deliberate deferral:** PRD §6.10 (re-hosting the five `cpp-dataflow.js` memory-safety detectors on real CFGs and reconsidering their default-off gate) is **not** in this plan. §6.10 itself makes the gate flip conditional on measuring false-positive density on the Godot run — which cannot happen until Task 8 produces that run. Attempting it here would mean flipping a default on an unmeasured basis, which §6.10 explicitly forbids. It belongs in a follow-up plan that starts from Task 8's numbers.

**Placeholder scan:** none. Task 8 Step 1 offers two routes for obtaining the baseline and requires the report to state which was used — a decision with a stated fallback, not an unfilled blank.

**Type consistency:** `parseCppFile` returns `{file, functions, classes, topLevel}` in Task 1 and is consumed with exactly that shape in Tasks 3, 4, 5. `fn.qname` and `fn.isDeclaration` are produced in Task 1 and consumed in Task 4. `ir.classes = [{name, bases, line}]` is produced in Task 1 and consumed in Task 5. Catalog entries in Task 6 match the documented shape in `catalog.js`'s header comment and are read via `matchSource`/`matchSinkOrSanitizer`, whose behaviour was verified at `catalog.js:765-810`. CFG node kinds in Task 2 match `scanner/src/ir/CLAUDE.md`.

**A defect caught during self-review, and what it changed.** The first draft of Task 6 asserted only that a catalog match *existed* for `getenv`, `system` and `popen`. Querying the live catalog showed all three — plus `realpath` — already match today via the Python, PHP, Ruby, Java and Kotlin entries, because `CALLEE_INDEX` is keyed by callee name with no language filter. Those tests would have passed with no new code written: four vacuous tests guarding the plan's central integration point. Task 6's tests now assert on `cpp-`prefixed entries and inspect `CATALOG` directly for colliding names. The same finding also means the genuine catalog gap is narrower than assumed — the C-specific value of those four entries is correct labels, provenance, CWE and `argIndex`, not first-time recognition.

**Known risk, stated rather than hidden:** the realistic failure mode is Task 8 returning parse coverage below 85% on real macro- and template-heavy C++. The plan handles this by measuring the baseline first (so partial progress is still quantified) and by requiring the shortfall to be published rather than retried away. The §6.5 scope contract exists so that "templates are not modelled" is a known limitation rather than a discovered disappointment.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-25-cpp-ir-parser.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
