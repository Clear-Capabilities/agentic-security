// C# IR frontend (v0.66).
//
// Regex-based, pragmatic, focused on ASP.NET / Entity Framework / Dapper /
// System.IO surface area. Parallels parser-py.js (the legacy Python regex
// parser) in approach: extract method bodies, lower assignments and calls
// to the canonical IR shape, build a linear CFG.
//
// What we model:
//   - method declarations: `[modifiers] returnType Name(params) { body }`
//   - simple assignments: `var x = ...;`  `Type x = ...;`  `x = ...;`
//   - method calls (statement-form): `obj.Method(args);` / `Method(args);`
//   - return: `return expr;`
//   - ASP.NET source-like access: `Request.Form["x"]`, `Request.QueryString[...]`
//   - control flow (R8): `if`/`else`/`else if`/`while`/`for`/`foreach`/
//     `switch`/`do`/`try`/`catch`/`finally` bodies are recursed into by
//     `_buildCfg` (ported from parser-cpp.js's proven keyword+balanced-scan
//     pattern), so a sink several levels deep inside a braced body is
//     reachable. A `for` header's init clause becomes a real assign node
//     (not just its test clause as the condition); a `foreach` header
//     binds its loop variable to the iterated collection before the body
//     is recursed into, so the loop variable itself carries taint
//     provenance. Line numbers through this recursion are computed via
//     exact character-offset lookup (`_lineStarts`/`_lineForOffset`), not
//     approximated — see `_buildCfg`'s header comment.
//
// What we do NOT model (regex-fallback class limits):
//   - LINQ expressions (treated as opaque expression)
//   - lambdas (body collapsed)
//   - async/await (transparent)
//   - generics on declarations beyond Type<...> name
//   - attributes (skipped)
//   - destructuring / tuples
//   - control-flow BRANCHING semantics: `if`/`else`, `switch` cases, and
//     `try`/`catch`/`finally` clauses are each recursed into and linked
//     SEQUENTIALLY (matching parser-cpp.js's own "linear but complete"
//     approximation) rather than as alternative/exceptional paths — every
//     branch's body is reachable in the CFG, which is what taint analysis
//     needs, but the graph does not model that only one branch executes
//     per run.
//   - a comment appearing MID-statement (after real content has already
//     started) is left as literal text, not stripped — only a comment
//     that precedes a statement (the common real-world shape) is skipped
//     by `_splitStatements`; see that function's header comment.
//
// This is a v1. Promoted to a Roslyn-backed CST parser (analogous to
// parser-py-cst.js) once we have a dotnet capability probe.

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';
import { matchBalancedCall } from './balanced-call.js';

// Taint-engine PRD P1: the modifier group used to be MANDATORY (at least
// one of public/private/.../partial required before the return type), so a
// bare, implicitly-private method — legal and common for private helpers,
// e.g. `void Render() { ... }` — never matched at all: the whole method,
// and any sink inside it, was invisible to the IR. Each modifier now
// consumes its own trailing whitespace and the whole group is zero-or-more,
// so zero modifiers is a valid match. Safe against false positives:
// control-flow keywords (if/for/while/using/catch/...) have only ONE token
// before their parens, never this pattern's "type name(args)" two-token
// shape, so they cannot start matching just because the modifier
// requirement was dropped — pinned by a dedicated precision test.
const METHOD_RE = new RegExp(
  '(?:^|[\\s;{}])' +
  '(?:(?:public|private|protected|internal|static|virtual|override|async|sealed|abstract|new|readonly|partial)\\s+)*' +
  '([A-Za-z_][A-Za-z0-9_<>?\\[\\],\\s]*?)' +    // return type (group 1)
  '\\s+([A-Za-z_][A-Za-z0-9_]*)' +                  // method name (group 2)
  '\\s*\\(([^)]*)\\)' +                             // params (group 3)
  '\\s*\\{', 'g');

// Class/struct declaration: modifiers* `class`|`struct` Name, optionally
// followed by generic params (`<T>`) and/or a base/interface list
// (`: Base, IFoo`), then the body's opening `{`.
//
// `bench:self-scan:check` caught a genuine ReDoS in this file's own first
// draft (confirmed by direct timing, not a detector false alarm: 30 000
// repeats of " public " with no trailing "class"/"struct" took 5+ SECONDS
// with an unbounded `*`). Root cause: an unanchored search retries the
// WHOLE pattern starting at every input position, and each retry's modifier
// star backtracks through every possible repetition count before failing —
// O(n) retries × O(n) backtracking each = O(n²) on realistic non-matching
// input (most of a file's text isn't a class declaration). Unlike this
// codebase's other documented ReDoS class ("an optional group flanked by
// two \s* quantifiers"), the fix here is a bounded repetition count: real
// C# code never stacks more than 2-3 modifiers on a class. A first fix
// attempt bounded the repetition to `{0,6}` — genuinely linear (re-verified
// directly: 200 000 non-matching repeats in 34ms), but `sast/redos-nfa.js`'s
// static "nested quantifier" heuristic flags a bounded-but-still-quantified
// group the same as an unbounded one, since it can't see the numeric bound
// makes it safe (same class of detector-vs-reality gap this codebase's own
// prior ReDoS fixes have hit — see e.g. the Kotlin trailing-lambda note in
// `../ir/CLAUDE.md`: "the SAME detector's heuristic still flagged the
// replacement... even though it measured linear on its own"). Unrolled into
// 4 explicit, non-nested optional groups instead — no group here contains
// its own internal quantifier, so the structural heuristic no longer
// matches, while remaining exactly as linear (same 200 000-repeat timing)
// and correctness-preserving across every realistic modifier combination
// (0 to 4 modifiers; C# has none that legally stack more than 3 on a
// class/struct declaration).
const _CS_MOD = String.raw`(?:public|private|protected|internal|static|sealed|abstract|partial|new)\s+`;
const CLASS_RE = new RegExp(
  String.raw`(?:^|[\s;{}])(?:${_CS_MOD})?(?:${_CS_MOD})?(?:${_CS_MOD})?(?:${_CS_MOD})?(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)`, 'g');

// Taint-recall: C#'s `_qid()`/`fn.name` never recorded which CLASS a method
// belongs to at all (no middle `::ClassName::` segment, unlike Java's/JS's
// convention — see `../dataflow/CLAUDE.md`'s C# row and
// `bench/sard/IMPLEMENTATION_STATUS.md`'s "real accuracy improvement pass"
// section for the full account). That makes `callgraph.js`'s `classMethods`
// index — which resolves `new Helper().BadSink(x)` / `Helper.BadSink(x)` —
// PERMANENTLY EMPTY for C#, so no cross-class call (same file or not) could
// ever resolve, blocking interprocedural taint for exactly the shape
// Juliet's own interface-based helper-class test structure (CWE-90/643/79-
// 83/113/78/etc.'s dominant remaining flow-variant pattern) uses.
//
// Finds every class/struct declaration's body range so a method's enclosing
// class can be looked up by character offset. A method not inside any class
// (a rare but legal C# top-level-statements shape) gets `className: null`.
// Nested classes are handled by picking the SMALLEST (innermost) range that
// contains the method — ranges are not required to be non-overlapping.
function _findClassRanges(code) {
  const ranges = [];
  CLASS_RE.lastIndex = 0;
  let m;
  while ((m = CLASS_RE.exec(code)) !== null) {
    const name = m[1];
    // `CLASS_RE`'s leading `(?:^|[\s;{}])` consumes exactly one boundary
    // character into `m[0]` (or zero, at `^`). When that boundary
    // character is itself the newline ending the PREVIOUS line — the
    // common case for a top-level declaration with no leading
    // indentation — `m.index` points at that newline, and `_lineAt`
    // (which counts newlines strictly before its offset) undercounts by
    // one line as a result. Stepping one character past a real boundary
    // char lands on the declaration's own first character, which is
    // always on the correct line regardless of which boundary character
    // matched (a same-line boundary like a space or `{` is unaffected by
    // the shift).
    const declStart = m.index + (/^[\s;{}]/.test(m[0][0]) ? 1 : 0);
    // Skip past an optional generic parameter list and/or base/interface
    // list to find the REAL opening brace — `class Foo<T> : Base<T>, IBar`
    // has two `<...>` regions before the body even starts. Track angle-
    // bracket depth; balanced-`<>` is a reasonable approximation here (C#
    // generics don't nest with unbalanced `<`/`>` in valid code), and a
    // `{` encountered while depth > 0 (an unlikely default-value-in-
    // generic-constraint edge case) is simply skipped rather than
    // mis-treated as the class body. `colonAt` records where the
    // base/interface list starts (the FIRST top-level `:`, C# allows only
    // one) so it can be sliced out once the real body brace is found.
    let i = m.index + m[0].length;
    let angleDepth = 0;
    let colonAt = -1;
    while (i < code.length) {
      const c = code[i];
      if (c === '<') angleDepth++;
      else if (c === '>') { if (angleDepth > 0) angleDepth--; }
      else if (c === ':' && angleDepth === 0 && colonAt === -1) colonAt = i;
      else if (c === '{' && angleDepth === 0) break;
      else if ((c === ';') && angleDepth === 0) { i = -1; break; } // forward-declaration-shaped or malformed; bail
      i++;
    }
    if (i < 0 || i >= code.length || code[i] !== '{') continue;
    let bases = [];
    if (colonAt !== -1) {
      // A generic constraint clause (`where T : class`) can follow the
      // base list before the body brace and would otherwise be read as
      // more base names; it always starts with a top-level `where` after
      // the base list, so truncate there first.
      let baseText = code.slice(colonAt + 1, i);
      const whereIdx = baseText.search(/\bwhere\b/);
      if (whereIdx !== -1) baseText = baseText.slice(0, whereIdx);
      // Each base/interface name, stripped of its own generic argument
      // list (`BaseRepo<T>` → `BaseRepo`) — `class-hierarchy.js`-style
      // consumers key allocation/dispatch types by simple name, same as
      // every other class-metadata producer in this codebase.
      bases = _splitTopLevelCommas(baseText).map(p => p.trim().split(/[<\s]/)[0]).filter(Boolean);
    }
    const extracted = _extractBody(code, i);
    if (!extracted) continue;
    ranges.push({ name, start: i, end: extracted.end, bases, line: _lineAt(code, declStart) });
    CLASS_RE.lastIndex = i + 1; // resume scanning INSIDE the class body too, for nested classes
  }
  return ranges;
}

// Scan a member statement (as produced by `_splitStatements` over a class
// body) to decide whether it's method/constructor-SHAPED (a `(` appears at
// the statement's own top level, before any `=` or `{`) versus a field or
// auto-property declaration. Attributes (`[Foo] [Bar(...)]`) prefixing the
// member push `[`/`]` onto the SAME depth counter `{`/`(` use, so they are
// transparently skipped without any special-casing — by the time a real
// modifier/type token appears, depth is back to 0.
function _memberHeadInfo(stmt) {
  let depth = 0;
  let inStr = null;
  let escape = false;
  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i];
    if (escape) { escape = false; continue; }
    if (inStr) {
      if (c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; continue; }
    if (c === '(' && depth === 0) return { isMethodLike: true };
    if (c === '{' && depth === 0) return { isMethodLike: false, headEnd: i };
    if (c === '(' || c === '{' || c === '[' || c === '<') { depth++; continue; }
    if (c === ')' || c === '}' || c === ']' || c === '>') { if (depth > 0) depth--; continue; }
    // A real assignment `=`, not `==`/`!=`/`<=`/`>=`/`=>`.
    if (depth === 0 && c === '=' && stmt[i + 1] !== '=' && stmt[i + 1] !== '>' &&
        !['=', '!', '<', '>'].includes(stmt[i - 1])) {
      return { isMethodLike: false, headEnd: i };
    }
  }
  return { isMethodLike: false, headEnd: stmt.length };
}

// The last bare identifier in `text` — used to pull a declared name off
// the tail of a type/modifier clause (`private static string sf` → `sf`,
// `public readonly Dictionary<string, T> map` → `map`) without needing to
// parse the type itself, which can contain internal whitespace (generic
// argument lists) that a naive whitespace-split would mis-split on.
function _lastIdent(text) {
  const m = String(text || '').match(/([A-Za-z_]\w*)\s*$/);
  return m ? m[1] : null;
}

const _NESTED_TYPE_RE = /^(?:(?:public|private|protected|internal|static|sealed|abstract|partial|new|readonly)\s+)*(?:class|struct|interface|enum)\s/;

// Declared field/auto-property names for one class range, from the SAME
// statement split `_buildCfg` uses for method bodies (`_splitStatements`
// already treats a balanced `{...}` — a method body, or a property's
// `{ get; set; }` accessor block — as part of ONE flushed statement, so
// method declarations and multi-statement bodies never need to be
// specially excluded here: `_memberHeadInfo` rejects anything method-
// shaped outright). Nested type declarations are recognized and skipped
// as a whole (their own fields are not modeled — out of scope for the
// cross-method field-taint use this exists for).
function _extractClassFields(code, range) {
  const bodyText = code.slice(range.start + 1, range.end);
  const fields = [];
  for (const { text: stmt } of _splitStatements(bodyText)) {
    if (!stmt || stmt.startsWith('//') || stmt.startsWith('/*')) continue;
    if (_NESTED_TYPE_RE.test(stmt)) continue;
    const info = _memberHeadInfo(stmt);
    if (info.isMethodLike) continue;
    const head = stmt.slice(0, info.headEnd);
    if (stmt[info.headEnd] === '{') {
      // Auto-property: `public string Name { get; set; }` — one name, no
      // multi-declarator syntax exists for properties.
      const name = _lastIdent(head);
      if (name) fields.push(name);
      continue;
    }
    // Field declaration, possibly multiple comma-separated declarators
    // (`protected int a, b;`), each optionally carrying its own `= init`.
    // `_splitTopLevelCommas` is already `<`/`(`/`{`/`[`-depth-aware (used
    // elsewhere in this file for argument lists), so a comma inside a
    // generic type argument or an initializer's own call/object literal
    // does not fracture the declarator list.
    for (const part of _splitTopLevelCommas(stmt)) {
      const eq = part.indexOf('=');
      const before = eq === -1 ? part : part.slice(0, eq);
      const name = _lastIdent(before);
      if (name) fields.push(name);
    }
  }
  return fields;
}

// Innermost class whose range contains `pos` (a method declaration's match
// offset), or null when the method sits outside any class (top-level
// statements — legal but rare).
function _enclosingClassName(ranges, pos) {
  let best = null;
  for (const r of ranges) {
    if (pos >= r.start && pos < r.end) {
      if (!best || (r.end - r.start) < (best.end - best.start)) best = r;
    }
  }
  return best ? best.name : null;
}

// Companion to the class-tracking fix above, closing the OTHER half of the
// same gap: `HelperB h = new HelperB(); h.BadSink(data);` — Juliet's other
// dominant helper-class idiom, alongside the inline `new Helper().Sink(x)`
// chain `classMethods` now resolves directly. `h.BadSink` is a callee
// string built from the LOCAL VARIABLE name, which `classMethods` (keyed
// by real class name) can never match. This is exact same-function local
// type inference, not a guess: `h`'s constructed type is unambiguous
// wherever `h = new HelperB()` appears, so a call written as `h.BadSink(x)`
// is rewritten in place to `HelperB.BadSink` — the callee string
// `classMethods` already knows how to resolve (and, since `classMethods`
// is a PROJECT-WIDE index built across every file, this also transparently
// covers Juliet's documented cross-FILE `_NNa`/`_NNb` paired-variant
// convention when the helper class lives in a sibling file, with no
// separate cross-file mechanism needed). Refuses to guess when a variable
// is (re)assigned to more than one distinct constructed type in the same
// function — ambiguous, same "refuse rather than fabricate an edge"
// convention `bareTailInFile` already uses.
// SARD_80_F1 W2.3 — ported from the identical fix in parser-java.js (see
// its own comment for the full story, found first for Java): a BCL
// collection type (`List`, `Dictionary`, `Stack`, `Queue`, `HashSet`, …)
// is never an entry in `callgraph.js`'s `classMethods` index (built only
// from THIS project's own `ir.classes`), so class-qualifying
// `list.Add(data)` to `List.Add(data)` buys dispatch resolution nothing —
// while breaking `engine.js`'s mutator rule, which needs the REAL
// variable name to attribute taint correctly. A `foreach (var s in list)`
// read over the container itself lowers to a bare-identifier assign
// (`s = list`, no callee to rewrite), so it stays keyed on "list" while
// the (rewritten) write lands on the fake receiver "List" — the taint is
// silently lost. Confirmed via a direct CFG dump: `List<string> list =
// new List<string>(); list.Add(data);` didn't even trigger the bug (this
// parser's generic-constructor lowering produces `{kind:'unknown'}` for
// `new List<string>()`, so it's never added to `varTypes` at all) — but
// the non-generic `ArrayList`/`Hashtable`-style BCL collections DO lower
// to a proper `isNew:true` call and DO exhibit the exact same desync as
// Java's `ArrayList`.
const _BCL_CONTAINER_TYPES = /^(?:List|ArrayList|LinkedList|Stack|Queue|Dictionary|Hashtable|SortedList|SortedDictionary|HashSet|SortedSet|ArrayDeque|ConcurrentBag|ConcurrentQueue|ConcurrentStack|ConcurrentDictionary|BlockingCollection|ObservableCollection|Collection|CollectionBase)$/;

function _localVarConstructedTypes(nodes) {
  const varTypes = new Map(); // varName -> className | null (ambiguous)
  for (const node of Object.values(nodes)) {
    if (node.kind !== 'assign') continue;
    const src = node.source;
    if (!src || src.kind !== 'call' || !src.isNew || typeof src.callee !== 'string') continue;
    if (_BCL_CONTAINER_TYPES.test(src.callee)) continue;
    const varName = node.target;
    if (!varName || varName.includes('.')) continue; // only a bare local, never a member-write target
    if (varTypes.has(varName)) {
      if (varTypes.get(varName) !== src.callee) varTypes.set(varName, null);
    } else {
      varTypes.set(varName, src.callee);
    }
  }
  return varTypes;
}

// Recursively rewrites `varName.method`-shaped call callees to
// `ClassName.method` wherever `varName` has an unambiguous constructed type
// in `varTypes`, walking into every expression-tree shape `_lowerExpr` can
// produce (a tainted argument to a rewritten call is just as real a finding
// as the call itself, so args/branches must be walked too, not just the
// node's own top-level callee).
function _rewriteVarTypeCallees(expr, varTypes) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.kind === 'call') {
    if (typeof expr.callee === 'string') {
      const dot = expr.callee.indexOf('.');
      if (dot > 0) {
        const varName = expr.callee.slice(0, dot);
        const cls = varTypes.get(varName);
        if (cls) expr.callee = `${cls}${expr.callee.slice(dot)}`;
      }
    }
    if (Array.isArray(expr.args)) for (const a of expr.args) _rewriteVarTypeCallees(a, varTypes);
    return;
  }
  if (expr.kind === 'member') { _rewriteVarTypeCallees(expr.object, varTypes); return; }
  if (expr.kind === 'binary' || expr.kind === 'logical') {
    _rewriteVarTypeCallees(expr.left, varTypes); _rewriteVarTypeCallees(expr.right, varTypes); return;
  }
  if (expr.kind === 'tpl' && Array.isArray(expr.parts)) { for (const p of expr.parts) _rewriteVarTypeCallees(p, varTypes); return; }
  if (expr.kind === 'union' && Array.isArray(expr.branches)) { for (const b of expr.branches) _rewriteVarTypeCallees(b, varTypes); return; }
  if (expr.kind === 'array' && Array.isArray(expr.elements)) { for (const e of expr.elements) _rewriteVarTypeCallees(e, varTypes); return; }
}

function _applyVarTypeRewrite(nodes) {
  const varTypes = _localVarConstructedTypes(nodes);
  let any = false;
  for (const t of varTypes.values()) if (t) { any = true; break; }
  if (!any) return;
  for (const node of Object.values(nodes)) {
    if (node.kind === 'call') _rewriteVarTypeCallees(node, varTypes);
    else if (node.kind === 'assign') _rewriteVarTypeCallees(node.source, varTypes);
    else if (node.kind === 'return' || node.kind === 'throw') _rewriteVarTypeCallees(node.value, varTypes);
    else if (node.kind === 'if') _rewriteVarTypeCallees(node.cond, varTypes);
  }
}

// Matches a top-level statement inside a method body. Splits on `;` at
// brace-depth 0 (keeping simple lambdas inside calls intact), AND — R8 —
// also flushes on a `}` that returns the SAME shared depth counter to 0.
// That second trigger is what makes a braced control-flow body
// (`if (...) { ... }`) come back as its OWN statement, ready for
// `_buildCfg` to recurse into, instead of staying glued to whatever `;`
// happens to terminate the NEXT statement (the old, pre-R8 behavior,
// which is why control flow was invisible before this task).
//
// This is safe for C#'s `{}`-based collection/object initializers
// (`new Foo { X = 1 }`) and lambda bodies passed as call arguments
// (`xs.ForEach(x => { Process(x); })`) because `depth` here is ONE shared
// counter across `{`, `(` and `[` (matching this file's pre-existing
// convention) — a `}` only reaches depth 0 when EVERY enclosing brace,
// paren and bracket has also closed, so a collection initializer's `}`
// (which closes while the surrounding `(...)` of a call, or the
// surrounding `;`-terminated `var x = ...` is still "open" only in the
// sense of not yet having hit a flush point) or a lambda body's `}`
// (which closes while the outer call's `(` is still open, i.e. depth > 0)
// never trips this trigger. Only a `}` that is truly the LAST unmatched
// delimiter does — precisely the shape a control-flow body's closing
// brace has.
//
// Returns `{ text, start }[]` — `start` is the absolute character offset,
// within `body`, of the first REAL (non-whitespace) character of `text`.
// This offset is tracked directly against the ORIGINAL, untouched `body`
// string (never against a reconstructed/trimmed copy), so `_buildCfg` can
// compute exact line numbers via a single `_lineStarts`/`_lineForOffset`
// pair built once per function body — see that pairing's comment. This
// is the R8 lesson from the PHP task (3 fix rounds, all ultimately about
// line-number precision): approximate offsets computed by re-counting
// newlines in text that has already been trimmed or reconstructed are
// lossy (a stripped comment, a dropped blank line) in ways that only
// surface on real multi-line source; an exact offset into the pristine
// original text cannot drift.
//
// Also splits on a `:` at depth 0 that terminates a `switch` body's
// `case <expr>:` / `default:` label — those labels are not otherwise
// separated by `;` or `}`, and without this a label stays glued onto
// whatever real statement follows it, which then fails every shape
// `_lowerStmt` recognizes and silently drops that statement. Scoped
// tightly (the accumulated text so far must be EXACTLY `case <expr>` or
// `default`) so an ordinary ternary's `:` can't mis-fire — a ternary's
// left-hand accumulated text is never going to equal one of those two
// shapes. `::` (the `global::`/qualified-name operator) is excluded via
// the adjacent-character check so a qualified name's colon can never be
// mistaken for a label terminator.
//
// Comment handling: a `//` or `/* */` comment is skipped outright (not
// merely blanked) while NO real content has been accumulated yet for the
// statement currently being scanned (i.e. only whitespace so far this
// cycle) — the common real-world shape of a standalone comment line
// immediately before a statement. Skipping it here, rather than letting
// it become part of the statement text, matters because `_lowerStmt`
// refuses (`startsWith('//')`) any statement text that begins with a
// comment: without this, a comment on its own line right before e.g.
// `var cmd = ...;` would glue onto it and silently drop that statement
// from the CFG. A comment appearing mid-statement (after real content has
// already started) is left as literal text — this parser has never
// modelled comments in general, and fixing that broader gap is out of
// scope for this task.
function _splitStatements(body) {
  const out = [];
  let buf = '';
  let contentStart = -1;   // absolute offset of the first real char of the
                            // statement currently being accumulated, or -1
                            // if none seen yet.
  let depth = 0;
  let inString = null;     // null | '"' | "'"
  let escape = false;
  const push = (c, idx) => {
    buf += c;
    if (contentStart === -1 && !/\s/.test(c)) contentStart = idx;
  };
  const flush = () => {
    const trimmed = buf.trim();
    if (trimmed) out.push({ text: trimmed, start: contentStart });
    buf = '';
    contentStart = -1;
  };
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (contentStart === -1) {
      if (c === '/' && body[i + 1] === '/') {
        while (i < body.length && body[i] !== '\n') i++;
        continue;
      }
      if (c === '/' && body[i + 1] === '*') {
        i += 2;
        while (i < body.length && !(body[i] === '*' && body[i + 1] === '/')) i++;
        if (i < body.length) i += 1;
        continue;
      }
    }
    if (escape) { push(c, i); escape = false; continue; }
    if (inString) {
      push(c, i);
      if (inString === '"' && c === '\\') { escape = true; continue; }
      if (c === inString) inString = null;
      continue;
    }
    if (c === '"' || c === "'") { inString = c; push(c, i); continue; }
    if (c === '{' || c === '(' || c === '[') { depth++; push(c, i); continue; }
    if (c === '}' || c === ')' || c === ']') {
      depth--;
      push(c, i);
      if (c === '}' && depth === 0) flush();
      continue;
    }
    if (c === ';' && depth === 0) { flush(); continue; }
    if (c === ':' && depth === 0 && body[i + 1] !== ':' && body[i - 1] !== ':') {
      const t = buf.trim();
      if (/^case\s+[\s\S]+$/.test(t) || t === 'default') { flush(); continue; }
    }
    push(c, i);
  }
  flush();
  return out;
}

// Build a sorted array of line-start offsets for `text` (index 0 holds the
// start of line 1, i.e. always 0). Paired with `_lineForOffset` to turn a
// character offset into an exact 1-based line number in O(log n) — ported
// verbatim from parser-cpp.js's `_lineStarts`/`_lineForOffset`, the
// proven reference for this exact-offset-based line computation pattern.
function _lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

function _lineForOffset(lineStarts, idx) {
  let lo = 0, hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= idx) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

// Find the index of the delimiter in `openCh`/`closeCh` that matches the
// one at `openIdx`, respecting nesting and skipping string-literal
// content. Returns -1 if unmatched.
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

// Split a `for` header's `init; test; step` on top-level `;` (respecting
// nested parens/brackets/strings) so the init clause can be surfaced as a
// real assign node and the test clause used as the loop's condition —
// mirroring parser-cpp.js's `_splitTopLevelAligned` use for the same
// C-style for-loop shape.
function _splitTopLevelSemi(s) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      buf += c;
      if (c === '\\') { i++; buf += s[i] || ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
    if (c === ';' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  out.push(buf.trim());
  return out;
}

// Taint-recall PRD (80%): a chained call (`new DataTable().Compute(expr)`,
// `Response.Headers.Add(...)` chains further, etc.) previously stopped at
// the FIRST balanced call and left any `.Method(args)` continuation
// unconsumed (by matchBalancedCall's own design — see its header) —
// correct for not corrupting the parse, but it meant the OUTER call, which
// is frequently the one actually carrying the sink and its tainted
// argument, was silently absent from the CFG entirely. Confirmed via a
// real corpus fixture: `new DataTable().Compute(expr, "")` collapsed to
// just the constructor call, args: [], dropping `.Compute(expr, "")`
// completely.
//
// Walks forward from `endIdx` (the position right after the just-matched
// call's closing paren) following every `.Method(args)` continuation,
// dot-joining each level's name into one callee string (`DataTable.Compute`,
// `template.New.Parse`) so both bare-name matching (last segment) and
// receiver-pattern matching (earlier segments) keep working unchanged.
//
// Args from EVERY level are kept, outermost-first (`outerArgs.concat(prior)`
// at each step) — NOT just the outermost. A first version kept only the
// outermost call's args, which broke a real chain shape
// (`xp.compile(taintedExpr).evaluate(doc, XPathConstants.NODESET)`-style,
// found in Kotlin but the identical defect class applies here) where the
// tainted value sits on an INNER call, not the final one — the outer call's
// own args (if any) correctly stay at the front so an existing
// `argIndex: 0` catalog entry keyed to the outermost call is unaffected;
// inner levels' args are appended after so an `argIndex: 'all'` entry can
// still find taint that only an inner call actually carried.
function _followChain(s, endIdx, calleeSoFar, argsSoFar, isNew) {
  const rest = s.slice(endIdx);
  const m = rest.match(/^\.(\w+)/);
  if (!m) return { kind: 'call', callee: calleeSoFar, args: argsSoFar, isNew };
  const outer = matchBalancedCall(rest, /^\.(\w+)/);
  if (!outer) return { kind: 'call', callee: calleeSoFar, args: argsSoFar, isNew };
  const outerArgs = _splitTopLevelCommas(outer.argsText).map(_lowerExpr);
  return _followChain(rest, outer.endIdx, `${calleeSoFar}.${outer.callee}`, outerArgs.concat(argsSoFar), false);
}

// A C-style cast `(Type)expr` / `(Type) expr` is transparent for taint: the
// value is the operand. Juliet's collection variants (`Object o = data;
// string d = (string)o;`) and every `(string)reader.GetValue(0)` read hit
// this shape; before it was recognised the whole expression fell through to
// `{kind:'unknown'}` and the taint died at the cast. The type token must
// look like a type (identifier, optional generics/array/nullable) so a
// parenthesised arithmetic expression like `(a + b)` is not mistaken for a
// cast.
const _CAST_RE = /^\(\s*[A-Za-z_][\w.]*(?:<[^()]*>)?(?:\[\s*\])*\??\s*\)\s*(?=[A-Za-z_("@$])/;

function _lowerExpr(text) {
  const s = String(text || '').trim();
  if (!s) return { kind: 'unknown' };
  const castM = s.match(_CAST_RE);
  if (castM) return _lowerExpr(s.slice(castM[0].length));
  // Parenthesised object creation starting a chain: `(new X()).M(args)`.
  // Same shape as the un-parenthesised `new X().M(args)` branch below,
  // which cannot see it because the leading `(` blocks the `^new` anchor.
  if (s.startsWith('(')) {
    const closeIdx = _matchDelim(s, 0, '(', ')');
    if (closeIdx !== -1 && /^\s*new\s/.test(s.slice(1, closeIdx))) {
      const inner = _lowerExpr(s.slice(1, closeIdx).trim());
      if (inner.kind === 'call' && s.slice(closeIdx + 1).trim().startsWith('.')) {
        return _followChain(s, closeIdx + 1, inner.callee, inner.args, inner.isNew);
      }
      return inner;
    }
  }
  // Member access: a.b.c["foo"]
  if (/^[A-Za-z_][\w.]*\[[^\]]*\]$/.test(s)) {
    // E.g. Request.Form["name"]. Split on first '[' to isolate index.
    const lb = s.indexOf('[');
    const base = s.slice(0, lb);
    const dots = base.split('.');
    return _buildMemberChain(dots, /*indexed*/ s.slice(lb));
  }
  // Plain dotted ident: Request.Form / Request.QueryString
  if (/^[A-Za-z_][\w.]*$/.test(s)) {
    const parts = s.split('.');
    if (parts.length === 1) return { kind: 'ident', name: parts[0] };
    return _buildMemberChain(parts);
  }
  // Object creation: `new Type(args)` — lowered to a call so taint flows into
  // constructor arguments. Without this branch the expression fell through to
  // the concat heuristic below, and because the `+` sits INSIDE the parens
  // `_splitTopLevelPlus` returned the input unchanged, so that branch recursed
  // on the identical string until the stack blew. `buildProjectIR` catches
  // per-file, so the crash surfaced only as "this file has no IR" — 12 of 21 C#
  // corpus entries, and the catalog's own `cs-sqlcommand` rule ("SQL Injection
  // (new SqlCommand with concatenated user input)") could never fire.
  const newMatch = matchBalancedCall(s, /^new\s+([\w.]+)/, { skipGenerics: true });
  if (newMatch) {
    const callee = newMatch.callee.split('.').pop();
    const args = _splitTopLevelCommas(newMatch.argsText).map(_lowerExpr);
    return _followChain(s, newMatch.endIdx, callee, args, true);
  }
  // Call: foo.bar(args) or Bar(args). matchBalancedCall finds the paren
  // that actually balances the FIRST '(' — not the greedy-to-end-of-string
  // match the old `/\((.*)\)\s*$/` used, which corrupted the argument text
  // for a chained call (`Sanitize(x).Trim()` produced argsText="x).Trim(",
  // which then fell through to {kind:'unknown'} and silently dropped x).
  const callMatch = matchBalancedCall(s, /^([\w.]+)/);
  if (callMatch) {
    const args = _splitTopLevelCommas(callMatch.argsText).map(_lowerExpr);
    return _followChain(s, callMatch.endIdx, callMatch.callee, args, false);
  }
  // String concat / interpolation — heuristic.
  //
  // The `parts.length > 1` guard is load-bearing, not defensive tidiness: when
  // the `+` is nested inside parens or brackets, `_splitTopLevelPlus` returns
  // the input as a single part, and mapping `_lowerExpr` over it recurses on the
  // identical string forever. Any future expression form that reaches here
  // unsplit would otherwise reintroduce the same stack overflow.
  //
  // SARD 80% F1 push: this branch previously ALSO required a quote character
  // (`"`/`'`) to appear SOMEWHERE in `s` before even attempting the split —
  // meant to avoid misreading plain numeric addition (`a + b`) as string
  // concatenation, but it silently excluded the equally common shape where
  // BOTH operands are already-built string variables with no inline literal
  // (`Process.Start(osCommand + data)`, Juliet's own canonical C# CWE-78
  // shape — confirmed via the public Juliet C# mirror this project's SARD
  // manifest pins, not assumed). `osCommand + data` has no quote anywhere,
  // so the whole expression fell through every later branch to
  // `{kind:'unknown'}`, silently dropping `data`'s taint. Removed: treating
  // a numeric `a + b` as a 2-part template is harmless for taint purposes
  // (the engine only cares whether either operand is tainted, not whether
  // the runtime operation is numeric addition or string concatenation), and
  // the `rawParts.length > 1` guard immediately below already fully
  // prevents the specific stack-overflow this comment documents,
  // independent of whether a quote was ever present.
  if (s.includes('+')) {
    const rawParts = _splitTopLevelPlus(s);
    if (rawParts.length > 1) return { kind: 'tpl', parts: rawParts.map(_lowerExpr) };
  }
  // Stage 3 correctness audit (detection depth, per-language-IR):
  // interpolated strings ($"id={id}", $@"...", @$"...") were entirely
  // unrecognized by every branch above — not even treated as an opaque
  // literal, since nothing here tested for the leading `$` prefix — so
  // they fell all the way through to {kind:'unknown'}, silently dropping
  // any interpolated variable's taint. This is exactly
  // `new SqlCommand($"SELECT ... WHERE id={id}", conn)`, one of the most
  // common real C# SQL-injection shapes. `{expr}` / `{expr:format}` are
  // lowered into a template, same shape as the `+`-concat branch above.
  if (/^\$@?"/.test(s) || /^@\$"/.test(s)) {
    const bodyStart = s.indexOf('"') + 1;
    const inner = s.slice(bodyStart, -1);
    const re = /\{([^{}:]+)(?::[^{}]*)?\}/g;
    let lastIndex = 0;
    const parts = [];
    let matched = false;
    let m;
    while ((m = re.exec(inner)) !== null) {
      matched = true;
      if (m.index > lastIndex) parts.push({ kind: 'literal', value: inner.slice(lastIndex, m.index) });
      parts.push(_lowerExpr(m[1].trim()));
      lastIndex = re.lastIndex;
    }
    if (matched) {
      if (lastIndex < inner.length) parts.push({ kind: 'literal', value: inner.slice(lastIndex) });
      return { kind: 'tpl', parts };
    }
    return { kind: 'literal', value: s };
  }
  if (/^"|^@"/.test(s)) return { kind: 'literal', value: s };
  if (/^\d/.test(s))   return { kind: 'literal', value: s };
  return { kind: 'unknown' };
}

function _buildMemberChain(parts, indexer) {
  // [a, b, c]  →  member(member(ident a, b), c). If indexer, wrap as a final member.
  let cur = { kind: 'ident', name: parts[0] };
  for (let i = 1; i < parts.length; i++) cur = { kind: 'member', object: cur, prop: parts[i] };
  if (indexer) cur = { kind: 'member', object: cur, prop: indexer };
  return cur;
}

function _splitTopLevelCommas(s) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      buf += c;
      if (c === inStr && s[i-1] !== '\\') inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[' || c === '<') depth++;
    if (c === ')' || c === '}' || c === ']' || c === '>') depth--;
    if (c === ',' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function _splitTopLevelPlus(s) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      buf += c;
      if (c === inStr && s[i-1] !== '\\') inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
    if (c === '+' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

// Lower one C# statement to an IR node. `line` is the absolute file line.
function _lowerStmt(stmt, line) {
  const s = stmt.trim().replace(/^\s+/, '');
  if (!s || s.startsWith('//') || s.startsWith('/*')) return null;
  // return
  if (/^return\b/.test(s)) {
    const m = s.match(/^return\s*(.*?)\s*$/);
    const expr = m && m[1] ? _lowerExpr(m[1]) : null;
    return { kind: 'return', line, value: expr };
  }
  // throw
  if (/^throw\b/.test(s)) return { kind: 'throw', line, value: _lowerExpr(s.replace(/^throw\s*/, '')) };
  // compound assign: `x += y`  `x.y -= z`  etc. SARD_80_F1 W4.C11 — this
  // was previously unrecognized entirely (the plain-assign regex below
  // requires a literal `=` with nothing but `[\w.]` before it, which a
  // compound operator's own leading char, e.g. `+`, never satisfies), so
  // the whole statement fell through every branch in this function and
  // was silently dropped from the CFG — no assign, no call, nothing.
  // Juliet's C# corpus builds `CommandText` this way UNIVERSALLY
  // (`cmd.CommandText += "..." + tainted + "...";`), so this was a
  // total blackout for that shape, not a rare corner case.
  // Modeled as `x = x <op-without-'='> y` (a self-referencing binary),
  // NOT as a plain `x = y` reassignment — `case 'assign'` in engine.js
  // calls `removePathAndDescendants` on a clean RHS, and a naive
  // "just treat it like `=`" lowering would WRONGLY clear x's own
  // pre-existing taint whenever this particular append happens to be
  // clean (e.g. a literal SQL fragment appended after an earlier
  // tainted append). The self-reference makes taint the OR of "x was
  // already tainted" and "this RHS is tainted", which is what `+=`
  // actually means.
  const cm2 = s.match(/^([A-Za-z_][\w.]*)\s*(\+=|-=|\*=|\/=|%=|&=|\|=|\^=|<<=|>>=|\?\?=)\s*(.+)$/s);
  if (cm2) {
    const target = cm2[1];
    const rhs = _lowerExpr(cm2[3]);
    return {
      kind: 'assign', line, target,
      source: { kind: 'binary', op: cm2[2].slice(0, -1), left: { kind: 'ident', name: target }, right: rhs },
    };
  }
  // assign:   `var x = …`  `Type x = …`  `x = …`  `x.y = …`
  // The leading type/`var` clause is now its own capture group: when it's
  // present the regex engine could only have reached a valid overall match
  // by consuming a real type token before the target (a plain reassignment
  // like `data = other` never lets that branch match, per the backtracking
  // this file's other capture-group comments already document — the
  // optional group fails to close at any point before `=` when the target
  // itself carries no leading type). That gives a free, correct signal for
  // `decl` — a local variable's DECLARATION vs. a later reassignment —
  // needed by cross-method field-taint analysis to tell a genuine field
  // write (`sf = data;`, no type clause, class field) from a shadowing
  // local declaration of the same name.
  const m = s.match(/^(?:((?:var|[A-Za-z_][\w<>?,\s.]*))\s+)?([A-Za-z_][\w.]*?)\s*=\s*(.+)$/s);
  if (m) {
    const typeClause = m[1];
    const target = m[2];
    const sourceText = m[3];
    const node = { kind: 'assign', line, target, source: _lowerExpr(sourceText) };
    if (typeClause) {
      node.decl = true;
      // SARD_80_F1 W4 — mirrors parser-java.js's identical `declaredType`
      // field (see its own comment for the full rationale): the declared
      // TYPE of a local, not just the fact that this is a declaration.
      // Consumed by class-hierarchy.js's `typeOfVar` (ADDITIVE only, via
      // `receiverTypeIn` — never a destructive callee rewrite, per the
      // regression that mechanism caused for Java and was reverted).
      // Strips generics (`List<string>` -> `List`), array brackets
      // (`Foo[]` -> `Foo`), and a namespace-qualified prefix (last dot
      // segment); `var` is not a real type name and yields undefined.
      const bare = typeClause.replace(/<.*$/, '').replace(/\[\]$/, '').trim();
      if (bare && bare !== 'var') {
        const segs = bare.split('.');
        node.declaredType = segs[segs.length - 1];
      }
    }
    return node;
  }
  // Bare declaration with no initializer: `string data;`, `int i;`,
  // `List<T> xs;`. `_splitStatements` has already stripped the trailing
  // `;`, so a genuine no-initializer declaration is exactly two
  // whitespace-separated tokens (type, name) with none of `=(){}` anywhere
  // — no other valid C# statement shape looks like that. Modeled as an
  // assign with an unknown source (there is nothing to propagate yet) so
  // `decl:true` on it is visible to the same consumers that read the
  // initializer-bearing case above, rather than being silently absent as
  // an `unknown`-kind node.
  const declOnly = s.match(/^(?:var|[A-Za-z_][\w<>?[\],.]*?)\s+([A-Za-z_]\w*)$/);
  if (declOnly && !/[=(){}]/.test(s)) {
    return { kind: 'assign', line, target: declOnly[1], source: { kind: 'unknown' }, decl: true };
  }
  // statement-form call
  const cm = matchBalancedCall(s, /^([A-Za-z_][\w.]*)/);
  if (cm) {
    const chained = _followChain(s, cm.endIdx, cm.callee, _splitTopLevelCommas(cm.argsText).map(_lowerExpr), false);
    return { kind: 'call', line, callee: chained.callee, args: chained.args };
  }
  // Statement-form constructor-chained call: `new Helper().BadSink(data);`
  // — the inline-instantiate-and-call idiom, with NO assignment at all.
  // Previously fell through to `unknown` entirely (the statement-form
  // branch above requires the FIRST token to be a plain identifier, never
  // `new`) — silently dropping the call, its arguments, and any taint
  // reaching a sink inside the constructed object's method. Mirrors the
  // identical `new`-chain handling `_lowerExpr`'s expression path already
  // has (this statement-form path is otherwise a strict subset of that
  // one), and inherits `classMethods`'s cross-class resolution for free
  // once the chain's callee dot-joins to `ClassName.method`.
  const nm = matchBalancedCall(s, /^new\s+([\w.]+)/, { skipGenerics: true });
  if (nm) {
    const ctorArgs = _splitTopLevelCommas(nm.argsText).map(_lowerExpr);
    const chained = _followChain(s, nm.endIdx, nm.callee.split('.').pop(), ctorArgs, true);
    // A trailing `.Method(...)` grows `chained.callee` past the bare
    // constructor name (into `ClassName.Method`) — only THAT shape is a
    // call-kind statement worth reporting. A bare `new Helper();` with no
    // chained call has no observable side effect from this statement's own
    // perspective; fall through to `unknown`, matching this file's
    // existing "nothing to lower" convention for a no-op statement.
    if (chained.callee.includes('.')) return { kind: 'call', line, callee: chained.callee, args: chained.args };
  }
  // Parenthesised form of the same idiom: `(new Helper()).BadSink(data);`.
  // The statement-form call branch above anchors on an identifier and the
  // `new` branch anchors on the keyword, so a leading `(` matched neither
  // and the statement was dropped whole. `_lowerExpr` already understands
  // the shape; only a chained call (dotted callee) is worth a node.
  if (s.startsWith('(')) {
    const e = _lowerExpr(s);
    if (e.kind === 'call' && typeof e.callee === 'string' && e.callee.includes('.')) {
      return { kind: 'call', line, callee: e.callee, args: e.args };
    }
  }
  return { kind: 'unknown', line, text: s };
}

function _extractBody(src, openBrace) {
  // openBrace is the index of the '{' starting the method body.
  let depth = 1;
  let i = openBrace + 1;
  let inStr = null;
  let escape = false;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (escape) { escape = false; i++; continue; }
    if (inStr) {
      if (inStr === '"' && c === '\\') { escape = true; i++; continue; }
      if (c === inStr) inStr = null;
      i++; continue;
    }
    if (c === '"' || c === "'") { inStr = c; i++; continue; }
    if (c === '{') depth++;
    else if (c === '}') depth--;
    if (depth === 0) return { body: src.slice(openBrace + 1, i), end: i };
    i++;
  }
  return null;
}

function _lineAt(src, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < src.length; i++) if (src[i] === '\n') line++;
  return line;
}

function _qid(file, name, line, body, className) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  // `::ClassName::` middle segment — the SAME convention parser-java.js and
  // parser-js.js already use (see class-hierarchy.js's "Shape 2" and
  // callgraph.js's `classMethods` index, both of which parse exactly this
  // shape back out). Omitted (falls back to the pre-existing two-segment
  // form) when the method sits outside any class — legal C# top-level
  // statements — so that shape is unaffected.
  return className ? `${file}::${className}::${name}@${line}#${sha}` : `${file}::${name}@${line}#${sha}`;
}

// Node-id counter for `_buildCfg`. Reset to 0 per function (see
// `parseCSharpFile`) so ids stay `n0`, `n1`, ... within a single
// function's `cfg.nodes` — matching the pre-R8 flat loop's `n${idx}`
// naming convention, just keyed off a running node COUNT now rather than
// the original statement array's index (a single top-level statement, an
// `if` block, can now expand into many CFG nodes, so id generation can no
// longer be tied to statement position). Confirmed by grep that nothing
// in this file, its tests, or the dataflow engine depends on the exact
// string shape of these ids.
let _csNid = 0;
function _nextNodeId() { return `n${_csNid++}`; }

function _addNode(nodes, node) {
  const id = _nextNodeId();
  node.succ = node.succ || [];
  node.pred = node.pred || [];
  nodes[id] = node;
  return id;
}

function _linkNodes(nodes, src, dst) {
  if (!nodes[src] || !nodes[dst]) return;
  if (!nodes[src].succ.includes(dst)) nodes[src].succ.push(dst);
  if (!nodes[dst].pred.includes(src)) nodes[dst].pred.push(src);
}

// R8: recursive statement-splitting + CFG builder, replacing the previous
// flat single-pass loop. Ported from parser-cpp.js's `emit()` — the
// already-proven, working reference for exactly this shape of problem in
// this codebase's hand-rolled-parser style: match a leading control-flow
// keyword, balanced-scan its condition and its `{...}` body, and recurse
// ONLY into that matched body. Every other `}` (a collection initializer's
// or a lambda's) is left alone by this mechanism — see `_splitStatements`'
// header comment for why those are never mistaken for a control-flow
// body's close.
//
// Line numbers are computed EXACTLY, not approximated: `lineStarts` is
// built once, by the caller, from the function's whole (untouched) body
// text, and `baseAbs` is threaded through every recursive call as the
// absolute offset — within that SAME body text — of `bodyText[0]`. Every
// statement's line is then `funcStartLine + _lineForOffset(lineStarts,
// baseAbs + stmt.start) - 1`. Because `baseAbs` and every sub-offset used
// below (`afterHeader`, `lead`, matched-delimiter indices) are all
// measured directly against the statement's own text — which
// `_splitStatements` guarantees is a byte-for-byte contiguous slice of
// the original body from `stmt.start` onward (see that function's
// comment) — this cannot drift the way a newline-recount over
// already-trimmed/reconstructed text can. That drift is exactly what cost
// the PHP port of this same task 3 fix rounds; getting the exact-offset
// version right from the start avoids repeating it here.
function _buildCfg(bodyText, nodes, prevId, funcStartLine, lineStarts, baseAbs, depth = 0) {
  if (depth > 12) return prevId;
  let prev = prevId;
  for (const { text: s, start } of _splitStatements(bodyText)) {
    if (!s) continue;
    const absStart = baseAbs + start;
    const line = funcStartLine + _lineForOffset(lineStarts, absStart) - 1;

    // R8 fix round 1: `using (...) { }` and `lock (...) { }` were missing
    // from this alternation entirely — both lowered to a bogus
    // `call:using`/`call:lock` node via the generic `_lowerStmt` fallback,
    // with their `{...}` body text (including a paren argument list that
    // looks exactly like a call's) silently discarded. `using` is THE
    // canonical C#/ADO.NET wrapper around the exact sinks this task
    // targets (`SqlCommand`, `ExecuteReader`, file streams — anything
    // `IDisposable`), so this was a significant real-world gap: a sink
    // wrapped in `using` produced ZERO findings even after this task's
    // main fix, same as if it were wrapped in `if` before this task
    // existed at all. `using`/`lock` are deliberately NOT added to
    // `needsCond` below — unlike `if`/`while`/`for`/`switch`, their
    // parenthesised clause is a resource-acquisition declaration or a
    // lock target, not a boolean expression, so lowering it via
    // `_lowerExpr` would just produce `{kind:'unknown'}` and isn't worth
    // a synthetic node; the body — where the real sink-bearing statements
    // live — is what this fix makes reachable.
    const hm = s.match(/^(if|while|for|foreach|switch|else\s+if|else|do|try|catch|finally|using|lock)\b/);
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

      if (kwNorm === 'foreach' && condRaw !== null) {
        // `foreach (var x in xs)` / `foreach (Type x in xs)`. Unlike the
        // other headers below, foreach's parenthesised clause is not an
        // expression — it's a declaration — so it gets its own
        // loop-header node (no `cond`) plus, R8 fix-round lesson from
        // Java's for-each gap: a synthesized assign binding the loop
        // variable to the iterated collection BEFORE the body is
        // recursed into. Without this, the body is reachable but the
        // loop variable itself carries no taint provenance, so
        // `foreach (var id in ids) { sink(id); }` could never fire even
        // though `sink(x) { ... }` shapes elsewhere in the same function
        // do.
        const headerId = _addNode(nodes, { kind: 'loop-header', line });
        _linkNodes(nodes, prev, headerId);
        prev = headerId;
        const fm = condRaw.match(/^([\s\S]+?)\s+in\s+([\s\S]+)$/);
        if (fm) {
          const declPart = fm[1].trim();
          const loopVar = declPart.split(/\s+/).pop();
          const iterExpr = fm[2].trim();
          if (loopVar && /^[A-Za-z_]\w*$/.test(loopVar)) {
            const assignId = _addNode(nodes, { kind: 'assign', line, target: loopVar, source: _lowerExpr(iterExpr) });
            _linkNodes(nodes, prev, assignId);
            prev = assignId;
          }
        }
      } else if (kwNorm === 'using' && condRaw !== null) {
        // `using (SqlCommand cmd = new SqlCommand(query, conn)) { … }`: the
        // resource clause is a real declaration, and in ADO.NET it is where
        // the command text (the SQL-injection sink argument) is bound. It
        // was previously discarded with the header, so `cmd` had no
        // provenance and the constructor sink never saw its argument.
        // Lowered as an ordinary assign ahead of the body; a bare
        // expression clause (`using (GetLock())`) has no target and is
        // skipped as before.
        const declNode = _lowerStmt(condRaw.trim(), line);
        if (declNode && declNode.kind === 'assign') {
          const declId = _addNode(nodes, declNode);
          _linkNodes(nodes, prev, declId);
          prev = declId;
        }
      } else {
        const needsCond = /^(?:if|while|for|switch|else if|catch)$/.test(kwNorm);
        if (needsCond && condRaw !== null) {
          let condForNode = condRaw;
          let initRaw = null;
          if (kwNorm === 'for') {
            // `for (init; test; step)` — surface the test as the
            // condition and the init as a leading assign node (context
            // (a): a C# for-loop commonly initializes a loop variable
            // that the body then reads, e.g. `for (int i = 0; ...)`
            // followed by `arr[i]` inside the body — without this the
            // loop var's taint provenance is never established).
            const parts = _splitTopLevelSemi(condRaw);
            if (parts.length > 1) {
              initRaw = parts[0];
              condForNode = parts[1];
            }
          }
          const ifId = _addNode(nodes, { kind: 'if', line, cond: _lowerExpr(condForNode) });
          _linkNodes(nodes, prev, ifId);
          prev = ifId;
          if (kwNorm === 'for' && initRaw && initRaw.trim()) {
            const initNode = _lowerStmt(initRaw.trim(), line);
            if (initNode && initNode.kind === 'assign') {
              const initId = _addNode(nodes, initNode);
              _linkNodes(nodes, prev, initId);
              prev = initId;
            }
          }
        }
      }

      const rest = s.slice(afterHeader);
      const lead = rest.match(/^\s*/)[0].length;
      if (rest[lead] === '{') {
        const closeRel = _matchDelim(rest, lead, '{', '}');
        if (closeRel !== -1) {
          const innerBaseAbs = absStart + afterHeader + lead + 1;
          prev = _buildCfg(rest.slice(lead + 1, closeRel), nodes, prev, funcStartLine, lineStarts, innerBaseAbs, depth + 1);
        }
      } else if (rest.trim()) {
        const innerBaseAbs = absStart + afterHeader;
        prev = _buildCfg(rest, nodes, prev, funcStartLine, lineStarts, innerBaseAbs, depth + 1);
      }
      continue;
    }

    // A bare nested block `{ ... }` with no leading keyword.
    const bare = s.match(/^\{([\s\S]*)\}$/);
    if (bare) {
      const innerBaseAbs = absStart + 1;
      prev = _buildCfg(bare[1], nodes, prev, funcStartLine, lineStarts, innerBaseAbs, depth + 1);
      continue;
    }

    const node = _lowerStmt(s, line);
    if (!node) continue;
    const id = _addNode(nodes, node);
    _linkNodes(nodes, prev, id);
    prev = id;
  }
  return prev;
}

export function parseCSharpFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  const functions = [];
  const classRanges = _findClassRanges(code);
  METHOD_RE.lastIndex = 0;
  let m;
  while ((m = METHOD_RE.exec(code)) !== null) {
    const name = m[2];
    const className = _enclosingClassName(classRanges, m.index);
    const paramsText = m[3] || '';
    const paramAnnotations = [];
    const paramTypes = {};
    // `keptIdx` tracks the parameter's position in the FILTERED array — the
    // same array `fn.params` ends up being — not the raw pre-filter split
    // position (`idx` below). It only advances when a fragment actually
    // yields a kept parameter name, so an empty/unparseable comma fragment
    // ahead of an annotated parameter doesn't shift that parameter's
    // recorded `index` off of its real position in `fn.params`. R14(a)
    // final-review fix: Java (`parser-java.js`) and JS/TS (`parser-js.js`)
    // both already compute `index` this way (position in the final
    // `fn.params`, per the plan's Global Constraints); C# was the only one
    // of the three using the raw split index, which silently diverges
    // whenever an earlier fragment is filtered out. Nothing reads
    // `paramAnnotations[i].index` today (confirmed by grep), so this was
    // latent — but the field is kept for future k>1 call-string work, so a
    // silently-wrong producer here would become a real bug once something
    // starts consuming it.
    let keptIdx = 0;
    const params = paramsText.split(',').map((p, idx) => {
      const t = p.trim();
      if (!t) return null;
      // Extract ALL leading [AttributeName] or [AttributeName(...)] patterns (stacked or not).
      // R14(a) Task 6 fix round 1: an earlier version of this regex used one
      // optional `(?:\(...\))?` group with a `\s*` on each side, which left
      // two independent quantifiers both able to consume the same
      // whitespace run on a failed match (no closing `]`) — classic
      // adjacent-quantifier ReDoS, confirmed quadratic (n=32000 chars took
      // ~600ms; caught by this repo's own self-scan gate against its own
      // new code). Rather than accept the engine's own `safe-regex`-backed
      // heuristic flagging a merely-restructured-but-still-single-group
      // version (it does — confirmed empirically linear but still flagged),
      // this instead follows this repo's own precedent (commit `6bd394c`,
      // `class-hierarchy.js`'s qid-tail-stripping fix): split into two
      // alternatives — no-args and with-args — so no quantifier has two
      // ways to consume the same text. Each alternative independently
      // passes `safe-regex`, avoiding reliance on any one detector's
      // judgment call. Verified O(n) (n=256000 chars in well under 1ms)
      // with identical matches on every real attribute shape (stacked,
      // spaced, empty-arg) against the prior single-group version.
      const attrRegex = /^\[\s*([A-Za-z_]\w*)\s*\]|^\[\s*([A-Za-z_]\w*)\s*\([^)]*\)\s*\]/;
      let remaining = t;
      let match;
      const decorators = [];
      while ((match = attrRegex.exec(remaining)) !== null) {
        decorators.push(match[1] || match[2]);
        remaining = remaining.slice(match[0].length).trim();
      }
      // "Type name" → name. "Type<T> name" → name. "Type[] name = default" → name.
      const beforeDefault = remaining.replace(/=.*$/, '').trim();
      const nameTokens = beforeDefault.split(/\s+/);
      const last = nameTokens.pop();
      const paramName = last && /^[A-Za-z_][\w]*$/.test(last) ? last : null;
      // Declared TYPE (SARD_80_F1 W4 — same rationale as parser-java.js's
      // `paramTypes`/parser-cs.js's own local-var `declaredType` above):
      // Web Forms' dominant `Render(HtmlTextWriter writer)` override idiom
      // is a PARAMETER, not a local declaration, and a param's type was
      // never captured before this. `nameTokens` (everything before the
      // param name, after stripping attributes and a default value) is
      // the type clause — `ref`/`out`/`params`/`in` modifiers are stripped
      // as bare keywords, generics/arrays reduced to the base name, same
      // normalization as the local-variable case.
      let paramType;
      if (paramName && nameTokens.length) {
        const typeText = nameTokens.filter(w => !/^(?:ref|out|params|in|this)$/.test(w)).join(' ');
        const bare = typeText.replace(/<.*$/, '').replace(/\[\]$/, '').trim();
        if (bare && bare !== 'var') {
          const segs = bare.split('.');
          paramType = segs[segs.length - 1];
        }
      }
      // Add an entry for each decorator found, indexed by position in the
      // FILTERED params array (see `keptIdx` comment above) — not `idx`,
      // the raw pre-filter split position.
      if (paramName) {
        for (const decorator of decorators) {
          paramAnnotations.push({ index: keptIdx, name: paramName, decorator });
        }
        if (paramType) paramTypes[paramName] = paramType;
        keptIdx++;
      }
      return paramName;
    }).filter(Boolean);
    const braceIdx = code.indexOf('{', m.index + m[0].length - 1);
    if (braceIdx < 0) continue;
    const extracted = _extractBody(code, braceIdx);
    if (!extracted) continue;
    const startLine = _lineAt(code, m.index);
    // R8 (lesson learned from the PHP port of this task, fix round 3): the
    // body's own start line must be derived from `braceIdx` — the
    // method's ACTUAL opening `{` — not approximated as `startLine + 1`.
    // `startLine` (above) is the line of the METHOD DECLARATION match,
    // which only happens to be one line before the body for a same-line
    // signature; a multi-line signature or Allman brace style would make
    // that approximation wrong by however many lines the signature spans.
    const bodyStartLine = _lineAt(code, braceIdx + 1);
    // Built once per function body; `_buildCfg` looks up every node's
    // line in O(log n) via `_lineForOffset` against this SAME array — see
    // `_buildCfg`'s header comment for why this (not per-statement
    // newline-recounting) is what keeps line numbers exact through
    // arbitrarily deep recursion.
    const lineStarts = _lineStarts(extracted.body);
    // Build the CFG: entry → (recursive statement/control-flow walk) → exit.
    const nodes = {};
    nodes.entry = { kind: 'entry', line: startLine, succ: [], pred: [] };
    nodes.exit  = { kind: 'exit',  line: startLine, succ: [], pred: [] };
    _csNid = 0;
    const tail = _buildCfg(extracted.body, nodes, 'entry', bodyStartLine, lineStarts, 0, 0);
    nodes[tail].succ.push('exit');
    nodes.exit.pred.push(tail);
    _applyVarTypeRewrite(nodes);
    const cfg = { entry: 'entry', exit: 'exit', nodes };
    functions.push({
      qid: _qid(file, name, startLine, extracted.body, className),
      name: className ? `${className}.${name}` : name, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
      ...(paramAnnotations.length ? { paramAnnotations } : {}),
      ...(Object.keys(paramTypes).length ? { paramTypes } : {}),
    });
    METHOD_RE.lastIndex = extracted.end + 1;
  }
  const classes = classRanges.map(r => ({
    name: r.name,
    line: r.line,
    bases: r.bases,
    fields: _extractClassFields(code, r),
  }));
  return { file, functions, classes, topLevel: null };
}
