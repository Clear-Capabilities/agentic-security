// Kotlin IR frontend (v0.66).
//
// Regex-based, pragmatic, focused on Spring / Ktor / Exposed / java.io
// surface area. Parallel approach to parser-cs.js (C#).
//
// What we model:
//   - top-level functions: `fun name(params): RetType { body }`
//   - member functions: `fun Class.name(params) { body }` (extension fns)
//   - assignments: `val x = …`  `var x = …`  `x = …`
//   - calls (statement-form): `obj.method(args)` / `method(args)`
//   - return: `return expr`
//   - control flow (R8): `if`/`else`/`else if`/`while`/`for`/`when`/`do`/
//     `try`/`catch`/`finally` bodies are recursed into by `_buildCfg`
//     (ported from parser-cs.js's proven keyword+balanced-scan+recurse
//     pattern), so a sink several levels deep inside a braced body is
//     reachable. A `for (x in xs)` header binds the loop variable to the
//     iterated collection before the body is recursed into, so the loop
//     variable itself carries taint provenance (same lesson as C#'s
//     `foreach` and Java's for-each). A `when (subject) { pattern -> rhs
//     … }` block is NOT recursed into via the generic keyword scan — its
//     arms are pattern-matched separately (see `_buildWhenArms`) because a
//     `when` arm's default label is the bare word `else`, which collides
//     with `if`/`else` chaining if run through the same generic matcher.
//     Line numbers through this recursion are computed via exact
//     character-offset lookup (`_lineStarts`/`_lineForOffset`), not
//     approximated.
//
// What we do NOT model:
//   - lambdas (collapsed to opaque expression) — this now explicitly
//     includes Kotlin's idiomatic trailing-lambda call syntax
//     (`xs.forEach { x -> … }`, `xs.reduce(0) { acc, x -> … }`): the call
//     itself is captured as a `call` node (so the call SITE is visible),
//     but the lambda body is not parsed, matching this file's pre-existing
//     scope limit for parenthesized lambda arguments elsewhere. This is a
//     deliberate scope boundary, not an oversight: `.use { }`,
//     `synchronized(lock) { }`, `run { }`, `apply { }`, `let { }` and
//     dozens of other Kotlin stdlib scope functions are ALL syntactically
//     identical — a plain function call with a trailing-lambda argument,
//     not language keyword syntax — so there is no reliable way for a
//     keyword-headed regex matcher (which is what `_buildCfg` is) to single
//     out `synchronized` from `run`/`apply`/`let`/`.use` without arbitrarily
//     privileging one function name over dozens of equally common ones.
//     This differs from C#'s `using`/`lock`, which the C# parser DOES
//     recurse into, because those are real C# keyword-headed statement
//     grammar, syntactically distinguishable from an ordinary method call.
//   - destructuring `val (a, b) = pair`, including a destructured `for
//     ((k, v) in map)` loop-variable binding (the loop body is still
//     recursed into; only the per-variable taint binding is skipped)
//   - `when` branch/pattern semantics: an arm's PATTERN (`1`, `is Foo`,
//     `in 1..5`) is not lowered or evaluated — only its right-hand-side
//     statement is. Matches this task's "recurse into bodies, don't model
//     branching semantics" scope, same as `if`/`try`/`catch` elsewhere in
//     this file.
//   - infix functions (the call shape isn't recognized)
//   - operator overloading
//   - control-flow BRANCHING semantics generally: `if`/`else`, `when` arms,
//     and `try`/`catch`/`finally` clauses are each recursed into and linked
//     SEQUENTIALLY (the same "linear but complete" approximation
//     parser-cs.js and parser-cpp.js use) rather than as alternative paths —
//     every branch's body is reachable in the CFG, which is what taint
//     analysis needs, but the graph does not model that only one branch
//     executes per run.
//
// Single-pass v1 lowering of leaf statements; the CFG shape above it is now
// recursive (R8). Roslyn/PSI-equivalent for Kotlin (kotlinc -p ir or PSI via
// gradle helper) is the upgrade path.

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';
import { matchBalancedCall } from './balanced-call.js';

const FUN_RE = new RegExp(
  '(?:^|[\\s;{}])(?:public|private|internal|protected|inline|suspend|tailrec|operator|infix|open|abstract|override|final|external)?' +
  '(?:\\s+(?:public|private|internal|protected|inline|suspend|tailrec|operator|infix|open|abstract|override|final|external))*' +
  '\\s*fun\\s+(?:[A-Za-z_][\\w.]*\\.)?' +              // optional receiver-type prefix
  '([A-Za-z_][\\w]*)' +                                // function name (group 1)
  '\\s*\\(([^)]*)\\)' +                                // params (group 2)
  '\\s*(?::\\s*[A-Za-z_][\\w<>?,\\s.]*)?\\s*\\{', 'g'); // optional return type then '{'

// R8: reused UNCHANGED by the new recursive `_buildCfg` below — this
// splitter already flushes on `\n` OR `;` at depth 0 (Kotlin has no
// C#-style `;`-only statement terminator), which is exactly the
// granularity `_buildCfg` needs. Because it does NOT also flush on a `}`
// returning to depth 0 (unlike parser-cs.js's R8-updated splitter), a
// single returned statement can itself be a CHAIN of glued keyword-headed
// constructs when they share a line in the common formatting style (`if
// (x) { … } else { … }`, `try { … } catch (…) { … } finally { … }`) — the
// `}` and the continuation keyword never straddle a depth-0 newline, so no
// flush point falls between them. `_buildCfg`'s inner chain loop
// (`_consumeChunk`) is what walks forward through such a glued statement,
// consuming one keyword-headed construct at a time.
function _splitStatements(body) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  let escape = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (escape) { buf += c; escape = false; continue; }
    if (inStr) {
      buf += c;
      if (inStr === '"' && c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; buf += c; continue; }
    if (c === '{' || c === '(' || c === '[') depth++;
    if (c === '}' || c === ')' || c === ']') depth--;
    // Kotlin uses newlines OR semicolons as statement separators.
    if ((c === '\n' || c === ';') && depth === 0) {
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

function _buildMemberChain(parts) {
  let cur = { kind: 'ident', name: parts[0] };
  for (let i = 1; i < parts.length; i++) cur = { kind: 'member', object: cur, prop: parts[i] };
  return cur;
}

// Taint-recall PRD (80%): same architectural fix as parser-cs.js/
// parser-go.js/parser-php.js/parser-rb.js — a chained call
// (`ScriptEngineManager().getEngineByName("js").eval(userCode)`) previously
// stopped at (or, here, actively corrupted the parse at) the FIRST call,
// leaving `.method(args)` continuations unconsumed or garbled. Args from
// EVERY level are kept, outermost-first — a first version kept only the
// outermost, which broke `xp.compile(taintedExpr).evaluate(doc,
// XPathConstants.NODESET)`: the tainted value sits on the INNER call
// (.compile), not the final one, and keeping only the outer args (doc,
// NODESET) silently dropped it — see parser-cs.js's twin function for the
// full reasoning.
function _followChain(s, endIdx, calleeSoFar, argsSoFar) {
  const rest = s.slice(endIdx);
  const outer = matchBalancedCall(rest, /^\.(\w+)/);
  if (!outer) return { kind: 'call', callee: calleeSoFar, args: argsSoFar };
  const outerArgs = _splitTopLevelCommas(outer.argsText).map(_lowerExpr);
  return _followChain(rest, outer.endIdx, `${calleeSoFar}.${outer.callee}`, outerArgs.concat(argsSoFar));
}

function _lowerExpr(text) {
  const s = String(text || '').trim();
  if (!s) return { kind: 'unknown' };
  // String interpolation: "hi $x" / "hi ${name}".
  if (/^".*"$/.test(s) && /\$/.test(s)) {
    const parts = [];
    const re = /\$\{([^}]+)\}|\$([A-Za-z_]\w*)/g;
    let last = 0;
    let m;
    while ((m = re.exec(s)) !== null) {
      if (m.index > last) parts.push({ kind: 'literal', value: s.slice(last, m.index) });
      parts.push(_lowerExpr((m[1] || m[2]).trim()));
      last = re.lastIndex;
    }
    if (last < s.length) parts.push({ kind: 'literal', value: s.slice(last) });
    return { kind: 'tpl', parts };
  }
  // Plain dotted ident
  if (/^[A-Za-z_][\w.]*$/.test(s)) {
    const parts = s.split('.');
    if (parts.length === 1) return { kind: 'ident', name: parts[0] };
    return _buildMemberChain(parts);
  }
  // Call. Taint-recall PRD (80%): this used to be the naive
  // `/^([\w.]+)\s*\((.*)\)\s*$/s` pattern every OTHER hand-rolled parser
  // (cs/go/php/rb) also started with and has since moved off of —
  // `(.*)` matches GREEDILY against the LAST `)` in the string, not the
  // one balancing the FIRST `(`, so a chained call
  // (`ScriptEngineManager().getEngineByName("js").eval(userCode)`)
  // corrupted the args text into garbage rather than just dropping the
  // chain. Kotlin never got migrated to matchBalancedCall when the other
  // four were — confirmed via a real corpus fixture (this exact
  // ScriptEngineManager shape). Now uses the same balanced-scan +
  // chain-following approach: only the OUTERMOST call's own arguments are
  // kept (see parser-cs.js's _followChain comment for why), each level's
  // name dot-joined into one callee string.
  const callMatch = matchBalancedCall(s, /^([\w.]+)/);
  if (callMatch) {
    const args = _splitTopLevelCommas(callMatch.argsText).map(_lowerExpr);
    return _followChain(s, callMatch.endIdx, callMatch.callee, args);
  }
  // Concat
  if (s.includes('+') && /["']/.test(s)) {
    return { kind: 'tpl', parts: _splitTopLevelPlus(s).map(_lowerExpr) };
  }
  if (/^"/.test(s) || /^\d/.test(s)) return { kind: 'literal', value: s };
  return { kind: 'unknown' };
}

function _lowerStmt(stmt, line) {
  const s = stmt.trim();
  if (!s || s.startsWith('//') || s.startsWith('/*') || s.startsWith('*')) return null;
  if (/^return\b/.test(s)) {
    const m = s.match(/^return\s*(.*?)\s*$/);
    return { kind: 'return', line, value: m && m[1] ? _lowerExpr(m[1]) : null };
  }
  if (/^throw\b/.test(s)) {
    return { kind: 'throw', line, value: _lowerExpr(s.replace(/^throw\s*/, '')) };
  }
  // Variable declarations: val/var name [: Type] = expr
  const decl = s.match(/^(?:val|var)\s+([A-Za-z_]\w*)\s*(?::\s*[\w<>?,\s.]*?)?\s*=\s*(.+)$/s);
  if (decl) return { kind: 'assign', line, target: decl[1], source: _lowerExpr(decl[2]) };
  // Plain assign: x = expr  (also x.y = expr)
  const assign = s.match(/^([A-Za-z_][\w.]*)\s*=\s*(.+)$/s);
  if (assign && !/[=!<>]=/.test(s.slice(0, s.indexOf('=')+1).slice(0, -1))) {
    return { kind: 'assign', line, target: assign[1], source: _lowerExpr(assign[2]) };
  }
  // Statement-form call — same matchBalancedCall + chain-following as the
  // expression-form case above (Taint-recall PRD 80%).
  const cm = matchBalancedCall(s, /^([\w.]+)/);
  if (cm) {
    const chained = _followChain(s, cm.endIdx, cm.callee, _splitTopLevelCommas(cm.argsText).map(_lowerExpr));
    return { kind: 'call', line, callee: chained.callee, args: chained.args };
  }
  // R8: trailing-lambda call — `recv.method(args)? { lambda }`, Kotlin's
  // idiomatic collection-operator / scope-function syntax
  // (`xs.forEach { x -> … }`, `xs.reduce(0) { acc, x -> … }`). Without this
  // branch the statement fell all the way through to `unknown` (verified:
  // this is NOT the same shape the ordinary call regex above already
  // handles — that regex requires the statement to END in `)`, but a
  // trailing-lambda statement ends in `}` with no enclosing parens around
  // the lambda at all, unlike C#'s `xs.ForEach(x => { … })` where the
  // lambda sits INSIDE a real paren argument list). The lambda body is
  // collapsed to an opaque expression — see this module's header comment
  // for why `.use{}`/`synchronized(){}`/etc are deliberately not recursed
  // into — so only the call's own identity (callee + any non-lambda args)
  // is modeled; that is enough to keep the call SITE visible instead of
  // silently vanishing.
  //
  // R8 fix round (found by this task's own bench:self-scan:check, the exact
  // same defect class as R14(a)'s C# `attrRegex` ReDoS): the original single
  // pattern here had an optional paren group sandwiched between two `\s*`
  // quantifiers (`\s*(\([^()]*\))?\s*`) — on a failing match, the engine can
  // partition a run of whitespace between the two `\s*`s in exponentially
  // many ways, confirmed genuinely quadratic (200,000-char adversarial input:
  // ~1.7s at 20,000 chars, extrapolating far higher at realistic file sizes).
  // Restructured into two mutually-exclusive alternatives — no-parens and
  // with-parens — exactly as `class-hierarchy.js` (commit `6bd394c`) and the
  // C# fix (PRD R14(a)) both did for the identical shape: a REQUIRED group
  // between two `\s*`s has no such ambiguity, because the parser is not
  // choosing whether to consume the group, only where the group starts.
  // Re-verified linear (200,000 chars: ~3ms) and byte-identical to the old
  // pattern's output across a 15-shape sweep (calls with/without args, no
  // parens at all, multi-segment callee, non-matching text, unbalanced
  // parens, empty body).
  const trailingNoParens = s.match(/^([\w.]+)\s*\{[\s\S]*\}\s*$/);
  const trailingWithParens = trailingNoParens ? null : s.match(/^([\w.]+)\s*(\([^()]*\))\s*\{[\s\S]*\}\s*$/);
  const trailing = trailingNoParens || trailingWithParens;
  if (trailing) {
    const parenGroup = trailingWithParens ? trailingWithParens[2] : null;
    const argsText = parenGroup ? parenGroup.slice(1, -1) : '';
    return { kind: 'call', line, callee: trailing[1], args: argsText ? _splitTopLevelCommas(argsText).map(_lowerExpr) : [] };
  }
  return { kind: 'unknown', line, text: s };
}

// Build a sorted array of line-start offsets for `text` (index 0 holds the
// start of line 1, i.e. always 0). Paired with `_lineForOffset` to turn a
// character offset into an exact 1-based line number in O(log n) — ported
// verbatim from parser-cs.js / parser-cpp.js, the proven reference for this
// exact-offset-based line computation pattern.
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

function _lineForAbs(lineStarts, funcStartLine, abs) {
  return funcStartLine + _lineForOffset(lineStarts, abs) - 1;
}

// Find the index of the delimiter in `openCh`/`closeCh` that matches the
// one at `openIdx`, respecting nesting and skipping string-literal content.
// Returns -1 if unmatched. Ported verbatim from parser-cs.js.
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

// R8 lesson from the PHP port of this task (fix round covering a comment
// between `}` and a continuation keyword defeating a whitespace-only
// lookahead): skip BOTH whitespace and `//`/`/* */` comments, not just
// whitespace, wherever `_consumeChunk` needs to look past a `}` for a
// possible continuation keyword (`else`, `catch`, `finally`) or past a
// header's closing `)` for its opening `{`. Kotlin's shared statement
// splitter (`_splitStatements`) does not strip comments the way
// parser-cs.js's does, so a comment sitting between a control-flow body's
// close and its continuation is genuinely reachable here, not merely
// hypothetical.
function _skipWsComments(s, i) {
  for (;;) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (s[i] === '/' && s[i + 1] === '/') {
      while (i < s.length && s[i] !== '\n') i++;
      continue;
    }
    if (s[i] === '/' && s[i + 1] === '*') {
      i += 2;
      while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) i++;
      if (i < s.length) i += 2;
      continue;
    }
    break;
  }
  return i;
}

// Find the first top-level `->` in a `when` arm's text (its arm separator,
// `pattern -> statement`), respecting string literals and nested
// parens/brackets/braces (a pattern can be `is Foo(1, 2)` or a range
// `in 1..5`, and an arm's RHS can itself be a `{ … }` block). Returns -1 if
// none is found (a malformed/unsupported arm shape — the caller skips it;
// this parser does not model `when` pattern semantics, only the RHS body).
function _findTopLevelArrow(s) {
  let depth = 0, inStr = null, escape = false;
  for (let i = 0; i < s.length - 1; i++) {
    const c = s[i];
    if (escape) { escape = false; continue; }
    if (inStr) {
      if (inStr === '"' && c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') depth--;
    else if (depth === 0 && c === '-' && s[i + 1] === '>') return i;
  }
  return -1;
}

// Node-id counter for `_buildCfg`. Reset to 0 per function (see
// `parseKotlinFile`) so ids stay `n0`, `n1`, ... within a single function's
// `cfg.nodes` — matching the pre-R8 flat loop's `n${idx}` naming
// convention, just keyed off a running node COUNT now rather than the
// original statement array's index (a single top-level statement, an `if`
// block, can now expand into many CFG nodes, so id generation can no
// longer be tied to statement position).
let _ktNid = 0;
function _nextNodeId() { return `n${_ktNid++}`; }

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

const HEADER_RE = /^(if|while|for|when|else\s+if|else|do|try|catch|finally)\b/;
const NEEDS_COND_RE = /^(?:if|while|when|else if|catch)$/;

// Taint-engine PRD P1: trailing-lambda body recursion. Detects the START of
// a `recv.method(args)? { … }` call — deliberately NOT the whole statement
// (the pre-P1 `_lowerStmt` trigger's `[\s\S]*\}\s*$` greedy tail is exactly
// what mis-captured a chained `xs.filter { … }.forEach { … }` as one big
// opaque lambda with the wrong callee). `_matchDelim` finds the REAL
// matching `}` from here, the same balanced-scan primitive every keyword
// branch below already uses.
//
// Split into two alternatives — no-args and with-args — rather than one
// optional group between two `\s*`s: `bench:self-scan:check` caught this
// exact shape as a genuine quadratic ReDoS (confirmed by direct timing:
// 40000 whitespace chars with no trailing `{` took ~1s), the identical
// defect class this file's own R8 task already fixed once (see the CLAUDE.md
// note on the sibling `decl` regex) and parser-cs.js's `attrRegex` fixed the
// same way. Each alternative has its own capture group for the callee name
// (`m[1]`/`m[2]`); only one is ever set.
const TRAILING_LAMBDA_TRIGGER_RE = /^([\w.]+)\s*\{|^([\w.]+)\s*(\([^()]*\))\s*\{/;

// Stdlib scope functions whose lambda receives the RECEIVER (or an element
// of it) as its own parameter — these get a synthesized taint-binding
// assign before the body is recursed into, mirroring the for-loop's
// loop-variable binding immediately below. `reduce`/`fold` pass BOTH an
// accumulator and an element; this codebase's recall-preserving doctrine
// (favor a false positive over a silent false negative — see catalog.js's
// sanitizer-recording comment for the same tradeoff) argues for binding
// every declared param to the receiver rather than trying to disambiguate
// which one is the actual element.
//
// Deliberately EXCLUDED: `apply`/`run` — these pass the receiver as an
// IMPLICIT `this`, not a named/`it` lambda parameter (`T.() -> R`, not
// `T.(T) -> R`), so there is nothing to bind here without modeling
// implicit-receiver member calls. Their bodies are still recursed into
// below (so an already-tainted OUTER variable referenced inside still
// works), just without receiver-as-param binding — a real, documented
// scope boundary, not a silent gap.
const LAMBDA_BINDABLE_METHODS = new Set(['forEach', 'map', 'filter', 'reduce', 'fold', 'use', 'let', 'also']);

// R8: recursive statement handler. `s` is ONE element returned by
// `_splitStatements` — which, because Kotlin's splitter (unlike C#'s) does
// not flush on a `}` reaching depth 0, may itself be a CHAIN of glued
// keyword-headed constructs (`if (x) { … } else { … }`,
// `try { … } catch (…) { … } finally { … }`) when they share a source line
// in the common formatting style. This walks forward through `s`,
// consuming one keyword-headed construct at a time and recursing into its
// body, until no further continuation keyword is found immediately after
// the previous construct's closing brace; genuinely leftover non-keyword
// text (rare) is lowered as its own statement rather than silently
// dropped. `abs0` is the absolute offset — within the function's whole,
// untouched body text — of `s[0]`; every position derived below is
// `abs0 + <offset within s>`, never re-approximated.
function _consumeChunk(s, abs0, nodes, prevId, funcStartLine, lineStarts, depth) {
  if (depth > 12) return prevId;
  let prev = prevId;
  let pos = 0;
  let first = true;
  for (;;) {
    const skipTo = _skipWsComments(s, pos);
    const rest = s.slice(skipTo);
    const hm = rest.match(HEADER_RE);
    if (!hm) {
      // Taint-engine PRD P1: trailing-lambda body recursion. Checked before
      // falling through to a leaf statement — `HEADER_RE` never matches an
      // identifier-starting trailing-lambda call, so there is no ambiguity
      // between the two triggers.
      const lambdaMatch = rest.match(TRAILING_LAMBDA_TRIGGER_RE);
      if (lambdaMatch) {
        const braceIdxInS = skipTo + lambdaMatch[0].length - 1; // index of '{' within s
        const closeRel = _matchDelim(s, braceIdxInS, '{', '}');
        if (closeRel !== -1) {
          first = false;
          const callee = lambdaMatch[1] || lambdaMatch[2];
          const parenGroup = lambdaMatch[3] || null;
          const argsText = parenGroup ? parenGroup.slice(1, -1) : '';
          const callArgs = argsText ? _splitTopLevelCommas(argsText).map(_lowerExpr) : [];
          const line = _lineForAbs(lineStarts, funcStartLine, abs0 + skipTo);
          const callId = _addNode(nodes, { kind: 'call', line, callee, args: callArgs });
          _linkNodes(nodes, prev, callId);
          prev = callId;

          const dot = callee.lastIndexOf('.');
          // A leading-dot callee (`.forEach { … }`, the second link of a
          // CHAINED trailing lambda like `xs.filter{}.forEach{}`) yields an
          // empty receiver here — deliberately falls into the same
          // no-binding path as .apply/.run below, since there is no real
          // identifier to bind from (the true receiver is the previous
          // lambda's return value, which this file does not model as a
          // synthetic variable). The call site and body are still captured.
          const receiver = dot > 0 ? callee.slice(0, dot) : null;
          const method = dot >= 0 ? callee.slice(dot + 1) : callee;

          const bodyInner = s.slice(braceIdxInS + 1, closeRel);
          const bodyAbs0 = abs0 + braceIdxInS + 1;

          if (receiver && LAMBDA_BINDABLE_METHODS.has(method)) {
            const arrowIdx = _findTopLevelArrow(bodyInner);
            const paramNames = arrowIdx >= 0
              ? bodyInner.slice(0, arrowIdx).split(',').map(p => p.trim()).filter(p => /^[A-Za-z_]\w*$/.test(p))
              : ['it'];
            for (const p of paramNames) {
              const assignId = _addNode(nodes, { kind: 'assign', line, target: p, source: _lowerExpr(receiver) });
              _linkNodes(nodes, prev, assignId);
              prev = assignId;
            }
            const recurseFrom = arrowIdx >= 0 ? arrowIdx + 2 : 0;
            prev = _buildCfg(bodyInner.slice(recurseFrom), nodes, prev, funcStartLine, lineStarts, bodyAbs0 + recurseFrom, depth + 1);
          } else {
            // .apply/.run, a chained continuation, or an unlisted scope
            // function: body still reachable, no param binding.
            prev = _buildCfg(bodyInner, nodes, prev, funcStartLine, lineStarts, bodyAbs0, depth + 1);
          }
          pos = closeRel + 1;
          if (pos >= s.length || depth > 12) return prev;
          continue;
        }
      }
      if (first) {
        return _lowerLeafOrBlock(s, abs0, nodes, prev, funcStartLine, lineStarts, depth);
      }
      if (rest.trim()) {
        prev = _lowerLeafOrBlock(rest, abs0 + skipTo, nodes, prev, funcStartLine, lineStarts, depth);
      }
      return prev;
    }
    first = false;
    const kwNorm = hm[1].replace(/\s+/g, ' ').trim();
    const line = _lineForAbs(lineStarts, funcStartLine, abs0 + skipTo);

    let p = skipTo + hm[0].length;
    p = _skipWsComments(s, p);
    let condRaw = null, afterHeader = p;
    if (s[p] === '(') {
      const closeIdx = _matchDelim(s, p, '(', ')');
      if (closeIdx !== -1) {
        condRaw = s.slice(p + 1, closeIdx);
        afterHeader = closeIdx + 1;
      }
    }

    if (kwNorm === 'for' && condRaw !== null) {
      // `for (x in xs)` — Kotlin's only `for` shape is a for-each; there is
      // no C-style `for (init; test; step)`. The parenthesised clause is a
      // declaration, not an expression, so it gets its own loop-header node
      // (no `cond`) plus — R8 lesson from Java's for-each gap — a
      // synthesized assign binding the loop variable to the iterated
      // collection BEFORE the body is recursed into, so the loop variable
      // itself carries taint provenance.
      const headerId = _addNode(nodes, { kind: 'loop-header', line });
      _linkNodes(nodes, prev, headerId);
      prev = headerId;
      const fm = condRaw.match(/^([\s\S]+?)\s+in\s+([\s\S]+)$/);
      if (fm) {
        const declPart = fm[1].trim();
        // Destructured loop var (`for ((k, v) in map)`) is out of scope —
        // same "destructuring not modeled" limit this file's header
        // documents for `val (a, b) = pair`; skip the binding, still
        // recurse into the body below.
        if (!/^\(/.test(declPart)) {
          const loopVar = declPart.replace(/:\s*[\w<>?,\s.]+$/, '').trim();
          const iterExpr = fm[2].trim();
          if (loopVar && /^[A-Za-z_]\w*$/.test(loopVar)) {
            const assignId = _addNode(nodes, { kind: 'assign', line, target: loopVar, source: _lowerExpr(iterExpr) });
            _linkNodes(nodes, prev, assignId);
            prev = assignId;
          }
        }
      }
    } else if (NEEDS_COND_RE.test(kwNorm) && condRaw !== null) {
      const ifId = _addNode(nodes, { kind: 'if', line, cond: _lowerExpr(condRaw) });
      _linkNodes(nodes, prev, ifId);
      prev = ifId;
    }

    const restIdx = _skipWsComments(s, afterHeader);
    if (s[restIdx] === '{') {
      const closeRel = _matchDelim(s, restIdx, '{', '}');
      if (closeRel !== -1) {
        const innerAbs0 = abs0 + restIdx + 1;
        if (kwNorm === 'when') {
          prev = _buildWhenArms(s.slice(restIdx + 1, closeRel), nodes, prev, funcStartLine, lineStarts, innerAbs0, depth + 1);
        } else {
          prev = _buildCfg(s.slice(restIdx + 1, closeRel), nodes, prev, funcStartLine, lineStarts, innerAbs0, depth + 1);
        }
        pos = closeRel + 1;
      } else {
        // Unbalanced braces — bail rather than loop forever.
        pos = s.length;
      }
    } else {
      // Braceless single-statement body (`if (x) doSomething()`), or a
      // continuation with no body at all (a do-while's trailing
      // `while (cond)`, which has no block of its own). Take whatever
      // remains of this chunk as the body and stop chaining further within
      // this call — matching parser-cs.js's own simplification for this
      // shape.
      const bodyText = s.slice(afterHeader);
      if (bodyText.trim()) {
        prev = _consumeChunk(bodyText, abs0 + afterHeader, nodes, prev, funcStartLine, lineStarts, depth + 1);
      }
      pos = s.length;
    }

    if (pos >= s.length || depth > 12) return prev;
  }
}

// A single leaf statement or a bare (keyword-less) `{ … }` block. Bare
// blocks are rare in idiomatic Kotlin but are still valid syntax.
function _lowerLeafOrBlock(s, abs0, nodes, prevId, funcStartLine, lineStarts, depth) {
  const leadWs = s.match(/^\s*/)[0].length;
  const trimmed = s.trim();
  if (!trimmed) return prevId;
  const bare = trimmed.match(/^\{([\s\S]*)\}$/);
  if (bare) {
    const innerAbs0 = abs0 + leadWs + 1;
    return _buildCfg(bare[1], nodes, prevId, funcStartLine, lineStarts, innerAbs0, depth + 1);
  }
  const line = _lineForAbs(lineStarts, funcStartLine, abs0 + leadWs);
  const node = _lowerStmt(trimmed, line);
  if (!node) return prevId;
  const id = _addNode(nodes, node);
  _linkNodes(nodes, prevId, id);
  return id;
}

// A `when (subject) { … }` block's body is NOT statements in the ordinary
// sense — each top-level unit is an ARM, `pattern -> rhs`, where `rhs` can
// be a single statement or a `{ … }` block. Handled separately from the
// generic `_buildCfg` recursion for one specific reason: a `when` arm's
// default label is the bare word `else` (`else -> …`), which is also
// `_consumeChunk`'s continuation keyword for `if`/`else` chaining — running
// the generic header matcher directly over arm text would misinterpret
// `else -> cleanup(id)` as an if-else continuation expecting a `{ … }`
// body, not a `when` arm. Splitting off the pattern (via
// `_findTopLevelArrow`, ignoring its text entirely — pattern semantics are
// out of scope) before handing the RHS to `_consumeChunk` sidesteps the
// collision: the generic matcher never sees the word `else` in the
// pattern position.
function _buildWhenArms(bodyInner, nodes, prevId, funcStartLine, lineStarts, abs0, depth) {
  let prev = prevId;
  let cursor = 0;
  for (const armText of _splitStatements(bodyInner)) {
    if (!armText) continue;
    let idx = bodyInner.indexOf(armText, cursor);
    if (idx === -1) idx = cursor;
    cursor = idx + armText.length;
    const armAbs0 = abs0 + idx;
    const arrowIdx = _findTopLevelArrow(armText);
    if (arrowIdx === -1) continue; // unsupported arm shape — skip, don't drop the whole when.
    const rhs = armText.slice(arrowIdx + 2);
    const rhsAbs0 = armAbs0 + arrowIdx + 2;
    if (!rhs.trim()) continue;
    prev = _consumeChunk(rhs, rhsAbs0, nodes, prev, funcStartLine, lineStarts, depth);
  }
  return prev;
}

// Top-level entry point: split `bodyText` into statements (Kotlin's own
// splitter — reused unchanged, see its header comment) and process each
// through `_consumeChunk`. `abs0` is the absolute offset — within the
// function's whole, untouched body text — of `bodyText[0]`; threaded
// through every recursive call so line numbers are always computed via a
// direct offset lookup, never approximated. Because `_splitStatements`
// itself does not report offsets (deliberately reused unmodified — see its
// header comment), each returned statement's offset is instead recovered
// by searching forward from a monotonically-advancing cursor: every
// statement is guaranteed (by that function's own accumulation logic — no
// character is ever rewritten, only leading/trailing whitespace trimmed)
// to be a literal, contiguous substring of `bodyText`, so `indexOf` from
// the previous statement's end can never mis-locate it.
function _buildCfg(bodyText, nodes, prevId, funcStartLine, lineStarts, abs0, depth = 0) {
  if (depth > 12) return prevId;
  let prev = prevId;
  let cursor = 0;
  for (const stmtText of _splitStatements(bodyText)) {
    if (!stmtText) continue;
    let idx = bodyText.indexOf(stmtText, cursor);
    if (idx === -1) idx = cursor;
    cursor = idx + stmtText.length;
    prev = _consumeChunk(stmtText, abs0 + idx, nodes, prev, funcStartLine, lineStarts, depth);
  }
  return prev;
}

function _extractBody(src, openBrace) {
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

// Taint-recall PRD (80%): Kotlin's null-safety `?.` operator is invisible to
// every regex-based matcher in this file — the callee-matching regexes
// (`[\w.]+`-style), the plain-dotted-ident check, the trailing-lambda
// trigger, and `_followChain`'s continuation regex all key off a character
// class that excludes `?`. Unlike `::` (parser-rb.js) or a chain
// continuation, this is NOT limited to a later segment of a chain — the
// safe-call operator can appear on the very FIRST segment of an expression
// (`str?.trim()`, `xs?.forEach { … }`, even a bare property read `x?.y`),
// so patching individual regexes one at a time would miss call sites this
// file doesn't yet enumerate. Normalized once, globally, at the very top of
// the parse pipeline instead: string-literal-aware (so `"a?.b"` inside a
// literal string is left untouched) and strips only the `?` immediately
// before a `.` (so the elvis operator `?:` and a bare nullable-type marker
// `String?` are both unaffected — neither is followed by `.`). Dropping the
// `?` (not replacing with a same-length filler) is safe for this file's
// line-number bookkeeping specifically because `_lineStarts`/`_lineAt`/
// `_lineForOffset` are all purely newline-position-based — removing a
// non-newline character can shift a later character's COLUMN but never its
// LINE, and column offsets are never relied on anywhere in this file.
function _stripSafeCallOperator(code) {
  let out = '';
  let inStr = null;
  let escape = false;
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (escape) { out += c; escape = false; continue; }
    if (inStr) {
      out += c;
      if (c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; out += c; continue; }
    if (c === '?' && code[i + 1] === '.') { out += '.'; i++; continue; }
    out += c;
  }
  return out;
}

function _qid(file, name, line, body) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  return `${file}::${name}@${line}#${sha}`;
}

export function parseKotlinFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  code = _stripSafeCallOperator(code);
  const functions = [];
  FUN_RE.lastIndex = 0;
  let m;
  while ((m = FUN_RE.exec(code)) !== null) {
    const name = m[1];
    const paramsText = m[2] || '';
    const params = paramsText.split(',').map(p => {
      const t = p.trim();
      if (!t) return null;
      // Kotlin params: `name: Type = default` or `vararg name: Type`
      const cleaned = t.replace(/^vararg\s+/, '');
      const colon = cleaned.indexOf(':');
      const namePart = colon > 0 ? cleaned.slice(0, colon).trim() : cleaned.trim();
      return /^[A-Za-z_]\w*$/.test(namePart) ? namePart : null;
    }).filter(Boolean);
    const braceIdx = code.indexOf('{', m.index + m[0].length - 1);
    if (braceIdx < 0) continue;
    const extracted = _extractBody(code, braceIdx);
    if (!extracted) continue;
    const startLine = _lineAt(code, m.index);
    // R8 (lesson learned from the PHP port of this task, and this
    // function's OWN pre-R8 bug): the body's own start line must be
    // derived from `braceIdx` — the function's ACTUAL opening `{` — not
    // approximated as `startLine` (the declaration line). Before this fix,
    // every statement's line was computed by starting at `startLine` and
    // accumulating `\n` counts across already-flattened statement text —
    // both wrong in the same direction (off by however many lines the
    // signature's own line differs from the body's first content line, at
    // minimum 1 for the extremely common same-line-brace style this file's
    // own tests use).
    const bodyStartLine = _lineAt(code, braceIdx + 1);
    // Built once per function body; `_buildCfg` looks up every node's line
    // in O(log n) via `_lineForOffset` against this SAME array.
    const lineStarts = _lineStarts(extracted.body);
    const nodes = {};
    nodes.entry = { kind: 'entry', line: startLine, succ: [], pred: [] };
    nodes.exit  = { kind: 'exit',  line: startLine, succ: [], pred: [] };
    _ktNid = 0;
    const tail = _buildCfg(extracted.body, nodes, 'entry', bodyStartLine, lineStarts, 0, 0);
    nodes[tail].succ.push('exit');
    nodes.exit.pred.push(tail);
    const cfg = { entry: 'entry', exit: 'exit', nodes };
    functions.push({
      qid: _qid(file, name, startLine, extracted.body),
      name, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
    });
    FUN_RE.lastIndex = extracted.end + 1;
  }
  return { file, functions, topLevel: null };
}
