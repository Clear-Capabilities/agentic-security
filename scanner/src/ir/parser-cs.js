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

const METHOD_RE = new RegExp(
  '(?:^|[\\s;{}])(?:public|private|protected|internal|static|virtual|override|async|sealed|abstract|new|readonly|partial)' +
  '(?:\\s+(?:public|private|protected|internal|static|virtual|override|async|sealed|abstract|new|readonly|partial))*' +
  '\\s+([A-Za-z_][A-Za-z0-9_<>?\\[\\],\\s]*?)' +    // return type (group 1)
  '\\s+([A-Za-z_][A-Za-z0-9_]*)' +                  // method name (group 2)
  '\\s*\\(([^)]*)\\)' +                             // params (group 3)
  '\\s*\\{', 'g');

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

function _lowerExpr(text) {
  const s = String(text || '').trim();
  if (!s) return { kind: 'unknown' };
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
  const newMatch = matchBalancedCall(s, /^new\s+([\w.]+)/);
  if (newMatch) {
    const callee = newMatch.callee.split('.').pop();
    const args = _splitTopLevelCommas(newMatch.argsText).map(_lowerExpr);
    return { kind: 'call', callee, args, isNew: true };
  }
  // Call: foo.bar(args) or Bar(args). matchBalancedCall finds the paren
  // that actually balances the FIRST '(' — not the greedy-to-end-of-string
  // match the old `/\((.*)\)\s*$/` used, which corrupted the argument text
  // for a chained call (`Sanitize(x).Trim()` produced argsText="x).Trim(",
  // which then fell through to {kind:'unknown'} and silently dropped x).
  const callMatch = matchBalancedCall(s, /^([\w.]+)/);
  if (callMatch) {
    const args = _splitTopLevelCommas(callMatch.argsText).map(_lowerExpr);
    return { kind: 'call', callee: callMatch.callee, args };
  }
  // String concat / interpolation — heuristic.
  //
  // The `parts.length > 1` guard is load-bearing, not defensive tidiness: when
  // the `+` is nested inside parens or brackets, `_splitTopLevelPlus` returns
  // the input as a single part, and mapping `_lowerExpr` over it recurses on the
  // identical string forever. Any future expression form that reaches here
  // unsplit would otherwise reintroduce the same stack overflow.
  if (s.includes('+') && /["']/.test(s)) {
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
  // assign:   `var x = …`  `Type x = …`  `x = …`  `x.y = …`
  const m = s.match(/^(?:(?:var|[A-Za-z_][\w<>?,\s.]*)\s+)?([A-Za-z_][\w.]*?)\s*=\s*(.+)$/s);
  if (m) {
    const target = m[1];
    const sourceText = m[2];
    return { kind: 'assign', line, target, source: _lowerExpr(sourceText) };
  }
  // statement-form call
  const cm = matchBalancedCall(s, /^([A-Za-z_][\w.]*)/);
  if (cm) {
    return { kind: 'call', line, callee: cm.callee, args: _splitTopLevelCommas(cm.argsText).map(_lowerExpr) };
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

function _qid(file, name, line, body) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  return `${file}::${name}@${line}#${sha}`;
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
  METHOD_RE.lastIndex = 0;
  let m;
  while ((m = METHOD_RE.exec(code)) !== null) {
    const name = m[2];
    const paramsText = m[3] || '';
    const paramAnnotations = [];
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
      const last = remaining.replace(/=.*$/, '').trim().split(/\s+/).pop();
      const paramName = last && /^[A-Za-z_][\w]*$/.test(last) ? last : null;
      // Add an entry for each decorator found, indexed by position in the
      // FILTERED params array (see `keptIdx` comment above) — not `idx`,
      // the raw pre-filter split position.
      if (paramName) {
        for (const decorator of decorators) {
          paramAnnotations.push({ index: keptIdx, name: paramName, decorator });
        }
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
    const cfg = { entry: 'entry', exit: 'exit', nodes };
    functions.push({
      qid: _qid(file, name, startLine, extracted.body),
      name, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
      ...(paramAnnotations.length ? { paramAnnotations } : {}),
    });
    METHOD_RE.lastIndex = extracted.end + 1;
  }
  return { file, functions, topLevel: null };
}
