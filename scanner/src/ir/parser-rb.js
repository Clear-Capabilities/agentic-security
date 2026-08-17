// Ruby IR frontend.
//
// Regex-based, follows the parser-cs.js / parser-go.js pattern. Focused on
// Rails params, ActiveRecord, Kernel methods surface area.
//
// What we model:
//   - def / def self. method declarations
//   - var = expr assignments
//   - method calls: obj.method(args) and method(args)
//   - return
//   - each/map/select blocks as loop-header
//
// What we do NOT model:
//   - blocks / procs / lambdas as first-class values
//   - metaprogramming (define_method, method_missing)
//   - module_function / protected / private method visibility scoping
//   - control flow (if/unless/while/until/case) — body is straight-line
//
// Ruby body extraction: count def/class/module/do/if/unless/while/until/
// for/case/begin as openers and `end` as closers. Return null on balance
// failure (heredocs, multi-line strings can confuse the regex parser).

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';
import { matchBalancedCall } from './balanced-call.js';

// `[ \t]*` before the optional parameter list, NOT `\s*`.
//
// `\s*` crosses newlines, so for `def show\n  c = params[:c]` the match ran to
// the next line's indentation. `parseRubyFile` then computes the body start as
// `indexOf('\n', m.index + m[0].length)`, which landed on the newline at the END
// of the first statement — so the body was sliced from after it and statement 1
// of EVERY Ruby method was silently discarded (a single-statement body became
// empty). In a Rails controller that first statement is almost always the
// `params` read, i.e. the taint source, which is why `bench/layer-recall`
// measured Ruby at 0/20 IR-TAINT recall while all 20 corpus entries passed on
// the regex layer. A parameter list on the same line still matches.
const DEF_RE = /(?:^|\n)[ \t]*def\s+(?:self\.)?(\w+[?!=]?)[ \t]*(?:\(([^)]*)\))?/g;

function _extractRubyBody(src, defEnd) {
  let depth = 1;
  let i = defEnd;
  let inStr = null;
  let escape = false;
  const openers = /\b(?:def|class|module|do|if|unless|while|until|for|case|begin)\b/;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (escape) { escape = false; i++; continue; }
    if (inStr) {
      if (c === '\\') { escape = true; i++; continue; }
      if (c === inStr) inStr = null;
      i++; continue;
    }
    if (c === '"' || c === '\'') { inStr = c; i++; continue; }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    // Check for keyword boundaries
    if (/[a-z]/i.test(c)) {
      let word = '';
      const start = i;
      while (i < src.length && /\w/.test(src[i])) { word += src[i]; i++; }
      if (word === 'end' && (start === 0 || /[^.\w]/.test(src[start - 1] || ' '))) {
        depth--;
      } else if (openers.test(word) && (start === 0 || /[^.\w]/.test(src[start - 1] || ' '))) {
        // Only count as opener if not preceded by . (e.g., x.if would be wrong but rare)
        depth++;
      }
      continue;
    }
    i++;
  }
  if (depth !== 0) return null;
  // `end` keyword ends at position `i`; body is between defEnd and the start of `end`
  return { body: src.slice(defEnd, i - 3).trimEnd(), end: i };
}

const _RB_BLOCK_KW = /\b(?:def|class|module|if|unless|while|until|for|case|begin|do)\b/g;

// Taint-recall PRD (80%): the count of these keywords in `line`, minus the
// count of `end` — used to detect whether a line OPENS (or continues) a
// depth-tracked block, not just when the line's FIRST word is a keyword.
// The old `_RB_OPENERS.test(line)` gate required the opener at the very
// START of the line, so a trailing block attached to a call — the
// idiomatic Ruby shape (`xs.each do |x|`, `Nokogiri::XML(xml) do |c|`) —
// was never recognized as starting a chunk at all: each line of the block
// body, and the `end` that should have closed it, were instead emitted as
// independent, nonsensical top-level statements. `#`-comments are stripped
// first so a keyword appearing only in a trailing comment doesn't
// false-positive (string-literal occurrences are a known, accepted
// imprecision shared with every other hand-rolled parser in this codebase).
function _rbLineDepthDelta(line) {
  const noComment = line.replace(/#.*$/, '');
  let delta = 0;
  for (const _ of noComment.matchAll(_RB_BLOCK_KW)) delta++;
  const endMatches = noComment.match(/\bend\b/g);
  if (endMatches) delta -= endMatches.length;
  return delta;
}

// Returns `{ text, line }[]` — `line` is the 1-indexed line, relative to the
// START of `body`, where that statement's text begins (the array index of
// its first raw source line, +1). For a multi-line if/while/until block
// this is the line of the OPENING keyword, not of `end`. Tracking this
// directly from each raw line's position — rather than recomputing it
// afterwards by counting newlines inside the joined, already-trimmed
// statement text — avoids silently losing blank/comment lines that were
// skipped along the way (they're dropped entirely by the `!line` guard
// below and never contribute to any count once the text is joined). See
// parser-php.js's twin fix and comment for the full rationale (Finding 2 of
// the R14(b) final whole-branch review) — this is the same root bug in a
// per-line splitter instead of a per-semicolon one.
// Taint-recall PRD (80%): the depth check now uses _rbLineDepthDelta (which
// scans the WHOLE line, not just its first word) at BOTH decision points —
// not just when already inside a chunk (the old `depth > 0` branch). A
// trailing block attached to a call (`xs.each do |x|`, `Nokogiri::XML(xml)
// do |c|`) has its opener keyword mid-line, so the old `depth === 0 &&
// _RB_OPENERS.test(line)` gate (line-START only) never even recognized
// such a line as starting a chunk — each line of the block body, and the
// `end` meant to close it, were emitted as independent, nonsensical
// top-level statements instead. Confirmed via a real corpus fixture
// (Nokogiri::XML's brace form was already broken the same way; do...end is
// the more common Rails idiom and was worse — not just dropped, actively
// mis-split line by line).
function _splitStatements(body) {
  const lines = body.split('\n');
  const out = [];
  let buf = '';
  let bufLine = 0;
  let depth = 0;
  lines.forEach((rawLine, idx) => {
    const lineNo = idx + 1;
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) return;
    if (depth === 0) {
      const delta = _rbLineDepthDelta(line);
      if (delta > 0) {
        buf = line + '\n';
        bufLine = lineNo;
        depth = delta;
        return;
      }
      out.push({ text: line, line: lineNo });
      return;
    }
    buf += line + '\n';
    depth += _rbLineDepthDelta(line);
    if (depth <= 0) { depth = 0; out.push({ text: buf.trim(), line: bufLine }); buf = ''; }
  });
  if (buf.trim()) out.push({ text: buf.trim(), line: bufLine });
  return out;
}

// Taint-recall PRD (80%): same architectural fix as parser-cs.js/
// parser-go.js/parser-php.js — a chained call (`sanitize(x).strip`, or a
// real sink shape like `Nokogiri::XML(x).at_xpath(...)`) previously stopped
// at the FIRST balanced call, leaving `.method(args)` unconsumed. Args from
// EVERY level are kept, outermost-first — see parser-cs.js's twin function
// for why (a first version that kept only the outermost broke a real chain
// shape where the tainted value sits on an INNER call).
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
  // String interpolation before plain literal check
  if (/^".*#\{/.test(s)) {
    const parts = [];
    for (const m of s.matchAll(/#\{([^}]+)\}/g)) parts.push(_lowerExpr(m[1]));
    if (parts.length) return { kind: 'tpl', parts };
  }
  // Taint-recall PRD (80%): string concat with `+` MUST be checked before
  // the plain-literal rule below — `"/var/data/" + name` starts with a
  // quote, so the old ordering swallowed the WHOLE expression (including
  // `+ name`) as one opaque literal, silently dropping the concatenated
  // variable (confirmed via a real corpus fixture). Same lesson
  // parser-go.js's R3 fix already learned for the identical reason. Only
  // fires on a TOP-LEVEL `+` (outside string/paren/bracket nesting, via
  // _splitTopLevelPlus) so a literal that merely CONTAINS a "+" character
  // (`"a+b"`) is not incorrectly split into broken fragments.
  if (s.includes('+')) {
    const plusParts = _splitTopLevelPlus(s);
    if (plusParts.length > 1) return { kind: 'tpl', parts: plusParts.map(_lowerExpr) };
  }
  if (/^['"]/.test(s)) return { kind: 'literal', value: s };
  if (/^\d/.test(s)) return { kind: 'literal', value: s };
  if (/^(true|false|nil)\b/.test(s)) return { kind: 'literal', value: s };
  // Symbol
  if (/^:\w+/.test(s)) return { kind: 'literal', value: s };
  // Taint-recall PRD (80%): keyword-argument / hash-shorthand syntax
  // (`method(base: "...", filter: tainted)`) had no branch at all — every
  // such arg text fell through to `{kind:'unknown'}`, silently dropping
  // whatever value (including a tainted one) it carried. This is Ruby's
  // dominant kwargs idiom (net/ldap, most Rails-adjacent APIs), so any call
  // using it lost taint through EVERY keyword arg, not just one. Lower to
  // just the value expression — the key name itself carries no taint
  // relevance, same treatment JS/Python object-literal properties already
  // get via exprTaint's 'object' case. The colon must immediately follow
  // the identifier (no space) so this can't mis-fire on a ternary's
  // `cond ? a : b` (space before its colon).
  const kwarg = s.match(/^([A-Za-z_]\w*):\s*(.+)$/);
  if (kwarg) return _lowerExpr(kwarg[2]);
  // Call: obj.method(args) or method(args). matchBalancedCall finds the
  // paren that actually balances the FIRST '(' — not the greedy-to-end-of-
  // string match the old `/\((.*)\)\s*$/` used, which corrupted the
  // argument text for a chained call (`sanitize(x).strip` produced
  // args="x).strip", which then fell through to {kind:'unknown'} and
  // silently dropped x).
  // Taint-recall PRD (80%): `[\w.]+` excludes `:`, so `Nokogiri::XML(xml)`
  // — Ruby's `::` module-scope call operator, a common idiom for
  // class/module-level factory methods — never matched here at all (the
  // regex only ever captured "Nokogiri", then failed to find `(`
  // immediately after it, since a `:` sat in between). Callee normalizes
  // `::` to `.` for consistency with _followChain's dot-joining and every
  // catalog entry's dotted-segment matching.
  const callMatch = matchBalancedCall(s, /^([\w.:]+)/);
  if (callMatch) {
    const callee = callMatch.callee.replace(/::/g, '.');
    const args = _splitTopLevelCommas(callMatch.argsText).map(_lowerExpr);
    return _followChain(s, callMatch.endIdx, callee, args);
  }
  // Method call without parens is very common in Ruby but hard to detect
  // reliably with regex. We handle the explicit-paren form above.
  // Dotted member: obj.prop
  if (/^[A-Za-z_]\w*(?:\.\w+)+$/.test(s)) {
    const parts = s.split('.');
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) cur = { kind: 'member', object: cur, prop: parts[i] };
    return cur;
  }
  // Hash access: params[:key]
  if (/^[A-Za-z_]\w*\[/.test(s)) {
    const lb = s.indexOf('[');
    const base = s.slice(0, lb);
    return { kind: 'member', object: { kind: 'ident', name: base }, prop: '[]' };
  }
  // Simple ident
  if (/^[A-Za-z_@]\w*$/.test(s)) return { kind: 'ident', name: s };
  return { kind: 'unknown' };
}

// Taint-recall PRD (80%): top-level-aware `+` splitter, same purpose as
// _splitTopLevelCommas below — tracks string/paren/bracket nesting so a
// `+` inside a string literal or a nested call's argument list doesn't get
// mistaken for a concatenation operator.
function _splitTopLevelPlus(s) {
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
    if (c === '"' || c === '\'') { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
    if (c === '+' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
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
      if (c === '\\') { i++; buf += s[i] || ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
    if (c === ',' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function _lowerStmt(stmt, line) {
  const s = stmt.trim();
  if (!s || s.startsWith('#')) return null;
  if (/^return\b/.test(s)) {
    const rest = s.replace(/^return\s*/, '').trim();
    return { kind: 'return', line, value: rest ? _lowerExpr(rest) : null };
  }
  if (/^raise\b/.test(s)) {
    return { kind: 'throw', line, value: _lowerExpr(s.replace(/^raise\s*/, '')) };
  }
  // Taint-recall PRD (80%): subscript-assignment on a member chain
  // (`response.headers["X-Trace"] = params[:trace]`) had no branch at
  // all — the plain assign regex below requires a bare `@?\w+` target, so
  // this fell through to the bareCall heuristic (further down), which also
  // doesn't match, and the WHOLE statement was silently dropped. Same
  // shape/fix as parser-py.helper.py's `__setitem__` synthesis this PRD
  // added earlier: lowered as a synthetic `<receiver>.[]=(key, value)`
  // call so it flows through the existing argument-based sink-matching
  // machinery — argIndex 1 is the assigned value.
  const subAssign = s.match(/^([A-Za-z_][\w.]*)\[(.+?)\]\s*=\s*(.+)$/s);
  if (subAssign) {
    const receiver = subAssign[1].replace(/::/g, '.');
    const key = _lowerExpr(subAssign[2]);
    const value = _lowerExpr(subAssign[3]);
    return { kind: 'call', line, callee: `${receiver}.[]=`, args: [key, value] };
  }
  // Assignment: var = expr
  const assign = s.match(/^(@?\w+)\s*=\s*(.+)$/s);
  if (assign && !/^={2}/.test(assign[2])) {
    return { kind: 'assign', line, target: assign[1], source: _lowerExpr(assign[2]) };
  }
  // Statement-form call with parens. Same `::`-inclusion fix as _lowerExpr's
  // twin (Taint-recall PRD 80%).
  const call = matchBalancedCall(s, /^([\w.:]+)/);
  if (call) {
    const callee = call.callee.replace(/::/g, '.');
    const chained = _followChain(s, call.endIdx, callee, _splitTopLevelCommas(call.argsText).map(_lowerExpr));
    return { kind: 'call', line, callee: chained.callee, args: chained.args };
  }
  // Statement-form call without parens (common Ruby idiom): redirect_to expr
  //
  // `class` and `module` must be excluded here: before R14(b), top-level
  // text was never fed through `_lowerStmt` at all, so a wrapper like
  // `class Foo < ApplicationController` never reached this heuristic. Now
  // that every top-level statement is, an unguarded match lowers it to a
  // bogus `{kind:'call', callee:'class', ...}` node — and since nearly
  // every Ruby file wraps its top-level content in a `class`/`module`
  // (an extremely common idiom), this alone caused most of this repo's own
  // Ruby fixtures to gain a spurious `<module>` entry containing nothing
  // but this one bogus node, contradicting the "zero existing fixtures
  // gain a <module> entry" constraint for Ruby specifically.
  const bareCall = s.match(/^([a-z_]\w*)\s+(.+)$/s);
  if (bareCall && /^[a-z_]/.test(bareCall[1]) && !/^(?:if|unless|while|until|for|case|when|elsif|else|end|return|raise|require|include|extend|attr_\w+|class|module)$/.test(bareCall[1])) {
    return { kind: 'call', line, callee: bareCall[1], args: [_lowerExpr(bareCall[2])] };
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

// DEF_RE's leading alternation `(?:^|\n)` matches a single boundary
// character (the newline ending the PRECEDING line) that belongs to
// whatever precedes the def, not to the def itself. `m.index` always points
// at the START of that boundary. `_blank` (below) never touches actual `\n`
// characters — only non-newline characters are turned into spaces — so
// including this boundary newline in the def's span would be harmless
// either way; this still excludes it, purely so the span's meaning (source
// consumed by the def declaration) doesn't include a character that
// belongs to the previous line, mirroring parser-php.js's twin fix (there
// the equivalent boundary CAN be a non-newline character like `;`, which
// does need excluding).
function _defBoundaryLen(idx) {
  return idx === 0 ? 0 : 1;
}

// Blank out every real def's span in a COPY of the full source (replace its
// characters with spaces, preserving every newline exactly). This lets the
// WHOLE file be lowered in a single _buildCfg call at startLine=1 for the
// module-level CFG, which keeps every remaining statement's reported line
// number exactly equal to its real source line — no character is ever
// deleted, only turned into a space, so nothing can shift. This replaces
// the old per-gap slicing + per-gap startLine re-derivation, which
// mis-tracked lines whenever a gap slice started with leading
// blank/newline characters and broke the line-scoped
// `agentic-security-ignore` suppression pragma for module-level findings.
function _blankSpans(code, spans) {
  let out = '';
  let cursor = 0;
  for (const span of spans) {
    if (span.start > cursor) out += code.slice(cursor, span.start);
    out += _blank(code.slice(span.start, span.end));
    cursor = span.end;
  }
  out += code.slice(cursor);
  return out;
}

function _blank(text) {
  return text.replace(/[^\n]/g, ' ');
}

let _nid = 0;
function _nextId() { return `rn${++_nid}`; }

function _addNode(nodes, node) {
  const id = _nextId();
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

function _extractRubyBlockBody(compound) {
  const lines = compound.split('\n');
  if (lines.length < 2) return '';
  return lines.slice(1, -1).join('\n');
}

// Taint-recall PRD (80%): full Ruby CFG rebuild. `case/when/else` was
// previously not recursed into at all (the whole block silently dropped —
// `_lowerStmt` has no branch for it and "case" is excluded from the
// bare-call fallback, so it returns null and the entire chunk vanishes).
// Splits the case body into `when`/`else` arms by scanning for those
// keywords at NESTED depth 0 (mirroring parser-kt.js's _buildWhenArms,
// which needed the identical depth guard to avoid colliding with a nested
// if/else's own `else`). Each arm is linked directly from the case's own
// entry point (not chained if-else-style) and its body-tail joins a common
// exit node — this doesn't model mutual exclusivity between arms, which is
// fine for taint purposes: every arm's sink is reachable, which is what
// recall-preserving analysis needs (a false "this arm is also reachable"
// is far cheaper than silently dropping the arm that actually executes).
function _buildCaseArms(innerBody, nodes, entryId, startLine, cfgDepth) {
  const lines = innerBody.split('\n');
  const arms = [];
  let depth = 0;
  let cur = null;
  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (depth === 0 && /^when\s+/.test(line)) {
      if (cur) arms.push(cur);
      cur = { condText: line.replace(/^when\s+/, '').replace(/\s+then\s*$/, '').trim(), bodyLines: [], startIdx: idx };
      return;
    }
    if (depth === 0 && /^else\b/.test(line)) {
      if (cur) arms.push(cur);
      cur = { condText: null, bodyLines: [], startIdx: idx };
      return;
    }
    if (cur) cur.bodyLines.push(rawLine);
    depth += _rbLineDepthDelta(line);
    if (depth < 0) depth = 0;
  });
  if (cur) arms.push(cur);

  const join = _addNode(nodes, { kind: 'noop', line: startLine });
  for (const arm of arms) {
    const armLine = startLine + arm.startIdx;
    const bodyText = arm.bodyLines.join('\n');
    let branchStart = entryId;
    if (arm.condText !== null) {
      const ifNode = _addNode(nodes, { kind: 'if', cond: _lowerExpr(arm.condText), line: armLine });
      _linkNodes(nodes, entryId, ifNode);
      branchStart = ifNode;
    }
    const tail = _buildCfg(bodyText, nodes, branchStart, armLine + 1, cfgDepth + 1);
    _linkNodes(nodes, tail, join);
  }
  if (!arms.length) _linkNodes(nodes, entryId, join);
  return join;
}

// Taint-recall PRD (80%): `begin/rescue/ensure` was also previously
// dropped entirely (same root cause as case/when — no _lowerStmt branch).
// `rescue` clauses are linked from the SAME entry point as the begin body
// (an exception can occur at any point inside it, so precise "which
// statement raised" ordering isn't modeled — same recall-preserving
// tradeoff as case/when). `ensure`, when present, always runs after every
// other path converges, mirroring real semantics for reachability purposes
// even though this doesn't model early-return-through-ensure precisely.
function _buildBeginRescueEnsure(innerBody, nodes, entryId, startLine, cfgDepth) {
  const lines = innerBody.split('\n');
  const clauses = [{ kind: 'begin', bodyLines: [], startIdx: 0 }];
  let depth = 0;
  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (depth === 0 && /^rescue\b/.test(line)) {
      clauses.push({ kind: 'rescue', bodyLines: [], startIdx: idx });
      return;
    }
    if (depth === 0 && /^ensure\b/.test(line)) {
      clauses.push({ kind: 'ensure', bodyLines: [], startIdx: idx });
      return;
    }
    clauses[clauses.length - 1].bodyLines.push(rawLine);
    depth += _rbLineDepthDelta(line);
    if (depth < 0) depth = 0;
  });

  let beginTail = entryId;
  const rescueTails = [];
  let ensureBody = null, ensureLine = startLine;
  for (const clause of clauses) {
    const clauseLine = startLine + clause.startIdx;
    const bodyText = clause.bodyLines.join('\n');
    if (clause.kind === 'begin') {
      beginTail = _buildCfg(bodyText, nodes, entryId, clauseLine + 1, cfgDepth + 1);
    } else if (clause.kind === 'rescue') {
      rescueTails.push(_buildCfg(bodyText, nodes, entryId, clauseLine + 1, cfgDepth + 1));
    } else {
      ensureBody = bodyText;
      ensureLine = clauseLine;
    }
  }
  const converge = _addNode(nodes, { kind: 'noop', line: startLine });
  _linkNodes(nodes, beginTail, converge);
  for (const t of rescueTails) _linkNodes(nodes, t, converge);
  const join = _addNode(nodes, { kind: 'noop', line: startLine });
  const finalTail = ensureBody !== null ? _buildCfg(ensureBody, nodes, converge, ensureLine + 1, cfgDepth + 1) : converge;
  _linkNodes(nodes, finalTail, join);
  return join;
}

// Taint-recall PRD (80%): a trailing block attached to a call
// (`xs.each do |x| ... end`, `Nokogiri::XML(xml) { |c| ... }`) — Ruby's
// dominant Rails/ActiveRecord idiom (`.each`/`.map`/scope chains, resource
// blocks) — was previously silently dropped (do...end) or corrupted
// (brace form, via the pre-fix matchBalancedCall gap). Recurses into the
// body unconditionally (the PRD's own investigation recommended this,
// given how dominant the idiom is in real Rails code) and binds every
// named block parameter to the call's receiver — permissive by design
// (Ruby has no equivalent of Kotlin's implicit-this apply/run that would
// need to NOT bind; over-binding here is the safe direction for a
// recall-preserving engine).
function _lowerBlockTrigger(callText) {
  const paren = matchBalancedCall(callText, /^([\w.:]+)/);
  if (paren) {
    const callee = paren.callee.replace(/::/g, '.');
    return { kind: 'call', callee, args: _splitTopLevelCommas(paren.argsText).map(_lowerExpr) };
  }
  return { kind: 'call', callee: callText.replace(/::/g, '.'), args: [] };
}

// `startLine` is the absolute source line of the FIRST raw line of
// `bodyText`. Each statement's absolute line is `startLine + stmt.line - 1`
// (`stmt.line` from _splitStatements is already 1-indexed and relative to
// `bodyText`), so — unlike the old incremental `line++`/`line += newlines+1`
// bookkeeping this replaced — no line is ever derived by re-counting
// newlines in already-joined, already-trimmed text. That old scheme
// silently dropped any blank line (or, at module level, any blanked-out def
// span — see `_blankSpans`) that preceded a statement, which is exactly
// what made module-level Ruby findings report the wrong source line.
//
// `depth` guards against unbounded recursion on deeply/adversarially
// nested input (confirmed real risk — every OTHER R8-style rebuild in this
// codebase, Kotlin's trailing-lambda work most recently, needed the same
// guard after hitting a real stack overflow during its own testing).
function _buildCfg(bodyText, nodes, prevId, startLine, depth = 0) {
  if (depth > 60) return prevId;
  const stmts = _splitStatements(bodyText);
  let prev = prevId;
  for (const stmt of stmts) {
    const s = stmt.text;
    const line = startLine + stmt.line - 1;
    if (!s || s.startsWith('#')) continue;

    const ifMatch = s.match(/^(if|unless)\s+(.+)$/m);
    if (ifMatch && /\bend\b\s*$/.test(s)) {
      const condText = ifMatch[2].trim();
      const innerBody = _extractRubyBlockBody(s);
      const ifNode = _addNode(nodes, { kind: 'if', cond: _lowerExpr(condText), line });
      _linkNodes(nodes, prev, ifNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      const thenTail = _buildCfg(innerBody, nodes, ifNode, line + 1, depth + 1);
      _linkNodes(nodes, thenTail, join);
      _linkNodes(nodes, ifNode, join);
      prev = join;
      continue;
    }

    const whileMatch = s.match(/^(while|until)\s+(.+)$/m);
    if (whileMatch && /\bend\b\s*$/.test(s)) {
      const innerBody = _extractRubyBlockBody(s);
      const header = _addNode(nodes, { kind: 'loop-header', line });
      _linkNodes(nodes, prev, header);
      const bodyTail = _buildCfg(innerBody, nodes, header, line + 1, depth + 1);
      _linkNodes(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, header, join);
      prev = join;
      continue;
    }

    // Taint-recall PRD (80%): `for x in xs ... end` (also accepts the
    // optional trailing `do` — `for x in xs do`) — previously not
    // recognized by _buildCfg at all, silently dropped. Synthesizes a
    // loop-variable binding assign, mirroring every OTHER R8-style
    // for-each fix in this codebase (Java's enhanced-for, C#'s foreach,
    // Kotlin's `for (x in xs)`) so the variable itself carries taint
    // provenance from the iterated expression.
    const forMatch = s.match(/^for\s+(\w+)\s+in\s+(.+?)\s*$/m);
    if (forMatch && /\bend\b\s*$/.test(s)) {
      const loopVar = forMatch[1];
      const iterText = forMatch[2].replace(/\bdo\s*$/, '').trim();
      const innerBody = _extractRubyBlockBody(s);
      const header = _addNode(nodes, { kind: 'loop-header', line });
      _linkNodes(nodes, prev, header);
      const bindId = _addNode(nodes, { kind: 'assign', target: loopVar, source: _lowerExpr(iterText), line });
      _linkNodes(nodes, header, bindId);
      const bodyTail = _buildCfg(innerBody, nodes, bindId, line + 1, depth + 1);
      _linkNodes(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, header, join);
      prev = join;
      continue;
    }

    if (/^case\b/.test(s) && /\bend\b\s*$/.test(s)) {
      const innerBody = _extractRubyBlockBody(s);
      prev = _buildCaseArms(innerBody, nodes, prev, line + 1, depth + 1);
      continue;
    }

    if (/^begin\b/.test(s) && /\bend\b\s*$/.test(s)) {
      const innerBody = _extractRubyBlockBody(s);
      prev = _buildBeginRescueEnsure(innerBody, nodes, prev, line + 1, depth + 1);
      continue;
    }

    // `bench:self-scan:check` caught a genuine ReDoS here — but NOT the
    // "optional group between two \s*" shape this session's other fixes
    // (parser-kt.js's trailing-lambda regex, parser-cs.js's attrRegex) were.
    // A first version split into two mutually exclusive alternatives
    // (no-params / with-params), the fix that worked for those — and it was
    // STILL quadratic (confirmed by direct timing: 200000 chars of
    // unmatched trailing whitespace took ~48s), because the real culprit is
    // the LEADING `(.+?)\s+do` shared by both alternatives: an unbounded
    // lazy group followed by a whitespace quantifier, which backtracks
    // catastrophically against a long homogeneous run (e.g. all spaces)
    // when the overall match fails — a different ReDoS class entirely, not
    // fixed by re-partitioning what comes AFTER "do". Fixed by dropping the
    // leading capturing group altogether: search directly for the
    // trailing `\bdo\b` (a plain forward scan, nothing to backtrack) and
    // derive the callee text from the substring before it — confirmed
    // linear (1,000,000 chars: 2ms) and correctness-preserving (word
    // boundaries correctly skip a method literally named `do_something`).
    // Split into two mutually exclusive alternatives (with-params /
    // no-params) rather than one optional group even though — unlike the
    // `(.+?)\s+do` version above — this specific shape already measured
    // linear on its own: bench:self-scan:check's detector flags the SHAPE
    // (an optional group between two `\s*`) independent of whether a
    // compounding leading group is present, so satisfying it here too
    // keeps this file's own precision baseline honest without another
    // detector-vs-reality debate.
    const firstLine = s.split('\n')[0].trim();
    const doMatch = firstLine.match(/\bdo\b\s*\|([^|]*)\|\s*$/) || firstLine.match(/\bdo\b\s*$/);
    const blockMatch = doMatch ? [doMatch[0], firstLine.slice(0, doMatch.index), doMatch[1]] : null;
    if (blockMatch && /\bend\s*$/.test(s)) {
      const callText = blockMatch[1].trim();
      const paramsText = blockMatch[2] || '';
      const innerBody = _extractRubyBlockBody(s);
      const triggerExpr = _lowerBlockTrigger(callText);
      const callId = _addNode(nodes, { kind: 'call', line, callee: triggerExpr.callee, args: triggerExpr.args });
      _linkNodes(nodes, prev, callId);
      let bodyStart = callId;
      const dot = triggerExpr.callee.lastIndexOf('.');
      const receiver = dot > 0 ? triggerExpr.callee.slice(0, dot) : null;
      if (receiver) {
        const params = paramsText.split(',').map(p => p.trim().replace(/^\*+/, '')).filter(p => /^[A-Za-z_]\w*$/.test(p));
        for (const p of params) {
          const bindId = _addNode(nodes, { kind: 'assign', target: p, source: { kind: 'ident', name: receiver }, line });
          _linkNodes(nodes, bodyStart, bindId);
          bodyStart = bindId;
        }
      }
      prev = _buildCfg(innerBody, nodes, bodyStart, line + 1, depth + 1);
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
      // Ruby never emitted `fn.calls` at all (ir/CLAUDE.md documents this
      // as a known gap) — tabulation.js, dataflow/index.js and
      // callgraph.js all read it to build call edges, so an absent array
      // is indistinguishable from "calls nothing," disabling ALL Ruby
      // interprocedural taint. call-sites.js's callSitesFromCfg is the
      // same language-agnostic CFG walk parser-py-cst.js already uses for
      // exactly this; Ruby's node shapes ('call' with callee/args,
      // 'assign' with source, 'return'/'throw' with value, 'if' with
      // cond) match its documented contract already, so no new lowering
      // logic is needed here — only wiring the call.
      calls: callSitesFromCfg(cfg),
    });
    spans.push({ start: m.index + _defBoundaryLen(m.index), end: extracted.end });
    DEF_RE.lastIndex = extracted.end;
  }

  // R14(b): lower top-level (module-scope) statements into a synthetic
  // <module> function, mirroring parser-js.js's Program-level lowering.
  // Every real def's span is blanked (see _blankSpans) in a copy of the
  // full source, and the WHOLE blanked text is lowered in a single
  // _buildCfg call at startLine=1 — this keeps every remaining statement's
  // reported line number exactly equal to its real source line, since no
  // character is ever deleted, only blanked to a space (newlines always
  // survive). Same approach as parser-php.js's twin fix.
  spans.sort((a, b) => a.start - b.start);
  const blanked = _blankSpans(code, spans);
  const modNodes = {};
  const modEntry = _addNode(modNodes, { kind: 'entry', line: 1 });
  const modExit = _addNode(modNodes, { kind: 'exit', line: 1 });
  const modTail = _buildCfg(blanked, modNodes, modEntry, 1);
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
