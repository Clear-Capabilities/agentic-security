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

const _RB_OPENERS = /^(?:if|unless|while|until|for|case|begin|do)\b/;
const _RB_BLOCK_KW = /\b(?:def|class|module|if|unless|while|until|for|case|begin|do)\b/;

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
    if (depth === 0 && _RB_OPENERS.test(line)) {
      if (buf.trim()) out.push({ text: buf.trim(), line: bufLine });
      buf = line + '\n';
      bufLine = lineNo;
      for (const m of line.matchAll(/\b(?:if|unless|while|until|for|case|begin|do|def|class|module)\b/g)) depth++;
      if (/\bend\b/.test(line)) depth--;
      if (depth <= 0) { depth = 0; out.push({ text: buf.trim(), line: bufLine }); buf = ''; }
      return;
    }
    if (depth > 0) {
      buf += line + '\n';
      for (const m of line.matchAll(/\b(?:if|unless|while|until|for|case|begin|do|def|class|module)\b/g)) depth++;
      const endMatches = line.match(/\bend\b/g);
      if (endMatches) depth -= endMatches.length;
      if (depth <= 0) { depth = 0; out.push({ text: buf.trim(), line: bufLine }); buf = ''; }
      return;
    }
    out.push({ text: line, line: lineNo });
  });
  if (buf.trim()) out.push({ text: buf.trim(), line: bufLine });
  return out;
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
  const callMatch = matchBalancedCall(s, /^([\w.]+)/);
  if (callMatch) {
    return { kind: 'call', callee: callMatch.callee, args: _splitTopLevelCommas(callMatch.argsText).map(_lowerExpr) };
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
  // Concat with +
  if (s.includes('+')) {
    const parts = s.split('+').map(p => _lowerExpr(p.trim()));
    return { kind: 'tpl', parts };
  }
  return { kind: 'unknown' };
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
  // Assignment: var = expr
  const assign = s.match(/^(@?\w+)\s*=\s*(.+)$/s);
  if (assign && !/^={2}/.test(assign[2])) {
    return { kind: 'assign', line, target: assign[1], source: _lowerExpr(assign[2]) };
  }
  // Statement-form call with parens
  const call = matchBalancedCall(s, /^([\w.]+)/);
  if (call) {
    return { kind: 'call', line, callee: call.callee, args: _splitTopLevelCommas(call.argsText).map(_lowerExpr) };
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

// `startLine` is the absolute source line of the FIRST raw line of
// `bodyText`. Each statement's absolute line is `startLine + stmt.line - 1`
// (`stmt.line` from _splitStatements is already 1-indexed and relative to
// `bodyText`), so — unlike the old incremental `line++`/`line += newlines+1`
// bookkeeping this replaced — no line is ever derived by re-counting
// newlines in already-joined, already-trimmed text. That old scheme
// silently dropped any blank line (or, at module level, any blanked-out def
// span — see `_blankSpans`) that preceded a statement, which is exactly
// what made module-level Ruby findings report the wrong source line.
function _buildCfg(bodyText, nodes, prevId, startLine) {
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
      const thenTail = _buildCfg(innerBody, nodes, ifNode, line + 1);
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
      const bodyTail = _buildCfg(innerBody, nodes, header, line + 1);
      _linkNodes(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, header, join);
      prev = join;
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
