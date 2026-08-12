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

function _splitStatements(body) {
  const lines = body.split('\n');
  const out = [];
  let buf = '';
  let depth = 0;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (depth === 0 && _RB_OPENERS.test(line)) {
      if (buf.trim()) out.push(buf.trim());
      buf = line + '\n';
      for (const m of line.matchAll(/\b(?:if|unless|while|until|for|case|begin|do|def|class|module)\b/g)) depth++;
      if (/\bend\b/.test(line)) depth--;
      if (depth <= 0) { depth = 0; out.push(buf.trim()); buf = ''; }
      continue;
    }
    if (depth > 0) {
      buf += line + '\n';
      for (const m of line.matchAll(/\b(?:if|unless|while|until|for|case|begin|do|def|class|module)\b/g)) depth++;
      const endMatches = line.match(/\bend\b/g);
      if (endMatches) depth -= endMatches.length;
      if (depth <= 0) { depth = 0; out.push(buf.trim()); buf = ''; }
      continue;
    }
    out.push(line);
  }
  if (buf.trim()) out.push(buf.trim());
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
  const bareCall = s.match(/^([a-z_]\w*)\s+(.+)$/s);
  if (bareCall && /^[a-z_]/.test(bareCall[1]) && !/^(?:if|unless|while|until|for|case|when|elsif|else|end|return|raise|require|include|extend|attr_\w+)$/.test(bareCall[1])) {
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

function _buildCfg(bodyText, nodes, prevId, startLine) {
  const stmts = _splitStatements(bodyText);
  let prev = prevId;
  let line = startLine;
  for (const stmt of stmts) {
    const s = stmt.trim();
    if (!s || s.startsWith('#')) { line++; continue; }

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
      line += (s.match(/\n/g) || []).length + 1;
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
      line += (s.match(/\n/g) || []).length + 1;
      continue;
    }

    const node = _lowerStmt(s, line);
    if (!node) { line += (s.match(/\n/g) || []).length + 1; continue; }
    const id = _addNode(nodes, node);
    _linkNodes(nodes, prev, id);
    prev = id;
    line += (s.match(/\n/g) || []).length + 1;
  }
  return prev;
}

export function parseRubyFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.rb$/i.test(file)) return null;
  if (code.length > 1_000_000) return null;

  const functions = [];
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
    DEF_RE.lastIndex = extracted.end;
  }
  return functions.length ? { file, functions, topLevel: null } : null;
}
