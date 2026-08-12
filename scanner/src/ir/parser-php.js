// PHP IR frontend.
//
// Regex-based, follows the parser-cs.js / parser-go.js pattern. Focused on
// PDO, mysqli, Laravel DB facade, and PHP superglobal taint surface.
//
// What we model:
//   - function / method declarations
//   - $var = expr assignments
//   - function calls and method calls ($obj->method(args))
//   - return
//   - foreach as loop-header + assign
//   - PHP superglobals ($_GET, $_POST, $_REQUEST, etc.) as ident sources
//
// What we do NOT model:
//   - arrow functions (fn($x) => expr)
//   - traits / interfaces
//   - anonymous classes
//   - control flow (if/for/while/switch) — body is straight-line

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';
import { matchBalancedCall } from './balanced-call.js';

const FUNC_RE = new RegExp(
  '(?:^|[\\n;{}]|<\\?php|<\\?)\\s*' +
  '(?:(?:public|private|protected|static|abstract|final)\\s+)*' +
  'function\\s+' +
  '([A-Za-z_]\\w*)' +                  // function name (g1)
  '\\s*\\(([^)]*)\\)' +                // params (g2)
  '(?:\\s*:\\s*\\??[A-Za-z_]\\w*)?' +   // optional return type
  '\\s*\\{', 'g');

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
      if (c === '\\') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; buf += c; continue; }
    if (c === '/' && body[i + 1] === '/') {
      while (i < body.length && body[i] !== '\n') i++;
      continue;
    }
    if (c === '{' || c === '(' || c === '[') depth++;
    if (c === '}' || c === ')' || c === ']') depth--;
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

function _lowerExpr(text) {
  const s = String(text || '').trim();
  if (!s) return { kind: 'unknown' };
  // Stage 3 correctness audit (detection depth, per-language-IR): PHP
  // double-quoted strings interpolate variables directly
  // ("SELECT ... WHERE id=$id", "hi {$user->name}") — single-quoted
  // strings never do. This must run BEFORE the generic string-literal
  // fallback just below, which otherwise treated ANY quoted string
  // (including a double-quoted one containing a live variable) as an
  // opaque clean literal — silently dropping the interpolated variable's
  // taint. This is exactly `"SELECT ... WHERE id=$id"`, one of the most
  // common real PHP SQL-injection shapes. Simple (`$var`, `$var->prop`,
  // `$var[key]`) and complex (`{$expr}`) interpolation forms are both
  // lowered into a template, same shape as the `.`-concat branch below.
  if (/^"/.test(s) && s.includes('$')) {
    const inner = s.slice(1, -1);
    const re = /\{(\$[^}]+)\}|(\$[A-Za-z_]\w*(?:->[A-Za-z_]\w*|\[[^\]]+\])?)/g;
    let lastIndex = 0;
    const parts = [];
    let matched = false;
    let m;
    while ((m = re.exec(inner)) !== null) {
      matched = true;
      if (m.index > lastIndex) parts.push({ kind: 'literal', value: inner.slice(lastIndex, m.index) });
      parts.push(_lowerExpr(m[1] !== undefined ? m[1] : m[2]));
      lastIndex = re.lastIndex;
    }
    if (matched) {
      if (lastIndex < inner.length) parts.push({ kind: 'literal', value: inner.slice(lastIndex) });
      return { kind: 'tpl', parts };
    }
  }
  if (/^"/.test(s) || /^'/.test(s)) return { kind: 'literal', value: s };
  if (/^\d/.test(s)) return { kind: 'literal', value: s };
  if (/^(true|false|null|NULL)\b/.test(s)) return { kind: 'literal', value: s };
  // Superglobals
  if (/^\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION|ENV)\b/.test(s)) {
    const parts = s.split(/[\[\]'"]+/).filter(Boolean);
    if (parts.length === 1) return { kind: 'ident', name: parts[0] };
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) {
      cur = { kind: 'member', object: cur, prop: parts[i] || '[]' };
    }
    return cur;
  }
  // Variable
  if (/^\$[A-Za-z_]\w*$/.test(s)) return { kind: 'ident', name: s };
  // Method call: $obj->method(args) or ClassName::method(args).
  // matchBalancedCall finds the paren that actually balances the FIRST
  // '(' — not the greedy-to-end-of-string match the old `/\((.*)\)\s*$/`
  // used, which corrupted the argument text for a chained call
  // (`sanitize($x)->trim()` produced args="$x)->trim(", which then fell
  // through to {kind:'unknown'} and silently dropped $x).
  const methodCall = matchBalancedCall(s, /^(\$[\w]+(?:->[\w]+)*|[A-Za-z_][\w]*(?:::[\w]+)*)/);
  if (methodCall) {
    const callee = methodCall.callee.replace(/->/g, '.').replace(/::/g, '.');
    const args = _splitTopLevelCommas(methodCall.argsText).map(_lowerExpr);
    return { kind: 'call', callee, args };
  }
  // Function call: func(args)
  const funcCall = matchBalancedCall(s, /^([A-Za-z_][\w]*)/);
  if (funcCall) {
    return { kind: 'call', callee: funcCall.callee, args: _splitTopLevelCommas(funcCall.argsText).map(_lowerExpr) };
  }
  // Concat with .
  if (s.includes('.') && /["'\$]/.test(s)) {
    const parts = _splitTopLevelDot(s).map(_lowerExpr);
    return { kind: 'tpl', parts };
  }
  // Member: $obj->prop
  if (/^\$[\w]+(?:->[\w]+)+$/.test(s)) {
    const parts = s.split('->');
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) cur = { kind: 'member', object: cur, prop: parts[i] };
    return cur;
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

function _splitTopLevelDot(s) {
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
    if (c === '.' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function _lowerStmt(stmt, line) {
  const s = stmt.trim();
  if (!s || s.startsWith('//') || s.startsWith('#')) return null;
  if (/^return\b/.test(s)) {
    const rest = s.replace(/^return\s*/, '').trim();
    return { kind: 'return', line, value: rest ? _lowerExpr(rest) : null };
  }
  if (/^throw\b/.test(s)) {
    return { kind: 'throw', line, value: _lowerExpr(s.replace(/^throw\s+/, '')) };
  }
  // Assignment: $var = expr
  const assign = s.match(/^(\$[\w]+(?:->[\w]+)*)\s*=\s*(.+)$/s);
  if (assign) {
    return { kind: 'assign', line, target: assign[1], source: _lowerExpr(assign[2]) };
  }
  // Statement-form call
  const call = matchBalancedCall(s, /^(\$[\w]+(?:->[\w]+)*|[A-Za-z_][\w]*(?:::[\w]+)*)/);
  if (call) {
    const callee = call.callee.replace(/->/g, '.').replace(/::/g, '.');
    return { kind: 'call', line, callee, args: _splitTopLevelCommas(call.argsText).map(_lowerExpr) };
  }
  return null;
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
      if (c === '\\') { escape = true; i++; continue; }
      if (c === inStr) inStr = null;
      i++; continue;
    }
    if (c === '"' || c === '\'') { inStr = c; i++; continue; }
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

let _nid = 0;
function _nextId() { return `pn${++_nid}`; }

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

function _buildCfg(bodyText, nodes, prevId, startLine) {
  const stmts = _splitStatements(bodyText);
  let prev = prevId;
  let line = startLine;
  for (const stmt of stmts) {
    const s = stmt.trim();
    if (!s || s.startsWith('//') || s.startsWith('#')) { line++; continue; }

    const ifMatch = s.match(/^if\s*\((.+?)\)\s*\{([\s\S]*)\}(?:\s*else\s*\{([\s\S]*)\})?\s*$/s);
    if (ifMatch) {
      const ifNode = _addNode(nodes, { kind: 'if', cond: _lowerExpr(ifMatch[1]), line });
      _linkNodes(nodes, prev, ifNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      const thenTail = _buildCfg(ifMatch[2], nodes, ifNode, line + 1);
      _linkNodes(nodes, thenTail, join);
      if (ifMatch[3]) {
        const elseTail = _buildCfg(ifMatch[3], nodes, ifNode, line + 1);
        _linkNodes(nodes, elseTail, join);
      } else {
        _linkNodes(nodes, ifNode, join);
      }
      prev = join;
      line += (s.match(/\n/g) || []).length + 1;
      continue;
    }

    const whileMatch = s.match(/^while\s*\((.+?)\)\s*\{([\s\S]*)\}\s*$/s);
    if (whileMatch) {
      const header = _addNode(nodes, { kind: 'loop-header', line });
      _linkNodes(nodes, prev, header);
      const bodyTail = _buildCfg(whileMatch[2], nodes, header, line + 1);
      _linkNodes(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, header, join);
      prev = join;
      line += (s.match(/\n/g) || []).length + 1;
      continue;
    }

    const foreachMatch = s.match(/^foreach\s*\((.+?)\s+as\s+(?:\$\w+\s*=>\s*)?(\$\w+)\)\s*\{([\s\S]*)\}\s*$/s);
    if (foreachMatch) {
      const header = _addNode(nodes, { kind: 'loop-header', line });
      _linkNodes(nodes, prev, header);
      const assignId = _addNode(nodes, { kind: 'assign', target: foreachMatch[2], source: _lowerExpr(foreachMatch[1]), line });
      _linkNodes(nodes, header, assignId);
      const bodyTail = _buildCfg(foreachMatch[3], nodes, assignId, line + 1);
      _linkNodes(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _linkNodes(nodes, header, join);
      prev = join;
      line += (s.match(/\n/g) || []).length + 1;
      continue;
    }

    const node = _lowerStmt(s, line);
    if (!node) { line++; continue; }
    const id = _addNode(nodes, node);
    _linkNodes(nodes, prev, id);
    prev = id;
    line += (s.match(/\n/g) || []).length + 1;
  }
  return prev;
}

export function parsePhpFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.(?:php|phtml)$/i.test(file)) return null;
  if (code.length > 1_000_000) return null;

  const functions = [];
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
    // Don't skip past the closing brace: for `<?php function h(){...} function m(){...}`
    // that brace is the only boundary character available to anchor the next
    // function's match (there's no newline/semicolon between them), and advancing
    // past it here would make the following function declaration unmatchable.
    FUNC_RE.lastIndex = extracted.end;
  }
  return functions.length ? { file, functions, topLevel: null } : null;
}
