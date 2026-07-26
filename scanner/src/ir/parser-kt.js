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
//
// What we do NOT model:
//   - lambdas (collapsed to opaque expression)
//   - destructuring `val (a, b) = pair`
//   - `if`/`when`/`for`/`while` control flow (body treated as straight-line)
//   - infix functions (the call shape isn't recognized)
//   - operator overloading
//
// Single-pass v1. Roslyn-equivalent for Kotlin (kotlinc -p ir or PSI via
// gradle helper) is the upgrade path.

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';

const FUN_RE = new RegExp(
  '(?:^|[\\s;{}])(?:public|private|internal|protected|inline|suspend|tailrec|operator|infix|open|abstract|override|final|external)?' +
  '(?:\\s+(?:public|private|internal|protected|inline|suspend|tailrec|operator|infix|open|abstract|override|final|external))*' +
  '\\s*fun\\s+(?:[A-Za-z_][\\w.]*\\.)?' +              // optional receiver-type prefix
  '([A-Za-z_][\\w]*)' +                                // function name (group 1)
  '\\s*\\(([^)]*)\\)' +                                // params (group 2)
  '\\s*(?::\\s*[A-Za-z_][\\w<>?,\\s.]*)?\\s*\\{', 'g'); // optional return type then '{'

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
  // Call
  const callMatch = s.match(/^([\w.]+)\s*\((.*)\)\s*$/s);
  if (callMatch) {
    return {
      kind: 'call',
      callee: callMatch[1],
      args: _splitTopLevelCommas(callMatch[2]).map(_lowerExpr),
    };
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
  // Statement-form call
  const cm = s.match(/^([\w.]+)\s*\((.*)\)\s*$/s);
  if (cm) return { kind: 'call', line, callee: cm[1], args: _splitTopLevelCommas(cm[2]).map(_lowerExpr) };
  return { kind: 'unknown', line, text: s };
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

function _qid(file, name, line, body) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  return `${file}::${name}@${line}#${sha}`;
}

export function parseKotlinFile(file, code) {
  if (!file || typeof code !== 'string') return null;
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
    const stmts = _splitStatements(extracted.body);
    const nodes = {};
    nodes.entry = { kind: 'entry', line: startLine, succ: [], pred: [] };
    nodes.exit  = { kind: 'exit',  line: startLine, succ: [], pred: [] };
    let prev = 'entry';
    let stmtLine = startLine;
    for (let idx = 0; idx < stmts.length; idx++) {
      const node = _lowerStmt(stmts[idx], stmtLine);
      if (!node) continue;
      const id = `n${idx}`;
      nodes[id] = { ...node, succ: [], pred: [prev] };
      nodes[prev].succ.push(id);
      prev = id;
      stmtLine += (stmts[idx].match(/\n/g) || []).length + 1;
    }
    nodes[prev].succ.push('exit');
    nodes.exit.pred.push(prev);
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
