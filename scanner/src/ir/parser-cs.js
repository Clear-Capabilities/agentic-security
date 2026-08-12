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
//
// What we do NOT model (regex-fallback class limits):
//   - LINQ expressions (treated as opaque expression)
//   - lambdas (body collapsed)
//   - async/await (transparent)
//   - generics on declarations beyond Type<...> name
//   - attributes (skipped)
//   - destructuring / tuples
//   - control flow (if/for/while/switch) — body is treated as straight-line;
//     this is enough for the source-reaches-sink shapes we care about.
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

// Matches a top-level statement inside a method body. We split on `;` only
// at brace-depth 0; this keeps simple lambdas inside calls intact.
function _splitStatements(body) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inString = null;     // null | '"' | "'" | '@"' style
  let escape = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (escape) { buf += c; escape = false; continue; }
    if (inString) {
      buf += c;
      if (inString === '"' && c === '\\') { escape = true; continue; }
      if (c === inString) inString = null;
      continue;
    }
    if (c === '"' || c === "'") { inString = c; buf += c; continue; }
    if (c === '{' || c === '(' || c === '[') depth++;
    if (c === '}' || c === ')' || c === ']') depth--;
    if (c === ';' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
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

export function parseCSharpFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  const functions = [];
  METHOD_RE.lastIndex = 0;
  let m;
  while ((m = METHOD_RE.exec(code)) !== null) {
    const name = m[2];
    const paramsText = m[3] || '';
    const params = paramsText.split(',').map(p => {
      const t = p.trim();
      if (!t) return null;
      // "Type name" → name. "Type<T> name" → name. "Type[] name = default" → name.
      const last = t.replace(/=.*$/, '').trim().split(/\s+/).pop();
      return last && /^[A-Za-z_][\w]*$/.test(last) ? last : null;
    }).filter(Boolean);
    const braceIdx = code.indexOf('{', m.index + m[0].length - 1);
    if (braceIdx < 0) continue;
    const extracted = _extractBody(code, braceIdx);
    if (!extracted) continue;
    const startLine = _lineAt(code, m.index);
    const stmts = _splitStatements(extracted.body);
    // Build a linear CFG: entry → s1 → s2 → ... → exit.
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
      // Approximate per-statement line advance by counting '\n' in source.
      // (Cheap, good-enough for finding line attribution.)
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
    METHOD_RE.lastIndex = extracted.end + 1;
  }
  return { file, functions, topLevel: null };
}
