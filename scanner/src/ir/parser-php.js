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

// Returns `{ text, line }[]` — `line` is the 1-indexed line, relative to the
// START of `body`, of the first non-whitespace character of that statement.
// This is computed from the ACTUAL scan position (a running `curLine`
// incremented on every physical `\n` encountered, including ones skipped
// inside a `//` comment) rather than by re-counting newlines inside the
// already-trimmed statement text afterwards — that reconstruction is lossy:
// `.trim()` discards any leading blank lines (or blanked-out characters —
// see parser-php.js's `_blankSpans`/`_buildCfg` module-level lowering) before
// a statement's real content, so a caller that tried to recover the line by
// counting embedded newlines would silently undercount by exactly the
// number of blank lines that preceded the statement. This was the root
// cause of PHP module-level findings reporting the wrong line and, in turn,
// making the line-scoped `agentic-security-ignore` suppression pragma inert
// for them (Finding 2 of the R14(b) final whole-branch review).
function _splitStatements(body) {
  const out = [];
  let buf = '';
  let bufLine = null; // line of the first non-whitespace char seen in `buf` so far
  let curLine = 1;    // line of body[i], the character currently under the cursor
  let depth = 0;
  let inStr = null;
  let escape = false;
  const push = (c) => {
    buf += c;
    if (bufLine === null && !/\s/.test(c)) bufLine = curLine;
  };
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (escape) { push(c); escape = false; if (c === '\n') curLine++; continue; }
    if (inStr) {
      push(c);
      if (c === '\\') { escape = true; if (c === '\n') curLine++; continue; }
      if (c === inStr) inStr = null;
      if (c === '\n') curLine++;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; push(c); continue; }
    if (c === '/' && body[i + 1] === '/') {
      while (i < body.length && body[i] !== '\n') i++;
      if (i < body.length) curLine++; // the newline terminating the comment
      continue;
    }
    if (c === '{' || c === '(' || c === '[') depth++;
    if (c === '}' || c === ')' || c === ']') depth--;
    if (c === ';' && depth === 0) {
      const t = buf.trim();
      if (t) out.push({ text: t, line: bufLine ?? curLine });
      buf = '';
      bufLine = null;
      continue;
    }
    push(c);
    if (c === '\n') curLine++;
  }
  const t = buf.trim();
  if (t) out.push({ text: t, line: bufLine ?? curLine });
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
  //
  // The `parts.length > 1` guard is load-bearing, not defensive tidiness:
  // when every `.` in `s` is nested inside brackets or strings (e.g.
  // `s = '"y.z"'` in `["health" => "check.status"]`), `_splitTopLevelDot`
  // returns `[s]` — the input unchanged, as a single part — and mapping
  // `_lowerExpr` over it recurses on the IDENTICAL string forever (stack
  // overflow). Before R14(b) this was only reachable from inside function
  // bodies; the module-level lowering now feeds every top-level statement
  // through here too, so real files (e.g. a top-level array literal with a
  // dotted string value) hit it and the per-file catch in `ir/index.js`
  // silently dropped the whole file from Layer-2 analysis. Same shape as
  // parser-cs.js's `_splitTopLevelPlus` guard.
  if (s.includes('.') && /["'\$]/.test(s)) {
    const rawParts = _splitTopLevelDot(s);
    if (rawParts.length > 1) return { kind: 'tpl', parts: rawParts.map(_lowerExpr) };
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

// FUNC_RE's leading alternation `(?:^|[\n;{}]|<\?php|<\?)` matches a single
// "boundary" character/token that belongs to whatever precedes the function
// (a statement terminator, a brace, or the PHP open tag) — not to the
// function itself. `m.index` always points at the START of that boundary,
// so including it verbatim in the function's span would blank away e.g. the
// `;` that terminates the PRECEDING top-level statement once the whole file
// is lowered in a single _buildCfg pass (see _blankSpans below), silently
// merging that statement with whatever gap text follows the function. This
// returns how many characters of the boundary token were actually consumed
// so the function's span can be made to start right after it.
function _funcBoundaryLen(code, idx) {
  if (idx > 0) {
    const c = code[idx];
    if (c === '\n' || c === ';' || c === '{' || c === '}') return 1;
  }
  if (/^<\?php/i.test(code.slice(idx, idx + 5))) return 5;
  if (/^<\?/.test(code.slice(idx, idx + 2))) return 2;
  return 0;
}

// Blank out every real function's span in a COPY of the full source
// (replace its characters with spaces, preserving every newline exactly).
// This lets the WHOLE file be lowered in a single _buildCfg call at
// startLine=1 for the module-level CFG, which keeps every remaining
// statement's reported line number exactly equal to its real source line —
// no character is ever deleted, only turned into a space, so nothing can
// shift. This replaces the old per-gap slicing + per-gap startLine
// re-derivation, which mis-tracked lines whenever a gap slice started with
// leading blank/newline characters and broke the line-scoped
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

// Blanks a leading PHP open tag (`<?php` or `<?`) if the file starts with
// one. Only the true start of the file is handled (matching the previous
// behavior's `cursor === 0` scope) — this is a real fix, not dead code:
// when top-level content sits between the open tag and the first function
// declaration (e.g. `<?php\n$x = [...];\nfunction f(){}`), the tag is NOT
// part of any function's span (the boundary FUNC_RE actually consumed
// before `function f` is the `;`, not the tag — see _funcBoundaryLen), so
// it survives into the blanked text as literal `<?php` characters. Left
// unblanked, that text glues onto the front of the first top-level
// statement (`<?php\n$x = [...]`), which then fails every `_lowerStmt`
// pattern (all anchored at the true start of the statement) and silently
// drops it. Blanking (not deleting) the tag keeps line numbers exact.
function _blankLeadingOpenTag(text) {
  const m = text.match(/^<\?(?:php)?/i);
  if (!m) return text;
  return _blank(m[0]) + text.slice(m[0].length);
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

// `startLine` is the absolute source line of the FIRST character of
// `bodyText`. Each statement's absolute line is `startLine + stmt.line - 1`
// (`stmt.line` from _splitStatements is already 1-indexed and relative to
// `bodyText`), so — unlike the old incremental `line++`/`line += newlines+1`
// bookkeeping this replaced — no line is ever derived by re-counting
// newlines in already-trimmed text. That old scheme silently dropped any
// blank line (or, at module level, any blanked-out function span — see
// `_blankSpans`) that preceded a statement, which is exactly what made
// module-level PHP findings report the wrong source line.
function _buildCfg(bodyText, nodes, prevId, startLine) {
  const stmts = _splitStatements(bodyText);
  let prev = prevId;
  for (const stmt of stmts) {
    const s = stmt.text;
    const line = startLine + stmt.line - 1;
    if (!s || s.startsWith('//') || s.startsWith('#')) continue;

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

export function parsePhpFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.(?:php|phtml)$/i.test(file)) return null;
  if (code.length > 1_000_000) return null;

  const functions = [];
  const spans = []; // {start, end}: source ranges fully consumed by a matched function (signature through closing brace)
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
    // span.end is exclusive (points after the closing brace), so interior and trailing
    // gaps both work correctly without special casing. extracted.end points AT the brace,
    // so we add 1 to make it exclusive. We keep FUNC_RE.lastIndex at extracted.end
    // (the brace position) so subsequent function matches can use it as a boundary.
    // span.start is m.index PLUS the boundary token FUNC_RE consumed ahead of the
    // function itself (see _funcBoundaryLen) — the boundary char/tag belongs to
    // whatever precedes the function, not to the function's own blanked span.
    spans.push({ start: m.index + _funcBoundaryLen(code, m.index), end: extracted.end + 1 });
    // Don't skip past the closing brace: for `<?php function h(){...} function m(){...}`
    // that brace is the only boundary character available to anchor the next
    // function's match (there's no newline/semicolon between them), and advancing
    // past it here would make the following function declaration unmatchable.
    FUNC_RE.lastIndex = extracted.end;
  }

  // R14(b): lower top-level (module-scope) statements into a synthetic
  // <module> function, mirroring parser-js.js's Program-level lowering.
  // Every real function's span is blanked (see _blankSpans) in a copy of
  // the full source, and the WHOLE blanked text is lowered in a single
  // _buildCfg call at startLine=1 — this keeps every remaining statement's
  // reported line number exactly equal to its real source line, since no
  // character is ever deleted, only blanked to a space (newlines always
  // survive). No new statement-classification logic is needed.
  spans.sort((a, b) => a.start - b.start);
  const blanked = _blankLeadingOpenTag(_blankSpans(code, spans));
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
