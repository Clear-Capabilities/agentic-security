// Go IR frontend.
//
// Regex-based, follows the parser-cs.js / parser-kt.js pattern. Focused on
// net/http, gin, echo, chi, gorm, database/sql surface area.
//
// What we model:
//   - func declarations: top-level, method receivers, closures (top-level only)
//   - := short declarations and = assignments
//   - method / function calls
//   - return
//   - if / for / switch as linear blocks (body treated as straight-line)
//   - defer / go as call nodes
//   - fmt.Sprintf as template literal
//   - multi-return first-target tracking: a, err := f()
//
// What we do NOT model:
//   - goroutine channel taint (send/receive)
//   - interface dispatch (dynamic method resolution)
//   - generics (type params)
//   - select statements (treated as noop)
//   - struct field assignments (x.Field = val) beyond simple dotted targets

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';
import { matchBalancedCall } from './balanced-call.js';

const FUNC_RE = new RegExp(
  '(?:^|[\\n;{}])\\s*func\\s+' +
  '(?:\\(\\s*(\\w+)\\s+\\*?([A-Za-z_]\\w*)\\s*\\)\\s+)?' + // optional receiver (g1=name, g2=type)
  '([A-Za-z_]\\w*)' +                                       // func name (g3)
  '\\s*\\(([^)]*)\\)' +                                     // params (g4)
  '(?:\\s*(?:\\([^)]*\\)|[A-Za-z_*\\[\\]\\w.,\\s]*))?' +     // optional return type(s)
  '\\s*\\{', 'g');

function _splitStatements(body) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  let inRaw = false;
  let escape = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (escape) { buf += c; escape = false; continue; }
    if (inStr) {
      buf += c;
      if (c === '\\' && inStr === '"') { escape = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (inRaw) {
      buf += c;
      if (c === '`') inRaw = false;
      continue;
    }
    if (c === '"' || c === '\'') { inStr = c; buf += c; continue; }
    if (c === '`') { inRaw = true; buf += c; continue; }
    if (c === '/' && body[i + 1] === '/') {
      while (i < body.length && body[i] !== '\n') i++;
      continue;
    }
    if (c === '{' || c === '(' || c === '[') depth++;
    if (c === '}' || c === ')' || c === ']') depth--;
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

// Taint-recall PRD (80%): a chained call (`w.Header().Set("X", tainted)`,
// `template.New("page").Parse(userTemplate)`) previously stopped at the
// FIRST balanced call, leaving any `.Method(args)` continuation
// unconsumed — matchBalancedCall's own deliberate design, correct for not
// corrupting the parse, but it meant the OUTER call — frequently the one
// actually carrying the sink and its tainted argument — was silently
// absent from the CFG. Confirmed via two real corpus fixtures (Go's
// response-splitting and code-injection entries both hit this). Same
// dot-joining approach as parser-cs.js's twin fix.
//
// Args from EVERY level are kept, outermost-first (`outerArgs.concat(prior)`
// at each step) — NOT just the outermost. A first version kept only the
// outermost call's args, which broke a real 3-level chain
// (`X().getEngineByName("js").eval(userCode)`-shaped) where the tainted
// value sits on an INNER call, not the final one — the outer call's own
// args (if any) correctly stay at the front so an existing `argIndex: 0`
// catalog entry keyed to the outermost call is unaffected; the inner
// levels' args are appended after so an `argIndex: 'all'` entry can still
// find taint that only an inner call actually carried.
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
  if (/^fmt\.Sprintf\s*\(/.test(s)) {
    // Same balanced-paren concern as the call patterns below — a chained
    // call after fmt.Sprintf(...) (rare but not impossible via a wrapper)
    // would otherwise have its args text swallow the chain's own parens.
    const sprintf = matchBalancedCall(s, /^fmt\.Sprintf/);
    const inner = sprintf ? sprintf.argsText : s.slice(s.indexOf('(') + 1, s.lastIndexOf(')'));
    const parts = _splitTopLevelCommas(inner).map(_lowerExpr);
    return { kind: 'tpl', parts };
  }
  // R3 (PRD §5): string concat with `+` MUST be checked before the bare-literal
  // rule below — otherwise `"SELECT " + q` (starts with `"`) is captured whole as
  // a single literal and taint cannot flow through the concatenation. Only fires
  // when there's a top-level `+` (a pure literal still falls through to literal).
  if (/["'`]/.test(s) && s.includes('+')) {
    const plusParts = _splitTopLevelPlus(s);
    if (plusParts.length > 1) return { kind: 'tpl', parts: plusParts.map(_lowerExpr) };
  }
  if (/^"/.test(s) || /^`/.test(s)) return { kind: 'literal', value: s };
  if (/^\d/.test(s)) return { kind: 'literal', value: s };
  if (/^(true|false|nil)\b/.test(s)) return { kind: 'literal', value: s };
  // Call: foo.Bar(args) or Bar(args). matchBalancedCall finds the paren
  // that actually balances the FIRST '(' — not the greedy-to-end-of-string
  // match the old `/\((.*)\)\s*$/` used, which corrupted the argument text
  // for a chained call (`Sanitize(x).Trim()` produced args="x).Trim(",
  // which then fell through to {kind:'unknown'} and silently dropped x).
  const callMatch = matchBalancedCall(s, /^([\w.]+)/);
  if (callMatch) {
    const args = _splitTopLevelCommas(callMatch.argsText).map(_lowerExpr);
    return _followChain(s, callMatch.endIdx, callMatch.callee, args);
  }
  // String concat with + — a SECOND occurrence of the same check as above
  // (line ~92), reached when the expression didn't match any branch in
  // between (calls, literals, etc.). It's missing the `parts.length > 1`
  // guard the first occurrence has: when the `+` sits inside an extra
  // pair of parens (`("SELECT " + name)` — e.g. an over-parenthesized
  // argument), `_splitTopLevelPlus` returns the input unchanged as ONE
  // part (depth never returns to 0 at the `+`), and `.map(_lowerExpr)`
  // then recurses on the IDENTICAL string forever — a stack overflow,
  // uncaught here (only caught by buildProjectIR's per-file try/catch, so
  // it surfaces only as "this file has no IR"). Same bug class, same fix,
  // as parser-cs.js's `_splitTopLevelPlus` guard for `new Type(concat)`.
  if (s.includes('+') && /["'`]/.test(s)) {
    const parts = _splitTopLevelPlus(s);
    if (parts.length > 1) return { kind: 'tpl', parts: parts.map(_lowerExpr) };
  }
  // Member: a.b.c
  if (/^[A-Za-z_][\w.]*$/.test(s)) {
    const parts = s.split('.');
    if (parts.length === 1) return { kind: 'ident', name: parts[0] };
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) cur = { kind: 'member', object: cur, prop: parts[i] };
    return cur;
  }
  // Indexing: a[b] or a["key"]
  if (/^[A-Za-z_][\w.]*\[/.test(s)) {
    const lb = s.indexOf('[');
    const base = s.slice(0, lb);
    const parts = base.split('.');
    let cur = { kind: 'ident', name: parts[0] };
    for (let i = 1; i < parts.length; i++) cur = { kind: 'member', object: cur, prop: parts[i] };
    return { kind: 'member', object: cur, prop: '[]' };
  }
  // Struct literal: Type{...}
  if (/^[A-Za-z_]\w*\s*\{/.test(s)) {
    return { kind: 'object', props: [] };
  }
  // Address-of / dereference
  if (s.startsWith('&') || s.startsWith('*')) return _lowerExpr(s.slice(1));
  return { kind: 'unknown' };
}

function _splitTopLevelCommas(s) {
  const out = [];
  let buf = '';
  let depth = 0;
  let inStr = null;
  let inRaw = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      buf += c;
      if (c === '\\' && inStr === '"') { i++; buf += s[i] || ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (inRaw) { buf += c; if (c === '`') inRaw = false; continue; }
    if (c === '"') { inStr = c; buf += c; continue; }
    if (c === '`') { inRaw = true; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
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
      if (c === '\\' && inStr === '"') { i++; buf += s[i] || ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === '`') { inStr = c; buf += c; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    if (c === ')' || c === '}' || c === ']') depth--;
    if (c === '+' && depth === 0) { out.push(buf.trim()); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function _lowerStmt(stmt, line) {
  const s = stmt.trim();
  if (!s || s.startsWith('//')) return null;
  // return
  if (/^return\b/.test(s)) {
    const rest = s.replace(/^return\s*/, '').trim();
    // Multi-return: return a, b → take the first
    const parts = _splitTopLevelCommas(rest);
    const value = parts.length ? _lowerExpr(parts[0]) : null;
    return { kind: 'return', line, value };
  }
  // defer / go: treat as call
  if (/^(?:defer|go)\s+/.test(s)) {
    const rest = s.replace(/^(?:defer|go)\s+/, '').trim();
    const cm = rest.match(/^([\w.]+)\s*\((.*)\)\s*$/s);
    if (cm) {
      return { kind: 'call', line, callee: cm[1], args: _splitTopLevelCommas(cm[2]).map(_lowerExpr) };
    }
    return { kind: 'noop', line };
  }
  // Short variable declaration: a, b := expr  or  a := expr
  const shortDecl = s.match(/^(\w+(?:\s*,\s*\w+)*)\s*:=\s*(.+)$/s);
  if (shortDecl) {
    const targets = shortDecl[1].split(',').map(t => t.trim());
    const rhs = shortDecl[2].trim();
    if (targets.length === 1) {
      return { kind: 'assign', line, target: targets[0], source: _lowerExpr(rhs) };
    }
    // Multi-return: a, err := f() → assign first target
    return { kind: 'assign', line, target: targets[0], source: _lowerExpr(rhs) };
  }
  // Regular assignment: a = expr  or  a.b = expr
  const assign = s.match(/^([A-Za-z_][\w.]*)\s*=\s*(.+)$/s);
  if (assign) {
    return { kind: 'assign', line, target: assign[1], source: _lowerExpr(assign[2]) };
  }
  // var declaration: var name Type = expr  or  var name = expr
  const varDecl = s.match(/^var\s+(\w+)\s+(?:\w[\w.*[\]]*\s*)?=\s*(.+)$/s);
  if (varDecl) {
    return { kind: 'assign', line, target: varDecl[1], source: _lowerExpr(varDecl[2]) };
  }
  // Statement-form call: obj.Method(args) or Method(args)
  const cm = matchBalancedCall(s, /^([\w.]+)/);
  if (cm) {
    const chained = _followChain(s, cm.endIdx, cm.callee, _splitTopLevelCommas(cm.argsText).map(_lowerExpr));
    return { kind: 'call', line, callee: chained.callee, args: chained.args };
  }
  return null;
}

// Taint-recall PRD (80%): Go's dominant HTTP-handler-registration idiom
// across every framework this file targets (net/http, gin, echo, fiber,
// chi) is an inline anonymous closure passed as the LAST argument to a
// registration call — `app.Get("/p", func(c *fiber.Ctx) error { ... })`,
// `http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
// ... })`. This parser previously had ZERO support for anonymous
// functions: `FUNC_RE` requires a NAME between `func` and `(`, so an
// inline closure never matched it at all, and `_lowerExpr`'s generic
// call-matching regex mis-parsed `func(params) rtype { body }` as a call
// to something literally named "func" — `matchBalancedCall` correctly
// captured only `(params)` as that "call"'s own args, and the return-type
// token plus the ENTIRE closure body were silently discarded (no
// `.method(...)` continuation follows a return type, so `_followChain`
// found nothing to recover). This was very likely this PRD's single most
// consequential Go gap: it made every framework's route-handler BODY
// invisible to taint analysis regardless of what it did — found via this
// PRD's Tier 3 audit, not the parent PRD's original per-language sweep.
const CLOSURE_ARG_RE = /^func\s*\(([^)]*)\)\s*(?:\([^)]*\)|[\w*[\].\s]*)?\s*\{/;

// If the LAST top-level comma-separated part of `argsText` is an inline
// closure literal, extracts its body text and returns `{ body, closureText,
// prefixParts }` — `prefixParts` are the OTHER top-level args (unchanged,
// still to be lowered normally), `closureText` is the exact substring
// matched (used by the caller to locate its start line within the
// enclosing statement). Returns null when there is no trailing closure —
// every existing call site is unaffected.
function _extractTrailingClosureArg(argsText) {
  const parts = _splitTopLevelCommas(argsText);
  if (!parts.length) return null;
  const last = parts[parts.length - 1];
  const m = last.match(CLOSURE_ARG_RE);
  if (!m) return null;
  const openBrace = last.indexOf('{', m[0].length - 1);
  if (openBrace < 0) return null;
  const extracted = _extractBody(last, openBrace);
  if (!extracted) return null;
  return { body: extracted.body, closureText: last, prefixParts: parts.slice(0, -1) };
}

function _countNewlinesUpTo(s, upTo) {
  let n = 0;
  const end = Math.min(upTo, s.length);
  for (let i = 0; i < end; i++) if (s[i] === '\n') n++;
  return n;
}

function _extractBody(src, openBrace) {
  let depth = 1;
  let i = openBrace + 1;
  let inStr = null;
  let inRaw = false;
  let escape = false;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (escape) { escape = false; i++; continue; }
    if (inStr) {
      if (c === '\\' && inStr === '"') { escape = true; i++; continue; }
      if (c === inStr) inStr = null;
      i++; continue;
    }
    if (inRaw) { if (c === '`') inRaw = false; i++; continue; }
    if (c === '"') { inStr = c; i++; continue; }
    if (c === '`') { inRaw = true; i++; continue; }
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

function _parseGoParams(paramsText) {
  if (!paramsText.trim()) return [];
  const parts = _splitTopLevelCommas(paramsText);
  const params = [];
  for (const p of parts) {
    const t = p.trim();
    if (!t) continue;
    // "name Type" or "name, name2 Type" or just "Type" (unnamed)
    const tokens = t.split(/\s+/);
    if (tokens.length >= 2) {
      // Could be "name Type" or "name *Type" or "name ...Type"
      const name = tokens[0].replace(/^\*/, '');
      if (/^[a-z_]\w*$/i.test(name) && !/^(?:func|chan|map|interface|struct)$/.test(name)) {
        params.push(name);
      }
    } else if (tokens.length === 1) {
      // Single token — could be just a type (unnamed param) or a name
      // In Go, if it looks like a lowercase identifier, it's likely a name
      const t0 = tokens[0].replace(/^\*/, '').replace(/^\.\.\./, '');
      if (/^[a-z_]\w*$/.test(t0) && !/^(?:int|string|bool|byte|rune|float32|float64|error|any|interface)$/.test(t0)) {
        params.push(t0);
      }
    }
  }
  return params;
}

let _nid = 0;
function _nextId() { return `gn${++_nid}`; }

function _addNode(nodes, node) {
  const id = _nextId();
  node.succ = node.succ || [];
  node.pred = node.pred || [];
  nodes[id] = node;
  return id;
}

function _link(nodes, src, dst) {
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
    if (!s || s.startsWith('//')) { line++; continue; }

    // if statement with brace body
    const ifMatch = s.match(/^if\s+([\s\S]+?)\s*\{([\s\S]*)\}(?:\s*else\s*\{([\s\S]*)\})?\s*$/s) ||
                    s.match(/^if\s+([\s\S]+?)\s*\{([\s\S]*)\}\s*$/s);
    if (ifMatch) {
      const condText = ifMatch[1].replace(/;[^;]*$/, '').trim();
      const thenBody = ifMatch[2];
      const elseBody = ifMatch[3] || null;
      const ifNode = _addNode(nodes, { kind: 'if', cond: _lowerExpr(condText), line });
      _link(nodes, prev, ifNode);
      const join = _addNode(nodes, { kind: 'noop', line });
      const thenTail = _buildCfg(thenBody, nodes, ifNode, line + 1);
      _link(nodes, thenTail, join);
      if (elseBody) {
        const elseTail = _buildCfg(elseBody, nodes, ifNode, line + 1);
        _link(nodes, elseTail, join);
      } else {
        _link(nodes, ifNode, join);
      }
      prev = join;
      line += (s.match(/\n/g) || []).length + 1;
      continue;
    }

    // for loop with brace body
    const forMatch = s.match(/^for\s+([\s\S]*?)\s*\{([\s\S]*)\}\s*$/s);
    if (forMatch) {
      const header = _addNode(nodes, { kind: 'loop-header', line });
      _link(nodes, prev, header);
      const loopBody = forMatch[2];
      // for-range: extract loop variable assignment
      const rangeMatch = forMatch[1].match(/^(\w+)(?:\s*,\s*(\w+))?\s*:=\s*range\s+(.+)$/s);
      let bodyPrev = header;
      if (rangeMatch) {
        const loopVar = rangeMatch[2] || rangeMatch[1];
        const iterExpr = rangeMatch[3];
        const assignId = _addNode(nodes, { kind: 'assign', target: loopVar, source: _lowerExpr(iterExpr), line });
        _link(nodes, header, assignId);
        bodyPrev = assignId;
      }
      const bodyTail = _buildCfg(loopBody, nodes, bodyPrev, line + 1);
      _link(nodes, bodyTail, header);
      const join = _addNode(nodes, { kind: 'noop', line });
      _link(nodes, header, join);
      prev = join;
      line += (s.match(/\n/g) || []).length + 1;
      continue;
    }

    // Statement-form call whose LAST top-level argument is an inline
    // closure literal — see `_extractTrailingClosureArg` above. Recall-
    // preserving inlining: the closure genuinely runs later (often
    // asynchronously, on a request), but for taint analysis what matters
    // is that its statements become real CFG nodes at all. The closure's
    // OWN parameter (`c`, `w`, `r`) needs no synthetic taint binding, unlike
    // e.g. Kotlin's `.forEach { x -> ... }`: a framework context object
    // isn't itself a taint source — `c.Query(...)` is recognized by the
    // EXISTING member/call-source catalog matching regardless of which
    // function scope `c` was declared in. Chained calls before the closure
    // arg (`app.Group("/api").Get(path, func(){...})`) are not specially
    // handled — out of scope for this fix, matches this file's existing
    // "handle the dominant shape" precedent elsewhere.
    const closureCall = matchBalancedCall(s, /^([\w.]+)/);
    if (closureCall) {
      const closure = _extractTrailingClosureArg(closureCall.argsText);
      if (closure) {
        const outerArgs = closure.prefixParts.map(_lowerExpr);
        const callId = _addNode(nodes, { kind: 'call', line, callee: closureCall.callee, args: outerArgs });
        _link(nodes, prev, callId);
        const closureOffset = s.indexOf(closure.closureText);
        const bodyStartLine = closureOffset >= 0
          ? line + _countNewlinesUpTo(s, closureOffset)
          : line;
        prev = _buildCfg(closure.body, nodes, callId, bodyStartLine);
        line += (s.match(/\n/g) || []).length + 1;
        continue;
      }
    }

    // Regular statement
    const node = _lowerStmt(s, line);
    if (!node) { line++; continue; }
    const id = _addNode(nodes, node);
    _link(nodes, prev, id);
    prev = id;
    line += (s.match(/\n/g) || []).length + 1;
  }
  return prev;
}

export function parseGoFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.go$/i.test(file)) return null;
  if (code.length > 1_000_000) return null;

  const functions = [];
  FUNC_RE.lastIndex = 0;
  _nid = 0;
  let m;
  while ((m = FUNC_RE.exec(code)) !== null) {
    const receiverName = m[1] || null;
    const name = m[3];
    const paramsText = m[4] || '';
    const params = _parseGoParams(paramsText);
    if (receiverName && !params.includes(receiverName)) {
      params.unshift(receiverName);
    }
    const braceIdx = code.indexOf('{', m.index + m[0].length - 1);
    if (braceIdx < 0) continue;
    const extracted = _extractBody(code, braceIdx);
    if (!extracted) continue;
    const startLine = _lineAt(code, m.index);
    const nodes = {};
    const entry = _addNode(nodes, { kind: 'entry', line: startLine });
    const exit = _addNode(nodes, { kind: 'exit', line: startLine });
    const tail = _buildCfg(extracted.body, nodes, entry, startLine + 1);
    _link(nodes, tail, exit);
    const cfg = { entry, exit, nodes };
    functions.push({
      qid: _qid(file, name, startLine, extracted.body),
      name, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
    });
    FUNC_RE.lastIndex = extracted.end + 1;
  }
  return functions.length ? { file, functions, topLevel: null } : null;
}
