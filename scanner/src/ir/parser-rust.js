// Rust IR frontend.
//
// Hand-rolled, following the parser-go.js / parser-cs.js pattern: one
// preprocessing pass normalizes the source (comments blanked with line
// structure preserved, `::` paths flattened to dots, turbofish/`?`/`.await`
// removed), then a statement splitter and a recursive CFG builder lower each
// function body into the IR contract documented in ./CLAUDE.md.
//
// What we model:
//   - fn items (free, impl, trait default) with pub/async/unsafe/const/extern
//     qualifiers, generics, where clauses; impl methods are named `Type.method`
//   - let / let mut / destructuring let / let-else; assignments; compound
//     assignments (`+=` lowers to a template of old value + rhs)
//   - calls and method chains, dot-joined, args accumulated innermost-first
//     (source order), so `Command::new("sh").arg("-c").arg(x)` has the literal
//     program name at arg 0
//   - macros: format!-family lower to templates (inline `{ident}` args and
//     positional args), vec! to arrays, every other macro to a call whose
//     callee keeps its `!` (so `sqlx::query!` never matches the `query` sink)
//   - if / else if / else, if let, while, while let, loop, for, match arms
//     (pattern bindings assigned from the scrutinee), unsafe/bare/async blocks
//   - control flow in expression position (`let x = match … { … }`) yields a
//     union of the branch tails
//   - closures passed as call arguments are inlined, parameters bound to the
//     call's receiver; extractor-typed closure params become synthetic sources
//   - fn.paramAnnotations for framework extractor types (Query/Path/Json/Form/
//     HeaderMap/…) and for route-attributed handlers (`#[get("/<x>")]`)
//
// What we do NOT model:
//   - trait dispatch, generics as types, lifetimes (stripped as text)
//   - closures stored in variables and invoked later
//   - struct field taint through method receivers beyond simple dotted paths
//   - labeled breaks, `?` early-return control flow (the `?` is stripped, the
//     happy path is what taint needs)

import * as crypto from 'node:crypto';
import { callSitesFromCfg } from './call-sites.js';

const U = { kind: 'unknown' };

// ─── literal scanning ────────────────────────────────────────────────────────
// Returns the index just past a string/char literal starting at `i`, or `i`
// when no literal starts there. Every splitter below routes through this so
// braces, commas and semicolons inside literals never count.
function _literalEnd(s, i) {
  const c = s[i];
  const prevIsWord = i > 0 && /[\w]/.test(s[i - 1]);
  if (c === '"') return _scanDq(s, i + 1);
  if (c === '\'') {
    if (s[i + 1] === '\\') {
      // '\n', '\'', '\u{1F600}'
      let j = i + 2;
      if (s[j] === 'u' && s[j + 1] === '{') { j = s.indexOf('}', j); if (j < 0) return i; j++; } else j++;
      return s[j] === '\'' ? j + 1 : i;
    }
    const cp = s.codePointAt(i + 1);
    const w = cp > 0xffff ? 2 : 1;
    if (s[i + 1 + w] === '\'' && s[i + 1] !== '\'') return i + 2 + w;
    return i; // lifetime or label
  }
  if (prevIsWord) return i;
  // raw / byte / c-string prefixes
  const m = /^(?:br|cr|r)(#*)"/.exec(s.slice(i, i + 12));
  if (m) {
    const hashes = m[1];
    const close = '"' + hashes;
    const j = s.indexOf(close, i + m[0].length);
    return j < 0 ? s.length : j + close.length;
  }
  if ((c === 'b' || c === 'c') && s[i + 1] === '"') return _scanDq(s, i + 2);
  if (c === 'b' && s[i + 1] === '\'') {
    const e = _literalEnd(s, i + 1);
    return e > i + 1 ? e : i;
  }
  return i;
}

function _scanDq(s, i) {
  for (; i < s.length; i++) {
    if (s[i] === '\\') { i++; continue; }
    if (s[i] === '"') return i + 1;
  }
  return s.length;
}

// ─── preprocessing ───────────────────────────────────────────────────────────
// Newlines are preserved exactly so every offset in the preprocessed text maps
// to the same line in the original file.
function _preprocess(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (c === '/' && d === '*') {
      let depth = 1;
      out += '  '; i += 2;
      while (i < n && depth > 0) {
        if (src[i] === '/' && src[i + 1] === '*') { depth++; out += '  '; i += 2; continue; }
        if (src[i] === '*' && src[i + 1] === '/') { depth--; out += '  '; i += 2; continue; }
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      continue;
    }
    const lit = _literalEnd(src, i);
    if (lit > i) { out += src.slice(i, lit); i = lit; continue; }
    if (c === ':' && d === ':') {
      if (src[i + 2] === '<') {
        // turbofish `::<T>`: drop entirely, keep any newlines inside
        let j = i + 2;
        let depth = 0;
        for (; j < n; j++) {
          if (src[j] === '<') depth++;
          else if (src[j] === '>') { depth--; if (depth === 0) { j++; break; } }
          else if (src[j] === '\n') out += '\n';
        }
        i = j;
        continue;
      }
      out += '.'; i += 2;
      continue;
    }
    if (c === '.' && src.startsWith('.await', i) && !/\w/.test(src[i + 6] || '')) { i += 6; continue; }
    if (c === '?') { i++; continue; }
    out += c; i++;
  }
  return out;
}

// ─── generic scanners ────────────────────────────────────────────────────────
function _matchingClose(s, openIdx) {
  const open = s[openIdx];
  const close = open === '(' ? ')' : open === '[' ? ']' : open === '{' ? '}' : null;
  if (!close) return -1;
  let depth = 0;
  for (let i = openIdx; i < s.length;) {
    const e = _literalEnd(s, i);
    if (e > i) { i = e; continue; }
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { depth--; if (depth === 0) return i; }
    i++;
  }
  return -1;
}

// Split on `sep` at depth 0 (parens/brackets/braces, and optionally angle
// brackets for type contexts). Returns [{text, start}] with `start` = offset of
// the part's first non-space char within `s`.
function _splitTopLevel(s, sep, { angles = false } = {}) {
  const out = [];
  let depth = 0;
  let angle = 0;
  let partStart = 0;
  const push = (end) => {
    let a = partStart;
    while (a < end && /\s/.test(s[a])) a++;
    let b = end;
    while (b > a && /\s/.test(s[b - 1])) b--;
    out.push({ text: s.slice(a, b), start: a });
  };
  for (let i = 0; i < s.length;) {
    const e = _literalEnd(s, i);
    if (e > i) { i = e; continue; }
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (angles && c === '<' && depth >= 0) angle++;
    else if (angles && c === '>' && s[i - 1] !== '-' && angle > 0) angle--;
    else if (c === sep && depth === 0 && angle === 0) { push(i); partStart = i + 1; i++; continue; }
    i++;
  }
  push(s.length);
  if (out.length === 1 && !out[0].text) return [];
  return out;
}

// `+` at depth 0, not part of `+=`, `->`, or a unary sign after an operator.
function _splitTopLevelPlus(s) {
  const out = [];
  let depth = 0;
  let partStart = 0;
  for (let i = 0; i < s.length;) {
    const e = _literalEnd(s, i);
    if (e > i) { i = e; continue; }
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === '+' && depth === 0 && s[i + 1] !== '=') {
      const t = s.slice(partStart, i).trim();
      if (t) { out.push(t); partStart = i + 1; }
    }
    i++;
  }
  const last = s.slice(partStart).trim();
  if (last) out.push(last);
  return out;
}

function _extractBody(src, openBrace) {
  const end = _matchingClose(src, openBrace);
  if (end < 0) return null;
  return { body: src.slice(openBrace + 1, end), end };
}

// Statement splitter. Flushes on `;` at depth 0 and on a `}` that closes a
// depth-0 block, unless the block is continued by `else`, a method call, a
// cast, or is itself an argument. Returns [{text, start, terminated}].
const _BLOCK_CONTINUERS = /^(?:else\b|as\b|\.|,|\)|\]|;|\}|\|\||&&|==|!=|[-+*\/%]?=|\?)/;
function _splitStatements(body) {
  const out = [];
  let depth = 0;
  let stmtStart = 0;
  const flush = (end, terminated) => {
    let a = stmtStart;
    while (a < end && /\s/.test(body[a])) a++;
    let b = end;
    while (b > a && /\s/.test(body[b - 1])) b--;
    if (b > a) out.push({ text: body.slice(a, b), start: a, terminated });
  };
  for (let i = 0; i < body.length;) {
    const e = _literalEnd(body, i);
    if (e > i) { i = e; continue; }
    const c = body[i];
    if (c === '(' || c === '[' || c === '{') { depth++; i++; continue; }
    if (c === ')' || c === ']') { depth--; i++; continue; }
    if (c === '}') {
      depth--;
      i++;
      if (depth === 0) {
        let j = i;
        while (j < body.length && /\s/.test(body[j])) j++;
        if (j >= body.length || !_BLOCK_CONTINUERS.test(body.slice(j, j + 4))) {
          flush(i, false);
          stmtStart = i;
        }
      }
      continue;
    }
    if (c === ';' && depth === 0) { flush(i, true); stmtStart = i + 1; i++; continue; }
    i++;
  }
  flush(body.length, false);
  return out;
}

// ─── chain parsing ───────────────────────────────────────────────────────────
// Parses `base . seg (args) [idx] …` into a flat op list. `base` is an ident
// path (`a.b.c`), a literal, a paren group, or a macro invocation.
const _IDENT_PATH_RE = /^[A-Za-z_][\w.]*/;
const _MACRO_RE = /^([A-Za-z_][\w.]*)!\s*([(\[{])/;

function _parseChain(s) {
  let i = 0;
  let base = null;
  const lit = _literalEnd(s, 0);
  if (lit > 0) {
    base = { type: 'literal', text: s.slice(0, lit) };
    i = lit;
  } else if (s[0] === '(') {
    const close = _matchingClose(s, 0);
    if (close < 0) return null;
    base = { type: 'paren', text: s.slice(1, close) };
    i = close + 1;
  } else {
    const mac = _MACRO_RE.exec(s);
    if (mac) {
      const open = mac[0].length - 1;
      const close = _matchingClose(s, open);
      if (close < 0) return null;
      base = { type: 'macro', name: mac[1], argsText: s.slice(open + 1, close), argsStart: open + 1 };
      i = close + 1;
    } else {
      const id = _IDENT_PATH_RE.exec(s);
      if (!id) return null;
      base = { type: 'path', text: id[0] };
      i = id[0].length;
    }
  }
  const ops = [];
  for (;;) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    const c = s[i];
    if (c === '(' && (base.type !== 'literal' || ops.length)) {
      const close = _matchingClose(s, i);
      if (close < 0) return null;
      ops.push({ kind: 'call', argsText: s.slice(i + 1, close), argsStart: i + 1 });
      i = close + 1;
      continue;
    }
    if (c === '[') {
      const close = _matchingClose(s, i);
      if (close < 0) return null;
      ops.push({ kind: 'index', text: s.slice(i + 1, close) });
      i = close + 1;
      continue;
    }
    if (c === '.') {
      const m = /^\.\s*([A-Za-z_]\w*|\d+)/.exec(s.slice(i));
      if (!m) break;
      ops.push({ kind: 'member', name: m[1] });
      i += m[0].length;
      continue;
    }
    break;
  }
  return { base, ops, end: i };
}

// ─── expression lowering ─────────────────────────────────────────────────────
const _FORMAT_MACROS = new Set(['format', 'print', 'println', 'eprint', 'eprintln', 'panic', 'format_args', 'write', 'writeln', 'assert', 'unreachable', 'todo', 'concat']);
const _WRITER_FIRST = new Set(['write', 'writeln']);
const _CLOSURE_RE = /^(?:move\s+)?\|([^|]*)\|\s*(?:async\s+(?:move\s+)?)?/;
const _ASYNC_BLOCK_RE = /^async\s+(?:move\s+)?\{/;

function _stripCast(s) {
  // drop a trailing top-level ` as Type`
  let depth = 0;
  let cut = -1;
  for (let i = 0; i < s.length;) {
    const e = _literalEnd(s, i);
    if (e > i) { i = e; continue; }
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth === 0 && c === 'a' && s[i + 1] === 's' && /\s/.test(s[i + 2] || '') && /\s/.test(s[i - 1] || '')) cut = i;
    i++;
  }
  return cut > 0 ? s.slice(0, cut).trim() : s;
}

function _lowerFormatArgs(argsText, dropFirst) {
  const parts = [];
  let args = _splitTopLevel(argsText, ',').map(p => p.text);
  if (dropFirst) args = args.slice(1);
  if (!args.length) return { kind: 'tpl', parts };
  const fmt = args[0];
  const positional = args.slice(1);
  const named = new Map();
  const positionalExprs = [];
  for (const a of positional) {
    const nm = /^([A-Za-z_]\w*)\s*=\s*([\s\S]+)$/.exec(a);
    if (nm) named.set(nm[1], _lowerExpr(nm[2]));
    else positionalExprs.push(_lowerExpr(a));
  }
  if (_literalEnd(fmt, 0) === fmt.length && fmt.length > 1) {
    parts.push({ kind: 'literal', value: fmt });
    let next = 0;
    const used = new Set();
    const re = /\{\{|\}\}|\{([^{}]*)\}/g;
    let m;
    while ((m = re.exec(fmt)) !== null) {
      if (m[0] === '{{' || m[0] === '}}') continue;
      const inner = (m[1] || '').split(':')[0].trim();
      if (!inner) {
        if (next < positionalExprs.length) { parts.push(positionalExprs[next]); used.add(next); }
        next++;
      } else if (/^\d+$/.test(inner)) {
        const idx = Number(inner);
        if (idx < positionalExprs.length) { parts.push(positionalExprs[idx]); used.add(idx); }
      } else if (named.has(inner)) {
        parts.push(named.get(inner));
      } else if (/^[A-Za-z_]\w*$/.test(inner)) {
        parts.push({ kind: 'ident', name: inner });
      }
    }
    positionalExprs.forEach((e, idx) => { if (!used.has(idx)) parts.push(e); });
    for (const [, e] of named) if (!parts.includes(e)) parts.push(e);
  } else {
    parts.push(_lowerExpr(fmt), ...positionalExprs, ...named.values());
  }
  return { kind: 'tpl', parts };
}

// `format!`/`format_args!`/`concat!` ARE the value they build, so they lower
// straight to a template. Every other format-family macro (`println!`,
// `write!`, `panic!`, and log macros later) is a statement-shaped call that
// consumes a template: it lowers to a call whose callee keeps the `!`, with
// the template as its single argument, so a catalog sink can key on the
// macro name (`info!` for log injection) exactly like a function.
const _VALUE_MACROS = new Set(['format', 'format_args', 'concat']);
function _lowerMacro(name, argsText) {
  const bare = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : name;
  if (_FORMAT_MACROS.has(bare)) {
    const tpl = _lowerFormatArgs(argsText, _WRITER_FIRST.has(bare));
    if (_VALUE_MACROS.has(bare)) return tpl;
    return { kind: 'call', callee: `${name}!`, args: [tpl] };
  }
  if (bare === 'vec') {
    const semi = _splitTopLevel(argsText, ';');
    const items = semi.length === 2 ? [semi[0].text] : _splitTopLevel(argsText, ',').map(p => p.text);
    return { kind: 'array', elements: items.map(_lowerExpr) };
  }
  return { kind: 'call', callee: `${name}!`, args: _splitTopLevel(argsText, ',').map(p => _lowerExpr(p.text)) };
}

const _PASSTHROUGH_CALLS = new Set(['unwrap', 'expect']);

function _memberChain(segs) {
  let cur = { kind: 'ident', name: segs[0] };
  for (let i = 1; i < segs.length; i++) cur = { kind: 'member', object: cur, prop: segs[i] };
  return cur;
}

function _lowerChain(chain) {
  const { base, ops } = chain;
  let segs;
  let args = [];
  let _baseIsCall = false;
  if (base.type === 'path') segs = base.text.split('.');
  else if (base.type === 'macro') {
    const m = _lowerMacro(base.name, base.argsText);
    if (!ops.length) return m;
    // A macro starting a chain keeps its own name (with the `!`) as the
    // chain root so `sqlx::query!(…).fetch_one(pool)` reads as
    // `sqlx.query!.fetch_one`, and its lowered value is the innermost arg.
    segs = `${base.name}!`.split('.');
    args = m.kind === 'call' ? m.args.slice() : [m];
    // A call-shaped macro (`write!`, `println!`, …) IS the call for this
    // statement even if every op that follows is a stripped passthrough
    // (`write!(w, "…", x).unwrap();`) — without this, a macro-only
    // statement whose sole continuation is `.unwrap()` would fall through
    // to `if (!hasCall)` below and silently stop being a call node at all.
    _baseIsCall = m.kind === 'call';
  } else if (base.type === 'literal') {
    const l = { kind: 'literal', value: base.text };
    if (!ops.length) return l;
    segs = ['_lit'];
    args = [l];
  } else { // paren
    const inner = _lowerExpr(base.text);
    if (!ops.length) return inner;
    segs = ['_expr'];
    args = [inner];
  }
  let hasCall = _baseIsCall;
  // `.unwrap()`/`.expect(msg)` are Result/Option combinators that neither
  // change WHAT the value is nor take a taint-relevant argument — they exist
  // purely to panic on an error path. Left in the chain, they shift the
  // TERMINAL segment away from the real sink/method name (the same "terminal
  // segment shift" defect class documented for Go/Java/Kotlin in ir/CLAUDE.md),
  // so `sqlx::query(&sql).fetch_all(pool).await.unwrap()` would otherwise end
  // in `.unwrap`, never `.fetch_all`, and no sink catalog entry could ever
  // match it — nearly every real async Rust call site ends this way. Popped
  // (segment AND args) as soon as the CALL that follows them is seen, so the
  // chain reads exactly as if they were never written.
  let pendingPassthrough = false;
  for (const op of ops) {
    if (op.kind === 'member') {
      pendingPassthrough = _PASSTHROUGH_CALLS.has(op.name);
      segs.push(op.name);
    } else if (op.kind === 'index') {
      pendingPassthrough = false;
      segs.push('[]');
    } else if (pendingPassthrough) {
      pendingPassthrough = false;
      segs.pop();
    } else {
      hasCall = true;
      const lowered = _splitTopLevel(op.argsText, ',').map(p => _lowerExpr(p.text));
      args = args.concat(lowered);
    }
  }
  if (!hasCall) {
    if (base.type === 'path') return _memberChain(segs);
    return args[0] || U;
  }
  return { kind: 'call', callee: segs.join('.'), args };
}

function _lowerExpr(text) {
  let s = String(text || '').trim();
  if (!s) return U;
  // fully parenthesized
  while (s.startsWith('(') && _matchingClose(s, 0) === s.length - 1) {
    const inner = s.slice(1, -1).trim();
    if (_splitTopLevel(inner, ',').length > 1) return { kind: 'array', elements: _splitTopLevel(inner, ',').map(p => _lowerExpr(p.text)) };
    s = inner;
    if (!s) return U;
  }
  const pre = /^(?:&\s*mut\s+|&\s*|\*\s*|mut\s+|!\s*|-\s*)/.exec(s);
  if (pre && pre[0].length < s.length) return _lowerExpr(s.slice(pre[0].length));
  s = _stripCast(s);
  // closure as a value: its body expression is what flows onward
  const cl = _CLOSURE_RE.exec(s);
  if (cl) {
    const body = s.slice(cl[0].length).trim();
    if (body.startsWith('{')) return U;
    return _lowerExpr(body);
  }
  if (/^(?:if|match|loop|while|for|unsafe|async)\b/.test(s) || s.startsWith('{')) return U;
  // array literal
  if (s.startsWith('[') && _matchingClose(s, 0) === s.length - 1) {
    const inner = s.slice(1, -1);
    const semi = _splitTopLevel(inner, ';');
    const items = semi.length === 2 ? [semi[0].text] : _splitTopLevel(inner, ',').map(p => p.text);
    return { kind: 'array', elements: items.map(_lowerExpr) };
  }
  // string concat with +
  const plusParts = _splitTopLevelPlus(s);
  if (plusParts.length > 1) return { kind: 'tpl', parts: plusParts.map(_lowerExpr) };
  // comparison / logical operators at top level: keep both sides visible
  const bin = _splitBinary(s);
  if (bin) return { kind: 'logical', op: bin.op, left: _lowerExpr(bin.left), right: _lowerExpr(bin.right) };
  // range `a..b`
  const range = /^([\s\S]*?)\.\.=?([\s\S]*)$/.exec(s);
  if (range && !s.startsWith('.') && range[1].trim() && !/[("[]/.test(range[1])) {
    return { kind: 'array', elements: [_lowerExpr(range[1]), _lowerExpr(range[2])].filter(e => e !== U) };
  }
  if (/^\d/.test(s)) return { kind: 'literal', value: s };
  if (/^(?:true|false|None|Self|self)$/.test(s)) return s === 'self' || s === 'Self' ? { kind: 'ident', name: s } : { kind: 'literal', value: s };
  // struct literal `Type { a: x, b }` / `Type.Variant { .. }`
  const sl = /^([A-Za-z_][\w.]*)\s*\{/.exec(s);
  if (sl && _matchingClose(s, sl[0].length - 1) === s.length - 1) {
    const inner = s.slice(sl[0].length, -1);
    const props = [];
    for (const f of _splitTopLevel(inner, ',')) {
      const t = f.text;
      if (!t) continue;
      if (t.startsWith('..')) { props.push({ value: _lowerExpr(t.slice(2)) }); continue; }
      const kv = /^([A-Za-z_]\w*)\s*:\s*([\s\S]+)$/.exec(t);
      props.push({ value: _lowerExpr(kv ? kv[2] : t) });
    }
    return { kind: 'object', props };
  }
  const chain = _parseChain(s);
  if (chain && chain.end >= s.length) return _lowerChain(chain);
  if (chain && chain.base.type === 'path' && !chain.ops.length) return _memberChain(chain.base.text.split('.'));
  return U;
}

// Top-level `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`: returns the split or
// null. Kept simple: first top-level operator found wins.
function _splitBinary(s) {
  let depth = 0;
  for (let i = 0; i < s.length;) {
    const e = _literalEnd(s, i);
    if (e > i) { i = e; continue; }
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth === 0) {
      const two = s.slice(i, i + 2);
      if (two === '&&' || two === '||' || two === '==' || two === '!=' || two === '<=' || two === '>=') {
        return { op: two, left: s.slice(0, i), right: s.slice(i + 2) };
      }
    }
    i++;
  }
  return null;
}

// ─── patterns ────────────────────────────────────────────────────────────────
const _PAT_KEYWORDS = new Set(['ref', 'mut', 'true', 'false', 'box', 'if', 'in', 'as', 'self', 'Self', 'crate', 'super']);

// Lowercase-initial identifiers bound by a pattern. Enum variants and struct
// names are capitalized in idiomatic Rust; field names before `:` are keys,
// not bindings.
function _patternIdents(pat) {
  const out = [];
  const p = String(pat || '');
  const re = /[A-Za-z_]\w*/g;
  let m;
  while ((m = re.exec(p)) !== null) {
    const id = m[0];
    if (_PAT_KEYWORDS.has(id) || id === '_') continue;
    if (!/^[a-z_]/.test(id)) continue;
    const after = p.slice(m.index + id.length);
    if (/^\s*:(?!:)/.test(after)) continue; // `field: pat`
    if (/^\s*\(/.test(after)) continue; // tuple-struct / call-like
    if (/^\s*!/.test(after)) continue; // macro
    if (m.index > 0 && p[m.index - 1] === '.') continue; // path segment
    if (/^\s*\./.test(after)) continue; // path prefix
    if (!out.includes(id)) out.push(id);
  }
  return out;
}

function _stripGuard(patText) {
  // `Some(x) if x > 3` → `Some(x)`
  let depth = 0;
  for (let i = 0; i < patText.length;) {
    const e = _literalEnd(patText, i);
    if (e > i) { i = e; continue; }
    const c = patText[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth === 0 && /\s/.test(patText[i - 1] || ' ') && patText.startsWith('if', i) && /\s/.test(patText[i + 2] || '')) {
      return patText.slice(0, i).trim();
    }
    i++;
  }
  return patText.trim();
}

// ─── params ──────────────────────────────────────────────────────────────────
const _EXTRACTORS = new Set([
  'Query', 'Path', 'Json', 'Form', 'HeaderMap', 'TypedHeader', 'RawQuery', 'RawForm',
  'Multipart', 'MultipartForm', 'HttpRequest', 'Request', 'CookieJar', 'Cookies', 'Host',
  'OriginalUri', 'RawPathParams', 'Bytes',
]);
const _ROUTE_ATTR_RE = /#\[\s*(?:rocket\.|actix_web\.|salvo\.)?(?:get|post|put|delete|patch|head|options|route|handler)\s*[(\]]/;

function _typeRoot(typeText) {
  const t = String(typeText || '').replace(/^\s*(?:&\s*(?:'\w+\s+)?(?:mut\s+)?|mut\s+)/, '').trim();
  const head = t.split('<')[0].trim();
  const last = head.includes('.') ? head.slice(head.lastIndexOf('.') + 1) : head;
  return last;
}

// `(?:#\[[^\]]*\]\s*)+` (here, in `_buildCfg`'s attribute-skip below, and
// inside `_FN_RE`) matches this repo's self-scan gate's "optional/quantified
// group flanked by `\s*`" ReDoS heuristic, but each iteration is bounded by
// the MANDATORY literal `#[`…`]` — there is no shared character class between
// the outer `+` and the inner `\s*`/`[^\]]*` for the engine to backtrack
// across, so the shape is linear by construction, not merely linear on the
// inputs tried. Confirmed by direct timing (this repo's own standard for
// this exact judgment call, per `ir/CLAUDE.md`'s ReDoS notes): 50 000
// back-to-back `#[a]` attributes and 200 000 non-matching whitespace
// characters both resolve in single-digit milliseconds.
function _parseParams(paramsText, hasRouteAttr) {
  const params = [];
  const paramAnnotations = [];
  for (const part of _splitTopLevel(paramsText, ',', { angles: true })) {
    let t = part.text.replace(/^(?:#\[[^\]]*\]\s*)+/, '').trim();
    if (!t) continue;
    if (/^(?:&\s*(?:'\w+\s+)?(?:mut\s+)?|mut\s+)?self\b/.test(t)) { params.push('self'); continue; }
    // split `pattern: Type` at the first top-level colon
    let colon = -1;
    let depth = 0;
    for (let i = 0; i < t.length; i++) {
      const c = t[i];
      if (c === '(' || c === '[' || c === '{' || c === '<') depth++;
      else if (c === ')' || c === ']' || c === '}' || c === '>') depth--;
      else if (c === ':' && depth === 0) { colon = i; break; }
    }
    const pat = colon >= 0 ? t.slice(0, colon).trim() : t;
    const type = colon >= 0 ? t.slice(colon + 1).trim() : '';
    const wrapper = /^([A-Z]\w*)\s*\(/.exec(pat);
    const idents = _patternIdents(pat.replace(/^mut\s+/, ''));
    const root = _typeRoot(type);
    let decorator = null;
    if (wrapper && _EXTRACTORS.has(wrapper[1])) decorator = wrapper[1];
    else if (_EXTRACTORS.has(root)) decorator = root;
    else if (hasRouteAttr) decorator = 'RouteParam';
    for (const id of idents) {
      if (decorator) paramAnnotations.push({ index: params.length, name: id, decorator });
      params.push(id);
    }
  }
  return { params, paramAnnotations };
}

// Skip backward over `fn`'s qualifier keywords (pub/pub(...)/const/async/
// unsafe/default/extern "…") so `_precedingAttributes` (below) can still see
// an attribute that precedes them, e.g. `#[get("/x")] async fn handler()` —
// the common shape for every Rust web-framework route macro. Plain bounded
// literal comparisons, not a regex: this is exactly the kind of fixed,
// small, disjoint-keyword set that is safe to skip character-by-character
// with no backtracking possible by construction (same reasoning
// `_precedingAttributes` itself already relies on for `#[...]`/`]`).
const _FN_QUALIFIER_KEYWORDS = ['pub', 'const', 'async', 'unsafe', 'default'];
function _skipFnQualifiersBackward(src, idx) {
  let pos = idx;
  for (;;) {
    while (pos > 0 && /\s/.test(src[pos - 1])) pos--;
    if (src[pos - 1] === ')') {
      // pub(crate)/pub(super)/pub(in ...) — find the matching '(' and check
      // it's immediately preceded by "pub".
      let depth = 0;
      let j = pos - 1;
      for (; j >= 0; j--) {
        if (src[j] === ')') depth++;
        else if (src[j] === '(') { depth--; if (depth === 0) break; }
      }
      if (j >= 3 && src.slice(j - 3, j) === 'pub' && !/\w/.test(src[j - 4] || '')) { pos = j - 3; continue; }
      break;
    }
    if (src[pos - 1] === '"') {
      // extern "C"/"Rust"/etc.
      let j = pos - 2;
      while (j >= 0 && src[j] !== '"') j--;
      if (j <= 0) break;
      const before = src.slice(0, j);
      const m = /extern\s*$/.exec(before);
      if (m) { pos = m.index; continue; }
      break;
    }
    let matched = false;
    for (const kw of _FN_QUALIFIER_KEYWORDS) {
      const start = pos - kw.length;
      if (start >= 0 && src.slice(start, pos) === kw && (start === 0 || !/\w/.test(src[start - 1]))) {
        pos = start;
        matched = true;
        break;
      }
    }
    if (!matched) break;
  }
  return pos;
}

// Attributes immediately preceding `idx`, scanned backwards over `#[…]` groups.
function _precedingAttributes(src, idx) {
  let pos = idx;
  let attrs = '';
  for (;;) {
    while (pos > 0 && /\s/.test(src[pos - 1])) pos--;
    if (src[pos - 1] !== ']') break;
    let depth = 0;
    let j = pos - 1;
    for (; j >= 0; j--) {
      if (src[j] === ']') depth++;
      else if (src[j] === '[') { depth--; if (depth === 0) break; }
    }
    if (j <= 0 || src[j - 1] !== '#') break;
    attrs = src.slice(j - 1, pos) + '\n' + attrs;
    pos = j - 1;
  }
  return attrs;
}

// ─── CFG construction ────────────────────────────────────────────────────────
let _nid = 0;
let _src = '';
let _lineStarts = [];

function _computeLineStarts(s) {
  const starts = [0];
  for (let i = 0; i < s.length; i++) if (s[i] === '\n') starts.push(i + 1);
  return starts;
}

function _lineForOffset(off) {
  let lo = 0;
  let hi = _lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (_lineStarts[mid] <= off) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

function _addNode(nodes, node) {
  const id = `rn${++_nid}`;
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

const _MAX_DEPTH = 60;
const _DECL_RE = /^(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|async|unsafe|extern\s+"[^"]*")\s+)*(?:fn|struct|enum|impl|trait|use|mod|type|macro_rules)\b/;
const _CTRL_RE = /^(?:if|while|loop|for|match|unsafe|async)\b|^\{/;

function _bindPattern(nodes, prev, patText, sourceExpr, line) {
  let cur = prev;
  for (const id of _patternIdents(patText)) {
    const n = _addNode(nodes, { kind: 'assign', target: id, source: sourceExpr, line });
    _link(nodes, cur, n);
    cur = n;
  }
  return cur;
}

// Where the `{` of a control-flow header is: first `{` at depth 0 in s (after
// the keyword), literal-aware.
function _headerBrace(s, from) {
  let depth = 0;
  for (let i = from; i < s.length;) {
    const e = _literalEnd(s, i);
    if (e > i) { i = e; continue; }
    const c = s[i];
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (c === '{' && depth === 0) return i;
    i++;
  }
  return -1;
}

// Inline every closure / async block found among a chain's call args.
function _inlineClosures(chain, stmtText, stmtStart, nodes, prev, depth) {
  let cur = prev;
  const segsSoFar = chain.base.type === 'path' ? chain.base.text.split('.') : ['_expr'];
  for (const op of chain.ops) {
    if (op.kind === 'member') { segsSoFar.push(op.name); continue; }
    if (op.kind === 'index') { segsSoFar.push('[]'); continue; }
    const receiverSegs = segsSoFar.slice(0, -1);
    for (const part of _splitTopLevel(op.argsText, ',')) {
      const t = part.text;
      const absStart = stmtStart + op.argsStart + part.start;
      const cl = _CLOSURE_RE.exec(t);
      let bodyText = null;
      let bodyAbs = 0;
      if (cl) {
        const rest = t.slice(cl[0].length);
        const line = _lineForOffset(absStart);
        for (const p of _splitTopLevel(cl[1], ',', { angles: true })) {
          const pt = p.text.trim();
          if (!pt) continue;
          let colon = -1;
          let d = 0;
          for (let i = 0; i < pt.length; i++) {
            const c = pt[i];
            if (c === '(' || c === '[' || c === '{' || c === '<') d++;
            else if (c === ')' || c === ']' || c === '}' || c === '>') d--;
            else if (c === ':' && d === 0) { colon = i; break; }
          }
          const pat = colon >= 0 ? pt.slice(0, colon) : pt;
          const type = colon >= 0 ? pt.slice(colon + 1) : '';
          const root = _typeRoot(type);
          const wrapper = /^([A-Z]\w*)\s*\(/.exec(pat.trim());
          const extractor = wrapper && _EXTRACTORS.has(wrapper[1]) ? wrapper[1] : (_EXTRACTORS.has(root) ? root : null);
          let source;
          if (extractor) source = { kind: 'call', callee: `__rs_extract__.${extractor}`, args: [] };
          else if (receiverSegs.length && receiverSegs[0] !== '_expr') source = _memberChain(receiverSegs);
          else source = null;
          if (source) cur = _bindPattern(nodes, cur, pat, source, line);
        }
        if (rest.startsWith('{')) {
          const ex = _extractBody(rest, 0);
          if (!ex) continue;
          bodyText = ex.body;
          bodyAbs = absStart + cl[0].length + 1;
        } else {
          bodyText = rest;
          bodyAbs = absStart + cl[0].length;
        }
      } else if (_ASYNC_BLOCK_RE.test(t)) {
        const open = t.indexOf('{');
        const ex = _extractBody(t, open);
        if (!ex) continue;
        bodyText = ex.body;
        bodyAbs = absStart + open + 1;
      }
      if (bodyText != null) cur = _buildCfg(bodyText, bodyAbs, nodes, cur, null, depth + 1);
    }
  }
  return cur;
}

function _hasClosureArg(chain) {
  return chain.ops.some(op => op.kind === 'call' && _splitTopLevel(op.argsText, ',').some(p => _CLOSURE_RE.test(p.text) || _ASYNC_BLOCK_RE.test(p.text)));
}

// Lower a chain, dropping closure/async-block args (they are inlined as CFG
// nodes instead of being passed as opaque unknowns).
function _lowerChainNoClosures(chain) {
  const clone = { base: chain.base, ops: chain.ops.map(op => op.kind !== 'call' ? op : {
    ...op,
    argsText: _splitTopLevel(op.argsText, ',').filter(p => !_CLOSURE_RE.test(p.text) && !_ASYNC_BLOCK_RE.test(p.text)).map(p => p.text).join(', '),
  }) };
  return _lowerChain(clone);
}

// Builds a control-flow construct that starts at `s` (statement text) whose
// absolute start is `start`. `tails` collects branch tail expressions when the
// construct is in expression position. Returns the join node id.
function _buildControl(s, start, nodes, prev, tails, depth) {
  const line = _lineForOffset(start);
  // if / if let … else if … else
  if (/^if\b/.test(s)) {
    const brace = _headerBrace(s, 2);
    if (brace < 0) return prev;
    const header = s.slice(2, brace).trim();
    const ex = _extractBody(s, brace);
    if (!ex) return prev;
    const ifLet = /^let\s+([\s\S]+?)\s*=\s*([\s\S]+)$/.exec(header);
    const condExpr = _lowerExpr(ifLet ? ifLet[2] : header);
    const ifNode = _addNode(nodes, { kind: 'if', cond: condExpr, line });
    _link(nodes, prev, ifNode);
    const join = _addNode(nodes, { kind: 'noop', line });
    let thenPrev = ifNode;
    if (ifLet) thenPrev = _bindPattern(nodes, ifNode, ifLet[1], condExpr, line);
    const thenTail = _buildCfg(ex.body, start + brace + 1, nodes, thenPrev, tails, depth + 1);
    _link(nodes, thenTail, join);
    const rest = s.slice(ex.end + 1).trim();
    const restStart = start + ex.end + 1 + (s.slice(ex.end + 1).length - s.slice(ex.end + 1).trimStart().length);
    const elseM = /^else\b\s*/.exec(rest);
    if (elseM) {
      const after = rest.slice(elseM[0].length);
      const afterStart = restStart + elseM[0].length;
      if (/^if\b/.test(after)) {
        const t = _buildControl(after, afterStart, nodes, ifNode, tails, depth + 1);
        _link(nodes, t, join);
      } else if (after.startsWith('{')) {
        const eb = _extractBody(after, 0);
        if (eb) {
          const t = _buildCfg(eb.body, afterStart + 1, nodes, ifNode, tails, depth + 1);
          _link(nodes, t, join);
        }
      }
    } else {
      _link(nodes, ifNode, join);
    }
    return join;
  }
  // while / while let
  if (/^while\b/.test(s)) {
    const brace = _headerBrace(s, 5);
    if (brace < 0) return prev;
    const header = s.slice(5, brace).trim();
    const ex = _extractBody(s, brace);
    if (!ex) return prev;
    const whileLet = /^let\s+([\s\S]+?)\s*=\s*([\s\S]+)$/.exec(header);
    const condExpr = _lowerExpr(whileLet ? whileLet[2] : header);
    const head = _addNode(nodes, { kind: 'loop-header', line });
    _link(nodes, prev, head);
    const ifNode = _addNode(nodes, { kind: 'if', cond: condExpr, line });
    _link(nodes, head, ifNode);
    let bodyPrev = ifNode;
    if (whileLet) bodyPrev = _bindPattern(nodes, ifNode, whileLet[1], condExpr, line);
    const tail = _buildCfg(ex.body, start + brace + 1, nodes, bodyPrev, null, depth + 1);
    _link(nodes, tail, head);
    const join = _addNode(nodes, { kind: 'noop', line });
    _link(nodes, ifNode, join);
    return join;
  }
  // loop
  if (/^loop\b/.test(s)) {
    const brace = _headerBrace(s, 4);
    if (brace < 0) return prev;
    const ex = _extractBody(s, brace);
    if (!ex) return prev;
    const head = _addNode(nodes, { kind: 'loop-header', line });
    _link(nodes, prev, head);
    const tail = _buildCfg(ex.body, start + brace + 1, nodes, head, tails, depth + 1);
    _link(nodes, tail, head);
    const join = _addNode(nodes, { kind: 'noop', line });
    _link(nodes, head, join);
    _link(nodes, tail, join);
    return join;
  }
  // for PAT in EXPR
  if (/^for\b/.test(s)) {
    const brace = _headerBrace(s, 3);
    if (brace < 0) return prev;
    const header = s.slice(3, brace).trim();
    const ex = _extractBody(s, brace);
    if (!ex) return prev;
    const m = /^([\s\S]+?)\s+in\s+([\s\S]+)$/.exec(header);
    const head = _addNode(nodes, { kind: 'loop-header', line });
    _link(nodes, prev, head);
    let bodyPrev = head;
    if (m) bodyPrev = _bindPattern(nodes, head, m[1], _lowerExpr(m[2]), line);
    const tail = _buildCfg(ex.body, start + brace + 1, nodes, bodyPrev, null, depth + 1);
    _link(nodes, tail, head);
    const join = _addNode(nodes, { kind: 'noop', line });
    _link(nodes, head, join);
    return join;
  }
  // match EXPR { arms }
  if (/^match\b/.test(s)) {
    const brace = _headerBrace(s, 5);
    if (brace < 0) return prev;
    const scrutinee = _lowerExpr(s.slice(5, brace).trim());
    const ex = _extractBody(s, brace);
    if (!ex) return prev;
    const matchNode = _addNode(nodes, { kind: 'if', cond: scrutinee, line });
    _link(nodes, prev, matchNode);
    const join = _addNode(nodes, { kind: 'noop', line });
    const body = ex.body;
    const bodyAbs = start + brace + 1;
    let i = 0;
    let armCount = 0;
    while (i < body.length) {
      // find `=>` at depth 0
      let d = 0;
      let arrow = -1;
      let j = i;
      for (; j < body.length;) {
        const e = _literalEnd(body, j);
        if (e > j) { j = e; continue; }
        const c = body[j];
        if (c === '(' || c === '[' || c === '{') d++;
        else if (c === ')' || c === ']' || c === '}') d--;
        else if (d === 0 && c === '=' && body[j + 1] === '>') { arrow = j; break; }
        j++;
      }
      if (arrow < 0) break;
      const patText = _stripGuard(body.slice(i, arrow).replace(/^\s*,?\s*/, ''));
      let k = arrow + 2;
      while (k < body.length && /\s/.test(body[k])) k++;
      let armBody;
      let armAbs;
      let next;
      if (body[k] === '{') {
        const eb = _extractBody(body, k);
        if (!eb) break;
        armBody = eb.body;
        armAbs = bodyAbs + k + 1;
        next = eb.end + 1;
      } else {
        // expression arm: up to the next top-level comma
        let dd = 0;
        let q = k;
        for (; q < body.length;) {
          const e = _literalEnd(body, q);
          if (e > q) { q = e; continue; }
          const c = body[q];
          if (c === '(' || c === '[' || c === '{') dd++;
          else if (c === ')' || c === ']' || c === '}') dd--;
          else if (c === ',' && dd === 0) break;
          q++;
        }
        armBody = body.slice(k, q);
        armAbs = bodyAbs + k;
        next = q;
      }
      const armLine = _lineForOffset(bodyAbs + i + (body.slice(i).length - body.slice(i).trimStart().length));
      const armPrev = _bindPattern(nodes, matchNode, patText, scrutinee, armLine);
      const tail = _buildCfg(armBody, armAbs, nodes, armPrev, tails, depth + 1);
      _link(nodes, tail, join);
      armCount++;
      i = next;
      while (i < body.length && (/\s/.test(body[i]) || body[i] === ',')) i++;
    }
    if (!armCount) _link(nodes, matchNode, join);
    return join;
  }
  // unsafe { } / async { } / async move { } / bare { }
  const open = s.indexOf('{');
  if (open >= 0) {
    const ex = _extractBody(s, open);
    if (!ex) return prev;
    return _buildCfg(ex.body, start + open + 1, nodes, prev, tails, depth + 1);
  }
  return prev;
}

function _lowerStmt(s, line) {
  if (/^return\b/.test(s)) {
    const rest = s.replace(/^return\b\s*/, '').trim();
    return { kind: 'return', line, value: rest ? _lowerExpr(rest) : null };
  }
  if (/^(?:break|continue)\b/.test(s)) return { kind: 'noop', line };
  // index write: base[idx] = rhs
  const idxWrite = /^([A-Za-z_][\w.]*)\s*\[([\s\S]*?)\]\s*(\+|-|\*|\/)?=(?!=)\s*([\s\S]+)$/.exec(s);
  if (idxWrite && _matchingClose(s, s.indexOf('[')) === s.indexOf(']', s.indexOf('['))) {
    return { kind: 'call', line, callee: `${idxWrite[1]}.__setitem__`, args: [_lowerExpr(idxWrite[2]), _lowerExpr(idxWrite[4])] };
  }
  const assign = /^(\*?[A-Za-z_][\w.]*)\s*(\+|-|\*|\/|%|&|\||\^)?=(?!=)\s*([\s\S]+)$/.exec(s);
  if (assign && !/^(?:if|while|for|match|let)\b/.test(s)) {
    const target = assign[1].replace(/^\*/, '');
    const rhs = _lowerExpr(assign[3]);
    if (assign[2]) return { kind: 'assign', line, target, source: { kind: 'tpl', parts: [_memberChain(target.split('.')), rhs] } };
    return { kind: 'assign', line, target, source: rhs };
  }
  const expr = _lowerExpr(s);
  if (expr.kind === 'call') return { kind: 'call', line, callee: expr.callee, args: expr.args };
  return null;
}

function _buildCfg(bodyText, bodyStart, nodes, prevId, tails, depth) {
  if (depth > _MAX_DEPTH) return prevId;
  const stmts = _splitStatements(bodyText);
  let prev = prevId;
  for (let si = 0; si < stmts.length; si++) {
    const { text: raw, start: localStart, terminated } = stmts[si];
    const isLast = si === stmts.length - 1;
    let s = raw;
    let start = bodyStart + localStart;
    // leading attributes on a statement
    const attr = /^(?:#\[[^\]]*\]\s*)+/.exec(s);
    if (attr) { s = s.slice(attr[0].length); start += attr[0].length; }
    if (!s) continue;
    const line = _lineForOffset(start);
    if (_DECL_RE.test(s) && !/^(?:const|static)\s+[A-Z_]\w*\s*:/.test(s)) continue; // nested items handled by the top-level scan
    // const/static locals
    const cst = /^(?:pub\s+)?(?:const|static)\s+(?:mut\s+)?([A-Za-z_]\w*)\s*:[^=]*=\s*([\s\S]+)$/.exec(s);
    if (cst) {
      const n = _addNode(nodes, { kind: 'assign', target: cst[1], source: _lowerExpr(cst[2]), line });
      _link(nodes, prev, n);
      prev = n;
      continue;
    }
    // let
    const letM = /^let\s+([\s\S]+?)\s*=\s*([\s\S]+)$/.exec(s);
    if (letM || /^let\b/.test(s)) {
      if (!letM) continue; // `let x;` declares without a value
      let patText = letM[1];
      const typeIdx = _topLevelColon(patText);
      if (typeIdx >= 0) patText = patText.slice(0, typeIdx);
      let rhs = letM[2].trim();
      const rhsStart = start + s.indexOf(letM[2], letM[0].length - letM[2].length);
      // let-else: `let PAT = EXPR else { … };`
      const letElse = /^([\s\S]+?)\s+else\s*\{[\s\S]*\}$/.exec(rhs);
      let elseBody = null;
      if (letElse && !/^(?:if|match)\b/.test(rhs)) {
        const ob = rhs.lastIndexOf('else');
        const eb = _extractBody(rhs, rhs.indexOf('{', ob));
        if (eb) { elseBody = { text: eb.body, abs: rhsStart + rhs.indexOf('{', ob) + 1 }; rhs = letElse[1].trim(); }
      }
      let sourceExpr;
      if (_CTRL_RE.test(rhs)) {
        const branchTails = [];
        prev = _buildControl(rhs, rhsStart, nodes, prev, branchTails, depth + 1);
        const branches = branchTails.filter(b => b && b.kind !== 'unknown');
        sourceExpr = branches.length === 1 ? branches[0] : branches.length ? { kind: 'union', branches } : U;
      } else if (_CLOSURE_RE.test(rhs)) {
        continue; // closures stored for later invocation are not modeled
      } else {
        const chain = _parseChain(rhs);
        if (chain && chain.end >= rhs.length && _hasClosureArg(chain)) {
          sourceExpr = _lowerChainNoClosures(chain);
          prev = _inlineClosures(chain, rhs, rhsStart, nodes, prev, depth);
        } else {
          sourceExpr = _lowerExpr(rhs);
        }
      }
      prev = _bindPattern(nodes, prev, patText, sourceExpr, line);
      if (elseBody) prev = _buildCfg(elseBody.text, elseBody.abs, nodes, prev, null, depth + 1);
      continue;
    }
    // control flow at statement position
    if (_CTRL_RE.test(s)) {
      const isTail = isLast && !terminated && tails !== undefined;
      const branchTails = isTail ? [] : null;
      prev = _buildControl(s, start, nodes, prev, isTail ? (tails || branchTails) : null, depth + 1);
      if (isTail && tails === null) {
        const branches = branchTails.filter(b => b && b.kind !== 'unknown');
        if (branches.length) {
          const r = _addNode(nodes, { kind: 'return', line, value: branches.length === 1 ? branches[0] : { kind: 'union', branches } });
          _link(nodes, prev, r);
          prev = r;
        }
      }
      continue;
    }
    // expression statement with closure args: keep the call, inline bodies
    const chain = _parseChain(s);
    if (chain && chain.end >= s.length && _hasClosureArg(chain)) {
      const lowered = _lowerChainNoClosures(chain);
      if (lowered.kind === 'call') {
        const n = _addNode(nodes, { kind: 'call', line, callee: lowered.callee, args: lowered.args });
        _link(nodes, prev, n);
        prev = n;
      }
      prev = _inlineClosures(chain, s, start, nodes, prev, depth);
      continue;
    }
    // tail expression (no `;`): the block's value
    if (isLast && !terminated && !/^return\b/.test(s)) {
      const expr = _lowerExpr(s);
      if (tails) { tails.push(expr); continue; }
      if (tails === null) {
        if (expr.kind === 'call') {
          const c = _addNode(nodes, { kind: 'call', line, callee: expr.callee, args: expr.args });
          _link(nodes, prev, c);
          prev = c;
        }
        const r = _addNode(nodes, { kind: 'return', line, value: expr });
        _link(nodes, prev, r);
        prev = r;
        continue;
      }
    }
    const node = _lowerStmt(s, line);
    if (!node) continue;
    const id = _addNode(nodes, node);
    _link(nodes, prev, id);
    prev = id;
  }
  return prev;
}

function _topLevelColon(s) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '(' || c === '[' || c === '{' || c === '<') depth++;
    else if (c === ')' || c === ']' || c === '}' || c === '>') depth--;
    else if (c === ':' && depth === 0) return i;
  }
  return -1;
}

// ─── items ───────────────────────────────────────────────────────────────────
// A REAL ReDoS, found via this repo's own self-scan gate after this file
// merged (confirmed by direct timing, not the heuristic alone: ~50s on
// 1000 repeated `#[a] ` attributes with no trailing `fn`, i.e. the ordinary
// shape of a file this parser is scanning that simply never reaches a match).
// The original version of this regex chained THREE separately-quantified
// constructs before `fn` — an attribute-skip star, an optional `pub`, and a
// qualifier-skip star — each one individually timed as linear in isolation
// (see the file-header note this repo's own review left on the sibling
// `(?:#\[[^\]]*\]\s*)+` shape in `_parseParams`), but a backtracking engine
// does not know the alternatives inside a `(?:A|B|C)*` are mutually
// exclusive on real input: on eventual overall-match failure (no `fn` ever
// reached) it explores every way the star COULD have divided its iterations
// among A/B/C, which is exponential regardless of how "obviously
// unambiguous" the alternation looks to a human reader — confirmed by
// re-timing a version that merged all three into one alternation-based star
// and finding it was STILL exponential (100ms+ on just 20 attributes).
// The actual fix is not a smarter regex at all: none of the skipped prefix
// text was ever used for anything. `_precedingAttributes` (below) already
// independently, safely (plain character-by-character backward scan, no
// regex) recovers real attribute text for route detection, and neither
// `fnKw` nor `name` extraction in the scan loop needs the qualifiers
// matched — `\bfn\b` already can't match inside a longer identifier
// (`myfn`, `fn_pointer`) on its own, since `\w` includes `_` and a word
// boundary requires a transition. Verified linear up to 500 000 repeated
// attributes+qualifiers with no trailing `fn` (single-digit ms).
const _FN_RE = /\bfn\s+([A-Za-z_]\w*)/g;
const _IMPL_RE = /(?:^|[\n;{}])\s*(?:unsafe\s+)?(?:impl|trait)\b/g;

function _findImplRanges(src) {
  const ranges = [];
  _IMPL_RE.lastIndex = 0;
  let m;
  while ((m = _IMPL_RE.exec(src)) !== null) {
    const kwIdx = m.index + m[0].search(/(?:impl|trait)\b/);
    const brace = _headerBrace(src, kwIdx);
    if (brace < 0) continue;
    const ex = _extractBody(src, brace);
    if (!ex) continue;
    let header = src.slice(kwIdx, brace).replace(/^(?:impl|trait)\s*/, '');
    header = header.replace(/^<[^>]*>\s*/, '');
    const forIdx = header.search(/\bfor\b/);
    if (forIdx >= 0) header = header.slice(forIdx + 3);
    const whereIdx = header.search(/\bwhere\b/);
    if (whereIdx >= 0) header = header.slice(0, whereIdx);
    header = header.replace(/^\s*&\s*(?:'\w+\s+)?(?:mut\s+)?/, '').trim();
    const name = _typeRoot(header);
    ranges.push({ start: brace, end: ex.end, name });
    _IMPL_RE.lastIndex = brace + 1;
  }
  return ranges;
}

function _enclosingImpl(ranges, idx) {
  let best = null;
  for (const r of ranges) {
    if (idx > r.start && idx < r.end && (!best || r.start > best.start)) best = r;
  }
  return best ? best.name : null;
}

function _qid(file, name, line, body) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  return `${file}::${name}@${line}#${sha}`;
}

export function parseRustFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  if (!/\.rs$/i.test(file)) return null;
  if (!code.trim() || code.length > 1_000_000) return null;

  const src = _preprocess(code);
  _src = src;
  _lineStarts = _computeLineStarts(src);
  _nid = 0;
  const implRanges = _findImplRanges(src);
  const functions = [];
  _FN_RE.lastIndex = 0;
  let m;
  while ((m = _FN_RE.exec(src)) !== null) {
    const name = m[1];
    // _FN_RE is now the bare `\bfn\s+(name)` pattern (see its own header
    // comment for why), so the match always starts exactly at "fn" itself —
    // no leading anchor/whitespace/qualifier text is ever consumed into
    // m[0] anymore.
    const fnKw = m.index;
    let i = m.index + m[0].length;
    // generics
    while (i < src.length && /\s/.test(src[i])) i++;
    if (src[i] === '<') {
      let d = 0;
      for (; i < src.length; i++) {
        if (src[i] === '<') d++;
        else if (src[i] === '>' && src[i - 1] !== '-') { d--; if (d === 0) { i++; break; } }
      }
    }
    while (i < src.length && /\s/.test(src[i])) i++;
    if (src[i] !== '(') continue;
    const paramsClose = _matchingClose(src, i);
    if (paramsClose < 0) continue;
    const paramsText = src.slice(i + 1, paramsClose);
    // find body `{` or a declaration `;`
    let j = paramsClose + 1;
    let brace = -1;
    let d = 0;
    for (; j < src.length;) {
      const e = _literalEnd(src, j);
      if (e > j) { j = e; continue; }
      const c = src[j];
      if (c === '(' || c === '[') d++;
      else if (c === ')' || c === ']') d--;
      else if (c === ';' && d === 0) break;
      else if (c === '{' && d === 0) { brace = j; break; }
      j++;
    }
    if (brace < 0) continue;
    const extracted = _extractBody(src, brace);
    if (!extracted) continue;
    const attrs = _precedingAttributes(src, _skipFnQualifiersBackward(src, fnKw));
    const hasRouteAttr = _ROUTE_ATTR_RE.test(attrs);
    const { params, paramAnnotations } = _parseParams(paramsText, hasRouteAttr);
    const startLine = _lineForOffset(fnKw);
    const className = _enclosingImpl(implRanges, fnKw);
    const nodes = {};
    const entry = _addNode(nodes, { kind: 'entry', line: startLine });
    const exit = _addNode(nodes, { kind: 'exit', line: startLine });
    let tail;
    try {
      tail = _buildCfg(extracted.body, brace + 1, nodes, entry, null, 0);
    } catch (err) {
      if (err instanceof RangeError) { tail = entry; } else throw err;
    }
    _link(nodes, tail, exit);
    const cfg = { entry, exit, nodes };
    const qualified = className ? `${className}.${name}` : name;
    functions.push({
      qid: _qid(file, qualified, startLine, extracted.body),
      name: qualified, line: startLine, params, file,
      cfg,
      calls: callSitesFromCfg(cfg),
      ...(paramAnnotations.length ? { paramAnnotations } : {}),
    });
    // nested fns are found by continuing the scan from inside the body
    _FN_RE.lastIndex = brace + 1;
  }
  return functions.length ? { file, functions, topLevel: null } : null;
}
