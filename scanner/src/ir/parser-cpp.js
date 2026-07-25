// C / C++ IR frontend.
//
// Hand-rolled, following the parser-cs.js / parser-go.js template. See
// docs/PROOF_CORPUS_PRD.md §6.3 for why this is not tree-sitter or libclang:
// the build excludes the tree-sitter deps from the bundle, and libclang would
// require native bindings plus a compile database we deliberately never build.
//
// The translation-unit splitter is the brace-balanced algorithm proven in
// sast/cpp-dataflow.js (written that way because a regex approach exhibited
// catastrophic backtracking on real headers), extended here to capture
// qualified names like `core::Buffer::size`.
//
// What we model:
//   - free functions, out-of-line methods (Ns::Class::method), constructors,
//     destructors, in-class method definitions
//   - header declarations (no body) recorded with isDeclaration: true
//   - parameters including refs, pointers, const, templates, default args
//   - class records with base classes, for class-hierarchy analysis
//
// What we do NOT model (PRD §6.5 — this list is a contract):
//   - templates (parsed; type parameters erased — one record per template,
//     not one per instantiation)
//   - operator overloading semantics beyond string building
//   - exact virtual dispatch (approximated via CHA)
//   - try/catch edges (throw is a node; handler edges are not built)
//   - pointer aliasing beyond direct assignment
//   - function-like macros, token pasting, conditional-compilation selection
//   - goto, multiple-inheritance vtable layout, placement new

import * as crypto from 'node:crypto';

const CPP_EXT_RE = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i;

// Keywords that are followed by `(...)  {` but are not functions.
const _NON_FN_KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'switch', 'catch', 'do', 'return', 'sizeof',
  'and', 'or', 'not', 'new', 'delete', 'throw', 'case', 'default',
]);

// Guard rails so a pathological file cannot dominate a scan.
const _MAX_FUNCTIONS = 5000;
const _LOOKBACK = 400;

export function cppExtRe() { return CPP_EXT_RE; }

// ── comment / string blanking ───────────────────────────────────────────────
// Replace comment and string bodies with spaces, preserving length and line
// structure so every index and line number computed later stays valid.
function _blank(src) {
  const out = src.split('');
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') { out[i] = ' '; i++; }
      continue;
    }
    if (c === '/' && d === '*') {
      out[i] = ' '; out[i + 1] = ' '; i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] !== '\n') out[i] = ' ';
        i++;
      }
      if (i < n) { out[i] = ' '; out[i + 1] = ' '; i += 2; }
      continue;
    }
    if (c === '"' || c === "'") {
      const quote = c;
      out[i] = ' '; // blank the opening quote too, symmetric with the closing one below
      i++;
      while (i < n) {
        if (src[i] === '\\') {
          out[i] = ' ';
          if (i + 1 < n && src[i + 1] !== '\n') out[i + 1] = ' ';
          i += 2;
          continue;
        }
        if (src[i] === quote) { out[i] = ' '; i++; break; }
        if (src[i] !== '\n') out[i] = ' ';
        i++;
      }
      continue;
    }
    i++;
  }
  return out.join('');
}

function _lineAt(src, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < src.length; i++) if (src[i] === '\n') line++;
  return line;
}

// Build a sorted array of line-start offsets for `text` (index 0 holds the
// start of line 1, i.e. always 0). Used with `_lineForOffset` to turn a
// character offset into a line number in O(log n) instead of O(n) — a
// per-statement `_lineAt` rescan from offset 0 is O(n) per call and O(n^2)
// over a whole function body, which is exactly the "hangs on a huge
// generated/unity-build source file" failure mode this parser must avoid.
function _lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

// Binary search `lineStarts` (as built by `_lineStarts`) for the 1-based
// line number containing offset `idx`.
function _lineForOffset(lineStarts, idx) {
  let lo = 0, hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= idx) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

function _qid(file, tail, line, body) {
  const sha = crypto.createHash('sha256').update(body).digest('hex').slice(0, 8);
  return `${file}::${tail}@${line}#${sha}`;
}

// Split `a, b<c, d>, e(f, g)` on top-level commas only.
function _splitTopLevelCommas(s) {
  const out = [];
  let depth = 0, buf = '';
  for (const ch of String(s || '')) {
    if (ch === '(' || ch === '[' || ch === '<' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '>' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { out.push(buf); buf = ''; continue; }
    buf += ch;
  }
  if (buf.trim()) out.push(buf);
  return out;
}

// `const std::string& name` → 'name'; `int n = 10` → 'n'; `void` → null.
function _parseParams(text) {
  const params = [];
  for (const raw of _splitTopLevelCommas(text)) {
    let t = raw.replace(/=.*$/s, '').trim();
    if (!t || t === 'void' || t === '...') continue;
    // Array suffix: `char buf[10]` → `char buf`
    t = t.replace(/\[[^\]]*\]\s*$/, '').trim();
    const m = t.match(/([A-Za-z_]\w*)\s*$/);
    if (m && !_NON_FN_KEYWORDS.has(m[1])) params.push(m[1]);
  }
  return params;
}

// Body extraction by brace counting over already-blanked source.
function _extractBody(blank, openBrace) {
  let depth = 1;
  let i = openBrace + 1;
  while (i < blank.length && depth > 0) {
    const c = blank[i];
    if (c === '{') depth++;
    else if (c === '}') depth--;
    if (depth === 0) return { start: openBrace + 1, end: i };
    i++;
  }
  return null; // unterminated — caller skips
}

// Walk back from a `(` to capture a possibly-qualified name: `core::Buffer::size`,
// `~Widget`, `operator+` is deliberately NOT captured (out of scope).
function _nameBefore(blank, lparen) {
  let end = lparen - 1;
  while (end >= 0 && /\s/.test(blank[end])) end--;
  if (end < 0) return null;
  let start = end;
  while (start >= 0 && /[A-Za-z0-9_:~]/.test(blank[start])) start--;
  start++;
  const raw = blank.slice(start, end + 1);
  if (!raw || !/^[~A-Za-z_][\w:~]*$/.test(raw)) return null;
  if (raw.includes(':') && !raw.includes('::')) return null; // label, not scope
  return raw;
}

// Find enclosing class for an index, from collected class spans.
function _enclosingClass(classSpans, idx) {
  let best = null;
  for (const c of classSpans) {
    if (idx > c.open && idx < c.close) {
      if (!best || c.open > best.open) best = c;
    }
  }
  return best ? best.name : null;
}

// Collect `class X : public A, private B {` / `struct X {` spans.
function _findClasses(blank) {
  const spans = [];
  const re = /\b(?:class|struct)\s+([A-Za-z_]\w*)\s*(?::([^{;]*))?\{/g;
  let m;
  while ((m = re.exec(blank)) !== null) {
    const open = m.index + m[0].length - 1;
    const body = _extractBody(blank, open);
    if (!body) continue;
    const bases = [];
    if (m[2]) {
      for (const part of _splitTopLevelCommas(m[2])) {
        const b = part.replace(/\b(?:public|private|protected|virtual)\b/g, '').trim();
        const last = b.split('::').pop();
        if (last && /^[A-Za-z_]\w*$/.test(last)) bases.push(last);
      }
    }
    spans.push({ name: m[1], bases, line: _lineAt(blank, m.index), open, close: body.end });
  }
  return spans;
}

// Find every function definition (with body) and declaration (no body).
function _findFunctions(blank, classSpans) {
  const found = [];
  const n = blank.length;
  let i = 0;
  while (i < n && found.length < _MAX_FUNCTIONS) {
    const ch = blank[i];
    if (ch !== '(') { i++; continue; }
    // Match the closing paren for this `(`.
    let depth = 1, j = i + 1;
    while (j < n && depth > 0) {
      if (blank[j] === '(') depth++;
      else if (blank[j] === ')') depth--;
      j++;
    }
    if (depth !== 0) { i++; continue; }
    const paramText = blank.slice(i + 1, j - 1);
    const name = _nameBefore(blank, i);
    if (!name) { i++; continue; }
    const bare = name.split('::').pop();
    if (!bare || _NON_FN_KEYWORDS.has(bare)) { i++; continue; }
    if (name.length > _LOOKBACK) { i++; continue; }

    // After the params: skip const/noexcept/override/final/ref-qualifiers.
    let k = j;
    while (k < n && /[\s\w&]/.test(blank[k])) {
      // Stop if we hit something that starts a body or ends a declaration.
      if (blank[k] === '{' || blank[k] === ';') break;
      k++;
    }
    const term = blank[k];
    if (term === '{') {
      const body = _extractBody(blank, k);
      if (!body) { i = j; continue; }
      found.push({
        name, paramText,
        line: _lineAt(blank, i),
        bodyStart: body.start, bodyEnd: body.end,
        isDeclaration: false,
        nameIdx: i,
      });
      i = body.end + 1;
      continue;
    }
    if (term === ';') {
      // A declaration only counts when it sits inside a class body — otherwise
      // it is very likely a call statement or a prototype we do not need.
      const cls = _enclosingClass(classSpans, i);
      if (cls) {
        found.push({
          name, paramText,
          line: _lineAt(blank, i),
          bodyStart: null, bodyEnd: null,
          isDeclaration: true,
          nameIdx: i,
        });
      }
      i = k + 1;
      continue;
    }
    i = j;
  }
  return found;
}

export function parseCppFile(file, code) {
  if (typeof file !== 'string' || typeof code !== 'string') return null;
  const blank = _blank(code);
  const classSpans = _findClasses(blank);
  const raw = _findFunctions(blank, classSpans);

  const functions = [];
  for (const f of raw) {
    const bare = f.name.split('::').pop();
    const explicitScope = f.name.includes('::')
      ? f.name.slice(0, f.name.lastIndexOf('::'))
      : null;
    const enclosing = _enclosingClass(classSpans, f.nameIdx);
    // Fully-qualified name for the cross-TU index.
    const qname = explicitScope
      ? `${explicitScope}::${bare}`
      : (enclosing ? `${enclosing}::${bare}` : bare);
    // The class used in the qid tail is the IMMEDIATE class — the last scope
    // segment — because class-hierarchy.js splits the tail on its first dot.
    const ownerClass = explicitScope ? explicitScope.split('::').pop() : enclosing;
    const tail = ownerClass ? `${ownerClass}.${bare}` : bare;
    const bodyText = f.isDeclaration ? '' : code.slice(f.bodyStart, f.bodyEnd);
    // Structure (statement/brace/paren boundaries) is decided from the
    // blanked body so a brace or paren inside a string/comment can't
    // silently swallow the statements that follow it; the matching RAW
    // slice (same offsets — `_blank` preserves length) is what actually
    // gets lowered, so identifiers and call names still survive.
    const blankBodyText = f.isDeclaration ? '' : blank.slice(f.bodyStart, f.bodyEnd);

    functions.push({
      qid: _qid(file, tail, f.line, bodyText || `${qname}@decl`),
      name: bare,
      qname,
      line: f.line,
      params: _parseParams(f.paramText),
      file,
      isDeclaration: f.isDeclaration,
      cfg: _buildCfg(bodyText, blankBodyText, f.line),
    });
  }

  return {
    file,
    functions,
    classes: classSpans.map(c => ({ name: c.name, bases: c.bases, line: c.line })),
    topLevel: null,
  };
}

// ── expression lowering ─────────────────────────────────────────────────────

// Split on a top-level binary operator, respecting nesting.
function _splitTopLevel(s, op) {
  const out = [];
  let depth = 0, buf = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    if (depth === 0 && ch === op) { out.push(buf); buf = ''; continue; }
    buf += ch;
  }
  out.push(buf);
  return out;
}

// Normalise `a->b->c` and `a.b.c` to dotted form; `::` is preserved as scope.
function _normaliseCallee(s) {
  return s.replace(/->/g, '.').trim();
}

function _lowerExpr(text) {
  const s = String(text || '').trim().replace(/;$/, '').trim();
  if (!s) return { kind: 'unknown' };

  // String concatenation — checked before the literal rule, or `"a" + x`
  // would be swallowed whole as a literal and taint could not flow.
  if (s.includes('+')) {
    const parts = _splitTopLevel(s, '+');
    if (parts.length > 1 && parts.every(p => p.trim())) {
      return { kind: 'tpl', parts: parts.map(_lowerExpr) };
    }
  }
  if (/^"/.test(s) || /^'/.test(s)) return { kind: 'literal', value: s };
  if (/^-?\d/.test(s)) return { kind: 'literal', value: s };
  if (/^(?:true|false|nullptr|NULL)$/.test(s)) return { kind: 'literal', value: s };

  // Cast: `(char*)expr` → lower the inner expression.
  const cast = s.match(/^\(\s*[A-Za-z_][\w:\s*&<>]*\)\s*(.+)$/s);
  if (cast && !/^\(\s*\)/.test(s)) return _lowerExpr(cast[1]);

  // Call: name(args) / a.b(args) / a->b(args) / ns::f(args)
  const call = s.match(/^([A-Za-z_][\w:.]*(?:->[A-Za-z_]\w*)*)\s*\((.*)\)$/s);
  if (call) {
    const callee = _normaliseCallee(call[1]);
    const bare = callee.split(/[.:]/).pop();
    if (!_NON_FN_KEYWORDS.has(bare)) {
      return { kind: 'call', callee, args: _splitTopLevelCommas(call[2]).map(_lowerExpr) };
    }
  }

  // Address-of / dereference: taint passes through transparently.
  const unary = s.match(/^[&*]\s*(.+)$/s);
  if (unary) return _lowerExpr(unary[1]);

  // Member read: a.b / a->b / ns::CONST
  if (/^[A-Za-z_][\w:.]*(?:->[A-Za-z_]\w*)*$/.test(s) && /[.:>]/.test(s)) {
    const d = _normaliseCallee(s);
    const idx = d.lastIndexOf('.');
    if (idx > 0) {
      return { kind: 'member', object: _lowerExpr(d.slice(0, idx)), prop: d.slice(idx + 1) };
    }
    return { kind: 'ident', name: d };
  }

  // Array index: `buf[i]` → treat as the base identifier.
  const idxm = s.match(/^([A-Za-z_]\w*)\s*\[.*\]$/s);
  if (idxm) return { kind: 'ident', name: idxm[1] };

  if (/^[A-Za-z_]\w*$/.test(s)) return { kind: 'ident', name: s };

  // Comparison / arithmetic — keep both sides so taint survives.
  for (const op of ['==', '!=', '<=', '>=', '<', '>', '-', '*', '/', '%']) {
    const parts = _splitTopLevel(s, op.length === 1 ? op : '\u0000');
    if (op.length === 1 && parts.length > 1 && parts.every(p => p.trim())) {
      return { kind: 'binary', op, left: _lowerExpr(parts[0]), right: _lowerExpr(parts.slice(1).join(op)) };
    }
  }
  return { kind: 'unknown' };
}

// ── statement splitting ─────────────────────────────────────────────────────

// Split a (blanked) body into top-level statements, returning character
// OFFSETS rather than text. The caller slices the same offsets out of both
// the blanked text (for further structural decisions) and the raw text (for
// content to lower) — see `_buildCfg`'s "structure from blank, content from
// raw" split. Operating on the blanked text means a `{`, `(`, `}` or `)`
// that only exists inside a string literal or comment in the RAW source
// (already turned to spaces by `_blank`) cannot be mistaken for real
// structure and swallow the statements that follow it.
//
// Blocks (`{...}`) are returned whole so the caller can recurse into them.
// A prior line-per-chunk approach (pre-splitting on '\n' before this
// function ran) silently dropped any statement whose opening brace and body
// lived on different physical lines, because a lone `{` or a lone
// continuation fragment doesn't round-trip through the statement grammar.
// This function is handed the WHOLE body in one call for exactly that
// reason — never split on '\n' first.
function _splitStatements(body) {
  const out = [];
  // `depth` tracks braces (statement/block boundaries); `parenDepth` tracks
  // parens separately so the `;` separators inside a `for (init; test; step)`
  // header don't get mistaken for statement terminators.
  let depth = 0, parenDepth = 0, buf = '', atStart = true, stmtStart = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (atStart && /\s/.test(c)) continue;
    if (atStart) { atStart = false; stmtStart = i; }
    if (c === '(') parenDepth++;
    else if (c === ')') parenDepth = Math.max(0, parenDepth - 1);
    if (c === '{') depth++;
    if (c === '}') {
      depth--;
      buf += c;
      if (depth === 0) { out.push({ start: stmtStart, end: i + 1 }); buf = ''; atStart = true; }
      continue;
    }
    if (c === ';' && depth === 0 && parenDepth === 0) {
      if (buf.trim()) out.push({ start: stmtStart, end: i });
      buf = '';
      atStart = true;
      continue;
    }
    buf += c;
  }
  if (buf.trim()) out.push({ start: stmtStart, end: body.length });
  return out;
}

// Find the index of the delimiter in `openCh`/`closeCh` that matches the one
// at `openIdx`, respecting nesting. Returns -1 if unmatched (caller must
// treat that as "give up gracefully", never hang or throw).
function _matchDelim(text, openIdx, openCh, closeCh) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (text[i] === openCh) depth++;
    else if (text[i] === closeCh) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Split `blankText`/`rawText` (same length, index-aligned — same contract as
// the blank/raw pairing everywhere else in this file) on a top-level
// occurrence of `sepChar`, deciding nesting depth from `blankText` so a
// separator character hidden inside a blanked string/comment in the raw
// text can't be mistaken for a real one. Returns the corresponding RAW
// substrings — used for the `for (init; test; step)` header split.
function _splitTopLevelAligned(blankText, rawText, sepChar) {
  const out = [];
  let depth = 0, start = 0;
  for (let i = 0; i < blankText.length; i++) {
    const ch = blankText[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    if (depth === 0 && ch === sepChar) { out.push(rawText.slice(start, i)); start = i + 1; }
  }
  out.push(rawText.slice(start));
  return out;
}

function _lowerStmt(stmt, line) {
  const s = stmt.trim();
  if (!s || s === '{' || s === '}') return null;

  if (/^return\b/.test(s)) {
    const v = s.replace(/^return\b/, '').trim();
    return { kind: 'return', line, value: v ? _lowerExpr(v) : null };
  }
  if (/^throw\b/.test(s)) {
    return { kind: 'throw', line, value: _lowerExpr(s.replace(/^throw\b/, '')) };
  }
  if (/^(?:break|continue|goto\b)/.test(s)) return { kind: 'noop', line };

  // Assignment. The type prefix is optional: `int x = e`, `x = e`, `a->b = e`.
  // `==`, `!=`, `<=`, `>=` must not match, hence the negative lookarounds.
  const asg = s.match(/^(?:[A-Za-z_][\w:<>,*&\s]*?\s+)?([A-Za-z_][\w:.\->\[\]]*?)\s*(?<![=!<>+\-*/%])=(?!=)\s*(.+)$/s);
  if (asg) {
    const target = _normaliseCallee(asg[1]).replace(/\[.*\]$/, '');
    return { kind: 'assign', line, target, source: _lowerExpr(asg[2]) };
  }

  // Statement-form call.
  const call = s.match(/^([A-Za-z_][\w:.]*(?:->[A-Za-z_]\w*)*)\s*\((.*)\)$/s);
  if (call) {
    const callee = _normaliseCallee(call[1]);
    const bare = callee.split(/[.:]/).pop();
    if (!_NON_FN_KEYWORDS.has(bare)) {
      return { kind: 'call', line, callee, args: _splitTopLevelCommas(call[2]).map(_lowerExpr) };
    }
  }
  return { kind: 'unknown', line, text: s.slice(0, 200) };
}

// ── CFG construction ────────────────────────────────────────────────────────

// `rawBody` and `blankBody` are the same function body, index-aligned:
// `blankBody` (comments/strings replaced with spaces, same length) decides
// STRUCTURE — where statements/blocks/parens begin and end; `rawBody` is
// sliced at those same offsets to provide the CONTENT that actually gets
// lowered into expressions. This is what stops a brace, paren, or semicolon
// that only exists inside a string literal from being mistaken for real
// code structure and swallowing (or mis-splitting) the statements after it.
function _buildCfg(rawBody, blankBody, startLine) {
  const nodes = {
    entry: { kind: 'entry', line: startLine, succ: [], pred: [] },
    exit: { kind: 'exit', line: startLine, succ: [], pred: [] },
  };
  let counter = 0;
  let prev = 'entry';
  const link = (id) => {
    nodes[prev].succ.push(id);
    nodes[id].pred.push(prev);
    prev = id;
  };

  // Built once per function body (O(n)); looked up per statement in
  // O(log n) via `_lineForOffset` — see that helper's comment for why a
  // per-statement `_lineAt` rescan is unacceptable here.
  const lineStarts = _lineStarts(blankBody);

  // Emit statements linearly. Control-flow headers become `if` nodes and
  // their blocks are recursed into, so bodies are never dropped — the same
  // straight-line treatment parser-go.js and parser-cs.js use.
  //
  // `baseAbs` is the absolute offset of `blankText[0]` within the top-level
  // `blankBody`. Every node's line number is computed from that absolute
  // offset via `_lineForOffset(lineStarts, ...)` rather than from a
  // per-recursion relative counter, so nested blocks get their true
  // physical line instead of one measured from the function's start line
  // regardless of nesting depth (a counter that restarts per recursion
  // compounds error as nesting gets deeper).
  const emit = (blankText, rawText, baseAbs, depth) => {
    if (depth > 12) return;
    for (const { start, end } of _splitStatements(blankText)) {
      const blankStmt = blankText.slice(start, end);
      const rawStmt = rawText.slice(start, end);
      const absStart = baseAbs + start;
      const line = startLine + _lineForOffset(lineStarts, absStart) - 1;

      const hm = blankStmt.match(/^(if|while|for|switch|else\s+if|else|do|try|catch)\b/);
      if (hm) {
        const kwNorm = hm[1].replace(/\s+/g, ' ').trim();
        let p = hm[0].length;
        while (p < blankStmt.length && /\s/.test(blankStmt[p])) p++;

        // A parenthesised group directly follows most of these keywords
        // (`if (`, `while (`, `for (`, `switch (`, `catch (Type& e)`); find
        // its TRUE matching close paren via a balanced scan (not a
        // non-greedy regex, which stops at the first `)` and truncates on
        // any nested call like `fgets(buf, sizeof(buf), stdin)`).
        let condBlank = null, condRaw = null, afterHeader = p;
        if (blankStmt[p] === '(') {
          const closeIdx = _matchDelim(blankStmt, p, '(', ')');
          if (closeIdx !== -1) {
            condBlank = blankStmt.slice(p + 1, closeIdx);
            condRaw = rawStmt.slice(p + 1, closeIdx);
            afterHeader = closeIdx + 1;
          }
        }

        const needsCond = /^(?:if|while|for|switch|else if)$/.test(kwNorm);
        if (needsCond && condRaw !== null) {
          let condForNode = condRaw;
          let initRaw = null;
          if (kwNorm === 'for') {
            // `for (init; test; step)` — surface the test as the condition
            // and the init as a leading assignment, splitting on the
            // BLANKED cond so a `;` inside a string literal in the header
            // can't be mistaken for a header separator.
            const parts = _splitTopLevelAligned(condBlank, condRaw, ';');
            condForNode = parts.length > 1 ? parts[1] : condRaw;
            initRaw = parts[0];
          }
          const id = `n${counter++}`;
          nodes[id] = { kind: 'if', line, cond: _lowerExpr(condForNode), succ: [], pred: [] };
          link(id);
          if (kwNorm === 'for' && initRaw) {
            const initNode = _lowerStmt(initRaw, line);
            if (initNode && initNode.kind === 'assign') {
              const iid = `n${counter++}`;
              nodes[iid] = { ...initNode, succ: [], pred: [] };
              link(iid);
            }
          }
        }

        const restBlank = blankText.slice(start + afterHeader, end);
        const restRaw = rawText.slice(start + afterHeader, end);
        const lead = restBlank.match(/^\s*/)[0].length;
        if (restBlank[lead] === '{') {
          const closeRel = _matchDelim(restBlank, lead, '{', '}');
          if (closeRel !== -1) {
            const innerStart = lead + 1;
            emit(restBlank.slice(innerStart, closeRel), restRaw.slice(innerStart, closeRel),
              baseAbs + start + afterHeader + innerStart, depth + 1);
          }
        } else if (restBlank.trim()) {
          emit(restBlank, restRaw, baseAbs + start + afterHeader, depth + 1);
        }
        continue;
      }

      const bare = blankStmt.match(/^\{([\s\S]*)\}$/);
      if (bare) {
        emit(blankStmt.slice(1, -1), rawStmt.slice(1, -1), baseAbs + start + 1, depth + 1);
        continue;
      }
      // Leaf statement: structure has been fully resolved by the blanked
      // split above, so content lowering uses the RAW text — identifiers,
      // call names and string-literal detection all need the real
      // characters, not the blanked-out ones.
      const node = _lowerStmt(rawStmt, line);
      if (!node) continue;
      const id = `n${counter++}`;
      nodes[id] = { ...node, succ: [], pred: [] };
      link(id);
    }
  };

  if (rawBody) emit(blankBody, rawBody, 0, 0);

  nodes[prev].succ.push('exit');
  nodes.exit.pred.push(prev);
  return { entry: 'entry', exit: 'exit', nodes };
}

export const _internals = {
  _blank, _splitTopLevelCommas, _parseParams, _extractBody,
  _lineAt, _qid, _findFunctions, _findClasses, _nameBefore,
  _lowerExpr, _lowerStmt, _splitStatements, _buildCfg,
  _matchDelim, _splitTopLevelAligned, _lineStarts, _lineForOffset,
};
