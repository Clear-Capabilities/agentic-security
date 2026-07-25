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
      i++;
      while (i < n) {
        if (src[i] === '\\') { out[i] = ' '; if (i + 1 < n) out[i + 1] = ' '; i += 2; continue; }
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
    if (depth !== 0) break;
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

    functions.push({
      qid: _qid(file, tail, f.line, bodyText || `${qname}@decl`),
      name: bare,
      qname,
      line: f.line,
      params: _parseParams(f.paramText),
      file,
      isDeclaration: f.isDeclaration,
      cfg: _buildCfg(bodyText, f.line),
    });
  }

  return {
    file,
    functions,
    classes: classSpans.map(c => ({ name: c.name, bases: c.bases, line: c.line })),
    topLevel: null,
  };
}

// Statement lowering arrives in Task 2; for now every body yields a
// well-formed entry→exit CFG so the IR shape contract holds from the start.
function _buildCfg(_bodyText, line) {
  const nodes = {
    entry: { kind: 'entry', line, succ: ['exit'], pred: [] },
    exit: { kind: 'exit', line, succ: [], pred: ['entry'] },
  };
  return { entry: 'entry', exit: 'exit', nodes };
}

export const _internals = {
  _blank, _splitTopLevelCommas, _parseParams, _extractBody,
  _lineAt, _qid, _findFunctions, _findClasses, _nameBefore,
};
