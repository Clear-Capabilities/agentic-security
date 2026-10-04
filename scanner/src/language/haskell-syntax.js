// Haskell expression/declaration syntax for the semantic IR (HS-002).
//
// Static and bounded. It lexes the ORIGINAL source (comments, pragmas and
// strings never become tokens), resolves the layout rule from token columns,
// and builds a small AST: declarations, clauses with guards and where blocks,
// patterns, and expressions with real operator precedence (`$`, `.`, `>>=`,
// `<$>`, `<*>`, backtick operators, sections). It never executes anything.
//
// What it does not do: type checking, typeclass resolution, fixity declarations
// (a fixed table is used), Template Haskell, quasi-quotes, CPP. A declaration
// it cannot parse becomes an `errors` entry and contributes no AST, so the
// caller can mark the module partial instead of inventing structure.

export class SyntaxBudgetError extends Error {}

const KW = new Set(['case', 'class', 'data', 'default', 'deriving', 'do', 'else', 'foreign', 'if', 'import', 'in', 'infix', 'infixl', 'infixr', 'instance', 'let', 'module', 'newtype', 'of', 'then', 'type', 'where']);
const RESERVED_OPS = new Set(['=', '|', '->', '<-', '::', '=>', '\\', '@', '~', '..']);
const SYM = new Set('!#$%&*+./<=>?@\\^|-~:'.split(''));
const OPEN = { '(': ')', '[': ']', '{': '}' };
const isSym = (c) => c !== undefined && SYM.has(c);
const isIdStart = (c) => c !== undefined && /[\p{L}_]/u.test(c);
const isIdChar = (c) => c !== undefined && /[\p{L}\p{N}_']/u.test(c);
const isUpper = (c) => c !== undefined && /\p{Lu}/u.test(c);
const NUM = /0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?/y;

/**
 * Token: {t, v, q?, line, col, first, off, end, cons?}
 * t is var|con|op|rop|kw|int|float|str|chr|sp. `first` is true for the first
 * token on its line; `col` is the 0-based column with tabs at 8.
 */
export function lexHs(src) {
  const T = [];
  const n = src.length;
  let i = 0;
  let line = 1;
  let col = 0;
  let lineHasTok = false;
  const adv = (k) => {
    for (let j = 0; j < k && i < n; j++) {
      const c = src[i++];
      if (c === '\n') { line++; col = 0; lineHasTok = false; }
      else if (c === '\t') col = (Math.floor(col / 8) + 1) * 8;
      else col++;
    }
  };
  const push = (t, v, extra, len) => {
    T.push({ t, v, line, col, first: !lineHasTok, off: i, end: i + len, ...extra });
    lineHasTok = true;
    adv(len);
  };
  while (i < n) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f') { adv(1); continue; }
    if (c === '{' && src[i + 1] === '-') {
      let depth = 0;
      let j = i;
      while (j < n) {
        if (src[j] === '{' && src[j + 1] === '-') { depth++; j += 2; }
        else if (src[j] === '-' && src[j + 1] === '}') { depth--; j += 2; if (depth === 0) break; }
        else j++;
      }
      adv(j - i);
      continue;
    }
    if (c === '-' && src[i + 1] === '-') {
      let j = i;
      while (src[j] === '-') j++;
      if (!isSym(src[j])) {
        while (j < n && src[j] !== '\n') j++;
        adv(j - i);
        continue;
      }
    }
    if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"') j += src[j] === '\\' ? 2 : 1;
      j = Math.min(n, j + 1);
      push('str', src.slice(i + 1, Math.max(i + 1, j - 1)), {}, j - i);
      continue;
    }
    if (c === "'") {
      if (src[i + 1] === '\\') {
        let j = i + 2;
        while (j < n && j < i + 12 && src[j] !== "'") j++;
        if (src[j] === "'") { push('chr', src.slice(i + 1, j), {}, j + 1 - i); continue; }
      } else if (src[i + 2] === "'" && src[i + 1] !== undefined) {
        push('chr', src[i + 1], {}, 3);
        continue;
      }
      adv(1);
      continue;
    }
    if (c >= '0' && c <= '9') {
      NUM.lastIndex = i;
      const m = NUM.exec(src);
      const txt = m ? m[0] : c;
      push(/^[0-9]/.test(txt) && !/^0[xXoObB]/.test(txt) && /[.eE]/.test(txt) ? 'float' : 'int', txt, {}, txt.length);
      continue;
    }
    if (isIdStart(c)) {
      if (isUpper(c)) {
        let j = i;
        const segs = [];
        let done = false;
        for (;;) {
          let k = j;
          while (isIdChar(src[k])) k++;
          segs.push(src.slice(j, k));
          j = k;
          if (src[j] === '.' && isIdStart(src[j + 1])) {
            if (isUpper(src[j + 1])) { j++; continue; }
            let m = j + 1;
            while (isIdChar(src[m])) m++;
            const name = src.slice(j + 1, m);
            if (KW.has(name)) break;
            push('var', name, { q: segs.join('.') }, m - i);
            done = true;
            break;
          }
          if (src[j] === '.' && isSym(src[j + 1])) {
            let m = j + 1;
            while (isSym(src[m])) m++;
            const op = src.slice(j + 1, m);
            push('op', op, { q: segs.join('.'), cons: op[0] === ':' }, m - i);
            done = true;
            break;
          }
          break;
        }
        if (!done) push('con', segs[segs.length - 1], segs.length > 1 ? { q: segs.slice(0, -1).join('.') } : {}, j - i);
        continue;
      }
      let k = i;
      while (isIdChar(src[k])) k++;
      const v = src.slice(i, k);
      push(KW.has(v) ? 'kw' : 'var', v, {}, k - i);
      continue;
    }
    if (c === '(' || c === ')' || c === '[' || c === ']' || c === ',' || c === ';' || c === '`' || c === '{' || c === '}') {
      push('sp', c, {}, 1);
      continue;
    }
    if (isSym(c)) {
      let j = i;
      while (isSym(src[j])) j++;
      const v = src.slice(i, j);
      if (RESERVED_OPS.has(v)) push('rop', v, {}, j - i);
      else push('op', v, { cons: v[0] === ':' }, j - i);
      continue;
    }
    adv(1);
  }
  return T;
}

export function matchBrackets(T) {
  const mate = new Int32Array(T.length).fill(-1);
  const st = [];
  for (let i = 0; i < T.length; i++) {
    const t = T[i];
    if (t.t !== 'sp') continue;
    if (OPEN[t.v]) st.push(i);
    else if (t.v === ')' || t.v === ']' || t.v === '}') {
      const top = st.length ? st[st.length - 1] : -1;
      if (top >= 0 && OPEN[T[top].v] === t.v) { mate[top] = i; mate[i] = top; st.pop(); }
    }
  }
  return mate;
}

const FIX = {
  '$': [0, 'r'], '$!': [0, 'r'], '>>=': [1, 'l'], '>>': [1, 'l'], '=<<': [1, 'r'], '>=>': [1, 'r'], '<=<': [1, 'r'],
  '&': [1, 'l'], '<&>': [1, 'l'], '||': [2, 'r'], '&&': [3, 'r'], '<|>': [3, 'l'],
  '==': [4, 'l'], '/=': [4, 'l'], '<': [4, 'l'], '<=': [4, 'l'], '>': [4, 'l'], '>=': [4, 'l'],
  '<$>': [4, 'l'], '<$': [4, 'l'], '$>': [4, 'l'], '<*>': [4, 'l'], '<*': [4, 'l'], '*>': [4, 'l'], '<$!>': [4, 'l'],
  '++': [5, 'r'], ':': [5, 'r'], '<>': [6, 'r'], '+': [6, 'l'], '-': [6, 'l'], '*': [7, 'l'], '/': [7, 'l'],
  '^': [8, 'r'], '.': [9, 'r'], '!!': [9, 'l'], '!': [9, 'l'],
};
const BT_FIX = { elem: [4, 'l'], notElem: [4, 'l'], div: [7, 'l'], mod: [7, 'l'], quot: [7, 'l'], rem: [7, 'l'] };

/**
 * Parse a Haskell source string.
 * @returns {{tokens:object[], module:object|null, imports:object[], decls:object[], sigs:object[], data:object[], classes:object[], instances:object[], errors:object[], boundaries:object[]}}
 */
export function parseSyntax(src, opts = {}) {
  const T = lexHs(src);
  const mate = matchBrackets(T);
  const N = T.length;
  const errors = [];
  const maxSteps = opts.maxSteps || 3_000_000;
  const maxDepth = opts.maxDepth || 160;
  let steps = 0;
  let depth = 0;
  const tick = () => { if (++steps > maxSteps) throw new SyntaxBudgetError('maxSteps'); };
  const err = (kind, tok, detail) => errors.push({ kind, line: tok ? tok.line : 1, detail });

  let pos = 0;
  let lim = 0;
  let layoutIndent = -1;

  const peek = () => (pos < lim ? T[pos] : null);
  const isSp = (t, v) => t && t.t === 'sp' && t.v === v;
  const isRop = (t, v) => t && t.t === 'rop' && t.v === v;
  const isKw = (t, v) => t && t.t === 'kw' && t.v === v;
  const groupEnd = (i) => (T[i] && T[i].t === 'sp' && OPEN[T[i].v] && mate[i] > i ? mate[i] + 1 : i + 1);

  function sub(a, b, fn) {
    const sp = pos; const sl = lim;
    pos = a; lim = b;
    let r;
    try {
      r = fn();
      if (pos < lim) err('unparsed-tail', T[pos], 'tokens left after expression');
    } finally { pos = sp; lim = sl; }
    return r;
  }
  function splitTop(a, b, pred) {
    const parts = [];
    let s = a;
    let i = a;
    while (i < b) {
      tick();
      if (pred(T[i])) { parts.push([s, i]); s = i + 1; i++; continue; }
      i = Math.min(b, groupEnd(i));
    }
    parts.push([s, b]);
    return parts;
  }
  function findTop(a, b, pred) {
    let i = a;
    while (i < b) {
      tick();
      if (pred(T[i])) return i;
      i = Math.min(b, groupEnd(i));
    }
    return -1;
  }
  const comma = (t) => isSp(t, ',');

  // ── layout ──────────────────────────────────────────────────────────────
  function splitItems(a, b, indent) {
    const items = [];
    let start = a;
    let i = a;
    while (i < b) {
      tick();
      const t = T[i];
      // A new line at the block's indent starts a new item EVEN when that line opens a bracket
      // (`("GET", ["a"]) -> ...`): the boundary test must run before the bracket is skipped.
      if (indent !== null && i > start && t.first && t.col === indent && !isSp(t, ';')) {
        items.push([start, i]);
        start = i;
      }
      if (t.t === 'sp' && OPEN[t.v] && mate[i] > i) { i = mate[i] + 1; continue; }
      if (isSp(t, ';')) {
        if (i > start) items.push([start, i]);
        start = i + 1;
      }
      i++;
    }
    if (start < b) items.push([start, b]);
    return items;
  }
  function blockAfter(k, rangeEnd, parentIndent) {
    const a = k + 1;
    if (a >= rangeEnd) return { a, b: a, items: [], indent: -1 };
    if (isSp(T[a], '{') && mate[a] > a) {
      const b = mate[a];
      return { a: a + 1, b: b + 1, items: splitItems(a + 1, b, null), indent: -1 };
    }
    const indent = T[a].col;
    if (indent <= parentIndent) return { a, b: a, items: [], indent };
    let ifOpen = 0; let thenOpen = 0; let caseOpen = 0; let letOpen = 0;
    let j = a;
    for (; j < rangeEnd; j++) {
      tick();
      const t = T[j];
      if (j > a && t.first && t.col < indent) break;
      // Haskell's parse-error(t) rule: a `where` that starts a line at the block's own
      // indent cannot begin an item, so it closes the implicit block (do/of/let/where).
      if (j > a && t.first && t.col === indent && t.t === 'kw' && t.v === 'where') break;
      if (t.t === 'sp' && OPEN[t.v] && mate[j] > j) { j = mate[j]; continue; }
      if (t.t === 'sp' && (t.v === ')' || t.v === ']' || t.v === '}')) break;
      if (t.t === 'kw') {
        const v = t.v;
        if (v === 'in') { if (letOpen > 0) letOpen--; else break; }
        else if (v === 'let') letOpen++;
        else if (v === 'case') caseOpen++;
        else if (v === 'of') { if (caseOpen > 0) caseOpen--; else break; }
        else if (v === 'if') ifOpen++;
        else if (v === 'then') { if (ifOpen > 0) { ifOpen--; thenOpen++; } else break; }
        else if (v === 'else') { if (thenOpen > 0) thenOpen--; else break; }
      }
    }
    return { a, b: j, items: splitItems(a, j, indent), indent };
  }
  function withIndent(ind, fn) {
    const s = layoutIndent;
    layoutIndent = ind;
    try { return fn(); } finally { layoutIndent = s; }
  }

  // ── patterns ────────────────────────────────────────────────────────────
  function apatAt(i, b) {
    tick();
    const t = T[i];
    if (!t || i >= b) return null;
    if (t.t === 'op' && t.v === '!' ) return apatAt(i + 1, b);
    if (t.t === 'rop' && t.v === '~') return apatAt(i + 1, b);
    if (t.t === 'var' && !t.q) {
      if (isRop(T[i + 1], '@') && T[i + 1].off === t.end) {
        const r = apatAt(i + 2, b);
        if (r) return [{ t: 'pas', name: t.v, p: r[0] }, r[1]];
      }
      return [t.v === '_' ? { t: 'pwild' } : { t: 'pvar', name: t.v }, i + 1];
    }
    if (t.t === 'con') {
      if (isSp(T[i + 1], '{') && mate[i + 1] > i + 1 && T[i + 1].off === t.end) {
        const close = mate[i + 1];
        const fields = [];
        for (const [s, e] of splitTop(i + 2, close, comma)) {
          if (s >= e) continue;
          if (isRop(T[s], '..')) { fields.push({ name: '..', wildcard: true }); continue; }
          const f = T[s];
          if (f.t !== 'var') continue;
          if (e - s >= 3 && isRop(T[s + 1], '=')) fields.push({ name: f.v, pat: patRange(s + 2, e) });
          else fields.push({ name: f.v, pat: { t: 'pvar', name: f.v }, pun: true });
        }
        return [{ t: 'pcon', con: t.v, qual: t.q || null, args: [], fields }, close + 1];
      }
      return [{ t: 'pcon', con: t.v, qual: t.q || null, args: [], fields: [] }, i + 1];
    }
    if (t.t === 'int' || t.t === 'float' || t.t === 'str' || t.t === 'chr') return [{ t: 'plit', v: t.v }, i + 1];
    if (isSp(t, '(') && mate[i] > i) {
      const close = mate[i];
      const parts = splitTop(i + 1, close, comma);
      if (i + 1 === close) return [{ t: 'pcon', con: '()', args: [], fields: [] }, close + 1];
      if (parts.length > 1) return [{ t: 'ptuple', items: parts.map(([s, e]) => patRange(s, e)) }, close + 1];
      let [s, e] = parts[0];
      const arrow = findTop(s, e, (x) => isRop(x, '->'));
      if (arrow >= 0) s = arrow + 1;
      return [patRange(s, e), close + 1];
    }
    if (isSp(t, '[') && mate[i] > i) {
      const close = mate[i];
      const items = i + 1 === close ? [] : splitTop(i + 1, close, comma).map(([s, e]) => patRange(s, e));
      return [{ t: 'plist', items }, close + 1];
    }
    return null;
  }
  function patRange(a, b) {
    const k = findTop(a, b, (x) => x.t === 'op' && x.cons);
    if (k > a) return { t: 'pcon', con: T[k].v, qual: T[k].q || null, args: [patRange(a, k), patRange(k + 1, b)], fields: [] };
    const r = apatAt(a, b);
    if (!r) return { t: 'pwild', unknown: true };
    const p = r[0];
    let j = r[1];
    if (p.t === 'pcon' && !p.args.length && !p.fields.length) {
      while (j < b) {
        const q = apatAt(j, b);
        if (!q) break;
        p.args.push(q[0]);
        j = q[1];
      }
    }
    return p;
  }
  function patVars(p, out = []) {
    if (!p) return out;
    if (p.t === 'pvar') out.push(p.name);
    else if (p.t === 'pas') { out.push(p.name); patVars(p.p, out); }
    else if (p.t === 'pcon') { for (const a of p.args) patVars(a, out); for (const f of p.fields) if (f.pat) patVars(f.pat, out); }
    else if (p.t === 'ptuple' || p.t === 'plist') for (const a of p.items) patVars(a, out);
    return out;
  }

  // ── expressions ─────────────────────────────────────────────────────────
  function peekOp() {
    const t = peek();
    if (!t) return null;
    if (t.t === 'op') return { name: t.v, qual: t.q || null, end: pos + 1, line: t.line };
    if (isSp(t, '`') && T[pos + 1] && (T[pos + 1].t === 'var' || T[pos + 1].t === 'con') && isSp(T[pos + 2], '`') && pos + 2 < lim) {
      const x = T[pos + 1];
      return { name: x.v, qual: x.q || null, end: pos + 3, line: t.line, backtick: true };
    }
    return null;
  }
  function fixityOf(op) {
    if (op.backtick) return BT_FIX[op.name] || [9, 'l'];
    return FIX[op.name] || (op.name[0] === ':' ? [5, 'r'] : [9, 'l']);
  }
  function skipType() {
    pos++;
    while (pos < lim) {
      const t = T[pos];
      if (isSp(t, ',') || isSp(t, ';') || (t.t === 'kw' && ['then', 'else', 'of', 'in', 'where'].includes(t.v)) || (t.t === 'rop' && (t.v === '|' || t.v === '=' || t.v === '<-'))) break;
      pos = Math.min(lim, groupEnd(pos));
    }
  }
  function expr0() {
    if (++depth > maxDepth) { depth--; throw new SyntaxBudgetError('maxDepth'); }
    try {
      let e = expr(0);
      while (isRop(peek(), '::')) skipType();
      return e;
    } finally { depth--; }
  }
  function expr(minPrec) {
    tick();
    let left = operand();
    for (;;) {
      const op = peekOp();
      if (!op) break;
      const [prec, assoc] = fixityOf(op);
      if (prec < minPrec) break;
      pos = op.end;
      const right = expr(assoc === 'r' ? prec : prec + 1);
      left = { t: 'op', op: op.name, qual: op.qual, l: left, r: right, line: op.line };
    }
    return left;
  }
  function operand() {
    const t = peek();
    if (t && t.t === 'op' && t.v === '-') {
      pos++;
      return { t: 'neg', e: expr(7), line: t.line };
    }
    return exp10();
  }
  function exp10() {
    const t = peek();
    if (!t) { errors.push({ kind: 'expected-expression', line: 0, detail: 'empty expression' }); return { t: 'unknown' }; }
    if (isRop(t, '\\')) {
      pos++;
      if (isKw(peek(), 'case')) {
        const blk = blockAfter(pos, lim, layoutIndent);
        pos = blk.b;
        return { t: 'lamcase', alts: withIndent(blk.indent, () => blk.items.map(([a, b]) => parseAlt(a, b))), line: t.line };
      }
      const params = [];
      while (pos < lim && !isRop(T[pos], '->')) {
        const r = apatAt(pos, lim);
        if (!r) { err('malformed-lambda', T[pos], 'bad lambda pattern'); pos = lim; return { t: 'unknown' }; }
        params.push(r[0]);
        pos = r[1];
      }
      pos++;
      return { t: 'lam', params, body: expr0(), line: t.line };
    }
    if (t.t === 'kw') {
      if (t.v === 'let') {
        const blk = blockAfter(pos, lim, layoutIndent);
        const decls = withIndent(blk.indent, () => parseDeclItems(blk.items));
        pos = blk.b;
        if (isKw(peek(), 'in')) { pos++; return { t: 'let', decls, body: expr0(), line: t.line }; }
        err('let-without-in', t, 'let expression has no `in`');
        return { t: 'unknown' };
      }
      if (t.v === 'if') {
        pos++;
        if (isRop(peek(), '|')) {
          const guards = [];
          while (isRop(peek(), '|')) {
            pos++;
            const arrow = findTop(pos, lim, (x) => isRop(x, '->'));
            if (arrow < 0) break;
            const quals = splitTop(pos, arrow, comma).map(([s, e]) => parseQual(s, e));
            pos = arrow + 1;
            guards.push({ quals, body: expr(0) });
          }
          return { t: 'multiif', guards, line: t.line };
        }
        const c = expr0();
        if (isSp(peek(), ';')) pos++;
        if (!isKw(peek(), 'then')) { err('if-without-then', t, 'if has no then'); return { t: 'unknown' }; }
        pos++;
        const a = expr0();
        if (isSp(peek(), ';')) pos++;
        if (!isKw(peek(), 'else')) { err('if-without-else', t, 'if has no else'); return { t: 'if', c, a, b: { t: 'unknown' }, line: t.line }; }
        pos++;
        return { t: 'if', c, a, b: expr0(), line: t.line };
      }
      if (t.v === 'case') {
        pos++;
        const scrut = expr0();
        if (!isKw(peek(), 'of')) { err('case-without-of', t, 'case has no of'); return { t: 'unknown' }; }
        const blk = blockAfter(pos, lim, layoutIndent);
        pos = blk.b;
        return { t: 'case', scrut, alts: withIndent(blk.indent, () => blk.items.map(([a, b]) => parseAlt(a, b))), line: t.line };
      }
      if (t.v === 'do') {
        const blk = blockAfter(pos, lim, layoutIndent);
        pos = blk.b;
        return { t: 'do', stmts: withIndent(blk.indent, () => blk.items.map(([a, b]) => parseStmt(a, b)).filter(Boolean)), line: t.line, endLine: blk.b > 0 && T[blk.b - 1] ? T[blk.b - 1].line : t.line };
      }
      return { t: 'unknown', line: t.line };
    }
    return fexp();
  }
  function startsAexp() {
    const t = peek();
    if (!t) return false;
    if (t.t === 'var' || t.t === 'con' || t.t === 'int' || t.t === 'float' || t.t === 'str' || t.t === 'chr') return true;
    return isSp(t, '(') || isSp(t, '[');
  }
  function fexp() {
    const first = peek();
    const f = aexp();
    const args = [];
    for (;;) {
      if (isRop(peek(), '@') && T[pos + 1] && peek().end === T[pos + 1].off) { pos += 2; continue; }
      if (!startsAexp()) break;
      args.push(aexp());
    }
    // BlockArguments: a trailing `do` / lambda / case is a final argument.
    const t = peek();
    if (t && ((t.t === 'kw' && (t.v === 'do' || t.v === 'case')) || isRop(t, '\\')) && (args.length || f.t === 'var')) args.push(exp10());
    return args.length ? { t: 'app', f, args, line: first ? first.line : 0 } : f;
  }
  function aexp() {
    const t = peek();
    if (!t) return { t: 'unknown' };
    let e;
    if (t.t === 'var') { pos++; e = { t: 'var', name: t.v, qual: t.q || null, line: t.line }; }
    else if (t.t === 'con') { pos++; e = { t: 'con', name: t.v, qual: t.q || null, line: t.line }; }
    else if (t.t === 'int' || t.t === 'float' || t.t === 'str' || t.t === 'chr') { pos++; e = { t: 'lit', kind: t.t, v: t.v, line: t.line }; }
    else if (isSp(t, '(') && mate[pos] > pos && mate[pos] < lim) { const close = mate[pos]; e = parenExpr(pos, close); pos = close + 1; }
    else if (isSp(t, '[') && mate[pos] > pos && mate[pos] < lim) { const close = mate[pos]; e = listExpr(pos, close); pos = close + 1; }
    else { err('unexpected-token', t, `unexpected token ${t.v}`); pos++; return { t: 'unknown', line: t.line }; }
    while (isSp(peek(), '{') && mate[pos] > pos && mate[pos] < lim && (e.t === 'con' || e.t === 'var' || e.t === 'rec' || e.t === 'paren')) {
      const close = mate[pos];
      const fields = [];
      for (const [s, en] of splitTop(pos + 1, close, comma)) {
        if (s >= en) continue;
        if (isRop(T[s], '..')) { fields.push({ name: '..', wildcard: true }); continue; }
        const f = T[s];
        if (f.t !== 'var') continue;
        if (en - s >= 3 && isRop(T[s + 1], '=')) fields.push({ name: f.v, e: sub(s + 2, en, expr0) });
        else fields.push({ name: f.v, e: { t: 'var', name: f.v, qual: null, line: f.line }, pun: true });
      }
      e = e.t === 'con' ? { t: 'rec', con: e, fields, line: t.line } : { t: 'recupd', base: e, fields, line: t.line };
      pos = close + 1;
    }
    return e;
  }
  const isOpTok = (x) => x && x.t === 'op';
  function parenExpr(open, close) {
    const a = open + 1;
    const line = T[open].line;
    if (a === close) return { t: 'con', name: '()', qual: null, line };
    const parts = splitTop(a, close, comma);
    if (parts.length > 1) {
      if (parts.every(([s, e]) => s >= e)) return { t: 'con', name: `(${','.repeat(parts.length - 1)})`, qual: null, line };
      return { t: 'tuple', items: parts.map(([s, e]) => (s >= e ? { t: 'unknown' } : sub(s, e, expr0))), line };
    }
    const [s, e] = parts[0];
    const first = T[s];
    if (isOpTok(first) && e - s === 1) return { t: 'var', name: first.v, qual: first.q || null, op: true, line };
    if (isOpTok(first) && first.v !== '-') return { t: 'rsec', op: first.v, qual: first.q || null, e: sub(s + 1, e, expr0), line };
    if (isSp(first, '`') && T[s + 2] && isSp(T[s + 2], '`') && e - s > 3) return { t: 'rsec', op: T[s + 1].v, qual: T[s + 1].q || null, e: sub(s + 3, e, expr0), line, backtick: true };
    const last = T[e - 1];
    if (isOpTok(last) && e - s > 1) return { t: 'lsec', op: last.v, qual: last.q || null, e: sub(s, e - 1, expr0), line };
    if (isSp(last, '`') && e - s > 3 && isSp(T[e - 3], '`')) return { t: 'lsec', op: T[e - 2].v, qual: T[e - 2].q || null, e: sub(s, e - 3, expr0), line, backtick: true };
    return { t: 'paren', e: sub(s, e, expr0), line };
  }
  function listExpr(open, close) {
    const a = open + 1;
    const line = T[open].line;
    if (a === close) return { t: 'list', items: [], line };
    const bar = findTop(a, close, (x) => isRop(x, '|'));
    if (bar > a) {
      const head = sub(a, bar, expr0);
      const quals = splitTop(bar + 1, close, comma).map(([s, e]) => parseQual(s, e));
      return { t: 'listcomp', head, quals, line };
    }
    if (findTop(a, close, (x) => isRop(x, '..')) >= 0) {
      const items = [];
      for (const [s, e] of splitTop(a, close, (x) => isRop(x, '..') || isSp(x, ','))) if (s < e) items.push(sub(s, e, expr0));
      return { t: 'range', items, line };
    }
    return { t: 'list', items: splitTop(a, close, comma).map(([s, e]) => (s >= e ? { t: 'unknown' } : sub(s, e, expr0))), line };
  }

  // ── guards, alternatives, statements, declarations ──────────────────────
  function parseQual(a, b) {
    if (isKw(T[a], 'let')) {
      const blk = blockAfter(a, b, layoutIndent);
      return { t: 'qlet', decls: withIndent(blk.indent, () => parseDeclItems(blk.items)) };
    }
    const k = findTop(a, b, (x) => isRop(x, '<-'));
    if (k > a) return { t: 'qbind', pat: patRange(a, k), e: sub(k + 1, b, expr0) };
    return { t: 'qbool', e: sub(a, b, expr0) };
  }
  // Parses the right-hand side starting at the `=`/`->`/`|` token index `from`.
  function parseRhs(from, b, eq) {
    return sub(from, b, () => {
      let guards = null;
      let body = null;
      if (isRop(peek(), '|')) {
        guards = [];
        while (isRop(peek(), '|')) {
          pos++;
          const k = findTop(pos, lim, (x) => isRop(x, eq));
          if (k < 0) { err('guard-without-body', T[pos - 1], 'guard has no body'); pos = lim; break; }
          const quals = splitTop(pos, k, comma).map(([s, e]) => parseQual(s, e));
          pos = k + 1;
          guards.push({ quals, body: expr0() });
        }
      } else if (isRop(peek(), eq)) { pos++; body = expr0(); }
      let where = [];
      if (isKw(peek(), 'where')) {
        const blk = blockAfter(pos, lim, layoutIndent);
        where = withIndent(blk.indent, () => parseDeclItems(blk.items));
        pos = blk.b;
      }
      return { guards, body, where };
    });
  }
  function parseAlt(a, b) {
    const k = findTop(a, b, (x) => isRop(x, '->') || isRop(x, '|'));
    if (k < 0) { err('expected-arrow', T[a], 'case alternative has no `->`'); return { pat: { t: 'pwild' }, rhs: { guards: null, body: { t: 'unknown' }, where: [] }, line: T[a].line, bad: true }; }
    return { pat: patRange(a, k), rhs: parseRhs(k, b, '->'), line: T[a].line, a, b };
  }
  function parseStmt(a, b) {
    if (a >= b) return null;
    if (isKw(T[a], 'let')) {
      const blk = blockAfter(a, b, layoutIndent);
      if (blk.b < b && isKw(T[blk.b], 'in')) return { t: 'sexpr', e: sub(a, b, expr0), line: T[a].line };
      return { t: 'slet', decls: withIndent(blk.indent, () => parseDeclItems(blk.items)), line: T[a].line };
    }
    let k = -1;
    for (let p = a; p < b;) {
      tick();
      const t = T[p];
      if (t.t === 'kw' && ['let', 'do', 'of', 'where', 'if', 'case'].includes(t.v)) break;
      if (isRop(t, '<-')) { k = p; break; }
      if (isRop(t, '\\') || isRop(t, '->')) break;
      p = groupEnd(p);
    }
    if (k > a) return { t: 'sbind', pat: patRange(a, k), e: sub(k + 1, b, expr0), line: T[a].line };
    return { t: 'sexpr', e: sub(a, b, expr0), line: T[a].line };
  }
  function parseDeclItems(items) {
    const out = [];
    for (const [a, b] of items) {
      try {
        const d = parseDecl(a, b);
        if (d) out.push(d);
      } catch (e) {
        if (e instanceof SyntaxBudgetError) throw e;
        err('parser-exception', T[a], String(e && e.message));
      }
    }
    return out;
  }
  function parseDecl(a, b) {
    const mark = findTop(a, b, (x) => x.t === 'rop' && (x.v === '=' || x.v === '|' || x.v === '::'));
    if (mark < 0) { err('expected-declaration', T[a], 'item is neither a binding nor a signature'); return null; }
    if (T[mark].v === '::') {
      const names = [];
      for (let q = a; q < mark; q++) {
        if (T[q].t === 'var') names.push(T[q].v);
        else if (isSp(T[q], '(') && T[q + 1] && T[q + 1].t === 'op') names.push(T[q + 1].v);
      }
      return { t: 'sig', names, ta: mark + 1, tb: b, line: T[a].line };
    }
    let name = null;
    let pats = [];
    let patbind = null;
    const prefixMark = (q) => T[q].t === 'op' && T[q].v === '!' && T[q + 1] && T[q].end === T[q + 1].off && (q === a || T[q - 1].end < T[q].off);
    let infixAt = -1;
    let infixEnd = -1;
    for (let q = a; q < mark; q = groupEnd(q)) {
      if (q > a && T[q].t === 'op' && T[q].cons) { infixAt = -2; break; }
      if (q > a && T[q].t === 'op' && !prefixMark(q)) { infixAt = q; infixEnd = q + 1; break; }
      if (isSp(T[q], '`') && T[q + 1] && T[q + 1].t === 'var' && isSp(T[q + 2], '`')) { infixAt = q + 1; infixEnd = q + 3; break; }
    }
    if (infixAt === -2) patbind = patRange(a, mark);
    else if (infixAt >= 0) {
      name = T[infixAt].v;
      pats = [patRange(a, infixAt === infixEnd - 1 ? infixAt : infixAt), patRange(infixEnd, mark)];
      if (isSp(T[infixAt - 1], '`')) pats[0] = patRange(a, infixAt - 1);
    } else if (T[a].t === 'var' && !T[a].q) {
      name = T[a].v;
      for (let q = a + 1; q < mark;) {
        const r = apatAt(q, mark);
        if (!r) { err('bad-clause-pattern', T[q], 'unparseable argument pattern'); break; }
        pats.push(r[0]);
        q = r[1];
      }
    } else if (isSp(T[a], '(') && mate[a] === a + 2 && T[a + 1] && T[a + 1].t === 'op') {
      name = T[a + 1].v;
      for (let q = a + 3; q < mark;) {
        const r = apatAt(q, mark);
        if (!r) break;
        pats.push(r[0]);
        q = r[1];
      }
    } else patbind = patRange(a, mark);
    const rhs = parseRhs(mark, b, '=');
    const clause = { pats, rhs, line: T[a].line, endLine: T[b - 1].line, ta: a, tb: b };
    return patbind ? { t: 'patbind', pat: patbind, rhs, line: T[a].line, ta: a, tb: b } : { t: 'clause', name, clause, line: T[a].line };
  }
  function parseData(a, b) {
    const isNewtype = T[a].v === 'newtype';
    let eq = findTop(a, b, (x) => isRop(x, '='));
    let nameTok = null;
    for (let q = a + 1; q < (eq < 0 ? b : eq); q++) if (T[q].t === 'con') { nameTok = T[q]; break; }
    const decl = { t: 'data', newtype: isNewtype, name: nameTok ? nameTok.v : null, constructors: [], line: T[a].line };
    if (eq < 0) return decl;
    let end = findTop(eq + 1, b, (x) => isKw(x, 'deriving'));
    if (end < 0) end = b;
    for (const [s0, e] of splitTop(eq + 1, end, (x) => isRop(x, '|'))) {
      let s = s0;
      const ctx = findTop(s, e, (x) => isRop(x, '=>'));
      if (ctx >= 0) s = ctx + 1;
      while (s < e && (T[s].t === 'op' || (T[s].t === 'var' && T[s].v === 'forall'))) s++;
      if (s >= e) continue;
      let k = s;
      let conTok = null;
      if (T[k].t === 'con') conTok = T[k];
      else if (isSp(T[k], '(') && T[k + 1] && T[k + 1].t === 'op') { conTok = T[k + 1]; k += 2; }
      else {
        const infix = findTop(s, e, (x) => x.t === 'op' && x.cons);
        if (infix > s) { decl.constructors.push({ name: T[infix].v, fields: null, arity: 2 }); }
        continue;
      }
      let fields = null;
      let arity = 0;
      if (isSp(T[k + 1], '{') && mate[k + 1] > k + 1) {
        fields = [];
        const close = mate[k + 1];
        let i = k + 2;
        while (i < close) {
          const names = [];
          while (i < close && T[i].t === 'var') { names.push(T[i].v); i++; if (isSp(T[i], ',')) i++; else break; }
          if (isRop(T[i], '::')) {
            i++;
            while (i < close && !isSp(T[i], ',')) i = Math.min(close, groupEnd(i));
            i++;
          } else break;
          for (const nme of names) fields.push(nme);
        }
        arity = fields.length;
      } else {
        for (let j = k + 1; j < e;) {
          if (T[j].t === 'op' && T[j].v === '!') { j++; continue; }
          if (T[j].t === 'var' || T[j].t === 'con' || isSp(T[j], '(') || isSp(T[j], '[')) { arity++; j = Math.min(e, groupEnd(j)); continue; }
          j++;
        }
      }
      decl.constructors.push({ name: conTok.v, fields, arity });
    }
    return decl;
  }
  function parseImport(a, b) {
    let j = a + 1;
    const rec = { module: null, qualified: false, as: null, hiding: false, items: null, typeAll: [], line: T[a].line };
    while (j < b) {
      const t = T[j];
      if (t.t === 'var' && (t.v === 'qualified' || t.v === 'safe')) { if (t.v === 'qualified') rec.qualified = true; j++; }
      else if (t.t === 'str' && !rec.module) j++;
      else break;
    }
    if (j < b && T[j].t === 'con') { rec.module = (T[j].q ? `${T[j].q}.` : '') + T[j].v; j++; }
    else { err('malformed-import', T[a], 'import has no module name'); return null; }
    while (j < b) {
      const t = T[j];
      if (t.t === 'var' && t.v === 'qualified') { rec.qualified = true; j++; }
      else if (t.t === 'var' && t.v === 'as' && T[j + 1] && T[j + 1].t === 'con') { rec.as = (T[j + 1].q ? `${T[j + 1].q}.` : '') + T[j + 1].v; j += 2; }
      else if (t.t === 'var' && t.v === 'hiding') { rec.hiding = true; j++; }
      else if (isSp(t, '(') && mate[j] > j) {
        rec.items = [];
        rec.typeAll = [];   // types/classes imported with (..): they bring their fields and methods
        for (let q = j + 1; q < mate[j]; q++) if (T[q].t === 'var' || T[q].t === 'con' || T[q].t === 'op') rec.items.push(T[q].v);
        for (const [s0, e0] of splitTop(j + 1, mate[j], comma)) {
          if (e0 - s0 >= 2 && T[s0].t === 'con' && isSp(T[s0 + 1], '(') && mate[s0 + 1] > s0 + 1 && T[s0 + 2] && isRop(T[s0 + 2], '..')) rec.typeAll.push(T[s0].v);
        }
        j = mate[j] + 1;
      } else j++;
    }
    return rec;
  }
  function parseExports(a, close) {
    const out = [];
    for (const [s, e] of splitTop(a, close, comma)) {
      if (s >= e) continue;
      const t = T[s];
      if (isKw(t, 'module') && T[s + 1] && T[s + 1].t === 'con') out.push({ kind: 'module', name: (T[s + 1].q ? `${T[s + 1].q}.` : '') + T[s + 1].v });
      else if (t.t === 'var') out.push({ kind: 'var', name: t.v, qual: t.q || null });
      else if (t.t === 'con') out.push({ kind: 'type', name: t.v, all: e - s > 1 });
      else if (isSp(t, '(') && T[s + 1] && T[s + 1].t === 'op') out.push({ kind: 'var', name: T[s + 1].v, qual: null });
    }
    return out;
  }

  // ── module ──────────────────────────────────────────────────────────────
  const res = { tokens: T, module: null, imports: [], decls: [], sigs: [], data: [], classes: [], instances: [], typeDecls: [], errors, boundaries: [] };
  let bodyStart = 0;
  if (N && isKw(T[0], 'module')) {
    let j = 1;
    for (; j < N;) {
      if (isKw(T[j], 'where')) break;
      j = groupEnd(j);
    }
    const nameTok = T[1] && T[1].t === 'con' ? T[1] : null;
    let exportsList = null;
    if (isSp(T[2], '(') && mate[2] > 2) exportsList = parseExports(3, mate[2]);
    res.module = { name: nameTok ? (nameTok.q ? `${nameTok.q}.` : '') + nameTok.v : null, exports: exportsList, line: 1 };
    bodyStart = j < N ? j + 1 : N;
  }
  const topExplicit = bodyStart < N && isSp(T[bodyStart], '{') && mate[bodyStart] > bodyStart;
  const topIndent = bodyStart < N ? T[bodyStart].col : 0;
  const topItems = topExplicit ? splitItems(bodyStart + 1, mate[bodyStart], null) : (bodyStart < N ? splitItems(bodyStart, N, topIndent) : []);
  lim = N;
  layoutIndent = topExplicit ? -1 : topIndent;
  const topDecls = [];
  for (const [a, b] of topItems) {
    try {
      const t0 = T[a];
      if (t0.t === 'kw') {
        if (t0.v === 'import') { const r = parseImport(a, b); if (r) res.imports.push(r); continue; }
        if (t0.v === 'data' || t0.v === 'newtype') { res.data.push(parseData(a, b)); continue; }
        if (t0.v === 'type') {
          // `type API = ...` is not executable, but Servant describes a whole web API in one: keep its token range.
          if (T[a + 1] && T[a + 1].t === 'con') res.typeDecls.push({ name: T[a + 1].v, line: t0.line, a, b });
          continue;
        }
        if (t0.v === 'infix' || t0.v === 'infixl' || t0.v === 'infixr' || t0.v === 'default' || t0.v === 'deriving') continue;
        if (t0.v === 'foreign') {
          // `foreign import ccall unsafe "string.h strlen" c_strlen :: ...` names the Haskell-side function.
          let fname = null;
          for (let q = a; q < b; q++) if (isRop(T[q], '::')) { if (q > a && T[q - 1].t === 'var') fname = T[q - 1].v; break; }
          res.boundaries.push({ kind: 'ffi', line: t0.line, detail: 'foreign declaration; the foreign code is not analyzed', ...(fname ? { name: fname } : {}) });
          continue;
        }
        if (t0.v === 'class' || t0.v === 'instance') {
          const w = findTop(a, b, (x) => isKw(x, 'where'));
          const headEnd = w < 0 ? b : w;
          const ctx = findTop(a, headEnd, (x) => isRop(x, '=>'));
          let nameTok = null;
          for (let q = (ctx >= 0 ? ctx + 1 : a + 1); q < headEnd; q++) if (T[q].t === 'con') { nameTok = T[q]; break; }
          let decls = [];
          if (w >= 0) {
            const blk = blockAfter(w, b, topIndent);
            decls = withIndent(blk.indent, () => parseDeclItems(blk.items));
          }
          const entry = { name: nameTok ? nameTok.v : null, qual: nameTok && nameTok.q ? nameTok.q : null, decls, line: t0.line, headText: T.slice(a + 1, headEnd).map((x) => x.v).join(' ') };
          if (t0.v === 'class') res.classes.push(entry); else res.instances.push(entry);
          continue;
        }
        err('unsupported-declaration', t0, `unsupported declaration keyword ${t0.v}`);
        continue;
      }
      const d = parseDecl(a, b);
      if (d) topDecls.push(d);
    } catch (e) {
      if (e instanceof SyntaxBudgetError) throw e;
      err('parser-exception', T[a], String(e && e.message));
    }
  }
  res.decls = topDecls;
  return res;
}

/** Group parsed clause declarations by name, preserving order. */
export function groupDecls(decls) {
  const funs = [];
  const byName = new Map();
  const patbinds = [];
  const sigs = new Map();
  for (const d of decls) {
    if (d.t === 'sig') { for (const n of d.names) sigs.set(n, d); }
    else if (d.t === 'patbind') patbinds.push(d);
    else if (d.t === 'clause') {
      let f = byName.get(d.name);
      if (!f) { f = { name: d.name, clauses: [], line: d.line }; byName.set(d.name, f); funs.push(f); }
      f.clauses.push(d.clause);
    }
  }
  return { funs, patbinds, sigs };
}

export function patternVars(p) {
  const out = [];
  const walk = (x) => {
    if (!x) return;
    if (x.t === 'pvar') out.push(x.name);
    else if (x.t === 'pas') { out.push(x.name); walk(x.p); }
    else if (x.t === 'pcon') { for (const a of x.args) walk(a); for (const f of x.fields) if (f.pat) walk(f.pat); }
    else if (x.t === 'ptuple' || x.t === 'plist') for (const a of x.items) walk(a);
  };
  walk(p);
  return out;
}
