// Nix parser with original source locations (NIX-001).
//
// Static, dependency-free and bounded. It lexes and parses the Nix expression
// language (let/in, with, assert, if, lambdas and formals, attribute sets and
// paths, selects with `or` defaults, `?`, `//`, `++`, strings, indented strings
// and interpolation, paths, search paths and URIs) over the shipped, SHA-256
// pinned grammar tables in nix-grammar.js. It never runs `nix`, never evaluates
// anything, and never reads a file other than the source it was given.
//
// Locations. Every node carries a span {startLine, startColumn, endLine,
// endColumn, startByte, endByte, startOffset, endOffset}: lines are 1-based,
// columns are 0-based UTF-16 code units, bytes are UTF-8 offsets and end
// positions are exclusive. Spans always index the ORIGINAL file, including for
// the text parts of indented strings whose leading indentation was stripped.
//
// Literal text versus interpolation. A string or path is a list of parts, each
// `{kind:'text', value, span}` (escapes resolved, indentation stripped) or
// `{kind:'interp', expr, span}`. `literal` is the full text when there is no
// interpolation, else null. Comment and string content is never tokens, so a
// suspicious option name inside either cannot become an assignment.
//
// Recovery. A syntax error inside an attribute set or let binding is recorded,
// that one binding is withheld, and parsing resumes at the next `;` at the same
// nesting. An error elsewhere returns status `failed` with the error. Budgets
// (bytes, tokens, parse depth, AST depth, nodes, string size, wall clock) are
// bounded; a bound hit returns `budget_exceeded` with the budget named and no
// partial analysis, and never throws into the caller.

import { loadNixGrammar } from './nix-grammar.js';

export const DEFAULT_PARSE_BUDGETS = Object.freeze({
  maxBytes: 4 * 1024 * 1024,
  maxTokens: 400_000,
  maxDepth: 600,
  maxAstDepth: 1500,
  maxNodes: 500_000,
  maxStringBytes: 1024 * 1024,
  deadlineMs: 8000,
  maxErrors: 100,
});

class BudgetError extends Error {
  constructor(budget, limit) {
    super(`parser budget "${budget}" exceeded (limit ${limit})`);
    this.budget = budget;
    this.limit = limit;
  }
}

class ParseError extends Error {
  constructor(detail, pos, end) {
    super(detail);
    this.detail = detail;
    this.pos = pos;
    this.end = end === undefined ? pos + 1 : end;
  }
}

// ── locations ──────────────────────────────────────────────────────────────

export function makeLocator(source) {
  const n = source.length;
  const starts = [0];
  for (let i = source.indexOf('\n'); i !== -1; i = source.indexOf('\n', i + 1)) starts.push(i + 1);
  let bytes = null;
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(source)) {
    bytes = new Uint32Array(n + 1);
    let acc = 0;
    for (let i = 0; i < n; i++) {
      bytes[i] = acc;
      const x = source.charCodeAt(i);
      if (x < 0x80) acc += 1;
      else if (x < 0x800) acc += 2;
      else if (x >= 0xd800 && x <= 0xdbff) acc += 4;
      else if (x >= 0xdc00 && x <= 0xdfff) acc += 0;
      else acc += 3;
    }
    bytes[n] = acc;
  }
  const lineOf = (off) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
  const byte = (off) => (bytes ? bytes[Math.min(off, n)] : off);
  const span = (s, e) => {
    const end = Math.max(s, e);
    const sl = lineOf(s);
    const el = lineOf(end);
    return {
      startLine: sl, startColumn: s - starts[sl - 1],
      endLine: el, endColumn: end - starts[el - 1],
      startByte: byte(s), endByte: byte(end),
      startOffset: s, endOffset: end,
    };
  };
  return { span };
}

/** Text of a span, read back from the ORIGINAL source by byte range (test and tooling helper). */
export function spanText(source, span) {
  return Buffer.from(source, 'utf8').subarray(span.startByte, span.endByte).toString('utf8');
}

const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === '﻿';
const isDigit = (c) => c >= '0' && c <= '9';
const PATH_CHAR = /[A-Za-z0-9._+/~-]/;
const CLOSE = { '(': ')', '[': ']', '{': '}' };

function sticky(src) {
  return new RegExp(src.replace(/^\^/, ''), 'y');
}

// ── parser ─────────────────────────────────────────────────────────────────

class NixParser {
  constructor(source, grammar, budgets) {
    this.src = source;
    this.n = source.length;
    this.g = grammar;
    this.b = budgets;
    this.loc = makeLocator(source);
    this.pos = 0;
    this.tok = null;
    this.depth = 0;
    this.tokens = 0;
    this.nodes = 0;
    this.errors = [];
    this.started = Date.now();
    this.reNumber = sticky(grammar.number);
    this.rePath = sticky(grammar.pathStart);
    this.reSearch = sticky(grammar.searchPath);
    this.reUri = sticky(grammar.uri);
    this.reIdent = sticky(grammar.identifier);
    this.keywords = new Set(grammar.keywords);
    this.binops = grammar.binaryOps;
    this.puncts = [...grammar.punctuation].sort((a, b) => b.length - a.length);
  }

  // nodes
  mk(type, s, e, props, kids) {
    if (++this.nodes > this.b.maxNodes) throw new BudgetError('maxNodes', this.b.maxNodes);
    let d = 1;
    if (kids) for (const k of kids) if (k && k.d >= d) d = k.d + 1;
    if (d > this.b.maxAstDepth) throw new BudgetError('maxAstDepth', this.b.maxAstDepth);
    return { type, start: s, end: e, span: this.loc.span(s, e), d, ...props };
  }

  err(detail, pos, end) {
    return new ParseError(detail, pos, end);
  }

  // lexing
  skipTrivia() {
    const { src, n } = this;
    let i = this.pos;
    for (;;) {
      while (i < n && isSpace(src[i])) i++;
      if (src[i] === '#') {
        while (i < n && src[i] !== '\n') i++;
      } else if (src[i] === '/' && src[i + 1] === '*') {
        const close = src.indexOf('*/', i + 2);
        if (close === -1) throw this.err('unterminated block comment', i, n);
        i = close + 2;
      } else break;
    }
    return i;
  }

  lex() {
    const { src, n } = this;
    const s = this.skipTrivia();
    if (s >= n) return { t: 'eof', v: '', s: n, e: n };
    const c = src[s];
    if (c === '"') return { t: '"', v: '"', s, e: s + 1 };
    if (c === "'" && src[s + 1] === "'") return { t: "''", v: "''", s, e: s + 2 };
    if (c === '$' && src[s + 1] === '{') return { t: '${', v: '${', s, e: s + 2 };
    if (c !== '-' && c !== '+' && (/[A-Za-z0-9._~/]/.test(c))) {
      this.rePath.lastIndex = s;
      if (this.rePath.test(src)) return { t: 'path', v: '', s, e: s };
    }
    if (isDigit(c) || (c === '.' && isDigit(src[s + 1] || ''))) {
      this.reNumber.lastIndex = s;
      const m = this.reNumber.exec(src);
      if (m) return { t: /[.eE]/.test(m[0]) ? 'float' : 'int', v: m[0], s, e: s + m[0].length };
    }
    if (c === '<') {
      this.reSearch.lastIndex = s;
      const m = this.reSearch.exec(src);
      if (m) return { t: 'spath', v: m[0].slice(1, -1), s, e: s + m[0].length };
    }
    if (/[A-Za-z_]/.test(c)) {
      this.reUri.lastIndex = s;
      const u = this.reUri.exec(src);
      if (u) return { t: 'uri', v: u[0], s, e: s + u[0].length };
      this.reIdent.lastIndex = s;
      const m = this.reIdent.exec(src);
      if (m) return { t: this.keywords.has(m[0]) ? 'kw' : 'id', v: m[0], s, e: s + m[0].length };
    }
    for (const p of this.puncts) if (src.startsWith(p, s)) return { t: p, v: p, s, e: s + p.length };
    throw this.err(`unexpected character ${JSON.stringify(c)}`, s);
  }

  peek() {
    if (!this.tok) this.tok = this.lex();
    return this.tok;
  }

  next() {
    const t = this.peek();
    if (++this.tokens > this.b.maxTokens) throw new BudgetError('maxTokens', this.b.maxTokens);
    if ((this.tokens & 255) === 0 && Date.now() - this.started > this.b.deadlineMs) throw new BudgetError('deadlineMs', this.b.deadlineMs);
    this.pos = t.e;
    this.tok = null;
    return t;
  }

  /** Lexes `k` tokens ahead without consuming. Bounded and non-recursive. */
  ahead(k) {
    const sp = this.pos;
    const st = this.tok;
    const out = [];
    try {
      for (let i = 0; i < k; i++) {
        const t = this.peek();
        out.push(t);
        if (t.t === 'eof' || t.t === '"' || t.t === "''" || t.t === 'path') break;
        this.pos = t.e;
        this.tok = null;
      }
    } catch {
      // a lex error ahead is reported when the token is actually consumed
    } finally {
      this.pos = sp;
      this.tok = st;
    }
    return out;
  }

  expect(t, why) {
    const tk = this.peek();
    if (tk.t !== t) throw this.err(`expected ${why || `"${t}"`} but found ${tk.t === 'eof' ? 'end of file' : `"${tk.v || tk.t}"`}`, tk.s, Math.max(tk.e, tk.s + 1));
    return this.next();
  }

  enter() {
    if (++this.depth > this.b.maxDepth) throw new BudgetError('maxDepth', this.b.maxDepth);
  }

  leave() { this.depth--; }

  // ── expressions ──

  parseExpr() {
    this.enter();
    try { return this.parseExprInner(); } finally { this.leave(); }
  }

  parseExprInner() {
    const t = this.peek();
    if (t.t === 'kw') {
      if (t.v === 'let') {
        const nx = this.ahead(2)[1];
        if (!(nx && nx.t === '{')) return this.parseLet();
      } else if (t.v === 'if') return this.parseIf();
      else if (t.v === 'with') return this.parseWith();
      else if (t.v === 'assert') return this.parseAssert();
    } else if (t.t === 'id') {
      const la = this.ahead(2)[1];
      if (la && (la.t === ':' || la.t === '@')) return this.parseLambda();
    } else if (t.t === '{' && this.looksLikePattern()) return this.parseLambda();
    return this.parseOp(0);
  }

  looksLikePattern() {
    const la = this.ahead(4);
    const a = la[1];
    const b = la[2];
    const c = la[3];
    if (!a) return false;
    if (a.t === '...') return true;
    if (a.t === '}') return !!b && (b.t === ':' || b.t === '@');
    if (a.t === 'id') {
      if (!b) return false;
      if (b.t === ',' || b.t === '?') return true;
      if (b.t === '}') return !!c && (c.t === ':' || c.t === '@');
    }
    return false;
  }

  parseLet() {
    const kw = this.next();
    const bindings = this.parseBindings((t) => t.t === 'kw' && t.v === 'in');
    const inTok = this.peek();
    if (!(inTok.t === 'kw' && inTok.v === 'in')) throw this.err('expected "in" to close let', inTok.s, Math.max(inTok.e, inTok.s + 1));
    this.next();
    const body = this.parseExpr();
    return this.mk('let', kw.s, body.end, { bindings, body }, [body, ...bindings.map((x) => x.value)]);
  }

  parseIf() {
    const kw = this.next();
    const cond = this.parseExpr();
    this.expectKw('then');
    const thenE = this.parseExpr();
    this.expectKw('else');
    const elseE = this.parseExpr();
    return this.mk('if', kw.s, elseE.end, { cond, then: thenE, else: elseE }, [cond, thenE, elseE]);
  }

  parseWith() {
    const kw = this.next();
    const env = this.parseExpr();
    this.expect(';');
    const body = this.parseExpr();
    return this.mk('with', kw.s, body.end, { env, body }, [env, body]);
  }

  parseAssert() {
    const kw = this.next();
    const cond = this.parseExpr();
    this.expect(';');
    const body = this.parseExpr();
    return this.mk('assert', kw.s, body.end, { cond, body }, [cond, body]);
  }

  expectKw(v) {
    const t = this.peek();
    if (!(t.t === 'kw' && t.v === v)) throw this.err(`expected "${v}"`, t.s, Math.max(t.e, t.s + 1));
    return this.next();
  }

  parseLambda() {
    const start = this.peek().s;
    const param = { kind: 'ident', name: null, formals: [], ellipsis: false, atName: null, span: null };
    const t = this.peek();
    if (t.t === 'id') {
      const id = this.next();
      if (this.peek().t === '@') {
        this.next();
        this.parsePattern(param);
        param.kind = 'pattern';
        param.atName = id.v;
      } else {
        param.name = id.v;
        param.span = this.loc.span(id.s, id.e);
      }
    } else {
      this.parsePattern(param);
      param.kind = 'pattern';
      if (this.peek().t === '@') {
        this.next();
        const id = this.expect('id', 'an identifier');
        param.atName = id.v;
      }
    }
    const endParam = this.pos;
    if (!param.span) param.span = this.loc.span(start, endParam);
    this.expect(':');
    const body = this.parseExpr();
    return this.mk('lambda', start, body.end, { param, body }, [body, ...param.formals.map((f) => f.default)]);
  }

  parsePattern(param) {
    this.expect('{');
    for (;;) {
      const t = this.peek();
      if (t.t === '}') { this.next(); break; }
      if (t.t === '...') { this.next(); param.ellipsis = true; if (this.peek().t === ',') this.next(); continue; }
      const id = this.expect('id', 'a parameter name');
      let def = null;
      if (this.peek().t === '?') { this.next(); def = this.parseExpr(); }
      param.formals.push({ name: id.v, default: def, span: this.loc.span(id.s, def ? def.end : id.e) });
      const sep = this.peek();
      if (sep.t === ',') this.next();
      else if (sep.t !== '}' ) throw this.err('expected "," or "}" in function parameters', sep.s, Math.max(sep.e, sep.s + 1));
    }
  }

  parseOp(minPrec) {
    this.enter();
    try {
      let left = this.parseUnary();
      for (;;) {
        const t = this.peek();
        if (t.t === '?' && this.g.precedence.hasAttr >= minPrec) {
          this.next();
          const attrpath = this.parseAttrPath();
          left = this.mk('hasattr', left.start, attrpath[attrpath.length - 1].span.endOffset, { base: left, attrpath }, [left, ...this.segKids(attrpath)]);
          continue;
        }
        const op = this.binops[t.t];
        if (!op || op.prec < minPrec) break;
        this.next();
        const right = this.parseOp(op.assoc === 'right' ? op.prec : op.prec + 1);
        left = this.mk('binop', left.start, right.end, { op: t.t, left, right }, [left, right]);
      }
      return left;
    } finally { this.leave(); }
  }

  parseUnary() {
    const t = this.peek();
    if (t.t === '-' || t.t === '!') {
      this.next();
      const operand = this.parseOp(t.t === '-' ? this.g.precedence.negate : this.g.precedence.not);
      return this.mk('unop', t.s, operand.end, { op: t.t, operand }, [operand]);
    }
    if (t.t === 'kw' && (t.v === 'let' || t.v === 'if' || t.v === 'with' || t.v === 'assert')) {
      const nx = t.v === 'let' ? this.ahead(2)[1] : null;
      if (!(nx && nx.t === '{')) return this.parseExprInner();
    }
    return this.parseApp();
  }

  startsArg(t) {
    switch (t.t) {
      case 'id': return t.v !== 'or';
      case 'int': case 'float': case 'path': case 'spath': case 'uri': case '"': case "''": case '(': case '[': case '{':
        return true;
      case 'kw': return t.v === 'rec';
      default: return false;
    }
  }

  parseApp() {
    let fn = this.parseSelect();
    for (;;) {
      const t = this.peek();
      if (!this.startsArg(t)) break;
      const arg = this.parseSelect();
      fn = this.mk('app', fn.start, arg.end, { fn, arg }, [fn, arg]);
    }
    return fn;
  }

  parseSelect() {
    let base = this.parseAtom();
    while (this.peek().t === '.') {
      this.next();
      const attrpath = this.parseAttrPath();
      let def = null;
      let end = attrpath[attrpath.length - 1].span.endOffset;
      const o = this.peek();
      if (o.t === 'id' && o.v === 'or') {
        this.next();
        def = this.parseSelect();
        end = def.end;
      }
      base = this.mk('select', base.start, end, { base, attrpath, default: def }, [base, def, ...this.segKids(attrpath)]);
    }
    return base;
  }

  segKids(attrpath) {
    const out = [];
    for (const sg of attrpath) {
      if (sg.expr) out.push(sg.expr);
      if (sg.parts) for (const p of sg.parts) if (p.kind === 'interp') out.push(p.expr);
    }
    return out;
  }

  /** attrpath: id | "string" | ${expr}, joined by `.` */
  parseAttrPath() {
    const segs = [];
    for (;;) {
      const t = this.peek();
      let seg;
      if (t.t === 'id') {
        this.next();
        seg = { kind: 'static', name: t.v, span: this.loc.span(t.s, t.e), quoted: false };
      } else if (t.t === '"') {
        this.next();
        const str = this.parseStringBody(t.s, false);
        seg = str.interpolated
          ? { kind: 'dynamic', name: null, expr: null, parts: str.parts, span: str.span, quoted: true }
          : { kind: 'static', name: str.literal, span: str.span, quoted: true };
      } else if (t.t === '${') {
        this.next();
        const expr = this.parseExpr();
        const close = this.expect('}');
        seg = { kind: 'dynamic', name: null, expr, parts: null, span: this.loc.span(t.s, close.e), quoted: false };
      } else {
        throw this.err('expected an attribute name', t.s, Math.max(t.e, t.s + 1));
      }
      segs.push(seg);
      if (this.peek().t !== '.') break;
      this.next();
    }
    return segs;
  }

  // Atoms recurse without passing through parseExpr (`[[[[...`), so they count toward the depth budget too.
  parseAtom() {
    this.enter();
    try { return this.parseAtomInner(); } finally { this.leave(); }
  }

  parseAtomInner() {
    const t = this.peek();
    switch (t.t) {
      case 'id': this.next(); return this.mk('ident', t.s, t.e, { name: t.v });
      case 'int': this.next(); return this.mk('int', t.s, t.e, { value: Number(t.v), raw: t.v });
      case 'float': this.next(); return this.mk('float', t.s, t.e, { value: Number(t.v), raw: t.v });
      case 'spath': this.next(); return this.mk('spath', t.s, t.e, { value: t.v });
      case 'uri': this.next(); return this.mk('uri', t.s, t.e, { value: t.v });
      case '"': this.next(); return this.parseStringBody(t.s, false);
      case "''": this.next(); return this.parseStringBody(t.s, true);
      case 'path': return this.parsePath(t.s);
      case '(': {
        this.next();
        const expr = this.parseExpr();
        const close = this.expect(')');
        return this.mk('paren', t.s, close.e, { expr }, [expr]);
      }
      case '[': {
        this.next();
        const items = [];
        for (;;) {
          const k = this.peek();
          if (k.t === ']') { this.next(); break; }
          if (k.t === 'eof') throw this.err('unterminated list', t.s, t.s + 1);
          items.push(this.parseSelect());
        }
        return this.mk('list', t.s, this.pos, { items }, items);
      }
      case '{': return this.parseAttrSet(false, t.s);
      case 'kw':
        if (t.v === 'rec') {
          this.next();
          const o = this.peek();
          if (o.t !== '{') throw this.err('expected "{" after rec', o.s, Math.max(o.e, o.s + 1));
          return this.parseAttrSet(true, t.s);
        }
        throw this.err(`unexpected keyword "${t.v}"`, t.s, t.e);
      case 'eof': throw this.err('unexpected end of file', t.s, t.s);
      default: throw this.err(`unexpected "${t.v || t.t}"`, t.s, Math.max(t.e, t.s + 1));
    }
  }

  parseAttrSet(rec, start) {
    this.expect('{');
    const bindings = this.parseBindings((t) => t.t === '}');
    const close = this.expect('}', '"}" to close the attribute set');
    return this.mk('attrset', start, close.e, { rec, bindings, errors: bindings.errorCount || 0 }, bindings.map((b) => b.value));
  }

  // ── bindings ──

  parseBindings(isCloser) {
    const out = [];
    out.errorCount = 0;
    for (;;) {
      const t = this.peek();
      if (isCloser(t) || t.t === 'eof') break;
      const saveDepth = this.depth;
      try {
        out.push(this.parseBinding());
      } catch (e) {
        if (!(e instanceof ParseError)) throw e;
        this.depth = saveDepth;
        this.recordError(e);
        out.errorCount++;
        this.resync(t.s, isCloser);
      }
    }
    return out;
  }

  recordError(e) {
    if (this.errors.length >= this.b.maxErrors) throw new BudgetError('maxErrors', this.b.maxErrors);
    this.errors.push({ kind: 'syntax-error', detail: e.detail, span: this.loc.span(e.pos, Math.min(Math.max(e.end, e.pos), this.n)) });
  }

  parseBinding() {
    const t = this.peek();
    if (t.t === 'kw' && t.v === 'inherit') {
      this.next();
      let from = null;
      if (this.peek().t === '(') {
        this.next();
        from = this.parseExpr();
        this.expect(')');
      }
      const names = [];
      for (;;) {
        const k = this.peek();
        if (k.t === ';') break;
        if (k.t === 'id' || (k.t === 'kw' && k.v === 'or')) {
          this.next();
          names.push({ kind: 'static', name: k.v, span: this.loc.span(k.s, k.e), quoted: false });
        } else if (k.t === '"') {
          this.next();
          const str = this.parseStringBody(k.s, false);
          names.push(str.interpolated
            ? { kind: 'dynamic', name: null, expr: null, parts: str.parts, span: str.span, quoted: true }
            : { kind: 'static', name: str.literal, span: str.span, quoted: true });
        } else if (k.t === '${') {
          this.next();
          const expr = this.parseExpr();
          const close = this.expect('}');
          names.push({ kind: 'dynamic', name: null, expr, parts: null, span: this.loc.span(k.s, close.e), quoted: false });
        } else throw this.err('expected an attribute name in inherit', k.s, Math.max(k.e, k.s + 1));
      }
      const semi = this.expect(';');
      return { kind: 'inherit', from, names, value: from, span: this.loc.span(t.s, semi.e) };
    }
    const path = this.parseAttrPath();
    this.expect('=');
    const value = this.parseExpr();
    const semi = this.expect(';', '";" after the binding value');
    return { kind: 'attr', path, value, span: this.loc.span(t.s, semi.e) };
  }

  /** Skips to the `;` that ends the failed binding, or stops before the closing token. */
  resync(from, isCloser) {
    this.pos = from;
    this.tok = null;
    const stack = [];
    let pending = 0;
    const wanted = { ')': ['('], ']': ['['], '}': ['{', '${'] };
    for (;;) {
      let t;
      try { t = this.peek(); } catch { this.pos = Math.min(this.pos + 1, this.n); this.tok = null; if (this.pos >= this.n) return; continue; }
      if (t.t === 'eof') return;
      if (t.t === '"') { this.pos = this.skipPlainString(t.e); this.tok = null; continue; }
      if (t.t === "''") { this.pos = this.skipIndentedString(t.e); this.tok = null; continue; }
      if (t.t === 'path') { this.pos = this.skipPathChars(t.s); this.tok = null; continue; }
      const isIn = t.t === 'kw' && t.v === 'in';
      if (t.t === '(' || t.t === '[' || t.t === '{' || t.t === '${' || (t.t === 'kw' && t.v === 'let')) {
        stack.push(t.t === 'kw' ? 'let' : t.t);
      } else if (t.t === ')' || t.t === ']' || t.t === '}' || isIn) {
        const want = isIn ? ['let'] : wanted[t.t];
        let idx = -1;
        for (let k = stack.length - 1; k >= 0; k--) if (want.includes(stack[k])) { idx = k; break; }
        if (idx >= 0) stack.length = idx;
        else if (isCloser(t)) return;
      } else if (t.t === 'kw' && (t.v === 'with' || t.v === 'assert')) pending++;
      else if (t.t === ';') {
        if (pending > 0) pending--;
        else if (!stack.length) { this.pos = t.e; this.tok = null; return; }
      }
      this.pos = t.e;
      this.tok = null;
    }
  }

  skipPathChars(s) {
    let i = s;
    while (i < this.n && PATH_CHAR.test(this.src[i])) i++;
    return Math.max(i, s + 1);
  }

  skipPlainString(i) {
    while (i < this.n) {
      const c = this.src[i];
      if (c === '\\') i += 2;
      else if (c === '"') return i + 1;
      else i++;
    }
    return this.n;
  }

  skipIndentedString(i) {
    while (i < this.n) {
      const c = this.src[i];
      if (c === "'" && this.src[i + 1] === "'") {
        const d = this.src[i + 2];
        if (d === "'" || d === '$') i += 3;
        else if (d === '\\') i += 4;
        else return i + 2;
      } else i++;
    }
    return this.n;
  }

  // ── strings and paths ──

  /** Parses `${ expr }` whose `${` starts at `i`. Returns the part and the offset after `}`. */
  parseInterp(i) {
    this.pos = i + 2;
    this.tok = null;
    const expr = this.parseExpr();
    const close = this.peek();
    if (close.t !== '}') throw this.err('expected "}" to close interpolation', close.s, Math.max(close.e, close.s + 1));
    this.next();
    return { part: { kind: 'interp', expr, span: this.loc.span(i, close.e) }, next: close.e };
  }

  parseStringBody(openStart, indented) {
    const { src, n } = this;
    const limit = this.b.maxStringBytes;
    // The caller consumed the opening delimiter; scanning is done on raw characters from here.
    let i = openStart + (indented ? 2 : 1);
    const parts = [];
    let size = 0;
    if (!indented) {
      let buf = '';
      let bufStart = i;
      const flush = (end) => {
        if (buf.length || end > bufStart) parts.push({ kind: 'text', value: buf, span: this.loc.span(bufStart, end) });
        buf = '';
      };
      for (;;) {
        if (i >= n) throw this.err('unterminated string', openStart, n);
        const c = src[i];
        if (c === '"') { flush(i); i++; break; }
        if (c === '\\') {
          if (i + 1 >= n) throw this.err('unterminated string', openStart, n);
          const e = src[i + 1];
          buf += Object.prototype.hasOwnProperty.call(this.g.stringEscapes, e) ? this.g.stringEscapes[e] : e;
          i += 2;
        } else if (c === '$' && src[i + 1] === '{') {
          if (buf.length || i > bufStart) flush(i);
          const r = this.parseInterp(i);
          parts.push(r.part);
          i = r.next;
          bufStart = i;
        } else { buf += c; i++; }
        if (++size > limit) throw new BudgetError('maxStringBytes', limit);
      }
    } else {
      let j = i;
      while (src[j] === ' ') j++;
      if (src[j] === '\n') i = j + 1;
      // units: text units carry resolved text and source offsets, interps are parts
      const items = [];
      for (;;) {
        if (i >= n) throw this.err('unterminated indented string', openStart, n);
        const c = src[i];
        if (c === "'" && src[i + 1] === "'") {
          const d = src[i + 2];
          if (d === "'") { items.push({ c: "''", o: i, l: 3 }); i += 3; }
          else if (d === '$') { items.push({ c: '$', o: i, l: 3 }); i += 3; }
          else if (d === '\\') {
            const e = src[i + 3];
            if (e === undefined) throw this.err('unterminated indented string', openStart, n);
            items.push({ c: Object.prototype.hasOwnProperty.call(this.g.indentedEscapes, e) ? this.g.indentedEscapes[e] : e, o: i, l: 4 });
            i += 4;
          } else { i += 2; break; }
        } else if (c === '$' && src[i + 1] === '{') {
          const r = this.parseInterp(i);
          items.push({ part: r.part });
          i = r.next;
        } else { items.push({ c, o: i, l: 1 }); i++; }
        if (items.length > limit) throw new BudgetError('maxStringBytes', limit);
      }
      this.dedent(items, parts);
    }
    this.pos = i;
    this.tok = null;
    const interpolated = parts.some((p) => p.kind === 'interp');
    const literal = interpolated ? null : parts.map((p) => p.value).join('');
    const kids = parts.filter((p) => p.kind === 'interp').map((p) => p.expr);
    return this.mk('string', openStart, i, { indented, parts, literal, interpolated }, kids);
  }

  /** Strips common indentation the way the language defines it (spaces only; blank lines do not count). */
  dedent(items, parts) {
    let min = Infinity;
    let atStart = true;
    let cur = 0;
    for (const it of items) {
      if (it.part) { if (atStart) { atStart = false; if (cur < min) min = cur; } continue; }
      if (it.c === ' ') { if (atStart) cur++; } else if (it.c === '\n') { atStart = true; cur = 0; } else if (atStart) { atStart = false; if (cur < min) min = cur; }
    }
    if (min === Infinity) min = 0;
    const kept = [];
    atStart = true;
    cur = 0;
    for (const it of items) {
      if (it.part) { atStart = false; kept.push(it); continue; }
      if (atStart && it.c === ' ' && cur < min) { cur++; continue; }
      if (it.c === '\n') { atStart = true; cur = 0; } else atStart = false;
      kept.push(it);
    }
    // a final line made only of spaces is dropped
    let k = kept.length;
    while (k > 0 && !kept[k - 1].part && kept[k - 1].c === ' ') k--;
    if (k === 0 || (!kept[k - 1].part && kept[k - 1].c === '\n')) kept.length = k;
    let buf = '';
    let first = -1;
    let last = -1;
    const flush = () => {
      if (first >= 0) parts.push({ kind: 'text', value: buf, span: this.loc.span(first, last) });
      buf = '';
      first = -1;
    };
    for (const it of kept) {
      if (it.part) { flush(); parts.push(it.part); continue; }
      if (first < 0) first = it.o;
      last = it.o + it.l;
      buf += it.c;
    }
    flush();
  }

  parsePath(start) {
    const { src, n } = this;
    const parts = [];
    let i = start;
    let buf = '';
    let bufStart = i;
    const flush = (end) => {
      if (end > bufStart) parts.push({ kind: 'text', value: buf, span: this.loc.span(bufStart, end) });
      buf = '';
    };
    for (;;) {
      if (i >= n) break;
      const c = src[i];
      if (c === '$' && src[i + 1] === '{') {
        flush(i);
        const r = this.parseInterp(i);
        parts.push(r.part);
        i = r.next;
        bufStart = i;
      } else if (PATH_CHAR.test(c)) { buf += c; i++; } else break;
      if (i - start > this.b.maxStringBytes) throw new BudgetError('maxStringBytes', this.b.maxStringBytes);
    }
    flush(i);
    this.pos = i;
    this.tok = null;
    const interpolated = parts.some((p) => p.kind === 'interp');
    const literal = interpolated ? null : parts.map((p) => p.value).join('');
    const first = parts[0] && parts[0].kind === 'text' ? parts[0].value : '';
    const pathKind = first.startsWith('/') ? 'absolute' : first.startsWith('~') ? 'home' : 'relative';
    return this.mk('path', start, i, { parts, literal, interpolated, pathKind }, parts.filter((p) => p.kind === 'interp').map((p) => p.expr));
  }
}

/** Direct expression children of a node, in source order. */
export function childrenOf(node) {
  const out = [];
  const add = (x) => { if (x) out.push(x); };
  const segs = (list) => {
    for (const sg of list) {
      add(sg.expr);
      if (sg.parts) for (const p of sg.parts) if (p.kind === 'interp') add(p.expr);
    }
  };
  switch (node.type) {
    case 'app': add(node.fn); add(node.arg); break;
    case 'binop': add(node.left); add(node.right); break;
    case 'unop': add(node.operand); break;
    case 'paren': add(node.expr); break;
    case 'list': for (const x of node.items) add(x); break;
    case 'if': add(node.cond); add(node.then); add(node.else); break;
    case 'with': add(node.env); add(node.body); break;
    case 'assert': add(node.cond); add(node.body); break;
    case 'lambda': for (const f of node.param.formals) add(f.default); add(node.body); break;
    case 'select': add(node.base); segs(node.attrpath); add(node.default); break;
    case 'hasattr': add(node.base); segs(node.attrpath); break;
    case 'string': case 'path': for (const p of node.parts) if (p.kind === 'interp') add(p.expr); break;
    case 'let': case 'attrset':
      for (const b of node.bindings) {
        if (b.kind === 'attr') { segs(b.path); add(b.value); } else { add(b.from); segs(b.names); }
      }
      if (node.type === 'let') add(node.body);
      break;
    default: break;
  }
  return out;
}

/**
 * Parses Nix source. Never throws.
 * @param {string} source
 * @param {{file?:string, budgets?:object, grammarSource?:Function}} [opts]
 * @returns {{status:'ok'|'partial'|'failed'|'budget_exceeded'|'missing_grammar', ast:object|null, errors:object[], budget?:{name:string,limit:number}, gap?:object, file:string|null, grammar:object|null, usedNixBinary:false, stats:object}}
 */
export function parseNix(source, opts = {}) {
  const file = opts.file || null;
  const budgets = { ...DEFAULT_PARSE_BUDGETS, ...(opts.budgets || {}) };
  const base = { file, ast: null, errors: [], grammar: null, usedNixBinary: false, stats: { bytes: 0, tokens: 0, nodes: 0 } };
  const loaded = loadNixGrammar({ grammarSource: opts.grammarSource });
  if (!loaded.available) return { ...base, status: 'missing_grammar', gap: loaded.gap };
  base.grammar = { name: loaded.grammar.name, version: loaded.grammar.version, sha256: loaded.checksum };
  if (typeof source !== 'string') return { ...base, status: 'failed', errors: [{ kind: 'malformed-input', detail: 'source is not a string', span: null }] };
  const text = source;
  const bytes = Buffer.byteLength(text, 'utf8');
  base.stats.bytes = bytes;
  if (bytes > budgets.maxBytes) return { ...base, status: 'budget_exceeded', budget: { name: 'maxBytes', limit: budgets.maxBytes } };
  if (text.includes('\u0000')) return { ...base, status: 'failed', errors: [{ kind: 'malformed-input', detail: 'source contains NUL bytes (binary data)', span: null }] };
  const p = new NixParser(text, loaded.grammar, budgets);
  try {
    const ast = p.parseExpr();
    const tail = p.peek();
    if (tail.t !== 'eof') throw new ParseError(`unexpected "${tail.v || tail.t}" after the expression`, tail.s, Math.max(tail.e, tail.s + 1));
    base.stats.tokens = p.tokens;
    base.stats.nodes = p.nodes;
    return { ...base, status: p.errors.length ? 'partial' : 'ok', ast, errors: p.errors };
  } catch (e) {
    base.stats.tokens = p.tokens;
    base.stats.nodes = p.nodes;
    if (e instanceof BudgetError) return { ...base, status: 'budget_exceeded', budget: { name: e.budget, limit: e.limit }, errors: [] };
    if (e instanceof ParseError) {
      const errors = [...p.errors, { kind: 'syntax-error', detail: e.detail, span: p.loc.span(Math.min(e.pos, text.length), Math.min(Math.max(e.end, e.pos), text.length)) }];
      return { ...base, status: 'failed', errors };
    }
    return { ...base, status: 'failed', errors: [{ kind: 'internal-error', detail: String((e && e.message) || e), span: null }] };
  }
}
