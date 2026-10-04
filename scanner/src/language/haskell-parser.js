// Haskell parser with original source locations (HS-001).
//
// Static, dependency-free and bounded. It lexes Haskell (nested comments,
// pragmas, strings with gaps, qualified names, literate Bird and LaTeX styles),
// resolves the layout rule, and extracts imports, declarations, calls,
// expressions, records and do blocks. It never executes anything: no GHC, no
// Template Haskell splice, no preprocessor.
//
// Locations. Preprocessing (literate unwrapping, CPP and hsc directive removal)
// is done by overwriting characters with spaces of the same UTF-16 length, never
// by deleting them, so every token offset is an offset into the ORIGINAL file.
// A span is {startLine, startColumn, endLine, endColumn, startByte, endByte,
// startOffset, endOffset}: lines are 1-based, columns are 0-based UTF-16 code
// units, bytes are UTF-8 offsets into the original, and end positions are
// exclusive.
//
// What is never invented. Comment text, string text, quasi-quote bodies and
// preprocessor lines are not tokens, so nothing inside them can become a call.
// A top-level declaration that contains a syntax error contributes no calls; the
// error is recorded with the count of calls it withheld. Both branches of a CPP
// conditional are parsed and their calls flagged `conditional`.
//
// Budgets. Bytes, tokens, nesting depth, comment nesting, steps and wall clock
// are bounded; a bound hit returns status `budget_exceeded` with the budget
// named and no partial analysis, and never throws into the caller.

import { loadHaskellGrammar } from './haskell-grammar.js';

export const DEFAULT_PARSE_BUDGETS = Object.freeze({
  maxBytes: 4 * 1024 * 1024,
  maxTokens: 400_000,
  maxDepth: 200,
  maxCommentNesting: 200,
  maxSteps: 8_000_000,
  deadlineMs: 8000,
  maxErrors: 200,
});

class BudgetError extends Error {
  constructor(budget, limit) {
    super(`parser budget "${budget}" exceeded (limit ${limit})`);
    this.budget = budget;
    this.limit = limit;
  }
}

// ── character classes ──────────────────────────────────────────────────────

const SYM = new Set('!#$%&*+./<=>?@\\^|-~:'.split(''));
const ID_START_U = /[\p{L}_]/u;
const ID_CHAR_U = /[\p{L}\p{N}_']/u;
const UPPER_U = /\p{Lu}/u;

function isIdStart(c) {
  if (c === undefined) return false;
  const x = c.charCodeAt(0);
  if (x < 128) return (x >= 65 && x <= 90) || (x >= 97 && x <= 122) || x === 95;
  return ID_START_U.test(c);
}
function isIdChar(c) {
  if (c === undefined) return false;
  const x = c.charCodeAt(0);
  if (x < 128) return (x >= 65 && x <= 90) || (x >= 97 && x <= 122) || x === 95 || (x >= 48 && x <= 57) || x === 39;
  return ID_CHAR_U.test(c);
}
function isUpper(c) {
  const x = c.charCodeAt(0);
  return x < 128 ? x >= 65 && x <= 90 : UPPER_U.test(c);
}
const isSym = (c) => c !== undefined && SYM.has(c);
const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === '\u00a0' || c === '\ufeff';

const OPENERS = { '(': ')', '[': ']', '{': '}' };
const CLOSERS = new Set([')', ']', '}']);
const ATOM_END = new Set(['varid', 'qvarid', 'conid', 'qconid', 'int', 'float', 'char', 'string', 'wild', 'quasiquote', 'thname', ')', ']', '}']);
const ATOM_START = new Set(['varid', 'qvarid', 'conid', 'qconid', 'int', 'float', 'char', 'string', 'wild', 'quasiquote', 'thname']);

// ── locations ──────────────────────────────────────────────────────────────

function makeLocator(source) {
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
    const sl = lineOf(s);
    const el = lineOf(Math.max(s, e));
    return {
      startLine: sl, startColumn: s - starts[sl - 1],
      endLine: el, endColumn: Math.max(s, e) - starts[el - 1],
      startByte: byte(s), endByte: byte(Math.max(s, e)),
      startOffset: s, endOffset: Math.max(s, e),
    };
  };
  return { starts, lineOf, byte, span, lineCount: starts.length };
}

/** Text of a span, read back from the ORIGINAL source by byte range (test and tooling helper). */
export function spanText(source, span) {
  return Buffer.from(source, 'utf8').subarray(span.startByte, span.endByte).toString('utf8');
}

// ── preprocessing (length-preserving) ──────────────────────────────────────

const blank = (s) => s.replace(/[^\r\n]/g, ' ');

function dialectOf(file) {
  const f = String(file || '').toLowerCase();
  if (/\.lhs(-boot)?$/.test(f)) return 'literate';
  if (/\.hsc$/.test(f)) return 'hsc';
  return 'haskell';
}

function unwrapLiterate(source) {
  const latex = /^[ \t]*\\begin\{code\}/m.test(source);
  let out = '';
  let inCode = false;
  let pos = 0;
  while (pos <= source.length) {
    let nl = source.indexOf('\n', pos);
    if (nl === -1) nl = source.length;
    const line = source.slice(pos, nl);
    if (latex) {
      if (/^[ \t]*\\begin\{code\}/.test(line)) { inCode = true; out += blank(line); }
      else if (/^[ \t]*\\end\{code\}/.test(line)) { inCode = false; out += blank(line); }
      else out += inCode ? line : blank(line);
    } else if (line.startsWith('>')) out += ' ' + line.slice(1);
    else out += blank(line);
    if (nl < source.length) out += '\n';
    pos = nl + 1;
  }
  return { code: out, style: latex ? 'latex' : 'bird' };
}

function stripDirectives(code, dialect, grammar, loc) {
  const cppNames = new Set(grammar.cppDirectives);
  const lines = code.split('\n');
  const directives = [];
  const depthAtLine = new Int32Array(lines.length + 2);
  let depth = 0;
  let off = 0;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    const m = /^#\s*([A-Za-z]+)/.exec(line);
    const shebang = i === 0 && line.startsWith('#!');
    const hscLine = dialect === 'hsc' && /^#/.test(line);
    if (shebang || hscLine || (m && cppNames.has(m[1]))) {
      const name = shebang ? 'shebang' : (m ? m[1] : 'hsc');
      directives.push({ name, line: i + 1, span: loc.span(off, off + line.length) });
      if (name === 'if' || name === 'ifdef' || name === 'ifndef') depth++;
      else if (name === 'endif' && depth > 0) depth--;
      depthAtLine[i + 1] = depth;
      let cur = blank(line);
      // A directive continued with a trailing backslash swallows the next line too.
      let k = i;
      while (/\\\r?$/.test(lines[k]) && k + 1 < lines.length) {
        k++;
        cur += '\n' + blank(lines[k]);
        depthAtLine[k + 1] = depth;
      }
      if (k > i) {
        off += lines[i].length + 1;
        for (let q = i + 1; q <= k; q++) off += lines[q].length + 1;
        lines.splice(i, k - i + 1, ...cur.split('\n'));
        i = k;
        continue;
      }
      lines[i] = cur;
      line = cur;
    } else {
      depthAtLine[i + 1] = depth;
      if (dialect === 'hsc') lines[i] = line.replace(/#\{[^}\n]*\}/g, (s) => ' '.repeat(s.length));
    }
    off += line.length + 1;
  }
  return { code: lines.join('\n'), directives, depthAtLine };
}

// ── lexer ──────────────────────────────────────────────────────────────────

function lexAll(code, loc, ctx, flags) {
  const g = ctx.grammar;
  const keywords = new Set(g.keywords);
  const reserved = new Set(g.reservedOps);
  const n = code.length;
  const tokens = [];
  const comments = [];
  const pragmas = [];
  const errors = [];
  const boundaries = [];
  const hasTabs = code.includes('\t');
  let i = 0;
  let prevEndLine = 0;
  let sawCode = false;
  const NUM = /0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?/y;
  const QQ = /\[([A-Za-z_][\w'.]*)?(\|\|?)/y;
  const CHAR_ESC = /'\\.[^'\n]{0,8}'/y;

  const push = (k, v, s, e, extra) => {
    if (tokens.length >= ctx.budgets.maxTokens) throw new BudgetError('maxTokens', ctx.budgets.maxTokens);
    const line = loc.lineOf(s);
    const el = e > s ? loc.lineOf(e - 1) : line;
    let col = s - loc.starts[line - 1];
    let lcol = col;
    if (hasTabs) {
      lcol = 0;
      for (let q = loc.starts[line - 1]; q < s; q++) lcol = code[q] === '\t' ? (Math.floor(lcol / 8) + 1) * 8 : lcol + 1;
    }
    const t = { k, v, s, e, line, el, col, lcol, fol: prevEndLine < line };
    if (extra) Object.assign(t, extra);
    prevEndLine = el;
    sawCode = true;
    tokens.push(t);
    return t;
  };
  const err = (kind, s, e, detail) => {
    if (errors.length < ctx.budgets.maxErrors) errors.push({ kind, offset: s, endOffset: e, detail });
  };

  while (i < n) {
    ctx.tick();
    const c = code[i];
    if (isSpace(c)) { i++; continue; }

    if (c === '{' && code[i + 1] === '-') {
      const isPragma = code[i + 2] === '#';
      let depth = 1;
      let j = i + 2;
      while (j < n) {
        if (code[j] === '{' && code[j + 1] === '-') {
          depth++;
          if (depth > ctx.budgets.maxCommentNesting) throw new BudgetError('maxCommentNesting', ctx.budgets.maxCommentNesting);
          j += 2;
        } else if (code[j] === '-' && code[j + 1] === '}') {
          depth--;
          j += 2;
          if (depth === 0) break;
        } else j++;
      }
      const closed = depth === 0;
      if (!closed) {
        err('unterminated-comment', i, i + 2, 'block comment is never closed; the rest of the file is comment text');
        j = n;
      }
      const sp = loc.span(i, j);
      if (isPragma && closed) {
        const text = code.slice(i, j);
        const m = /^\{-#\s*([A-Za-z_]+)/.exec(text);
        pragmas.push({ name: m ? m[1].toUpperCase() : '', span: sp, headerPosition: !sawCode, text: text.slice(3, -3).trim() });
      } else comments.push({ kind: isPragma ? 'pragma' : 'block', span: sp, terminated: closed, headerPosition: !sawCode });
      i = j;
      continue;
    }
    if (c === '-' && code[i + 1] === '-') {
      let j = i;
      while (code[j] === '-') j++;
      if (j >= n || !isSym(code[j])) {
        let e = code.indexOf('\n', j);
        if (e === -1) e = n;
        comments.push({ kind: 'line', span: loc.span(i, e), terminated: true, headerPosition: !sawCode });
        i = e;
        continue;
      }
    }

    if (c === '"') {
      let j = i + 1;
      let ok = false;
      while (true) {
        const ch = code[j];
        if (j >= n || ch === '\n') break;
        if (ch === '\\') {
          const nx = code[j + 1];
          if (nx !== undefined && isSpace(nx)) {
            j += 2;
            while (j < n && isSpace(code[j])) j++;
            if (code[j] === '\\') j++; else break;
          } else j += 2;
        } else if (ch === '"') { j++; ok = true; break; } else j++;
      }
      if (j > n) j = n;
      if (!ok) err('unterminated-string', i, Math.max(i + 1, j), 'string literal is not closed on its line');
      push('string', code.slice(i, j), i, j, ok ? null : { bad: true });
      i = j;
      continue;
    }

    if (c === "'") {
      CHAR_ESC.lastIndex = i;
      let m = code[i + 1] === '\\' ? CHAR_ESC.exec(code) : null;
      if (m) { push('char', m[0], i, i + m[0].length); i += m[0].length; continue; }
      const cp = code.codePointAt(i + 1);
      const w = cp !== undefined && cp > 0xffff ? 2 : 1;
      if (cp !== undefined && code[i + 1] !== "'" && code[i + 1] !== '\n' && code[i + 1 + w] === "'") {
        push('char', code.slice(i, i + w + 2), i, i + w + 2);
        i += w + 2;
        continue;
      }
      if (flags.th) {
        let j = i + 1;
        if (code[j] === "'") j++;
        if (isIdStart(code[j]) || code[j] === '(' || code[j] === '[') {
          if (isIdStart(code[j])) { while (isIdChar(code[j]) || (code[j] === '.' && isIdStart(code[j + 1]))) j++; }
          else j += 1;
          push('thname', code.slice(i, j), i, j);
          boundaries.push({ kind: 'th-name-quote', span: loc.span(i, j), detail: 'Template Haskell name quote; resolved at compile time' });
          i = j;
          continue;
        }
      }
      push('tick', "'", i, i + 1);
      i++;
      continue;
    }

    if (c === '[' && (flags.th || flags.qq)) {
      QQ.lastIndex = i;
      const m = QQ.exec(code);
      if (m && (m[1] ? true : flags.th)) {
        const close = m[2] === '||' ? '||]' : '|]';
        let e = code.indexOf(close, i + m[0].length);
        let ok = true;
        if (e === -1) { ok = false; e = n; err('unterminated-quasiquote', i, i + m[0].length, 'quasi-quotation is never closed'); } else e += close.length;
        push('quasiquote', null, i, e, { quoter: m[1] || (m[2] === '||' ? 'typed-quote' : 'quote') });
        boundaries.push({
          kind: m[1] && !['e', 'd', 't', 'p'].includes(m[1]) ? 'quasiquote' : 'th-quote',
          span: loc.span(i, e),
          detail: `${m[1] || 'quote'} body is opaque to the parser${ok ? '' : ' (unterminated)'}`,
          quoter: m[1] || null,
        });
        i = e;
        continue;
      }
    }

    if (isIdStart(c)) {
      const readWord = (p) => { let q = p; while (q < n && isIdChar(code[q])) q++; while (code[q] === '#') q++; return q; };
      let end = readWord(i);
      if (!isUpper(c)) {
        const word = code.slice(i, end);
        if (keywords.has(word)) push('kw', word, i, end);
        else if (word === '_') push('wild', word, i, end);
        else push('varid', word, i, end, { name: word });
        i = end;
        continue;
      }
      let lastSeg = i;
      let segs = 0;
      let cur = end;
      let done = null;
      while (code[cur] === '.') {
        const nx = code[cur + 1];
        if (isIdStart(nx)) {
          const e2 = readWord(cur + 1);
          if (isUpper(nx)) { lastSeg = cur + 1; segs++; cur = e2; continue; }
          done = { k: 'qvarid', qual: code.slice(i, cur), name: code.slice(cur + 1, e2), end: e2 };
          break;
        }
        if (isSym(nx)) {
          let e2 = cur + 1;
          while (isSym(code[e2])) e2++;
          const op = code.slice(cur + 1, e2);
          done = { k: op[0] === ':' ? 'qconsym' : 'qop', qual: code.slice(i, cur), name: op, end: e2 };
        }
        break;
      }
      if (done) { push(done.k, code.slice(i, done.end), i, done.end, { qual: done.qual, name: done.name }); i = done.end; continue; }
      if (segs > 0) push('qconid', code.slice(i, cur), i, cur, { qual: code.slice(i, lastSeg - 1), name: code.slice(lastSeg, cur) });
      else push('conid', code.slice(i, cur), i, cur, { name: code.slice(i, cur) });
      i = cur;
      continue;
    }

    if (c >= '0' && c <= '9') {
      NUM.lastIndex = i;
      const m = NUM.exec(code);
      const txt = m ? m[0] : c;
      const isF = /^[0-9]/.test(txt) && !/^0[xXoObB]/.test(txt) && /[.eE]/.test(txt);
      push(isF ? 'float' : 'int', txt, i, i + txt.length);
      i += txt.length;
      continue;
    }

    if (c === '(' || c === ')' || c === '[' || c === ']' || c === ',' || c === ';' || c === '`' || c === '{' || c === '}') {
      push(c, c, i, i + 1);
      i++;
      continue;
    }

    if (isSym(c)) {
      let j = i;
      while (isSym(code[j])) j++;
      const op = code.slice(i, j);
      if (flags.th && (op === '$' || op === '$$') && (code[j] === '(' || isIdStart(code[j])) && (i === 0 || !isIdChar(code[i - 1]))) {
        boundaries.push({ kind: 'th-splice', span: loc.span(i, j), detail: 'Template Haskell splice; its expansion is generated at compile time and is not evaluated' });
      }
      push(reserved.has(op) ? 'rop' : (op[0] === ':' ? 'consym' : 'op'), op, i, j);
      i = j;
      continue;
    }

    err('invalid-character', i, i + 1, `unexpected character U+${c.codePointAt(0).toString(16).padStart(4, '0')}`);
    i++;
  }
  return { tokens, comments, pragmas, errors, boundaries };
}

// ── driver ─────────────────────────────────────────────────────────────────

function emptyResult(file, dialect) {
  return {
    language: 'haskell', file, dialect, ok: false, status: 'failed', complete: false,
    module: null, imports: [], functions: [], signatures: [], declarations: [], calls: [], expressions: [],
    records: [], doBlocks: [], comments: [], pragmas: [], errors: [], boundaries: [], uncertainty: [], gaps: [],
    stats: { bytes: 0, tokens: 0, steps: 0 },
  };
}

export function parseHaskell(source, opts = {}) {
  const file = opts.file || '';
  const dialect = dialectOf(file);
  const res = emptyResult(file, dialect);
  const budgets = { ...DEFAULT_PARSE_BUDGETS, ...(opts.budgets || {}) };
  if (typeof source !== 'string') {
    res.errors.push({ kind: 'parser-exception', detail: 'source must be a string' });
    return res;
  }
  res.stats.bytes = Buffer.byteLength(source, 'utf8');
  const g = loadHaskellGrammar({ grammarSource: opts.grammarSource });
  if (!g.available) {
    res.status = 'missing_grammar';
    res.gaps.push({ ...g.gap, capability: 'parse' });
    return res;
  }
  if (opts.mode === 'ghc') {
    res.gaps.push({ kind: 'optional-mode-unavailable', capability: 'parse', mode: 'ghc', detail: 'GHC-assisted parsing is not available; the shipped grammar was used and GHC was not run' });
  }
  const started = Date.now();
  const ctx = {
    grammar: g.grammar, budgets, steps: 0,
    tick() {
      this.steps++;
      if (this.steps > budgets.maxSteps) throw new BudgetError('maxSteps', budgets.maxSteps);
      if ((this.steps & 2047) === 0 && Date.now() - started > budgets.deadlineMs) throw new BudgetError('deadlineMs', budgets.deadlineMs);
    },
  };
  try {
    if (res.stats.bytes > budgets.maxBytes) throw new BudgetError('maxBytes', budgets.maxBytes);
    analyze(source, file, dialect, ctx, res);
    res.stats.steps = ctx.steps;
    res.status = res.errors.length ? 'parsed_with_errors' : 'parsed';
    res.ok = true;
    res.complete = res.errors.length === 0 && !res.boundaries.some((b) => b.kind !== 'cpp' && b.kind !== 'ffi');
  } catch (e) {
    const fresh = emptyResult(file, dialect);
    fresh.stats = { ...res.stats, steps: ctx.steps };
    fresh.gaps = res.gaps;
    if (e instanceof BudgetError) {
      fresh.status = 'budget_exceeded';
      fresh.budget = { name: e.budget, limit: e.limit };
      fresh.errors.push({ kind: 'budget-exceeded', budget: e.budget, limit: e.limit, detail: e.message });
      fresh.uncertainty.push({ kind: 'partial-parse', detail: `parser budget ${e.budget} exceeded; the file was not analyzed` });
    } else {
      fresh.status = 'failed';
      fresh.errors.push({ kind: 'parser-exception', detail: String((e && e.message) || e) });
    }
    return fresh;
  }
  return res;
}

function analyze(source, file, dialect, ctx, res) {
  const g = ctx.grammar;
  const loc = makeLocator(source);
  let code = source;
  if (dialect === 'literate') {
    const lit = unwrapLiterate(code);
    code = lit.code;
    res.dialect = lit.style === 'latex' ? 'literate-latex' : 'literate-bird';
  }
  const pre = stripDirectives(code, dialect, g, loc);
  code = pre.code;
  const cppLines = pre.directives.filter((d) => d.name !== 'shebang');
  if (cppLines.length && dialect !== 'hsc') {
    res.boundaries.push({ kind: 'cpp', span: cppLines[0].span, detail: `${cppLines.length} preprocessor line(s) removed in place; every conditional branch was parsed`, count: cppLines.length });
  }
  if (dialect === 'hsc') {
    res.boundaries.push({ kind: 'hsc', span: loc.span(0, Math.min(source.length, 1)), detail: 'hsc2hs source: # directives and #{...} blanked in place, never run through hsc2hs' });
  }

  let lexed = lexAll(code, loc, ctx, { th: false, qq: false });
  const exts = new Set();
  for (const p of lexed.pragmas) {
    if (p.name === 'LANGUAGE' && p.headerPosition) for (const e of p.text.replace(/^LANGUAGE/i, '').split(',')) exts.add(e.trim());
  }
  const th = exts.has('TemplateHaskell') || exts.has('TemplateHaskellQuotes');
  const qq = exts.has('QuasiQuotes');
  if (th || qq) lexed = lexAll(code, loc, ctx, { th, qq });
  const T = lexed.tokens;
  res.stats.tokens = T.length;
  res.comments = lexed.comments;
  res.pragmas = lexed.pragmas.map((p) => ({ name: p.name, text: p.text, span: p.span }));
  res.boundaries.push(...lexed.boundaries);
  const errors = [...lexed.errors];

  // Generated-source disclosure from the header comments only.
  const base = String(file).split(/[\\/]/).pop() || '';
  const headerText = lexed.comments.filter((c) => c.headerPosition).slice(0, 5).map((c) => source.slice(c.span.startOffset, c.span.endOffset)).join('\n');
  if (/^Paths_[\w']+\.hs$/.test(base) || /@generated|\bgenerated by\b|auto-?generated|DO NOT EDIT/i.test(headerText)) {
    res.boundaries.push({ kind: 'generated', span: loc.span(0, 0), detail: 'file declares itself generated; treat its contents as generated source' });
  }
  for (const d of pre.directives) if (d.name === 'shebang') res.comments.push({ kind: 'shebang', span: d.span, terminated: true });

  const N = T.length;
  // ── module header ──
  let bodyStart = 0;
  if (N && T[0].k === 'kw' && T[0].v === 'module') {
    let depth = 0;
    let j = 1;
    for (; j < N; j++) {
      ctx.tick();
      const k = T[j].k;
      if (k === '(' || k === '[' || k === '{') depth++;
      else if (k === ')' || k === ']' || k === '}') depth--;
      else if (k === 'kw' && T[j].v === 'where' && depth <= 0) break;
    }
    const nameTok = T[1] && (T[1].k === 'conid' || T[1].k === 'qconid') ? T[1] : null;
    if (j >= N) {
      errors.push({ kind: 'module-header', offset: T[0].s, endOffset: T[0].e, detail: 'module header has no `where`' });
      bodyStart = Math.min(N, 2);
    } else bodyStart = j + 1;
    const exportsOpen = T[2] && T[2].k === '(' ? 2 : -1;
    const exportNames = [];
    if (exportsOpen > 0) for (let q = exportsOpen + 1; q < Math.min(j, N); q++) if (['varid', 'conid', 'qvarid', 'qconid'].includes(T[q].k)) exportNames.push(T[q].v);
    res.module = { name: nameTok ? nameTok.v : null, exports: exportsOpen > 0 ? exportNames : null, span: loc.span(T[0].s, T[Math.min(j, N - 1)].e) };
  }
  let topIndent = 0;
  let explicitTop = false;
  if (bodyStart < N) {
    if (T[bodyStart].k === '{') explicitTop = true;
    else topIndent = T[bodyStart].lcol;
  }

  // ── bracket matching with layout resynchronisation ──
  const match = new Int32Array(N).fill(-1);
  const stack = [];
  const unclosed = (idx) => errors.push({ kind: 'unclosed-bracket', offset: T[idx].s, endOffset: T[idx].e, detail: `\`${T[idx].v}\` is never closed` });
  for (let i = 0; i < N; i++) {
    ctx.tick();
    const t = T[i];
    if (!explicitTop && i >= bodyStart && stack.length && t.fol && t.lcol <= topIndent && !CLOSERS.has(t.k)) {
      for (const idx of stack) unclosed(idx);
      stack.length = 0;
    }
    if (OPENERS[t.k]) {
      stack.push(i);
      if (stack.length > ctx.budgets.maxDepth) throw new BudgetError('maxDepth', ctx.budgets.maxDepth);
    } else if (CLOSERS.has(t.k)) {
      const top = stack.length ? stack[stack.length - 1] : -1;
      if (top >= 0 && OPENERS[T[top].k] === t.k) { match[top] = i; match[i] = top; stack.pop(); }
      else errors.push({ kind: 'unmatched-bracket', offset: t.s, endOffset: t.e, detail: `\`${t.v}\` has no matching opener` });
    }
  }
  for (const idx of stack) unclosed(idx);

  // ── layout blocks and items ──
  const cut = (idx, end) => (idx >= end ? end : idx);
  const splitItems = (a, b, indent) => {
    const items = [];
    let start = a;
    let i = a;
    while (i < b) {
      ctx.tick();
      const t = T[i];
      if (OPENERS[t.k] && match[i] > i) { i = match[i] + 1; continue; }
      if (t.k === ';') {
        if (i > start) items.push({ a: start, b: i });
        start = i + 1;
      } else if (indent !== null && i > start && t.fol && t.lcol === indent) {
        items.push({ a: start, b: i });
        start = i;
      }
      i++;
    }
    if (start < b) items.push({ a: start, b });
    return items;
  };

  const openBlock = (k, rangeEnd, parentIndent, termComma) => {
    const kw = T[k].v;
    const a = k + 1;
    if (a >= rangeEnd) return { a, b: a, items: [], indent: -1 };
    if (T[a].k === '{' && match[a] > a) {
      const b = match[a];
      return { a: a + 1, b: b + 1, items: splitItems(a + 1, b, null), indent: -1, explicit: true };
    }
    const indent = T[a].lcol;
    if (indent <= parentIndent) return { a, b: a, items: [], indent };
    let ifOpen = 0; let thenOpen = 0; let caseOpen = 0; let letOpen = 0;
    let j = a;
    for (; j < rangeEnd; j++) {
      ctx.tick();
      const t = T[j];
      if (j > a && t.fol && t.lcol < indent) break;
      if (OPENERS[t.k] && match[j] > j) { j = match[j]; continue; }
      if (CLOSERS.has(t.k)) break;
      if (t.k === ',' && termComma) break;
      if (t.k === 'kw') {
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
    void kw;
    return { a, b: j, items: splitItems(a, j, indent), indent };
  };

  // ── extraction ──
  const work = [];
  const fnIndex = new Map();
  const callsOut = [];
  const spanOf = (a, b) => loc.span(T[a].s, T[Math.max(a, b - 1)].e);
  const condAt = (t) => pre.depthAtLine[t.line] > 0;
  const topRanges = [];

  const registerFunction = (key, rec) => {
    let f = fnIndex.get(key);
    if (!f) {
      f = { name: rec.name, kind: rec.kind, scope: rec.scope, parent: rec.parent, arity: rec.arity, guardCount: 0, clauses: [], span: null, signature: null, _s: rec.s, _e: rec.e };
      fnIndex.set(key, f);
      res.functions.push(f);
    }
    f._e = Math.max(f._e, rec.e);
    f.guardCount += rec.guards;
    f.clauses.push({ span: loc.span(rec.s, rec.e), arity: rec.arity, guardCount: rec.guards, bodySpan: rec.body });
    f.span = loc.span(f._s_ ?? f._s, f._e);
    return f;
  };

  const argsOf = (head, b) => {
    let j = head + 1;
    let count = 0;
    let lastEnd = T[head].e;
    while (j < b) {
      ctx.tick();
      const t = T[j];
      if (ATOM_START.has(t.k)) {
        count++; lastEnd = t.e; j++;
        if (T[j] && T[j].k === '{' && T[j].s === t.e && match[j] > j && (t.k === 'conid' || t.k === 'qconid' || t.k === 'varid')) { lastEnd = T[match[j]].e; j = match[j] + 1; }
      } else if ((t.k === '(' || t.k === '[') && match[j] > j) { count++; lastEnd = T[match[j]].e; j = match[j] + 1; }
      else if (t.k === 'rop' && t.v === '@' && j + 1 < b && t.e === T[j + 1].s && (j === 0 || T[j - 1].e < t.s)) {
        const nx = T[j + 1];
        if ((nx.k === '(' || nx.k === '[') && match[j + 1] > j + 1) j = match[j + 1] + 1; else j += 2;
      } else break;
    }
    return { count, lastEnd };
  };

  // Scan one item. role: decl | alt | stmt. Returns nothing; pushes extracted facts.
  const scanItem = (role, a, b, c) => {
    // Locate the end of the pattern/LHS region.
    let i = a;
    let state = 'expr';
    let eqop = '=';
    let guardCount = 0;
    let bodyStart = -1;
    let lastBody = -1;
    const closeBody = (endIdx) => { if (bodyStart >= 0 && endIdx > bodyStart) { res.expressions.push({ kind: 'clause-body', span: spanOf(bodyStart, endIdx), function: c.fn }); lastBody = endIdx; } bodyStart = -1; };

    if (role === 'decl') { i = c.rhs; eqop = '='; }
    else if (role === 'alt') {
      eqop = '->';
      let p = a;
      while (p < b) {
        ctx.tick();
        const t = T[p];
        if (OPENERS[t.k] && match[p] > p) { p = match[p] + 1; continue; }
        if ((t.k === 'rop' && (t.v === '->' || t.v === '|'))) break;
        p++;
      }
      if (p >= b) { errors.push({ kind: 'expected-arrow', offset: T[a].s, endOffset: T[b - 1].e, detail: 'case alternative has no `->`' }); return; }
      i = p;
    } else {
      let p = a;
      let found = -1;
      while (p < b) {
        ctx.tick();
        const t = T[p];
        if (OPENERS[t.k] && match[p] > p) { p = match[p] + 1; continue; }
        if (t.k === 'kw' && (t.v === 'let' || t.v === 'do' || t.v === 'of' || t.v === 'where' || t.v === 'if' || t.v === 'case')) break;
        if (t.k === 'rop' && t.v === '<-') { found = p; break; }
        p++;
      }
      if (found >= 0) {
        res.expressions.push({ kind: 'bind', span: spanOf(a, b), function: c.fn });
        i = found + 1;
      } else i = a;
      eqop = null;
    }
    if (role !== 'stmt' && T[i] && T[i].k === 'rop' && T[i].v === '|') state = 'guard';
    else if (role !== 'stmt' && T[i] && T[i].k === 'rop' && T[i].v === eqop) { i++; state = 'expr'; }
    if (state === 'guard') { guardCount++; i++; }
    if (state === 'expr') bodyStart = i;

    const caseStack = [];
    let multiIf = false;
    let skipType = -1; // bracket depth marker not needed; ends at closer/comma
    let prev = null;
    let depth = 0;
    let qualStart = state === 'guard' ? i : -1;
    let typeUntilDepth = null;

    while (i < b) {
      ctx.tick();
      const t = T[i];
      // Guard qualifiers: `pat <- e` skips the pattern.
      if (state === 'guard' && qualStart === i) {
        let p = i;
        while (p < b) {
          const q = T[p];
          if (OPENERS[q.k] && match[p] > p) { p = match[p] + 1; continue; }
          if (q.k === ',' || (q.k === 'rop' && (q.v === eqop || q.v === '<-'))) break;
          if (q.k === 'kw' && q.v === 'let') break;
          p++;
        }
        if (p < b && T[p].k === 'rop' && T[p].v === '<-') { i = p + 1; qualStart = -1; prev = T[p]; continue; }
        qualStart = -1;
      }
      if (typeUntilDepth !== null) {
        // inside a type annotation: skip to its end
        if (OPENERS[t.k] && match[i] > i) { i = match[i] + 1; continue; }
        if (CLOSERS.has(t.k) || t.k === ',' || (t.k === 'rop' && (t.v === '=' || t.v === '|' || t.v === '<-')) || (t.k === 'kw' && ['then', 'else', 'of', 'in', 'where'].includes(t.v))) typeUntilDepth = null;
        else { prev = t; i++; continue; }
      }
      if (t.k === 'rop' && t.v === '|' && !multiIf && role !== 'stmt' && depth === 0) {
        closeBody(i);
        state = 'guard'; guardCount++; qualStart = i + 1; i++; prev = null; continue;
      }
      if (state === 'guard' && t.k === ',') { qualStart = i + 1; i++; prev = null; continue; }
      if (state === 'guard' && t.k === 'rop' && t.v === eqop) { state = 'expr'; bodyStart = i + 1; i++; prev = null; continue; }
      if (t.k === 'kw' && c.layout.has(t.v)) {
        const termComma = state === 'guard';
        const blk = openBlock(i, b, c.indent, termComma);
        const role2 = t.v === 'do' || t.v === 'mdo' ? 'stmt' : (t.v === 'of' ? 'alt' : 'decl');
        const scope2 = t.v === 'where' ? 'where' : (t.v === 'let' ? 'let' : c.scope);
        for (const it of blk.items) work.push({ role: role2, a: it.a, b: it.b, indent: blk.indent, scope: scope2, parent: c.fn, depth: c.depth + 1, layout: c.layout, fn: c.fn });
        const endTok = Math.max(i, blk.b - 1);
        if (t.v === 'do' || t.v === 'mdo') {
          res.doBlocks.push({ span: loc.span(t.s, T[endTok].e), statements: blk.items.length, binds: blk.items.filter((it) => { for (let p = it.a; p < it.b; p++) { if (OPENERS[T[p].k] && match[p] > p) { p = match[p]; continue; } if (T[p].k === 'rop' && T[p].v === '<-') return true; } return false; }).length, function: c.fn });
          res.expressions.push({ kind: 'do', span: loc.span(t.s, T[endTok].e), function: c.fn });
        } else if (t.v === 'of') {
          const cs = caseStack.length ? caseStack.pop() : null;
          res.expressions.push({ kind: 'case', span: loc.span(cs !== null ? T[cs].s : t.s, T[endTok].e), function: c.fn });
        } else if (t.v === 'let') res.expressions.push({ kind: 'let', span: loc.span(t.s, T[endTok].e), function: c.fn });
        i = Math.max(i + 1, blk.b);
        prev = T[i - 1];
        continue;
      }
      if (t.k === 'rop' && t.v === '\\') {
        if (T[i + 1] && T[i + 1].k === 'kw' && T[i + 1].v === 'case') {
          const blk = openBlock(i + 1, b, c.indent, state === 'guard');
          for (const it of blk.items) work.push({ role: 'alt', a: it.a, b: it.b, indent: blk.indent, scope: c.scope, parent: c.fn, depth: c.depth + 1, layout: c.layout, fn: c.fn });
          const endTok = Math.max(i + 1, blk.b - 1);
          res.expressions.push({ kind: 'lambda-case', span: loc.span(t.s, T[endTok].e), function: c.fn });
          i = Math.max(i + 2, blk.b);
          prev = T[i - 1];
          continue;
        }
        let p = i + 1;
        while (p < b) {
          const q = T[p];
          if (OPENERS[q.k] && match[p] > p) { p = match[p] + 1; continue; }
          if (q.k === 'rop' && q.v === '->') break;
          p++;
        }
        if (p >= b) { errors.push({ kind: 'malformed-lambda', offset: t.s, endOffset: t.e, detail: 'lambda has no `->`' }); i = b; continue; }
        i = p + 1;
        prev = T[p];
        continue;
      }
      if (t.k === 'kw') {
        if (t.v === 'case') caseStack.push(i);
        else if (t.v === 'if' && T[i + 1] && T[i + 1].k === 'rop' && T[i + 1].v === '|') multiIf = true;
        prev = t; i++; continue;
      }
      if (t.k === 'rop' && t.v === '::') { typeUntilDepth = 0; prev = t; i++; continue; }
      if (t.k === '{' && match[i] > i && prev && (prev.k === 'conid' || prev.k === 'qconid' || prev.k === ')' || (prev.k === 'varid' && prev.e === t.s)) ) {
        const close = match[i];
        const fields = [];
        let d = 0;
        for (let p = i + 1; p < close; p++) {
          const q = T[p];
          if (OPENERS[q.k] && match[p] > p) { p = match[p]; continue; }
          void d;
          if ((q.k === 'varid' || q.k === 'qvarid') && T[p + 1] && (T[p + 1].k === 'rop' && T[p + 1].v === '=') && (p === i + 1 || T[p - 1].k === ',')) fields.push({ name: q.v, span: loc.span(q.s, q.e) });
          else if ((q.k === 'varid') && (p === i + 1 || T[p - 1].k === ',') && (T[p + 1] ? (T[p + 1].k === ',' || p + 1 === close) : true)) fields.push({ name: q.v, span: loc.span(q.s, q.e), pun: true });
        }
        res.records.push({ kind: prev.k === 'conid' || prev.k === 'qconid' ? 'construction' : 'update', name: prev.k === 'conid' || prev.k === 'qconid' ? prev.v : null, fields, span: loc.span(prev.s, T[close].e), function: c.fn });
        prev = T[i]; depth = 0; i++; continue;
      }
      if (t.k === '`' && T[i + 1] && (T[i + 1].k === 'varid' || T[i + 1].k === 'qvarid') && T[i + 2] && T[i + 2].k === '`') {
        const h = T[i + 1];
        callsOut.push({ kind: 'call', callee: h.v, name: h.name || h.v, qualifier: h.qual || null, infix: true, argCount: 2, span: loc.span(T[i].s, T[i + 2].e), calleeSpan: loc.span(h.s, h.e), function: c.fn, scope: c.scope, conditional: condAt(h) });
        prev = T[i + 2]; i += 3; continue;
      }
      if ((t.k === 'varid' || t.k === 'qvarid') && t.line >= 1) {
        const atomPrev = prev && ATOM_END.has(prev.k);
        const fwdPrev = prev && prev.k === 'op' && ctx.grammar.forwardingOps.includes(prev.v);
        const typeApp = prev && prev.k === 'rop' && prev.v === '@' && prev.e === t.s;
        if (!typeApp && (!atomPrev || fwdPrev) && !(prev && prev.k === 'tick')) {
          const { count, lastEnd } = argsOf(i, b);
          if (count > 0 || fwdPrev) {
            callsOut.push({ kind: 'call', callee: t.v, name: t.name || t.v, qualifier: t.qual || null, infix: false, argCount: count, span: loc.span(t.s, lastEnd), calleeSpan: loc.span(t.s, t.e), function: c.fn, scope: c.scope, conditional: condAt(t) });
          }
        }
      }
      prev = t;
      i++;
    }
    closeBody(b);
    return { guardCount, lastBody };
  };

  const handleDecl = (it, c) => {
    const { a, b } = it;
    let p = a;
    let mark = -1;
    while (p < b) {
      ctx.tick();
      const t = T[p];
      if (OPENERS[t.k] && match[p] > p) { p = match[p] + 1; continue; }
      if (t.k === 'rop' && (t.v === '=' || t.v === '|' || t.v === '::')) { mark = p; break; }
      if (t.k === 'kw' && (t.v === 'where' || t.v === 'of')) break;
      p++;
    }
    if (mark < 0) {
      if (c.scope === 'top' && ctx.th) {
        res.boundaries.push({ kind: 'th-top-level-splice', span: spanOf(a, b), detail: 'top-level Template Haskell splice; declarations it generates are not visible' });
        return;
      }
      errors.push({ kind: 'expected-declaration', offset: T[a].s, endOffset: T[b - 1].e, detail: 'item is neither a binding nor a signature' });
      return;
    }
    if (T[mark].v === '::') {
      const names = [];
      for (let q = a; q < mark; q++) {
        if (T[q].k === 'varid') names.push(T[q].v);
        else if (T[q].k === '(' && match[q] === q + 2 && /op|consym/.test(T[q + 1].k)) { names.push(T[q + 1].v); q += 2; }
      }
      res.signatures.push({ names, span: spanOf(a, b), scope: c.scope });
      return;
    }
    // clause
    let name = null;
    let kind = 'function';
    let arity = 0;
    const isPrefixMark = (q) => T[q].k === 'op' && q + 1 < mark && T[q].e === T[q + 1].s && (q === a || T[q - 1].e < T[q].s);
    let infixAt = -1;
    for (let q = a; q < mark; q++) {
      if (OPENERS[T[q].k] && match[q] > q) { q = match[q]; continue; }
      if (T[q].k === 'consym') { infixAt = -2; break; }
      if (q > a && T[q].k === 'op' && !isPrefixMark(q)) { infixAt = q; break; }
      if (T[q].k === '`' && T[q + 1] && T[q + 1].k === 'varid' && T[q + 2] && T[q + 2].k === '`') { infixAt = q + 1; break; }
    }
    if (infixAt === -2) kind = 'pattern-binding';
    else if (infixAt >= 0) { name = T[infixAt].v; arity = 2; }
    else if (T[a].k === 'varid') {
      name = T[a].v;
      for (let q = a + 1; q < mark; q++) {
        const t = T[q];
        if (t.k === 'op' && isPrefixMark(q)) continue;
        if (t.k === 'rop' && t.v === '@' ) { q++; if (OPENERS[T[q] && T[q].k] && match[q] > q) q = match[q]; continue; }
        if (OPENERS[t.k] && match[q] > q) q = match[q];
        arity++;
      }
    } else if (T[a].k === '(' && match[a] === a + 2 && T[a + 1] && (T[a + 1].k === 'op' || T[a + 1].k === 'consym')) {
      name = T[a + 1].v;
      for (let q = a + 3; q < mark; q++) { if (OPENERS[T[q].k] && match[q] > q) q = match[q]; arity++; }
    } else kind = 'pattern-binding';
    const rec = scanItem('decl', a, b, { ...c, rhs: mark, fn: name || c.fn });
    const body = rec && rec.lastBody > 0 ? spanOf(Math.min(mark + 1, b - 1), rec.lastBody) : null;
    const endTok = b - 1;
    const bodyFirst = Math.min(mark + 1, b - 1);
    const f = registerFunction(`${c.blockId}:${name === null ? `#${a}` : name}`, {
      name, kind, scope: c.scope, parent: c.parent || null, arity, guards: rec ? rec.guardCount : 0,
      s: T[a].s, e: T[endTok].e, body: b > mark + 1 ? loc.span(T[bodyFirst].s, T[endTok].e) : null,
    });
    void body;
    f.span = loc.span(f._s, f._e);
  };

  const parseImport = (a, b) => {
    let j = a + 1;
    const rec = { module: null, qualified: false, as: null, hiding: false, safe: false, package: null, items: null, span: spanOf(a, b) };
    while (j < b) {
      const t = T[j];
      if (t.k === 'varid' && (t.v === 'qualified' || t.v === 'safe')) { if (t.v === 'qualified') rec.qualified = true; else rec.safe = true; j++; }
      else if (t.k === 'string' && !rec.module) { rec.package = t.v; j++; }
      else break;
    }
    if (j < b && (T[j].k === 'conid' || T[j].k === 'qconid')) { rec.module = T[j].v; rec.moduleSpan = loc.span(T[j].s, T[j].e); j++; }
    else errors.push({ kind: 'malformed-import', offset: T[a].s, endOffset: T[b - 1].e, detail: 'import has no module name' });
    while (j < b) {
      const t = T[j];
      if (t.k === 'varid' && t.v === 'qualified') { rec.qualified = true; j++; }
      else if (t.k === 'varid' && t.v === 'as' && T[j + 1] && (T[j + 1].k === 'conid' || T[j + 1].k === 'qconid')) { rec.as = T[j + 1].v; j += 2; }
      else if (t.k === 'varid' && t.v === 'hiding') { rec.hiding = true; j++; }
      else if (t.k === '(' && match[j] > j) {
        rec.items = [];
        for (let q = j + 1; q < match[j]; q++) if (['varid', 'conid'].includes(T[q].k)) rec.items.push(T[q].v);
        j = match[j] + 1;
      } else j++;
    }
    res.imports.push(rec);
  };

  const topItems = explicitTop && bodyStart < N && match[bodyStart] > bodyStart
    ? splitItems(bodyStart + 1, match[bodyStart], null)
    : splitItems(bodyStart, N, topIndent);
  ctx.th = th;
  const layout = new Set(g.layoutKeywords);
  let blockSeq = 0;
  for (const it of topItems) {
    topRanges.push({ s: T[it.a].s, e: T[it.b - 1].e });
    const t0 = T[it.a];
    const c0 = { scope: 'top', indent: topIndent, depth: 0, layout, blockId: 'top', fn: null, parent: null };
    if (t0.k === 'kw' && g.declarationKeywords.includes(t0.v)) {
      if (t0.v === 'import') parseImport(it.a, it.b);
      else if (t0.v === 'foreign') {
        const dir = T[it.a + 1] && T[it.a + 1].v;
        const nameTok = T.slice(it.a, it.b).find((x, qi, arr) => x.k === 'varid' && arr[qi + 1] && arr[qi + 1].v === '::');
        res.declarations.push({ kind: 'foreign', direction: dir, name: nameTok ? nameTok.v : null, span: spanOf(it.a, it.b) });
        res.boundaries.push({ kind: 'ffi', span: spanOf(it.a, it.b), detail: `foreign ${dir || ''} declaration; the foreign code is not analyzed` });
      } else if (t0.v === 'data' || t0.v === 'newtype') {
        const decl = { kind: t0.v, name: null, constructors: [], fields: [], span: spanOf(it.a, it.b) };
        let q = it.a + 1;
        for (; q < it.b; q++) {
          if (T[q].k === 'conid') { decl.name = T[q].v; break; }
          if (T[q].k === 'rop' && T[q].v === '=') break;
        }
        for (let p = it.a; p < it.b; p++) {
          const tk = T[p];
          if (tk.k === 'rop' && (tk.v === '=' || tk.v === '|') && T[p + 1] && T[p + 1].k === 'conid') decl.constructors.push(T[p + 1].v);
          if (tk.k === '{' && match[p] > p) {
            for (let r = p + 1; r < match[p]; r++) {
              if (OPENERS[T[r].k] && match[r] > r) { r = match[r]; continue; }
              if (T[r].k === 'varid' && (r === p + 1 || T[r - 1].k === ',')) {
                let m2 = r;
                const names = [];
                while (T[m2] && T[m2].k === 'varid') { names.push(T[m2]); if (T[m2 + 1] && T[m2 + 1].k === ',') m2 += 2; else { m2++; break; } }
                if (T[m2] && T[m2].k === 'rop' && T[m2].v === '::') for (const nt of names) decl.fields.push({ name: nt.v, span: loc.span(nt.s, nt.e) });
                r = m2 - 1;
              }
            }
            res.records.push({ kind: 'declaration', name: decl.name, fields: decl.fields.slice(), span: loc.span(T[p].s, T[match[p]].e), function: null });
            p = match[p];
          }
        }
        res.declarations.push(decl);
      } else if (t0.v === 'class' || t0.v === 'instance') {
        let w = -1;
        for (let q = it.a + 1; q < it.b; q++) {
          if (OPENERS[T[q].k] && match[q] > q) { q = match[q]; continue; }
          if (T[q].k === 'kw' && T[q].v === 'where') { w = q; break; }
        }
        const nameTok = T.slice(it.a + 1, w < 0 ? it.b : w).find((x) => x.k === 'conid' || x.k === 'qconid');
        res.declarations.push({ kind: t0.v, name: nameTok ? nameTok.v : null, span: spanOf(it.a, it.b) });
        if (w >= 0) {
          const blk = openBlock(w, it.b, topIndent, false);
          const bid = `${t0.v}${blockSeq++}`;
          for (const sub of blk.items) work.push({ role: 'decl', a: sub.a, b: sub.b, indent: blk.indent, scope: t0.v, parent: nameTok ? nameTok.v : null, depth: 1, layout, fn: null, blockId: bid });
        }
      } else res.declarations.push({ kind: t0.v, name: null, span: spanOf(it.a, it.b) });
      continue;
    }
    handleDecl(it, c0);
  }

  // Worklist for nested blocks, iterative and depth-bounded.
  let wi = 0;
  const blockIds = new Map();
  while (wi < work.length) {
    ctx.tick();
    const w = work[wi++];
    if (w.depth > ctx.budgets.maxDepth) throw new BudgetError('maxDepth', ctx.budgets.maxDepth);
    const key = `${w.role}:${w.indent}:${w.parent}:${w.scope}`;
    if (!w.blockId) {
      if (!blockIds.has(key + ':' + T[w.a].line)) blockIds.set(key + ':' + T[w.a].line, `b${blockIds.size}`);
      w.blockId = blockIds.get(key + ':' + T[w.a].line);
    }
    if (w.role === 'decl') handleDecl({ a: w.a, b: w.b }, w);
    else scanItem(w.role, w.a, w.b, w);
  }

  // ── errors → withheld calls ──
  const bad = [];
  for (const e of errors) {
    const r = topRanges.find((x) => e.offset >= x.s && e.offset <= x.e) || null;
    if (r) bad.push(r);
  }
  bad.sort((x, y) => x.s - y.s);
  const merged = [];
  for (const r of bad) {
    const last = merged[merged.length - 1];
    if (last && r.s <= last.e) last.e = Math.max(last.e, r.e); else merged.push({ ...r });
  }
  const inBad = (off) => {
    let lo = 0; let hi = merged.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (off < merged[mid].s) hi = mid - 1; else if (off > merged[mid].e) lo = mid + 1; else return mid;
    }
    return -1;
  };
  const withheld = new Map();
  for (const call of callsOut) {
    const idx = merged.length ? inBad(call.span.startOffset) : -1;
    if (idx >= 0) withheld.set(idx, (withheld.get(idx) || 0) + 1); else res.calls.push(call);
  }
  for (const f of res.functions) {
    if (merged.length && inBad(f._s) >= 0) f.partial = true;
    delete f._s; delete f._e; delete f._s_;
  }
  res.expressions = res.expressions.filter((x) => merged.length === 0 || inBad(x.span.startOffset) < 0);
  res.doBlocks = res.doBlocks.filter((x) => merged.length === 0 || inBad(x.span.startOffset) < 0);
  res.records = res.records.filter((x) => merged.length === 0 || inBad(x.span.startOffset) < 0);

  const total = errors.length;
  const outErrors = errors.slice(0, ctx.budgets.maxErrors);
  for (const e of outErrors) {
    const idx = merged.length ? inBad(e.offset) : -1;
    res.errors.push({ kind: e.kind, detail: e.detail, span: loc.span(e.offset, e.endOffset), withheldCalls: idx >= 0 ? (withheld.get(idx) || 0) : 0 });
  }
  if (total > outErrors.length) res.errors.push({ kind: 'errors-truncated', detail: `${total - outErrors.length} further syntax error(s) not listed` });

  // ── uncertainty ──
  if (res.boundaries.some((x) => x.kind === 'cpp' || x.kind === 'hsc')) res.uncertainty.push({ kind: 'preprocessed' });
  if (res.boundaries.some((x) => x.kind === 'generated' || x.kind.startsWith('th-') || x.kind === 'quasiquote')) res.uncertainty.push({ kind: 'generated-source' });
  if (res.errors.length) res.uncertainty.push({ kind: 'partial-parse' });
  res.functions.sort((x, y) => x.span.startOffset - y.span.startOffset);
  res.calls.sort((x, y) => x.span.startOffset - y.span.startOffset);
  void cut;
}
