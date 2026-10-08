// CPP conditional evaluation for Haskell sources (HS boundaries).
//
// Static and dependency-free: it never runs cpp, GHC or Cabal. It evaluates `#if` / `#ifdef` / `#ifndef` / `#elif` /
// `#else` chains with THREE-valued logic (true, false, unknown) so that:
//   - a decidable conditional keeps only its live branch (the dead branch is overwritten with same-length spaces by the
//     caller, so locations stay exact),
//   - an undecidable one keeps EVERY possible branch (the union) and is reported as undecided,
//   - nothing is ever invented: a macro that the file does not define and the project does not state is `unknown`, never 0.
//
// What decides a condition, and on what basis (each decision records its basis):
//   file            `#define` / `#undef` in the same file, integer literals, `#if 0` / `#if 1`, `defined(X)`.
//   compiler:pinned __GLASGOW_HASKELL__, MIN_VERSION_GLASGOW_HASKELL and the boot-package MIN_VERSION_base, when the
//                   project PINS a compiler (`with-compiler: ghc-X` in cabal.project). Pinned means "this is what builds".
//   compiler:tested-with   the same, from `tested-with: GHC == X` lines. That is a claim by the project, not a pin, so a
//                   decision on this basis is only taken when EVERY listed version agrees, and it is disclosed as an assumption.
//   cabal-bounds    MIN_VERSION_<pkg>(a,b,c) judged against the hull of the `build-depends` ranges of every component in the
//                   project: a built version must satisfy its component's range, so it lies inside the hull.

import { parseCabalFile, parseVersion, compareVersions } from './haskell-manifests.js';

const UNKNOWN = null;

// ── tri-state helpers ──────────────────────────────────────────────────────

const truthy = (v) => (v === UNKNOWN ? UNKNOWN : v !== 0);

// ── versions ───────────────────────────────────────────────────────────────

const toNums = (v) => v.map((x) => Number(x));

/**
 * Three-valued `v >= t` where `v` may have an unknown tail (a wildcard such as 9.6.* has no patch level): undefined
 * components of v are unknown, so the answer is decided only by the components that exist.
 */
function triGte(v, t) {
  for (let i = 0; i < Math.max(v.length, t.length); i++) {
    const p = v[i];
    const q = t[i] ?? 0;
    if (p === undefined) return t.slice(i).every((x) => x === 0) ? true : UNKNOWN;
    if (p > q) return true;
    if (p < q) return false;
  }
  return true;
}

// GHC ships a fixed `base`. Only major.minor is recorded: a patch level of base varies inside one GHC series.
const GHC_BASE = new Map([['8.6', [4, 12]], ['8.8', [4, 13]], ['8.10', [4, 14]], ['9.0', [4, 15]], ['9.2', [4, 16]], ['9.4', [4, 17]], ['9.6', [4, 18]], ['9.8', [4, 19]], ['9.10', [4, 20]], ['9.12', [4, 21]]]);

function baseRangeOf(ghc) {
  const b = GHC_BASE.get(`${ghc[0]}.${ghc[1]}`);
  return b ? { lo: b, hiExcl: [b[0], b[1] + 1] } : null;
}

/** Hull {lo, hiExcl, hiIncl} of a parsed version-range AST (null bounds are open). Over-approximates, never under. */
export function rangeHull(ast) {
  const inter = (a, b) => ({
    lo: !a.lo ? b.lo : !b.lo ? a.lo : (compareVersions(a.lo, b.lo) >= 0 ? a.lo : b.lo),
    hiExcl: !a.hiExcl ? b.hiExcl : !b.hiExcl ? a.hiExcl : (compareVersions(a.hiExcl, b.hiExcl) <= 0 ? a.hiExcl : b.hiExcl),
    hiIncl: !a.hiIncl ? b.hiIncl : !b.hiIncl ? a.hiIncl : (compareVersions(a.hiIncl, b.hiIncl) <= 0 ? a.hiIncl : b.hiIncl),
  });
  const open = { lo: null, hiExcl: null, hiIncl: null };
  const walk = (n) => {
    if (!n) return open;
    switch (n.t) {
      case 'and': return inter(walk(n.l), walk(n.r));
      case 'or': {
        const a = walk(n.l); const b = walk(n.r);
        const hiOf = (x) => (x.hiExcl || x.hiIncl);
        const unbounded = (x) => !x.hiExcl && !x.hiIncl;
        let hi = { hiExcl: null, hiIncl: null };
        if (!unbounded(a) && !unbounded(b)) {
          // the larger of the two upper bounds; an inclusive bound outranks an exclusive one at the same version
          const ha = hiOf(a); const hb = hiOf(b);
          const c = compareVersions(ha, hb);
          const pick = c > 0 ? a : c < 0 ? b : (a.hiIncl ? a : b);
          hi = { hiExcl: pick.hiExcl && !pick.hiIncl ? pick.hiExcl : null, hiIncl: pick.hiIncl || null };
        }
        return { lo: !a.lo || !b.lo ? null : (compareVersions(a.lo, b.lo) <= 0 ? a.lo : b.lo), ...hi };
      }
      case 'cmp': {
        const v = n.version;
        if (n.op === '>=' || n.op === '>') return { ...open, lo: v };
        if (n.op === '<') return { ...open, hiExcl: v };
        if (n.op === '<=') return { ...open, hiIncl: v };
        if (n.op === '^>=') { const up = [v[0], (v[1] ?? 0n) + 1n]; return { lo: v, hiExcl: up, hiIncl: null }; }
        if (n.op === '==') {
          if (n.wildcard) { const up = v.slice(); up[up.length - 1] += 1n; return { lo: v, hiExcl: up, hiIncl: null }; }
          return { lo: v, hiExcl: null, hiIncl: v };
        }
        return open;
      }
      case 'none': return { lo: [1n], hiExcl: [0n], hiIncl: null };
      default: return open;
    }
  };
  return walk(ast);
}

/** Three-valued MIN_VERSION_x(a,b,c): is the installed version >= target, given that it lies in `r`? */
function minVersion(r, target) {
  if (!r) return UNKNOWN;
  const t = target.map((x) => BigInt(x));
  if (r.lo && compareVersions(r.lo, t) >= 0) return true;
  if (r.hiExcl && compareVersions(r.hiExcl, t) <= 0) return false;
  if (r.hiIncl && compareVersions(r.hiIncl, t) < 0) return false;
  return UNKNOWN;
}

const intersectHull = (a, b) => {
  if (!a) return b; if (!b) return a;
  return {
    lo: !a.lo ? b.lo : !b.lo ? a.lo : (compareVersions(a.lo, b.lo) >= 0 ? a.lo : b.lo),
    hiExcl: !a.hiExcl ? b.hiExcl : !b.hiExcl ? a.hiExcl : (compareVersions(a.hiExcl, b.hiExcl) <= 0 ? a.hiExcl : b.hiExcl),
    hiIncl: !a.hiIncl ? b.hiIncl : !b.hiIncl ? a.hiIncl : (compareVersions(a.hiIncl, b.hiIncl) <= 0 ? a.hiIncl : b.hiIncl),
  };
};

// ── project context ────────────────────────────────────────────────────────

/**
 * Derive what the project itself states, from manifest files in `files` (path -> text). Returns
 * { ghc: {versions:number[][], basis:'pinned'|'tested-with'}|null, packages: Map<name, hull> }. Never throws.
 */
export function deriveCppContext(files = {}) {
  const ctx = { ghc: null, packages: new Map() };
  const pinned = [];
  const tested = [];
  let testedUsable = true;
  const hulls = new Map();
  for (const [file, text] of Object.entries(files || {})) {
    if (typeof text !== 'string') continue;
    try {
      if (/(?:^|\/)cabal\.project(?:\.local)?$/i.test(file)) {
        const m = /^\s*with-compiler\s*:\s*ghc-(\d+(?:\.\d+)+)\s*$/im.exec(text);
        if (m) pinned.push(toNums(parseVersion(m[1])));
      } else if (/\.cabal$/i.test(file)) {
        const tw = /^tested-with\s*:((?:.*\n?)(?:[ \t]+.*\n?)*)/im.exec(text);
        if (tw) {
          const body = tw[1];
          for (const part of body.split(',').map((s) => s.trim()).filter(Boolean)) {
            const m = /^GHC\s*==\s*(\d+(?:\.\d+)*)(\.\*)?$/i.exec(part);
            if (m) tested.push(toNums(parseVersion(m[1])));
            else if (/^GHC\b/i.test(part)) testedUsable = false;   // a range or an unparsable item: never guess a version from it
          }
        }
        const parsed = parseCabalFile(text, { file });
        for (const comp of parsed.components || []) {
          for (const d of comp.dependencies || []) {
            if (!d || !d.name) continue;
            const h = d.range ? rangeHull(d.range) : { lo: null, hiExcl: null, hiIncl: null };
            const prior = hulls.get(d.name);
            // union of components: the lower of the lows, the larger of the highs; an open end stays open
            hulls.set(d.name, !prior ? h : {
              lo: !prior.lo || !h.lo ? null : (compareVersions(prior.lo, h.lo) <= 0 ? prior.lo : h.lo),
              ...((!prior.hiExcl && !prior.hiIncl) || (!h.hiExcl && !h.hiIncl) ? { hiExcl: null, hiIncl: null } : (() => {
                const pa = prior.hiExcl || prior.hiIncl; const pb = h.hiExcl || h.hiIncl;
                const c = compareVersions(pa, pb);
                const pick = c > 0 ? prior : c < 0 ? h : (prior.hiIncl ? prior : h);
                return { hiExcl: pick.hiIncl ? null : pick.hiExcl, hiIncl: pick.hiIncl || null };
              })()),
            });
          }
        }
      }
    } catch { /* an unreadable manifest states nothing */ }
  }
  if (pinned.length) ctx.ghc = { versions: pinned, basis: 'pinned' };
  else if (tested.length && testedUsable) ctx.ghc = { versions: tested, basis: 'tested-with' };
  ctx.packages = hulls;
  return ctx;
}

// ── expression evaluation ──────────────────────────────────────────────────

const TOKEN = /\s*(0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|[A-Za-z_]\w*|&&|\|\||==|!=|<=|>=|<<|>>|[-+*/%()!<>,~&|^?:])/y;

function tokenize(text) {
  const s = text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/.*$/, ' ').trim();
  const out = [];
  let pos = 0;
  while (pos < s.length) {
    TOKEN.lastIndex = pos;
    const m = TOKEN.exec(s);
    if (!m) return null;
    out.push(m[1]);
    pos = TOKEN.lastIndex;
    if (out.length > 400) return null;
  }
  return out;
}

const isIdent = (t) => /^[A-Za-z_]/.test(t);

/**
 * Evaluate an `#if` expression to a number, or UNKNOWN. `env` = { macros: Map, ghc: number[]|null, packages: Map }.
 * `used` collects the bases the answer depended on.
 */
function evalExpression(text, env, used) {
  const toks = tokenize(text);
  if (!toks || !toks.length) return UNKNOWN;
  let i = 0;
  let bad = false;
  const macroValue = (name, depth) => {
    const m = env.macros.get(name);
    if (m === undefined) return UNKNOWN;
    if (m.state === 'undefined') return 0;
    if (m.state !== 'defined' || m.fn) return UNKNOWN;
    if (m.value === '') return UNKNOWN;
    if (depth > 8) return UNKNOWN;
    const t2 = tokenize(m.value);
    if (!t2 || t2.length !== 1) return UNKNOWN;
    if (/^\d/.test(t2[0])) return parseInt(t2[0], /^0[xX]/.test(t2[0]) ? 16 : 10);
    if (isIdent(t2[0])) return macroValue(t2[0], depth + 1);
    return UNKNOWN;
  };
  const definedState = (name) => {
    const m = env.macros.get(name);
    if (m) return m.state === 'defined' ? true : m.state === 'undefined' ? false : UNKNOWN;
    if (name === '__GLASGOW_HASKELL__' && env.ghc) { used.add(`compiler:${env.basis}`); return true; }
    return UNKNOWN;
  };
  const num = () => {
    const t = toks[i++];
    if (t === undefined) { bad = true; return UNKNOWN; }
    if (t === '(') { const v = ternary(); if (toks[i++] !== ')') bad = true; return v; }
    if (t === '!') { const v = unary(); return v === UNKNOWN ? UNKNOWN : (v === 0 ? 1 : 0); }
    if (t === '-') { const v = unary(); return v === UNKNOWN ? UNKNOWN : -v; }
    if (t === '+') return unary();
    if (t === '~') { const v = unary(); return v === UNKNOWN ? UNKNOWN : ~v; }
    if (/^\d/.test(t)) return parseInt(t, /^0[xX]/.test(t) ? 16 : 10);
    if (!isIdent(t)) { bad = true; return UNKNOWN; }
    if (t === 'defined') {
      let paren = false;
      if (toks[i] === '(') { paren = true; i++; }
      const name = toks[i++];
      if (paren && toks[i++] !== ')') bad = true;
      if (!name || !isIdent(name)) { bad = true; return UNKNOWN; }
      const d = definedState(name);
      return d === UNKNOWN ? UNKNOWN : (d ? 1 : 0);
    }
    if (toks[i] === '(') {
      // function-like macro call: MIN_VERSION_*(a,b,c) is modelled, every other call is unknown
      const args = [];
      i++;
      if (toks[i] !== ')') {
        for (;;) {
          const a = ternary();
          args.push(a);
          if (toks[i] === ',') { i++; continue; }
          break;
        }
      }
      if (toks[i++] !== ')') { bad = true; return UNKNOWN; }
      const fnMacro = env.macros.get(t);
      if (fnMacro) return UNKNOWN;   // defined (or possibly defined) in the file: its body is not expanded
      return minVersionCall(t, args);
    }
    if (t === '__GLASGOW_HASKELL__') {
      const m = env.macros.get(t);
      if (m) return macroValue(t, 0);
      if (!env.ghc) return UNKNOWN;
      used.add(`compiler:${env.basis}`);
      return env.ghc[0] * 100 + (env.ghc[1] ?? 0);
    }
    return macroValue(t, 0);
  };
  const minVersionCall = (name, args) => {
    const m = /^MIN_VERSION_(.+)$/.exec(name);
    if (!m || args.some((a) => a === UNKNOWN || a < 0)) return UNKNOWN;
    if (m[1] === 'GLASGOW_HASKELL') {
      if (!env.ghc || args.length !== 4) return UNKNOWN;
      used.add(`compiler:${env.basis}`);
      const r = triGte(env.ghc, args);
      return r === UNKNOWN ? UNKNOWN : (r ? 1 : 0);
    }
    if (args.length !== 3) return UNKNOWN;
    const pkg = m[1].replace(/_/g, '-');
    let hull = env.packages.get(pkg) || env.packages.get(m[1]) || null;
    if (hull) used.add('cabal-bounds');
    if (pkg === 'base' && env.ghc) {
      const bt = baseRangeOf(env.ghc);
      if (bt) {
        used.add(`compiler:${env.basis}`);
        hull = intersectHull(hull, { lo: bt.lo.map((x) => BigInt(x)), hiExcl: bt.hiExcl.map((x) => BigInt(x)), hiIncl: null });
      }
    }
    const r = minVersion(hull, args);
    return r === UNKNOWN ? UNKNOWN : (r ? 1 : 0);
  };
  const unary = () => num();
  const bin = (next, ops) => () => {
    let l = next();
    while (ops.includes(toks[i])) {
      const op = toks[i++];
      const r = next();
      l = apply(op, l, r);
    }
    return l;
  };
  const apply = (op, l, r) => {
    if (op === '&&') { if (l === 0 || r === 0) return 0; if (l === UNKNOWN || r === UNKNOWN) return UNKNOWN; return 1; }
    if (op === '||') { if ((l !== UNKNOWN && l !== 0) || (r !== UNKNOWN && r !== 0)) return 1; if (l === UNKNOWN || r === UNKNOWN) return UNKNOWN; return 0; }
    if (l === UNKNOWN || r === UNKNOWN) return UNKNOWN;
    switch (op) {
      case '*': return l * r;
      case '/': return r === 0 ? UNKNOWN : Math.trunc(l / r);
      case '%': return r === 0 ? UNKNOWN : l % r;
      case '+': return l + r;
      case '-': return l - r;
      case '<<': return r < 0 || r > 30 ? UNKNOWN : l << r;
      case '>>': return r < 0 || r > 30 ? UNKNOWN : l >> r;
      case '<': return l < r ? 1 : 0;
      case '>': return l > r ? 1 : 0;
      case '<=': return l <= r ? 1 : 0;
      case '>=': return l >= r ? 1 : 0;
      case '==': return l === r ? 1 : 0;
      case '!=': return l !== r ? 1 : 0;
      case '&': return l & r;
      case '^': return l ^ r;
      case '|': return l | r;
      default: return UNKNOWN;
    }
  };
  const mul = bin(unary, ['*', '/', '%']);
  const add = bin(mul, ['+', '-']);
  const shift = bin(add, ['<<', '>>']);
  const rel = bin(shift, ['<', '>', '<=', '>=']);
  const eq = bin(rel, ['==', '!=']);
  const band = bin(eq, ['&']);
  const bxor = bin(band, ['^']);
  const bor = bin(bxor, ['|']);
  const land = bin(bor, ['&&']);
  const lor = bin(land, ['||']);
  const ternary = () => {
    const c = lor();
    if (toks[i] === '?') {
      i++;
      const a = ternary();
      if (toks[i++] !== ':') { bad = true; return UNKNOWN; }
      const b = ternary();
      if (c === UNKNOWN) return a === b ? a : UNKNOWN;
      return c !== 0 ? a : b;
    }
    return c;
  };
  const v = ternary();
  if (bad || i < toks.length) return UNKNOWN;
  return v;
}

/** Tri-state truth of an `#if` expression, across every candidate compiler version (they must all agree). */
function decide(text, state, ctx) {
  const ghcs = ctx && ctx.ghc && ctx.ghc.versions.length ? ctx.ghc.versions : [null];
  const results = [];
  const used = new Set();
  for (const g of ghcs) {
    const env = { macros: state.macros, ghc: g, basis: ctx && ctx.ghc ? ctx.ghc.basis : null, packages: (ctx && ctx.packages) || new Map() };
    results.push(truthy(evalExpression(text, env, used)));
  }
  const first = results[0];
  const value = results.every((r) => r === first) ? first : UNKNOWN;
  return { value, basis: value === UNKNOWN ? null : (used.size ? [...used].sort() : ['file']) };
}

function decideDefined(name, state, ctx) {
  const m = state.macros.get(name);
  if (m) return { value: m.state === 'defined' ? true : m.state === 'undefined' ? false : UNKNOWN, basis: ['file'] };
  if (name === '__GLASGOW_HASKELL__' && ctx && ctx.ghc) return { value: true, basis: [`compiler:${ctx.ghc.basis}`] };
  return { value: UNKNOWN, basis: null };
}

const blank = (s) => s.replace(/[^\r\n]/g, ' ');

/**
 * Evaluate the CPP conditionals of `code` line by line.
 * @param {string[]} lines  the source split on '\n' (modified copies are returned, lengths preserved)
 * @param {{ghc?:object, packages?:Map, defines?:object}} [ctx]
 * @returns {{lines:string[], maybeDepth:Int32Array, decided:object[], undecided:object[], deadLines:number}}
 */
export function evaluateCppLines(lines, isDirective, ctx = {}) {
  const state = { macros: new Map() };
  for (const [k, v] of Object.entries((ctx && ctx.defines) || {})) state.macros.set(k, { state: 'defined', value: String(v), fn: false });
  const out = lines.slice();
  const maybeDepth = new Int32Array(lines.length + 2);
  const stack = [];
  const decided = [];
  const undecided = [];
  let deadLines = 0;
  const region = () => {
    let r = 'live';
    for (const f of stack) { if (f.cur === 'dead') return 'dead'; if (f.cur === 'maybe') r = 'maybe'; }
    return r;
  };
  const maybeCount = () => stack.filter((f) => f.cur === 'maybe').length;

  for (let i = 0; i < lines.length; i++) {
    const info = isDirective(i);
    if (!info) {
      // an ordinary line: a dead region is overwritten, a live or possible one is kept
      if (region() === 'dead') { out[i] = blank(out[i]); deadLines++; }
      maybeDepth[i + 1] = maybeCount();
      continue;
    }
    // directive logical line (continuations already joined by the caller in info.text); the physical lines it spans
    const { name, text, last } = info;
    const parentRegion = region();
    const rest = text.replace(/^#\s*[A-Za-z]+/, '').trim();
    const lineNo = i + 1;
    const note = (kind, value, basis) => {
      const rec = { line: lineNo, directive: name, outcome: value === UNKNOWN ? 'undecided' : (value ? 'true' : 'false'), basis };
      if (kind === 'decided') decided.push(rec); else undecided.push(rec);
    };
    if (name === 'if' || name === 'ifdef' || name === 'ifndef') {
      if (parentRegion === 'dead') stack.push({ cur: 'dead', taken: 'yes', parentDead: true });
      else {
        let d;
        if (name === 'if') d = decide(rest, state, ctx);
        else {
          const id = /^[A-Za-z_]\w*/.exec(rest);
          d = id ? decideDefined(id[0], state, ctx) : { value: UNKNOWN, basis: null };
          if (name === 'ifndef' && d.value !== UNKNOWN) d = { ...d, value: !d.value };
        }
        const cur = d.value === UNKNOWN ? 'maybe' : (d.value ? 'live' : 'dead');
        stack.push({ cur, taken: cur === 'live' ? 'yes' : cur === 'maybe' ? 'maybe' : 'no', parentDead: false });
        if (d.value === UNKNOWN) note('undecided', d.value, null); else note('decided', d.value, d.basis);
      }
    } else if (name === 'elif' || name === 'else') {
      const f = stack[stack.length - 1];
      if (f && !f.parentDead) {
        let c;
        let basis = null;
        if (name === 'else') c = true;
        else if (f.taken === 'yes') c = false;   // an earlier branch was taken for certain: this one is dead whatever it says
        else { const d = decide(rest, state, ctx); c = d.value; basis = d.basis; }
        let cur;
        if (f.taken === 'yes' || c === false) cur = 'dead';
        else if (c === true) cur = f.taken === 'no' ? 'live' : 'maybe';
        else cur = 'maybe';
        if (cur === 'live') f.taken = 'yes'; else if (cur === 'maybe' && f.taken === 'no') f.taken = 'maybe';
        f.cur = cur;
        if (name === 'elif' && f.taken !== 'yes') { if (c === UNKNOWN) note('undecided', c, null); else note('decided', c, basis); }
      }
    } else if (name === 'endif') {
      stack.pop();
    } else if (name === 'define' || name === 'undef') {
      const m = /^([A-Za-z_]\w*)(\()?\s*(.*)$/.exec(rest);
      if (m && parentRegion !== 'dead') {
        const maybe = parentRegion === 'maybe';
        if (name === 'undef') state.macros.set(m[1], { state: maybe ? 'maybe' : 'undefined', value: '', fn: false });
        else state.macros.set(m[1], { state: maybe ? 'maybe' : 'defined', value: m[2] ? '' : m[3].replace(/\\\s*$/, '').trim(), fn: !!m[2] });
      }
    }
    // the directive lines themselves are always blanked by the caller; mark whether they sat in a possible region
    const rg = region();
    void rg;
    for (let q = i; q <= last; q++) maybeDepth[q + 1] = maybeCount();
    i = last;
  }
  return { lines: out, maybeDepth, decided, undecided, deadLines, unbalanced: stack.length > 0 };
}
