// Pure pieces of the bounded NixOS option evaluator (NIX-002): value classes, equality, and the
// closed table of library functions the evaluator is willing to run.
//
// The evaluator (nixos-module-resolver.js) is a SOUNDNESS-first subset: a value is either fully known
// or unknown, and any unknown part makes the whole value unknown. This file is the allow-list. A
// function that is not in these tables is never run, so `import`, `fetch*`, `readFile`, `toFile`,
// `currentSystem`, `getEnv`, derivations and every other effectful or environment-dependent primitive
// are unknown by construction (there is no deny-list to forget an entry in).

/** Thrown by a table function (and caught by the resolver) when its arguments are not statically usable. */
export const NOT_STATIC = Object.freeze({ notStatic: true });

/** A lambda captured with its definition environment. Never a final option value. */
export class Closure {
  constructor(param, body, env) { this.param = param; this.body = body; this.env = env; }
}

/** A table function, possibly partially applied. Never a final option value. */
export class Builtin {
  constructor(name, def, args = []) { this.name = name; this.def = def; this.args = args; }
}

/** A namespace value (`lib`, `builtins`, `lib.strings`, `lib.lists`). Never a final option value. */
export class Ns {
  constructor(kind) { this.kind = kind; }
}

export const isAttrs = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
export const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isInt = (v) => typeof v === 'number' && Number.isSafeInteger(v);

/** Own-property assignment that is safe for the attribute name `__proto__`. */
export function setAttr(obj, key, value) {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/** True when a value contains only data (no closure, partial application or namespace). Bounded. */
export function isPlain(v, budget = { n: 20_000 }, depth = 0) {
  if (--budget.n < 0 || depth > 48) return false;
  if (v === null || typeof v === 'string' || typeof v === 'boolean' || typeof v === 'number') return true;
  if (Array.isArray(v)) return v.every((x) => isPlain(x, budget, depth + 1));
  if (isAttrs(v)) return Object.keys(v).every((k) => isPlain(v[k], budget, depth + 1));
  return false;
}

/** Nix `==`: true, false, or null when it cannot be decided statically (functions are never compared). */
export function deepEq(a, b, depth = 0) {
  if (depth > 48) return null;
  const fnA = a instanceof Closure || a instanceof Builtin || a instanceof Ns;
  const fnB = b instanceof Closure || b instanceof Builtin || b instanceof Ns;
  if (fnA || fnB) return null;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    if (a.length !== b.length) return false;
    let unknown = false;
    for (let i = 0; i < a.length; i++) { const r = deepEq(a[i], b[i], depth + 1); if (r === false) return false; if (r === null) unknown = true; }
    return unknown ? null : true;
  }
  if (isAttrs(a) || isAttrs(b)) {
    if (!isAttrs(a) || !isAttrs(b)) return false;
    const ka = Object.keys(a); const kb = Object.keys(b);
    if (ka.length !== kb.length || !ka.every((k) => hasOwn(b, k))) return false;
    let unknown = false;
    for (const k of ka) { const r = deepEq(a[k], b[k], depth + 1); if (r === false) return false; if (r === null) unknown = true; }
    return unknown ? null : true;
  }
  return a === b;
}

const need = (cond) => { if (!cond) throw NOT_STATIC; };
const MAX_STRING = 65_536;

function toStr(v) {
  if (typeof v === 'string') return v;
  if (v === null || v === false) return '';
  if (v === true) return '1';
  if (isInt(v)) return String(v);
  throw NOT_STATIC;
}

// Each entry: arity and a function over the evaluated arguments. `c.apply(f, x)` runs a closure or table
// function and throws NOT_STATIC if it is not statically known; `c.size(n)` enforces the size cap.
const DEFS = {
  map: { arity: 2, call: ([f, xs], c) => { need(Array.isArray(xs)); c.size(xs.length); return xs.map((x) => c.apply(f, x)); } },
  filter: {
    arity: 2,
    call: ([f, xs], c) => { need(Array.isArray(xs)); c.size(xs.length); return xs.filter((x) => { const r = c.apply(f, x); need(typeof r === 'boolean'); return r; }); },
  },
  elem: {
    arity: 2,
    call: ([x, xs]) => {
      need(Array.isArray(xs));
      let unknown = false;
      for (const y of xs) { const r = deepEq(x, y); if (r === true) return true; if (r === null) unknown = true; }
      need(!unknown);
      return false;
    },
  },
  length: { arity: 1, call: ([xs]) => { need(Array.isArray(xs)); return xs.length; } },
  concatLists: {
    arity: 1,
    call: ([xss], c) => { need(Array.isArray(xss) && xss.every(Array.isArray)); const out = [].concat(...xss); c.size(out.length); return out; },
  },
  concatMap: {
    arity: 2,
    call: ([f, xs], c) => {
      need(Array.isArray(xs)); c.size(xs.length);
      const parts = xs.map((x) => { const r = c.apply(f, x); need(Array.isArray(r)); return r; });
      const out = [].concat(...parts); c.size(out.length); return out;
    },
  },
  hasAttr: { arity: 2, call: ([name, set]) => { need(typeof name === 'string' && isAttrs(set)); return hasOwn(set, name); } },
  toString: { arity: 1, call: ([v]) => toStr(v) },
  optionals: { arity: 2, call: ([cond, xs]) => { need(typeof cond === 'boolean' && Array.isArray(xs)); return cond ? xs : []; } },
  optional: { arity: 2, call: ([cond, x]) => { need(typeof cond === 'boolean'); return cond ? [x] : []; } },
  optionalAttrs: { arity: 2, call: ([cond, set]) => { need(typeof cond === 'boolean' && isAttrs(set)); return cond ? set : {}; } },
  optionalString: { arity: 2, call: ([cond, s]) => { need(typeof cond === 'boolean' && typeof s === 'string'); return cond ? s : ''; } },
  concatStringsSep: {
    arity: 2,
    call: ([sep, xs], c) => {
      need(typeof sep === 'string' && Array.isArray(xs) && xs.every((x) => typeof x === 'string')); c.size(xs.length);
      const out = xs.join(sep); need(out.length <= MAX_STRING); return out;
    },
  },
  concatMapStringsSep: {
    arity: 3,
    call: ([sep, f, xs], c) => {
      need(typeof sep === 'string' && Array.isArray(xs)); c.size(xs.length);
      const parts = xs.map((x) => { const r = c.apply(f, x); need(typeof r === 'string'); return r; });
      const out = parts.join(sep); need(out.length <= MAX_STRING); return out;
    },
  },
  hasPrefix: { arity: 2, call: ([p, s]) => { need(typeof p === 'string' && typeof s === 'string'); return s.startsWith(p); } },
  hasSuffix: { arity: 2, call: ([p, s]) => { need(typeof p === 'string' && typeof s === 'string'); return s.endsWith(p); } },
  boolToString: { arity: 1, call: ([b]) => { need(typeof b === 'boolean'); return b ? 'true' : 'false'; } },
  // Only a merge of plain lists is a plain list; any other element (an attribute set, a priority or condition
  // wrapper, an unknown) cannot be merged without the option's type, so it is not static.
  mkMerge: { arity: 1, call: ([xss], c) => { need(Array.isArray(xss) && xss.every(Array.isArray)); const out = [].concat(...xss); c.size(out.length); return out; } },
};

const LIB_NAMES = new Set(['map', 'filter', 'elem', 'length', 'concatLists', 'concatMap', 'optionals', 'optional', 'optionalAttrs', 'optionalString',
  'concatStringsSep', 'concatMapStringsSep', 'hasPrefix', 'hasSuffix', 'boolToString', 'mkMerge']);
const LIB_STRINGS = new Set(['concatStringsSep', 'concatMapStringsSep', 'hasPrefix', 'hasSuffix', 'optionalString']);
const LIB_LISTS = new Set(['map', 'filter', 'elem', 'length', 'concatLists', 'concatMap', 'optionals', 'optional']);
const BUILTIN_NAMES = new Set(['map', 'filter', 'elem', 'length', 'concatLists', 'concatMap', 'hasAttr', 'toString']);
/** Names a Nix program has without any import (the ones we model). */
const GLOBAL_NAMES = new Set(['map', 'toString']);

const SETS = { lib: LIB_NAMES, builtins: BUILTIN_NAMES, 'lib.strings': LIB_STRINGS, 'lib.lists': LIB_LISTS };

/** Resolves `<ns>.<name>`: a table function, a sub-namespace, or undefined (not modelled). */
export function nsLookup(kind, name) {
  if (kind === 'lib' && name === 'strings') return new Ns('lib.strings');
  if (kind === 'lib' && name === 'lists') return new Ns('lib.lists');
  const set = SETS[kind];
  if (!set || !set.has(name)) return undefined;
  return new Builtin(name, DEFS[name]);
}

export const isGlobalName = (name) => GLOBAL_NAMES.has(name);
export const globalValue = (name) => (name === 'builtins' ? new Ns('builtins') : nsLookup('builtins', name));
export const MODELLED = Object.freeze({ lib: [...LIB_NAMES].sort(), builtins: [...BUILTIN_NAMES].sort() });
