// Declared option types, read from the module sources that are in scope.
//
// A NixOS or Home Manager option is declared with `mkOption { type = ...; }`
// (or `mkEnableOption`, `mkPackageOption`). The module system checks a value
// against that type before the module's `config` is used, so the TYPE bounds
// what a reference to the option can contain, whatever the name suggests:
//
//   bool, int, ints.*, port, float, number   digits, `0`/`1`, a sign or a dot
//   package, shellPackage                    a store path (`/nix/store/<hash>-<name>`),
//                                            whose name part is restricted by Nix to
//                                            [A-Za-z0-9+._?=-]
//   enum [ "a" "b" ]                         one of the listed literals
//   nullOr T, either A B, uniq T             only when every member is itself bounded
//
// `str`, `path`, `lines`, `attrs`, `listOf`, `submodule`, an unknown or computed
// type are all UNBOUNDED here: they can carry any characters, so nothing is
// inferred from them.
//
// Two consumers use the answer in opposite directions, and both are sound for
// the same reason:
//   * the script-injection analysis treats a reference to a bounded option as
//     a constant, because no value of that type contains a shell metacharacter;
//   * the secret analysis does not treat a reference to a bounded option as a
//     credential, because a bool, a number, a package path or a choice among
//     listed words does not hold a secret, whatever the option is called
//     (`cacheCredentials`, `forwardPass`, `wheelNeedsPassword`).
//
// Only options DECLARED in the files handed to the analyzer are known. An
// option declared elsewhere (upstream NixOS) has no entry, so it keeps the
// previous behaviour: unknown stays conservative.

const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };
const segName = (s) => (s && s.kind === 'static' ? s.name : null);
const attrKey = (path) => (path || []).map(segName);

const BOUNDED_LEAF = new Set(['bool', 'int', 'float', 'number', 'port', 'package', 'shellPackage', 'unsigned', 'positive', 'u8', 'u16', 'u32', 's8', 's16', 's32', 'between']);
const BOUNDED_NAMESPACES = new Set(['ints', 'numbers']);
const SAFE_ENUM_MEMBER = /^[A-Za-z0-9_.+-]*$/;

function flatten(n) {
  const args = []; let fn = unparen(n);
  while (fn && fn.type === 'app') { args.unshift(fn.arg); fn = unparen(fn.fn); }
  return { fn, args };
}

function calleeName(fn) {
  const f = unparen(fn);
  if (!f) return null;
  if (f.type === 'ident') return f.name;
  if (f.type === 'select') { const segs = f.attrpath.map(segName); return segs[segs.length - 1] || null; }
  return null;
}

function selectSegments(n) {
  const segs = n.attrpath.map(segName);
  return segs.every((s) => s !== null) ? segs : null;
}

/** Classify a `type = ...` expression. Returns { kind, bounded }. */
export function classifyOptionType(expr, depth = 0) {
  const n = unparen(expr);
  if (!n || depth > 8) return { kind: 'unknown', bounded: false };
  if (n.type === 'ident') return { kind: n.name, bounded: BOUNDED_LEAF.has(n.name) };
  if (n.type === 'select') {
    const segs = selectSegments(n);
    if (!segs) return { kind: 'unknown', bounded: false };
    const last = segs[segs.length - 1];
    if (segs.some((s) => BOUNDED_NAMESPACES.has(s))) return { kind: `${segs.slice(-2).join('.')}`, bounded: true };
    return { kind: last, bounded: BOUNDED_LEAF.has(last) };
  }
  if (n.type === 'app') {
    const { fn, args } = flatten(n);
    const name = calleeName(fn);
    const fnSel = unparen(fn);
    if (fnSel && fnSel.type === 'select') {
      const segs = selectSegments(fnSel);
      if (segs && segs.some((s) => BOUNDED_NAMESPACES.has(s))) return { kind: segs.slice(-2).join('.'), bounded: true };
    }
    if (name === 'nullOr' || name === 'uniq' || name === 'unique') return args[0] ? classifyOptionType(args[0], depth + 1) : { kind: name, bounded: false };
    if (name === 'either') {
      const parts = args.slice(0, 2).map((a) => classifyOptionType(a, depth + 1));
      return { kind: 'either', bounded: parts.length === 2 && parts.every((p) => p.bounded) };
    }
    if (name === 'enum') {
      const list = unparen(args[0]);
      if (list && list.type === 'list') {
        const members = list.items.map((i) => unparen(i));
        const ok = members.length > 0 && members.every((m) => m && m.type === 'string' && !m.interpolated && SAFE_ENUM_MEMBER.test(m.literal || ''));
        return { kind: 'enum', bounded: ok };
      }
      return { kind: 'enum', bounded: false };
    }
    return { kind: name || 'unknown', bounded: false };
  }
  return { kind: 'unknown', bounded: false };
}

function declarationOf(valueNode) {
  const v = unparen(valueNode);
  if (!v || v.type !== 'app') return null;
  const { fn, args } = flatten(v);
  const name = calleeName(fn);
  if (name === 'mkEnableOption') return { kind: 'bool', bounded: true };
  if (name === 'mkPackageOption' || name === 'mkPackageOptionMD') return { kind: 'package', bounded: true };
  if (name === 'mkOption') {
    const a = unparen(args[0]);
    if (!a || a.type !== 'attrset') return { kind: 'unknown', bounded: false };
    for (const b of a.bindings || []) {
      if (b.kind !== 'attr') continue;
      const k = attrKey(b.path);
      if (k.length === 1 && k[0] === 'type') return classifyOptionType(b.value);
    }
    return { kind: 'untyped', bounded: false };
  }
  return null;
}

function record(index, key, decl) {
  const prev = index.get(key);
  // two declarations of one option: bounded only if every declaration is
  index.set(key, prev ? { kind: prev.kind, bounded: prev.bounded && decl.bounded } : decl);
}

function collect(node, prefix, index, depth) {
  if (!node || typeof node !== 'object' || depth > 200) return;
  if (Array.isArray(node)) { for (const x of node) collect(x, prefix, index, depth + 1); return; }
  if (node.type === 'attrset') {
    for (const b of node.bindings || []) {
      if (b.kind !== 'attr' || !b.value) continue;
      const keys = attrKey(b.path);
      if (keys.some((k) => k === null)) { collect(b.value, null, index, depth + 1); continue; }
      let full = null;
      if (prefix !== null) full = [...prefix, ...keys];
      else if (keys[0] === 'options') full = keys.slice(1);
      if (full === null) { collect(b.value, null, index, depth + 1); continue; }
      const decl = full.length ? declarationOf(b.value) : null;
      if (decl) { record(index, full.join('.'), decl); continue; }
      const v = unparen(b.value);
      if (v && v.type === 'attrset') collect(v, full, index, depth + 1);
      else collect(b.value, null, index, depth + 1);
    }
    return;
  }
  for (const [k, c] of Object.entries(node)) {
    if (k === 'span' || k === 'loc') continue;
    if (c && typeof c === 'object') collect(c, prefix === null ? null : null, index, depth + 1);
  }
}

/**
 * Index every option declared in the parsed files: dotted path -> { kind, bounded }.
 * `parsed` is an iterable of ASTs.
 */
export function buildOptionTypeIndex(parsed) {
  const index = new Map();
  for (const ast of parsed) collect(ast, null, index, 0);
  return index;
}

/**
 * Is the option behind an origin detail (`option config.a.b.c`) declared with a
 * bounded type? Returns the declaration, or null when it is unknown or unbounded.
 */
export function boundedOptionFor(index, detail) {
  if (!index || typeof detail !== 'string') return null;
  const m = /^option (?:config|osConfig)\.(.+)$/.exec(detail);
  if (!m) return null;
  const d = index.get(m[1]);
  return d && d.bounded ? d : null;
}
