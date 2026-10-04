// Haskell declared-manifest parsers (HS-007).
//
// Static only: .cabal, cabal.project, cabal.project.freeze, package.yaml (Hpack),
// stack.yaml and stack.yaml.lock are READ as text. No solver, no `cabal`/`stack`/
// `hpack` process, no Setup.hs, no network. Everything here is a DECLARATION:
//
//   * a version bound (`>=4 && <5`) is never reported as an installed version;
//     `resolvedVersion` is always null on a declared dependency;
//   * only a lock-shaped source (cabal.project.freeze `==x.y.z`, stack.yaml.lock,
//     a pinned stack extra-dep) populates `lockedPackages`;
//   * a Stack snapshot selector (lts-22.10) is recorded as a selector. Its package
//     set needs the snapshot file, which we do not fetch, so it is `resolved:false`;
//   * constraints we cannot parse are preserved with their raw text and a
//     diagnostic instead of being dropped.
//
// Every parser is bounded by MANIFEST_BUDGETS and returns diagnostics rather than
// throwing on malformed input.
import { redactUrlsDeep } from './secrets.js';
import fs from 'node:fs';
import path from 'node:path';
import { load as yamlLoad, CORE_SCHEMA } from '../util/yaml.js';
import { isLanguageExcludedPath } from './discovery.js';

export const MANIFEST_SCHEMA_VERSION = 1;

export const MANIFEST_BUDGETS = Object.freeze({
  maxBytes: 2 * 1024 * 1024,
  maxLines: 40000,
  maxDepth: 48,
  maxNodes: 50000,
  maxFiles: 2000,
  maxImportDepth: 4,
  maxRangeTokens: 1000,
  maxRangeDepth: 64,
});

function budgetsOf(opts) {
  return { ...MANIFEST_BUDGETS, ...(opts && opts.budgets ? opts.budgets : {}) };
}

function diag(kind, message, file, line, severity = 'warning', extra = {}) {
  return { kind, severity, message, file: file || null, line: Number.isInteger(line) ? line : null, ...extra };
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// ---------------------------------------------------------------------------
// Version ranges
// ---------------------------------------------------------------------------

/** Parse "1.2.3.4.5" into BigInt components (any length). Null when not a version. */
export function parseVersion(text) {
  if (typeof text !== 'string' || text.length > 256 || !/^\d+(?:\.\d+)*$/.test(text)) return null;
  return text.split('.').map((p) => BigInt(p));
}

function asVersion(v) {
  if (Array.isArray(v)) return v;
  const p = parseVersion(v);
  if (!p) throw new TypeError(`not a version: ${String(v)}`);
  return p;
}

/** Haskell (PVP) ordering: component-wise, missing trailing components are 0. */
export function compareVersions(a, b) {
  const x = asVersion(a);
  const y = asVersion(b);
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const p = x[i] ?? 0n;
    const q = y[i] ?? 0n;
    if (p < q) return -1;
    if (p > q) return 1;
  }
  return 0;
}

const RANGE_TOKEN = /\s*(\|\||&&|\^>=|>=|<=|==|<|>|\(|\)|-any\b|-none\b|\d+(?:\.\d+)*(?:\.\*)?)/y;
const CMP_OPS = new Set(['>=', '>', '<=', '<', '==', '^>=']);

function tokenizeRange(text, budgets) {
  const src = text.trim();
  const toks = [];
  let pos = 0;
  while (pos < src.length) {
    RANGE_TOKEN.lastIndex = pos;
    const m = RANGE_TOKEN.exec(src);
    if (!m) throw new SyntaxError(`unexpected text '${src.slice(pos, pos + 12).trim()}' in version range`);
    toks.push(m[1]);
    pos = RANGE_TOKEN.lastIndex;
    if (toks.length > budgets.maxRangeTokens) throw new RangeError('version range exceeds token budget');
  }
  return toks;
}

/**
 * Parse a Cabal/Hpack version range. Returns {ok:true, ast, text} or
 * {ok:false, error, text}; never throws. `&&` binds tighter than `||`.
 * AST nodes: any | none | cmp{op,version,wildcard} | and{l,r} | or{l,r}.
 */
export function parseVersionRange(text, opts = {}) {
  const budgets = budgetsOf(opts);
  const raw = typeof text === 'string' ? text : '';
  if (raw.trim() === '') return { ok: true, ast: { t: 'any' }, text: raw, implicit: true };
  try {
    const toks = tokenizeRange(raw, budgets);
    let i = 0;
    const atom = (d) => {
      const t = toks[i++];
      if (t === undefined) throw new SyntaxError('unexpected end of version range');
      if (t === '(') {
        const e = expr(d + 1);
        if (toks[i++] !== ')') throw new SyntaxError("missing ')' in version range");
        return e;
      }
      if (t === '-any') return { t: 'any' };
      if (t === '-none') return { t: 'none' };
      if (CMP_OPS.has(t)) {
        const v = toks[i++];
        if (v === undefined || !/^\d/.test(v)) throw new SyntaxError(`operator '${t}' needs a version`);
        const wildcard = v.endsWith('.*');
        if (wildcard && t !== '==') throw new SyntaxError(`wildcard version only valid after '==', got '${t}'`);
        return { t: 'cmp', op: t, version: parseVersion(wildcard ? v.slice(0, -2) : v), wildcard, text: v };
      }
      throw new SyntaxError(`unexpected token '${t}' in version range`);
    };
    const and = (d) => {
      let l = atom(d);
      while (toks[i] === '&&') { i++; l = { t: 'and', l, r: atom(d) }; }
      return l;
    };
    const expr = (d) => {
      if (d > budgets.maxRangeDepth) throw new RangeError('version range nested too deeply');
      let l = and(d);
      while (toks[i] === '||') { i++; l = { t: 'or', l, r: and(d) }; }
      return l;
    };
    const ast = expr(0);
    if (i < toks.length) throw new SyntaxError(`unexpected token '${toks[i]}' in version range`);
    return { ok: true, ast, text: raw };
  } catch (e) {
    return { ok: false, error: e.message, text: raw };
  }
}

/** Upper bound of a caret range: ^>=1.2.3 is <1.3, ^>=1 is <1.1 (Cabal's majorUpperBound). */
export function caretUpperBound(version) {
  const v = asVersion(version);
  return v.length < 2 ? [v[0], 1n] : [v[0], v[1] + 1n];
}

function evalRange(n, v) {
  switch (n.t) {
    case 'any': return true;
    case 'none': return false;
    case 'and': return evalRange(n.l, v) && evalRange(n.r, v);
    case 'or': return evalRange(n.l, v) || evalRange(n.r, v);
    case 'cmp': {
      const c = compareVersions(v, n.version);
      switch (n.op) {
        case '>=': return c >= 0;
        case '>': return c > 0;
        case '<=': return c <= 0;
        case '<': return c < 0;
        case '==':
          if (n.wildcard) return n.version.every((p, i) => (v[i] ?? 0n) === p);
          return c === 0;
        case '^>=': return c >= 0 && compareVersions(v, caretUpperBound(n.version)) < 0;
        default: return false;
      }
    }
    default: return false;
  }
}

/** True when `version` (string) is inside `range` (string or a parseVersionRange result). */
export function versionSatisfies(range, version) {
  const r = typeof range === 'string' ? parseVersionRange(range) : range;
  if (!r || !r.ok) throw new SyntaxError(r && r.error ? r.error : 'invalid version range');
  return evalRange(r.ast, asVersion(version));
}

/** 'exact' for a single `==x.y.z`, 'unbounded' for any, 'none', otherwise 'bounded'. */
export function rangeKind(ast) {
  if (!ast) return 'unparsed';
  if (ast.t === 'any') return 'unbounded';
  if (ast.t === 'none') return 'none';
  if (ast.t === 'cmp' && ast.op === '==' && !ast.wildcard) return 'exact';
  return 'bounded';
}

// ---------------------------------------------------------------------------
// Cabal-style layout: lines -> indentation tree
// ---------------------------------------------------------------------------

const FIELD = /^([A-Za-z][A-Za-z0-9_.-]*)\s*:(.*)$/;
const DEP = /^([A-Za-z0-9][A-Za-z0-9-]*)(?::(?:\{([^}]*)\}|([A-Za-z0-9][A-Za-z0-9_-]*)))?\s*(.*)$/s;

function indentOf(raw) {
  let n = 0;
  for (const ch of raw) {
    if (ch === ' ') n += 1;
    else if (ch === '\t') n += 8 - (n % 8);
    else break;
  }
  return n;
}

function lexLines(text, budgets, diagnostics, file) {
  let src = typeof text === 'string' ? text : '';
  if (src.length > budgets.maxBytes) {
    diagnostics.push(diag('budget_exceeded', `manifest larger than ${budgets.maxBytes} bytes; remainder not read`, file, null));
    src = src.slice(0, budgets.maxBytes);
  }
  const raw = src.replace(/^﻿/, '').split(/\r\n|\r|\n/);
  const limit = Math.min(raw.length, budgets.maxLines);
  if (raw.length > limit) diagnostics.push(diag('budget_exceeded', `manifest has more than ${limit} lines; remainder not read`, file, limit));
  const out = [];
  for (let i = 0; i < limit; i++) {
    const r = raw[i];
    const t = r.trim();
    if (!t) continue;
    // `--sha256: <hash>` inside a source-repository-package is a comment by
    // syntax but carries the content hash; keep it as a field.
    const sha = /^--\s*sha256:\s*(\S+)/.exec(t);
    if (sha) { out.push({ n: i + 1, indent: indentOf(r), raw: r, text: `sha256: ${sha[1]}`, fromComment: true }); continue; }
    if (t.startsWith('--')) continue;
    out.push({ n: i + 1, indent: indentOf(r), raw: r, text: t });
  }
  return out;
}

function buildTree(lines, budgets, diagnostics, file) {
  const root = { indent: -1, children: [] };
  const stack = [root];
  let warned = false;
  for (const ln of lines) {
    while (stack.length > 1 && ln.indent <= stack[stack.length - 1].indent) stack.pop();
    const node = { line: ln, indent: ln.indent, children: [] };
    stack[stack.length - 1].children.push(node);
    if (stack.length <= budgets.maxDepth) stack.push(node);
    else if (!warned) { warned = true; diagnostics.push(diag('budget_exceeded', `indentation deeper than ${budgets.maxDepth}; nesting flattened`, file, ln.n)); }
  }
  return root;
}

function* descendants(node) {
  for (const c of node.children) { yield c; yield* descendants(c); }
}

/** Field value text across continuation lines, with offset -> (line, column) marks. */
function fieldValue(node) {
  const first = node.line;
  let text = '';
  const marks = [];
  const add = (s, line, col) => { marks.push({ offset: text.length, line, col }); text += `${s}\n`; };
  if (first.fromComment) {
    add(first.text.slice(first.text.indexOf(':') + 1).trim(), first.n, 0);
  } else {
    const ci = first.raw.indexOf(':');
    const rest = first.raw.slice(ci + 1);
    add(rest.trim(), first.n, ci + 1 + (rest.length - rest.trimStart().length));
  }
  for (const d of descendants(node)) {
    add(d.line.text, d.line.n, d.line.raw.length - d.line.raw.trimStart().length);
  }
  return { text, marks, line: first.n, column: marks[0].col };
}

function locate(val, offset) {
  let m = val.marks[0];
  for (const k of val.marks) { if (k.offset <= offset) m = k; else break; }
  return { line: m.line, column: m.col + (offset - m.offset) };
}

/** Split on top-level commas (outside parens/braces); pieces keep their text offset. */
function splitCommas(text) {
  const out = [];
  let depth = 0;
  let start = 0;
  const push = (end) => {
    const seg = text.slice(start, end);
    const t = seg.trim();
    if (t) out.push({ text: t.replace(/\s+/g, ' '), offset: start + (seg.length - seg.trimStart().length) });
  };
  for (let i = 0; i <= text.length; i++) {
    const c = text[i];
    if (c === '(' || c === '{') depth++;
    else if (c === ')' || c === '}') depth = Math.max(0, depth - 1);
    if (i === text.length || (c === ',' && depth === 0)) { push(i); start = i + 1; }
  }
  return out;
}

/** Whitespace/comma separated words honouring double quotes. */
function splitWords(text) {
  const out = [];
  const re = /"([^"]*)"|([^\s,]+)/g;
  let m;
  while ((m = re.exec(text)) !== null) out.push({ text: m[1] !== undefined ? m[1] : m[2], offset: m.index });
  return out;
}

function flagRefsOf(cond) {
  const out = [];
  const re = /flag\(\s*([^)\s]+)\s*\)/g;
  let m;
  while ((m = re.exec(cond)) !== null) out.push(m[1]);
  return out;
}

function makeDep(parsed, ctx) {
  const rr = parseVersionRange(parsed.rangeText);
  return {
    name: parsed.name,
    sublibrary: parsed.sublibrary || null,
    declaredRange: parsed.rangeText === '' ? null : parsed.rangeText,
    rangeKind: rr.ok ? rangeKind(rr.ast) : 'unparsed',
    range: rr.ok ? rr.ast : null,
    rangeError: rr.ok ? null : rr.error,
    // A bound is a declaration. It is never an installed or resolved version.
    resolvedVersion: null,
    exactPin: rr.ok && rr.ast.t === 'cmp' && rr.ast.op === '==' && !rr.ast.wildcard ? rr.ast.text : null,
    field: ctx.field,
    scopeOverride: ctx.scopeOverride || null,
    conditions: ctx.conds.slice(),
    flagRefs: [...new Set(ctx.conds.flatMap(flagRefsOf))],
    line: ctx.line,
    column: ctx.column,
    locationKind: ctx.locationKind || 'exact',
  };
}

function parseDepPiece(text) {
  const m = DEP.exec(text);
  if (!m) return null;
  const subs = m[2] !== undefined ? m[2].split(',').map((s) => s.trim()).filter(Boolean) : (m[3] ? [m[3]] : [null]);
  return subs.map((sublibrary) => ({ name: m[1], sublibrary, rangeText: m[4].trim() }));
}

function scanGhcOptions(text, locFor, sink) {
  const re = /\S+/g;
  const toks = [];
  let m;
  while ((m = re.exec(text)) !== null) toks.push({ t: m[0], index: m.index });
  for (let i = 0; i < toks.length; i++) {
    const { t, index } = toks[i];
    let mm;
    if ((mm = /^-fplugin=(.+)$/.exec(t))) sink('ghc-plugin', `-fplugin=${mm[1]}`, index);
    else if (/^-(?:f)?plugin-package(?:-id)?(?:=.*)?$/.test(t)) sink('ghc-plugin-package', t, index);
    else if (t === '-F') sink('ghc-preprocessor', '-F', index);
    else if (/^-pgm[A-Za-z]+$/.test(t)) sink('ghc-program-override', `${t} ${toks[i + 1] ? toks[i + 1].t : ''}`.trim(), index);
  }
  void locFor;
}

// ---------------------------------------------------------------------------
// .cabal
// ---------------------------------------------------------------------------

const HEADER = /^(library|executable|test-suite|benchmark|foreign-library|common|flag|source-repository|custom-setup)\b\s*(.*)$/i;
const SCOPE_OF = { library: 'runtime', executable: 'runtime', 'foreign-library': 'runtime', 'test-suite': 'test', benchmark: 'benchmark', 'custom-setup': 'setup', common: 'runtime' };

function detectGenerated(text) {
  const head = String(text).slice(0, 4000);
  const g = /generated from (\S+) by hpack version (\d+(?:\.\d+)*)/i.exec(head);
  if (!g) return { generatedBy: null };
  const h = /^--\s*hash:\s*([0-9a-f]{64})/im.exec(head);
  return { generatedBy: 'hpack', source: g[1], hpackVersion: g[2], hash: h ? h[1] : null, hashVerified: false };
}

function newStanza(kind, name, line, scope) {
  return { kind, name, scope, line, deps: [], imports: [], surfaces: [], flagRefs: [], fields: {} };
}

function handleCabalField(st, name, node, conds, file) {
  const val = fieldValue(node);
  const addDeps = (field, scopeOverride) => {
    for (const piece of splitCommas(val.text)) {
      const parsed = parseDepPiece(piece.text);
      if (!parsed) { st.problems.push(diag('malformed_dependency', `cannot read dependency '${piece.text}'`, file, locate(val, piece.offset).line)); continue; }
      const loc = locate(val, piece.offset);
      for (const p of parsed) {
        const d = makeDep(p, { field, scopeOverride, conds, line: loc.line, column: loc.column });
        if (d.rangeError) st.problems.push(diag('invalid_version_range', `${p.name}: ${d.rangeError}`, file, loc.line, 'warning', { rangeText: p.rangeText }));
        st.deps.push(d);
        if (scopeOverride === 'build-tool') st.surfaces.push({ kind: 'build-tool-depends', detail: `${p.name}${p.sublibrary ? `:${p.sublibrary}` : ''} ${p.rangeText}`.trim(), file, line: loc.line, column: loc.column });
      }
    }
  };
  switch (name) {
    case 'build-depends': addDeps('build-depends', null); break;
    case 'setup-depends': addDeps('setup-depends', 'setup'); break;
    case 'build-tool-depends': addDeps('build-tool-depends', 'build-tool'); break;
    case 'build-tools': addDeps('build-tools', 'build-tool'); break;
    case 'import':
      for (const w of splitWords(val.text)) st.imports.push({ name: w.text, line: locate(val, w.offset).line });
      break;
    case 'ghc-options': case 'ghc-prof-options': case 'ghc-shared-options':
      scanGhcOptions(val.text, null, (kind, detail, idx) => {
        const loc = locate(val, idx);
        st.surfaces.push({ kind, detail, file, line: loc.line, column: loc.column });
      });
      break;
    case 'hs-source-dirs': case 'main-is': st.fields[name] = val.text.trim(); break;
    default: break;
  }
}

function walkCabalBody(children, st, conds, file, depth, budgets) {
  if (depth > budgets.maxDepth) return;
  let prev = [];
  for (const node of children) {
    const t = node.line.text;
    const fm = FIELD.exec(t);
    if (fm) { prev = []; handleCabalField(st, fm[1].toLowerCase(), node, conds, file); continue; }
    const cm = /^(if|elif|else)\b\s*(.*)$/i.exec(t);
    if (!cm) continue;
    const kw = cm[1].toLowerCase();
    const negs = prev.map((p) => `!(${p})`);
    let next;
    if (kw === 'if') { prev = [cm[2]]; next = [...conds, cm[2]]; }
    else if (kw === 'elif') { next = [...conds, ...negs, cm[2]]; prev.push(cm[2]); }
    else { next = [...conds, ...negs]; prev = []; }
    for (const r of flagRefsOf(cm[2])) st.flagRefs.push({ flag: r, line: node.line.n });
    walkCabalBody(node.children, st, next, file, depth + 1, budgets);
  }
}

/** Parse one .cabal file into a package model. Never throws. */
export function parseCabalFile(text, opts = {}) {
  const file = opts.file || 'package.cabal';
  const budgets = budgetsOf(opts);
  const diagnostics = [];
  const provenance = detectGenerated(text);
  const lines = lexLines(text, budgets, diagnostics, file);
  const tree = buildTree(lines, budgets, diagnostics, file);

  const pkg = { name: null, version: null, buildType: null, cabalVersion: null };
  const topSurfaces = [];
  const stanzas = [];
  const commons = {};
  const flags = [];
  const sourceRepositories = [];

  for (const node of tree.children) {
    const t = node.line.text;
    const fm = FIELD.exec(t);
    if (fm) {
      const name = fm[1].toLowerCase();
      const val = fieldValue(node);
      const v = val.text.trim();
      if (name === 'name') pkg.name = v;
      else if (name === 'version') pkg.version = v;
      else if (name === 'cabal-version') pkg.cabalVersion = v;
      else if (name === 'build-type') {
        pkg.buildType = v;
        if (/^(custom|configure|make)$/i.test(v)) topSurfaces.push({ kind: `build-type-${v.toLowerCase()}`, detail: `build-type: ${v}`, file, line: val.line, column: val.column });
      }
      continue;
    }
    const hm = HEADER.exec(t);
    if (!hm) { diagnostics.push(diag('unrecognized_line', `unrecognized top-level line '${t.slice(0, 60)}'`, file, node.line.n, 'info')); continue; }
    const kind = hm[1].toLowerCase();
    const arg = hm[2].trim();
    if (kind === 'flag') {
      const f = { package: null, name: arg, default: true, defaultDeclared: false, manual: false, file, line: node.line.n };
      for (const c of node.children) {
        const cf = FIELD.exec(c.line.text);
        if (!cf) continue;
        const fname = cf[1].toLowerCase();
        const v = fieldValue(c).text.trim().toLowerCase();
        if (fname === 'default') { f.default = v === 'true'; f.defaultDeclared = true; }
        else if (fname === 'manual') f.manual = v === 'true';
      }
      flags.push(f);
      continue;
    }
    if (kind === 'source-repository') {
      const r = { kind: arg || 'head', type: null, location: null, tag: null, branch: null, subdir: null, file, line: node.line.n };
      for (const c of node.children) {
        const cf = FIELD.exec(c.line.text);
        if (!cf) continue;
        const fname = cf[1].toLowerCase();
        const v = fieldValue(c).text.trim();
        if (['type', 'location', 'tag', 'branch', 'subdir'].includes(fname)) r[fname] = v;
      }
      r.pinned = !!r.tag && /^[0-9a-f]{7,40}$/i.test(r.tag);
      sourceRepositories.push(r);
      continue;
    }
    const isLib = kind === 'library';
    const name = kind === 'common' ? arg : (isLib ? (arg || pkg.name) : (kind === 'custom-setup' ? 'setup' : arg));
    const st = newStanza(kind, name, node.line.n, SCOPE_OF[kind]);
    st.problems = diagnostics;
    st.sublibrary = isLib && !!arg;
    st.name = name;
    if (kind === 'custom-setup') st.surfaces.push({ kind: 'custom-setup', detail: 'custom-setup stanza', file, line: node.line.n, column: node.line.indent });
    walkCabalBody(node.children, st, [], file, 0, budgets);
    if (kind === 'common') commons[arg] = st; else stanzas.push(st);
  }

  // Expand `import:` of common stanzas; the dependency keeps its ORIGINAL line.
  const expand = (st, into, seen, via) => {
    for (const imp of st.imports) {
      const c = commons[imp.name];
      if (!c) { diagnostics.push(diag('unresolved_import', `import '${imp.name}' has no matching common stanza`, file, imp.line)); continue; }
      if (seen.has(imp.name)) { diagnostics.push(diag('import_cycle', `common stanza '${imp.name}' imports itself`, file, imp.line)); continue; }
      const nextSeen = new Set(seen).add(imp.name);
      for (const d of c.deps) into.deps.push({ ...d, via: `common:${imp.name}` });
      for (const s of c.surfaces) into.surfaces.push({ ...s, via: `common:${imp.name}` });
      for (const r of c.flagRefs) into.flagRefs.push(r);
      expand(c, into, nextSeen, via);
    }
  };

  const declared = new Set(flags.map((f) => f.name));
  const unknownFlags = [];
  const components = stanzas.map((st) => {
    const own = { deps: st.deps.slice(), surfaces: st.surfaces.slice(), flagRefs: st.flagRefs.slice() };
    expand(st, own, new Set(), null);
    for (const r of own.flagRefs) {
      if (!declared.has(r.flag)) {
        unknownFlags.push({ flag: r.flag, component: st.name, file, line: r.line });
        diagnostics.push(diag('unknown_flag', `condition references flag '${r.flag}' that this package never declares`, file, r.line, 'warning', { flag: r.flag }));
      }
    }
    return {
      kind: st.kind,
      name: st.name,
      scope: st.scope,
      sublibrary: st.sublibrary,
      file,
      line: st.line,
      imports: st.imports,
      fields: st.fields,
      dependencies: own.deps.map((d) => ({ ...d, scope: d.scopeOverride || st.scope, scopeOverride: undefined })),
      surfaces: own.surfaces,
    };
  });
  for (const f of flags) f.package = pkg.name;
  if (!pkg.name) diagnostics.push(diag('missing_package_name', 'no `name:` field found', file, null));

  return {
    kind: 'cabal', file, package: pkg, provenance, components, flags, unknownFlags,
    sourceRepositories: sourceRepositories.map((r) => ({ ...r, package: pkg.name })),
    surfaces: [...topSurfaces, ...components.flatMap((c) => c.surfaces.map((s) => ({ ...s, component: c.name })))],
    diagnostics,
  };
}

// ---------------------------------------------------------------------------
// package.yaml (Hpack)
// ---------------------------------------------------------------------------

class BudgetError extends Error {}

function findLine(lines, re, from) {
  for (let i = Math.max(0, from); i < lines.length; i++) if (re.test(lines[i])) return i;
  return -1;
}

function hpackDepEntries(v, budget) {
  const tick = () => { if (++budget.n > budget.max) throw new BudgetError('node budget exceeded'); };
  const out = [];
  const fromObj = (o) => {
    for (const [k, val] of Object.entries(o)) {
      tick();
      let rangeText = '';
      let numeric = false;
      if (typeof val === 'string') rangeText = val;
      else if (typeof val === 'number') { rangeText = String(val); numeric = true; }
      else if (isObj(val) && val.version != null) rangeText = String(val.version);
      out.push({ name: k, sublibrary: null, rangeText: rangeText.trim(), numeric });
    }
  };
  const fromString = (s) => {
    const p = parseDepPiece(s.trim());
    if (p) out.push(...p.map((x) => ({ ...x, numeric: false }))); else out.push({ name: s, malformed: true, rangeText: '' });
  };
  tick();
  if (typeof v === 'string') fromString(v);
  else if (Array.isArray(v)) {
    for (const e of v) { tick(); if (typeof e === 'string') fromString(e); else if (isObj(e)) fromObj(e); }
  } else if (isObj(v)) fromObj(v);
  return out;
}

/** Parse package.yaml. Malformed YAML yields {incomplete:true} plus a diagnostic. */
export function parseHpackFile(text, opts = {}) {
  const file = opts.file || 'package.yaml';
  const budgets = budgetsOf(opts);
  const diagnostics = [];
  const empty = (extra = {}) => ({ kind: 'hpack', file, package: { name: null, version: null, buildType: null }, provenance: { generatedBy: null }, components: [], packageDependencies: [], flags: [], unknownFlags: [], sourceRepositories: [], surfaces: [], incomplete: true, diagnostics, ...extra });
  const src = typeof text === 'string' ? text : '';
  if (src.length > budgets.maxBytes) { diagnostics.push(diag('budget_exceeded', `manifest larger than ${budgets.maxBytes} bytes; not parsed`, file, null)); return empty(); }
  let doc;
  try {
    doc = yamlLoad(src, { schema: CORE_SCHEMA });
  } catch (e) {
    const line = e && e.mark && Number.isInteger(e.mark.line) ? e.mark.line + 1 : null;
    diagnostics.push(diag('malformed_yaml', String(e && e.reason ? e.reason : e && e.message).split('\n')[0].slice(0, 200), file, line, 'error'));
    return empty();
  }
  if (doc === undefined) { diagnostics.push(diag('empty_manifest', 'package.yaml has no content', file, null)); return empty(); }
  if (!isObj(doc)) { diagnostics.push(diag('malformed_manifest', 'package.yaml top level must be a mapping', file, 1, 'error')); return empty(); }

  const lines = src.split(/\r\n|\r|\n/);
  const budget = { n: 0, max: budgets.maxNodes };
  const pkg = { name: typeof doc.name === 'string' ? doc.name : null, version: doc.version != null ? String(doc.version) : null, buildType: typeof doc['build-type'] === 'string' ? doc['build-type'] : null };
  const surfaces = [];
  const flagList = [];
  const sourceRepositories = [];
  const unknownFlags = [];
  let incomplete = false;

  const collect = (sec, st, conds, start, depth) => {
    if (!isObj(sec) || depth > budgets.maxDepth) return;
    if (++budget.n > budget.max) throw new BudgetError('node budget exceeded');
    // Top-level keys sit at column 0; anchoring stops a nested section's key
    // (custom-setup, library) from being mistaken for the package-wide one.
    const ind = depth === 0 ? '' : '\\s*';
    for (const [key, scopeOverride] of [['dependencies', null], ['build-tools', 'build-tool'], ['build-tool-depends', 'build-tool']]) {
      if (!(key in sec)) continue;
      let cursor = findLine(lines, new RegExp(`^${ind}(?:-\\s+)?${esc(key)}\\s*:`), start);
      if (cursor < 0) cursor = start;
      for (const e of hpackDepEntries(sec[key], budget)) {
        let li = findLine(lines, new RegExp(`(?<![A-Za-z0-9-])${esc(e.name)}(?![A-Za-z0-9-])`), cursor);
        const exact = li >= 0;
        if (li < 0) li = cursor;
        cursor = li;
        const line = li + 1;
        if (e.malformed) { diagnostics.push(diag('malformed_dependency', `cannot read dependency '${e.name}'`, file, line)); continue; }
        const d = makeDep(e, { field: key, scopeOverride, conds, line, column: Math.max(0, (lines[li] || '').search(new RegExp(`(?<![A-Za-z0-9-])${esc(e.name)}(?![A-Za-z0-9-])`))), locationKind: exact ? 'text-match' : 'section' });
        if (d.rangeError) diagnostics.push(diag('invalid_version_range', `${e.name}: ${d.rangeError}`, file, line, 'warning', { rangeText: e.rangeText }));
        if (e.numeric) diagnostics.push(diag('yaml_numeric_version', `'${e.name}: ${e.rangeText}' is a YAML number; quote it, trailing zeros are lost`, file, line));
        st.deps.push(d);
        if (scopeOverride === 'build-tool') surfaces.push({ kind: 'build-tool-depends', detail: `${e.name} ${e.rangeText}`.trim(), file, line, column: d.column, component: st.name });
      }
    }
    if ('ghc-options' in sec) {
      const opt = Array.isArray(sec['ghc-options']) ? sec['ghc-options'].join(' ') : String(sec['ghc-options']);
      let li = findLine(lines, new RegExp(`^${ind}(?:-\\s+)?ghc-options\\s*:`), start);
      if (li < 0) li = start;
      scanGhcOptions(opt, null, (kind, detail) => surfaces.push({ kind, detail, file, line: li + 1, column: 0, component: st.name }));
    }
    if ('verbatim' in sec) surfaces.push({ kind: 'hpack-verbatim', detail: 'verbatim cabal passthrough', file, line: Math.max(1, findLine(lines, /^\s*verbatim\s*:/, start) + 1), column: 0, component: st.name });
    if ('when' in sec) {
      const whens = Array.isArray(sec.when) ? sec.when : [sec.when];
      for (const w of whens) {
        if (!isObj(w)) continue;
        const cond = String(w.condition);
        let ws = findLine(lines, new RegExp(`condition\\s*:\\s*['"]?${esc(cond)}`), start);
        if (ws < 0) ws = start;
        for (const r of flagRefsOf(cond)) st.flagRefs.push({ flag: r, line: ws + 1 });
        const inner = { ...w }; delete inner.then; delete inner.else; delete inner.condition;
        collect(inner, st, [...conds, cond], ws, depth + 1);
        if (isObj(w.then)) collect(w.then, st, [...conds, cond], ws, depth + 1);
        if (isObj(w.else)) collect(w.else, st, [...conds, `!(${cond})`], ws, depth + 1);
      }
    }
  };

  const mkStanza = (kind, name, scope) => ({ kind, name, scope, deps: [], flagRefs: [] });
  const finish = (st, line) => {
    for (const r of st.flagRefs) {
      if (!(doc.flags && isObj(doc.flags) && r.flag in doc.flags)) {
        unknownFlags.push({ flag: r.flag, component: st.name, file, line: r.line });
        diagnostics.push(diag('unknown_flag', `condition references flag '${r.flag}' that package.yaml never declares`, file, r.line, 'warning', { flag: r.flag }));
      }
    }
    return { kind: st.kind, name: st.name, scope: st.scope, file, line, dependencies: st.deps.map((d) => ({ ...d, scope: d.scopeOverride || st.scope, scopeOverride: undefined })) };
  };

  const components = [];
  let packageDependencies = [];
  try {
    const top = mkStanza('package', pkg.name, 'package');
    collect(doc, top, [], 0, 0);
    // top-level `when` and deps apply to every component
    const topLoc = finish(top, 1);
    packageDependencies = topLoc.dependencies;

    const section = (key, kind, scope, single) => {
      if (!(key in doc)) return;
      const base = Math.max(0, findLine(lines, new RegExp(`^${esc(key)}\\s*:`), 0));
      const add = (name, sec, start) => {
        const st = mkStanza(kind, name, scope);
        collect(sec, st, [], start, 1);
        components.push(finish(st, start + 1));
      };
      if (single) { add(kind === 'library' ? pkg.name : pkg.name, doc[key], base); return; }
      if (!isObj(doc[key])) { diagnostics.push(diag('malformed_manifest', `'${key}' must be a mapping`, file, base + 1)); return; }
      for (const [name, sec] of Object.entries(doc[key])) {
        let s = findLine(lines, new RegExp(`^\\s+${esc(name)}\\s*:`), base);
        if (s < 0) s = base;
        add(name, sec, s);
      }
    };
    section('library', 'library', 'runtime', true);
    section('internal-libraries', 'library', 'runtime', false);
    section('executable', 'executable', 'runtime', true);
    section('executables', 'executable', 'runtime', false);
    section('foreign-libraries', 'foreign-library', 'runtime', false);
    section('tests', 'test-suite', 'test', false);
    section('benchmarks', 'benchmark', 'benchmark', false);

    if (isObj(doc['custom-setup'])) {
      const st = mkStanza('custom-setup', 'setup', 'setup');
      const start = Math.max(0, findLine(lines, /^custom-setup\s*:/, 0));
      collect(doc['custom-setup'], st, [], start, 1);
      surfaces.push({ kind: 'custom-setup', detail: 'custom-setup section', file, line: start + 1, column: 0, component: 'setup' });
      components.push(finish(st, start + 1));
    }
  } catch (e) {
    if (e instanceof BudgetError) { incomplete = true; diagnostics.push(diag('budget_exceeded', 'package.yaml exceeds node budget (alias expansion or size); inventory truncated', file, null, 'error')); }
    else throw e;
  }
  if (pkg.buildType && /^(custom|configure|make)$/i.test(pkg.buildType)) {
    surfaces.push({ kind: `build-type-${pkg.buildType.toLowerCase()}`, detail: `build-type: ${pkg.buildType}`, file, line: Math.max(1, findLine(lines, /^build-type\s*:/, 0) + 1), column: 0 });
  }
  if (isObj(doc.flags)) {
    for (const [name, f] of Object.entries(doc.flags)) {
      flagList.push({ package: pkg.name, name, default: isObj(f) && typeof f.default === 'boolean' ? f.default : null, manual: isObj(f) && f.manual === true, file, line: Math.max(1, findLine(lines, new RegExp(`^\\s+${esc(name)}\\s*:`), Math.max(0, findLine(lines, /^flags\s*:/, 0))) + 1) });
    }
  }
  const repoLine = (key) => Math.max(1, findLine(lines, new RegExp(`^${key}\\s*:`), 0) + 1);
  if (typeof doc.github === 'string') {
    const [user, repo, ...sub] = doc.github.split('/');
    sourceRepositories.push({ kind: 'head', type: 'git', location: `https://github.com/${user}/${repo}`, subdir: sub.join('/') || null, tag: null, branch: null, pinned: false, package: pkg.name, file, line: repoLine('github') });
  }
  if (typeof doc.git === 'string') sourceRepositories.push({ kind: 'head', type: 'git', location: doc.git, subdir: null, tag: null, branch: null, pinned: false, package: pkg.name, file, line: repoLine('git') });

  return {
    kind: 'hpack', file, package: pkg, provenance: { generatedBy: null, source: 'hand-written' },
    components, packageDependencies, flags: flagList, unknownFlags, sourceRepositories,
    surfaces, incomplete, diagnostics,
  };
}

// ---------------------------------------------------------------------------
// cabal.project / cabal.project.freeze
// ---------------------------------------------------------------------------

function parseConstraintEntry(text) {
  const m = /^(?:(any|setup)\.|([A-Za-z0-9-]+):setup\.)?([A-Za-z0-9][A-Za-z0-9-]*)\s*(.*)$/.exec(text);
  if (!m) return null;
  const rest = m[4].trim();
  const base = { name: m[3], qualifier: m[1] || (m[2] ? `${m[2]}:setup` : null), raw: text };
  if (rest === '') return { ...base, kind: 'bare', rangeText: '' };
  if (rest !== '-any' && rest !== '-none' && /^(?:[+-][A-Za-z0-9_-]+\s*)+$/.test(rest)) {
    return { ...base, kind: 'flags', flags: rest.split(/\s+/).map((f) => ({ flag: f.slice(1), value: f[0] === '+' })) };
  }
  if (rest === 'installed' || rest === 'source') return { ...base, kind: 'preference', preference: rest };
  if (rest === 'test' || rest === 'bench') return { ...base, kind: 'preference', preference: rest };
  const rr = parseVersionRange(rest);
  return { ...base, kind: 'range', rangeText: rest, range: rr.ok ? rr.ast : null, rangeError: rr.ok ? null : rr.error };
}

function isRemote(p) { return /^[a-z][a-z0-9+.-]*:\/\//i.test(p); }

/** Parse cabal.project, cabal.project.local, cabal.project.freeze or cabal.config. */
export function parseCabalProject(text, opts = {}) {
  const file = opts.file || 'cabal.project';
  const budgets = budgetsOf(opts);
  const diagnostics = [];
  const base = path.posix.basename(file);
  const isFreeze = opts.freeze === true || /\.freeze$/.test(base) || base === 'cabal.config';
  const depth = opts._depth || 0;
  const seen = opts._seen || new Set([file]);
  const lines = lexLines(text, budgets, diagnostics, file);
  const tree = buildTree(lines, budgets, diagnostics, file);

  const res = {
    kind: isFreeze ? 'cabal-freeze' : 'cabal-project', file,
    packages: [], constraints: [], allowRelaxations: [], extraPackages: [], imports: [], sourceRepositories: [],
    flagSettings: [], packageStanzas: [], lockedPackages: [], surfaces: [], indexState: null, withCompiler: null, diagnostics,
  };

  const addConstraint = (c, val, offset, conds, from) => {
    const loc = locate(val, offset);
    const rec = { ...c, conditions: conds.slice(), file: from || file, line: loc.line, column: loc.column, importedFrom: from && from !== file ? from : null };
    if (rec.rangeError) diagnostics.push(diag('invalid_version_range', `${rec.name}: ${rec.rangeError}`, rec.file, rec.line, 'warning', { rangeText: rec.rangeText }));
    res.constraints.push(rec);
    if (rec.kind === 'flags') for (const f of rec.flags) res.flagSettings.push({ scope: 'project', package: rec.name, name: f.flag, value: f.value, file: rec.file, line: rec.line });
    if (isFreeze) {
      if (rec.kind === 'range' && rec.range && rec.range.t === 'cmp' && rec.range.op === '==' && !rec.range.wildcard) {
        res.lockedPackages.push({ name: rec.name, version: rec.range.text, qualifier: rec.qualifier, source: base, file: rec.file, line: rec.line, column: rec.column });
      } else if (rec.kind === 'preference' && rec.preference === 'installed') {
        res.lockedPackages.push({ name: rec.name, version: null, installed: true, qualifier: rec.qualifier, source: base, file: rec.file, line: rec.line, column: rec.column });
      }
    }
  };

  const walk = (children, conds, dpt) => {
    if (dpt > budgets.maxDepth) return;
    for (const node of children) {
      const t = node.line.text;
      const fm = FIELD.exec(t);
      if (fm) {
        const name = fm[1].toLowerCase();
        const val = fieldValue(node);
        switch (name) {
          case 'packages': case 'optional-packages':
            for (const w of splitWords(val.text)) res.packages.push({ pattern: w.text, optional: name === 'optional-packages', file, line: locate(val, w.offset).line });
            break;
          case 'extra-packages':
            for (const piece of splitCommas(val.text)) {
              const p = parseDepPiece(piece.text);
              if (!p) { diagnostics.push(diag('malformed_dependency', `cannot read extra-package '${piece.text}'`, file, locate(val, piece.offset).line)); continue; }
              const loc = locate(val, piece.offset);
              for (const x of p) res.extraPackages.push(makeDep(x, { field: 'extra-packages', conds, line: loc.line, column: loc.column }));
            }
            break;
          case 'constraints':
            for (const piece of splitCommas(val.text)) {
              const c = parseConstraintEntry(piece.text);
              if (!c) { diagnostics.push(diag('malformed_constraint', `cannot read constraint '${piece.text}'`, file, locate(val, piece.offset).line)); continue; }
              addConstraint(c, val, piece.offset, conds, null);
            }
            break;
          case 'allow-newer': case 'allow-older':
            for (const piece of splitCommas(val.text)) res.allowRelaxations.push({ direction: name === 'allow-newer' ? 'newer' : 'older', target: piece.text, weakensBounds: true, file, line: locate(val, piece.offset).line });
            break;
          case 'index-state': res.indexState = val.text.trim(); break;
          case 'with-compiler': res.withCompiler = val.text.trim(); break;
          case 'flags':
            for (const w of splitWords(val.text)) {
              const fl = /^([+-])([A-Za-z0-9_-]+)$/.exec(w.text);
              if (fl) res.flagSettings.push({ scope: 'project', package: null, name: fl[2], value: fl[1] === '+', file, line: locate(val, w.offset).line });
            }
            break;
          case 'import': {
            const target = val.text.trim();
            handleImport(target, val.line, conds);
            break;
          }
          default: break;
        }
        continue;
      }
      const sm = /^source-repository-package\b/i.exec(t);
      if (sm) {
        const r = { type: null, location: null, tag: null, branch: null, subdir: null, sha256: null, file, line: node.line.n };
        for (const c of node.children) {
          const cf = FIELD.exec(c.line.text);
          if (!cf) continue;
          const k = cf[1].toLowerCase();
          const v = fieldValue(c).text.trim();
          if (k in r && k !== 'file' && k !== 'line') r[k] = v;
        }
        r.pinned = !!r.tag && /^[0-9a-f]{7,40}$/i.test(r.tag);
        r.integrity = r.sha256 ? 'sha256' : 'none';
        res.sourceRepositories.push(r);
        res.surfaces.push({ kind: 'source-repository-package', detail: `${r.location || '?'} ${r.tag || r.branch || '(no ref)'}`, file, line: r.line, column: node.line.indent });
        continue;
      }
      const pm = /^package\s+(\S+)$/i.exec(t);
      if (pm) {
        const sp = { selector: pm[1], flags: [], file, line: node.line.n };
        for (const c of node.children) {
          const cf = FIELD.exec(c.line.text);
          if (!cf) continue;
          if (cf[1].toLowerCase() === 'flags') {
            const val = fieldValue(c);
            for (const w of splitWords(val.text)) {
              const fl = /^([+-])([A-Za-z0-9_-]+)$/.exec(w.text);
              if (fl) { sp.flags.push({ name: fl[2], value: fl[1] === '+' }); res.flagSettings.push({ scope: 'package', package: pm[1], name: fl[2], value: fl[1] === '+', file, line: locate(val, w.offset).line }); }
            }
          }
        }
        res.packageStanzas.push(sp);
        continue;
      }
      const cm = /^(if|elif|else)\b\s*(.*)$/i.exec(t);
      if (cm) walk(node.children, [...conds, cm[1].toLowerCase() === 'else' ? 'else' : cm[2]], dpt + 1);
    }
  };

  function handleImport(target, line, conds) {
    const rec = { target, resolved: false, file, line, conditions: conds.slice() };
    res.imports.push(rec);
    if (isRemote(target)) {
      res.surfaces.push({ kind: 'remote-import', detail: target, file, line, column: 0 });
      diagnostics.push(diag('remote_import_not_fetched', `import of ${target} is a remote fetch; not followed, so its constraints are unknown`, file, line));
      return;
    }
    const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), target));
    if (resolved.startsWith('..') || path.posix.isAbsolute(resolved)) { diagnostics.push(diag('import_outside_root', `import '${target}' escapes the project root; not read`, file, line)); return; }
    if (seen.has(resolved)) { diagnostics.push(diag('import_cycle', `import '${target}' forms a cycle`, file, line)); return; }
    if (depth >= budgets.maxImportDepth) { diagnostics.push(diag('budget_exceeded', `import chain deeper than ${budgets.maxImportDepth}`, file, line)); return; }
    const sub = typeof opts.readFile === 'function' ? opts.readFile(resolved) : null;
    if (typeof sub !== 'string') { diagnostics.push(diag('unresolved_import', `import '${target}' could not be read; constraints it contributes are unknown`, file, line)); return; }
    rec.resolved = true;
    rec.resolvedPath = resolved;
    const child = parseCabalProject(sub, { ...opts, file: resolved, _depth: depth + 1, _seen: new Set(seen).add(resolved) });
    const local = new Map(res.constraints.map((c) => [c.name, c]));
    for (const c of child.constraints) {
      const prior = local.get(c.name);
      if (prior && prior.kind === 'range' && c.kind === 'range' && prior.rangeText !== c.rangeText) {
        diagnostics.push(diag('import_override', `'${c.name}' is constrained as '${prior.rangeText}' and also by import ${resolved} as '${c.rangeText}'; the effective bound is their intersection or the later one, not decided here`, file, line, 'warning', { name: c.name }));
      }
      res.constraints.push({ ...c, importedFrom: c.importedFrom || resolved });
    }
    res.packages.push(...child.packages);
    res.allowRelaxations.push(...child.allowRelaxations);
    res.sourceRepositories.push(...child.sourceRepositories);
    res.flagSettings.push(...child.flagSettings);
    res.surfaces.push(...child.surfaces);
    res.lockedPackages.push(...child.lockedPackages.map((l) => ({ ...l, importedFrom: resolved })));
    res.imports.push(...child.imports);
    diagnostics.push(...child.diagnostics);
    if (!res.indexState && child.indexState) res.indexState = child.indexState;
  }

  walk(tree.children, [], 0);
  return res;
}

// ---------------------------------------------------------------------------
// stack.yaml / stack.yaml.lock
// ---------------------------------------------------------------------------

/** Classify a Stack snapshot selector. The package set is NOT resolved (needs the snapshot file). */
export function classifySnapshot(v) {
  const out = { kind: 'unknown', selector: null, floating: false, url: null, sha256: null, resolved: false, pinnedByHash: false };
  if (typeof v === 'string') {
    out.selector = v;
    if (/^lts-\d+$/.test(v)) { out.kind = 'lts'; out.floating = true; }
    else if (/^lts-\d+\.\d+$/.test(v)) out.kind = 'lts';
    else if (/^nightly-\d{4}-\d{2}-\d{2}$/.test(v)) out.kind = 'nightly';
    else if (/^ghc-\d+(?:\.\d+)*$/.test(v)) out.kind = 'compiler';
    else if (/^https?:\/\//i.test(v)) { out.kind = 'url'; out.url = v; }
    else if (/\.ya?ml$/i.test(v) || /^\.{0,2}\//.test(v)) out.kind = 'file';
    return out;
  }
  if (isObj(v)) {
    if (typeof v.url === 'string') { out.kind = 'url'; out.url = v.url; out.selector = v.url; }
    else if (typeof v.github === 'string') { out.kind = 'github'; out.selector = `${v.github}:${v.path || ''}`; }
    else if (typeof v.compiler === 'string') { out.kind = 'compiler'; out.selector = v.compiler; }
    if (typeof v.sha256 === 'string') { out.sha256 = v.sha256; out.pinnedByHash = true; }
  }
  return out;
}

/** Parse a Pantry locator such as `foo-1.2.3@sha256:ab..,1234` or `foo-1.2.3@rev:2`. */
export function parseHackageLocator(s) {
  const [id, ...restParts] = String(s).split('@');
  const rest = restParts.join('@');
  const m = /^(.+)-(\d+(?:\.\d+)*)$/.exec(id);
  const out = { name: m ? m[1] : id, version: m ? m[2] : null, sha256: null, size: null, revision: null, malformed: false };
  if (rest) {
    const sha = /^sha256:([0-9a-f]{64})(?:,(\d+))?$/i.exec(rest);
    const rev = /^rev:(\d+)$/.exec(rest);
    if (sha) { out.sha256 = sha[1]; out.size = sha[2] ? Number(sha[2]) : null; } else if (rev) out.revision = Number(rev[1]); else out.malformed = true;
  }
  if (!m) out.malformed = true;
  return out;
}

function parseExtraDep(e, line) {
  const base = { file: null, line, kind: 'unknown', name: null, version: null, commit: null, locator: null, sha256: null, size: null, revision: null, subdirs: [] };
  if (typeof e === 'string') {
    if (/^\.{0,2}\//.test(e) || e === '.') return { ...base, kind: 'path', locator: e };
    if (isRemote(e)) return { ...base, kind: 'url', locator: e };
    const h = parseHackageLocator(e);
    return { ...base, kind: 'hackage', name: h.name, version: h.version, sha256: h.sha256, size: h.size, revision: h.revision, locator: e, malformed: h.malformed };
  }
  if (isObj(e)) {
    const subdirs = Array.isArray(e.subdirs) ? e.subdirs.map(String) : [];
    if (typeof e.hackage === 'string') { const h = parseHackageLocator(e.hackage); return { ...base, kind: 'hackage', name: h.name, version: h.version, sha256: h.sha256, size: h.size, revision: h.revision, locator: e.hackage, malformed: h.malformed }; }
    if (typeof e.git === 'string') return { ...base, kind: 'git', locator: e.git, commit: e.commit ? String(e.commit) : null, subdirs };
    if (typeof e.github === 'string') return { ...base, kind: 'github', locator: e.github, commit: e.commit ? String(e.commit) : null, subdirs };
    if (typeof e.hg === 'string') return { ...base, kind: 'hg', locator: e.hg, commit: e.commit ? String(e.commit) : null, subdirs };
    if (typeof e.url === 'string' || typeof e.archive === 'string') return { ...base, kind: 'url', locator: e.url || e.archive, sha256: typeof e.sha256 === 'string' ? e.sha256 : null, size: Number.isInteger(e.size) ? e.size : null, subdirs };
  }
  return base;
}

/** Parse stack.yaml. */
export function parseStackYaml(text, opts = {}) {
  const file = opts.file || 'stack.yaml';
  const budgets = budgetsOf(opts);
  const diagnostics = [];
  const res = { kind: 'stack', file, snapshot: null, compiler: null, packages: [], extraDeps: [], flagSettings: [], allowNewer: false, surfaces: [], incomplete: false, diagnostics };
  const src = typeof text === 'string' ? text : '';
  if (src.length > budgets.maxBytes) { diagnostics.push(diag('budget_exceeded', `manifest larger than ${budgets.maxBytes} bytes; not parsed`, file, null)); res.incomplete = true; return res; }
  let doc;
  try { doc = yamlLoad(src, { schema: CORE_SCHEMA }); } catch (e) {
    diagnostics.push(diag('malformed_yaml', String(e && e.reason ? e.reason : e && e.message).split('\n')[0].slice(0, 200), file, e && e.mark && Number.isInteger(e.mark.line) ? e.mark.line + 1 : null, 'error'));
    res.incomplete = true; return res;
  }
  if (doc === undefined) { diagnostics.push(diag('empty_manifest', 'stack.yaml has no content', file, null)); res.incomplete = true; return res; }
  if (!isObj(doc)) { diagnostics.push(diag('malformed_manifest', 'stack.yaml top level must be a mapping', file, 1, 'error')); res.incomplete = true; return res; }
  const lines = src.split(/\r\n|\r|\n/);
  const keyLine = (k) => Math.max(1, findLine(lines, new RegExp(`^${esc(k)}\\s*:`), 0) + 1);

  const selKey = 'snapshot' in doc ? 'snapshot' : ('resolver' in doc ? 'resolver' : null);
  if ('snapshot' in doc && 'resolver' in doc) diagnostics.push(diag('both_resolver_and_snapshot', 'both `snapshot` and `resolver` are set; `snapshot` wins', file, keyLine('resolver')));
  if (selKey) res.snapshot = { ...classifySnapshot(doc[selKey]), key: selKey, file, line: keyLine(selKey) };
  else diagnostics.push(diag('missing_snapshot', 'stack.yaml declares no snapshot/resolver; the package set is undetermined', file, null));
  if (res.snapshot) {
    if (res.snapshot.floating) diagnostics.push(diag('floating_snapshot', `snapshot '${res.snapshot.selector}' has no minor version; it resolves to whatever is latest`, file, res.snapshot.line));
    if (res.snapshot.kind === 'url' && !res.snapshot.pinnedByHash) diagnostics.push(diag('unpinned_snapshot_url', `snapshot URL has no sha256; its contents can change`, file, res.snapshot.line));
    if (res.snapshot.kind === 'unknown') diagnostics.push(diag('unrecognized_snapshot', 'snapshot selector not recognised; kept verbatim', file, res.snapshot.line));
  }
  if (typeof doc.compiler === 'string') res.compiler = doc.compiler;

  if ('packages' in doc) {
    const arr = Array.isArray(doc.packages) ? doc.packages : [doc.packages];
    for (const p of arr.slice(0, budgets.maxNodes)) res.packages.push(typeof p === 'string' ? p : (isObj(p) && typeof p.location === 'string' ? p.location : String(p)));
  } else res.packages.push('.');

  if (Array.isArray(doc['extra-deps'])) {
    const base = keyLine('extra-deps');
    let cursor = base - 1;
    for (const e of doc['extra-deps'].slice(0, budgets.maxNodes)) {
      const rec = parseExtraDep(e, base);
      const needle = rec.name || rec.locator;
      if (needle) { const li = findLine(lines, new RegExp(esc(String(needle).split(/[@,]/)[0])), cursor + 1); if (li >= 0) { cursor = li; rec.line = li + 1; } }
      rec.file = file;
      rec.integrity = rec.sha256 ? 'sha256' : (rec.commit ? 'commit' : (rec.revision != null ? 'revision' : 'none'));
      if (rec.malformed) diagnostics.push(diag('malformed_extra_dep', `cannot read extra-dep '${String(rec.locator)}'`, file, rec.line));
      if (rec.kind === 'unknown') diagnostics.push(diag('malformed_extra_dep', 'unrecognised extra-dep entry', file, rec.line));
      if (rec.kind === 'git' && !rec.commit) diagnostics.push(diag('unpinned_extra_dep', `git extra-dep ${rec.locator} has no commit`, file, rec.line));
      if (rec.kind === 'url' && !rec.sha256) diagnostics.push(diag('unpinned_extra_dep', `url extra-dep ${rec.locator} has no sha256`, file, rec.line));
      if (['git', 'github', 'hg', 'url'].includes(rec.kind)) res.surfaces.push({ kind: 'extra-dep-source', detail: `${rec.kind} ${rec.locator}`, file, line: rec.line, column: 0 });
      res.extraDeps.push(rec);
    }
  } else if ('extra-deps' in doc) diagnostics.push(diag('malformed_manifest', "'extra-deps' must be a list", file, keyLine('extra-deps')));

  if (isObj(doc.flags)) {
    const base = keyLine('flags') - 1;
    for (const [pkgName, fl] of Object.entries(doc.flags)) {
      if (!isObj(fl)) { diagnostics.push(diag('malformed_manifest', `flags for '${pkgName}' must be a mapping`, file, base + 1)); continue; }
      for (const [flag, value] of Object.entries(fl)) {
        const li = findLine(lines, new RegExp(`^\\s+${esc(flag)}\\s*:`), base);
        res.flagSettings.push({ scope: 'stack', package: pkgName, name: flag, value: value === true || value === false ? value : null, file, line: (li >= 0 ? li : base) + 1 });
      }
    }
  }
  if (doc['allow-newer'] === true) { res.allowNewer = true; diagnostics.push(diag('allow_newer', 'allow-newer: true disables upper bounds across the project', file, keyLine('allow-newer'))); }
  if (isObj(doc.nix) && doc.nix.enable === true) res.surfaces.push({ kind: 'stack-nix-integration', detail: 'nix.enable: true', file, line: keyLine('nix'), column: 0 });
  if (isObj(doc.docker) && doc.docker.enable === true) res.surfaces.push({ kind: 'stack-docker-integration', detail: 'docker.enable: true', file, line: keyLine('docker'), column: 0 });
  return res;
}

/** Parse stack.yaml.lock. Hashes here are Pantry content hashes. */
export function parseStackLock(text, opts = {}) {
  const file = opts.file || 'stack.yaml.lock';
  const budgets = budgetsOf(opts);
  const diagnostics = [];
  const res = { kind: 'stack-lock', file, packages: [], snapshots: [], incomplete: false, diagnostics };
  const src = typeof text === 'string' ? text : '';
  if (src.length > budgets.maxBytes) { diagnostics.push(diag('budget_exceeded', `lockfile larger than ${budgets.maxBytes} bytes; not parsed`, file, null)); res.incomplete = true; return res; }
  let doc;
  try { doc = yamlLoad(src, { schema: CORE_SCHEMA }); } catch (e) {
    diagnostics.push(diag('malformed_yaml', String(e && e.reason ? e.reason : e && e.message).split('\n')[0].slice(0, 200), file, e && e.mark && Number.isInteger(e.mark.line) ? e.mark.line + 1 : null, 'error'));
    res.incomplete = true; return res;
  }
  if (!isObj(doc)) { diagnostics.push(diag(doc === undefined ? 'empty_manifest' : 'malformed_manifest', 'stack.yaml.lock must be a mapping', file, 1, doc === undefined ? 'warning' : 'error')); res.incomplete = true; return res; }
  const lines = src.split(/\r\n|\r|\n/);
  const pkgBase = Math.max(0, findLine(lines, /^packages\s*:/, 0));
  let cursor = pkgBase;
  for (const p of (Array.isArray(doc.packages) ? doc.packages : []).slice(0, budgets.maxNodes)) {
    const c = isObj(p) && isObj(p.completed) ? p.completed : null;
    const o = isObj(p) && isObj(p.original) ? p.original : null;
    if (!c) { diagnostics.push(diag('malformed_lock_entry', 'lock package entry has no `completed` mapping', file, cursor + 1)); continue; }
    const tree = isObj(c['pantry-tree']) ? { sha256: c['pantry-tree'].sha256 || null, size: Number.isInteger(c['pantry-tree'].size) ? c['pantry-tree'].size : null } : null;
    let rec;
    if (typeof c.hackage === 'string') {
      const h = parseHackageLocator(c.hackage);
      rec = { kind: 'hackage', name: h.name, version: h.version, sha256: h.sha256, size: h.size, revision: h.revision, locator: c.hackage };
    } else if (typeof c.git === 'string') rec = { kind: 'git', name: c.name || null, version: c.version != null ? String(c.version) : null, commit: c.commit || null, locator: c.git };
    else if (typeof c.url === 'string') rec = { kind: 'url', name: c.name || null, version: c.version != null ? String(c.version) : null, sha256: c.sha256 || null, locator: c.url };
    else { diagnostics.push(diag('malformed_lock_entry', 'lock entry has no hackage/git/url locator', file, cursor + 1)); continue; }
    const needle = rec.locator.split('@')[0];
    const li = findLine(lines, new RegExp(esc(needle)), cursor);
    if (li >= 0) cursor = li;
    res.packages.push({ ...rec, pantryTree: tree, original: o, file, line: cursor + 1, source: 'stack.yaml.lock' });
  }
  const snapBase = Math.max(0, findLine(lines, /^snapshots\s*:/, 0));
  for (const s of (Array.isArray(doc.snapshots) ? doc.snapshots : []).slice(0, budgets.maxNodes)) {
    const c = isObj(s) && isObj(s.completed) ? s.completed : {};
    const o = isObj(s) && isObj(s.original) ? s.original : (isObj(s) ? s.original : null);
    res.snapshots.push({ original: o, url: typeof c.url === 'string' ? c.url : null, sha256: typeof c.sha256 === 'string' ? c.sha256 : null, size: Number.isInteger(c.size) ? c.size : null, file, line: snapBase + 1 });
  }
  return res;
}

// ---------------------------------------------------------------------------
// Project-level analysis
// ---------------------------------------------------------------------------

function classifyManifest(rel) {
  const base = path.posix.basename(rel);
  if (/\.cabal$/i.test(base) && base.length > 6) return 'cabal';
  if (base === 'package.yaml') return 'hpack';
  if (base === 'cabal.project' || base === 'cabal.project.local') return 'project';
  if (base === 'cabal.project.freeze' || base === 'cabal.config') return 'freeze';
  if (base === 'stack.yaml.lock') return 'stack-lock';
  if (/^stack(?:-[\w.-]+)?\.yaml$/.test(base)) return 'stack';
  return null;
}

function inventoryDep(d, ctx) {
  return {
    ecosystem: 'hackage', name: d.name, sublibrary: d.sublibrary, declaredRange: d.declaredRange, rangeKind: d.rangeKind,
    rangeError: d.rangeError, resolvedVersion: null, exactPin: d.exactPin,
    package: ctx.package, component: ctx.component, componentKind: ctx.componentKind, scope: d.scope || ctx.scope, field: d.field,
    conditions: d.conditions, flagRefs: d.flagRefs, via: d.via || null,
    manifest: ctx.file, manifestType: ctx.manifestType, provenance: ctx.provenance,
    shadowedBy: ctx.shadowedBy || null, line: d.line, column: d.column, locationKind: d.locationKind,
  };
}

/**
 * Analyse a set of manifests. `files` is [{path, text}] with posix paths relative
 * to the project root. Handles multi-package projects, pairs package.yaml with its
 * generated .cabal, and reports mismatches. Never throws on malformed input.
 */
export function analyzeHaskellManifests(files, opts = {}) {
  const budgets = budgetsOf(opts);
  const byPath = new Map();
  for (const f of files || []) if (f && typeof f.path === 'string') byPath.set(f.path.replace(/\\/g, '/'), typeof f.text === 'string' ? f.text : '');
  const readFile = (p) => (byPath.has(p) ? byPath.get(p) : null);

  const out = {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    packages: [], hpack: [], projects: [], stack: [], stackLocks: [],
    dependencies: [], lockedPackages: [], constraints: [], sourceRepositories: [], flags: [], flagSettings: [], snapshots: [], surfaces: [],
    diagnostics: [],
    coverage: { discovered: 0, parsed: 0, failed: 0, skipped: 0 },
  };
  const entries = [...byPath.keys()].sort().map((p) => [p, classifyManifest(p)]).filter(([, k]) => k);
  out.coverage.discovered = entries.length;
  const toParse = entries.slice(0, budgets.maxFiles);
  out.coverage.skipped = entries.length - toParse.length;
  if (out.coverage.skipped) out.diagnostics.push(diag('budget_exceeded', `${out.coverage.skipped} manifest(s) beyond the ${budgets.maxFiles} file budget were not read`, null, null));

  const hpackByDir = new Map();
  const cabalByDir = new Map();
  const parsedResults = [];
  for (const [p, kind] of toParse) {
    const text = byPath.get(p);
    let r;
    try {
      if (kind === 'cabal') r = parseCabalFile(text, { file: p, budgets });
      else if (kind === 'hpack') r = parseHpackFile(text, { file: p, budgets });
      else if (kind === 'project' || kind === 'freeze') r = parseCabalProject(text, { file: p, freeze: kind === 'freeze', readFile, budgets });
      else if (kind === 'stack') r = parseStackYaml(text, { file: p, budgets });
      else r = parseStackLock(text, { file: p, budgets });
    } catch (e) {
      out.coverage.failed++;
      out.diagnostics.push(diag('parser_failure', `${kind} parser failed: ${String(e && e.message).slice(0, 160)}`, p, null, 'error'));
      continue;
    }
    if (r.incomplete) out.coverage.failed++; else out.coverage.parsed++;
    out.diagnostics.push(...r.diagnostics);
    parsedResults.push([p, kind, r]);
    const dir = path.posix.dirname(p);
    if (kind === 'hpack') hpackByDir.set(dir, r);
    if (kind === 'cabal') { if (!cabalByDir.has(dir)) cabalByDir.set(dir, []); cabalByDir.get(dir).push(r); }
  }

  const localPackages = new Map(); // name -> declared flag name set
  for (const [, kind, r] of parsedResults) {
    if ((kind === 'cabal' || kind === 'hpack') && r.package.name) {
      const set = localPackages.get(r.package.name) || new Set();
      for (const f of r.flags) set.add(f.name);
      localPackages.set(r.package.name, set);
    }
  }

  for (const [p, kind, r] of parsedResults) {
    const dir = path.posix.dirname(p);
    if (kind === 'cabal') {
      const hp = hpackByDir.get(dir);
      let provenance = 'hand-written';
      let shadowedBy = null;
      if (r.provenance.generatedBy === 'hpack') {
        provenance = 'hpack-generated';
        if (hp && !hp.incomplete) shadowedBy = hp.file;
        else if (!hp) out.diagnostics.push(diag('generated_cabal_source_missing', 'cabal file says it was generated by hpack but no package.yaml sits beside it', p, 1));
      } else if (hp && !hp.incomplete && (!hp.package.name || hp.package.name === r.package.name)) {
        out.diagnostics.push(diag('cabal_not_hpack_generated', 'package.yaml sits beside a hand-written .cabal; Hpack will refuse to overwrite it, so the two can drift', p, 1));
      }
      if (r.provenance.generatedBy === 'hpack' && hp && !hp.incomplete) {
        if (hp.package.name && r.package.name && hp.package.name !== r.package.name) out.diagnostics.push(diag('hpack_cabal_mismatch', `package.yaml name '${hp.package.name}' differs from generated cabal name '${r.package.name}'`, p, 1, 'warning', { field: 'name' }));
        if (hp.package.version && r.package.version && hp.package.version !== r.package.version) out.diagnostics.push(diag('hpack_cabal_mismatch', `package.yaml version '${hp.package.version}' differs from generated cabal version '${r.package.version}'`, p, 1, 'warning', { field: 'version' }));
        const hn = new Set([...hp.packageDependencies, ...hp.components.flatMap((c) => c.dependencies)].filter((d) => d.scope !== 'setup' && d.scope !== 'build-tool').map((d) => d.name));
        const cn = new Set(r.components.flatMap((c) => c.dependencies).filter((d) => d.scope !== 'setup' && d.scope !== 'build-tool').map((d) => d.name));
        const onlyHpack = [...hn].filter((n) => !cn.has(n)).sort();
        const onlyCabal = [...cn].filter((n) => !hn.has(n)).sort();
        if (onlyHpack.length || onlyCabal.length) out.diagnostics.push(diag('hpack_cabal_mismatch', `dependency sets differ between package.yaml and its generated cabal (only in package.yaml: ${onlyHpack.join(', ') || 'none'}; only in cabal: ${onlyCabal.join(', ') || 'none'}); the cabal file is stale or hand-edited`, p, 1, 'warning', { field: 'dependencies', onlyInHpack: onlyHpack, onlyInCabal: onlyCabal }));
      }
      out.packages.push({ name: r.package.name, version: r.package.version, buildType: r.package.buildType, file: p, provenance: r.provenance, manifestProvenance: provenance, components: r.components.map((c) => ({ kind: c.kind, name: c.name, scope: c.scope })) });
      for (const c of r.components) for (const d of c.dependencies) out.dependencies.push(inventoryDep(d, { package: r.package.name, component: c.name, componentKind: c.kind, scope: c.scope, file: p, manifestType: 'cabal', provenance, shadowedBy }));
      out.flags.push(...r.flags);
      out.sourceRepositories.push(...r.sourceRepositories.map((s) => ({ ...s, source: 'cabal' })));
      out.surfaces.push(...r.surfaces.map((s) => ({ ...s, package: r.package.name })));
    } else if (kind === 'hpack') {
      if (!(cabalByDir.get(dir) || []).length) out.diagnostics.push(diag('hpack_cabal_missing', 'package.yaml has no generated .cabal beside it; dependencies are declared by package.yaml only', p, 1, 'info'));
      out.hpack.push({ name: r.package.name, version: r.package.version, buildType: r.package.buildType, file: p, incomplete: r.incomplete, components: r.components.map((c) => ({ kind: c.kind, name: c.name, scope: c.scope })) });
      for (const d of r.packageDependencies) out.dependencies.push(inventoryDep(d, { package: r.package.name, component: null, componentKind: 'package', scope: 'package', file: p, manifestType: 'hpack', provenance: 'hand-written' }));
      for (const c of r.components) for (const d of c.dependencies) out.dependencies.push(inventoryDep(d, { package: r.package.name, component: c.name, componentKind: c.kind, scope: c.scope, file: p, manifestType: 'hpack', provenance: 'hand-written' }));
      out.flags.push(...r.flags);
      out.sourceRepositories.push(...r.sourceRepositories.map((s) => ({ ...s, source: 'hpack' })));
      out.surfaces.push(...r.surfaces.map((s) => ({ ...s, package: r.package.name })));
    } else if (kind === 'project' || kind === 'freeze') {
      out.projects.push({ file: p, kind: r.kind, packages: r.packages, imports: r.imports, indexState: r.indexState, withCompiler: r.withCompiler, allowRelaxations: r.allowRelaxations, packageStanzas: r.packageStanzas });
      out.constraints.push(...r.constraints.map((c) => ({ ...c, manifest: p, resolvedVersion: null })));
      out.lockedPackages.push(...r.lockedPackages);
      for (const e of r.extraPackages) out.dependencies.push(inventoryDep(e, { package: null, component: null, componentKind: 'project', scope: 'project', file: p, manifestType: 'cabal.project', provenance: 'hand-written' }));
      out.sourceRepositories.push(...r.sourceRepositories.map((s) => ({ ...s, source: 'cabal.project' })));
      out.flagSettings.push(...r.flagSettings);
      out.surfaces.push(...r.surfaces);
      if (r.allowRelaxations.length) out.diagnostics.push(diag('bounds_relaxed', `project relaxes version bounds (${r.allowRelaxations.map((a) => `allow-${a.direction}: ${a.target}`).join('; ')}); declared bounds are not authoritative`, p, r.allowRelaxations[0].line, 'info'));
    } else if (kind === 'stack') {
      out.stack.push({ file: p, snapshot: r.snapshot, compiler: r.compiler, packages: r.packages, extraDeps: r.extraDeps, incomplete: r.incomplete });
      if (r.snapshot) out.snapshots.push({ ...r.snapshot, source: 'stack.yaml' });
      for (const e of r.extraDeps) {
        if (e.kind === 'hackage' && e.version) out.lockedPackages.push({ name: e.name, version: e.version, source: 'stack.yaml extra-deps', integrity: e.integrity, file: p, line: e.line, column: 0 });
      }
      out.flagSettings.push(...r.flagSettings);
      out.surfaces.push(...r.surfaces);
    } else if (kind === 'stack-lock') {
      out.stackLocks.push({ file: p, snapshots: r.snapshots, packageCount: r.packages.length, incomplete: r.incomplete });
      out.lockedPackages.push(...r.packages.filter((x) => x.version).map((x) => ({ name: x.name, version: x.version, source: 'stack.yaml.lock', integrity: x.sha256 || (x.pantryTree && x.pantryTree.sha256) ? 'sha256' : 'none', kind: x.kind, file: p, line: x.line, column: 0 })));
      for (const s of r.snapshots) out.snapshots.push({ kind: 'lock', selector: typeof s.original === 'string' ? s.original : (s.original && s.original.url) || null, url: s.url, sha256: s.sha256, resolved: !!s.sha256, resolvedBy: 'stack.yaml.lock', pinnedByHash: !!s.sha256, file: p, line: s.line, source: 'stack.yaml.lock' });
    }
  }

  // Stack lock vs extra-deps disagreement (same directory).
  for (const [p, kind, r] of parsedResults) {
    if (kind !== 'stack') continue;
    const lockRes = parsedResults.find(([lp, lk]) => lk === 'stack-lock' && path.posix.dirname(lp) === path.posix.dirname(p));
    if (!lockRes) continue;
    const locked = new Map(lockRes[2].packages.filter((x) => x.version).map((x) => [x.name, x.version]));
    for (const e of r.extraDeps) {
      if (e.kind === 'hackage' && e.version && locked.has(e.name) && locked.get(e.name) !== e.version) {
        out.diagnostics.push(diag('stack_lock_mismatch', `extra-dep ${e.name}-${e.version} but stack.yaml.lock records ${locked.get(e.name)}; the lock is stale`, p, e.line));
      }
    }
  }

  // Flag settings that name a flag a LOCAL package never declares.
  for (const s of out.flagSettings) {
    if (!s.package || s.package === '*') continue;
    const declared = localPackages.get(s.package);
    if (declared && !declared.has(s.name)) {
      s.unknown = true;
      out.diagnostics.push(diag('unknown_flag', `${s.scope} sets flag '${s.name}' on '${s.package}', which that package does not declare`, s.file, s.line, 'warning', { flag: s.name, package: s.package }));
    } else if (!declared) s.verified = false;
  }

  return redactUrlsDeep(out);
}

const WALK_SKIP = new Set(['node_modules', '.git', '.hg', '.svn']);

/** Read manifests under `root` (bounded, symlinks never followed) and analyse them. */
export function analyzeHaskellManifestsInDir(root, opts = {}) {
  const budgets = budgetsOf(opts);
  const files = [];
  const diagnostics = [];
  const queue = ['.'];
  let dirs = 0;
  while (queue.length) {
    const rel = queue.shift();
    if (++dirs > budgets.maxFiles) { diagnostics.push(diag('budget_exceeded', 'directory walk budget reached', null, null)); break; }
    let ents;
    try { ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const r = rel === '.' ? e.name : `${rel}/${e.name}`;
      if (e.isSymbolicLink()) { if (classifyManifest(r)) diagnostics.push(diag('symlink_skipped', 'symlinked manifest not followed', r, null, 'info')); continue; }
      if (e.isDirectory()) { if (!WALK_SKIP.has(e.name) && !isLanguageExcludedPath(`${r}/`)) queue.push(r); continue; }
      if (!e.isFile() || !classifyManifest(r) || isLanguageExcludedPath(r)) continue;
      try {
        const st = fs.statSync(path.join(root, r));
        if (st.size > budgets.maxBytes) { diagnostics.push(diag('budget_exceeded', `${r} exceeds ${budgets.maxBytes} bytes; not read`, r, null)); continue; }
        files.push({ path: r, text: fs.readFileSync(path.join(root, r), 'utf8') });
      } catch (err) { diagnostics.push(diag('read_failed', String(err && err.message).slice(0, 120), r, null)); }
    }
  }
  const res = analyzeHaskellManifests(files, opts);
  res.diagnostics.unshift(...diagnostics);
  return res;
}
