// R7 — import-aware SCA function-reachability (JS/TS + Python).
//
// The default reachability pass (engine.js#markUsedVulnFunctions) is a regex
// over `pkg.fn` / bare function names. It has two documented failure modes:
//   - FALSE NEGATIVE on aliased / namespace imports:
//       import { merge as deepMerge } from 'lodash'; deepMerge(a, b)   // missed
//       import * as _ from 'lodash'; _.merge(a, b)                      // member ok
//   - FALSE POSITIVE on coincidental names: a bare `parse(` in a file that never
//     imports the vulnerable package is matched anyway.
//
// This module parses the import statements of each JS/TS and Python file into an
// alias map, then finds call sites of a package's vulnerable functions resolved
// THROUGH that map and GATED to files that actually import the package. It does
// not decide `functionReachable` itself — it augments `vulnerableFunctionCallSites`
// so the existing route-reachability classifier (which distinguishes
// reachable / unreachable / unknown) sees the calls the regex missed.
//
// Other ecosystems keep the regex pass (this module is a no-op for them).

import { blankComments } from '../sast/_comment-strip.js';

const JS_RE = /\.(?:m|c)?[jt]sx?$/i;
const PY_RE = /\.py$/i;

export function languageOfFile(file) {
  if (JS_RE.test(file)) return 'js';
  if (PY_RE.test(file)) return 'py';
  return null;
}

// Normalize an import source to a package base name.
//   '@scope/pkg/sub' -> '@scope/pkg'   'pkg/sub' -> 'pkg'   (npm)
//   'pkg.sub.mod'     -> 'pkg'                              (python)
function pkgBase(source, lang) {
  let s = String(source || '').trim();
  if (lang === 'py') return s.split('.')[0];
  if (s.startsWith('@')) {
    const parts = s.split('/');
    return parts.slice(0, 2).join('/');
  }
  return s.split('/')[0];
}

// Loose package-name equivalence. npm is case-sensitive; PyPI dist names differ
// from import names by case and -/_ (PyYAML→yaml is NOT covered — that needs a
// dist→import table; documented limitation).
export function pkgMatches(depName, importedPkg, lang) {
  if (!depName || !importedPkg) return false;
  if (depName === importedPkg) return true;
  if (lang === 'py') {
    const norm = (x) => x.toLowerCase().replace(/[-_.]/g, '');
    return norm(depName) === norm(importedPkg);
  }
  return false;
}

// Split a named-imports clause body ("a, b as c, default as d") into pairs.
function parseNamedClause(body) {
  const out = [];
  for (const raw of body.split(',')) {
    const t = raw.trim();
    if (!t) continue;
    const m = t.match(/^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/);
    if (m) out.push({ imported: m[1], local: m[2] });
    else if (/^[A-Za-z_$][\w$]*$/.test(t)) out.push({ imported: t, local: t });
  }
  return out;
}

/**
 * Parse JS/TS imports into:
 *   named: Map<localName, { pkg, imported }>
 *   ns:    Map<localName, pkg>            (namespace/default whole-module binding)
 *   packages: Set<pkg>
 * Handles ESM (named / default / namespace) and CJS require (destructure / whole).
 */
export function extractJsImports(content) {
  const code = blankComments(content);
  const named = new Map();
  const ns = new Map();
  const packages = new Set();
  const add = (pkg) => { if (pkg) packages.add(pkg); };

  // ESM: import ... from 'pkg'
  const esm = /\bimport\s+([^;'"]+?)\s+from\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = esm.exec(code))) {
    const clause = m[1].trim();
    const pkg = pkgBase(m[2], 'js');
    add(pkg);
    // namespace: * as ns
    const nsM = clause.match(/\*\s+as\s+([A-Za-z_$][\w$]*)/);
    if (nsM) ns.set(nsM[1], pkg);
    // named: { ... }
    const braceM = clause.match(/\{([^}]*)\}/);
    if (braceM) for (const p of parseNamedClause(braceM[1])) named.set(p.local, { pkg, imported: p.imported });
    // default: leading bare identifier (before any { or *)
    const defM = clause.match(/^([A-Za-z_$][\w$]*)\s*(?:,|$)/);
    if (defM && !nsM) ns.set(defM[1], pkg);
  }
  // CJS: const X = require('pkg')  /  const { a, b: c } = require('pkg')
  const cjs = /(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = cjs.exec(code))) {
    const bind = m[1].trim();
    const pkg = pkgBase(m[2], 'js');
    add(pkg);
    if (bind.startsWith('{')) {
      // require destructure uses `orig: local`
      for (const raw of bind.slice(1, -1).split(',')) {
        const t = raw.trim(); if (!t) continue;
        const mm = t.match(/^([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)$/);
        if (mm) named.set(mm[2], { pkg, imported: mm[1] });
        else if (/^[A-Za-z_$][\w$]*$/.test(t)) named.set(t, { pkg, imported: t });
      }
    } else {
      ns.set(bind, pkg);
    }
  }
  return { named, ns, packages };
}

/**
 * Parse Python imports. Same return shape as extractJsImports.
 *   from pkg import a, b as c        -> named: a->{pkg,a}, c->{pkg,b}
 *   from pkg.sub import a            -> named: a->{pkg,a}  (pkg base)
 *   import pkg / import pkg as p     -> ns: pkg->pkg / p->pkg
 */
export function extractPyImports(content) {
  const code = blankComments(content);
  const named = new Map();
  const ns = new Map();
  const packages = new Set();

  const from = /^[ \t]*from\s+([A-Za-z_][\w.]*)\s+import\s+(.+)$/gm;
  let m;
  while ((m = from.exec(code))) {
    const pkg = pkgBase(m[1], 'py');
    packages.add(pkg);
    let names = m[2].trim();
    if (names === '*') continue;
    names = names.replace(/[()]/g, '');
    for (const p of parseNamedClause(names)) named.set(p.local, { pkg, imported: p.imported });
  }
  const imp = /^[ \t]*import\s+(.+)$/gm;
  while ((m = imp.exec(code))) {
    if (/^\s*import\s+/.test(m[0]) && /\bfrom\b/.test(m[0])) continue;
    for (const raw of m[1].split(',')) {
      const t = raw.trim(); if (!t) continue;
      const mm = t.match(/^([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?$/);
      if (!mm) continue;
      const pkg = pkgBase(mm[1], 'py');
      packages.add(pkg);
      ns.set(mm[2] || mm[1].split('.')[0], pkg);
    }
  }
  return { named, ns, packages };
}

export function extractImports(content, lang) {
  return lang === 'py' ? extractPyImports(content) : extractJsImports(content);
}

/**
 * Find call sites in `content` of `vulnFns` belonging to `pkg`, resolved through
 * this file's import map. Returns [{ fn, line, via }]. Empty if the file does
 * not import `pkg` (the precision gate).
 */
export function findImportAwareCallSites(content, lang, imports, pkg, vulnFns) {
  if (!imports || !vulnFns || !vulnFns.length) return [];
  const importsPkg = [...imports.packages].some((p) => pkgMatches(pkg, p, lang));
  if (!importsPkg) return [];
  const want = new Set(vulnFns);
  const code = blankComments(content);
  const lines = code.split('\n');
  const sites = [];
  const lineOf = (idx) => code.slice(0, idx).split('\n').length;

  // 1) named/aliased imports: localName bound to {pkg, imported} where imported ∈ want
  for (const [local, info] of imports.named) {
    if (!pkgMatches(pkg, info.pkg, lang)) continue;
    if (!want.has(info.imported)) continue;
    const re = new RegExp(`\\b${local.replace(/[$]/g, '\\$&')}\\s*\\(`, 'g');
    let mm;
    while ((mm = re.exec(code))) sites.push({ fn: info.imported, line: lineOf(mm.index), via: local === info.imported ? 'named' : 'alias' });
  }
  // 2) namespace/default member access: ns.fn( where ns→pkg and fn ∈ want
  for (const [local, p] of imports.ns) {
    if (!pkgMatches(pkg, p, lang)) continue;
    for (const fn of want) {
      const sep = lang === 'py' ? '\\.' : '\\.';
      const re = new RegExp(`\\b${local.replace(/[$]/g, '\\$&')}\\s*${sep}\\s*${fn.replace(/[^\w]/g, '\\$&')}\\s*\\(`, 'g');
      let mm;
      while ((mm = re.exec(code))) sites.push({ fn, line: lineOf(mm.index), via: 'namespace' });
    }
  }
  // Dedup by fn+line.
  const seen = new Set();
  return sites.filter((s) => { const k = `${s.fn}:${s.line}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

/**
 * Augment supplyChain findings (npm/pypi only) with import-aware call sites the
 * regex pass missed, gated to files that import the package. Additive: it never
 * removes existing sites, so it cannot regress the route-reachability classifier
 * that runs next — it only gives it more (and more accurate) call sites.
 *
 * Mutates and returns `supplyChain`. Records `sc._importAwareCallSites` (count)
 * for observability.
 */
export function augmentReachabilityViaImports(supplyChain, fileContents, vulnFnHints = {}) {
  if (!Array.isArray(supplyChain)) return supplyChain;
  // Collect the hardcoded/generated hint function names for a package. The
  // hint map is keyed by `pkg` and by versioned `pkg@range` (and packages may
  // be scoped `@scope/pkg`). The vulnerability decision already happened
  // upstream; here we only need candidate function NAMES to locate call sites,
  // so we gather version-agnostically.
  const hintFnsFor = (name) => {
    const out = [];
    for (const [k, v] of Object.entries(vulnFnHints || {})) {
      if (!Array.isArray(v)) continue;
      const atIdx = k.lastIndexOf('@');
      const base = atIdx > 0 ? k.slice(0, atIdx) : k; // >0 keeps a leading-@ scope intact
      if (base === name) out.push(...v);
    }
    return out;
  };
  // Pre-parse imports per JS/PY file once.
  const importsByFile = new Map();
  for (const [file, content] of Object.entries(fileContents || {})) {
    const lang = languageOfFile(file);
    if (!lang) continue;
    try { importsByFile.set(file, { lang, imports: extractImports(content, lang) }); } catch { /* skip unparseable */ }
  }
  if (!importsByFile.size) return supplyChain;

  for (const sc of supplyChain) {
    if (!sc || sc.type !== 'vulnerable_dep') continue;
    if (sc.ecosystem !== 'npm' && sc.ecosystem !== 'pypi') continue;
    const lang = sc.ecosystem === 'npm' ? 'js' : 'py';
    const vulnFns = (sc.osvVulnFunctions || []).map((f) => {
      const d = String(f).lastIndexOf('.'); return d > 0 ? String(f).slice(d + 1) : String(f);
    }).concat(sc.usedVulnerableFunctions || []).concat(hintFnsFor(sc.name));
    const uniqFns = [...new Set(vulnFns.filter(Boolean))];
    if (!uniqFns.length) continue;

    const existing = Array.isArray(sc.vulnerableFunctionCallSites) ? sc.vulnerableFunctionCallSites : [];
    const seen = new Set(existing.map((s) => `${s.file}:${s.line}:${s.fn}`));
    let added = 0;
    for (const [file, { lang: fl, imports }] of importsByFile) {
      if (fl !== lang) continue;
      const content = fileContents[file];
      const sites = findImportAwareCallSites(content, lang, imports, sc.name, uniqFns);
      for (const s of sites) {
        const key = `${file}:${s.line}:${s.fn}`;
        if (seen.has(key)) continue;
        seen.add(key);
        existing.push({ pkg: sc.name, fn: s.fn, file, line: s.line, via: s.via, _r7: true });
        added++;
      }
    }
    if (added > 0) {
      sc.vulnerableFunctionCallSites = existing;
      const usedSet = new Set(sc.usedVulnerableFunctions || []);
      for (const s of existing) usedSet.add(s.fn);
      sc.usedVulnerableFunctions = [...usedSet];
      sc.noKnownCallSite = false;
      sc._importAwareCallSites = (sc._importAwareCallSites || 0) + added;
    }
  }
  return supplyChain;
}
