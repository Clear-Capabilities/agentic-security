//
// Import maps (JS/TS and Python): which local name in a file refers to which module, and which declaration in it.
//
// The shared IR resolves a call to a declaration only for the shapes it models; a destructured `require` or a named
// ES import is not one of them, so a call such as `getReport(id)` arrives as an edge to nowhere. Left alone, nearly
// every Express/Node route would be reported as having an unresolved call. This module recovers those edges from the
// import statements themselves and records HOW each was resolved, so the result is still evidence and not a guess:
//
//   exact-import   the local name is bound by an import of a module in the repository, and that module declares a
//                  function of that name (or, for a namespace, of the member name)
//   third-party    the module is a package, not a repository file: a boundary, not first-party code
//   unresolved     a relative import that no repository file satisfies
//
// Scope, stated plainly: this is statement-level pattern matching. Re-export chains, `import()` expressions,
// computed `require` arguments and package-relative aliases (tsconfig paths) are not followed.
import * as path from 'node:path';

const JS_EXTS = ['', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '/index.js', '/index.mjs', '/index.ts', '/index.tsx'];

function resolveJsModule(fromFile, source, files) {
  if (!source.startsWith('.')) return { kind: 'third-party', target: null };
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), source));
  for (const ext of JS_EXTS) if (files.has(base + ext)) return { kind: 'repo', target: base + ext };
  return { kind: 'unresolved', target: null };
}

function resolvePyModule(fromFile, dotted, files) {
  let dir = path.posix.dirname(fromFile);
  let mod = dotted;
  const lead = /^\.+/.exec(mod);
  const candidatesBase = [];
  if (lead) {
    for (let i = 1; i < lead[0].length; i++) dir = path.posix.dirname(dir);
    mod = mod.slice(lead[0].length);
    candidatesBase.push(dir === '.' ? '' : dir);
  } else {
    candidatesBase.push('', path.posix.dirname(fromFile) === '.' ? '' : path.posix.dirname(fromFile));
  }
  for (const b of candidatesBase) {
    const rel = mod.replace(/\./g, '/');
    for (const cand of [rel ? `${rel}.py` : '__init__.py', rel ? `${rel}/__init__.py` : '__init__.py']) {
      const full = b ? path.posix.join(b, cand) : cand;
      if (files.has(full)) return { kind: 'repo', target: full };
    }
  }
  return { kind: lead ? 'unresolved' : 'third-party', target: null };
}

function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' ')).replace(/(^|[^:'"`\\])\/\/[^\n]*/g, (m, p1) => p1 + ' '.repeat(m.length - p1.length));
}

function names(list) {
  return list.split(',').map(s => s.trim()).filter(Boolean).map(s => {
    const m = /^(?:\w+\s+as\s+)?([\w$]+)$/.exec(s.replace(/^type\s+/, '').replace(/^([\w$]+)\s*:\s*([\w$]+)$/, '$1 as $2'));
    const parts = s.replace(/^type\s+/, '').split(/\s+as\s+|\s*:\s*/).map(x => x.trim()).filter(Boolean);
    void m;
    if (parts.length === 2) return { imported: parts[0], local: parts[1] };
    if (parts.length === 1) return { imported: parts[0], local: parts[0] };
    return null;
  }).filter(Boolean).filter(n => /^[\w$]+$/.test(n.imported) && /^[\w$]+$/.test(n.local));
}

/** Import entries for one JS/TS file. */
function jsImports(file, text, files) {
  const t = stripComments(text);
  const out = [];
  const add = (local, source, member) => out.push({ file, local, source, member, ...resolveJsModule(file, source, files) });
  for (const m of t.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?require\(\s*['"]([^'"]+)['"]\s*\)/g)) for (const n of names(m[1])) add(n.local, m[2], n.imported);
  for (const m of t.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?require\(\s*['"]([^'"]+)['"]\s*\)/g)) add(m[1], m[2], '*');
  for (const m of t.matchAll(/\bimport\s+(?:type\s+)?([\w$]+)?\s*,?\s*(?:\{([^}]*)\}|\*\s+as\s+([\w$]+))?\s*from\s*['"]([^'"]+)['"]/g)) {
    if (m[1]) add(m[1], m[4], 'default');
    if (m[2]) for (const n of names(m[2])) add(n.local, m[4], n.imported);
    if (m[3]) add(m[3], m[4], '*');
  }
  return out;
}

function pyImports(file, text, files) {
  const out = [];
  const add = (local, source, member) => out.push({ file, local, source, member, ...resolvePyModule(file, source, files) });
  // the unparenthesised form ends at the line end; only the parenthesised form may span lines
  for (const m of text.matchAll(/^[ \t]*from[ \t]+([.\w]+)[ \t]+import[ \t]+(?:\(([\w\s,]+)\)|([\w \t,]+))/gm)) {
    for (const n of (m[2] ?? m[3]).split(',').map(s => s.trim()).filter(Boolean)) {
      const p = n.split(/\s+as\s+/);
      add(p[1] || p[0], m[1], p[0]);
    }
  }
  for (const m of text.matchAll(/^[ \t]*import\s+([.\w]+)(?:\s+as\s+(\w+))?\s*$/gm)) add(m[2] || m[1].split('.')[0], m[1], '*');
  return out;
}

/** All import entries, deterministically ordered. */
export function buildImportMap(fileContents) {
  const files = new Set(Object.keys(fileContents));
  const out = [];
  for (const file of [...files].sort()) {
    if (/\.(?:js|jsx|mjs|cjs|ts|tsx)$/i.test(file)) out.push(...jsImports(file, fileContents[file], files));
    else if (/\.py$/i.test(file)) out.push(...pyImports(file, fileContents[file], files));
  }
  return out.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || (a.local < b.local ? -1 : a.local > b.local ? 1 : 0) || (a.source < b.source ? -1 : 1));
}

/**
 * Resolve a callee name used in `file` against the import map.
 * Returns { kind:'exact-import', targetFile, member } | { kind:'third-party' } | { kind:'unresolved-import' } | null.
 */
export function resolveViaImports(imports, file, calleeName) {
  const parts = String(calleeName || '').split('.');
  const head = parts[0];
  const imp = imports.filter(i => i.file === file && i.local === head);
  if (!imp.length) return null;
  const i = imp[0];
  if (i.kind === 'third-party') return { kind: 'third-party' };
  if (i.kind === 'unresolved') return { kind: 'unresolved-import' };
  if (parts.length === 1) {
    const member = i.member === '*' || i.member === 'default' ? head : i.member;
    return { kind: 'exact-import', targetFile: i.target, member, namespaceCall: i.member === '*' || i.member === 'default' };
  }
  if (i.member === '*' || i.member === 'default') return { kind: 'exact-import', targetFile: i.target, member: parts[parts.length - 1], namespaceCall: false };
  // `db.query()` where `db` is a NAMED import: a method of an imported object, not a function of that module
  return { kind: 'imported-object-method' };
}
