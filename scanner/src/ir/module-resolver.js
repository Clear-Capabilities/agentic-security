// Import-aware module resolution (E2-02): which function does `svc.run(x)` in routes.js actually call?
//
// The call graph used to resolve a cross-file call by NAME alone: any function called `run` anywhere in the project could be the callee,
// and a member call through an imported module (`const svc = require('./service'); svc.run(x)`) was not resolved at all because `svc.run`
// is not a function name. That was a false negative for the second shape and a false-edge risk for the first. This resolver follows the
// program's own import/export statements instead.
//
// WHAT IT UNDERSTANDS (JavaScript and TypeScript, parsed with Babel; Python by line patterns)
//   imports   `import {a as b} from`, default, namespace, `import x = require()`, `const x = require()`, `const {a: b} = require()`,
//             `const f = require('m').f`; Python `from m import a as b`, `import m as n`, `import a.b`
//   exports   `export function/const/class`, `export {a as b}`, `export {a} from`, `export * from`, `export default`, `exports.a =`,
//             `module.exports.a =`, `module.exports = {a, b: fn}`, `module.exports = fn`, `module.exports = require('./x')`
//   paths     relative specifiers with extension and index-file probing, TypeScript's `./x.js` -> `./x.ts`, Python dotted modules and
//             relative `from . import`
//
// WHAT IT DOES NOT, SAID OUT LOUD (each shows up as a status, never as a guess)
//   dynamic `require(expr)` / `import()`, path aliases (`@/x`, `~/x`, tsconfig `paths`), conditional exports, `export * as ns`, call-through
//   property chains deeper than one level (`a.b.c()`), an export that is not a function, shadowing of an imported name by a local.
//
// TERMINATION. Re-export chains are followed to a depth of MAX_HOPS with a visited set, so a cycle (a re-exports b re-exports a) ends as
// `cycle` and a long chain ends as `depth-limit`. The result always carries the hops it took.
import { parseSync } from '@babel/core';
import presetReact from '@babel/preset-react';
import presetTypescript from '@babel/preset-typescript';

export const MAX_HOPS = 8;
const MAX_FILE_BYTES = 1_500_000;
const BUILTINS = new Set(['assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram', 'dns', 'events', 'fs', 'http', 'http2', 'https', 'net', 'os', 'path', 'perf_hooks', 'process', 'querystring', 'readline', 'stream', 'string_decoder', 'timers', 'tls', 'url', 'util', 'vm', 'worker_threads', 'zlib']);
const JS_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts'];

const posix = (p) => String(p).replace(/\\/g, '/');
function normalize(p) {
  const out = [];
  for (const seg of posix(p).split('/')) { if (seg === '' || seg === '.') continue; if (seg === '..') { if (!out.length) return null; out.pop(); } else out.push(seg); }
  return out.join('/');
}
const dirOf = (f) => { const i = posix(f).lastIndexOf('/'); return i < 0 ? '' : posix(f).slice(0, i); };

// ---- JavaScript / TypeScript extraction -------------------------------------------------------------------------------------

function parseJs(file, code) {
  try {
    return parseSync(code, { filename: file, presets: [presetReact, [presetTypescript, { ignoreExtensions: true }]], parserOpts: { plugins: ['decorators-legacy', 'decoratorAutoAccessors'] }, babelrc: false, configFile: false });
  } catch { return null; }
}
const litString = (n) => (n && (n.type === 'StringLiteral' || (n.type === 'Literal' && typeof n.value === 'string')) ? n.value : (n && n.type === 'TemplateLiteral' && !n.expressions.length && n.quasis.length === 1 ? n.quasis[0].value.cooked : null));
const keyName = (k) => (k.type === 'Identifier' ? k.name : litString(k));
const isRequire = (n) => n && n.type === 'CallExpression' && n.callee.type === 'Identifier' && n.callee.name === 'require' && n.arguments.length === 1;
const isFnNode = (n) => n && (n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression' || n.type === 'FunctionDeclaration');

export function extractJsFacts(file, code) {
  const facts = { language: 'js', imports: [], exports: [], unsupported: [] };
  const ast = parseJs(file, code);
  if (!ast) { facts.unsupported.push('parse-failed'); return facts; }
  const addImport = (local, kind, source, imported = null) => facts.imports.push({ local, kind, source, imported });
  const addExport = (e) => facts.exports.push(e);
  for (const st of ast.program.body) {
    switch (st.type) {
      case 'ImportDeclaration':
        for (const sp of st.specifiers) {
          if (sp.type === 'ImportSpecifier') addImport(sp.local.name, 'named', st.source.value, sp.imported.type === 'Identifier' ? sp.imported.name : sp.imported.value);
          else if (sp.type === 'ImportDefaultSpecifier') addImport(sp.local.name, 'default', st.source.value);
          else if (sp.type === 'ImportNamespaceSpecifier') addImport(sp.local.name, 'namespace', st.source.value);
        }
        break;
      case 'TSImportEqualsDeclaration':
        if (st.moduleReference?.type === 'TSExternalModuleReference') addImport(st.id.name, 'namespace', litString(st.moduleReference.expression));
        break;
      case 'VariableDeclaration':
        for (const d of st.declarations) {
          const init = d.init;
          if (isRequire(init)) {
            const src = litString(init.arguments[0]);
            if (src === null) { facts.unsupported.push('dynamic-require'); continue; }
            if (d.id.type === 'Identifier') addImport(d.id.name, 'namespace', src);
            else if (d.id.type === 'ObjectPattern') for (const p of d.id.properties) {
              if (p.type !== 'ObjectProperty') { facts.unsupported.push('rest-in-require-pattern'); continue; }
              const v = p.value.type === 'AssignmentPattern' ? p.value.left : p.value;
              if (v.type === 'Identifier') addImport(v.name, 'named', src, keyName(p.key));
            }
          } else if (init && init.type === 'MemberExpression' && isRequire(init.object) && d.id.type === 'Identifier' && !init.computed) {
            const src = litString(init.object.arguments[0]);
            if (src !== null) addImport(d.id.name, 'named', src, init.property.name);
          } else if (init && init.type === 'CallExpression' && init.callee.type === 'CallExpression' && isRequire(init.callee)) facts.unsupported.push('call-of-require-result');
          if (isFnNode(init) && st.parent === undefined && d.id.type === 'Identifier') { /* local function value: found through the IR by name */ }
        }
        break;
      case 'ExportNamedDeclaration':
        if (st.declaration) {
          const dec = st.declaration;
          if (dec.type === 'FunctionDeclaration' || dec.type === 'ClassDeclaration') addExport({ name: dec.id.name, local: dec.id.name, kind: dec.type === 'FunctionDeclaration' ? 'function' : 'value' });
          else if (dec.type === 'VariableDeclaration') for (const d of dec.declarations) if (d.id.type === 'Identifier') addExport({ name: d.id.name, local: d.id.name, kind: isFnNode(d.init) ? 'function' : 'value' });
        }
        for (const sp of st.specifiers || []) {
          if (sp.type !== 'ExportSpecifier') { facts.unsupported.push('export-namespace-specifier'); continue; }
          const exported = sp.exported.type === 'Identifier' ? sp.exported.name : sp.exported.value;
          if (st.source) addExport({ name: exported, kind: 'reexport', from: st.source.value, imported: sp.local.name });
          else addExport({ name: exported, local: sp.local.name, kind: 'local' });
        }
        break;
      case 'ExportAllDeclaration':
        addExport({ name: '*', kind: 'star', from: st.source.value });
        break;
      case 'ExportDefaultDeclaration': {
        const d = st.declaration;
        if ((d.type === 'FunctionDeclaration' || d.type === 'ClassDeclaration') && d.id) addExport({ name: 'default', local: d.id.name, kind: 'local' });
        else if (d.type === 'Identifier') addExport({ name: 'default', local: d.name, kind: 'local' });
        else if (isFnNode(d)) addExport({ name: 'default', local: null, kind: 'anonymous-function' });
        else addExport({ name: 'default', local: null, kind: 'value' });
        break;
      }
      case 'ExpressionStatement': {
        const e = st.expression;
        if (e.type === 'AssignmentExpression' && e.operator === '=' && e.left.type === 'MemberExpression') {
          const L = e.left;
          const objIsExports = L.object.type === 'Identifier' && L.object.name === 'exports';
          const objIsModuleExports = L.object.type === 'MemberExpression' && L.object.object.type === 'Identifier' && L.object.object.name === 'module' && L.object.property.name === 'exports';
          const isModuleExportsItself = L.object.type === 'Identifier' && L.object.name === 'module' && !L.computed && L.property.name === 'exports';
          if ((objIsExports || objIsModuleExports) && !L.computed) {
            const r = e.right;
            addExport({ name: L.property.name, local: r.type === 'Identifier' ? r.name : null, kind: isFnNode(r) ? 'function' : r.type === 'Identifier' ? 'local' : 'value' });
          } else if (isModuleExportsItself) {
            const r = e.right;
            if (r.type === 'ObjectExpression') for (const p of r.properties) {
              if (p.type === 'ObjectProperty' || p.type === 'ObjectMethod') { const n = keyName(p.key); if (n) addExport({ name: n, local: p.type === 'ObjectProperty' && p.value.type === 'Identifier' ? p.value.name : null, kind: p.type === 'ObjectMethod' || (p.type === 'ObjectProperty' && isFnNode(p.value)) ? 'function' : p.type === 'ObjectProperty' && p.value.type === 'Identifier' ? 'local' : 'value' }); }
              else facts.unsupported.push('spread-in-module-exports');
            }
            else if (isRequire(r)) { const src = litString(r.arguments[0]); if (src !== null) addExport({ name: '*', kind: 'star', from: src, whole: true }); else facts.unsupported.push('dynamic-require'); }
            else if (r.type === 'Identifier') addExport({ name: 'default', local: r.name, kind: 'local' });
            else if (isFnNode(r)) addExport({ name: 'default', local: r.id?.name ?? null, kind: r.id ? 'local' : 'anonymous-function' });
            else addExport({ name: 'default', local: null, kind: 'value' });
          }
        } else if (e.type === 'CallExpression' && e.callee.type === 'Import') facts.unsupported.push('dynamic-import');
        break;
      }
      default: break;
    }
  }
  return facts;
}

// ---- Python extraction ------------------------------------------------------------------------------------------------------

export function extractPyFacts(file, code) {
  const facts = { language: 'py', imports: [], exports: [], unsupported: [] };
  for (const raw of String(code).split('\n')) {
    const line = raw.replace(/#.*$/, '');
    let m;
    if ((m = /^from\s+(\.+)?([\w.]*)\s+import\s+(.+)$/.exec(line))) {
      const source = `${m[1] || ''}${m[2] || ''}`;
      const list = m[3].replace(/[()\\]/g, '').split(',').map((s) => s.trim()).filter(Boolean);
      for (const item of list) { const mm = /^(\w+|\*)(?:\s+as\s+(\w+))?$/.exec(item); if (!mm) continue; if (mm[1] === '*') facts.unsupported.push('star-import'); else facts.imports.push({ local: mm[2] || mm[1], kind: 'py-from', source, imported: mm[1] }); }
    } else if ((m = /^import\s+(.+)$/.exec(line))) {
      for (const item of m[1].split(',').map((s) => s.trim()).filter(Boolean)) {
        const mm = /^([\w.]+)(?:\s+as\s+(\w+))?$/.exec(item); if (!mm) continue;
        facts.imports.push(mm[2] ? { local: mm[2], kind: 'py-module', source: mm[1] } : { local: mm[1].split('.')[0], kind: 'py-module-root', source: mm[1] });
      }
    } else if ((m = /^(?:async\s+)?def\s+(\w+)\s*\(/.exec(line))) facts.exports.push({ name: m[1], local: m[1], kind: 'function' });
  }
  return facts;
}

// ---- index ------------------------------------------------------------------------------------------------------------------

/**
 * @param {Record<string,string>} fileContents repository-relative path -> source
 * @param {Record<string,{functions:object[]}>} perFile the IR's perFile map
 */
export function buildModuleIndex(fileContents, perFile) {
  const files = new Set(Object.keys(fileContents || {}).map(posix));
  const facts = new Map();
  for (const [f, code] of Object.entries(fileContents || {})) {
    if (typeof code !== 'string' || code.length > MAX_FILE_BYTES) continue;
    const file = posix(f);
    if (/\.(js|jsx|ts|tsx|mjs|cjs|mts|cts)$/.test(file)) { if (/\b(import|export|require|module\.exports|exports\.)/.test(code)) facts.set(file, extractJsFacts(file, code)); }
    else if (/\.py$/.test(file)) facts.set(file, extractPyFacts(file, code));
  }
  const fnsByFile = new Map();
  for (const [f, ir] of Object.entries(perFile || {})) fnsByFile.set(posix(f), (ir?.functions || []).filter((fn) => fn.name !== '<module>'));

  function resolveSpecifier(from, spec, language) {
    if (typeof spec !== 'string' || !spec) return { kind: 'unresolved', reason: 'empty specifier' };
    if (language === 'py') {
      const rel = /^(\.+)(.*)$/.exec(spec);
      let baseDir; let dotted;
      if (rel) { baseDir = dirOf(from); for (let i = 1; i < rel[1].length; i++) baseDir = dirOf(baseDir); dotted = rel[2]; } else { baseDir = ''; dotted = spec; }
      const rest = dotted ? dotted.split('.').join('/') : '';
      const stem = normalize(baseDir ? (rest ? `${baseDir}/${rest}` : baseDir) : rest);
      if (stem === null) return { kind: 'unresolved', reason: 'path leaves the repository' };
      for (const c of [`${stem}.py`, `${stem}/__init__.py`]) if (stem !== '' && files.has(c)) return { kind: 'file', file: c };
      if (stem === '' && files.has('__init__.py')) return { kind: 'file', file: '__init__.py' };
      return rel ? { kind: 'unresolved', reason: `relative module ${spec} not found` } : { kind: 'external', reason: 'not a module of this repository' };
    }
    if (spec.startsWith('node:') || BUILTINS.has(spec.split('/')[0])) return { kind: 'external', reason: 'node builtin' };
    if (spec.startsWith('.') || spec.startsWith('/')) {
      const stem = normalize(spec.startsWith('/') ? spec.slice(1) : `${dirOf(from)}/${spec}`);
      if (stem === null) return { kind: 'unresolved', reason: 'path leaves the repository' };
      const noExt = stem.replace(/\.(m|c)?js$/, '');
      const cands = [stem, ...JS_EXT.map((e) => stem + e), noExt + '.ts', noExt + '.tsx', noExt + '.mts', noExt + '.cts', ...JS_EXT.map((e) => `${stem}/index${e}`)];
      for (const c of cands) if (files.has(c)) return { kind: 'file', file: c };
      return { kind: 'unresolved', reason: `${spec} not found in the repository` };
    }
    if (/^(@\/|~\/|#|\$)/.test(spec)) return { kind: 'unresolved', reason: 'path alias: tsconfig paths and bundler aliases are not read' };
    return { kind: 'external', reason: 'package import' };
  }

  function functionIn(file, local) {
    const hits = (fnsByFile.get(file) || []).filter((fn) => fn.name === local || String(fn.name).endsWith(`.${local}`));
    if (hits.length === 1) return { qid: hits[0].qid };
    return hits.length ? { ambiguous: hits.map((h) => h.qid) } : null;
  }

  // follow an export of `file` named `name` to the function that implements it
  function resolveExport(file, name, hops, visited) {
    const key = `${file}#${name}`;
    if (visited.has(key)) return { status: 'cycle', hops, reason: `re-export cycle at ${key}` };
    if (hops.length >= MAX_HOPS) return { status: 'depth-limit', hops, reason: `more than ${MAX_HOPS} re-export hops` };
    visited.add(key);
    const f = facts.get(file);
    if (!f) return { status: 'unresolved-export', hops, reason: `${file} has no import/export statements` };
    const hop = (extra) => [...hops, { file, name, ...extra }];
    const direct = f.exports.filter((e) => e.name === name && e.kind !== 'star');
    if (direct.length) {
      const e = direct[direct.length - 1];
      if (e.kind === 'reexport') {
        const spec = resolveSpecifier(file, e.from, f.language);
        if (spec.kind === 'file') return resolveExport(spec.file, e.imported, hop({ via: 're-export', from: e.from }), visited);
        return { status: spec.kind === 'external' ? 'external' : 'unresolved-import', hops: hop({ via: 're-export', from: e.from }), reason: spec.reason };
      }
      if (e.kind === 'anonymous-function') {
        const cands = (fnsByFile.get(file) || []).filter((fn) => /^(default|anonymous|<anonymous>)/i.test(fn.name));
        return cands.length === 1 ? { status: 'resolved', qid: cands[0].qid, file, exportName: name, hops: hop({}) } : { status: 'unresolved-export', hops: hop({}), reason: 'anonymous default export function not identifiable in the IR' };
      }
      if (e.kind === 'value') {
        const byName = functionIn(file, name);
        if (byName?.qid) return { status: 'resolved', qid: byName.qid, file, exportName: name, hops: hop({}) };
        return { status: 'unresolved-export', hops: hop({}), reason: `${name} is exported but is not a function the IR knows` };
      }
      const local = e.local || name;
      const fn = functionIn(file, local) || (local !== name ? functionIn(file, name) : null);
      if (fn?.qid) return { status: 'resolved', qid: fn.qid, file, exportName: name, hops: hop({}) };
      if (fn?.ambiguous) return { status: 'ambiguous', hops: hop({}), reason: `several functions named ${local} in ${file}`, candidates: fn.ambiguous };
      // an imported binding re-exported by name (`import {a} from './x'; export {a}`)
      const imp = f.imports.find((i) => i.local === local);
      if (imp) return resolveBinding(file, imp, hop({ via: 'import-then-export' }), visited);
      return { status: 'unresolved-export', hops: hop({}), reason: `${local} is exported by ${file} but no function of that name was found` };
    }
    // `export * from` / `module.exports = require()`: search each star target; more than one hit is ambiguous
    const stars = f.exports.filter((e) => e.kind === 'star');
    const found = [];
    for (const s of stars) {
      const spec = resolveSpecifier(file, s.from, f.language);
      if (spec.kind !== 'file') continue;
      const r = resolveExport(spec.file, name, hop({ via: s.whole ? 'module.exports = require' : 'export *', from: s.from }), new Set(visited));
      if (r.status === 'resolved') found.push(r); else if (r.status === 'cycle' || r.status === 'depth-limit') return r;
    }
    if (found.length === 1) return found[0];
    if (found.length > 1) return { status: 'ambiguous', hops: hop({}), reason: `${name} is provided by ${found.length} star re-exports`, candidates: found.map((r) => r.qid) };
    return { status: 'unresolved-export', hops: hop({}), reason: `${file} does not export ${name}` };
  }

  function resolveBinding(callerFile, imp, hops, visited) {
    const f = facts.get(callerFile);
    const spec = resolveSpecifier(callerFile, imp.source, f?.language);
    if (spec.kind === 'external') return { status: 'external', hops, reason: spec.reason, source: imp.source };
    if (spec.kind === 'unresolved') return { status: 'unresolved-import', hops, reason: spec.reason, source: imp.source };
    const name = imp.kind === 'default' ? 'default' : imp.kind === 'py-from' ? imp.imported : imp.imported;
    if (name == null) return { status: 'module', file: spec.file, hops, source: imp.source };
    return resolveExport(spec.file, name, [...hops, { file: callerFile, via: `import ${imp.source}` }], visited);
  }

  /** Resolve the callee text of a call made in `callerFile`. Never throws; always terminates. */
  function resolveCall(callerFile, calleeText) {
    const caller = posix(callerFile);
    const f = facts.get(caller);
    if (!f || typeof calleeText !== 'string' || !calleeText) return { status: 'no-facts', hops: [] };
    const parts = calleeText.split('.');
    const head = parts[0];
    const imp = f.imports.find((i) => i.local === head);
    if (!imp) return { status: 'not-imported', hops: [] };
    const visited = new Set();
    if (parts.length === 1) {
      if (imp.kind === 'namespace' || imp.kind === 'py-module' || imp.kind === 'py-module-root') {
        // calling the module object itself: `const f = require('./f'); f(x)` -> the module's default / module.exports function
        const spec = resolveSpecifier(caller, imp.source, f.language);
        if (spec.kind !== 'file') return { status: spec.kind === 'external' ? 'external' : 'unresolved-import', hops: [], reason: spec.reason, source: imp.source };
        return resolveExport(spec.file, 'default', [{ file: caller, via: `import ${imp.source}` }], visited);
      }
      return resolveBinding(caller, imp, [], visited);
    }
    if (parts.length > 2 && !(imp.kind === 'py-module-root')) return { status: 'unsupported', hops: [], reason: `${calleeText}: property chains deeper than one level are not resolved`, source: imp.source };
    if (imp.kind === 'namespace' || imp.kind === 'py-module') {
      const spec = resolveSpecifier(caller, imp.source, f.language);
      if (spec.kind === 'external') return { status: 'external', hops: [], reason: spec.reason, source: imp.source };
      if (spec.kind !== 'file') return { status: 'unresolved-import', hops: [], reason: spec.reason, source: imp.source };
      return resolveExport(spec.file, parts[1], [{ file: caller, via: `import ${imp.source}` }], visited);
    }
    if (imp.kind === 'py-module-root') {
      // `import a.b` binds `a`; `a.b.fn()` names the module a/b and the function fn
      const dotted = parts.slice(0, -1).join('.');
      if (!imp.source.startsWith(dotted)) return { status: 'unsupported', hops: [], reason: `${calleeText} does not match import ${imp.source}`, source: imp.source };
      const spec = resolveSpecifier(caller, dotted, 'py');
      if (spec.kind === 'external') return { status: 'external', hops: [], reason: spec.reason, source: imp.source };
      if (spec.kind !== 'file') return { status: 'unresolved-import', hops: [], reason: spec.reason, source: imp.source };
      return resolveExport(spec.file, parts[parts.length - 1], [{ file: caller, via: `import ${imp.source}` }], visited);
    }
    // `x.y()` where x is a named/default import: a method on an imported value, not a module member. If the import is an external
    // package that is still the answer that matters (`axios.get` is the package's, not ours).
    const specOther = resolveSpecifier(caller, imp.source, f.language);
    if (specOther.kind === 'external') return { status: 'external', hops: [], reason: specOther.reason, source: imp.source };
    return { status: 'unsupported', hops: [], reason: `${calleeText}: member of an imported value, not of a module`, source: imp.source };
  }

  return { facts, resolveSpecifier, resolveExport: (file, name) => resolveExport(posix(file), name, [], new Set()), resolveCall };
}
