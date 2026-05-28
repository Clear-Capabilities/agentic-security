// Cross-file call graph from the JS/TS IR.
//
// Resolves call sites to callee function IDs. Resolution rules (best-effort):
//   1. Direct function call to a name defined in the same file → resolve to that fn.
//   2. Method call `obj.foo()` where obj is a class instance with a known
//      method `foo` in the same file → resolve to that method.
//   3. Module-imported name: look up in another file's exports.
//   4. Anything else → unresolved; the dataflow engine treats the callee as
//      an opaque sink for taint.

export function buildCallGraph(perFileIR, fileContents) {
  const functions = new Map();
  const byNameInFile = new Map();
  const classMethods = new Map();
  // Re-export resolution: track `export { x } from './y'` and `module.exports = require('./y')`
  const reexportMap = new Map();
  if (fileContents) {
    for (const [file, code] of Object.entries(fileContents)) {
      if (!code || typeof code !== 'string') continue;
      for (const m of code.matchAll(/export\s*\{\s*([^}]+)\s*\}\s*from\s*['"]([^'"]+)['"]/g)) {
        const names = m[1].split(',').map(n => n.trim().split(/\s+as\s+/));
        for (const [orig, alias] of names) {
          reexportMap.set(`${file}::${alias || orig}`, { sourceFile: m[2], sourceName: orig.trim() });
        }
      }
      const cjsReexport = code.match(/module\.exports\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/);
      if (cjsReexport) reexportMap.set(`${file}::*`, { sourceFile: cjsReexport[1], sourceName: '*' });
    }
  }

  for (const file of Object.keys(perFileIR || {})) {
    const ir = perFileIR[file];
    if (!ir || !ir.functions) continue;
    byNameInFile.set(file, new Map());
    for (const fn of ir.functions) {
      functions.set(fn.qid, fn);
      byNameInFile.get(file).set(fn.name, fn.qid);
      const m = fn.qid.match(/::([A-Z]\w*)::(\w+)@/);
      if (m) classMethods.set(`${m[1]}.${m[2]}`, fn.qid);
    }
  }

  // Resolve each call site.
  const edges = []; // { caller, site, callee, ambiguous? }
  for (const fn of functions.values()) {
    for (const c of (fn.calls || [])) {
      if (!c.callee) { edges.push({ caller: fn.qid, site: c.site, callee: null, line: c.line }); continue; }
      // 1. Direct name in same file
      const sameFileMap = byNameInFile.get(fn.file);
      const resolved = sameFileMap?.get(c.callee) ||
                       classMethods.get(c.callee) ||
                       // 2. ClassName.method form
                       (c.callee.includes('.') ? classMethods.get(c.callee) : null) ||
                       null;
      edges.push({ caller: fn.qid, site: c.site, callee: resolved, calleeName: c.callee, line: c.line });
    }
  }

  // Reverse index: callee → callers.
  const callersOf = new Map();
  for (const e of edges) {
    if (!e.callee) continue;
    if (!callersOf.has(e.callee)) callersOf.set(e.callee, []);
    callersOf.get(e.callee).push(e);
  }
  // Premortem #7: expose a name→qid resolver so the taint engine can ask
  // the call graph for the callee's qid at the assign-from-call site.
  // Same precedence as the edge resolution above (same-file ident wins,
  // ClassName.method falls back).
  function resolve(name) {
    if (!name || typeof name !== 'string') return null;
    for (const m of byNameInFile.values()) {
      if (m.has(name)) return m.get(name);
    }
    if (classMethods.has(name)) return classMethods.get(name);
    if (name.includes('.')) {
      const tail = name.split('.').slice(-1)[0];
      for (const m of byNameInFile.values()) {
        if (m.has(tail)) return m.get(tail);
      }
    }
    // Follow re-exports: if name was re-exported from another file, resolve there
    for (const [key, { sourceName }] of reexportMap) {
      if (key.endsWith(`::${name}`) || (sourceName === name)) {
        for (const m of byNameInFile.values()) {
          if (m.has(sourceName)) return m.get(sourceName);
        }
      }
    }
    return null;
  }
  return { functions, edges, callersOf, resolve };
}
