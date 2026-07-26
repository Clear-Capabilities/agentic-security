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

  // Project-wide qualified-name index. C++ splits declaration from definition
  // (`Foo::bar` declared in a header, defined in a .cpp), so a file-local
  // lookup resolves almost nothing. Definitions take precedence over
  // declarations, which are indexed only as a fallback.
  const byQname = new Map();
  for (const ir of Object.values(perFileIR || {})) {
    for (const fn of (ir && ir.functions) || []) {
      if (!fn.qname) continue;
      const existing = byQname.get(fn.qname);
      if (!existing || (existing.isDeclaration && !fn.isDeclaration)) {
        byQname.set(fn.qname, fn);
      }
      // Also index the bare method name so `b->fill(p)` — which carries no
      // class qualification at the call site — can still find `Buffer::fill`,
      // but only when that bare name is unambiguous project-wide.
      const bare = fn.qname.includes('::') ? fn.qname.split('::').pop() : null;
      if (bare) {
        const key = `~bare~${bare}`;
        if (byQname.has(key)) {
          const cur = byQname.get(key);
          if (cur !== null && cur.qname !== fn.qname) {
            byQname.set(key, null); // ambiguous — refuse to guess
          } else if (cur && cur.isDeclaration && !fn.isDeclaration) {
            // Same method, declaration seen first — a later definition must
            // still win, exactly as the direct qname index above.
            byQname.set(key, fn);
          }
        } else {
          byQname.set(key, fn);
        }
      }
    }
  }

  // Qualified-name resolution (C++ header/source pairing). Try the name as
  // written, then its dotted form re-expressed with `::`, then the
  // unambiguous bare name. Returns a qid or null — never a bodiless
  // declaration's qid, and never a guess when a bare name is ambiguous.
  function resolveQname(name) {
    if (!name) return null;
    const direct = byQname.get(name);
    if (direct && !direct.isDeclaration) return direct.qid;
    const colonised = name.replace(/\./g, '::');
    const viaColon = byQname.get(colonised);
    if (viaColon && !viaColon.isDeclaration) return viaColon.qid;
    const bare = name.includes('.') || name.includes('::')
      ? name.split(/[.:]+/).pop()
      : name;
    const viaBare = byQname.get(`~bare~${bare}`);
    if (viaBare && !viaBare.isDeclaration) return viaBare.qid;
    return null;
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
                       // 3. Cross-TU qualified-name index (C++ header/source pairing).
                       resolveQname(c.callee) ||
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
  function resolve(name, callerFile) {
    if (!name || typeof name !== 'string') return null;
    // Roadmap #3: same-file preference. A bare name (`handler`, `save`,
    // `query`) defined in several files would otherwise resolve to whichever
    // file Map is iterated first, mis-targeting interprocedural taint to a
    // same-named function in an unrelated file. When the caller's own file
    // defines the name, that is overwhelmingly the intended callee — prefer
    // it. Backward-compatible: with no callerFile (or no local match) the
    // original resolution order is unchanged, so no edge is ever dropped.
    if (callerFile) {
      const local = byNameInFile.get(callerFile);
      if (local && local.has(name)) return local.get(name);
    }
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
    // Cross-TU qualified-name index (C++ header/source pairing) — runs after
    // all existing rules and only matches functions carrying a `qname`.
    const viaQname = resolveQname(name);
    if (viaQname) return viaQname;
    return null;
  }
  return { functions, edges, callersOf, resolve };
}
