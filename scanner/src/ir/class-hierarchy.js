// Class Hierarchy Analysis (CHA) — JS/TS (P1.2).
//
// Walks the Babel ASTs across the project to build:
//
//   classDefs:    Map<className, { file, line, methods, fields, extends?, implements? }>
//   methodOwners: Map<methodQid, className>
//   typeOfVar:    Map<file::scope::varName, className>  — assignment-time type
//                                                          inference (simple, no
//                                                          flow analysis)
//
// The output is consumed by the dataflow engine's receiver-sensitivity layer
// (`receiver-context.js`) and by `callgraph.js` to refine virtual-call resolution.
//
// Scope of this v1: shallow analysis. We DON'T resolve:
//   - polymorphic types (T<U>),
//   - cross-file class inheritance via dynamic imports,
//   - mixins (Object.assign / class factories),
//   - prototype-based assignments outside `class` declarations.
//
// What we DO catch:
//   - `class Foo {}` declarations + their method signatures.
//   - `class Bar extends Foo {}` extends relationships.
//   - `let x = new Foo()` typed-LHS inference — and ONLY this shape. The
//     assign's RHS must be a call with `isNew: true` and a bare PascalCase
//     (or already-known-class) identifier callee.
//
// What this header used to claim and the code has never done (corrected in
// whole-branch review; do not re-add the claim without the code):
//   - `const x: Foo = ...` TS-annotated-LHS inference — NOT implemented. A
//     TS type annotation never reaches typeOfVar.
//   - `function buildFoo(): Foo { ... }` typed-return inference — NOT
//     implemented. `const x = buildFoo()` is untyped (correctly: it is a
//     plain call, not a `new`), so classOfVar returns null for `x`.
// Both are "unknown", which downstream consumers must treat as permissive.

const _AST_CACHE = new WeakMap();

/**
 * Build the CHA over a perFileIR map (file → parsed IR with raw AST attached
 * under `_ast`). When AST isn't attached, fall back to the IR's own
 * structural hints (class names appearing in qids).
 */
export function buildClassHierarchy(perFileIR) {
  const classes = new Map();       // className -> { file, line, methods, extends }
  const methodOwners = new Map();  // qid -> className
  const typeOfVar = new Map();     // file::scope::var -> className

  if (!perFileIR || typeof perFileIR !== 'object') {
    return { classes, methodOwners, typeOfVar };
  }

  for (const [file, ir] of Object.entries(perFileIR)) {
    if (!ir) continue;
    // Language-neutral inheritance input. A parser may attach a `classes`
    // array to its IR record; parser-cpp.js does. Nothing else populates
    // `extends`, for any language, so this is purely additive.
    if (Array.isArray(ir.classes)) {
      for (const c of ir.classes) {
        if (!c || !c.name) continue;
        let cls = classes.get(c.name);
        if (!cls) {
          cls = { name: c.name, file, line: c.line || 0, methods: new Set(), extends: null };
          classes.set(c.name, cls);
        }
        // v1 keeps a single base: the CHA walk in resolveMethod follows one
        // chain. Multiple inheritance is flattened to the first base, which is
        // a deliberate over-simplification recorded in PRD §6.8.
        if (!cls.extends && Array.isArray(c.bases) && c.bases.length) {
          cls.extends = c.bases[0];
        }
      }
    }
    if (!Array.isArray(ir.functions)) continue;
    // Recover class names from method qids. Two shapes are recognized:
    //   1. "Foo.bar@line#hash" — class and method dot-joined in the qid's
    //      last segment (parser-cpp.js's convention).
    //   2. "<file>::ClassName::method@line#hash" — class and method as
    //      separate `::`-joined qid segments (parser-js.js's and
    //      parser-java.js's ACTUAL convention — this was previously
    //      unrecognized, which silently left `classes` permanently empty
    //      for JS/Java, making resolveMethod() a no-op for those languages;
    //      the only prior test for this coded the dot-joined shape by hand
    //      rather than checking real parser output, which is how the gap
    //      went uncaught. See test/receiver-type-and-nested-calls.test.js's
    //      "registers a real JS class method from actual parser output"
    //      regression test.)
    for (const fn of ir.functions) {
      if (!fn.qid) continue;
      const segs = fn.qid.split('::');
      const tail = segs[segs.length - 1] || '';
      const dotIdx = tail.indexOf('.');
      let className = null;
      let methodName = null;
      if (dotIdx > 0) {
        className = tail.slice(0, dotIdx);
        methodName = tail.slice(dotIdx + 1).replace(/@\d+#[0-9a-f]+$/, '');
      } else if (segs.length >= 3 && /^[A-Z]/.test(segs[segs.length - 2])) {
        // Gated on the second-to-last segment being PascalCase so this
        // doesn't misfire on an ordinary nested-function scope segment.
        className = segs[segs.length - 2];
        methodName = tail.replace(/@\d+(#[0-9a-f]+)?$/, '');
      }
      if (!className || !methodName) continue;
      methodOwners.set(fn.qid, className);
      let cls = classes.get(className);
      if (!cls) {
        cls = { name: className, file, line: fn.line || 0, methods: new Set(), extends: null };
        classes.set(className, cls);
      }
      cls.methods.add(methodName);
    }
    // Try to recover `let x = new Foo(...)` typing — we walk the IR's
    // assign nodes for any call whose callee starts with a known class name.
    for (const fn of ir.functions) {
      const cfg = fn.cfg;
      if (!cfg || !cfg.nodes) continue;
      for (const id of Object.keys(cfg.nodes)) {
        const n = cfg.nodes[id];
        if (!n || n.kind !== 'assign') continue;
        const src = n.source;
        if (!src || src.kind !== 'call') continue;
        // `new Foo()` is shaped as { kind: 'call', callee: { kind: 'ident', name: 'Foo' }, isNew: true }
        // `isNew` is REQUIRED, not optional: without it a plain call to a
        // PascalCase-named function (`let x = SomeFactoryFn()`) is
        // indistinguishable from a real constructor call and silently
        // mistypes `x` as class `SomeFactoryFn`. That mistype then flows
        // into the dataflow engine's receiver-type gate, where a wrong
        // "confidently resolved" type can suppress a real finding. Same
        // `n.source.isNew` test collectInstantiatedClasses uses below.
        if (!src.isNew) continue;
        const callee = src.callee;
        const className = callee?.kind === 'ident' ? callee.name : null;
        if (!className) continue;
        if (classes.has(className) || /^[A-Z]/.test(className)) {
          // Convention: PascalCase `new` callees treated as constructors.
          const target = typeof n.target === 'string' ? n.target : null;
          if (target) typeOfVar.set(`${file}::${fn.qid}::${target}`, className);
        }
      }
    }
  }

  return { classes, methodOwners, typeOfVar };
}

/**
 * Given a variable reference (file + enclosing fn qid + var name), return
 * the inferred class name if any.
 */
export function classOfVar(cha, file, fnQid, varName) {
  if (!cha || !cha.typeOfVar || !varName) return null;
  return cha.typeOfVar.get(`${file}::${fnQid}::${varName}`) || null;
}

/**
 * Given a class name + method, return the resolved qid (if we know it).
 * v1: no override resolution — only direct definition.
 */
export function resolveMethod(cha, className, methodName) {
  if (!cha || !cha.classes || !className || !methodName) return null;
  // Walk the class hierarchy upward — extends chain — to find a method.
  let cur = className;
  const seen = new Set();
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    const cls = cha.classes.get(cur);
    if (!cls) break;
    if (cls.methods && cls.methods.has(methodName)) {
      // Return a synthetic qid; the call graph may have its own resolution.
      return { className: cur, methodName };
    }
    cur = cls.extends || null;
  }
  return null;
}

// ════════════════════════════════════════════════════════════════════════════
// P4.5 — Rapid Type Analysis (RTA)
// ════════════════════════════════════════════════════════════════════════════
//
// CHA over-approximates virtual dispatch: a call on a receiver of type
// Animal resolves to EVERY method named `speak` on EVERY subclass — even
// subclasses that are never instantiated. RTA narrows this by tracking
// which classes are actually instantiated in the program.

/**
 * Walk the IR for `new ClassName(...)` expressions and return the set of
 * instantiated class names.
 */
export function collectInstantiatedClasses(perFileIR) {
  const live = new Set();
  if (!perFileIR) return live;
  for (const ir of Object.values(perFileIR)) {
    for (const fn of (ir.functions || [])) {
      const cfg = fn.cfg;
      if (!cfg || !cfg.nodes) continue;
      for (const id of Object.keys(cfg.nodes)) {
        const n = cfg.nodes[id];
        if (!n) continue;
        if (n.kind === 'assign' && n.source && n.source.kind === 'call' && n.source.isNew) {
          const callee = n.source.callee;
          if (callee && typeof callee === 'object' && callee.kind === 'ident') live.add(callee.name);
          else if (typeof callee === 'string') live.add(callee);
        }
        if (n.kind === 'call' && n.isNew && typeof n.callee === 'string') live.add(n.callee);
      }
    }
  }
  return live;
}

/**
 * RTA-refined virtual-call resolution. Narrows a virtual-call candidate set
 * to actually-live (instantiated) classes.
 *
 *   cha:           class hierarchy
 *   methodName:    the method being dispatched
 *   liveClasses:   output of collectInstantiatedClasses
 *   rootClass:     the declared/inferred receiver type (or null = any class)
 */
export function resolveMethodRTA(cha, methodName, liveClasses, rootClass) {
  if (!cha || !methodName || !liveClasses) return [];
  const out = [];
  for (const [cn, cls] of cha.classes) {
    if (!liveClasses.has(cn)) continue;
    if (!cls.methods || !cls.methods.has(methodName)) continue;
    if (rootClass) {
      // cn must be rootClass or a transitive subclass.
      let cur = cn;
      let inHierarchy = false;
      const seen = new Set();
      while (cur && !seen.has(cur)) {
        seen.add(cur);
        if (cur === rootClass) { inHierarchy = true; break; }
        cur = cha.classes.get(cur)?.extends || null;
      }
      if (!inHierarchy) continue;
    }
    out.push({ className: cn, methodName });
  }
  return out;
}

/**
 * Annotate an existing CHA with the live-class set so consumers don't have
 * to recompute it.
 */
export function annotateRTA(cha, perFileIR) {
  if (!cha) return cha;
  cha.liveClasses = collectInstantiatedClasses(perFileIR);
  return cha;
}
