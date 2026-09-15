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
  // A variable assigned two DIFFERENT constructed types within one function
  // must never resolve to either — same "refuse to guess on ambiguity"
  // convention `_localVarConstructedTypes` (parser-java.js/parser-cs.js)
  // already enforces at parse time for the callee-string-rewrite path. This
  // map had NO ambiguity tracking of its own (last assign silently won) —
  // latent since day one, but never exercised for hand-rolled-parser
  // languages because `_resolveMemberCalleeViaCHA` (engine.js) only ever
  // consulted `classOfVar` for the Babel `{kind:'member'}` shape (JS-only)
  // until PRD W2.5 extended it to flat dotted-string callees too. Caught by
  // `test/catalog-cs-p1.test.js`'s existing ambiguity-refusal regression
  // test the moment that extension shipped.
  const ambiguousVarKeys = new Set();

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
          cls = { name: c.name, file, line: c.line || 0, methods: new Set(), extends: null, bases: [], fields: new Set() };
          classes.set(c.name, cls);
        }
        if (!cls.bases) cls.bases = [];
        if (!cls.fields) cls.fields = new Set();
        // v1 keeps a single base: the CHA walk in resolveMethod follows one
        // chain. Multiple inheritance is flattened to the first base, which is
        // a deliberate over-simplification recorded in PRD §6.8.
        if (!cls.extends && Array.isArray(c.bases) && c.bases.length) {
          cls.extends = c.bases[0];
        }
        // Full base/interface list (SARD_80_F1_SCANNER_PRD.md — abstract/
        // interface-receiver dispatch, Juliet flow variants 81/82): `extends`
        // above follows exactly one chain for resolveMethod's walk, but a
        // receiver typed as an INTERFACE (`IAction b = new BadImpl();`) needs
        // to know every implemented name, not just the first. Purely additive
        // — nothing previously read `cls.bases`.
        if (Array.isArray(c.bases)) {
          for (const b of c.bases) if (b && !cls.bases.includes(b)) cls.bases.push(b);
        }
        // Declared field names (SARD_80_F1_SCANNER_PRD.md — cross-method field
        // taint, Juliet flow variants 45/65-68): lets the taint engine tell a
        // field write (`sf = data;`, `this.inst = data;`) apart from an
        // ordinary local variable with the same name in a DIFFERENT method of
        // the same class, without which a field write in one method could
        // never be told to taint a read in another. Merged across every file
        // that contributes to this class (partial classes, or a parser that
        // emits one `ir.classes` entry per method's enclosing file).
        if (Array.isArray(c.fields)) {
          for (const f of c.fields) if (f) cls.fields.add(f);
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
      } else if (segs.length >= 3 && (classes.has(segs[segs.length - 2]) || /^[A-Z]/.test(segs[segs.length - 2]))) {
        // PRD W1 (SARD_80_F1_EXECUTION_PRD.md) — `classes` was already
        // populated from this file's real `ir.classes` structural facts
        // above (lines 57-94), so `classes.has(...)` recognizes a scrambled
        // class name (`case_<hash>`, no longer PascalCase) exactly as
        // reliably as a real one. The `/^[A-Z]/` fallback stays for
        // languages that don't emit `ir.classes` yet (JS/Python/PHP/Ruby/Go/
        // Kotlin — W1.1) so an ordinary nested-function scope segment still
        // doesn't misfire there, same as before this change.
        className = segs[segs.length - 2];
        // Two sequential strips, not one `(#[0-9a-f]+)?` optional group: the
        // combined form is flagged by this project's own self-scan gate
        // (engine.js's safe-regex-backed ReDoS heuristic says unsafe; the
        // NFA-based analyzer in sast/redos-nfa.js says safe — no genuine
        // superlinear ambiguity exists here, safe-regex's star-height
        // heuristic is just coarser). Splitting into two definitively-safe
        // regexes (each independently passes both checkers) is behavior-
        // identical — verified against "tail@5#hash" and "tail@5" — and
        // avoids relying on any one detector's judgment call.
        methodName = tail.replace(/#[0-9a-f]+$/, '').replace(/@\d+$/, '');
      }
      if (!className || !methodName) continue;
      methodOwners.set(fn.qid, className);
      let cls = classes.get(className);
      if (!cls) {
        cls = { name: className, file, line: fn.line || 0, methods: new Set(), extends: null, bases: [], fields: new Set() };
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
        // SARD_80_F1_SCANNER_PRD.md §9/§15.1: the Babel-only `{kind:'ident'}`
        // shape below is what parser-js.js emits for `new Foo()`. Every
        // hand-rolled parser (C#, Go, PHP, Ruby, Kotlin, Java-CST — see
        // ../ir/CLAUDE.md's IR shape contract: `callee: string|expr`) instead
        // emits a flat, possibly dot-joined STRING callee for a `new`
        // expression (e.g. `"DirectorySearcher"`, or a fully-qualified
        // `"System.DirectoryServices.DirectorySearcher"`). Before this fix
        // `classOfVar` was silently a permanent no-op for every one of those
        // languages — not merely incomplete, since the only caller-visible
        // effect of "unknown" and "wrong" is identical (both return null) —
        // discovered while wiring `receiverTypeIn`-based sink matching for a
        // C# write-sink (`cs-directorysearcher-filter`) and finding
        // `callContext._cha` present but every lookup coming back null even
        // for the exact `var x = new DirectorySearcher()` shape this
        // function's own header comment describes as supported.
        const callee = src.callee;
        const className = callee?.kind === 'ident' ? callee.name
          : typeof callee === 'string' ? (callee.includes('.') ? callee.slice(callee.lastIndexOf('.') + 1) : callee)
          : null;
        if (!className) continue;
        if (classes.has(className) || /^[A-Z]/.test(className)) {
          // Convention: PascalCase `new` callees treated as constructors.
          const target = typeof n.target === 'string' ? n.target : null;
          if (target) {
            const key = `${file}::${fn.qid}::${target}`;
            if (ambiguousVarKeys.has(key)) continue;
            if (typeOfVar.has(key) && typeOfVar.get(key) !== className) {
              ambiguousVarKeys.add(key);
              typeOfVar.delete(key);
            } else {
              typeOfVar.set(key, className);
            }
          }
        }
      }
    }
    // PRD W2.5 (SARD_80_F1_EXECUTION_PRD.md) — a PARAMETER's declared type is
    // just as real a type binding as a local `let x = new Foo()`, and it's
    // Juliet's OWN dominant abstract/interface dispatch idiom: the "runTest"
    // driver constructs the concrete (bad/good) instance and passes it as a
    // parameter to a helper that invokes the virtual method — `_localVarConstructedTypes`
    // (parser-java.js/parser-cs.js) only ever sees the CONSTRUCTOR site, not
    // this call site, so `b` in `void helper(BaseType b, ...) { b.action(x); }`
    // was completely untyped. Reuses the EXACT same `typeOfVar` map and key
    // shape `classOfVar` already reads — no new lookup mechanism, so every
    // existing consumer (engine.js's `_resolveMemberCalleeViaCHA` once it
    // learns to read a flat dotted-string callee, `receiver-context.js`)
    // benefits with no changes on their end. Only populated when
    // `fn.paramTypes` exists (currently parser-java.js; parser-cs.js is a
    // candidate follow-up, same shape). Deliberately does NOT overwrite an
    // existing binding for the same key — a parameter name can never collide
    // with a local var name in the same scope in Java, so this is purely
    // additive, but the guard costs nothing and documents the intent.
    for (const fn of ir.functions) {
      if (!fn.paramTypes) continue;
      for (const [paramName, paramType] of Object.entries(fn.paramTypes)) {
        const key = `${file}::${fn.qid}::${paramName}`;
        if (!typeOfVar.has(key) && !ambiguousVarKeys.has(key)) typeOfVar.set(key, paramType);
      }
    }
    // SARD_80_F1 W4: a local's DECLARED type (`PrintWriter out =
    // response.getWriter();`, parser-java.js's `declaredType` on the assign
    // node) is the third source of a type binding, alongside a constructor
    // call above and a parameter's declared type. This is Java's dominant
    // "get an object via a factory/getter method, not `new`" idiom — the
    // constructor pass above can never see it (there is no `new` at all).
    // Deliberately consulted via `receiverTypeIn` only (additive — see
    // `catalog.js`'s `java-writer-*` entries), never via the destructive
    // callee-string rewrite `parser-java.js`'s `_localVarConstructedTypes`
    // does for constructor types: that mechanism was tried for declared
    // types too and reverted after it broke an unrelated, name-scoped
    // catalog entry (see its own comment). Populated by both
    // parser-java.js and parser-cs.js (C#'s `Type x = expr;` decl-typeClause
    // capture, same field name and rationale).
    for (const fn of ir.functions) {
      if (!fn.cfg || !fn.cfg.nodes) continue;
      for (const node of Object.values(fn.cfg.nodes)) {
        if (node.kind !== 'assign' || !node.declaredType || typeof node.target !== 'string' || node.target.includes('.')) continue;
        const key = `${file}::${fn.qid}::${node.target}`;
        if (!typeOfVar.has(key) && !ambiguousVarKeys.has(key)) typeOfVar.set(key, node.declaredType);
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
