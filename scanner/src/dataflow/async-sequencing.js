// Async / Promise sequencing (P3.3).
//
// Today's engine treats every await/then/catch as a synchronous call. That's
// CORRECT for most flows — taint propagates through resolved values just
// like return values. But several real patterns break:
//
//   const data = await fetch(url).then(r => r.json());
//                                       ^^^^^^^^^^^^^^   ← need first-arg taint
//   p.then(onFulfilled).catch(onRejected)
//                              ^^^^^^^^^^^^   ← rejected branch carries error taint
//   Promise.all([fetchA(req.body), fetchB(req.body)])
//          .then(([a, b]) => use(a, b))         ← destructured array elements
//   for await (const chunk of req)              ← async iter — body chunks are sources
//   const stream = req.body                     ← Node 18+ web streams
//
// This module captures the SHAPES of these chains and tells the engine
// which callbacks to walk and how the result of the chain inherits taint.
// It's a structural helper consumed by the IR-driven dataflow engine.
//
// Public API:
//   describeChain(callExpr)
//     → returns a normalized AsyncChain descriptor:
//       { ops: [{ kind, callback?, argIndex? }], rootCallee, isPromise }
//   resultTaintFor(chain, sourceTainted)
//     → returns true iff the chain's resolved value is tainted given the
//       root callee returned a tainted promise.
//   awaitedTaint(state, varName)
//     → adapts the engine's taint state at `await x` (no-op for typed
//       values; for `await req.body.text()` we lift the call's result).
//
// Identification heuristic (no types in JS): a callee is considered
// "promise-shaped" iff its name matches a known async source/sink in the
// catalog, OR it's awaited at least once in the analyzed function. The
// engine threads `isPromise` based on the catalog hit.

const PROMISE_CHAIN_METHODS = new Set([
  'then', 'catch', 'finally', 'allSettled',
]);

const PROMISE_STATIC_METHODS = new Set([
  'all', 'allSettled', 'race', 'any',
]);

const ASYNC_ITER_BODY_SOURCES = new Set([
  // req.body (Node 18+ / Fetch API web streams) — `for await` over it yields
  // raw user-controlled chunks.
  'body', 'stream',
]);

/**
 * Describe a Promise-chain AST tail. Input is the OUTERMOST call expression
 * of the chain (e.g., for `fetch(url).then(r).catch(e)`, pass the .catch call).
 * Returns a normalized list of operations plus the root callee.
 *
 * AST shape expected (parser-js.js neutral):
 *   { kind: 'call', callee: { kind: 'member', object: <expr>, prop: <string> }, args: [...] }
 */
export function describeChain(callExpr) {
  if (!callExpr || callExpr.kind !== 'call') return null;
  const ops = [];
  let cur = callExpr;
  // Walk leftward through .then/.catch/.finally chain.
  while (cur && cur.kind === 'call' && cur.callee && cur.callee.kind === 'member' && PROMISE_CHAIN_METHODS.has(cur.callee.prop)) {
    const arg = (cur.args || [])[0];
    ops.unshift({
      kind: cur.callee.prop,           // 'then' | 'catch' | 'finally'
      callback: arg && (arg.kind === 'ident' || arg.kind === 'arrow' || arg.kind === 'function') ? arg : null,
      argIndex: 0,
    });
    cur = cur.callee.object;
  }
  // `cur` should be the root call (e.g., `fetch(url)` or `Promise.all([...])`).
  const isPromise = isPromiseRoot(cur);
  return { ops, rootCallee: cur, isPromise };
}

function isPromiseRoot(expr) {
  if (!expr) return false;
  if (expr.kind !== 'call') return false;
  const c = expr.callee;
  if (!c) return false;
  if (c.kind === 'ident') {
    return /^(fetch|axios|request|got)$/.test(c.name);
  }
  if (c.kind === 'member') {
    if (c.object && c.object.kind === 'ident' && c.object.name === 'Promise' && PROMISE_STATIC_METHODS.has(c.prop)) return true;
    // any .xxxAsync() pattern, or .then-chainable: too noisy to assume; require
    // an explicit await elsewhere or a known callee.
    return /Async$/.test(c.prop) || /^(fetch|json|text|blob|formData)$/.test(c.prop);
  }
  return false;
}

/**
 * Given a chain descriptor + a `sourceTainted` boolean indicating whether
 * the root callee's resolved value is tainted, return whether each callback
 * in the chain receives tainted input and whether the final resolved value
 * is tainted.
 *
 * Semantics:
 *   - `.then(fn)`     — fn(resolved) — fn receives taint iff source tainted
 *   - `.catch(fn)`    — fn(error)   — fn receives ERROR taint; treated as
 *                        tainted iff `assumeRejectionTainted` (default true:
 *                        error.message can include user input via thrown
 *                        new Error(req.body)).
 *   - `.finally(fn)`  — fn() — no input; passes through previous taint
 *   - chain result is tainted iff the LAST .then's callback returns a
 *     tainted value (we approximate: any `.then` after a tainted input
 *     keeps result tainted unless its callback is a known sanitizer).
 *
 * Returns:
 *   { callbacks: [{ callback, taintedInput }], finalTainted }
 */
export function resultTaintFor(chain, sourceTainted, opts = {}) {
  const assumeRejectionTainted = opts.assumeRejectionTainted !== false;
  if (!chain) return { callbacks: [], finalTainted: !!sourceTainted };
  let cur = !!sourceTainted;
  const callbacks = [];
  for (const op of chain.ops) {
    if (op.kind === 'then') {
      callbacks.push({ callback: op.callback, taintedInput: cur });
      // result remains tainted until a sanitizer-known .then callback
      // proves otherwise. We can't analyze the callback body here — that's
      // the engine's job. Conservative default: tainted-in → tainted-out.
    } else if (op.kind === 'catch') {
      const errTainted = assumeRejectionTainted;
      callbacks.push({ callback: op.callback, taintedInput: errTainted });
      // catch can sanitize OR propagate. Conservative: keep current value.
    } else if (op.kind === 'finally') {
      callbacks.push({ callback: op.callback, taintedInput: false });
      // finally callback gets no input.
    }
  }
  return { callbacks, finalTainted: cur };
}

/**
 * For `for await (const x of obj)` — return whether x should inherit taint
 * given the object's name/property shape. The check is name-based since
 * we don't have types.
 *
 *   `for await (const chunk of req.body)`           → chunk tainted
 *   `for await (const chunk of req)`                → chunk tainted
 *   `for await (const item of someInternal)`        → not tainted
 */
export function asyncIterYieldsTaint(iterableExpr, knownTaintedVars) {
  if (!iterableExpr) return false;
  if (iterableExpr.kind === 'ident') {
    return knownTaintedVars && knownTaintedVars.has(iterableExpr.name);
  }
  if (iterableExpr.kind === 'member' && iterableExpr.object && iterableExpr.object.kind === 'ident') {
    if (iterableExpr.object.name === 'req' || iterableExpr.object.name === 'request') {
      // req.body / req.stream → tainted
      if (ASYNC_ITER_BODY_SOURCES.has(iterableExpr.prop)) return true;
    }
    // user-tainted object's any property is tainted too (field-collapsing
    // approximation matching engine.js's pre-P1.1 behavior).
    if (knownTaintedVars && knownTaintedVars.has(iterableExpr.object.name)) return true;
  }
  return false;
}

/**
 * Promise.all / Promise.race / Promise.any aggregate flow.
 *
 *   Promise.all([p1, p2, p3]).then(([a, b, c]) => …)
 *
 * Returns: an array of booleans indicating which destructured names
 * inherit taint.
 *
 *   args:         the array literal passed to Promise.all (AST node or null)
 *   eachTaintedFn: (argExpr) => boolean    — engine's per-expr predicate
 */
export function promiseAggregateTaint(args, eachTaintedFn) {
  if (!args || !Array.isArray(args.elements)) return [];
  return args.elements.map(eachTaintedFn || (() => false));
}
