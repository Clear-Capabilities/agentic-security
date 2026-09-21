// Interprocedural taint engine — IFDS-lite tabulation over the IR.
//
// Algorithm (simplified):
//
//   For each function F:
//     We compute a SUMMARY of the form
//        (entry: Set<TaintFact>) → { returnTaint: bool, paramMutations: { paramName: bool }, sideEffectFindings: Finding[] }
//     where TaintFact is currently a variable name (string).
//
//   To handle inter-procedural flow:
//     When the engine encounters a call site `f(...args)`:
//       1. Look up the resolved callee qid in the call graph.
//       2. Compute an entry-taint-state for that callee: which of the callee's
//          parameters bind to tainted caller-side expressions?
//       3. If a summary already exists for that callee + entry-state, use it.
//          Otherwise, recursively analyze the callee with that entry state,
//          cache the summary, and use it.
//       4. The callee's `returnTaint` determines whether the call expression's
//          value is tainted on return.
//       5. The callee's `paramMutations` taint specific caller-side variables
//          (param-by-reference, e.g. `Object.assign(target, tainted)`).
//
//   Recursion: We use the standard fixed-point trick — when a function is
//   already on the analysis stack, return a conservative summary (no
//   tainting). The cache then re-iterates.
//
// Sources: anywhere a CFG node reads a catalog-registered source pattern,
// the resulting variable becomes tainted.
//
// Sinks: anywhere a CFG node calls a catalog-registered sink with a tainted
// argument, we emit a finding.
//
// Sanitizers: RECORDED, but they do not kill taint in this walk.
// `_sanitizersForExpr` (below) collects the sanitizer callees applied to the
// value reaching each sink argument — inline, or inherited via
// `_sanitizersByVar` from the variable it reads — and stamps them on the
// finding as `_sanitizersOnPath`. `dataflow/sanitizer-gate.js` then labels the
// finding `sanitized:true` only when the sanitizer's `appliesTo` family
// actually covers the finding's threat class; `engine.js`'s proof gate demotes
// from there. Taint itself still dies only when a variable is re-assigned from
// a clean expression (removePathAndDescendants, below) — a mislabelled
// sanitizer must never silently drop a real vulnerability, so the walk never
// treats a sanitizer call as clearing the tainted path on its own.

import { matchSource, matchSinkOrSanitizer, matchMemberWriteSink, matchAnnotationParams } from './catalog.js';
import { functionRecord } from '../ir/callgraph.js';
import { accessPathOf, isCoveredBy, addPath, removePathAndDescendants, joinSets as joinAccessSets, setsEqual as accessSetsEqual, pathIsCoveredByPrefix } from './access-paths.js';
import { aliasesForVar } from './points-to.js';
import { higherOrderTaintFlow } from './higher-order.js';
import { SummaryCache, entryStateFromCall } from './summaries.js';
import { lookupBuiltinSummary } from './builtin-summaries.js';
import { isImplicitFlowEnabled, buildImplicitContext, implicitAssignTarget, markImplicitTaint, createImplicitFinding } from './implicit-flow.js';
import { isSafeValidationPattern } from './string-domain.js';
// NOTE: receiver-context.js's receiverTypeAtCall is deliberately NOT imported
// here. It was the implementation of _receiverTypeFor's old `this.field`
// branch, whose PascalCase-of-field-name guess is the false-negative bug this
// file's _receiverTypeFor comment describes. Its other exports are still used
// (summaries.js imports hashReceiverType for cache keying); only this call
// site is gone.
import { resolveMethod, resolveMethodRTA, classOfVar } from '../ir/class-hierarchy.js';

// v0.70 #2 — addPath that also taints every alias of the variable.
// When `target` is a dotted path like "a.x" and the root `a` has aliases
// {a, obj}, we taint both `a.x` and `obj.x`. The points-to graph is read
// from callContext._pointsTo (built by runDeepAnalysis when
// AGENTIC_SECURITY_POINTS_TO=1).
function _addPathAliasAware(state, path, callContext) {
  let s = addPath(state, path);
  // T3.3 — a write through an UNKNOWN key taints the whole container.
  //
  // `parser-js.js` lowers a computed write whose key is not a literal
  // (`bag[k] = tainted`) to the access path `bag.*`, and — as that parser's own
  // comment states — `'*'` is a LITERAL property name here, not a
  // match-anything token. `isCoveredBy` only propagates DOWN from a prefix, so
  // `bag.*` covers nothing: a later read of `bag.anything` resolves to a
  // different path entirely and the taint is unreachable from every correctly
  // computed read.
  //
  // Since the key is statically unknown, the write may have landed on ANY
  // property, so the sound abstraction is the container itself. Widening to the
  // base is what makes the value observable again, and it is the same
  // over-approximate direction the lattice already takes at branch joins.
  //
  // Scoped deliberately to a TRAILING `.*`. An interior wildcard
  // (`bag.*.inner`) still describes a definite final property and does not
  // justify tainting the root.
  if (typeof path === 'string' && path.length > 2 && path.endsWith('.*')) {
    s = addPath(s, path.slice(0, -2));
  }
  const pt = callContext && callContext._pointsTo;
  const fnQid = callContext && callContext._currentFnQid;
  if (!pt || !fnQid || typeof path !== 'string') return s;
  // Determine the variable root + remainder of the path.
  const dot = path.indexOf('.');
  const root = dot >= 0 ? path.slice(0, dot) : path;
  const rest = dot >= 0 ? path.slice(dot) : '';
  const aliases = aliasesForVar(pt, fnQid, root);
  for (const a of aliases) {
    if (a === root) continue;
    s = addPath(s, a + rest);
  }
  return s;
}

// The file of the function currently being analyzed. Set at the top of
// analyzeFunction so exprIsSource/exprTaint/step can pass it to matchSource /
// matchSinkOrSanitizer without plumbing it through every call signature.
// It scopes language-specific catalog entries (currently just `cpp`) to
// files of that language — see the header comment in catalog.js.
let _currentFile = null;

// Flatten a callee — which may be a plain dotted STRING (Go/PHP/Ruby/C++/
// Python parsers all emit call targets this way) or an expression object
// (JS/TS's `exprOf`-shaped `{kind:'ident',name}` / `{kind:'member',...}`) —
// into a name `callGraph.resolve()` can look up. Mirrors the normalisation
// catalog.js's matchSinkOrSanitizer/matchSource already apply to callees, so
// the interprocedural resolve path and the catalog match agree on shape.
// The string path is returned unchanged — languages that already flatten to
// a string at parse time must keep working exactly as before.
function _flattenCalleeName(calleeExpr) {
  if (!calleeExpr) return null;
  if (typeof calleeExpr === 'string') return calleeExpr;
  if (calleeExpr.kind === 'ident') return calleeExpr.name || null;
  if (calleeExpr.kind === 'member' && calleeExpr.prop) {
    return (calleeExpr.object && calleeExpr.object.kind === 'ident')
      ? `${calleeExpr.object.name}.${calleeExpr.prop}`
      : calleeExpr.prop;
  }
  return null;
}

// PRD R6/R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md): unlike _flattenCalleeName
// (which only flattens ONE level — `x.method`/`this.method` — because that is
// the 2-segment shape catalog matching and resolveKnownCallee both key on),
// _receiverTypeFor needs the FULL dotted chain, including `this`, to see how
// LONG the chain actually is: a 3+-segment chain (`this.userRepo.save` ->
// ['this','userRepo','save'], `svc.db.query` -> ['svc','db','query']) names a
// receiver that is a property path, and CHA cannot type property paths at all.
// A partial flatten (`_flattenCalleeName` returns just 'save' for
// `this.userRepo.save`, since its object isn't a bare ident) would hide that
// distinction and make a 3-segment chain look like an untyped bare call.
//
// Note: parser-js.js encodes ThisExpression as {kind:'ident', name:'_this_'}
// (a sentinel, not literal 'this'). We convert it to the literal string
// 'this' so the flattened chain reads the way the source does and its segment
// count is honest (`this.db.query` is 3 segments, not 2).
function _fullyFlattenMemberChain(calleeExpr) {
  if (!calleeExpr) return null;
  if (typeof calleeExpr === 'string') return calleeExpr;
  if (calleeExpr.kind === 'ident') {
    const name = calleeExpr.name || null;
    // Convert the parser's _this_ sentinel to the literal 'this' string
    return name === '_this_' ? 'this' : name;
  }
  if (calleeExpr.kind === 'member' && typeof calleeExpr.prop === 'string') {
    const base = _fullyFlattenMemberChain(calleeExpr.object);
    return base ? `${base}.${calleeExpr.prop}` : calleeExpr.prop;
  }
  return null;
}

// Shared by R6 (catalog receiver-type gating) and R11 (member-call
// resolution) so both use the exact same precision bar, per the PRD's own
// sequencing note that R11 must not be more permissive than R6. Returns null
// whenever CHA has nothing useful to say — callers must treat null as
// "unknown", never as a signal to suppress or refuse (see this file's
// "Unknown ≠ clean" global constraint).
function _receiverTypeFor(calleeExpr, callContext) {
  if (!callContext || !callContext._cha) return null;
  const flat = _fullyFlattenMemberChain(calleeExpr);
  if (!flat || !flat.includes('.')) return null;
  const parts = flat.split('.');
  // Only a bare `x.method()` receiver (exactly 2 dot-separated parts) is
  // something CHA can genuinely verify: classOfVar only tracks bare local
  // variable -> class bindings from `let/const x = new Foo()`, never
  // property-path types. This one condition replaces two separate prior
  // bugs found in whole-branch review: the this.field branch (`this.x.y()`
  // is 3 parts, `this` as root) used to PascalCase-guess a type from the
  // field name and could never return null, silently suppressing real
  // findings on any field name outside a fixed vocabulary
  // (this.dbConn.query(), this.readReplica.query(), ...); the non-this
  // branch used to resolve parts[0] (the chain ROOT) for multi-segment
  // chains like svc.db.query(), which answers "what type is svc?" instead
  // of the actual question "what type is svc.db?" -- a question CHA has no
  // way to answer, since it never tracks field types, only local-variable
  // types. Both were name/shape guesses being trusted as confident
  // resolutions. A multi-segment or `this`-rooted chain now honestly
  // returns null (unknown, permissive) rather than guessing.
  //
  // The same doctrine already killed a third instance of this bug class: a
  // receiver assigned via `const c = mysql.createConnection({})` cannot be
  // typed by CHA (member-call factory, not `new X()`), so classOfVar returns
  // null — returning the bare name 'c' as a "type" suppressed a real finding
  // (regression: CVE-2021-22214-node-sqli-shape). There is no name-based
  // fallback anywhere in this function for exactly that reason.
  if (parts.length !== 2) return null;
  return classOfVar(callContext._cha, _currentFile, callContext._currentFnQid, parts[0]);
}

// Narrower than _flattenCalleeName: the name to hand to callGraph.resolve().
// Only a bare identifier call (`helper()`) — or a pre-flattened STRING, which
// is how the Go/PHP/Ruby/Python/C++ parsers already emit call targets —
// genuinely identifies one resolvable function. A JS/TS *member* call
// (`loader.read()`) does not: resolve()'s generic dotted-name fallback
// strips a dotted name to its last segment and matches ANY same-named
// function project-wide, inventing a call edge that may not exist (found in
// engine-reconnect review — `loader.read()` resolved to an unrelated local
// `read()`, producing 8 false positives on this repo's own hooks/scripts).
// A missing edge here is a false negative; a wrong edge invents a data-flow
// path that isn't there — refuse to guess.
function _resolvableCalleeName(calleeExpr) {
  if (!calleeExpr) return null;
  if (typeof calleeExpr === 'string') return calleeExpr;
  if (calleeExpr.kind === 'ident') return calleeExpr.name || null;
  return null;
}

// R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md): unlike R6's _receiverTypeFor
// (used only to narrow an ALREADY-pattern-matched catalog sink — safe to be
// wrong in either direction, since the worst case is over/under-gating an
// existing match), this function creates a NEW interprocedural call-graph
// edge. A wrong resolution here fabricates a data-flow path that does not
// exist, which this codebase's own doctrine treats as strictly worse than
// a missed one (see _resolvableCalleeName's comment above). It therefore
// calls classOfVar DIRECTLY, which only returns non-null when the receiver
// was genuinely assignment-tracked (`let x = new Foo()`), and additionally
// requires the receiver to be a bare, non-`this` identifier expression.
//
// Historically _receiverTypeFor carried NAME-based fallbacks (a
// PascalCase-of-`this.field` guess and a bare-identifier-name fallback) that
// this function was careful never to reuse, because a same-named
// parameter/variable/field (e.g. a duck-typed
// `function process(Model, data) { Model.save(data); }`) would resolve to an
// unrelated real class purely by name coincidence. Whole-branch review found
// those same guesses were also wrong for R6's much softer use, so they are
// gone: _receiverTypeFor now bottoms out in the same classOfVar call this
// function makes. The two are deliberately kept as separate functions
// anyway — they take different inputs (a flattened chain vs. a member
// expression) and R11's extra `resolveMethod` step means it can still refuse
// where R6 does not.
function _resolveMemberCalleeViaCHA(calleeExpr, callContext) {
  if (!callContext || !callContext._cha) return null;
  let receiverName, methodName;
  if (calleeExpr && calleeExpr.kind === 'member' && typeof calleeExpr.prop === 'string') {
    if (!calleeExpr.object || calleeExpr.object.kind !== 'ident' || calleeExpr.object.name === '_this_') return null;
    receiverName = calleeExpr.object.name;
    methodName = calleeExpr.prop;
  } else if (typeof calleeExpr === 'string') {
    // PRD W2.5 (SARD_80_F1_EXECUTION_PRD.md) — the hand-rolled parsers
    // (Java/C#/Go/PHP/Ruby/Kotlin) emit a FLAT dotted-string callee
    // ("b.action"), never the Babel `{kind:'member'}` shape above. This
    // function previously only ever handled the latter, so this whole
    // CHA-gated path was silently JS-only. Only a simple `receiver.method`
    // (exactly one dot) is handled — a longer chain (`a.b.c`) is a member
    // chain this function has no way to walk without an AST, and guessing
    // would risk exactly the fabricated-edge failure mode this function's
    // own header comment warns about; refuse rather than guess.
    const dot = calleeExpr.indexOf('.');
    if (dot <= 0 || calleeExpr.indexOf('.', dot + 1) !== -1) return null;
    receiverName = calleeExpr.slice(0, dot);
    methodName = calleeExpr.slice(dot + 1);
    if (receiverName === '_this_' || receiverName === 'this') return null;
  } else {
    return null;
  }
  const className = classOfVar(callContext._cha, _currentFile, callContext._currentFnQid, receiverName);
  if (!className) return null;
  const direct = resolveMethod(callContext._cha, className, methodName);
  if (direct) return `${direct.className}.${direct.methodName}`;
  // Direct/inherited resolution failed — this is expected when `className`
  // is an ABSTRACT class or interface with no body of its own (Juliet's
  // dominant idiom: `abstract void action(String d);` is never emitted as a
  // function at all, so it's never added to any class's `methods` set).
  // Fall back to RTA: which LIVE (actually `new`'d somewhere in this scan)
  // subclasses of `className` implement `methodName`. Deliberately
  // single-candidate-only for this landing — refuse rather than guess when
  // more than one live subclass implements the method (e.g. a bad/good
  // variant pair both alive in the same scan), matching this codebase's
  // dominant ambiguity-refusal convention. Known, accepted limitation: this
  // means the fix does nothing when Juliet's own bad+good siblings are
  // scanned together, which is the common case — see the ledger for the
  // measured impact and whether that limitation is worth lifting next.
  const cha = callContext._cha;
  if (!cha.liveClasses) return null;
  const candidates = resolveMethodRTA(cha, methodName, cha.liveClasses, className);
  if (candidates.length !== 1) return null;
  return `${candidates[0].className}.${candidates[0].methodName}`;
}

// Resolve calleeExpr to { qid, fn } via the call graph — the shared
// resolve-and-lookup sequence every summary-consulting call site needs.
// Extracted from what were two independent, drifting copies (assign-RHS and
// plain-call-statement) so a future change (like PRD R11 in this same file)
// only has to land once. See _resolvableCalleeName's own comment for why a
// bare-name/pre-flattened-string callee is the ONLY case handled here for
// now — Task 4 (PRD R11) extends this function's body to add a second,
// CHA-gated resolution path for member-expression callees.
function _resolveCalleeForSummary(calleeExpr, callContext) {
  if (!callContext || !callContext._callGraph || !callContext._callGraph.resolveKnownCallee) return null;
  const _callerFile = (callContext._currentFnQid || '').split('::')[0] || undefined;
  const _resolvableName = _resolvableCalleeName(calleeExpr);
  if (_resolvableName) {
    const resolved = callContext._callGraph.resolveKnownCallee(_resolvableName, _callerFile);
    const fn = functionRecord(callContext._callGraph, resolved);
    const qid = resolved && (resolved.qid || resolved);
    if (typeof qid === 'string') return { qid, fn };
  }
  // PRD R11 / W2.5: reached either because `_resolvableCalleeName` refused
  // outright (a Babel member-expression callee), or because it handed back
  // a name (a flat dotted string like "b.action" — the hand-rolled parsers'
  // shape) that `resolveKnownCallee` could NOT resolve by name (`b` isn't a
  // class name, it's a local/parameter). Try the CHA-gated path ONLY as a
  // fallback after ordinary name resolution has already failed, so a callee
  // that resolves correctly by name is never second-guessed by a coarser,
  // over-approximating CHA/RTA lookup.
  const _chaName = _resolveMemberCalleeViaCHA(calleeExpr, callContext);
  if (!_chaName) return null;
  const resolved = callContext._callGraph.resolveKnownCallee(_chaName, _callerFile);
  const fn = functionRecord(callContext._callGraph, resolved);
  const qid = resolved && (resolved.qid || resolved);
  return typeof qid === 'string' ? { qid, fn } : null;
}

// PRD R10 (docs/DETECTION_GAP_REMEDIATION_PRD.md): the only two places that
// consult a callee's SummaryCache entry are the assign-RHS and plain-call-
// statement paths in step() below — a call nested INSIDE another expression
// (most commonly a sink's own argument list, `sink(getUserInput())`) reaches
// neither, so exprTaint's 'call' case fell back to checking only the nested
// call's OWN arguments, silently losing the callee's return-taint. Mirrors
// the same resolve -> get-or-compute -> merge sequence step()'s two existing
// call sites use, via the Task 3/4 shared _resolveCalleeForSummary.
function _nestedCallReturnTainted(calleeExpr, argExprs, state, callContext) {
  if (!callContext || !callContext._summaryCache) return false;
  const target = _resolveCalleeForSummary(calleeExpr, callContext);
  if (!target) return false;
  const { qid, fn } = target;
  const paramNames = (fn && Array.isArray(fn.params)) ? fn.params : [];
  const entry = paramNames.length
    ? entryStateFromCall(paramNames, argExprs || [], state, (a) => exprTaint(a, state, callContext))
    : new Set();
  let sum = callContext._summaryCache.get(qid, entry);
  if (!sum && fn && fn.cfg) {
    sum = callContext._summaryCache.compute(qid, entry, () => {
      const inner = {
        _findings: [], _taintSources: [], _returnTainted: false,
        _stack: new Set(), deadlineMs: callContext.deadlineMs,
        _summaryCache: callContext._summaryCache,
        _callGraph: callContext._callGraph,
        _mutatedParamsOut: new Set(),
        _cha: callContext._cha,
      };
      try { analyzeFunction(fn, _unionAnnotationTaint(fn, entry), inner); } catch {}
      return {
        returnTainted: !!inner._returnTainted,
        mutatedParams: inner._mutatedParamsOut || new Set(),
        mutatedThisFields: inner._mutatedThisFieldsOut || new Set(),
        taintedGlobals: new Set(),
        findings: inner._findings,
      };
    });
  }
  _mergeSummaryFindings(callContext, callContext._currentFnQid, sum, 'interproc');
  // Next-gen taint capability #3: a single-field getter's return is tainted
  // whenever THIS call's own receiver already carries that field as
  // tainted, independent of `sum.returnTainted` (which reflects only the
  // EMPTY-args entry state a zero-param getter always computes under).
  return _calleeGetterFieldTainted(calleeExpr, state, callContext) || !!(sum && sum.returnTainted);
}

// Taint-recall PRD (80%): is a call's own RECEIVER tainted? Handles the two
// distinct shapes this codebase's IR frontends use for a call's `callee`:
// parser-js.js (Babel) emits a structured {kind:'member', object, prop}
// node, so the receiver is `callee.object`, checked via a normal exprTaint
// recursion. parser-cs.js/parser-go.js/parser-kt.js/parser-php.js/
// parser-rb.js/parser-java.js/parser-py.js instead emit a flat, dot-joined
// STRING callee ("it.toString", "user.getName") — there is no sub-expression
// to recurse into, so the receiver is recovered by slicing off the string
// after its LAST '.' and checking that prefix directly against the access-
// path lattice via `isCoveredBy` (handles both a bare var and a longer
// chain, e.g. "req.session.user.toString" -> receiver "req.session.user").
function _calleeReceiverTainted(callee, state, callContext) {
  if (!callee) return false;
  if (typeof callee === 'string') {
    const idx = callee.lastIndexOf('.');
    if (idx <= 0) return false;
    return isCoveredBy(state, callee.slice(0, idx));
  }
  if (callee.kind === 'member' && callee.object) {
    return exprTaint(callee.object, state, callContext);
  }
  return false;
}

// Next-gen taint capability #3 — object-instance field taint via method
// calls (JS/TS). `classTaintedFields` (below, in the pre-pass) already
// tracks "does ANY method of this class ever taint field F", but that is a
// deliberate, CLASS-WIDE over-approximation used only when no direct call-
// graph link between writer and reader is discoverable. When code instead
// calls a mutator method directly on a LOCAL receiver variable —
// `const bad = new Holder(); bad.setData(tainted); ...` — the engine had no
// mechanism at all to taint `bad`'s own `data` field: `_mutatedParamsOut`
// (v0.66) only ever tracks the callee's DECLARED PARAMETERS, never the
// implicit `this` receiver, so a setter's `this.field = v` mutation was
// invisible to its own caller. Fixed by treating `this` as an implicit
// mutable parameter (see the `_mutatedThisFieldsOut` population in
// `analyzeFunction`, mirroring `_mutatedParamsOut` exactly) and, on the read
// side, recognizing a single-field getter shape (`return this.field;`) so a
// later `bad.getData()` resolves to whatever was tainted on `bad` SPECIFICALLY
// — not on every other instance of `Holder`. Because the caller-side effect
// lands on the RECEIVER'S OWN access path (`bad.data`, not a class-wide
// bucket), two different local variables holding instances of the SAME
// class are naturally kept distinct — real object-instance sensitivity,
// without needing a full allocation-site-keyed heap model.

// Field name a getter-shaped function unconditionally returns, or null.
// Deliberately narrow and structural (no taint-state dependency): only a
// BARE `this.<field>`/`_this_.<field>`/`$this.<field>` return value counts
// (not `this.field.sub`, not `this.field + x`) — accessPathOf already
// rejects anything with further computation. If the function has multiple
// return statements naming DIFFERENT fields, this is ambiguous and bails to
// null rather than guess, since guessing the wrong field here couldn't add
// a false negative (the true field would just stay whatever it already was)
// but a memoized wrong answer would be needlessly confusing to reason about.
const _THIS_FIELD_RETURN_RE = /^(?:_this_|this|\$this)\.([^.]+)$/;
// Same receiver-spelling prefix, WITHOUT the end anchor — matches a deeper
// path too (`_this_.data.sub`), used to recover just the top-level field
// name a function's exit state taints on its receiver (mutator side).
const _THIS_FIELD_PREFIX_RE = /^(?:_this_|this|\$this)\.([^.]+)/;
const _getterFieldCache = new WeakMap();
function _thisFieldGetterName(fn) {
  if (!fn || !fn.cfg || !fn.cfg.nodes) return null;
  if (_getterFieldCache.has(fn)) return _getterFieldCache.get(fn);
  let field = null;
  for (const node of Object.values(fn.cfg.nodes)) {
    if (node.kind !== 'return' || !node.value) continue;
    const path = accessPathOf(node.value);
    if (!path) continue;
    const m = _THIS_FIELD_RETURN_RE.exec(path);
    if (!m) continue;
    if (field === null) field = m[1];
    else if (field !== m[1]) { field = null; break; }
  }
  _getterFieldCache.set(fn, field);
  return field;
}

// The receiver's OWN access path for a receiver-qualified callee, in
// EITHER IR shape this codebase's frontends produce — same dual-shape
// handling as `_calleeReceiverTainted` just above, but returning the path
// itself (to taint/query it) rather than a boolean.
function _receiverAccessPathOf(callee) {
  if (!callee) return null;
  if (typeof callee === 'string') {
    const idx = callee.lastIndexOf('.');
    return idx > 0 ? callee.slice(0, idx) : null;
  }
  if (callee.kind === 'member' && callee.object) return accessPathOf(callee.object);
  return null;
}

// Does calling `calleeExpr` return a receiver-specific field that is
// ALREADY tainted on THIS SPECIFIC receiver (per `_thisFieldGetterName`)?
// Read-side counterpart of the `_mutatedThisFieldsOut` write-side fix.
function _calleeGetterFieldTainted(calleeExpr, state, callContext) {
  if (!callContext || !callContext._summaryCache) return false;
  const target = _resolveCalleeForSummary(calleeExpr, callContext);
  const field = target && _thisFieldGetterName(target.fn);
  if (!field) return false;
  const receiverPath = _receiverAccessPathOf(calleeExpr);
  return !!(receiverPath && isCoveredBy(state, `${receiverPath}.${field}`));
}

function exprTaint(expr, state, callContext) {
  if (expr && (expr.kind === 'member' || expr.kind === 'call' || expr.kind === 'ident') && exprIsSource(expr, callContext)) return true;
  if (!expr) return false;
  // P1.1 — field-sensitive access path: if the expression is a pure
  // ident/member chain ("x.y.z"), ask the access-path lattice whether any
  // shorter prefix in the state covers it. This is what makes
  // `user.password` distinguishable from `user.email`.
  const ap = accessPathOf(expr);
  if (ap !== null) return isCoveredBy(state, ap);
  switch (expr.kind) {
    case 'literal':           return false;
    case 'binary':
    case 'logical':           return exprTaint(expr.left, state, callContext) || exprTaint(expr.right, state, callContext);
    case 'tpl':               return (expr.parts || []).some(p => exprTaint(p, state, callContext));
    case 'union':             return (expr.branches || []).some(b => exprTaint(b, state, callContext));
    case 'object':            return (expr.props || []).some(p => exprTaint(p.value, state, callContext));
    case 'array':             return (expr.elements || []).some(e => exprTaint(e, state, callContext));
    case 'call': {
      // Sound taint-kill for a coercion sanitizer used INLINE (not assigned
      // to a variable first) — `sink("x=" . intval($_GET['id']))`,
      // `if (sink(intval($x)))`. See _isCoercionCall's header comment for why
      // this specific class of sanitizer is the one exception to "never kill
      // taint on a sanitizer call": a genuine type coercion makes the VALUE
      // itself non-injectable, independent of which sink it reaches, so its
      // own return value is clean regardless of whether its argument was
      // tainted. Checked first and returns immediately — a coerced value
      // cannot un-clean itself via its own (nonexistent, since this exits
      // early) receiver/nested-return taint.
      if (_isCoercionCall(expr)) return false;
      // The call's own arguments OR — PRD R10 — the resolved callee's own
      // return-taint summary. Taint-recall PRD (80%): this used to
      // short-circuit on args-tainted and SKIP _nestedCallReturnTainted
      // entirely — but that call's real job isn't just the boolean it
      // returns, it's the _mergeSummaryFindings side effect that surfaces
      // the CALLEE's own internal sink findings (e.g. `return
      // helper(taintedArg)` where `helper`'s body itself contains
      // `sink(param)`). Short-circuiting on "args are tainted" (the
      // overwhelmingly common interprocedural shape — a tainted value IS
      // usually passed as an argument) silently dropped exactly the
      // findings this mechanism exists to surface. Confirmed via direct
      // fixture debugging (PHP: `$name = get_name(); return
      // find_user($doc, $name);` produced zero findings until this fix,
      // even though find_user's own body has a cataloged sink fed by
      // $name) — not language-specific, this is generic exprTaint logic.
      // Both sides always evaluated now (no short-circuit either
      // direction) so the merge always runs when a call expression is
      // visited; _resolveCalleeForSummary + SummaryCache make repeat
      // resolution/computation for the same (qid, entry-state) cheap.
      const argsTainted = (expr.args || []).some((a, i) => !_isSprintfSafeArg(expr, i) && exprTaint(a, state, callContext));
      const nestedTainted = _nestedCallReturnTainted(expr.callee, expr.args, state, callContext);
      // Taint-recall PRD (80%): a call's RECEIVER can itself be tainted
      // independent of its arguments — `tainted.toString()`, `tainted.trim()`,
      // `it.getBytes()` — and neither argsTainted (there are no/unrelated
      // args) nor nestedTainted (that resolves a FUNCTION-NAME callee via the
      // call graph; a bare method name like "toString" never resolves) sees
      // it. Confirmed via `req.getBytes()` (Java @RequestBody InputStream) and
      // the general shape this codebase's five hand-rolled parsers all
      // produce for a chained call: `expr.callee` there is a flat DOT-JOINED
      // STRING ("it.toString"), not a structured {kind:'member', object,
      // prop} node like parser-js.js emits — so the two shapes need distinct
      // handling. Deliberately receiver-taint-propagates for ANY call on a
      // tainted receiver (not just no-arg ones): `tainted.replace(a,b)`'s
      // receiver taint matters exactly as much as `tainted.toString()`'s, and
      // this is already OR'd with argsTainted so it only WIDENS recall,
      // matching this engine's recall-preserving precedent everywhere else.
      const receiverTainted = _calleeReceiverTainted(expr.callee, state, callContext);
      return argsTainted || nestedTainted || receiverTainted;
    }
    case 'unknown':           return false;
    default:                  return false;
  }
}

// Premortem #10: which recorded sources actually reach this expression?
// Collects the variable / access-path roots referenced by `expr` and returns
// the _taintSources entries whose varName matches one of those roots. This
// replaces "first source we ever saw" with "sources tied to this argument."
// Exported (next-gen taint capability #5, SMT path-feasibility rebuild) so
// backward.js's `annotateBackwardSlices` can reuse the SAME free-variable
// extraction for a COMPOUND tainted-sink-argument expression (`'SELECT...'
// + id`, not a bare identifier) — `accessPathOf` alone returns null for
// anything but a pure ident/member chain, which previously made
// `annotateBackwardSlices` fall back to an unmatchable placeholder string
// for the overwhelmingly common "string-concatenation into a sink" shape,
// silently degrading the backward slice to just the bare sink node.
export function _collectExprVars(expr, out) {
  if (!expr) return;
  if (typeof expr === 'string') { out.add(expr); return; }
  if (expr.kind === 'ident' && expr.name) { out.add(expr.name); return; }
  if (expr.kind === 'member') {
    // Capture the access path (e.g. `user.email`) AND its root (`user`).
    const ap = accessPathOf(expr);
    if (ap) out.add(ap);
    if (expr.object) _collectExprVars(expr.object, out);
    return;
  }
  if (expr.kind === 'binary' || expr.kind === 'logical') {
    _collectExprVars(expr.left, out); _collectExprVars(expr.right, out); return;
  }
  if (expr.kind === 'tpl' && Array.isArray(expr.parts)) {
    for (const p of expr.parts) _collectExprVars(p, out); return;
  }
  if (expr.kind === 'union' && Array.isArray(expr.branches)) {
    for (const b of expr.branches) _collectExprVars(b, out); return;
  }
  if (expr.kind === 'object' && Array.isArray(expr.props)) {
    for (const p of expr.props) _collectExprVars(p.value, out); return;
  }
  if (expr.kind === 'array' && Array.isArray(expr.elements)) {
    for (const e of expr.elements) _collectExprVars(e, out); return;
  }
  if (expr.kind === 'call' && Array.isArray(expr.args)) {
    for (const a of expr.args) _collectExprVars(a, out); return;
  }
}
function _sourcesReachingExpr(expr, _state, taintSources) {
  if (!Array.isArray(taintSources) || taintSources.length === 0) return [];
  const vars = new Set();
  _collectExprVars(expr, vars);
  if (vars.size === 0) return [];
  // Match by exact varName OR by access-path prefix (a source recorded for
  // `user` covers `user.email`, and a source recorded for `user.email`
  // covers the literal expression `user.email`).
  const matched = [];
  for (const s of taintSources) {
    const v = s.varName;
    if (!v) continue;
    if (vars.has(v)) { matched.push(s); continue; }
    for (const candidate of vars) {
      if (typeof candidate === 'string' && (candidate === v || candidate.startsWith(v + '.'))) {
        matched.push(s); break;
      }
    }
  }
  return matched;
}

// Heuristic: does this expression read a registered source?
// `callContext` (SARD_80_F1 W4.C39, optional) lets the CALL-shaped branch
// resolve a receiver's CHA-declared type (mirroring `_receiverTypeFor`'s use
// for sinks) and pass it to `matchSource` so a `receiverTypeIn`-bearing
// source entry can confirm a match even when the receiver's own NAME fails
// (`dr.GetString(1)` — Juliet's idiomatic short SqlDataReader variable name,
// no "reader" substring). Every caller that has a callContext in scope now
// passes it through; callers that don't (none currently) simply get the
// prior, name-only behavior — `_receiverTypeFor` itself degrades to null
// when callContext/CHA is absent, so this is purely additive.
function exprIsSource(expr, callContext) {
  if (!expr) return null;
  if (expr.kind === 'member') {
    const hit = matchSource(expr, _currentFile);
    if (hit) return hit;
  }
  // R3 (PRD §5): call-shaped sources (r.FormValue(), r.URL.Query(), c.Query()).
  // Previously only member reads were recognized, so Go's call-style sources
  // never tainted the assignment target. matchSource now resolves call sources.
  if (expr.kind === 'call') {
    const receiverType = _receiverTypeFor(expr.callee, callContext);
    const hit = matchSource(expr, _currentFile, receiverType);
    if (hit) return hit;
  }
  // Taint-recall PRD (80%): bare-identifier GLOBAL sources — PHP's $_GET/
  // $_POST/$_REQUEST/$_SERVER, Ruby's params/cookies/session/ENV, JS's
  // location — referenced DIRECTLY (not first assigned to a local, not a
  // member-read off them) were completely unreachable here. matchSource
  // itself has always supported a bare-ident branch (GLOBAL_INDEX lookup by
  // the identifier's own name), but neither this function nor exprTaint's
  // early check ever called it for expr.kind === 'ident' — only
  // 'member'/'call'. So `header("X: " . $_GET)` (or any shape where a
  // global is read directly rather than through member/subscript access)
  // never tainted anything, no matter how the value was actually used.
  // Confirmed via a real corpus fixture whose PHP parser also mis-splits
  // `$_GET["trace"]`'s string literal, leaving a bare `$_GET` ident in a
  // template's parts — this fix makes that residue still count, which is
  // the right behavior regardless of that separate mis-split bug.
  if (expr.kind === 'ident') {
    const hit = matchSource(expr, _currentFile);
    if (hit) return hit;
  }
  if (expr.kind === 'member' && expr.object) {
    return exprIsSource(expr.object, callContext);
  }
  return null;
}

const _SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|WHERE|FROM|JOIN|INTO|VALUES|SET|EXEC|EXECUTE)\b/i;
const _HTML_META = /[<>'"&]|innerHTML|outerHTML|document\.write/;

function _literalPartsOfExpr(expr) {
  if (!expr) return [];
  if (expr.kind === 'literal') return [String(expr.value || '')];
  if (expr.kind === 'tpl') return (expr.parts || []).filter(p => p.kind === 'literal').map(p => String(p.value || ''));
  if (expr.kind === 'binary') return [..._literalPartsOfExpr(expr.left), ..._literalPartsOfExpr(expr.right)];
  return [];
}

function literalSkeletonMatchesFamily(expr, cwe) {
  const literals = _literalPartsOfExpr(expr);
  if (!literals.length) return true;
  const joined = literals.join(' ');
  if (!joined.trim()) return true;
  if (cwe === 'CWE-89' || cwe === 'CWE-943') return _SQL_KEYWORDS.test(joined);
  if (cwe === 'CWE-79') return _HTML_META.test(joined);
  // Taint-recall PRD (80%): CWE-78 (command injection) deliberately does NOT
  // require the STATIC portion of the concat to contain a shell
  // metacharacter. The SQL/HTML checks above make sense because their sinks
  // (a generic `.raw()`/`.query()` call, an `innerHTML` assignment) can
  // legitimately carry non-SQL, non-HTML strings — the skeleton check filters
  // those out. Command-injection's sink catalog has no such ambiguity: every
  // CWE-78 entry (`os.system`, `subprocess.call`, `Runtime.exec`,
  // `child_process.exec`, …) is an unambiguous shell-execution API, so a
  // tainted argument reaching one is inherently suspicious regardless of what
  // the static prefix looks like. Requiring a metacharacter in the STATIC
  // portion gets the vulnerability backwards: the textbook shape is
  // `exec("ping " + host)` — the attacker supplies the metacharacter via the
  // TAINTED value, not the template, so the static prefix is legitimately
  // metacharacter-free in the overwhelmingly common case. Confirmed this was
  // blocking CVE-2016-10033-java-cmdi's exact real-world shape; found while
  // investigating this PRD's Java chained-call fix and left deferred until
  // now, when the corpus's Tier 2/3 audit showed it plausibly gates a large
  // fraction of the whole command-injection family, not just one entry.
  if (cwe === 'CWE-78') return true;
  return true;
}

// Shared sink-matching logic for a call expression, regardless of whether
// that call appears in statement position (`case 'call'`) or on an
// assignment's right-hand side (`case 'assign'`). Split into two parts
// (compute, then emit) so `case 'call'` can compute `cat`/`argTaints` at its
// original position — BEFORE the mutated-param / Object.assign / array-taint
// passes that follow it read and rely on those values, and that themselves
// mutate `state` and `callContext._taintSources` in ways the finding-emission
// step (further below, unchanged position) must observe — while still
// sharing the actual matching + emission code with `case 'assign'`, which has
// no such ordering constraint. Extracted rather than duplicated: this
// repository has twice had a rule implemented at one call site and re-broken
// by the next change.

// calleeExpr / argExprs: the IR nodes for the call's callee and arguments.
// state: the taint-state Set to evaluate argument taint against.
// callContext: context from the engine (contains _cha for CHA lookups).
// Returns { cat, argTaints }.
function _matchCallCatalog(calleeExpr, argExprs, state, callContext) {
  const receiverType = _receiverTypeFor(calleeExpr, callContext);
  const cat = matchSinkOrSanitizer(calleeExpr, _currentFile, receiverType);
  const argTaints = (argExprs || []).map(a => exprTaint(a, state, callContext));
  return { cat, argTaints };
}

// Sanitizer callees observed on an expression.
//
// The engine deliberately does NOT let a sanitizer kill taint. A blanket
// "any sanitizer clears the flow" rule scores well on benchmarks and silently
// drops a real SQL injection whenever the code applied an HTML escaper — the
// C/C++ catalog work already found strncpy/snprintf tagged effect:'strip' when
// they bound length rather than sanitising content. So the walk RECORDS which
// sanitizers touched the value and hands them to sanitizer-gate.js, which
// labels the finding, and the proof gate demotes it. Recall-preserving, same
// precedent as falsification.js / proof-gate.js: never removed, never
// severity-touched.
// Calls that UNDO an encoding. The catalog has no entry for these — it models
// sanitizers, and a decoder is the opposite — so they would never be recorded
// on the path and `sanitizer-gate.js` could not see them.
//
// Measured by bench/mutation: `he.decode(escapeHtml(req.query.name))` reaching
// an HTML sink was labelled SANITIZED. The decode puts back exactly what the
// escape removed, so that was a missed XSS reported as clean.
//
// Deliberately a NAME list rather than a catalog kind: these are not analysis
// entries with families and effects, they are a short list of well-known
// inverses, and the gate maps them to the family they reverse.
const _UNSANITIZER_CALLEES = new Set([
  'unescape', 'unescapeHtml', 'unescapeHtml3', 'unescapeHtml4',
  'StringEscapeUtils.unescapeHtml3', 'StringEscapeUtils.unescapeHtml4',
  'he.decode', 'entities.decode', 'html.decode', 'decodeHTML',
  'decodeHTMLStrict', 'decodeEntities', 'html.unescape',
  'html_entity_decode', 'htmlspecialchars_decode', '_.unescape', 'lodash.unescape',
  'decodeURI', 'decodeURIComponent', 'unquote', 'unquote_plus',
  'URLDecoder.decode', 'urldecode', 'querystring.unescape',
]);

// `callee` is an IR NODE, not a string: `{kind:'ident',name:'escapeHtml'}` or
// `{kind:'member',object:{kind:'ident',name:'he'},prop:'decode'}`. Flattened to
// the dotted form the name list is written in, plus the bare leaf so a call
// through an alias (`const {decode} = he`) still matches on an unambiguous name.
function _calleeNames(callee) {
  if (!callee || typeof callee !== 'object') return [];
  if (callee.kind === 'ident' && callee.name) return [callee.name];
  if (callee.kind === 'member' && callee.prop) {
    const obj = callee.object;
    const base = obj && obj.kind === 'ident' && obj.name ? obj.name : null;
    return base ? [`${base}.${callee.prop}`, callee.prop] : [callee.prop];
  }
  return [];
}

// SARD_80_F1 W3.2 — guard-predicate narrowing. `_calleeNames` only handles
// an OBJECT-shaped callee (Babel's `{kind:'ident'|'member',...}`); the five
// hand-rolled parsers (C#/Go/Kotlin/PHP/Ruby) plus Java/Python instead emit
// a flat, dot-joined STRING callee (per ir/CLAUDE.md) — `is_numeric` or
// `int.TryParse`, never a structured node. This normalizes both shapes to
// the same {full, bare-leaf} name pair `GUARD_PREDICATES` matches against.
function _bareCalleeNames(callee) {
  if (typeof callee === 'string') {
    const parts = callee.split('.');
    return [callee, parts[parts.length - 1]];
  }
  return _calleeNames(callee);
}

// A hand-picked, deliberately CONSERVATIVE set of validating predicates
// that, when used as an if-statement's CONDITION and observed true, prove
// the checked variable cannot carry injection metacharacters on the TRUE
// branch specifically — never on the false branch (a guard that FAILS says
// nothing about the value's safety, so that edge, and any code after an
// if-with-no-else, keeps the original tainted state unchanged). Each entry
// names the callees that count as this guard and which argument holds the
// checked variable. Deliberately narrow for this first landing: a regex-
// based guard (`preg_match('/^\d+$/', $x)`) needs the PATTERN itself
// validated as a fully-anchored numeric literal to be sound, and an
// allow-list guard (`in_array($x, $allow, true)`) needs `$allow` resolved
// to a literal array — both are real, documented follow-ups, not attempted
// here to keep this landing's soundness easy to verify.
const GUARD_PREDICATES = [
  // PHP: is_numeric/ctype_* — a string that PASSES is provably digits-only
  // (or alnum), which cannot carry SQL/XPath/shell/LDAP metacharacters.
  { names: ['is_numeric', 'ctype_digit', 'ctype_alnum'], argIndex: 0 },
  // Java: Apache Commons / Spring's StringUtils.isNumeric(x).
  { names: ['StringUtils.isNumeric', 'isNumeric'], argIndex: 0 },
  // C#: `if (int.TryParse(x, out n))` and its numeric-type siblings. Each
  // full dotted name is listed explicitly (not a bare 'TryParse' catch-all)
  // to avoid over-matching an unrelated same-named helper method.
  {
    names: [
      'int.TryParse', 'Int32.TryParse', 'long.TryParse', 'Int64.TryParse',
      'double.TryParse', 'decimal.TryParse', 'float.TryParse',
      'uint.TryParse', 'short.TryParse', 'byte.TryParse',
    ],
    argIndex: 0,
  },
];

// Does `cond` (an if-statement's condition expression) recognizably guard a
// currently-tainted variable per `GUARD_PREDICATES`? Returns that variable's
// access path (to narrow on the true-branch edge only) or null.
function _guardNarrowsVar(cond, state) {
  if (!cond || cond.kind !== 'call') return null;
  const names = _bareCalleeNames(cond.callee);
  for (const g of GUARD_PREDICATES) {
    if (!g.names.some((n) => names.includes(n))) continue;
    const arg = cond.args && cond.args[g.argIndex];
    const path = arg && accessPathOf(arg);
    if (path && isCoveredBy(state, path)) return path;
  }
  return null;
}

// Next-gen taint capability #2 — regex-validation guard narrowing (JS/TS).
// Recognizes the idiom `if (<regex-literal>.test(x)) { ... }` — `parser-js.js`
// lowers a regex literal's own `.test(...)` call to `{kind:'call',
// callee:{kind:'member', object:{kind:'literal', value:RegExp, isRegex:true},
// prop:'test'}, args:[x]}`. When the literal's pattern is
// `isSafeValidationPattern`-safe, an OBSERVED true return proves `x` cannot
// carry injection metacharacters, same soundness contract and TRUE-branch-
// only narrowing as `GUARD_PREDICATES`/`_guardNarrowsVar` above. Deliberately
// narrow for this landing, same "documented follow-up" precedent as that
// function's own header comment: a regex bound to a variable first
// (`const re = /.../; if (re.test(x))`) is not resolved back to its literal —
// this engine has no constant-propagation map for local variable bindings to
// reuse here, and adding one is a real, separate piece of work.
function _regexTestGuardNarrowsVar(cond, state) {
  if (!cond || cond.kind !== 'call') return null;
  const callee = cond.callee;
  if (!callee || typeof callee !== 'object' || callee.kind !== 'member' || callee.prop !== 'test') return null;
  const obj = callee.object;
  if (!obj || obj.kind !== 'literal' || !obj.isRegex || !(obj.value instanceof RegExp)) return null;
  if (!isSafeValidationPattern(obj.value)) return null;
  const arg = cond.args && cond.args[0];
  const path = arg && accessPathOf(arg);
  if (path && isCoveredBy(state, path)) return path;
  return null;
}

function _unsanitizersInExprTree(expr, out) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.kind === 'call') {
    for (const n of _calleeNames(expr.callee)) {
      // The bare leaf is accepted only when it is unambiguous on its own.
      // `decode` is not — jwt.decode, base64 decode, protobuf decode — and
      // matching it would void correct sanitization claims all over the tree.
      if (n === 'decode') continue;
      if (_UNSANITIZER_CALLEES.has(n)) { out.add(n); break; }
    }
  }
  for (const k of ['left', 'right', 'callee', 'object', 'property', 'value']) {
    if (expr[k] && typeof expr[k] === 'object') _unsanitizersInExprTree(expr[k], out);
  }
  for (const k of ['args', 'parts', 'branches', 'elements']) {
    if (Array.isArray(expr[k])) for (const e of expr[k]) _unsanitizersInExprTree(e, out);
  }
  if (Array.isArray(expr.props)) for (const p of expr.props) _unsanitizersInExprTree(p && p.value, out);
}

function _sanitizersInExprTree(expr, out) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.kind === 'call') {
    const cat = matchSinkOrSanitizer(expr.callee, _currentFile);
    if (cat) {
      for (const e of cat) {
        if (e.kind === 'sanitizer' && e.match && e.match.callee) out.add(e.match.callee);
      }
    }
  }
  for (const k of ['left', 'right', 'callee', 'object', 'property', 'value']) {
    if (expr[k] && typeof expr[k] === 'object') _sanitizersInExprTree(expr[k], out);
  }
  for (const k of ['args', 'parts', 'branches', 'elements']) {
    if (Array.isArray(expr[k])) for (const e of expr[k]) _sanitizersInExprTree(e, out);
  }
  if (Array.isArray(expr.props)) for (const p of expr.props) _sanitizersInExprTree(p && p.value, out);
}

// Sanitizers applied to `expr`: those called inline within it, plus those
// Un-sanitizers applied to `expr`, by the same rule: inline in the expression,
// or inherited from a variable it reads. The inheritance half is what makes it
// work at all — `const escaped = escapeHtml(x); const name = he.decode(escaped);
// sink(name)` puts the decode on an ASSIGNMENT, so an expression-tree walk of
// the sink argument sees only `name` and would never find it.
function _unsanitizersForExpr(expr, callContext) {
  const out = new Set();
  _unsanitizersInExprTree(expr, out);
  const byVar = callContext && callContext._unsanitizersByVar;
  if (byVar && byVar.size) {
    const vars = new Set();
    _collectExprVars(expr, vars);
    for (const v of vars) {
      const s = byVar.get(v);
      if (s) for (const n of s) out.add(n);
    }
  }
  return out;
}

// recorded against any variable it reads (`const safe = escapeHtml(x); sink(safe)`).
function _sanitizersForExpr(expr, callContext) {
  const out = new Set();
  _sanitizersInExprTree(expr, out);
  const byVar = callContext && callContext._sanitizersByVar;
  if (byVar && byVar.size) {
    const vars = new Set();
    _collectExprVars(expr, vars);
    for (const v of vars) {
      const s = byVar.get(v);
      if (s) for (const n of s) out.add(n);
    }
  }
  return out;
}

// Sound taint-kill for TYPE-COERCION sanitizers (SARD_80_F1_SCANNER_PRD.md).
//
// Every OTHER sanitizer in this engine only ever DEMOTES (sanitizer-gate.js /
// proof-gate.js), never kills taint outright — the well-documented reason is
// that a sanitizer's effect is family-specific (`htmlspecialchars` does
// nothing for SQLi), so killing taint on ANY sanitizer call would silently
// drop a real vulnerability whenever an unrelated escaper happened to sit on
// the path. A catalog entry tagged `appliesTo: ['*']` is categorically
// different: it is registered specifically because it changes the VALUE'S
// TYPE (intval, filter_var(..., FILTER_VALIDATE_INT), parseInt, Integer.parseInt,
// strconv.Atoi, ...), not because it neutralizes one syntax. A value that has
// gone through a genuine type coercion cannot carry injection syntax for ANY
// string-based family at once — the same reasoning that forbids a blanket
// kill for family-specific sanitizers affirmatively REQUIRES one here, or
// every one of these 17+ catalog entries does nothing but cost confidence
// point.
//
// Scoped tightly: only fires when `expr` IS ITSELF a direct call whose own
// callee catalog-matches a universal sanitizer — never a guess, never
// something buried deeper in an unrelated expression tree (that's what
// `_sanitizersForExpr` already recall-preservingly handles for the DEMOTE
// path). `data = intval($_GET['x']);` fires this; `data = "x=" . intval($y);`
// (the coercion is only PART of the value) does not, and correctly still
// gets full taint tracking on the concatenation.
// Shared with _sinkFindingsForCall's identical sink-side check (below): a
// `requireLiteralArg` gate applies equally to a SANITIZER entry whose
// effectiveness depends on which literal was passed (`filter_var($x,
// FILTER_VALIDATE_INT)` genuinely coerces; `filter_var($x,
// FILTER_SANITIZE_STRING)` or a bare `filter_var($x)` does not — both are the
// SAME callee, distinguished only by this argument). Fails CLOSED: a missing
// or non-literal arg does not satisfy the requirement, same direction every
// other precision gate in this file takes when evidence is unavailable.
function _literalArgSatisfied(argExprs, requireLiteralArg) {
  const { index, pattern } = requireLiteralArg;
  const checkArg = (argExprs || [])[index];
  return !!checkArg && checkArg.kind === 'literal' && new RegExp(pattern).test(String(checkArg.value));
}

// SARD_80_F1 W5.49 — PHP's `sprintf("...%d...", $tainted)` is a PER-ARGUMENT
// coercion sanitizer, distinct from `_isCoercionCall`'s whole-call model
// (intval/floatval/etc, where the ENTIRE call's return value is the coerced
// scalar). `sprintf` returns a TEMPLATE string; only the specific argument(s)
// bound to a purely-numeric conversion (%d/%u/%f/%x/%o/%b/...) are coerced —
// an argument bound to %s passes through raw and is NOT coerced, and %c
// converts an integer to a single arbitrary BYTE (an attacker-controlled
// code point can still be a quote/semicolon/backslash), so it is
// deliberately excluded from the safe set even though it looks numeric-ish.
//
// Confirmed as a REAL, previously-unrecognized PHP SQL-injection false-
// positive source via the public generator source this session already has
// an established exception for (stivalet/PHP-Vuln-test-suite-generator's own
// `bin/XML/construction.xml`): its CWE-89 "safe" construction sample is
// LITERALLY `$query = sprintf("SELECT * FROM student where id=%d",
// $tainted);` (`safety flawType="CWE_89_Injection" ... safe="1"`) — a type-
// coercion mitigation this engine had no mechanism for at all before this
// fix, confirmed via a direct, from-scratch `runScan()` reproduction of this
// exact real-generator shape (not corpus/gold access).
//
// Positional-vs-explicit argnum handling matches PHP's own sprintf spec
// (`%2$d` explicitly names argument 2, 1-based); an unrecognized/malformed
// conversion is conservatively treated as unsafe (not added to the safe
// set) rather than guessed.
const _SPRINTF_SAFE_NUMERIC_SPECS = new Set(['d', 'u', 'f', 'F', 'e', 'E', 'g', 'G', 'x', 'X', 'o', 'b']);
const _SPRINTF_CONVERSION_RE = /%(\d+\$)?[-+ 0']*(\d+)?(\.\d+)?([bcdeEfFgGosuxX%])/g;
function _sprintfSafeArgIndices(fmt) {
  if (typeof fmt !== 'string') return null;
  const safe = new Set();
  let positional = 0;
  const re = new RegExp(_SPRINTF_CONVERSION_RE.source, 'g');
  let m;
  while ((m = re.exec(fmt))) {
    const spec = m[4];
    if (spec === '%') continue; // literal %% consumes no argument
    const idx = m[1] ? (parseInt(m[1], 10) - 1) : positional++;
    if (_SPRINTF_SAFE_NUMERIC_SPECS.has(spec)) safe.add(idx);
  }
  return safe;
}
// Numeric coercion defeats SYNTAX-ESCAPING injection (SQL/XPath/LDAP/
// command/eval all require the attacker to inject a quote/semicolon/
// metacharacter to break out of a string literal — impossible once the
// value is pure digits) but does NOT defeat RESOURCE-SELECTION vulnerabilities
// (file inclusion, path traversal): a purely numeric value can still select
// an unintended resource among many (`pages/5.php` vs `pages/999.php`), so
// coercion alone does not make it safe. Confirmed via the SAME public
// generator source this fix already relies on: `bin/XML/construction.xml`
// marks `$var = include(sprintf("pages/'%d'.php", $tainted));` UNSAFE
// (`safe="0"`) even though the value is %d-coerced — found via a real,
// reproducible regression (CWE-98 tp -1) during this fix's own real-corpus
// verification. `_isCoercionCall`'s existing intval/floatval mechanism has
// the IDENTICAL blind spot already (confirmed via direct reproduction:
// `include("pages/" . intval($_GET['page']) . ".php")` already produces
// zero findings before this change) — this fix does not introduce a new
// risk class, but it's common enough via sprintf specifically to be worth
// closing here: skip the coercion whenever the format string's STATIC
// (non-conversion) text looks like a file-path template, a narrow,
// principled heuristic (a `/` path separator, or a trailing `.ext`-shaped
// suffix) rather than a benchmark-fitted exclusion.
function _sprintfLooksLikeFilePath(fmt) {
  const stripped = fmt.replace(new RegExp(_SPRINTF_CONVERSION_RE.source, 'g'), '');
  if (stripped.includes('/')) return true;
  return /\.[A-Za-z0-9]{1,5}['")\]]*\s*$/.test(stripped);
}
// `argExprIndex` is the index within `expr.args` (0 = the format string
// itself, 1 = the first value argument) — matches how callers already index
// `expr.args` elsewhere in this file (e.g. `_literalArgSatisfied`).
function _isSprintfSafeArg(expr, argExprIndex) {
  if (!expr || expr.kind !== 'call' || argExprIndex < 1) return false;
  const name = typeof expr.callee === 'string' ? expr.callee.split('.').pop() : null;
  if (name !== 'sprintf') return false;
  const fmtArg = (expr.args || [])[0];
  if (!fmtArg || fmtArg.kind !== 'literal' || typeof fmtArg.value !== 'string') return false;
  if (_sprintfLooksLikeFilePath(fmtArg.value)) return false;
  const safe = _sprintfSafeArgIndices(fmtArg.value);
  return !!safe && safe.has(argExprIndex - 1);
}

function _isCoercionCall(expr) {
  if (!expr || expr.kind !== 'call' || !expr.callee) return false;
  const cat = matchSinkOrSanitizer(expr.callee, _currentFile);
  if (!Array.isArray(cat)) return false;
  return cat.some(e => e.kind === 'sanitizer' && Array.isArray(e.appliesTo) && e.appliesTo.includes('*')
    && (!e.match || !e.match.requireLiteralArg || _literalArgSatisfied(expr.args, e.match.requireLiteralArg)));
}

// cat / argTaints: the result of _matchCallCatalog (computed by the caller,
// at whatever point in its case is appropriate for its own state-mutation
// ordering).
// state: used only to attribute reaching sources to the tainted argument
// expression (via callContext._taintSources, not the state Set itself).
// line: source line to attach to any emitted finding.
// Returns { findings }.
function _sinkFindingsForCall(calleeExpr, argExprs, cat, argTaints, state, callContext, line, callKwargs) {
  const findings = [];
  if (cat) {
    for (const e of cat) {
      if (e.kind === 'sink' && (
        e.argIndex === 'all' ? argTaints.some(Boolean) :
        (typeof e.argIndex === 'number' && argTaints[e.argIndex])
      )) {
        const taintedArgIdx = e.argIndex === 'all'
          ? argTaints.findIndex(Boolean) : e.argIndex;
        const taintedArgExpr = (argExprs || [])[taintedArgIdx];
        // String content analysis: skip if literal skeleton doesn't match injection family
        if (e.vuln && taintedArgExpr && !literalSkeletonMatchesFamily(taintedArgExpr, e.vuln.cwe)) continue;
        // Taint-recall PRD (80%): `match.requireLiteralArg` — a precision
        // gate for sinks whose danger depends on a SIBLING argument's
        // literal value, not the tainted one. Go's `exec.Command(path,
        // args...)` is only actually shell-interpreted (so a metacharacter
        // in a tainted arg is dangerous) when `path` is "/bin/sh"/"bash"/
        // "sh" and the next arg is "-c" — the array-execve form
        // (`exec.Command("ping", "-c", "1", host)`) never invokes a shell
        // at all, so `host` becomes one opaque argv element regardless of
        // its content and is SAFE even when tainted. `argIndex: 'all'`
        // alone can't express this (it only asks "is ANY arg tainted", not
        // "is the INVOCATION FORM itself dangerous"). Fails CLOSED on
        // precision: if the checked arg isn't a literal at all (a
        // variable — we can't statically know its value), the requirement
        // is NOT satisfied, same direction proof-gate.js and every other
        // precision annotator in this codebase take when evidence is
        // simply unavailable rather than affirmatively clean.
        if (e.match && e.match.requireLiteralArg && !_literalArgSatisfied(argExprs, e.match.requireLiteralArg)) continue;
        // `match.requireKeyword` — the KEYWORD-argument analogue of the
        // positional gate above, for languages where the dangerous form is
        // selected by a named argument rather than a positional literal.
        //
        // Python's `subprocess.run(cmd, shell=True)` is command injection;
        // `subprocess.run([cmd], capture_output=True)` is an argv-array
        // execve that cannot be, however tainted `cmd` is. requireLiteralArg
        // cannot express the difference — it matches a POSITIONAL literal,
        // and shell is a keyword. Measured cost of not having this: enabling
        // the argparse CLI source surfaced 15 findings across 9 of this
        // repository's own hand-reviewed scripts, on argv-array calls,
        // labelled "shell=True".
        //
        // Fails CLOSED exactly like requireLiteralArg: a keyword that is
        // absent, or present but not a statically-known literal matching the
        // pattern, does NOT satisfy the requirement.
        if (e.match && e.match.requireKeyword) {
          const { name, pattern } = e.match.requireKeyword;
          // A `**opts` splat means the keyword set is not enumerable: we
          // cannot prove `shell` is absent, so we must not suppress. Failing
          // closed here would be a FALSE NEGATIVE on a genuinely exploitable
          // call — bench/cve-replay/deep/py-interproc-cmdi-shape exists
          // precisely to pin that case (`subprocess.call(cmd, **SHELL_OPTS)`)
          // and caught this the first time the gate was written without it.
          const enumerable = !(callKwargs && callKwargs['**']);
          if (enumerable) {
            const kw = callKwargs && callKwargs[name];
            if (!kw || kw.kind !== 'literal' || !new RegExp(pattern).test(String(kw.value))) continue;
          }
        }
        // Premortem #10: attribute the source for THIS sink to the
        // source(s) that taint the actual argument expression — not the
        // first source the worklist happened to record. We walk the
        // expression's free vars / access paths against the recorded
        // _taintSources and keep entries whose root variable still
        // covers something in the expression.
        const reachingSources = _sourcesReachingExpr(taintedArgExpr, state, callContext._taintSources);
        const traceForThisFinding = reachingSources.length
          ? reachingSources.slice(0, 5)
          // Fallback: better to surface "no precise source" than the wrong source.
          : [];
        // Sanitizers seen on the value reaching THIS argument. Consumed by
        // sanitizer-gate.js, which labels only when the sanitizer's family
        // covers the finding's threat class — an xss escaper on a SQL sink
        // must not read as sanitised.
        const _sanNames = _sanitizersForExpr(taintedArgExpr, callContext);
        const _unsanNames = _unsanitizersForExpr(taintedArgExpr, callContext);
        findings.push({
          ...(_sanNames.size ? { _sanitizersOnPath: [..._sanNames] } : {}),
          ...(_unsanNames.size ? { _unsanitizersOnPath: [..._unsanNames] } : {}),
          kind: 'taint',
          sinkId: e.id,
          vuln: e.vuln?.name || 'Tainted Sink',
          severity: e.vuln?.severity || 'high',
          cwe: e.vuln?.cwe || null,
          remediation: e.vuln?.remediation || null,
          line,
          argIndex: taintedArgIdx,
          callee: calleeExpr,
          sourceProvenance: (traceForThisFinding[0]?.provenance) || null,
          trace: traceForThisFinding,
        });
      }
    }
  }
  return { findings };
}

// Taint-recall PRD (80%): a sink call NESTED inside another call's own
// argument (`render(File.read(tainted))`, Rails' idiomatic wrap-and-render
// pattern) was invisible to sink-matching entirely. `_sinkFindingsForCall`
// only ever checks the CFG NODE'S OWN callee/args — a node representing
// `render(...)` never independently examines whether one of `render`'s OWN
// arguments is itself a sink-shaped call expression. Confirmed via a real
// corpus fixture: `File.read` is a correctly-cataloged sink and `name` a
// correctly-cataloged source, but nested one level inside `render`'s own
// arg list, neither `case 'call'` nor `case 'assign'` ever checked it — the
// exact "sink nested inside another call's own argument" limitation
// documented in this PRD's Ruby/C#/Go/Kotlin corpus notes, now closed for
// the general case rather than left as a permanent gap. Recall-preserving:
// walks every arg looking for a nested call expression, checks each
// independently against the catalog, and recurses further (an arg's arg
// can itself be a call) — bounded by JS's own call-stack depth on
// pathologically deep expressions, no explicit cap needed at this level of
// real-world nesting. Deliberately does NOT re-check the TOP-LEVEL call
// itself (the caller already did that via its own _matchCallCatalog +
// _sinkFindingsForCall), so this never duplicates a finding.
function _nestedSinkFindings(argExprs, state, callContext, line) {
  const findings = [];
  for (const arg of (argExprs || [])) {
    if (!arg || arg.kind !== 'call') continue;
    const { cat, argTaints } = _matchCallCatalog(arg.callee, arg.args, state, callContext);
    findings.push(..._sinkFindingsForCall(arg.callee, arg.args, cat, argTaints, state, callContext, line).findings);
    findings.push(..._nestedSinkFindings(arg.args, state, callContext, line));
  }
  return findings;
}

// PRD R13(a): finding shape for a member-write sink match (el.innerHTML =
// tainted). Distinct from _sinkFindingsForCall because there is no call
// argument list to index into — the "argument" of interest is the whole
// assignment RHS, which the catalog entries already mark via argIndex:'rhs'
// (a sentinel that existed in these 3 entries since they were added, with no
// consumer until now). Mirrors _sinkFindingsForCall's trace/sanitizer
// attribution exactly, so a member-write finding looks like any other
// deep-mode finding downstream.
function _memberWriteSinkFindings(hits, sourceExpr, state, callContext, line, targetPath) {
  const findings = [];
  for (const e of hits) {
    const reachingSources = _sourcesReachingExpr(sourceExpr, state, callContext._taintSources);
    const traceForThisFinding = reachingSources.length ? reachingSources.slice(0, 5) : [];
    const _sanNames = _sanitizersForExpr(sourceExpr, callContext);
    const _unsanNames = _unsanitizersForExpr(sourceExpr, callContext);
    findings.push({
      ...(_sanNames.size ? { _sanitizersOnPath: [..._sanNames] } : {}),
      ...(_unsanNames.size ? { _unsanitizersOnPath: [..._unsanNames] } : {}),
      kind: 'taint',
      sinkId: e.id,
      vuln: e.vuln?.name || 'Tainted Sink',
      severity: e.vuln?.severity || 'high',
      cwe: e.vuln?.cwe || null,
      remediation: e.vuln?.remediation || null,
      line,
      argIndex: 'rhs',
      callee: targetPath,
      sourceProvenance: (traceForThisFinding[0]?.provenance) || null,
      trace: traceForThisFinding,
    });
  }
  return findings;
}

// Surfaces a cached (or freshly computed) summary's `findings` into the
// CURRENT caller's context — the only place a class-field/k=2 pre-pass's
// speculative findings (in runTaintEngine) become reportable, because
// reaching this point means a real call site actually consulted that exact
// qid+entry. Called uniformly on both a cache HIT (`summaryCache.get()`)
// and a cache MISS (`summaryCache.compute()`'s return value), so it doesn't
// matter whether this call site is the first one to ever reach this
// qid+entry or the fifth — findings ride on the summary object itself now,
// not on a one-shot merge inside compute()'s callback. Module-level (not
// nested in runTaintEngine) because step()'s assign/plain-call interproc
// branches call it too, and step() is a top-level function with no access
// to runTaintEngine's locals.
function _mergeSummaryFindings(callContext, callerQid, sum, via) {
  if (!sum || !Array.isArray(sum.findings) || !sum.findings.length) return;
  callContext._findings.push(...sum.findings.map(f => ({ ...f, _funcQid: callerQid || null, _via: via })));
}

// Apply a CFG node to a taint-state. Returns the new state + any finding emitted.
function step(node, stateIn, callContext) {
  // `let`, not `const` — the 'call' case (built-in-mutation and mutated-param
  // branches below) reassigns this binding. It was `const` until Stage 3 of
  // the correctness audit: a bare-statement call to Object.assign/_.merge/
  // etc. with a tainted source arg, or any plain call whose callee summary
  // reports mutated params, threw "Assignment to constant variable" here.
  // The engine's per-function analyzeFunction() call sites all wrap in a
  // blanket try/catch, so the exception was silent — and it discarded every
  // finding already collected for the ENTIRE containing function, not just
  // the mutation site, since the throw unwound past `findings.push(...)`
  // calls for unrelated sinks earlier in the same function body.
  let state = new Set(stateIn);
  const findings = [];

  switch (node.kind) {
    case 'entry':
    case 'exit':
    case 'noop':
    case 'loop-header':
      return { state, findings };

    case 'assign': {
      const src = exprIsSource(node.source, callContext);
      const target = typeof node.target === 'string' ? node.target : null;
      // Sink matching is additive to this case's existing source/target/taint
      // handling below: an assignment's RHS can itself be a sink call (e.g.
      // `const rows = db.query(tainted)`), which previously went unreported
      // because this case never consulted the catalog at all. Computed here,
      // against the incoming (pre-mutation) `state`, mirroring how `case
      // 'call'` computes its own cat/argTaints before its mutation passes —
      // and pushed into the shared `findings` array so it survives every
      // return path below, including the early interprocedural returns.
      if (node.source && node.source.kind === 'call') {
        const { cat: _sinkCat, argTaints: _sinkArgTaints } =
          _matchCallCatalog(node.source.callee, node.source.args, state, callContext);
        findings.push(..._sinkFindingsForCall(
          node.source.callee, node.source.args, _sinkCat, _sinkArgTaints,
          state, callContext, node.line, node.source.kwargs).findings);
        findings.push(..._nestedSinkFindings(node.source.args, state, callContext, node.line));
      }
      // PRD R13(a): the assignment TARGET can itself be a sink shape
      // (el.innerHTML = tainted) — additive to the RHS-call-sink check
      // above, which only ever looked at node.source. `target` is only a
      // dotted member-access path when the LHS was a member expression
      // (lhsPath in parser-js.js); a bare identifier target ("x") has no
      // dot and _matchMemberWriteSink correctly returns null for it.
      if (target && target.includes('.')) {
        // PRD SARD_80_F1 §9/§15.1: a bare, non-dotted receiver segment
        // (`searcher` in `searcher.Filter`) can be CHA-typed exactly like
        // `_receiverTypeFor` types a call receiver — same classOfVar lookup,
        // same "only a plain local var-name assigned `new X()`" scope. This
        // lets a write-sink entry's `receiverTypeIn` fire on the real
        // allocation type when the variable's NAME doesn't match its
        // `receiver` regex (renamed identifiers, or just a different naming
        // convention than the one the regex was written against).
        const _receiverVar = target.slice(0, target.lastIndexOf('.'));
        const _memberReceiverType = (_receiverVar && !_receiverVar.includes('.') && callContext && callContext._cha)
          ? classOfVar(callContext._cha, _currentFile, callContext._currentFnQid, _receiverVar)
          : null;
        const _memberHits = matchMemberWriteSink(target, _currentFile, _memberReceiverType);
        if (_memberHits && exprTaint(node.source, state, callContext)) {
          findings.push(..._memberWriteSinkFindings(
            _memberHits, node.source, state, callContext, node.line, target));
        }
      }
      // Record which sanitizers were applied to the value now held by `target`
      // (inline in the RHS, or inherited from the vars the RHS reads). Placed
      // before every early return in this case so the map cannot go stale on
      // the interprocedural paths below. A clean RHS clears the entry, mirroring
      // removePathAndDescendants — a stale sanitizer would label a later,
      // genuinely unsanitized flow.
      if (target) {
        const _san = _sanitizersForExpr(node.source, callContext);
        const _byVar = (callContext._sanitizersByVar ||= new Map());
        if (_san.size) _byVar.set(target, _san);
        else _byVar.delete(target);
        // The same bookkeeping for reversals, and for the same reason: a clean
        // re-assignment must clear it, or a decode recorded once would void
        // every later sanitization claim on that name.
        const _unsan = _unsanitizersForExpr(node.source, callContext);
        const _unByVar = (callContext._unsanitizersByVar ||= new Map());
        if (_unsan.size) _unByVar.set(target, _unsan);
        else _unByVar.delete(target);
      }
      let newState = state;
      // Premortem #7: interprocedural return-taint via SummaryCache. If the
      // RHS is a call to a known callee whose empty-entry-state summary says
      // the return is tainted, taint the assignment target. This makes the
      // simplest cross-function flow (helper reads req.body and returns it)
      // visible to the engine — the case the cache was built for.
      const calleeName = node.source && node.source.kind === 'call'
        ? _flattenCalleeName(node.source.callee) : null;
      if (target && calleeName && callContext._summaryCache && callContext._callGraph) {
        const _resolvedTarget = node.source && node.source.kind === 'call'
          ? _resolveCalleeForSummary(node.source.callee, callContext) : null;
        const fn  = _resolvedTarget && _resolvedTarget.fn;
        const qid = _resolvedTarget && _resolvedTarget.qid;
        if (typeof qid === 'string') {
          // v0.66 — context-sensitive lookup. Build the entry-state from
          // the call args + current taint; look up (and lazily compute) the
          // summary for THAT state, not just empty. This is what closes the
          // "helper is pure when called clean but tainted when called with
          // user input" FN class.
          const callerTainted = newState;
          const callArgs = (node.source.args || []);
          const paramNames = (fn && Array.isArray(fn.params)) ? fn.params : [];
          const entry = paramNames.length
            ? entryStateFromCall(paramNames, callArgs, callerTainted, (a) => exprTaint(a, callerTainted, callContext))
            : new Set();
          let sum = callContext._summaryCache.get(qid, entry);
          if (!sum && fn && fn.cfg) {
            // Lazy compute under this entry state. Use a fresh ctx so we
            // don't pollute the outer caller's _taintSources with the
            // callee's internal noise.
            sum = callContext._summaryCache.compute(qid, entry, () => {
              const inner = {
                _findings: [], _taintSources: [], _returnTainted: false,
                _stack: new Set(), deadlineMs: callContext.deadlineMs,
                _summaryCache: callContext._summaryCache,
                _callGraph: callContext._callGraph,
                _mutatedParamsOut: new Set(),
                _cha: callContext._cha,
              };
              try { analyzeFunction(fn, _unionAnnotationTaint(fn, entry), inner); } catch {}
              return {
                returnTainted: !!inner._returnTainted,
                mutatedParams: inner._mutatedParamsOut || new Set(),
                mutatedThisFields: inner._mutatedThisFieldsOut || new Set(),
                taintedGlobals: new Set(),
                // Real findings from the callee's own body — e.g.
                // `function makeQuery(id){ db.query(...id) } ... makeQuery(uid)`
                // — ride on the summary itself (was hardcoded `[]`, so
                // nothing ever read inner._findings and the SQLi inside
                // makeQuery was silently dropped). _mergeSummaryFindings
                // below surfaces them into THIS caller now that a real
                // call site has been established, and does the same on a
                // future cache hit from any other real caller.
                findings: inner._findings,
              };
            });
          }
          _mergeSummaryFindings(callContext, callContext._currentFnQid, sum, 'interproc');
          // Next-gen taint capability #3: `x = bad.getData()` — a single-
          // field getter's return is tainted whenever THIS call's own
          // receiver already carries that field, independent of `sum`
          // (a zero-param getter's entry-state summary can never see it).
          const _getterTainted = _calleeGetterFieldTainted(node.source.callee, newState, callContext);
          if ((sum && sum.returnTainted) || _getterTainted) {
            newState = _addPathAliasAware(newState, target, callContext);
            callContext._taintSources.push({
              varName: target,
              sourceId: `interproc:${qid}`,
              sourceLabel: `interproc-return:${calleeName}`,
              provenance: 'interproc',
              line: node.line,
            });
          }
          // applyAtCallSite — mutated params (and, next-gen capability #3,
          // the implicit `this` receiver's own mutated fields) propagate to
          // the caller's state.
          if (sum && ((sum.mutatedParams && sum.mutatedParams.size && paramNames.length) || (sum.mutatedThisFields && sum.mutatedThisFields.size))) {
            const receiverPath = _receiverAccessPathOf(node.source.callee);
            const applied = callContext._summaryCache.applyAtCallSite(
              sum, paramNames, callArgs, callerTainted, receiverPath);
            for (const v of applied.mutated) newState = addPath(newState, v);
            for (const p of applied.mutatedThisPaths) newState = addPath(newState, p);
          }
          if ((sum && sum.returnTainted) || _getterTainted) return { state: newState, findings };
        } else if (target && calleeName) {
          // Fallback: check builtin summaries for unresolved external calls
          const builtin = lookupBuiltinSummary(calleeName);
          if (builtin) {
            const _argTainted = (node.source.args || []).some(a => exprTaint(a, newState, callContext));
            if (builtin.returnTainted && _argTainted) {
              newState = _addPathAliasAware(newState, target, callContext);
            } else if (!builtin.returnTainted) {
              // PRD R4b: a builtin summary saying returnTainted:false can mean
              // two very different things — a genuinely non-deriving function
              // (crypto.randomBytes) where clearing taint is correct, or a
              // sanitizer-shaped function (encodeURIComponent, parseInt,
              // DOMPurify.sanitize...) that DOES receive tainted input and
              // whose safety is family-scoped (a URL encoder does nothing for
              // SQLi). `_sanitizersForExpr` above already recorded the latter
              // case into `_sanitizersByVar` when this callee is ALSO a
              // registered catalog sanitizer — defer to sanitizer-gate.js's
              // family-aware demotion there instead of unconditionally
              // killing every family's taint here. Only a genuinely-untainted
              // argument, or a callee with no catalog-sanitizer registration,
              // still clears via removePathAndDescendants.
              const _recordedSan = target && callContext._sanitizersByVar && callContext._sanitizersByVar.get(target);
              if (_argTainted && _recordedSan && _recordedSan.size) {
                newState = _addPathAliasAware(newState, target, callContext);
              } else {
                newState = removePathAndDescendants(newState, target);
              }
              return { state: newState, findings };
            }
            if (builtin.mutatedParams && builtin.mutatedParams.size) {
              for (const idx of builtin.mutatedParams) {
                const argExpr = (node.source.args || [])[parseInt(idx)];
                if (argExpr && argExpr.kind === 'ident' && (node.source.args || []).some(a => exprTaint(a, newState, callContext))) {
                  newState = _addPathAliasAware(newState, argExpr.name, callContext);
                }
              }
            }
          }
        }
      }
      if (target && _isCoercionCall(node.source)) {
        // See _isCoercionCall's header comment: a real type coercion kills
        // taint outright, unconditionally of sink family — the one case in
        // this engine where a sanitizer does more than demote.
        newState = removePathAndDescendants(newState, target);
      } else if (src && target) {
        newState = _addPathAliasAware(newState, target, callContext);
        const sourcePath = accessPathOf(node.source);
        if (sourcePath) newState = addPath(newState, sourcePath);
        callContext._taintSources.push({ varName: target, sourceId: src.id, sourceLabel: src.label, provenance: src.provenance || null, line: node.line });
      } else if (exprTaint(node.source, newState, callContext)) {
        // P1.1: when the source IS a pure access path (e.g., RHS is `obj.foo.bar`),
        // taint the TARGET as well as transitively propagate the source path so
        // later uses of the same source remain tainted. The target path
        // becomes the new tainted location.
        if (target) {
          newState = _addPathAliasAware(newState, target, callContext);
          const sourcePath = accessPathOf(node.source);
          if (sourcePath && !isCoveredBy(newState, sourcePath)) newState = addPath(newState, sourcePath);
        }
      } else {
        // Re-assigning a previously-tainted var to a clean value clears it
        // AND its descendants — P1.1 semantics: assigning `x = clean` kills
        // `x.foo`, `x.foo.bar`, etc. Sanitization at root level.
        if (target) newState = removePathAndDescendants(newState, target);
      }
      return { state: newState, findings };
    }

    case 'call': {
      // 1. Catalog match: sanitizer, sink, or just an external/unresolved call.
      // Computed here (before the mutation passes below) so that argTaints
      // reflects the pre-mutation state, exactly as before this logic was
      // extracted into _matchCallCatalog/_sinkFindingsForCall.
      const { cat, argTaints } = _matchCallCatalog(node.callee, node.args, state, callContext);
      // v0.66 — apply mutated-param taint at plain (non-assign) call sites.
      // Object.assign(target, tainted) → target becomes tainted in caller.
      const _plainCallCalleeName = _flattenCalleeName(node.callee);
      if (callContext._summaryCache && callContext._callGraph && _plainCallCalleeName) {
        const _resolvedTarget = _resolveCalleeForSummary(node.callee, callContext);
        const fn  = _resolvedTarget && _resolvedTarget.fn;
        const qid = _resolvedTarget && _resolvedTarget.qid;
        if (typeof qid === 'string' && fn && Array.isArray(fn.params)) {
          const paramNames = fn.params;
          const entry = paramNames.length
            ? entryStateFromCall(paramNames, node.args || [], state, (a) => exprTaint(a, state, callContext))
            : new Set();
          let sum = callContext._summaryCache.get(qid, entry);
          // FR-SEM-2: context-sensitive lazy compute at the plain-call site,
          // mirroring the assign-call site. On a miss for a NON-empty entry,
          // compute the callee's summary UNDER that tainted-arg context so a
          // param mutated only when called with user input is detected here
          // too (not just when the call's result is assigned). Bounded by the
          // SummaryCache context cap.
          if (!sum && entry.size && fn && fn.cfg) {
            sum = callContext._summaryCache.compute(qid, entry, () => {
              const inner = {
                _findings: [], _taintSources: [], _returnTainted: false,
                _stack: new Set(), deadlineMs: callContext.deadlineMs,
                _summaryCache: callContext._summaryCache,
                _callGraph: callContext._callGraph,
                _mutatedParamsOut: new Set(),
                _cha: callContext._cha,
              };
              try { analyzeFunction(fn, _unionAnnotationTaint(fn, entry), inner); } catch {}
              return {
                returnTainted: !!inner._returnTainted,
                mutatedParams: inner._mutatedParamsOut || new Set(),
                mutatedThisFields: inner._mutatedThisFieldsOut || new Set(),
                taintedGlobals: new Set(),
                // See the sibling assign-call-site compute() above — same
                // fix, same reason: this callee's own findings were
                // computed correctly and then thrown away (hardcoded `[]`).
                findings: inner._findings,
              };
            });
          }
          _mergeSummaryFindings(callContext, callContext._currentFnQid, sum, 'interproc');
          // Next-gen taint capability #3: the plain-statement-position
          // counterpart of the assign-from-call site above — `bad.setData(
          // tainted);` never assigns anything, but the receiver's OWN field
          // still needs tainting so a LATER `bad.getData()`/`bad.data` read
          // sees it.
          if (sum && ((sum.mutatedParams && sum.mutatedParams.size) || (sum.mutatedThisFields && sum.mutatedThisFields.size))) {
            const receiverPath = _receiverAccessPathOf(node.callee);
            const applied = callContext._summaryCache.applyAtCallSite(
              sum, paramNames, node.args || [], state, receiverPath);
            for (const v of applied.mutated) state = addPath(state, v);
            for (const p of applied.mutatedThisPaths) state = addPath(state, p);
          }
        }
      }
      // Built-in mutation functions: Object.assign(target, ...sources),
      // _.merge(target, ...sources), etc. When any source arg is tainted,
      // taint the target in the caller's scope.
      const calleeName = _plainCallCalleeName;
      if (calleeName && /^(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|_\.defaults|Object\.defineProperties?)$/.test(calleeName)) {
        const targetArg = (node.args || [])[0];
        const sourceArgsTainted = argTaints.slice(1).some(Boolean);
        if (targetArg && targetArg.kind === 'ident' && sourceArgsTainted) {
          state = _addPathAliasAware(state, targetArg.name, callContext);
          callContext._taintSources.push({
            varName: targetArg.name,
            sourceId: `builtin-mutation:${calleeName}`,
            sourceLabel: `${calleeName} mutation`,
            provenance: 'mutation',
            line: node.line,
          });
        }
      }
      // R4 (PRD §5) + T3.3: collection-element taint. A mutating collection
      // method called with a tainted argument taints the receiver; an index or
      // key read (`a[0]` → access path "a.0", `m.get(k)` → receiver taint via
      // _calleeReceiverTainted) is then covered by the receiver prefix.
      // Object-property taint already flows via the access-path lattice — this
      // closes the container case.
      //
      // R4 covered JS arrays only, in both of its dimensions, and T3.3 widens
      // each:
      //   - METHODS: keyed collections mutate through `set`/`add`, and the
      //     non-JS containers through `append`/`extend`/`insert`/`update`/
      //     `addAll`/`putAll`/`put`. These are writes exactly as `push` is.
      //   - CALLEE SHAPE: the `callee.kind === 'member'` test only ever matched
      //     `parser-js.js` (Babel), the one frontend emitting a structured
      //     callee. The seven hand-rolled parsers emit a flat dot-joined STRING
      //     ("items.append"), so Python/Ruby/PHP/Go/Java/C#/Kotlin containers
      //     never matched at all — measured: python's `items.append(tainted)`
      //     produced no IR-TAINT finding, and only a PY-SAST pattern rule
      //     caught the sink, which masked the taint-layer miss entirely. Same
      //     frontend duality `_calleeReceiverTainted` documents and handles.
      //
      // `add`/`put` are deliberately NOT extended to bare-name calls: the
      // receiver is what gets tainted, so a call with no receiver has nothing
      // to taint and is skipped by both branches below.
      if (Array.isArray(argTaints) && argTaints.some(Boolean)) {
        // `__setitem__` is not a method anyone writes: `parser-py.js` lowers a
        // subscript assignment (`bag['k'] = v`, `arr[i] = v`) to a CALL node
        // with that flat callee rather than to an assign node with a member
        // target, so it reaches this rule instead of the assign path. The
        // matching read lowers to `bag.[]`, already covered by the tainted
        // receiver prefix.
        // Case-insensitive: C#/Java collection APIs use PascalCase (`List.Add`,
        // `Dictionary.Insert`, `Stack.Push`) while JS/Python/Ruby use lowerCamel
        // (`push`, `append`, `add`) — a case-sensitive regex silently matched
        // only the latter group, so C#'s `list.Add(data)` (Juliet flow variants
        // 71-74, container-element taint) never registered as a mutator at all.
        // Widening to case-insensitive only ADDS matches (recall-preserving);
        // no existing lowercase mutator name collides with an unrelated,
        // dangerous PascalCase method by accident (checked against the C#/Java
        // catalog sink list). `push_str`/`extend_from_slice` are Rust's
        // String/Vec appenders (`push`/`extend`/`insert` already cover the
        // other languages and apply to Rust unchanged).
        // SARD_80_F1 W2.3: `addElement` (java.util.Vector's pre-Collections-
        // Framework method, still idiomatic in older code — Juliet's own age)
        // and `offer`/`offerFirst`/`offerLast` (the Queue/Deque interface's
        // mutator, implemented by ArrayDeque/LinkedList/PriorityQueue) were
        // both missing — found via direct probes showing `Vector.addElement`/
        // `ArrayDeque.offer` silently failed to taint their receiver while
        // every sibling API (`Vector`'s modern `add`, `Stack.push`,
        // `Hashtable.put`, `Properties.setProperty`, `TreeMap.put`) already
        // worked, an inconsistency with no principled reason — all six are
        // the same "write one element into a collection" shape.
        const _MUTATORS = /^(?:push|unshift|splice|fill|copyWithin|set|add|addElement|append|extend|insert|update|addAll|putAll|put|addrange|enqueue|offer|offerFirst|offerLast|__setitem__|push_str|extend_from_slice)$/i;
        // Mutate the state Set IN PLACE (the binding is const; the call case
        // returns this same Set ref). Avoids touching the unrelated
        // mutated-param paths in this case, keeping the blast radius to
        // collection-element taint only.
        let _recv = null;
        if (node.callee && node.callee.kind === 'member' && typeof node.callee.prop === 'string'
            && _MUTATORS.test(node.callee.prop)) {
          _recv = accessPathOf(node.callee.object);
        } else if (typeof _plainCallCalleeName === 'string') {
          // SARD_80_F1 W2.3 follow-up: a REPEATED-method fluent chain
          // (`sb.append(a).append(b).append(c)`, StringBuilder/StringBuffer's
          // own idiomatic multi-line-SQL-building shape) dot-joins to
          // "StringBuilder.append.append.append" via the hand-rolled/CST
          // chain-flattening convention every frontend in this codebase
          // uses (correct for a chain ending in a DIFFERENT terminal method,
          // e.g. `DocumentBuilderFactory.newInstance().newDocumentBuilder()`
          // — wrong here, since `.append()` returning `this` means every
          // segment is really the SAME receiver, not a new one). Naively
          // taking everything before the LAST dot recovers
          // "StringBuilder.append.append" as the "receiver" — an
          // ever-growing, never-matching key that silently drops the
          // mutator's own taint tracking for every chained-append call.
          // Strip ALL trailing segments that repeat the SAME mutator method
          // name first, so `X.append.append.append` and plain `X.append`
          // resolve to the identical, real receiver "X".
          const _segs = _plainCallCalleeName.split('.');
          let _end = _segs.length - 1;
          const _lastSeg = _segs[_end];
          if (_end > 0 && _MUTATORS.test(_lastSeg)) {
            while (_end > 0 && _segs[_end] === _lastSeg) _end--;
            if (_end >= 0) _recv = _segs.slice(0, _end + 1).join('.');
          }
        }
        if (_recv) state.add(_recv);
      }
      findings.push(..._sinkFindingsForCall(node.callee, node.args, cat, argTaints, state, callContext, node.line, node.kwargs).findings);
      findings.push(..._nestedSinkFindings(node.args, state, callContext, node.line));
      // 2. P1.3 — higher-order taint flow. When the call is `arr.map(fn)` or
      //    `promise.then(fn)` and the receiver is tainted, propagate taint
      //    into the callback's first parameter. v1: we propagate AT THE
      //    CALLBACK INVOCATION LEVEL by adding the callback's first-arg
      //    name (when resolvable as a plain ident or function-value) into
      //    the taint state.
      const hoFlow = (() => {
        // Heuristic receiver-tainted check: if the callee string is
        // "<recv>.<method>", check whether <recv> is in state.
        const callee = _plainCallCalleeName;
        if (!callee) return null;
        const dot = callee.lastIndexOf('.');
        if (dot <= 0) return null;
        const recv = callee.slice(0, dot);
        const recvTainted = isCoveredBy(state, recv);
        // higherOrderTaintFlow requires a flattened STRING callee (its own
        // `typeof callee !== 'string'` guard) — passing the raw `node` here
        // handed it a JS/TS structured callee expr ({kind:'member',...})
        // unconditionally, which never passed that guard, so this feature
        // was entirely dead for JS/TS (the primary catalogued language).
        // `callee` here is `_plainCallCalleeName`, already flattened above.
        return higherOrderTaintFlow({ ...node, callee }, recvTainted);
      })();
      if (hoFlow && hoFlow.taintsCallbackParam === 0) {
        // The first arg should be the callback. If it's a plain ident or
        // function-value, the engine's per-callee summary path will pick it
        // up when the callee is independently analyzed. We don't model the
        // callback inline here; instead we record on callContext that the
        // callback was invoked with a tainted first param, so the engine's
        // call-graph pass can re-run the callback with that entry state.
        const cb = (node.args || [])[0];
        if (cb && (cb.kind === 'ident' || cb.kind === 'function-value')) {
          callContext._higherOrderInvocations = callContext._higherOrderInvocations || [];
          callContext._higherOrderInvocations.push({
            // A resolved-by-name callback (`arr.map(processItem)`) and an
            // inline callback (`arr.map(x => ...)`, parser-js.js's
            // exprOf now emits {kind:'function-value', qid}) need different
            // resolution strategies downstream — a bare name looked up via
            // the call graph's byNameInFile index (ambiguous/guessable) vs.
            // an exact qid looked up directly in callGraph.functions. Kept
            // as two fields rather than overloading `callee` with either
            // shape, so the consumer can't accidentally hand a qid to the
            // name-based resolver (or vice versa).
            callee: cb.kind === 'ident' ? cb.name : null,
            calleeQid: cb.kind === 'function-value' ? (cb.qid || null) : null,
            paramIndex: 0,
            taintedParam: true,
            line: node.line,
            via: hoFlow.kind,
          });
        }
      }
      return { state, findings };
    }

    case 'if': {
      // Path-feasibility lite: if the condition is a literal false / unreachable,
      // mark the node so the CFG walker can skip the consequent edge.
      // For now we simply propagate state to both branches — EXCEPT for a
      // recognized guard-predicate condition (SARD_80_F1 W3.2), where the
      // TRUE branch specifically gets a narrowed (un-tainted-on-the-guarded-
      // var) state via `succOverride`; the false branch and any code after
      // an if-with-no-else still see the original, unnarrowed `state`. Per
      // this codebase's established CFG convention (path-feasibility.js),
      // `succ[0]` is the THEN edge and `succ[1+]` are the ELSE/fall-through
      // edge(s).
      const narrowedVar = _guardNarrowsVar(node.cond, state) || _regexTestGuardNarrowsVar(node.cond, state);
      if (narrowedVar && node.succ && node.succ.length > 0) {
        const thenState = removePathAndDescendants(state, narrowedVar);
        return { state, findings, succOverride: new Map([[node.succ[0], thenState]]) };
      }
      return { state, findings };
    }

    case 'return': {
      // Taint-engine PRD P1: `return sink(x)` was invisible — this only ever
      // asked whether the returned value is TAINTED (for interprocedural
      // callers, below), never whether the call expression itself is a sink.
      // JS is accidentally immune (Babel emits a redundant standalone 'call'
      // node for every CallExpression, including ones nested in a return
      // argument, so case 'call' above already caught it there). Every
      // hand-rolled parser does not do that, so `return
      // File.ReadAllText(path)` — idiomatic ASP.NET Core — was structurally
      // blind. Mirrors case 'call''s sink-check exactly; deliberately does
      // NOT mirror its summary-cache/mutation/higher-order machinery, which
      // is about a callee's OWN internal findings and mutated params — an
      // unrelated concern from whether this return statement's own call
      // expression is directly a sink.
      if (node.value && node.value.kind === 'call') {
        const { cat, argTaints } = _matchCallCatalog(node.value.callee, node.value.args, state, callContext);
        findings.push(..._sinkFindingsForCall(
          node.value.callee, node.value.args, cat, argTaints, state, callContext, node.line, node.value.kwargs).findings);
        findings.push(..._nestedSinkFindings(node.value.args, state, callContext, node.line));
      }
      if (exprTaint(node.value, state, callContext)) {
        callContext._returnTainted = true;
      }
      return { state, findings };
    }

    case 'throw': {
      // Thrown values don't taint subsequent code in the same fn — exit.
      return { state, findings };
    }

    default:
      return { state, findings };
  }
}

// R14(a): annotation-derived taint is a function-invariant fact — identical
// for every call to this qid — so it is unioned into the per-call-site entry
// state, never into the SummaryCache key (that stays exactly what the caller
// supplied). Returns the ORIGINAL Set unchanged when there's nothing to add,
// so callers that never touch annotation-shaped params pay zero extra cost.
function _unionAnnotationTaint(fn, entrySet) {
  if (!fn.paramAnnotations || !fn.paramAnnotations.length) return entrySet;
  const extra = matchAnnotationParams(fn.paramAnnotations, fn.file);
  if (!extra.size) return entrySet;
  return new Set([...entrySet, ...extra]);
}

// Worklist traversal of one function's CFG with a given entry-taint-state.
// Returns the merged exit state + the union of findings on every path + the
// taint sources observed (for evidence trails).
//
// Premortem 2R4.4 / 2R-9: also honors callContext.deadlineMs by checking
// every 100 iterations. A pathological CFG (large generated file with dense
// control flow) can otherwise hold past the global timeout.
function analyzeFunction(fn, entryState, callContext) {
  const nodes = fn.cfg.nodes;
  // R2 (PRD §5): set the call-string caller context to THIS function while its
  // worklist computes callee summaries (so a callee is keyed by its caller).
  // No-op for the key unless AGENTIC_SECURITY_KCFA_CALLSTRING=1. Restored below.
  const _prevCallerCtx = (callContext && callContext._summaryCache && callContext._summaryCache.setCallerContext)
    ? callContext._summaryCache.setCallerContext(fn.qid) : undefined;
  // SARD_80_F1 W4.C21/C22 — `_currentFile` (module-level, set just below) was
  // never saved/restored around a NESTED analyzeFunction call the way
  // `_prevCallerCtx` already is on the line above. A cross-FILE call site
  // (e.g. Bad() in file A calling a summary-computed callee in file B)
  // recurses into analyzeFunction(calleeFn, ..., inner) to compute the
  // callee's summary — that inner call sets `_currentFile = calleeFn.file`
  // (file B) and, until this fix, never set it back, so every subsequent
  // catalog lookup (`matchSinkOrSanitizer`/`matchSource`/`classOfVar`) in
  // the OUTER function's own remaining CFG nodes ran against the WRONG
  // file's language scoping for the rest of that outer function's walk.
  // Confirmed via a same-file-vs-cross-file A/B reproduction of a real
  // corpus false positive (see W4.C20/C21/C22) that isolated this leak as
  // one of two compounding defects. Saving/restoring here — the exact
  // pattern `_prevCallerCtx` already uses — makes `_currentFile` correctly
  // scoped to this function's own analysis regardless of what any callee's
  // nested summary computation does to it in between.
  const _prevFile = _currentFile;
  const work = [];
  const inStates = new Map();
  const outStates = new Map();
  inStates.set(fn.cfg.entry, new Set(entryState));
  work.push(fn.cfg.entry);
  _currentFile = fn.file || null;
  // v0.70 #2 — points-to context for the step() transfer. Setting it here
  // (instead of plumbing through step's signature) keeps the worklist loop
  // unchanged and lets `step` consult `aliasesForVar` when callContext._pointsTo
  // is present.
  if (callContext) callContext._currentFnQid = fn.qid;
  const deadlineMs = (callContext && typeof callContext.deadlineMs === 'number') ? callContext.deadlineMs : Infinity;
  const visited = 0;
  let iterations = 0;
  const ITER_BUDGET = 5000;

  while (work.length) {
    if (++iterations > ITER_BUDGET) break;
    // Check the global deadline every 100 iterations — Date.now() is cheap
    // but not free; this keeps overhead negligible on small functions.
    if ((iterations & 0x7f) === 0 && Date.now() > deadlineMs) break;
    const nid = work.shift();
    const node = nodes[nid];
    if (!node) continue;
    const incoming = inStates.get(nid) || new Set();
    const { state: out, findings, succOverride } = step(node, incoming, callContext);
    // SARD_80_F1 W4.C21/C22: stamp the file THIS finding actually belongs to
    // (fn's own file) at the moment of discovery — see `_collectFindings`'s
    // header comment for why this matters. `step()`/`_sinkFindingsForCall`
    // never set `file` themselves (only `line`), so every finding reaching
    // this line was, until now, implicitly reattributed later to whichever
    // function `_collectFindings` happened to be called with — correct only
    // when that's the SAME function, which a cross-file interprocedural
    // merge (`_mergeSummaryFindings`) is specifically the case where it is
    // NOT.
    callContext._findings.push(...findings.map(f => ({ ...f, _funcQid: fn.qid, file: f.file || fn.file })));
    const prevOut = outStates.get(nid);
    const merged = mergeStates(prevOut, out);
    if (!prevOut || !stateEq(prevOut, merged)) {
      outStates.set(nid, merged);
      for (const s of (node.succ || [])) {
        // SARD_80_F1 W3.2 — guard-predicate narrowing (case 'if' above): a
        // specific successor edge (the guard's TRUE branch) can carry a
        // NARROWER state than every other edge out of this node. `out` (not
        // `merged`) is what `succOverride` was derived from, and `out` is a
        // pure function of `incoming`, so gating this on `merged`'s own
        // convergence check above is sound — an unchanged `merged` means an
        // unchanged `incoming` means an unchanged override too.
        const edgeState = (succOverride && succOverride.has(s)) ? succOverride.get(s) : merged;
        const succIn = inStates.get(s);
        const newIn = mergeStates(succIn, edgeState);
        if (!succIn || !stateEq(succIn, newIn)) {
          inStates.set(s, newIn);
          work.push(s);
        }
      }
    }
  }

  // R4 (PRD §5) — implicit / control-dependence flow. OPT-IN (default OFF, see
  // isImplicitFlowEnabled). Post-pass over the converged CFG: a sink reached
  // INSIDE a tainted-condition branch can leak information even when its
  // argument is constant or only implicitly tainted (a var assigned in that
  // branch). Findings carry implicit:true + capped confidence.
  if (isImplicitFlowEnabled() && fn.cfg) {
    try {
      const union = new Set();
      for (const s of inStates.values()) for (const p of s) union.add(p);
      const ictx = buildImplicitContext(fn.cfg, (expr) => exprTaint(expr, union, callContext));
      // Mark vars assigned inside a tainted branch as implicit-tainted.
      let implicitState = new Set();
      for (const [nid, ctx] of ictx) {
        const t = implicitAssignTarget(nodes[nid], ctx);
        if (t) implicitState = markImplicitTaint(implicitState, t);
      }
      // Stage 6 correctness audit: these are two genuinely different gates,
      // previously conflated into one loop over `ictx`. `allConst` is a
      // leak from the SINK CALL'S OWN EXECUTION revealing the branch was
      // taken — that requires the call itself to be genuinely inside the
      // tainted branch (now correctly dominance-scoped by
      // buildImplicitContext, see its header). `argRefsImplicit` is a leak
      // from a VARIABLE that was implicit-tainted earlier — once a var is
      // marked, its taint is a normal fact about the var, not about where
      // it's later read; requiring the READ site to also be lexically
      // inside a branch would miss the canonical
      // `if (tainted) { p = x; } eval(p)` pattern the moment `eval(p)` is
      // (correctly) recognized as being outside the branch.
      const reportedNids = new Set();
      const reportImplicit = (nid, node, sink, conditionLabel) => {
        if (reportedNids.has(nid)) return;
        reportedNids.add(nid);
        callContext._findings.push({
          ...createImplicitFinding(node, conditionLabel),
          _funcQid: fn.qid, sinkId: sink.id, file: fn.file,
          cwe: (sink.vuln && sink.vuln.cwe) || 'CWE-200',
        });
      };
      // Pass 1 — constant-arg sink calls genuinely inside a tainted branch.
      for (const [nid, ctx] of ictx) {
        const node = nodes[nid];
        if (!node || node.kind !== 'call') continue;
        const cat = matchSinkOrSanitizer(node.callee, _currentFile);
        const sink = cat && cat.find((e) => e.kind === 'sink');
        if (!sink) continue;
        const inS = inStates.get(nid) || new Set();
        if ((node.args || []).some((a) => exprTaint(a, inS, callContext))) continue;
        const allConst = (node.args || []).length > 0 && (node.args || []).every((a) => a && a.kind === 'literal');
        if (allConst) reportImplicit(nid, node, sink, ctx.conditionLabel);
      }
      // Pass 2 — any sink call anywhere in the function whose argument
      // reads an implicit-tainted variable, regardless of whether the
      // call site itself is inside a branch.
      if (implicitState.size) {
        for (const [nid, node] of Object.entries(nodes)) {
          if (!node || node.kind !== 'call') continue;
          const cat = matchSinkOrSanitizer(node.callee, _currentFile);
          const sink = cat && cat.find((e) => e.kind === 'sink');
          if (!sink) continue;
          const inS = inStates.get(nid) || new Set();
          if ((node.args || []).some((a) => exprTaint(a, inS, callContext))) continue;
          const argRefsImplicit = (node.args || []).some((a) => {
            const ap = accessPathOf(a); return ap && isCoveredBy(implicitState, `implicit:${ap}`);
          });
          if (argRefsImplicit) reportImplicit(nid, node, sink, ictx.get(nid)?.conditionLabel || null);
        }
      }
    } catch { /* implicit flow is best-effort + opt-in */ }
  }

  const exit = outStates.get(fn.cfg.exit) || new Set();
  // Real cross-method field taint (SARD_80_F1_SCANNER_PRD.md, Juliet flow
  // variants 45/65-68): the runTaintEngine pre-pass needs the RAW exit state
  // (every tainted access path, not just the ones matching a declared param)
  // to tell whether THIS function's own body genuinely taints a class field —
  // see the pre-pass loop below for why this must be the real exit state, not
  // a guess.
  if (callContext) callContext._exitState = exit;
  // v0.66 — record which params are tainted at function exit so the
  // caller's applyAtCallSite can propagate that mutated taint back. We
  // intersect the exit-state with the function's declared params (only
  // param vars count as "mutated by reference"; locals are caller-invisible).
  if (callContext && Array.isArray(fn.params) && fn.params.length) {
    if (!callContext._mutatedParamsOut) callContext._mutatedParamsOut = new Set();
    for (const p of fn.params) {
      if (isCoveredBy(exit, p)) callContext._mutatedParamsOut.add(p);
    }
  }
  // Next-gen taint capability #3 — treat `this` as an implicit mutable
  // parameter, mirroring the block just above exactly: extract every field
  // name this function's own exit state taints on its receiver (any of the
  // three `this` spellings this codebase's frontends use), so the caller can
  // propagate that mutation onto ITS OWN receiver variable's access path
  // (`bad.data`), not a class-wide bucket. See this file's own header
  // comment above `_thisFieldGetterName` for the full rationale.
  if (callContext) {
    if (!callContext._mutatedThisFieldsOut) callContext._mutatedThisFieldsOut = new Set();
    for (const p of exit) {
      const m = _THIS_FIELD_PREFIX_RE.exec(p);
      if (m) callContext._mutatedThisFieldsOut.add(m[1]);
    }
  }
  // R2: restore the caller context for the enclosing function's analysis.
  if (_prevCallerCtx !== undefined && callContext && callContext._summaryCache && callContext._summaryCache.setCallerContext) {
    callContext._summaryCache.setCallerContext(_prevCallerCtx);
  }
  // W4.C21/C22: restore _currentFile — see the save at this function's start.
  _currentFile = _prevFile;
  return exit;
}

function mergeStates(a, b) {
  // P1.1: use access-path-aware union that collapses longer descendants
  // under their shorter-prefix parents.
  return joinAccessSets(a, b);
}
function stateEq(a, b) {
  // P1.1: use access-path-aware set equality (canonicalized).
  return accessSetsEqual(a, b);
}

// ── Top-level entry ─────────────────────────────────────────────────────────
//
// Iterate each function with an EMPTY entry-taint-state. The function's
// internal sources will populate the state as we walk. (Future work: when the
// caller of F passes tainted args, re-analyze F with those params marked.
// The infra for it is in callContext.)
//
// Returns a flat array of findings, each enriched with file/line/etc.
export function runTaintEngine(perFileIR, callGraph, opts = {}) {
  const all = [];
  const seen = new Set();
  const fnLimit = opts.fnLimit || 5000;
  const deadlineMs = typeof opts.deadlineMs === 'number' ? opts.deadlineMs : Infinity;
  let n = 0;
  // Live progress for this engine's dominant per-function loop (below,
  // bounded by fnLimit) — the longest-running phase of a deep scan on any
  // real-sized project. Additive/opt-in: with no `opts.onProgress`, nothing
  // here runs and every existing caller is byte-identical to before this
  // existed. Only the pre-passes above (fixed-point empty-entry pre-pass,
  // class-field cross-taint pass, k=2 pass) are NOT instrumented — they run
  // before `fnList.length` is known to be the final total below, and adding
  // per-iteration reporting to all four loops was judged disproportionate
  // risk to this engine's own worklist for the UX gain; the operator sees
  // the phase-start message the caller prints before this function is ever
  // invoked, then live per-function progress once this loop begins.
  const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : null;

  // Premortem #7: instantiate the k=1 SummaryCache and seed it with each
  // function's empty-entry-state summary (returnTainted bit). The cache is
  // available to call sites through callContext so the worklist can ask
  // "does callee F return tainted under this entry state?" before
  // conservatively assuming it doesn't. This wires the cache that was
  // exported-but-unused for several releases.
  //
  // v0.69 — opts.summaryCache lets the caller (runDeepAnalysis with
  // incremental mode) hand in a pre-seeded cache from persisted state.
  const summaryCache = opts.summaryCache || new SummaryCache();

  // Deterministic ordering (Sentinel-parity §9.2): sort functions by qid so
  // cache-cold runs produce the same finding sequence run-over-run.
  const fnList = [...callGraph.functions.values()].sort((a, b) =>
    a.qid < b.qid ? -1 : a.qid > b.qid ? 1 : 0
  );
  // PRD W0.1 (SARD_80_F1_EXECUTION_PRD.md) — the main per-function loop below
  // silently `break`s once `n > fnLimit` (default 5000), which for a single
  // large SARD CWE directory (Java CWE-89 alone: 3668 files, 17604
  // functions) means roughly 70% of the corpus is never analyzed at all, no
  // matter how correct the resolution logic is for the functions it DOES
  // reach. This was completely invisible to every existing truncation
  // signal (wall-clock budget, per-file timeout/skip counts) — found while
  // investigating why a real, verified class-resolution fix (W1) showed
  // almost no aggregate SARD recall movement despite fixing individual
  // fixtures in isolation. Surfaced the same way the wall-clock budget
  // already is: a single info finding, not a return-shape change (this
  // function's return type — a flat array — is a wide, load-bearing
  // contract; changing it would touch every caller).
  if (fnList.length > fnLimit) {
    all.push({
      id: `ir-taint-fn-limit:${fnList[0] ? fnList[0].qid.split('::')[0] : ''}`,
      file: '(deep-engine)', line: 0,
      vuln: `IR-TAINT deep mode analyzed only ${fnLimit}/${fnList.length} functions (AGENTIC_SECURITY_DEEP_FN_LIMIT) — results are incomplete`,
      severity: 'info',
      parser: 'IR-TAINT',
      confidence: 0.5,
    });
  }
  // Pre-pass + fixed-point: compute empty-entry-state summaries for every
  // function, then re-run the pre-pass until the summary cache stabilizes
  // (capped at MAX_FP_ITERS so recursion and chains converge without
  // unbounded blowup). v0.66 — the inner ctx now records mutatedParams
  // via _mutatedParamsOut so cross-function param mutation propagates.
  const MAX_FP_ITERS = 3;
  // qid -> this function's own exit-state (every tainted access path at
  // return, from the LAST pre-pass iteration only — see the class-field
  // cross-taint pass below for why this must be a real, already-observed
  // exit state rather than a re-derived guess).
  const exitStateByQid = new Map();
  for (let it = 0; it < MAX_FP_ITERS; it++) {
    if (Date.now() > deadlineMs) break;
    // Tracks whether this iteration actually changed any cached summary's
    // VALUE — the correct convergence signal (see below). Reset each
    // iteration; if nothing changed, the fixed point has been reached and
    // further iterations would recompute byte-identical results.
    let changedThisIter = false;
    for (const fn of fnList) {
      if (Date.now() > deadlineMs) break;
      const entry = new Set();
      const key = fn.qid + '::empty';
      const existing = summaryCache.get(fn.qid, entry);
      // On re-iterations, recompute even if cached so refined summaries
      // (from now-known callee summaries) can lift returnTainted/mutated.
      const ctx = {
        _findings: [], _taintSources: [], _returnTainted: false,
        _stack: new Set(), deadlineMs,
        _summaryCache: summaryCache, _callGraph: callGraph,
        _mutatedParamsOut: new Set(),
        _currentFnQid: fn.qid,
        _cha: opts._cha,
        _pointsTo: opts._pointsTo,
      };
      try { analyzeFunction(fn, _unionAnnotationTaint(fn, entry), ctx); } catch {}
      // Report real findings discovered by this probe rather than letting
      // them die with `ctx` — see _collectFindings's header comment. Safe to
      // call every iteration and again from the main loop below: dedup is by
      // (sinkId, file, line), so re-discovering the same empty-entry finding
      // multiple times collapses to one reported finding, never a duplicate.
      _collectFindings(fn, ctx._findings);
      exitStateByQid.set(fn.qid, ctx._exitState || new Set());
      const next = {
        returnTainted: !!ctx._returnTainted,
        mutatedParams: ctx._mutatedParamsOut || new Set(),
        mutatedThisFields: ctx._mutatedThisFieldsOut || new Set(),
        taintedGlobals: new Set(),
        findings: [],
      };
      // Membership-aware, not size-only — two summaries with the same
      // mutatedParams CARDINALITY but different MEMBERS (e.g. {'a'} vs
      // {'b'}) were treated as unchanged, so a real refinement across
      // iterations (a callee's mutated-field identity settling once its own
      // callees' summaries became known) was silently never written to the
      // cache. Same bug class as summaries.js's _summaryEq, fixed alongside
      // it. Reuses the same access-path-aware setsEqual already imported
      // for taint-state comparison elsewhere in this file (mutatedParams
      // entries are access paths too, e.g. '_this_.field').
      if (!existing
          || existing.returnTainted !== next.returnTainted
          || !accessSetsEqual(existing.mutatedParams, next.mutatedParams)) {
        summaryCache.set(fn.qid, entry, next);
        changedThisIter = true;
      }
    }
    // NOT `summaryCache.size() === prevCacheSize` (the pre-fix check): every
    // function gets a cache key on iteration 0 (`!existing` is true for all
    // of them), so `.size()` — a KEY COUNT — jumps from 0 to N once and then
    // never changes again, since overwriting an existing Map key never
    // changes `.size`. That made the loop `break` after iteration 1
    // regardless of whether iteration 1 itself found real refinements to
    // write, silently delivering 2 rounds of fixed-point refinement instead
    // of the MAX_FP_ITERS=3 this code and dataflow/CLAUDE.md both promise.
    // `changedThisIter` tracks actual value changes instead.
    if (!changedThisIter) break;
  }
  // Class-field cross-taint pass (SARD_80_F1_SCANNER_PRD.md — Juliet flow
  // variants 45/65-68: a method writes a tainted value to a static or
  // instance field and a SIBLING method of the same class reads it into a
  // sink). The mechanism this replaced kept only the JS/Babel `_this_.field`
  // mutated-PARAM shape — but `_mutatedParamsOut` (above) only ever
  // intersects a function's own EXIT state against its declared PARAMS, and
  // a field is never a param, so that map was permanently empty for every
  // hand-rolled parser (C#, Java, PHP, Go, Ruby, Kotlin) — confirmed by
  // direct probing, not assumed: none of `sf = data;`, `this.inst = data;`
  // ever populated it, for any language.
  //
  // Real fix: `callContext._exitState` (stamped just above) is EVERY tainted
  // access path at a function's exit, not just the ones matching a param
  // name. Cross-reference it against the class's DECLARED FIELD NAMES (from
  // `ir.classes[].fields`, via `buildClassHierarchy` — only populated by a
  // parser that emits it; classes with no field list simply contribute
  // nothing here, which is a missed opportunity, never a wrong edge) to ask
  // "did this method's own body, taken alone, genuinely taint one of its
  // class's fields?" — a REAL, observed fact from the empty-entry pre-pass
  // above, not a guess. Both the bare form (`sf`) and the `this.`-qualified
  // form (`this.inst`, `_this_.inst`) are checked, since different parsers
  // lower a field write differently.
  const cha = opts._cha;
  const classTaintedFields = new Map(); // className -> Set(bareFieldName)
  // SARD_80_F1 W5.48 — per-WRITER record alongside the per-class union just
  // above: className -> field -> Set(qid of a method whose OWN exit state
  // taints this field). `classTaintedFields` only ever answers "is this
  // field EVER tainted somewhere in the class" (unioned across every
  // method), which is what made the cross-class pass below seed a reader
  // like `goodG2BSink()` as tainted even though its own real caller chain
  // (`goodG2B()`) only ever writes this field a LITERAL — Juliet's Flow
  // Variant 65-68 idiom (`_68a`/`_68b`) has bad()/goodG2B()/goodB2G() each
  // write the SAME static field then immediately call their OWN uniquely-
  // named sink (badSink/goodG2BSink/goodB2GSink), so "ever tainted
  // anywhere in the class" is true (via bad()) but says nothing about
  // which SPECIFIC caller reaches a SPECIFIC reader. This map lets the
  // cross-class pass ask the narrower, call-string-sensitive question
  // instead: "is EVERY discoverable direct caller of this reader a
  // confirmed NON-tainting writer of this field" — see its own use site.
  const fieldWriterQids = new Map();
  if (cha && cha.methodOwners && cha.classes) {
    for (const fn of fnList) {
      if (Date.now() > deadlineMs) break;
      const className = cha.methodOwners.get(fn.qid);
      if (!className) continue;
      const cls = cha.classes.get(className);
      const declaredFields = cls && cls.fields;
      if (!declaredFields || !declaredFields.size) continue;
      const exitState = exitStateByQid.get(fn.qid);
      if (!exitState || !exitState.size) continue;
      for (const field of declaredFields) {
        // SARD_80_F1 W5.10 — PHP's own `$this` reference keeps its `$`
        // sigil in every access path (`$this.field`, never bare `this.` —
        // parser-php.js's own `->`-to-`.` normalization, W5.9), a fourth
        // spelling alongside JS's `_this_.`/C#'s and Java's bare `this.`.
        //
        // SARD_80_F1 W5.17 — `isCoveredBy` deliberately never propagates UP
        // (its own doc: `set={"x.y.z"}` does NOT cover "x.y"), which is
        // correct for ordinary field reads but wrong here: an ARRAY-INDEXED
        // field write (`$this->input[1] = $_GET[...]`) taints the access
        // path `this.input.1`, not the bare `this.input`/`input` this loop
        // queries — so a getter method returning `$this->input[1]` (the
        // PHP-Vuln-test-suite-generator's own "object/Array" input-
        // indirection sample, confirmed via direct reproduction, not corpus
        // access) was invisible to this whole class-field pass, while the
        // scalar-field form one line below (`$this->input = $_GET[...]`)
        // already worked. `pathIsCoveredByPrefix(entry, field)` checks the
        // OPPOSITE direction — does `entry` sit AT OR BELOW `field` — which
        // is exactly "did the constructor taint SOME sub-path of this
        // field", independent of which specific index or nesting depth.
        const hasTaintedSubpath = (prefix) => { for (const p of exitState) { if (pathIsCoveredByPrefix(p, prefix)) return true; } return false; };
        if (isCoveredBy(exitState, field) || isCoveredBy(exitState, `this.${field}`) || isCoveredBy(exitState, `_this_.${field}`) || isCoveredBy(exitState, `$this.${field}`)
            || hasTaintedSubpath(field) || hasTaintedSubpath(`this.${field}`) || hasTaintedSubpath(`_this_.${field}`) || hasTaintedSubpath(`$this.${field}`)) {
          if (!classTaintedFields.has(className)) classTaintedFields.set(className, new Set());
          classTaintedFields.get(className).add(field);
          if (!fieldWriterQids.has(className)) fieldWriterQids.set(className, new Map());
          const fw = fieldWriterQids.get(className);
          if (!fw.has(field)) fw.set(field, new Set());
          fw.get(field).add(fn.qid);
        }
      }
    }
  }
  // SARD_80_F1 W5.50 — same reverse-call-graph lookup the cross-class pass
  // below uses (`callGraph.callersOf`, already built once by `buildCallGraph`
  // — see that pass's own header comment for why this reads the existing
  // index rather than re-deriving one), hoisted up so the SAME-class pass
  // immediately below can ALSO apply call-string precision. This pass had
  // the IDENTICAL over-approximation `classTaintedFields`'s own header
  // comment describes for the cross-class case — a sibling method reached
  // ONLY via a confirmed non-tainting writer was still blanket-seeded as
  // tainted, just scoped to siblings of the SAME class instead of a
  // different one. Genuinely a rarer shape here (per this pass's OWN
  // original comment, most sibling methods have no discoverable caller/
  // callee edge to each other at all — that remains true and still fails
  // closed correctly), but real whenever a sibling reader is directly
  // called from a KNOWN writer method (mirrors the cross-class idiom, just
  // without the class boundary).
  const _callerQidSetCache = new Map(); // fn.qid -> Set(callerQid)|null, memoized
  const callersOfQid = (qid) => {
    if (_callerQidSetCache.has(qid)) return _callerQidSetCache.get(qid);
    const edges = callGraph && callGraph.callersOf && callGraph.callersOf.get(qid);
    const set = edges && edges.length ? new Set(edges.map((e) => e.caller).filter(Boolean)) : null;
    _callerQidSetCache.set(qid, set);
    return set;
  };
  for (const [className, fields] of classTaintedFields) {
    if (Date.now() > deadlineMs) break;
    for (const fn of fnList) {
      if (cha.methodOwners.get(fn.qid) !== className) continue;

      // Call-string precision (mirrors the cross-class pass below): narrow
      // `fields` to only the ones fn's own discoverable callers can
      // actually supply as tainted. Fails closed (keeps the field seeded)
      // whenever fn has no discoverable caller, a caller outside this
      // class, or any caller not positively confirmed as a non-tainting
      // writer — this can ONLY ever narrow what was already being seeded,
      // never widen it, so it cannot introduce a new false negative beyond
      // what the pre-existing blanket behavior already accepted.
      const callers = callersOfQid(fn.qid);
      let seedFields = fields;
      if (callers && callers.size) {
        const effectiveFields = new Set();
        for (const f of fields) {
          const writers = fieldWriterQids.get(className) && fieldWriterQids.get(className).get(f);
          let keep = false;
          for (const callerQid of callers) {
            if (writers && writers.has(callerQid)) { keep = true; break; }
            if (cha.methodOwners.get(callerQid) !== className) { keep = true; break; }
          }
          if (keep) effectiveFields.add(f);
        }
        seedFields = effectiveFields;
      }
      if (!seedFields.size) continue; // every discoverable caller of fn provably never taints any of these fields

      if (summaryCache.has(fn.qid, seedFields)) continue;
      const ctx = {
        _findings: [], _taintSources: [], _returnTainted: false,
        _stack: new Set(), deadlineMs,
        _summaryCache: summaryCache, _callGraph: callGraph,
        _mutatedParamsOut: new Set(),
        _currentFnQid: fn.qid,
        _cha: opts._cha,
        _pointsTo: opts._pointsTo,
      };
      // Seed every spelling of every tainted field so a reading method sees
      // the taint regardless of which form it uses to reference the field
      // — mirrors the write-side check above, `$this.` (PHP, W5.10) included.
      const seeded = new Set();
      for (const f of seedFields) { seeded.add(f); seeded.add(`this.${f}`); seeded.add(`_this_.${f}`); seeded.add(`$this.${f}`); }
      try { analyzeFunction(fn, _unionAnnotationTaint(fn, seeded), ctx); } catch {}
      // Unlike the k=2 pass below, this is NOT speculative: `seedFields` was
      // derived from a REAL, already-observed write elsewhere in this exact
      // class (the loop above), so a sink this re-analysis finds is a real,
      // reachable flow — report it directly instead of waiting for a call
      // site that will never come (most sibling methods still have no
      // caller/callee relationship for the taint engine to discover; the
      // call-string narrowing just above only ever removes fields when one
      // WAS discoverable).
      _collectFindings(fn, ctx._findings);
      // `findings` still rides on the cached summary too, for the (rarer)
      // case where a real caller ALSO consults this exact qid+entry pair via
      // _mergeSummaryFindings — dedup in _collectFindings makes this safe.
      const fieldSummary = {
        returnTainted: !!ctx._returnTainted,
        mutatedParams: ctx._mutatedParamsOut || new Set(),
        mutatedThisFields: ctx._mutatedThisFieldsOut || new Set(),
        taintedGlobals: new Set(),
        findings: ctx._findings,
      };
      summaryCache.set(fn.qid, seedFields, fieldSummary);
      // SARD_80_F1 W3.x — the getter+return interprocedural-composition gap
      // documented at PHP W5.10: an EXTERNAL, no-argument caller of this
      // method (`$tainted = $obj->getInput();`) never consults the
      // `fields`-keyed entry above — it looks up the ORDINARY empty-context
      // summary (`summaryCache.get(fn.qid, new Set())`), which the earlier
      // fixed-point pre-pass computed WITHOUT knowing the field was tainted
      // (that fact is only established by the class-scan just above, which
      // runs once, after the pre-pass). `entryContext = new Set()` means
      // "no CALLER-supplied parameter is tainted" — true here regardless of
      // how many params `fn` declares, since this re-analysis seeded ONLY
      // the class's own already-tainted fields, no parameters — so this
      // result is exactly the correct value for that key, not a guess.
      // Safe to overwrite unconditionally: this model has no un-taint step,
      // so a field-seeded re-analysis can only find a superset of whatever
      // the plain empty-context pre-pass already found. The final per-
      // function reporting pass (the `for (const fn of fnList)` loop that
      // does the REAL, non-speculative analysis of every function,
      // including whatever caller invokes this getter) runs strictly AFTER
      // this whole class-field block, so it is guaranteed to see the
      // corrected summary — no fixed-point re-iteration needed for THIS
      // specific external-caller shape.
      summaryCache.set(fn.qid, new Set(), fieldSummary);
    }
  }

  // Cross-class static-field taint (SARD_80_F1_EXECUTION_PRD.md — Juliet flow
  // variant 68: a driver class writes a tainted value to its OWN static
  // field, then a COMPLETELY DIFFERENT class reads it back via a qualified
  // reference — `String data = OtherClass.field;` — with no parameter
  // passed at all. The same-class pass just above is deliberately scoped to
  // "a sibling method of the SAME class" (see its own header comment); this
  // is the same mechanism widened one hop further, to any function anywhere
  // that references `<taintedClassName>.<taintedField>` by name.
  //
  // Bounded by a cheap TEXT pre-filter rather than re-analyzing every
  // function in the project for every tainted class: only a function whose
  // OWN source text contains the literal `<ClassName>.` substring is a
  // candidate at all (Juliet's own per-test-case files reference at most a
  // couple of sibling classes each, so this stays cheap even across a
  // 17000+ function corpus). `opts.fileContents` is the same map already
  // threaded through for incremental-cache hashing; falls back to
  // no-op when absent (in-process callers that don't pass it), same
  // graceful-degradation convention as this file's other opt-in passes.
  const fileContents = opts.fileContents;
  if (cha && fileContents && classTaintedFields.size) {
    // `callersOfQid` (SARD_80_F1 W5.48) is hoisted above the same-class pass
    // now that pass ALSO consults it (W5.50) — reused here rather than
    // re-derived, same memoized map, zero extra cost.
    for (const [className, fields] of classTaintedFields) {
      if (Date.now() > deadlineMs) break;
      const needle = `${className}.`;
      for (const fn of fnList) {
        if (Date.now() > deadlineMs) break;
        if (cha.methodOwners.get(fn.qid) === className) continue; // already covered above
        const src = fileContents[fn.file];
        if (typeof src !== 'string' || !src.includes(needle)) continue;

        // Call-string precision: narrow `fields` to only the ones fn should
        // actually be seeded with. A field drops out only when EVERY direct
        // caller of fn is a same-class method we POSITIVELY confirmed does
        // NOT taint that field (absent from `fieldWriterQids`) — never when
        // a caller is unresolved, ambiguous, or outside this class, since
        // those cases carry no evidence either way. This is deliberately a
        // narrow, local instance of call-string sensitivity (Juliet's own
        // "write-then-immediately-call-a-uniquely-named-sink" idiom, one
        // direct hop) rather than a general k>1 CFA — see this file's own
        // CLAUDE.md "Scope — what we still do NOT model" for why the general
        // form is out of scope. Fails closed (keeps the field seeded) the
        // instant precision can't be established, same direction every
        // other heuristic in this pass already takes.
        const callers = callersOfQid(fn.qid);
        const effectiveFields = new Set();
        for (const f of fields) {
          if (!callers || !callers.size) { effectiveFields.add(f); continue; }
          const writers = fieldWriterQids.get(className) && fieldWriterQids.get(className).get(f);
          let keep = false;
          for (const callerQid of callers) {
            if (writers && writers.has(callerQid)) { keep = true; break; }
            if (cha.methodOwners.get(callerQid) !== className) { keep = true; break; }
          }
          if (keep) effectiveFields.add(f);
        }
        if (!effectiveFields.size) continue; // every caller of fn provably never taints any of these fields

        const qualifiedSeeds = new Set();
        for (const f of effectiveFields) qualifiedSeeds.add(`${className}.${f}`);
        if (summaryCache.has(fn.qid, qualifiedSeeds)) continue;
        const ctx = {
          _findings: [], _taintSources: [], _returnTainted: false,
          _stack: new Set(), deadlineMs,
          _summaryCache: summaryCache, _callGraph: callGraph,
          _mutatedParamsOut: new Set(),
          _currentFnQid: fn.qid,
          _cha: opts._cha,
          _pointsTo: opts._pointsTo,
        };
        try { analyzeFunction(fn, _unionAnnotationTaint(fn, qualifiedSeeds), ctx); } catch {}
        _collectFindings(fn, ctx._findings);
        summaryCache.set(fn.qid, qualifiedSeeds, {
          returnTainted: !!ctx._returnTainted,
          mutatedParams: ctx._mutatedParamsOut || new Set(),
          mutatedThisFields: ctx._mutatedThisFieldsOut || new Set(),
          taintedGlobals: new Set(),
          findings: ctx._findings,
        });
      }
    }
  }

  // k=2 pass: compute tainted-entry-state summaries for functions with params
  // AND at least one caller in the call graph. This catches "safe when called
  // clean, dangerous when called with tainted input" wrapper patterns.
  for (const fn of fnList) {
    if (Date.now() > deadlineMs) break;
    if (!fn.params || !fn.params.length) continue;
    const taintedEntry = new Set(fn.params);
    if (summaryCache.has(fn.qid, taintedEntry)) continue;
    const ctx = {
      _findings: [], _taintSources: [], _returnTainted: false,
      _stack: new Set(), deadlineMs,
      _summaryCache: summaryCache, _callGraph: callGraph,
      _mutatedParamsOut: new Set(),
      _currentFnQid: fn.qid,
      _cha: opts._cha,
      _pointsTo: opts._pointsTo,
    };
    try { analyzeFunction(fn, _unionAnnotationTaint(fn, taintedEntry), ctx); } catch {}
    // `findings` carries the real findings from this probe (was hardcoded
    // `[]`). This pass assumes EVERY param is simultaneously tainted —
    // there's no check that any real caller ever passes tainted data here
    // at all (the header comment above claims "AND at least one caller in
    // the call graph"; the code has never actually enforced that) — so
    // these findings must not be reported unconditionally, only when a real
    // call site's own entry state happens to match and consults this cached
    // summary via _mergeSummaryFindings. This is the exact scenario that
    // motivated storing them at all: an inline callback
    // (`arr.forEach(x => sink(x))`) has one param, so it gets probed here
    // with taintedEntry={param} BEFORE the higher-order invocation loop
    // below ever runs; without `findings` riding on the cached summary, the
    // real finding computed right here was thrown away and unrecoverable —
    // the higher-order loop's own `summaryCache.get()` would hit this
    // now-cached (finding-less) summary and never call `compute()` (the
    // only place that used to merge findings) at all.
    summaryCache.set(fn.qid, taintedEntry, {
      returnTainted: !!ctx._returnTainted,
      mutatedParams: ctx._mutatedParamsOut || new Set(),
      mutatedThisFields: ctx._mutatedThisFieldsOut || new Set(),
      taintedGlobals: new Set(),
      findings: ctx._findings,
    });
  }
  const _progressTotal = Math.min(fnList.length, fnLimit);
  for (const fn of fnList) {
    if (++n > fnLimit) break;
    if (Date.now() > deadlineMs) break;  // global timeout
    if (onProgress) onProgress({ current: n, total: _progressTotal });
    // Module-level functions: analyze with an empty entry state. The function
    // discovers its own sources from req.body/process.env/etc. as it walks.
    const callContext = {
      _findings: [],
      _taintSources: [],
      _returnTainted: false,
      _stack: new Set(),
      deadlineMs,   // honored by the worklist inside analyzeFunction
      _summaryCache: summaryCache,
      _callGraph: callGraph,
      _currentFnQid: fn.qid,
      // PRD R12: index.js builds this graph (AGENTIC_SECURITY_POINTS_TO=1)
      // and passes it in opts._pointsTo, but nothing previously copied it
      // onto callContext — _addPathAliasAware reads callContext._pointsTo,
      // which was therefore always undefined, and alias-aware tainting was
      // a no-op even with the flag set.
      _pointsTo: opts._pointsTo,
      // PRD R6/R11: same pattern as _pointsTo above — the CHA opts.js builds
      // must reach callContext or every receiver-type/member-call consumer
      // is permanently a no-op.
      _cha: opts._cha,
    };
    try {
      analyzeFunction(fn, _unionAnnotationTaint(fn, new Set()), callContext);
    } catch { continue; }
    // Process higher-order invocations: resolve callbacks and analyze with
    // tainted first-param. Feed findings back into the caller's finding set.
    const hoInvocations = callContext._higherOrderInvocations || [];
    const HO_CAP = 50;
    for (let hi = 0; hi < Math.min(hoInvocations.length, HO_CAP); hi++) {
      if (Date.now() > deadlineMs) break;
      const inv = hoInvocations[hi];
      if ((!inv.callee && !inv.calleeQid) || !inv.taintedParam) continue;
      // Two resolution strategies, matching the two shapes the push site can
      // record: an inline callback (`arr.map(x => ...)`) carries an exact
      // qid (parser-js.js's exprOf synthesizes it identically to how
      // enterFn will independently name the same node) — look it up directly
      // in callGraph.functions, no name resolution involved. A by-reference
      // callback (`arr.map(processItem)`) carries a bare ident name; resolve
      // it the same way every other call-graph lookup in this file does.
      // resolveKnownCallee (never the bare-tail-guessing resolve()) since a
      // wrong guess here would fabricate a callback relationship that
      // doesn't exist.
      const cbFn = inv.calleeQid
        ? functionRecord(callGraph, inv.calleeQid)
        : functionRecord(callGraph, callGraph.resolveKnownCallee ? callGraph.resolveKnownCallee(inv.callee, fn && fn.file) : null);
      if (!cbFn || !cbFn.params || !cbFn.params.length) continue;
      const cbEntry = new Set([cbFn.params[inv.paramIndex || 0]]);
      let cbSummary = summaryCache.get(cbFn.qid, cbEntry);
      if (!cbSummary) {
        cbSummary = summaryCache.compute(cbFn.qid, cbEntry, () => {
          const inner = {
            _findings: [], _taintSources: [], _returnTainted: false,
            _stack: new Set(), deadlineMs,
            _summaryCache: summaryCache, _callGraph: callGraph,
            _mutatedParamsOut: new Set(),
            _cha: callContext._cha,
          };
          try { analyzeFunction(cbFn, _unionAnnotationTaint(cbFn, cbEntry), inner); } catch {}
          return {
            returnTainted: !!inner._returnTainted,
            mutatedParams: inner._mutatedParamsOut || new Set(),
            mutatedThisFields: inner._mutatedThisFieldsOut || new Set(),
            taintedGlobals: new Set(),
            findings: inner._findings,
          };
        });
      }
      // Uniform with the assign/plain-call sites: merge whether this was a
      // fresh compute() (findings from `inner` just above) or a cache HIT —
      // e.g. the k=2 pass already probed this exact qid+entry (a callback
      // with one param has taintedEntry===cbEntry) and stashed its own real
      // findings on the summary rather than reporting them speculatively.
      _mergeSummaryFindings(callContext, fn.qid, cbSummary, 'higher-order');
    }
    _collectFindings(fn, callContext._findings);
  }
  // v0.69 — expose cache to caller (runDeepAnalysis) for incremental persistence.
  // Dead code suppression: demote findings in functions with zero callers
  // (except route handlers which are entry points)
  const calledQids = new Set();
  if (callGraph.edges) for (const e of callGraph.edges) if (e.callee) calledQids.add(typeof e.callee === 'string' ? e.callee : e.callee?.qid);
  if (callGraph.callersOf) for (const [qid, callers] of callGraph.callersOf) { if (Array.isArray(callers) ? callers.length : callers?.size) calledQids.add(qid); }
  for (const f of all) {
    if (!f._funcQid) continue;
    const fn = callGraph.functions?.get(f._funcQid);
    if (!fn) continue;
    if (calledQids.has(f._funcQid)) continue;
    if (fn.name === '<module>' || /handler|route|controller|middleware|endpoint/i.test(fn.name || '')) continue;
    f._inDeadCode = true;
    const dg = { critical: 'high', high: 'medium', medium: 'low', low: 'info' };
    if (dg[f.severity]) f.severity = dg[f.severity];
  }
  Object.defineProperty(all, '_summaryCache', { value: summaryCache, enumerable: false });
  return all;

  // Dedup + map a raw findings array (from analyzeFunction's callContext)
  // into the reported IR-TAINT shape, attributed to `fn`. Used directly by
  // the main loop and the empty-entry pre-pass (both analyze under an entry
  // state that is either empty or true-by-construction, so their findings
  // are unconditionally real). The class-field and k=2 pre-passes are
  // speculative (they assume fields/params are tainted without confirming
  // any real caller ever does that) — see _mergeSummaryFindings, which is
  // the gate that gives their findings a chance to be reported only once a
  // genuine caller is established.
  function _collectFindings(attributedFn, srcFindings) {
    for (const f of srcFindings) {
      // SARD_80_F1 W4.C21/C22 — prefer the finding's OWN `file` (now stamped
      // at discovery time inside analyzeFunction, using the function that
      // ACTUALLY produced it) over `attributedFn.file`. `attributedFn` here
      // is whichever function the CALLER of `_collectFindings` happens to
      // be processing — correct for a finding discovered directly in that
      // function's own CFG walk, but WRONG for one merged in from a
      // callee's summary via `_mergeSummaryFindings` (most commonly a
      // cross-file interprocedural call): that finding genuinely belongs to
      // the callee's own file/line, which `f.file` now carries correctly.
      // The `attributedFn.file` fallback stays for defense-in-depth only —
      // every path pushing into `_findings` sets `file` explicitly as of
      // this fix.
      const file = f.file || attributedFn.file;
      const key = `${f.sinkId}:${file}:${f.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const fn = attributedFn;
      all.push({
        id: `ir-taint:${file}:${f.line}:${f.sinkId}`,
        file,
        line: f.line,
        vuln: f.vuln,
        severity: f.severity,
        cwe: f.cwe,
        remediation: f.remediation,
        parser: 'IR-TAINT',
        // R4 implicit-flow: preserve the implicit flag + its capped confidence
        // (a control-dependence finding, not an explicit data-flow one).
        confidence: (f.implicit && typeof f.confidence === 'number') ? f.confidence : 0.75,
        ...(f.implicit === true ? { implicit: true } : {}),
        // Sanitizer callees observed on the value reaching this sink. This
        // mapping is an explicit allowlist, so a field absent here is silently
        // dropped — which is what previously left sanitizer-gate.js inert.
        ...(Array.isArray(f._sanitizersOnPath) && f._sanitizersOnPath.length
          ? { _sanitizersOnPath: f._sanitizersOnPath } : {}),
        // The reversal half, and it hit the very trap this comment warns about:
        // the walk collected `he.decode` correctly, the gate was wired to
        // consume it, and the field was dropped HERE — so the fix looked inert
        // through three rounds of debugging. An explicit allowlist is the right
        // design and this is its standing cost: every new field must be added
        // in two places, and the omission is silent.
        ...(Array.isArray(f._unsanitizersOnPath) && f._unsanitizersOnPath.length
          ? { _unsanitizersOnPath: f._unsanitizersOnPath } : {}),
        // _funcQid: the enclosing function's qid, set upstream during the walk
        // but silently dropped by this allowlist before backward.js's
        // annotateBackwardSlices ever saw it — the same class of omission
        // _sanitizersOnPath had. Without it, annotateBackwardSlices's very
        // first check (`if (!f._funcQid) skip`) discarded every finding, so
        // backward-slice annotation was permanently a no-op regardless of
        // AGENTIC_SECURITY_BACKWARD_SLICE.
        ...(f._funcQid ? { _funcQid: f._funcQid } : {}),
        // argIndex: which sink argument is the tainted one (a number, or the
        // literal 'all'/'rhs') — set upstream at the finding's creation site
        // but, exactly like `_funcQid`/`callee` above, silently dropped by
        // this same allowlist before backward.js's `annotateBackwardSlices`
        // ever saw it. Without it, `annotateBackwardSlices` falls back to
        // the placeholder string `arg[undefined]` for EVERY finding (it can
        // never be a real access path, since no source ever names a
        // variable that literally), so `sliceBackward` always started and
        // ended at the bare sink node with no source/sanitize steps at all
        // — the backward-slice pass was a structural no-op for real findings
        // regardless of AGENTIC_SECURITY_BACKWARD_SLICE, discovered while
        // rebuilding the SMT path-feasibility mechanism (next-gen taint
        // capability #5) to depend on a REAL slice for a sound proof.
        ...(f.argIndex !== undefined ? { argIndex: f.argIndex } : {}),
        // callee: kept as plain `callee` (not underscore-prefixed) to match
        // backward.js's own contract, which reads `f.callee` on both real and
        // fake-fixture findings throughout its module and test suite. It is
        // the SAME object reference as the CFG call node's own `callee` (set
        // at `_sinkFindingsForCall`'s call site as `callee: calleeExpr`,
        // never copied) — backward.js's sink-node lookup matches
        // `n.callee === f.callee` by reference identity, so dropping this
        // field (as the allowlist previously did) meant that match could
        // never succeed regardless of `_funcQid`. It is not read by
        // report/index.js's normalizeFindings, which is itself an explicit
        // allowlist that never names `callee`, so this does not reach SARIF/
        // JSON/HTML report output.
        ...(f.callee !== undefined ? { callee: f.callee } : {}),
        // sourceProvenance/chain[].provenance: catalog.js's per-source label
        // (e.g. 'http-body' for req.body) computed earlier at the finding's
        // creation site — previously dropped by this allowlist, which is
        // what left posture/exploitability-probability.js's
        // 'source-from-network' factor permanently dead (it reads
        // t.provenance off chain/trace entries).
        sourceProvenance: f.sourceProvenance || null,
        source: f.trace && f.trace.length ? {
          file: fn.file,
          line: f.trace[0].line,
          label: f.trace[0].sourceLabel,
        } : null,
        sink: {
          file: fn.file,
          line: f.line,
          label: f.sinkId,
        },
        chain: (f.trace || []).map(t => ({
          file: fn.file, line: t.line, label: t.sourceLabel, provenance: t.provenance || null,
        })),
      });
    }
  }

}
