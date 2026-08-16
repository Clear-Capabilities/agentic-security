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
import { accessPathOf, isCoveredBy, addPath, removePathAndDescendants, joinSets as joinAccessSets, setsEqual as accessSetsEqual } from './access-paths.js';
import { aliasesForVar } from './points-to.js';
import { higherOrderTaintFlow } from './higher-order.js';
import { SummaryCache, entryStateFromCall } from './summaries.js';
import { lookupBuiltinSummary } from './builtin-summaries.js';
import { isImplicitFlowEnabled, buildImplicitContext, implicitAssignTarget, markImplicitTaint, createImplicitFinding } from './implicit-flow.js';
// NOTE: receiver-context.js's receiverTypeAtCall is deliberately NOT imported
// here. It was the implementation of _receiverTypeFor's old `this.field`
// branch, whose PascalCase-of-field-name guess is the false-negative bug this
// file's _receiverTypeFor comment describes. Its other exports are still used
// (summaries.js imports hashReceiverType for cache keying); only this call
// site is gone.
import { resolveMethod, classOfVar } from '../ir/class-hierarchy.js';

// v0.70 #2 — addPath that also taints every alias of the variable.
// When `target` is a dotted path like "a.x" and the root `a` has aliases
// {a, obj}, we taint both `a.x` and `obj.x`. The points-to graph is read
// from callContext._pointsTo (built by runDeepAnalysis when
// AGENTIC_SECURITY_POINTS_TO=1).
function _addPathAliasAware(state, path, callContext) {
  let s = addPath(state, path);
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

let _activeConstantVars = null;
// The file of the function currently being analyzed. Set at the top of
// analyzeFunction (same context-threading pattern as _activeConstantVars
// above) so exprIsSource/exprTaint/step can pass it to matchSource /
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
  if (!calleeExpr || calleeExpr.kind !== 'member' || typeof calleeExpr.prop !== 'string') return null;
  if (!callContext || !callContext._cha) return null;
  if (!calleeExpr.object || calleeExpr.object.kind !== 'ident' || calleeExpr.object.name === '_this_') return null;
  const className = classOfVar(callContext._cha, _currentFile, callContext._currentFnQid, calleeExpr.object.name);
  if (!className) return null;
  const found = resolveMethod(callContext._cha, className, calleeExpr.prop);
  if (!found) return null;
  return `${found.className}.${found.methodName}`;
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
  let _resolvableName = _resolvableCalleeName(calleeExpr);
  // PRD R11: _resolvableCalleeName refuses every member-expression callee.
  // When that's the reason we have nothing, try the CHA-gated path before
  // giving up — but ONLY then, so the existing exact/bare-name behavior is
  // completely unchanged for every case it already handled.
  if (!_resolvableName) _resolvableName = _resolveMemberCalleeViaCHA(calleeExpr, callContext);
  if (!_resolvableName) return null;
  const resolved = callContext._callGraph.resolveKnownCallee(_resolvableName, _callerFile);
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
        taintedGlobals: new Set(),
        findings: inner._findings,
      };
    });
  }
  _mergeSummaryFindings(callContext, callContext._currentFnQid, sum, 'interproc');
  return !!(sum && sum.returnTainted);
}

function exprTaint(expr, state, callContext) {
  if (expr && (expr.kind === 'member' || expr.kind === 'call') && exprIsSource(expr)) return true;
  if (!expr) return false;
  // Constant propagation: variables assigned from literals are never tainted
  if (expr.kind === 'ident' && _activeConstantVars && _activeConstantVars.has(expr.name)) return false;
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
      const argsTainted = (expr.args || []).some(a => exprTaint(a, state, callContext));
      const nestedTainted = _nestedCallReturnTainted(expr.callee, expr.args, state, callContext);
      return argsTainted || nestedTainted;
    }
    case 'unknown':           return false;
    default:                  return false;
  }
}

// Premortem #10: which recorded sources actually reach this expression?
// Collects the variable / access-path roots referenced by `expr` and returns
// the _taintSources entries whose varName matches one of those roots. This
// replaces "first source we ever saw" with "sources tied to this argument."
function _collectExprVars(expr, out) {
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
function exprIsSource(expr) {
  if (!expr) return null;
  if (expr.kind === 'member') {
    const hit = matchSource(expr, _currentFile);
    if (hit) return hit;
  }
  // R3 (PRD §5): call-shaped sources (r.FormValue(), r.URL.Query(), c.Query()).
  // Previously only member reads were recognized, so Go's call-style sources
  // never tainted the assignment target. matchSource now resolves call sources.
  if (expr.kind === 'call') {
    const hit = matchSource(expr, _currentFile);
    if (hit) return hit;
  }
  if (expr.kind === 'member' && expr.object) {
    return exprIsSource(expr.object);
  }
  return null;
}

const _SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|WHERE|FROM|JOIN|INTO|VALUES|SET|EXEC|EXECUTE)\b/i;
const _HTML_META = /[<>'"&]|innerHTML|outerHTML|document\.write/;
const _SHELL_META = /[;|`$(){}]|&&|\|\|/;

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
  if (cwe === 'CWE-78') return _SHELL_META.test(joined);
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

// cat / argTaints: the result of _matchCallCatalog (computed by the caller,
// at whatever point in its case is appropriate for its own state-mutation
// ordering).
// state: used only to attribute reaching sources to the tainted argument
// expression (via callContext._taintSources, not the state Set itself).
// line: source line to attach to any emitted finding.
// Returns { findings }.
function _sinkFindingsForCall(calleeExpr, argExprs, cat, argTaints, state, callContext, line) {
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
        findings.push({
          ...(_sanNames.size ? { _sanitizersOnPath: [..._sanNames] } : {}),
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
    findings.push({
      ...(_sanNames.size ? { _sanitizersOnPath: [..._sanNames] } : {}),
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
      const src = exprIsSource(node.source);
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
          state, callContext, node.line).findings);
      }
      // PRD R13(a): the assignment TARGET can itself be a sink shape
      // (el.innerHTML = tainted) — additive to the RHS-call-sink check
      // above, which only ever looked at node.source. `target` is only a
      // dotted member-access path when the LHS was a member expression
      // (lhsPath in parser-js.js); a bare identifier target ("x") has no
      // dot and _matchMemberWriteSink correctly returns null for it.
      if (target && target.includes('.')) {
        const _memberHits = matchMemberWriteSink(target, _currentFile);
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
      }
      // Constant propagation: track variables assigned from literals
      if (target && _activeConstantVars) {
        if (node.source && node.source.kind === 'literal') _activeConstantVars.set(target, node.source.value);
        else _activeConstantVars.delete(target);
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
          if (sum && sum.returnTainted) {
            newState = _addPathAliasAware(newState, target, callContext);
            callContext._taintSources.push({
              varName: target,
              sourceId: `interproc:${qid}`,
              sourceLabel: `interproc-return:${calleeName}`,
              provenance: 'interproc',
              line: node.line,
            });
          }
          // applyAtCallSite — mutated params propagate to caller arg-vars.
          if (sum && sum.mutatedParams && sum.mutatedParams.size && paramNames.length) {
            const mutated = callContext._summaryCache.applyAtCallSite(
              sum, paramNames, callArgs, callerTainted);
            for (const v of mutated.mutated) newState = addPath(newState, v);
          }
          if (sum && sum.returnTainted) return { state: newState, findings };
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
      if (src && target) {
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
                taintedGlobals: new Set(),
                // See the sibling assign-call-site compute() above — same
                // fix, same reason: this callee's own findings were
                // computed correctly and then thrown away (hardcoded `[]`).
                findings: inner._findings,
              };
            });
          }
          _mergeSummaryFindings(callContext, callContext._currentFnQid, sum, 'interproc');
          if (sum && sum.mutatedParams && sum.mutatedParams.size) {
            const mutated = callContext._summaryCache.applyAtCallSite(
              sum, paramNames, node.args || [], state);
            for (const v of mutated.mutated) state = addPath(state, v);
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
      // R4 (PRD §5): array-element taint. A mutating array method (push/unshift/
      // splice/fill/copyWithin) called with a tainted argument taints the
      // receiver array; an index read (a[0] → access path "a.0") is then covered
      // by the receiver prefix. Object-property taint already flows via the
      // access-path lattice — this closes the array case.
      if (node.callee && node.callee.kind === 'member' && typeof node.callee.prop === 'string'
          && /^(?:push|unshift|splice|fill|copyWithin)$/.test(node.callee.prop)
          && Array.isArray(argTaints) && argTaints.some(Boolean)) {
        // Mutate the state Set IN PLACE (the binding is const; the call case
        // returns this same Set ref). Avoids touching the unrelated mutated-param
        // paths in this case, keeping the blast radius to array-element taint only.
        const _arrRecv = accessPathOf(node.callee.object);
        if (_arrRecv) state.add(_arrRecv);
      }
      findings.push(..._sinkFindingsForCall(node.callee, node.args, cat, argTaints, state, callContext, node.line).findings);
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
      // For now we simply propagate state to both branches.
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
          node.value.callee, node.value.args, cat, argTaints, state, callContext, node.line).findings);
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
  const work = [];
  const inStates = new Map();
  const outStates = new Map();
  inStates.set(fn.cfg.entry, new Set(entryState));
  work.push(fn.cfg.entry);
  _activeConstantVars = new Map();
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
    const { state: out, findings } = step(node, incoming, callContext);
    callContext._findings.push(...findings.map(f => ({ ...f, _funcQid: fn.qid })));
    const prevOut = outStates.get(nid);
    const merged = mergeStates(prevOut, out);
    if (!prevOut || !stateEq(prevOut, merged)) {
      outStates.set(nid, merged);
      for (const s of (node.succ || [])) {
        const succIn = inStates.get(s);
        const newIn = mergeStates(succIn, merged);
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
          _funcQid: fn.qid, sinkId: sink.id,
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
  // R2: restore the caller context for the enclosing function's analysis.
  if (_prevCallerCtx !== undefined && callContext && callContext._summaryCache && callContext._summaryCache.setCallerContext) {
    callContext._summaryCache.setCallerContext(_prevCallerCtx);
  }
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
  // Pre-pass + fixed-point: compute empty-entry-state summaries for every
  // function, then re-run the pre-pass until the summary cache stabilizes
  // (capped at MAX_FP_ITERS so recursion and chains converge without
  // unbounded blowup). v0.66 — the inner ctx now records mutatedParams
  // via _mutatedParamsOut so cross-function param mutation propagates.
  const MAX_FP_ITERS = 3;
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
      const next = {
        returnTainted: !!ctx._returnTainted,
        mutatedParams: ctx._mutatedParamsOut || new Set(),
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
  // Class-field cross-taint pass: when a method writes tainted data to _this_.field,
  // re-analyze other methods of the same class with those fields in the entry state.
  const classTaintedFields = new Map();
  for (const fn of fnList) {
    if (Date.now() > deadlineMs) break;
    const sum = summaryCache.get(fn.qid, new Set());
    if (!sum || !sum.mutatedParams) continue;
    for (const p of sum.mutatedParams) {
      if (typeof p === 'string' && p.startsWith('_this_.')) {
        const classPrefix = fn.qid.split('::')[0] + '::';
        if (!classTaintedFields.has(classPrefix)) classTaintedFields.set(classPrefix, new Set());
        classTaintedFields.get(classPrefix).add(p);
      }
    }
  }
  for (const [classPrefix, fields] of classTaintedFields) {
    if (Date.now() > deadlineMs) break;
    for (const fn of fnList) {
      if (!fn.qid.startsWith(classPrefix)) continue;
      if (summaryCache.has(fn.qid, fields)) continue;
      const ctx = {
        _findings: [], _taintSources: [], _returnTainted: false,
        _stack: new Set(), deadlineMs,
        _summaryCache: summaryCache, _callGraph: callGraph,
        _mutatedParamsOut: new Set(),
        _currentFnQid: fn.qid,
        _cha: opts._cha,
        _pointsTo: opts._pointsTo,
      };
      try { analyzeFunction(fn, _unionAnnotationTaint(fn, fields), ctx); } catch {}
      // `findings` carries the REAL findings from this probe (was hardcoded
      // `[]`, discarding them) — but this pass is speculative (every field
      // in `fields` is assumed simultaneously tainted; nothing here confirms
      // this exact method is ever reached with that state), so it must not
      // report them itself. They ride on the cached summary and are only
      // surfaced by _mergeSummaryFindings when a REAL call site (assign,
      // plain-call, or higher-order) actually consults this qid+entry —
      // at that point a genuine reachable caller has been established.
      summaryCache.set(fn.qid, fields, {
        returnTainted: !!ctx._returnTainted,
        mutatedParams: ctx._mutatedParamsOut || new Set(),
        taintedGlobals: new Set(),
        findings: ctx._findings,
      });
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
      taintedGlobals: new Set(),
      findings: ctx._findings,
    });
  }
  for (const fn of fnList) {
    if (++n > fnLimit) break;
    if (Date.now() > deadlineMs) break;  // global timeout
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
      const key = `${f.sinkId}:${attributedFn.file}:${f.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const fn = attributedFn;
      all.push({
        id: `ir-taint:${fn.file}:${f.line}:${f.sinkId}`,
        file: fn.file,
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
        // _funcQid: the enclosing function's qid, set upstream during the walk
        // but silently dropped by this allowlist before backward.js's
        // annotateBackwardSlices ever saw it — the same class of omission
        // _sanitizersOnPath had. Without it, annotateBackwardSlices's very
        // first check (`if (!f._funcQid) skip`) discarded every finding, so
        // backward-slice annotation was permanently a no-op regardless of
        // AGENTIC_SECURITY_BACKWARD_SLICE.
        ...(f._funcQid ? { _funcQid: f._funcQid } : {}),
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
