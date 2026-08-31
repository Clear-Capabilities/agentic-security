import { hashState, emptyState, addIdentity } from './field-identity.js';
import { resolveExprIdentities, residualFlat, analyzeFunctionFieldIdentity } from './engine.js';
import { accessPathOf } from '../dataflow/access-paths.js';
import { functionRecord } from '../ir/callgraph.js';

export function emptyFieldSummary() {
  return { returnFlat: new Set(), returnByPath: new Map(), mutatedParams: new Map(), widenings: [] };
}

// Increment B6: the per-function distinct-context cap's operator-facing
// knob. `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` is DELIBERATELY a separate
// env var from dataflow/summaries.js's own `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS`
// — per the isolation principle every prior increment in this sub-project
// has verified holds, the two engines' tuning knobs must stay decoupled,
// so an operator tuning one engine's cap can never silently affect the
// other's. Mirrors dataflow's own exact validation FORMULA
// (`Number.isFinite(...) && ... >= 0`, falling back to 16 on anything
// invalid or absent) — same reasoning, independently re-derived for this
// package rather than shared config.
//
// The formula match does NOT extend to what a cap of exactly `0` means,
// though — a final whole-branch review found and corrected an earlier,
// wrong claim of full equivalence here (see the regression test's own
// comment in summaries.test.js for the full trace). dataflow's own
// compute() exempts the empty-entry context from its cap entirely ("Empty
// entry is always allowed"), so a cap of 0 there is genuinely monovariant
// — the empty-entry pass still runs, over-cap contexts reuse it. THIS
// package's compute() has no such exemption (unchanged since B1): the
// empty-entry context counts against the cap like any other, so
// AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS=0 degrades EVERY context,
// including the empty one, to an empty summary with nothing real to fall
// back to — resolution goes fully off, not merely monovariant. Verified
// empirically through a real call-graph/parser scenario. Closing this gap
// (giving the empty-entry context the same exemption dataflow's own has)
// is a candidate for a later increment; nothing in B1-B6 commits to it.
//
// Evaluated as a FUNCTION (not a module-level constant) specifically so it
// is read fresh on every `new FieldIdentitySummaryCache()` call with no
// explicit constructor argument — JS default-parameter expressions are
// evaluated at CALL time, not at module-load time, which is what makes
// this testable via `process.env` mutation without needing to re-import
// the module between test cases.
function _defaultMaxContexts() {
  const envCap = Number(process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS);
  return Number.isFinite(envCap) && envCap >= 0 ? envCap : 16;
}

export class FieldIdentitySummaryCache {
  constructor(maxContextsPerFn = _defaultMaxContexts()) {
    this._cache = new Map();
    this._stack = new Set();
    this._contextsByQid = new Map();
    this._maxContextsPerFn = maxContextsPerFn;
  }

  _key(qid, entryState) {
    return `${qid}::${hashState(entryState)}`;
  }

  has(qid, entryState) {
    return this._cache.has(this._key(qid, entryState));
  }

  get(qid, entryState) {
    return this._cache.get(this._key(qid, entryState));
  }

  set(qid, entryState, summary) {
    this._cache.set(this._key(qid, entryState), summary);
    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    seen.add(hash);
    this._contextsByQid.set(qid, seen);
  }

  compute(qid, entryState, analyzeFn) {
    // Ordering matches dataflow/summaries.js's own compute() exactly:
    // cache-hit checked FIRST, before the `_stack`-based recursion guard.
    // This is load-bearing, not incidental — B5's whole point is that a
    // nested self/mutual-reference call, on a LATER refinement round, must
    // see the PRIOR round's real (already-cached) summary instead of the
    // bottom stub, so the summary can genuinely grow round over round (e.g.
    // a self-recursive `function chain() { return {base: X, nested:
    // chain()}}` picks up one more `nested:` layer per round). An earlier
    // version of this method checked `_stack.has(qid)` BEFORE the cache-hit
    // check specifically to keep the pre-existing B1 recursion test passing
    // unmodified — but that ordering makes every nested self-call within
    // the SAME compute() invocation hit the bottom-stub branch on every
    // round (since `qid` never leaves `_stack` until the whole call
    // returns), so round 2's self-call is byte-identical to round 1's, and
    // `fieldSummaryEq` converges immediately without ever changing anything
    // — refinement runs but is a structural no-op for genuine
    // self-recursion, defeating the actual purpose of this increment.
    // Verified empirically: with `_stack` checked first, a self-referencing
    // `chain()`-shaped scenario stays stuck at `{'data:base'}` forever;
    // with the cache-hit checked first (this ordering), it genuinely grows
    // (`{'data:base', 'nested:data:base', 'nested:nested:data:base', ...}`)
    // across rounds, bounded by FP_MAX. The pre-existing B1 test's own
    // safety property (a nested self-call is NEVER unboundedly recursive,
    // and — checked once, on its FIRST occurrence — gets a genuine bottom
    // stub) still holds under this ordering; only the test's assertion
    // needed updating to check the FIRST occurrence rather than every
    // occurrence, since round 2+'s nested self-call now legitimately
    // resolves to the real (still `_stack`-guarded from ever calling
    // `innerFn` a second time — see below) prior-round summary. This is
    // this increment's own coordinator-reviewed correction — see the
    // Task 1 report's "Fix round" section for the full trace.
    if (this.has(qid, entryState)) {
      const cached = this.get(qid, entryState);
      if (!cached._recursive) return cached;
    }

    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    if (!seen.has(hash) && seen.size >= this._maxContextsPerFn) {
      // Past this function's distinct-context cap: degrade to the
      // empty-entry summary (if one exists) rather than computing an
      // unbounded number of contexts. Mirrors
      // dataflow/summaries.js's own graceful degradation past its own cap.
      //
      // Path provenance (Sub-project C, increment 3, §13.6/§13.7 item 11):
      // mark the degradation with a PERMANENT, externally-visible
      // `degradedReason` — unlike `_recursive` (a transient
      // recursion-in-progress marker stripped before external use), a
      // degraded summary stays degraded for the life of this cache entry,
      // so this field is never stripped. Marked on a SHALLOW COPY, never
      // on `base` in place: `base` is the exact object already cached for
      // this qid's empty-entry context (Finding 2) — mutating it here
      // would retroactively mark that PRECISE summary as degraded for
      // every later reader of the empty-entry context too.
      const base = this._cache.get(this._key(qid, emptyState())) ?? emptyFieldSummary();
      const fallback = { ...base, degradedReason: 'context-cap' };
      this.set(qid, entryState, fallback);
      return fallback;
    }

    if (this._stack.has(qid)) {
      // Recursion guard: return a bottom stub immediately to the NESTED
      // caller, never recurse further — this part is unchanged from B1 and
      // stays the safety mechanism (never infinite-loop on a recursive call
      // graph). What B5 adds is downstream of this: this ALSO flags
      // `_hitRecursion` on the cache instance (shared across the whole
      // nested call chain, mirroring dataflow/summaries.js's own exact
      // design) so that whichever OUTER compute() call is currently
      // mid-analyzeFn() knows, once its own analyzeFn() returns, to
      // refine its result via the bounded fixed-point loop below. This
      // branch is only ever reached when the cache-hit check above found
      // NOTHING cached yet for this exact qid+entryState — i.e. the FIRST
      // time this qid is encountered while still on `_stack` (every LATER
      // encounter, within the same or a later refinement round, hits the
      // cache-hit branch above instead, once the first round has cached a
      // real summary).
      this._hitRecursion = true;
      return { ...emptyFieldSummary(), _recursive: true };
    }

    this._stack.add(qid);
    // Mirrors dataflow/summaries.js's own exact placement: reset AFTER
    // pushing onto `_stack`, immediately before the analyzeFn() call this
    // flag is scoped to. Nothing reads `_hitRecursion` between the push and
    // this reset, so the two orderings are behaviorally identical here —
    // reset-after-push is what the reference precedent actually does.
    //
    // Known, disclosed imprecision (a final whole-branch review found this
    // via a real 2-function, non-recursive-then-recursive scenario through
    // the real driver — see CLAUDE.md's B5 section): this flag is
    // LAST-WRITER-WINS across the whole nested call chain, not scoped to
    // "did MY OWN analyzeFn() hit recursion." If `analyzeFn`'s body first
    // makes a self/mutual-recursive call (setting the flag true) and THEN
    // makes an unrelated, cache-missing call to some other function, that
    // second call's own `this._hitRecursion = false` (right here, for ITS
    // OWN frame) does not touch the OUTER flag — but if that inner call
    // itself hits a recursion or cache-miss chain, the flag can end up
    // reset by the time control returns to this frame's own post-analyze
    // check, silently skipping refinement this frame otherwise deserved.
    // Sound either way (skipping refinement only under-approximates,
    // never fabricates), but means refinement reliably fires only when
    // the recursive self-call is the LAST uncached compute() an
    // analyzeFn() body makes — not merely "somewhere in the body."
    // Mirrors dataflow/summaries.js's own precedent exactly, so not a new
    // risk this package introduces; inherit this knowledge if B6 touches
    // this same flag.
    this._hitRecursion = false;
    try {
      // A final whole-branch review found this method previously had no
      // try/finally around analyzeFn — if it threw, qid stayed on _stack
      // forever, and every LATER compute() call for that qid would fall
      // into the recursion guard above and silently return a bottom stub,
      // permanently. Not reachable at this increment's own hand-built-test
      // scope, but live the moment a real driver (B4) runs
      // analyzeFunctionFieldIdentity over real parsed IR — that function
      // throws a plain TypeError on a malformed `fn`, and a sensible
      // driver catching-and-continuing would otherwise silently spread
      // "one function failed" into "this function under-reports for the
      // rest of the run," the exact silent-under-approximation class the
      // intraprocedural engine spent six rounds closing. Mirrors
      // dataflow/summaries.js's own try/finally around the identical
      // stack-push/pop pattern.
      let summary = analyzeFn(entryState);
      this.set(qid, entryState, summary);
      // Increment B5: bounded fixed-point refinement. If a NESTED call for
      // THIS SAME qid (still on `_stack` for the duration of this
      // analyzeFn() call) hit the recursion guard above, the summary just
      // computed treated that self/mutual reference as carrying zero
      // identity (the bottom stub) — an honest but possibly permanent
      // under-approximation if nothing ever revisits it. Re-invoking
      // analyzeFn() now, AFTER this qid is already cached with a real
      // (non-bottom-stub) summary, lets a nested self-call resolve against
      // THAT cached value instead of the guard on the next round, so each
      // round can only get more complete, never regress. Bounded by
      // FP_MAX (mirrors dataflow's own `FP_MAX = 3`) as a hard safety cap,
      // not a precision target — a function that never converges within
      // the cap is left at whatever the last round produced, an honest,
      // sound under-approximation. `fieldSummaryEq` (membership-based, see
      // below) decides convergence: a round judged equal to the previous
      // one is NOT cached (the cache still holds the prior — equal — round,
      // which is correct), and the loop stops. Ordering (cache the round
      // BEFORE the loop starts; compare BEFORE caching each subsequent
      // round) mirrors dataflow/summaries.js's own compute() exactly.
      if (this._hitRecursion) {
        const FP_MAX = 3;
        for (let fp = 0; fp < FP_MAX; fp++) {
          const prev = summary;
          summary = analyzeFn(entryState);
          if (fieldSummaryEq(prev, summary)) break;
          this.set(qid, entryState, summary);
        }
      }
      // Defensive strip, mirroring dataflow's own equivalent: analyzeFn's
      // real return shape here never actually carries `_recursive` under
      // normal operation, but this guards against a future change to
      // analyzeFn's callers accidentally leaking it through a cached,
      // externally-visible summary.
      if (summary._recursive) delete summary._recursive;
      return summary;
    } finally {
      this._stack.delete(qid);
    }
  }

  size() {
    return this._cache.size;
  }

  clear() {
    this._cache.clear();
    this._stack.clear();
    this._contextsByQid.clear();
  }
}

// Compares two FieldSummary objects for VALUE equality — by membership,
// never by size alone. dataflow/summaries.js's own equivalent (_summaryEq)
// carries a documented, previously-shipped bug ("Stage 3 correctness
// audit," see that file's comment directly above _summaryEq): an earlier
// version compared mutatedParams by SIZE only, so two summaries with the
// same cardinality but different actual members were wrongly judged
// equal — the fixed-point loop then broke early WITHOUT caching the
// fresher, more-correct summary, silently serving a stale one to any
// LATER cache read. This function is written correctly from the start,
// citing that precedent as the reason, not discovered the same way twice.
//
// Deliberately does NOT compare `widenings` — mirrors dataflow's own
// `_summaryEq`, which also excludes its diagnostic-list equivalent
// (`findings`) from the equality check. Two summaries that agree on their
// actual FACTS (returnFlat, returnByPath, mutatedParams) but happen to
// carry a differently-ordered or differently-worded widening-reason list
// should still be treated as converged — the facts are what a caller
// actually consumes; the widening list is diagnostic.
//
// `degradedReason` (Sub-project C, increment 3, §13.6/§13.7 item 13) is
// excluded from this comparison for the SAME reason as `widenings` — it is
// diagnostic (why a summary is honestly incomplete), never a fact the
// analysis result itself depends on. This is stated here deliberately, not
// left as an accidental omission: `fieldSummaryEq`'s field-by-field
// comparison below never touched `degradedReason` to begin with (it isn't
// one of `returnFlat`/`mutatedParams`), so nothing had to change to keep
// this true — the comment exists so a future reader doesn't "fix" the
// omission by adding it.
//
// `returnByPath` is deliberately NOT compared either — it is currently
// always `new Map()` for every summary this cache ever stores, per B1's
// own disclosed, still-open limitation; comparing two always-empty Maps
// would be a no-op check, not a meaningful omission. If a future
// increment populates `returnByPath`, this function will need extending.
export function fieldSummaryEq(a, b) {
  if (!a || !b) return a === b;
  if (a.returnFlat.size !== b.returnFlat.size) return false;
  for (const id of a.returnFlat) if (!b.returnFlat.has(id)) return false;
  if (a.mutatedParams.size !== b.mutatedParams.size) return false;
  for (const [path, ids] of a.mutatedParams) {
    const bIds = b.mutatedParams.get(path);
    if (!bIds || bIds.size !== ids.size) return false;
    for (const id of ids) if (!bIds.has(id)) return false;
  }
  return true;
}

// Maps a call site's argument expressions onto a fresh entry state for the
// callee, keyed by the callee's own parameter names — the interprocedural
// analog of `engine.js`'s `assign` transfer function: each argument is
// resolved against the CALLER's current state via `resolveExprIdentities`,
// and its residual (root-level) identities plus its byPath (field-level)
// structure are both written into the callee's entry state at the
// corresponding parameter name, using the exact same residual+byPath split
// `assign` already uses — this is a direct, deliberate reuse of Sub-project
// A's already-hardened write pattern, not a new mechanism.
export function entryStateFromCall(paramNames, callArgs, callerState, ctx) {
  // Path provenance (Sub-project C, increment 3, §13.2a). `ctx` is an
  // OPTIONAL 4th parameter. THE SINGLE MOST IMPORTANT THING HERE: derive a
  // RECORDER-ONLY ctx — never forward `ctx` itself to resolveExprIdentities.
  // Forwarding the full ctx hands resolveExprIdentities a live
  // `resolveCallSummary`, so a call argument that is itself a resolvable
  // call (e.g. `sink(scrub(user))`) starts resolving interprocedurally
  // where the shipped engine takes the unresolved fallback — changing the
  // ANALYSIS RESULT with no recorder attached anywhere, in the unsound
  // direction under a tight B6 context cap (the extra nested resolve
  // consumes the callee's only context slot, so a later, unrelated call
  // degrades to an empty summary and loses an identity the shipped engine
  // keeps). This is exactly the hazard found and closed in
  // DESIGN_PATH_PROVENANCE.md §13.2a's fix round; see
  // engine-provenance-interprocedural.test.js's golden-baseline regression
  // tests for the guard that pins this closed.
  //
  // Deriving this ONCE, here, inside entryStateFromCall itself (not at a
  // call site) is load-bearing, not stylistic — it means no future second
  // caller of entryStateFromCall can reintroduce the hazard by passing the
  // full ctx through a different path.
  const argCtx = ctx?.recordHop ? { recordHop: ctx.recordHop } : undefined;
  let entryState = emptyState();
  const n = Math.min(paramNames.length, callArgs.length);
  for (let i = 0; i < n; i++) {
    const paramName = paramNames[i];
    const resolved = resolveExprIdentities(callerState, callArgs[i], argCtx);
    const residual = residualFlat(resolved.flat, resolved.byPath);
    for (const id of residual) entryState = addIdentity(entryState, paramName, id);
    for (const [subPath, ids] of resolved.byPath) {
      for (const id of ids) entryState = addIdentity(entryState, `${paramName}.${subPath}`, id);
    }
  }
  return entryState;
}

// Maps a callee's summary back onto the CALLER's own state at the call
// site — the interprocedural analog of reading a function's return value
// and observing its side effects. Unlike dataflow/summaries.js's
// applyAtCallSite (which only propagates a mutation back for a bare
// `ident` argument, silently dropping a `member`-expression argument like
// `f(obj.field)`), this version also resolves a member-expression argument
// via `accessPathOf` — a deliberate, scoped improvement: field mutations
// plausibly target `obj.field`-shaped arguments often enough that
// dropping them silently would be a real, avoidable under-approximation.
export function applyAtCallSite(summary, paramNames, callArgs) {
  const mutations = [];
  for (const [paramPath, ids] of summary.mutatedParams) {
    const [rootParamName, ...rest] = paramPath.split('.');
    const idx = paramNames.indexOf(rootParamName);
    if (idx === -1) continue;
    const arg = callArgs[idx];
    const argPath = accessPathOf(arg);
    if (!argPath) continue;
    const fullPath = rest.length > 0 ? `${argPath}.${rest.join('.')}` : argPath;
    mutations.push({ path: fullPath, dataElementIds: [...ids] });
  }
  return { returnFlat: summary.returnFlat, returnByPath: summary.returnByPath, mutations };
}

// Builds a `resolveCallSummary` closure — the shape `resolveExprIdentities`'s
// `call` case now consults (see engine.js) — wired to a real
// FieldIdentitySummaryCache. `lookupCallee` is itself injected and
// deliberately opaque to this function: this increment's own tests pass a
// simple hand-built name-to-function map; increment B3's real call-graph
// integration will pass a resolver backed by `scanner/src/ir/callgraph.js`
// instead, without this function (or `resolveExprIdentities`) needing to
// change at all.
export function createCallSummaryResolver(cache, lookupCallee) {
  return function resolveCallSummary(calleeExpr, callArgs, callerState, ctx) {
    const resolved = lookupCallee(calleeExpr);
    if (!resolved) return null;
    const { qid, fn } = resolved;
    // Path provenance (Sub-project C, increment 3, §13.7 item 7):
    // `entryStateFromCall` does the recorder-only stripping itself (see its
    // own header comment) — this call site forwards the caller's `ctx`
    // unmodified; the hazard cannot reappear here because the strip
    // happens one level down, not at each call site.
    const entryState = entryStateFromCall(fn.params, callArgs, callerState, ctx);
    // §13.2's first half: the callee's own entry context, computed once so
    // both the bind hop below and the return-direction wrapper at the
    // bottom of this function can reference the exact same value.
    const calleeContext = hashState(entryState);

    // Path provenance (§13.2b): the argument -> parameter binding out-half,
    // emitted once per (path, id) entry of the freshly built entryState —
    // entryState IS the complete record of every (toPath, id) the binding
    // wrote, so nothing has to be re-resolved to enumerate them. fromPath
    // stays null: the argument expression's own in-halves (emitted inside
    // entryStateFromCall, above) already carry the real contributing keys
    // at the join key (callerScope, callerNodeId, id, callerContext); a
    // non-null fromPath here would double-emit the same information in a
    // differently-shaped record. peerScope/peerContext are mandatory, not
    // decorative: toPath lives in the CALLEE's namespace, so without them
    // C4 would collide this binding's target with any caller-local
    // variable of the same name (Decision 5's bug class).
    if (ctx?.recordHop) {
      for (const [path, ids] of entryState) {
        for (const id of ids) {
          ctx.recordHop({
            kind: 'write-out', subKind: 'call-arg-bind',
            fromPath: null, toPath: path, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
            peerScope: qid, peerContext: calleeContext,
          });
        }
      }
    }

    const summary = cache.compute(qid, entryState, (es) => {
      // Pass THIS SAME resolver down as the callee's own ctx — without
      // this, a chain of resolved calls (outer resolves to middle, middle
      // itself calls inner) would silently stop resolving after one hop:
      // middle's own analysis would run with no ctx, so its call to inner
      // would take the unresolved fallback, and outer would receive a
      // coarsely-widened summary reported as `widened: false` (since
      // resolveExprIdentities's call case only reads summary.returnFlat/
      // returnByPath, never summary.widenings) — a confident-looking
      // answer that's silently wrong one level down. A final whole-branch
      // review found and proved this exact gap via a real three-function
      // chain. Passing the resolver down makes resolution recurse through
      // as many resolved hops as `lookupCallee` can cover, with the
      // existing recursion guard (field-identity summary cache's `_stack`
      // bottom-stub) already sufficient to keep a self- or mutually-
      // recursive chain safe (verified: both terminate immediately,
      // returning an empty, honestly-unrefined result — precision there
      // is increment B5's job, not this fix's).
      //
      // Path provenance (§13.7 item 9, hole 3): keep the caller's recorder
      // alive on the callee's own ctx instead of discarding it (the
      // pre-C3 `{ resolveCallSummary }`-only object was hole 3). Do NOT
      // re-stamp `context` here — the callee's own analyzeFunctionFieldIdentity
      // call (engine.js's stepCtx wrapper) computes and stamps its own
      // `context` from ITS OWN entry state (`es`, not the caller's), and
      // its stamps win over anything this object would set, by spread
      // order (`{ ...ctx, ..., ...h }` — the innermost `h` from the
      // deepest call always wins). Passing a `context` field here would be
      // silently overwritten and is dead code.
      const calleeCtx = ctx?.recordHop
        ? { resolveCallSummary, recordHop: ctx.recordHop }
        : { resolveCallSummary };
      const result = analyzeFunctionFieldIdentity(fn, es, calleeCtx);
      return summaryFromAnalysisResult(result);
    });

    // Path provenance (§13.6/§13.7 item 12): a summary the cache honestly
    // degraded (B6 context-cap) has an empty `returnFlat`, so
    // engine.js's `case 'call'` `for (const id of flat)` loop can never
    // fire — there is no hop at all to carry a marker (Finding 1: the
    // degradation is otherwise completely silent). Emitted HERE, at the
    // resolver, one loss hop per id that entered the callee (the entry
    // state's own ids — the identities whose downstream fate is now
    // unrepresented), `fromPath`/`toPath` both null so it reads as an
    // ANNOTATION on the argument's own real in-half at the same join key
    // under §2.2's rule (or, when there is no path-shaped argument, as
    // edge-forming in its own right) — never dropped either way.
    if (summary?.degradedReason && ctx?.recordHop) {
      for (const [, ids] of entryState) {
        for (const id of ids) {
          ctx.recordHop({
            kind: 'production', subKind: 'call-resolved',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: null,
            lossReason: 'context-cap-degraded',
            peerScope: qid, peerContext: calleeContext,
          });
        }
      }
    }

    // §13.2(c), the return direction: a FRESH wrapper every call — the
    // cached summary is never mutated, so fieldSummaryEq and the B5
    // refinement loop are untouched. engine.js reads only
    // returnFlat/returnByPath, so this augmentation is inert to it; it
    // exists purely so `case 'call'`'s own production/call-resolved hop can
    // carry peerScope/peerContext naming the callee it resolved to.
    return summary ? { ...summary, resolvedQid: qid, resolvedContext: calleeContext } : summary;
  };
}

// Converts analyzeFunctionFieldIdentity's raw per-function result
// (`{exitState, returnFacts, mutatedParams, widenings}`) into the
// FieldSummary shape (`{returnFlat, returnByPath, mutatedParams,
// widenings}`) that FieldIdentitySummaryCache stores and every consumer of
// a resolved summary reads. Extracted (increment B4) from what was
// previously inline-only logic inside createCallSummaryResolver's own
// cache.compute callback, so increment B4's project-wide driver can seed
// the cache with the exact SAME conversion for a function's own top-level
// analysis, rather than reimplementing it a second time and risking the
// two copies drifting apart.
//
// Unions identities across EVERY return site, not just the first — a
// function with multiple return statements (e.g. an early-return branch)
// must have all of them reflected, not just whichever happened to be
// recorded first. This was a genuine correctness improvement over
// increment B1's own round-trip test's `returnFacts[0]` shortcut (that
// test only ever exercised a single-return-site function, so the shortcut
// was harmless there).
export function summaryFromAnalysisResult(result) {
  const returnFlat = new Set();
  for (const rf of result.returnFacts) {
    for (const id of rf.identities) returnFlat.add(id);
  }
  return {
    returnFlat,
    returnByPath: new Map(), // still flat-only — see B1's disclosed limitation in CLAUDE.md; not closed by this increment either.
    // If this ever stops being an unconditional empty Map, fieldSummaryEq
    // (above) MUST be extended to compare it too — that function currently
    // omits it, reasoned as safe only because every value here is always
    // empty. Skipping this would silently reintroduce the exact
    // "Stage 3 correctness audit" bug class dataflow/summaries.js
    // documents: two summaries wrongly judged equal, the fresher one
    // never cached, a later reader silently served the stale value.
    mutatedParams: result.mutatedParams,
    widenings: result.widenings,
  };
}

// Resolves a call expression's callee to a bare, resolvable name — the
// lineage-engine analog of dataflow/engine.js's own `_resolvableCalleeName`
// BASE CASE (before that file's later, CHA-gated member-expression
// extension) for the `calleeExpr.kind === 'ident'` branch specifically.
// Deliberately narrow: only a bare identifier callee (`helper(x)`) resolves
// to a name at all. A member-expression callee (`obj.helper(x)`) returns
// null here, on purpose — resolving THAT safely needs class-hierarchy
// analysis (which method does the object concretely carry), a separate,
// much larger mechanism dataflow built specifically for its own R11
// requirement (`_resolveMemberCalleeViaCHA`, gated on a `_cha` object this
// package has no equivalent of and is not in scope to build here).
// Guessing from the property name alone would fabricate a call edge that
// may not exist — worse than leaving the call unresolved, matching this
// whole codebase's own stated doctrine (see callgraph.js's comments on
// `resolveKnownCallee` vs. the guessing `resolve()`).
//
// UNLIKE dataflow's version, this one does NOT also accept a plain string
// callee (`typeof calleeExpr === 'string'`). Per the IR shape contract
// (scanner/src/ir/CLAUDE.md), `callee` is `string|expr` — the seven
// hand-rolled parsers (Python/Ruby/PHP/Go/Java/C#/Kotlin) emit a flat,
// dot-joined STRING callee, never a structured `{kind:'ident'}` node. This
// means `createCallGraphLookup` below resolves NOTHING for those
// languages' IR today — every call in a non-JS/TS file silently takes the
// unresolved-call fallback (flat + widened:true), the same fail-safe
// direction as an unresolvable JS/TS call, just unconditionally so. This
// is not an oversight: naively accepting a dotted string (e.g. Java's
// class-qualified `"App.getUser"`) and handing it to `resolveKnownCallee`
// would resolve it via that function's project-wide bare-name index —
// which is member-call resolution in disguise, exactly what this
// increment's CHA-free scope forbids. Whether/how to extend real
// interprocedural resolution to the hand-rolled-parser languages is
// undecided and out of scope for Sub-project B's current B1-B6 breakdown.
function _resolvableCalleeName(calleeExpr) {
  if (!calleeExpr) return null;
  if (calleeExpr.kind === 'ident') return calleeExpr.name || null;
  return null;
}

// Builds a real `lookupCallee` closure — the shape `createCallSummaryResolver`
// expects as its second argument — backed by a real call graph from
// `scanner/src/ir/callgraph.js#buildCallGraph`. `callerFile` is fixed at
// construction time: one `lookupCallee` closure is built per analyzed
// function/file (mirroring how `dataflow/engine.js`'s own
// `_resolveCalleeForSummary` derives `_callerFile` fresh per call context),
// so `createCallSummaryResolver`'s existing single-argument `lookupCallee`
// shape (no caller-file parameter) does not need to change.
//
// Uses `resolveKnownCallee` — never `resolve()` — matching `callgraph.js`'s
// own documented distinction: `resolveKnownCallee` is "safe-by-default,"
// refusing the bare-name-tail guess `resolve()` is willing to make. This
// package's own doctrine (see FR-301, never silently merge/drop distinct
// identities) treats a fabricated call edge as strictly worse than a missed
// one, same as dataflow's own precedent.
export function createCallGraphLookup(callGraph, callerFile) {
  return function lookupCallee(calleeExpr) {
    if (!callGraph || typeof callGraph.resolveKnownCallee !== 'function') return null;
    const name = _resolvableCalleeName(calleeExpr);
    if (!name) return null;
    const resolved = callGraph.resolveKnownCallee(name, callerFile);
    if (!resolved) return null;
    const fn = functionRecord(callGraph, resolved);
    if (!fn) return null;
    return { qid: resolved, fn };
  };
}
