// FR-403 (assurance-hardening PRD) step 3: a genuinely SEPARATE, isolated
// CFG walker for privacy-classified (PII/PHI/PCI) taint, per D-0047.
//
// D-0047's decision, in full: the general taint engine's `step`/`exprTaint`
// (dataflow/engine.js) are the single hottest, most heavily-relied-upon
// functions in this codebase, already proven correct against the corpus and
// self-scan. Threading a second ("privacy") Set through their existing
// signature would touch every internal reference to the state parameter for
// an orthogonal, still-opt-in capability — an unacceptable risk to already-
// validated general-security taint accuracy. This file instead reuses ONLY
// the pure, generic Set utilities from access-paths.js (isCoveredBy/addPath/
// removePathAndDescendants/joinSets/setsEqual — none of which are specific
// to general-security taint semantics) and implements its OWN worklist and
// its OWN, much simpler expression-taint recursion, with ZERO shared
// mutable state and ZERO call-site overlap with `step`/`exprTaint`.
//
// DELIBERATE v1 SCOPE (intra-procedural only, per D-0047): no interprocedural
// SummaryCache, no higher-order taint flow, no k-CFA context sensitivity, no
// receiver-type (CHA) inference for matchPrivacySink's receiverType param
// (passed null — matchPrivacySink's "unknown != clean" contract means this
// never SUPPRESSES a real match, only widens which receiverTypeIn entries
// are permitted to fire, the safe recall-preserving direction). Each
// function is analyzed independently, in isolation from its callers/callees.
// This is a real, bounded capability — direct source-to-sink privacy taint
// within one function — not the full FR-403 acceptance criterion (which
// also needs interprocedural/cross-file tracking); it is the foundation
// those richer capabilities build on incrementally, mirroring how the
// general engine itself grew capability over many versions (see
// dataflow/CLAUDE.md's own "Scope — now modelled" history).
//
// STEP 3 ITEM (a), SIMPLE SAME-FUNCTION ALIASING (added after v1): a bare
// `let a = obj;` (identifier-to-identifier assignment) records `a`/`obj` as
// mutual aliases in a per-function `ctx.aliasesByVar` map. A later member
// WRITE through either name (`a.x = tainted`) applies to both; a later READ
// through either name (`sink(obj.x)`) resolves through the alias too. This
// is deliberately NOT a general points-to/alias analysis (no field-
// sensitive points-to graph, no branch-sensitivity, no alias chains through
// calls or containers) — just the single most common privacy-leak shape a
// declaration-based source needs: renaming a variable before it reaches a
// sink, which the general engine's own `points-to.js` (AGENTIC_SECURITY_
// POINTS_TO=1) solves far more generally for security taint but is
// deliberately NOT reused here, for the same D-0047 isolation reason
// `step`/`exprTaint` are not reused: consuming a shared, general-engine data
// structure would reintroduce a dependency this file's whole design avoids.
//
// OFF BY DEFAULT. Gated by AGENTIC_SECURITY_PRIVACY_DEEP=1 at the call site
// in dataflow/index.js's runDeepAnalysis (mirrors AGENTIC_SECURITY_IFDS=1's
// exact wiring shape: an additional, independently-failing pass whose
// findings are merged in, never replacing the primary engine's output).
// MUST be bench-compared against the existing shallow annotatePrivacyTaint
// (privacy-taint.js) before ever being considered for default-on — that
// comparison harness does not exist yet and is tracked as separate,
// necessary follow-up work, not done in this file.

import {
  accessPathOf, isCoveredBy, addPath, removePathAndDescendants,
  joinSets, setsEqual,
} from './access-paths.js';
import { matchPrivacyDeclSource, matchPrivacyDeclSources, matchPrivacySink, isPrivacyTransformCallee } from './privacy-catalog.js';
// FR-403 step 3, item (b): `functionRecord` is a pure, read-only lookup
// (callGraph.functions.get(qid), roughly) -- reused here for the same
// reason `_languageFamilyExtensions` (catalog.js) is reused: it is shared,
// stateless infrastructure, not the general engine's mutable taint state or
// its `step`/`exprTaint` hot path. `callGraph.resolveKnownCallee(...)` --
// the OTHER half of resolution -- is a method already attached to the
// callGraph object passed into runPrivacyTaintEngine, so it needs no import.
import { functionRecord } from '../ir/callgraph.js';

// FR-403 step 3, item (d) demotion factor. Mirrors stub-aware-filter.js's
// own demotion shape (dataflow/CLAUDE.md: "demotes confidence... by one
// step"), not a fixed magic number invented here.
const TRANSFORM_CONFIDENCE_FACTOR = 0.3;

// Human-readable callee name for recording on a finding -- handles both real
// IR callee shapes (a flat dotted string from the hand-rolled parsers, or a
// structured {kind:'member', object, prop} node from parser-js.js/Babel).
function _calleeDisplayName(calleeExpr) {
  if (typeof calleeExpr === 'string') return calleeExpr;
  if (calleeExpr && calleeExpr.kind === 'member' && calleeExpr.prop) {
    const objName = calleeExpr.object && calleeExpr.object.kind === 'ident' ? calleeExpr.object.name : null;
    return objName ? `${objName}.${calleeExpr.prop}` : calleeExpr.prop;
  }
  if (calleeExpr && calleeExpr.kind === 'ident') return calleeExpr.name || 'unknown';
  return 'unknown';
}

// FR-403 step 3, item (a): resolve a bare-identifier root through the
// per-function alias map before checking coverage. `ctx.aliasesByVar` is
// symmetric (a aliases b => b aliases a), so a single lookup on the
// expression's OWN root is sufficient — the caller does not need to also
// check from the "other side".
function _isCoveredByWithAliases(state, ap, ctx) {
  if (isCoveredBy(state, ap)) return true;
  if (!ctx || !ctx.aliasesByVar || !ap) return false;
  const dot = ap.indexOf('.');
  const root = dot === -1 ? ap : ap.slice(0, dot);
  const rest = dot === -1 ? '' : ap.slice(dot);
  const aliases = ctx.aliasesByVar.get(root);
  if (!aliases || !aliases.size) return false;
  for (const alias of aliases) {
    if (isCoveredBy(state, alias + rest)) return true;
  }
  return false;
}

// Deliberately simpler than dataflow/engine.js's exprTaint: no receiver-
// taint propagation (_calleeReceiverTainted), no interprocedural callee-
// return-taint resolution (_nestedCallReturnTainted), no constant-
// propagation table. Those all exist to widen RECALL for general-security
// taint against an adversarial, heavily-obfuscated corpus; v1's job is a
// correct, bounded DIRECT-flow check, and adding them here would mean
// duplicating (and now independently maintaining) a meaningful slice of the
// general engine's own logic for a capability that does not need it yet.
//
// `ctx` is OPTIONAL (third param, backward-compatible with every existing
// caller/test) — when supplied, member/ident reads are also checked through
// the item (a) alias map, and 'call' expressions also check item (b)'s
// interprocedural return-taint resolution.
export function exprPrivacyTaint(expr, state, ctx) {
  if (!expr) return false;
  const ap = accessPathOf(expr);
  if (ap !== null) return _isCoveredByWithAliases(state, ap, ctx);
  switch (expr.kind) {
    case 'literal': return false;
    case 'binary':
    case 'logical': return exprPrivacyTaint(expr.left, state, ctx) || exprPrivacyTaint(expr.right, state, ctx);
    case 'tpl': return (expr.parts || []).some((p) => exprPrivacyTaint(p, state, ctx));
    case 'union': return (expr.branches || []).some((b) => exprPrivacyTaint(b, state, ctx));
    case 'object': return (expr.props || []).some((p) => exprPrivacyTaint(p.value, state, ctx));
    case 'array': return (expr.elements || []).some((e) => exprPrivacyTaint(e, state, ctx));
    case 'call': {
      const argsTainted = (expr.args || []).some((a) => exprPrivacyTaint(a, state, ctx));
      // FR-403 step 3, item (b): a call's own arguments being tainted is
      // the common case; the callee's OWN return value can ALSO be tainted
      // independent of these specific arguments' taint (e.g. the callee
      // returns a closed-over module-level value) -- mirroring the general
      // engine's exprTaint 'call' case, which evaluates BOTH sides rather
      // than short-circuiting (Taint-recall PRD 80%'s own documented
      // reasoning, in dataflow/engine.js, for why args-tainted alone is not
      // sufficient). Both are cheap here since v1 has no summary-merge side
      // effects to lose by short-circuiting; this just widens recall.
      const nestedTainted = _nestedCallReturnPrivacyTainted(expr.callee, expr.args, state, ctx);
      return argsTainted || nestedTainted;
    }
    default: return false;
  }
}

// FR-403 step 3, item (b): resolve a SIMPLE (bare-identifier, no receiver)
// callee to a known function via the SAME callGraph the general engine
// builds -- callGraph.resolveKnownCallee()/functionRecord() are pure,
// read-only lookups, not the general engine's mutable taint state, so
// reusing them does not violate D-0047's isolation requirement (which is
// about `step`/`exprTaint`'s DATA SHAPE and the SummaryCache, not about
// call-graph name resolution). Deliberately as conservative as the general
// engine's own `_resolvableCalleeName`: refuses every member-expression/
// dotted-string callee (a receiver-qualified call needs CHA-style receiver
// resolution this file does not implement) -- a real, in-scope in-file
// helper call (`helper(x)`) is the only shape resolved.
function _resolvableCalleeNameSimple(calleeExpr) {
  if (typeof calleeExpr === 'string') return calleeExpr.includes('.') ? null : calleeExpr;
  if (calleeExpr && calleeExpr.kind === 'ident') return calleeExpr.name || null;
  return null;
}

// Returns true iff calling `calleeExpr` with `argExprs` (evaluated against
// the CALLER's `state`) resolves to a known, analyzable function whose
// return value is tainted under the entry state those arguments imply.
// `ctx.interproc` (set by analyzePrivacyFunction/runPrivacyTaintEngine) is
// the shared-across-the-whole-scan {callGraph, summaryCache, stack}; absent
// (or missing a resolvable callGraph) degrades to false -- exactly the
// "not this capability, not a wrong answer" contract every optional ctx
// field in this file already follows.
function _nestedCallReturnPrivacyTainted(calleeExpr, argExprs, state, ctx) {
  if (!ctx || !ctx.interproc || !ctx.interproc.callGraph) return false;
  const name = _resolvableCalleeNameSimple(calleeExpr);
  if (!name) return false;
  const cg = ctx.interproc.callGraph;
  if (typeof cg.resolveKnownCallee !== 'function') return false;

  const callerFile = ctx.currentFn && ctx.currentFn.qid ? String(ctx.currentFn.qid).split('::')[0] : undefined;
  let resolved;
  try {
    resolved = cg.resolveKnownCallee(name, callerFile);
  } catch {
    return false;
  }
  const fn = functionRecord(cg, resolved);
  const qid = resolved && (resolved.qid || resolved);
  if (!fn || typeof qid !== 'string' || !fn.cfg) return false;

  // Recursion guard: a function already being analyzed higher up THIS same
  // interprocedural chain is treated as returning untainted -- a sound,
  // conservative "bottom" for a cycle, mirroring the general engine's own
  // SummaryCache behavior for a function it finds already on its `_stack`.
  if (ctx.interproc.stack.has(qid)) return false;

  const paramNames = Array.isArray(fn.params) ? fn.params : [];
  const declEntry = matchPrivacyDeclSources(paramNames, ctx.compiled);
  const entrySet = new Set(declEntry.keys());
  const taintedParamIdx = [];
  (argExprs || []).forEach((a, i) => {
    if (i < paramNames.length && exprPrivacyTaint(a, state, ctx)) {
      entrySet.add(paramNames[i]);
      taintedParamIdx.push(i);
    }
  });

  // Context-sensitive on WHICH params are tainted (not the general engine's
  // richer k-CFA context), keyed per callee -- a helper called once with
  // clean args and once with a tainted arg gets two independent answers,
  // exactly the shape FR-SEM-2 (the general engine's own value-context
  // sensitivity) targets, just monovariant-per-call-site here rather than
  // capped-and-cached the same elaborate way.
  const cacheKey = `${qid}::${taintedParamIdx.join(',')}`;
  if (ctx.interproc.summaryCache.has(cacheKey)) return ctx.interproc.summaryCache.get(cacheKey);

  ctx.interproc.stack.add(qid);
  let result = false;
  try {
    result = _computeReturnTaintUnderEntry(fn, ctx.compiled, entrySet, ctx.interproc);
  } catch {
    result = false;
  } finally {
    ctx.interproc.stack.delete(qid);
  }
  ctx.interproc.summaryCache.set(cacheKey, result);
  return result;
}

// FR-403 step 3, item (d): which arg indices reached the sink through a
// value some named privacy-transform callee touched. `ctx.transformsByVar`
// is keyed by variable NAME (the root of an access path), mirroring
// engine.js's own `_sanitizersByVar` shape exactly.
function _transformsForArg(arg, ctx) {
  if (!ctx || !ctx.transformsByVar || !ctx.transformsByVar.size) return null;
  const ap = accessPathOf(arg);
  if (!ap) return null;
  const root = ap.includes('.') ? ap.slice(0, ap.indexOf('.')) : ap;
  return ctx.transformsByVar.get(root) || null;
}

function _privacySinkFindingsForCall(callee, args, file, line, state, ctx) {
  const hits = matchPrivacySink(callee, file, null);
  if (!hits) return [];
  const argTaints = (args || []).map((a) => exprPrivacyTaint(a, state, ctx));
  const out = [];
  for (const e of hits) {
    const taintedArgIdx = e.argIndex === 'all'
      ? argTaints.findIndex(Boolean)
      : (typeof e.argIndex === 'number' && argTaints[e.argIndex] ? e.argIndex : -1);
    if (taintedArgIdx < 0) continue;
    // Recall-preserving, exactly like the general engine's sanitizer
    // handling (dataflow/CLAUDE.md): a transform callee DEMOTES confidence,
    // it never suppresses the finding — a weak hash, a partial mask, or a
    // transform applied on only one branch would otherwise become a real
    // false negative, not a fixed false positive.
    const transformNames = _transformsForArg((args || [])[taintedArgIdx], ctx);
    const confidence = transformNames ? +(0.6 * TRANSFORM_CONFIDENCE_FACTOR).toFixed(3) : 0.6;
    out.push({
      id: `ir-privacy-taint:${file}:${line}:${e.id}`,
      file,
      line,
      vuln: e.vuln.name,
      cwe: e.vuln.cwe,
      severity: e.vuln.severity,
      remediation: e.vuln.remediation,
      family: 'pii-exposure',
      parser: 'IR-PRIVACY-TAINT',
      confidence,
      confidenceTier: transformNames ? 'low' : 'medium',
      _sinkCategory: e.category,
      ...(transformNames ? { _privacyTransformsOnPath: [...transformNames] } : {}),
    });
  }
  return out;
}

// Mirrors dataflow/engine.js's step()'s node-kind switch shape, but only
// the subset of cases privacy taint needs (assign/call/return) — every
// other kind ('entry'/'exit'/'noop'/'loop-header'/'throw'/anything unknown)
// is a pure pass-through, exactly as in the general engine.
function stepPrivacy(node, stateIn, file, compiled, ctx) {
  let state = new Set(stateIn);
  const findings = [];

  switch (node.kind) {
    case 'assign': {
      const target = typeof node.target === 'string' ? node.target : null;
      if (node.source && node.source.kind === 'call') {
        findings.push(..._privacySinkFindingsForCall(node.source.callee, node.source.args, file, node.line, state, ctx));
      }
      if (target) {
        const rhsTainted = exprPrivacyTaint(node.source, state, ctx);
        // D-0041 step 2's whole reason for existing: the DECLARATION NAME
        // itself, independent of what value it currently holds, can be a
        // privacy source (e.g. `let medicalRecordNumber;` later assigned a
        // plain local computation still deserves scrutiny at its sink).
        const isMemberTarget = target.includes('.');
        const baseName = isMemberTarget ? target.slice(0, target.indexOf('.')) : target;
        const declHit = matchPrivacyDeclSource(baseName, compiled);
        if (rhsTainted || declHit) {
          state = addPath(state, target);
        } else {
          state = removePathAndDescendants(state, target);
        }
        // FR-403 step 3, item (a): a MEMBER write's effect must also reach
        // any known alias of its root — `let a = obj; a.x = tainted;` must
        // taint `obj.x` too, or a later `sink(obj.x)` would (wrongly) read
        // as clean. Bare-identifier targets don't need this: a plain
        // `a = tainted` already taints `a` itself above, and `a`'s own
        // aliases are resolved at READ time by exprPrivacyTaint instead
        // (an alias relationship is symmetric, not a live pointer -- see
        // _isCoveredByWithAliases).
        if (ctx && ctx.aliasesByVar && isMemberTarget) {
          const rest = target.slice(target.indexOf('.'));
          const aliases = ctx.aliasesByVar.get(baseName);
          if (aliases && aliases.size) {
            for (const alias of aliases) {
              const aliasPath = alias + rest;
              state = (rhsTainted || declHit) ? addPath(state, aliasPath) : removePathAndDescendants(state, aliasPath);
            }
          }
        }
        // FR-403 step 3, item (a): record/clear the alias relationship
        // itself. A plain `a = obj` (bare ident RHS, bare ident target) is
        // an alias; anything else assigned to a bare identifier invalidates
        // whatever it used to alias (mirrors the taint-clearing branch
        // above: a clean or unrelated reassignment ends the old relationship).
        if (ctx && ctx.aliasesByVar && !isMemberTarget) {
          // Sever every EXISTING alias relationship `target` had before
          // this assignment, in both directions, first. Without this, a
          // reassignment (`a = other` after `a = obj`) would ADD `other`
          // to `a`'s alias set while leaving the stale `obj` entry behind,
          // so a later `a.x = ...` would keep (wrongly) tainting `obj.x`
          // forever after `a` had already moved on.
          const staleAliases = ctx.aliasesByVar.get(target);
          if (staleAliases) {
            for (const stale of staleAliases) {
              const staleSet = ctx.aliasesByVar.get(stale);
              if (staleSet) staleSet.delete(target);
            }
            ctx.aliasesByVar.delete(target);
          }
          if (node.source && node.source.kind === 'ident' && node.source.name) {
            const srcName = node.source.name;
            if (srcName !== target) {
              if (!ctx.aliasesByVar.has(target)) ctx.aliasesByVar.set(target, new Set());
              if (!ctx.aliasesByVar.has(srcName)) ctx.aliasesByVar.set(srcName, new Set());
              ctx.aliasesByVar.get(target).add(srcName);
              ctx.aliasesByVar.get(srcName).add(target);
            }
          }
        }
        // FR-403 step 3, item (d): record which named transform (if any)
        // produced this value, mirroring engine.js's own _sanitizersByVar
        // (updated on every assignment, cleared when the RHS doesn't apply
        // one) — a re-assignment from a NON-transform source must not keep
        // stealing an earlier transform's credit for the same variable name.
        if (ctx && ctx.transformsByVar) {
          if (node.source && node.source.kind === 'call' && isPrivacyTransformCallee(node.source.callee)) {
            ctx.transformsByVar.set(target, new Set([_calleeDisplayName(node.source.callee)]));
          } else {
            ctx.transformsByVar.delete(target);
          }
        }
      }
      return { state, findings };
    }

    case 'call': {
      findings.push(..._privacySinkFindingsForCall(node.callee, node.args, file, node.line, state, ctx));
      return { state, findings };
    }

    case 'return': {
      if (node.value && node.value.kind === 'call') {
        findings.push(..._privacySinkFindingsForCall(node.value.callee, node.value.args, file, node.line, state, ctx));
      }
      // FR-403 step 3, item (b): record whether THIS function's return
      // value is tainted under the entry state it was analyzed with --
      // mirrors dataflow/engine.js's own `case 'return'` exactly
      // (`callContext._returnTainted = true`). Multiple return statements
      // OR together (any tainted return makes the function's result
      // tainted under this entry state); `ctx.returnTainted` is undefined
      // when no interprocedural caller cares, so this is a no-op cost for
      // every ordinary per-file analysis.
      if (ctx && exprPrivacyTaint(node.value, state, ctx)) {
        ctx.returnTainted = true;
      }
      return { state, findings };
    }

    default:
      return { state, findings };
  }
}

// Shared worklist core, extracted so both the real per-function analysis
// (analyzePrivacyFunction) and the interprocedural return-taint probe
// (_computeReturnTaintUnderEntry) run the IDENTICAL walk -- a probe that
// diverged from the real analysis logic would be its own source of bugs.
// Returns findings; mutates `ctx.returnTainted` as a side effect (read by
// the caller when it cares, ignored otherwise).
function _runWorklist(fn, entrySet, compiled, ctx) {
  const nodes = fn.cfg.nodes;
  const file = fn.file || null;
  const inStates = new Map();
  const outStates = new Map();
  inStates.set(fn.cfg.entry, entrySet);
  const work = [fn.cfg.entry];
  const findings = [];

  let iterations = 0;
  const ITER_BUDGET = 5000;
  while (work.length) {
    if (++iterations > ITER_BUDGET) break;
    const nid = work.shift();
    const node = nodes[nid];
    if (!node) continue;
    const incoming = inStates.get(nid) || new Set();
    const { state: out, findings: nodeFindings } = stepPrivacy(node, incoming, file, compiled, ctx);
    findings.push(...nodeFindings);
    const prevOut = outStates.get(nid);
    const merged = joinSets(prevOut, out);
    if (!prevOut || !setsEqual(prevOut, merged)) {
      outStates.set(nid, merged);
      for (const s of (node.succ || [])) {
        const succIn = inStates.get(s);
        const newIn = joinSets(succIn, merged);
        if (!succIn || !setsEqual(succIn, newIn)) {
          inStates.set(s, newIn);
          work.push(s);
        }
      }
    }
  }
  return findings;
}

function _freshCtx(compiled, interprocCtx, fn) {
  return {
    transformsByVar: new Map(),
    aliasesByVar: new Map(),
    returnTainted: false,
    compiled,
    interproc: interprocCtx || null,
    currentFn: fn,
  };
}

// FR-403 step 3, item (b): probe whether `fn`'s return value is tainted
// under a SPECIFIC caller-supplied `entrySet` -- called only from
// _nestedCallReturnPrivacyTainted, never from the top-level per-file loop.
// Findings produced by this probe are DISCARDED: they would either
// duplicate what the function's own real per-file analysis already found
// (under its OWN, real entry state), or belong to a hypothetical entry
// state that does not correspond to any actual call in the file being
// reported on -- reporting them would be confusing, not more complete.
function _computeReturnTaintUnderEntry(fn, compiled, entrySet, interprocCtx) {
  const ctx = _freshCtx(compiled, interprocCtx, fn);
  _runWorklist(fn, entrySet, compiled, ctx);
  return ctx.returnTainted;
}

// Intra-procedural entry state is seeded from this function's OWN declared
// parameter names (declaration-based sources); `interprocCtx`, when
// supplied by runPrivacyTaintEngine, additionally lets item (b)'s
// interprocedural resolution look up and probe OTHER functions this one
// calls. Omitting it (or calling with the old 2-arg form) degrades cleanly
// to the original intra-procedural-only v1 behavior -- backward-compatible
// with every existing direct caller/test.
export function analyzePrivacyFunction(fn, compiled, interprocCtx) {
  if (!fn || !fn.cfg || !fn.cfg.nodes || fn.cfg.entry == null) return [];
  const declHits = matchPrivacyDeclSources(fn.params || [], compiled);
  const entrySet = new Set(declHits.keys());
  const ctx = _freshCtx(compiled, interprocCtx, fn);
  return _runWorklist(fn, entrySet, compiled, ctx);
}

/**
 * Public entry point, mirroring runTaintEngine(perFileIR, callGraph, opts)'s
 * shape closely enough that dataflow/index.js's runDeepAnalysis can call it
 * the same way it already calls the opt-in IFDS engine — an additional
 * pass whose findings are merged in, never replacing the primary engine's
 * output, and whose own failure (per function OR as a whole) must never
 * fail the containing scan.
 *
 * @param {object} callGraph - the same callGraph object runTaintEngine consumes (callGraph.functions: Map<qid, fn>).
 * @param {object} [opts]
 * @param {object} [opts.compiledTaxonomy] - passed through to matchPrivacyDeclSource(s); undefined uses the built-in default taxonomy.
 * @returns {Array} findings, family:'pii-exposure', cwe:'CWE-359', parser:'IR-PRIVACY-TAINT'.
 */
export function runPrivacyTaintEngine(callGraph, opts = {}) {
  if (!callGraph || !callGraph.functions) return [];
  const compiled = opts.compiledTaxonomy;
  const fnList = [...callGraph.functions.values()].sort((a, b) =>
    a.qid < b.qid ? -1 : a.qid > b.qid ? 1 : 0);
  // FR-403 step 3, item (b): shared across the WHOLE scan (not per-function),
  // mirroring the general engine's own SummaryCache/`_stack` scope exactly --
  // a summary computed while analyzing one function is reusable by every
  // other caller of the same callee, and the recursion guard must see the
  // full chain, not just one function's own local view of it.
  const interprocCtx = { callGraph, summaryCache: new Map(), stack: new Set() };
  const all = [];
  for (const fn of fnList) {
    try {
      all.push(...analyzePrivacyFunction(fn, compiled, interprocCtx));
    } catch {
      // One function's failure must not fail the whole privacy-deep pass,
      // exactly mirroring runTaintEngine's own per-function try/catch.
    }
  }
  return all;
}
