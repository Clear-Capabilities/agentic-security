// PRD R14(a) (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme E): annotation/
// decorator-shaped framework sources. Task 1 added `matchAnnotationParams` to
// catalog.js; this task wires it into engine.js so a function whose IR
// carries a `paramAnnotations` field has those parameters treated as tainted
// at entry — at every site in the engine that starts analyzing a function,
// not just the ones a caller happens to exercise.
//
// This test hand-constructs a Java-shaped IR fixture directly (no real
// java-parser involved — Tasks 3-5 give real parsers the ability to populate
// paramAnnotations). It proves engine.js's CONSUMPTION of the field.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { buildCallGraph } from '../src/ir/callgraph.js';

test('R14(a): a paramAnnotations-tainted parameter reaches a sink even with no caller-supplied taint', () => {
  // Simulates: public String show(@RequestParam String q) { Statement.execute(q); }
  // No in-repo caller passes tainted data — this is exactly the shape of a
  // Spring controller method invoked by the framework via reflection, which
  // the empty-entry base pass (engine.js's main analysis loop) must catch.
  const fn = {
    qid: 'UserController.java::UserController::show@3',
    name: 'UserController.show',
    line: 3,
    params: ['q'],
    paramAnnotations: [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    file: 'UserController.java',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 3, succ: ['n3'], pred: ['n1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 4, succ: [], pred: ['n2'] },
      },
    },
  };
  const perFileIR = { 'UserController.java': { file: 'UserController.java', functions: [fn], topLevel: null } };
  const callGraph = { functions: new Map([[fn.qid, fn]]), edges: [], callersOf: new Map() };
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'UserController.java' && /command injection|sql injection/i.test(f.vuln || ''));
  assert.ok(hit, `expected an annotation-sourced finding, got: ${JSON.stringify(findings.map(f => f.vuln))}`);
});

test('R14(a): a function with no paramAnnotations is unaffected (no false positive)', () => {
  const fn = {
    qid: 'Helper.java::Helper::show@3',
    name: 'Helper.show',
    line: 3,
    params: ['q'],
    // no paramAnnotations field at all
    file: 'Helper.java',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 3, succ: ['n3'], pred: ['n1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 4, succ: [], pred: ['n2'] },
      },
    },
  };
  const perFileIR = { 'Helper.java': { file: 'Helper.java', functions: [fn], topLevel: null } };
  const callGraph = { functions: new Map([[fn.qid, fn]]), edges: [], callersOf: new Map() };
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'Helper.java');
  assert.equal(hit, undefined, 'q is an untainted local parameter with no annotation and no caller-supplied taint — must not fire');
});

// ─────────────────────────────────────────────────────────────────────────
// Task-2 fix round 1 (task review coverage gap). The two tests above give
// JOINT coverage of 2 of the 8 `analyzeFunction` call sites: the k=1
// empty-entry pre-pass (engine.js's `runTaintEngine`, the loop that seeds
// `summaryCache` before the main per-function pass) and the main per-
// function base pass. Both unconditionally analyze EVERY function in the
// call graph with `entry = _unionAnnotationTaint(fn, new Set())`, so a
// finding reachable purely from an annotated parameter WITHIN THAT SAME
// FUNCTION's own body is independently rediscovered by whichever of the two
// runs first — reverting either ONE alone leaves the OTHER's coverage
// intact and the finding still fires. That masking is structural, not a
// test-writing oversight: it holds for ANY fixture where the sink sits
// inside the annotated function's own body, because every function in the
// call graph is unconditionally re-analyzed by both of those two passes.
//
// The two tests below instead drive taint THROUGH a function boundary: the
// annotated function REASSIGNS a sibling (unannotated) param from its own
// annotated param — a MUTATED-PARAM effect, not a return value — with the
// actual sink living in a DIFFERENT function that consumes that mutated
// argument via `SummaryCache.applyAtCallSite`. A return-taint version of
// this idea was tried FIRST and empirically disproved (see the long comment
// inside the first test below) — the mutated-param path was required
// because it is the only propagation channel with no generic, taint-
// agnostic fallback riding on the same argument list used to force a
// non-empty, cache-key-avoiding entry state. Because neither the k=1
// pre-pass nor the base pass ever produces a "finding" from a function that
// merely sets `mutatedParams` (only a direct sink call inside that
// function's own body is ever reported directly), this cross-function
// value only reaches a finding at all via the interprocedural
// SummaryCache-consulting call sites in `step()` — letting each of those be
// exercised with an entry state that provably belongs to ONLY that call
// site (see the per-test comments for the exact cache-key-collision-
// avoidance reasoning).
//
// Sites where this kind of isolation was attempted but is NOT achievable in
// the current architecture (documented rather than silently skipped, per
// the fix-round instructions):
//
//   - `_nestedCallReturnTainted` (site 1, `sink(helper(args))` nested in a
//     sink argument): `exprTaint`'s 'call' case checks `expr.args` for
//     taint FIRST and short-circuits before ever calling
//     `_nestedCallReturnTainted` — but `entryStateFromCall` (which computes
//     the SummaryCache entry `_nestedCallReturnTainted` looks up) reads
//     that exact same `expr.args` array. Any argument tainted enough to
//     force a non-empty, non-colliding entry (required to dodge the k=1
//     pre-pass's cache key and force a fresh compute) is, by construction,
//     ALSO enough to make the args-tainted short-circuit fire on its own —
//     so the finding never depends on annotation taint specifically, and no
//     fixture can distinguish "site 1 reverted" from "site 1 intact."
//   - Class-field cross-taint pass (site 5, entries keyed by a Set of
//     `_this_.<field>` access-path strings): those cache entries are only
//     ever WRITTEN (`summaryCache.set(fn.qid, fields, …)`), never read back
//     by any other call site in engine.js. `entryStateFromCall` and the
//     higher-order callback's `cbEntry` only ever produce sets of bare
//     parameter names, never `_this_.`-prefixed strings, so no real call
//     site's own computed entry can ever collide with a `fields` key and
//     retrieve what this pass cached. The pass's own header comment claims
//     these findings are surfaced "when a REAL call site … consults this
//     qid+entry" — grepping the file shows nothing does.
//   - k=2 pass (site 6, `taintedEntry = new Set(fn.params)` — every
//     declared param, simultaneously): `matchAnnotationParams` can only ever
//     return a SUBSET of `fn.params` (annotations attach to real params), so
//     `_unionAnnotationTaint(fn, new Set(fn.params))` can never add anything
//     not already in the set — the union is a mathematical no-op at this
//     one call site by construction, for every possible fixture.
//   - Higher-order callback (site 8, `cbEntry = new Set([cbFn.params[…]])`):
//     the only OBSERVABLE effect of this site's summary is
//     `_mergeSummaryFindings` reading `cbSummary.findings` — i.e. a sink
//     call inside the callback's OWN body. `cbFn` is, like every function,
//     independently and unconditionally re-analyzed by the k=1/base passes
//     with the SAME annotation union — so any sink reachable purely from
//     `cbFn`'s annotated param is already caught by those, for the same
//     structural reason as sites 4/7 above. Unlike the interprocedural
//     call/assign sites, the higher-order path never propagates a
//     callback's `returnTainted`/`mutatedParams` to any caller-observable
//     effect — there's no cross-function consumption to hang an isolated
//     fixture on.
//
// (All four claims above were verified empirically, not just by reading:
// each site was reverted alone and the full suite re-run — see the fix-
// round report for the exact commands and results.)

test('R14(a) site isolation: assign-from-call interprocedural summary (site ~line 713) unions annotation taint independent of the base pass', () => {
  // Simulates: `void copy(@RequestParam String q, String x, String y) { y = q; }`
  // called via an ASSIGNMENT whose result is discarded:
  // `String ignored = copy("clean", requestParamX, outY); executeQuery(outY);`
  //
  // This deliberately uses MUTATED-PARAM propagation, not return-taint.
  // A return-taint design was tried first and DISPROVED empirically: when
  // the interprocedural summary's own `sum.returnTainted` is false (as it
  // is whenever this call site's fix is reverted), `step()`'s assign-case
  // does NOT early-return — it falls through to a SEPARATE, cheaper
  // generic check a few lines below, `exprTaint(node.source, …)`, which
  // taints the assignment TARGET whenever ANY of the call's own arguments
  // is independently tainted. Forcing a non-empty, non-cache-colliding
  // entry state requires making SOME argument caller-tainted — but that
  // same tainted argument then ALSO satisfies the generic fallback,
  // regardless of whether the interprocedural summary's own annotation
  // union ran at all. A return-taint fixture can never distinguish "this
  // site's fix is reverted" from "this site's fix is intact" for exactly
  // that reason (confirmed by actually reverting the site and re-running:
  // the naive version of this test kept passing).
  //
  // Mutated-param propagation (`applyAtCallSite`) has no such fallback: it
  // taints the caller-side variable bound to the MUTATED parameter only,
  // entirely independent of whatever the generic RHS-tainted check decides
  // for the (here, unused) assignment target `ignored`. copy() reassigns
  // its own `y` from `q` — the caller passes a tainted value only for `x`
  // (a decoy: copy() never reads `x`; its only purpose is forcing
  // `entryStateFromCall` to compute entry = {'x'}, which collides with
  // neither the k=1 pre-pass's key (empty Set) nor the k=2 pass's key (the
  // full 3-param set)). That forces THIS specific assign-from-call site to
  // freshly compute copy()'s summary; only with annotation taint unioned
  // in does `y = q` mark `y` mutated, which `applyAtCallSite` maps onto the
  // caller's own `outY`. Revert this site's wiring and `q` never joins
  // {'x'}, `y` is never marked mutated, `outY` stays clean, and
  // `executeQuery(outY)` never fires — while `ignored` (irrelevant to the
  // assertion) gets tainted via the generic fallback regardless, exactly
  // as the comment above describes, and is never checked.
  const copyFn = {
    qid: 'ReaderA.java::ReaderA::copy@1',
    name: 'copy',
    line: 1,
    params: ['q', 'x', 'y'],
    paramAnnotations: [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    file: 'ReaderA.java',
    cfg: {
      entry: 'p1', exit: 'p3',
      nodes: {
        p1: { id: 'p1', kind: 'entry', line: 1, succ: ['p2'], pred: [] },
        p2: { id: 'p2', kind: 'assign', line: 2, succ: ['p3'], pred: ['p1'], target: 'y', source: { kind: 'ident', name: 'q' } },
        p3: { id: 'p3', kind: 'exit', line: 3, succ: [], pred: ['p2'] },
      },
    },
  };
  const callerFn = {
    qid: 'ReaderA.java::ReaderA::caller@5',
    name: 'caller',
    line: 5,
    params: [],
    file: 'ReaderA.java',
    cfg: {
      entry: 'c1', exit: 'c5',
      nodes: {
        c1: { id: 'c1', kind: 'entry', line: 5, succ: ['c2'], pred: [] },
        // z = request.getParameter("x")  — a genuine Java catalog source
        // (java-request-getParameter), taints `z`, mapped to copy()'s
        // (unannotated) second param `x`.
        c2: {
          id: 'c2', kind: 'assign', line: 6, succ: ['c3'], pred: ['c1'],
          target: 'z',
          source: {
            kind: 'call',
            callee: { kind: 'member', object: { kind: 'ident', name: 'request' }, prop: 'getParameter' },
            args: [{ kind: 'literal', value: 'x' }],
          },
        },
        // ignored = copy("clean", z, outY)  — ASSIGN-FROM-CALL, result
        // discarded: this is the code path under test (site ~line 713).
        c3: {
          id: 'c3', kind: 'assign', line: 7, succ: ['c4'], pred: ['c2'],
          target: 'ignored',
          source: {
            kind: 'call',
            callee: { kind: 'ident', name: 'copy' },
            args: [{ kind: 'literal', value: 'clean' }, { kind: 'ident', name: 'z' }, { kind: 'ident', name: 'outY' }],
          },
        },
        c4: {
          id: 'c4', kind: 'call', line: 8, succ: ['c5'], pred: ['c3'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'outY' }],
        },
        c5: { id: 'c5', kind: 'exit', line: 9, succ: [], pred: ['c4'] },
      },
    },
  };
  const perFileIR = { 'ReaderA.java': { file: 'ReaderA.java', functions: [copyFn, callerFn], topLevel: null } };
  // A real callGraph (not a hand-rolled Map) so callGraph.resolveKnownCallee
  // actually resolves the bare `copy` call to copyFn — required for the
  // interprocedural summary path under test to be reached at all.
  const callGraph = buildCallGraph(perFileIR);
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'ReaderA.java' && f.line === 8 && /sql injection/i.test(f.vuln || ''));
  assert.ok(hit, `expected executeQuery(outY) at line 8 to fire via the assign-from-call interprocedural summary's mutated-param propagation picking up copy()'s annotation-tainted q, got: ${JSON.stringify(findings.map(f => ({ line: f.line, vuln: f.vuln })))}`);
});

test('R14(a) site isolation: plain-call (mutated-param) interprocedural summary (site ~line 847) unions annotation taint independent of the base pass', () => {
  // Simulates: `void copy(@RequestParam String q, String x, String y) { y = q; }`
  // called as a bare statement (no assignment): `copy("clean", requestParamX, outY); executeQuery(outY);`
  //
  // copy() has no sink in its own body either — it only reassigns its OWN
  // param `y` from `q`, which the engine tracks as a "mutated param" at
  // function exit (v0.66's `applyAtCallSite` mechanism). The caller passes
  // a tainted value only for `x` (a decoy — copy() never reads `x`, its
  // sole purpose is to force `entryStateFromCall` to compute entry = {'x'},
  // which collides with neither the k=1 pre-pass's key (empty Set) nor the
  // k=2 pass's key (the full 3-param set). That forces THIS plain-call
  // site to freshly compute copy()'s summary; only with annotation taint
  // unioned in does `y = q` mark `y` mutated, which `applyAtCallSite` then
  // maps back onto the caller's own `outY` variable. Revert this site's
  // wiring and `q` never joins {'x'}, `y` is never marked mutated, `outY`
  // stays clean, and `executeQuery(outY)` never fires.
  const copyFn = {
    qid: 'Copier.java::Copier::copy@1',
    name: 'copy',
    line: 1,
    params: ['q', 'x', 'y'],
    paramAnnotations: [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    file: 'Copier.java',
    cfg: {
      entry: 'p1', exit: 'p3',
      nodes: {
        p1: { id: 'p1', kind: 'entry', line: 1, succ: ['p2'], pred: [] },
        p2: { id: 'p2', kind: 'assign', line: 2, succ: ['p3'], pred: ['p1'], target: 'y', source: { kind: 'ident', name: 'q' } },
        p3: { id: 'p3', kind: 'exit', line: 3, succ: [], pred: ['p2'] },
      },
    },
  };
  const callerFn = {
    qid: 'Copier.java::Copier::caller@5',
    name: 'caller',
    line: 5,
    params: [],
    file: 'Copier.java',
    cfg: {
      entry: 'c1', exit: 'c5',
      nodes: {
        c1: { id: 'c1', kind: 'entry', line: 5, succ: ['c2'], pred: [] },
        // z = request.getParameter("x")  — taints z, mapped to copy()'s
        // (unannotated) second param `x`.
        c2: {
          id: 'c2', kind: 'assign', line: 6, succ: ['c3'], pred: ['c1'],
          target: 'z',
          source: {
            kind: 'call',
            callee: { kind: 'member', object: { kind: 'ident', name: 'request' }, prop: 'getParameter' },
            args: [{ kind: 'literal', value: 'x' }],
          },
        },
        // copy("clean", z, outY)  — a PLAIN call statement, no assignment:
        // this is the code path under test (site ~line 847).
        c3: {
          id: 'c3', kind: 'call', line: 7, succ: ['c4'], pred: ['c2'],
          callee: 'copy',
          args: [{ kind: 'literal', value: 'clean' }, { kind: 'ident', name: 'z' }, { kind: 'ident', name: 'outY' }],
        },
        c4: {
          id: 'c4', kind: 'call', line: 8, succ: ['c5'], pred: ['c3'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'outY' }],
        },
        c5: { id: 'c5', kind: 'exit', line: 9, succ: [], pred: ['c4'] },
      },
    },
  };
  const perFileIR = { 'Copier.java': { file: 'Copier.java', functions: [copyFn, callerFn], topLevel: null } };
  const callGraph = buildCallGraph(perFileIR);
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'Copier.java' && f.line === 8 && /sql injection/i.test(f.vuln || ''));
  assert.ok(hit, `expected executeQuery(outY) at line 8 to fire via the plain-call interprocedural summary's mutated-param propagation picking up copy()'s annotation-tainted q, got: ${JSON.stringify(findings.map(f => ({ line: f.line, vuln: f.vuln })))}`);
});
