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
import { SummaryCache } from '../src/dataflow/summaries.js';

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
// Task-2 fix round 2 CORRECTION: fix round 1 also claimed sites 1
// (`_nestedCallReturnTainted`) and 8 (higher-order callback) were
// impossible to isolate. Both claims were WRONG — a scoped re-review
// found real, isolable channels for both, which fix round 2 adds tests
// for below. The mistake in both cases was the same: `_mergeSummaryFindings`
// merges the callee's own `sum.findings` into the CALLER's finding set
// UNCONDITIONALLY, regardless of `sum.returnTainted` — a channel entirely
// separate from the returnTainted-based reasoning that (correctly) ruled
// out a *different* signal at site 1, and from the "cbFn is independently
// re-analyzed anyway" reasoning that (correctly, but incompletely) applied
// only to cbFn's *own* file-attributed finding at site 8, not to the
// separate merge-into-the-caller channel. See the two new tests near the
// end of this file for the corrected, empirically-verified fixtures.
//
// Sites still believed NOT achievable in the current architecture, after
// the round-2 correction (documented rather than silently skipped, per the
// fix-round instructions):
//
//   - Class-field cross-taint pass (site 5, entries keyed by a Set of
//     `_this_.<field>` access-path strings): those cache entries are only
//     ever WRITTEN (`summaryCache.set(fn.qid, fields, …)`), never read back
//     by any other call site in engine.js. `entryStateFromCall` and the
//     higher-order callback's `cbEntry` only ever produce sets of bare
//     parameter names, never `_this_.`-prefixed strings, so no real call
//     site's own computed entry can ever collide with a `fields` key and
//     retrieve what this pass cached. The pass's own header comment claims
//     these findings are surfaced "when a REAL call site … consults this
//     qid+entry" — grepping the file shows nothing does. (Per the fix-round-2
//     coordinator note: this is a known, pre-existing, unrelated dead-code
//     bug that predates this plan and is out of scope to fix here — left
//     exactly as wired.)
//   - k=2 pass (site 6, `taintedEntry = new Set(fn.params)` — every
//     declared param, simultaneously): `matchAnnotationParams` can only ever
//     return a SUBSET of `fn.params` (annotations attach to real params), so
//     `_unionAnnotationTaint(fn, new Set(fn.params))` can never add anything
//     not already in the set — the union is a mathematical no-op at this
//     one call site by construction, for every possible fixture. This is
//     the one claim in this file provable algebraically, not just
//     empirically — an actual revert-and-rerun (twice: once against the
//     round-1 fixtures, once against the round-2 site-1/8 fixtures) still
//     backs it up.
//
// (Every claim above — including the round-2 correction — was verified
// empirically, not just by reading: each site was reverted alone, one at a
// time, and the relevant fixture re-run — see the fix-round report for the
// exact commands and results, including the counter-evidence for sites 1
// and 8 that overturned round 1's conclusion.)

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

// ─────────────────────────────────────────────────────────────────────────
// Task-2 fix round 2 (second-round task review). A scoped re-review found
// that round 1's "sites 1 and 8 are impossible to isolate" conclusions were
// WRONG: both rulings only considered the `returnTainted` propagation
// channel, but `_nestedCallReturnTainted` (site 1) and the higher-order
// callback path (site 8) BOTH also call `_mergeSummaryFindings`
// UNCONDITIONALLY — merging the callee's own `sum.findings` into the
// CALLER's finding set regardless of whether `sum.returnTainted` is true.
// That is a second, independent channel round 1 never considered, and it
// turns out to be genuinely isolable at both sites.
//
// A methodological note, stated plainly because it bit round 1 already
// once this same investigation (see the long comment on the first test in
// this file, about the discarded return-taint design for site 2): writing
// a fixture that *looks* like it isolates a site, and reverting that one
// site to confirm the EXISTING 4 tests still pass, only proves those 4
// tests don't cover it — it does NOT prove no channel exists. Both of the
// new tests below were validated the opposite way: build the NEW fixture
// first, confirm it fails when its OWN target site is reverted, THEN
// confirm it still passes when every OTHER site is reverted one at a time.
// Both directions were run for both new tests below (8 reverts each,
// 16 total) before this file was finalized.
test('R14(a) site isolation: nested-call-in-sink-argument interprocedural summary (site ~line 284) merges the callee\'s OWN findings into the caller independent of the base pass', () => {
  // Simulates:
  //   AMain.java: public void run() { stmt.executeQuery(helper("clean")); }
  //   ZHelper.java: public String helper(String a, @RequestParam String q) {
  //     stmt.executeQuery(q); return a;
  //   }
  //
  // helper()'s call is NESTED directly inside the outer sink's own argument
  // list (`executeQuery(helper(...))`), which is exactly `step()`'s 'call'
  // case reaching `_matchCallCatalog` -> `exprTaint` -> (arg is itself a
  // 'call' expr) -> `_nestedCallReturnTainted`, site ~line 284. The nested
  // call's own argument ("clean") is a literal, so `entryStateFromCall`
  // computes an EMPTY entry — deliberately, to avoid the OTHER bug this
  // investigation already found once (see the site-2 test's comment): any
  // caller-tainted argument here would ALSO trip `exprTaint`'s own
  // args-tainted short-circuit a few lines up, which is a real, SEPARATE,
  // and still-real reason a *return-taint*-based fixture can't isolate this
  // site — but that reasoning never applied to the findings-MERGE channel
  // this test actually exercises, since `_mergeSummaryFindings` runs
  // regardless of the short-circuit or of `returnTainted`.
  //
  // `AMain` is named to sort ALPHABETICALLY BEFORE `ZHelper` — `fnList` in
  // `runTaintEngine` is qid-sorted, so the k=1 pre-pass's OWN per-function
  // loop reaches `AMain.run` first. Walking `AMain.run`'s body hits this
  // nested call, and — since nothing has cached `(helper.qid, empty-Set)`
  // yet at that point — THIS call site's own `compute()` is what populates
  // it for the very first time, merging helper()'s sink finding into
  // `AMain.run`'s own finding set right then. (The k=1 pre-pass's LATER
  // top-level pass over `ZHelper.helper` itself does not undo this: it
  // reports its OWN, separately-attributed finding for `ZHelper.java`, and
  // — as it happens — the two rulings on whether to re-cache that same
  // empty-Set slot depend on `returnTainted`/`mutatedParams` staying
  // unchanged, which held in exploratory testing but is NOT what this
  // assertion depends on. This test intentionally checks the FINAL
  // findings array, not the cache, for exactly that reason — see the next
  // test's comment for why the cache-based assertion form is safe there
  // but was empirically found UNSAFE for this particular fixture: a
  // same-key race with the k=1 pre-pass's own write means a cache check
  // here would sometimes read a value clobbered by an unrelated site's
  // revert, which is a false signal in the opposite direction from what a
  // regression test must never produce.)
  //
  // Per the fix-round-2 coordinator note: there is a known, pre-existing,
  // unrelated bug where a merged cross-file finding is reported under the
  // CALLER's file but the CALLEE's line. That bug is out of scope here —
  // this assertion only checks for the PRESENCE of an AMain.java-attributed
  // finding (the caller-side merge channel), not its exact line, so it is
  // unaffected by that bug either way.
  const helperFn = {
    qid: 'ZHelper.java::ZHelper::helper@2',
    name: 'helper',
    line: 2,
    params: ['a', 'q'],
    paramAnnotations: [{ index: 1, name: 'q', decorator: 'RequestParam' }],
    file: 'ZHelper.java',
    cfg: {
      entry: 'h1', exit: 'h3',
      nodes: {
        h1: { id: 'h1', kind: 'entry', line: 2, succ: ['h2'], pred: [] },
        h2: {
          id: 'h2', kind: 'call', line: 3, succ: ['h3'], pred: ['h1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        h3: { id: 'h3', kind: 'exit', line: 4, succ: [], pred: ['h2'] },
      },
    },
  };
  const callerFn = {
    qid: 'AMain.java::AMain::run@2',
    name: 'run',
    line: 2,
    params: [],
    file: 'AMain.java',
    cfg: {
      entry: 'c1', exit: 'c3',
      nodes: {
        c1: { id: 'c1', kind: 'entry', line: 2, succ: ['c2'], pred: [] },
        // stmt.executeQuery(helper("clean"))  — the outer sink's own
        // argument is a NESTED CALL to helper(): the code path under test.
        c2: {
          id: 'c2', kind: 'call', line: 3, succ: ['c3'], pred: ['c1'],
          callee: 'executeQuery',
          args: [{
            kind: 'call',
            callee: { kind: 'ident', name: 'helper' },
            args: [{ kind: 'literal', value: 'clean' }],
          }],
        },
        c3: { id: 'c3', kind: 'exit', line: 4, succ: [], pred: ['c2'] },
      },
    },
  };
  const perFileIR = {
    'AMain.java': { file: 'AMain.java', functions: [callerFn], topLevel: null },
    'ZHelper.java': { file: 'ZHelper.java', functions: [helperFn], topLevel: null },
  };
  const callGraph = buildCallGraph(perFileIR);
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hasCallerSideFinding = findings.some(f => f.file === 'AMain.java');
  const hasCalleeSideFinding = findings.some(f => f.file === 'ZHelper.java');
  assert.ok(hasCalleeSideFinding,
    `sanity check: ZHelper.java's own direct annotation-sourced flow must still be reported (base/k=1 pass, unrelated to this site) — got: ${JSON.stringify(findings.map(f => ({ file: f.file, line: f.line, vuln: f.vuln })))}`);
  assert.ok(hasCallerSideFinding,
    `expected the nested-call-in-sink-argument interprocedural summary to merge ZHelper.helper's own annotation-sourced finding into AMain.run's finding set, got: ${JSON.stringify(findings.map(f => ({ file: f.file, line: f.line, vuln: f.vuln })))}`);
});

test('R14(a) site isolation: higher-order callback interprocedural summary (site ~line 1395) merges the callback\'s OWN findings into the caller independent of the base pass', () => {
  // Simulates:
  //   Main.java: public void run() {
  //     List<String> items = request.getParameter("list");
  //     items.forEach(this::handler);
  //   }
  //   Cb.java: public void handler(String item, @RequestParam String q) {
  //     stmt.executeQuery(q);
  //   }
  //
  // `handler` has TWO params: `item` (index 0, the higher-order-injected
  // array-element param — `cbEntry` is always `new Set([cbFn.params[0]])`,
  // a SINGLE-element set) and `q` (index 1, annotated). With only one param
  // (as an earlier, disproved draft of this test used), `cbEntry` — {item}
  // — would be IDENTICAL to the k=2 pass's own cache key for a one-param
  // function (`new Set(fn.params)`), so k=2's pre-existing correct
  // computation would satisfy this site's `summaryCache.get()` as a cache
  // HIT and this site's own `compute()` — the code actually under test —
  // would never run at all, masking whatever this site's wiring does. The
  // second (unannotated, unused-by-the-fixture) param exists purely to
  // make `cbEntry` ({item}, size 1) a DIFFERENT key from k=2's
  // ({item,q}, size 2), forcing a genuine cache miss and a fresh compute.
  //
  // Unlike the site-1 test above, this assertion form directly inspects
  // the SummaryCache (passed in via `opts.summaryCache` so it survives past
  // the call) rather than the final findings array — empirically confirmed
  // safe here (unlike the site-1 fixture) because `cbEntry` never collides
  // with any OTHER pass's cache key for `handler` (k=1 uses the empty Set,
  // k=2 uses the full 2-param set), so nothing else ever writes to this
  // specific cache slot to race with or clobber it.
  const cbFn = {
    qid: 'Cb.java::Cb::handler@2',
    name: 'handler',
    line: 2,
    params: ['item', 'q'],
    paramAnnotations: [{ index: 1, name: 'q', decorator: 'RequestParam' }],
    file: 'Cb.java',
    cfg: {
      entry: 'b1', exit: 'b3',
      nodes: {
        b1: { id: 'b1', kind: 'entry', line: 2, succ: ['b2'], pred: [] },
        b2: {
          id: 'b2', kind: 'call', line: 3, succ: ['b3'], pred: ['b1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        b3: { id: 'b3', kind: 'exit', line: 4, succ: [], pred: ['b2'] },
      },
    },
  };
  const callerFn = {
    qid: 'Main.java::Main::run@2',
    name: 'run',
    line: 2,
    params: [],
    file: 'Main.java',
    cfg: {
      entry: 'c1', exit: 'c4',
      nodes: {
        c1: { id: 'c1', kind: 'entry', line: 2, succ: ['c2'], pred: [] },
        // items = request.getParameter("list")  — a genuine Java catalog
        // source, taints `items` (the higher-order receiver).
        c2: {
          id: 'c2', kind: 'assign', line: 3, succ: ['c3'], pred: ['c1'],
          target: 'items',
          source: {
            kind: 'call',
            callee: { kind: 'member', object: { kind: 'ident', name: 'request' }, prop: 'getParameter' },
            args: [{ kind: 'literal', value: 'list' }],
          },
        },
        // items.forEach(handler)  — by-reference callback on a tainted
        // receiver: triggers the `_higherOrderInvocations` push and, from
        // there, this test's target call site.
        c3: {
          id: 'c3', kind: 'call', line: 4, succ: ['c4'], pred: ['c2'],
          callee: { kind: 'member', object: { kind: 'ident', name: 'items' }, prop: 'forEach' },
          args: [{ kind: 'ident', name: 'handler' }],
        },
        c4: { id: 'c4', kind: 'exit', line: 5, succ: [], pred: ['c3'] },
      },
    },
  };
  const perFileIR = {
    'Main.java': { file: 'Main.java', functions: [callerFn], topLevel: null },
    'Cb.java': { file: 'Cb.java', functions: [cbFn], topLevel: null },
  };
  const callGraph = buildCallGraph(perFileIR);
  const summaryCache = new SummaryCache();
  const findings = runTaintEngine(perFileIR, callGraph, { summaryCache });
  const cached = summaryCache.get(cbFn.qid, new Set(['item']));
  assert.ok(cached, 'expected the higher-order call site to have computed and cached a summary for handler() under entry {item}');
  assert.equal(cached.findings.length, 2,
    `expected handler()'s own executeQuery(q) finding(s) to ride on the {item}-keyed summary (annotation taint unioned into cbEntry), got: ${JSON.stringify(cached.findings.map(f => f.vuln))}`);
  // Sanity: the callback's own direct annotation-sourced flow must also
  // still be independently reported (base/k=1 pass, unrelated to this site).
  assert.ok(findings.some(f => f.file === 'Cb.java'),
    `sanity check: Cb.java's own direct annotation-sourced flow must still be reported, got: ${JSON.stringify(findings.map(f => ({ file: f.file, line: f.line, vuln: f.vuln })))}`);
});
