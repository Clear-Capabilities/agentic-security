// PHP cross-file `include`/`require` scope merging.
//
// SARD_80_F1 W5.7 — root-caused in W5.5: PHP's `include`/`require`/
// `include_once`/`require_once` was previously modeled PURELY as a CWE-98
// (LFI/RFI) SINK (`__php_include__` in parser-php.js, checked for a tainted
// PATH argument) — the included FILE'S OWN top-level variable assignments
// were never parsed and merged into the including file's scope. Real PHP
// semantics: an `include`d file's top-level code executes IN THE CALLER'S
// OWN VARIABLE SCOPE (unlike an ordinary function call, which gets its own
// local scope) — so a two-file split (`source.php`: `$tainted =
// $_GET['x'];` / `main.php`: `include "source.php"; sink($tainted);`) is
// genuinely, structurally invisible to a taint engine that treats `include`
// as an opaque sink call. Confirmed via the SARD PHP generator's own public
// source (`stivalet/PHP-Vuln-test-suite-generator`), which can emit any
// test case's source/sanitizer/construction component as its OWN separate
// file connected via exactly this shape.
//
// This module runs AFTER buildProjectIR's per-file parse loop (both the
// sync and async builders — PHP needs neither Java's async parser nor
// per-language ordering, so one shared post-pass covers both) and mutates
// each PHP file's `topLevel` function's CFG in place: for every
// `__php_include__` call site whose path argument is a LITERAL string that
// resolves to another file already in `perFile`, the included file's own
// top-level ASSIGN nodes are cloned and spliced into the includer's CFG
// immediately before the include call site.
//
// Deliberately scoped, matching W5.5's own stated caution:
//  - Only LITERAL include paths are resolved. A dynamic/conditional path
//    (`include $_GET['page'] . '.php';`) is left entirely alone — untainted
//    for taint purposes) — over-approximating scope-merging content we
//    genuinely can't rule out for a target we can't even name.
//  - Control flow INSIDE the included file is flattened to a straight-line
//    sequence of its own assign nodes (in CFG-order from its own entry),
//    the same "over-approximate rather than model precisely" tradeoff this
//    taint model already makes elsewhere (recall-preserving: a value that
//    MIGHT be tainted along some path in the included file becomes
//    unconditionally tainted after the splice, never LESS tainted than
//    reality).
//  - The include call node ITSELF is kept, unchanged, after the spliced
//    chain — its own path-argument taint check (the pre-existing CWE-98
//    sink) still runs exactly as before. This module is purely additive.
//  - Cycle-guarded (a visited-file set per top-level merge) and depth-capped
//    (`maxDepth`), so a mutual-include pair or a long chain can't recurse
//    unboundedly.
//  - Node IDs are per-file counters (reset to `pn1`, `pn2`, ... for every
//    file parsed), so every cloned node gets a fresh, namespaced ID — never
//    naively reusing the source file's own IDs, which would collide with
//    the includer's own nodes or a second include of the same file.
//
// Known, accepted tradeoff: if the includer and the included file happen to
// use the SAME variable name for unrelated purposes, the splice can taint
// the includer's own pre-existing variable of that name. This mirrors the
// real PHP semantics being modeled (an actual `include` really does share
// the variable namespace), so it is not a modeling error — genuine
// real-world PHP code that reuses generic names across included files has
// exactly this exposure at runtime too.

import path from 'node:path';

let _mergeCounter = 0;

// Test-only reset so the namespace counter doesn't leak between test files.
export function _resetPhpIncludeMergeCounter() {
  _mergeCounter = 0;
}

function _literalPathOf(argExpr) {
  if (!argExpr || argExpr.kind !== 'literal' || typeof argExpr.value !== 'string') return null;
  const v = argExpr.value;
  const m = /^(["'])((?:[^\\]|\\.)*)\1$/.exec(v);
  if (!m) return null;
  // Unescape the handful of sequences PHP double-quoted strings support in
  // a bare filename; single-quoted strings only ever need `\\` and `\'`.
  return m[2].replace(/\\(.)/g, '$1');
}

// Candidate resolved paths for a literal include argument, relative to the
// includer's own directory (PHP's `include` resolves relative to the
// including SCRIPT'S directory by default, absent an include_path entry —
// exactly the SARD generator's own convention, a bare sibling filename).
function _resolveCandidates(includerFile, literalPath) {
  if (!literalPath || path.posix.isAbsolute(literalPath)) return [];
  const dir = path.posix.dirname(includerFile.replace(/\\/g, '/'));
  const joined = path.posix.normalize(path.posix.join(dir, literalPath));
  const candidates = [joined];
  if (!/\.(?:php|phtml)$/i.test(joined)) candidates.push(`${joined}.php`);
  return candidates;
}

// BFS node-id order from `cfg.entry`, so cloned assign nodes preserve the
// included file's own true execution order. Cycle-safe (a `seen` set) even
// though a straight-line module CFG should never actually cycle.
function _orderedNodeIds(cfg) {
  const order = [];
  const seen = new Set();
  const queue = [cfg.entry];
  while (queue.length) {
    const id = queue.shift();
    if (!id || seen.has(id) || !cfg.nodes[id]) continue;
    seen.add(id);
    order.push(id);
    for (const s of cfg.nodes[id].succ || []) queue.push(s);
  }
  return order;
}

function _link(nodes, src, dst) {
  if (!nodes[src] || !nodes[dst]) return;
  if (!nodes[src].succ.includes(dst)) nodes[src].succ.push(dst);
  if (!nodes[dst].pred.includes(src)) nodes[dst].pred.push(src);
}

function _topLevelFn(ir) {
  if (!ir || !ir.topLevel) return null;
  return (ir.functions || []).find((f) => f.qid === ir.topLevel) || null;
}

function _mergeIncludesInFunction(fn, currentFile, perFile, visited, depthLeft) {
  if (!fn || !fn.cfg || depthLeft <= 0) return;
  const cfg = fn.cfg;
  // Snapshot node ids up front — the loop body adds new nodes to cfg.nodes,
  // and those must not themselves be re-scanned for (nonexistent) includes.
  const ids = Object.keys(cfg.nodes);
  for (const id of ids) {
    const node = cfg.nodes[id];
    if (!node || node.kind !== 'call' || node.callee !== '__php_include__') continue;
    const literalPath = _literalPathOf((node.args || [])[0]);
    if (!literalPath) continue; // dynamic/non-literal include path — out of scope, never mistaint
    const candidates = _resolveCandidates(currentFile, literalPath);
    const targetFile = candidates.find((c) => perFile[c]);
    if (!targetFile || visited.has(targetFile)) continue;
    const targetFn = _topLevelFn(perFile[targetFile]);
    if (!targetFn || !targetFn.cfg) continue;

    // Recurse into the included file's OWN includes first, so a transitive
    // chain (A includes B, B includes C) sees C's assignments merged into
    // B before B's are cloned into A.
    const nextVisited = new Set(visited);
    nextVisited.add(targetFile);
    _mergeIncludesInFunction(targetFn, targetFile, perFile, nextVisited, depthLeft - 1);

    const srcOrder = _orderedNodeIds(targetFn.cfg).filter(
      (nid) => targetFn.cfg.nodes[nid].kind === 'assign',
    );
    if (!srcOrder.length) continue;

    _mergeCounter++;
    const ns = `phpinc${_mergeCounter}_`;
    const clones = srcOrder.map((nid) => {
      const orig = targetFn.cfg.nodes[nid];
      const cloneId = ns + nid;
      cfg.nodes[cloneId] = {
        kind: 'assign',
        line: orig.line,
        target: orig.target,
        source: orig.source,
        succ: [],
        pred: [],
      };
      return cloneId;
    });
    for (let i = 0; i < clones.length - 1; i++) _link(cfg.nodes, clones[i], clones[i + 1]);

    // Splice the clone chain in BEFORE the include call node: every current
    // predecessor of the call node now points at the chain's first clone
    // instead, and the chain's last clone points at the (unchanged) call
    // node, whose own pred is reset to just that.
    for (const p of [...node.pred]) {
      const predNode = cfg.nodes[p];
      if (!predNode) continue;
      predNode.succ = predNode.succ.map((s) => (s === id ? clones[0] : s));
      if (!cfg.nodes[clones[0]].pred.includes(p)) cfg.nodes[clones[0]].pred.push(p);
    }
    _link(cfg.nodes, clones[clones.length - 1], id);
    node.pred = [clones[clones.length - 1]];
  }
}

// Mutates every PHP file's `topLevel` function's CFG in place. Call once,
// after every file in the project has already been parsed into `perFile`
// (both `buildProjectIR` and `buildProjectIRAsync` share this one pass).
export function mergePhpIncludes(perFile, opts = {}) {
  const maxDepth = opts.maxDepth ?? 4;
  for (const [file, ir] of Object.entries(perFile || {})) {
    if (!/\.(?:php|phtml)$/i.test(file)) continue;
    const fn = _topLevelFn(ir);
    if (!fn) continue;
    _mergeIncludesInFunction(fn, file, perFile, new Set([file]), maxDepth);
  }
}
