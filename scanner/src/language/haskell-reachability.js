// Project-reachability adjudication of Haskell taint findings.
//
// `haskell-ir.js` `projectReachability` stamps every function with `hs.reachability {status, rootKind, holeReason}`: could any caller exist, judged from
// the project's entry points over the call graph? This module reads that verdict for the function a taint finding was found in and records it on the
// finding as `reachability {status, reason, premise, roots, holeReason}`. It is a SEPARATE record from `trustBoundary`: that one answers who controls
// the input, this one answers whether a caller can exist, and either may be `unknown` independently.
//
//   status        entrypoint-reachable | unreachable-in-project | external-api | unknown
//   premise       what the finding's own claim rests on:
//                   caller-controlled-parameter   the only origin recorded is the assumption that an untrusted caller supplies a parameter of
//                                                 an exported function (the weak label, `hs:caller-controlled`)
//                   recorded-read                 a real environment, command-line, file, standard-input, socket or request read is on the chain
//
// What the verdict does to the finding:
//   unreachable-in-project and premise caller-controlled-parameter   the premise is withdrawn (an entry-point-rooted walk over a hole-free graph says
//                                                 there is no caller at all): lowered to `info`, never dropped (`lowerFinding`, `_reachLowered`)
//   unreachable-in-project and premise recorded-read   NOT lowered. "Nothing calls this" is a claim about a call graph in a language where typeclass
//                                                 dispatch, re-exports and point-free aliasing routinely defeat call graphs; being wrong costs a real
//                                                 vulnerability, so it may cost rank (`posture/relevance.js` reads `f.reachability`) and not visibility
//   unknown, external-api, entrypoint-reachable   nothing happens to the severity
//
// Nothing here reads a comment, a name or a path: the inputs are the call-graph verdict and the origins the taint engine recorded.

import { lowerFinding, originClasses } from './haskell-trust.js';

const HS_FILE = /\.(?:l?hs|hsc)$/i;

const fnByQid = (perFile, qid) => {
  if (!qid) return null;
  const file = String(qid).split('::')[0];
  const ir = perFile && perFile[file];
  return ir ? ir.functions.find((x) => x.qid === qid) || null : null;
};

const REASONS = Object.freeze({
  'entrypoint-reachable': 'a call path from a project entry point reaches the function',
  'external-api': 'the function belongs to a module the package exposes, so its callers are outside the analysed code',
  'unreachable-in-project': 'no entry point of the project reaches the function through the call graph (complete scan, hole-free graph, a main and a manifest present, module not exposed)',
});
const HOLE_TEXT = Object.freeze({
  'partial-scan': 'the scan covered only part of the project',
  'policy-excluded': 'Haskell sources were kept out of the scan by the path policy',
  'size-skipped': 'Haskell sources were too large to read',
  'no-entrypoint': 'the analysed files contain no `main`, so there is no entry point to walk from',
  'no-manifest': 'no manifest says which modules the package exposes',
  'parse-failure': 'a declaration could not be read, so its calls are missing from the graph',
  'function-cap': 'functions past the per-file cap are not in the graph',
  'opaque-boundary': 'Template Haskell, a quasi-quote, a foreign export, a build step that generates code or a source format the IR does not read can call functions the graph does not show',
  'unresolved-call': 'a function reachable from an entry point makes a call the IR could not resolve',
  'instance-method': 'an instance method can be invoked by anything that can see its type',
  'unresolved-route': 'a route registration could not be resolved',
});

/** What the finding's own claim rests on (see the header). `null` when the recorded origins do not settle it. */
function premiseOf(f) {
  const { roots, classes } = originClasses(f);
  if (!roots.length) return null;
  if ([...classes].every((c) => c === 'weak-param')) return 'caller-controlled-parameter';
  if ([...classes].some((c) => c === 'operator' || c === 'external' || c === 'data')) return 'recorded-read';
  return null;
}

/**
 * Stamps `reachability` on every Haskell IR-TAINT finding that has a verdict for its function, and lowers to `info` the ones whose only premise
 * (a caller-controlled parameter) the verdict withdraws. Mutates the findings; returns counts.
 */
export function applyHaskellReachability(findings, perFile) {
  const stats = { 'entrypoint-reachable': 0, 'unreachable-in-project': 0, 'external-api': 0, unknown: 0, lowered: 0, rankOnly: 0, unstamped: 0 };
  for (const f of findings || []) {
    if (!f || f.parser !== 'IR-TAINT' || !HS_FILE.test(String(f.file || ''))) continue;
    const fn = fnByQid(perFile, f._funcQid);
    const r = fn && fn.hs && fn.hs.reachability;
    if (!r || !r.status) { stats.unstamped++; continue; }
    const premise = premiseOf(f);
    const reason = r.status === 'unknown' ? (HOLE_TEXT[r.holeReason] || 'the call graph cannot settle it') : REASONS[r.status];
    f.reachability = { status: r.status, reason, premise, roots: r.rootKind ? [r.rootKind] : [], holeReason: r.holeReason || null };
    stats[r.status] = (stats[r.status] || 0) + 1;
    if (r.status !== 'unreachable-in-project') continue;
    if (premise === 'caller-controlled-parameter') {
      if (lowerFinding(f, { kind: 'unreachable-in-project', reason: 'the finding rests on a caller of an exported function supplying a parameter, and nothing in the project can call it', controlKind: 'no-caller-in-project', guard: '_reachLowered', keepNote: true })) stats.lowered++;
    } else if (premise === 'recorded-read') stats.rankOnly++;
  }
  return stats;
}
