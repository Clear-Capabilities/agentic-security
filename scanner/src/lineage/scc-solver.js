// Recursive-component solver for the lineage driver (DAG-01, R01.3 to R01.5).
//
// Pure: no I/O, no clock of its own (a budget is an injected callback), and
// no import of any analysis engine. `driver.js` supplies the per-function
// analysis; tests supply synthetic transfer functions.
//
// ## Fact domain (R01.4)
//
// A function summary is a finite set of facts:
//   - `ret:<dataElementId>`                 the return value carries the id
//   - `mut:<paramPath>:<dataElementId>`     the parameter access path
//                                           `paramPath` is mutated to carry
//                                           the id
// The id universe is the set of data-element ids that appear in the entry
// states of the analyzed contexts and the program text (finite per run). The
// path universe is the set of syntactic parameter access paths, additionally
// BOUNDED by `maxPathDepth` (default 6 segments): a deeper path is folded to
// its depth-bounded prefix, which only adds the id to a coarser path (an
// over-approximation) and is recorded as the widening reason
// `path-depth-cap`.
//
// ## Join and monotonicity
//
// The join is set union per fact family. The solver stores
// `next = join(previous, analyze(previous))`, so the per-function summary
// sequence is an ascending chain in a finite lattice whether or not the
// underlying analysis is itself monotone. An ascending chain over a finite
// lattice stabilizes, so the iteration terminates; `maxRounds` is a second,
// independent safety bound. A fixed point reached here is the least fixed
// point of the joined transfer function, which is exactly what a naive
// exhaustive iteration to stability computes (the reference solver in the
// tests).
//
// ## What converged means
//
// `converged: true` means a full round changed no member summary AND at least
// two rounds ran (round one is compared with the bottom seed, which is not an
// analysis result). It does not mean the program is safe: summaries
// under-approximate whatever the analysis does not model. If a budget stops
// the iteration, a round cap is hit, or a member is never analyzed, the
// result is `converged: false` with the remaining frontier listed, and the
// last iterate must be treated as partial, never as a conservative proof.

function cmp(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

export const DEFAULT_MAX_PATH_DEPTH = 6;
export const DEFAULT_MAX_ROUNDS = 32;
export const DEFAULT_MAX_CHANGED_FACTS = 1000;

function foldPath(path, maxDepth) {
  const segs = String(path).split('.');
  if (segs.length <= maxDepth) return null;
  return segs.slice(0, maxDepth).join('.');
}

// Joins two field-identity summaries. Returns `{ summary, reasons }`.
// `reasons` lists widening reasons applied by this join (deterministic order).
export function joinFieldSummaries(prev, next, opts = {}) {
  const maxDepth = opts.maxPathDepth ?? DEFAULT_MAX_PATH_DEPTH;
  const reasons = new Set();
  const returnFlat = new Set(prev ? prev.returnFlat : []);
  for (const id of next.returnFlat) returnFlat.add(id);

  const mutatedParams = new Map();
  const addMut = (path, ids) => {
    const folded = foldPath(path, maxDepth);
    const key = folded ?? path;
    if (folded !== null) reasons.add('path-depth-cap');
    let set = mutatedParams.get(key);
    if (!set) { set = new Set(); mutatedParams.set(key, set); }
    for (const id of ids) set.add(id);
  };
  if (prev) for (const [p, ids] of prev.mutatedParams) addMut(p, ids);
  for (const [p, ids] of next.mutatedParams) addMut(p, ids);

  const returnByPath = new Map();
  for (const src of [prev && prev.returnByPath, next.returnByPath]) {
    if (!src) continue;
    for (const [p, ids] of src) {
      const set = returnByPath.get(p) ?? new Set();
      for (const id of ids) set.add(id);
      returnByPath.set(p, set);
    }
  }
  const summary = { returnFlat, returnByPath, mutatedParams, widenings: next.widenings ?? [] };
  if (next.degradedReason) summary.degradedReason = next.degradedReason;
  return { summary, reasons: [...reasons].sort(cmp) };
}

export function fieldFacts(summary) {
  const out = [];
  if (!summary) return out;
  for (const id of summary.returnFlat) out.push(`ret:${id}`);
  for (const [p, ids] of summary.mutatedParams) for (const id of ids) out.push(`mut:${p}:${id}`);
  return out.sort(cmp);
}

export function bottomFieldSummary() {
  return { returnFlat: new Set(), returnByPath: new Map(), mutatedParams: new Map(), widenings: [] };
}

function factsEqual(a, b) {
  const fa = fieldFacts(a);
  const fb = fieldFacts(b);
  if (fa.length !== fb.length) return false;
  for (let i = 0; i < fa.length; i++) if (fa[i] !== fb[i]) return false;
  return true;
}

// Solves one recursive component.
//
//   members            sorted qids in the component
//   analyze(qid)       runs one analysis of `qid` against the currently
//                      published summaries and returns a RAW summary
//   publish(qid, s)    makes `s` the summary other members will read
//   bottom(qid)        initial summary (default: empty)
//   beforeRound(round) hook, called before each round
//   shouldStop()       returns a reason string to stop, or a falsy value
//   maxRounds, maxPathDepth, maxChangedFacts   bounds
//
// Returns { converged, rounds, changedFacts, changedFactsTotal,
//           changedFactsTruncated, wideningReasons, stoppedBy,
//           remainingFrontier, summaries }.
export function solveRecursiveComponent(args) {
  const members = [...args.members].sort(cmp);
  const maxRounds = args.maxRounds ?? DEFAULT_MAX_ROUNDS;
  const maxChanged = args.maxChangedFacts ?? DEFAULT_MAX_CHANGED_FACTS;
  const bottom = args.bottom || (() => bottomFieldSummary());
  const current = new Map();
  for (const q of members) {
    const b = bottom(q);
    current.set(q, b);
    args.publish(q, b);
  }
  const reasons = new Set();
  const changedFacts = [];
  let changedTotal = 0;
  let rounds = 0;
  let converged = false;
  let stoppedBy = null;
  let analyzedThisRound = new Set();

  while (rounds < maxRounds) {
    rounds++;
    if (args.beforeRound) args.beforeRound(rounds);
    let changedInRound = false;
    analyzedThisRound = new Set();
    for (const q of members) {
      const stop = args.shouldStop ? args.shouldStop() : null;
      if (stop) { stoppedBy = stop; break; }
      const prev = current.get(q);
      const raw = args.analyze(q);
      analyzedThisRound.add(q);
      const { summary: joined, reasons: rs } = joinFieldSummaries(prev, raw, { maxPathDepth: args.maxPathDepth });
      for (const r of rs) reasons.add(r);
      if (!factsEqual(prev, joined)) {
        changedInRound = true;
        const before = new Set(fieldFacts(prev));
        for (const f of fieldFacts(joined)) {
          if (before.has(f)) continue;
          changedTotal++;
          if (changedFacts.length < maxChanged) changedFacts.push({ round: rounds, qid: q, fact: f });
        }
      }
      current.set(q, joined);
      args.publish(q, joined);
    }
    if (stoppedBy) { rounds = analyzedThisRound.size === 0 && rounds > 0 ? rounds - 1 : rounds; break; }
    if (!changedInRound && rounds >= 2) { converged = true; break; }
  }
  if (!converged && !stoppedBy && rounds >= maxRounds) {
    reasons.add('round-cap');
    stoppedBy = 'round-cap';
  }
  return {
    converged,
    rounds,
    changedFacts,
    changedFactsTotal: changedTotal,
    changedFactsTruncated: changedTotal > changedFacts.length,
    wideningReasons: [...reasons].sort(cmp),
    stoppedBy,
    remainingFrontier: converged ? [] : members.slice(),
    summaries: current,
  };
}
