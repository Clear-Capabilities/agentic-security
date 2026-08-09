//
// Compose the discovery pipeline:
//
//   partition → (area × lens) hunters → confirm → disprove → judge
//
// COVERAGE IS PART OF THE OUTPUT. Every report states how many areas were
// planned versus hunted and how many runs degraded, with reasons. A discovery
// pass that half failed and reports "no findings" is indistinguishable from a
// clean codebase unless it says so.
import { partitionCallGraph } from './partition.js';
import { LENSES, lensByKey } from './lenses.js';
import { runHunter } from './hunter.js';
import { confirmAll } from './confirm.js';
import { disprovePanel } from './disprove.js';
import { judgeCandidates } from './judge.js';

// Bridge a candidate to the deterministic layer. A taint finding at or within
// two lines of the candidate corroborates it; a modelled sink on the line
// without a full path is weaker corroboration ("sink-adjacent").
//
// NOTE: `runDeepAnalysis(perFileIR, callGraph, opts)` returns a BARE ARRAY of
// findings (see scanner/src/dataflow/index.js), not an object with a
// `.findings` property. Treat anything else defensively.
export function makeTaintProbe(perFileIR, callGraph) {
  let cache = null;
  return async (candidate) => {
    if (!callGraph || !perFileIR) return null;
    try {
      if (!cache) cache = runDeepAnalysisSafe(perFileIR, callGraph);
      const deep = await cache;
      if (!Array.isArray(deep)) return null;
      const hits = deep.filter(f => f.file === candidate.file);
      const exact = hits.find(f => Math.abs((f.line ?? -1) - candidate.line) <= 2);
      if (exact) {
        return { tier: 'taint-confirmed', evidence: { matchedFinding: exact.id ?? null, line: exact.line, vuln: exact.vuln ?? null } };
      }
      return hits.length ? { tier: 'sink-adjacent', evidence: { sameFileFindings: hits.length } } : null;
    } catch {
      return null;
    }
  };
}

async function runDeepAnalysisSafe(perFileIR, callGraph) {
  try {
    const { runDeepAnalysis } = await import('../dataflow/index.js');
    return runDeepAnalysis(perFileIR, callGraph, {});
  } catch {
    return null;
  }
}

// ctx = { perFileIR, callGraph, fileContents, priorScan, triageFeedback }
// where { perFileIR, callGraph } come from buildProjectIR(fileContents),
// which returns { perFile, callGraph } — callers must pass perFile as
// perFileIR (see scanner/src/ir/index.js).
export async function runDiscovery(ctx = {}, opts = {}) {
  const areas = partitionCallGraph(ctx.callGraph, { maxAreas: opts.maxAreas ?? 8 });

  const reasons = [];

  // An explicit array (including an empty one) is honoured exactly — a caller
  // narrowing a run to no lenses must get no lenses, not a silent fallback to
  // all seven. Only an absent/non-array value falls back to the full set.
  const lensKeys = Array.isArray(opts.lenses) ? opts.lenses : LENSES.map(l => l.key);

  const lenses = [];
  for (const key of lensKeys) {
    const lens = lensByKey(key);
    // An unknown key must degrade visibly, not vanish via a silent filter.
    if (lens) lenses.push(lens);
    else reasons.push(`unresolved lens key: "${key}"`);
  }
  if (lenses.length === 0) {
    reasons.push('no lenses resolved for this run (empty or fully-unresolved lens selection); nothing was hunted');
  }

  const runs = [];
  let candidates = [];
  // areasHunted: areas where AT LEAST ONE lens run completed without degrading.
  const hunted = new Set();
  // areasFullyHunted: areas where EVERY lens run completed without degrading.
  // Distinct from areasHunted so a partially-degraded area (e.g. 6 of 7 lenses
  // failed) cannot be read as fully covered from a single number.
  const fullyHunted = new Set();

  for (const area of areas) {
    let areaDegradedCount = 0;
    for (const lens of lenses) {
      const run = await runHunter(area, lens, { fileContents: ctx.fileContents || {} }, { llmInvoke: opts.llmInvoke });
      runs.push({ focusAreaId: run.focusAreaId, lens: run.lens, degraded: run.degraded, reason: run.reason, candidateCount: run.candidates.length });
      if (run.degraded && run.reason) reasons.push(`${area.label} × ${lens.key}: ${run.reason}`);
      if (run.degraded) areaDegradedCount += 1;
      else hunted.add(area.id);
      candidates = candidates.concat(run.candidates);
    }
    if (lenses.length > 0 && areaDegradedCount === 0) fullyHunted.add(area.id);
  }

  const taintProbe = makeTaintProbe(ctx.perFileIR, ctx.callGraph);
  const confirmed = await confirmAll(candidates, { taintProbe });
  const { survivors, refuted } = await disprovePanel(confirmed, { llmInvoke: opts.llmInvoke });
  const { fresh, duplicates, suppressed } = judgeCandidates(survivors, ctx.priorScan, ctx.triageFeedback);

  // Coverage must not stop at the hunter stage. `confirm.js` correctly never
  // lowers a candidate below `unconfirmed`, and `disprove.js` correctly lets
  // a candidate survive when no voter votes — each rule is right on its own,
  // but composed, a run where BOTH later stages died silently would still
  // report clean hunter coverage while 100% of raw, uncorroborated model
  // output landed in `fresh`. These counters and reasons make that visible.
  const confirmedByTier = { 'taint-confirmed': 0, 'sink-adjacent': 0, 'unconfirmed': 0 };
  for (const c of confirmed) {
    const tier = c?.confirmation?.tier;
    if (tier && Object.prototype.hasOwnProperty.call(confirmedByTier, tier)) confirmedByTier[tier] += 1;
  }
  if (confirmed.length > 0 && confirmedByTier['taint-confirmed'] === 0 && confirmedByTier['sink-adjacent'] === 0) {
    reasons.push(`confirmation stage corroborated nothing for ${confirmed.length} candidate(s) — all remain "unconfirmed"; the deterministic gate may not have run, and the findings below are uncorroborated, not vetted`);
  }

  const panelled = [...survivors, ...refuted];
  const panelsRun = panelled.length;
  const undecidedPanels = panelled.filter(c => c?.refutation?.undecided === true).length;
  if (panelsRun > 0 && undecidedPanels === panelsRun) {
    reasons.push(`refutation panel returned no votes for any of ${panelsRun} candidate(s) — every finding below survived unrefuted, not because it withstood scrutiny`);
  }

  return {
    schema: 'agentic-security/discovery@1',
    focusAreas: areas.map(a => ({ id: a.id, label: a.label, files: a.files.length, size: a.size })),
    runs,
    fresh,
    duplicates,
    suppressed,
    // `refutedCandidates` holds RAW candidates straight from `disprovePanel`,
    // NOT findings — no `vuln`, `severity`, `parser`, or `stableId`. It is
    // deliberately not run through `toFindingShape`: a refuted candidate is
    // deliberately not promoted to a finding, and giving it finding shape
    // would misrepresent it as one. Unlike `fresh`/`duplicates`/`suppressed`,
    // do not iterate this array as if it were finding-shaped.
    refutedCandidates: refuted,
    coverage: {
      areasPlanned: areas.length,
      // At least one lens run completed for the area. Does NOT mean every
      // lens succeeded there — see areasFullyHunted for that stronger claim.
      areasHunted: hunted.size,
      // Every lens run for the area completed without degrading.
      areasFullyHunted: fullyHunted.size,
      lensesPerArea: lenses.length,
      degradedRuns: runs.filter(r => r.degraded).length,
      // Per-tier count of every candidate that went through confirm.js.
      confirmedByTier,
      // How many candidates went through the refutation panel, and how many
      // of those came back with no votes at all (undecided, not refuted).
      panelsRun,
      undecidedPanels,
      reasons,
    },
  };
}
