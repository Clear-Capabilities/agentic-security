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
  const lensKeys = Array.isArray(opts.lenses) && opts.lenses.length ? opts.lenses : LENSES.map(l => l.key);
  const lenses = lensKeys.map(lensByKey).filter(Boolean);

  const runs = [];
  const reasons = [];
  let candidates = [];
  const hunted = new Set();

  for (const area of areas) {
    for (const lens of lenses) {
      const run = await runHunter(area, lens, { fileContents: ctx.fileContents || {} }, { llmInvoke: opts.llmInvoke });
      runs.push({ focusAreaId: run.focusAreaId, lens: run.lens, degraded: run.degraded, reason: run.reason, candidateCount: run.candidates.length });
      if (run.degraded && run.reason) reasons.push(`${area.label} × ${lens.key}: ${run.reason}`);
      if (!run.degraded) hunted.add(area.id);
      candidates = candidates.concat(run.candidates);
    }
  }

  const taintProbe = makeTaintProbe(ctx.perFileIR, ctx.callGraph);
  const confirmed = await confirmAll(candidates, { taintProbe });
  const { survivors, refuted } = await disprovePanel(confirmed, { llmInvoke: opts.llmInvoke });
  const { fresh, duplicates, suppressed } = judgeCandidates(survivors, ctx.priorScan, ctx.triageFeedback);

  return {
    schema: 'agentic-security/discovery@1',
    focusAreas: areas.map(a => ({ id: a.id, label: a.label, files: a.files.length, size: a.size })),
    runs,
    fresh,
    duplicates,
    suppressed,
    refuted,
    coverage: {
      areasPlanned: areas.length,
      areasHunted: hunted.size,
      lensesPerArea: lenses.length,
      degradedRuns: runs.filter(r => r.degraded).length,
      reasons,
    },
  };
}
