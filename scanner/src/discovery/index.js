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
import { loadMemory, saveMemory, rememberRun, previouslyRefuted, nextWavePlan } from './memory.js';

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
/**
 * PRD Phase 0 / C3 — the run budget.
 *
 * This pipeline is multiplicative and was, until now, unbounded. Eight focus
 * areas × seven lenses is 56 hunter calls before a single candidate exists, and
 * every surviving candidate then costs three more calls in the refutation
 * panel. Nothing capped any of it, so the cost of a run was a function of how
 * large the repository happened to be — which is not a property you want to
 * discover from an invoice.
 *
 * ENFORCED AT THE ONE SEAM EVERY CALL PASSES THROUGH. Rather than thread checks
 * through the hunter and the panel, the budget wraps `llmInvoke` itself. When
 * it is spent the wrapper throws, and both callers already treat a throwing
 * llmInvoke as ordinary degradation with a stated reason. So exhaustion arrives
 * through the same path as a rate limit or a dead endpoint, and lands in
 * `coverage.reasons` like any other coverage gap. No new failure mode.
 *
 * CALLS AND WALL CLOCK, NOT TOKENS. `llmInvoke` is an injected callback that
 * returns a string; it carries no usage metadata, so counting tokens here would
 * mean inventing a number. Calls are exactly countable and wall clock is
 * exactly observable. A caller who knows their per-call cost can pass
 * `costPerCallUsd` and get a `maxCostUsd` ceiling expressed in calls, which is
 * honest about being an estimate derived from their figure rather than ours.
 */
// Internal, not exported: the dead-module guard treats an export with no
// external call site as shipped dead code, and these are read only by
// makeBudget below. A consumer sets a ceiling by passing opts, not by importing
// a constant.
const DEFAULT_MAX_LLM_CALLS = 200;
const DEFAULT_MAX_WALL_MS = 15 * 60 * 1000;
const DEFAULT_MAX_CANDIDATES = 50;

export function makeBudget(opts = {}, now = Date.now) {
  const startedAt = now();
  let maxCalls = Number.isInteger(opts.maxLlmCalls) && opts.maxLlmCalls >= 0
    ? opts.maxLlmCalls : DEFAULT_MAX_LLM_CALLS;
  // A dollar ceiling is only meaningful with a caller-supplied per-call cost.
  // Converting it to a call count keeps one enforcement mechanism rather than
  // two that can disagree.
  if (Number.isFinite(opts.maxCostUsd) && Number.isFinite(opts.costPerCallUsd) && opts.costPerCallUsd > 0) {
    maxCalls = Math.min(maxCalls, Math.floor(opts.maxCostUsd / opts.costPerCallUsd));
  }
  const maxWallMs = Number.isInteger(opts.maxWallMs) && opts.maxWallMs > 0
    ? opts.maxWallMs : DEFAULT_MAX_WALL_MS;

  let calls = 0;
  let exhaustedReason = null;

  const check = () => {
    if (exhaustedReason) return exhaustedReason;
    if (calls >= maxCalls) return (exhaustedReason = `LLM call budget spent (${calls}/${maxCalls} calls)`);
    if (now() - startedAt >= maxWallMs) {
      return (exhaustedReason = `wall-clock budget spent (${Math.round(maxWallMs / 1000)}s)`);
    }
    return null;
  };

  return {
    get calls() { return calls; },
    get maxCalls() { return maxCalls; },
    get exhaustedReason() { return exhaustedReason; },
    spent: () => check() !== null,
    /** Wrap an llmInvoke so every call is counted and the ceiling is enforced. */
    wrap(llmInvoke) {
      if (typeof llmInvoke !== 'function') return llmInvoke;
      return async (prompt) => {
        const stop = check();
        if (stop) throw new Error(`discovery budget exhausted: ${stop}`);
        calls += 1;
        return llmInvoke(prompt);
      };
    },
  };
}

export async function runDiscovery(ctx = {}, opts = {}) {
  const areas = partitionCallGraph(ctx.callGraph, { maxAreas: opts.maxAreas ?? 8 });

  const reasons = [];
  const budget = makeBudget(opts);
  // PRD C4 — what previous runs already judged. scanRoot absent => no memory,
  // which is the correct default for a library call with nowhere to persist.
  const memory = opts.scanRoot ? loadMemory(opts.scanRoot) : null;
  // Every LLM call in this pipeline goes through this one wrapped callback.
  const llmInvoke = budget.wrap(opts.llmInvoke);

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
      const run = await runHunter(area, lens, { fileContents: ctx.fileContents || {} }, { llmInvoke });
      runs.push({ focusAreaId: run.focusAreaId, lens: run.lens, degraded: run.degraded, reason: run.reason, candidateCount: run.candidates.length });
      if (run.degraded && run.reason) reasons.push(`${area.label} × ${lens.key}: ${run.reason}`);
      if (run.degraded) areaDegradedCount += 1;
      else hunted.add(area.id);
      candidates = candidates.concat(run.candidates);
    }
    if (lenses.length > 0 && areaDegradedCount === 0) fullyHunted.add(area.id);
  }

  // PRD Phase 0 / C3.2 — the candidate cap.
  //
  // Every candidate that reaches the panel costs three more LLM calls, so an
  // unusually productive hunt multiplies straight into spend. Cap it, and
  // REPORT the cap rather than applying it silently: a run that quietly
  // examined the first N candidates and said nothing would look identical to a
  // run that found only N. Same precedent as prove-findings.js's `capped`.
  // PRD C4 — drop what a previous run already refuted, BEFORE spending the
  // panel's three calls per candidate on it again. Only refutals suppress: a
  // candidate previously judged fresh is re-reported, because it was never
  // fixed, which is the same asymmetry judge.js applies to tp/fp triage.
  let rememberedRefutals = 0;
  if (memory) {
    const before = candidates.length;
    candidates = candidates.filter(c => !previouslyRefuted(memory, c));
    rememberedRefutals = before - candidates.length;
    if (rememberedRefutals > 0) {
      reasons.push(`${rememberedRefutals} candidate(s) were refuted by an earlier run and not re-examined ` +
        '(clear with --forget-refuted if a model, ruleset or the code has changed since)');
    }
  }

  const maxCandidates = Number.isInteger(opts.maxCandidates) && opts.maxCandidates >= 0
    ? opts.maxCandidates : DEFAULT_MAX_CANDIDATES;
  let candidatesCapped = 0;
  if (candidates.length > maxCandidates) {
    candidatesCapped = candidates.length - maxCandidates;
    // Deterministic: candidates arrive in a stable (area, lens) order, so the
    // cap keeps the same prefix on every run over the same inputs.
    candidates = candidates.slice(0, maxCandidates);
    reasons.push(`candidate cap: ${candidatesCapped} candidate(s) were NOT confirmed or refuted ` +
      `(cap ${maxCandidates}); they are neither findings nor cleared — they were not examined`);
  }

  // PRD D3 — the hybrid-loop uplift measurement.
  //
  // `confirm: false` runs the pipeline with the deterministic gate switched OFF,
  // so every candidate reaches the panel as `unconfirmed`. Running a population
  // both ways and diffing the result isolates what the taint engine contributes
  // on top of the model — a number no surveyed competitor can compute, because
  // none of them has a deterministic layer to switch off.
  //
  // It exists ONLY to be measured against. It is not a performance switch, and
  // a run with it disabled is strictly weaker: severity collapses to `low` for
  // everything, since the confirmation tier is what sets it.
  const confirmationEnabled = opts.confirm !== false;
  const taintProbe = confirmationEnabled ? makeTaintProbe(ctx.perFileIR, ctx.callGraph) : null;
  if (!confirmationEnabled) {
    reasons.push('deterministic confirmation was DISABLED for this run (uplift measurement); ' +
      'every candidate is reported unconfirmed and severity is not evidence-derived');
  }
  const confirmed = await confirmAll(candidates, { taintProbe });
  const { survivors, refuted } = await disprovePanel(confirmed, { llmInvoke });
  const { fresh, duplicates, suppressed } = judgeCandidates(survivors, ctx.priorScan, ctx.triageFeedback);

  // A spent budget is a coverage gap, stated once at the top level rather than
  // left to be inferred from N identical per-run degradation reasons.
  if (budget.exhaustedReason) {
    reasons.push(`RUN INCOMPLETE — ${budget.exhaustedReason}. Work remained when the budget ran ` +
      'out, so absence of a finding below is not evidence of absence. Raise maxLlmCalls / ' +
      'maxWallMs, or narrow the scope with --root or --lens, and re-run.');
  }

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

  // PRD C4 — fold this run into the memory so the next one can be additive
  // rather than a repeat. Persistence failure is non-fatal: the report is still
  // valid, it just will not inform the next run.
  if (memory && opts.scanRoot) {
    saveMemory(opts.scanRoot, rememberRun(memory, {
      fresh, refutedCandidates: refuted,
      areas: areas.map(a => ({ id: a.id, label: a.label, files: a.files.length, hunted: hunted.has(a.id) })),
    }));
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
      // PRD Phase 0 / C3 — what the run cost and whether the budget stopped it.
      // `budgetExhausted` true means the report is INCOMPLETE by construction:
      // work remained and was not done. Reading it as a clean result is the
      // exact misreading the coverage block exists to prevent.
      // PRD C4 — what history contributed, and what to hunt next. A coverage
      // report says what happened; `nextWave` says what to do about it.
      rememberedRefutals,
      priorRuns: memory ? memory.runs : null,
      nextWave: memory ? nextWavePlan(memory, areas.map(a => ({ id: a.id, label: a.label }))) : null,
      llmCalls: budget.calls,
      maxLlmCalls: budget.maxCalls,
      budgetExhausted: Boolean(budget.exhaustedReason),
      candidatesCapped,
      reasons,
    },
  };
}
