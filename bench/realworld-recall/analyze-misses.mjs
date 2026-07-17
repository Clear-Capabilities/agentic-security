// Addition #6 — self-improving recall harness: the MISS-ANALYZER.
//
// PURE, I/O-free. For a known vulnerability the scanner FAILED to surface, this
// pinpoints the earliest pipeline stage that dropped it and proposes a concrete
// rule/detector/prompt change to close the gap. This is the "self-improving"
// half of the harness: every miss becomes an actionable, stage-attributed TODO
// instead of an anonymous recall dip.
//
// STAGE MODEL. Findings flow through an ordered pipeline; a miss is attributed
// to the FIRST stage whose signal says the data never made it through:
//   recon-entrypoint → detector → taint → posture-filter → proof-gate
// The caller passes the ordered stage list, so the ordering (and even the stage
// names) can evolve without touching this module — attribution is by keyword
// against whatever list is supplied, walked in order so the earliest failure
// wins.
//
// SIGNALS. The miss object carries whatever observability the runner could
// gather. Recognised booleans (all optional):
//   entrypointFound:false | fileScanned:false | reachedStage:'none'  → recon
//   detectorFired:false   | candidateEmitted:false                    → detector
//   taintConnected:false  | taintReached:false                        → taint
//   postureFiltered:true  | suppressed:true                           → posture-filter
//   proofFailed:true      | demotedUnreachable:true | unreachable:true→ proof-gate
// With no signal at all it falls back to a plausible default (the detector
// stage — the most common real-world recall gap) so the output is never empty.

export const DEFAULT_STAGES = ['recon-entrypoint', 'detector', 'taint', 'posture-filter', 'proof-gate'];

// Each concept: the keywords that identify its stage in a supplied stage list,
// and the predicate over miss metadata that says "the finding died here".
const STAGE_CONCEPTS = [
  { keys: ['recon', 'entrypoint', 'entry', 'crawl', 'discover'],
    test: (m) => m.entrypointFound === false || m.fileScanned === false || m.reachedStage === 'none' },
  { keys: ['detector', 'detect', 'rule', 'pattern', 'sast'],
    test: (m) => m.detectorFired === false || m.candidateEmitted === false || m.candidateAtLocation === false },
  { keys: ['taint', 'dataflow', 'flow'],
    test: (m) => m.taintConnected === false || m.taintReached === false },
  { keys: ['posture', 'filter', 'suppress', 'dedupe'],
    test: (m) => m.postureFiltered === true || m.suppressed === true },
  { keys: ['proof', 'reachab', 'gate', 'validate'],
    test: (m) => m.proofFailed === true || m.demotedUnreachable === true || m.unreachable === true },
];

function conceptForStage(stage) {
  const s = String(stage || '').toLowerCase();
  return STAGE_CONCEPTS.find((c) => c.keys.some((k) => s.includes(k))) || null;
}

/**
 * Analyze one miss.
 *   analyzeMiss(miss, { stages }) → { missId, lostAtStage, proposedFix }
 * `stages` is the ordered pipeline (defaults to DEFAULT_STAGES). Deterministic.
 */
export function analyzeMiss(miss, { stages } = {}) {
  const m = (miss && typeof miss === 'object') ? miss : {};
  const missId = m.id || m.finding_id || m.missId || 'unknown';
  const stageList = Array.isArray(stages) && stages.length ? stages : DEFAULT_STAGES;

  // Walk the pipeline in order; the earliest stage whose signal fires owns the miss.
  let lostAtStage = null;
  for (const stage of stageList) {
    const concept = conceptForStage(stage);
    if (concept && concept.test(m)) { lostAtStage = stage; break; }
  }

  // No explicit signal → honour an explicit hint, else default to the detector
  // stage (or the earliest available), so attribution is never empty.
  if (!lostAtStage) lostAtStage = fallbackStage(m, stageList);

  return { missId, lostAtStage, proposedFix: proposeFix(lostAtStage, m) };
}

function fallbackStage(m, stageList) {
  const hint = m.lostAtStage || m.stage;
  if (hint && stageList.includes(hint)) return hint;
  const detector = stageList.find((s) => /detect|rule|pattern|sast/i.test(s));
  if (detector) return detector;
  return stageList[Math.min(1, stageList.length - 1)] || stageList[0] || 'detector';
}

/** A short, concrete, stage-appropriate remediation suggestion. Never empty. */
function proposeFix(stage, m) {
  const s = String(stage || '').toLowerCase();
  const type = m.type || m.family || m.class || 'the vuln class';
  const loc = m.location || m.file || 'the affected module';
  if (/recon|entry|crawl|discover/.test(s)) {
    return `recon-entrypoint: extend entrypoint discovery to reach ${loc} (teach the crawler its framework/route convention) so ${type} sinks there are scanned at all.`;
  }
  if (/detect|rule|pattern|sast/.test(s)) {
    return `detector: add or broaden a detector rule for ${type} — the sink at ${loc} matched no pattern. Author a SAST rule + vulnerable/clean fixture per scanner/src/sast/CLAUDE.md.`;
  }
  if (/taint|flow/.test(s)) {
    return `taint: model the missing source→sink flow for ${type} at ${loc} (register the source/sink/sanitizer signatures) so the taint engine connects the path.`;
  }
  if (/posture|filter|suppress|dedupe/.test(s)) {
    return `posture-filter: a ${type} candidate at ${loc} was emitted then suppressed — review the posture annotator/dedupe rule that demoted it and relax the over-eager filter.`;
  }
  if (/proof|reachab|gate|validate/.test(s)) {
    return `proof-gate: the reachability/proof gate demoted ${type} at ${loc} as unreachable — a false-negative in the reachability model; revisit its call-graph assumptions.`;
  }
  return `${stage}: investigate the ${stage} stage for the ${type} miss at ${loc} and add coverage.`;
}
