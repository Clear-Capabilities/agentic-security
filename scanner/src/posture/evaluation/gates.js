// Real-code quality gates over a frozen protocol (section 5 of the programme PRD).
//
// This module can answer `pass` ONLY when every population minimum is met by
// real, independently adjudicated, non-synthetic labels inside the sealed split,
// AND the measured value clears the threshold registered in the protocol. In
// every other case it answers `insufficient-population` or `unmeasured`, with the
// reason. It never answers `pass` for a smaller convenient sample, for synthetic
// data, or for a threshold it was handed by the caller: thresholds are read from
// the protocol, and a protocol that fails its hash check is rejected outright.
//
// The statuses are deliberately not boolean: `unmeasured` is not `fail`, and
// neither is a pass.

import { validateProtocol, CORE_LANGUAGES } from './protocol.js';
import { isScoreable } from './labels.js';
import { groupTargets } from './grouping.js';
import { groupedBootstrap, f1Of } from './interval.js';

export const GATE_STATUSES = Object.freeze(['pass', 'fail', 'insufficient-population', 'unmeasured']);

const gate = (id, status, extra = {}) => ({ id, status, ...extra });

/**
 * @param {object} o
 * @param {object} o.protocol  frozen protocol (thresholds and splits come from here)
 * @param {object} o.score     a score (score.js) of the SEALED split of a run bound to this protocol
 * @param {object[]} o.defects all defect labels
 * @param {object[]} o.negatives all negative labels
 * @param {object} [o.run]      the sealed-split run record the score came from; enables the integrity gates (leaks, denominator)
 * @param {object} [o.baseline] the last verified release score; enables the no-regression gate
 */
export function evaluateGates({ protocol, score, defects = [], negatives = [], run = null, baseline = null }) {
  const v = validateProtocol(protocol);
  if (!v.ok) return { ok: false, rejected: true, errors: v.errors, overall: 'rejected', gates: [] };
  if (score && score.protocolHash !== protocol.protocolHash) {
    return { ok: false, rejected: true, errors: [{ code: 'PROTOCOL_MISMATCH', path: 'score.protocolHash', message: 'the score was produced under a different protocol; it cannot be judged against these thresholds' }], overall: 'rejected', gates: [] };
  }
  const t = protocol.thresholds;
  const gates = [];
  const sealed = new Set(protocol.splits.sealed);

  const realD = defects.filter((l) => isScoreable(l) && !l.synthetic && sealed.has(l.targetId));
  const realN = negatives.filter((l) => isScoreable(l) && !l.synthetic && sealed.has(l.targetId));
  const count = (xs, key, val) => xs.filter((x) => x[key] === val).length;
  const shortfalls = [];
  for (const lang of CORE_LANGUAGES) {
    const p = count(realD, 'language', lang); const n = count(realN, 'language', lang);
    if (p < t.minPositivesPerCoreLanguage) shortfalls.push(`${lang}: ${p}/${t.minPositivesPerCoreLanguage} positives`);
    if (n < t.minNegativesPerCoreLanguage) shortfalls.push(`${lang}: ${n}/${t.minNegativesPerCoreLanguage} negatives`);
  }
  const familyShort = [...new Set(protocol.scope.families)].filter((f) => count(realD, 'family', f) < t.minPositivesPerFamily);
  const populationOk = shortfalls.length === 0 && familyShort.length === 0;
  const popDetail = {
    reason: protocol.synthetic
      ? 'the protocol is synthetic: a synthetic population can exercise the machinery and can never satisfy a real-code gate'
      : `population minimums not met: ${shortfalls.slice(0, 6).join('; ')}${shortfalls.length > 6 ? `; and ${shortfalls.length - 6} more` : ''}${familyShort.length ? `; ${familyShort.length} famil${familyShort.length === 1 ? 'y' : 'ies'} below ${t.minPositivesPerFamily} sealed positives` : ''}`,
    realSealedPositives: realD.length, realSealedNegatives: realN.length,
  };
  const blocked = protocol.synthetic || !populationOk || !score;
  const unmet = (id, threshold) => gate(id, score ? 'insufficient-population' : 'unmeasured', {
    threshold, measured: null, ...(score ? popDetail : { reason: 'no sealed-split score exists' }),
  });

  const e2e = score?.endToEnd;
  const decide = (id, threshold, measured, cmp = (m, th) => m >= th) => {
    if (blocked) return unmet(id, threshold);
    if (measured === null || measured === undefined) return gate(id, 'unmeasured', { threshold, measured: null, reason: 'value undefined on this population' });
    return gate(id, cmp(measured, threshold) ? 'pass' : 'fail', { threshold, measured });
  };

  gates.push(decide('overall-micro-f1', t.overallMicroF1, e2e?.micro?.f1));
  gates.push(decide('overall-macro-f1', t.overallMacroF1, e2e?.macroF1));
  gates.push(decide('pooled-precision', t.pooledPrecision, e2e?.micro?.precision));
  gates.push(decide('pooled-recall', t.pooledRecall, e2e?.micro?.recall));
  gates.push(decide('completion', t.completion, score?.completion?.rate));
  for (const lang of CORE_LANGUAGES) gates.push(decide(`per-language-f1:${lang}`, t.perLanguageF1, e2e?.byLanguage?.[lang]?.f1 ?? null));
  gates.push(lowerBoundGate({ protocol, score, blocked, popDetail }));
  for (const g of integrityGates({ protocol, score, run, defects, negatives })) gates.push(g);
  if (baseline) gates.push(regressionGate({ score, baseline, blocked, popDetail }));

  const overall = gates.every((g) => g.status === 'pass') ? 'pass'
    : gates.some((g) => g.status === 'fail') ? 'fail'
      : gates.some((g) => g.status === 'insufficient-population') ? 'insufficient-population' : 'unmeasured';
  return { ok: true, rejected: false, errors: [], protocolHash: protocol.protocolHash, synthetic: protocol.synthetic, overall, gates, population: popDetail };
}

// ---------------------------------------------------------------- the interval gate

/** The lowest per-language F1 lower bound (grouped bootstrap) against the registered bound. Unmeasured, never assumed. */
function lowerBoundGate({ protocol, score, blocked, popDetail }) {
  const id = 'per-language-f1-lower-bound';
  const threshold = protocol.thresholds.perLanguageF1LowerBound;
  if (!score) return gate(id, 'unmeasured', { threshold, measured: null, reason: 'no sealed-split score exists' });
  if (blocked) return gate(id, 'insufficient-population', { threshold, measured: null, reason: popDetail.reason });
  if (!score.perTarget || typeof score.perTarget !== 'object') return gate(id, 'unmeasured', { threshold, measured: null, reason: 'the score carries no per-target tallies, so no grouped interval can be computed' });
  const { groupOf } = groupTargets(protocol.targets);
  const units = Object.entries(score.perTarget).map(([tid, c]) => ({ id: tid, ...c }));
  const perLanguage = {};
  for (const lang of CORE_LANGUAGES) {
    perLanguage[lang] = groupedBootstrap({
      units: units.filter((u) => u.language === lang), groupOf, statistic: (a) => f1Of(a.total), name: `lang:${lang}:f1`, protocolHash: protocol.protocolHash,
    });
  }
  const measured = Object.values(perLanguage).filter((iv) => iv.status === 'measured');
  const unmeasured = Object.entries(perLanguage).filter(([, iv]) => iv.status !== 'measured');
  const lows = measured.map((iv) => iv.low);
  const min = lows.length ? Math.min(...lows) : null;
  const detail = Object.fromEntries(Object.entries(perLanguage).map(([l, iv]) => [l, { status: iv.status, low: iv.low, high: iv.high, groups: iv.groups }]));
  if (min !== null && min < threshold) return gate(id, 'fail', { threshold, measured: min, method: protocol.thresholds.intervalMethod, perLanguage: detail, reason: 'at least one language has an F1 lower bound under the registered bound' });
  if (unmeasured.length) return gate(id, 'unmeasured', { threshold, measured: min, method: protocol.thresholds.intervalMethod, perLanguage: detail, reason: `${unmeasured.length} language${unmeasured.length === 1 ? '' : 's'} without enough independent groups for an interval: ${unmeasured.slice(0, 4).map(([l]) => l).join(', ')}` });
  return gate(id, 'pass', { threshold, measured: min, method: protocol.thresholds.intervalMethod, perLanguage: detail });
}

// ---------------------------------------------------------------- integrity gates

const LEAK_REASON = /leakage control/i;

/** Gates that judge the evaluation's own integrity. They are measurable on any population, so they never read insufficient-population. */
function integrityGates({ protocol, score, run, defects, negatives }) {
  // Without a run record there is nothing to check; release-gate.js refuses to produce a release verdict without one.
  if (!run) return [];
  const leaks = (run.outcomes || []).filter((o) => o.status === 'quarantined' && LEAK_REASON.test(o.failureReason || ''));
  const out = [gate('answer-key-leaks', leaks.length === 0 ? 'pass' : 'fail', { threshold: 0, measured: leaks.length, ...(leaks.length ? { reason: `${leaks.length} target workspace(s) carried label or answer-key material`, targets: leaks.map((o) => o.targetId).sort() } : {}) })];

  // The denominator is the frozen population, not whatever the run happened to cover.
  const problems = [];
  if (run.protocolHash !== protocol.protocolHash) problems.push('run is bound to a different protocol');
  const have = new Set((run.outcomes || []).map((o) => `${o.targetId}|${o.variant}`));
  for (const t of protocol.targets.filter((x) => protocol.splits.sealed.includes(x.id))) {
    if (!have.has(`${t.id}|pre`)) problems.push(`sealed target ${t.id} has no pre outcome`);
    if (t.postCommit && !have.has(`${t.id}|post`)) problems.push(`sealed target ${t.id} has no post outcome`);
  }
  const sealed = new Set(protocol.splits.sealed);
  const positives = defects.filter((l) => isScoreable(l) && sealed.has(l.targetId)).length;
  const negs = negatives.filter((l) => isScoreable(l) && sealed.has(l.targetId)).length;
  if (score?.endToEnd?.micro && Number.isFinite(score.endToEnd.micro.tp)) {
    const m = score.endToEnd.micro;
    if (m.tp + m.fn !== positives) problems.push(`scored positives ${m.tp + m.fn} differ from the ${positives} adjudicated sealed positives`);
    const negScored = m.tn + m.fp;
    const failed = (score.negativeFailures || []).length;
    if (Array.isArray(score.negativeFailures) && negScored + failed < negs && negScored + failed !== negs) problems.push(`scored negatives ${negScored + failed} differ from the ${negs} adjudicated sealed negatives`);
  }
  out.push(gate('denominator-intact', problems.length === 0 ? 'pass' : 'fail', { threshold: null, measured: problems.length, ...(problems.length ? { reason: problems.slice(0, 5).join('; '), problems: problems.slice(0, 20) } : {}) }));
  return out;
}

/** Compare to the last VERIFIED release score; a drop in micro F1 or in any language's F1 fails. */
function regressionGate({ score, baseline, blocked, popDetail }) {
  const id = 'no-regression-vs-baseline';
  const cur = score?.endToEnd; const base = baseline?.endToEnd;
  if (!cur || !base) return gate(id, 'unmeasured', { threshold: 'baseline', measured: null, reason: 'a score or a baseline is missing' });
  const regressions = [];
  const cmp = (name, c, b) => { if (typeof c === 'number' && typeof b === 'number' && c < b) regressions.push({ name, baseline: b, current: c }); };
  cmp('micro-f1', cur.micro?.f1, base.micro?.f1);
  cmp('micro-precision', cur.micro?.precision, base.micro?.precision);
  cmp('micro-recall', cur.micro?.recall, base.micro?.recall);
  for (const [lang, b] of Object.entries(base.byLanguage || {})) cmp(`f1:${lang}`, cur.byLanguage?.[lang]?.f1, b?.f1);
  if (regressions.length) return gate(id, 'fail', { threshold: 'baseline', measured: regressions.length, regressions, reason: 'the current engine scores below the recorded baseline' });
  if (blocked) return gate(id, 'insufficient-population', { threshold: 'baseline', measured: null, reason: popDetail.reason });
  return gate(id, 'pass', { threshold: 'baseline', measured: 0 });
}
