// Per-vulnerability stability and stage attrition for an Eval Lab run (contract-driven verification, Epic C-02 and B-04).
//
// A model arm is scheduled `repeats` times over the same frozen population. For every reference defect this module records how many
// scheduled repetitions detected it, so the run answers "how consistently is this defect rediscovered?" and not only "what was the
// mean F1?". Denominators are the SCHEDULED repetitions: a repetition that timed out, errored, was blocked, unavailable, skipped for
// budget or never started (cancelled) is a scheduled non-detection, never dropped. The same figures over completed repetitions only
// are reported beside them, labelled `validRunOnly`, and never substitute for the end-to-end figures.
//
// `stableRecall` is the fraction of defects detected in at least `ceil(threshold * scheduled)` repetitions (the preregistered
// descriptive threshold, 7 of 10 by default). It is a descriptive criterion: with fewer than `minRepeatsForClaim` repetitions the
// report says so (`claim: 'descriptive-only'`), and the Wilson interval beside each frequency is the uncertainty of that frequency,
// not a statement about an underlying detection probability. Pure: no fs, no clock.
import { detectedEntryIds } from './score.js';
import { wilsonInterval } from '../interval.js';

const STABILITY_SCHEMA = 'agentic-security/eval-lab-stability';
export const DEFAULT_STABILITY_POLICY = Object.freeze({ threshold: 0.7, minRepeatsForClaim: 10 });
const ATTEMPT_STATUSES = Object.freeze(['completed', 'timeout', 'error', 'blocked', 'unavailable', 'skipped-budget', 'cancelled']);

/** How many repetitions must detect a defect for it to count as stable under the policy. */
export function stableThreshold(scheduled, threshold = DEFAULT_STABILITY_POLICY.threshold) {
  return Math.max(1, Math.ceil(threshold * scheduled));
}

/**
 * @param {object} o
 * @param {object[]} o.armPlans      [{ arm, repeats, tasks }]
 * @param {object[]} o.usable        the dataset entries that were staged
 * @param {object[]} o.attempts      every attempt record of the run (including cancelled ones)
 * @param {function} o.mapFile       (entryId, path) -> staged path
 * @param {object}  [o.policy]       { threshold, minRepeatsForClaim }
 */
export function stabilityReport({ armPlans, usable, attempts, mapFile, policy = DEFAULT_STABILITY_POLICY }) {
  const positives = usable.filter((e) => e.kind === 'vulnerable');
  const arms = [];
  for (const plan of armPlans.filter((p) => p.tasks.includes('detect'))) {
    const scheduled = plan.repeats;
    const need = stableThreshold(scheduled, policy.threshold);
    const perRepeat = [];
    for (let r = 0; r < scheduled; r++) {
      const mine = attempts.filter((a) => a.armId === plan.arm.id && a.repeat === r && a.task === 'detect');
      const byEntry = new Map(mine.map((a) => [a.entryId, a]));
      perRepeat.push({ repeat: r, detected: detectedEntryIds({ entries: usable, attempts: byEntry, mapFile }), byEntry });
    }
    const perDefect = positives.map((e) => {
      const statuses = Object.fromEntries(ATTEMPT_STATUSES.map((s) => [s, 0]));
      let detected = 0; let started = 0; let completed = 0;
      for (const rr of perRepeat) {
        const a = rr.byEntry.get(e.id);
        const status = a ? (ATTEMPT_STATUSES.includes(a.status) ? a.status : 'error') : 'cancelled';
        statuses[status] += 1;
        if (a && status !== 'cancelled' && status !== 'skipped-budget') started += 1;
        if (status === 'completed') completed += 1;
        if (rr.detected.has(e.id)) detected += 1;
      }
      return {
        entryId: e.id, cwe: e.cwe ?? null, scheduled, started, completed, detected,
        frequency: detected / scheduled, interval: wilsonInterval(detected, scheduled),
        validRunOnly: { completed, detected, frequency: completed > 0 ? detected / completed : null },
        stable: detected >= need, statuses,
      };
    });
    const n = perDefect.length;
    const union = perDefect.filter((d) => d.detected >= 1).length;
    const stable = perDefect.filter((d) => d.stable).length;
    const completion = Object.fromEntries(ATTEMPT_STATUSES.map((s) => [s, perDefect.reduce((k, d) => k + d.statuses[s], 0)]));
    arms.push({
      armId: plan.arm.id, kind: plan.arm.kind, scheduledRepeats: scheduled, threshold: policy.threshold, detectionsNeededForStable: need,
      claim: plan.arm.kind === 'deterministic' ? 'deterministic-single-run' : scheduled >= policy.minRepeatsForClaim ? 'descriptive-at-preregistered-repeats' : 'descriptive-only',
      claimNote: plan.arm.kind === 'deterministic' ? 'a deterministic arm runs once; its frequency is 0 or 1 by construction and is not a stability measurement'
        : scheduled >= policy.minRepeatsForClaim ? `${need} of ${scheduled} is the preregistered descriptive threshold; it is not a statistical claim about an underlying detection probability`
        : `${scheduled} repeat(s) is below the ${policy.minRepeatsForClaim} the stability policy asks for; the figures describe this run only`,
      defects: n,
      unionRecall: n ? union / n : null,
      stableRecall: n ? stable / n : null,
      unionInterval: wilsonInterval(union, n), stableInterval: wilsonInterval(stable, n),
      completion: { scheduledAttempts: n * scheduled, ...completion },
      perDefect,
      validRunOnly: { note: 'completed repetitions only; a diagnostic, never the end-to-end figure', unionRecall: n ? perDefect.filter((d) => d.validRunOnly.detected >= 1).length / n : null },
    });
  }
  return { schema: STABILITY_SCHEMA, policy, arms, stageAttrition: stageAttrition(attempts) };
}

/**
 * Stage attrition from what the arms recorded: the hunt arm's counters (`output.hunt`) and, in contract mode, the hunt's own
 * per-stage attrition (`output.contract.attrition`). Summed per arm; absent when the arm recorded nothing.
 */
export function stageAttrition(attempts) {
  const byArm = {};
  for (const a of attempts) {
    if (!a.output || (!a.output.hunt && !a.output.contract)) continue;
    const slot = (byArm[a.armId] ||= { attempts: 0, hunt: {}, stages: {} });
    slot.attempts += 1;
    for (const [k, v] of Object.entries(a.output.hunt || {})) if (typeof v === 'number') slot.hunt[k] = (slot.hunt[k] || 0) + v;
    for (const [stage, s] of Object.entries(a.output.contract?.attrition || {})) {
      const st = (slot.stages[stage] ||= { entered: 0, decisions: {} });
      st.entered += s.entered || 0;
      for (const [d, c] of Object.entries(s.decisions || {})) st.decisions[d] = (st.decisions[d] || 0) + c;
    }
  }
  return byArm;
}
