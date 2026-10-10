// Staged rollout policy for the assurance features (REL-002.AC01).
//
// Every feature in config.js is off by default. This module is the policy that says
// how a feature moves from "exists in the code" to "an operator may rely on it":
//
//   offline-fixtures  ->  shadow-canary  ->  opt-in-supported
//
//   offline-fixtures  The feature runs against recorded fixtures in tests only. No real target.
//   shadow-canary     It may run beside the existing behaviour on real input, but its result is
//                     RECORDED, never used: no verdict, exit code or report line changes. A canary is a
//                     named, bounded subset an operator chose.
//   opt-in-supported  An operator enabled it (config.js), the platform is supported, and every gate for
//                     the stage is met. Only here may a result change an outcome.
//
// A stage is entered only by `promote`, one step at a time, and only when every documented gate of
// the stage being entered has evidence that matches the gate's own declared reference. There is no
// way to skip a stage, to promote a feature the kill switch has stopped, or to promote on a gate
// that is merely "not failing". Nothing here runs a suite or measures anything: it judges evidence a
// caller supplies, and a gate that names a suite only accepts evidence for THAT suite.
//
// The ledger is append-only history plus a current position. `rollback` (rollback.js) moves the
// position back to the last known-good entry and appends; it never rewrites or removes history.

import { FEATURES, featureStatus } from './config.js';

const ROLLOUT_LEDGER_SCHEMA = 'agentic-security/rollout-ledger@1';
export const STAGES = Object.freeze(['offline-fixtures', 'shadow-canary', 'opt-in-supported']);

export const STAGE_MEANING = Object.freeze({
  'offline-fixtures': 'Runs against recorded fixtures in tests only; no real target is touched.',
  'shadow-canary': 'May run beside existing behaviour on real input or a named canary subset; results are recorded and never used, so no verdict, exit code or report line changes.',
  'opt-in-supported': 'An operator enabled it, the platform is supported and every gate is met; only here may a result change an outcome.',
});

// Gate evidence kinds. `suite` names a closure step (scripts/release-closure.mjs) whose recorded result is
// the evidence; `measurement` and `review` name an artifact a person or a bench produced.
const suite = (id, closureStep, statement) => ({ id, kind: 'suite', closureStep, statement });
const measure = (id, statement) => ({ id, kind: 'measurement', statement });
const review = (id, statement) => ({ id, kind: 'review', statement });

// The suite that proves each feature's offline behaviour.
const FEATURE_SUITE = Object.freeze({
  'verification-oracles': 'verification',
  'patch-negative-verification': 'verification',
  'deployment-boundaries': 'deployment',
  'invariant-scenarios': 'invariants',
  'capability-enforcement': 'capabilities',
  'model-routing': 'routing',
  'portfolio-assurance': 'portfolio',
});

// What each feature must show before opt-in. Feature specific, and quoted from the PRD's own targets
// (section 5) rather than invented here.
const OPT_IN_SPECIFIC = Object.freeze({
  'verification-oracles': [measure('oracle-conformance', 'Every advertised adapter passes positive, negative, inconclusive and tamper controls (verification-conformance-gate); unavailable prerequisites are reported unsupported')],
  'patch-negative-verification': [measure('repair-evidence-triple', 'Every advertised verified fix carries original-positive, patched-negative and functional-regression evidence bound to the exact environment, patch and oracle')],
  'deployment-boundaries': [measure('paired-ablation', 'A frozen contextual ablation shows additional confirmed defects or fewer false positives with unchanged scoring, and no lost baseline defect')],
  'invariant-scenarios': [review('contract-approval-path', 'Invariant contracts are approved by an authorized reviewer, never by the generator that proposed them')],
  'capability-enforcement': [measure('backend-probes', 'Every mandatory canary-secret and escape fixture is blocked on the advertised backend with zero canary leakage; macOS stays supervise-only')],
  'model-routing': [measure('promotion-thresholds', 'At least 200 paired adjudicated tasks overall and 30 per promoted stratum, lower 95% quality bound above -0.02, median cost 20% lower or quality 0.05 higher at no higher median cost, p95 latency within 1.2x')],
  'portfolio-assurance': [measure('interrupted-run-convergence', 'Interrupted, duplicate-delivery and incremental runs converge to a fresh scoped result with no double-counted progress')],
});

/** The documented gates for entering `stage` with `feature`. Pure and frozen. */
export function gatesFor(feature, stage) {
  if (!FEATURES[feature] || !STAGES.includes(stage)) return null;
  const own = FEATURE_SUITE[feature];
  if (stage === 'offline-fixtures') {
    return [
      suite('fixtures-green', own, `The ${own} suite passes against recorded fixtures`),
      suite('default-off-unchanged', 'foundation', 'With the feature disabled, scan and report behaviour is unchanged (configuration and kill-switch tests)'),
    ];
  }
  if (stage === 'shadow-canary') {
    return [
      suite('fixtures-green', own, `The ${own} suite still passes at the commit being promoted`),
      measure('shadow-no-outcome-change', 'A recorded shadow run on real input changed no verdict, exit code or report line'),
      suite('rollback-rehearsed', 'release-closure-suite', 'Rollback was rehearsed and restored known-good behaviour without erasing evidence'),
    ];
  }
  return [
    suite('fixtures-green', own, `The ${own} suite passes at the commit being promoted`),
    suite('compatibility-holds', 'compat-nix', 'Existing Haskell/Nix and core-language behaviour is unchanged'),
    suite('documentation-current', 'documentation-suite', 'Scope, examples and the policy card for this feature are published and drift-checked'),
    review('canary-record', 'A shadow-canary record exists with no unresolved incident'),
    ...(OPT_IN_SPECIFIC[feature] || []),
  ];
}

/** Every feature's documented gates, for documentation and drift checks. */
export function describeRollout() {
  return Object.keys(FEATURES).map((feature) => ({
    feature, risk: FEATURES[feature].risk, platforms: [...FEATURES[feature].platforms],
    stages: STAGES.map((stage) => ({ stage, meaning: STAGE_MEANING[stage], gates: gatesFor(feature, stage) })),
  }));
}

// ---------------------------------------------------------------- ledger

const DIGEST = /^(?:sha256:)?[0-9a-f]{64}$/;

export function newLedger() {
  const features = {};
  for (const id of Object.keys(FEATURES)) {
    features[id] = { stage: 'offline-fixtures', policyVersion: 1, history: [{ seq: 0, event: 'init', from: null, to: 'offline-fixtures', policyVersion: 1, knownGood: true, evidence: null }] };
  }
  return { schema: ROLLOUT_LEDGER_SCHEMA, features };
}

const clone = (x) => JSON.parse(JSON.stringify(x));

/**
 * Judge supplied evidence against the gates for entering `target`.
 * evidence: { [gateId]: { met: true, ref, digest } }. `ref` must equal the gate's own reference
 * (a suite gate accepts only its closure step id); `digest` must be a sha256.
 * -> { ok, unmet: [{ gate, reason }] }
 */
export function evaluateGates(feature, target, evidence = {}) {
  const gates = gatesFor(feature, target);
  if (!gates) return { ok: false, unmet: [{ gate: null, reason: `unknown feature '${feature}' or stage '${target}'` }] };
  const unmet = [];
  for (const g of gates) {
    const e = evidence?.[g.id];
    if (!e || e.met !== true) { unmet.push({ gate: g.id, reason: 'no evidence that the gate is met' }); continue; }
    if (typeof e.digest !== 'string' || !DIGEST.test(e.digest)) { unmet.push({ gate: g.id, reason: 'evidence carries no sha256 digest' }); continue; }
    if (g.kind === 'suite' && e.ref !== g.closureStep) { unmet.push({ gate: g.id, reason: `evidence is for '${e.ref}', not the required suite '${g.closureStep}'` }); continue; }
    if (g.kind !== 'suite' && (typeof e.ref !== 'string' || !e.ref.trim())) { unmet.push({ gate: g.id, reason: 'evidence names no artifact' }); continue; }
  }
  return { ok: unmet.length === 0, unmet };
}

/**
 * Build gate evidence from recorded closure steps (id, state, log.sha256). Only a step in state
 * `pass` produces evidence; an unsupported, incomplete or failed step produces none.
 */
export function evidenceFromSteps(steps = []) {
  const out = {};
  for (const s of steps) {
    if (s?.state !== 'pass' || !/^[0-9a-f]{64}$/.test(s.log?.sha256 || '')) continue;
    out[`step:${s.id}`] = { met: true, ref: s.id, digest: s.log.sha256 };
  }
  return out;
}

/** Fill suite-gate evidence for `feature`/`target` from closure-step evidence; other kinds come from `extra`. */
export function assembleEvidence(feature, target, stepEvidence = {}, extra = {}) {
  const out = { ...extra };
  for (const g of gatesFor(feature, target) || []) {
    if (g.kind === 'suite' && stepEvidence[`step:${g.closureStep}`]) out[g.id] = stepEvidence[`step:${g.closureStep}`];
  }
  return out;
}

/**
 * Move one feature up one stage. Returns a NEW ledger; the input is never mutated.
 * Refuses: an unknown feature, skipping a stage, standing still, any unmet gate, and a feature the
 * kill switch has stopped (config given) or an unsupported platform for opt-in.
 */
export function promote(ledger, feature, evidence, { config = null } = {}) {
  const cur = ledger?.features?.[feature];
  if (!cur) return { ok: false, ledger, blockers: [{ gate: null, reason: `unknown feature '${feature}'` }] };
  const at = STAGES.indexOf(cur.stage);
  if (at === STAGES.length - 1) return { ok: false, ledger, blockers: [{ gate: null, reason: 'already at the final stage' }] };
  const target = STAGES[at + 1];
  const blockers = [];
  if (config) {
    const st = featureStatus(config, feature);
    if (st.code === 'kill-switch') blockers.push({ gate: null, reason: `the kill switch is set (${st.reason}); a stopped feature is not promoted` });
    if (target === 'opt-in-supported' && st.code === 'platform-unsupported') blockers.push({ gate: null, reason: st.reason });
  }
  const g = evaluateGates(feature, target, evidence);
  blockers.push(...g.unmet);
  if (blockers.length) return { ok: false, ledger, blockers };
  const next = clone(ledger);
  const f = next.features[feature];
  // Monotonic over the whole history: a version number is never reused after a rollback, so a record
  // produced under a rolled-back policy can never be mistaken for one produced under a later policy.
  const policyVersion = Math.max(...cur.history.map((h) => h.policyVersion)) + 1;
  f.history.push({ seq: f.history.length, event: 'promote', from: cur.stage, to: target, policyVersion, knownGood: true, evidence: clone(evidence) });
  f.stage = target; f.policyVersion = policyVersion;
  return { ok: true, ledger: next, blockers: [] };
}

/**
 * How a feature behaves given its configuration AND its stage. Below opt-in a feature that an operator
 * enabled still only runs in the stage's mode, and says so.
 *   'off'          disabled, killed, invalid or unsupported: inert
 *   'fixtures'     offline-fixtures: the code path is fixtures-only; a real run is refused
 *   'shadow'       shadow-canary: run, record, never change an outcome
 *   'active'       opt-in-supported: results may change an outcome
 */
export function effectiveMode(config, ledger, feature) {
  const st = featureStatus(config, feature);
  if (st.status !== 'ok') return { mode: 'off', stage: ledger?.features?.[feature]?.stage ?? null, reason: st.reason, code: st.code };
  const stage = ledger?.features?.[feature]?.stage;
  if (!stage) return { mode: 'off', stage: null, reason: 'the feature has no rollout record, so it has not passed any gate', code: 'no-rollout-record' };
  if (stage === 'offline-fixtures') return { mode: 'fixtures', stage, reason: 'enabled, but the feature has not passed the shadow-canary gates; it runs against fixtures only', code: 'below-stage' };
  if (stage === 'shadow-canary') return { mode: 'shadow', stage, reason: 'enabled, but at shadow-canary: results are recorded and never change an outcome', code: 'below-stage' };
  return { mode: 'active', stage, reason: 'enabled at opt-in-supported', code: null };
}
