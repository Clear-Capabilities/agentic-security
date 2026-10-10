// REL-002.AC01: rollout progresses from offline fixtures to shadow/canary to opt-in supported execution
// using documented gates for each feature.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { FEATURES, resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import {
  STAGES, STAGE_MEANING, gatesFor, describeRollout, newLedger, evaluateGates, promote, effectiveMode, evidenceFromSteps, assembleEvidence,
} from '../../src/posture/assurance/rollout.js';
import { CLOSURE_STEPS } from '../../../scripts/release-closure.mjs';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO } from '../helpers/closure-fixtures.js';

const D = 'a'.repeat(64);
const features = Object.keys(FEATURES);
const cfg = (env = {}, overrides = {}, platform = 'darwin') => resolveAssuranceConfig({ scanRoot: mkTestTmp('rollout-'), env, overrides, platform });

/** Evidence that satisfies every gate of `stage` for `feature`. */
function fullEvidence(feature, stage) {
  const out = {};
  for (const g of gatesFor(feature, stage)) out[g.id] = { met: true, ref: g.kind === 'suite' ? g.closureStep : `artifact-for-${g.id}`, digest: D };
  return out;
}

test('[REL-002.AC01] every feature has documented gates for each stage, and the stages are exactly offline, shadow-canary, opt-in', () => {
  assert.deepEqual([...STAGES], ['offline-fixtures', 'shadow-canary', 'opt-in-supported']);
  for (const s of STAGES) assert.ok(STAGE_MEANING[s].length > 20);
  const closureIds = new Set(CLOSURE_STEPS.map((s) => s.id));
  for (const f of features) {
    for (const stage of STAGES) {
      const gates = gatesFor(f, stage);
      assert.ok(gates.length >= 2, `${f}/${stage} has gates`);
      assert.equal(new Set(gates.map((g) => g.id)).size, gates.length, `${f}/${stage}: gate ids are unique`);
      for (const g of gates) {
        assert.ok(g.statement.length > 20, `${f}/${stage}/${g.id} states its condition`);
        assert.ok(['suite', 'measurement', 'review'].includes(g.kind));
        if (g.kind === 'suite') assert.ok(closureIds.has(g.closureStep), `${g.id} names a real closure step (${g.closureStep})`);
      }
    }
    assert.ok(gatesFor(f, 'opt-in-supported').length > gatesFor(f, 'offline-fixtures').length, `${f}: opt-in is the strictest stage`);
  }
  assert.equal(gatesFor('no-such-feature', 'shadow-canary'), null);
  assert.equal(gatesFor(features[0], 'no-such-stage'), null);
  assert.equal(describeRollout().length, features.length);
});

test('[REL-002.AC01] a feature progresses one stage at a time and only with every gate met', () => {
  let ledger = newLedger();
  for (const f of features) assert.equal(ledger.features[f].stage, 'offline-fixtures', 'every feature starts offline');
  const f = 'verification-oracles';
  let r = promote(ledger, f, fullEvidence(f, 'shadow-canary'));
  assert.equal(r.ok, true, JSON.stringify(r.blockers));
  assert.equal(r.ledger.features[f].stage, 'shadow-canary');
  assert.equal(ledger.features[f].stage, 'offline-fixtures', 'the input ledger is not mutated');
  ledger = r.ledger;
  r = promote(ledger, f, fullEvidence(f, 'opt-in-supported'));
  assert.equal(r.ok, true, JSON.stringify(r.blockers));
  assert.equal(r.ledger.features[f].stage, 'opt-in-supported');
  assert.deepEqual(r.ledger.features[f].history.map((h) => h.event), ['init', 'promote', 'promote']);
  assert.deepEqual(r.ledger.features[f].history.map((h) => h.policyVersion), [1, 2, 3]);
  assert.equal(promote(r.ledger, f, {}).ok, false, 'nothing past the final stage');
  assert.match(promote(r.ledger, f, {}).blockers[0].reason, /final stage/);
});

test('[REL-002.AC01] a promotion is refused when any gate is missing, not met, for the wrong suite, undigested or unnamed', () => {
  const f = 'capability-enforcement';
  const ledger = newLedger();
  const good = fullEvidence(f, 'shadow-canary');
  assert.equal(promote(ledger, f, good).ok, true, 'control: complete evidence promotes');
  const cases = {
    'a missing gate': (e) => { delete e['shadow-no-outcome-change']; },
    'a gate not met': (e) => { e['shadow-no-outcome-change'].met = false; },
    'a suite gate with another suite\'s evidence': (e) => { e['fixtures-green'].ref = 'routing'; },
    'evidence with no digest': (e) => { delete e['rollback-rehearsed'].digest; },
    'evidence with a malformed digest': (e) => { e['rollback-rehearsed'].digest = 'trust-me'; },
    'a measurement with no artifact': (e) => { e['shadow-no-outcome-change'].ref = ''; },
    'met: "yes" instead of true': (e) => { e['fixtures-green'].met = 'yes'; },
  };
  for (const [label, mutate] of Object.entries(cases)) {
    const e = JSON.parse(JSON.stringify(good));
    mutate(e);
    const r = promote(ledger, f, e);
    assert.equal(r.ok, false, `${label} blocks`);
    assert.ok(r.blockers.length >= 1);
    assert.equal(r.ledger, ledger, 'a refused promotion returns the ledger untouched');
  }
  assert.equal(promote(ledger, 'nope', good).ok, false);
  assert.deepEqual(evaluateGates(f, 'shadow-canary', {}).unmet.map((u) => u.gate).sort(), gatesFor(f, 'shadow-canary').map((g) => g.id).sort());
});

test('[REL-002.AC01] stages cannot be skipped, and evidence for a lower stage does not open a higher one', () => {
  const f = 'model-routing';
  const ledger = newLedger();
  // asking for opt-in evidence at offline: the next stage is shadow-canary, whose gate ids the opt-in set lacks
  const r = promote(ledger, f, fullEvidence(f, 'opt-in-supported'));
  assert.equal(r.ok, false);
  assert.ok(r.blockers.some((b) => b.gate === 'shadow-no-outcome-change'));
  assert.equal(r.ledger.features[f].stage, 'offline-fixtures');
  const spec = gatesFor(f, 'opt-in-supported').find((g) => g.id === 'promotion-thresholds');
  assert.match(spec.statement, /200 paired adjudicated tasks/, 'the routing gate quotes the PRD targets');
});

test('[REL-002.AC01] the kill switch and an unsupported platform block promotion', () => {
  const f = 'capability-enforcement';
  let ledger = newLedger();
  ledger = promote(ledger, f, fullEvidence(f, 'shadow-canary')).ledger;
  const killed = cfg({ AGENTIC_SECURITY_NO_CAPABILITY_ENFORCEMENT: '1' });
  assert.match(promote(ledger, f, fullEvidence(f, 'opt-in-supported'), { config: killed }).blockers[0].reason, /kill switch is set/);
  const mac = cfg({}, { features: { [f]: true } }, 'darwin');
  const r = promote(ledger, f, fullEvidence(f, 'opt-in-supported'), { config: mac });
  assert.equal(r.ok, false);
  assert.match(r.blockers.map((b) => b.reason).join('\n'), /not supported on darwin/);
  const linux = cfg({ AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT: '1' }, {}, 'linux');
  assert.equal(promote(ledger, f, fullEvidence(f, 'opt-in-supported'), { config: linux }).ok, true, 'control: linux, no kill switch');
});

test('[REL-002.AC01] an enabled feature below opt-in runs in its stage\'s mode, and only opt-in may change an outcome', () => {
  const f = 'model-routing';
  const on = cfg({}, { features: { [f]: true } });
  let ledger = newLedger();
  assert.equal(effectiveMode(on, ledger, f).mode, 'fixtures');
  assert.equal(effectiveMode(on, ledger, f).code, 'below-stage');
  ledger = promote(ledger, f, fullEvidence(f, 'shadow-canary')).ledger;
  assert.equal(effectiveMode(on, ledger, f).mode, 'shadow');
  ledger = promote(ledger, f, fullEvidence(f, 'opt-in-supported')).ledger;
  assert.equal(effectiveMode(on, ledger, f).mode, 'active');
  // the default configuration is off at every stage
  assert.equal(effectiveMode(cfg(), ledger, f).mode, 'off');
  assert.equal(effectiveMode(cfg({ AGENTIC_SECURITY_NO_ASSURANCE: '1' }, { features: { [f]: true } }), ledger, f).mode, 'off', 'kill switch wins');
  assert.equal(effectiveMode(on, { schema: 'x', features: {} }, f).code, 'no-rollout-record', 'no record means no gate passed');
});

test('[REL-002.AC01] gate evidence can be assembled from recorded closure steps, and only a passing step yields any', () => {
  const steps = [
    { id: 'verification', state: 'pass', log: { sha256: D } },
    { id: 'foundation', state: 'fail', log: { sha256: D } },
    { id: 'compat-nix', state: 'unsupported', log: null },
    { id: 'routing', state: 'incomplete', log: { sha256: D } },
    { id: 'portfolio', state: 'pass', log: { sha256: 'short' } },
  ];
  const ev = evidenceFromSteps(steps);
  assert.deepEqual(Object.keys(ev), ['step:verification']);
  const assembled = assembleEvidence('verification-oracles', 'offline-fixtures', ev);
  assert.ok(assembled['fixtures-green'], 'the suite gate is filled from its own step');
  assert.equal(assembled['default-off-unchanged'], undefined, 'a failed step supplies nothing');
  assert.equal(promote(newLedger(), 'verification-oracles', assembled).ok, false, 'so the promotion is still blocked');
});

test('[REL-002.AC01] the rollout guide documents every feature, stage and gate id', () => {
  const guide = fs.readFileSync(path.join(REPO, 'docs', 'guides', 'assurance-rollout-and-rollback.md'), 'utf8');
  for (const stage of STAGES) assert.ok(guide.includes(`\`${stage}\``), `guide names stage ${stage}`);
  for (const f of features) {
    assert.ok(guide.includes(`\`${f}\``), `guide names feature ${f}`);
    for (const stage of STAGES) for (const g of gatesFor(f, stage)) assert.ok(guide.includes(`\`${g.id}\``), `guide documents gate ${g.id}`);
  }
});
