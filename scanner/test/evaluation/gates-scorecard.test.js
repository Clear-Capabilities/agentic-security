// Real-code gates, the scorecard section and the driver script. SYNTHETIC / GENERATED data only.
//
// The "generated population" below exists to test gate ARITHMETIC. Its labels were never adjudicated by anyone and
// describe no real code; they are built inside this test file and written nowhere.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { evaluateGates, GATE_STATUSES } from '../../src/posture/evaluation/gates.js';
import { freezeProtocol, CORE_LANGUAGES, PREREGISTERED_THRESHOLDS, DEFAULT_MATCHING } from '../../src/posture/evaluation/protocol.js';
import { buildDefectLabel, buildNegativeLabel } from '../../src/posture/evaluation/labels.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { buildScorecard, renderScorecardMarkdown, summarizeEvaluationGates } from '../../src/posture/accuracy-scorecard.js';
import { suite, clone } from '../helpers/evaluation-suite.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.resolve(HERE, '..', '..', '..', 'scripts', 'evaluation.mjs');
const FAMILY = 'sql-injection';

// ---- a generated population: `per` positives and `per` negatives per core language, all sealed, none synthetic-flagged ----
function generated({ per = 100, flagSynthetic = false, split = 'sealed', skipLang = null } = {}) {
  const targets = []; const defects = []; const negatives = [];
  const adj = (tag) => ({ status: 'adjudicated', independent: true, reviewers: [{ reviewerId: `gen-a-${tag}`, verdict: 'confirmed' }, { reviewerId: `gen-b-${tag}`, verdict: 'confirmed' }] });
  const common = (tag) => ({ synthetic: flagSynthetic, adjudication: adj(tag), proposedBy: { role: 'worker', id: 'gen-proposer' } });
  let n = 0;
  for (const lang of CORE_LANGUAGES) {
    const count = lang === skipLang ? per - 1 : per;
    for (let i = 0; i < count; i++, n++) {
      const id = `gen-${lang}-${i}`;
      const hex = (n + 1).toString(16).padStart(40, '0');
      targets.push({ id, language: lang, license: 'gen-license', upstream: `example.invalid/${id}`, pairId: `pair-${id}`, preCommit: hex, postCommit: hex.replace(/0/g, 'f'), advisoryIds: [], digest: digestOf(id) });
      const d = buildDefectLabel({ ...common(`d${n}`), targetId: id, rootCauseId: `root-${id}`, affected: { commit: hex }, language: lang, family: FAMILY, cwe: 'CWE-89', location: { file: 'a.x', startLine: 1, endLine: 1 }, evidence: [{ ref: `ref-${id}`, producer: 'human' }] });
      defects.push(d);
      negatives.push(buildNegativeLabel({ ...common(`n${n}`), targetId: id, variant: 'post', kind: 'patched', language: lang, family: FAMILY, scope: { files: ['a.x'] }, pairedDefectId: d.id, rationale: `gen-rationale-${id}` }));
    }
  }
  // A development-split sink, for tests that move one side of a language's labels out of the sealed split.
  targets.push({ id: 'gen-dev-sink', language: 'rust', license: 'gen-license', upstream: 'example.invalid/gen-dev-sink', pairId: 'pair-gen-dev-sink', preCommit: 'e'.repeat(40), postCommit: 'd'.repeat(40), advisoryIds: [], digest: digestOf('gen-dev-sink') });
  const ids = targets.map((t) => t.id).filter((id) => id !== 'gen-dev-sink').sort();
  const draft = {
    synthetic: false,
    engine: { version: '0.0.0-gen', bundleDigest: digestOf('gen-engine') },
    measurement: { commit: 'a'.repeat(40), cleanTree: true },
    tools: { node: 'gen' }, models: [], datasetLicenses: { 'gen-license': 'generated' },
    scope: { languages: [...CORE_LANGUAGES], families: [FAMILY] }, matching: { ...DEFAULT_MATCHING },
    limits: { perTargetTimeoutMs: 1000, spendCeilingUsd: 0, replicates: 3 }, thresholds: { ...PREREGISTERED_THRESHOLDS },
    targets, splits: split === 'sealed' ? { dev: ['gen-dev-sink'], sealed: ids } : { dev: [...ids, 'gen-dev-sink'], sealed: [] },
  };
  const f = freezeProtocol(draft);
  assert.ok(f.ok, JSON.stringify(f.errors.slice(0, 3)));
  return { protocol: f.protocol, defects, negatives };
}

const goodScore = (protocol, over = {}) => ({
  protocolHash: protocol.protocolHash,
  endToEnd: {
    micro: { f1: 0.9, precision: 0.95, recall: 0.85 }, macroF1: 0.9,
    byLanguage: Object.fromEntries(CORE_LANGUAGES.map((l) => [l, { f1: 0.9 }])),
  },
  completion: { rate: 0.99 },
  ...over,
});

const statusOf = (r, id) => r.gates.find((g) => g.id === id).status;

describe('[QA-001.AC03] the real-code gates cannot pass on a synthetic or undersized population, and thresholds come only from the frozen protocol', () => {
  test('the synthetic suite never passes a real-code gate, even when handed a perfect score', () => {
    const { protocol, defects, negatives } = suite();
    const r = evaluateGates({ protocol, score: goodScore(protocol), defects, negatives });
    assert.equal(r.ok, true);
    assert.equal(r.synthetic, true);
    assert.equal(r.overall, 'insufficient-population');
    assert.ok(r.gates.length >= 14);
    assert.ok(r.gates.every((g) => g.status === 'insufficient-population'), JSON.stringify(r.gates.map((g) => g.status)));
    assert.match(r.gates[0].reason, /synthetic/);
    assert.ok(r.gates.every((g) => GATE_STATUSES.includes(g.status)));
  });

  test('with no sealed-split score every gate is unmeasured', () => {
    const { protocol, defects, negatives } = suite();
    const r = evaluateGates({ protocol, score: null, defects, negatives });
    assert.equal(r.overall, 'unmeasured');
    assert.ok(r.gates.every((g) => g.status === 'unmeasured'));
  });

  test('a population one label short in one language is insufficient, even with a perfect score (control: the full one is not)', () => {
    const full = generated();
    const ok = evaluateGates({ protocol: full.protocol, score: goodScore(full.protocol), defects: full.defects, negatives: full.negatives });
    assert.equal(statusOf(ok, 'overall-micro-f1'), 'pass', 'control: the population minimums are reachable');
    const short = generated({ skipLang: 'rust' });
    const r = evaluateGates({ protocol: short.protocol, score: goodScore(short.protocol), defects: short.defects, negatives: short.negatives });
    assert.equal(r.overall, 'insufficient-population');
    assert.ok(r.gates.every((g) => g.status === 'insufficient-population'));
    assert.match(r.population.reason, /rust: 99\/100 positives/);
  });

  test('labels flagged synthetic, or sitting in the development split, never count toward the minimums', () => {
    const synth = generated({ flagSynthetic: true });
    assert.equal(evaluateGates({ protocol: synth.protocol, score: goodScore(synth.protocol), defects: synth.defects, negatives: synth.negatives }).overall, 'insufficient-population');
    const dev = generated({ split: 'dev' });
    assert.equal(evaluateGates({ protocol: dev.protocol, score: goodScore(dev.protocol), defects: dev.defects, negatives: dev.negatives }).overall, 'insufficient-population');
    const thin = generated({ per: 99 });
    assert.equal(evaluateGates({ protocol: thin.protocol, score: goodScore(thin.protocol), defects: thin.defects, negatives: thin.negatives }).overall, 'insufficient-population', 'a smaller convenient sample is never a pass');
  });

  test('each side of the population is checked on its own: synthetic or development-split labels for ONE side of one language are not enough', () => {
    const g = generated();
    const ev = (defects, negatives) => evaluateGates({ protocol: g.protocol, score: goodScore(g.protocol), defects, negatives }).overall;
    assert.equal(statusOf(evaluateGates({ protocol: g.protocol, score: goodScore(g.protocol), defects: g.defects, negatives: g.negatives }), 'overall-micro-f1'), 'pass', 'control');
    const rust = (l) => l.language === 'rust';
    const asDefect = (l, over) => buildDefectLabel({ ...l, ...over });
    const asNegative = (l, over) => buildNegativeLabel({ ...l, ...over });
    const swap = (list, f) => list.map((l) => (rust(l) ? f(l) : l));
    assert.equal(ev(swap(g.defects, (l) => asDefect(l, { synthetic: true })), g.negatives), 'insufficient-population', 'synthetic positives');
    assert.equal(ev(g.defects, swap(g.negatives, (l) => asNegative(l, { synthetic: true }))), 'insufficient-population', 'synthetic negatives');
    assert.equal(ev(swap(g.defects, (l) => asDefect(l, { targetId: 'gen-dev-sink' })), g.negatives), 'insufficient-population', 'positives in the development split');
    assert.equal(ev(g.defects, swap(g.negatives, (l) => asNegative(l, { targetId: 'gen-dev-sink' }))), 'insufficient-population', 'negatives in the development split');
    const candidate = (l) => ({ ...l, adjudication: { status: 'candidate', reviewers: [] } });
    assert.equal(ev(swap(g.defects, (l) => buildDefectLabel(candidate(l))), g.negatives), 'insufficient-population', 'advisory-only candidates');
  });

  test('on a sufficient population the verdicts follow the registered thresholds, in both directions; the interval gate stays unmeasured', () => {
    const g = generated();
    const run = (score) => evaluateGates({ protocol: g.protocol, score, defects: g.defects, negatives: g.negatives });
    const good = run(goodScore(g.protocol));
    for (const id of ['overall-micro-f1', 'overall-macro-f1', 'pooled-precision', 'pooled-recall', 'completion', 'per-language-f1:rust']) assert.equal(statusOf(good, id), 'pass', id);
    assert.equal(statusOf(good, 'per-language-f1-lower-bound'), 'unmeasured', 'the interval method is not implemented, so this cannot pass');
    assert.notEqual(good.overall, 'pass', 'no gate set can pass overall while one is unmeasured');
    const weak = run(goodScore(g.protocol, { endToEnd: { micro: { f1: 0.7, precision: 0.85, recall: 0.6 }, macroF1: 0.7, byLanguage: Object.fromEntries(CORE_LANGUAGES.map((l) => [l, { f1: l === 'go' ? 0.5 : 0.9 }])) } }));
    assert.equal(statusOf(weak, 'overall-micro-f1'), 'fail');
    assert.equal(statusOf(weak, 'pooled-precision'), 'fail');
    assert.equal(statusOf(weak, 'pooled-recall'), 'fail');
    assert.equal(statusOf(weak, 'per-language-f1:go'), 'fail');
    assert.equal(statusOf(weak, 'per-language-f1:rust'), 'pass');
    assert.equal(weak.overall, 'fail');
    const spike = run(goodScore(g.protocol, { completion: { rate: 0.8 } }));
    assert.equal(statusOf(spike, 'completion'), 'fail', 'a failed-target spike fails the completion gate');
    const undefinedValue = run(goodScore(g.protocol, { endToEnd: { micro: { f1: null, precision: null, recall: null }, macroF1: null, byLanguage: {} } }));
    assert.equal(statusOf(undefinedValue, 'overall-micro-f1'), 'unmeasured');
  });

  test('a threshold edited after freezing, or a score from another protocol, is rejected, and a caller cannot supply thresholds', () => {
    const g = generated();
    const edited = clone(g.protocol); edited.thresholds.overallMicroF1 = 0.1;
    const r1 = evaluateGates({ protocol: edited, score: goodScore(g.protocol, { endToEnd: { micro: { f1: 0.2, precision: 0.2, recall: 0.2 }, macroF1: 0.2, byLanguage: {} } }), defects: g.defects, negatives: g.negatives });
    assert.equal(r1.rejected, true);
    assert.equal(r1.overall, 'rejected');
    assert.deepEqual(r1.gates, []);
    const other = evaluateGates({ protocol: g.protocol, score: goodScore(g.protocol, { protocolHash: 'sha256:' + '0'.repeat(64) }), defects: g.defects, negatives: g.negatives });
    assert.equal(other.rejected, true);
    assert.equal(other.errors[0].code, 'PROTOCOL_MISMATCH');
    const weak = goodScore(g.protocol, { endToEnd: { micro: { f1: 0.2, precision: 0.2, recall: 0.2 }, macroF1: 0.2, byLanguage: {} } });
    const smuggled = evaluateGates({ protocol: g.protocol, score: weak, defects: g.defects, negatives: g.negatives, thresholds: { overallMicroF1: 0.01 } });
    assert.equal(statusOf(smuggled, 'overall-micro-f1'), 'fail', 'an extra thresholds argument is ignored');
  });
});

describe('[QA-003.AC03] the scorecard relays gate status and cannot show a pass for a synthetic protocol', () => {
  const minimal = (evaluation) => buildScorecard({ provenance: { engineVersion: 'x' }, corpusDetail: [], selfScan: {}, committed: {}, ...(evaluation === undefined ? {} : { evaluation }) });

  test('absent report: unmeasured, with the reason', () => {
    const s = summarizeEvaluationGates(undefined);
    assert.equal(s.status, 'unmeasured');
    assert.match(s.reason, /no frozen real-code evaluation protocol/);
    assert.equal(minimal().evaluationGates.status, 'unmeasured');
    const md = renderScorecardMarkdown(minimal());
    assert.match(md, /## Real-code evaluation gates/);
    assert.match(md, /Status: \*\*unmeasured\*\*/);
  });

  test('a synthetic report is forced to unmeasured and publishes no gate rows', () => {
    const { protocol, defects, negatives } = suite();
    const report = evaluateGates({ protocol, score: goodScore(protocol), defects, negatives });
    const s = summarizeEvaluationGates({ ...report, synthetic: true });
    assert.equal(s.status, 'unmeasured');
    assert.deepEqual(s.gates, []);
    const lying = summarizeEvaluationGates({ synthetic: true, overall: 'pass', gates: [{ id: 'overall-micro-f1', status: 'pass' }] });
    assert.equal(lying.status, 'unmeasured');
    assert.doesNotMatch(renderScorecardMarkdown(minimal({ synthetic: true, overall: 'pass', gates: [{ id: 'overall-micro-f1', status: 'pass', threshold: 0.8, measured: 0.9 }] })), /\| pass \|/);
  });

  test('a non-synthetic report is relayed, not recomputed', () => {
    const g = generated();
    const report = evaluateGates({ protocol: g.protocol, score: goodScore(g.protocol), defects: g.defects, negatives: g.negatives });
    const s = summarizeEvaluationGates(report);
    assert.equal(s.synthetic, false);
    assert.equal(s.status, report.overall);
    assert.equal(s.gates.length, report.gates.length);
    assert.match(renderScorecardMarkdown(minimal(report)), /\| overall-micro-f1 \| pass \|/);
    assert.equal(summarizeEvaluationGates({ overall: 'pass', gates: [] }).synthetic, true, 'a report that does not say it is real is treated as synthetic');
  });
});

describe('[QA-003.AC02] the driver script', () => {
  const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 120000 });

  test('synthetic: exits 0, labels itself synthetic, and every real-code gate reads insufficient-population', () => {
    const r = run('synthetic', '--json');
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.synthetic, true);
    assert.deepEqual(out.results.map((x) => x.layer), ['deterministic-only', 'deep-taint', 'model-assisted']);
    assert.ok(out.results.every((x) => x.gatesOverall === 'insufficient-population'));
    assert.ok(out.results.every((x) => !x.gateStatuses.includes('pass')));
    const det = out.results[0]; const deep = out.results[1];
    assert.ok(deep.endToEnd.tp >= det.endToEnd.tp);
    const text = run('synthetic');
    assert.match(text.stdout, /SYNTHETIC suite/);
    assert.match(text.stdout, /not engine accuracy/);
  });

  test('freeze and verify-protocol: a good protocol verifies (0), an edited one does not (1), a dirty-tree draft will not freeze (1)', () => {
    const dir = mkTestTmp('eval-cli-');
    const draftFile = path.join(dir, 'draft.json');
    fs.writeFileSync(draftFile, JSON.stringify(suite().draft));
    const frozen = path.join(dir, 'protocol.json');
    assert.equal(run('freeze', draftFile, '--out', frozen).status, 0);
    assert.equal(run('verify-protocol', frozen).status, 0);
    const p = JSON.parse(fs.readFileSync(frozen, 'utf8')); p.thresholds.pooledRecall = 0.1;
    const edited = path.join(dir, 'edited.json'); fs.writeFileSync(edited, JSON.stringify(p));
    assert.equal(run('verify-protocol', edited).status, 1);
    const dirty = clone(suite().draft); dirty.measurement.cleanTree = false;
    const dirtyFile = path.join(dir, 'dirty.json'); fs.writeFileSync(dirtyFile, JSON.stringify(dirty));
    assert.equal(run('freeze', dirtyFile).status, 1);
    assert.equal(run('nonsense').status, 2);
    assert.equal(run('gates').status, 2);
  });
});
