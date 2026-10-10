// QA-002.AC01 and QA-002.AC02: adjudicated defect labels and reviewed negatives. SYNTHETIC data only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateDefectLabel, validateNegativeLabel, isScoreable, matchFinding, matchNegative, buildDefectLabel, buildNegativeLabel, populationCounts,
} from '../../src/posture/evaluation/labels.js';
import { runEvaluation } from '../../src/posture/evaluation/runner.js';
import { scoreRun } from '../../src/posture/evaluation/score.js';
import { suite, resolver, clone, stubScan, SYN_FINDING } from '../helpers/evaluation-suite.js';

const defect = () => clone(suite().defects[0]);
const negative = () => clone(suite().negatives[0]);
const reId = (l, kind) => (kind === 'n' ? buildNegativeLabel(l) : buildDefectLabel(l));
const errPaths = (v) => v.errors.map((e) => e.path);
const POLICY = suite().protocol.matching;

describe('[QA-002.AC01] a scored defect has root cause, build, family, reviewed range, evidence and adjudication', () => {
  test('the synthetic labels validate and are scoreable', () => {
    for (const d of suite().defects) { assert.equal(validateDefectLabel(d).ok, true, JSON.stringify(validateDefectLabel(d).errors)); assert.equal(isScoreable(d), true); }
    for (const n of suite().negatives) assert.equal(validateNegativeLabel(n).ok, true, JSON.stringify(validateNegativeLabel(n).errors));
  });

  test('every required identity field is enforced', () => {
    const cases = [
      ['root cause', (d) => { d.rootCauseId = ''; }, 'rootCauseId'],
      ['affected commit', (d) => { d.affected = { commit: 'nope' }; }, 'affected.commit'],
      ['language', (d) => { d.language = ''; }, 'language'],
      ['family', (d) => { d.family = ''; }, 'family'],
      ['evidence kind', (d) => { d.evidence = [{ ref: 'x', producer: 'astrology' }]; }, 'evidence[0].producer'],
      ['proposer', (d) => { delete d.proposedBy; }, 'proposedBy'],
    ];
    for (const [name, mutate, path] of cases) {
      const d = defect(); mutate(d); const r = reId(d);
      const v = validateDefectLabel(r);
      assert.equal(v.ok, false, `${name} must be enforced`);
      assert.ok(errPaths(v).some((p) => p === path || p.startsWith(path)), `${name}: wanted ${path}, got ${errPaths(v)}`);
    }
  });

  test('a CWE alone never identifies a defect: the reviewed location range is mandatory', () => {
    const d = defect(); delete d.location; d.cwe = 'CWE-89';
    const v = validateDefectLabel(reId(d));
    assert.equal(v.ok, false);
    assert.ok(errPaths(v).includes('location'));
    const d2 = defect(); d2.location = { file: 'app.js', startLine: 9, endLine: 3 };
    assert.equal(validateDefectLabel(reId(d2)).ok, false, 'a reversed range is not a range');
  });

  test('adjudication needs two distinct independent reviewers who are not the proposer, and non-model evidence', () => {
    const mk = (mutate) => { const d = defect(); mutate(d); return reId(d); };
    assert.equal(isScoreable(mk((d) => { d.adjudication.reviewers = [d.adjudication.reviewers[0]]; })), false, 'one reviewer');
    assert.equal(isScoreable(mk((d) => { d.adjudication.reviewers[1].reviewerId = d.adjudication.reviewers[0].reviewerId; })), false, 'the same reviewer twice');
    assert.equal(isScoreable(mk((d) => { d.adjudication.reviewers[1].reviewerId = d.proposedBy.id; })), false, 'proposer reviewing own label');
    assert.equal(isScoreable(mk((d) => { d.adjudication.independent = false; })), false, 'not recorded as independent');
    assert.equal(isScoreable(mk((d) => { d.adjudication.reviewers[0].verdict = 'disputed'; })), false, 'a reviewer who did not confirm');
    assert.equal(isScoreable(mk((d) => { d.evidence = [{ ref: 'model-says-so', producer: 'model' }]; })), false, 'model output alone');
    assert.equal(isScoreable(mk((d) => { d.evidence = []; })), false, 'no evidence');
    assert.equal(isScoreable(defect()), true, 'control: the untouched label is scoreable');
  });

  test('an advisory-only candidate is valid data but is never scoreable', () => {
    const c = defect(); c.adjudication = { status: 'candidate', reviewers: [] }; c.advisoryRefs = ['advisory:synthetic-1'];
    const l = reId(c);
    assert.equal(validateDefectLabel(l).ok, true);
    assert.equal(isScoreable(l), false);
    const pop = populationCounts([l, defect()], []);
    assert.equal(pop.unadjudicated, 1);
    assert.equal(pop.syntheticPositives, 1, 'synthetic labels are counted apart from real ones');
    assert.deepEqual(pop.positivesByLanguage, {}, 'a synthetic label never counts toward a real-code language minimum');
  });

  test('a tampered label fails its identity check', () => {
    const d = defect(); d.location = { ...d.location, startLine: 99, endLine: 99 };
    const v = validateDefectLabel(d);
    assert.equal(v.ok, false);
    assert.ok(v.errors.some((e) => e.code === 'ID_MISMATCH'));
  });

  test('matching is by reviewed location: CWE agreement alone, wrong file, no line, or a distant line is not a true positive', () => {
    const d = defect();
    assert.deepEqual(matchFinding(SYN_FINDING(), d, POLICY), { matched: true, reason: 'location-and-family' });
    assert.equal(matchFinding(SYN_FINDING({ line: 10 }), d, POLICY).matched, true, 'inside the window');
    assert.equal(matchFinding(SYN_FINDING({ file: 'other.js' }), d, POLICY).reason, 'cwe-only', 'right CWE in the wrong file');
    assert.equal(matchFinding(SYN_FINDING({ file: 'other.js', cwe: 'CWE-1' }), d, POLICY).reason, 'wrong-file');
    assert.equal(matchFinding(SYN_FINDING({ line: null }), d, POLICY).reason, 'no-line');
    assert.equal(matchFinding(SYN_FINDING({ line: 400 }), d, POLICY).matched, false);
    assert.equal(matchFinding(SYN_FINDING({ line: 400 }), d, POLICY).reason, 'outside-range');
    assert.equal(matchFinding(SYN_FINDING({ family: 'xss', cwe: 'CWE-79' }), d, POLICY).reason, 'family-mismatch');
    // CWE agreement can stand in for the family spelling, but only together with the location.
    assert.equal(matchFinding(SYN_FINDING({ family: 'sqli-variant', cwe: 'CWE-89' }), d, POLICY).matched, true);
  });
});

describe('[QA-002.AC02] negatives: safe real code, patched code and near-misses; new findings are reviewed, not called false', () => {
  test('negative kinds are validated, and a patched negative must be the fixed variant paired to a defect', () => {
    const mk = (mutate) => { const n = negative(); mutate(n); return buildNegativeLabel(n); };
    assert.equal(validateNegativeLabel(mk((n) => { n.kind = 'imagined'; })).ok, false);
    assert.equal(validateNegativeLabel(mk((n) => { n.variant = 'pre'; })).ok, false, 'patched must be post');
    assert.equal(validateNegativeLabel(mk((n) => { delete n.pairedDefectId; })).ok, false, 'patched needs its defect');
    assert.equal(validateNegativeLabel(mk((n) => { n.scope = { files: [] }; })).ok, false);
    assert.equal(validateNegativeLabel(mk((n) => { n.rationale = ''; })).ok, false);
    assert.equal(validateNegativeLabel(mk((n) => { n.kind = 'safe-real'; n.variant = 'pre'; delete n.pairedDefectId; })).ok, true, 'safe real code needs no pair');
    assert.equal(validateNegativeLabel(mk((n) => { n.kind = 'near-miss'; n.variant = 'pre'; delete n.pairedDefectId; })).ok, true);
    assert.deepEqual(new Set(suite().negatives.map((n) => n.kind)), new Set(['patched', 'near-miss']));
  });

  test('a negative is adjudicated like a defect: an unreviewed negative is not scoreable', () => {
    const n = negative(); n.adjudication = { status: 'candidate', reviewers: [] };
    assert.equal(isScoreable(buildNegativeLabel(n)), false);
  });

  test('negative matching needs the file in scope AND the family it is negative for', () => {
    const n = negative();
    assert.equal(matchNegative(SYN_FINDING(), n).matched, true);
    assert.equal(matchNegative(SYN_FINDING({ file: 'elsewhere.js' }), n).reason, 'out-of-scope');
    assert.equal(matchNegative(SYN_FINDING({ family: 'header-hardening' }), n).reason, 'other-family');
  });

  test('a finding no label accounts for goes to a review queue; it is not counted as a false positive', async () => {
    const extra = (id, line) => SYN_FINDING({ id, file: 'app.js', line, family: 'broken-access-control', cwe: 'CWE-639' });
    const run = async (byTarget) => (await runEvaluation({ protocol: suite().protocol, config: { layer: 'deep-taint' }, resolveTarget: resolver(), scanFn: stubScan(byTarget), split: 'dev' })).run;
    const score = (r) => scoreRun({ run: r, protocol: suite().protocol, defects: suite().defects, negatives: suite().negatives });
    const quiet = score(await run({ 'syn-sqli-js-pre': [SYN_FINDING()] }));
    const noisy = score(await run({ 'syn-sqli-js-pre': [SYN_FINDING(), extra('n1', 2)], 'syn-sqli-js-post': [extra('n2', 3)] }));
    assert.equal(noisy.endToEnd.micro.fp, quiet.endToEnd.micro.fp, 'unlabelled findings must not change the false-positive count');
    assert.equal(noisy.endToEnd.micro.tp, 1);
    assert.equal(noisy.reviewQueue.length, 2);
    assert.ok(noisy.reviewQueue.every((q) => q.status === 'needs-adjudication'));
    assert.deepEqual(noisy.reviewQueue.map((q) => q.reason).sort(), ['finding-in-negative-scope-other-family', 'no-adjudicated-label']);
    assert.equal(noisy.unscored.unlabeledFindings.count >= 1, true, 'counted with a reason, not dropped');
    // Control: a same-family finding in the reviewed patched code IS a false positive.
    const fp = score(await run({ 'syn-sqli-js-pre': [SYN_FINDING()], 'syn-sqli-js-post': [SYN_FINDING({ id: 'still', line: 8 })] }));
    assert.equal(fp.endToEnd.micro.fp, quiet.endToEnd.micro.fp + 1);
    assert.equal(fp.falsePositives[0].kind, 'patched');
  });
});
