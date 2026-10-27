// The two-labeler capability for the independent Haskell set, the shared Wilson interval and Cohen's kappa, tested on SYNTHETIC data only. Nothing here
// reads, runs or lists the sealed set's data: the fixtures are built in a temp directory, and the code under test is the lib and the build script.
//
// What is pinned: (1) extending the schema did not change the single-labeler digest, so the sealed labels stay valid; (2) one Wilson, with the numbers the
// plan quotes; (3) kappa and percent agreement on a table whose answer is known; (4) the panel keeps "the labelers disagreed" apart from "one labeler was
// unsure"; (5) independence is refused when it is not real; (6) build-labels.mjs --panel writes the panel and leaves labels.json byte-identical.

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from './helpers/tmp.js';
import { wilson as sharedWilson } from '../../bench/_lib/wilson.mjs';
import { cohen } from '../../bench/_lib/agreement.mjs';
import * as lib from '../../bench/dag/independent-haskell/lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const BENCH = join(HERE, '..', '..', 'bench', 'dag', 'independent-haskell');

const sample = [
  { project: 'p', file: 'a.hs', line: 1, vuln: 'V1' }, { project: 'p', file: 'a.hs', line: 2, vuln: 'V2' }, { project: 'p', file: 'b.hs', line: 3, vuln: 'V3' },
  { project: 'p', file: 'b.hs', line: 4, vuln: 'V4' }, { project: 'q', file: 'c.hs', line: 5, vuln: 'V5' }, { project: 'q', file: 'c.hs', line: 6, vuln: 'V6' },
];
const idOf = (s) => crypto.createHash('sha256').update([s.project, s.file, s.line, s.vuln].join('|')).digest('hex').slice(0, 12);
const baseVerdicts = ['tp', 'fp', 'tp', 'ambiguous', 'ambiguous', 'fp'];
const baseLabels = () => sample.map((s, i) => ({ id: idOf(s), project: s.project, language: 'haskell', file: s.file, line: s.line, vuln: s.vuln, verdict: baseVerdicts[i], evidence: `base ${i}` }));
// labeler b: agrees on 0 and 1, disagrees on 2 (fp vs tp), is unsure on 3 where a was ambiguous too (all-unsure), decides 4 where a was unsure (one-unsure), agrees on 5
const bDraft = [['tp', 'b0'], ['fp', 'b1'], ['fp', 'b2'], ['unsure', 'b3'], ['tp', 'b4'], ['fp', 'b5']].map(([v, e], i) => ({ i, v, e }));
const adjDraft = [{ i: 2, v: 'tp', e: 'adj2' }, { i: 4, v: 'fp', e: 'adj4' }];
const labelers = [{ labelerId: 'a', model: 'model-one', blind: true }, { labelerId: 'b', model: 'model-two', blind: true }];
const build = (over = {}) => lib.buildPanel({
  sample, labelers, drafts: { b: bDraft }, base: baseLabels(), baseLabelerId: 'a', baseLabelsDigest: lib.digestOf(baseLabels()),
  adjudicator: { labelerId: 'c', model: 'model-three' }, adjudication: adjDraft, ...over,
});

// ── 1. the sealed set's digest cannot have moved ─────────────────────────────

test('the single-labeler digest is the canonical form it always was: eight fields, sorted by id, sha-256 of the JSON', () => {
  const labels = baseLabels();
  const independent = crypto.createHash('sha256').update(JSON.stringify([...labels].sort((x, y) => x.id.localeCompare(y.id)).map((l) => ({
    id: l.id, project: l.project, language: l.language, file: l.file, line: l.line, vuln: l.vuln, verdict: l.verdict, evidence: l.evidence })))).digest('hex');
  assert.equal(lib.digestOf(labels), independent);
  // extra fields on a label (a labeler id, a second verdict) do not enter the digest: extending the record cannot invalidate it
  const extended = labels.map((l) => ({ ...l, labeler: 'a', votes: [{ labelerId: 'b', verdict: 'fp' }], status: 'disagreed' }));
  assert.equal(lib.digestOf(extended), independent);
  assert.deepEqual(Object.keys(lib.canonicalLabels(labels)[0]), ['id', 'project', 'language', 'file', 'line', 'vuln', 'verdict', 'evidence']);
});

// ── 2. one Wilson ────────────────────────────────────────────────────────────

test('one Wilson interval: the figure the plan quotes for 1 of 35, null for no observations, and the lib re-exports it', () => {
  const [lo, hi] = sharedWilson(1, 35);
  assert.equal(lo.toFixed(3), '0.005');
  assert.equal(hi.toFixed(3), '0.145');
  assert.equal(sharedWilson(0, 0), null);
  assert.deepEqual(sharedWilson(0, 10).map((x) => +x.toFixed(4)), [0, 0.2775]);
  assert.equal(lib.wilson, sharedWilson, 'the lib exports the shared function, not a copy');
});

// ── 3. kappa ─────────────────────────────────────────────────────────────────

test('Cohen kappa and percent agreement on a table with a known answer; undefined when one category is all there is', () => {
  // 50 sites: both yes 20, A yes B no 5, A no B yes 10, both no 15 -> po 0.7, pe 0.5, kappa 0.4
  const pairs = [...Array(20).fill(['y', 'y']), ...Array(5).fill(['y', 'n']), ...Array(10).fill(['n', 'y']), ...Array(15).fill(['n', 'n'])];
  const r = cohen(pairs, ['y', 'n']);
  assert.equal(r.n, 50);
  assert.equal(r.percentAgreement, 0.7);
  assert.ok(Math.abs(r.expected - 0.5) < 1e-12);
  assert.ok(Math.abs(r.kappa - 0.4) < 1e-12);
  assert.deepEqual(r.matrix.y, { y: 20, n: 5 });
  const same = cohen(Array(8).fill(['y', 'y']), ['y', 'n']);
  assert.equal(same.percentAgreement, 1);
  assert.equal(same.kappa, null);
  assert.match(same.kappaUndefinedReason, /single category/);
  assert.equal(cohen([], ['y', 'n']).kappa, null);
  assert.throws(() => cohen([['y', 'maybe']], ['y', 'n']), /outside the category set/);
  // perfect disagreement on balanced data is kappa -1
  assert.equal(cohen([['y', 'n'], ['n', 'y']], ['y', 'n']).kappa, -1);
});

// ── 4. disagreed is not unsure ───────────────────────────────────────────────

test('the panel tells a disagreement from an unsure labeler, adjudicates only what was not agreed, and reports agreement', () => {
  const panel = build();
  assert.deepEqual(lib.validatePanel(panel, baseLabels()), { ok: true, errors: [] });
  const byLine = Object.fromEntries(panel.sites.map((s) => [s.line, s]));
  assert.equal(byLine[1].status, 'agreed'); assert.equal(byLine[1].final, 'tp');
  assert.equal(byLine[2].status, 'agreed'); assert.equal(byLine[2].final, 'fp');
  assert.equal(byLine[3].status, 'disagreed'); assert.equal(byLine[3].final, 'tp', 'the adjudicator settled a disagreement');
  assert.equal(byLine[4].status, 'all-unsure'); assert.equal(byLine[4].final, 'ambiguous', 'nobody decided it and the adjudicator did not either');
  assert.equal(byLine[5].status, 'one-unsure'); assert.equal(byLine[5].final, 'fp', 'one labeler declined; the adjudicator settled it');
  assert.equal(byLine[6].status, 'agreed');
  const rep = lib.agreementReport(panel);
  assert.deepEqual(rep.statusCounts, { agreed: 3, disagreed: 1, 'one-unsure': 1, 'all-unsure': 1 });
  assert.equal(rep.nonAgreed, 3);
  assert.equal(rep.adjudicated, 2);
  assert.equal(rep.unsettledAfterAdjudication, 1);
  assert.deepEqual(rep.finalCounts, { tp: 2, fp: 3, ambiguous: 1 });
  const pair = rep.pairs[0];
  assert.deepEqual(pair.labelers, ['a', 'b']);
  assert.equal(pair.threeWay.n, 6);
  assert.equal(pair.threeWay.agreed, 4);
  assert.ok(Math.abs(pair.threeWay.percentAgreement - 4 / 6) < 1e-12);
  assert.equal(pair.decidedOnly.sites, 4, 'sites both decided: lines 1, 2, 3 and 6');
  assert.equal(pair.decidedOnly.excludedBecauseUnsure, 2);
  assert.ok(pair.decidedOnly.kappa !== undefined);
  // the labelers' base verdict `ambiguous` became `unsure`: the single record cannot say whether it meant "unsure" or "disagreed"
  assert.equal(lib.voteOfBaseVerdict('ambiguous'), 'unsure');
  assert.equal(lib.voteOfBaseVerdict('tp'), 'tp');
});

// ── 5. independence is asserted, not assumed ─────────────────────────────────

test('a panel is refused when the labelers are not independent: same model, not blind, adjudicator is a labeler, adjudication over agreement, missing vote, edited', () => {
  const errs = (panel, base = baseLabels()) => lib.validatePanel(panel, base).errors.join(' | ');
  assert.match(errs(build({ labelers: [labelers[0], { ...labelers[1], model: 'model-one' }] })), /same model/);
  assert.match(errs(build({ labelers: [labelers[0], { ...labelers[1], blind: false }] })), /not declared blind/);
  assert.match(errs(build({ adjudicator: { labelerId: 'b', model: 'model-three' } })), /also a labeler/);
  assert.match(errs(build({ adjudicator: { labelerId: 'c', model: 'model-two' } })), /same model/);
  assert.match(errs(build({ adjudication: [...adjDraft, { i: 0, v: 'fp', e: 'overrule' }] })), /cannot override agreement/);
  assert.match(errs(build({ labelers: [labelers[0]] })), /at least two labelers/);
  const missing = build(); missing.sites[0].votes.pop(); assert.match(errs(missing), /no vote from/);
  const edited = build(); edited.sites[1].final = 'tp'; assert.match(errs(edited), /final tp does not follow/);
  const redigest = build(); redigest.sites[2].votes[0].evidence = 'changed'; assert.match(errs(redigest), /panelDigest does not match/);
  const foreign = build(); foreign.sites[0].line = 99; assert.match(errs(foreign), /differs from the single-labeler record/);
  const noEvidence = build({ drafts: { b: bDraft.map((r) => (r.i === 0 ? { ...r, e: '' } : r)) } }); assert.match(errs(noEvidence), /carries no evidence/);
  assert.throws(() => build({ drafts: { b: bDraft.slice(1) } }), /verdicts from b for 6 sampled sites/);
});

// ── 6. the build script ──────────────────────────────────────────────────────

function fixtureDir() {
  const dir = mkTestTmp('indep-hs-panel-');
  const labels = lib.canonicalLabels(baseLabels());
  writeFileSync(join(dir, 'sample-haskell.json'), JSON.stringify(sample));
  writeFileSync(join(dir, 'labels.json'), JSON.stringify({ labelsVersion: 1, labeledBy: 'synthetic', labelsDigest: lib.digestOf(labels), labels }, null, 1) + '\n');
  writeFileSync(join(dir, 'draft-haskell-b.txt'), bDraft.map((r) => `${r.i}|${r.v}|${r.e}`).join('\n') + '\n');
  writeFileSync(join(dir, 'adjudication-haskell.txt'), adjDraft.map((r) => `${r.i}|${r.v}|${r.e}`).join('\n') + '\n');
  writeFileSync(join(dir, 'labelers.json'), JSON.stringify({ base: { labelerId: 'a', model: 'model-one' }, labelers: [{ labelerId: 'b', model: 'model-two', blind: true }], adjudicator: { labelerId: 'c', model: 'model-three' } }));
  return dir;
}
const sha = (f) => crypto.createHash('sha256').update(readFileSync(f)).digest('hex');
const runBuild = (dir, ...args) => spawnSync(process.execPath, [join(BENCH, 'build-labels.mjs'), ...args], { cwd: dir, encoding: 'utf8' });

test('build-labels.mjs --panel writes the panel and the agreement report and leaves labels.json byte-identical; the default mode is unchanged', () => {
  const dir = fixtureDir();
  const before = sha(join(dir, 'labels.json'));
  const r = runBuild(dir, '--panel', '--dir', dir);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(sha(join(dir, 'labels.json')), before, 'the single-labeler record is not touched');
  const panel = JSON.parse(readFileSync(join(dir, 'labels-panel.json'), 'utf8'));
  assert.equal(panel.baseLabelsDigest, JSON.parse(readFileSync(join(dir, 'labels.json'), 'utf8')).labelsDigest);
  assert.deepEqual(lib.validatePanel(panel, JSON.parse(readFileSync(join(dir, 'labels.json'), 'utf8')).labels), { ok: true, errors: [] });
  const ag = JSON.parse(readFileSync(join(dir, 'agreement.json'), 'utf8'));
  assert.deepEqual(ag.statusCounts, { agreed: 3, disagreed: 1, 'one-unsure': 1, 'all-unsure': 1 });
  assert.match(readFileSync(join(dir, 'agreement.md'), 'utf8'), /Cohen kappa/);

  // the single-labeler mode, run on the same kind of fixture, still produces the digest of its canonical form
  const solo = mkTestTmp('indep-hs-solo-');
  writeFileSync(join(solo, 'sample-haskell.json'), JSON.stringify(sample));
  writeFileSync(join(solo, 'draft-haskell.txt'), baseVerdicts.map((v, i) => `${i}|${v}|base ${i}`).join('\n') + '\n');
  const s = runBuild(solo);
  assert.equal(s.status, 0, s.stderr);
  const out = JSON.parse(readFileSync(join(solo, 'labels.json'), 'utf8'));
  assert.equal(out.labelsDigest, lib.digestOf(baseLabels()));
  assert.equal(out.labels.length, 6);
});

test('build-labels.mjs --panel refuses a panel that is not independent, or a base record that was edited, and writes nothing', () => {
  const same = fixtureDir();
  writeFileSync(join(same, 'labelers.json'), JSON.stringify({ base: { labelerId: 'a', model: 'model-one' }, labelers: [{ labelerId: 'b', model: 'model-one', blind: true }], adjudicator: { labelerId: 'c', model: 'model-three' } }));
  const r = runBuild(same, '--panel', '--dir', same);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /same model/);
  assert.equal(existsSync(join(same, 'labels-panel.json')), false);

  const edited = fixtureDir();
  const doc = JSON.parse(readFileSync(join(edited, 'labels.json'), 'utf8'));
  doc.labels[0].verdict = doc.labels[0].verdict === 'tp' ? 'fp' : 'tp';
  writeFileSync(join(edited, 'labels.json'), JSON.stringify(doc));
  const e = runBuild(edited, '--panel', '--dir', edited);
  assert.equal(e.status, 1);
  assert.match(e.stderr, /does not match its recorded digest/);
  assert.equal(existsSync(join(edited, 'labels-panel.json')), false);
});
