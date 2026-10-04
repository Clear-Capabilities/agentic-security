// QA-002: accuracy gates and existing-language non-regression. Tests are tagged [QA-002.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TARGETS, PAIR_GATE } from '../../src/language/support-registry.js';
import { checkFreshness } from '../../../bench/language-support/check.mjs';
import { currentFrozen } from '../../../bench/language-support/promote.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..', '..');
const SCANNER = path.join(REPO, 'scanner');
const RES = path.join(REPO, 'bench', 'language-support', 'results');
const holdout = JSON.parse(fs.readFileSync(path.join(RES, 'holdout.json'), 'utf8'));
const suites = JSON.parse(fs.readFileSync(path.join(RES, 'suites.json'), 'utf8'));
const registry = JSON.parse(fs.readFileSync(path.join(REPO, 'docs', 'language-support.json'), 'utf8'));
const meets = (m) => m.precision >= TARGETS.precision && m.recall >= TARGETS.recall && m.f1 >= TARGETS.f1;
const gate = (cmd, args, cwd = SCANNER, timeout = 900000) => spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout, env: { ...process.env, NO_COLOR: '1' } });

test('[QA-002.AC01] every section 9.2 new-language target passes on the frozen holdout, with the exact command, hashes and counts', () => {
  assert.equal(holdout.split, 'holdout');
  assert.deepEqual({ h: holdout.hashes.holdoutRollup, l: holdout.hashes.labelsSha256, p: holdout.hashes.privacyLabelsSha256 }, { h: currentFrozen().holdoutRollup, l: currentFrozen().labelsSha256, p: currentFrozen().privacyLabelsSha256 }, 'measured on the data the corpus has now');
  for (const eco of ['haskell', 'nix']) {
    const e = holdout.ecosystems[eco];
    const lay = e.detection.layers;
    // parser/discovery: 100% of valid fixtures, no crash
    assert.equal(e.parser.validFixturesParsedCleanly, e.parser.validFixtures, `${eco} parser`);
    assert.equal(e.parser.crashed.length, 0);
    // SAST (config SAST for Nix) and taint: independent layers, each with its own denominators
    for (const key of ['sast', 'taint']) {
      assert.ok(lay[key].measured, `${eco}/${key} measured`);
      assert.ok(meets(lay[key]), `${eco}/${key}: P ${lay[key].precision} R ${lay[key].recall} F1 ${lay[key].f1}`);
      for (const [fam, m] of Object.entries(lay[key].families)) assert.ok(m.f1 >= TARGETS.perFamilyF1, `${eco}/${fam}`);
    }
    // privacy: per ecosystem, with the corpus-wide denominators the PRD asks for
    assert.ok(meets(e.privacy), `${eco} privacy`);
    assert.ok(holdout.corpusTotals[eco].privacy.positives >= 100 && holdout.corpusTotals[eco].privacy.negatives >= 100);
    // fix safety, 100%; metamorphic pairs, this project's own gate
    assert.equal(e.fixes.accept.correct, e.fixes.accept.total);
    assert.equal(e.fixes.reject.correct, e.fixes.reject.total, 'every intentionally bad proposal is rejected');
    assert.equal(e.fixes.advertised.verified, e.fixes.advertised.planned);
    assert.ok(e.pairs.change.held / e.pairs.change.total >= PAIR_GATE.change, `${eco} semantics-changing pairs`);
    assert.ok(e.pairs.preserve.held / e.pairs.preserve.total >= PAIR_GATE.preserve, `${eco} semantics-preserving pairs`);
    // unknown and unmodelled cases are reported SEPARATELY, and never as a clean result
    assert.equal(e.detection.unknownOutcomes.silentClean, 0, `${eco}: no unknown case came back silent`);
    assert.equal(e.detection.unknownOutcomes.requiredDisclosureMissing, 0);
    assert.ok(e.detection.unknownOutcomes.total >= 15, 'unknown cases are in the holdout');
  }
  assert.equal(holdout.supply.manifests.exact, holdout.supply.manifests.total, 'SCA resolved fixtures: 100% exact');
  assert.equal(holdout.supply.advisoryRanges.correct, holdout.supply.advisoryRanges.total, 'advisory replay: 100% of range checks');
  assert.equal(holdout.supply.nixPatchEvidence.correct, holdout.supply.nixPatchEvidence.total);
  // auth models: every analysis fixture passes; the only failing test is the compiler check, which is BLOCKED, not hidden
  const auth = suites.results['haskell-web-auth.test.js'];
  if (suites.tools.ghc) {
    assert.equal(auth.fail, 0, `a compiler was present when this was measured, so the compile check must pass: ${JSON.stringify(auth.failing)}`);
    assert.ok(!auth.blocked, 'nothing is blocked when the compiler ran');
  } else {
    assert.ok(auth.tests - auth.pass === auth.failing.length && auth.failing.every((t) => /requires GHC/.test(t)), `auth: ${JSON.stringify(auth.failing)}`);
    assert.ok(auth.blocked, 'the missing compiler is recorded as blocked');
  }
  // BOM/AI-BOM suites pass in full
  for (const f of ['language-bom.test.js', 'language-aibom.test.js']) assert.equal(suites.results[f].fail, 0, f);
  // the registry records how it was measured
  assert.match(registry.generatedAt, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(registry.languages.haskell.measuredOn.hashes.holdoutRollup);
});

test('[QA-002.AC02] a changed baseline is a deliberate enrolment, never a weakened expectation: the old corpus and layer baselines are untouched', () => {
  const git = (args) => spawnSync('git', args, { cwd: REPO, encoding: 'utf8' });
  for (const f of ['bench/cve-replay/corpus-baseline.json', 'bench/layer-recall/baseline.json']) {
    if (!fs.existsSync(path.join(REPO, f))) continue;
    const d = git(['diff', '--numstat', '--', f]);
    assert.equal(d.stdout.trim(), '', `${f} must not be edited by the Haskell/Nix work (a gain or a loss there is a separate, deliberate enrolment)`);
  }
});

test('[QA-002.AC03] the registry freshness check fails on an unrecorded improvement, a drop, a changed corpus and a hand edit', () => {
  assert.deepEqual(checkFreshness(), [], 'the committed registry is current');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa002-'));
  try {
    const put = (name, v) => { const p = path.join(dir, name); fs.writeFileSync(p, typeof v === 'string' ? v : JSON.stringify(v, null, 2)); return p; };
    const h = JSON.parse(JSON.stringify(holdout));
    const reg = put('registry.json', fs.readFileSync(path.join(REPO, 'docs', 'language-support.json'), 'utf8'));
    const table = put('table.md', fs.readFileSync(path.join(REPO, 'docs', 'language-support.md'), 'utf8'));
    const suitesPath = put('suites.json', suites);
    const base = { suites: suitesPath, registryPath: reg, tablePath: table, frozen: currentFrozen() };

    // a drop: recall falls in the stored measurement while the registry still claims support
    const drop = JSON.parse(JSON.stringify(h)); drop.ecosystems.haskell.detection.layers.taint.fn = 5; drop.ecosystems.haskell.detection.layers.taint.recall = 30 / 35;
    assert.ok(checkFreshness({ ...base, holdout: put('drop.json', drop) }).some((p) => /haskell\/taint/.test(p)), 'a drop is reported');
    // an UNRECORDED IMPROVEMENT: a number rises in the measurement and the registry was not regenerated
    const gain = JSON.parse(JSON.stringify(h)); gain.ecosystems.haskell.privacy.tn = gain.ecosystems.haskell.privacy.tn + 1; gain.ecosystems.haskell.privacy.negatives += 1;
    assert.ok(checkFreshness({ ...base, holdout: put('gain.json', gain) }).length > 0, 'an unrecorded improvement is reported just like a drop');
    // a changed corpus
    assert.ok(checkFreshness({ ...base, holdout: put('same.json', h), frozen: { ...currentFrozen(), labelsSha256: 'a'.repeat(64) } }).some((p) => /different data|labels/i.test(p)), 'changed labels are reported');
    // a hand-edited registry row and a hand-edited table
    const edited = JSON.parse(fs.readFileSync(reg, 'utf8')); edited.languages.nix.rows['nix-eval'].status = 'supported';   // blocked wherever no nix was available: promoting it by hand must be caught
    assert.ok(checkFreshness({ ...base, holdout: put('same2.json', h), registryPath: put('edited.json', edited) }).some((p) => /nix\/nix-eval/.test(p)), 'a hand-promoted row is reported');
    assert.ok(checkFreshness({ ...base, holdout: put('same3.json', h), tablePath: put('t2.md', `${fs.readFileSync(table, 'utf8')}\nextra\n`) }).some((p) => /table|rendering/i.test(p)));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('[QA-002.AC04] a failed family cannot be hidden by an aggregate, by excluded cases, or by mixing SAST with taint or privacy', async () => {
  const { gateLayer, evaluateSupport } = await import('../../src/language/support-registry.js');
  // one weak family inside a strong aggregate still fails the layer
  const layer = { measured: true, tp: 95, fp: 2, fn: 3, tn: 100, precision: 95 / 97, recall: 95 / 98, f1: 0.97, families: { a: { f1: 1 }, b: { f1: 1 }, weak: { f1: 0.4 } } };
  const g = gateLayer(layer, { a: { vulnerable: 9, safe: 9 }, b: { vulnerable: 9, safe: 9 }, weak: { vulnerable: 9, safe: 9 } }, { kind: 'sast' });
  assert.equal(g.ok, false);
  assert.ok(g.reasons.some((r) => /family weak/.test(r)), 'the failing family is named');
  // no case is excluded: every holdout case is either scored or reported as unknown, and the counts are the corpus's own
  const labels = JSON.parse(fs.readFileSync(path.join(HERE, 'corpora', 'data', 'labels', 'cases.json'), 'utf8'));
  for (const eco of ['haskell', 'nix']) {
    const d = holdout.ecosystems[eco].detection;
    const inHoldout = labels.filter((c) => c.ecosystem === eco && c.split === 'holdout');
    assert.equal(d.cases, inHoldout.length, `${eco}: every holdout case was measured`);
    assert.equal(d.scored + d.unknownOutcomes.total, d.cases, `${eco}: scored + unknown accounts for every case`);
    assert.equal(d.scored, inHoldout.filter((c) => c.label !== 'unknown').length);
    // SAST and taint are scored over disjoint sets of families, so neither covers for the other
    const sast = new Set(Object.keys(d.layers.sast.families)); const taint = new Set(Object.keys(d.layers.taint.families));
    for (const f of taint) assert.ok(!sast.has(f), `${eco}: family ${f} is in both layers`);
    assert.equal(d.layers.sast.cases + d.layers.taint.cases, d.scored, `${eco}: the two layers together are exactly the scored cases`);
  }
  // privacy is its own measurement: a perfect taint layer cannot supply it
  const noPrivacy = JSON.parse(JSON.stringify(holdout)); delete noPrivacy.ecosystems.haskell.privacy;
  const ev = evaluateSupport('haskell', { measurement: noPrivacy, suites: suites.results, capabilitySuites: suites.capabilitySuites.haskell, tools: suites.tools, frozen: currentFrozen() });
  assert.equal(ev.rows['privacy-lineage'].status, 'not-measured');
  // an unknown case that returns neither a finding nor a disclosure fails the parser/disclosure rows
  const hidden = JSON.parse(JSON.stringify(holdout)); hidden.ecosystems.haskell.detection.unknownOutcomes.silentClean = 1;
  const ev2 = evaluateSupport('haskell', { measurement: hidden, suites: suites.results, capabilitySuites: suites.capabilitySuites.haskell, tools: suites.tools, frozen: currentFrozen() });
  assert.notEqual(ev2.rows.parser.status, 'supported');
  assert.notEqual(ev2.rows.sast.status, 'supported');
});
