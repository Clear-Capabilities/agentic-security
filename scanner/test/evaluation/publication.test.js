// QA-008: the published scorecard, the bake-off recipe and the offline public reproduction.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildScorecard, renderScorecardMarkdown, summarizeMeasurement } from '../../src/posture/accuracy-scorecard.js';
import { validateBakeoffManifest, judgeBakeoff, resolveParticipants, workloadDigestOf, UNAVAILABLE_REASONS } from '../../src/posture/evaluation/bakeoff.js';

const REPO = path.resolve(import.meta.dirname, '..', '..', '..');
const read = (...p) => fs.readFileSync(path.join(REPO, ...p), 'utf8');
const json = (...p) => JSON.parse(read(...p));
const node = (args, opts = {}) => spawnSync(process.execPath, args, { cwd: REPO, encoding: 'utf8', timeout: 180000, ...opts });

// ---------------------------------------------------------------- QA-008.AC01

const baseInputs = (over = {}) => ({
  provenance: { engineVersion: '0.162.0', bundleSha256: 'a'.repeat(64), commit: 'b'.repeat(40), worktreeClean: true, nodeVersion: 'v24', generatedAt: '2026-10-09T00:00:00.000Z', ...over },
  corpusDetail: [], selfScan: {}, committed: {},
});
const HISTORICAL = {
  measuredAt: '2026-08-23', engineVersion: '0.141.0',
  population: { totalEntries: 1004, scoredEntries: 991, unscored: new Array(13).fill({ id: 'x', reason: 'r' }) },
  overall: { tp: 54, fp: 45, fn: 700, tn: 1, precision: { n: 54, d: 99 }, recall: { n: 54, d: 754 }, f1: 0.127 },
};
const scorecard = (inputs) => ({ model: buildScorecard(inputs), md: renderScorecardMarkdown(buildScorecard(inputs)) });

describe('[QA-008.AC01] the scorecard identifies the clean measured commit and bundle, and keeps the historical independent record dated and separate', () => {
  test('a clean measurement names its commit and bundle as identifying the measured tree; a dirty one says it does not', () => {
    const clean = scorecard(baseInputs());
    assert.equal(clean.model.measurement.cleanMeasurement, true);
    assert.equal(clean.model.measurement.commit, 'b'.repeat(40)); assert.equal(clean.model.measurement.bundleSha256, 'a'.repeat(64));
    assert.match(clean.md, /clean measurement: the commit and bundle above identify the measured tree/);
    const dirty = scorecard(baseInputs({ worktreeClean: false }));
    assert.equal(dirty.model.measurement.cleanMeasurement, false);
    assert.match(dirty.md, /NOT a clean measurement/);
    assert.match(summarizeMeasurement({ engineVersion: 'x' }, null).identity, /not recorded/, 'unknown cleanliness is not read as clean');
  });

  test('the 0.141.0 independent record is kept, dated and labelled historical; the current engine is unmeasured and no figure is combined', () => {
    const { model, md } = scorecard({ ...baseInputs(), committed: { independent: HISTORICAL } });
    const ind = model.committedInputs.independent;
    assert.equal(ind.engineVersion, '0.141.0'); assert.equal(ind.measuredAt, '2026-08-23');
    assert.equal(ind.historical, true); assert.equal(ind.comparableToCurrentEngine, false);
    assert.equal(model.measurement.currentEngineIndependentAccuracy, 'unmeasured');
    assert.equal(model.measurement.historicalIndependentRecord.engineVersion, '0.141.0');
    assert.match(md, /## Independent evaluation population: historical record \(engine 0\.141\.0, 2026-08-23\)/);
    assert.match(md, /not a measurement of the\s+engine this scorecard describes \(0\.162\.0\)/);
    assert.match(md, /never combined into one accuracy figure/);
    assert.match(md, /Independent accuracy of THIS engine \| unmeasured/);
    // the old record still carries its own denominator and is not blended with the curated corpus
    assert.match(md, /54\/99 \(54\.5%\)/);
    assert.doesNotMatch(md, /That gap is the most useful number/, 'no sentence invites reading the old figure beside the new corpus as one claim');
    for (const key of Object.keys(model)) assert.doesNotMatch(key, /combined|blended|merged/i);
  });

  test('control: an independent record measured on the SAME engine is current, not historical', () => {
    const { model, md } = scorecard({ ...baseInputs({ engineVersion: '0.141.0' }), committed: { independent: HISTORICAL } });
    assert.equal(model.committedInputs.independent.historical, false); assert.equal(model.committedInputs.independent.comparableToCurrentEngine, true);
    assert.match(md, /## Independent evaluation population — the number that matters/);
  });

  test('the committed scorecard still carries the 0.141.0 record with its date, and `npm run scorecard:check` passes', () => {
    const committed = json('docs', 'scorecard.json');
    const ind = committed.committedInputs.independent;
    assert.equal(ind.engineVersion, '0.141.0'); assert.equal(ind.measuredAt, '2026-08-23');
    const r = node(['scripts/scorecard-check.mjs']);
    assert.equal(r.status, 0, r.stderr);
  });
});

// ---------------------------------------------------------------- QA-008.AC02

const MANIFEST = () => json('docs', 'guides', 'bakeoff', 'manifest.example.json');
const ENTRIES = () => json('docs', 'guides', 'bakeoff', 'entries.example.json');
const RUNS = () => json('docs', 'guides', 'bakeoff', 'runs.example.json');
const ADAPTERS = () => json('docs', 'guides', 'bakeoff', 'adapters.example.json');
const clone = (x) => JSON.parse(JSON.stringify(x));

describe('[QA-008.AC02] the bake-off recipe pins workload, scope, provider, standard, limits and failures; an unavailable comparator is not evaluated', () => {
  test('the shipped example manifest is valid, and every pinned field is required (each removal is refused)', () => {
    assert.equal(validateBakeoffManifest(MANIFEST()).ok, true);
    for (const [field, mutate] of Object.entries({
      workload: (m) => { delete m.workload; }, workloadDigest: (m) => { m.workload.workloadDigest = 'sha256:' + '0'.repeat(64); }, scope: (m) => { delete m.scope; },
      standard: (m) => { delete m.verification; }, limits: (m) => { m.limits = {}; }, failurePolicy: (m) => { m.failurePolicy = 'drop-failures'; },
      provider: (m) => { delete m.participants[0].provider; }, engine: (m) => { m.participants = m.participants.filter((p) => p.slot !== 'this-engine'); },
      alone: (m) => { m.participants = m.participants.slice(0, 1); },
    })) {
      const m = clone(MANIFEST()); mutate(m);
      assert.equal(validateBakeoffManifest(m).ok, false, field);
    }
  });

  test('slots are generic: a name that is not this-engine or comparator-<letter> is refused', () => {
    for (const bad of ['SomeScanner', 'comparator-1', 'comparator', 'comparator-AB', '']) {
      const m = clone(MANIFEST()); m.participants[1].slot = bad;
      assert.equal(validateBakeoffManifest(m).ok, false, JSON.stringify(bad));
    }
    const m = clone(MANIFEST()); m.participants[2].slot = 'comparator-a';
    assert.equal(validateBakeoffManifest(m).ok, false, 'duplicate slot');
  });

  test('unavailable adapters mark the comparators not-evaluated with a typed reason; they are neither a zero nor a loss, and nothing is claimed', () => {
    const report = judgeBakeoff({ manifest: MANIFEST(), entries: ENTRIES(), runs: RUNS(), adapters: ADAPTERS() });
    assert.equal(report.ok, true);
    const by = Object.fromEntries(report.participants.map((p) => [p.slot, p]));
    assert.equal(by['this-engine'].state, 'evaluated');
    assert.equal(by['comparator-a'].state, 'not-evaluated'); assert.equal(by['comparator-a'].reason, 'not-installed');
    assert.equal(by['comparator-b'].reason, 'no-licence');
    assert.ok(UNAVAILABLE_REASONS.includes(by['comparator-a'].reason));
    assert.equal(report.comparison, null); assert.deepEqual(report.claims, []);
    assert.equal(report.superiority, 'none claimed');
    assert.ok(report.withheld.some((w) => w.slot === 'comparator-a' && /not evaluated/.test(w.reason)));
    assert.ok(report.endToEnd['this-engine'], 'the engine\'s own end-to-end view is still published');
    // a slot with no adapter at all is `not-configured`, never silently absent
    const none = resolveParticipants(MANIFEST(), { 'this-engine': { available: true } });
    assert.equal(none.find((p) => p.slot === 'comparator-b').reason, 'not-configured');
  });

  test('with two participants evaluated on the identical workload the comparison and an accuracy claim exist; superiority still is not claimed', () => {
    const runs = RUNS();
    runs['comparator-a'] = { ...clone(runs['this-engine']), costUsd: null };
    const adapters = { ...ADAPTERS(), 'comparator-a': { available: true } };
    const report = judgeBakeoff({ manifest: MANIFEST(), entries: ENTRIES(), runs, adapters });
    assert.ok(report.comparison && report.comparison.ok);
    assert.equal(report.comparison.intersection, 2);
    assert.ok(report.claims.some((c) => c.kind === 'accuracy'));
    assert.equal(report.claims.some((c) => c.kind === 'cost'), false, 'no cost claim without measured costs');
    assert.ok(report.withheld.some((w) => /did not report a measured cost/.test(w.reason)));
    assert.equal(report.superiority, 'none claimed');
    // a cost claim appears only when both measured
    runs['this-engine'].costUsd = 0; runs['comparator-a'].costUsd = 1.5;
    const priced = judgeBakeoff({ manifest: MANIFEST(), entries: ENTRIES(), runs, adapters });
    assert.ok(priced.claims.some((c) => c.kind === 'cost' && c.costsUsd['comparator-a'] === 1.5));
  });

  test('a participant that ran a different workload or standard is flagged and left out; a failure counts as a miss end to end', () => {
    const runs = RUNS();
    runs['comparator-a'] = { ...clone(runs['this-engine']), workloadDigest: 'sha256:' + '1'.repeat(64) };
    runs['comparator-b'] = { ...clone(runs['this-engine']), verificationStandard: 'a different standard' };
    const adapters = { 'this-engine': { available: true }, 'comparator-a': { available: true }, 'comparator-b': { available: true } };
    const report = judgeBakeoff({ manifest: MANIFEST(), entries: ENTRIES(), runs, adapters });
    assert.equal(report.comparison, null, 'only one comparable participant is left');
    assert.equal(report.withheld.filter((w) => /not comparable/.test(w.reason)).length, 2);
    // a participant that failed on an entry: end to end it is a miss
    const failed = RUNS(); failed['this-engine'].results['syn-sqli-js'] = { error: 'timeout' };
    const r = judgeBakeoff({ manifest: MANIFEST(), entries: ENTRIES(), runs: failed, adapters: ADAPTERS() });
    assert.equal(r.endToEnd['this-engine'].failedOrMissing, 1);
    assert.equal(r.endToEnd['this-engine'].detected, 1);
    assert.equal(r.endToEnd['this-engine'].recallEndToEnd, 0.5);
  });

  test('the workload digest is derived from the targets: changing a target changes it, so a quietly different workload cannot reuse a manifest', () => {
    const w = clone(MANIFEST().workload);
    const d = workloadDigestOf(w);
    w.treeDigests['syn-cmd-py'] = 'sha256:' + '2'.repeat(64);
    assert.notEqual(workloadDigestOf(w), d);
    assert.equal(workloadDigestOf({ ...MANIFEST().workload, targetIds: [...MANIFEST().workload.targetIds].reverse() }), MANIFEST().workload.workloadDigest, 'order does not matter');
  });

  test('the driver commands: validate exits 0/1, judge prints the not-evaluated states', () => {
    const ok = node(['scripts/evaluation.mjs', 'bakeoff-validate', 'docs/guides/bakeoff/manifest.example.json']);
    assert.equal(ok.status, 0, ok.stderr);
    const bad = clone(MANIFEST()); bad.failurePolicy = 'drop-failures';
    const tmp = path.join(REPO, 'docs', 'guides', 'bakeoff', '.tmp-bad-manifest.json');
    fs.writeFileSync(tmp, JSON.stringify(bad));
    try { assert.equal(node(['scripts/evaluation.mjs', 'bakeoff-validate', tmp]).status, 1); } finally { fs.rmSync(tmp, { force: true }); }
    const j = node(['scripts/evaluation.mjs', 'bakeoff-judge', 'docs/guides/bakeoff/manifest.example.json', '--entries', 'docs/guides/bakeoff/entries.example.json', '--runs', 'docs/guides/bakeoff/runs.example.json', '--adapters', 'docs/guides/bakeoff/adapters.example.json']);
    assert.equal(j.status, 0, j.stderr);
    assert.equal(JSON.parse(j.stdout).participants.filter((p) => p.state === 'not-evaluated').length, 2);
  });

  test('the shipped recipe and example files name no external tool: slots are generic and the recipe says so', () => {
    const recipe = read('docs', 'guides', 'bakeoff-recipe.md');
    assert.match(recipe, /comparator-a/); assert.match(recipe, /names no other tool/);
    const m = MANIFEST();
    for (const p of m.participants) assert.match(p.slot, /^(?:this-engine|comparator-[a-z])$/);
    for (const p of m.participants) assert.match(p.provider.name, /^(?:local|operator-supplied)$/);
  });
});

// ---------------------------------------------------------------- QA-008.AC03

describe('[QA-008.AC03] an offline miniature public reproduction runs scoring and negative controls without sealed labels; every referenced command and artifact exists', () => {
  test('npm run reproduce:mini equivalent exits 0 with every control behaving, using no network and no sealed labels', () => {
    const r = node(['scripts/public-reproduction.mjs', '--json'], { env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C', AGENTIC_SECURITY_OFFLINE: '1' } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.synthetic, true); assert.equal(out.allControlsBehaved, true);
    assert.deepEqual(out.controls.map((c) => c.name).sort(), ['flag-everything', 'gates-need-data', 'null-engine', 'planted-leak', 'shuffled-labels']);
    assert.ok(out.controls.every((c) => c.ok));
    assert.equal(out.gates.overall, 'insufficient-population');
    const src = read('scripts', 'public-reproduction.mjs');
    assert.doesNotMatch(src, /custodianReadLabels|sealed-labels|https?:\/\/|fetch\(/, 'no label custody, no network');
  });

  test('each control can FAIL: with the measuring path broken on purpose the script exits 1 and names that control', () => {
    for (const fault of ['null-engine', 'flag-everything', 'shuffled-labels', 'planted-leak']) {
      const r = node(['scripts/public-reproduction.mjs', '--json', '--fault', fault]);
      assert.equal(r.status, 1, `${fault}: ${r.stderr}`);
      const out = JSON.parse(r.stdout);
      assert.equal(out.allControlsBehaved, false);
      assert.deepEqual(out.controls.filter((c) => !c.ok).map((c) => c.name), [fault]);
    }
    assert.equal(node(['scripts/public-reproduction.mjs', '--fault', 'nonsense']).status, 2);
  });

  test('every npm script, repository path and script command the new documents reference exists', () => {
    const pkg = json('scanner', 'package.json');
    const docs = ['docs/guides/bakeoff-recipe.md', 'docs/guides/miniature-reproduction.md', 'docs/guides/evaluation-reporting.md', 'docs/guides/engine-mechanism-evidence.md'];
    const problems = [];
    for (const d of docs) {
      if (!fs.existsSync(path.join(REPO, d))) { problems.push(`missing document ${d}`); continue; }
      const text = read(...d.split('/'));
      for (const m of text.matchAll(/npm run ([A-Za-z0-9:_-]+)/g)) if (!pkg.scripts[m[1]]) problems.push(`${d}: npm run ${m[1]} is not a script`);
      for (const m of text.matchAll(/node (scripts\/[A-Za-z0-9._/-]+\.mjs)(?: ([a-z-]+))?/g)) {
        if (!fs.existsSync(path.join(REPO, m[1]))) { problems.push(`${d}: ${m[1]} does not exist`); continue; }
        if (m[1] === 'scripts/evaluation.mjs' && m[2] && !/^--/.test(m[2]) && !/<|\.json$/.test(m[2])) {
          const header = read('scripts', 'evaluation.mjs');
          if (!new RegExp(`^//\\s+${m[2]}\\b`, 'm').test(header)) problems.push(`${d}: evaluation.mjs has no ${m[2]} command`);
        }
      }
      for (const m of text.matchAll(/`((?:docs|scanner|scripts|bench)\/[A-Za-z0-9._/@-]+)`/g)) {
        const p = m[1].replace(/\/$/, '');
        if (/[*<>]/.test(p)) continue;
        if (!fs.existsSync(path.join(REPO, p))) problems.push(`${d}: ${p} does not exist`);
      }
    }
    assert.deepEqual(problems, []);
  });

  test('the package scripts the documents rely on are real: reproduce:mini and dev-recovery point at existing files', () => {
    const pkg = json('scanner', 'package.json');
    for (const s of ['reproduce:mini', 'dev-recovery', 'evaluation', 'evaluation:synthetic', 'test:evaluation']) assert.ok(pkg.scripts[s], s);
    for (const s of ['reproduce:mini', 'dev-recovery']) {
      const file = /\.\.\/(scripts\/[\w.-]+)/.exec(pkg.scripts[s])[1];
      assert.ok(fs.existsSync(path.join(REPO, file)), file);
    }
  });
});
