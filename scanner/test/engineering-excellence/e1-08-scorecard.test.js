// E1-08: the scorecard shows independent accuracy and the curated regression net as two different things, with provenance.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildScorecard, renderScorecardMarkdown, summarizeIndependentRun, summarizeMeasurement } from '../../src/posture/accuracy-scorecard.js';
import { scorePopulation, headline } from '../../../bench/independent/scorer.mjs';

const entry = (i, lang) => ({ id: `${lang}-${i}`, repo: `org/${lang}-${i}`, cve: null, parentCommit: `p${lang}${i}`, fixCommit: `f${lang}${i}`, language: lang, cwe: 'CWE-89' });
const row = (e, hit) => ({ id: e.id, cwe: e.cwe, language: e.language, repo: e.repo, tp: hit ? 1 : 0, fn: hit ? 0 : 1, fp: 0, tn: 1, tpWide: hit ? 1 : 0, fnWide: hit ? 0 : 1, fpWide: 0, tnWide: 1, tpLocal: hit ? 1 : 0, fnLocal: hit ? 0 : 1, fpLocal: 0, tnLocal: 1, survivedFix: 0, survivedFixWide: 0, preFindings: 1, postFindings: 0 });

function fakeRun({ plan = { python: { n: 60, hits: 24 }, go: { n: 40, hits: 12 }, kotlin: { n: 3, hits: 1 } }, engineVersion = '9.9.9', valid = true, dropRows = 0, unscored = 0 } = {}) {
  const entries = []; const rows = [];
  for (const [lang, { n, hits }] of Object.entries(plan)) for (let i = 0; i < n; i++) { const e = entry(i, lang); entries.push(e); rows.push(row(e, i < hits)); }
  const un = Array.from({ length: unscored }, (_, i) => ({ id: `u${i}`, reason: 'not fetched' }));
  const all = [...entries, ...un.map((u) => ({ ...entry(0, 'x'), id: u.id, repo: `org/${u.id}`, language: 'python' }))];
  const scoring = scorePopulation({ rows: rows.slice(0, rows.length - dropRows), unscored: un, manifestEntries: all, protocolHash: 'sha256:t' });
  return {
    runId: 'run-test', engineVersion, mergedAt: '2026-10-16T12:00:00.000Z', configuration: { deep: true, llm: 'none' },
    identity: { sourceCommit: 'c'.repeat(40), bundleSha256: 'a'.repeat(64), bundleSidecarSha256: 'a'.repeat(64), measurementValid: valid, invalidReasons: valid ? [] : ['dirty_worktree'], config: { modelEndpointMode: 'none' }, toolchain: { node: 'v24.0.0', os: 'darwin' } },
    population: { role: 'independent population', selection: { entries: all.length, counts: { python: 60, go: 40, kotlin: 3 }, splitNames: ['dev', 'validation'], perLanguage: 60 }, manifestSha256: 'm'.repeat(64), splitsProtocolHash: 'sha256:' + 's'.repeat(64), sealedSplitTouched: false },
    splits: { protocolHash: 'sha256:' + 's'.repeat(64) },
    scoring, headline: headline(scoring),
  };
}

const CURATED = [
  { cve: 'A', tier: 'capability', cwe: 'CWE-89', language: 'javascript', status: 'pre:TP post:TN' },
  { cve: 'B', tier: 'capability', cwe: 'CWE-78', language: 'javascript', status: 'pre:TP post:TN' },
];
function scorecardWith(run) {
  const model = buildScorecard({
    provenance: { engineVersion: '9.9.9', bundleSha256: 'a'.repeat(64), commit: 'c'.repeat(40), nodeVersion: 'v24.0.0', generatedAt: '2026-10-16T12:00:00.000Z', worktreeClean: true },
    corpusDetail: CURATED,
    selfScan: { targets: { hooks: { total: 1, byFile: { 'a.js': 1 } } }, polyglot: { total: 0, byLanguage: {} } },
    committed: { corpusBaseline: { generatedAt: '2026-07-27', total: 2, passing: 2 }, independentRun: run },
  });
  return { model, md: renderScorecardMarkdown(model) };
}

test('without an independent run of this engine the scorecard says unmeasured and shows no independent section', () => {
  const { model, md } = scorecardWith(null);
  assert.equal(model.measurement.currentEngineIndependentAccuracy, 'unmeasured');
  assert.match(md, /Independent accuracy of THIS engine \| unmeasured/);
  assert.doesNotMatch(md, /Independent accuracy of this engine \(run/);
});

test('with a clean run of this engine, the section carries commit, bundle, date, population, denominators, per-language rates and intervals', () => {
  const { model, md } = scorecardWith(fakeRun());
  assert.equal(model.measurement.currentEngineIndependentAccuracy, 'measured');
  assert.match(md, /Independent accuracy of THIS engine \| measured on a clean commit/);
  const sec = md.slice(md.indexOf('## Independent accuracy of this engine (run run-test)'));
  assert.ok(sec.length > 500);
  assert.match(sec, /Measured at commit \| `c{40}`/);
  assert.match(sec, /Bundle SHA-256 \| `a{64}` \(sidecar matches\)/);
  assert.match(sec, /Measurement \| valid: clean tree, bundle matches its digest/);
  assert.match(sec, /Date \(UTC\) \| 2026-10-16T12:00:00\.000Z/);
  assert.match(sec, /dev \+ validation only/);
  assert.match(sec, /sealed split touched: no/);
  assert.match(sec, /Entries in scope \| 103: scored 103, unscored 0, unaccounted 0; denominators reconcile/);
  assert.match(sec, /\*\*Headline \(localized\):\*\* precision 100\.0% \(37\/37\), recall 35\.9% \(37\/103\), F1 0\.529/);
  assert.match(sec, /\| python \| 60 \| 40\.0% \(24\/60\) \| 100\.0% \(24\/24\) \| [\d.]+% to [\d.]+% \| reportable \|/);
  assert.match(sec, /\| go \| 40 \| 30\.0% \(12\/40\)/);
});

test('a language below the declared minimum shows counts and the reason, never a rate, and is listed as unmeasured', () => {
  const { md } = scorecardWith(fakeRun());
  assert.match(md, /\| kotlin \| 3 \| counts only \(1 true positive, 2 missed\) \| \| \| insufficient_population \(below 30\) \|/);
  assert.match(md, /Languages with no rate in this run: kotlin\. They are unmeasured here, not good or bad\./);
});

test('every rate in the independent section carries its numerator and denominator', () => {
  const { md } = scorecardWith(fakeRun());
  const sec = md.slice(md.indexOf('## Independent accuracy of this engine'));
  const end = sec.indexOf('\n## ', 10);
  const body = end > 0 ? sec.slice(0, end) : sec;
  for (const line of body.split('\n').filter((l) => /\d\.\d%/.test(l) && !/interval|to \d/.test(l))) assert.match(line, /\(\d+\/\d+\)/, line);
});

test('a run that is not on a clean tree is shown as not release grade, with the reason', () => {
  const { model, md } = scorecardWith(fakeRun({ valid: false }));
  assert.equal(model.measurement.currentEngineIndependentAccuracy, 'measured_not_release_grade');
  assert.match(md, /NOT valid for a release claim: dirty_worktree/);
  assert.match(md, /measured, but NOT release grade/);
});

test('a run of an older engine is a historical record, kept and labelled, and the engine above stays unmeasured', () => {
  const { model, md } = scorecardWith(fakeRun({ engineVersion: '0.141.0' }));
  assert.equal(model.measurement.currentEngineIndependentAccuracy, 'unmeasured');
  assert.match(md, /## Independent run run-test: historical record \(engine 0\.141\.0\)/);
  assert.match(md, /NOT the engine this scorecard describes/);
});

test('denominators that do not reconcile, or a mostly-unscored run, are stated and give no headline figure', () => {
  const bad = scorecardWith(fakeRun({ dropRows: 4 })).md;
  assert.match(bad, /DO NOT reconcile/);
  assert.match(bad, /No headline figure:\*\*/);
  const sparse = fakeRun({ plan: { python: { n: 10, hits: 5 } } });
  const m = scorecardWith(sparse).md;
  assert.match(m, /No headline figure:\*\* insufficient_population/);
});

test('the curated regression net stays a separate instrument: no F1 is drawn from it and it is never merged with the independent figures', () => {
  const { md } = scorecardWith(fakeRun());
  assert.match(md, /regression net/i);
  assert.match(md, /never combined/);
  const curated = md.slice(0, md.indexOf('## Independent accuracy of this engine'));
  assert.doesNotMatch(curated, /\bF1\b[^.\n]*\d\.\d{2,}/, 'no F1 value is computed from the curated corpus');
});

test('summarizeIndependentRun is null without a run and never throws on a thin one', () => {
  assert.equal(summarizeIndependentRun(null, {}), null);
  assert.equal(summarizeIndependentRun({}, {}), null);
  const s = summarizeMeasurement({ engineVersion: '1.0.0', worktreeClean: true }, null, fakeRun({ engineVersion: '1.0.0' }));
  assert.equal(s.independentRun.comparableToCurrentEngine, true);
  assert.equal(s.currentEngineIndependentAccuracy, 'measured');
});
