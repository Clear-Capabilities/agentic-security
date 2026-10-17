// E1-03: the independent-population scorer. A truth table for the cases the PRD lists, plus agreement with the runner on real data.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { REPO } from './helpers.js';
import { labelUsable, rowFor } from '../../../bench/independent/runner.mjs';
import { DEFINITIONS, MIN_ENTRIES_FOR_RATE, aggregatesOf, classifyUnscored, headline, metricsOf, scorePopulation } from '../../../bench/independent/scorer.mjs';

// ---- rowFor: one entry's row from its findings -------------------------------------------------------------------------------

const ENTRY = { id: 'GHSA-t1', cwe: 'CWE-89', language: 'python', repo: 'org/r', files: ['app/db.py'] };
const ranges = (pre = [[10, 12]], post = [[10, 12]]) => ({ local: () => pre, postSide: () => post });
const F = (cwe, line, file = 'app/db.py', extra = {}) => ({ cwe, line, file, parser: 'IR-TAINT', ...extra });

test('a matching finding on a changed line is a localized true positive; the fixed side being silent is a true negative', () => {
  const r = rowFor(ENTRY, [F('CWE-89', 11)], [], ranges());
  assert.deepEqual([r.tpLocal, r.fnLocal, r.fpLocal, r.tnLocal], [1, 0, 0, 1]);
  assert.deepEqual([r.tp, r.fn, r.fp, r.tn], [1, 0, 0, 1]);
  assert.equal(r.matchedParser, 'IR-TAINT');
  assert.equal(r.matchedLine, 11);
});

test('the right CWE in the right file but far from the fix is file-scoped only, not a localized hit', () => {
  const r = rowFor(ENTRY, [F('CWE-89', 400)], [], ranges());
  assert.equal(r.tp, 1, 'file-scoped credit');
  assert.equal(r.tpLocal, 0);
  assert.equal(r.fnLocal, 1, 'a miss under the claimed definition');
});

test('a finding in a file the advisory does not name is excluded from the file-scoped and localized definitions but counted by the wide one', () => {
  const r = rowFor(ENTRY, [F('CWE-89', 11, 'other/file.py')], [], ranges());
  assert.equal(r.tp, 0);
  assert.equal(r.tpLocal, 0);
  assert.equal(r.tpWide, 1);
});

test('a finding that survives the fix is a false positive on the fixed side and is reported as survival', () => {
  const r = rowFor(ENTRY, [F('CWE-89', 11)], [F('CWE-89', 11)], ranges());
  assert.equal(r.fp, 1);
  assert.equal(r.tn, 0);
  assert.equal(r.survivedFix, 1);
  assert.equal(r.fpLocal, 0, 'the fixed-side finding of a localized TP is survival, not a separate false positive');
  const silent = rowFor(ENTRY, [F('CWE-89', 11)], [F('CWE-89', 300)], ranges());
  assert.equal(silent.survivedFix, 0, 'a finding elsewhere in the file is not survival of the fixed code');
});

test('duplicate findings never inflate a count: two findings for the same defect are one true positive', () => {
  const r = rowFor(ENTRY, [F('CWE-89', 11), F('CWE-89', 11), F('CWE-89', 12)], [F('CWE-89', 11), F('CWE-89', 11)], ranges());
  assert.equal(r.tpLocal, 1);
  assert.equal(r.fn, 0);
  assert.equal(r.fp, 1);
  assert.equal(r.preFindings, 3, 'the alert burden is still reported');
  assert.equal(r.postFindings, 2);
});

test('several CWEs reported on the same code credit only the labelled one', () => {
  const same = [F('CWE-79', 11), F('CWE-89', 11), F('CWE-22', 11)];
  assert.equal(rowFor(ENTRY, same, [], ranges()).tpLocal, 1);
  assert.equal(rowFor({ ...ENTRY, cwe: 'CWE-79' }, same, [], ranges()).tpLocal, 1);
  assert.equal(rowFor({ ...ENTRY, cwe: 'CWE-918' }, same, [], ranges()).tpLocal, 0, 'a CWE that was not reported is a miss, however many others were');
});

test('an unknown or malformed CWE never matches and never crashes', () => {
  for (const cwe of ['CWE-99999', 'not-a-cwe', '', undefined, null, 'CWE-']) {
    const r = rowFor({ ...ENTRY, cwe }, [F('CWE-89', 11)], [], ranges());
    assert.equal(r.tpLocal, 0, String(cwe));
    assert.equal(r.fnLocal, 1);
  }
  assert.equal(labelUsable({ cwe: 'CWE-89' }), true);
  for (const cwe of ['CWE-', 'x', '', undefined, 89]) assert.equal(labelUsable({ cwe }), false, String(cwe));
});

test('the CWE hierarchy credits a parent or child of the label only on the localized definition', () => {
  const r = rowFor({ ...ENTRY, cwe: 'CWE-78' }, [F('CWE-77', 11)], [], ranges());
  assert.equal(r.tpLocal, 1, 'CWE-77 is the recorded parent of CWE-78');
  assert.equal(r.tp, 0, 'the file-scoped diagnostic stays exact');
});

// ---- scorePopulation: denominators --------------------------------------------------------------------------------------------

const mkEntry = (i, over = {}) => ({ id: `E${i}`, repo: `org/r${i}`, cve: null, parentCommit: `p${i}`, fixCommit: `f${i}`, language: 'python', cwe: 'CWE-89', ...over });
const mkRow = (i, outcome = 'tp', over = {}) => {
  const base = { id: `E${i}`, cwe: 'CWE-89', language: 'python', repo: `org/r${i}`, tp: 0, fn: 0, fp: 0, tn: 0, tpWide: 0, fnWide: 0, fpWide: 0, tnWide: 0, tpLocal: 0, fnLocal: 0, fpLocal: 0, tnLocal: 0, survivedFix: 0, survivedFixWide: 0, preFindings: 1, postFindings: 0 };
  const set = (suffix, v) => { for (const s of ['', 'Wide', 'Local']) Object.assign(base, v(s)); };
  if (outcome === 'tp') set('', (s) => ({ [`tp${s}`]: 1, [`tn${s}`]: 1 }));
  if (outcome === 'fn') set('', (s) => ({ [`fn${s}`]: 1, [`tn${s}`]: 1 }));
  if (outcome === 'fp') set('', (s) => ({ [`fn${s}`]: 1, [`fp${s}`]: 1 }));
  return { ...base, ...over };
};
const population = (n, outcomes, lang = 'python') => ({ entries: Array.from({ length: n }, (_, i) => mkEntry(i, { language: lang })), rows: Array.from({ length: n }, (_, i) => mkRow(i, outcomes(i), { language: lang })) });

test('zero scored entries: no division by zero, every group insufficient, nothing quotable, and all entries accounted as unscored', () => {
  const entries = Array.from({ length: 5 }, (_, i) => mkEntry(i));
  const s = scorePopulation({ rows: [], unscored: entries.map((e) => ({ id: e.id, reason: 'not fetched' })), manifestEntries: entries });
  assert.equal(s.denominators.scored, 0);
  assert.equal(s.denominators.unscored, 5);
  assert.equal(s.denominators.unaccounted, 0);
  assert.equal(s.denominators.reconciles, true);
  const t = s.definitions.localized.total;
  assert.equal(t.status, 'insufficient_population');
  assert.equal(t.precision, undefined);
  assert.deepEqual(metricsOf({ tp: 0, fp: 0, fn: 0, tn: 0 }).precision, { n: 0, d: 0, value: null });
  assert.equal(metricsOf({ tp: 0, fp: 0, fn: 0, tn: 0 }).f1, null);
  const h = headline(s);
  assert.equal(h.quotable, false);
  assert.match(h.reason, /insufficient_population/);
});

test('entries that were neither scored nor reported unscored are counted as unaccounted, and the totals stop reconciling', () => {
  const { entries, rows } = population(40, (i) => (i % 2 ? 'tp' : 'fn'));
  const s = scorePopulation({ rows: rows.slice(0, 30), unscored: [{ id: 'E30', reason: 'scan failed: boom' }], manifestEntries: entries });
  assert.equal(s.denominators.scored, 30);
  assert.equal(s.denominators.unscored, 1);
  assert.equal(s.denominators.unaccounted, 9);
  assert.equal(s.denominators.reconciles, false);
  assert.equal(s.denominators.unaccountedExamples.length, 5);
  assert.equal(headline(s).quotable, false, 'a report whose denominators do not reconcile is not quotable');
});

test('unscored entries are in no denominator: they are not misses and not negatives, and they are counted by cause', () => {
  const { entries, rows } = population(40, (i) => (i < 20 ? 'tp' : 'fn'));
  const extra = Array.from({ length: 6 }, (_, k) => mkEntry(100 + k));
  const reasons = ['not fetched', 'scan failed: crash', 'timed out after 600000 ms', 'advisory file(s) absent from the materialised pre/ tree: a.py', 'parse error in x.py', 'weird'];
  const s = scorePopulation({ rows, unscored: extra.map((e, k) => ({ id: e.id, reason: reasons[k] })), manifestEntries: [...entries, ...extra] });
  const base = scorePopulation({ rows, unscored: [], manifestEntries: entries });
  assert.deepEqual(s.definitions.localized.total.tp, base.definitions.localized.total.tp);
  assert.equal(s.definitions.localized.total.fn, base.definitions.localized.total.fn);
  assert.equal(s.definitions.localized.total.tn, base.definitions.localized.total.tn);
  assert.deepEqual(s.denominators.unscoredByClass, { acquisition: 1, other: 1, parse: 1, scan_failure: 1, scope_file_absent: 1, timeout: 1 });
  assert.equal(s.denominators.reconciles, true);
});

test('classification of unscored reasons', () => {
  assert.equal(classifyUnscored('not fetched, run bench:independent:fetch'), 'acquisition');
  assert.equal(classifyUnscored('scan failed: Error: x'), 'scan_failure');
  assert.equal(classifyUnscored('entry exceeded the 600000 ms watchdog'), 'timeout');
  assert.equal(classifyUnscored('label has no usable CWE (null)'), 'label_unusable');
  assert.equal(classifyUnscored(''), 'other');
});

test('a duplicate row, a row outside the run and a row that is also reported unscored are flagged, and a duplicate is counted once', () => {
  const { entries, rows } = population(35, () => 'tp');
  const s = scorePopulation({ rows: [...rows, rows[0], mkRow(999, 'tp')], unscored: [{ id: 'E1', reason: 'x' }], manifestEntries: entries });
  assert.equal(s.denominators.scored, 35);
  assert.deepEqual(s.denominators.duplicateRows, ['E0', 'E1']);
  assert.deepEqual(s.denominators.rowsNotInScope, ['E999']);
  assert.equal(s.denominators.reconciles, false);
  assert.equal(s.definitions.localized.total.tp, 35);
});

// ---- metrics, aggregates, populations ---------------------------------------------------------------------------------------

test('a group below the minimum is counts only; at the minimum it carries a rate with its numerator and denominator', () => {
  const small = population(MIN_ENTRIES_FOR_RATE - 1, () => 'tp');
  const s1 = scorePopulation({ rows: small.rows, manifestEntries: small.entries });
  assert.equal(s1.definitions.localized.total.status, 'insufficient_population');
  assert.equal(s1.definitions.localized.total.tp, MIN_ENTRIES_FOR_RATE - 1);
  assert.match(s1.definitions.localized.total.note, /counts only, no rate/);
  const big = population(MIN_ENTRIES_FOR_RATE, (i) => (i < 10 ? 'tp' : 'fn'));
  const s2 = scorePopulation({ rows: big.rows, manifestEntries: big.entries });
  const t = s2.definitions.localized.total;
  assert.equal(t.status, 'reportable');
  assert.deepEqual(t.recall, { n: 10, d: 30, value: 10 / 30 });
  assert.deepEqual(t.precision, { n: 10, d: 10, value: 1 });
  assert.ok(Math.abs(t.f1 - (2 * 10) / (2 * 10 + 0 + 20)) < 1e-12);
});

test('micro, macro and weighted F1 are computed from reportable groups only and differ when the groups differ', () => {
  const py = population(40, (i) => (i < 30 ? 'tp' : 'fn'), 'python');
  const go = population(30, (i) => (i < 6 ? 'tp' : 'fn'), 'go');
  const tiny = population(5, () => 'tp', 'kotlin');
  const rows = [...py.rows, ...go.rows.map((r) => ({ ...r, id: `G${r.id}` })), ...tiny.rows.map((r) => ({ ...r, id: `K${r.id}` }))];
  const entries = [...py.entries, ...go.entries.map((e) => ({ ...e, id: `G${e.id}`, repo: `go/${e.repo}` })), ...tiny.entries.map((e) => ({ ...e, id: `K${e.id}`, repo: `kt/${e.repo}` }))];
  const s = scorePopulation({ rows, manifestEntries: entries });
  const l = s.definitions.localized;
  assert.equal(l.byLanguage.kotlin.status, 'insufficient_population');
  assert.equal(l.aggregates.groupsUsed, 2, 'kotlin is not in the macro average');
  const f1py = (2 * 30) / (2 * 30 + 0 + 10); const f1go = (2 * 6) / (2 * 6 + 0 + 24);
  assert.ok(Math.abs(l.byLanguage.python.f1 - f1py) < 1e-12);
  assert.ok(Math.abs(l.aggregates.macroF1 - (f1py + f1go) / 2) < 1e-12);
  assert.ok(Math.abs(l.aggregates.weightedF1 - (f1py * 40 + f1go * 30) / 70) < 1e-12);
  assert.notEqual(l.aggregates.macroF1, l.aggregates.weightedF1);
  assert.ok(Math.abs(l.aggregates.micro - l.total.f1) < 1e-12);
  assert.equal(aggregatesOf({}).macroF1, null);
});

test('per-CWE metrics are present and respect the same minimum', () => {
  const a = population(40, (i) => (i < 15 ? 'tp' : 'fn'));
  const rows = a.rows.map((r, i) => ({ ...r, cwe: i < 33 ? 'CWE-89' : 'CWE-22' }));
  const s = scorePopulation({ rows, manifestEntries: a.entries });
  assert.equal(s.definitions.localized.byCwe['CWE-89'].status, 'reportable');
  assert.equal(s.definitions.localized.byCwe['CWE-22'].status, 'insufficient_population');
});

test('intervals resample whole groups; with fewer than ten independent groups they are unmeasured, never made up', () => {
  const sameRepo = population(40, (i) => (i % 2 ? 'tp' : 'fn'));
  sameRepo.entries.forEach((e) => { e.repo = 'org/one'; });
  sameRepo.rows.forEach((r) => { r.repo = 'org/one'; });
  const s = scorePopulation({ rows: sameRepo.rows, manifestEntries: sameRepo.entries });
  assert.equal(s.definitions.localized.intervals.f1.status, 'unmeasured');
  assert.match(s.definitions.localized.intervals.f1.reason, /independent group/);
  const many = population(60, (i) => (i % 3 === 0 ? 'tp' : 'fn'));
  const a = scorePopulation({ rows: many.rows, manifestEntries: many.entries, protocolHash: 'sha256:p' });
  const b = scorePopulation({ rows: many.rows, manifestEntries: many.entries, protocolHash: 'sha256:p' });
  const iv = a.definitions.localized.intervals.f1;
  assert.equal(iv.status, 'measured');
  assert.ok(iv.low <= iv.point && iv.point <= iv.high);
  assert.deepEqual(a.definitions.localized.intervals, b.definitions.localized.intervals, 'same input and protocol, same interval');
});

test('the three definitions are reported apart and only the localized one is a claim', () => {
  assert.deepEqual(Object.entries(DEFINITIONS).filter(([, d]) => d.claim).map(([k]) => k), ['localized']);
  const p = population(40, (i) => (i < 20 ? 'tp' : 'fn'));
  p.rows.forEach((r, i) => { if (i < 5) Object.assign(r, { tpLocal: 0, fnLocal: 1 }); });
  const s = scorePopulation({ rows: p.rows, manifestEntries: p.entries });
  assert.equal(s.definitions.file.total.tp, 20);
  assert.equal(s.definitions.localized.total.tp, 15, 'the localized figure is lower than the file-scoped one');
  assert.equal(s.definitions.localized.claim, true);
  assert.equal(s.definitions.wide.claim, false);
});

test('fixed-version pressure and fix survival are reported', () => {
  const p = population(40, (i) => (i < 20 ? 'tp' : 'fn'));
  p.rows.forEach((r, i) => { r.postFindings = i % 4; if (i < 8) r.survivedFix = 1; });
  const s = scorePopulation({ rows: p.rows, manifestEntries: p.entries });
  assert.equal(s.fixedVersionPressure.entriesMeasured, 40);
  assert.equal(s.fixedVersionPressure.total, 10 * (0 + 1 + 2 + 3));
  assert.equal(s.fixedVersionPressure.entriesWithAnyFinding, 30);
  assert.deepEqual([s.fixDiscrimination.n, s.fixDiscrimination.d], [12, 20]);
});

test('a split assignment adds a per-split block and an unassigned entry is shown as such', () => {
  const p = population(60, (i) => (i % 2 ? 'tp' : 'fn'));
  const assignment = Object.fromEntries(p.entries.map((e, i) => [e.id, i < 30 ? 'dev' : i < 50 ? 'validation' : 'sealed']));
  delete assignment.E59;
  const s = scorePopulation({ rows: p.rows, manifestEntries: p.entries, splits: { assignment, protocolHash: 'sha256:s' } });
  const by = s.definitions.localized.bySplit;
  assert.equal(by.dev.entries, 30);
  assert.equal(by.validation.entries, 20);
  assert.equal(by.sealed.entries, 9);
  assert.equal(by.sealed.status, 'insufficient_population');
  assert.equal(by.unassigned.entries, 1);
});

// ---- agreement with the runner on real data ---------------------------------------------------------------------------------

test('on the archived real result the new scorer reproduces the runner\'s own numbers and accounts for every manifest entry', () => {
  const result = JSON.parse(fs.readFileSync(path.join(REPO, 'bench/independent/RESULT.json'), 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(REPO, 'bench/independent/manifest.json'), 'utf8')).entries;
  const inScope = manifest.filter((e) => result.perEntry.some((r) => r.id === e.id) || (result.population.unscored || []).some((u) => (typeof u === 'string' ? u : u.id) === e.id));
  const s = scorePopulation({ rows: result.perEntry, unscored: (result.population.unscored || []).map((u) => (typeof u === 'string' ? { id: u, reason: 'unscored' } : u)), manifestEntries: inScope });
  for (const k of ['tp', 'fp', 'fn', 'tn']) {
    assert.equal(s.definitions.localized.total[k], result.localized[k], `localized.${k}`);
    assert.equal(s.definitions.file.total[k], result.overall[k], `file.${k}`);
    assert.equal(s.definitions.wide.total[k], result.wide[k], `wide.${k}`);
  }
  assert.equal(s.denominators.reconciles, true, JSON.stringify(s.denominators));
  assert.equal(s.denominators.scored, result.population.scoredEntries);
  for (const [lang, v] of Object.entries(result.byLanguage)) assert.equal(s.definitions.file.byLanguage[lang].entries, v.entries, lang);
});

test('the archived result stays historical: it names its engine version, which is not the current one', () => {
  const result = JSON.parse(fs.readFileSync(path.join(REPO, 'bench/independent/RESULT.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner/package.json'), 'utf8'));
  assert.ok(result.engineVersion && result.measuredAt);
  assert.notEqual(result.engineVersion, pkg.version);
});
