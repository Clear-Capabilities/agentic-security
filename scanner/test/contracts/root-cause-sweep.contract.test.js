// Contract test for the repository-wide sibling sweep (docs/reference/root-cause-sweep.md).
//
// The reference page is the contract. This test reads its field tables and holds the implementation to them in BOTH directions: a
// field the output has that the page does not list fails, and a field the page lists that the output lacks fails. It also pins the
// guarantees the page makes (exact accounting, own-site exclusion, a bounded sample with exact counts, the confirmation gate) and the
// figures the page quotes from bench/sibling-sweep.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sweepRootCauses } from '../../src/posture/root-cause-sweep.js';
import { runScan } from '../../src/runScan.js';
import { CASES, build } from '../../../bench/sibling-sweep/cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..', '..');
const PAGE = fs.readFileSync(path.join(REPO, 'docs', 'reference', 'root-cause-sweep.md'), 'utf8');
const BASELINE = JSON.parse(fs.readFileSync(path.join(REPO, 'bench', 'sibling-sweep', 'BASELINE.json'), 'utf8'));

/** The field names in the table that follows a bold heading such as **`totals`**. */
function fieldsUnder(heading) {
  const lines = PAGE.split('\n');
  const at = lines.findIndex(l => l.startsWith(`**${heading}`));
  assert.ok(at >= 0, `the page has no "${heading}" table`);
  const names = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (lines[i].startsWith('**') || lines[i].startsWith('## ')) break;
    const m = /^\| `([A-Za-z]+)` \|/.exec(lines[i]);
    if (m) names.push(m[1]);
  }
  assert.ok(names.length, `the "${heading}" table lists no fields`);
  return names;
}

const OPTIONAL = new Set(['language']);   // present only on a Haskell sweep
const TOTALS = fieldsUnder('`totals`');
const SWEEP = fieldsUnder('Each entry of `sweeps`');
const INSTANCE = fieldsUnder('Each entry of `instances`');

const finding = (over = {}) => ({
  id: 'F1', confirmed: true, file: 'origin.js', line: 1, vuln: 'SQL Injection', cwe: 'CWE-89',
  sink: { file: 'origin.js', line: 1, snippet: 'db.query(`select ${a}`)' }, ...over,
});
const corpus = { 'origin.js': 'db.query(`select ${a}`);\n', 'a.js': 'x();\ndb.query(`select ${b}`);\n', 'b.js': 'db.query(`select ${c}`);\n' };

const same = (actual, documented, optional = new Set()) => {
  const need = documented.filter(k => !optional.has(k));
  assert.deepEqual(Object.keys(actual).filter(k => !optional.has(k)).sort(), [...need].sort());
};

test('contract: the result has exactly the documented fields at every level', () => {
  const r = sweepRootCauses([finding()], corpus);
  same(r, ['sweeps', 'totals']);
  same(r.totals, TOTALS);
  assert.equal(r.sweeps.length, 1);
  same(r.sweeps[0], SWEEP, OPTIONAL);
  assert.ok(r.sweeps[0].instances.length >= 1);
  for (const inst of r.sweeps[0].instances) same(inst, INSTANCE);
});

test('contract: a field the page does not list, or lists and the output lacks, is caught (the check itself fails both ways)', () => {
  const r = sweepRootCauses([finding()], corpus);
  assert.throws(() => same({ ...r.totals, extra: 1 }, TOTALS));
  const { found, ...rest } = r.totals;
  assert.throws(() => same(rest, TOTALS));
  assert.ok(found >= 0);
});

test('contract: found === candidates + mitigated, and remaining === candidates, for every seeded case', () => {
  for (const c of CASES) {
    const { findings, files } = build(c);
    const r = sweepRootCauses(findings, files);
    for (const s of r.sweeps) {
      assert.equal(s.found, s.candidates + s.mitigated, c.id);
      assert.equal(s.remaining, s.candidates, c.id);
    }
    assert.equal(r.totals.found, r.totals.candidates + r.totals.mitigated, c.id);
    assert.equal(r.totals.found, r.sweeps.reduce((a, s) => a + s.found, 0), c.id);
  }
});

test('contract: the finding\'s own site is never reported, and two findings sharing a pattern each exclude only their own site', () => {
  const two = [finding(), finding({ id: 'F2', file: 'b.js', line: 1, sink: { file: 'b.js', line: 1, snippet: 'db.query(`select ${c}`)' } })];
  const r = sweepRootCauses(two, corpus);
  const s1 = r.sweeps.find(s => s.fromFindingId === 'F1');
  const s2 = r.sweeps.find(s => s.fromFindingId === 'F2');
  assert.equal(s1.instances.some(i => i.file === 'origin.js' && i.line === 1), false);
  assert.equal(s2.instances.some(i => i.file === 'b.js' && i.line === 1), false);
  assert.equal(s1.instances.some(i => i.file === 'b.js'), true, 'F1 reports F2\'s site');
  assert.equal(s2.instances.some(i => i.file === 'origin.js'), true, 'F2 reports F1\'s site');
});

test('contract: a match that already has a finding is mitigated-or-known, never dropped', () => {
  const known = { id: 'K', confirmed: false, file: 'a.js', line: 2, vuln: 'SQL Injection', cwe: 'CWE-89' };
  const r = sweepRootCauses([finding(), known], corpus);
  const s = r.sweeps[0];
  assert.equal(s.mitigated, 1);
  assert.equal(s.instances.find(i => i.file === 'a.js').status, 'mitigated-or-known');
  assert.equal(s.instances.find(i => i.file === 'b.js').status, 'candidate');
  assert.equal(s.found, s.candidates + s.mitigated);
});

test('contract: the instance list is bounded at 100, the counts stay exact, and truncation is disclosed', () => {
  const files = { 'origin.js': 'db.query(`select ${a}`);\n' };
  for (let i = 0; i < 250; i++) files[`g${i}.js`] = 'db.query(`select ${z}`);\n';
  const s = sweepRootCauses([finding()], files).sweeps[0];
  assert.equal(s.instances.length, 100);
  assert.equal(s.found, 250);
  assert.equal(s.candidates, 250);
  assert.equal(s.instancesTruncated, true);
  const small = sweepRootCauses([finding()], corpus).sweeps[0];
  assert.equal(small.instancesTruncated, false);
});

test('contract: only a confirmed finding (confirmed true, or confidenceTier high) drives a sweep unless confirmedOnly is false', () => {
  const unconfirmed = finding({ confirmed: false });
  assert.equal(sweepRootCauses([unconfirmed], corpus).sweeps.length, 0);
  assert.equal(sweepRootCauses([finding({ confirmed: false, confidenceTier: 'high' })], corpus).sweeps.length, 1);
  assert.equal(sweepRootCauses([unconfirmed], corpus, { confirmedOnly: false }).sweeps.length, 1);
});

test('contract: a finding with no callee falls back to its keyword, and one with nothing to search is skipped', () => {
  const kw = sweepRootCauses([finding({ sink: { file: 'origin.js', line: 1, snippet: '' }, vuln: 'select' })], corpus);
  assert.equal(kw.sweeps.length, 1);
  assert.equal(kw.sweeps[0].sinkPattern, 'select');
  assert.equal(sweepRootCauses([finding({ sink: { snippet: '' }, vuln: '', cwe: '' })], corpus).sweeps.length, 0);
});

test('contract: garbage in gives an empty result, not an exception', () => {
  for (const bad of [null, undefined, 'x', 7, [null, 7, 'x', {}]]) {
    const r = sweepRootCauses(bad, null);
    assert.deepEqual(r.totals, { found: 0, candidates: 0, mitigated: 0 });
  }
  assert.doesNotThrow(() => sweepRootCauses([finding()], { 'a.js': null, 'b.js': undefined }));
});

test('contract: a chain of argument-less calls anchors on the whole chain, so an unrelated method on the same object is not a sibling', () => {
  const f = finding({ sink: { file: 'N.java', line: 1, snippet: 'Runtime.getRuntime().exec("p " + h)' }, file: 'N.java' });
  const files = { 'N.java': 'Runtime.getRuntime().exec("p " + h);\n', 'O.java': 'Runtime.getRuntime().exec("q " + k);\nRuntime.getRuntime().availableProcessors();\n' };
  const s = sweepRootCauses([f], files).sweeps[0];
  assert.deepEqual(s.instances.map(i => `${i.file}:${i.line}`), ['O.java:1']);
});

test('contract: the figures the page quotes are the recorded bench figures', () => {
  const t = BASELINE.total;
  assert.ok(PAGE.includes(`(${t.siblings.found} of ${t.siblings.planted})`), 'same-shape recall on the page');
  assert.ok(PAGE.includes(`${t.differentlyWritten.found} of ${t.differentlyWritten.planted} siblings`), 'other-form recall on the page');
  assert.ok(PAGE.includes(`${t.nearMisses.planted - t.nearMisses.falselyReported} of ${t.nearMisses.planted} times`), 'look-alike rejection on the page');
  const reported = BASELINE.cases.flatMap(c => Object.values(c.lim)).filter(v => v === 'reported').length;
  const planted = BASELINE.cases.flatMap(c => Object.values(c.lim)).length;
  assert.ok(PAGE.includes(`${reported} of the ${planted} such cases`) || (reported === 2 && planted === 3 && PAGE.includes('Two of the three')), 'comment and string matches on the page');
});

test('contract: a real scan carries rootCauseSweep with the documented totals', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sweep-contract-'));
  try {
    fs.writeFileSync(path.join(root, 'a.js'), "const db = require('./db');\napp.get('/a', (req, res) => { db.query(`SELECT * FROM t WHERE id = ${req.query.id}`); });\napp.get('/b', (req, res) => { db.query(`SELECT * FROM u WHERE id = ${req.query.k}`); });\n");
    const { scan } = await runScan(root, { network: false });
    assert.ok(scan.rootCauseSweep, 'a scan result carries rootCauseSweep');
    same(scan.rootCauseSweep.totals, TOTALS);
    for (const s of scan.rootCauseSweep.sweeps) same(s, SWEEP, OPTIONAL);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
