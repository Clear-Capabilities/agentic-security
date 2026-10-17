// E0-06: the prioritised root-cause backlog.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { REPO } from './helpers.js';
import { CONFIDENCE, EFFORT, IMPACT, build, parseRootCause, resolvePrefixes, scoreItem } from '../../../scripts/engineering-excellence/backlog.mjs';

const ROW = (id, lang, cwe, cat, sub, ev = 'evidence text') => `| ${id} | ${lang} | ${cwe} | ${cat} | ${sub} | none | ${ev} |`;
const TABLE = ['| id | language |', '|---|---|', ROW('GHSA-aaaa-1111-bbbb', 'python', 'CWE-22', 'shape-doesnt-occur', 'deeper-engine-gap'), ROW('GHSA-cccc-2222-dddd', 'python', 'CWE-22', 'shape-doesnt-occur', 'missing-catalog'), ROW('GHSA-eeee-3333-ffff', 'typescript', 'CWE-639', 'shape-doesnt-occur', 'deeper-engine-gap', 'CORPUS SCOPING ISSUE: x | y')].join('\n');

test('the root-cause table is parsed into entries, keeping the evidence column whole', () => {
  const rows = parseRootCause(TABLE);
  assert.equal(rows.length, 3);
  assert.deepEqual(rows[0], { id: 'GHSA-aaaa-1111-bbbb', language: 'python', cwe: 'CWE-22', category: 'shape-doesnt-occur', subcategory: 'deeper-engine-gap', fixStatus: 'none', evidence: 'evidence text' });
  assert.equal(rows[2].evidence, 'CORPUS SCOPING ISSUE: x|y');
});

test('the score is examples x impact x confidence / effort, and an item with no independent example is ranked on a floor of one example', () => {
  const misses = parseRootCause(TABLE);
  const a = scoreItem({ cwes: ['CWE-22'], categories: ['deeper-engine-gap'], evidenceKind: 'reproducer', effort: 'M' }, misses);
  assert.equal(a.examples, 1);
  assert.equal(a.impact, IMPACT['CWE-22']);
  assert.equal(a.score, Math.round((1 * 4 * CONFIDENCE.reproducer / EFFORT.M) * 100) / 100);
  const both = scoreItem({ cwes: ['CWE-22'], categories: ['deeper-engine-gap', 'missing-catalog'], evidenceKind: 'trace', effort: 'S' }, misses);
  assert.equal(both.examples, 2);
  const none = scoreItem({ cwes: [], examplesOverride: 0, impact: 5, evidenceKind: 'hypothesis', effort: 'L' }, misses);
  assert.equal(none.examples, 0);
  assert.equal(none.score, Math.round((1 * 5 * CONFIDENCE.hypothesis / EFFORT.L) * 100) / 100, 'floored at one example, discounted by confidence and effort');
  const byText = scoreItem({ cwes: [], evidenceRegex: 'CORPUS SCOPING', impact: 3, evidenceKind: 'reproducer', effort: 'S' }, misses);
  assert.equal(byText.examples, 1);
});

test('entry-id prefixes resolve to exactly one full id; an ambiguous or unknown prefix is reported, never guessed', () => {
  const misses = parseRootCause(TABLE);
  assert.deepEqual(resolvePrefixes(['GHSA-aaaa', 'GHSA-cccc-2222-dddd'], misses).ids, ['GHSA-aaaa-1111-bbbb', 'GHSA-cccc-2222-dddd']);
  const bad = resolvePrefixes(['GHSA-zzzz', 'GHSA'], misses);
  assert.deepEqual(bad.ids, []);
  assert.equal(bad.unresolved.length, 2);
});

test('the committed backlog: every item has an upstream source that exists, an owner task in the manifest, and a stated kind of evidence', () => {
  const b = build(REPO);
  assert.ok(b.items.length >= 10);
  assert.equal(b.independentMisses.count, 96, 'the record the counts come from');
  const tasks = new Set(JSON.parse(fs.readFileSync(path.join(REPO, 'scripts/engineering-excellence/tasks.json'), 'utf8')).tasks.map((t) => t.id));
  for (const it of b.items) {
    assert.deepEqual(it.problems, [], `${it.id}: ${it.problems.join('; ')}`);
    assert.ok(tasks.has(it.ownerTask), `${it.id} owner ${it.ownerTask}`);
    assert.ok(it.sources.length >= 1);
    for (const s of it.sources) assert.ok(fs.existsSync(path.join(REPO, s.split('#')[0])), `${it.id}: ${s}`);
    assert.ok(['reproducer', 'trace', 'hypothesis'].includes(it.evidenceKind));
    if (it.evidenceKind === 'hypothesis') assert.ok(it.hypothesis.length > 40, `${it.id} states its hypothesis`);
    if (it.evidenceKind === 'reproducer') assert.ok(it.reproducer || it.reproducerIds.length, `${it.id} names a reproducer`);
    if (it.evidenceKind === 'trace') assert.ok(it.trace.length > 40, `${it.id} states its trace`);
  }
});

test('every named independent reproducer is a real entry in the root-cause record and in the independent manifest', () => {
  const b = build(REPO);
  const manifest = JSON.parse(fs.readFileSync(path.join(REPO, 'bench/independent/manifest.json'), 'utf8'));
  const known = new Set((manifest.entries || manifest).map((e) => e.id));
  let checked = 0;
  for (const it of b.items) for (const id of it.reproducerIds) { checked++; assert.ok(known.has(id), `${it.id}: ${id} is not in bench/independent/manifest.json`); }
  assert.ok(checked >= 12);
});

test('items are ordered by score, and the top items all name an owner task from the independent evidence or an explicit hypothesis', () => {
  const b = build(REPO);
  for (let i = 1; i < b.items.length; i++) assert.ok(b.items[i - 1].score >= b.items[i].score, 'sorted by descending score');
  for (const it of b.items.slice(0, 10)) assert.ok(it.ownerTask && (it.evidenceKind === 'hypothesis' ? it.hypothesis : it.evidenceKind === 'trace' ? it.trace : (it.reproducer || it.reproducerIds.length)), it.id);
});

test('the rendered PRIORITY_BACKLOG.md is current: it lists every item with its score and owner task', () => {
  const b = build(REPO);
  const md = fs.readFileSync(path.join(REPO, 'docs/engineering-excellence/PRIORITY_BACKLOG.md'), 'utf8');
  for (const it of b.items) {
    assert.ok(md.includes(it.title), `${it.id} is rendered`);
    assert.ok(md.includes(`| ${it.score} |`), `${it.id} score ${it.score} is current`);
  }
  assert.match(md, /not how accurate anything is today/);
});
