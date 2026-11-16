// FR-03 / GAP-03: actual patch scope. Every test here fails against the old |lines(after) - lines(before)| measure.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computePatchScope, legacyBounds } from '../../src/fix/patch-scope.js';
import { diffLines } from '../../src/fix/line-diff.js';
import { countPatchBounds } from '../../src/posture/fix-plan.js';

const lines = (n, f) => Array.from({ length: n }, (_, i) => f(i)).join('\n') + '\n';

test('AC-03.1 / T-03: a same-length 150-line rewrite is not zero', () => {
  const before = lines(150, (i) => `const a${i} = ${i};`);
  const after = lines(150, (i) => `const b${i} = ${i * 2};`);
  const s = computePatchScope({ before: { 'a.js': before }, after: { 'a.js': after } });
  assert.equal(s.totals.additions, 150);
  assert.equal(s.totals.deletions, 150);
  assert.equal(s.totals.editedLines, 150);
  assert.equal(s.exceedsBounds, true);
  // the old measure, for the record: it said 0
  assert.equal(Math.abs(after.split('\n').length - before.split('\n').length), 0);
  const legacy = countPatchBounds({ 'a.js': after }, { 'a.js': before });
  assert.equal(legacy.loc, 150);
  assert.equal(legacy.exceedsBounds, true);
});

test('line diff: insertion, deletion and replacement ranges are exact', () => {
  const d = diffLines('a\nb\nc\nd\n', 'a\nB\nc\nd\ne\n');
  assert.equal(d.additions, 2); assert.equal(d.deletions, 1);
  assert.deepEqual(d.hunks.map((h) => [h.beforeStart, h.beforeCount, h.afterStart, h.afterCount]), [[2, 1, 2, 1], [5, 0, 5, 1]]);
  assert.equal(diffLines('x\n', 'x\n').hunks.length, 0);
  assert.equal(diffLines(null, 'a\nb\n').additions, 2);
  assert.equal(diffLines('a\nb\n', null).deletions, 2);
});

test('line diff: past the search bound the count is approximate and over-counts, never under-counts', () => {
  const before = lines(50, (i) => `x${i}`); const after = lines(50, (i) => `y${i}`);
  const d = diffLines(before, after, { maxEditDistance: 3 });
  assert.equal(d.approximate, true);
  assert.equal(d.additions, 50); assert.equal(d.deletions, 50);
});

test('AC-03.2: whole-file replacement, deletion, rename, added helper and several files are measured', () => {
  const s = computePatchScope({
    before: { 'a.js': 'one\ntwo\n', 'gone.js': 'x\ny\nz\n', 'old.js': 'keep\n', 'c.js': 'function f() {\n  return 1;\n}\n' },
    after: { 'a.js': 'three\nfour\nfive\n', 'gone.js': null, 'new.js': 'keep\nmore\n', 'c.js': 'function helper() {\n  return 2;\n}\nfunction f() {\n  return helper();\n}\n', 'added.js': 'export const h = 1;\n' },
    renames: [{ from: 'old.js', to: 'new.js' }],
  });
  const by = Object.fromEntries(s.files.map((f) => [f.file, f]));
  assert.equal(by['a.js'].operation, 'modify'); assert.equal(by['a.js'].editedLines, 3);
  assert.equal(by['gone.js'].operation, 'delete'); assert.equal(by['gone.js'].deletions, 3);
  assert.equal(by['new.js'].operation, 'rename'); assert.equal(by['new.js'].renamedFrom, 'old.js'); assert.equal(by['new.js'].additions, 1);
  assert.equal(by['added.js'].operation, 'add'); assert.equal(by['added.js'].additions, 1);
  assert.ok(by['c.js'].touchedSymbols.some((t) => t.name === 'helper'), 'the added helper is a touched symbol');
  assert.ok(by['c.js'].touchedSymbols.some((t) => t.name === 'f'), 'the changed caller is a touched symbol');
  assert.equal(by['c.js'].structural, 'ast');
  assert.equal(s.totals.files, 5);
  assert.deepEqual(s.totals.operations, { add: 1, modify: 2, delete: 1, rename: 1 });
  assert.equal(s.exceedsBounds, true, '5 files exceed the 3-file default');
  assert.ok(!('old.js' in by), 'the rename source is not listed as a separate file');
});

test('AC-03.3: an equal-length change to an authorization condition is material', () => {
  const before = "app.get('/doc/:id', (req, res) => {\n  if (doc.owner !== req.user.id) return res.sendStatus(403);\n  res.json(doc);\n});\n";
  const after = "app.get('/doc/:id', (req, res) => {\n  if (doc.owner === req.user.id) return res.sendStatus(403);\n  res.json(doc);\n});\n";
  const s = computePatchScope({ before: { 'r.js': before }, after: { 'r.js': after } });
  assert.equal(s.totals.editedLines, 1);
  assert.equal(s.material.material, true);
  assert.ok(s.material.categories.includes('authZ'));
  assert.ok(s.files[0].touchedSymbols.some((t) => t.name === 'GET /doc/:id'));
});

test('formatting-only changes are counted and labelled, not invisible', () => {
  const s = computePatchScope({ before: { 'a.js': 'const x = 1;\nconst y=2;\n' }, after: { 'a.js': 'const x =  1;\n\nconst y = 2;\n' } });
  assert.equal(s.files[0].formattingOnly, true);
  assert.ok(s.totals.editedLines > 0);
  assert.equal(s.totals.semanticEditedLines, 0);
  assert.equal(s.material.material, false);
});

test('a file type with no structural parser names the fallback', () => {
  const s = computePatchScope({ before: { 'a.go': 'package a\nfunc F() int {\n\treturn 1\n}\n' }, after: { 'a.go': 'package a\nfunc F() int {\n\treturn 2\n}\n' } });
  assert.equal(s.files[0].structural, 'heuristic');
  assert.deepEqual(s.structuralFallback, ['a.go']);
  assert.ok(s.files[0].structuralFallback);
  assert.ok(s.files[0].touchedSymbols.some((t) => t.name === 'F'));
});

test('python symbols by indentation', () => {
  const s = computePatchScope({ before: { 'a.py': 'class A:\n    def f(self):\n        return 1\n\ndef g():\n    return 2\n' }, after: { 'a.py': 'class A:\n    def f(self):\n        return 3\n\ndef g():\n    return 2\n' } });
  assert.deepEqual(s.files[0].touchedSymbols.map((t) => t.name).sort(), ['A', 'A.f']);
});

test('digests identify the exact before and after images', () => {
  const s = computePatchScope({ before: { 'a.js': 'x\n' }, after: { 'a.js': 'y\n' } });
  assert.match(s.files[0].beforeDigest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(s.files[0].beforeDigest, s.files[0].afterDigest);
  assert.deepEqual(legacyBounds(s), { files: 1, loc: 1, exceedsBounds: false });
});
