// The pre-push gate's test selection (scripts/gate-select.mjs) and its fast-tier planning (scripts/pre-push-gate.mjs planChecks).
// Every case is a pair that differs in one fact, so a selector that always says "full" or always says "nothing" fails one half.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, selectTests, transitiveImporters, mentionTokens } from '../../scripts/gate-select.mjs';
import { planChecks, CHECKS, HOSTED_COVERS } from '../../scripts/pre-push-gate.mjs';

const FILES = {
  'scanner/src/a.js': "import { b } from './b.js';",
  'scanner/src/b.js': 'export const b = 1;',
  'scanner/src/c.js': 'export const c = 1;',
  'scanner/test/a.test.js': "import { b } from '../src/b.js';",
  'scanner/test/c.test.js': "import { c } from '../src/c.js';",
  'scanner/test/doc.test.js': "readFileSync('docs/guides/haskell.md')",
  'scanner/test/other.test.js': 'nothing here',
  'scanner/test/no-orphan-tests.test.js': 'walks everything',
};
const TESTS = Object.keys(FILES).filter((f) => f.endsWith('.test.js'));
const graph = () => buildGraph({ repo: '/x', list: Object.keys(FILES).map((f) => `/x/${f}`), read: (rel) => FILES[rel] });

test('a change to a module selects the tests that import it, directly or through another module, and no others', () => {
  const g = graph();
  assert.deepEqual([...transitiveImporters(g.importers, ['scanner/src/b.js'])].sort(), ['scanner/src/a.js', 'scanner/src/b.js', 'scanner/test/a.test.js']);
  const sel = selectTests({ changed: ['scanner/src/b.js'], tests: TESTS, graph: g, maxFraction: 1 });
  assert.equal(sel.mode, 'subset');
  assert.deepEqual(sel.files, ['scanner/test/a.test.js', 'scanner/test/no-orphan-tests.test.js'], 'the importer and the always-run structural test, not c.test.js, doc.test.js or other.test.js');
  const sel2 = selectTests({ changed: ['scanner/src/c.js'], tests: TESTS, graph: g, maxFraction: 1 });
  assert.deepEqual(sel2.files, ['scanner/test/c.test.js', 'scanner/test/no-orphan-tests.test.js']);
});

test('a test that names a changed file by path is selected even though it imports nothing from it', () => {
  const sel = selectTests({ changed: ['docs/guides/haskell.md'], tests: TESTS, graph: graph(), maxFraction: 1 });
  assert.ok(sel.files.includes('scanner/test/doc.test.js'));
  assert.ok(!sel.files.includes('scanner/test/other.test.js'));
});

test('a selection over the fraction, an empty change list, and a change that decides how every test runs all select the full suite', () => {
  const g = graph();
  assert.equal(selectTests({ changed: ['scanner/src/b.js'], tests: TESTS, graph: g, maxFraction: 0.1 }).mode, 'full', 'running most of the suite costs the same as running it');
  assert.equal(selectTests({ changed: [], tests: TESTS, graph: g }).mode, 'full', 'unknown change: exclude nothing');
  assert.equal(selectTests({ changed: null, tests: TESTS, graph: g }).mode, 'full');
  assert.equal(selectTests({ changed: ['scripts/run-unit-tests.mjs'], tests: TESTS, graph: g }).mode, 'full');
  assert.equal(selectTests({ changed: ['scanner/package.json'], tests: TESTS, graph: g }).mode, 'full', 'a manifest change beyond its version line');
});

test('a version-only manifest and lock change does not widen the selection; the same files changed otherwise do', () => {
  const g = graph();
  const only = selectTests({ changed: ['scanner/package.json', 'scanner/package-lock.json', 'scanner/src/c.js'], tests: TESTS, graph: g, versionOnly: true, maxFraction: 1 });
  assert.equal(only.mode, 'subset');
  const other = selectTests({ changed: ['scanner/package.json', 'scanner/src/c.js'], tests: TESTS, graph: g, versionOnly: false, maxFraction: 1 });
  assert.equal(other.mode, 'full');
});

test('mention tokens: the path, the scanner-relative path, a distinctive file name and the containing directories, but not a short common name', () => {
  const t = mentionTokens('scanner/src/language/haskell-fix.js');
  for (const x of ['scanner/src/language/haskell-fix.js', 'src/language/haskell-fix.js', 'haskell-fix.js', 'scanner/src/language', 'scanner/src']) assert.ok(t.includes(x), x);
  assert.ok(!mentionTokens('scanner/src/x.js').includes('x.js'), 'a short file name would match unrelated text');
});

test('planChecks: the full tier changes nothing; the fast tier drops exactly the hosted-covered checks and says why', () => {
  const full = planChecks({ checks: CHECKS, tier: 'full' });
  assert.deepEqual(full.checks.map((c) => c.id), CHECKS.map((c) => c.id));
  assert.deepEqual(full.skipped, []);
  const fast = planChecks({ checks: CHECKS, tier: 'fast', selection: null, changed: ['scanner/src/language/haskell-fix.js'] });
  for (const id of Object.keys(HOSTED_COVERS)) {
    assert.ok(!fast.checks.some((c) => c.id === id), `${id} is not run locally`);
    assert.match(fast.skipped.find((s) => s.id === id).reason, /hosted CI job/);
  }
  assert.ok(fast.checks.some((c) => c.id === 'haskell-precision-gate'), 'a change to the Haskell engine still runs the live precision check');
  assert.ok(fast.checks.some((c) => c.id === 'bundle-matches-source') && fast.checks.some((c) => c.id === 'ci-parity'), 'the cheap whole-repo checks stay');
  const docsOnly = planChecks({ checks: CHECKS, tier: 'fast', changed: ['docs/guides/haskell.md'] });
  assert.ok(!docsOnly.checks.some((c) => c.id === 'haskell-precision-gate'), 'a docs-only change does not run the live precision check');
});

test('planChecks: a subset selection replaces the suite with a differently named check, so a subset pass can never be cached as a full pass', () => {
  const sel = { mode: 'subset', files: ['scanner/test/a.test.js'], total: 100, reason: '1 of 100' };
  const p = planChecks({ checks: CHECKS, tier: 'fast', selection: sel, changed: ['scanner/src/b.js'] });
  assert.ok(!p.checks.some((c) => c.id === 'test-suite'));
  const aff = p.checks.find((c) => /^test-suite-affected-[0-9a-f]{8}$/.test(c.id));
  assert.ok(aff && aff.onlyFiles.length === 1 && aff.npmScript === undefined);
  assert.match(p.skipped.find((s) => s.id === 'test-suite').reason, /full suite runs in hosted CI/);
  const p2 = planChecks({ checks: CHECKS, tier: 'fast', selection: { ...sel, files: ['scanner/test/b.test.js'] }, changed: ['scanner/src/b.js'] });
  assert.notEqual(p2.checks.find((c) => /^test-suite-affected/.test(c.id)).id, aff.id, 'a different selection is a different cache key');
  const full = planChecks({ checks: CHECKS, tier: 'fast', selection: { mode: 'full', files: [], total: 100, reason: 'x' }, changed: ['scanner/src/b.js'] });
  assert.ok(full.checks.some((c) => c.id === 'test-suite'), 'a full selection keeps the full suite');
});
