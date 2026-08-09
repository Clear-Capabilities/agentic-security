// Dependency-currency release gate — unit tests for the pure decision logic.
//
// See scripts/dependency-currency.mjs for the design rationale. Same shape as
// test/release-check.test.js: the I/O path (registry queries, both package
// trees) is proven by hand in the release report with captured exit codes;
// these tests pin the decision logic on constructed inputs so a refactor
// cannot quietly loosen the gate — in particular so the vulnerability half
// can never grow an opt-out and the hold list can never stop expiring.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEPENDENCY_TREES,
  classifyDependencyKind,
  parseNpmJson,
  normalizeOutdated,
  evaluateDependencyCurrency,
} from '../../scripts/dependency-currency.mjs';

const NOW = new Date('2026-07-28T00:00:00Z');

function tree(overrides = {}) {
  return {
    id: 'scanner',
    audit: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
    outdated: [],
    ...overrides,
  };
}

function facts(overrides = {}) {
  return {
    trees: [tree()],
    holdsDoc: { holds: [] },
    holdsReadError: null,
    now: NOW,
    ...overrides,
  };
}

const held = (o = {}) => ({
  package: 'some-pkg',
  tree: 'scanner',
  heldAt: '1.0.0',
  reason: 'Upgrading drops a capability; verified by test.',
  addedAt: '2026-07-01',
  reviewBy: '2026-12-31',
  ...o,
});

const outdated = (o = {}) => ({
  package: 'some-pkg', current: '1.0.0', wanted: '1.0.0', latest: '2.0.0', kind: 'runtime', ...o,
});

// ------------------------------------------------------------ registry facts
test('dependency-currency — both trees are covered by the gate', () => {
  const ids = DEPENDENCY_TREES.map(t => t.id);
  assert.deepEqual(ids, ['scanner', 'ide/vscode']);
});

test('dependency-currency — a clean, current tree passes', () => {
  const r = evaluateDependencyCurrency(facts());
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
});

// ------------------------------------------------- half A: known advisories
test('dependency-currency — a moderate advisory fails the gate', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ audit: { info: 0, low: 0, moderate: 1, high: 0, critical: 0, total: 1 } })],
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /moderate/.test(e) && /scanner/.test(e)));
});

test('dependency-currency — critical advisories fail and name the count', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ audit: { info: 0, low: 0, moderate: 0, high: 2, critical: 1, total: 3 } })],
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /high=2/.test(e) && /critical=1/.test(e)));
});

test('dependency-currency — info/low advisories alone do not fail', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ audit: { info: 3, low: 4, moderate: 0, high: 0, critical: 0, total: 7 } })],
  }));
  assert.equal(r.ok, true);
  assert.ok(r.warnings.some(w => /low/.test(w)));
});

test('dependency-currency — a hold can never suppress an advisory', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({
      audit: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 },
      outdated: [outdated()],
    })],
    holdsDoc: { holds: [held()] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /high=1/.test(e)));
  assert.ok(r.errors.some(e => /no opt-out/i.test(e)));
});

test('dependency-currency — an unreadable advisory result fails as unverified', () => {
  const r = evaluateDependencyCurrency(facts({ trees: [tree({ audit: null })] }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /unverified/i.test(e) && /not the same as/i.test(e)));
});

// -------------------------------------------------- half B: outdated + holds
test('dependency-currency — an outdated, unheld dependency fails', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [outdated({ package: 'left-behind' })] })],
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /left-behind/.test(e) && /1\.0\.0/.test(e) && /2\.0\.0/.test(e)));
});

test('dependency-currency — an outdated dependency with a valid hold passes', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [outdated()] })],
    holdsDoc: { holds: [held()] },
  }));
  assert.equal(r.ok, true);
  assert.ok(r.warnings.some(w => /some-pkg/.test(w) && /held/i.test(w)));
});

test('dependency-currency — a hold only applies to the tree it names', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ id: 'ide/vscode', outdated: [outdated()] })],
    holdsDoc: { holds: [held({ tree: 'scanner' })] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /some-pkg/.test(e) && /ide\/vscode/.test(e)));
});

test('dependency-currency — dev and runtime outdated deps are both reported, distinguishably', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({
      outdated: [
        outdated({ package: 'build-tool', kind: 'dev' }),
        outdated({ package: 'shipped-lib', kind: 'runtime' }),
      ],
    })],
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /build-tool/.test(e) && /\[dev\]/.test(e)));
  assert.ok(r.errors.some(e => /shipped-lib/.test(e) && /\[runtime\]/.test(e)));
});

test('dependency-currency — an unreadable outdated result fails as unverified', () => {
  const r = evaluateDependencyCurrency(facts({ trees: [tree({ outdated: null })] }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /unverified/i.test(e) && /registry/i.test(e)));
});

// ------------------------------------------------------- anti-rot rule 1/3
test('dependency-currency — an expired reviewBy fails', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [outdated()] })],
    holdsDoc: { holds: [held({ reviewBy: '2026-07-27' })] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /review.*(passed|due)/i.test(e) && /some-pkg/.test(e)));
  assert.ok(r.errors.some(e => /re-test/i.test(e)));
});

test('dependency-currency — a reviewBy exactly today is still in date', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [outdated()] })],
    holdsDoc: { holds: [held({ reviewBy: '2026-07-28' })] },
  }));
  assert.equal(r.ok, true);
});

test('dependency-currency — a missing or unparseable reviewBy fails', () => {
  for (const reviewBy of [undefined, '', 'soon']) {
    const r = evaluateDependencyCurrency(facts({
      trees: [tree({ outdated: [outdated()] })],
      holdsDoc: { holds: [held({ reviewBy })] },
    }));
    assert.equal(r.ok, false, `reviewBy=${String(reviewBy)}`);
    assert.ok(r.errors.some(e => /reviewBy/.test(e)));
  }
});

// ------------------------------------------------------- anti-rot rule 2/3
test('dependency-currency — a hold for a package that is current fails as stale', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [] })],
    holdsDoc: { holds: [held()] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /stale/i.test(e) && /some-pkg/.test(e) && /delete/i.test(e)));
});

test('dependency-currency — a hold naming an unknown tree fails', () => {
  const r = evaluateDependencyCurrency(facts({
    holdsDoc: { holds: [held({ tree: 'nowhere' })] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /nowhere/.test(e)));
});

// ------------------------------------------------------- anti-rot rule 3/3
test('dependency-currency — a hold with no reason fails', () => {
  for (const reason of [undefined, '', '   ']) {
    const r = evaluateDependencyCurrency(facts({
      trees: [tree({ outdated: [outdated()] })],
      holdsDoc: { holds: [held({ reason })] },
    }));
    assert.equal(r.ok, false, `reason=${JSON.stringify(reason)}`);
    assert.ok(r.errors.some(e => /reason/i.test(e)));
  }
});

test('dependency-currency — a hold missing heldAt fails', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [outdated()] })],
    holdsDoc: { holds: [held({ heldAt: undefined })] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /heldAt/.test(e)));
});

test('dependency-currency — heldAt that disagrees with the installed version fails', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [outdated({ current: '1.5.0' })] })],
    holdsDoc: { holds: [held({ heldAt: '1.0.0' })] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /heldAt/.test(e) && /1\.5\.0/.test(e)));
});

test('dependency-currency — a hold missing addedAt fails', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree({ outdated: [outdated()] })],
    holdsDoc: { holds: [held({ addedAt: undefined })] },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /addedAt/.test(e)));
});

// ------------------------------------------------------------- holds file
test('dependency-currency — an unreadable hold file fails rather than waiving holds', () => {
  const r = evaluateDependencyCurrency(facts({
    holdsDoc: null,
    holdsReadError: 'not valid JSON',
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /\.dependency-holds\.json/.test(e)));
});

test('dependency-currency — an absent hold file is simply no holds', () => {
  const r = evaluateDependencyCurrency(facts({ holdsDoc: null, holdsReadError: null }));
  assert.equal(r.ok, true);
});

// ------------------------------------------------------------- fact parsing
test('dependency-currency — dependency kind comes from the manifest section', () => {
  const manifest = {
    dependencies: { 'shipped-lib': '^1.0.0' },
    devDependencies: { 'build-tool': '^2.0.0' },
    optionalDependencies: { 'maybe-lib': '3.0.0' },
  };
  assert.equal(classifyDependencyKind(manifest, 'shipped-lib'), 'runtime');
  assert.equal(classifyDependencyKind(manifest, 'build-tool'), 'dev');
  assert.equal(classifyDependencyKind(manifest, 'maybe-lib'), 'optional');
  assert.equal(classifyDependencyKind(manifest, 'nowhere'), 'unknown');
  assert.equal(classifyDependencyKind(null, 'shipped-lib'), 'unknown');
});

test('dependency-currency — registry JSON that is not JSON yields null, not an empty pass', () => {
  assert.equal(parseNpmJson(''), null);
  assert.equal(parseNpmJson('npm ERR! network request failed'), null);
  assert.deepEqual(parseNpmJson('{"a":1}'), { a: 1 });
});

test('dependency-currency — outdated entries missing a latest version are unverified', () => {
  assert.equal(normalizeOutdated({ 'p': { current: '1.0.0' } }, null), null);
});

test('dependency-currency — outdated entries normalize with kind attached', () => {
  const rows = normalizeOutdated(
    { 'build-tool': { current: '1.0.0', wanted: '1.1.0', latest: '2.0.0' } },
    { devDependencies: { 'build-tool': '^1.0.0' } },
  );
  assert.deepEqual(rows, [
    { package: 'build-tool', current: '1.0.0', wanted: '1.1.0', latest: '2.0.0', kind: 'dev' },
  ]);
});

test('dependency-currency — a package already at latest is not reported outdated', () => {
  const rows = normalizeOutdated(
    { 'fine': { current: '2.0.0', wanted: '2.0.0', latest: '2.0.0' } },
    { dependencies: { fine: '^2.0.0' } },
  );
  assert.deepEqual(rows, []);
});

// ------------------------------------------- unverifiable is never a pass
//
// PRD R4 made `gatherTreeFacts` try `npm ci --ignore-scripts` when a tree has
// no node_modules, because a publisher on a fresh clone otherwise hits a hard
// failure about their environment rather than their code. That convenience sits
// directly on top of this rule, and the rule had no test: an install that fails
// must leave the tree `uninstalled`, and an uninstalled tree must FAIL.
//
// Without this, a future change to the auto-install could quietly turn a tree
// nobody verified into a silent pass — which is the gate's worst failure mode,
// since both registry commands answer "{}" for an uninstalled tree and "{}" is
// indistinguishable from "everything is current".

test('dependency-currency — an uninstalled tree FAILS, it is never a silent pass', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [{ id: 'ide/vscode', audit: null, outdated: null, uninstalled: true }],
  }));
  assert.equal(r.ok, false, 'an unverified tree must not pass');
  assert.match(r.errors.join('\n'), /not installed/i);
  assert.match(r.errors.join('\n'), /UNVERIFIED/,
    'the message must say the tree was unverified, not merely that something is missing');
});

test('dependency-currency — one uninstalled tree fails even when the other is clean', () => {
  const r = evaluateDependencyCurrency(facts({
    trees: [tree(), { id: 'ide/vscode', audit: null, outdated: null, uninstalled: true }],
  }));
  assert.equal(r.ok, false);
});
