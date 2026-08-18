// PRD Theme 6 — repo-internal convention deviation.
//
// The shape under test is drawn from GHSA-9rj7-rf2p-w77r (GitPython argument
// injection): four sibling methods call Git.check_unsafe_options() before
// forwarding **kwargs to git.*, and Repo.init() does not — so a `--template`
// kwarg becomes a git CLI flag that installs an attacker-controlled hook.
//
// Fixtures here are SYNTHETIC reproductions of that shape rather than reads of
// bench/independent/cache, which is gitignored and fetched on demand — a test
// that depends on it would pass or fail based on whether someone had run the
// miner. The detector was additionally verified by hand against the real
// pre/post trees: it reports init() on the vulnerable revision and correctly
// goes SILENT on init() in the fixed revision.
//
// The bias: this detector asserts an absence relative to neighbours, so every
// precision control gets a test proving it REFUSES to fire, not just one
// proving it fires.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scanConventionDeviation, scanConventionDeviationProject, analyseUnits, pythonUnits,
  MIN_GUARDED_SIBLINGS, MIN_GUARDED_RATIO,
} from '../src/sast/convention-deviation.js';

/** n guarded siblings + the named unguarded ones, all forwarding into git.*  */
function repo({ guarded = 4, unguarded = ['init'] } = {}) {
  const lines = ['class Repo:'];
  for (let i = 0; i < guarded; i++) {
    lines.push(
      `    def guarded_${i}(self, path, **kwargs):`,
      '        Git.check_unsafe_options(options=kwargs, unsafe_options=self.unsafe_opts)',
      `        return self.git.cmd_${i}(path, **kwargs)`,
      '');
  }
  for (const name of unguarded) {
    lines.push(
      `    def ${name}(self, path, **kwargs):`,
      `        return self.git.${name}(path, **kwargs)`,
      '');
  }
  return lines.join('\n');
}

test('the real shape fires: an unguarded sibling among guarded neighbours', () => {
  const f = scanConventionDeviation('git/repo/base.py', repo());
  assert.equal(f.length, 1, `expected exactly the unguarded method, got ${JSON.stringify(f.map(x => x.vuln))}`);
  assert.match(f[0].vuln, /init\(\)/);
  assert.equal(f[0].cwe, 'CWE-88');
  assert.equal(f[0].family, 'convention-deviation');
  assert.equal(f[0].parser, 'CONVENTION');
});

test('the finding carries its sibling evidence — the claim must be checkable', () => {
  const [f] = scanConventionDeviation('git/repo/base.py', repo());
  assert.ok(Array.isArray(f.evidenceSiblings) && f.evidenceSiblings.length >= MIN_GUARDED_SIBLINGS);
  assert.ok(f.checkedFor, 'an absence-claim must record what it looked for (T2.2)');
  assert.match(f.description, /check_unsafe_options/);
});

test('FIX-DISCRIMINATION: adding the guard silences it (T0.2 — the property the engine mostly lacks)', () => {
  const fixed = repo().replace(
    '    def init(self, path, **kwargs):\n        return self.git.init(path, **kwargs)',
    '    def init(self, path, **kwargs):\n' +
    '        Git.check_unsafe_options(options=kwargs, unsafe_options=self.unsafe_opts)\n' +
    '        return self.git.init(path, **kwargs)');
  assert.deepEqual(scanConventionDeviation('git/repo/base.py', fixed), [],
    'once the guard is applied, the deviation must disappear');
});

test('REFUSES to fire without a real population of guarded neighbours', () => {
  // Two guarded siblings is below MIN_GUARDED_SIBLINGS: not yet a convention.
  assert.equal(MIN_GUARDED_SIBLINGS, 3);
  assert.deepEqual(scanConventionDeviation('a.py', repo({ guarded: 2 })), []);
});

test('REFUSES to fire when the guard is a minority habit, not a convention', () => {
  // 3 guarded, 4 unguarded → ratio 3/7 < 0.5.
  assert.equal(MIN_GUARDED_RATIO, 0.5);
  const f = scanConventionDeviation('a.py', repo({ guarded: 3, unguarded: ['a', 'b', 'c', 'd'] }));
  assert.deepEqual(f, [], `minority guard must not condemn the majority, got ${f.length} findings`);
});

test('REFUSES to fire when every sibling is consistent', () => {
  assert.deepEqual(scanConventionDeviation('a.py', repo({ guarded: 5, unguarded: [] })), []);
});

test('a method that takes no option bag is not compared at all', () => {
  const src = repo() + '\n    def plain(self, path):\n        return self.git.plain(path)\n';
  const f = scanConventionDeviation('a.py', src);
  assert.ok(!f.some(x => /plain\(\)/.test(x.vuln)), 'a method with no **kwargs cannot deviate on option handling');
});

test('a method that accepts but never forwards the option bag is not compared', () => {
  const src = repo() + '\n    def stores(self, path, **kwargs):\n        self.opts = kwargs\n        return None\n';
  const f = scanConventionDeviation('a.py', src);
  assert.ok(!f.some(x => /stores\(\)/.test(x.vuln)));
});

test('grouping is per primitive: unrelated receivers are never weighed together', () => {
  // git.* has a 4-strong guarded convention; TagReference.* has one unguarded
  // method and no convention at all, so it must not inherit git's.
  const src = repo() + '\n    def create_tag(self, path, **kwargs):\n        return TagReference.create(path, **kwargs)\n';
  const f = scanConventionDeviation('a.py', src);
  assert.ok(!f.some(x => /create_tag\(\)/.test(x.vuln)),
    'a receiver with no established convention must not borrow another receiver\'s');
});

test('self/cls delegation is excluded (the guard lives one hop away, in the sibling)', () => {
  const src = repo({ unguarded: [] }) +
    '\n    def wrapper(self, path, **kwargs):\n        return self.guarded_0(path, **kwargs)\n';
  const f = scanConventionDeviation('a.py', src);
  assert.deepEqual(f, [], 'delegating to a guarded sibling is not a deviation');
});

test('non-Python files and option-bag-free files are skipped cheaply', () => {
  assert.deepEqual(scanConventionDeviation('a.js', repo()), []);
  assert.deepEqual(scanConventionDeviation('a.py', 'def f(a, b):\n    return a + b\n'), []);
});

test('pythonUnits captures multi-line signatures', () => {
  const units = pythonUnits('def f(\n    a,\n    **kwargs,\n):\n    return 1\n');
  assert.equal(units.length, 1);
  assert.match(units[0].sig, /\*\*kwargs/);
});

test('analyseUnits is pure and reports the consensus guard', () => {
  const out = analyseUnits(pythonUnits(repo()));
  assert.equal(out.length, 1);
  assert.equal(out[0].name, 'init');
  assert.equal(out[0].consensusGuard, 'Git.check_unsafe_options');
  assert.equal(out[0].receiver, 'self.git'.split('.').pop());
});

// ─────────────────────────────── project-scoped convention mining
test('the convention is mined ACROSS files, not per-file', () => {
  // Split the same convention over three files so that NO single file clears
  // MIN_GUARDED_SIBLINGS on its own. Per-file analysis sees populations of
  // 2/1/1 and stays silent; project-scoped sees 4 and reports the deviant.
  // This is the GitPython shape: Git.check_unsafe_options spans repo/base.py,
  // index/base.py and objects/commit.py.
  const guarded = (i) => [
    `class C${i}:`,
    `    def guarded_${i}(self, path, **kwargs):`,
    '        Git.check_unsafe_options(options=kwargs, unsafe_options=self.unsafe_opts)',
    `        return self.git.cmd_${i}(path, **kwargs)`,
  ].join('\n');
  const files = {
    'a.py': guarded(1) + '\n' + guarded(2).split('\n').slice(1).join('\n'),
    'b.py': guarded(3),
    'c.py': guarded(4) + '\n' +
      '    def init(self, path, **kwargs):\n' +
      '        return self.git.init(path, **kwargs)\n',
  };
  // Per-file: no file has >=3 guarded, so nothing fires.
  for (const [f, src] of Object.entries(files)) {
    assert.deepEqual(scanConventionDeviation(f, src), [], `${f} alone must be silent`);
  }
  // Project-wide: the convention is visible and the deviant is reported.
  const out = scanConventionDeviationProject(files);
  assert.equal(out.length, 1, `expected the one deviant, got ${JSON.stringify(out.map(x => x.vuln))}`);
  assert.match(out[0].vuln, /init\(\)/);
  assert.equal(out[0].file, 'c.py');
  // Evidence cites peers from other files, qualified by path.
  assert.ok(out[0].evidenceSiblings.some(x => x.includes('a.py') || x.includes('b.py')),
    `expected cross-file evidence, got ${JSON.stringify(out[0].evidenceSiblings)}`);
});
