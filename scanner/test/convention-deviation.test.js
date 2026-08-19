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
  scanConventionDeviation, scanConventionDeviationProject, analyseUnits, pythonUnits, jsUnits, _internals,
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

// ─────────────────────────────── JS/TS support (6 of the 10 known entries)
const tsGuarded = (i) => [
  `  async guarded${i}(path, ...opts) {`,
  '    assertWorkspaceAccess(opts);',
  `    return this.client.cmd${i}(path, ...opts);`,
  '  }',
].join('\n');

test('JS/TS: an unguarded method among guarded peers fires', () => {
  const files = {
    'a.ts': 'class A {\n' + tsGuarded(1) + '\n' + tsGuarded(2) + '\n}',
    'b.ts': 'class B {\n' + tsGuarded(3) + '\n}',
    'c.ts': 'class C {\n' + tsGuarded(4) +
      '\n  async remove(path, ...opts) {\n    return this.client.remove(path, ...opts);\n  }\n}',
  };
  const out = scanConventionDeviationProject(files);
  assert.equal(out.length, 1, `got ${JSON.stringify(out.map(x => x.vuln))}`);
  assert.match(out[0].vuln, /remove\(\)/);
  assert.equal(out[0].file, 'c.ts');
});

test('JS/TS: camelCase guards are recognised (snake_case is not the only form)', () => {
  // The Python convention is check_unsafe_options; the JS one is
  // assertWorkspaceAccess. A verb-only match (`check(x)`) must NOT qualify.
  const { GUARD_CALL_RE } = _internals;
  assert.ok(GUARD_CALL_RE.test('assertWorkspaceAccess(opts)'));
  assert.ok(GUARD_CALL_RE.test('Git.check_unsafe_options(o)'));
  assert.ok(!GUARD_CALL_RE.test('check(x)'));
  assert.ok(!GUARD_CALL_RE.test('requirement(x)'));
});

test('JS/TS FIX-DISCRIMINATION: adding the guard silences it', () => {
  const files = {
    'a.ts': 'class A {\n' + tsGuarded(1) + '\n' + tsGuarded(2) + '\n}',
    'b.ts': 'class B {\n' + tsGuarded(3) + '\n}',
    'c.ts': 'class C {\n' + tsGuarded(4) +
      '\n  async remove(path, ...opts) {\n    assertWorkspaceAccess(opts);\n    return this.client.remove(path, ...opts);\n  }\n}',
  };
  assert.deepEqual(scanConventionDeviationProject(files), []);
});

// `jsUnits` is the JS/TS half of Theme 6 — 6 of the 10 known sibling-omission
// entries are TypeScript, so it carries the majority of the family. It was
// wired into `scanConventionDeviationProject` but had no test of its own; the
// dead-export guard (`test/no-dead-modules.test.js`) is what surfaced that.
// These pin the extractor directly, because a silent regression in unit
// EXTRACTION reads downstream as "the convention does not exist" — a false
// negative with no error anywhere.
test('jsUnits extracts the four declaration shapes it claims to support', () => {
  const code = [
    'function plain(a, ...opts) { return a; }',
    'const arrow = (b, ...opts) => { return b; };',
    'class K {',
    '  async method(c, ...opts) { return c; }',
    '}',
  ].join('\n');
  const names = jsUnits(code).map((u) => u.name).sort();
  assert.deepEqual(names, ['arrow', 'method', 'plain']);
});

test('jsUnits captures the body by brace matching, not to end-of-file', () => {
  const code = [
    'function first(a, ...opts) {',
    '  guardOne(opts);',
    '}',
    'function second(b, ...opts) {',
    '  guardTwo(opts);',
    '}',
  ].join('\n');
  const units = jsUnits(code);
  assert.equal(units.length, 2);
  const first = units.find((u) => u.name === 'first');
  assert.ok(first.body.includes('guardOne'), 'first unit should contain its own body');
  assert.ok(!first.body.includes('guardTwo'),
    `brace matching must stop at the closing brace; body leaked into the sibling:\n${first.body}`);
});

test('jsUnits does not treat control-flow keywords as function declarations', () => {
  const code = 'function real(a, ...opts) {\n  if (a) { return 1; }\n  for (const x of a) { use(x); }\n  return 0;\n}';
  assert.deepEqual(jsUnits(code).map((u) => u.name), ['real']);
});

test('jsUnits reports a 1-based line number for each unit', () => {
  const code = ['// header', '', 'function target(a, ...opts) {', '  return a;', '}'].join('\n');
  const [unit] = jsUnits(code);
  assert.equal(unit.name, 'target');
  assert.equal(unit.line, 3);
});
