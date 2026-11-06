import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { buildScanInventory } from '../../src/scope/inventory.js';
import { mkTestTmp } from '../helpers/tmp.js';

function repo(files, { ignore = '', commit = [] } = {}) {
  const dir = mkTestTmp('as-scope-');
  const sh = (...a) => cp.execFileSync('git', a, { cwd: dir, env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null' } });
  sh('init', '-q');
  if (ignore) fs.writeFileSync(path.join(dir, '.gitignore'), ignore);
  for (const [rel, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), c);
  }
  if (commit.length) { sh('add', '-f', ...commit); }
  return dir;
}

test('ignored build output is skipped and recorded without enumerating it', () => {
  const dir = repo({ 'src/A.hs': 'x', 'buck-out/gen/Generated.hs': 'x' }, { ignore: 'buck-out/\n' });
  const inv = buildScanInventory(dir);
  assert.deepEqual(inv.included.filter((f) => f.endsWith('.hs')), ['src/A.hs']);
  assert.ok(inv.skipped.some((s) => s.path === 'buck-out/' && s.reason === 'git-ignored'));
  assert.ok(!inv.skipped.some((s) => s.path.includes('Generated.hs')), 'subtree not enumerated');
});

test('Buck workflow and tool paths stay eligible; buck-out segment does not', () => {
  const dir = repo({ '.github/workflows/buck2.yml': 'a', 'tools/buck2/run.sh': 'a', 'third_party/buck2/x.bzl': 'a', 'buck-out/v2/o.hs': 'a' });
  const inv = buildScanInventory(dir);
  for (const f of ['.github/workflows/buck2.yml', 'tools/buck2/run.sh', 'third_party/buck2/x.bzl']) assert.ok(inv.included.includes(f), f);
  assert.ok(!inv.included.includes('buck-out/v2/o.hs'));
  assert.ok(inv.skipped.some((s) => s.path === 'buck-out/v2/o.hs' && s.reason === 'generated-default'));
});

test('a tracked file stays eligible even when an ignore pattern matches it', () => {
  const dir = repo({ 'keep.js': 'a', 'drop.js': 'a' }, { ignore: '*.js\n', commit: ['keep.js'] });
  const inv = buildScanInventory(dir);
  assert.ok(inv.included.includes('keep.js'));
  assert.ok(!inv.included.includes('drop.js'));
});

test('nested gitignore, negation, spaces and unusual filenames follow Git', () => {
  const dir = repo({ 'a b/x.js': 'a', 'sub/.gitignore': '*.log\n!keep.log\n', 'sub/n.log': 'a', 'sub/keep.log': 'a', 'we"ird\nname.js': 'a' });
  const inv = buildScanInventory(dir);
  assert.ok(inv.included.includes('a b/x.js'));
  assert.ok(inv.included.includes('sub/keep.log'));
  assert.ok(!inv.included.includes('sub/n.log'));
  assert.ok(inv.included.includes('we"ird\nname.js'));
});

test('precedence: explicit exclude beats include; exact include beats git ignore and generated default', () => {
  const dir = repo({ 'secret.env': 'a', 'buck-out/a.hs': 'a', 'x/y.js': 'a' }, { ignore: 'secret.env\n' });
  const inv = buildScanInventory(dir, {
    includeIgnoredPaths: ['secret.env'], includePaths: ['buck-out/a.hs', 'x/y.js'], excludePaths: ['x'],
  });
  assert.ok(inv.included.includes('secret.env'));
  assert.ok(inv.included.includes('buck-out/a.hs'));
  assert.ok(!inv.included.includes('x/y.js'));
  assert.ok(inv.overrides.some((o) => o.path === 'secret.env' && o.overrode === 'git-ignore'));
  assert.ok(inv.overrides.some((o) => o.path === 'buck-out/a.hs' && o.overrode === 'generated-default'));
});

test('include cannot escape the root or follow a symlink out', () => {
  const dir = repo({ 'a.js': 'a' });
  const outside = mkTestTmp('as-outside-');
  fs.writeFileSync(path.join(outside, 'o.js'), 'a');
  fs.symlinkSync(path.join(outside, 'o.js'), path.join(dir, 'link.js'));
  const inv = buildScanInventory(dir, { includePaths: ['../' + path.basename(outside) + '/o.js', 'link.js'] });
  assert.ok(!inv.included.some((f) => f.includes('o.js') || f === 'link.js'));
});

test('repository mode ignores .git/info/exclude; local mode honours it; digests differ', () => {
  const dir = repo({ 'a.js': 'a', 'local.js': 'a' });
  fs.writeFileSync(path.join(dir, '.git/info/exclude'), 'local.js\n');
  const local = buildScanInventory(dir);
  const repoMode = buildScanInventory(dir, { ignoreSource: 'repository' });
  assert.ok(!local.included.includes('local.js'));
  assert.ok(repoMode.included.includes('local.js'));
  assert.notEqual(local.policy.ruleDigest, repoMode.policy.ruleDigest);
});

test('changing an ignore rule changes the rule digest', () => {
  const dir = repo({ 'a.js': 'a' }, { ignore: 'x\n' });
  const d1 = buildScanInventory(dir).policy.ruleDigest;
  fs.writeFileSync(path.join(dir, '.gitignore'), 'y\n');
  assert.notEqual(d1, buildScanInventory(dir).policy.ruleDigest);
});

test('non-git directory discloses missing tracked-file semantics', () => {
  const dir = mkTestTmp('as-nogit-');
  fs.writeFileSync(path.join(dir, 'a.js'), 'a');
  const inv = buildScanInventory(dir);
  assert.deepEqual(inv.included, ['a.js']);
  assert.equal(inv.policy.trackedFileSemantics, false);
  assert.ok(inv.policy.disclosures.length);
});
