// Semantics contract for src/util/glob.js.
//
// `listFiles()` is the file-discovery primitive behind readTree(): it decides
// which files every scan sees. The five options it has to honour used to be
// supplied by a third-party glob package; they are now implemented on top of
// node:fs + path.matchesGlob. Each option gets its own test here because a
// silent change in any one of them changes what gets scanned without failing
// anything else.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { listFiles, globFiles, matchesAnyGlob } from '../src/util/glob.js';

function mktree(spec) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-compat-'));
  for (const [rel, body] of Object.entries(spec)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body);
  }
  return root;
}

const sorted = a => [...a].sort();

test('hidden files and directories are discovered (dot semantics)', async () => {
  const root = mktree({
    'visible.js': '1',
    '.dotfile': '1',
    '.hidden/inner.js': '1',
    '.hidden/.deeper/leaf.js': '1',
    'a/.b/c.js': '1',
  });
  assert.deepEqual(sorted(await listFiles(root)), [
    '.dotfile', '.hidden/.deeper/leaf.js', '.hidden/inner.js', 'a/.b/c.js', 'visible.js',
  ]);
});

test('directories are never returned (files-only semantics)', async () => {
  const root = mktree({ 'a/b/c.js': '1' });
  fs.mkdirSync(path.join(root, 'empty-dir'), { recursive: true });
  const out = await listFiles(root);
  assert.deepEqual(out, ['a/b/c.js']);
  for (const p of out) {
    assert.ok(fs.statSync(path.join(root, p)).isFile(), `${p} should be a regular file`);
  }
});

test('ignore patterns exclude nested and top-level matches alike', async () => {
  const root = mktree({
    'keep.js': '1',
    'node_modules/pkg/index.js': '1',
    'src/node_modules/pkg/index.js': '1',
    'src/keep.js': '1',
  });
  assert.deepEqual(
    sorted(await listFiles(root, { ignore: ['**/node_modules/**'] })),
    ['keep.js', 'src/keep.js'],
  );
});

test('a directory ignore pattern excludes the whole subtree, at any depth', async () => {
  const root = mktree({
    'src/app.js': '1',
    'src/test/a.js': '1',
    'src/test/deep/nested/b.js': '1',
    'test/top.js': '1',
    'test/deep/c.js': '1',
    'contest/notmatched.js': '1',
  });
  assert.deepEqual(
    sorted(await listFiles(root, { ignore: ['**/test/**'] })),
    ['contest/notmatched.js', 'src/app.js'],
  );
});

test('ignore patterns apply inside hidden directories too', async () => {
  // A dot-segment anywhere on the path must not stop an ignore pattern from
  // matching; the underlying matcher is dot-blind by default and this is the
  // one place the helper has to compensate.
  const root = mktree({
    '.cache/dist/bundle.js': '1',
    '.cache/keep.js': '1',
    'dist/bundle.js': '1',
  });
  assert.deepEqual(
    sorted(await listFiles(root, { ignore: ['**/dist/**'] })),
    ['.cache/keep.js'],
  );
});

test('symlinks are not followed: a link escaping the root yields nothing', async () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-outside-'));
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'do-not-scan');
  fs.mkdirSync(path.join(outside, 'sub'), { recursive: true });
  fs.writeFileSync(path.join(outside, 'sub', 'deep.txt'), 'do-not-scan');

  const root = mktree({ 'inside.js': '1' });
  fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(root, 'link-to-file'));
  fs.symlinkSync(outside, path.join(root, 'link-to-dir'));

  const out = await listFiles(root);
  assert.deepEqual(out, ['inside.js']);
  assert.ok(!out.some(p => p.includes('link-to-dir')), 'symlinked directory must not be traversed');
  assert.ok(!out.includes('link-to-file'), 'symlink to a file must not be reported as a file');
  assert.ok(!out.some(p => p.includes('secret')), 'no content outside the root may be reached');
});

test('an unreadable directory does not throw and does not stop the walk', async (t) => {
  if (process.getuid && process.getuid() === 0) return t.skip('root can read anything');
  const root = mktree({
    'before.js': '1',
    'locked/hidden-from-us.js': '1',
    'zzz-after/later.js': '1',
  });
  const locked = path.join(root, 'locked');
  fs.chmodSync(locked, 0o000);
  try {
    const out = sorted(await listFiles(root));
    assert.deepEqual(out, ['before.js', 'zzz-after/later.js']);
  } finally {
    fs.chmodSync(locked, 0o755);
  }
});

test('matchesAnyGlob is dot-permissive but still literal about named dot dirs', () => {
  assert.equal(matchesAnyGlob('.git/config', ['**/.git/**']), true);
  assert.equal(matchesAnyGlob('git/config', ['**/.git/**']), false);
  assert.equal(matchesAnyGlob('.a/.b/node_modules/z.js', ['**/node_modules/**']), true);
  assert.equal(matchesAnyGlob('a/b.js', ['**/dist/**']), false);
  assert.equal(matchesAnyGlob('a/b.js', []), false);
});

test('ignore matching is case-sensitive', async () => {
  // The underlying matcher folds case in some positions and not others. A
  // directory named Test/ must not be swept away by a lower-case pattern, and
  // a .JS file must not answer to *.js.
  // Names are chosen so they stay distinct on a case-insensitive filesystem.
  const root = mktree({
    'Test/upper.js': '1',
    'lowerdir/lower.js': '1',
    'UPPER/MiXeD.JS': '1',
  });
  assert.deepEqual(
    sorted(await listFiles(root, { ignore: ['**/test/**'] })),
    ['Test/upper.js', 'UPPER/MiXeD.JS', 'lowerdir/lower.js'],
  );
  assert.deepEqual(
    sorted(await listFiles(root, { ignore: ['**/*.js'] })),
    ['UPPER/MiXeD.JS'],
  );
  assert.equal(matchesAnyGlob('UPPER/MiXeD.JS', ['**/*.js']), false);
  assert.equal(matchesAnyGlob('UPPER/MiXeD.JS', ['**/*.JS']), true);
});

test('globFiles is case-sensitive about the pattern it was given', async () => {
  const root = mktree({ 'a/report.SARIF': '1' });
  assert.deepEqual(await globFiles('**/*.sarif', { cwd: root }), []);
  assert.deepEqual(await globFiles('**/*.SARIF', { cwd: root }), ['a/report.SARIF']);
});

test('globFiles resolves a user-supplied pattern to regular files only', async () => {
  const root = mktree({
    'fixtures/one/vulnerable.js': '1',
    'fixtures/two/clean.js': '1',
    'fixtures/notes.txt': '1',
    '.fixtures/hidden.js': '1',
  });
  fs.mkdirSync(path.join(root, 'fixtures/three.js'), { recursive: true }); // a directory named like a file
  const out = sorted(await globFiles('fixtures/**/*.js', { cwd: root }));
  assert.deepEqual(out, ['fixtures/one/vulnerable.js', 'fixtures/two/clean.js']);
});

test('globFiles does not match hidden paths (dot:false semantics)', async () => {
  const root = mktree({ '.hidden/x.js': '1', 'shown/x.js': '1' });
  assert.deepEqual(sorted(await globFiles('**/*.js', { cwd: root })), ['shown/x.js']);
});

test('globFiles returns an empty list for a pattern that matches nothing', async () => {
  const root = mktree({ 'a.js': '1' });
  assert.deepEqual(await globFiles('**/*.nope', { cwd: root }), []);
});
