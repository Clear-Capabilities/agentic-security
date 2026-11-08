// PRD FR 01: under Git scope the watcher asks the same inventory as the scan, so an ignored file never triggers a rescan, a
// tracked file under a default-skipped directory always does, and a change to an ignore source rebuilds the decision.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createScopeFilter, _internals } from '../../src/posture/watch-mode.js';
import { mkTestTmp } from '../helpers/tmp.js';

function repo(files, { track = [] } = {}) {
  const dir = mkTestTmp('watch-scope-');
  const git = (...a) => spawnSync('git', a, { cwd: dir, encoding: 'utf8' });
  git('init', '-q');
  for (const [rel, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), c); }
  for (const t of track) git('add', '-f', t);
  return dir;
}

test('ignored files do not trigger, tracked files under a default-skipped directory do', () => {
  const dir = repo({ '.gitignore': 'generated/\n', 'src/app.js': 'x', 'generated/out.js': 'x', 'dist/keep.js': 'x' }, { track: ['dist/keep.js'] });
  const ok = createScopeFilter(dir, {});
  assert.equal(ok('src/app.js'), true);
  assert.equal(ok('generated/out.js'), false, 'Git-ignored');
  assert.equal(ok('dist/keep.js'), true, 'tracked, so eligible under Git scope');
  assert.equal(_internals._isScanable('dist/keep.js'), false, 'the default filter would have missed it');
  assert.equal(ok('.agentic-security/last-scan.json'), false);
  assert.equal(ok('.git/index'), false);
});

test('explicit exclusions from the scope flags apply to the watcher too', () => {
  const dir = repo({ 'src/app.js': 'x', 'legacy/old.js': 'x' });
  const ok = createScopeFilter(dir, { excludePaths: ['legacy'] });
  assert.equal(ok('src/app.js'), true);
  assert.equal(ok('legacy/old.js'), false);
});

test('a new file and a changed ignore source rebuild the inventory', () => {
  let t = 0;
  const dir = repo({ '.gitignore': '', 'src/app.js': 'x' });
  const ok = createScopeFilter(dir, {}, { now: () => t });
  fs.writeFileSync(path.join(dir, 'src/new.js'), 'x');
  t += 1000;
  assert.equal(ok('src/new.js'), true, 'a file created after the watcher started is seen once the inventory is rebuilt');
  fs.writeFileSync(path.join(dir, '.gitignore'), 'src/new.js\n');
  assert.equal(ok('.gitignore'), true, 'an ignore-source change triggers a rescan');
  assert.equal(ok('src/new.js'), false, 'and the rebuilt inventory now excludes the file');
});

test('rebuilds for unseen paths are throttled to one a second', () => {
  let builds = 0; let t = 0;
  const build = () => { builds++; return { included: ['a.js'] }; };
  const ok = createScopeFilter('/nowhere', {}, { build, now: () => t });
  assert.equal(builds, 1);
  ok('b.js'); ok('c.js'); ok('d.js');
  assert.equal(builds, 1, 'within the same second no rebuild');
  t = 1000; ok('e.js');
  assert.equal(builds, 2);
});
