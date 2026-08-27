import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createGitFixture } from './build-git-fixture.js';

test('createGitFixture builds a real, committable git repo', () => {
  const fx = createGitFixture();
  try {
    assert.ok(fs.existsSync(fx.root));
    fx.writeFile('a.js', 'console.log(1);\n');
    const sha1 = fx.commit('first commit', { date: '2026-01-01T00:00:00Z' });
    assert.match(sha1, /^[0-9a-f]{40}$/);
    fx.writeFile('a.js', 'console.log(2);\n');
    const sha2 = fx.commit('second commit', { date: '2026-01-02T00:00:00Z' });
    assert.notEqual(sha1, sha2);
    const log = execFileSync('git', ['log', '--format=%H'], { cwd: fx.root, encoding: 'utf8' }).trim().split('\n');
    assert.deepEqual(log, [sha2, sha1]);
  } finally {
    fx.cleanup();
  }
});
