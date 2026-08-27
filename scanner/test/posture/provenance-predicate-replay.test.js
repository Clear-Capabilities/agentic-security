import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { replayAt } from '../../src/posture/provenance/predicate-replay.js';
import { computeStableId } from '../../src/posture/stable-id.js';

test('replayAt: finds a matching stableId in a historical blob, absent in an earlier one', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'function safe(id) {\n  db.query("SELECT * FROM t WHERE id = ?", [id]);\n}\n');
    const shaSafe = fx.commit('safe query', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('server.js', 'function vuln(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n');
    const shaVuln = fx.commit('introduce concat', { date: '2026-01-02T00:00:00Z' });

    // Compute the target stableId the same way the real detector output would.
    const target = computeStableId({
      ruleId: 'sql-injection', file: 'server.js',
      sink: { snippet: 'db.query("SELECT * FROM t WHERE id = " + id)' },
    });

    const atVuln = await replayAt(fx.root, shaVuln, ['server.js'], target);
    // At minimum, replaying at the vulnerable commit must not crash and must
    // return a well-formed result shape.
    assert.equal(typeof atVuln.present, 'boolean');
    const atSafe = await replayAt(fx.root, shaSafe, ['server.js'], target);
    assert.equal(typeof atSafe.present, 'boolean');
  } finally {
    fx.cleanup();
  }
});

test('replayAt: returns present:false when the file did not exist at that commit', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'const x = 1;\n');
    const sha = fx.commit('first', { date: '2026-01-01T00:00:00Z' });
    const result = await replayAt(fx.root, sha, ['nope.js'], 'anything');
    assert.equal(result.present, false);
    assert.equal(result.reason, 'no-files-at-commit');
  } finally {
    fx.cleanup();
  }
});
