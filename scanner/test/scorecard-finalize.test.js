import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { createGitFixture } from './helpers/build-git-fixture.js';
import { scorecardIdentity, SCORECARD_DERIVED } from '../../scripts/scorecard-finalize.mjs';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'scorecard-finalize.mjs');
const C = 'a'.repeat(40);
const clean = (over = {}) => ({
  provenance: { commit: C, worktreeClean: true, engineVersion: '1.0.0', bundleSha256: 'b'.repeat(64), ...over },
  measurement: { cleanMeasurement: over.worktreeClean ?? true, engineVersion: over.engineVersion ?? '1.0.0' },
});

test('refuses a dirty tree', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.txt', 'one');
    fx.commit('init');
    fx.writeFile('x.js', 'uncommitted');
    const r = spawnSync(process.execPath, [CLI, '--root', fx.root], { encoding: 'utf8' });
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout + r.stderr, /x\.js/);
  } finally { fx.cleanup(); }
});

test('the derived pages are the scorecard pair and the GA status pair', () => {
  assert.deepEqual([...SCORECARD_DERIVED].sort(), ['docs/SCORECARD.md', 'docs/ga-program/STATUS.md', 'docs/ga-program/status.json', 'docs/scorecard.json']);
});

test('passes when only scorecard files changed since the measured commit', () => {
  const r = scorecardIdentity({ scorecard: clean(), version: '1.0.0', changedSince: ['docs/SCORECARD.md', 'docs/scorecard.json'] });
  assert.equal(r.ok, true, r.reasons.join('; '));
});

test('fails when HEAD differs from the measured commit beyond the scorecard', () => {
  const r = scorecardIdentity({ scorecard: clean(), version: '1.0.0', changedSince: ['docs/scorecard.json', 'scanner/src/engine.js'] });
  assert.equal(r.ok, false);
  assert.match(r.reasons.join('; '), /scanner\/src\/engine\.js/);
});

test('fails on a version mismatch', () => {
  const r = scorecardIdentity({ scorecard: clean(), version: '1.0.1', changedSince: [] });
  assert.equal(r.ok, false);
  assert.match(r.reasons.join('; '), /1\.0\.0/);
});

test('fails when the measurement is not clean', () => {
  const r = scorecardIdentity({ scorecard: clean({ worktreeClean: false }), version: '1.0.0', changedSince: [] });
  assert.equal(r.ok, false);
  assert.match(r.reasons.join('; '), /dirty/);
});

test('fails when the measured commit is not in this history', () => {
  const r = scorecardIdentity({ scorecard: clean(), version: '1.0.0', changedSince: null });
  assert.equal(r.ok, false);
  assert.match(r.reasons.join('; '), /not in this history/);
});
