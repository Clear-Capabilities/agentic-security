// Guards against fitting the corpus to the detectors it measures.
//
// Both directions are exercised against REAL commit ranges from this
// repository's history rather than synthetic input, because the rule is about
// what actually happened: `3b491db..3a05f4d` is the commit pair where a
// detector (`sast/crypto-specialist.js`) and the ten corpus entries exercising
// it landed together, and two of those entries only passed after the detector
// was changed to make them pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CHECK = path.join(REPO, 'scripts', 'corpus-provenance-check.mjs');

function run(env = {}, args = []) {
  const r = spawnSync(process.execPath, [CHECK, ...args], {
    encoding: 'utf8', cwd: REPO, env: { ...process.env, ...env },
  });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

test('reports the provenance mix, and does not hide how synthetic it is', () => {
  const r = run();
  assert.match(r.out, /corpus provenance \(\d+ entries\)/);
  assert.match(r.out, /synthetic-shape-of-disclosed-cve/);
  // The reader must be told what the corpus can and cannot support. A bare
  // percentage would let a 100%-synthetic corpus read as a recall measurement.
  assert.match(r.out, /REGRESSION net/);
  assert.match(r.out, /cannot support a\s*\n?\s*recall claim/);
  assert.match(r.out, /ceiling\s*\n?\s*by construction/);
});

test('a detector and its corpus entries landing together FAILS', () => {
  // The real occurrence, not a hypothetical.
  const r = run({ CORPUS_PROVENANCE_RANGE: '3b491db..3a05f4d' });
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /changes 1 detector file\(s\) AND adds\/changes 10 corpus entr/);
  assert.match(r.out, /crypto-specialist\.js/);
  assert.match(r.out, /Land the detector\s*\n?\s*first/);
});

test('a range with entries but no detector change passes', () => {
  // The corpus-only commit: entries were added, no detector moved with them.
  const r = run({ CORPUS_PROVENANCE_RANGE: '3a05f4d..468938c' });
  assert.equal(r.code, 0, r.out);
});

test('--report never fails the build, but still says what it found', () => {
  const r = run({ CORPUS_PROVENANCE_RANGE: '3b491db..3a05f4d' }, ['--report']);
  assert.equal(r.code, 0, 'report mode must not gate');
  assert.match(r.out, /report only/);
  assert.match(r.out, /detector file\(s\) AND adds\/changes/);
});

test('an unreadable history degrades rather than failing the build', () => {
  const r = run({ CORPUS_PROVENANCE_RANGE: 'not-a-real-ref..also-not-real' });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /coupling check skipped/);
});
