// Guards against fitting the corpus to the detectors it measures.
//
// The rule is about something that actually happened: a detector
// (`sast/crypto-specialist.js`) and the ten corpus entries exercising it landed
// in one commit, and two of those entries only passed after the DETECTOR was
// changed to make them pass.
//
// The coupling cases are driven against purpose-built repos rather than that
// real commit range. An earlier version pinned the real SHAs and passed locally
// while failing in CI, where a shallow clone does not contain them: the check
// degraded to "history unavailable" and the assertion failed for a reason
// unrelated to the logic. A rule worth gating on must be testable anywhere.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
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

// A purpose-built repo, so the coupling rule is exercised anywhere — including
// a shallow CI clone, which does not contain this project's own history. The
// earlier version of these tests pinned real SHAs and failed in CI for a reason
// that had nothing to do with the logic under test.
function repoWith(commits) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-'));
  const g = (...a) => spawnSync('git', ['-C', dir, ...a], { encoding: 'utf8' });
  spawnSync('git', ['init', '-q', dir], { encoding: 'utf8' });
  g('config', 'user.email', 't@example.com');
  g('config', 'user.name', 'T');
  g('config', 'commit.gpgsign', 'false');
  for (const files of commits) {
    for (const f of files) {
      const abs = path.join(dir, f);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, `x${Math.random()}`);
      g('add', f);
    }
    g('commit', '-q', '-m', 'c');
  }
  return dir;
}

const DETECTOR = 'scanner/src/sast/example.js';
const ENTRY = 'bench/cve-replay/capability/EX-1/manifest.json';

test('a detector and its corpus entries landing together FAILS', () => {
  const dir = repoWith([['README.md'], [DETECTOR, ENTRY]]);
  try {
    const r = run({ CORPUS_PROVENANCE_GIT_DIR: dir, CORPUS_PROVENANCE_RANGE: 'HEAD~1..HEAD' });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /detector file\(s\) AND adds\/changes/);
    assert.match(r.out, /Land the detector\s*\n?\s*first/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the coupling rule covers posture, ir and engine — not just sast', () => {
  // A change to relevance.js (which demotes findings) or to a parser can flip a
  // corpus verdict as surely as a rule edit.
  for (const detector of [
    'scanner/src/posture/relevance.js',
    'scanner/src/ir/parser-py-cst.js',
    'scanner/src/engine.js',
    'scanner/src/dataflow/engine.js',
  ]) {
    const dir = repoWith([['README.md'], [detector, ENTRY]]);
    try {
      const r = run({ CORPUS_PROVENANCE_GIT_DIR: dir, CORPUS_PROVENANCE_RANGE: 'HEAD~1..HEAD' });
      assert.equal(r.code, 1, `${detector} was not treated as a detector change`);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  }
});

test('a corpus-only commit passes', () => {
  const dir = repoWith([['README.md'], [ENTRY]]);
  try {
    const r = run({ CORPUS_PROVENANCE_GIT_DIR: dir, CORPUS_PROVENANCE_RANGE: 'HEAD~1..HEAD' });
    assert.equal(r.code, 0, r.out);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a detector-only commit passes', () => {
  const dir = repoWith([['README.md'], [DETECTOR]]);
  try {
    const r = run({ CORPUS_PROVENANCE_GIT_DIR: dir, CORPUS_PROVENANCE_RANGE: 'HEAD~1..HEAD' });
    assert.equal(r.code, 0, r.out);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('--report never fails the build, but still says what it found', () => {
  const dir = repoWith([['README.md'], [DETECTOR, ENTRY]]);
  try {
    const r = run({ CORPUS_PROVENANCE_GIT_DIR: dir, CORPUS_PROVENANCE_RANGE: 'HEAD~1..HEAD' }, ['--report']);
    assert.equal(r.code, 0, 'report mode must not gate');
    assert.match(r.out, /report only/);
    assert.match(r.out, /detector file\(s\) AND adds\/changes/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an unreadable history degrades rather than failing the build', () => {
  const r = run({ CORPUS_PROVENANCE_RANGE: 'not-a-real-ref..also-not-real' });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /coupling check skipped/);
});
