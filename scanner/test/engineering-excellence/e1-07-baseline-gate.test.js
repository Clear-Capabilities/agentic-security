// E1-07 on the real baseline: the floors are the Wilson lower bounds recomputed here from the run, the release check passes the run they came from, a worsened copy
// fails, and a missing corpus is unmeasured and not green.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { wilsonInterval } from '../../src/posture/evaluation/interval.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), 'utf8'));
const pointer = read('bench/independent/runs/BASELINE.json'); const RUN = `bench/independent/runs/${pointer.runId}`;
const result = read(`${RUN}/RESULT.json`); const floors = read(`bench/independent/runs/${pointer.floorsFile}`);
const REALCODE = path.join(ROOT, 'bench', 'independent', 'realcode.mjs');
const run = (...a) => spawnSync(process.execPath, [REALCODE, ...a], { cwd: ROOT, encoding: 'utf8', timeout: 120_000 });

test('FLOORS ARE PRE-REGISTERED FROM THE OBSERVED BASELINE AND ITS UNCERTAINTY: each is the 95% Wilson lower bound, recomputed here from the rows', () => {
  assert.equal(floors.derivedFrom.runId, pointer.runId); assert.equal(floors.derivedFrom.commit, result.identity.sourceCommit); assert.equal(floors.derivedFrom.bundleSha256, result.identity.bundleSha256);
  assert.equal(floors.minEntriesForComparison, 30);
  const byLang = {}; for (const r of result.perEntry) { const l = (byLang[r.language] ||= { entries: 0, tp: 0, fp: 0, fn: 0 }); l.entries++; l.tp += r.tpLocal; l.fp += r.fpLocal; l.fn += r.fnLocal; }
  let withFloor = 0;
  for (const [lang, v] of Object.entries(floors.languages)) {
    const c = byLang[lang]; assert.equal(v.entries, c.entries, lang);
    if (c.entries < 30) { assert.equal(v.status, 'insufficient_population', lang); assert.ok(!('recallFloor' in v), `${lang} gets no floor`); continue; }
    withFloor++; assert.equal(v.status, 'floor');
    assert.ok(Math.abs(v.recallFloor - wilsonInterval(c.tp, c.tp + c.fn).low) < 1e-9, `${lang} recall floor`);
    if (c.tp + c.fp > 0) assert.ok(Math.abs(v.precisionFloor - wilsonInterval(c.tp, c.tp + c.fp).low) < 1e-9, `${lang} precision floor`);
    assert.ok(v.recallFloor <= v.baseline.recall, 'a floor is below what was observed');
  }
  assert.equal(withFloor, 6, 'six languages have enough scored entries for a floor');
});

test('THE RELEASE CHECK PASSES THE RUN THE FLOORS CAME FROM, and says which languages it compared', () => {
  const r = run('check', '--tier', 'release', '--run', pointer.runId);
  assert.equal(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /realcode release: PASSED - 6 language\(s\) at or above their pre-registered floors/);
  assert.match(r.stdout, /denominators-reconcile/); assert.match(r.stdout, /scan-health: 1\.8% of entries were unscored or unaccounted \(limit 10%\)/); assert.match(r.stdout, /clean-measurement: clean commit/);
});

test('AN INTENTIONALLY WORSENED DETECTION FAILS THE GATE: the same run with a language\'s true positives removed is below its floor and the check exits non-zero', () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e1-07-'));
  try {
    const runs = path.join(work, 'runs'); fs.mkdirSync(path.join(runs, pointer.runId), { recursive: true });
    const check = (res) => { fs.writeFileSync(path.join(runs, pointer.runId, 'RESULT.json'), JSON.stringify(res)); return spawnSync(process.execPath, [REALCODE, 'check', '--tier', 'release', '--run', pointer.runId], { cwd: ROOT, encoding: 'utf8', timeout: 120_000, env: { ...process.env, AGENTIC_SECURITY_REALCODE_RUNS_DIR: runs } }); };
    fs.copyFileSync(path.join(ROOT, 'bench/independent/runs/BASELINE.json'), path.join(runs, 'BASELINE.json')); fs.copyFileSync(path.join(ROOT, `bench/independent/runs/${pointer.floorsFile}`), path.join(runs, pointer.floorsFile));
    const same = check(result); assert.equal(same.status, 0, 'the unmodified run passes from the redirected directory too: ' + same.stdout + same.stderr);
    const worse = JSON.parse(JSON.stringify(result));
    // the detection gets worse: ruby's two true positives are lost, in the rows and in the aggregate the gate reads
    for (const r of worse.perEntry) if (r.language === 'ruby' && r.tpLocal) { r.fnLocal += r.tpLocal; r.tpLocal = 0; }
    const g = worse.scoring.definitions.localized.byLanguage.ruby; g.tp = 0; g.fn += 2; g.recall = { n: 0, d: g.recall.d, value: 0 }; g.precision = { n: 0, d: g.precision.d, value: 0 };
    const bad = check(worse);
    assert.notEqual(bad.status, 0, bad.stdout + bad.stderr); assert.match(bad.stdout + bad.stderr, /language:ruby/); assert.match(bad.stdout + bad.stderr, /FAILED|failed/);
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
});

test('A MISSING CORPUS CANNOT PASS GREEN: a run that does not exist is unmeasured and the check exits non-zero', () => {
  const r = run('check', '--tier', 'release', '--run', 'doesnotexist00');
  assert.notEqual(r.status, 0); assert.match(r.stdout + r.stderr, /unmeasured|no run|not found|missing/i);
});
