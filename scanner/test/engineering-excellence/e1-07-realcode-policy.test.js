// E1-07: the real-code regression policy. Floors are pre-registered; a missing, unhealthy or underpowered run is never green.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO, cleanup } from './helpers.js';
import { scorePopulation, headline } from '../../../bench/independent/scorer.mjs';
import { approve, buildFloors, evaluate, exitCodeFor, latestRunId, loadBaseline, report } from '../../../bench/independent/realcode.mjs';

const REALCODE = path.join(REPO, 'bench/independent/realcode.mjs');
const entry = (i, lang) => ({ id: `${lang}-${i}`, repo: `org/${lang}-${i}`, cve: null, parentCommit: `p${lang}${i}`, fixCommit: `f${lang}${i}`, language: lang, cwe: 'CWE-89' });
const row = (e, hit) => ({ id: e.id, cwe: e.cwe, language: e.language, repo: e.repo, tp: hit ? 1 : 0, fn: hit ? 0 : 1, fp: 0, tn: 1, tpWide: hit ? 1 : 0, fnWide: hit ? 0 : 1, fpWide: 0, tnWide: 1, tpLocal: hit ? 1 : 0, fnLocal: hit ? 0 : 1, fpLocal: 0, tnLocal: 1, survivedFix: 0, survivedFixWide: 0, preFindings: 1, postFindings: 0 });
const VALID = { measurementValid: true, invalidReasons: [], sourceCommit: 'a'.repeat(40), bundleSha256: 'b'.repeat(64) };

/** A finished-run result: `plan` is { language: { n, hits } }. */
function result({ plan, runId = 'run-1', identity = VALID, extraUnscored = 0, dropRows = 0 }) {
  const entries = []; const rows = [];
  for (const [lang, { n, hits }] of Object.entries(plan)) for (let i = 0; i < n; i++) { const e = entry(i, lang); entries.push(e); rows.push(row(e, i < hits)); }
  const unscored = Array.from({ length: extraUnscored }, (_, i) => ({ id: `u-${i}`, reason: 'not fetched' }));
  const all = [...entries, ...unscored.map((u) => ({ ...entry(0, 'x'), id: u.id, repo: `org/${u.id}`, language: 'python' }))];
  const sc = scorePopulation({ rows: rows.slice(0, rows.length - dropRows), unscored, manifestEntries: all, protocolHash: 'sha256:t' });
  return { runId, engineVersion: '9.9.9', mergedAt: '2026-10-16T00:00:00Z', identity, scoring: sc, headline: headline(sc) };
}
const BASE = { python: { n: 60, hits: 24 }, go: { n: 50, hits: 20 }, kotlin: { n: 5, hits: 1 } };

test('approving needs a reason; floors are the lower bound of the baseline interval, only for languages with enough entries', () => {
  const r = result({ plan: BASE });
  assert.throws(() => buildFloors(r, {}), /stated reason/);
  const f = buildFloors(r, { reason: 'first clean-commit run of the independent population' });
  assert.equal(f.languages.python.status, 'floor');
  assert.ok(f.languages.python.recallFloor < f.languages.python.baseline.recall, 'the floor is below the observed value');
  assert.ok(f.languages.python.recallFloor > 0.2);
  assert.equal(f.languages.kotlin.status, 'insufficient_population');
  assert.equal(f.languages.kotlin.recallFloor, undefined);
  assert.equal(f.derivedFrom.runId, 'run-1');
});

test('no baseline, or no run, is unmeasured and never green', () => {
  const f = buildFloors(result({ plan: BASE }), { reason: 'baseline for tests of the policy' });
  const a = evaluate({ floors: null, current: result({ plan: BASE }) });
  assert.equal(a.status, 'unmeasured'); assert.equal(a.green, false);
  const b = evaluate({ floors: f, current: null });
  assert.equal(b.status, 'unmeasured'); assert.equal(b.green, false);
  assert.equal(exitCodeFor(a), 2);
});

test('the same result passes; a language that falls below its floor fails (an intentionally worsened detection)', () => {
  const f = buildFloors(result({ plan: BASE }), { reason: 'baseline for tests of the policy' });
  const same = evaluate({ floors: f, current: result({ plan: BASE, runId: 'r2' }) });
  assert.equal(same.status, 'passed', 'kotlin never had a floor (too few entries at baseline), so there is nothing to compare for it; python and go are compared');
  assert.equal(same.checks.filter((c) => c.id.startsWith('language:')).length, 2);
  const comparable = { python: { n: 60, hits: 24 }, go: { n: 50, hits: 20 } };
  const f2 = buildFloors(result({ plan: comparable }), { reason: 'baseline without a small language' });
  const ok = evaluate({ floors: f2, current: result({ plan: comparable, runId: 'r2' }) });
  assert.equal(ok.status, 'passed'); assert.equal(ok.green, true); assert.equal(exitCodeFor(ok), 0);
  const worse = evaluate({ floors: f2, current: result({ plan: { python: { n: 60, hits: 9 }, go: { n: 50, hits: 20 } }, runId: 'r3' }) });
  assert.equal(worse.status, 'failed');
  assert.deepEqual(worse.regressions.map((r) => `${r.language}:${r.metric}`), ['python:recall']);
  assert.equal(exitCodeFor(worse), 1);
  const slightlyLower = evaluate({ floors: f2, current: result({ plan: { python: { n: 60, hits: 21 }, go: { n: 50, hits: 20 } }, runId: 'r4' }) });
  assert.equal(slightlyLower.status, 'passed', 'sampling noise inside the interval does not trip the floor');
});

test('a floor language that vanished from the run is a regression, and a language with too few entries is insufficient, not passed', () => {
  const f = buildFloors(result({ plan: { python: { n: 60, hits: 24 }, go: { n: 50, hits: 20 } } }), { reason: 'baseline for tests of the policy' });
  const missing = evaluate({ floors: f, current: result({ plan: { python: { n: 60, hits: 24 } } }) });
  assert.equal(missing.status, 'failed');
  assert.equal(missing.regressions[0].metric, 'presence');
  const thin = evaluate({ floors: f, current: result({ plan: { python: { n: 60, hits: 24 }, go: { n: 8, hits: 4 } } }) });
  assert.equal(thin.status, 'insufficient_population');
  assert.equal(thin.green, false);
  assert.equal(exitCodeFor(thin), 2);
});

test('a run that cannot support a comparison is blocked: unreconciled denominators, too many unscored entries, an unclean measurement', () => {
  const f = buildFloors(result({ plan: { python: { n: 60, hits: 24 } } }), { reason: 'baseline for tests of the policy' });
  const p = { python: { n: 60, hits: 24 } };
  assert.equal(evaluate({ floors: f, current: result({ plan: p, dropRows: 3 }) }).status, 'blocked');
  const unhealthy = evaluate({ floors: f, current: result({ plan: p, extraUnscored: 20 }) });
  assert.equal(unhealthy.status, 'blocked');
  assert.match(unhealthy.why, /unscored or unaccounted/);
  const dirty = evaluate({ floors: f, current: result({ plan: p, identity: { measurementValid: false, invalidReasons: ['dirty_worktree'], sourceCommit: 'a'.repeat(40) } }) });
  assert.equal(dirty.status, 'blocked');
  assert.match(dirty.why, /dirty_worktree/);
  assert.equal(evaluate({ floors: f, current: result({ plan: p, identity: null }) }).status, 'blocked');
});

test('the quick tier is diagnostic: it reports the verdict but only a blocked run fails the build', () => {
  const f = buildFloors(result({ plan: { python: { n: 60, hits: 24 } } }), { reason: 'baseline for tests of the policy' });
  const worse = evaluate({ floors: f, current: result({ plan: { python: { n: 60, hits: 5 } } }), tier: 'quick' });
  assert.equal(worse.status, 'failed');
  assert.equal(exitCodeFor(worse), 0, 'a small PR sample carries no gate');
  const dirtyQuick = evaluate({ floors: f, current: result({ plan: { python: { n: 60, hits: 24 } }, identity: { measurementValid: false, invalidReasons: ['dirty_worktree'], sourceCommit: 'a'.repeat(40) } }), tier: 'quick' });
  assert.equal(dirtyQuick.status, 'passed', 'a dirty tree is allowed for a diagnostic');
  assert.equal(dirtyQuick.checks.find((c) => c.id === 'clean-measurement').status, 'warning');
  assert.equal(exitCodeFor(evaluate({ floors: f, current: null, tier: 'quick' })), 0);
  assert.equal(exitCodeFor(evaluate({ floors: f, current: result({ plan: { python: { n: 60, hits: 24 } }, extraUnscored: 30 }), tier: 'quick' })), 1);
});

// ---- files and the command line ---------------------------------------------------------------------------------------------------

function runsDirWith(results) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-realcode-'));
  for (const r of results) { fs.mkdirSync(path.join(dir, r.runId), { recursive: true }); fs.writeFileSync(path.join(dir, r.runId, 'RESULT.json'), JSON.stringify(r)); }
  return dir;
}
const cli = (args, dir) => spawnSync(process.execPath, [REALCODE, ...args, '--runs-dir', dir], { encoding: 'utf8', timeout: 60000 });

test('approving writes floors once, refuses an overwrite, and records a successor with its history', () => {
  const dir = runsDirWith([result({ plan: { python: { n: 60, hits: 24 } }, runId: 'a' }), result({ plan: { python: { n: 60, hits: 30 } }, runId: 'b' })]);
  try {
    const first = approve('a', { reason: 'first clean-commit baseline', runsDir: dir });
    assert.equal(first.pointer.runId, 'a');
    assert.ok(fs.existsSync(path.join(dir, 'floors-a.json')));
    assert.throws(() => approve('b', { reason: 'a better run, quietly replacing the first', runsDir: dir }), /already approved/);
    const second = approve('b', { reason: 'engine improvement accepted as the new baseline', supersede: true, runsDir: dir });
    assert.equal(second.pointer.supersedes.runId, 'a');
    assert.ok(fs.existsSync(path.join(dir, 'floors-a.json')), 'the original floors are kept');
    assert.deepEqual(second.pointer.history.map((h) => h.runId), ['a']);
    assert.equal(loadBaseline(dir).pointer.runId, 'b');
    assert.throws(() => approve('nope', { reason: 'a run that does not exist', runsDir: dir }), /no RESULT\.json/);
  } finally { cleanup(dir); }
});

test('a missing corpus cannot pass green: with nothing recorded the release check is unmeasured and exits non-zero', () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-realcode-empty-'));
  try {
    const rel = cli(['check', '--tier', 'release'], empty);
    assert.equal(rel.status, 2, rel.stdout + rel.stderr);
    assert.match(rel.stdout, /UNMEASURED/);
    const quick = cli(['check', '--tier', 'quick'], empty);
    assert.equal(quick.status, 0);
    assert.match(quick.stdout, /UNMEASURED/);
    assert.match(cli(['report'], empty).stdout, /accuracy is unmeasured/);
  } finally { cleanup(empty); }
});

test('end to end on disk: approve a baseline, a healthy run passes, a worsened run fails with a non-zero exit', () => {
  const dir = runsDirWith([result({ plan: { python: { n: 60, hits: 24 }, go: { n: 50, hits: 20 } }, runId: '2026-a' })]);
  try {
    assert.equal(cli(['approve', '--run', '2026-a', '--reason', 'first clean-commit baseline of the engine'], dir).status, 0);
    const same = cli(['check', '--tier', 'release', '--run', '2026-a'], dir);
    assert.equal(same.status, 0, same.stdout);
    assert.match(same.stdout, /PASSED/);
    fs.mkdirSync(path.join(dir, '2026-b'));
    fs.writeFileSync(path.join(dir, '2026-b', 'RESULT.json'), JSON.stringify(result({ plan: { python: { n: 60, hits: 6 }, go: { n: 50, hits: 20 } }, runId: '2026-b' })));
    const worse = cli(['check', '--tier', 'release', '--run', '2026-b'], dir);
    assert.equal(worse.status, 1, worse.stdout);
    assert.match(worse.stdout, /FAILED.*python recall/);
    assert.equal(latestRunId(dir) !== null, true);
    assert.match(report('2026-a', { runsDir: dir }), /Independent run 2026-a/);
  } finally { cleanup(dir); }
});

test('the npm scripts exist and the release script is the release tier', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner/package.json'), 'utf8'));
  assert.match(pkg.scripts['bench:realcode:check'], /realcode\.mjs check --tier release/);
  assert.match(pkg.scripts['bench:realcode:check:quick'], /--tier quick/);
  assert.match(pkg.scripts['bench:realcode:report'], /realcode\.mjs report/);
});
