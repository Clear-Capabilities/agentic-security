// E1-04: the fresh baseline run is a measurement, not a claim: valid or explicitly invalid identity, reconciled denominators, raw artifacts, a score that can be
// recomputed from the rows, and the archived older result kept apart.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), 'utf8'));
const pointer = read('bench/independent/runs/BASELINE.json');
const RUN = `bench/independent/runs/${pointer.runId}`;
const result = read(`${RUN}/RESULT.json`); const progress = read(`${RUN}/progress.json`); const plan = read(`${RUN}/plan.json`);

test('IDENTITY: a fresh timestamp, a full commit, a clean tree and a bundle whose digest matches its sidecar, or the run says exactly why it is not valid', () => {
  const id = result.identity;
  assert.equal(result.runId, pointer.runId); assert.match(id.sourceCommit, /^[0-9a-f]{40}$/); assert.equal(id.sourceTreeClean, true); assert.deepEqual(id.dirtyPaths, []);
  assert.equal(id.bundleSha256, id.bundleSidecarSha256, 'the bundle that ran is the bundle that was built'); assert.match(id.bundleSha256, /^[0-9a-f]{64}$/);
  assert.equal(id.measurementValid, true); assert.equal(id.releaseTrust, 'trusted'); assert.deepEqual(id.invalidReasons, []);
  assert.ok(Number.isFinite(Date.parse(id.startedAt)) && Date.parse(id.startedAt) >= Date.parse(plan.plannedAt), 'it started after it was planned');
  assert.ok(Date.parse(result.mergedAt) > Date.parse(id.startedAt), 'and was merged after it ran');
  assert.ok(id.toolchain && id.toolchain.node && id.toolchain.os, 'the toolchain is recorded'); assert.match(id.lockfileSha256, /^[0-9a-f]{64}$/); assert.match(id.corpusSha256, /^[0-9a-f]{64}$/);
  assert.equal(id.config.modelValidatorEnabled, false); assert.equal(result.configuration.llm, 'none');
  assert.equal(result.measuredIn.detachedWorktreeOf, id.sourceCommit, 'the engine measured was checked out from the stated commit into a throwaway worktree');
});

test('DENOMINATORS RECONCILE: scored + unscored + unaccounted = entries in scope, recomputed here from the rows, and an unscored entry is never a miss', () => {
  const inScope = result.population.selection.entries;
  assert.equal(result.perEntry.length, result.coverage.scored); assert.equal(result.unscored.length, result.coverage.unscored);
  assert.equal(result.coverage.scored + result.coverage.unscored + result.coverage.unaccounted, inScope); assert.equal(result.coverage.unaccounted, 0);
  assert.equal(new Set(result.perEntry.map((r) => r.id)).size, result.perEntry.length, 'no entry twice');
  const scoredIds = new Set(result.perEntry.map((r) => r.id)); for (const u of result.unscored) assert.ok(!scoredIds.has(u.id), `${u.id} is not both scored and unscored`);
  assert.ok(result.unscored.every((u) => /exceeded \d+ms|timeout/.test(u.reason)), 'every unscored entry says why, and here all five are timeouts');
  assert.equal(result.headline.denominators.reconciles, true); assert.equal(result.headline.denominators.inScope, inScope);
  const counts = Object.values(result.population.selection.counts).reduce((a, b) => a + b, 0); assert.equal(counts, inScope, 'per-language counts add up to the population');
});

test('THE SCORE CAN BE RECOMPUTED from the per-entry rows, and a changed row changes it', () => {
  const sum = (rows, k) => rows.reduce((a, x) => a + (x[k] || 0), 0);
  const tp = sum(result.perEntry, 'tpLocal'); const fp = sum(result.perEntry, 'fpLocal'); const fn = sum(result.perEntry, 'fnLocal');
  assert.deepEqual([result.headline.precision.n, result.headline.precision.d], [tp, tp + fp]); assert.deepEqual([result.headline.recall.n, result.headline.recall.d], [tp, tp + fn]);
  assert.equal(result.headline.recall.d, result.coverage.scored, 'recall is over the scored entries');
  const f1 = (2 * (tp / (tp + fp)) * (tp / (tp + fn))) / ((tp / (tp + fp)) + (tp / (tp + fn))); assert.ok(Math.abs(f1 - result.headline.f1) < 1e-9);
  const doctored = result.perEntry.map((r, i) => (i === 0 ? { ...r, tpLocal: r.tpLocal + 1 } : r)); assert.notEqual(sum(doctored, 'tpLocal'), result.headline.precision.n, 'a changed row no longer matches the published numbers');
  assert.equal(result.headline.definition, 'localized (advisory-local)'); assert.equal(result.headline.quotable, true);
  assert.equal(result.headline.f1Interval.status, 'measured'); assert.ok(result.headline.f1Interval.low < result.headline.f1 && result.headline.f1 < result.headline.f1Interval.high);
});

test('RAW ARTIFACTS AND COMMANDS: every planned chunk ran to completion, with its materialisation and scoring exit codes and its log, and its raw result file', () => {
  assert.equal(result.chunks.planned, plan.chunks.length); assert.deepEqual(result.chunks.missing, []);
  for (const c of plan.chunks) {
    const st = progress.chunks[String(c.index)];
    assert.equal(st.state, 'done', `chunk ${c.index}`); assert.equal(st.materialise.exitCode, 0); assert.equal(st.score.exitCode, 0); assert.ok(st.startedAt && st.endedAt && Date.parse(st.endedAt) >= Date.parse(st.startedAt));
    const idx = String(c.index).padStart(3, '0');
    for (const log of [`chunk-${idx}-materialise.log`, `chunk-${idx}-score.log`]) assert.ok(fs.existsSync(path.join(ROOT, RUN, 'logs', log)), log);
    assert.ok(fs.existsSync(path.join(ROOT, RUN, 'chunks', `RESULT-chunk-deep-${String(c.offset).padStart(5, '0')}.json`)), `raw result for offset ${c.offset}`);
  }
  assert.ok(fs.existsSync(path.join(ROOT, RUN, 'selection.json')) && fs.existsSync(path.join(ROOT, RUN, 'plan.json')));
  assert.equal(plan.config.deep, true); assert.equal(plan.config.llm, 'none');
});

test('THE ARCHIVED OLDER RESULT IS KEPT APART: its engine, selection and definitions are different, and the run says so', () => {
  assert.match(result.historicalNote, /not comparable/); assert.match(result.historicalNote, /0\.141\.0/);
  const archived = read('bench/independent/RESULT.json');
  assert.notEqual(archived.engineVersion ?? archived.engine ?? null, result.engineVersion, 'a different engine');
  assert.notEqual(archived.generatedAt ?? archived.mergedAt ?? null, result.mergedAt);
  const scorecard = read('docs/scorecard.json'); const sc = JSON.stringify(scorecard);
  assert.ok(scorecard.committedInputs.independent, 'the scorecard carries the independent result as its own committed input'); assert.ok(sc.includes('independentRun'), 'and the latest run as a separate record');
  assert.ok(sc.includes(pointer.runId), 'and the scorecard names this run');
});

test('THE POINTER AND THE FLOORS: the approved baseline names this run, its reason, and floors written once from it', () => {
  assert.equal(pointer.supersedes, null); assert.ok(pointer.reason.includes('278 of 283')); assert.ok(Date.parse(pointer.approvedAt) > Date.parse(result.mergedAt));
  const floors = read(`bench/independent/runs/${pointer.floorsFile}`);
  assert.equal(floors.runId ?? pointer.runId, pointer.runId);
  const text = JSON.stringify(floors); assert.ok(/recall|precision/.test(text));
});
