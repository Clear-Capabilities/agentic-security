// E6-08: performance budgets. The measurement is a slow run kept in docs/engineering-excellence/data/perf-budget.json; these tests check the arithmetic, the rule
// that turns a measurement into a budget, and that exhaustion or an incomplete scan is never reported green, without re-running the slow measurement.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CLASSES, summarise, deriveBudget, judge } from '../../../scripts/engineering-excellence/perf-budget.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/data/perf-budget.json'), 'utf8'));
const md = fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/PERFORMANCE.md'), 'utf8');
const ok = (wallMs, maxRssMb = 100, health = 'complete', findings = 5) => ({ ok: true, wallMs, cpuMs: wallMs / 2, maxRssMb, health, findings, files: 10 });

test('THE REPORT STATES DISTRIBUTION, HARDWARE, N, CORPUS AND TRADE-OFFS for small, medium and large projects', () => {
  assert.deepEqual(data.classes.map((c) => c.id), ['small', 'medium', 'large']); assert.deepEqual(CLASSES.map((c) => c.id), ['small', 'medium', 'large']);
  for (const c of data.classes) {
    assert.ok(c.summary.n >= 3 && c.samples.length === c.summary.n); assert.ok(c.summary.wallMs.p50 <= c.summary.wallMs.p95 && c.summary.wallMs.min <= c.summary.wallMs.p50 && c.summary.wallMs.p95 <= c.summary.wallMs.max);
    assert.ok(fs.existsSync(path.join(ROOT, c.dir)), `${c.dir} exists`); assert.equal(c.summary.findings.length, 1, 'every sample did the same work');
    assert.ok(md.includes(c.dir) && md.includes(`${c.summary.wallMs.p95} ms`));
  }
  assert.ok(data.hardware.cpus > 0 && data.hardware.memoryGb > 0 && /^v\d+/.test(data.hardware.node) && data.hardware.os); assert.ok(data.limits.length >= 3);
  for (const w of ['Hardware:', 'N', 'wall P95', 'peak RSS', 'Trade-offs and limits', 'Exhaustion is not green']) assert.ok(md.includes(w), w);
});

test('THE BUDGET RULE IS APPLIED AS STATED: 1.5 x the observed P95 and the observed peak RSS, rounded up', () => {
  for (const c of data.classes) assert.deepEqual(c.budget, deriveBudget(c.summary), c.id);
  assert.deepEqual(deriveBudget(summarise([ok(1000, 120), ok(2000, 130), ok(3000, 140)])), { wallMsP95: 5000, maxRssMb: 250 });
});

test('EXHAUSTION IS NOT GREEN: an errored run, an incomplete scan, an over-budget P95, an over-budget RSS and a missing budget each make a class red', () => {
  const budget = { wallMsP95: 5000, maxRssMb: 200 };
  assert.equal(judge(summarise([ok(1000), ok(1200), ok(1100)]), budget).green, true);
  assert.equal(judge(summarise([ok(1000), { ok: false, error: 'killed' }, ok(1100)]), budget).green, false);
  assert.equal(judge(summarise([ok(1000), ok(1000, 100, 'partial'), ok(1100)]), budget).green, false);
  assert.equal(judge(summarise([ok(1000), ok(9000), ok(1100)]), budget).green, false);
  assert.equal(judge(summarise([ok(1000, 500), ok(1000), ok(1100)]), budget).green, false);
  assert.equal(judge(summarise([ok(1000)]), null).green, false);
});

test('THE LARGE CLASS IS REPORTED RED BECAUSE ITS SCAN WAS NOT COMPLETE, not hidden behind a fast time; small and medium are within budget', () => {
  const by = Object.fromEntries(data.classes.map((c) => [c.id, c]));
  assert.equal(by.small.verdict.green, true); assert.equal(by.medium.verdict.green, true);
  assert.equal(by.large.verdict.green, false); assert.ok(by.large.summary.notComplete > 0); assert.match(md, /NOT GREEN/);
});

test('THE 2x WARM-INCREMENTAL ASPIRATION IS REPORTED AS NOT MET, with the measured speed-up and the reason', () => {
  assert.ok(data.warm.wallReductionPct.warmOneFileChanged < 50, 'under 50% less time is under 2x');
  assert.match(md, /at least 2x for a changed-file scan is NOT met/); assert.equal(data.warm.warmEqualsColdForTheSameTree, true, 'no findings were lost');
});
