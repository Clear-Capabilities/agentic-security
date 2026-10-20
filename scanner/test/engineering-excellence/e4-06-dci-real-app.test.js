// E4-06: the deterministic context analysis scored on application-shaped authorization cases in two web stacks. The corpus is hand-written and labelled by its
// author, which the report says in its first section; these tests check that the measurement is complete and honest, not that the numbers are good.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CASES, NOT_REPRESENTABLE } from '../../../bench/dci-real-app/cases.mjs';
import { scoreCase } from '../../../bench/dci-real-app/runner.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const result = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/data/dci-real-app.json'), 'utf8'));
const md = fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/DCI_REAL_APP.md'), 'utf8');

test('THE COMMITTED REPORT IS CURRENT: re-running the corpus reproduces both files byte for byte', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'bench/dci-real-app/runner.mjs'), '--check'], { cwd: ROOT, encoding: 'utf8', timeout: 240_000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('COVERAGE: at least two web stacks, the PRD families that can be represented, vulnerable and fixed twins, and non-obvious safe counterexamples', () => {
  assert.ok(new Set(CASES.map((c) => c.stack)).size >= 2); assert.deepEqual([...new Set(CASES.map((c) => c.stack))].sort(), ['express', 'flask']);
  for (const fam of ['missing-middleware', 'ownership', 'indirect-ownership', 'multi-tenant', 'function-level-authorization']) assert.ok(CASES.some((c) => c.family === fam), fam);
  assert.ok(CASES.some((c) => c.nonObvious && Object.values(c.routes).includes('safe')), 'a safe route that looks unprotected');
  assert.ok(CASES.some((c) => c.nonObvious && Object.values(c.routes).includes('vulnerable')), 'a vulnerable route that looks protected');
  for (const stack of ['express', 'flask']) { const labels = CASES.filter((c) => c.stack === stack).flatMap((c) => Object.values(c.routes)); assert.ok(labels.includes('vulnerable') && labels.includes('safe'), stack); }
});

test('NOTHING IS DROPPED FROM THE DENOMINATORS: every labelled route is a TP, FP, FN, TN or unresolved, per stack and per family, and the totals add up', () => {
  const labelled = CASES.reduce((a, c) => a + Object.keys(c.routes).length, 0); assert.equal(result.routes, labelled);
  const sum = (t) => t.tp + t.fp + t.fn + t.tn + t.unresolved;
  assert.equal(sum(result.overall), labelled);
  for (const group of [result.byStack, result.byFamily, result.byNonObvious]) assert.equal(Object.values(group).reduce((a, t) => a + sum(t), 0), labelled);
  for (const t of [result.overall, ...Object.values(result.byStack), ...Object.values(result.byFamily)]) { assert.equal(t.precisionOf, t.tp + t.fp); assert.equal(t.recallOf, t.tp + t.fn); if (t.precisionOf) assert.ok(Math.abs(t.precision - t.tp / t.precisionOf) < 1e-3); }
  assert.equal(result.misses.length, result.overall.fp + result.overall.fn + result.overall.unresolved, 'every wrong or unsettled route is listed');
});

test('FAILURES ARE LIMITATIONS, NOT EXCLUSIONS: the report lists each wrong route, lists the routes it could not settle, and names the families that cannot be represented', () => {
  for (const m of result.misses) assert.ok(md.includes(`| ${m.case} |`) && md.includes(m.route), `${m.case} ${m.route} is in the report`);
  assert.ok(result.overall.unresolved >= 1, 'router-mounted routes are not resolved to their mounted path, so those routes stay unresolved and are listed');
  assert.equal(result.misses.length, result.overall.fp + result.overall.fn + result.overall.unresolved, 'whatever the analysis gets wrong or cannot settle is reported, and nothing is dropped');
  assert.deepEqual(result.notRepresentable.map((n) => n.family), NOT_REPRESENTABLE.map((n) => n.family)); assert.deepEqual(NOT_REPRESENTABLE.map((n) => n.family), ['state-machine-bypass', 'race-toctou']);
  assert.match(md, /not an independent reviewer/); assert.match(md, /not.* accuracy on real software/); assert.match(result.labelledBy, /not an independent reviewer/);
});

test('THE MEASUREMENT CAN FAIL: flipping a label changes the outcome, and removing the control from a safe twin turns a true negative into a true positive', async () => {
  const c = CASES.find((x) => x.id === 'js-own-2'); const base = await scoreCase(c); assert.ok(base.rows.every((r) => r.outcome === 'tn'));
  const flipped = await scoreCase({ ...c, routes: Object.fromEntries(Object.keys(c.routes).map((k) => [k, 'vulnerable'])) }); assert.ok(flipped.rows.every((r) => r.outcome === 'fn'), 'a wrong label is a miss, so labels cannot be silently bent to fit');
  const broken = await scoreCase({ ...c, files: { 'app.js': c.files['app.js'].replace(/, ownerId: req\.user\.id/g, '') }, routes: Object.fromEntries(Object.keys(c.routes).map((k) => [k, 'vulnerable'])) });
  assert.ok(broken.rows.every((r) => r.outcome === 'tp'), 'removing the owner scope is detected on every route');
});
