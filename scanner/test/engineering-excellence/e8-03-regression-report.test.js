// E8-03: the before/after report is generated from recorded results, current, and does not mix instruments.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const md = fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/REGRESSION_REPORT.md'), 'utf8');

test('THE REPORT IS CURRENT: regenerating it from the recorded results reproduces it byte for byte', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/engineering-excellence/regression-report.mjs'), '--check'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('IT COVERS EVERY AREA THE TASK NAMES, and says "not measured" where there was no before', () => {
  for (const w of ['Independent accuracy', 'Known-miss clusters', 'Fix verification safety', 'Scan completion', 'CPU and memory', 'Privacy hardening', 'Evidence coverage', 'Regressions and costs, plainly', 'Release candidate']) assert.ok(md.includes(w), w);
  assert.match(md, /\*\*unmeasured\*\*/); assert.match(md, /not measured at baseline/); assert.match(md, /95% interval/);
});

test('NO MISLEADING COMPARISON: the older engine\'s result is its own table with no difference computed, and the first measurement is not called an improvement', () => {
  assert.match(md, /not comparable and no difference is drawn/); assert.match(md, /first measurement/); assert.match(md, /not an improvement or a regression/);
  const archivedRow = md.split('\n').find((l) => l.startsWith('| 0.141.0')); assert.ok(archivedRow && !/%.*→|delta|\+\d/.test(archivedRow));
  assert.match(md, /\*\*not\*\* accuracy/, 'the curated net is labelled as not accuracy');
});

test('REGRESSIONS ARE LISTED AS REGRESSIONS, with numbers where there are numbers', () => {
  const section = md.slice(md.indexOf('## 9.'));
  for (const w of ['Bundle size', 'Published package files', 'Scan health', 'Large trees', 'Warm incremental', 'false positives', 'Miss forensics']) assert.ok(section.includes(w), w);
  assert.match(section, /2869 to 3095/); assert.match(section, /partial/);
});
