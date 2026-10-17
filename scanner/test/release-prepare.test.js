import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { bumpVersion, planSteps, VERSION_FILES } from '../../scripts/release-prepare.mjs';
import { mkTestTmp } from './helpers/tmp.js';

test('bumpVersion replaces every occurrence and reports a file that had none', () => {
  const dir = mkTestTmp('release-prepare-');
  writeFileSync(join(dir, 'a.json'), '{"version":"1.2.3","dep":"1.2.3","other":"1.2.30"}');
  writeFileSync(join(dir, 'b.md'), 'nothing here');
  const counts = bumpVersion(dir, '1.2.3', '1.2.4', ['a.json', 'b.md']);
  assert.equal(counts['a.json'], 3, 'a substring match is counted too, which is why the caller reviews the diff');
  assert.equal(counts['b.md'], 0);
  assert.match(readFileSync(join(dir, 'a.json'), 'utf8'), /"version":"1.2.4"/);
  assert.equal(readFileSync(join(dir, 'b.md'), 'utf8'), 'nothing here');
});

test('bumpVersion refuses anything that is not X.Y.Z', () => {
  assert.throws(() => bumpVersion('.', '1.2', '1.3.0', []), /X\.Y\.Z/);
  assert.throws(() => bumpVersion('.', '1.2.3', 'latest', []), /X\.Y\.Z/);
});

test('the plan regenerates before it verifies, and --no-tests drops only the suites', () => {
  const all = planSteps().map((s) => s.name);
  const gen = planSteps({ tests: false }).map((s) => s.name);
  assert.deepEqual(all.slice(0, gen.length), gen);
  assert.ok(all.length > gen.length);
  assert.ok(gen.indexOf('build the bundle') < gen.indexOf('regenerate the scorecard'));
  assert.ok(gen.indexOf('record inventory test runs') < gen.indexOf('render the inventory'));
  assert.ok(gen.indexOf('regenerate the regression report') < gen.indexOf('regenerate the final report'));
});

test('the version files are the ones the release check compares', () => {
  assert.ok(VERSION_FILES.includes('scanner/package.json') && VERSION_FILES.includes('scanner/package-lock.json'));
});
